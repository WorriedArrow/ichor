//! SNTP (RFC 4330), sans-I/O: one request, and the clock offset and round
//! trip its answer gives, and a [`Discipline`] that steers a wall clock
//! from them (a cloud's metadata server answers NTP).

use core::time::Duration;

pub const PORT: u16 = 123;
/// The size of a packet.
pub const LEN: usize = 48;
/// Seconds from 1900 (NTP's epoch) to 1970 (Unix's).
const EPOCH: u64 = 2_208_988_800;

/// An NTP timestamp of Unix time `t`.
fn stamp(t: Duration) -> [u8; 8] {
    let secs = (t.as_secs() + EPOCH) as u32;
    let frac = ((u64::from(t.subsec_nanos()) << 32) / 1_000_000_000) as u32;
    let mut b = [0; 8];
    b[..4].copy_from_slice(&secs.to_be_bytes());
    b[4..].copy_from_slice(&frac.to_be_bytes());
    b
}

/// The Unix time of an NTP timestamp, in nanoseconds (it may be before
/// 1970 only if the server is badly wrong: then `None`).
fn unix_ns(b: &[u8]) -> Option<i128> {
    let secs = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    let frac = u64::from(u32::from_be_bytes([b[4], b[5], b[6], b[7]]));
    let secs = secs.checked_sub(EPOCH)?;
    Some(i128::from(secs) * 1_000_000_000 + i128::from((frac * 1_000_000_000) >> 32))
}

/// A client request sent at Unix time `sent` (the server echoes it back).
pub fn request(sent: Duration) -> [u8; LEN] {
    const VERSION_4_CLIENT: u8 = 4 << 3 | 3;
    let mut b = [0; LEN];
    b[0] = VERSION_4_CLIENT;
    b[40..48].copy_from_slice(&stamp(sent));
    b
}

/// What an answer says of this machine's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// The server's clock less this one's, in nanoseconds.
    pub offset_ns: i64,
    /// The round trip less the server's time on it.
    pub rtt_ns: i64,
    pub stratum: u8,
}

/// Reads the answer to the request sent at `sent`, received at `received`
/// (both by this machine's clock): `None` if it is not a server's answer
/// to that request, or the server says it is not synchronized.
pub fn answer(b: &[u8], sent: Duration, received: Duration) -> Option<Sample> {
    const SERVER: u8 = 4;
    const UNSYNCHRONIZED: u8 = 3;
    if b.len() < LEN || b[0] & 7 != SERVER || b[0] >> 6 == UNSYNCHRONIZED {
        return None;
    }
    let stratum = b[1];
    if stratum == 0 || stratum > 15 || b[24..32] != stamp(sent) {
        return None;
    }
    let t1 = i128::try_from(sent.as_nanos()).ok()?;
    let t4 = i128::try_from(received.as_nanos()).ok()?;
    let (t2, t3) = (unix_ns(&b[32..40])?, unix_ns(&b[40..48])?);
    Some(Sample {
        offset_ns: (((t2 - t1) + (t3 - t4)) / 2) as i64,
        rtt_ns: ((t4 - t1) - (t3 - t2)) as i64,
        stratum,
    })
}

/// Under this round trip a sample is trusted to steer the clock (its error
/// is at most half the round trip).
pub const STEER_RTT_NS: i64 = 3_000_000;
/// An offset larger than this is stepped at once, not slewed away.
pub const STEP_NS: i64 = 100_000_000;
/// The loop's time constant, in seconds.
const TAU_S: i128 = 60;
/// The fastest the clock is made to gain or lose: 500 ppm.
pub const MAX_PPB: i64 = 500_000;

/// What the clock should do after a sample: step by `step_ns`, then gain
/// `ppb` parts per billion on its own rate until the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Steer {
    pub step_ns: i64,
    pub ppb: i64,
}

/// Disciplines a clock from samples: the first trusted sample (and any
/// off by more than [`STEP_NS`]) steps it; the rest steer its rate with a
/// proportional-integral loop, so it slews, never jumps, and the integral
/// learns the clock's own rate error (how far its oscillator is off).
#[derive(Clone, Copy, Debug, Default)]
pub struct Discipline {
    freq_ppb: i64,
    last_ns: Option<u64>,
}

impl Discipline {
    /// The clock's rate error as learned: what it is made to gain.
    pub fn freq_ppb(&self) -> i64 {
        self.freq_ppb
    }

    /// Takes a sample taken at `t_ns` (a monotonic clock); how to steer,
    /// or `None` if the sample is not trusted.
    pub fn sample(&mut self, t_ns: u64, s: Sample) -> Option<Steer> {
        if !(0..STEER_RTT_NS).contains(&s.rtt_ns) {
            return None;
        }
        let off = s.offset_ns;
        let last = self.last_ns.replace(t_ns);
        let Some(last) = last.filter(|_| off.abs() <= STEP_NS) else {
            return Some(Steer {
                step_ns: off,
                ppb: self.freq_ppb,
            });
        };
        let dt_ns = i128::from(t_ns.saturating_sub(last)).min(TAU_S * 1_000_000_000);
        let gained = i128::from(off) * dt_ns / (TAU_S * TAU_S * 1_000_000_000);
        let max = i128::from(MAX_PPB);
        let freq = (i128::from(self.freq_ppb) + gained).clamp(-max, max);
        self.freq_ppb = freq as i64;
        let ppb = (freq + i128::from(off) / TAU_S).clamp(-max, max);
        Some(Steer {
            step_ns: 0,
            ppb: ppb as i64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock that runs `drift_ppb` fast, steered as frame steers the wall
    /// clock, against true time; the offsets a server would see.
    struct Clock {
        drift_ppb: i64,
        start_ns: i64,
        at: u64,
        by: i64,
        ppb: i64,
    }

    impl Clock {
        fn read(&self, t: u64) -> i64 {
            let own = t as i64
                + (i128::from(t as i64) * i128::from(self.drift_ppb) / 1_000_000_000) as i64;
            let steer = self.by
                + (i128::from((t - self.at) as i64) * i128::from(self.ppb) / 1_000_000_000) as i64;
            self.start_ns + own + steer
        }

        fn steer(&mut self, t: u64, s: Steer) {
            let by = self.read(t)
                - self.start_ns
                - t as i64
                - (i128::from(t as i64) * i128::from(self.drift_ppb) / 1_000_000_000) as i64;
            self.at = t;
            self.by = by + s.step_ns;
            self.ppb = s.ppb;
        }
    }

    fn sample(offset_ns: i64, rtt_ns: i64) -> Sample {
        Sample {
            offset_ns,
            rtt_ns,
            stratum: 2,
        }
    }

    #[test]
    fn a_drifting_clock_is_brought_in_and_kept() {
        // kvmclock on GCP: 71 ppm slow, the firmware's clock 0.57 s ahead.
        let mut c = Clock {
            drift_ppb: -71_000,
            start_ns: 567_700_000,
            at: 0,
            by: 0,
            ppb: 0,
        };
        let mut d = Discipline::default();
        let mut worst_late = 0i64;
        for i in 1..=720u64 {
            let t = i * 5_000_000_000;
            if i == 361 {
                // A migration: the clock jumps 300 ms and runs 96 ppm
                // differently.
                c.start_ns -= 300_000_000;
                c.drift_ppb += 96_000;
            }
            let off = t as i64 - c.read(t);
            if i == 1 || i == 361 {
                assert!(off.abs() > STEP_NS, "{i}: {off}");
            }
            // Every third sample came back slowly and is not trusted.
            let rtt = if i % 3 == 0 { 9_000_000 } else { 1_000_000 };
            match d.sample(t, sample(off, rtt)) {
                Some(s) => {
                    assert_eq!(s.step_ns != 0, i == 1 || i == 361, "{i}: {s:?}");
                    c.steer(t, s)
                }
                None => assert_eq!(rtt, 9_000_000),
            }
            // Twenty minutes after either step, within a millisecond.
            if (240..361).contains(&i) || i >= 600 {
                worst_late = worst_late.max(off.abs());
            }
        }
        assert!(worst_late < 1_000_000, "{worst_late}");
        // And it learned the clock's rate: 25 ppm fast after the move.
        assert!((d.freq_ppb() + 25_000).abs() < 500, "{}", d.freq_ppb());
    }

    #[test]
    fn steering_is_bounded() {
        let mut d = Discipline::default();
        assert_eq!(d.sample(0, sample(5, 1_000)).unwrap().step_ns, 5);
        let mut t = 0;
        for _ in 0..1000 {
            t += 5_000_000_000;
            let s = d.sample(t, sample(STEP_NS, 1_000)).unwrap();
            assert_eq!(s.step_ns, 0);
            assert!(s.ppb.abs() <= MAX_PPB);
        }
        assert_eq!(d.freq_ppb(), MAX_PPB);
        assert!(d.sample(t, sample(0, -1)).is_none());
    }

    fn server(req: &[u8; LEN], recv: Duration, xmit: Duration) -> [u8; LEN] {
        let mut b = [0; LEN];
        b[0] = 4 << 3 | 4;
        b[1] = 2;
        b[24..32].copy_from_slice(&req[40..48]);
        b[32..40].copy_from_slice(&stamp(recv));
        b[40..48].copy_from_slice(&stamp(xmit));
        b
    }

    #[test]
    fn offset_and_round_trip() {
        let t1 = Duration::new(1_795_400_000, 0);
        let req = request(t1);
        assert_eq!(req[0], 0x23);
        // The server is 1.5 s ahead; 10 ms each way, 2 ms inside it.
        let ahead = Duration::from_millis(1500);
        let t2 = t1 + Duration::from_millis(10) + ahead;
        let t3 = t2 + Duration::from_millis(2);
        let t4 = t1 + Duration::from_millis(22);
        let s = answer(&server(&req, t2, t3), t1, t4).unwrap();
        // (NTP fractions round to under a nanosecond each.)
        assert!((s.offset_ns - 1_500_000_000).abs() < 4, "{s:?}");
        assert!((s.rtt_ns - 20_000_000).abs() < 4, "{s:?}");
        assert_eq!(s.stratum, 2);
        // Behind, too.
        let t2 = t1 + Duration::from_millis(10) - Duration::from_millis(300);
        let s = answer(&server(&req, t2, t2), t1, t1 + Duration::from_millis(20)).unwrap();
        assert!((s.offset_ns + 300_000_000).abs() < 4, "{s:?}");
    }

    #[test]
    fn what_is_not_the_answer_is_refused() {
        let t1 = Duration::new(1_795_400_000, 500);
        let req = request(t1);
        let good = server(&req, t1, t1);
        assert!(answer(&good, t1, t1).is_some());
        // Another request's answer, a client's packet, an unsynchronized
        // server, stratum 0 (a kiss of death), short.
        assert!(answer(&good, t1 + Duration::from_secs(1), t1).is_none());
        let mut b = good;
        b[0] = 4 << 3 | 3;
        assert!(answer(&b, t1, t1).is_none());
        let mut b = good;
        b[0] |= 3 << 6;
        assert!(answer(&b, t1, t1).is_none());
        let mut b = good;
        b[1] = 0;
        assert!(answer(&b, t1, t1).is_none());
        assert!(answer(&good[..47], t1, t1).is_none());
    }
}
