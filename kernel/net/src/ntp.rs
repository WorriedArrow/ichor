//! SNTP (RFC 4330), sans-I/O: one request, and the clock offset and round
//! trip its answer gives. Ichor sets no clock from it; it measures how far
//! its own wall clock is from a server's (a cloud's metadata server
//! answers NTP), so a jump or a drift shows.

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

#[cfg(test)]
mod tests {
    use super::*;

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
