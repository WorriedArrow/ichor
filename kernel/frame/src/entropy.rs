//! The CPU's hardware random number generator.
//!
//! RDSEED reads the conditioned entropy source; RDRAND reads a DRBG that
//! source reseeds. Both can run dry for a moment, so each word is retried a
//! bounded number of times (Intel's guidance: RDRAND failing ten times in a
//! row means the hardware is broken). Callers decide how much entropy to
//! credit; frame only reports which instruction produced the words.

use crate::arch::{cpu, regs};

/// Which instruction filled the words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Rdseed,
    Rdrand,
}

const RDSEED_TRIES: usize = 100;
const RDRAND_TRIES: usize = 10;

/// Fills `out` from RDSEED if the CPU has it, else RDRAND. Returns the
/// source and how many words were filled from the front (fewer than
/// `out.len()` only if the hardware kept failing), or `None` if the CPU has
/// neither instruction.
pub fn hardware_random(out: &mut [u64]) -> Option<(Source, usize)> {
    use core::sync::atomic::{AtomicU8, Ordering::Relaxed};
    // What CPUID said, asked once: in a virtual machine each CPUID traps to
    // the hypervisor, and this runs for every random request (every exec).
    static HAS: AtomicU8 = AtomicU8::new(0); // 0 unknown, else 1 | 2 rdrand | 4 rdseed
    let mut has = HAS.load(Relaxed);
    if has == 0 {
        let f = cpu::features();
        has = 1 | if f.rdrand { 2 } else { 0 } | if f.rdseed { 4 } else { 0 };
        HAS.store(has, Relaxed);
    }
    let (source, tries) = if has & 4 != 0 {
        (Source::Rdseed, RDSEED_TRIES)
    } else if has & 2 != 0 {
        (Source::Rdrand, RDRAND_TRIES)
    } else {
        return None;
    };
    let mut filled = 0;
    for w in out.iter_mut() {
        let got = (0..tries).find_map(|_| match source {
            // SAFETY: CPUID reported RDSEED.
            Source::Rdseed => unsafe { regs::rdseed() },
            // SAFETY: CPUID reported RDRAND.
            Source::Rdrand => unsafe { regs::rdrand() },
        });
        match got {
            Some(v) => *w = v,
            None => break,
        }
        filled += 1;
    }
    Some((source, filled))
}
