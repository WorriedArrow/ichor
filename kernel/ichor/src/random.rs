//! The kernel's random generator, behind `getrandom`, `/dev/random`,
//! `/dev/urandom` and `AT_RANDOM`.
//!
//! One ChaCha20 generator with fast key erasure (the `csprng` crate),
//! seeded at boot from the CPU (RDSEED, else RDRAND) and from virtio-rng,
//! with the TSC mixed in uncredited. Every request also absorbs a fresh
//! hardware word (uncredited), so a state compromise does not outlive the
//! next request on a machine with RDRAND. Requests are served in 4 KiB
//! pieces, each a separate generator request, so the lock is never held
//! long and each piece's key is erased before the next.
//!
//! Credit: 64 bits per RDSEED word and per virtio-rng 8 bytes; 32 bits per
//! RDRAND word (a DRBG output, so counted at half). The generator is
//! seeded once 256 bits are credited; if no source gave that much at boot,
//! [`seeded`] stays false and `getrandom` refuses callers that did not ask
//! for `GRND_INSECURE`.

use core::sync::atomic::{AtomicBool, Ordering};

use csprng::Csprng;
use frame::entropy::Source;
use frame::println;
use frame::sync::SpinLock;

static GENERATOR: SpinLock<Csprng> = SpinLock::new(Csprng::new());
static SEEDED: AtomicBool = AtomicBool::new(false);
const PIECE: usize = 4096;

fn words_to_bytes(w: &[u64]) -> alloc::vec::Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

/// Seeds the generator from every source there is and reports what it got.
pub(crate) fn init() {
    let mut g = GENERATOR.lock();
    let tsc = frame::time::now().as_nanos() as u64;
    g.absorb(&tsc.to_le_bytes(), 0);
    let mut cpu_bits = 0u32;
    let mut cpu = alloc::string::String::from("no RDSEED/RDRAND");
    let mut w = [0u64; 8];
    if let Some((src, n)) = frame::entropy::hardware_random(&mut w) {
        let per = if src == Source::Rdseed { 64 } else { 32 };
        cpu_bits = per * n as u32;
        g.absorb(&words_to_bytes(&w[..n]), cpu_bits);
        cpu = alloc::format!("{src:?} {cpu_bits} bits");
    }
    let mut rng_bits = 0u32;
    let rng = match virtio_rng::probe() {
        Some(Ok(mut dev)) => {
            let mut b = [0u8; 64];
            let n = dev.read(&mut b);
            rng_bits = (n as u32 / 8) * 64;
            g.absorb(&b[..n], rng_bits);
            alloc::format!("virtio-rng {rng_bits} bits")
        }
        Some(Err(e)) => alloc::format!("virtio-rng failed ({e:?})"),
        None => alloc::string::String::from("no virtio-rng"),
    };
    let seeded = g.seeded();
    drop(g);
    SEEDED.store(seeded, Ordering::Release);
    if seeded {
        println!("ichor: random: ChaCha20 seeded ({cpu}, {rng})");
    } else {
        println!(
            "ichor: random: WARNING: only {} bits of entropy ({cpu}, {rng}); getrandom needs GRND_INSECURE",
            cpu_bits + rng_bits
        );
    }
}

/// Whether the generator was seeded with enough entropy.
pub(crate) fn seeded() -> bool {
    SEEDED.load(Ordering::Acquire)
}

/// Fills `out` from the generator.
pub(crate) fn fill(out: &mut [u8]) {
    for piece in out.chunks_mut(PIECE) {
        let mut w = [0u64; 1];
        let fresh = frame::entropy::hardware_random(&mut w).is_some_and(|(_, n)| n == 1);
        let mut g = GENERATOR.lock();
        if fresh {
            g.absorb(&w[0].to_le_bytes(), 0);
        }
        g.fill(piece);
    }
}
