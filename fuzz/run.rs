//! Runs every fuzz target: briefly by default (CI), or as long as
//! `ICHOR_FUZZ_ITERATIONS` says. `ICHOR_FUZZ_TARGET` picks one target,
//! `ICHOR_FUZZ_SEED` the mutator's seed, and `ICHOR_FUZZ_REPLAY` a saved
//! input to run once instead.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn every_parser_survives_mutated_input() {
    let iterations: u64 = std::env::var("ICHOR_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let seed: u64 = std::env::var("ICHOR_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x1c40);
    let only = std::env::var("ICHOR_FUZZ_TARGET").ok();
    let targets: Vec<_> = fuzz::TARGETS
        .iter()
        .filter(|t| only.as_deref().is_none_or(|o| o == t.name))
        .collect();
    assert!(!targets.is_empty(), "no target named {only:?}");
    if let Ok(path) = std::env::var("ICHOR_FUZZ_REPLAY") {
        let input = std::fs::read(&path).unwrap();
        for t in &targets {
            fuzz::replay(t, &input);
        }
        return;
    }
    // Panics are caught and reported with their input, not printed twice.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|info| eprintln!("fuzz: {info}")));
    let mut failures = Vec::new();
    for t in targets {
        let t0 = std::time::Instant::now();
        match fuzz::fuzz(t, iterations, seed) {
            Ok(()) => eprintln!(
                "fuzz: {}: {iterations} inputs in {:?}",
                t.name,
                t0.elapsed()
            ),
            Err(e) => failures.push(e),
        }
    }
    std::panic::set_hook(hook);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The harness itself: a target that panics on some inputs is caught,
/// reported, and its input saved.
#[test]
fn a_panicking_target_is_reported() {
    fn seeds() -> Vec<Vec<u8>> {
        vec![b"fine".to_vec()]
    }
    fn run(input: &[u8]) {
        // Panics once a mutation puts a 0xff anywhere.
        assert!(!input.contains(&0xff), "found 0xff");
    }
    let t = fuzz::Target {
        name: "self-check",
        seeds,
        run,
    };
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = fuzz::fuzz(&t, 20_000, 1);
    std::panic::set_hook(hook);
    let e = r.expect_err("the harness missed a panic");
    assert!(e.contains("panicked"), "{e}");
    let path = e.rsplit("saved to ").next().unwrap();
    assert!(std::fs::read(path).unwrap().contains(&0xff));
}
