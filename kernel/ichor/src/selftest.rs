//! Boot-time self-tests. Each prints a marker line that `tests/boot.rs`
//! looks for; a failure stops the machine with a failure status.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use core::time::Duration;

use frame::cpu::{self, IrqGuard};
use frame::power::{ExitStatus, shutdown};
use frame::println;
use frame::task::{TaskOptions, WaitQueue};

fn fail(what: &str) -> ! {
    println!("ichor: selftest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

/// Many small objects of every size class, a large block, and frees that
/// must return all memory.
pub(crate) fn heap() {
    let before = frame::mm::stats();
    {
        let mut v: Vec<u64> = Vec::new();
        for i in 0..100_000 {
            v.push(i);
        }
        let sum: u64 = v.iter().sum();
        let mut map = BTreeMap::new();
        for i in 0..2_000u32 {
            map.insert(i, Box::new([i; 7]));
        }
        let boxes: Vec<Box<[u8]>> = (1..300)
            .map(|n| alloc::vec![n as u8; n * 7].into_boxed_slice())
            .collect();
        let big = alloc::vec![0xA5u8; 3 << 20];
        let ok = sum == 4_999_950_000
            && map.get(&1234).is_some_and(|b| b[6] == 1234)
            && boxes
                .iter()
                .enumerate()
                .all(|(i, b)| b.len() == (i + 1) * 7 && b[0] == (i + 1) as u8)
            && big.iter().all(|&b| b == 0xA5);
        if !ok {
            fail("heap contents corrupted");
        }
        println!("ichor: heap: selftest passed");
    }
    let after = frame::mm::stats();
    println!(
        "ichor: heap: {} MiB managed, {} MiB free ({} pages not returned)",
        after.total_pages / 256,
        after.free_pages / 256,
        before.free_pages.saturating_sub(after.free_pages),
    );
}

pub(crate) fn breakpoint() {
    frame::debug::breakpoint();
    println!(
        "ichor: trap: breakpoint handled ({} so far)",
        frame::debug::breakpoint_count()
    );
}

frame::cpu_local! {
    static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);
}

/// Timer interrupts each CPU takes during the timer self-test.
const TICKS_WANTED: u64 = 5;

frame::cpu_local! {
    /// This CPU has seen its ticks: no more needed.
    static TICKS_SEEN: AtomicBool = AtomicBool::new(false);
}

/// Keeps ticking until the waiter has seen enough: one that stopped at the
/// last tick wanted could be that tick arriving between the waiter's check
/// and its halt, which then nothing would end.
fn on_timer() {
    let guard = IrqGuard::new();
    TIMER_TICKS.get(&guard).fetch_add(1, Relaxed);
    if !TICKS_SEEN.get(&guard).load(Relaxed) {
        frame::time::arm_timer(Duration::from_millis(2));
    }
}

/// Arms this CPU's timer and sleeps until it has fired `TICKS_WANTED` times.
pub(crate) fn wait_for_ticks() {
    frame::time::arm_timer(Duration::from_millis(2));
    loop {
        let done = {
            let guard = IrqGuard::new();
            let done = TIMER_TICKS.get(&guard).load(Relaxed) >= TICKS_WANTED;
            TICKS_SEEN.get(&guard).store(done, Relaxed);
            done
        };
        if done {
            break;
        }
        frame::irq::enable_and_wait();
    }
}

/// Installs the timer self-test's handler. Call before starting the APs,
/// which run `wait_for_ticks` straight away.
pub(crate) fn install_timer_handler() {
    frame::time::set_timer_handler(on_timer);
}

/// Every CPU (the APs run `wait_for_ticks` from `ap_main`) takes timer
/// interrupts.
pub(crate) fn timers_on_every_cpu(cpus: usize) {
    wait_for_ticks();
    let deadline = frame::time::now() + Duration::from_secs(5);
    let all_ticked = || {
        TIMER_TICKS
            .iter()
            .all(|(_, t)| t.load(Relaxed) >= TICKS_WANTED)
    };
    while !all_ticked() && frame::time::now() < deadline {
        core::hint::spin_loop();
    }
    if !all_ticked() {
        for (cpu, t) in TIMER_TICKS.iter() {
            println!("ichor: smp: {cpu:?}: {} timer interrupts", t.load(Relaxed));
        }
        fail("not every CPU took timer interrupts");
    }
    println!("ichor: smp: {cpus} CPUs online, every CPU took {TICKS_WANTED} timer interrupts");
}

/// Waits (yielding, so other tasks run) until `cond` holds or `timeout`.
fn yield_until(timeout: Duration, cond: impl Fn() -> bool) -> bool {
    let deadline = frame::time::now() + timeout;
    while !cond() {
        if frame::time::now() >= deadline {
            return false;
        }
        frame::task::yield_now();
    }
    true
}

/// Kernel threads that cooperate: many tasks yielding repeatedly, spread
/// over the CPUs, with the main task blocked on a wait queue until the last
/// one finishes.
pub(crate) fn threads() {
    const N: usize = 32;
    static DONE: AtomicUsize = AtomicUsize::new(0);
    static CPUS_SEEN: AtomicU64 = AtomicU64::new(0);
    static ALL_DONE: WaitQueue = WaitQueue::new();

    for i in 0..N {
        let spawned = TaskOptions::new(move || {
            let mut x = i as u64;
            for _ in 0..50 {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                CPUS_SEEN.fetch_or(1 << (cpu::current().index() % 64), Relaxed);
                frame::task::yield_now();
            }
            core::hint::black_box(x);
            if DONE.fetch_add(1, Relaxed) + 1 == N {
                ALL_DONE.wake_all();
            }
        })
        .spawn();
        if spawned.is_none() {
            fail("could not spawn a kernel thread");
        }
    }
    ALL_DONE.wait_until(|| (DONE.load(Relaxed) == N).then_some(()));
    println!(
        "ichor: sched: {N} threads finished (seen on {} of {} CPUs)",
        CPUS_SEEN.load(Relaxed).count_ones(),
        cpu::online_count()
    );
}

/// Timed waits: threads sleeping to staggered deadlines each wake after
/// their deadline and not much later, and a wait whose condition comes
/// true wakes early instead of timing out.
pub(crate) fn timed_waits() {
    const N: usize = 4;
    static DONE: AtomicUsize = AtomicUsize::new(0);
    static LATE: AtomicU64 = AtomicU64::new(0);
    static EARLY: AtomicUsize = AtomicUsize::new(0);
    static ALL_DONE: WaitQueue = WaitQueue::new();
    let start = frame::time::now();
    for i in 0..N {
        let deadline = start + Duration::from_millis(20 * (i as u64 + 1));
        let spawned = TaskOptions::new(move || {
            frame::task::sleep_until(deadline);
            let woke = frame::time::now();
            if woke < deadline {
                EARLY.fetch_add(1, Relaxed);
            }
            let late = (woke - deadline.min(woke)).as_millis() as u64;
            LATE.fetch_max(late, Relaxed);
            if DONE.fetch_add(1, Relaxed) + 1 == N {
                ALL_DONE.wake_all();
            }
        })
        .spawn();
        if spawned.is_none() {
            fail("could not spawn a sleeper");
        }
    }
    // Wakes when the last sleeper finishes, long before this deadline.
    let timeout = start + Duration::from_secs(10);
    let finished =
        ALL_DONE.wait_until_deadline(timeout, || (DONE.load(Relaxed) == N).then_some(()));
    if finished.is_none() || EARLY.load(Relaxed) != 0 {
        fail("timed waits: a sleeper woke early or never");
    }
    // A wait that times out returns None at about its deadline.
    let q = WaitQueue::new();
    let t0 = frame::time::now();
    let r = q.wait_until_deadline(t0 + Duration::from_millis(15), || None::<()>);
    let waited = frame::time::now() - t0;
    if r.is_some() || waited < Duration::from_millis(15) {
        fail("timed waits: timeout returned early");
    }
    println!(
        "ichor: sleep: {N} timed waits woke after their deadlines (worst {} ms late), timeout ok",
        LATE.load(Relaxed)
    );
}

/// Preemption: more never-yielding spinners than CPUs must all make
/// progress, and the main task (which competes with them) must still get
/// to run and stop them.
pub(crate) fn preemption() {
    const MAX: usize = 64;
    static STOP: AtomicBool = AtomicBool::new(false);
    static PROGRESS: [AtomicU64; MAX] = [const { AtomicU64::new(0) }; MAX];
    static FINISHED: AtomicUsize = AtomicUsize::new(0);

    let n = (cpu::online_count() * 2 + 1).min(MAX);
    for slot in PROGRESS.iter().take(n) {
        let spawned = TaskOptions::new(move || {
            while !STOP.load(Relaxed) {
                slot.fetch_add(1, Relaxed);
                core::hint::spin_loop();
            }
            FINISHED.fetch_add(1, Relaxed);
        })
        .spawn();
        if spawned.is_none() {
            fail("could not spawn a spinner");
        }
    }
    let started = frame::time::now();
    let all_progressed = || PROGRESS.iter().take(n).all(|p| p.load(Relaxed) > 0);
    let progressed = yield_until(Duration::from_secs(10), all_progressed);
    yield_until(Duration::from_millis(100), || false);
    if !progressed {
        dump_sched();
        for (i, p) in PROGRESS.iter().take(n).enumerate() {
            println!("ichor: sched: spinner {i}: {}", p.load(Relaxed));
        }
        fail("a spinner never ran: no preemption");
    }
    STOP.store(true, Relaxed);
    if !yield_until(Duration::from_secs(10), || FINISHED.load(Relaxed) == n) {
        fail("spinners did not stop");
    }
    println!(
        "ichor: sched: {n} spinners on {} CPUs all ran (preemption works, {} ms)",
        cpu::online_count(),
        (frame::time::now() - started).as_millis()
    );
}

fn dump_sched() {
    for c in cpu::online() {
        let s = frame::task::snapshot(c);
        println!(
            "ichor: sched: {c:?}: current {:?} {:?}{} need_resched {} queued {} ticks {} preemptions {} deadlines {:?}",
            s.current,
            s.current_state,
            if s.current_is_idle { " (idle)" } else { "" },
            s.need_resched,
            crate::sched::queue_len(c),
            s.ticks,
            s.preemptions,
            frame::time::deadlines(c),
        );
    }
}

/// Recurses until the stack overflows into its guard page.
pub(crate) fn stack_overflow() -> ! {
    println!("ichor: overflowing the kernel stack");
    let r = recurse(0);
    println!("unreachable: {r}");
    fail("stack overflow was not caught")
}

#[allow(unconditional_recursion)]
fn recurse(n: u64) -> u64 {
    let frame = core::hint::black_box([n; 32]);
    recurse(frame[0] + 1).wrapping_add(frame[31])
}

/// Runs the ring-3 self-test on its own kernel thread (entering ring 3 sets
/// that thread's RSP0, so it must not be the adopted main task).
pub(crate) fn user_mode() {
    use core::sync::atomic::{AtomicBool, Ordering::Relaxed};
    static DONE: AtomicBool = AtomicBool::new(false);
    static GATE: WaitQueue = WaitQueue::new();
    let spawned = TaskOptions::new(|| {
        crate::usertest::run();
        DONE.store(true, Relaxed);
        GATE.wake_all();
    })
    .spawn();
    if spawned.is_none() {
        fail("could not spawn the user-mode test thread");
    }
    GATE.wait_until(|| DONE.load(Relaxed).then_some(()));
}
