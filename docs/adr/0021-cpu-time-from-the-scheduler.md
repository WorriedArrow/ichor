# ADR-0021: CPU time comes from the scheduler

- Status: Accepted
- Date: 2026-11-26
- Amends: ADR-0001 §8 (frame budget)
- Milestone: 7 (workloads), Phase E (scalability)

## Context

A Linux thread's CPU time (`CLOCK_THREAD_CPUTIME_ID`,
`CLOCK_PROCESS_CPUTIME_ID`, `getrusage`, `times`, `/proc/<pid>/stat`, and
the CPU-time timers `ITIMER_VIRTUAL`, `ITIMER_PROF` and POSIX timers on
those clocks) was measured around every trip into ring 3: the clock read
before `UserMode::execute` and again after it, the difference added to the
thread's `cpu_ns`.

That is two clock reads on every system call, page fault and interrupt
that comes back to the kernel. On KVM the clock is kvmclock (ADR-0018):
each read is about ten atomic loads and two `rdtsc`s. On GCP's Ice Lake
(n2) a null system call took 163 ns against Debian 12's 106 ns on the same
machine type (`docs/benchmarks.md`, third round); locally, without
kvmclock, the two reads and the CPU-timer check were about 8 of 100 ns.
It also counted user time only: what a thread spent in the kernel, on its
behalf, was nobody's.

Linux charges a task's run time at the scheduler: `sum_exec_runtime` is
advanced when a task is switched out (and when the clock is read for it
while it runs), so a system call pays no clock read.

## Decision

- **Frame counts each task's time on a CPU.** At every context switch
  (`schedule_inner`, interrupts off), frame reads the clock once, adds the
  outgoing task's time since it was switched in to its total, and records
  the incoming task's start. `Task::cpu_time` is the total plus, while the
  task runs, the time since its start; a sequence counter in the task
  keeps a reader on another CPU from seeing the two halfway through a
  switch, so the value never goes backward. Only the CPUs switching a task
  out and in write it, and those two never overlap (the switch-in waits for
  `finish_switch` on the other CPU).
- **A Linux thread's CPU time is its task's, since it started running the
  thread** (`ProcEntry::cpu_ns`: the task's time less what it had when
  `proc::run` began; frozen when the thread ends). The system call path
  reads no clock.
- **CPU time is user and system time together**, as Linux's CPU-time
  clocks are (`CLOCK_*_CPUTIME_ID` are `utime + stime`). `getrusage` and
  `times` report it as user time and system time as zero, since they have
  no split to give; Linux's own split is a sample taken at the tick.
  `ITIMER_PROF` is now what Linux means by it; `ITIMER_VIRTUAL` counts the
  system time too (partial, as before but the other way around).
- Interrupts count toward the task they interrupt, as on Linux without
  `IRQ_TIME_ACCOUNTING`. Time a task spends blocked is not counted: it is
  switched out.

## Alternatives considered

- **One clock read per trip instead of two** (the time between one return
  and the next): counts the time a thread sleeps in a blocking system call
  as CPU time. Rejected.
- **Raw TSC deltas instead of the clock:** two `rdtsc`s are still most of
  the cost, and a TSC delta across a migration between hosts is a little
  off the clock's rate. Rejected.
- **Tick sampling (Linux's utime/stime split):** a user/system split at the
  cost of a tick that must run while user code does, which Ichor's
  tickless timer avoids. Not needed by any workload so far.

## Consequences

- A system call, page fault or interrupt that returns to ring 3 reads no
  clock; a context switch reads it once (about 20 ns under kvmclock, on a
  switch that costs about a microsecond).
- Frame grows by the counter (`RunTime` in `Task`, `Task::cpu_time`): 47
  lines and no unsafe site, to 7,654 / 304. `audit.toml` step 18 is
  7,700 / 310, inside ADR-0007's 9,500 / 420.
