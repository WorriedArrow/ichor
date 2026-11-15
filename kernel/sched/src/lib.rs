//! Scheduling policy.
//!
//! Each CPU has a [`RunQueue`]. Runnable tasks belong to *groups* (in Ichor,
//! a group is a cell or a sub-account of one). CPU time is shared between
//! groups in proportion to their weights using weighted virtual runtime:
//! the queue always runs the non-empty group that has received the least
//! weighted time, and tasks within a group run round-robin. A group that
//! becomes runnable starts at the queue's current minimum virtual runtime,
//! so sleeping earns no burst credit (no starvation of busy groups).
//!
//! The expected call order mirrors frame's: when a task stops running it is
//! re-enqueued (if still runnable) *before* the time it used is charged.
//! [`RunQueue::pick`] marks its group as running until the matching
//! [`RunQueue::charge`], so a group never looks idle while its task runs.
//!
//! This crate is pure policy. It owns no locks and knows nothing about real
//! tasks: the kernel wraps one `RunQueue` per CPU in a lock and plugs it into
//! frame's `Scheduler` hook. Every method is O(groups) or better and never
//! panics.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};

/// Identifies a scheduling group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub u64);

/// Default weight, comparable to a Linux nice-0 task.
pub const DEFAULT_WEIGHT: u32 = 1024;

#[derive(Debug)]
struct Group<T> {
    weight: u32,
    /// Weighted nanoseconds of CPU received on this queue.
    vruntime: u64,
    /// Tasks picked but not yet charged (running now).
    running: usize,
    tasks: VecDeque<T>,
}

impl<T> Group<T> {
    fn active(&self) -> bool {
        !self.tasks.is_empty() || self.running > 0
    }
}

/// One CPU's run queue.
#[derive(Debug)]
pub struct RunQueue<T> {
    groups: BTreeMap<GroupId, Group<T>>,
    len: usize,
    /// Lower bound of the vruntime of runnable groups; never decreases.
    min_vruntime: u64,
}

impl<T> Default for RunQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> RunQueue<T> {
    pub const fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            len: 0,
            min_vruntime: 0,
        }
    }

    /// Runnable tasks on this queue.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Adds a runnable task of `group` (with `weight`, at least 1).
    pub fn enqueue(&mut self, group: GroupId, weight: u32, task: T) {
        let min = self.min_vruntime;
        let g = self.groups.entry(group).or_insert_with(|| Group {
            weight: weight.max(1),
            vruntime: min,
            running: 0,
            tasks: VecDeque::new(),
        });
        g.weight = weight.max(1);
        if !g.active() {
            // Becoming runnable: no credit for time spent asleep.
            g.vruntime = g.vruntime.max(min);
        }
        g.tasks.push_back(task);
        self.len += 1;
    }

    /// Removes the next task to run: the front task of the runnable group
    /// with the least virtual runtime.
    pub fn pick(&mut self) -> Option<(GroupId, T)> {
        let (&id, _) = self
            .groups
            .iter()
            .filter(|(_, g)| !g.tasks.is_empty())
            .min_by_key(|(id, g)| (g.vruntime, **id))?;
        let g = self.groups.get_mut(&id)?;
        let t = g.tasks.pop_front()?;
        g.running += 1;
        self.len -= 1;
        self.update_min();
        Some((id, t))
    }

    /// Charges `ns` of CPU time to `group`, ending the run started by the
    /// matching [`RunQueue::pick`].
    pub fn charge(&mut self, group: GroupId, ns: u64) {
        if let Some(g) = self.groups.get_mut(&group) {
            g.running = g.running.saturating_sub(1);
            let weighted = (u128::from(ns) * u128::from(DEFAULT_WEIGHT)) / u128::from(g.weight);
            g.vruntime = g
                .vruntime
                .saturating_add(u64::try_from(weighted).unwrap_or(u64::MAX));
        }
        self.update_min();
    }

    /// Takes a task for another CPU: from the back of the group with the
    /// most queued tasks (the least cache-hot one).
    pub fn steal(&mut self) -> Option<(GroupId, u32, T)> {
        let (&id, _) = self
            .groups
            .iter()
            .filter(|(_, g)| !g.tasks.is_empty())
            .max_by_key(|(_, g)| g.tasks.len())?;
        let g = self.groups.get_mut(&id)?;
        let t = g.tasks.pop_back()?;
        let w = g.weight;
        self.len -= 1;
        self.update_min();
        Some((id, w, t))
    }

    /// Drops bookkeeping for groups with nothing queued that have fallen
    /// behind (keeps the map small as cells come and go).
    pub fn prune(&mut self) {
        let min = self.min_vruntime;
        self.groups.retain(|_, g| g.active() || g.vruntime > min);
    }

    fn update_min(&mut self) {
        if let Some(m) = self
            .groups
            .values()
            .filter(|g| g.active())
            .map(|g| g.vruntime)
            .min()
        {
            self.min_vruntime = self.min_vruntime.max(m);
        }
    }
}

/// Picks the CPU with the fewest runnable tasks among `loads`
/// (`(cpu, load)` pairs), preferring `local` on ties.
pub fn least_loaded(loads: impl Iterator<Item = (usize, usize)>, local: usize) -> usize {
    loads
        .min_by_key(|&(cpu, load)| (load, cpu != local, cpu))
        .map_or(local, |(cpu, _)| cpu)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::HashMap;
    use std::vec::Vec;

    #[test]
    fn round_robin_within_a_group() {
        let mut q = RunQueue::new();
        for t in 0..3 {
            q.enqueue(GroupId(1), DEFAULT_WEIGHT, t);
        }
        let mut order = Vec::new();
        for _ in 0..6 {
            let (g, t) = q.pick().unwrap();
            order.push(t);
            q.enqueue(g, DEFAULT_WEIGHT, t);
            q.charge(g, 1000);
        }
        assert_eq!(order, [0, 1, 2, 0, 1, 2]);
    }

    /// Two always-runnable groups with weights 3:1 get CPU in that ratio.
    #[test]
    fn weighted_fair_share() {
        let mut q = RunQueue::new();
        q.enqueue(GroupId(1), 3 * DEFAULT_WEIGHT, 'a');
        q.enqueue(GroupId(2), DEFAULT_WEIGHT, 'b');
        let mut got: HashMap<GroupId, u64> = HashMap::new();
        for _ in 0..4000 {
            let (g, t) = q.pick().unwrap();
            *got.entry(g).or_default() += 1;
            let w = if g == GroupId(1) {
                3 * DEFAULT_WEIGHT
            } else {
                DEFAULT_WEIGHT
            };
            q.enqueue(g, w, t);
            q.charge(g, 1_000_000);
        }
        let ratio = got[&GroupId(1)] as f64 / got[&GroupId(2)] as f64;
        assert!((2.9..3.1).contains(&ratio), "ratio {ratio}");
    }

    /// A group that slept for a long time does not get a burst that
    /// starves the busy group.
    #[test]
    fn no_credit_for_sleeping() {
        let mut q = RunQueue::new();
        q.enqueue(GroupId(1), DEFAULT_WEIGHT, 1);
        for _ in 0..1000 {
            let (g, t) = q.pick().unwrap();
            q.enqueue(g, DEFAULT_WEIGHT, t);
            q.charge(g, 1_000_000);
        }
        q.enqueue(GroupId(2), DEFAULT_WEIGHT, 2);
        let mut b_streak = 0;
        let mut max_streak = 0;
        for _ in 0..100 {
            let (g, t) = q.pick().unwrap();
            if g == GroupId(2) {
                b_streak += 1;
                max_streak = max_streak.max(b_streak);
            } else {
                b_streak = 0;
            }
            q.enqueue(g, DEFAULT_WEIGHT, t);
            q.charge(g, 1_000_000);
        }
        assert!(max_streak <= 2, "sleeper ran {max_streak} times in a row");
    }

    /// A task that blocks (is not re-enqueued) leaves its group idle; when
    /// it wakes, the group restarts at the queue minimum.
    #[test]
    fn blocked_group_restarts_at_minimum() {
        let mut q = RunQueue::new();
        q.enqueue(GroupId(1), DEFAULT_WEIGHT, 1);
        q.enqueue(GroupId(2), DEFAULT_WEIGHT, 2);
        let (g, _) = q.pick().unwrap();
        q.charge(g, 10); // blocked: not re-enqueued
        for _ in 0..50 {
            let (g2, t) = q.pick().unwrap();
            q.enqueue(g2, DEFAULT_WEIGHT, t);
            q.charge(g2, 1_000_000);
        }
        q.enqueue(g, DEFAULT_WEIGHT, 1);
        // The woken group runs soon but cannot monopolise the CPU.
        let picks: Vec<GroupId> = (0..6)
            .map(|_| {
                let (g, t) = q.pick().unwrap();
                q.enqueue(g, DEFAULT_WEIGHT, t);
                q.charge(g, 1_000_000);
                g
            })
            .collect();
        assert!(
            picks.contains(&GroupId(1)) && picks.contains(&GroupId(2)),
            "{picks:?}"
        );
    }

    #[test]
    fn steal_and_len() {
        let mut q = RunQueue::new();
        assert!(q.pick().is_none() && q.steal().is_none() && q.is_empty());
        for t in 0..4 {
            q.enqueue(GroupId(t % 2), DEFAULT_WEIGHT, t);
        }
        assert_eq!(q.len(), 4);
        let (_, w, _) = q.steal().unwrap();
        assert_eq!(w, DEFAULT_WEIGHT);
        assert_eq!(q.len(), 3);
        while q.pick().is_some() {}
        assert!(q.is_empty());
        q.prune();
    }

    #[test]
    fn least_loaded_prefers_local_on_ties() {
        assert_eq!(least_loaded([(0, 2), (1, 1), (2, 1)].into_iter(), 2), 2);
        assert_eq!(least_loaded([(0, 0), (1, 1)].into_iter(), 1), 0);
        assert_eq!(least_loaded(core::iter::empty(), 5), 5);
    }

    #[test]
    fn extreme_weights_and_charges_do_not_panic() {
        let mut q = RunQueue::new();
        q.enqueue(GroupId(1), 0, 1);
        q.enqueue(GroupId(2), u32::MAX, 2);
        q.charge(GroupId(1), u64::MAX);
        q.charge(GroupId(2), u64::MAX);
        q.charge(GroupId(3), 5);
        assert!(q.pick().is_some());
        assert!(q.pick().is_some());
        assert!(q.pick().is_none());
    }
}
