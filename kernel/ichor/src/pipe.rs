//! Pipes: a bounded byte queue between descriptors, with blocking reads and
//! writes on frame wait queues.
//!
//! Every open file description of an end counts as one reader or writer
//! (descriptors made by `dup` or `fork` share it; the count drops when the
//! description's last descriptor closes), which is how a reader
//! sees end-of-file once the last writer is gone, and a writer gets `EPIPE`
//! once the last reader is gone. Writes of up to `PIPE_BUF` bytes are
//! atomic, as POSIX requires; longer blocking writes complete in pieces.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use frame::sync::SpinLock;
use frame::task::WaitQueue;

const EAGAIN: i64 = 11;
const EPIPE: i64 = 32;
use crate::signal::ERESTARTSYS;

/// Bytes a pipe buffers (Linux's default).
const CAPACITY: usize = 64 * 1024;
/// Writes up to this size are never interleaved with other writers.
const PIPE_BUF: usize = 4096;

#[derive(Debug)]
struct State {
    buf: VecDeque<u8>,
    readers: u32,
    writers: u32,
    /// Opens of each end so far (a FIFO's blocking open waits for the other
    /// end to be opened, even if it is closed again before the waiter runs).
    reader_opens: u64,
    writer_opens: u64,
    /// Bytes the pipe holds (`F_SETPIPE_SZ`; CAPACITY to start).
    capacity: usize,
}

/// A pipe.
#[derive(Debug)]
pub(crate) struct Pipe {
    state: SpinLock<State>,
    /// Waiters for data (or for the last writer to leave).
    readable: WaitQueue,
    /// Waiters for space (or for the last reader to leave).
    writable: WaitQueue,
    /// State changes so far (edge-triggered epoll).
    changes: core::sync::atomic::AtomicU64,
    /// Tasks polling either end.
    watchers: crate::poll::Watchers,
}

impl Pipe {
    /// A new pipe with one reader and one writer reference.
    pub(crate) fn new() -> Arc<Pipe> {
        Self::with_ends(1)
    }

    /// A named pipe's pipe: no ends until the FIFO is opened
    /// ([`Pipe::add_end`]).
    pub(crate) fn new_fifo() -> Arc<Pipe> {
        Self::with_ends(0)
    }

    fn with_ends(n: u32) -> Arc<Pipe> {
        Arc::new(Pipe {
            state: SpinLock::new(State {
                buf: VecDeque::new(),
                readers: n,
                writers: n,
                reader_opens: u64::from(n),
                writer_opens: u64::from(n),
                capacity: CAPACITY,
            }),
            readable: WaitQueue::new(),
            writable: WaitQueue::new(),
            changes: core::sync::atomic::AtomicU64::new(0),
            watchers: crate::poll::Watchers::new(),
        })
    }

    /// The tasks polling this pipe.
    pub(crate) fn watchers(&self) -> &crate::poll::Watchers {
        &self.watchers
    }

    /// Adds a reference to one end (a FIFO opened for reading or writing),
    /// waking opens waiting for it. Returns how often the other end had
    /// been opened, for [`Pipe::wait_peer`]: counted in the same step,
    /// because the peer this wakes may open, write and close before the
    /// caller gets to wait.
    pub(crate) fn add_end(&self, write: bool) -> u64 {
        let peer_opens = {
            let mut s = self.state.lock();
            if write {
                s.writers += 1;
                s.writer_opens += 1;
                s.reader_opens
            } else {
                s.readers += 1;
                s.reader_opens += 1;
                s.writer_opens
            }
        };
        self.readable.wake_all();
        self.writable.wake_all();
        self.changed();
        peer_opens
    }

    /// `F_GETPIPE_SZ`: the bytes the pipe holds.
    pub(crate) fn capacity(&self) -> usize {
        self.state.lock().capacity
    }

    /// `F_SETPIPE_SZ`: rounds `size` up to a power-of-two number of pages
    /// (at least one) and makes that the capacity, as Linux does; above
    /// Linux's default `pipe-max-size` (1 MiB) is EPERM, and less than what
    /// is buffered now is EBUSY. Returns the new capacity.
    pub(crate) fn set_capacity(&self, size: u64) -> Result<usize, i64> {
        const EPERM: i64 = 1;
        const EBUSY: i64 = 16;
        const MAX: usize = 1 << 20;
        let want = usize::try_from(size).map_err(|_| EPERM)?;
        if want > MAX {
            return Err(EPERM);
        }
        let n = want.max(4096).next_power_of_two();
        let mut s = self.state.lock();
        if n < s.buf.len() {
            return Err(EBUSY);
        }
        s.capacity = n;
        drop(s);
        self.writable.wake_all();
        self.changed();
        Ok(n)
    }

    /// Readers now (a FIFO's non-blocking open for writing needs one).
    pub(crate) fn readers(&self) -> u32 {
        self.state.lock().readers
    }

    /// Blocks a FIFO's open of one end until the other end is open, or has
    /// been opened more than `start` times (what [`Pipe::add_end`] gave).
    pub(crate) fn wait_peer(
        &self,
        write: bool,
        start: u64,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<(), i64> {
        let opens = |s: &State| {
            if write {
                s.reader_opens
            } else {
                s.writer_opens
            }
        };
        let q = if write {
            &self.writable
        } else {
            &self.readable
        };
        q.wait_until(|| {
            let s = self.state.lock();
            let peers = if write { s.readers } else { s.writers };
            if peers > 0 || opens(&s) != start {
                Some(Ok(()))
            } else if interrupted() {
                Some(Err(ERESTARTSYS))
            } else {
                None
            }
        })
    }

    /// Drops a reference to one end, waking the other side so it sees EOF
    /// or `EPIPE`.
    pub(crate) fn drop_end(&self, write: bool) {
        {
            let mut s = self.state.lock();
            if write {
                s.writers = s.writers.saturating_sub(1);
            } else {
                s.readers = s.readers.saturating_sub(1);
            }
        }
        self.readable.wake_all();
        self.writable.wake_all();
        self.changed();
    }

    /// State changes so far (data in or out, an end closed).
    pub(crate) fn changes(&self) -> u64 {
        self.changes.load(core::sync::atomic::Ordering::Acquire)
    }

    fn changed(&self) {
        self.changes
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        self.watchers.notify();
    }

    /// Readiness of the read end (`write` false) or write end, as `poll`
    /// reports it.
    pub(crate) fn poll(&self, write: bool) -> u16 {
        use crate::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT};
        let s = self.state.lock();
        if write {
            if s.readers == 0 {
                POLLERR
            } else if s.capacity.saturating_sub(s.buf.len()) >= PIPE_BUF.min(s.capacity) {
                POLLOUT
            } else {
                0
            }
        } else {
            let mut r = 0;
            if !s.buf.is_empty() {
                r |= POLLIN;
            }
            if s.writers == 0 {
                r |= POLLHUP;
            }
            r
        }
    }

    /// Reads up to `out.len()` bytes (see [`Pipe::take`]).
    pub(crate) fn read(
        &self,
        out: &mut [u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        let got = self.take(out.len(), nonblock, interrupted)?;
        out[..got.len()].copy_from_slice(&got);
        Ok(got.len())
    }

    /// Takes up to `max` bytes out, blocking until some data is available
    /// or every writer is gone (then nothing, end of file).
    pub(crate) fn take(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        if max == 0 {
            return Ok(Vec::new());
        }
        let r = self.readable.wait_until(|| {
            let mut s = self.state.lock();
            if !s.buf.is_empty() {
                let n = max.min(s.buf.len());
                Some(Ok(s.buf.drain(..n).collect()))
            } else if s.writers == 0 {
                Some(Ok(Vec::new()))
            } else if nonblock {
                Some(Err(EAGAIN))
            } else if interrupted() {
                Some(Err(ERESTARTSYS))
            } else {
                None
            }
        });
        self.writable.wake_all();
        self.changed();
        r
    }

    /// Bytes waiting to be read.
    pub(crate) fn buffered(&self) -> usize {
        self.state.lock().buf.len()
    }

    /// Puts back, in front, bytes [`Pipe::take`] gave that could not be
    /// passed on (`splice` to a socket that took only part). Another reader
    /// may have come in between: it then read later bytes first.
    pub(crate) fn give_back(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        {
            let mut s = self.state.lock();
            for &b in data.iter().rev() {
                s.buf.push_front(b);
            }
        }
        self.readable.wake_all();
        self.changed();
    }

    /// A copy of up to `max` bytes, left where they are (`tee`): blocking
    /// as [`Pipe::take`].
    pub(crate) fn peek(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        self.readable.wait_until(|| {
            let s = self.state.lock();
            if !s.buf.is_empty() {
                Some(Ok(s.buf.iter().take(max).copied().collect()))
            } else if s.writers == 0 {
                Some(Ok(Vec::new()))
            } else if nonblock {
                Some(Err(EAGAIN))
            } else if interrupted() {
                Some(Err(ERESTARTSYS))
            } else {
                None
            }
        })
    }

    /// Waits until the pipe has room, and says how much: EPIPE once no
    /// reader is left.
    pub(crate) fn room(
        &self,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        self.writable.wait_until(|| {
            let s = self.state.lock();
            if s.readers == 0 {
                return Some(Err(EPIPE));
            }
            match s.capacity.saturating_sub(s.buf.len()) {
                0 if nonblock => Some(Err(EAGAIN)),
                0 if interrupted() => Some(Err(ERESTARTSYS)),
                0 => None,
                n => Some(Ok(n)),
            }
        })
    }

    /// Writes all of `data` (blocking while the pipe is full), or fails
    /// with `EPIPE` once no reader is left. Returns the bytes written.
    pub(crate) fn write(
        &self,
        data: &[u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        let mut done = 0;
        while done < data.len() {
            let rest = &data[done..];
            // Small writes go in whole or not at all.
            let need = if rest.len() <= PIPE_BUF {
                rest.len()
            } else {
                1
            };
            let r = self.writable.wait_until(|| {
                let mut s = self.state.lock();
                if s.readers == 0 {
                    return Some(Err(EPIPE));
                }
                let room = s.capacity.saturating_sub(s.buf.len());
                if room >= need {
                    let n = room.min(rest.len());
                    s.buf.extend(&rest[..n]);
                    Some(Ok(n))
                } else if nonblock {
                    Some(Err(EAGAIN))
                } else if interrupted() {
                    Some(Err(ERESTARTSYS))
                } else {
                    None
                }
            });
            self.readable.wake_all();
            self.changed();
            match r {
                Ok(n) => done += n,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(done)
    }
}

/// Named pipes' pipes, by FIFO id (`Overlay::fifo_id`, never reused). A
/// FIFO's pipe lives while any end of it is open; opened again after that,
/// it starts empty, as on Linux.
static FIFOS: SpinLock<BTreeMap<u64, Weak<Pipe>>> = SpinLock::new(BTreeMap::new());

/// A blocking FIFO open whose peer opens and closes again before the wait
/// begins returns at once (it used to wait forever).
pub(crate) fn fifo_selftest() {
    for write in [false, true] {
        let p = Pipe::new_fifo();
        let opens = p.add_end(write);
        p.add_end(!write);
        p.drop_end(!write);
        // "Interrupted" at once: a wait that would block fails instead.
        if p.wait_peer(write, opens, &|| true) != Ok(()) {
            crate::runtest::fail("pipe: a FIFO open missed a peer that came and went");
        }
        // With no peer at all it does wait.
        let lone = Pipe::new_fifo();
        let opens = lone.add_end(write);
        if lone.wait_peer(write, opens, &|| true) != Err(ERESTARTSYS) {
            crate::runtest::fail("pipe: a FIFO open did not wait for its peer");
        }
    }
}

/// The pipe behind FIFO `id`, made on its first open.
pub(crate) fn fifo(id: u64) -> Arc<Pipe> {
    let mut m = FIFOS.lock();
    if let Some(p) = m.get(&id).and_then(Weak::upgrade) {
        return p;
    }
    m.retain(|_, w| w.strong_count() > 0);
    let p = Pipe::new_fifo();
    m.insert(id, Arc::downgrade(&p));
    p
}
