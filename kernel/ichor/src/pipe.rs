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
    /// waking opens waiting for it.
    pub(crate) fn add_end(&self, write: bool) {
        {
            let mut s = self.state.lock();
            if write {
                s.writers += 1;
                s.writer_opens += 1;
            } else {
                s.readers += 1;
                s.reader_opens += 1;
            }
        }
        self.readable.wake_all();
        self.writable.wake_all();
        self.changed();
    }

    /// Readers now (a FIFO's non-blocking open for writing needs one).
    pub(crate) fn readers(&self) -> u32 {
        self.state.lock().readers
    }

    /// Blocks a FIFO's open of one end until the other end is open, or has
    /// been opened since this call began.
    pub(crate) fn wait_peer(&self, write: bool, interrupted: &dyn Fn() -> bool) -> Result<(), i64> {
        let opens = |s: &State| {
            if write {
                s.reader_opens
            } else {
                s.writer_opens
            }
        };
        let start = opens(&self.state.lock());
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
            } else if CAPACITY - s.buf.len() >= PIPE_BUF {
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

    /// Reads up to `out.len()` bytes, blocking until some data is available
    /// or every writer is gone (then 0, end of file).
    pub(crate) fn read(
        &self,
        out: &mut [u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        if out.is_empty() {
            return Ok(0);
        }
        let r = self.readable.wait_until(|| {
            let mut s = self.state.lock();
            if !s.buf.is_empty() {
                let n = out.len().min(s.buf.len());
                for (o, b) in out.iter_mut().zip(s.buf.drain(..n)) {
                    *o = b;
                }
                Some(Ok(n))
            } else if s.writers == 0 {
                Some(Ok(0))
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
                let room = CAPACITY - s.buf.len();
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
