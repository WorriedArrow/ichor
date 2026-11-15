//! Pipes: a bounded byte queue between descriptors, with blocking reads and
//! writes on frame wait queues.
//!
//! Every descriptor that refers to an end counts as one reader or writer
//! (`dup`, `fork` and `close` adjust the counts), which is how a reader
//! sees end-of-file once the last writer is gone, and a writer gets `EPIPE`
//! once the last reader is gone. Writes of up to `PIPE_BUF` bytes are
//! atomic, as POSIX requires; longer blocking writes complete in pieces.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

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
}

/// A pipe.
#[derive(Debug)]
pub(crate) struct Pipe {
    state: SpinLock<State>,
    /// Waiters for data (or for the last writer to leave).
    readable: WaitQueue,
    /// Waiters for space (or for the last reader to leave).
    writable: WaitQueue,
}

impl Pipe {
    /// A new pipe with one reader and one writer reference.
    pub(crate) fn new() -> Arc<Pipe> {
        Arc::new(Pipe {
            state: SpinLock::new(State {
                buf: VecDeque::new(),
                readers: 1,
                writers: 1,
            }),
            readable: WaitQueue::new(),
            writable: WaitQueue::new(),
        })
    }

    /// Adds a reference to one end (a `dup` or `fork` of a descriptor).
    pub(crate) fn add(&self, write: bool) {
        let mut s = self.state.lock();
        if write {
            s.writers += 1;
        } else {
            s.readers += 1;
        }
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
        crate::poll::notify();
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
        crate::poll::notify();
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
            crate::poll::notify();
            match r {
                Ok(n) => done += n,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(done)
    }
}
