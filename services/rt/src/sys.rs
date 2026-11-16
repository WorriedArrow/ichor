//! Safe wrappers over the native ABI (`docs/abi/native.md`). Buffers are
//! slices, so the kernel reads and writes only memory the caller lent it;
//! handles close when dropped.

use alloc::vec::Vec;
use core::arch::asm;

use ichor_abi::{CLOCK_MONOTONIC, CLOCK_REALTIME, sys};
pub use ichor_abi::{Error, FAILED, HANGUP, READABLE, WRITABLE, WaitItem};

/// A native call's result.
pub type Result<T> = core::result::Result<T, Error>;

/// Makes native call `nr` with `args`.
///
/// # Safety
///
/// The kernel may read or write memory at addresses among `args`, as the
/// call's documentation says: each such buffer must be valid for that
/// access for its stated length (and not otherwise borrowed).
unsafe fn syscall(nr: u64, args: [u64; 5]) -> u64 {
    let ret;
    // SAFETY: `syscall` enters the kernel, which reads only these
    // registers, clobbers `rcx` and `r11`, and returns to the next
    // instruction; memory it touches is the caller's to lend (see above).
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// A call that lends the kernel no memory.
fn call(nr: u64, args: [u64; 5]) -> Result<u64> {
    // SAFETY: none of `args` is a buffer for this call.
    decode(unsafe { syscall(nr, args) })
}

fn decode(rax: u64) -> Result<u64> {
    ichor_abi::decode(rax).map_err(|c| Error::from_code(c).unwrap_or(Error::Failed))
}

/// A capability handle in this process's cell; dropping it closes it.
#[derive(Debug)]
pub struct Handle(u64);

impl Handle {
    /// A handle by its raw value (passed in arguments, say). A wrong
    /// value only fails to resolve.
    pub fn from_raw(raw: u64) -> Handle {
        Handle(raw)
    }

    pub fn raw(&self) -> u64 {
        self.0
    }

    /// A second handle to the same object with `rights` (a subset).
    pub fn dup(&self, rights: u32) -> Result<Handle> {
        call(sys::HANDLE_DUP, [self.0, u64::from(rights), 0, 0, 0]).map(Handle)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = call(sys::HANDLE_CLOSE, [self.0, 0, 0, 0, 0]);
    }
}

/// Ends the process.
pub fn exit(code: u64) -> ! {
    let _ = call(sys::EXIT, [code, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

/// Writes one line to the console, tagged with the cell.
pub fn log(s: &str) {
    // SAFETY: the kernel reads `s.len()` bytes at `s`.
    let _ = unsafe { syscall(sys::LOG, [s.as_ptr() as u64, s.len() as u64, 0, 0, 0]) };
}

/// Nanoseconds since boot.
pub fn monotonic() -> u64 {
    call(sys::CLOCK, [CLOCK_MONOTONIC, 0, 0, 0, 0]).unwrap_or(0)
}

/// Nanoseconds since the Unix epoch.
pub fn realtime() -> u64 {
    call(sys::CLOCK, [CLOCK_REALTIME, 0, 0, 0, 0]).unwrap_or(0)
}

/// Fills `buf` from the kernel's CSPRNG.
pub fn random(buf: &mut [u8]) {
    for part in buf.chunks_mut(64 * 1024) {
        // SAFETY: the kernel writes `part.len()` bytes at `part`.
        let _ = unsafe {
            syscall(
                sys::RANDOM,
                [part.as_mut_ptr() as u64, part.len() as u64, 0, 0, 0],
            )
        };
    }
}

/// Maps `len` bytes of zeroed memory (the heap's source).
pub(crate) fn mem_map(len: usize) -> Result<*mut u8> {
    call(sys::MEM_MAP, [len as u64, 0, 0, 0, 0]).map(|a| a as *mut u8)
}

/// Unmaps memory from [`mem_map`].
pub(crate) fn mem_unmap(ptr: *mut u8, len: usize) {
    let _ = call(sys::MEM_UNMAP, [ptr as u64, len as u64, 0, 0, 0]);
}

/// Waits until one of `items` is ready or `timeout_ns` passes
/// (`u64::MAX`: no limit); sets each item's `revents` and returns how many
/// are ready.
pub fn wait(items: &mut [WaitItem], timeout_ns: u64) -> Result<usize> {
    let mut raw: Vec<u8> = items.iter().flat_map(|w| w.to_bytes()).collect();
    // SAFETY: the kernel reads and writes `items.len()` 16-byte entries at
    // `raw`, which holds exactly that many.
    let r = decode(unsafe {
        syscall(
            sys::OBJECT_WAIT,
            [
                raw.as_mut_ptr() as u64,
                items.len() as u64,
                timeout_ns,
                0,
                0,
            ],
        )
    })?;
    for (w, c) in items.iter_mut().zip(raw.as_chunks::<16>().0) {
        *w = WaitItem::from_bytes(c);
    }
    Ok(r as usize)
}

fn ip(a: [u8; 4]) -> u64 {
    u64::from(u32::from_be_bytes(a))
}

/// Starts a TCP connection; it is writable once [`sock_error`] knows.
pub fn tcp_connect(addr: [u8; 4], port: u16) -> Result<Handle> {
    call(sys::TCP_CONNECT, [ip(addr), u64::from(port), 0, 0, 0]).map(Handle)
}

pub fn tcp_listen(port: u16, backlog: usize) -> Result<Handle> {
    call(sys::TCP_LISTEN, [u64::from(port), backlog as u64, 0, 0, 0]).map(Handle)
}

pub fn tcp_accept(listener: &Handle) -> Result<Handle> {
    call(sys::TCP_ACCEPT, [listener.0, 0, 0, 0, 0]).map(Handle)
}

/// A connecting socket's outcome (`WouldBlock` while connecting).
pub fn sock_error(s: &Handle) -> Result<()> {
    call(sys::SOCK_ERROR, [s.0, 0, 0, 0, 0]).map(|_| ())
}

pub fn send(s: &Handle, data: &[u8]) -> Result<usize> {
    // SAFETY: the kernel reads `data.len()` bytes at `data`.
    decode(unsafe {
        syscall(
            sys::SOCK_SEND,
            [s.0, data.as_ptr() as u64, data.len() as u64, 0, 0],
        )
    })
    .map(|n| n as usize)
}

/// Receives into `buf`; 0 is the end of the stream.
pub fn recv(s: &Handle, buf: &mut [u8]) -> Result<usize> {
    let len = buf.len().min(256 * 1024) as u64;
    // SAFETY: the kernel writes at most `len` (<= `buf.len()`) bytes at
    // `buf`.
    decode(unsafe { syscall(sys::SOCK_RECV, [s.0, buf.as_mut_ptr() as u64, len, 0, 0]) })
        .map(|n| n as usize)
}

pub fn udp_bind(port: u16) -> Result<Handle> {
    call(sys::UDP_BIND, [u64::from(port), 0, 0, 0, 0]).map(Handle)
}

pub fn udp_send(s: &Handle, data: &[u8], to: [u8; 4], port: u16) -> Result<usize> {
    // SAFETY: the kernel reads `data.len()` bytes at `data`.
    decode(unsafe {
        syscall(
            sys::UDP_SEND,
            [
                s.0,
                data.as_ptr() as u64,
                data.len() as u64,
                ip(to),
                u64::from(port),
            ],
        )
    })
    .map(|n| n as usize)
}

/// Receives a datagram: its length (truncated to `buf`) and source.
pub fn udp_recv(s: &Handle, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16)> {
    let len = buf.len().min(256 * 1024) as u64;
    let mut src = [0u8; 6];
    // SAFETY: the kernel writes at most `len` bytes at `buf` and 6 at
    // `src`.
    let n = decode(unsafe {
        syscall(
            sys::UDP_RECV,
            [
                s.0,
                buf.as_mut_ptr() as u64,
                len,
                src.as_mut_ptr() as u64,
                0,
            ],
        )
    })?;
    Ok((
        n as usize,
        [src[0], src[1], src[2], src[3]],
        u16::from_be_bytes([src[4], src[5]]),
    ))
}

/// Publishes TCP port `outside` of the uplink to `inside` of `cell`.
pub fn port_publish(switch: &Handle, outside: u16, cell: &Handle, inside: u16) -> Result<()> {
    call(
        sys::PORT_PUBLISH,
        [switch.0, u64::from(outside), cell.0, u64::from(inside), 0],
    )
    .map(|_| ())
}

/// Verifies an Ichor image and keeps it in the kernel.
pub fn image_create(image: &[u8]) -> Result<Handle> {
    // SAFETY: the kernel reads `image.len()` bytes at `image`.
    decode(unsafe {
        syscall(
            sys::IMAGE_CREATE,
            [image.as_ptr() as u64, image.len() as u64, 0, 0, 0],
        )
    })
    .map(Handle)
}

/// A cell under `parent` rooted at `image`, with `pages` of memory.
pub fn cell_create(parent: &Handle, image: &Handle, pages: u64) -> Result<Handle> {
    call(sys::CELL_CREATE, [parent.0, image.0, pages, 0, 0]).map(Handle)
}

/// Starts `argv` (looked up on the cell's root along `PATH`) in `cell`
/// with environment `env`.
pub fn cell_spawn(cell: &Handle, argv: &[&str], env: &[&str]) -> Result<Handle> {
    let mut spec = Vec::new();
    for s in argv {
        spec.extend_from_slice(s.as_bytes());
        spec.push(0);
    }
    spec.push(0);
    for s in env {
        spec.extend_from_slice(s.as_bytes());
        spec.push(0);
    }
    // SAFETY: the kernel reads `spec.len()` bytes at `spec`.
    decode(unsafe {
        syscall(
            sys::CELL_SPAWN,
            [cell.0, spec.as_ptr() as u64, spec.len() as u64, 0, 0],
        )
    })
    .map(Handle)
}

/// Reads a process's output; 0 once it has exited and all was read.
pub fn process_read(p: &Handle, buf: &mut [u8]) -> Result<usize> {
    let len = buf.len().min(256 * 1024) as u64;
    // SAFETY: the kernel writes at most `len` bytes at `buf`.
    decode(unsafe { syscall(sys::PROCESS_READ, [p.0, buf.as_mut_ptr() as u64, len, 0, 0]) })
        .map(|n| n as usize)
}

/// A process's wait status (`WouldBlock` while it runs).
pub fn process_wait(p: &Handle) -> Result<u32> {
    call(sys::PROCESS_WAIT, [p.0, 0, 0, 0, 0]).map(|s| s as u32)
}

/// The address the switch gave a cell.
pub fn cell_addr(cell: &Handle) -> Result<[u8; 4]> {
    call(sys::CELL_ADDR, [cell.0, 0, 0, 0, 0]).map(|a| (a as u32).to_be_bytes())
}

/// A fixed buffer for formatting one log line without the heap.
#[derive(Debug)]
pub struct Line {
    buf: [u8; 512],
    len: usize,
}

impl Line {
    pub fn new() -> Line {
        Line {
            buf: [0; 512],
            len: 0,
        }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Default for Line {
    fn default() -> Line {
        Line::new()
    }
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for c in s.chars() {
            let mut b = [0u8; 4];
            let e = c.encode_utf8(&mut b);
            if self.len + e.len() > self.buf.len() {
                break;
            }
            self.buf[self.len..self.len + e.len()].copy_from_slice(e.as_bytes());
            self.len += e.len();
        }
        Ok(())
    }
}

/// `log!` with `format!` arguments.
#[macro_export]
macro_rules! log {
    ($($t:tt)*) => {
        $crate::log(&::alloc::format!($($t)*))
    };
}
