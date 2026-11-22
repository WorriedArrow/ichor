//! The native personality, version 2 (ADR-0012 §2): what Ichor's own
//! services (the control plane) run on. A native process lives in a cell,
//! has a demand-paged address space charged to it, and reaches kernel
//! objects only through handles in its cell's CSpace: sockets on the
//! cell's stack, verified images, cells made from them, and Linux processes
//! started in those cells with their output captured.
//!
//! Every call is non-blocking except `OBJECT_WAIT`, which sleeps until one
//! of the named objects changes. Version 1's calls stay in `nativeabi.rs`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use cap::{Cap, Handle, Rights};
use frame::mm::{PAGE_SIZE, UFrame};
use frame::println;
use frame::sync::SpinLock;
use frame::task::TaskOptions;
use frame::user::{UserContext, UserEvent, UserMode};
use ichor_abi::{Error, WaitItem, sys};
use net::Ipv4Addr;

use crate::kcell::{Cell, Object, rights};
use crate::linuxabi::socket::native as sock;
use crate::pagecache::Mounted;
use crate::pipe::Pipe;
use crate::poll::Watchers;
use crate::process::{Fd, LinuxProcess, PipeEnd};
use crate::umem::Mm;
use crate::vfs::{Kind, ROOT, Vfs};

/// Most bytes one call copies in or out (LOG, SOCK_*, PROCESS_READ).
const MAX_IO: usize = 256 * 1024;
/// Most bytes of a `CELL_SPAWN` spec.
const MAX_SPEC: usize = 128 * 1024;
/// Most items one `OBJECT_WAIT` watches.
const MAX_WAIT: usize = 256;
/// Largest image `IMAGE_CREATE` takes.
const MAX_IMAGE: u64 = 4 << 30;
/// `PATH` when the spec's environment has none.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Rights on a socket handle.
const SOCKET_RIGHTS: Rights = Rights(
    Rights::DUPLICATE.0 | Rights::INSPECT.0 | Rights::WAIT.0 | rights::READ.0 | rights::WRITE.0,
);

/// A cell made by `CELL_CREATE`: the cell and its root (the image with an
/// upper layer in memory).
pub(crate) struct Container {
    pub(crate) cell: Arc<Cell>,
    pub(crate) vfs: Arc<Vfs>,
}

/// A Linux process started by `CELL_SPAWN`. Its stdout and stderr are one
/// pipe whose read end this holds.
pub(crate) struct Process {
    output: Arc<Pipe>,
    status: SpinLock<Option<u32>>,
}

impl Process {
    fn exited(&self) -> Option<u32> {
        *self.status.lock()
    }

    /// Readable with output buffered; readable and hung up once the exit
    /// status is recorded (not merely when the pipe closes, which happens
    /// just before: the end of the output promises the status).
    fn readiness(&self) -> u32 {
        let mut r = u32::from(self.output.poll(false)) & ichor_abi::READABLE;
        if self.exited().is_some() {
            r |= ichor_abi::READABLE | ichor_abi::HANGUP;
        }
        r
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Closing the handle closes the read end: further writes are EPIPE.
        self.output.drop_end(false);
    }
}

/// An image handed in by `IMAGE_CREATE`, held in pages: the block device
/// the page cache reads (and verifies) its chunks from. The pages are in
/// groups, so a large image needs no large table.
struct PageDisk {
    pages: Vec<Vec<UFrame>>,
    len: u64,
}

/// Pages in a [`PageDisk`] group.
const GROUP: u64 = 4096;

impl block::BlockDevice for PageDisk {
    fn sector_count(&self) -> u64 {
        self.len.div_ceil(block::SECTOR_SIZE as u64)
    }

    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), block::BlockError> {
        block::check(self, sector, buf.len())?;
        let mut at = sector * block::SECTOR_SIZE as u64;
        let mut done = 0;
        while done < buf.len() {
            let page = at / PAGE_SIZE;
            let page = (self.pages.get((page / GROUP) as usize))
                .and_then(|g| g.get((page % GROUP) as usize));
            let off = (at % PAGE_SIZE) as usize;
            let n = (PAGE_SIZE as usize - off).min(buf.len() - done);
            let out = &mut buf[done..done + n];
            match page {
                Some(f) => {
                    let mut r = f.reader();
                    r.skip(off);
                    r.read(out);
                }
                None => out.fill(0),
            }
            done += n;
            at += n as u64;
        }
        Ok(())
    }
}

/// Copies `len` bytes of the process's memory at `va` into the kernel.
fn read_user(mm: &mut Mm, va: u64, len: usize) -> Result<Vec<u8>, Error> {
    let mut v = alloc::vec![0u8; len];
    if mm.copy_from_user(va, &mut v) != len {
        return Err(Error::Invalid);
    }
    Ok(v)
}

/// Copies `data` into the process's memory at `va`, with the permissions
/// a user store has (ADR-0011).
fn write_user(mm: &mut Mm, va: u64, data: &[u8]) -> Result<(), Error> {
    if mm.copy_to_user(va, data) != data.len() {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// A Linux errno as a native error.
fn errno(e: i64) -> Error {
    match e {
        11 => Error::WouldBlock,
        111 => Error::Refused,
        12 | 105 => Error::NoMemory,
        2 => Error::NotFound,
        22 | 98 | 99 => Error::Invalid,
        _ => Error::Failed,
    }
}

fn install(cell: &Cell, obj: Object, grant: Rights) -> Result<u64, Error> {
    cell.install(Cap::mint(obj, grant))
        .map(Handle::raw)
        .ok_or(Error::NoMemory)
}

fn object(cell: &Cell, h: u64, required: Rights) -> Result<Object, Error> {
    cell.object(Handle::from_raw(h), required)
        .ok_or(Error::BadHandle)
}

fn socket(cell: &Cell, h: u64, required: Rights) -> Result<Arc<dyn crate::poll::Object>, Error> {
    match object(cell, h, required)? {
        Object::Socket(s) => Ok(s),
        _ => Err(Error::BadHandle),
    }
}

fn container(cell: &Cell, h: u64, required: Rights) -> Result<Arc<Container>, Error> {
    match object(cell, h, required)? {
        Object::Container(c) => Ok(c),
        _ => Err(Error::BadHandle),
    }
}

fn process(cell: &Cell, h: u64, required: Rights) -> Result<Arc<Process>, Error> {
    match object(cell, h, required)? {
        Object::Process(p) => Ok(p),
        _ => Err(Error::BadHandle),
    }
}

/// The cell a container or cell handle names.
fn cell_of(cell: &Cell, h: u64, required: Rights) -> Result<Arc<Cell>, Error> {
    match object(cell, h, required)? {
        Object::Container(c) => Ok(c.cell.clone()),
        Object::Cell(c) => Ok(c),
        _ => Err(Error::BadHandle),
    }
}

fn addr(ip: u64, port: u64) -> Result<(Ipv4Addr, u16), Error> {
    let ip = u32::try_from(ip).map_err(|_| Error::Invalid)?;
    let port = u16::try_from(port).map_err(|_| Error::Invalid)?;
    Ok((Ipv4Addr::from(ip), port))
}

fn io_len(len: u64) -> Result<usize, Error> {
    usize::try_from(len)
        .ok()
        .filter(|&l| l <= MAX_IO)
        .ok_or(Error::Invalid)
}

/// One version-2 call from a native process of `cell` with address space
/// `mm`.
pub(crate) fn call(cell: &Arc<Cell>, mm: &mut Mm, nr: u64, a: [u64; 6]) -> Result<u64, Error> {
    match nr {
        sys::LOG => {
            let text = read_user(mm, a[0], io_len(a[1])?)?;
            let text = String::from_utf8_lossy(&text);
            println!("ichor: cell {}: {}", cell.id(), text.trim_end());
            Ok(0)
        }
        sys::CLOCK => match a[0] {
            ichor_abi::CLOCK_MONOTONIC => Ok(frame::time::now().as_nanos() as u64),
            ichor_abi::CLOCK_REALTIME => Ok(crate::vfs::wall_clock().as_nanos() as u64),
            _ => Err(Error::Invalid),
        },
        sys::RANDOM => {
            let len = io_len(a[1])?;
            let mut buf = alloc::vec![0u8; len];
            crate::random::fill(&mut buf);
            write_user(mm, a[0], &buf)?;
            Ok(0)
        }
        sys::MEM_MAP => {
            const PROT_RW: u64 = 3;
            const MAP_PRIVATE_ANON: u64 = 0x22;
            if a[0] == 0 || a[0] > 1 << 40 {
                return Err(Error::Invalid);
            }
            mm.mmap(0, a[0], PROT_RW, MAP_PRIVATE_ANON, None)
                .map_err(|_| Error::NoMemory)
        }
        sys::MEM_UNMAP => mm.munmap(a[0], a[1]).map_err(|_| Error::Invalid),
        sys::OBJECT_WAIT => object_wait(cell, mm, a[0], a[1], a[2]),
        sys::TCP_CONNECT => {
            let s = sock::tcp_connect(cell, addr(a[0], a[1])?).map_err(errno)?;
            install(cell, Object::Socket(s), SOCKET_RIGHTS)
        }
        sys::TCP_LISTEN => {
            let port = u16::try_from(a[0]).map_err(|_| Error::Invalid)?;
            let backlog = (a[1] as usize).clamp(1, 4096);
            let ip = u32::try_from(a[2]).map_err(|_| Error::Invalid)?;
            let s = sock::tcp_listen(cell, Ipv4Addr::from(ip), port, backlog).map_err(errno)?;
            install(cell, Object::Socket(s), SOCKET_RIGHTS)
        }
        sys::TCP_ACCEPT => {
            let l = socket(cell, a[0], rights::READ)?;
            match sock::accept(&l).map_err(errno)? {
                Some(s) => install(cell, Object::Socket(s), SOCKET_RIGHTS),
                None => Err(Error::WouldBlock),
            }
        }
        sys::SOCK_SEND => {
            let s = socket(cell, a[0], rights::WRITE)?;
            let data = read_user(mm, a[1], io_len(a[2])?)?;
            s.write(&data, true, &|| false)
                .map(|n| n as u64)
                .map_err(errno)
        }
        sys::SOCK_RECV => {
            let s = socket(cell, a[0], rights::READ)?;
            let data = s.read(io_len(a[2])?, true, &|| false).map_err(errno)?;
            write_user(mm, a[1], &data)?;
            Ok(data.len() as u64)
        }
        sys::UDP_BIND => {
            let port = u16::try_from(a[0]).map_err(|_| Error::Invalid)?;
            let s = sock::udp_bind(cell, port).map_err(errno)?;
            install(cell, Object::Socket(s), SOCKET_RIGHTS)
        }
        sys::UDP_SEND => {
            let s = socket(cell, a[0], rights::WRITE)?;
            let data = read_user(mm, a[1], io_len(a[2])?)?;
            sock::udp_send(&s, &data, addr(a[3], a[4])?)
                .map(|n| n as u64)
                .map_err(errno)
        }
        sys::UDP_RECV => {
            let s = socket(cell, a[0], rights::READ)?;
            let max = io_len(a[2])?;
            let Some(((ip, port), data)) = sock::udp_recv(&s).map_err(errno)? else {
                return Err(Error::WouldBlock);
            };
            let n = data.len().min(max);
            write_user(mm, a[1], &data[..n])?;
            if a[3] != 0 {
                let mut src = [0u8; 6];
                src[..4].copy_from_slice(&ip.octets());
                src[4..].copy_from_slice(&port.to_be_bytes());
                write_user(mm, a[3], &src)?;
            }
            Ok(n as u64)
        }
        sys::SOCK_ERROR => {
            let s = socket(cell, a[0], Rights::INSPECT)?;
            match sock::connect_result(&s).map_err(errno)? {
                None => Err(Error::WouldBlock),
                Some(Ok(())) => Ok(0),
                Some(Err(e)) => Err(errno(e)),
            }
        }
        sys::PORT_PUBLISH => {
            if !matches!(object(cell, a[0], rights::WRITE)?, Object::Switch) {
                return Err(Error::BadHandle);
            }
            let target = cell_of(cell, a[2], Rights::INSPECT)?;
            let outside = u16::try_from(a[1]).map_err(|_| Error::Invalid)?;
            let inside = u16::try_from(a[3]).map_err(|_| Error::Invalid)?;
            if crate::switch::publish(net::wire::PROTO_TCP, outside, target.id(), inside) {
                Ok(0)
            } else {
                Err(Error::Failed)
            }
        }
        sys::IMAGE_CREATE => image_create(cell, mm, a[0], a[1]),
        sys::CELL_CREATE => cell_create(cell, a[0], a[1], a[2]),
        sys::CELL_SPAWN => {
            let c = container(cell, a[0], rights::WRITE)?;
            let len = usize::try_from(a[2])
                .ok()
                .filter(|&l| l <= MAX_SPEC)
                .ok_or(Error::Invalid)?;
            let spec = read_user(mm, a[1], len)?;
            let p = spawn(&c, &spec)?;
            install(
                cell,
                Object::Process(p),
                Rights::DUPLICATE | Rights::INSPECT | Rights::WAIT | rights::READ,
            )
        }
        sys::PROCESS_READ => {
            let p = process(cell, a[0], rights::READ)?;
            let mut buf = alloc::vec![0u8; io_len(a[2])?];
            match p.output.read(&mut buf, true, &|| false) {
                // The pipe closed, but the status is not recorded yet.
                Ok(0) if p.exited().is_none() => Err(Error::WouldBlock),
                Ok(n) => {
                    write_user(mm, a[1], &buf[..n])?;
                    Ok(n as u64)
                }
                // Orphans may hold the pipe open: once the process itself
                // has exited, what it buffered is all there is.
                Err(11) if p.exited().is_some() => Ok(0),
                Err(e) => Err(errno(e)),
            }
        }
        sys::PROCESS_WAIT => process(cell, a[0], Rights::INSPECT)?
            .exited()
            .map(u64::from)
            .ok_or(Error::WouldBlock),
        sys::CELL_SIGNAL => {
            let c = container(cell, a[0], rights::WRITE)?;
            let sig = u32::try_from(a[1])
                .ok()
                .filter(|s| (1..=64).contains(s))
                .ok_or(Error::Invalid)?;
            Ok(crate::proc::signal_cell(c.cell.id(), sig))
        }
        sys::CELL_INSPECT => {
            let c = container(cell, a[0], Rights::INSPECT)?;
            let (threads, processes, _) = crate::proc::census(c.cell.id());
            let info = ichor_abi::CellInfo {
                memory_used: c.cell.account().used(),
                memory_limit: c.cell.account().limit(),
                processes: processes as u64,
                threads: threads as u64,
                address: crate::netstack::stack_for(&c.cell)
                    .addr()
                    .map_or(0, |ip| ip.to_bits()),
            };
            write_user(mm, a[1], &info.to_bytes())?;
            Ok(ichor_abi::CELL_INFO_LEN as u64)
        }
        sys::BLOB_READ => {
            let Object::Blob(b) = object(cell, a[0], rights::READ)? else {
                return Err(Error::BadHandle);
            };
            let at = usize::try_from(a[1]).unwrap_or(usize::MAX).min(b.len());
            let n = io_len(a[3])?.min(b.len() - at);
            write_user(mm, a[2], &b[at..at + n])?;
            Ok(n as u64)
        }
        sys::CELL_ADDR => {
            let c = cell_of(cell, a[0], Rights::INSPECT)?;
            crate::netstack::stack_for(&c)
                .addr()
                .map(|ip| u64::from(ip.to_bits()))
                .ok_or(Error::NotFound)
        }
        _ => Err(Error::NoSys),
    }
}

/// What `obj` is ready for, as `OBJECT_WAIT` reports it, and the pollers
/// to join while waiting on it.
fn readiness(obj: &Object) -> u32 {
    match obj {
        Object::Socket(s) => u32::from(s.poll()),
        Object::Process(p) => p.readiness(),
        _ => 0,
    }
}

fn watchers(obj: &Object) -> Option<&Watchers> {
    match obj {
        Object::Socket(s) => s.watchers(),
        Object::Process(p) => Some(p.output.watchers()),
        _ => None,
    }
}

fn object_wait(cell: &Cell, mm: &mut Mm, ptr: u64, n: u64, timeout: u64) -> Result<u64, Error> {
    let n = usize::try_from(n)
        .ok()
        .filter(|&n| n <= MAX_WAIT)
        .ok_or(Error::Invalid)?;
    let raw = read_user(mm, ptr, n * 16)?;
    let mut items: Vec<WaitItem> = raw
        .as_chunks::<16>()
        .0
        .iter()
        .map(WaitItem::from_bytes)
        .collect();
    let objs = items
        .iter()
        .map(|w| object(cell, w.handle, Rights::WAIT))
        .collect::<Result<Vec<_>, _>>()?;
    let scan = |items: &mut [WaitItem]| {
        let mut ready = 0;
        for (w, o) in items.iter_mut().zip(&objs) {
            w.revents = readiness(o) & (w.events | ichor_abi::FAILED | ichor_abi::HANGUP);
            if w.revents != 0 {
                ready += 1;
            }
        }
        ready
    };
    let mut ready = scan(&mut items);
    if ready == 0 && timeout != 0 {
        let deadline =
            (timeout != u64::MAX).then(|| frame::time::now() + Duration::from_nanos(timeout));
        let watched: Vec<&Watchers> = objs.iter().filter_map(watchers).collect();
        ready = crate::poll::wait_watchers(&watched, deadline, || {
            let r = scan(&mut items);
            (r > 0).then_some(r)
        })
        .unwrap_or(0);
    }
    let out: Vec<u8> = items.iter().flat_map(|w| w.to_bytes()).collect();
    write_user(mm, ptr, &out)?;
    Ok(ready as u64)
}

/// `IMAGE_CREATE`: copies the image into pages charged to the caller's
/// cell (as is the copy of its metadata the kernel keeps), checks its
/// metadata and root hash, and keeps it as a disk for the life of the
/// system (its chunks are verified as they are read).
fn image_create(cell: &Cell, mm: &mut Mm, ptr: u64, len: u64) -> Result<u64, Error> {
    if !(image::HEADER_LEN as u64..=MAX_IMAGE).contains(&len) {
        return Err(Error::Invalid);
    }
    let head = read_user(mm, ptr, image::HEADER_LEN)?;
    let meta_len = image::metadata_len(&head).map_err(|_| Error::Failed)? as u64;
    if meta_len > len {
        return Err(Error::Failed);
    }
    let npages = len.div_ceil(PAGE_SIZE) + meta_len.div_ceil(PAGE_SIZE);
    cell.account().charge(npages).map_err(|_| Error::NoMemory)?;
    let copied = (|| {
        let mut pages: Vec<Vec<UFrame>> = Vec::new();
        let mut buf = alloc::vec![0u8; PAGE_SIZE as usize];
        for i in 0..len.div_ceil(PAGE_SIZE) {
            let at = i * PAGE_SIZE;
            let n = (len - at).min(PAGE_SIZE) as usize;
            if mm.copy_from_user(ptr + at, &mut buf[..n]) != n {
                return Err(Error::Invalid);
            }
            buf[n..].fill(0);
            let f = UFrame::alloc_zeroed().ok_or(Error::NoMemory)?;
            f.writer().write(&buf);
            match pages.last_mut() {
                Some(g) if g.len() < GROUP as usize => g.push(f),
                _ => pages.push(alloc::vec![f]),
            }
        }
        // Checks the metadata and its root hash (the process may have
        // changed its copy since the charge: a longer metadata fails too).
        let m = crate::pagecache::mount_disk(PageDisk { pages, len }).map_err(|_| Error::Failed)?;
        if m.image.metadata_len() as u64 > meta_len {
            return Err(Error::Failed);
        }
        Ok(m)
    })();
    match copied {
        Ok(m) => {
            let m: &'static Mounted = alloc::boxed::Box::leak(alloc::boxed::Box::new(m));
            install(
                cell,
                Object::Image(m),
                Rights::DUPLICATE | Rights::INSPECT | rights::READ,
            )
        }
        Err(e) => {
            cell.account().release(npages);
            Err(e)
        }
    }
}

/// A cell's host name (what `uname` reports as the node name).
const HOSTNAME: &str = "ichor";

/// Writes `/etc/<name>` in a new cell's root, replacing the image's (as a
/// runtime's bind mount would). A root where that fails keeps the image's.
fn write_etc(vfs: &crate::vfs::Vfs, name: &str, data: &[u8]) {
    let mut fs = vfs.lock();
    let root = crate::vfs::ROOT;
    let Ok(etc) = fs
        .lookup(root, "etc")
        .or_else(|_| fs.mkdir(root, "etc", 0o755))
    else {
        return;
    };
    let ino = match fs.lookup(etc, name) {
        Ok(ino) => fs.truncate(ino, 0).map(|()| ino),
        Err(_) => fs.create(etc, name, 0o644),
    };
    if let Ok(ino) = ino {
        let _ = fs.write(ino, 0, data);
    }
}

/// `CELL_CREATE`: a cell under `parent` with `pages` of memory (what its
/// processes use and what it writes to its root), rooted at the image,
/// attached to the switch.
fn cell_create(cell: &Cell, parent: u64, image: u64, pages: u64) -> Result<u64, Error> {
    let Object::Cell(parent) = object(cell, parent, rights::CREATE_CELL)? else {
        return Err(Error::BadHandle);
    };
    let Object::Image(m) = object(cell, image, rights::READ)? else {
        return Err(Error::BadHandle);
    };
    if pages < 64 {
        return Err(Error::Invalid);
    }
    let new = Cell::new(parent.account(), pages).ok_or(Error::NoMemory)?;
    let vfs = Vfs::mount_disk_for(m, new.account()).map_err(|_| Error::Failed)?;
    let vfs = Arc::new(vfs);
    let addr = crate::netstack::stack_for(&new).addr();
    if addr.is_none() {
        println!("ichor: native: cell {} has no switch address", new.id());
    }
    // What a container runtime writes into every container (images do not
    // carry them): `localhost` and the cell's own name resolve.
    let mut hosts = alloc::string::String::from("127.0.0.1\tlocalhost\n");
    if let Some(ip) = addr {
        let o = ip.octets();
        hosts += &alloc::format!("{}.{}.{}.{}\t{HOSTNAME}\n", o[0], o[1], o[2], o[3]);
    }
    write_etc(&vfs, "hosts", hosts.as_bytes());
    write_etc(&vfs, "hostname", alloc::format!("{HOSTNAME}\n").as_bytes());
    install(
        cell,
        Object::Container(Arc::new(Container { cell: new, vfs })),
        Rights::DUPLICATE | Rights::INSPECT | Rights::WAIT | rights::WRITE,
    )
}

fn is_file(vfs: &Vfs, path: &str) -> bool {
    let mut fs = vfs.lock();
    fs.resolve(ROOT, path, true)
        .and_then(|i| fs.stat(i))
        .is_ok_and(|s| s.kind == Kind::File)
}

/// `argv[0]` as a path on the container's root, searched along `PATH` if
/// it has no slash.
fn find(vfs: &Vfs, name: &str, envp: &[String]) -> Option<String> {
    if name.contains('/') {
        return is_file(vfs, name).then(|| name.into());
    }
    let path = envp
        .iter()
        .find_map(|e| e.strip_prefix("PATH="))
        .unwrap_or(DEFAULT_PATH);
    path.split(':').find_map(|dir| {
        let full = alloc::format!("{}/{name}", dir.trim_end_matches('/'));
        is_file(vfs, &full).then_some(full)
    })
}

/// Splits a spec: NUL-terminated strings, the argv, an empty string, then
/// the environment.
fn parse_spec(spec: &[u8]) -> Result<(Vec<String>, Vec<String>), Error> {
    let s = core::str::from_utf8(spec).map_err(|_| Error::Invalid)?;
    let s = s.strip_suffix('\0').ok_or(Error::Invalid)?;
    let mut parts = s.split('\0');
    let argv: Vec<String> = parts
        .by_ref()
        .take_while(|p| !p.is_empty())
        .map(String::from)
        .collect();
    let envp: Vec<String> = parts.filter(|p| !p.is_empty()).map(String::from).collect();
    if argv.is_empty() {
        return Err(Error::Invalid);
    }
    Ok((argv, envp))
}

/// `CELL_SPAWN`: a Linux process in `c` running `argv` (found on its root),
/// on a task of its own, with stdout and stderr going to one pipe.
fn spawn(c: &Container, spec: &[u8]) -> Result<Arc<Process>, Error> {
    let (argv, envp) = parse_spec(spec)?;
    let path = find(&c.vfs, &argv[0], &envp).ok_or(Error::NotFound)?;
    let mut p = LinuxProcess::new(c.cell.clone(), c.vfs.clone()).ok_or(Error::NoMemory)?;
    let output = Pipe::new(c.cell.account());
    p.close(1);
    p.close(2);
    let end = PipeEnd {
        pipe: output.clone(),
        write: true,
        nonblock: false,
    };
    if p.install_flags(Fd::Pipe(end), false) != Some(1) || p.dup_to(1, 2, false).is_none() {
        crate::proc::discard(p);
        return Err(Error::NoMemory);
    }
    let process = Arc::new(Process {
        output,
        status: SpinLock::new(None),
    });
    let pid = p.entry.pid;
    let sched = crate::sched::SchedInfo::of_cell(p.cell.id());
    let record = process.clone();
    let argv: Vec<Vec<u8>> = argv.into_iter().map(String::into_bytes).collect();
    let envp: Vec<Vec<u8>> = envp.into_iter().map(String::into_bytes).collect();
    let task = TaskOptions::new(move || {
        let leader = p.group.leader.clone();
        let mut ctx = UserContext::new(0, 0);
        let status = match crate::linuxabi::exec::exec(&mut p, &mut ctx, path, argv, envp) {
            Ok(()) => {
                crate::proc::run(p, ctx);
                loop {
                    if let Some(s) = crate::proc::exit_status(&leader) {
                        break s;
                    }
                    frame::task::sleep_until(frame::time::now() + Duration::from_millis(2));
                }
            }
            Err(e) => {
                println!("ichor: native: spawn failed: errno {e}");
                frame::mm::activate_kernel_space();
                crate::proc::discard(p);
                127 << 8
            }
        };
        *record.status.lock() = Some(status);
        record.output.watchers().notify();
    })
    .data(sched)
    .spawn();
    if task.is_none() {
        crate::proc::forget(pid);
        return Err(Error::NoMemory);
    }
    Ok(process)
}

/// Runs a native program (a static ELF) in `cell` on the calling task
/// until it exits; returns its exit code, or `None` if it could not load
/// or was killed by an exception.
pub(crate) fn run(cell: &Arc<Cell>, elf: &[u8], argv: &[&str]) -> Option<u64> {
    let mut mm = Mm::new(cell.account())?;
    let loaded =
        match crate::loader::load(&mut mm, &crate::file::Bytes(elf), None, argv, &[], 1 << 20) {
            Ok(l) => l,
            Err(e) => {
                println!("ichor: native: cannot load {:?}: {e:?}", argv.first());
                return None;
            }
        };
    mm.space().bind_to_current_task();
    frame::task::set_current_domain(cell.id());
    let mut ctx = UserContext::new(loaded.entry, loaded.stack_pointer);
    let code = loop {
        match UserMode::new(&mut ctx).execute() {
            UserEvent::Syscall => {
                let code = ctx.syscall_args().1[0];
                if !crate::nativeabi::dispatch(cell, Some(&mut mm), &mut ctx) {
                    break Some(code);
                }
            }
            UserEvent::Preempted => frame::task::yield_now(),
            UserEvent::Exception {
                vector: 14,
                error,
                cr2,
            } if mm.fault(cr2, error & 2 != 0, error & 16 != 0) => {}
            UserEvent::Exception { vector, error, cr2 } => {
                println!(
                    "ichor: native: cell {} killed: exception {vector} (error {error:#x}) at rip {:#x} (cr2 {cr2:#x})",
                    cell.id(),
                    ctx.rip
                );
                // The registers, so a crash seen once can be read off the
                // disassembly (a corrupted pointer names what held it).
                println!(
                    "ichor: native:   rax {:#x} rbx {:#x} rcx {:#x} rdx {:#x} rsi {:#x} rdi {:#x} rbp {:#x} rsp {:#x}",
                    ctx.rax, ctx.rbx, ctx.rcx, ctx.rdx, ctx.rsi, ctx.rdi, ctx.rbp, ctx.rsp
                );
                println!(
                    "ichor: native:   r8 {:#x} r9 {:#x} r10 {:#x} r11 {:#x} r12 {:#x} r13 {:#x} r14 {:#x} r15 {:#x}",
                    ctx.r8, ctx.r9, ctx.r10, ctx.r11, ctx.r12, ctx.r13, ctx.r14, ctx.r15
                );
                break None;
            }
        }
    };
    frame::mm::activate_kernel_space();
    drop(mm);
    code
}
