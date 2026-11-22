//! `/proc`: generated files about the calling process and the system.
//!
//! Absolute paths under `/proc` are answered here before the root overlay
//! sees them. Opening a file snapshots its contents into a descriptor
//! (like Linux's `seq_file`, reads continue through the snapshot);
//! directories list their entries through `getdents64`; links answer
//! `readlink` and are followed like symlinks.
//!
//! Partial: only the calling process's own `/proc/<pid>` tree exists (as
//! `self` or its pid); relative paths into `/proc` (a working directory
//! there) see the image's empty `/proc` instead; descriptor links name
//! files as `anon_inode:[file]` (open files do not record their paths).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use frame::sync::SpinLock;

use crate::poll::Object;
use crate::process::{Fd, LinuxProcess};

const ENOENT: i64 = 2;
const EINVAL: i64 = 22;

const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

/// What a `/proc` path names.
#[derive(Debug)]
pub(crate) enum Node {
    Dir(Vec<(String, u8)>),
    File(Vec<u8>),
    Link(String),
}

fn dir(names: &[(&str, u8)]) -> Node {
    Node::Dir(names.iter().map(|&(n, t)| (n.to_string(), t)).collect())
}

/// Answers `path` if it is under `/proc` (`None` otherwise). With
/// `follow_last`, a link in the final component is reported as the link
/// (the caller follows it; `self` is followed here).
pub(crate) fn lookup(p: &LinuxProcess, path: &str, follow_last: bool) -> Option<Result<Node, i64>> {
    if let Some(n) = sys(path) {
        return Some(n);
    }
    let rest = path.strip_prefix("/proc")?;
    if !(rest.is_empty() || rest.starts_with('/')) {
        return None;
    }
    let mut comps: Vec<String> = rest
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .map(ToString::to_string)
        .collect();
    let me = p.group.tgid.to_string();
    if comps.first().map(String::as_str) == Some("self") {
        if comps.len() == 1 && !follow_last {
            return Some(Ok(Node::Link(me)));
        }
        comps[0] = me.clone();
    }
    let c: Vec<&str> = comps.iter().map(String::as_str).collect();
    Some(match c.as_slice() {
        [] => {
            let mut v: Vec<(String, u8)> = [
                ("cpuinfo", DT_REG),
                ("filesystems", DT_REG),
                ("loadavg", DT_REG),
                ("meminfo", DT_REG),
                ("mounts", DT_LNK),
                ("self", DT_LNK),
                ("stat", DT_REG),
                ("sys", DT_DIR),
                ("uptime", DT_REG),
                ("version", DT_REG),
            ]
            .iter()
            .map(|&(n, t)| (n.to_string(), t))
            .collect();
            v.push((me, DT_DIR));
            Ok(Node::Dir(v))
        }
        ["cpuinfo"] => Ok(Node::File(cpuinfo())),
        ["filesystems"] => Ok(Node::File(
            b"nodev\tproc\nnodev\tdevtmpfs\n\tichor\n".to_vec(),
        )),
        ["loadavg"] => Ok(Node::File(loadavg(p))),
        ["meminfo"] => Ok(Node::File(meminfo(p))),
        ["mounts"] if !follow_last => Ok(Node::Link("self/mounts".to_string())),
        ["mounts"] => Ok(Node::File(mounts())),
        ["stat"] => Ok(Node::File(stat_global(p))),
        ["uptime"] => {
            let t = frame::time::now();
            Ok(Node::File(
                format!("{}.{:02} 0.00\n", t.as_secs(), t.subsec_millis() / 10).into_bytes(),
            ))
        }
        ["version"] => Ok(Node::File(
            b"Linux version 6.6.0-ichor (Ichor framekernel) #1 SMP\n".to_vec(),
        )),
        ["sys"] => Ok(dir(&[("kernel", DT_DIR), ("net", DT_DIR)])),
        ["sys", "net"] => Ok(dir(&[("core", DT_DIR)])),
        ["sys", "net", "core"] => Ok(dir(&[("somaxconn", DT_REG)])),
        // `listen` clamps backlogs to this (redis checks it).
        ["sys", "net", "core", "somaxconn"] => Ok(Node::File(b"4096\n".to_vec())),
        ["sys", "kernel"] => Ok(dir(&[
            ("hostname", DT_REG),
            ("osrelease", DT_REG),
            ("ostype", DT_REG),
            ("pid_max", DT_REG),
        ])),
        ["sys", "kernel", "hostname"] => Ok(Node::File(b"ichor\n".to_vec())),
        ["sys", "kernel", "osrelease"] => Ok(Node::File(b"6.6.0-ichor\n".to_vec())),
        ["sys", "kernel", "ostype"] => Ok(Node::File(b"Linux\n".to_vec())),
        ["sys", "kernel", "pid_max"] => Ok(Node::File(b"4194304\n".to_vec())),
        [pid, rest @ ..] if *pid == me => process(p, rest, follow_last),
        _ => Err(ENOENT),
    })
}

/// The few `/sys` files libc consults: the CPU lists
/// (`/sys/devices/system/cpu/{online,possible,present}`, which glibc's
/// `get_nprocs` reads) and the directories above them.
fn sys(path: &str) -> Option<Result<Node, i64>> {
    let rest = path.strip_prefix("/sys")?;
    if !(rest.is_empty() || rest.starts_with('/')) {
        return None;
    }
    let c: Vec<&str> = rest
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let n = frame::cpu::online_count();
    let list = if n <= 1 {
        String::from("0\n")
    } else {
        alloc::format!("0-{}\n", n - 1)
    };
    Some(match c.as_slice() {
        [] => Ok(dir(&[("devices", DT_DIR)])),
        ["devices"] => Ok(dir(&[("system", DT_DIR)])),
        ["devices", "system"] => Ok(dir(&[("cpu", DT_DIR)])),
        ["devices", "system", "cpu"] => Ok(dir(&[
            ("online", DT_REG),
            ("possible", DT_REG),
            ("present", DT_REG),
        ])),
        [
            "devices",
            "system",
            "cpu",
            "online" | "possible" | "present",
        ] => Ok(Node::File(list.into_bytes())),
        _ => Err(ENOENT),
    })
}

fn process(p: &LinuxProcess, rest: &[&str], follow_last: bool) -> Result<Node, i64> {
    let _ = follow_last;
    match rest {
        [] => Ok(dir(&[
            ("cgroup", DT_REG),
            ("cmdline", DT_REG),
            ("comm", DT_REG),
            ("cwd", DT_LNK),
            ("exe", DT_LNK),
            ("fd", DT_DIR),
            ("maps", DT_REG),
            ("mountinfo", DT_REG),
            ("mounts", DT_REG),
            ("stat", DT_REG),
            ("status", DT_REG),
        ])),
        // A cell sees itself as the root of a cgroup (v2) namespace; there
        // is no cgroup file system to look further in.
        ["cgroup"] => Ok(Node::File(b"0::/\n".to_vec())),
        ["cmdline"] => Ok(Node::File(p.group.cmdline())),
        ["comm"] => Ok(Node::File(format!("{}\n", comm(p)).into_bytes())),
        ["cwd"] => {
            let cwd = p.cwd();
            Ok(Node::Link(
                p.vfs.lock().path(cwd).unwrap_or_else(|_| "/".to_string()),
            ))
        }
        ["exe"] => Ok(Node::Link(p.group.exe())),
        ["fd"] => {
            let v = p
                .open_fds()
                .into_iter()
                .map(|n| (n.to_string(), DT_LNK))
                .collect();
            Ok(Node::Dir(v))
        }
        ["fd", n] => {
            let n: u64 = n.parse().map_err(|_| ENOENT)?;
            let f = p.fd(n).ok_or(ENOENT)?;
            Ok(Node::Link(describe(p, &f)))
        }
        ["maps"] => Ok(Node::File(p.mm().maps().into_bytes())),
        ["mountinfo"] => Ok(Node::File(
            b"1 0 0:1 / / rw - ichor rootfs rw\n2 1 0:2 / /proc rw - proc proc rw\n\
              3 1 0:3 / /dev rw - devtmpfs devtmpfs rw\n"
                .to_vec(),
        )),
        ["mounts"] => Ok(Node::File(mounts())),
        ["stat"] => Ok(Node::File(stat_process(p))),
        ["status"] => Ok(Node::File(status(p))),
        _ => Err(ENOENT),
    }
}

fn comm(p: &LinuxProcess) -> String {
    if let Some(n) = p.group.prctl.lock().name.clone() {
        return n;
    }
    let exe = p.group.exe();
    let base = exe.rsplit('/').next().unwrap_or("");
    base.chars().take(15).collect()
}

fn describe(p: &LinuxProcess, f: &Fd) -> String {
    match f {
        Fd::Console => "/dev/console".to_string(),
        Fd::Dev(d) => match d.rdev() {
            0x103 => "/dev/null".to_string(),
            0x105 => "/dev/zero".to_string(),
            0x107 => "/dev/full".to_string(),
            _ => "/dev/urandom".to_string(),
        },
        Fd::File(of) => p
            .vfs
            .lock()
            .path(of.ino)
            .unwrap_or_else(|_| "anon_inode:[file]".to_string()),
        Fd::Pipe(e) => format!(
            "pipe:[{:x}]",
            alloc::sync::Arc::as_ptr(&e.pipe) as usize & 0xffff_ffff
        ),
        Fd::Object(o) => match (o.obj.tty(), o.obj.socket(), o.obj.unix()) {
            (Some(t), _, _) => t.path(),
            (None, Some(s), _) => alloc::format!("socket:[{}]", s.inode()),
            (None, None, Some(u)) => alloc::format!("socket:[{}]", u.inode()),
            (None, None, None) => "anon_inode:[eventpoll]".to_string(),
        },
    }
}

fn cpuinfo() -> Vec<u8> {
    let mut s = String::new();
    for cpu in frame::cpu::online() {
        s.push_str(&format!(
            "processor\t: {}\nvendor_id\t: Ichor\nmodel name\t: x86-64 (Ichor)\n\
             cpu MHz\t\t: {}\nflags\t\t: fpu sse sse2\n\n",
            cpu.index(),
            frame::time::tsc_hz() / 1_000_000
        ));
    }
    s.into_bytes()
}

/// The cell's view of memory: its account's limit and what is left of it
/// (or the machine's free memory, if that is less), as a container sees its
/// cgroup limit. No page cache or swap yet.
fn meminfo(p: &LinuxProcess) -> Vec<u8> {
    let st = frame::mm::stats();
    let account = p.cell.account();
    let total = account.limit().min(st.total_pages as u64) * 4;
    let free = account.available().min(st.free_pages as u64) * 4;
    format!(
        "MemTotal:       {total:8} kB\nMemFree:        {free:8} kB\nMemAvailable:   {free:8} kB\n\
         Buffers:               0 kB\nCached:                0 kB\nSwapTotal:             0 kB\n\
         SwapFree:              0 kB\n"
    )
    .into_bytes()
}

/// Load averages are not tracked yet (0.00); the counts are the cell's live
/// threads, with the reader as the one known to be running.
fn loadavg(p: &LinuxProcess) -> Vec<u8> {
    let (threads, _, last) = crate::proc::census(p.entry.cell);
    format!("0.00 0.00 0.00 1/{threads} {last}\n").into_bytes()
}

fn mounts() -> Vec<u8> {
    b"rootfs / ichor rw 0 0\nproc /proc proc rw 0 0\ndevtmpfs /dev devtmpfs rw 0 0\n".to_vec()
}

/// CPU times are not accounted yet (zeros); `processes` counts every pid
/// handed out since boot, as Linux counts forks.
fn stat_global(p: &LinuxProcess) -> Vec<u8> {
    let n = frame::cpu::online_count();
    let mut s = String::from("cpu  0 0 0 0 0 0 0 0 0 0\n");
    for i in 0..n {
        s.push_str(&format!("cpu{i} 0 0 0 0 0 0 0 0 0 0\n"));
    }
    let (_, _, last) = crate::proc::census(p.entry.cell);
    s.push_str(&format!(
        "btime 0\nprocesses {last}\nprocs_running 1\nprocs_blocked 0\n"
    ));
    s.into_bytes()
}

fn status(p: &LinuxProcess) -> Vec<u8> {
    let (size, rss) = {
        let mm = p.mm();
        (mm.virtual_size() / 1024, mm.resident_pages() as u64 * 4)
    };
    format!(
        "Name:\t{}\nState:\tR (running)\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t0\t0\t0\t0\n\
         Gid:\t0\t0\t0\t0\nVmSize:\t{} kB\nVmRSS:\t{} kB\nThreads:\t{}\nSigBlk:\t{:016x}\n",
        comm(p),
        p.group.tgid,
        p.entry.pid,
        p.entry.ppid(),
        size,
        rss,
        p.group.threads().len(),
        p.sig.mask
    )
    .into_bytes()
}

/// `/proc/<pid>/stat` up to rss (field 24). CPU times are zero (not
/// accounted yet); start time, size and resident pages are real.
fn stat_process(p: &LinuxProcess) -> Vec<u8> {
    let (pgid, sid) = p.group.leader.group();
    let (vsize, rss) = {
        let mm = p.mm();
        (mm.virtual_size(), mm.resident_pages())
    };
    format!(
        "{} ({}) R {} {} {} 0 -1 0 0 0 0 0 0 0 0 0 20 0 {} 0 {} {} {}\n",
        p.group.tgid,
        comm(p),
        p.entry.ppid(),
        pgid,
        sid,
        p.group.threads().len(),
        p.group.leader.started,
        vsize,
        rss
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Descriptors for opened /proc nodes.
// ---------------------------------------------------------------------------

/// An opened `/proc` file: a snapshot read sequentially.
#[derive(Debug)]
pub(crate) struct ProcFile {
    data: Vec<u8>,
    pos: SpinLock<usize>,
}

/// An opened `/proc` directory.
#[derive(Debug)]
pub(crate) struct ProcDir {
    entries: Vec<(String, u8)>,
    pos: SpinLock<u64>,
}

impl ProcFile {
    pub(crate) fn new(data: Vec<u8>) -> ProcFile {
        ProcFile {
            data,
            pos: SpinLock::new(0),
        }
    }
}

impl ProcDir {
    pub(crate) fn new(entries: Vec<(String, u8)>) -> ProcDir {
        ProcDir {
            entries,
            pos: SpinLock::new(0),
        }
    }
}

impl Object for ProcFile {
    fn read(&self, max: usize, _: bool, _: &dyn Fn() -> bool) -> Result<Vec<u8>, i64> {
        let mut pos = self.pos.lock();
        let start = (*pos).min(self.data.len());
        let end = start.saturating_add(max).min(self.data.len());
        *pos = end;
        Ok(self.data[start..end].to_vec())
    }
    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(EINVAL)
    }
    fn poll(&self) -> u16 {
        crate::poll::POLLIN | crate::poll::POLLOUT
    }
    fn mode(&self) -> u32 {
        0o100_000 // S_IFREG
    }
}

impl Object for ProcDir {
    fn read(&self, _: usize, _: bool, _: &dyn Fn() -> bool) -> Result<Vec<u8>, i64> {
        Err(21) // EISDIR
    }
    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(21)
    }
    fn poll(&self) -> u16 {
        crate::poll::POLLIN | crate::poll::POLLOUT
    }
    fn mode(&self) -> u32 {
        0o040_000 // S_IFDIR
    }
    fn dir(&self) -> Option<(&[crate::poll::DirEntry], &SpinLock<u64>)> {
        Some((&self.entries, &self.pos))
    }
}
