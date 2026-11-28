//! `/proc`: generated files about the cell's processes and the system.
//!
//! Paths under `/proc` are answered here: the root overlay hands on those
//! that lead there (`Overlay::set_elsewhere`), by a symbolic link, a working
//! directory or otherwise. Opening a file snapshots its contents into a
//! descriptor (like Linux's `seq_file`, reads continue through the
//! snapshot; `maps` is written as it is read); directories list their entries through `getdents64`; links
//! answer `readlink` and are followed like symlinks, but for descriptors',
//! which are opened anew (`fs::reopen`).
//!
//! Partial: a zombie has only `stat` and `status`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use frame::sync::{Mutex, SpinLock};

use crate::page::Reserved;
use crate::poll::Object;
use crate::proc::{self, ProcEntry};
use crate::process::{Fd, Group, LinuxProcess};

const ENOENT: i64 = 2;
const EACCES: i64 = 13;
const EINVAL: i64 = 22;

const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

/// What a `/proc` path names.
#[derive(Debug)]
pub(crate) enum Node {
    Dir(Vec<(String, u8)>),
    File(Vec<u8>),
    /// A process's `maps`, written as it is read: it may be long.
    Maps(Weak<Group>),
    Link(String),
}

fn dir(names: &[(&str, u8)]) -> Node {
    Node::Dir(names.iter().map(|&(n, t)| (n.to_string(), t)).collect())
}

/// Whether an absolute path is one this answers.
pub(crate) fn serves(path: &str) -> bool {
    ["/proc", "/sys"].iter().any(|d| {
        path.strip_prefix(d)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// The caller's descriptor `path` names (`/proc/self/fd/N`).
pub(crate) fn own_fd(p: &LinuxProcess, path: &str) -> Option<u64> {
    let rest = path.strip_prefix("/proc/")?;
    let c: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    let [who, "fd", n] = c.as_slice() else {
        return None;
    };
    let mine = matches!(*who, "self" | "thread-self") || who.parse() == Ok(p.group.tgid);
    n.parse().ok().filter(|_| mine)
}

/// Whose the `/proc` file at `path` is: a process's, that of the user it
/// acts as.
pub(crate) fn owner(p: &LinuxProcess, path: &str) -> (u32, u32) {
    let who = path
        .strip_prefix("/proc/")
        .and_then(|rest| rest.split('/').next());
    let group = match who {
        // (The link itself is nobody's in particular.)
        Some("self" | "thread-self") if path.matches('/').count() > 2 => Some(p.group.clone()),
        Some(pid) => pid
            .parse()
            .ok()
            .and_then(|pid| proc::find(p.entry.cell, pid))
            .and_then(|e| proc::find(p.entry.cell, e.tgid))
            .and_then(|e| e.process()),
        None => None,
    };
    group.map_or((0, 0), |g| {
        let c = g.creds();
        (c.euid, c.egid)
    })
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
    if matches!(
        comps.first().map(String::as_str),
        Some("self" | "thread-self")
    ) {
        if comps.len() == 1 && !follow_last {
            return Some(Ok(Node::Link(me)));
        }
        comps[0] = me;
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
            let pids = proc::pids(p.entry.cell);
            v.extend(pids.into_iter().map(|n| (n.to_string(), DT_DIR)));
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
        ["sys", "net"] => Ok(dir(&[("core", DT_DIR), ("ipv4", DT_DIR)])),
        // The cell's own: 0 unless the control plane set another, as Docker
        // and containerd do (a cell's ports are its own). Read-only, as
        // /proc/sys is in a container.
        ["sys", "net", "ipv4"] => Ok(dir(&[("ip_unprivileged_port_start", DT_REG)])),
        ["sys", "net", "ipv4", "ip_unprivileged_port_start"] => Ok(Node::File(
            format!(
                "{}\n",
                crate::netstack::stack_for(&p.cell).unprivileged_ports()
            )
            .into_bytes(),
        )),
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
        [pid, rest @ ..] => match pid.parse::<u64>() {
            Ok(pid) => process(p, pid, rest),
            Err(_) => Err(ENOENT),
        },
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
    let list = cpu_list() + "\n";
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

/// `/proc/<pid>/...` of a process of the caller's cell.
fn process(p: &LinuxProcess, pid: u64, rest: &[&str]) -> Result<Node, i64> {
    let e = proc::find(p.entry.cell, pid)
        .and_then(|e| proc::find(p.entry.cell, e.tgid))
        .ok_or(ENOENT)?;
    let Some(g) = e.process() else {
        return zombie(&e, rest);
    };
    // Where another's memory and files are is for those who may signal it.
    let own = g.tgid == p.group.tgid;
    let private = matches!(
        rest.first(),
        Some(&("cwd" | "exe" | "fd" | "maps" | "environ"))
    );
    if private && !own && !p.group.creds().may_signal(e.uids()) {
        return Err(EACCES);
    }
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
            ("statm", DT_REG),
            ("status", DT_REG),
            ("task", DT_DIR),
        ])),
        // A cell sees itself as the root of a cgroup (v2) namespace; there
        // is no cgroup file system to look further in.
        ["cgroup"] => Ok(Node::File(b"0::/\n".to_vec())),
        ["cmdline"] => Ok(Node::File(g.cmdline())),
        ["comm"] => Ok(Node::File(format!("{}\n", comm(&g)).into_bytes())),
        ["cwd"] => {
            let cwd = g.cwd();
            let path = g.vfs().lock().path(cwd);
            Ok(Node::Link(path.unwrap_or_else(|_| "/".to_string())))
        }
        ["exe"] => Ok(Node::Link(g.exe())),
        ["fd"] => {
            let v = g
                .open_fds()
                .into_iter()
                .map(|n| (n.to_string(), DT_LNK))
                .collect();
            Ok(Node::Dir(v))
        }
        ["fd", n] => {
            let n: u64 = n.parse().map_err(|_| ENOENT)?;
            let f = g.fd(n).ok_or(ENOENT)?;
            Ok(Node::Link(describe(&g, &f)))
        }
        ["maps"] => Ok(Node::Maps(Arc::downgrade(&g))),
        ["mountinfo"] => Ok(Node::File(
            b"1 0 0:1 / / rw - ichor rootfs rw\n2 1 0:2 / /proc rw - proc proc rw\n\
              3 1 0:3 / /dev rw - devtmpfs devtmpfs rw\n"
                .to_vec(),
        )),
        ["mounts"] => Ok(Node::File(mounts())),
        ["stat"] => Ok(Node::File(stat_process(&g, &g.leader))),
        ["statm"] => {
            let (size, rss) = {
                let mm = g.mm();
                (mm.virtual_size() / 4096, mm.resident_pages())
            };
            Ok(Node::File(
                format!("{size} {rss} 0 0 0 {rss} 0\n").into_bytes(),
            ))
        }
        ["status"] => Ok(Node::File(status(&g, &g.leader))),
        ["task"] => {
            let t = g.threads();
            let names = t.iter().map(|t| (t.pid.to_string(), DT_DIR));
            Ok(Node::Dir(names.collect()))
        }
        ["task", tid, rest @ ..] => {
            let tid: u64 = tid.parse().map_err(|_| ENOENT)?;
            let threads = g.threads();
            let t = threads.iter().find(|t| t.pid == tid).ok_or(ENOENT)?;
            match rest {
                [] => Ok(dir(&[
                    ("comm", DT_REG),
                    ("stat", DT_REG),
                    ("status", DT_REG),
                ])),
                ["comm"] => Ok(Node::File(format!("{}\n", comm(&g)).into_bytes())),
                ["stat"] => Ok(Node::File(stat_process(&g, t))),
                ["status"] => Ok(Node::File(status(&g, t))),
                // Shared by the process's threads.
                ["cmdline" | "cwd" | "exe" | "fd" | "maps" | "mounts", ..] => process(p, pid, rest),
                _ => Err(ENOENT),
            }
        }
        _ => Err(ENOENT),
    }
}

/// A process that has exited and was not waited for.
fn zombie(e: &ProcEntry, rest: &[&str]) -> Result<Node, i64> {
    let (pgid, sid) = e.group();
    match rest {
        [] => Ok(dir(&[("stat", DT_REG), ("status", DT_REG)])),
        ["stat"] => Ok(Node::File(
            format!(
                "{} (defunct) Z {} {pgid} {sid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {} 0 0{}\n",
                e.pid,
                e.ppid(),
                e.started,
                " 0".repeat(28),
            )
            .into_bytes(),
        )),
        ["status"] => Ok(Node::File(
            format!(
                "Name:\tdefunct\nState:\tZ (zombie)\nTgid:\t{0}\nPid:\t{0}\nPPid:\t{1}\n\
                 Threads:\t1\n",
                e.pid,
                e.ppid()
            )
            .into_bytes(),
        )),
        ["cmdline"] => Ok(Node::File(Vec::new())),
        _ => Err(ENOENT),
    }
}

fn comm(g: &Group) -> String {
    if let Some(n) = g.prctl.lock().name.clone() {
        return n;
    }
    let exe = g.exe();
    let base = exe.rsplit('/').next().unwrap_or("");
    base.chars().take(15).collect()
}

/// A process's state as `stat` and `status` give it.
fn state(g: &Group) -> (char, &'static str) {
    if proc::stopping(&g.leader) {
        ('T', "stopped")
    } else if g.threads().iter().any(|t| t.runnable()) {
        ('R', "running")
    } else {
        ('S', "sleeping")
    }
}

fn describe(p: &Group, f: &Fd) -> String {
    match f {
        Fd::Console => "/dev/console".to_string(),
        Fd::Dev(d) => match d.rdev() {
            0x103 => "/dev/null".to_string(),
            0x105 => "/dev/zero".to_string(),
            0x107 => "/dev/full".to_string(),
            _ => "/dev/urandom".to_string(),
        },
        Fd::File(of) => p
            .vfs()
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
    let boot = crate::vfs::wall_clock().saturating_sub(frame::time::now());
    s.push_str(&format!(
        "btime {}\nprocesses {last}\nprocs_running 1\nprocs_blocked 0\n",
        boot.as_secs()
    ));
    s.into_bytes()
}

/// `status` of thread `t` of a process.
fn status(g: &Group, t: &ProcEntry) -> Vec<u8> {
    let (size, rss) = {
        let mm = g.mm();
        (mm.virtual_size() / 1024, mm.resident_pages() as u64 * 4)
    };
    let c = g.creds();
    let (letter, word) = state(g);
    let mut groups = String::new();
    for n in &c.groups {
        groups.push_str(&format!("{n} "));
    }
    let acts = g.actions.lock().clone();
    format!(
        "Name:\t{}\nUmask:\t{:04o}\nState:\t{letter} ({word})\nTgid:\t{}\nNgid:\t0\n\
         Pid:\t{}\nPPid:\t{}\nTracerPid:\t0\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\n\
         FDSize:\t{}\nGroups:\t{groups}\nVmPeak:\t{size} kB\nVmSize:\t{size} kB\n\
         VmHWM:\t{rss} kB\nVmRSS:\t{rss} kB\nThreads:\t{}\nSigQ:\t0/4096\n\
         SigPnd:\t0000000000000000\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\n\
         SigCgt:\t{:016x}\nCapInh:\t0000000000000000\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\n\
         CapBnd:\t{:016x}\nCapAmb:\t0000000000000000\nNoNewPrivs:\t{}\nSeccomp:\t0\n\
         Cpus_allowed_list:\t{}\n",
        comm(g),
        g.umask(),
        g.tgid,
        t.pid,
        g.leader.ppid(),
        c.ruid,
        c.euid,
        c.suid,
        c.fsuid,
        c.rgid,
        c.egid,
        c.sgid,
        c.fsgid,
        g.open_fds().len().next_power_of_two().max(64),
        g.threads().len(),
        proc::pending(t),
        proc::blocked(t),
        acts.set_ignored(),
        acts.caught(),
        c.permitted,
        c.effective,
        crate::cred::BOUNDING,
        u8::from(g.prctl.lock().no_new_privs),
        cpu_list(),
    )
    .into_bytes()
}

/// The CPUs, as a list ("0-3").
fn cpu_list() -> String {
    match frame::cpu::online_count() {
        0 | 1 => String::from("0"),
        n => format!("0-{}", n - 1),
    }
}

/// `/proc/<pid>/stat`. CPU time (user and system together, as user time),
/// start time, size and resident pages are real; what is not counted is
/// zero.
fn stat_process(g: &Group, t: &ProcEntry) -> Vec<u8> {
    let (pgid, sid) = g.leader.group();
    let (vsize, rss) = {
        let mm = g.mm();
        (mm.virtual_size(), mm.resident_pages())
    };
    let (letter, _) = state(g);
    let ticks = g.cpu_ns() / 10_000_000;
    let nice = g.prctl.lock().nice;
    format!(
        "{} ({}) {letter} {} {pgid} {sid} 0 -1 0 0 0 0 0 {ticks} 0 0 0 {} {nice} {} 0 {} {vsize} \
         {rss} {}{}\n",
        t.pid,
        comm(g),
        g.leader.ppid(),
        20 + nice,
        g.threads().len(),
        g.leader.started,
        u64::MAX,
        " 0".repeat(27),
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Descriptors for opened /proc nodes.
// ---------------------------------------------------------------------------

/// An opened `/proc` file: a snapshot read sequentially, or (`maps`) text
/// made a piece at a time.
#[derive(Debug)]
pub(crate) struct ProcFile {
    path: String,
    state: Mutex<Text>,
    maps: Option<Weak<Group>>,
    /// What the snapshot costs its opener's cell.
    _kept: Option<Reserved>,
}

#[derive(Debug, Default)]
struct Text {
    data: Vec<u8>,
    pos: usize,
    /// Where the next piece of `maps` starts.
    next: Option<u64>,
}

/// An opened `/proc` directory.
#[derive(Debug)]
pub(crate) struct ProcDir {
    path: String,
    entries: Vec<(String, u8)>,
    pos: SpinLock<u64>,
}

impl ProcFile {
    /// A snapshot, which `p`'s cell pays for; `None` if it cannot.
    pub(crate) fn new(path: &str, data: Vec<u8>, p: &LinuxProcess) -> Option<ProcFile> {
        let pages = data.len().div_ceil(4096) as u64;
        Some(ProcFile {
            path: path.to_string(),
            state: Mutex::new(Text {
                data,
                ..Text::default()
            }),
            maps: None,
            _kept: Some(Reserved::new(p.cell.account(), pages)?),
        })
    }

    pub(crate) fn maps(path: &str, of: Weak<Group>) -> ProcFile {
        ProcFile {
            path: path.to_string(),
            state: Mutex::new(Text {
                next: Some(0),
                ..Text::default()
            }),
            maps: Some(of),
            _kept: None,
        }
    }
}

impl ProcDir {
    pub(crate) fn new(path: &str, entries: Vec<(String, u8)>) -> ProcDir {
        ProcDir {
            path: path.trim_end_matches('/').to_string(),
            entries,
            pos: SpinLock::new(0),
        }
    }
}

impl Object for ProcFile {
    fn read(&self, max: usize, _: bool, _: &dyn Fn() -> bool) -> Result<Vec<u8>, i64> {
        let mut t = self.state.lock();
        if t.pos >= t.data.len()
            && let Some(from) = t.next
        {
            // A process that has exited maps nothing.
            let group = self.maps.as_ref().and_then(Weak::upgrade);
            let (text, next) = group.map_or_else(Default::default, |g| g.mm().maps(from));
            *t = Text {
                data: text.into_bytes(),
                pos: 0,
                next,
            };
        }
        let start = t.pos.min(t.data.len());
        let end = start.saturating_add(max).min(t.data.len());
        t.pos = end;
        Ok(t.data[start..end].to_vec())
    }
    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(EINVAL)
    }
    fn seek(&self, offset: i64, whence: u64) -> Result<u64, i64> {
        let mut t = self.state.lock();
        let base = match whence {
            0 => 0,
            1 => t.pos as i64,
            _ => return Err(EINVAL),
        };
        let to = base.checked_add(offset).and_then(|n| u64::try_from(n).ok());
        let to = to.ok_or(EINVAL)?;
        if self.maps.is_none() {
            t.pos = usize::try_from(to).map_err(|_| EINVAL)?;
        } else if to == 0 && whence == 0 {
            *t = Text {
                next: Some(0),
                ..Text::default()
            };
        } else if whence == 0 || offset != 0 {
            return Err(EINVAL);
        }
        Ok(to)
    }
    fn poll(&self) -> u16 {
        crate::poll::POLLIN | crate::poll::POLLOUT
    }
    fn mode(&self) -> u32 {
        0o100_000 // S_IFREG
    }
    fn proc_file(&self) -> Option<&str> {
        Some(&self.path)
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
    fn seek(&self, offset: i64, whence: u64) -> Result<u64, i64> {
        let to = u64::try_from(offset).map_err(|_| EINVAL)?;
        if whence != 0 {
            return Err(EINVAL);
        }
        *self.pos.lock() = to;
        Ok(to)
    }
    fn dir(&self) -> Option<(&[crate::poll::DirEntry], &SpinLock<u64>)> {
        Some((&self.entries, &self.pos))
    }
    fn proc_dir(&self) -> Option<&str> {
        Some(&self.path)
    }
}
