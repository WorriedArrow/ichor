//! A cell's root file system (ADR-0002 §6, ADR-0006): a read-only Ichor
//! image as the lower layer and a copy-on-write upper layer in memory.
//!
//! Everything is an inode in one table. Lower files and directories become
//! inodes lazily, the first time a lookup reaches them, and from then on the
//! upper directory entry points at that inode, so identity is stable and a
//! rename simply moves the entry. A lower file is copied into memory on its
//! first write ("copy-up"). Removing a name the lower layer has leaves a
//! whiteout so the lower entry stays hidden.
//!
//! Upper data is bounded by a byte budget (`ENOSPC`) and a per-file limit
//! (`EFBIG`). An inode is freed once it has no names and no open handles.
//!
//! Path resolution lives here too: `.` and `..` (via parent pointers), and
//! symlinks (absolute and relative) with Linux's bound of 40 hops.
//!
//! The API is single-threaded (`&mut self`); the kernel puts the overlay
//! behind a lock. Errors are Linux errno values.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use image::{ChunkSource, Image, Node};

/// Linux errno values.
pub mod errno {
    pub const EPERM: i64 = 1;
    pub const EACCES: i64 = 13;
    pub const ENOENT: i64 = 2;
    pub const EIO: i64 = 5;
    pub const EEXIST: i64 = 17;
    pub const ENOTDIR: i64 = 20;
    pub const EISDIR: i64 = 21;
    pub const EINVAL: i64 = 22;
    pub const EFBIG: i64 = 27;
    pub const ENOSPC: i64 = 28;
    pub const ENAMETOOLONG: i64 = 36;
    pub const ENOTEMPTY: i64 = 39;
    pub const ELOOP: i64 = 40;
    pub const EMLINK: i64 = 31;
}
use errno::*;

/// Who is asking, for permission checks (ADR-0009): filesystem uid and
/// gid, supplementary groups, and Linux capability bits ([`cap`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cred {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub caps: u64,
}

/// Linux capability numbers the file system consults.
pub mod cap {
    pub const CHOWN: u32 = 0;
    pub const DAC_OVERRIDE: u32 = 1;
    pub const DAC_READ_SEARCH: u32 = 2;
    pub const FOWNER: u32 = 3;
    pub const FSETID: u32 = 4;
}

/// Access wanted, as `access(2)` spells it.
pub const MAY_READ: u32 = 4;
pub const MAY_WRITE: u32 = 2;
pub const MAY_EXEC: u32 = 1;

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_ISVTX: u32 = 0o1000;

impl Cred {
    /// uid 0 with every capability: what a cell's root holds.
    pub fn root() -> Cred {
        Cred {
            caps: u64::MAX,
            ..Cred::default()
        }
    }

    pub fn has(&self, cap: u32) -> bool {
        self.caps & (1 << cap) != 0
    }

    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// An inode number (index into the overlay's table).
pub type Ino = usize;

/// The root directory.
pub const ROOT: Ino = 0;
/// Longest path accepted.
pub const PATH_MAX: usize = 4096;
/// Longest name accepted.
pub const NAME_MAX: usize = 255;
/// Largest file the upper layer holds (files are paged and sparse, so this
/// bounds offsets, not memory: the layer's byte budget does that).
pub const MAX_FILE: usize = 1 << 40;
/// Most hard links to one inode.
pub const LINK_MAX: u32 = 65_000;
/// Upper-layer file pages.
const PAGE: usize = 4096;
/// Most symlinks followed while resolving one path.
const MAX_SYMLINK_HOPS: u32 = 40;

/// What an inode is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    /// A character device node; the kernel decides what it is from `rdev`.
    CharDevice,
}

/// A timestamp (seconds and nanoseconds since the epoch the kernel's
/// clock uses).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Time {
    pub sec: u64,
    pub nsec: u32,
}

/// What `stat` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub ino: u64,
    pub kind: Kind,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    pub size: u64,
    pub nlink: u32,
    /// Device number (`major << 8 | minor`, Linux's old encoding) of a
    /// character device; 0 otherwise.
    pub rdev: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: Time,
    pub mtime: Time,
    pub ctime: Time,
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Ino(Ino),
    Whiteout,
}

#[derive(Debug)]
struct Dir<'a> {
    lower: Option<Node<'a>>,
    entries: BTreeMap<String, Entry>,
    /// Whether every lower child already has an entry.
    complete: bool,
    parent: Ino,
}

/// An upper-layer file's bytes: pages by index, absent pages read as zero
/// (files are sparse). The layer's budget counts allocated pages.
#[derive(Debug, Default)]
struct FileData {
    size: u64,
    pages: BTreeMap<u64, Box<[u8; PAGE]>>,
}

impl FileData {
    /// Bytes of memory the file holds.
    fn bytes(&self) -> usize {
        self.pages.len() * PAGE
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> usize {
        if offset >= self.size {
            return 0;
        }
        let end = self.size.min(offset + out.len() as u64);
        let mut pos = offset;
        while pos < end {
            let (idx, at) = (pos / PAGE as u64, (pos % PAGE as u64) as usize);
            let n = ((end - pos) as usize).min(PAGE - at);
            let dst = &mut out[(pos - offset) as usize..(pos - offset) as usize + n];
            match self.pages.get(&idx) {
                Some(p) => dst.copy_from_slice(&p[at..at + n]),
                None => dst.fill(0),
            }
            pos += n as u64;
        }
        (end - offset) as usize
    }

    /// Pages a write of `len` bytes at `offset` would add.
    fn new_pages(&self, offset: u64, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let first = offset / PAGE as u64;
        let last = (offset + len as u64 - 1) / PAGE as u64;
        (first..=last)
            .filter(|i| !self.pages.contains_key(i))
            .count()
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let mut pos = offset;
        let end = offset + data.len() as u64;
        while pos < end {
            let (idx, at) = (pos / PAGE as u64, (pos % PAGE as u64) as usize);
            let n = ((end - pos) as usize).min(PAGE - at);
            let page = self
                .pages
                .entry(idx)
                .or_insert_with(|| Box::new([0u8; PAGE]));
            let src = (pos - offset) as usize;
            page[at..at + n].copy_from_slice(&data[src..src + n]);
            pos += n as u64;
        }
        self.size = self.size.max(end);
    }

    /// Sets the length; pages past it are freed and the tail of the last
    /// page is zeroed, so growing again reads zeros.
    fn truncate(&mut self, len: u64) {
        if len < self.size {
            let keep = len.div_ceil(PAGE as u64);
            self.pages.retain(|&i, _| i < keep);
            let at = (len % PAGE as u64) as usize;
            if at != 0
                && let Some(p) = self.pages.get_mut(&(len / PAGE as u64))
            {
                p[at..].fill(0);
            }
        }
        self.size = len;
    }
}

#[derive(Debug)]
enum Data<'a> {
    LowerFile(Node<'a>),
    File(FileData),
    Dir(Dir<'a>),
    Symlink(String),
    Device(u32),
}

#[derive(Debug)]
struct Inode<'a> {
    data: Data<'a>,
    mode: u32,
    nlink: u32,
    opens: u32,
    uid: u32,
    gid: u32,
    atime: Time,
    mtime: Time,
    ctime: Time,
}

impl<'a> Inode<'a> {
    /// A new upper-layer inode, owned by root, all times `now`.
    fn fresh(data: Data<'a>, mode: u32, nlink: u32, now: Time) -> Inode<'a> {
        Inode {
            data,
            mode,
            nlink,
            opens: 0,
            uid: 0,
            gid: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

impl Inode<'_> {
    fn kind(&self) -> Kind {
        match self.data {
            Data::LowerFile(_) | Data::File(_) => Kind::File,
            Data::Dir(_) => Kind::Directory,
            Data::Symlink(_) => Kind::Symlink,
            Data::Device(_) => Kind::CharDevice,
        }
    }
}

/// An image with a copy-on-write upper layer.
#[derive(Debug)]
pub struct Overlay<'a> {
    inodes: Vec<Option<Inode<'a>>>,
    /// Where the lower layer's file data comes from (verified chunks).
    src: Option<&'a (dyn ChunkSource + Sync)>,
    /// The credentials operations are checked against; `None` (the
    /// kernel's own use) checks nothing.
    cred: Option<Cred>,
    /// The clock that stamps changes (the kernel installs its own).
    clock: fn() -> Time,
    free: Vec<Ino>,
    used_bytes: usize,
    max_bytes: usize,
}

fn upper_dir<'a>(parent: Ino, lower: Option<Node<'a>>) -> Data<'a> {
    Data::Dir(Dir {
        complete: lower.is_none(),
        lower,
        entries: BTreeMap::new(),
        parent,
    })
}

fn from_lower<'a>(node: Node<'a>, parent: Ino) -> Inode<'a> {
    let data = match node.kind() {
        image::Kind::File => Data::LowerFile(node),
        image::Kind::Directory => upper_dir(parent, Some(node)),
        image::Kind::Symlink => Data::Symlink(node.symlink_target().unwrap_or("").to_string()),
    };
    // Owners and times as the image recorded them (format v3).
    let t = Time {
        sec: node.mtime,
        nsec: 0,
    };
    let mut i = Inode::fresh(data, node.mode & 0o7777, 1, t);
    i.uid = node.uid;
    i.gid = node.gid;
    i
}

fn check_name(name: &str) -> Result<(), i64> {
    if name.is_empty() || name.contains('/') {
        return Err(ENOENT);
    }
    if name.len() > NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    Ok(())
}

fn components(path: &str) -> impl Iterator<Item = String> + '_ {
    path.split('/')
        .filter(|c| !c.is_empty())
        .map(ToString::to_string)
}

impl<'a> Overlay<'a> {
    /// An overlay over `lower`, whose file data `src` provides, with an
    /// upper layer that may hold `max_bytes`.
    pub fn new(
        lower: &Image<'a>,
        src: &'a (dyn ChunkSource + Sync),
        max_bytes: usize,
    ) -> Result<Overlay<'a>, image::Error> {
        let root = lower.root()?;
        let mut fs = Overlay::empty(max_bytes);
        fs.src = Some(src);
        if let Some(Some(r)) = fs.inodes.get_mut(ROOT) {
            r.data = upper_dir(ROOT, Some(root));
            r.mode = root.mode & 0o7777;
        }
        Ok(fs)
    }

    /// An overlay with no lower layer (a `tmpfs`).
    pub fn empty(max_bytes: usize) -> Overlay<'a> {
        Overlay {
            inodes: alloc::vec![Some(Inode::fresh(
                upper_dir(ROOT, None),
                0o755,
                2,
                Time::default()
            ))],
            src: None,
            cred: None,
            free: Vec::new(),
            clock: || Time::default(),
            used_bytes: 0,
            max_bytes,
        }
    }

    /// Sets the credentials later operations are checked against (`None`:
    /// unchecked, for the kernel itself).
    pub fn set_cred(&mut self, cred: Option<Cred>) {
        self.cred = cred;
    }

    /// Whether the current credentials may access `ino` as `mask`
    /// ([`MAY_READ`] | [`MAY_WRITE`] | [`MAY_EXEC`]); EACCES if not.
    pub fn permission(&self, ino: Ino, mask: u32) -> Result<(), i64> {
        let Some(c) = &self.cred else {
            return Ok(());
        };
        let i = self.get(ino)?;
        let mode = i.mode;
        let bits = if c.uid == i.uid {
            mode >> 6
        } else if c.in_group(i.gid) {
            mode >> 3
        } else {
            mode
        } & 7;
        if bits & mask == mask {
            return Ok(());
        }
        let dir = i.kind() == Kind::Directory;
        // Read on anything and search on directories, without the bits.
        if c.has(cap::DAC_READ_SEARCH) && mask & MAY_WRITE == 0 && (dir || mask & MAY_EXEC == 0) {
            return Ok(());
        }
        // Everything, except executing a file no one may execute.
        if c.has(cap::DAC_OVERRIDE) && (mask & MAY_EXEC == 0 || dir || mode & 0o111 != 0) {
            return Ok(());
        }
        Err(EACCES)
    }

    /// Whether the current credentials own `ino` or hold `CAP_FOWNER`.
    fn owner_or_fowner(&self, ino: Ino) -> Result<bool, i64> {
        let Some(c) = &self.cred else {
            return Ok(true);
        };
        Ok(c.uid == self.get(ino)?.uid || c.has(cap::FOWNER))
    }

    /// `utimensat` rules: explicit times need ownership (or `CAP_FOWNER`);
    /// "now" also allows anyone who may write the file.
    pub fn may_set_times(&self, ino: Ino, explicit: bool) -> Result<(), i64> {
        if self.owner_or_fowner(ino)? {
            return Ok(());
        }
        if explicit {
            return Err(EPERM);
        }
        self.permission(ino, MAY_WRITE)
    }

    /// The sticky-bit rule for removing or replacing `victim` in `dir`.
    fn may_delete(&self, dir: Ino, victim: Ino) -> Result<(), i64> {
        self.permission(dir, MAY_WRITE | MAY_EXEC)?;
        let Some(c) = &self.cred else {
            return Ok(());
        };
        let d = self.get(dir)?;
        if d.mode & S_ISVTX != 0
            && c.uid != d.uid
            && c.uid != self.get(victim)?.uid
            && !c.has(cap::FOWNER)
        {
            return Err(EPERM);
        }
        Ok(())
    }

    /// Installs the clock that stamps modification and change times.
    pub fn set_clock(&mut self, clock: fn() -> Time) {
        self.clock = clock;
    }

    /// Marks `ino` modified (`mtime` and `ctime` now).
    fn touch(&mut self, ino: Ino) {
        let now = (self.clock)();
        if let Ok(i) = self.get_mut(ino) {
            i.mtime = now;
            i.ctime = now;
        }
    }

    /// Changes the owner (`None` leaves a field as it is), as `chown`.
    pub fn chown(&mut self, ino: Ino, uid: Option<u32>, gid: Option<u32>) -> Result<(), i64> {
        if let Some(c) = &self.cred {
            let i = self.get(ino)?;
            let new_uid = uid.is_some_and(|u| u != i.uid);
            let new_gid = gid.is_some_and(|g| g != i.gid);
            // Changing the owner needs CAP_CHOWN; the owner may change the
            // group to one of their own groups.
            let allowed = c.has(cap::CHOWN)
                || (!new_uid && c.uid == i.uid && gid.is_none_or(|g| !new_gid || c.in_group(g)));
            if !allowed {
                return Err(EPERM);
            }
        }
        let now = (self.clock)();
        let i = self.get_mut(ino)?;
        let changed = uid.is_some_and(|u| u != i.uid) || gid.is_some_and(|g| g != i.gid);
        if let Some(u) = uid {
            i.uid = u;
        }
        if let Some(g) = gid {
            i.gid = g;
        }
        if changed && i.kind() != Kind::Directory {
            i.mode &= !(S_ISUID | S_ISGID); // as Linux does on chown
        }
        i.ctime = now;
        Ok(())
    }

    /// Sets access and modification times (`None` leaves one as it is), as
    /// `utimensat`; the change time becomes now.
    pub fn set_times(
        &mut self,
        ino: Ino,
        atime: Option<Time>,
        mtime: Option<Time>,
    ) -> Result<(), i64> {
        let now = (self.clock)();
        let i = self.get_mut(ino)?;
        if let Some(a) = atime {
            i.atime = a;
        }
        if let Some(m) = mtime {
            i.mtime = m;
        }
        i.ctime = now;
        Ok(())
    }

    /// The current time by the installed clock.
    pub fn now(&self) -> Time {
        (self.clock)()
    }

    /// Bytes the upper layer holds.
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    fn get(&self, ino: Ino) -> Result<&Inode<'a>, i64> {
        self.inodes.get(ino).and_then(Option::as_ref).ok_or(ENOENT)
    }

    fn get_mut(&mut self, ino: Ino) -> Result<&mut Inode<'a>, i64> {
        self.inodes
            .get_mut(ino)
            .and_then(Option::as_mut)
            .ok_or(ENOENT)
    }

    fn dir(&self, ino: Ino) -> Result<&Dir<'a>, i64> {
        match &self.get(ino)?.data {
            Data::Dir(d) => Ok(d),
            _ => Err(ENOTDIR),
        }
    }

    fn dir_mut(&mut self, ino: Ino) -> Result<&mut Dir<'a>, i64> {
        match &mut self.get_mut(ino)?.data {
            Data::Dir(d) => Ok(d),
            _ => Err(ENOTDIR),
        }
    }

    fn alloc(&mut self, inode: Inode<'a>) -> Ino {
        if let Some(i) = self.free.pop()
            && let Some(slot) = self.inodes.get_mut(i)
        {
            *slot = Some(inode);
            return i;
        }
        self.inodes.push(Some(inode));
        self.inodes.len() - 1
    }

    fn maybe_free(&mut self, ino: Ino) {
        if ino == ROOT {
            return;
        }
        let dead = matches!(self.get(ino), Ok(i) if i.nlink == 0 && i.opens == 0);
        if !dead {
            return;
        }
        if let Some(slot) = self.inodes.get_mut(ino)
            && let Some(Inode {
                data: Data::File(f),
                ..
            }) = slot.take()
        {
            self.used_bytes -= f.bytes();
        }
        self.free.push(ino);
    }

    /// Notes an open handle on `ino` (it stays alive while open).
    pub fn open(&mut self, ino: Ino) -> Result<(), i64> {
        self.get_mut(ino)?.opens += 1;
        Ok(())
    }

    /// Drops an open handle on `ino`.
    pub fn close(&mut self, ino: Ino) {
        if let Ok(i) = self.get_mut(ino) {
            i.opens = i.opens.saturating_sub(1);
        }
        self.maybe_free(ino);
    }

    /// The entry `name` in directory `dir` (also `.` and `..`).
    pub fn lookup(&mut self, dir: Ino, name: &str) -> Result<Ino, i64> {
        let d = self.dir(dir)?;
        match name {
            "." => return Ok(dir),
            ".." => return Ok(d.parent),
            _ => {}
        }
        match d.entries.get(name) {
            Some(Entry::Ino(i)) => return Ok(*i),
            Some(Entry::Whiteout) => return Err(ENOENT),
            None => {}
        }
        let child = d.lower.and_then(|l| l.child(name)).ok_or(ENOENT)?;
        let ino = self.alloc(from_lower(child, dir));
        self.dir_mut(dir)?
            .entries
            .insert(name.to_string(), Entry::Ino(ino));
        Ok(ino)
    }

    /// Whether `name` exists in `dir`.
    fn find(&mut self, dir: Ino, name: &str) -> Result<Option<Ino>, i64> {
        match self.lookup(dir, name) {
            Ok(i) => Ok(Some(i)),
            Err(ENOENT) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn stat(&self, ino: Ino) -> Result<Stat, i64> {
        let i = self.get(ino)?;
        let size = match &i.data {
            Data::LowerFile(n) => n.size(),
            Data::File(f) => f.size,
            Data::Dir(_) => 4096,
            Data::Symlink(t) => t.len() as u64,
            Data::Device(_) => 0,
        };
        let rdev = match i.data {
            Data::Device(d) => d,
            _ => 0,
        };
        Ok(Stat {
            ino: ino as u64 + 1,
            kind: i.kind(),
            mode: i.mode,
            size,
            nlink: if i.kind() == Kind::Directory {
                2 + self.subdirs(ino)
            } else {
                i.nlink
            },
            rdev,
            uid: i.uid,
            gid: i.gid,
            atime: i.atime,
            mtime: i.mtime,
            ctime: i.ctime,
        })
    }

    /// Reads file bytes at `offset`; returns how many were read.
    pub fn read(&self, ino: Ino, offset: u64, out: &mut [u8]) -> Result<usize, i64> {
        match &self.get(ino)?.data {
            Data::LowerFile(n) => self.read_lower(n, offset, out),
            Data::File(f) => Ok(f.read(offset, out)),
            Data::Dir(_) => Err(EISDIR),
            Data::Symlink(_) | Data::Device(_) => Err(EINVAL),
        }
    }

    /// Where page `index` of `ino` lives in the lower image, if `ino` is
    /// still an unmodified lower file (for mapping the cached page).
    pub fn lower_extent(&self, ino: Ino, index: u64) -> Option<image::Extent> {
        match &self.get(ino).ok()?.data {
            Data::LowerFile(n) => n.extent(index),
            _ => None,
        }
    }

    fn read_lower(&self, n: &Node<'a>, offset: u64, out: &mut [u8]) -> Result<usize, i64> {
        let src = self.src.ok_or(EIO)?;
        n.read_at(offset, out, src).map_err(|_| EIO)
    }

    /// The target of a symlink.
    pub fn readlink(&self, ino: Ino) -> Result<String, i64> {
        match &self.get(ino)?.data {
            Data::Symlink(t) => Ok(t.clone()),
            _ => Err(EINVAL),
        }
    }

    /// Makes `ino`'s bytes writable in the upper layer.
    fn copy_up(&mut self, ino: Ino) -> Result<(), i64> {
        let node = match &self.get(ino)?.data {
            Data::LowerFile(n) => *n,
            Data::File(_) => return Ok(()),
            Data::Dir(_) => return Err(EISDIR),
            Data::Symlink(_) | Data::Device(_) => return Err(EINVAL),
        };
        let size = usize::try_from(node.size()).map_err(|_| EFBIG)?;
        if size > MAX_FILE {
            return Err(EFBIG);
        }
        let need = size.div_ceil(PAGE) * PAGE;
        if self.used_bytes + need > self.max_bytes {
            return Err(ENOSPC);
        }
        // Page by page: no buffer the size of the file.
        let mut f = FileData::default();
        let mut page = [0u8; PAGE];
        let mut at = 0u64;
        while at < size as u64 {
            let n = self.read_lower(&node, at, &mut page)?;
            if n == 0 {
                break;
            }
            f.write(at, &page[..n]);
            at += n as u64;
        }
        f.size = at;
        self.used_bytes += f.bytes();
        self.get_mut(ino)?.data = Data::File(f);
        Ok(())
    }

    /// Sets a file's length (zero-extending).
    pub fn truncate(&mut self, ino: Ino, len: u64) -> Result<(), i64> {
        let len = usize::try_from(len).map_err(|_| EFBIG)?;
        if len > MAX_FILE {
            return Err(EFBIG);
        }
        if matches!(self.get(ino)?.data, Data::Device(_)) {
            return Ok(()); // `O_TRUNC` on /dev/null and friends
        }
        if len == 0 && matches!(self.get(ino)?.data, Data::LowerFile(_)) {
            // No need to copy bytes that are about to be dropped.
            self.get_mut(ino)?.data = Data::File(FileData::default());
            self.touch(ino);
            return Ok(());
        }
        self.copy_up(ino)?;
        let Data::File(f) = &mut self.get_mut(ino)?.data else {
            return Err(EINVAL);
        };
        // Growing is sparse (no pages); shrinking frees pages.
        let before = f.bytes();
        f.truncate(len as u64);
        let after = f.bytes();
        self.used_bytes = self.used_bytes - before + after;
        self.touch(ino);
        Ok(())
    }

    /// Writes `data` at `offset` (zero-filling any gap); returns its length.
    pub fn write(&mut self, ino: Ino, offset: u64, data: &[u8]) -> Result<usize, i64> {
        self.copy_up(ino)?;
        // A write by someone without CAP_FSETID drops set-id bits.
        if self.cred.as_ref().is_some_and(|c| !c.has(cap::FSETID)) {
            let i = self.get_mut(ino)?;
            if i.mode & (S_ISUID | S_ISGID) != 0 {
                i.mode &= !(S_ISUID | S_ISGID);
            }
        }
        let off = usize::try_from(offset).map_err(|_| EFBIG)?;
        let end = off.checked_add(data.len()).ok_or(EFBIG)?;
        if end > MAX_FILE {
            return Err(EFBIG);
        }
        let used = self.used_bytes;
        let max = self.max_bytes;
        let Data::File(f) = &mut self.get_mut(ino)?.data else {
            return Err(EINVAL);
        };
        let grow = f.new_pages(off as u64, data.len()) * PAGE;
        if used + grow > max {
            return Err(ENOSPC);
        }
        f.write(off as u64, data);
        self.used_bytes = used + grow;
        self.touch(ino);
        Ok(data.len())
    }

    /// Appends `data` at the current end of the file in one step (so two
    /// `O_APPEND` writers never overwrite each other); returns the new end.
    pub fn append(&mut self, ino: Ino, data: &[u8]) -> Result<u64, i64> {
        let end = self.stat(ino)?.size;
        self.write(ino, end, data)?;
        Ok(end + data.len() as u64)
    }

    /// Changes permission bits.
    pub fn chmod(&mut self, ino: Ino, mode: u32) -> Result<(), i64> {
        if !self.owner_or_fowner(ino)? {
            return Err(EPERM);
        }
        let mut mode = mode & 0o7777;
        // Setting the group-id bit needs membership of the file's group.
        if let Some(c) = &self.cred
            && !c.in_group(self.get(ino)?.gid)
            && !c.has(cap::FSETID)
        {
            mode &= !S_ISGID;
        }
        let now = (self.clock)();
        let i = self.get_mut(ino)?;
        i.mode = mode;
        i.ctime = now;
        Ok(())
    }

    fn add(&mut self, dir: Ino, name: &str, mut inode: Inode<'a>) -> Result<Ino, i64> {
        check_name(name)?;
        self.dir(dir)?;
        if self.find(dir, name)?.is_some() {
            return Err(EEXIST);
        }
        self.permission(dir, MAY_WRITE | MAY_EXEC)?;
        // New inodes belong to the creator; a set-group-id directory
        // passes its group down (and the bit, to subdirectories).
        if let Some(c) = &self.cred {
            inode.uid = c.uid;
            inode.gid = c.gid;
        }
        let d = self.get(dir)?;
        if d.mode & S_ISGID != 0 {
            inode.gid = d.gid;
            if inode.kind() == Kind::Directory {
                inode.mode |= S_ISGID;
            }
        }
        let ino = self.alloc(inode);
        self.dir_mut(dir)?
            .entries
            .insert(name.to_string(), Entry::Ino(ino));
        self.touch(dir);
        Ok(ino)
    }

    /// Creates an empty file.
    pub fn create(&mut self, dir: Ino, name: &str, mode: u32) -> Result<Ino, i64> {
        let inode = Inode::fresh(
            Data::File(FileData::default()),
            mode & 0o7777,
            1,
            (self.clock)(),
        );
        self.add(dir, name, inode)
    }

    /// Adds the name `ndir/nname` for the existing non-directory `ino` (a
    /// hard link): both names are the same inode, which lives until its
    /// last name is gone and it is closed.
    pub fn link(&mut self, ino: Ino, ndir: Ino, nname: &str) -> Result<(), i64> {
        check_name(nname)?;
        let i = self.get(ino)?;
        if i.kind() == Kind::Directory {
            return Err(EPERM);
        }
        if i.nlink == 0 {
            return Err(ENOENT); // an unlinked, still-open file
        }
        if i.nlink >= LINK_MAX {
            return Err(EMLINK);
        }
        self.dir(ndir)?;
        if self.find(ndir, nname)?.is_some() {
            return Err(EEXIST);
        }
        self.permission(ndir, MAY_WRITE | MAY_EXEC)?;
        self.dir_mut(ndir)?
            .entries
            .insert(nname.to_string(), Entry::Ino(ino));
        self.touch(ndir);
        let now = (self.clock)();
        let i = self.get_mut(ino)?;
        i.nlink += 1;
        i.ctime = now;
        Ok(())
    }

    /// The subdirectories of `dir` (for its link count `2 + n`): upper
    /// entries that are directories, plus lower ones not hidden or replaced.
    fn subdirs(&self, dir: Ino) -> u32 {
        let Ok(d) = self.dir(dir) else {
            return 0;
        };
        let mut n = 0u32;
        for e in d.entries.values() {
            if let Entry::Ino(i) = e
                && self.get(*i).is_ok_and(|i| i.kind() == Kind::Directory)
            {
                n += 1;
            }
        }
        if !d.complete
            && let Some(l) = d.lower
        {
            n += l
                .entries()
                .filter(|c| c.kind() == image::Kind::Directory && !d.entries.contains_key(c.name()))
                .count() as u32;
        }
        n
    }

    /// Creates an empty directory.
    pub fn mkdir(&mut self, dir: Ino, name: &str, mode: u32) -> Result<Ino, i64> {
        let inode = Inode::fresh(upper_dir(dir, None), mode & 0o7777, 1, (self.clock)());
        self.add(dir, name, inode)
    }

    /// Creates a character device node.
    pub fn mknod(&mut self, dir: Ino, name: &str, mode: u32, rdev: u32) -> Result<Ino, i64> {
        let inode = Inode::fresh(Data::Device(rdev), mode & 0o7777, 1, (self.clock)());
        self.add(dir, name, inode)
    }

    /// Creates a symbolic link to `target`.
    pub fn symlink(&mut self, dir: Ino, name: &str, target: &str) -> Result<Ino, i64> {
        if target.is_empty() {
            return Err(ENOENT);
        }
        if target.len() > PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        let inode = Inode::fresh(Data::Symlink(target.to_string()), 0o777, 1, (self.clock)());
        self.add(dir, name, inode)
    }

    /// Removes the entry `name` from `dir`, leaving a whiteout if the lower
    /// layer has that name.
    fn detach(&mut self, dir: Ino, name: &str) -> Result<(), i64> {
        let d = self.dir_mut(dir)?;
        let in_lower = d.lower.is_some_and(|l| l.child(name).is_some());
        if in_lower {
            d.entries.insert(name.to_string(), Entry::Whiteout);
        } else {
            d.entries.remove(name);
        }
        self.touch(dir);
        Ok(())
    }

    fn drop_link(&mut self, ino: Ino) -> Result<(), i64> {
        let i = self.get_mut(ino)?;
        i.nlink = i.nlink.saturating_sub(1);
        self.maybe_free(ino);
        Ok(())
    }

    /// Removes a non-directory.
    pub fn unlink(&mut self, dir: Ino, name: &str) -> Result<(), i64> {
        check_name(name)?;
        let ino = self.lookup(dir, name)?;
        if self.get(ino)?.kind() == Kind::Directory {
            return Err(EISDIR);
        }
        self.may_delete(dir, ino)?;
        self.detach(dir, name)?;
        self.drop_link(ino)
    }

    /// Whether a directory has no entries.
    fn is_empty_dir(&mut self, ino: Ino) -> Result<bool, i64> {
        Ok(self.readdir(ino)?.is_empty())
    }

    /// Removes an empty directory.
    pub fn rmdir(&mut self, dir: Ino, name: &str) -> Result<(), i64> {
        if name == "." {
            return Err(EINVAL);
        }
        if name == ".." {
            return Err(ENOTEMPTY);
        }
        check_name(name)?;
        let ino = self.lookup(dir, name)?;
        if self.get(ino)?.kind() != Kind::Directory {
            return Err(ENOTDIR);
        }
        if !self.is_empty_dir(ino)? {
            return Err(ENOTEMPTY);
        }
        self.may_delete(dir, ino)?;
        self.detach(dir, name)?;
        self.drop_link(ino)
    }

    /// Whether `ancestor` is `ino` or one of its ancestors.
    fn is_ancestor(&self, ancestor: Ino, mut ino: Ino) -> bool {
        for _ in 0..self.inodes.len() {
            if ino == ancestor {
                return true;
            }
            match self.dir(ino) {
                Ok(d) if ino != ROOT => ino = d.parent,
                _ => return false,
            }
        }
        false
    }

    /// Moves `odir/oname` to `ndir/nname`, replacing a file there, or an
    /// empty directory if the source is a directory.
    pub fn rename(&mut self, odir: Ino, oname: &str, ndir: Ino, nname: &str) -> Result<(), i64> {
        for n in [oname, nname] {
            if n == "." || n == ".." {
                return Err(EINVAL);
            }
            check_name(n)?;
        }
        let src = self.lookup(odir, oname)?;
        self.dir(ndir)?;
        let src_dir = self.get(src)?.kind() == Kind::Directory;
        if src_dir && self.is_ancestor(src, ndir) {
            return Err(EINVAL);
        }
        self.may_delete(odir, src)?;
        self.permission(ndir, MAY_WRITE | MAY_EXEC)?;
        if src_dir && odir != ndir {
            self.permission(src, MAY_WRITE)?; // its ".." changes
        }
        if let Some(dst) = self.find(ndir, nname)? {
            if dst == src {
                return Ok(());
            }
            self.may_delete(ndir, dst)?;
            let dst_dir = self.get(dst)?.kind() == Kind::Directory;
            match (src_dir, dst_dir) {
                (false, true) => return Err(EISDIR),
                (true, false) => return Err(ENOTDIR),
                (true, true) if !self.is_empty_dir(dst)? => return Err(ENOTEMPTY),
                _ => {}
            }
            self.detach(ndir, nname)?;
            self.drop_link(dst)?;
        }
        self.detach(odir, oname)?;
        self.dir_mut(ndir)?
            .entries
            .insert(nname.to_string(), Entry::Ino(src));
        if let Data::Dir(d) = &mut self.get_mut(src)?.data {
            d.parent = ndir;
        }
        self.touch(ndir);
        let now = (self.clock)();
        self.get_mut(src)?.ctime = now;
        Ok(())
    }

    /// A directory's entries in name order (without `.` and `..`).
    pub fn readdir(&mut self, dir: Ino) -> Result<Vec<(String, Ino, Kind)>, i64> {
        let d = self.dir(dir)?;
        if !d.complete {
            let names: Vec<String> = d
                .lower
                .map(|l| l.entries().map(|e| e.name().to_string()).collect())
                .unwrap_or_default();
            for n in names {
                // Materializes lower children; whiteouts stay hidden.
                let _ = self.find(dir, &n)?;
            }
            self.dir_mut(dir)?.complete = true;
        }
        let entries: Vec<(String, Ino)> = self
            .dir(dir)?
            .entries
            .iter()
            .filter_map(|(n, e)| match e {
                Entry::Ino(i) => Some((n.clone(), *i)),
                Entry::Whiteout => None,
            })
            .collect();
        entries
            .into_iter()
            .map(|(n, i)| Ok((n, i, self.get(i)?.kind())))
            .collect()
    }

    /// The absolute path of directory `ino` (for `getcwd`); `ENOENT` if
    /// it has been removed.
    pub fn path(&self, ino: Ino) -> Result<String, i64> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = ino;
        for _ in 0..self.inodes.len() {
            if cur == ROOT {
                break;
            }
            let parent = self.dir(cur)?.parent;
            let name = self
                .dir(parent)?
                .entries
                .iter()
                .find(|(_, e)| matches!(e, Entry::Ino(i) if *i == cur))
                .map(|(n, _)| n.clone())
                .ok_or(ENOENT)?;
            parts.push(name);
            cur = parent;
        }
        if cur != ROOT {
            return Err(ENOENT);
        }
        let mut out = String::new();
        for p in parts.iter().rev() {
            out.push('/');
            out.push_str(p);
        }
        if out.is_empty() {
            out.push('/');
        }
        Ok(out)
    }

    /// Resolves `path` from `cwd` (absolute paths from the root). With
    /// `follow_last`, a symlink in the final component is followed too.
    pub fn resolve(&mut self, cwd: Ino, path: &str, follow_last: bool) -> Result<Ino, i64> {
        if path.len() > PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        if path.is_empty() {
            return Err(ENOENT);
        }
        let mut cur = if path.starts_with('/') { ROOT } else { cwd };
        let mut pending: VecDeque<String> = components(path).collect();
        let mut hops = 0;
        while let Some(comp) = pending.pop_front() {
            if self.get(cur)?.kind() != Kind::Directory {
                return Err(ENOTDIR);
            }
            self.permission(cur, MAY_EXEC)?;
            let child = self.lookup(cur, &comp)?;
            let is_last = pending.is_empty();
            if self.get(child)?.kind() == Kind::Symlink && (follow_last || !is_last) {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(ELOOP);
                }
                let target = self.readlink(child)?;
                if target.starts_with('/') {
                    cur = ROOT;
                }
                for (i, c) in components(&target).enumerate() {
                    pending.insert(i, c);
                }
                continue;
            }
            cur = child;
        }
        if path.ends_with('/') && self.get(cur)?.kind() != Kind::Directory {
            return Err(ENOTDIR);
        }
        Ok(cur)
    }

    /// Resolves all but the last component of `path`; returns the parent
    /// directory and the last name (for create, unlink, rename, ...).
    pub fn resolve_parent(&mut self, cwd: Ino, path: &str) -> Result<(Ino, String), i64> {
        if path.len() > PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            // "/" itself (or "" which is ENOENT).
            return if path.is_empty() {
                Err(ENOENT)
            } else {
                Ok((ROOT, ".".to_string()))
            };
        }
        let (dir_part, name) = match trimmed.rfind('/') {
            Some(i) => (&trimmed[..=i], &trimmed[i + 1..]),
            None => ("", trimmed),
        };
        let dir = if dir_part.is_empty() {
            cwd
        } else {
            self.resolve(cwd, dir_part, true)?
        };
        if self.get(dir)?.kind() != Kind::Directory {
            return Err(ENOTDIR);
        }
        Ok((dir, name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use image::builder::Builder;

    /// `/etc/motd`, `/etc/link -> motd`, `/usr/bin/` (empty), `/abs -> /etc`.
    fn lower_image() -> Vec<u8> {
        let mut b = Builder::new();
        let motd = b.file("motd", b"lower motd\n", 0o644);
        let link = b.symlink("link", "motd");
        let etc = b.dir("etc", &[motd, link], 0o755);
        let bin = b.dir("bin", &[], 0o755);
        let usr = b.dir("usr", &[bin], 0o755);
        let abs = b.symlink("abs", "/etc");
        let root = b.dir("/", &[abs, etc, usr], 0o755);
        b.finish(root)
    }

    fn read_all(fs: &Overlay<'_>, ino: Ino) -> Vec<u8> {
        let size = fs.stat(ino).unwrap().size as usize;
        let mut v = std::vec![0u8; size];
        let n = fs.read(ino, 0, &mut v).unwrap();
        v.truncate(n);
        v
    }

    fn names(fs: &mut Overlay<'_>, dir: Ino) -> Vec<String> {
        fs.readdir(dir).unwrap().into_iter().map(|e| e.0).collect()
    }

    #[test]
    fn resolves_like_the_image() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let src = image::SliceSource(&img);
        let mut fs = Overlay::new(&image, &src, 1 << 20).unwrap();
        let motd = fs.resolve(ROOT, "/etc/motd", true).unwrap();
        assert_eq!(read_all(&fs, motd), b"lower motd\n");
        assert_eq!(fs.resolve(ROOT, "/etc/link", true).unwrap(), motd);
        assert_eq!(fs.resolve(ROOT, "/abs/link", true).unwrap(), motd);
        assert_eq!(
            fs.resolve(ROOT, "/usr/bin/../../etc/./motd", true).unwrap(),
            motd
        );
        let link = fs.resolve(ROOT, "/etc/link", false).unwrap();
        assert_eq!(fs.stat(link).unwrap().kind, Kind::Symlink);
        assert_eq!(fs.resolve(ROOT, "/nope", true), Err(ENOENT));
        assert_eq!(fs.resolve(ROOT, "/etc/motd/x", true), Err(ENOTDIR));
        assert_eq!(fs.resolve(ROOT, "/etc/motd/", true), Err(ENOTDIR));
        // Relative to a working directory, and `..` above the root.
        let etc = fs.resolve(ROOT, "/etc", true).unwrap();
        assert_eq!(fs.resolve(etc, "motd", true).unwrap(), motd);
        assert_eq!(fs.resolve(etc, "../../../etc/motd", true).unwrap(), motd);
        // Loops are bounded.
        let tmp = fs.mkdir(ROOT, "tmp", 0o777).unwrap();
        fs.symlink(tmp, "a", "b").unwrap();
        fs.symlink(tmp, "b", "a").unwrap();
        assert_eq!(fs.resolve(ROOT, "/tmp/a", true), Err(ELOOP));
    }

    #[test]
    fn copy_up_leaves_the_image_untouched() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let src = image::SliceSource(&img);
        let mut fs = Overlay::new(&image, &src, 1 << 20).unwrap();
        let motd = fs.resolve(ROOT, "/etc/motd", true).unwrap();
        assert_eq!(fs.write(motd, 0, b"UPPER").unwrap(), 5);
        assert_eq!(read_all(&fs, motd), b"UPPER motd\n");
        assert_eq!(fs.used_bytes(), PAGE); // one page for 11 bytes
        // A second overlay over the same image still sees the original.
        let mut other = Overlay::new(&image, &src, 1 << 20).unwrap();
        let m2 = other.resolve(ROOT, "/etc/motd", true).unwrap();
        assert_eq!(read_all(&other, m2), b"lower motd\n");
        // Writing past the end zero-fills; truncate shrinks.
        fs.write(motd, 13, b"!").unwrap();
        assert_eq!(read_all(&fs, motd), b"UPPER motd\n\0\0!");
        fs.truncate(motd, 5).unwrap();
        assert_eq!(read_all(&fs, motd), b"UPPER");
        assert_eq!(fs.used_bytes(), PAGE);
    }

    #[test]
    fn create_unlink_and_whiteouts() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let src = image::SliceSource(&img);
        let mut fs = Overlay::new(&image, &src, 1 << 20).unwrap();
        let etc = fs.resolve(ROOT, "/etc", true).unwrap();
        let f = fs.create(etc, "new", 0o600).unwrap();
        fs.write(f, 0, b"hi").unwrap();
        assert_eq!(fs.create(etc, "new", 0o600), Err(EEXIST));
        assert_eq!(fs.create(etc, "motd", 0o600), Err(EEXIST));
        assert_eq!(names(&mut fs, etc), ["link", "motd", "new"]);
        // Unlinking a lower name hides it; unlinking an upper one frees it.
        fs.unlink(etc, "motd").unwrap();
        assert_eq!(fs.resolve(ROOT, "/etc/motd", true), Err(ENOENT));
        assert_eq!(fs.resolve(ROOT, "/etc/link", true), Err(ENOENT)); // dangling
        fs.unlink(etc, "new").unwrap();
        assert_eq!(fs.used_bytes(), 0);
        assert_eq!(names(&mut fs, etc), ["link"]);
        // The name can be reused, and is a fresh, empty file.
        let again = fs.create(etc, "motd", 0o644).unwrap();
        assert_eq!(fs.stat(again).unwrap().size, 0);
        assert_eq!(fs.unlink(ROOT, "etc"), Err(EISDIR));
    }

    #[test]
    fn open_files_outlive_unlink() {
        let mut fs = Overlay::empty(1 << 20);
        let f = fs.create(ROOT, "f", 0o644).unwrap();
        fs.write(f, 0, b"data").unwrap();
        fs.open(f).unwrap();
        fs.unlink(ROOT, "f").unwrap();
        assert_eq!(read_all(&fs, f), b"data");
        assert_eq!(fs.used_bytes(), PAGE);
        fs.close(f);
        assert_eq!(fs.used_bytes(), 0);
        assert!(fs.stat(f).is_err());
    }

    #[test]
    fn directories() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let src = image::SliceSource(&img);
        let mut fs = Overlay::new(&image, &src, 1 << 20).unwrap();
        assert_eq!(fs.rmdir(ROOT, "etc"), Err(ENOTEMPTY));
        let usr = fs.resolve(ROOT, "/usr", true).unwrap();
        fs.rmdir(usr, "bin").unwrap();
        assert!(names(&mut fs, usr).is_empty());
        let bin = fs.mkdir(usr, "bin", 0o755).unwrap();
        // The new directory is empty: the old lower contents do not return.
        assert!(names(&mut fs, bin).is_empty());
        let sub = fs.mkdir(bin, "sub", 0o755).unwrap();
        assert_eq!(fs.lookup(sub, "..").unwrap(), bin);
        assert_eq!(fs.rmdir(bin, "."), Err(EINVAL));
        assert_eq!(fs.mkdir(bin, "sub", 0o755), Err(EEXIST));
        assert_eq!(fs.rmdir(ROOT, "abs"), Err(ENOTDIR));
    }

    #[test]
    fn rename_moves_inodes() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let src = image::SliceSource(&img);
        let mut fs = Overlay::new(&image, &src, 1 << 20).unwrap();
        let etc = fs.resolve(ROOT, "/etc", true).unwrap();
        let motd = fs.lookup(etc, "motd").unwrap();
        // A lower file moves to another directory and keeps its identity.
        let usr = fs.resolve(ROOT, "/usr", true).unwrap();
        fs.rename(etc, "motd", usr, "moved").unwrap();
        assert_eq!(fs.resolve(ROOT, "/usr/moved", true).unwrap(), motd);
        assert_eq!(fs.resolve(ROOT, "/etc/motd", true), Err(ENOENT));
        // A whole lower directory moves with its contents.
        fs.rename(ROOT, "etc", usr, "etc2").unwrap();
        let link = fs.resolve(ROOT, "/usr/etc2/link", false).unwrap();
        assert_eq!(fs.readlink(link).unwrap(), "motd");
        let etc2 = fs.resolve(ROOT, "/usr/etc2", true).unwrap();
        assert_eq!(fs.lookup(etc2, "..").unwrap(), usr);
        // Replacing a file.
        let a = fs.create(ROOT, "a", 0o644).unwrap();
        fs.create(ROOT, "b", 0o644).unwrap();
        fs.rename(ROOT, "a", ROOT, "b").unwrap();
        assert_eq!(fs.resolve(ROOT, "/b", true).unwrap(), a);
        // Not into its own subtree; not a file over a directory.
        assert_eq!(fs.rename(ROOT, "usr", usr, "x"), Err(EINVAL));
        assert_eq!(fs.rename(ROOT, "b", ROOT, "usr"), Err(EISDIR));
        assert_eq!(fs.rename(ROOT, "usr", ROOT, "b"), Err(ENOTDIR));
    }

    #[test]
    fn device_nodes() {
        let mut fs = Overlay::empty(1 << 20);
        let dev = fs.mkdir(ROOT, "dev", 0o755).unwrap();
        let null = fs.mknod(dev, "null", 0o666, (1 << 8) | 3).unwrap();
        let st = fs.stat(null).unwrap();
        assert_eq!((st.kind, st.rdev, st.size), (Kind::CharDevice, 0x103, 0));
        assert_eq!(fs.resolve(ROOT, "/dev/null", true).unwrap(), null);
        assert!(fs.truncate(null, 0).is_ok());
        assert_eq!(fs.write(null, 0, b"x"), Err(EINVAL));
        assert_eq!(fs.readdir(dev).unwrap()[0].2, Kind::CharDevice);
    }

    #[test]
    fn owners_and_times() {
        let mut fs = Overlay::empty(1 << 20);
        fs.set_clock(|| Time { sec: 100, nsec: 5 });
        let d = fs.mkdir(ROOT, "d", 0o755).unwrap();
        let f = fs.create(d, "f", 0o644).unwrap();
        let st = fs.stat(f).unwrap();
        assert_eq!(
            (st.uid, st.gid, st.mtime.sec, st.ctime.nsec),
            (0, 0, 100, 5)
        );
        assert_eq!(fs.stat(d).unwrap().mtime.sec, 100);
        fs.chown(f, Some(1000), None).unwrap();
        fs.set_times(
            f,
            Some(Time { sec: 7, nsec: 0 }),
            Some(Time { sec: 8, nsec: 9 }),
        )
        .unwrap();
        let st = fs.stat(f).unwrap();
        assert_eq!(
            (st.uid, st.gid, st.atime.sec, st.mtime.sec, st.mtime.nsec),
            (1000, 0, 7, 8, 9)
        );
        fs.set_clock(|| Time { sec: 200, nsec: 0 });
        fs.write(f, 0, b"x").unwrap();
        assert_eq!(fs.stat(f).unwrap().mtime.sec, 200);
        fs.unlink(d, "f").unwrap();
        assert_eq!(fs.stat(d).unwrap().ctime.sec, 200);
    }

    #[test]
    fn budgets() {
        // The budget is in pages: one page fits, a second does not.
        let mut fs = Overlay::empty(PAGE);
        let f = fs.create(ROOT, "f", 0o644).unwrap();
        assert_eq!(fs.write(f, 0, &[7u8; PAGE]), Ok(PAGE));
        assert_eq!(fs.write(f, 10, b"x"), Ok(1)); // same page
        assert_eq!(fs.write(f, PAGE as u64, b"x"), Err(ENOSPC));
        // Growing by truncate is sparse, so it is not refused.
        assert_eq!(fs.truncate(f, 1 << 30), Ok(()));
        assert_eq!(fs.write(f, MAX_FILE as u64, b"x"), Err(EFBIG));
        fs.truncate(f, 0).unwrap();
        assert_eq!(fs.used_bytes(), 0);
    }

    #[test]
    fn parents_and_names() {
        let mut fs = Overlay::empty(1 << 20);
        let d = fs.mkdir(ROOT, "d", 0o755).unwrap();
        assert_eq!(
            fs.resolve_parent(ROOT, "/d/x").unwrap(),
            (d, "x".to_string())
        );
        assert_eq!(fs.resolve_parent(d, "y/").unwrap(), (d, "y".to_string()));
        assert_eq!(
            fs.resolve_parent(ROOT, "/").unwrap(),
            (ROOT, ".".to_string())
        );
        assert_eq!(fs.resolve_parent(ROOT, "/nope/x"), Err(ENOENT));
        let sub = fs.mkdir(d, "sub", 0o755).unwrap();
        assert_eq!(fs.path(sub).unwrap(), "/d/sub");
        assert_eq!(fs.path(ROOT).unwrap(), "/");
        fs.rmdir(d, "sub").unwrap();
        assert_eq!(fs.path(sub), Err(ENOENT));
        let long = "x".repeat(NAME_MAX + 1);
        assert_eq!(fs.create(ROOT, &long, 0o644), Err(ENAMETOOLONG));
    }

    #[test]
    fn files_are_paged_and_sparse() {
        let mut fs = Overlay::empty(64 * PAGE);
        let f = fs.create(ROOT, "f", 0o644).unwrap();
        // A write far out allocates one page; the hole reads as zeros.
        fs.write(f, 10 * PAGE as u64 + 5, b"xyz").unwrap();
        assert_eq!(fs.stat(f).unwrap().size, 10 * PAGE as u64 + 8);
        assert_eq!(fs.used_bytes(), PAGE);
        let mut buf = [1u8; 16];
        assert_eq!(fs.read(f, 3 * PAGE as u64, &mut buf).unwrap(), 16);
        assert_eq!(buf, [0u8; 16]);
        assert_eq!(fs.read(f, 10 * PAGE as u64 + 4, &mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"\0xyz");
        // A write across a page boundary.
        fs.write(f, PAGE as u64 - 2, b"abcd").unwrap();
        assert_eq!(fs.used_bytes(), 3 * PAGE);
        assert_eq!(fs.read(f, PAGE as u64 - 2, &mut buf[..4]).unwrap(), 4);
        assert_eq!(&buf[..4], b"abcd");
        // Shrinking frees pages and zeroes the tail; growing reads zeros.
        fs.truncate(f, PAGE as u64 - 1).unwrap();
        assert_eq!(fs.used_bytes(), PAGE);
        fs.truncate(f, PAGE as u64 + 10).unwrap();
        assert_eq!(fs.read(f, PAGE as u64 - 2, &mut buf[..4]).unwrap(), 4);
        assert_eq!(&buf[..4], b"a\0\0\0");
        // The budget counts pages.
        assert_eq!(
            fs.write(f, 100 * PAGE as u64, &[0u8; 64 * PAGE]),
            Err(ENOSPC)
        );
        fs.unlink(ROOT, "f").unwrap();
        assert_eq!(fs.used_bytes(), 0);
    }

    #[test]
    fn hard_links_share_an_inode() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let src = image::SliceSource(&img);
        let mut fs = Overlay::new(&image, &src, 1 << 20).unwrap();
        let f = fs.create(ROOT, "a", 0o644).unwrap();
        fs.write(f, 0, b"shared").unwrap();
        fs.link(f, ROOT, "b").unwrap();
        assert_eq!(fs.lookup(ROOT, "b").unwrap(), f);
        assert_eq!(fs.stat(f).unwrap().nlink, 2);
        assert_eq!(fs.link(f, ROOT, "b"), Err(EEXIST));
        fs.unlink(ROOT, "a").unwrap();
        let b = fs.lookup(ROOT, "b").unwrap();
        assert_eq!(read_all(&fs, b), b"shared");
        assert_eq!(fs.stat(b).unwrap().nlink, 1);
        // A lower file can be linked without a copy-up.
        let etc = fs.lookup(ROOT, "etc").unwrap();
        let motd = fs.lookup(etc, "motd").unwrap();
        fs.link(motd, ROOT, "motd2").unwrap();
        assert_eq!(fs.stat(motd).unwrap().nlink, 2);
        assert_eq!(fs.used_bytes(), PAGE);
        // Directories cannot be hard-linked.
        assert_eq!(fs.link(etc, ROOT, "etc2"), Err(EPERM));
    }

    #[test]
    fn directory_link_counts() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let src = image::SliceSource(&img);
        let mut fs = Overlay::new(&image, &src, 1 << 20).unwrap();
        let root_links = fs.stat(ROOT).unwrap().nlink;
        let d = fs.mkdir(ROOT, "d", 0o755).unwrap();
        assert_eq!(fs.stat(ROOT).unwrap().nlink, root_links + 1);
        assert_eq!(fs.stat(d).unwrap().nlink, 2);
        fs.mkdir(d, "e", 0o755).unwrap();
        fs.create(d, "f", 0o644).unwrap();
        assert_eq!(fs.stat(d).unwrap().nlink, 3);
    }

    fn user(uid: u32, gid: u32) -> Cred {
        Cred {
            uid,
            gid,
            groups: Vec::new(),
            caps: 0,
        }
    }

    #[test]
    fn permissions_are_enforced() {
        let mut fs = Overlay::empty(1 << 20);
        let home = fs.mkdir(ROOT, "home", 0o755).unwrap();
        let bob = fs.mkdir(home, "bob", 0o700).unwrap();
        fs.chown(bob, Some(1000), Some(1000)).unwrap();
        let secret = fs.create(ROOT, "secret", 0o640).unwrap();
        fs.chown(secret, None, Some(42)).unwrap();
        let tmp = fs.mkdir(ROOT, "tmp", 0o1777).unwrap();

        // bob: his home, not root's secret unless in group 42.
        fs.set_cred(Some(user(1000, 1000)));
        assert!(fs.resolve(ROOT, "/home/bob", true).is_ok());
        let f = fs.create(bob, "notes", 0o644).unwrap();
        assert_eq!(fs.stat(f).unwrap().uid, 1000);
        assert_eq!(fs.permission(secret, MAY_READ), Err(EACCES));
        assert_eq!(fs.create(ROOT, "x", 0o644), Err(EACCES));
        assert_eq!(fs.chmod(secret, 0o777), Err(EPERM));
        assert_eq!(fs.chown(f, Some(0), None), Err(EPERM));
        assert_eq!(fs.chown(f, None, Some(42)), Err(EPERM));
        let mut grp = user(1000, 1000);
        grp.groups.push(42);
        fs.set_cred(Some(grp.clone()));
        assert_eq!(fs.permission(secret, MAY_READ), Ok(()));
        assert_eq!(fs.permission(secret, MAY_WRITE), Err(EACCES));
        assert_eq!(fs.chown(f, None, Some(42)), Ok(()));

        // Sticky /tmp: carol cannot remove bob's file.
        let t = fs.create(tmp, "bobs", 0o666).unwrap();
        assert_eq!(fs.stat(t).unwrap().uid, 1000);
        fs.set_cred(Some(user(1001, 1001)));
        assert_eq!(fs.resolve(ROOT, "/home/bob/notes", true), Err(EACCES));
        assert_eq!(fs.unlink(tmp, "bobs"), Err(EPERM));
        assert_eq!(fs.permission(t, MAY_WRITE), Ok(()));

        // root's DAC capabilities bypass the bits (but not exec of 0644).
        fs.set_cred(Some(Cred::root()));
        assert!(fs.resolve(ROOT, "/home/bob/notes", true).is_ok());
        assert_eq!(fs.permission(secret, MAY_READ | MAY_WRITE), Ok(()));
        assert_eq!(fs.permission(f, MAY_EXEC), Err(EACCES));
        assert_eq!(fs.unlink(tmp, "bobs"), Ok(()));
        fs.set_cred(None);
    }

    #[test]
    fn set_id_bits_and_setgid_directories() {
        let mut fs = Overlay::empty(1 << 20);
        let shared = fs.mkdir(ROOT, "shared", 0o2777).unwrap();
        fs.chown(shared, None, Some(50)).unwrap();
        let prog = fs.create(ROOT, "prog", 0o4755).unwrap();
        fs.chown(prog, Some(1000), None).unwrap(); // chown drops S_ISUID
        assert_eq!(fs.stat(prog).unwrap().mode, 0o755);
        fs.chmod(prog, 0o6777).unwrap();
        fs.set_cred(Some(user(1000, 1000)));
        // A write without CAP_FSETID drops set-id bits.
        fs.write(prog, 0, b"x").unwrap();
        assert_eq!(fs.stat(prog).unwrap().mode, 0o777);
        // New entries in a set-group-id directory take its group.
        let f = fs.create(shared, "f", 0o644).unwrap();
        let d = fs.mkdir(shared, "d", 0o755).unwrap();
        assert_eq!(fs.stat(f).unwrap().gid, 50);
        assert_eq!(fs.stat(d).unwrap().mode & 0o2000, 0o2000);
        fs.set_cred(None);
    }
}
