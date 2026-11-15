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

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use image::{Image, Node};

/// Linux errno values.
pub mod errno {
    pub const ENOENT: i64 = 2;
    pub const EEXIST: i64 = 17;
    pub const ENOTDIR: i64 = 20;
    pub const EISDIR: i64 = 21;
    pub const EINVAL: i64 = 22;
    pub const EFBIG: i64 = 27;
    pub const ENOSPC: i64 = 28;
    pub const ENAMETOOLONG: i64 = 36;
    pub const ENOTEMPTY: i64 = 39;
    pub const ELOOP: i64 = 40;
}
use errno::*;

/// An inode number (index into the overlay's table).
pub type Ino = usize;

/// The root directory.
pub const ROOT: Ino = 0;
/// Longest path accepted.
pub const PATH_MAX: usize = 4096;
/// Longest name accepted.
pub const NAME_MAX: usize = 255;
/// Largest file the upper layer holds.
pub const MAX_FILE: usize = 64 << 20;
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

#[derive(Debug)]
enum Data<'a> {
    LowerFile(Node<'a>),
    File(Vec<u8>),
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
    Inode {
        data,
        mode: node.mode & 0o7777,
        nlink: 1,
        opens: 0,
    }
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
    /// An overlay over `lower` whose upper layer may hold `max_bytes`.
    pub fn new(lower: &Image<'a>, max_bytes: usize) -> Result<Overlay<'a>, image::Error> {
        let root = lower.root()?;
        let mut fs = Overlay::empty(max_bytes);
        if let Some(Some(r)) = fs.inodes.get_mut(ROOT) {
            r.data = upper_dir(ROOT, Some(root));
            r.mode = root.mode & 0o7777;
        }
        Ok(fs)
    }

    /// An overlay with no lower layer (a `tmpfs`).
    pub fn empty(max_bytes: usize) -> Overlay<'a> {
        Overlay {
            inodes: alloc::vec![Some(Inode {
                data: upper_dir(ROOT, None),
                mode: 0o755,
                nlink: 2,
                opens: 0,
            })],
            free: Vec::new(),
            used_bytes: 0,
            max_bytes,
        }
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
                data: Data::File(v),
                ..
            }) = slot.take()
        {
            self.used_bytes -= v.len();
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
            Data::File(v) => v.len() as u64,
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
                2
            } else {
                i.nlink
            },
            rdev,
        })
    }

    /// Reads file bytes at `offset`; returns how many were read.
    pub fn read(&self, ino: Ino, offset: u64, out: &mut [u8]) -> Result<usize, i64> {
        match &self.get(ino)?.data {
            Data::LowerFile(n) => Ok(n.read_at(offset, out)),
            Data::File(v) => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(v.len());
                let n = out.len().min(v.len() - start);
                out[..n].copy_from_slice(&v[start..start + n]);
                Ok(n)
            }
            Data::Dir(_) => Err(EISDIR),
            Data::Symlink(_) | Data::Device(_) => Err(EINVAL),
        }
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
        if self.used_bytes + size > self.max_bytes {
            return Err(ENOSPC);
        }
        let mut v = alloc::vec![0u8; size];
        let n = node.read_at(0, &mut v);
        v.truncate(n);
        self.used_bytes += v.len();
        self.get_mut(ino)?.data = Data::File(v);
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
            self.get_mut(ino)?.data = Data::File(Vec::new());
            return Ok(());
        }
        self.copy_up(ino)?;
        let used = self.used_bytes;
        let max = self.max_bytes;
        let Data::File(v) = &mut self.get_mut(ino)?.data else {
            return Err(EINVAL);
        };
        if len > v.len() && used + (len - v.len()) > max {
            return Err(ENOSPC);
        }
        let old = v.len();
        v.resize(len, 0);
        self.used_bytes = used - old + len;
        Ok(())
    }

    /// Writes `data` at `offset` (zero-filling any gap); returns its length.
    pub fn write(&mut self, ino: Ino, offset: u64, data: &[u8]) -> Result<usize, i64> {
        self.copy_up(ino)?;
        let off = usize::try_from(offset).map_err(|_| EFBIG)?;
        let end = off.checked_add(data.len()).ok_or(EFBIG)?;
        if end > MAX_FILE {
            return Err(EFBIG);
        }
        let used = self.used_bytes;
        let max = self.max_bytes;
        let Data::File(v) = &mut self.get_mut(ino)?.data else {
            return Err(EINVAL);
        };
        let grow = end.saturating_sub(v.len());
        if used + grow > max {
            return Err(ENOSPC);
        }
        if grow > 0 {
            v.resize(end, 0);
        }
        v[off..end].copy_from_slice(data);
        self.used_bytes = used + grow;
        Ok(data.len())
    }

    /// Changes permission bits.
    pub fn chmod(&mut self, ino: Ino, mode: u32) -> Result<(), i64> {
        self.get_mut(ino)?.mode = mode & 0o7777;
        Ok(())
    }

    fn add(&mut self, dir: Ino, name: &str, inode: Inode<'a>) -> Result<Ino, i64> {
        check_name(name)?;
        self.dir(dir)?;
        if self.find(dir, name)?.is_some() {
            return Err(EEXIST);
        }
        let ino = self.alloc(inode);
        self.dir_mut(dir)?
            .entries
            .insert(name.to_string(), Entry::Ino(ino));
        Ok(ino)
    }

    /// Creates an empty file.
    pub fn create(&mut self, dir: Ino, name: &str, mode: u32) -> Result<Ino, i64> {
        let inode = Inode {
            data: Data::File(Vec::new()),
            mode: mode & 0o7777,
            nlink: 1,
            opens: 0,
        };
        self.add(dir, name, inode)
    }

    /// Creates an empty directory.
    pub fn mkdir(&mut self, dir: Ino, name: &str, mode: u32) -> Result<Ino, i64> {
        let inode = Inode {
            data: upper_dir(dir, None),
            mode: mode & 0o7777,
            nlink: 1,
            opens: 0,
        };
        self.add(dir, name, inode)
    }

    /// Creates a character device node.
    pub fn mknod(&mut self, dir: Ino, name: &str, mode: u32, rdev: u32) -> Result<Ino, i64> {
        let inode = Inode {
            data: Data::Device(rdev),
            mode: mode & 0o7777,
            nlink: 1,
            opens: 0,
        };
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
        let inode = Inode {
            data: Data::Symlink(target.to_string()),
            mode: 0o777,
            nlink: 1,
            opens: 0,
        };
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
        if let Some(dst) = self.find(ndir, nname)? {
            if dst == src {
                return Ok(());
            }
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
        let mut fs = Overlay::new(&image, 1 << 20).unwrap();
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
        let mut fs = Overlay::new(&image, 1 << 20).unwrap();
        let motd = fs.resolve(ROOT, "/etc/motd", true).unwrap();
        assert_eq!(fs.write(motd, 0, b"UPPER").unwrap(), 5);
        assert_eq!(read_all(&fs, motd), b"UPPER motd\n");
        assert_eq!(fs.used_bytes(), 11);
        // A second overlay over the same image still sees the original.
        let mut other = Overlay::new(&image, 1 << 20).unwrap();
        let m2 = other.resolve(ROOT, "/etc/motd", true).unwrap();
        assert_eq!(read_all(&other, m2), b"lower motd\n");
        // Writing past the end zero-fills; truncate shrinks.
        fs.write(motd, 13, b"!").unwrap();
        assert_eq!(read_all(&fs, motd), b"UPPER motd\n\0\0!");
        fs.truncate(motd, 5).unwrap();
        assert_eq!(read_all(&fs, motd), b"UPPER");
        assert_eq!(fs.used_bytes(), 5);
    }

    #[test]
    fn create_unlink_and_whiteouts() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let mut fs = Overlay::new(&image, 1 << 20).unwrap();
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
        assert_eq!(fs.used_bytes(), 4);
        fs.close(f);
        assert_eq!(fs.used_bytes(), 0);
        assert!(fs.stat(f).is_err());
    }

    #[test]
    fn directories() {
        let img = lower_image();
        let image = Image::mount(&img).unwrap();
        let mut fs = Overlay::new(&image, 1 << 20).unwrap();
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
        let mut fs = Overlay::new(&image, 1 << 20).unwrap();
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
    fn budgets() {
        let mut fs = Overlay::empty(10);
        let f = fs.create(ROOT, "f", 0o644).unwrap();
        assert_eq!(fs.write(f, 0, b"0123456789"), Ok(10));
        assert_eq!(fs.write(f, 10, b"x"), Err(ENOSPC));
        assert_eq!(fs.truncate(f, 11), Err(ENOSPC));
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
}
