//! The virtual file system, milestone 3 slice: a read-only root mounted from
//! an Ichor image.
//!
//! Path resolution walks the image's directories, handles `.` and `..`, and
//! follows symbolic links (absolute and relative) with a bounded hop count,
//! as Linux does (`ELOOP` after 40). The copy-on-write upper layer and volume
//! mounts are the next steps; they sit on top of this resolver.

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use image::{Image, Kind, Node};

/// Linux errno values the VFS can return.
pub(crate) mod errno {
    pub(crate) const ENOENT: i64 = 2;
    pub(crate) const ENOTDIR: i64 = 20;
    pub(crate) const ENAMETOOLONG: i64 = 36;
    pub(crate) const ELOOP: i64 = 40;
}

/// Most symlinks followed while resolving one path.
const MAX_SYMLINK_HOPS: u32 = 40;
/// Longest path accepted.
pub(crate) const PATH_MAX: usize = 4096;

/// A mounted root file system.
#[derive(Debug)]
pub(crate) struct Vfs {
    root: Image<'static>,
}

impl Vfs {
    /// Mounts `bytes` (an Ichor image that lives for the life of the system)
    /// as the root.
    pub(crate) fn mount(bytes: &'static [u8]) -> Result<Vfs, image::Error> {
        let root = Image::mount(bytes)?;
        root.root()?;
        Ok(Vfs { root })
    }

    /// Resolves `path` (relative paths resolve from `/`, the only working
    /// directory so far). With `follow_last`, a symlink in the final
    /// component is followed too (`stat` vs `lstat`).
    pub(crate) fn resolve(&self, path: &str, follow_last: bool) -> Result<Node<'static>, i64> {
        if path.len() > PATH_MAX {
            return Err(errno::ENAMETOOLONG);
        }
        let root = self.root.root().map_err(|_| errno::ENOENT)?;
        let mut stack: Vec<Node<'static>> = alloc::vec![root];
        let mut pending: VecDeque<String> = components(path).collect();
        let mut hops = 0;
        while let Some(comp) = pending.pop_front() {
            match comp.as_str() {
                "." => continue,
                ".." => {
                    if stack.len() > 1 {
                        stack.pop();
                    }
                    continue;
                }
                _ => {}
            }
            let Some(&cur) = stack.last() else {
                return Err(errno::ENOENT);
            };
            if cur.kind() != Kind::Directory {
                return Err(errno::ENOTDIR);
            }
            let child = cur.child(&comp).ok_or(errno::ENOENT)?;
            let is_last = pending.is_empty();
            if child.kind() == Kind::Symlink && (follow_last || !is_last) {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(errno::ELOOP);
                }
                let target = child.symlink_target().unwrap_or("");
                if target.starts_with('/') {
                    stack.truncate(1);
                }
                for (i, c) in components(target).enumerate() {
                    pending.insert(i, c);
                }
                continue;
            }
            stack.push(child);
        }
        stack.last().copied().ok_or(errno::ENOENT)
    }
}

fn components(path: &str) -> impl Iterator<Item = String> + '_ {
    path.split('/')
        .filter(|c| !c.is_empty())
        .map(ToString::to_string)
}
