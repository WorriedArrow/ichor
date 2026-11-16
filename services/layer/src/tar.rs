//! Tar archives applied as layers into a tree, then built into an Ichor
//! image, without extracting anything to a host disk.
//!
//! Reads ustar, GNU (`L`/`K` long names) and PAX (`x`) headers. Regular
//! files, directories, symlinks and hard links are kept; device nodes and
//! FIFOs are skipped (a cell's `/dev` is synthesized). Hard links become
//! copies (the image format has no link count; dedup shares the bytes).
//! OCI whiteouts: `.wh.NAME` removes `NAME` from the layers below, and
//! `.wh..wh..opq` empties its directory of what the layers below put there.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::Result;

/// Owner, group and modification time of an entry.
#[derive(Debug, Clone, Copy, Default)]
struct Own {
    uid: u32,
    gid: u32,
    mtime: u64,
}

/// One entry of the tree being built.
#[derive(Debug, Clone)]
enum Entry {
    File {
        data: Vec<u8>,
        mode: u32,
        own: Own,
    },
    Symlink(String, Own),
    Dir {
        mode: u32,
        own: Own,
        children: BTreeMap<String, Entry>,
    },
}

/// A directory tree, assembled from tar entries in any order.
#[derive(Debug)]
pub struct Tree {
    root: Entry,
}

/// One tar member, parsed.
struct Member<'a> {
    name: String,
    kind: u8,
    link: String,
    data: &'a [u8],
    mode: u32,
    own: Own,
}

const OPAQUE: &str = ".wh..wh..opq";

fn octal(field: &[u8]) -> Result<u64> {
    let s = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .skip_while(|&&b| b == b' ');
    let mut v = 0u64;
    for &b in s {
        if !(b'0'..=b'7').contains(&b) {
            return Err(format!("tar: bad octal field {field:?}").into());
        }
        v = v.checked_mul(8).ok_or("tar: octal field overflows")? + u64::from(b - b'0');
    }
    Ok(v)
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Splits a tar path into normal components (drops `.` and leading `/`);
/// `..` is refused, so no entry lands outside the tree.
fn parts(path: &str) -> Result<Vec<&str>> {
    let ps: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if ps.contains(&"..") {
        return Err(format!("tar: {path} climbs out of the root").into());
    }
    Ok(ps)
}

fn members(tar: &[u8]) -> Result<Vec<Member<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut long_name: Option<String> = None;
    let mut long_link: Option<String> = None;
    while pos + 512 <= tar.len() {
        let h = &tar[pos..pos + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let size = usize::try_from(octal(&h[124..136])?).map_err(|_| "tar: size too large")?;
        let kind = h[156];
        let data_start = pos + 512;
        let data = data_start
            .checked_add(size)
            .and_then(|end| tar.get(data_start..end))
            .ok_or("tar: entry runs past the end")?;
        pos = data_start + size.next_multiple_of(512);
        match kind {
            b'L' => {
                long_name = Some(cstr(data));
                continue;
            }
            b'K' => {
                long_link = Some(cstr(data));
                continue;
            }
            b'x' => {
                // PAX records: "<len> key=value\n".
                let text = String::from_utf8_lossy(data);
                for rec in text.split_terminator('\n') {
                    if let Some((_, kv)) = rec.split_once(' ')
                        && let Some((k, v)) = kv.split_once('=')
                    {
                        match k {
                            "path" => long_name = Some(v.to_string()),
                            "linkpath" => long_link = Some(v.to_string()),
                            _ => {}
                        }
                    }
                }
                continue;
            }
            b'g' => continue,
            _ => {}
        }
        let name = long_name.take().unwrap_or_else(|| {
            let prefix = cstr(&h[345..500]);
            let base = cstr(&h[0..100]);
            if &h[257..262] == b"ustar" && !prefix.is_empty() {
                format!("{prefix}/{base}")
            } else {
                base
            }
        });
        let link = long_link.take().unwrap_or_else(|| cstr(&h[157..257]));
        out.push(Member {
            name,
            kind,
            link,
            data,
            mode: (octal(&h[100..108])? & 0o7777) as u32,
            own: Own {
                uid: octal(&h[108..116])? as u32,
                gid: octal(&h[116..124])? as u32,
                mtime: octal(&h[136..148])?,
            },
        });
    }
    Ok(out)
}

impl Tree {
    pub fn new() -> Tree {
        Tree {
            root: Entry::Dir {
                mode: 0o755,
                own: Own::default(),
                children: BTreeMap::new(),
            },
        }
    }

    /// The directory at `path`, created (mode 0755) if missing.
    fn dir_mut(&mut self, path: &[&str]) -> Result<&mut BTreeMap<String, Entry>> {
        let mut cur = &mut self.root;
        for p in path {
            let Entry::Dir { children, .. } = cur else {
                return Err(format!("tar: {p} is under a non-directory").into());
            };
            cur = children
                .entry((*p).to_string())
                .or_insert_with(|| Entry::Dir {
                    mode: 0o755,
                    own: Own::default(),
                    children: BTreeMap::new(),
                });
        }
        match cur {
            Entry::Dir { children, .. } => Ok(children),
            _ => Err("tar: path component is not a directory".into()),
        }
    }

    /// The existing directory at `path`, if it is one.
    fn existing_dir_mut(&mut self, path: &[&str]) -> Option<&mut BTreeMap<String, Entry>> {
        let mut cur = &mut self.root;
        for p in path {
            match cur {
                Entry::Dir { children, .. } => cur = children.get_mut(*p)?,
                _ => return None,
            }
        }
        match cur {
            Entry::Dir { children, .. } => Some(children),
            _ => None,
        }
    }

    fn get(&self, path: &[&str]) -> Option<&Entry> {
        let mut cur = &self.root;
        for p in path {
            match cur {
                Entry::Dir { children, .. } => cur = children.get(*p)?,
                _ => return None,
            }
        }
        Some(cur)
    }

    fn put(&mut self, path: &str, e: Entry) -> Result<()> {
        let ps = parts(path)?;
        let Some((last, dirs)) = ps.split_last() else {
            // The root itself: keep its mode and owner if it is a directory.
            if let (
                Entry::Dir { mode, own, .. },
                Entry::Dir {
                    mode: m, own: o, ..
                },
            ) = (&e, &mut self.root)
            {
                *m = *mode;
                *o = *own;
            }
            return Ok(());
        };
        let parent = self.dir_mut(dirs)?;
        match (parent.get_mut(*last), e) {
            // A directory entry after its contents: keep them, take the
            // mode and owner.
            (
                Some(Entry::Dir { mode, own, .. }),
                Entry::Dir {
                    mode: m, own: o, ..
                },
            ) => {
                *mode = m;
                *own = o;
            }
            (_, e) => {
                parent.insert((*last).to_string(), e);
            }
        }
        Ok(())
    }

    /// Applies one layer (an uncompressed tar archive) on top of the tree:
    /// its whiteouts first, against the layers below, then its entries in
    /// order (a later entry replaces an earlier one).
    pub fn add_tar(&mut self, tar: &[u8]) -> Result<()> {
        self.apply(members(tar)?)
    }

    /// [`Tree::add_tar`] for an archive that is not an image layer (a
    /// source release): only its entries under `from` are applied, moved
    /// to `to` (`Python-3.12.7/Lib/` to `usr/local/lib/python3.12/`, say).
    /// Hard link targets move with them.
    pub fn add_tar_at(&mut self, tar: &[u8], from: &str, to: &str) -> Result<()> {
        let norm = |s: &str| {
            s.trim_start_matches("./")
                .trim_start_matches('/')
                .to_string()
        };
        let (from, to) = (norm(from), norm(to));
        let moved = |name: &str| -> Option<String> {
            let rest = norm(name).strip_prefix(from.as_str())?.to_string();
            let joined = if to.is_empty() || to.ends_with('/') || rest.is_empty() {
                format!("{to}{rest}")
            } else {
                format!("{to}/{rest}")
            };
            (!joined.is_empty()).then_some(joined)
        };
        let mut ms = Vec::new();
        for mut m in members(tar)? {
            let Some(name) = moved(&m.name) else {
                continue;
            };
            m.name = name;
            if m.kind == b'1' {
                m.link = moved(&m.link)
                    .ok_or_else(|| format!("tar: hard link {} leaves {from}", m.name))?;
            }
            ms.push(m);
        }
        self.apply(ms)
    }

    fn apply(&mut self, ms: Vec<Member<'_>>) -> Result<()> {
        for m in &ms {
            let ps = parts(&m.name)?;
            let Some((base, dir)) = ps.split_last() else {
                continue;
            };
            if *base == OPAQUE {
                if let Some(children) = self.existing_dir_mut(dir) {
                    children.clear();
                }
            } else if let Some(hidden) = base.strip_prefix(".wh.")
                && let Some(children) = self.existing_dir_mut(dir)
            {
                children.remove(hidden);
            }
        }
        for m in ms {
            let base = m.name.rsplit('/').find(|c| !c.is_empty()).unwrap_or("");
            if base.starts_with(".wh.") {
                continue;
            }
            let (mode, own) = (m.mode, m.own);
            match m.kind {
                b'0' | 0 | b'7' => self.put(
                    &m.name,
                    Entry::File {
                        data: m.data.to_vec(),
                        mode,
                        own,
                    },
                )?,
                b'5' => self.put(
                    &m.name,
                    Entry::Dir {
                        mode,
                        own,
                        children: BTreeMap::new(),
                    },
                )?,
                b'2' => self.put(&m.name, Entry::Symlink(m.link, own))?,
                b'1' => {
                    let target = self.get(&parts(&m.link)?).cloned().ok_or_else(|| {
                        format!("tar: hard link {} -> missing {}", m.name, m.link)
                    })?;
                    self.put(&m.name, target)?;
                }
                // Character/block devices and FIFOs: synthesized at run time.
                b'3' | b'4' | b'6' => {}
                other => {
                    return Err(format!(
                        "tar: unsupported entry type {:?} for {}",
                        other as char, m.name
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    /// Adds a regular file at `path` (creating parent directories).
    pub fn add_file(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        self.put(
            path,
            Entry::File {
                data: data.to_vec(),
                mode,
                own: Own::default(),
            },
        )
    }

    /// Builds the Ichor image (padded to whole 4 KiB blocks).
    pub fn image(&self) -> Vec<u8> {
        fn emit(b: &mut image::builder::Builder, name: &str, e: &Entry) -> image::builder::NodeId {
            let (id, own) = match e {
                Entry::File { data, mode, own } => (b.file(name, data, *mode), own),
                Entry::Symlink(t, own) => (b.symlink(name, t), own),
                Entry::Dir {
                    mode,
                    own,
                    children,
                } => {
                    let ids: Vec<_> = children.iter().map(|(n, c)| emit(b, n, c)).collect();
                    (b.dir(name, &ids, *mode), own)
                }
            };
            b.set_owner(id, own.uid, own.gid, own.mtime);
            id
        }
        let mut b = image::builder::Builder::new();
        let root = emit(&mut b, "/", &self.root);
        let mut img = b.finish(root);
        img.resize(img.len().next_multiple_of(4096), 0);
        img
    }
}

impl Default for Tree {
    fn default() -> Self {
        Tree::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Builds a ustar header block plus data.
    fn entry(name: &str, kind: u8, link: &str, data: &[u8], mode: u32) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        h[156] = kind;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        let mut out = h;
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(512), 0);
        out
    }

    fn read(img: &[u8], path: &str) -> Option<Vec<u8>> {
        let image = image::Image::mount(img).ok()?;
        let node = image.lookup(path)?;
        let mut buf = vec![0u8; node.size() as usize];
        node.read_at(0, &mut buf, &image::SliceSource(img)).ok()?;
        Some(buf)
    }

    #[test]
    fn builds_an_image_from_a_tar() {
        let mut tar = Vec::new();
        tar.extend(entry("./", b'5', "", b"", 0o755));
        tar.extend(entry("./etc/motd", b'0', "", b"hi\n", 0o644)); // parent implied
        tar.extend(entry("./etc/", b'5', "", b"", 0o700)); // after its contents
        tar.extend(entry("./bin/busybox", b'0', "", b"\x7fELF", 0o755));
        tar.extend(entry("./bin/sh", b'2', "busybox", b"", 0o777));
        tar.extend(entry("./bin/hard", b'1', "./bin/busybox", b"", 0o755));
        tar.extend(entry("./dev/null", b'3', "", b"", 0o666));
        tar.extend(vec![0u8; 1024]);

        let mut t = Tree::new();
        t.add_tar(&tar).unwrap();
        let img = t.image();
        assert_eq!(read(&img, "/etc/motd").unwrap(), b"hi\n");
        let image = image::Image::mount(&img).unwrap();
        assert_eq!(image.lookup("/etc").unwrap().mode & 0o777, 0o700);
        assert_eq!(
            image.lookup("/bin/sh").unwrap().symlink_target(),
            Some("busybox")
        );
        assert_eq!(image.lookup("/bin/hard").unwrap().size(), 4);
        assert!(image.lookup("/dev/null").is_none());
    }

    #[test]
    fn a_subtree_of_an_archive_moves_into_place() {
        let mut src = Vec::new();
        src.extend(entry("Python-3.12.7/", b'5', "", b"", 0o755));
        src.extend(entry("Python-3.12.7/README", b'0', "", b"no", 0o644));
        src.extend(entry(
            "Python-3.12.7/Lib/test/test_os.py",
            b'0',
            "",
            b"os",
            0o644,
        ));
        src.extend(entry(
            "Python-3.12.7/Lib/test/same.py",
            b'1',
            "Python-3.12.7/Lib/test/test_os.py",
            b"",
            0o644,
        ));
        src.extend(vec![0u8; 1024]);
        let mut t = Tree::new();
        t.add_file("usr/local/lib/python3.12/os.py", b"base", 0o644)
            .unwrap();
        t.add_tar_at(&src, "Python-3.12.7/Lib/", "/usr/local/lib/python3.12/")
            .unwrap();
        let img = t.image();
        let lib = "/usr/local/lib/python3.12";
        assert_eq!(
            read(&img, &format!("{lib}/test/test_os.py")).unwrap(),
            b"os"
        );
        assert_eq!(read(&img, &format!("{lib}/test/same.py")).unwrap(), b"os");
        assert_eq!(read(&img, &format!("{lib}/os.py")).unwrap(), b"base");
        assert!(read(&img, "/README").is_none() && read(&img, &format!("{lib}/README")).is_none());
        // A hard link out of the subtree is refused.
        let mut bad = entry("a/x", b'1', "b/y", b"", 0o644);
        bad.extend(vec![0u8; 1024]);
        assert!(Tree::new().add_tar_at(&bad, "a/", "c/").is_err());
    }

    #[test]
    fn long_names() {
        let long = format!("./{}/file", "d".repeat(150));
        let mut tar = entry("././@LongLink", b'L', "", format!("{long}\0").as_bytes(), 0);
        tar.extend(entry("truncated", b'0', "", b"x", 0o644));
        tar.extend(vec![0u8; 1024]);
        let mut t = Tree::new();
        t.add_tar(&tar).unwrap();
        let img = t.image();
        let image = image::Image::mount(&img).unwrap();
        assert!(image.lookup(&long[1..]).is_some());
    }

    #[test]
    fn whiteouts_hide_lower_layers_only() {
        let mut lower = Vec::new();
        lower.extend(entry("etc/keep", b'0', "", b"k", 0o644));
        lower.extend(entry("etc/gone", b'0', "", b"g", 0o644));
        lower.extend(entry("var/cache/a", b'0', "", b"a", 0o644));
        lower.extend(entry("var/cache/b", b'0', "", b"b", 0o644));
        lower.extend(vec![0u8; 1024]);
        let mut upper = Vec::new();
        // The new file comes before the opaque marker in the archive: the
        // marker still only empties what the lower layer had.
        upper.extend(entry("var/cache/new", b'0', "", b"n", 0o644));
        upper.extend(entry("var/cache/.wh..wh..opq", b'0', "", b"", 0o644));
        upper.extend(entry("etc/.wh.gone", b'0', "", b"", 0o644));
        upper.extend(vec![0u8; 1024]);
        let mut t = Tree::new();
        t.add_tar(&lower).unwrap();
        t.add_tar(&upper).unwrap();
        let img = t.image();
        assert_eq!(read(&img, "/etc/keep").unwrap(), b"k");
        assert!(read(&img, "/etc/gone").is_none());
        assert!(read(&img, "/etc/.wh.gone").is_none());
        assert!(read(&img, "/var/cache/a").is_none());
        assert_eq!(read(&img, "/var/cache/new").unwrap(), b"n");
        assert!(read(&img, "/var/cache/.wh..wh..opq").is_none());
    }

    #[test]
    fn hostile_archives_are_errors() {
        let mut climb = entry("../../etc/passwd", b'0', "", b"x", 0o644);
        climb.extend(vec![0u8; 1024]);
        assert!(Tree::new().add_tar(&climb).is_err());
        let mut short = entry("big", b'0', "", &[7u8; 1000], 0o644);
        short.truncate(700);
        assert!(Tree::new().add_tar(&short).is_err());
        let mut bad = entry("x", b'0', "", b"", 0o644);
        bad[124] = b'9';
        assert!(Tree::new().add_tar(&bad).is_err());
    }
}
