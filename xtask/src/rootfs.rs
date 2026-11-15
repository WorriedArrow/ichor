//! Turning a root file system tarball (an OCI layer, Alpine's minirootfs,
//! ...) into an Ichor image, without extracting anything to the host's
//! disk (which would mangle symlinks and modes on Windows).
//!
//! Reads ustar, GNU (`L`/`K` long names) and PAX (`x`) headers. Regular
//! files, directories, symlinks and hard links are kept; device nodes and
//! FIFOs are skipped (a cell's `/dev` is synthesized). Hard links become
//! copies (the image format has no link count; dedup shares the bytes).

use std::collections::BTreeMap;

use crate::Result;

/// One entry of the tree being built.
#[derive(Debug, Clone)]
enum Entry {
    File {
        data: Vec<u8>,
        mode: u32,
    },
    Symlink(String),
    Dir {
        mode: u32,
        children: BTreeMap<String, Entry>,
    },
}

/// A directory tree, assembled from tar entries in any order.
#[derive(Debug)]
pub struct Tree {
    root: Entry,
}

fn octal(field: &[u8]) -> Result<u64> {
    let s = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .skip_while(|&&b| b == b' ');
    let mut v = 0u64;
    for &b in s {
        if !(b'0'..=b'7').contains(&b) {
            return Err(format!("tar: bad octal field {field:?}"));
        }
        v = v * 8 + u64::from(b - b'0');
    }
    Ok(v)
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Splits a tar path into normal components (drops `.` and leading `/`).
fn parts(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect()
}

impl Tree {
    pub fn new() -> Tree {
        Tree {
            root: Entry::Dir {
                mode: 0o755,
                children: BTreeMap::new(),
            },
        }
    }

    /// The directory at `path`, created (mode 0755) if missing.
    fn dir_mut(&mut self, path: &[&str]) -> Result<&mut BTreeMap<String, Entry>> {
        let mut cur = &mut self.root;
        for p in path {
            let Entry::Dir { children, .. } = cur else {
                return Err(format!("tar: {p} is under a non-directory"));
            };
            cur = children
                .entry((*p).to_string())
                .or_insert_with(|| Entry::Dir {
                    mode: 0o755,
                    children: BTreeMap::new(),
                });
        }
        match cur {
            Entry::Dir { children, .. } => Ok(children),
            _ => Err("tar: path component is not a directory".into()),
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
        let ps = parts(path);
        let Some((last, dirs)) = ps.split_last() else {
            // The root itself: keep its mode if it is a directory entry.
            if let (Entry::Dir { mode, .. }, Entry::Dir { mode: m, .. }) = (&e, &mut self.root) {
                *m = *mode;
            }
            return Ok(());
        };
        let parent = self.dir_mut(dirs)?;
        match (parent.get_mut(*last), e) {
            // A directory entry after its contents: keep them, take the mode.
            (Some(Entry::Dir { mode, .. }), Entry::Dir { mode: m, .. }) => *mode = m,
            (_, e) => {
                parent.insert((*last).to_string(), e);
            }
        }
        Ok(())
    }

    /// Adds every entry of an uncompressed tar archive. Later entries
    /// replace earlier ones (as when unpacking layers in order).
    pub fn add_tar(&mut self, tar: &[u8]) -> Result<()> {
        let mut pos = 0;
        let mut long_name: Option<String> = None;
        let mut long_link: Option<String> = None;
        while pos + 512 <= tar.len() {
            let h = &tar[pos..pos + 512];
            if h.iter().all(|&b| b == 0) {
                break;
            }
            let size = octal(&h[124..136])? as usize;
            let kind = h[156];
            let data_start = pos + 512;
            let data = tar
                .get(data_start..data_start + size)
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
            let mode = (octal(&h[100..108])? & 0o7777) as u32;
            match kind {
                b'0' | 0 | b'7' => self.put(
                    &name,
                    Entry::File {
                        data: data.to_vec(),
                        mode,
                    },
                )?,
                b'5' => self.put(
                    &name,
                    Entry::Dir {
                        mode,
                        children: BTreeMap::new(),
                    },
                )?,
                b'2' => self.put(&name, Entry::Symlink(link))?,
                b'1' => {
                    let target = self
                        .get(&parts(&link))
                        .cloned()
                        .ok_or_else(|| format!("tar: hard link {name} -> missing {link}"))?;
                    self.put(&name, target)?;
                }
                // Character/block devices and FIFOs: synthesized at run time.
                b'3' | b'4' | b'6' => {}
                other => {
                    return Err(format!(
                        "tar: unsupported entry type {:?} for {name}",
                        other as char
                    ));
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
            },
        )
    }

    /// Builds the Ichor image (padded to whole 4 KiB blocks).
    pub fn image(&self) -> Vec<u8> {
        fn emit(b: &mut image::builder::Builder, name: &str, e: &Entry) -> image::builder::NodeId {
            match e {
                Entry::File { data, mode } => b.file(name, data, *mode),
                Entry::Symlink(t) => b.symlink(name, t),
                Entry::Dir { mode, children } => {
                    let ids: Vec<_> = children.iter().map(|(n, c)| emit(b, n, c)).collect();
                    b.dir(name, &ids, *mode)
                }
            }
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
        let image = image::Image::mount(&img).unwrap();
        let motd = image.lookup("/etc/motd").unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(motd.read_at(0, &mut buf, &image::SliceSource(&img)), Ok(3));
        assert_eq!(&buf, b"hi\n");
        assert_eq!(image.lookup("/etc").unwrap().mode & 0o777, 0o700);
        assert_eq!(
            image.lookup("/bin/sh").unwrap().symlink_target(),
            Some("busybox")
        );
        assert_eq!(image.lookup("/bin/hard").unwrap().size(), 4);
        assert!(image.lookup("/dev/null").is_none());
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
}
