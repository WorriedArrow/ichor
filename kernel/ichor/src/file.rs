//! Files as the loader and file mappings see them: a length, positioned
//! reads, and (for an unmodified lower-layer file) the page cache's own
//! verified page for a file page, which they map copy-on-write instead of
//! copying.

use alloc::sync::Arc;

use frame::mm::UFrame;

use crate::page::Page;
use crate::vfs::{Ino, Vfs};

/// A file's bytes.
pub(crate) trait File: Send + Sync {
    /// Length in bytes.
    fn size(&self) -> u64;
    /// Copies bytes at `offset` into `out`; returns how many (short at EOF).
    fn read_at(&self, offset: u64, out: &mut [u8]) -> usize;
    /// The cache page holding file page `index` (bytes `[index * 4096, +4096)`,
    /// zero past the end), if the page cache can serve it. The page is
    /// never written; callers map it read-only and copy on write.
    fn cached_page(&self, _index: u64) -> Option<UFrame> {
        None
    }
    /// The file's own page `index`, for a shared mapping (`write`: to be
    /// written through it). `None`: the file is the image's and unwritten,
    /// or cannot be shared at all. `Err`: there is no such page (past the
    /// end of the file), or no memory for it.
    fn shared_page(&self, _index: u64, _write: bool) -> Result<Option<Page>, i64> {
        Ok(None)
    }
    /// A reference to this file that a mapping can keep for as long as it
    /// lives, so its pages can be filled on demand (`None`: the caller must
    /// copy what it needs now, as for bytes it holds).
    fn mappable(&self) -> Option<Arc<dyn File>> {
        None
    }
}

/// Bytes in memory (self-test programs).
pub(crate) struct Bytes<'a>(pub(crate) &'a [u8]);

impl File for Bytes<'_> {
    fn size(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> usize {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.0.len());
        let n = out.len().min(self.0.len() - start);
        out[..n].copy_from_slice(&self.0[start..start + n]);
        n
    }
}

/// A file on a root, held open (so it outlives an unlink) for as long as
/// this lives.
pub(crate) struct VfsFile {
    vfs: Arc<Vfs>,
    ino: Ino,
}

impl VfsFile {
    /// Opens `ino` on `vfs`.
    pub(crate) fn open(vfs: &Arc<Vfs>, ino: Ino) -> Result<VfsFile, i64> {
        vfs.lock().open(ino)?;
        Ok(VfsFile {
            vfs: vfs.clone(),
            ino,
        })
    }

    /// A path of the file in its root.
    pub(crate) fn path(&self) -> Option<alloc::string::String> {
        self.vfs.lock().path(self.ino).ok()
    }
}

impl Drop for VfsFile {
    fn drop(&mut self) {
        self.vfs.lock().close(self.ino);
    }
}

impl File for VfsFile {
    fn size(&self) -> u64 {
        self.vfs.lock().stat(self.ino).map(|s| s.size).unwrap_or(0)
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> usize {
        self.vfs.read(self.ino, offset, out).unwrap_or(0)
    }

    fn cached_page(&self, index: u64) -> Option<UFrame> {
        self.vfs.cached_page(self.ino, index)
    }

    fn shared_page(&self, index: u64, write: bool) -> Result<Option<Page>, i64> {
        let page = self.vfs.lock().page(self.ino, index, write)?;
        Ok(page.map(|p| p.0))
    }

    fn mappable(&self) -> Option<Arc<dyn File>> {
        // A new open reference: the mapping keeps the file alive (even
        // after an unlink) independently of this handle.
        VfsFile::open(&self.vfs, self.ino)
            .ok()
            .map(|f| Arc::new(f) as Arc<dyn File>)
    }
}
