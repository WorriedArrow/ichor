//! Charged pages: frames that count against a cell's account for as long
//! as anything holds them. Process memory (`umem`) and the files of a
//! cell's root (`vfs`) are made of the same pages, so a shared file mapping
//! maps the file's own page.

use alloc::sync::Arc;

use cell::Account;
use frame::mm::UFrame;

/// A resident page with its one charge to the account it was made under
/// (none, for a root no cell owns). Address spaces and files share it, and
/// the charge is released when the last of them lets go: a page counts once
/// however many processes of the cell map it, as on Linux, where a forked
/// child costs only the pages it copies.
#[derive(Debug)]
pub(crate) struct Charged {
    frame: UFrame,
    account: Option<Arc<Account>>,
}

impl Drop for Charged {
    fn drop(&mut self) {
        if let Some(a) = &self.account {
            a.release(1);
        }
    }
}

impl core::ops::Deref for Charged {
    type Target = UFrame;
    fn deref(&self) -> &UFrame {
        &self.frame
    }
}

pub(crate) type Page = Arc<Charged>;

/// Charges `account` for `frame`, or `None` if it is full.
pub(crate) fn charged(account: &Arc<Account>, frame: UFrame) -> Option<Page> {
    account.charge(1).ok()?;
    Some(Arc::new(Charged {
        frame,
        account: Some(account.clone()),
    }))
}

/// Where a root's written files get their pages: the owning cell's account
/// (a root without one is bounded by its byte budget alone).
#[derive(Debug)]
pub(crate) struct RootPages {
    account: Option<Arc<Account>>,
    /// Charged for the root's inodes and names.
    kept: usize,
}

impl RootPages {
    pub(crate) fn new(account: Option<Arc<Account>>) -> RootPages {
        RootPages { account, kept: 0 }
    }
}

impl Drop for RootPages {
    fn drop(&mut self) {
        overlay::Pages::keep(self, 0);
    }
}

/// A page of a written file.
#[derive(Clone, Debug)]
pub(crate) struct FilePage(pub(crate) Page);

impl overlay::Pages for RootPages {
    type Page = FilePage;

    fn alloc(&self) -> Option<FilePage> {
        let frame = UFrame::alloc_zeroed()?;
        let page = match &self.account {
            Some(a) => charged(a, frame)?,
            None => Arc::new(Charged {
                frame,
                account: None,
            }),
        };
        Some(FilePage(page))
    }

    fn keep(&mut self, pages: usize) -> bool {
        if let Some(a) = &self.account {
            if pages > self.kept && a.charge((pages - self.kept) as u64).is_err() {
                return false;
            }
            a.release(self.kept.saturating_sub(pages) as u64);
        }
        self.kept = pages;
        true
    }
}

/// Pages of kernel memory charged to an account for as long as this lives
/// (a thread's stack and bookkeeping).
#[derive(Debug)]
pub(crate) struct Reserved {
    account: Arc<Account>,
    pages: u64,
}

impl Reserved {
    /// Charges `pages`, or `None` if the account is full.
    pub(crate) fn new(account: &Arc<Account>, pages: u64) -> Option<Reserved> {
        account.charge(pages).ok()?;
        Some(Reserved {
            account: account.clone(),
            pages,
        })
    }

    /// Charges for `pages` from now on; false (and nothing changes) if the
    /// account cannot pay for more.
    pub(crate) fn resize(&mut self, pages: u64) -> bool {
        if pages > self.pages && self.account.charge(pages - self.pages).is_err() {
            return false;
        }
        self.account.release(self.pages.saturating_sub(pages));
        self.pages = pages;
        true
    }
}

impl Drop for Reserved {
    fn drop(&mut self) {
        self.account.release(self.pages);
    }
}

impl overlay::Page for FilePage {
    fn read(&self, at: usize, out: &mut [u8]) {
        let mut r = self.0.reader();
        r.skip(at);
        r.read(out);
    }

    fn write(&self, at: usize, data: &[u8]) {
        let mut w = self.0.writer();
        w.skip(at);
        w.write(data);
    }
}
