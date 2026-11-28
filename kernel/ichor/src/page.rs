//! Charged pages: frames that count against a cell's account for as long
//! as anything holds them. Process memory (`umem`) and the files of a
//! cell's root (`vfs`) are made of the same pages, so a shared file mapping
//! maps the file's own page.

use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed};

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

/// Pages in a 2 MiB block.
const BLOCK_PAGES: usize = 512;

/// The charge of one 2 MiB block of anonymous memory (ADR-0020), paid once
/// for its 512 pages: entries made one by one cost a heap object and the
/// account's chain each, for each page, on the way in and out. Each page
/// still counts until its last holder lets go, as a [`Charged`] page does;
/// what has gone is released by [`Block::settle`], and the rest when the
/// block goes.
#[derive(Debug)]
pub(crate) struct Block {
    account: Arc<Account>,
    /// Each page's holders (address spaces sharing it after `fork`).
    holders: [AtomicU32; BLOCK_PAGES],
    /// Pages with a holder.
    live: AtomicU32,
    /// Pages the account pays for: `live`, or more until settled.
    charged: AtomicU32,
}

impl Block {
    /// Charges `account` for `frames`, a 2 MiB block in address order, and
    /// gives one entry per page; `None` (and nothing charged) if the
    /// account cannot pay for them all.
    pub(crate) fn charge(
        account: &Arc<Account>,
        frames: alloc::vec::Vec<UFrame>,
    ) -> Option<impl Iterator<Item = Resident>> {
        let n = u32::try_from(frames.len())
            .ok()
            .filter(|&n| n as usize <= BLOCK_PAGES)?;
        account.charge(u64::from(n)).ok()?;
        let block = Arc::new(Block {
            account: account.clone(),
            holders: [const { AtomicU32::new(1) }; BLOCK_PAGES],
            live: AtomicU32::new(n),
            charged: AtomicU32::new(n),
        });
        Some(frames.into_iter().zip(0u16..).map(move |(frame, index)| {
            Resident::Block(InBlock {
                frame,
                block: block.clone(),
                index,
            })
        }))
    }

    /// Releases the charge of the pages that lost their last holder.
    pub(crate) fn settle(&self) {
        let mut charged = self.charged.load(Acquire);
        loop {
            // `live` only falls: a page without holders gets none again.
            let live = self.live.load(Acquire);
            if live >= charged {
                return;
            }
            match self
                .charged
                .compare_exchange(charged, live, AcqRel, Acquire)
            {
                Ok(_) => {
                    self.account.release(u64::from(charged - live));
                    return;
                }
                Err(now) => charged = now,
            }
        }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        self.account.release(u64::from(*self.charged.get_mut()));
    }
}

/// One page of a [`Block`]: its own frame (freed when its last handle and
/// mapping go), and a hold on the block's charge.
#[derive(Debug)]
pub(crate) struct InBlock {
    frame: UFrame,
    block: Arc<Block>,
    index: u16,
}

impl InBlock {
    fn holders(&self) -> Option<&AtomicU32> {
        self.block.holders.get(usize::from(self.index))
    }
}

impl Clone for InBlock {
    fn clone(&self) -> InBlock {
        if let Some(h) = self.holders() {
            h.fetch_add(1, Relaxed);
        }
        InBlock {
            frame: self.frame.clone(),
            block: self.block.clone(),
            index: self.index,
        }
    }
}

impl Drop for InBlock {
    fn drop(&mut self) {
        if self.holders().is_some_and(|h| h.fetch_sub(1, AcqRel) == 1) {
            self.block.live.fetch_sub(1, AcqRel);
        }
    }
}

/// A page an address space holds: one charged on its own, or one of a
/// 2 MiB block's.
#[derive(Clone, Debug)]
pub(crate) enum Resident {
    Page(Page),
    Block(InBlock),
}

impl core::ops::Deref for Resident {
    type Target = UFrame;
    fn deref(&self) -> &UFrame {
        match self {
            Resident::Page(p) => p,
            Resident::Block(b) => &b.frame,
        }
    }
}

/// Settles the blocks whose entries are dropped through it, in address
/// order (so one block at a time): each when the next begins, and the last
/// when it goes.
#[derive(Default)]
pub(crate) struct Settle(Option<Arc<Block>>);

impl Settle {
    /// Drops `old`, an entry taken out of an address space.
    pub(crate) fn drop_entry(&mut self, old: Option<Resident>) {
        let Some(Resident::Block(e)) = &old else {
            return;
        };
        if self.0.as_ref().is_some_and(|b| Arc::ptr_eq(b, &e.block)) {
            return;
        }
        let done = self.0.replace(e.block.clone());
        drop(old);
        if let Some(b) = done {
            b.settle();
        }
    }
}

impl Drop for Settle {
    fn drop(&mut self) {
        if let Some(b) = self.0.take() {
            b.settle();
        }
    }
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
