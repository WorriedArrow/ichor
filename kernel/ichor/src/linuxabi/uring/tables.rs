//! What is registered with a ring (`io_uring_register`): files, buffers and
//! groups of provided buffers, an eventfd, restrictions; and the rings a
//! thread registers for itself.
//!
//! Registered buffers are address ranges: Linux pins their pages, so there
//! an operation on one works after the program unmaps it; here it fails
//! with `EFAULT`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use core::time::Duration;

use ::uring::{Sqe, abi};
use cell::Account;
use frame::mm::PAGE_SIZE;

use super::super::le_u64;
use super::{
    EALREADY, EBADF, EBADFD, EEXIST, EFAULT, EINVAL, EMFILE, ENOENT, ENOMEM, ENXIO, EOPNOTSUPP,
    ETIME, Mem, Notify, Ring, ops, registered_ring, ring_of,
};
use crate::page::{Page, Reserved};
use crate::poll::Object;
use crate::process::{Description, Fd, LinuxProcess, RLIMIT_NOFILE};

const EACCES: i64 = 13;
const EBUSY: i64 = 16;
const ENFILE: i64 = 23;
const EOVERFLOW: i64 = 75;

/// Rings a thread may register.
pub(super) const RING_FDS: usize = 16;
/// Most buffers a ring may register, and bytes in one.
const MAX_BUFFERS: u64 = 1 << 14;
const MAX_BUFFER: u64 = 1 << 30;
/// Most buffers in a group.
const MAX_PROVIDED: usize = 1 << 16;
/// Where user addresses end.
pub(super) const USER_END: u64 = 1 << 47;

/// Something in a table, and what its owner is told when it leaves.
#[derive(Debug, Default)]
struct Slot {
    file: Option<Arc<Description>>,
    tag: u64,
}

/// The registered files.
#[derive(Debug, Default)]
pub(super) struct Files {
    slots: Option<Vec<Slot>>,
    /// Where free slots are picked (`REGISTER_FILE_ALLOC_RANGE`), and the
    /// one to look at first.
    range: (u32, u32),
    hint: u32,
}

/// Item `n` of `v`: an index an SQE chose, clamped so that the CPU does
/// not run past the bounds check with a larger one (Spectre v1, ADR-0004
/// §2).
fn nth<T>(v: &[T], n: usize) -> Option<&T> {
    (n < v.len()).then(|| &v[frame::nospec::index(n, v.len())])
}

impl Files {
    pub(super) fn get(&self, n: u32) -> Option<Arc<Description>> {
        nth(self.slots.as_ref()?, n as usize)?.file.clone()
    }

    /// Puts `d` in slot `index - 1`, or a free one
    /// ([`abi::FILE_INDEX_ALLOC`], which it then answers with). What was
    /// there comes out.
    fn put(&mut self, index: u32, d: Arc<Description>) -> Result<(u64, Slot), i64> {
        let (lo, hi) = self.range;
        let start = self.hint.clamp(lo, hi.max(lo));
        let any = index == abi::FILE_INDEX_ALLOC;
        let slots = self
            .slots
            .as_mut()
            .ok_or(if any { ENFILE } else { ENXIO })?;
        let n = if any {
            let free = |&n: &u32| slots.get(n as usize).is_some_and(|s| s.file.is_none());
            let n = (start..hi).chain(lo..start).find(free).ok_or(ENFILE)?;
            self.hint = n + 1;
            n
        } else {
            index - 1
        };
        let slot = slots.get_mut(n as usize).ok_or(EINVAL)?;
        let was = core::mem::replace(
            slot,
            Slot {
                file: Some(d),
                tag: 0,
            },
        );
        Ok((if any { u64::from(n) } else { 0 }, was))
    }
}

/// The registered buffers: where each is, and its tag.
#[derive(Debug, Default)]
pub(super) struct Buffers(Option<Vec<(u64, u64, u64)>>);

impl Buffers {
    /// Whether `len` bytes at `addr` are in buffer `n`.
    pub(super) fn holds(&self, n: u16, addr: u64, len: u64) -> bool {
        self.0
            .as_ref()
            .and_then(|b| nth(b, usize::from(n)))
            .is_some_and(|&(at, size, _)| {
                at != 0
                    && addr >= at
                    && addr
                        .checked_add(len)
                        .is_some_and(|end| end <= at.saturating_add(size))
            })
    }
}

/// A provided buffer.
#[derive(Clone, Copy, Debug)]
pub(super) struct Buffer {
    pub(super) addr: u64,
    pub(super) len: u64,
    id: u16,
}

impl Buffer {
    /// What its completion says of it.
    pub(super) fn flags(&self) -> u32 {
        abi::CQE_F_BUFFER | u32::from(self.id) << abi::CQE_BUFFER_SHIFT
    }
}

/// Where a group's buffers come from.
#[derive(Debug)]
enum Source {
    /// `PROVIDE_BUFFERS`.
    Given,
    /// A ring the program fills, in its memory at this address.
    User(u64),
    /// A ring the program fills, in pages it maps.
    Kernel(RingPages),
}

struct RingPages(Arc<Mem>);

impl core::fmt::Debug for RingPages {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RingPages")
    }
}

/// A group of provided buffers.
#[derive(Debug)]
struct Group {
    source: Source,
    /// Buffers to hand out before the ring's: those given, and those taken
    /// for an operation that did not need one after all.
    free: VecDeque<Buffer>,
    /// A ring's size and where it is read next.
    entries: u16,
    head: u16,
}

/// What a ring holds for its program.
#[derive(Debug)]
pub(super) struct Tables {
    pub(super) files: Files,
    pub(super) buffers: Buffers,
    groups: BTreeMap<u16, Group>,
    /// What the cell pays for them.
    paid: Reserved,
}

impl Tables {
    pub(super) fn new(account: &Arc<Account>) -> Option<Tables> {
        Some(Tables {
            files: Files::default(),
            buffers: Buffers::default(),
            groups: BTreeMap::new(),
            paid: Reserved::new(account, 0)?,
        })
    }

    /// Charges the cell for what is held, with `more` bytes to come; false
    /// if it cannot pay.
    fn settle(&mut self, more: usize) -> bool {
        let files = self.files.slots.as_ref().map_or(0, Vec::len) * size_of::<Slot>();
        let buffers = self.buffers.0.as_ref().map_or(0, Vec::len) * 24;
        let groups: usize = self
            .groups
            .values()
            .map(|g| 128 + g.free.len() * size_of::<Buffer>())
            .sum();
        let bytes = files + buffers + groups + more;
        self.paid.resize(bytes.div_ceil(PAGE_SIZE as usize) as u64)
    }

    /// The pages of a group's ring, to be mapped.
    pub(super) fn buffer_pages(&self, group: u16) -> Option<Vec<Page>> {
        match &self.groups.get(&group)?.source {
            Source::Kernel(m) => Some(m.0.0.clone()),
            _ => None,
        }
    }
}

/// `IORING_REGISTER_RESTRICTIONS`: what the ring is for.
#[derive(Clone, Debug, Default)]
pub(super) struct Restrictions {
    register: u64,
    ops: [u64; 4],
    flags: u8,
    required: u8,
}

impl Restrictions {
    pub(super) fn sqe(&self, s: &Sqe) -> Result<(), i64> {
        let op = usize::from(s.opcode);
        let allowed = self.ops[op / 64] & (1 << (op % 64)) != 0
            && s.flags & self.required == self.required
            && s.flags & !(self.flags | self.required) == 0;
        if allowed { Ok(()) } else { Err(EACCES) }
    }

    fn registers(&self, op: u32) -> Result<(), i64> {
        if op < 64 && self.register & (1 << op) != 0 {
            Ok(())
        } else {
            Err(EACCES)
        }
    }
}

fn u32s(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Reads `N` bytes of the program's at `at`.
fn get<const N: usize>(p: &mut LinuxProcess, at: u64) -> Result<[u8; N], i64> {
    let mut b = [0u8; N];
    if p.copy_from_user(at, &mut b) == N {
        Ok(b)
    } else {
        Err(EFAULT)
    }
}

impl Ring {
    /// Registers `d` as file `index - 1` (or any).
    pub(super) fn put_file(&self, index: u32, d: Arc<Description>) -> Result<u64, i64> {
        if !ops::may_register(&d) {
            return Err(EBADF);
        }
        // (Its last reference is not dropped with the tables locked.)
        let _kept = d.clone();
        let r = self.tables.lock().files.put(index, d);
        let (n, was) = r?;
        self.left(was.tag);
        Ok(n)
    }

    /// Closes registered file `n`.
    pub(super) fn drop_file(&self, n: u32) -> Result<u64, i64> {
        let was = {
            let mut t = self.tables.lock();
            let slots = t.files.slots.as_mut().ok_or(ENXIO)?;
            let slot = slots.get_mut(n as usize).ok_or(EINVAL)?;
            let was = core::mem::take(slot);
            if was.file.is_none() {
                return Err(EBADF);
            }
            t.files.hint = n;
            was
        };
        self.left(was.tag);
        Ok(0)
    }

    /// Changes `n` registered files from slot `at`, to the descriptors at
    /// `fds` (-1: none), with the tags at `tags` (0: none). With `alloc`
    /// and a slot of -1 they go to free ones, which are told back.
    pub(super) fn update_files(
        &self,
        p: &mut LinuxProcess,
        at: u32,
        fds: u64,
        tags: u64,
        n: u32,
        alloc: bool,
    ) -> Result<u64, i64> {
        let any = alloc && at == abi::FILE_INDEX_ALLOC;
        {
            let t = self.tables.lock();
            let len = t.files.slots.as_ref().ok_or(ENXIO)?.len();
            let end = u64::from(at) + u64::from(n);
            if !any && end > len as u64 {
                return Err(EINVAL);
            }
        }
        let mut done = 0;
        let mut err = None;
        for i in 0..n {
            match self.update_file(p, at, fds, tags, i, any) {
                Ok(()) => done += 1,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        match err {
            Some(e) if done == 0 => Err(e),
            _ => Ok(done),
        }
    }

    fn update_file(
        &self,
        p: &mut LinuxProcess,
        at: u32,
        fds: u64,
        tags: u64,
        i: u32,
        any: bool,
    ) -> Result<(), i64> {
        self.may_leave()?;
        let fd_at = fds + u64::from(i) * 4;
        let fd = i32::from_le_bytes(get(p, fd_at)?);
        let tag = match tags {
            0 => 0,
            t => le_u64(&get::<8>(p, t + u64::from(i) * 8)?),
        };
        if any {
            let d = p.desc(u64::from(fd as u32)).ok_or(EBADF)?;
            let n = self.put_file(abi::FILE_INDEX_ALLOC, d)?;
            if p.copy_to_user(fd_at, &(n as u32).to_le_bytes()) != 4 {
                let _ = self.drop_file(n as u32);
                return Err(EFAULT);
            }
            return Ok(());
        }
        if fd == abi::REGISTER_FILES_SKIP || (fd == -1 && tag != 0) {
            return if tag == 0 { Ok(()) } else { Err(EINVAL) };
        }
        let file = match fd {
            -1 => None,
            fd => Some(p.desc(u64::from(fd as u32)).ok_or(EBADF)?),
        };
        if file.as_ref().is_some_and(|d| !ops::may_register(d)) {
            return Err(EBADF);
        }
        let _kept = file.clone();
        let was = {
            let mut t = self.tables.lock();
            let slots = t.files.slots.as_mut().ok_or(ENXIO)?;
            let slot = slots.get_mut((at + i) as usize).ok_or(EINVAL)?;
            core::mem::replace(slot, Slot { file, tag })
        };
        self.left(was.tag);
        Ok(())
    }

    /// Registers `n` files, from the descriptors at `fds` (null: none yet).
    fn register_files(
        &self,
        p: &mut LinuxProcess,
        fds: u64,
        tags: u64,
        n: u32,
    ) -> Result<u64, i64> {
        if self.tables.lock().files.slots.is_some() {
            return Err(EBUSY);
        }
        if n == 0 {
            return Err(EINVAL);
        }
        let limit = p.group.limits()[RLIMIT_NOFILE]
            .0
            .min(crate::process::MAX_FDS as u64);
        if u64::from(n) > limit {
            return Err(EMFILE);
        }
        let mut slots = Vec::with_capacity(n as usize);
        for i in 0..u64::from(n) {
            let fd = match fds {
                0 => -1,
                at => i32::from_le_bytes(get(p, at + i * 4)?),
            };
            let tag = match tags {
                0 => 0,
                at => le_u64(&get::<8>(p, at + i * 8)?),
            };
            let file = match fd {
                -1 if tag != 0 => return Err(EINVAL),
                -1 => None,
                fd => Some(p.desc(u64::from(fd as u32)).ok_or(EBADF)?),
            };
            if file.as_ref().is_some_and(|d| !ops::may_register(d)) {
                return Err(EBADF);
            }
            slots.push(Slot { file, tag });
        }
        let refused = {
            let mut t = self.tables.lock();
            if t.files.slots.is_some() {
                Some((slots, EBUSY))
            } else if !t.settle(slots.len() * size_of::<Slot>()) {
                Some((slots, ENOMEM))
            } else {
                t.files = Files {
                    slots: Some(slots),
                    range: (0, n),
                    hint: 0,
                };
                None
            }
        };
        match refused {
            Some((_, e)) => Err(e),
            None => Ok(0),
        }
    }

    fn unregister_files(&self) -> Result<u64, i64> {
        let was = {
            let mut t = self.tables.lock();
            let was = t.files.slots.take().ok_or(ENXIO)?;
            t.settle(0);
            was
        };
        for s in &was {
            self.left(s.tag);
        }
        Ok(0)
    }

    /// One buffer, from the `iovec` at `at`.
    fn read_buffer(p: &mut LinuxProcess, at: u64, tag: u64) -> Result<(u64, u64, u64), i64> {
        let b: [u8; 16] = get(p, at)?;
        let (base, len) = (le_u64(&b[..8]), le_u64(&b[8..]));
        if base == 0 {
            // A place for one.
            return if len != 0 || tag != 0 {
                Err(if len != 0 { EFAULT } else { EINVAL })
            } else {
                Ok((0, 0, 0))
            };
        }
        if len == 0 || len > MAX_BUFFER {
            return Err(EFAULT);
        }
        let end = base.checked_add(len).ok_or(EOVERFLOW)?;
        let mm = p.mm();
        if end > USER_END || !mm.mapped(base) || !mm.mapped(end - 1) {
            return Err(EFAULT);
        }
        // As on Linux, which does not pin the pages of files.
        if mm.maps_file(base) {
            return Err(EOPNOTSUPP);
        }
        Ok((base, len, tag))
    }

    fn register_buffers(
        &self,
        p: &mut LinuxProcess,
        iovs: u64,
        tags: u64,
        n: u64,
    ) -> Result<u64, i64> {
        if self.tables.lock().buffers.0.is_some() {
            return Err(EBUSY);
        }
        if n == 0 || n > MAX_BUFFERS {
            return Err(EINVAL);
        }
        let mut v = Vec::with_capacity(n as usize);
        for i in 0..n {
            let tag = match tags {
                0 => 0,
                at => le_u64(&get::<8>(p, at + i * 8)?),
            };
            v.push(match iovs {
                0 => (0, 0, 0),
                at => Self::read_buffer(p, at + i * 16, tag)?,
            });
        }
        let mut t = self.tables.lock();
        if t.buffers.0.is_some() {
            return Err(EBUSY);
        }
        if !t.settle(v.len() * 24) {
            return Err(ENOMEM);
        }
        t.buffers.0 = Some(v);
        Ok(0)
    }

    fn unregister_buffers(&self) -> Result<u64, i64> {
        let was = {
            let mut t = self.tables.lock();
            let was = t.buffers.0.take().ok_or(ENXIO)?;
            t.settle(0);
            was
        };
        for b in was {
            self.left(b.2);
        }
        Ok(0)
    }

    fn update_buffers(
        &self,
        p: &mut LinuxProcess,
        at: u32,
        iovs: u64,
        tags: u64,
        n: u32,
    ) -> Result<u64, i64> {
        {
            let t = self.tables.lock();
            let len = t.buffers.0.as_ref().ok_or(ENXIO)?.len() as u64;
            if u64::from(at) + u64::from(n) > len {
                return Err(EINVAL);
            }
        }
        for i in 0..u64::from(n) {
            let new = (|| {
                self.may_leave()?;
                let tag = match tags {
                    0 => 0,
                    at => le_u64(&get::<8>(p, at + i * 8)?),
                };
                Self::read_buffer(p, iovs + i * 16, tag)
            })();
            let new = match new {
                Ok(b) => b,
                Err(e) => return if i == 0 { Err(e) } else { Ok(i) },
            };
            let was = {
                let mut t = self.tables.lock();
                let v = t.buffers.0.as_mut().ok_or(ENXIO)?;
                let slot = v.get_mut(at as usize + i as usize).ok_or(EINVAL)?;
                core::mem::replace(slot, new)
            };
            self.left(was.2);
        }
        Ok(u64::from(n))
    }

    /// Takes a buffer of `group` for an operation.
    pub(super) fn pick(&self, p: &mut LinuxProcess, group: u16) -> Option<Buffer> {
        // (The program fills rings as it likes; another thread may take the
        // one that is looked at.)
        for _ in 0..1000 {
            let (head, entries, user) = {
                let mut t = self.tables.lock();
                let g = t.groups.get_mut(&group)?;
                if let Some(b) = g.free.pop_front() {
                    return Some(b);
                }
                let kernel = match &g.source {
                    Source::Given => return None,
                    Source::User(at) => Err(*at),
                    Source::Kernel(m) => Ok(m.0.clone()),
                };
                (g.head, g.entries, kernel)
            };
            let mut read = |off: usize, out: &mut [u8]| match &user {
                Ok(m) => {
                    m.read(off, out);
                    true
                }
                Err(at) => p.copy_from_user(*at + off as u64, out) == out.len(),
            };
            let mut tail = [0u8; 2];
            if !read(14, &mut tail) || u16::from_le_bytes(tail) == head {
                return None;
            }
            core::sync::atomic::fence(Ordering::Acquire);
            let mut b = [0u8; 16];
            if !read(usize::from(head & (entries - 1)) * 16, &mut b) {
                return None;
            }
            let mut t = self.tables.lock();
            let g = t.groups.get_mut(&group)?;
            if g.head == head {
                g.head = head.wrapping_add(1);
                return Some(Buffer {
                    addr: le_u64(&b[..8]),
                    len: u64::from(u32s(&b, 8)),
                    id: u16::from_le_bytes([b[12], b[13]]),
                });
            }
        }
        None
    }

    /// Gives back a buffer that was not needed.
    pub(super) fn unpick(&self, group: u16, b: Option<Buffer>) {
        let Some(b) = b else { return };
        if let Some(g) = self.tables.lock().groups.get_mut(&group) {
            g.free.push_front(b);
        }
    }

    /// `PROVIDE_BUFFERS`.
    pub(super) fn provide(&self, s: &Sqe) -> Result<u64, i64> {
        let n = s.fd as usize;
        let mut t = self.tables.lock();
        let have = match t.groups.get(&s.buf_index) {
            Some(g) if !matches!(g.source, Source::Given) => return Err(EINVAL),
            Some(g) => g.free.len(),
            None => 0,
        };
        if have + n > MAX_PROVIDED {
            return Err(EOVERFLOW);
        }
        if !t.settle(128 + n * size_of::<Buffer>()) {
            return Err(ENOMEM);
        }
        let g = t.groups.entry(s.buf_index).or_insert_with(|| Group {
            source: Source::Given,
            free: VecDeque::new(),
            entries: 0,
            head: 0,
        });
        for i in 0..n {
            g.free.push_back(Buffer {
                addr: s.addr + i as u64 * u64::from(s.len),
                len: u64::from(s.len),
                id: s.off as u16 + i as u16,
            });
        }
        Ok(0)
    }

    /// `REMOVE_BUFFERS`.
    pub(super) fn take_back(&self, group: u16, n: usize) -> Result<u64, i64> {
        let mut t = self.tables.lock();
        let g = t.groups.get_mut(&group).ok_or(ENOENT)?;
        if !matches!(g.source, Source::Given) {
            return Err(EINVAL);
        }
        let n = n.min(g.free.len());
        g.free.drain(..n);
        t.settle(0);
        Ok(n as u64)
    }

    fn register_group(&self, p: &mut LinuxProcess, arg: u64) -> Result<u64, i64> {
        let b: [u8; 40] = get(p, arg)?;
        let (at, entries) = (le_u64(&b[..8]), u32s(&b, 8));
        let id = u16::from_le_bytes([b[12], b[13]]);
        let flags = u16::from_le_bytes([b[14], b[15]]);
        if b[16..].iter().any(|&x| x != 0) || flags & !abi::PBUF_RING_MMAP != 0 {
            return Err(EINVAL);
        }
        let kernel = flags & abi::PBUF_RING_MMAP != 0;
        let bytes = u64::from(entries) * 16;
        if kernel {
            if at != 0 {
                return Err(EINVAL);
            }
        } else if at == 0 {
            return Err(EFAULT);
        } else if at % PAGE_SIZE != 0 {
            return Err(EINVAL);
        }
        // The tail has sixteen bits.
        if !entries.is_power_of_two() || entries >= 65536 {
            return Err(EINVAL);
        }
        let source = if kernel {
            let m = Mem::alloc(&self.account, bytes).ok_or(ENOMEM)?;
            Source::Kernel(RingPages(Arc::new(m)))
        } else {
            if !p.mm().mapped(at) || !p.mm().mapped(at + bytes - 1) {
                return Err(EFAULT);
            }
            Source::User(at)
        };
        let mut t = self.tables.lock();
        if let Some(g) = t.groups.get(&id)
            && !(matches!(g.source, Source::Given) && g.free.is_empty())
        {
            return Err(EEXIST);
        }
        if !t.settle(128) {
            return Err(ENOMEM);
        }
        t.groups.insert(
            id,
            Group {
                source,
                free: VecDeque::new(),
                entries: entries as u16,
                head: 0,
            },
        );
        Ok(0)
    }

    fn unregister_group(&self, p: &mut LinuxProcess, arg: u64) -> Result<u64, i64> {
        let b: [u8; 40] = get(p, arg)?;
        if b[16..].iter().any(|&x| x != 0) {
            return Err(EINVAL);
        }
        let id = u16::from_le_bytes([b[12], b[13]]);
        let was = {
            let mut t = self.tables.lock();
            let g = t.groups.get(&id).ok_or(ENOENT)?;
            if matches!(g.source, Source::Given) {
                return Err(EINVAL);
            }
            let was = t.groups.remove(&id);
            t.settle(0);
            was
        };
        drop(was);
        Ok(0)
    }

    fn restrict(&self, p: &mut LinuxProcess, arg: u64, n: u64) -> Result<u64, i64> {
        if self.enabled.load(Ordering::Acquire) {
            return Err(EBADFD);
        }
        if self.limits.lock().is_some() {
            return Err(EBUSY);
        }
        if arg == 0 || n > 68 {
            return Err(EINVAL);
        }
        let mut r = Restrictions::default();
        for i in 0..n {
            let b: [u8; 16] = get(p, arg + i * 16)?;
            let what = u16::from_le_bytes([b[0], b[1]]);
            match (what, b[2]) {
                (0, op) if op < 64 => r.register |= 1 << op,
                (1, op) if usize::from(op) < 4 * 64 => {
                    r.ops[usize::from(op) / 64] |= 1 << (op % 64);
                }
                (2, flags) => r.flags = flags,
                (3, flags) => r.required = flags,
                _ => return Err(EINVAL),
            }
        }
        *self.limits.lock() = Some(r);
        Ok(0)
    }

    fn probe(&self, p: &mut LinuxProcess, arg: u64, n: u64) -> Result<u64, i64> {
        // `struct io_uring_probe { last_op, ops_len, resv, resv2[3],
        // ops[] }`, each op `{ op, resv, flags, resv2 }`.
        let n = (n as usize).min(256);
        let last = ops::SUPPORTED.iter().copied().max().unwrap_or(0);
        let shown = n.min(usize::from(last) + 1);
        let mut b = alloc::vec![0u8; 16 + n * 8];
        if p.copy_from_user(arg, &mut b) != b.len() {
            return Err(EFAULT);
        }
        if b.iter().any(|&x| x != 0) {
            return Err(EINVAL);
        }
        b[0] = last;
        b[1] = shown as u8;
        for op in 0..shown {
            let e = &mut b[16 + op * 8..24 + op * 8];
            e[0] = op as u8;
            if ops::SUPPORTED.contains(&(op as u8)) {
                e[2..4].copy_from_slice(&abi::OP_SUPPORTED.to_le_bytes());
            }
        }
        if p.copy_to_user(arg, &b) != b.len() {
            return Err(EFAULT);
        }
        Ok(0)
    }

    /// `REGISTER_SYNC_CANCEL`: ASYNC_CANCEL, waited for.
    fn sync_cancel(&self, p: &mut LinuxProcess, arg: u64) -> Result<u64, i64> {
        let b: [u8; 64] = get(p, arg)?;
        let (user_data, fd, flags) = (le_u64(&b[..8]), u32s(&b, 8) as i32, u32s(&b, 12));
        let known = abi::ASYNC_CANCEL_ALL
            | abi::ASYNC_CANCEL_FD
            | abi::ASYNC_CANCEL_ANY
            | abi::ASYNC_CANCEL_FD_FIXED;
        if flags & !known != 0 || b[32..].iter().any(|&x| x != 0) {
            return Err(EINVAL);
        }
        let (sec, nsec) = (le_u64(&b[16..24]) as i64, le_u64(&b[24..32]) as i64);
        let deadline = (sec != -1 || nsec != -1).then(|| {
            frame::time::now().saturating_add(Duration::new(
                sec.max(0) as u64,
                nsec.clamp(0, 999_999_999) as u32,
            ))
        });
        loop {
            let told = self.hub.told();
            let c = self.cancel_matching(p, user_data, fd, flags);
            self.end(c.ids);
            match c.result {
                Err(EALREADY) => {}
                Err(e) => return Err(e),
                Ok(_) => return Ok(0),
            }
            if deadline.is_some_and(|d| frame::time::now() >= d) {
                return Err(ETIME);
            }
            if !self.hub.wait(&p.entry, told, deadline) {
                return Err(super::EINTR);
            }
        }
    }

    fn set_eventfd(
        &self,
        p: &mut LinuxProcess,
        arg: u64,
        n: u64,
        waited: bool,
    ) -> Result<u64, i64> {
        if n != 1 {
            return Err(EINVAL);
        }
        let fd = u64::from(u32::from_le_bytes(get(p, arg)?));
        let eventfd = match p.fd(fd).ok_or(EBADF)? {
            Fd::Object(o) if o.obj.eventfd().is_some() => o.obj,
            _ => return Err(EINVAL),
        };
        let mut notify = self.notify.lock();
        if notify.is_some() {
            return Err(EBUSY);
        }
        *notify = Some(Notify { eventfd, waited });
        Ok(0)
    }
}

/// `IORING_REGISTER_RING_FDS` and its opposite: `n` places among the
/// thread's rings.
fn ring_fds(p: &mut LinuxProcess, arg: u64, n: u64, register: bool) -> Result<u64, i64> {
    if n == 0 || n > RING_FDS as u64 {
        return Err(EINVAL);
    }
    let one = |p: &mut LinuxProcess, at: u64| -> Result<(), i64> {
        // `struct io_uring_rsrc_update { offset, resv, data }`.
        let b: [u8; 16] = get(p, at)?;
        let (place, resv, fd) = (u32s(&b, 0), u32s(&b, 4), le_u64(&b[8..]));
        if resv != 0 {
            return Err(EINVAL);
        }
        if p.uring.rings.is_empty() {
            p.uring.rings = alloc::vec![None; RING_FDS];
        }
        if !register {
            if fd != 0 || place as usize >= RING_FDS {
                return Err(EINVAL);
            }
            p.uring.rings[place as usize] = None;
            return Ok(());
        }
        let ring = ring_of(p, u64::from(fd as u32))?;
        let rings: &mut Vec<Option<Arc<dyn Object>>> = &mut p.uring.rings;
        let place = if place == u32::MAX {
            rings.iter().position(Option::is_none).ok_or(EBUSY)?
        } else if place as usize >= RING_FDS {
            return Err(EINVAL);
        } else if rings[place as usize].is_some() {
            return Err(EBUSY);
        } else {
            place as usize
        };
        rings[place] = Some(ring);
        if p.copy_to_user(at, &(place as u32).to_le_bytes()) != 4 {
            p.uring.rings[place] = None;
            return Err(EFAULT);
        }
        Ok(())
    };
    let mut done = 0;
    for i in 0..n {
        match one(p, arg + i * 16) {
            Ok(()) => done += 1,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// `struct io_uring_rsrc_register { nr, flags, resv2, data, tags }`.
fn rsrc(p: &mut LinuxProcess, arg: u64, size: u64) -> Result<(u32, u32, u64, u64), i64> {
    if size != 32 {
        return Err(EINVAL);
    }
    let b: [u8; 32] = get(p, arg)?;
    let (n, flags, resv) = (u32s(&b, 0), u32s(&b, 4), le_u64(&b[8..16]));
    if n == 0 || resv != 0 || flags & !abi::RSRC_REGISTER_SPARSE != 0 {
        return Err(EINVAL);
    }
    let (data, tags) = (le_u64(&b[16..24]), le_u64(&b[24..]));
    if flags & abi::RSRC_REGISTER_SPARSE != 0 && data != 0 {
        return Err(EINVAL);
    }
    Ok((n, flags, data, tags))
}

/// `struct io_uring_rsrc_update2 { offset, resv, data, tags, nr, resv2 }`.
fn rsrc_update(p: &mut LinuxProcess, arg: u64, size: u64) -> Result<(u32, u64, u64, u32), i64> {
    if size != 32 {
        return Err(EINVAL);
    }
    let b: [u8; 32] = get(p, arg)?;
    let n = u32s(&b, 24);
    if n == 0 || u32s(&b, 4) != 0 || u32s(&b, 28) != 0 {
        return Err(EINVAL);
    }
    Ok((u32s(&b, 0), le_u64(&b[8..16]), le_u64(&b[16..24]), n))
}

/// `io_uring_register(fd, opcode, arg, nr_args)`.
pub(in super::super) fn register(
    p: &mut LinuxProcess,
    fd: u64,
    opcode: u64,
    arg: u64,
    n: u64,
) -> Result<u64, i64> {
    let opcode = opcode as u32;
    let op = opcode & !abi::REGISTER_USE_REGISTERED_RING;
    let n = u64::from(n as u32);
    let obj = if op == opcode {
        ring_of(p, fd)?
    } else {
        registered_ring(p, fd)?
    };
    let ring = obj.uring().ok_or(EOPNOTSUPP)?;
    let issuer = ring.issuer.load(Ordering::Acquire);
    if issuer != 0 && issuer != p.entry.pid {
        return Err(EEXIST);
    }
    if ring.enabled.load(Ordering::Acquire)
        && let Some(r) = &*ring.limits.lock()
    {
        r.registers(op)?;
    }
    let none = |ok: bool| if ok { Ok(()) } else { Err(EINVAL) };
    match op {
        abi::REGISTER_BUFFERS => {
            none(arg != 0)?;
            ring.register_buffers(p, arg, 0, n)
        }
        abi::UNREGISTER_BUFFERS => {
            none(arg == 0 && n == 0)?;
            ring.unregister_buffers()
        }
        abi::REGISTER_FILES => {
            none(arg != 0)?;
            ring.register_files(p, arg, 0, n as u32)
        }
        abi::UNREGISTER_FILES => {
            none(arg == 0 && n == 0)?;
            ring.unregister_files()
        }
        abi::REGISTER_FILES_UPDATE => {
            // `struct io_uring_files_update { offset, resv, fds }`.
            let b: [u8; 16] = get(p, arg)?;
            none(n != 0 && u32s(&b, 4) == 0)?;
            ring.update_files(p, u32s(&b, 0), le_u64(&b[8..]), 0, n as u32, false)
        }
        abi::REGISTER_FILES2 => {
            let (n, flags, data, tags) = rsrc(p, arg, n)?;
            none(data != 0 || flags & abi::RSRC_REGISTER_SPARSE != 0)?;
            ring.register_files(p, data, tags, n)
        }
        abi::REGISTER_FILES_UPDATE2 => {
            let (at, data, tags, n) = rsrc_update(p, arg, n)?;
            ring.update_files(p, at, data, tags, n, false)
        }
        abi::REGISTER_BUFFERS2 => {
            let (n, _, data, tags) = rsrc(p, arg, n)?;
            ring.register_buffers(p, data, tags, u64::from(n))
        }
        abi::REGISTER_BUFFERS_UPDATE => {
            let (at, data, tags, n) = rsrc_update(p, arg, n)?;
            ring.update_buffers(p, at, data, tags, n)
        }
        abi::REGISTER_EVENTFD => ring.set_eventfd(p, arg, n, false),
        abi::REGISTER_EVENTFD_ASYNC => ring.set_eventfd(p, arg, n, true),
        abi::UNREGISTER_EVENTFD => {
            none(arg == 0 && n == 0)?;
            let was = ring.notify.lock().take();
            if was.is_some() { Ok(0) } else { Err(ENXIO) }
        }
        abi::REGISTER_PROBE => {
            none(arg != 0 && n <= 256)?;
            ring.probe(p, arg, n)
        }
        abi::REGISTER_RESTRICTIONS => ring.restrict(p, arg, n),
        abi::REGISTER_ENABLE_RINGS => {
            none(arg == 0 && n == 0)?;
            if ring.enabled.load(Ordering::Acquire) {
                return Err(EBADFD);
            }
            if ring.layout.has(abi::SETUP_SINGLE_ISSUER) {
                ring.issuer.store(p.entry.pid, Ordering::Release);
            }
            ring.enabled.store(true, Ordering::Release);
            Ok(0)
        }
        abi::REGISTER_IOWQ_AFF => {
            // Linux's `io_register_iowq_aff`: `n` bytes of a CPU mask,
            // which must name an online CPU and no CPU beyond the possible.
            none(arg != 0 && n != 0)?;
            let take = usize::try_from(n).unwrap_or(usize::MAX).min(128);
            let mut b = [0u8; 128];
            if p.copy_from_user(arg, &mut b[..take]) != take {
                return Err(EFAULT);
            }
            let cpus = frame::cpu::online_count().min(64);
            let online = if cpus == 64 {
                u64::MAX
            } else {
                (1u64 << cpus) - 1
            };
            let mut low = [0u8; 8];
            low.copy_from_slice(&b[..8]);
            let mask = u64::from_le_bytes(low);
            if mask & !online != 0 || b[8..take.max(8)].iter().any(|&x| x != 0) || mask == 0 {
                return Err(EINVAL);
            }
            *ring.worker_cpus.lock() = (mask != online).then_some(mask);
            Ok(0)
        }
        abi::UNREGISTER_IOWQ_AFF => {
            none(arg == 0 && n == 0)?;
            *ring.worker_cpus.lock() = None;
            Ok(0)
        }
        abi::REGISTER_IOWQ_MAX_WORKERS => {
            none(arg != 0 && n == 2)?;
            let b: [u8; 8] = get(p, arg)?;
            let asked = [u32s(&b, 0), u32s(&b, 4)];
            let mut max = ring.max_workers.lock();
            let was = *max;
            for (m, a) in max.iter_mut().zip(asked) {
                // (0: only to be told.)
                if a != 0 {
                    *m = a;
                }
            }
            drop(max);
            let mut out = [0u8; 8];
            out[..4].copy_from_slice(&was[0].to_le_bytes());
            out[4..].copy_from_slice(&was[1].to_le_bytes());
            if p.copy_to_user(arg, &out) != 8 {
                return Err(EFAULT);
            }
            Ok(0)
        }
        abi::REGISTER_RING_FDS => ring_fds(p, arg, n, true),
        abi::UNREGISTER_RING_FDS => ring_fds(p, arg, n, false),
        abi::REGISTER_PBUF_RING => {
            none(arg != 0 && n == 1)?;
            ring.register_group(p, arg)
        }
        abi::UNREGISTER_PBUF_RING => {
            none(arg != 0 && n == 1)?;
            ring.unregister_group(p, arg)
        }
        abi::REGISTER_SYNC_CANCEL => {
            none(arg != 0 && n == 1)?;
            ring.sync_cancel(p, arg)
        }
        abi::REGISTER_FILE_ALLOC_RANGE => {
            none(arg != 0 && n == 0)?;
            let b: [u8; 16] = get(p, arg)?;
            let (at, len) = (u32s(&b, 0), u32s(&b, 4));
            let end = at.checked_add(len).ok_or(EOVERFLOW)?;
            let mut t = ring.tables.lock();
            let slots = t.files.slots.as_ref().map_or(0, Vec::len);
            none(le_u64(&b[8..]) == 0 && end as usize <= slots)?;
            t.files.range = (at, end);
            t.files.hint = at;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}
