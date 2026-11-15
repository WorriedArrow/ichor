//! Process credentials (ADR-0009): real, effective, saved and filesystem
//! uids and gids, supplementary groups, and the capability sets, bounded
//! by the cell bounding set.
//!
//! Credentials are per process (libc makes them so anyway). The set*id
//! rules follow Linux, including how capabilities follow the uids and
//! `PR_SET_KEEPCAPS`. Partial: no setuid/setgid executables (the bits are
//! ignored at exec), no file capabilities, no `SECBIT_*`.

use alloc::vec::Vec;

const EPERM: i64 = 1;
const EINVAL: i64 = 22;

/// Linux capability numbers.
pub(crate) mod cap {
    pub(crate) const CHOWN: u32 = 0;
    pub(crate) const DAC_OVERRIDE: u32 = 1;
    pub(crate) const DAC_READ_SEARCH: u32 = 2;
    pub(crate) const FOWNER: u32 = 3;
    pub(crate) const FSETID: u32 = 4;
    pub(crate) const KILL: u32 = 5;
    pub(crate) const SETGID: u32 = 6;
    pub(crate) const SETUID: u32 = 7;
    pub(crate) const SETPCAP: u32 = 8;
    pub(crate) const NET_BIND_SERVICE: u32 = 10;
    pub(crate) const SYS_CHROOT: u32 = 18;
    pub(crate) const MKNOD: u32 = 27;
    pub(crate) const AUDIT_WRITE: u32 = 29;
    pub(crate) const SETFCAP: u32 = 31;
}

const fn bit(c: u32) -> u64 {
    1 << c
}

/// What uid 0 in a cell may hold (ADR-0009 §3): capabilities whose effect
/// stays inside the cell's own objects.
pub(crate) const BOUNDING: u64 = bit(cap::CHOWN)
    | bit(cap::DAC_OVERRIDE)
    | bit(cap::DAC_READ_SEARCH)
    | bit(cap::FOWNER)
    | bit(cap::FSETID)
    | bit(cap::KILL)
    | bit(cap::SETGID)
    | bit(cap::SETUID)
    | bit(cap::SETPCAP)
    | bit(cap::NET_BIND_SERVICE)
    | bit(cap::SYS_CHROOT)
    | bit(cap::MKNOD)
    | bit(cap::AUDIT_WRITE)
    | bit(cap::SETFCAP);

/// The capabilities that act on the file system as the filesystem uid.
const FS_CAPS: u64 = bit(cap::CHOWN)
    | bit(cap::DAC_OVERRIDE)
    | bit(cap::DAC_READ_SEARCH)
    | bit(cap::FOWNER)
    | bit(cap::FSETID)
    | bit(cap::MKNOD);

/// Most supplementary groups.
pub(crate) const NGROUPS_MAX: usize = 65536;

/// One process's credentials.
#[derive(Clone, Debug)]
pub(crate) struct Creds {
    pub(crate) ruid: u32,
    pub(crate) euid: u32,
    pub(crate) suid: u32,
    pub(crate) fsuid: u32,
    pub(crate) rgid: u32,
    pub(crate) egid: u32,
    pub(crate) sgid: u32,
    pub(crate) fsgid: u32,
    pub(crate) groups: Vec<u32>,
    pub(crate) permitted: u64,
    pub(crate) effective: u64,
    /// `PR_SET_KEEPCAPS`: keep the permitted set when the last uid 0 goes.
    pub(crate) keepcaps: bool,
}

/// `-1` in a set*id argument: leave that id alone.
fn keep(v: u64) -> Option<u32> {
    (v as u32 != u32::MAX).then_some(v as u32)
}

impl Creds {
    /// A cell's first process: uid and gid 0 with the bounding set.
    pub(crate) fn root() -> Creds {
        Creds {
            ruid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            groups: Vec::new(),
            permitted: BOUNDING,
            effective: BOUNDING,
            keepcaps: false,
        }
    }

    pub(crate) fn has(&self, c: u32) -> bool {
        self.effective & bit(c) != 0
    }

    /// The file-system view: filesystem ids and effective capabilities.
    pub(crate) fn fs(&self) -> overlay::Cred {
        overlay::Cred {
            uid: self.fsuid,
            gid: self.fsgid,
            groups: self.groups.clone(),
            caps: self.effective,
        }
    }

    /// The view `access`/`faccessat` check with: the real ids, and the
    /// capabilities the real uid would have.
    pub(crate) fn real(&self) -> overlay::Cred {
        overlay::Cred {
            uid: self.ruid,
            gid: self.rgid,
            groups: self.groups.clone(),
            caps: if self.ruid == 0 { BOUNDING } else { 0 },
        }
    }

    /// `execve`: saved ids take the effective ones, and capabilities follow
    /// the uids (no set-id or file-capability executables).
    pub(crate) fn exec(&mut self) {
        self.keepcaps = false;
        self.suid = self.euid;
        self.sgid = self.egid;
        self.fsuid = self.euid;
        self.fsgid = self.egid;
        if self.euid == 0 || self.ruid == 0 {
            self.permitted = BOUNDING;
            self.effective = if self.euid == 0 { BOUNDING } else { 0 };
        } else {
            self.permitted = 0;
            self.effective = 0;
        }
    }

    /// Linux's capability adjustments after a uid change from `old`.
    fn fix_caps(&mut self, old: (u32, u32, u32, u32)) {
        let (or, oe, os, ofs) = old;
        let had_root = or == 0 || oe == 0 || os == 0;
        let has_root = self.ruid == 0 || self.euid == 0 || self.suid == 0;
        if had_root && !has_root {
            if !self.keepcaps {
                self.permitted = 0;
            }
            self.effective = 0;
        }
        if oe == 0 && self.euid != 0 {
            self.effective = 0;
        }
        if oe != 0 && self.euid == 0 {
            self.effective = self.permitted;
        }
        if ofs == 0 && self.fsuid != 0 {
            self.effective &= !FS_CAPS;
        } else if ofs != 0 && self.fsuid == 0 {
            self.effective |= self.permitted & FS_CAPS;
        }
    }

    fn uids(&self) -> (u32, u32, u32, u32) {
        (self.ruid, self.euid, self.suid, self.fsuid)
    }

    fn holds_uid(&self, u: u32) -> bool {
        u == self.ruid || u == self.euid || u == self.suid
    }

    fn holds_gid(&self, g: u32) -> bool {
        g == self.rgid || g == self.egid || g == self.sgid
    }

    pub(crate) fn setresuid(&mut self, r: u64, e: u64, s: u64) -> Result<(), i64> {
        let (r, e, s) = (keep(r), keep(e), keep(s));
        if !self.has(cap::SETUID) && [r, e, s].into_iter().flatten().any(|u| !self.holds_uid(u)) {
            return Err(EPERM);
        }
        let old = self.uids();
        if let Some(r) = r {
            self.ruid = r;
        }
        if let Some(e) = e {
            self.euid = e;
        }
        if let Some(s) = s {
            self.suid = s;
        }
        self.fsuid = self.euid;
        self.fix_caps(old);
        Ok(())
    }

    pub(crate) fn setreuid(&mut self, r: u64, e: u64) -> Result<(), i64> {
        let (r, e) = (keep(r), keep(e));
        let priv_ = self.has(cap::SETUID);
        if !priv_
            && (r.is_some_and(|r| r != self.ruid && r != self.euid)
                || e.is_some_and(|e| !self.holds_uid(e)))
        {
            return Err(EPERM);
        }
        let old = self.uids();
        let old_r = self.ruid;
        if let Some(r) = r {
            self.ruid = r;
        }
        if let Some(e) = e {
            self.euid = e;
        }
        if r.is_some() || e.is_some_and(|e| e != old_r) {
            self.suid = self.euid;
        }
        self.fsuid = self.euid;
        self.fix_caps(old);
        Ok(())
    }

    pub(crate) fn setuid(&mut self, u: u64) -> Result<(), i64> {
        let u = keep(u).ok_or(EINVAL)?;
        let old = self.uids();
        if self.has(cap::SETUID) {
            self.ruid = u;
            self.suid = u;
        } else if u != self.ruid && u != self.suid {
            return Err(EPERM);
        }
        self.euid = u;
        self.fsuid = u;
        self.fix_caps(old);
        Ok(())
    }

    pub(crate) fn setfsuid(&mut self, u: u64) -> u32 {
        let prev = self.fsuid;
        if let Some(u) = keep(u)
            && (self.has(cap::SETUID) || self.holds_uid(u) || u == self.fsuid)
        {
            let old = self.uids();
            self.fsuid = u;
            self.fix_caps(old);
        }
        prev
    }

    pub(crate) fn setresgid(&mut self, r: u64, e: u64, s: u64) -> Result<(), i64> {
        let (r, e, s) = (keep(r), keep(e), keep(s));
        if !self.has(cap::SETGID) && [r, e, s].into_iter().flatten().any(|g| !self.holds_gid(g)) {
            return Err(EPERM);
        }
        if let Some(r) = r {
            self.rgid = r;
        }
        if let Some(e) = e {
            self.egid = e;
        }
        if let Some(s) = s {
            self.sgid = s;
        }
        self.fsgid = self.egid;
        Ok(())
    }

    pub(crate) fn setregid(&mut self, r: u64, e: u64) -> Result<(), i64> {
        let (r, e) = (keep(r), keep(e));
        if !self.has(cap::SETGID)
            && (r.is_some_and(|r| r != self.rgid && r != self.egid)
                || e.is_some_and(|e| !self.holds_gid(e)))
        {
            return Err(EPERM);
        }
        let old_r = self.rgid;
        if let Some(r) = r {
            self.rgid = r;
        }
        if let Some(e) = e {
            self.egid = e;
        }
        if r.is_some() || e.is_some_and(|e| e != old_r) {
            self.sgid = self.egid;
        }
        self.fsgid = self.egid;
        Ok(())
    }

    pub(crate) fn setgid(&mut self, g: u64) -> Result<(), i64> {
        let g = keep(g).ok_or(EINVAL)?;
        if self.has(cap::SETGID) {
            self.rgid = g;
            self.sgid = g;
        } else if g != self.rgid && g != self.sgid {
            return Err(EPERM);
        }
        self.egid = g;
        self.fsgid = g;
        Ok(())
    }

    pub(crate) fn setfsgid(&mut self, g: u64) -> u32 {
        let prev = self.fsgid;
        if let Some(g) = keep(g)
            && (self.has(cap::SETGID) || self.holds_gid(g) || g == self.fsgid)
        {
            self.fsgid = g;
        }
        prev
    }

    pub(crate) fn setgroups(&mut self, groups: Vec<u32>) -> Result<(), i64> {
        if !self.has(cap::SETGID) {
            return Err(EPERM);
        }
        if groups.len() > NGROUPS_MAX {
            return Err(EINVAL);
        }
        self.groups = groups;
        Ok(())
    }

    /// Whether these credentials may signal a process whose real and saved
    /// uids are `target` (same cell; ADR-0009 §4).
    pub(crate) fn may_signal(&self, target: (u32, u32)) -> bool {
        self.has(cap::KILL)
            || [self.ruid, self.euid]
                .iter()
                .any(|u| *u == target.0 || *u == target.1)
    }
}
