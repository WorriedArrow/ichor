//! `execve`: replaces the calling process's program with an ELF read from
//! its root. Dynamically linked programs load their `PT_INTERP`
//! interpreter from the same root. The new image is built in a fresh
//! address space; only once it has loaded does the process switch to it,
//! so a failed `execve` returns to the old program intact.
//!
//! Partial: `FD_CLOEXEC` is not tracked (every descriptor survives), and
//! `#!` scripts return `ENOEXEC`, which shells handle by running the script
//! themselves.

use alloc::string::String;
use alloc::vec::Vec;

use frame::user::UserContext;

use super::EFAULT;
use super::fs::user_path;
use crate::loader::{self, LoadError};
use crate::process::LinuxProcess;
use crate::umem::Mm;
use crate::vfs::Kind;

const E2BIG: i64 = 7;
const ENOEXEC: i64 = 8;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;

/// Most argv or envp entries.
const MAX_STRINGS: usize = 4096;
/// Most bytes of argv plus envp strings.
const MAX_STRING_BYTES: usize = 128 * 1024;
/// Largest executable read.
const MAX_EXECUTABLE: u64 = 64 << 20;

/// Reads a NULL-terminated array of string pointers (argv, envp).
fn user_strings(p: &mut LinuxProcess, addr: u64, total: &mut usize) -> Result<Vec<String>, i64> {
    let mut out = Vec::new();
    if addr == 0 {
        return Ok(out);
    }
    loop {
        if out.len() >= MAX_STRINGS {
            return Err(E2BIG);
        }
        let mut ptr = [0u8; 8];
        if p.copy_from_user(addr + out.len() as u64 * 8, &mut ptr) != 8 {
            return Err(EFAULT);
        }
        let ptr = u64::from_le_bytes(ptr);
        if ptr == 0 {
            return Ok(out);
        }
        let s = user_path(p, ptr).map_err(|e| if e == EFAULT { EFAULT } else { E2BIG })?;
        *total += s.len() + 1;
        if *total > MAX_STRING_BYTES {
            return Err(E2BIG);
        }
        out.push(s);
    }
}

pub(super) fn execve(
    p: &mut LinuxProcess,
    ctx: &mut UserContext,
    path: u64,
    argv: u64,
    envp: u64,
) -> Result<(), i64> {
    let path = user_path(p, path)?;
    let mut total = 0;
    let argv = user_strings(p, argv, &mut total)?;
    let envp = user_strings(p, envp, &mut total)?;

    let image = read_executable(p, &path)?;
    let interp = match loader::interp_path(&image).map_err(|_| ENOEXEC)? {
        Some(ld) => Some(read_executable(p, &ld)?),
        None => None,
    };

    let mut mm = Mm::new(p.cell.account()).ok_or(ENOMEM)?;
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let envp_refs: Vec<&str> = envp.iter().map(String::as_str).collect();
    let loaded =
        loader::load(&mut mm, &image, interp.as_deref(), &argv_refs, &envp_refs).map_err(|e| {
            match e {
                LoadError::OutOfMemory => ENOMEM,
                LoadError::ArgsTooLong => E2BIG,
                _ => ENOEXEC,
            }
        })?;

    // Switch to the new space, then drop the old one (no longer active).
    mm.space().bind_to_current_task();
    drop(core::mem::replace(&mut p.mm, mm));
    *ctx = UserContext::new(loaded.entry, loaded.stack_pointer);
    Ok(())
}

/// Reads an executable (or interpreter) from the process's root.
fn read_executable(p: &LinuxProcess, path: &str) -> Result<Vec<u8>, i64> {
    let mut fs = p.vfs.lock();
    let ino = fs.resolve(p.cwd, path, true)?;
    let st = fs.stat(ino)?;
    if st.kind != Kind::File || st.mode & 0o111 == 0 {
        return Err(EACCES);
    }
    if st.size > MAX_EXECUTABLE {
        return Err(ENOMEM);
    }
    let mut bytes = alloc::vec![0u8; st.size as usize];
    let n = fs.read(ino, 0, &mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}
