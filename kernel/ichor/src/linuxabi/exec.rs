//! `execve`: replaces the calling process's program with an ELF on its
//! root, which stays open while it loads (its pages come from the page
//! cache, mapped copy-on-write, not copied whole into memory). Dynamically linked programs load their `PT_INTERP`
//! interpreter from the same root. The new image is built in a fresh
//! address space; only once it has loaded does the process switch to it,
//! so a failed `execve` returns to the old program intact.
//!
//! `#!` scripts run their interpreter with the script path as an argument.
//!
//! `FD_CLOEXEC` descriptors close once the new image is in place.

use alloc::string::String;
use alloc::vec::Vec;

use frame::user::UserContext;

use super::EFAULT;
use super::fs::{AT_FDCWD, user_path};
use crate::file::{File, VfsFile};
use crate::loader::{self, LoadError};
use crate::process::LinuxProcess;
use crate::umem::Mm;
use crate::vfs::Kind;

const E2BIG: i64 = 7;
const ENOEXEC: i64 = 8;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const ENOENT: i64 = 2;
const ELOOP: i64 = 40;

/// Most argv or envp entries.
const MAX_STRINGS: usize = 4096;
/// Most bytes of argv plus envp strings.
const MAX_STRING_BYTES: usize = 128 * 1024;

/// Longest single argv or envp string, with its NUL (Linux's
/// `MAX_ARG_STRLEN`, 32 pages).
const MAX_ARG_STRLEN: usize = 32 * 4096;

/// Reads a NULL-terminated array of string pointers (argv, envp). The
/// strings are bytes: Linux requires nothing of them but the NUL, and
/// programs pass non-UTF-8 (CPython's test runner does on purpose).
fn user_strings(p: &mut LinuxProcess, addr: u64, total: &mut usize) -> Result<Vec<Vec<u8>>, i64> {
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
        let s = user_bytes(p, ptr)?;
        *total += s.len() + 1;
        if *total > MAX_STRING_BYTES {
            return Err(E2BIG);
        }
        out.push(s);
    }
}

/// One NUL-terminated string from user memory, as bytes: E2BIG past
/// `MAX_ARG_STRLEN`, EFAULT if it runs into memory the process cannot read.
fn user_bytes(p: &mut LinuxProcess, addr: u64) -> Result<Vec<u8>, i64> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 256];
    while out.len() < MAX_ARG_STRLEN {
        let got = p.copy_from_user(addr + out.len() as u64, &mut chunk);
        if got == 0 {
            return Err(EFAULT);
        }
        if let Some(nul) = chunk[..got].iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul]);
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..got]);
    }
    Err(E2BIG)
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
    exec(p, ctx, path, argv, envp)
}

/// `execveat(dirfd, path, argv, envp, flags)`: `path` relative to the
/// directory `dirfd`, or with AT_EMPTY_PATH and an empty path the file
/// `dirfd` itself is open on (`fexecve`). The file is found again by its
/// name, so one unlinked since it was opened is ENOENT (partial);
/// AT_SYMLINK_NOFOLLOW is accepted and not applied.
pub(super) fn execveat(
    p: &mut LinuxProcess,
    ctx: &mut UserContext,
    dirfd: i64,
    path: u64,
    argv: u64,
    envp: u64,
    flags: u64,
) -> Result<(), i64> {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const EBADF: i64 = 9;
    const EINVAL: i64 = 22;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let rel = user_path(p, path)?;
    let at = |p: &LinuxProcess| -> Result<String, i64> {
        match p.fd(dirfd as u64).ok_or(EBADF)? {
            crate::process::Fd::File(f) => p.fs().path(f.ino),
            _ => Err(EBADF),
        }
    };
    let full = if rel.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        at(p)?
    } else if rel.starts_with('/') || dirfd == AT_FDCWD {
        rel
    } else {
        let mut d = at(p)?;
        if !d.ends_with('/') {
            d.push('/');
        }
        d + &rel
    };
    let mut total = 0;
    let argv = user_strings(p, argv, &mut total)?;
    let envp = user_strings(p, envp, &mut total)?;
    exec(p, ctx, full, argv, envp)
}

/// `execve` with its arguments already in the kernel (also how the native
/// personality's `CELL_SPAWN` starts a process's first program).
pub(crate) fn exec(
    p: &mut LinuxProcess,
    ctx: &mut UserContext,
    path: String,
    mut argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
) -> Result<(), i64> {
    // `#!` scripts: run the interpreter with the script as an argument, as
    // Linux does (`interp [arg] script argv[1..]`). An interpreter may itself
    // be a script, a few levels deep.
    let mut exe_path = path.clone();
    let mut image = read_executable(p, &exe_path)?;
    for _ in 0..4 {
        let Some((interp, arg)) = shebang(&image) else {
            break;
        };
        let mut new_argv = alloc::vec![interp.clone().into_bytes()];
        new_argv.extend(arg.map(String::into_bytes));
        new_argv.push(exe_path.clone().into_bytes());
        new_argv.extend(argv.iter().skip(1).cloned());
        argv = new_argv;
        exe_path = interp;
        image = read_executable(p, &exe_path)?;
    }
    if shebang(&image).is_some() {
        return Err(ELOOP);
    }
    let interp = match loader::interp_path(&image).map_err(|_| ENOEXEC)? {
        Some(ld) => Some(read_executable(p, &ld)?),
        None => None,
    };

    let mut mm = Mm::new(p.cell.account()).ok_or(ENOMEM)?;
    let loaded = loader::load(
        &mut mm,
        &image,
        interp.as_ref().map(|f| f as &dyn File),
        &argv,
        &envp,
        p.group.limits()[crate::process::RLIMIT_STACK].0,
    )
    .map_err(|e| match e {
        LoadError::OutOfMemory => ENOMEM,
        LoadError::ArgsTooLong => E2BIG,
        _ => ENOEXEC,
    })?;

    // Robust futexes held in the old image are released (and the list
    // forgotten) while that memory is still the process's, as Linux does.
    crate::futex::exit_robust_list(p);
    // Every other thread of the process goes away, and this one becomes its
    // first. Nothing fails from here on.
    p.entry = p.group.sole_thread(&p.entry).ok_or(EAGAIN)?;
    p.clear_tid = 0;
    crate::itimer::exec(p);
    // Switch to the new space, then drop the old one (no longer active).
    mm.space().bind_to_current_task();
    drop(p.replace_mm(mm));
    p.group.actions.lock().exec_reset();
    p.close_on_exec();
    let _ = p.group.update_creds(|c| {
        c.exec();
        Ok(())
    });
    if let Some(v) = p.group.take_vfork() {
        v.release(); // the vfork parent goes on
    }
    p.sig.clear_alt_stack();
    p.group.set_exec(&exe_path, &argv);
    crate::signal::sync(p);
    *ctx = UserContext::new(loaded.entry, loaded.stack_pointer);
    Ok(())
}

/// Reads an executable (or interpreter) from the process's root.
fn read_executable(p: &LinuxProcess, path: &str) -> Result<VfsFile, i64> {
    let cwd = p.cwd();
    let ino = {
        let mut fs = p.fs();
        let ino = fs.resolve(cwd, path, true)?;
        if fs.stat(ino)?.kind != Kind::File {
            return Err(EACCES);
        }
        fs.permission(ino, overlay::MAY_EXEC)?;
        ino
    };
    VfsFile::open(&p.vfs, ino).map_err(|_| ENOENT)
}

/// Parses a `#!` line: the interpreter path and its optional single
/// argument (Linux passes everything after the path as one argument).
fn shebang(image: &dyn File) -> Option<(String, Option<String>)> {
    let mut head = [0u8; 258];
    let n = image.read_at(0, &mut head);
    let rest = head[..n].strip_prefix(b"#!")?;
    let line = &rest[..rest
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(rest.len())
        .min(255)];
    let line = core::str::from_utf8(line).ok()?.trim();
    let (interp, arg) = match line.find([' ', '\t']) {
        Some(i) => (&line[..i], Some(line[i..].trim())),
        None => (line, None),
    };
    if interp.is_empty() {
        return None;
    }
    let arg = arg.filter(|a| !a.is_empty()).map(String::from);
    Some((String::from(interp), arg))
}
