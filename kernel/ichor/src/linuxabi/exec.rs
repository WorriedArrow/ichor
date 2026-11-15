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
use super::fs::user_path;
use crate::file::{File, VfsFile};
use crate::loader::{self, LoadError};
use crate::process::LinuxProcess;
use crate::umem::Mm;
use crate::vfs::Kind;

const E2BIG: i64 = 7;
const ENOEXEC: i64 = 8;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const ENOENT: i64 = 2;
const ELOOP: i64 = 40;

/// Most argv or envp entries.
const MAX_STRINGS: usize = 4096;
/// Most bytes of argv plus envp strings.
const MAX_STRING_BYTES: usize = 128 * 1024;

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
    let mut argv = user_strings(p, argv, &mut total)?;
    let envp = user_strings(p, envp, &mut total)?;

    // `#!` scripts: run the interpreter with the script as an argument, as
    // Linux does (`interp [arg] script argv[1..]`). An interpreter may itself
    // be a script, a few levels deep.
    let mut exe_path = path.clone();
    let mut image = read_executable(p, &exe_path)?;
    for _ in 0..4 {
        let Some((interp, arg)) = shebang(&image) else {
            break;
        };
        let mut new_argv = alloc::vec![interp.clone()];
        new_argv.extend(arg);
        new_argv.push(exe_path.clone());
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

    // Every other thread of the process goes away first.
    let others: Vec<_> = p
        .group
        .threads()
        .into_iter()
        .filter(|t| t.pid != p.entry.pid)
        .collect();
    for t in &others {
        crate::proc::post(t, crate::signal::SIGKILL);
    }
    p.group.wait_threads(1);

    let mut mm = Mm::new(p.cell.account()).ok_or(ENOMEM)?;
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let envp_refs: Vec<&str> = envp.iter().map(String::as_str).collect();
    let loaded = loader::load(
        &mut mm,
        &image,
        interp.as_ref().map(|f| f as &dyn File),
        &argv_refs,
        &envp_refs,
        p.group.limits()[crate::process::RLIMIT_STACK].0,
    )
    .map_err(|e| match e {
        LoadError::OutOfMemory => ENOMEM,
        LoadError::ArgsTooLong => E2BIG,
        _ => ENOEXEC,
    })?;

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
    p.group.set_exec(&exe_path, &argv_refs);
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
