//! Milestone 3 self-tests: real static Linux x86-64 ELF binaries run,
//! unmodified, in cells through the Linux syscall personality, reading files
//! from a mounted Ichor image.

use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::power::{ExitStatus, shutdown};
use frame::println;
use frame::user::{UserContext, UserEvent, UserMode};

use crate::kcell::{Cell, System};
use crate::linuxabi::{self, Outcome};
use crate::loader;
use crate::process::LinuxProcess;
use crate::testprog::{Asm, BLOB_VADDR, Reg, static_elf};
use crate::vfs::Vfs;

pub(crate) fn fail(what: &str) -> ! {
    println!("ichor: runtest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

/// Linux syscall numbers the test programs use.
mod sys {
    pub(super) const READ: u64 = 0;
    pub(super) const WRITE: u64 = 1;
    pub(super) const OPEN: u64 = 2;
    pub(super) const CLOSE: u64 = 3;
    pub(super) const FSTAT: u64 = 5;
    pub(super) const EXIT_GROUP: u64 = 231;
}

const MOTD: &[u8] = b"hello from /etc/motd inside an Ichor image\n";
const HELLO: &[u8] = b"hello from a real Linux ELF running on Ichor\n";

/// Loads `elf` into `p`'s cell and runs it to exit; returns the exit status
/// and the number of syscalls it made.
pub(crate) fn run_linux(p: &mut LinuxProcess, elf: &[u8]) -> (i32, u32) {
    let loaded = match loader::load(&p.cell, elf) {
        Ok(l) => l,
        Err(e) => {
            println!("ichor: runtest: load error {e:?}");
            fail("could not load the ELF");
        }
    };
    p.cell.space().bind_to_current_task();
    let mut ctx = UserContext::new(loaded.entry, loaded.stack_pointer);
    let mut syscalls = 0u32;
    let status = loop {
        match UserMode::new(&mut ctx).execute() {
            UserEvent::Syscall => {
                syscalls += 1;
                if let Outcome::Exit(code) = linuxabi::dispatch(p, &mut ctx) {
                    break code;
                }
            }
            UserEvent::Exception { vector, cr2, .. } => {
                frame::mm::activate_kernel_space();
                println!(
                    "ichor: runtest: fault vector {vector} cr2 {cr2:#x} rip {:#x}",
                    ctx.rip
                );
                fail("the Linux binary faulted");
            }
        }
        if syscalls > 1000 {
            fail("the Linux binary made too many syscalls");
        }
    };
    frame::mm::activate_kernel_space();
    (status, syscalls)
}

/// `write(1, msg); exit_group(7)`.
fn hello_program() -> Vec<u8> {
    let mut a = Asm::new();
    let msg = a.data(HELLO);
    a.mov_imm(Reg::Rdi, 1);
    a.mov_data(Reg::Rsi, msg);
    a.mov_imm(Reg::Rdx, HELLO.len() as u64);
    a.sys(sys::WRITE);
    a.mov_imm(Reg::Rdi, 7);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// A tiny `cat /etc/motd` with checks; exits 0 only if every check held.
pub(crate) fn cat_program() -> Vec<u8> {
    let mut a = Asm::new();
    let nope = a.data(b"/nope\0");
    let motd = a.data(b"/etc/motd\0");
    let bad = a.label();
    let done = a.label();
    // r13 = open("/nope", O_RDONLY)   (expect -ENOENT)
    a.mov_data(Reg::Rdi, nope);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    a.mov(Reg::R13, Reg::Rax);
    // r12 = open("/etc/motd", O_RDONLY)   (a symlink to /usr/share/motd)
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    a.mov(Reg::R12, Reg::Rax);
    // r14 = read(r12, rbx = rsp - 4096, 1024); write(1, rbx, r14)
    a.mov(Reg::Rbx, Reg::Rsp);
    a.sub_imm(Reg::Rbx, 4096);
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::Rbx);
    a.mov_imm(Reg::Rdx, 1024);
    a.sys(sys::READ);
    a.mov(Reg::R14, Reg::Rax);
    a.mov_imm(Reg::Rdi, 1);
    a.mov(Reg::Rsi, Reg::Rbx);
    a.mov(Reg::Rdx, Reg::R14);
    a.sys(sys::WRITE);
    // fstat(r12, rbp = rsp - 8192); r15 = st_size
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 8192);
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::FSTAT);
    a.load(Reg::R15, Reg::Rbp, 48);
    // close(r12)
    a.mov(Reg::Rdi, Reg::R12);
    a.sys(sys::CLOSE);
    // Checks: ENOENT for /nope, fd 3 for the first open, size == bytes read.
    a.cmp_imm(Reg::R13, -2);
    a.jne(bad);
    a.cmp_imm(Reg::R12, 3);
    a.jne(bad);
    a.cmp(Reg::R15, Reg::R14);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 0);
    a.jmp(done);
    a.bind(bad);
    a.mov_imm(Reg::Rdi, 1);
    a.bind(done);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// The root image: `/usr/share/motd`, `/etc/motd -> /usr/share/motd`.
fn root_image() -> &'static [u8] {
    let mut b = image::builder::Builder::new();
    let motd = b.file("motd", MOTD, 0o644);
    let share = b.dir("share", &[motd], 0o755);
    let usr = b.dir("usr", &[share], 0o755);
    let link = b.symlink("motd", "/usr/share/motd");
    let etc = b.dir("etc", &[link], 0o755);
    let root = b.dir("/", &[etc, usr], 0o755);
    b.finish(root).leak()
}

pub(crate) fn run() {
    let system = System::new(4096).unwrap_or_else(|| fail("no system cell"));
    let vfs = Arc::new(
        Vfs::mount(root_image()).unwrap_or_else(|_| fail("could not mount the root image")),
    );
    let new_process = || {
        let cell = Cell::new(&system.root_account, 128).unwrap_or_else(|| fail("no process cell"));
        LinuxProcess::new(cell, vfs.clone())
    };

    let (status, syscalls) = run_linux(&mut new_process(), &hello_program());
    if status != 7 {
        fail("hello did not exit with status 7");
    }
    println!(
        "ichor: linux: static ELF ran via the Linux ABI, exited {status} after {syscalls} syscalls"
    );

    let (status, syscalls) = run_linux(&mut new_process(), &cat_program());
    if status != 0 {
        fail("cat: ENOENT, fd number, read or fstat check failed");
    }
    println!(
        "ichor: linux: cat read /etc/motd through a symlink in the image ({syscalls} syscalls, checks passed)"
    );
}
