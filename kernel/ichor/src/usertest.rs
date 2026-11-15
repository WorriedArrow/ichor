//! A minimal ring-3 self-test: run a hand-assembled program in a fresh
//! address space and check that `syscall` and a page fault both return
//! correctly, and that address spaces are isolated.

use frame::mm::{UFrame, UserProt, VmSpace};
use frame::power::{ExitStatus, shutdown};
use frame::println;
use frame::user::{UserContext, UserEvent, UserMode};

fn fail(what: &str) -> ! {
    println!("ichor: usertest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

const CODE_VA: u64 = 0x40_0000;
const STACK_VA: u64 = 0x50_0000;
const DATA_VA: u64 = 0x60_0000;

/// Ring-3 program: load the seeded value, `syscall` (the kernel returns it
/// plus one), keep the result in rbx, then write to address 0 to fault.
fn program() -> [u8; 64] {
    let mut c = [0x90u8; 64];
    let mut i = 0;
    let mut emit = |c: &mut [u8; 64], bytes: &[u8]| {
        c[i..i + bytes.len()].copy_from_slice(bytes);
        i += bytes.len();
    };
    emit(&mut c, &[0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00]); // mov rax, 0x1234
    emit(&mut c, &[0x48, 0xBF]); // mov rdi, imm64
    emit(&mut c, &DATA_VA.to_le_bytes());
    emit(&mut c, &[0x48, 0x8B, 0x3F]); // mov rdi, [rdi]
    emit(&mut c, &[0x48, 0x83, 0xC7, 0x01]); // add rdi, 1
    emit(&mut c, &[0x0F, 0x05]); // syscall
    emit(&mut c, &[0x48, 0x89, 0xC3]); // mov rbx, rax
    emit(&mut c, &[0x48, 0x31, 0xC0]); // xor rax, rax
    emit(&mut c, &[0x48, 0x89, 0x00]); // mov [rax], rax  -> page fault at 0
    c
}

pub(crate) fn run() {
    let space = VmSpace::new().unwrap_or_else(|| fail("no memory for a VmSpace"));

    let code_frame = UFrame::alloc_zeroed().unwrap_or_else(|| fail("no code frame"));
    code_frame.writer().write(&program());
    let stack_frame = UFrame::alloc_zeroed().unwrap_or_else(|| fail("no stack frame"));
    let data_frame = UFrame::alloc_zeroed().unwrap_or_else(|| fail("no data frame"));
    data_frame.writer().write(&41u64.to_le_bytes());

    let map = |va, f: &UFrame, prot| {
        if space.map(va, f, prot).is_err() {
            fail("mapping a user page failed");
        }
    };
    map(
        CODE_VA,
        &code_frame,
        UserProt {
            write: false,
            exec: true,
        },
    );
    map(
        STACK_VA,
        &stack_frame,
        UserProt {
            write: true,
            exec: false,
        },
    );
    map(
        DATA_VA,
        &data_frame,
        UserProt {
            write: true,
            exec: false,
        },
    );

    space.bind_to_current_task();
    let mut ctx = UserContext::new(CODE_VA, STACK_VA + 4096 - 16);

    let mut syscalls = 0;
    let fault = loop {
        match UserMode::new(&mut ctx).execute() {
            UserEvent::Syscall => {
                let (nr, args) = ctx.syscall_args();
                syscalls += 1;
                if nr != 0x1234 || args[0] != 42 {
                    fail("unexpected syscall");
                }
                ctx.set_return(args[0] + 1);
            }
            UserEvent::Exception { vector, cr2, .. } => break (vector, cr2),
        }
        if syscalls > 4 {
            fail("user did not fault");
        }
    };

    let (vector, cr2) = fault;
    if vector != 14 || cr2 != 0 {
        fail("expected a page fault at address 0");
    }
    if ctx.rbx != 43 {
        fail("syscall result did not reach the user program");
    }
    if syscalls != 1 {
        fail("expected exactly one syscall");
    }

    let other = VmSpace::new().unwrap_or_else(|| fail("no memory for a second VmSpace"));
    if other.translate(DATA_VA).is_some() {
        fail("a fresh address space should not see the first's pages");
    }

    frame::mm::activate_kernel_space();
    drop(space);
    drop(other);

    println!(
        "ichor: user: ring-3 program ran, {syscalls} syscall(s), page fault at 0 handled, isolation ok"
    );
}
