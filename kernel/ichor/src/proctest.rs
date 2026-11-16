//! Self-test for native-ABI user processes (ADR-0002 §5): a ring-3 program
//! running in a cell makes capability syscalls that succeed on a handle it
//! owns and fail on a forged one.

use cap::Rights;
use frame::mm::{UFrame, UserProt};
use frame::power::{ExitStatus, shutdown};
use frame::println;
use frame::user::{UserContext, UserEvent, UserMode};
use ichor_abi::sys;

use crate::kcell::{Cell, System, rights};

fn fail(what: &str) -> ! {
    println!("ichor: proctest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

const CODE_VA: u64 = 0x40_0000;
const STACK_VA: u64 = 0x50_0000;
const DATA_VA: u64 = 0x60_0000;

/// Program: read the handle from the data page, `MEM_SIZE` it (expect 4096),
/// `MEM_SIZE` handle+0x10000 (a different slot index -> bad), then `EXIT`.
/// Results are written to the data page at offsets 8 and 16 so the kernel can
/// read them out after exit.
fn program() -> [u8; 128] {
    let mut c = [0x90u8; 128];
    let mut i = 0;
    let mut emit = |c: &mut [u8; 128], b: &[u8]| {
        c[i..i + b.len()].copy_from_slice(b);
        i += b.len();
    };
    // mov r15, DATA_VA           (keep the data page base in r15)
    emit(&mut c, &[0x49, 0xBF]);
    emit(&mut c, &DATA_VA.to_le_bytes());
    // mov rax, MEM_SIZE
    emit(&mut c, &[0x48, 0xC7, 0xC0, sys::MEM_SIZE as u8, 0, 0, 0]);
    // mov rdi, [r15]             (the valid handle)
    emit(&mut c, &[0x49, 0x8B, 0x3F]);
    // syscall
    emit(&mut c, &[0x0F, 0x05]);
    // mov [r15+8], rax           (store good result)
    emit(&mut c, &[0x49, 0x89, 0x47, 0x08]);
    // mov rax, MEM_SIZE
    emit(&mut c, &[0x48, 0xC7, 0xC0, sys::MEM_SIZE as u8, 0, 0, 0]);
    // mov rdi, [r15]
    emit(&mut c, &[0x49, 0x8B, 0x3F]);
    // add rdi, 0x10000           (bump the slot index -> different, unused slot)
    emit(&mut c, &[0x48, 0x81, 0xC7, 0x00, 0x00, 0x01, 0x00]);
    // syscall
    emit(&mut c, &[0x0F, 0x05]);
    // mov [r15+16], rax          (store bad result)
    emit(&mut c, &[0x49, 0x89, 0x47, 0x10]);
    // mov rax, EXIT ; xor rdi,rdi ; syscall
    emit(&mut c, &[0x48, 0xC7, 0xC0, sys::EXIT as u8, 0, 0, 0]);
    emit(&mut c, &[0x48, 0x31, 0xFF]);
    emit(&mut c, &[0x0F, 0x05]);
    c
}

pub(crate) fn run() {
    let system = System::new(1024).unwrap_or_else(|| fail("no system cell"));
    let proc_cell = Cell::new(&system.root_account, 16).unwrap_or_else(|| fail("no process cell"));

    // Give the cell a memory capability (with INSPECT) and record its handle.
    let grant = Rights::INSPECT | Rights::DUPLICATE | rights::READ | rights::WRITE;
    let handle = proc_cell
        .alloc_memory(grant)
        .unwrap_or_else(|| fail("process cell could not allocate"));

    // Map the program, a stack, and a data page into the cell's space.
    let code = UFrame::alloc_zeroed().unwrap_or_else(|| fail("no code frame"));
    code.writer().write(&program());
    let stack = UFrame::alloc_zeroed().unwrap_or_else(|| fail("no stack frame"));
    let data = UFrame::alloc_zeroed().unwrap_or_else(|| fail("no data frame"));
    data.writer().write(&handle.raw().to_le_bytes());

    let space = proc_cell.space();
    let map = |va, f: &UFrame, prot| {
        if space.map(va, f, prot).is_err() {
            fail("mapping into the process cell failed");
        }
    };
    map(
        CODE_VA,
        &code,
        UserProt {
            write: false,
            exec: true,
        },
    );
    map(
        STACK_VA,
        &stack,
        UserProt {
            write: true,
            exec: false,
        },
    );
    map(
        DATA_VA,
        &data,
        UserProt {
            write: true,
            exec: false,
        },
    );

    space.bind_to_current_task();
    let mut ctx = UserContext::new(CODE_VA, STACK_VA + 4096 - 16);

    let mut traps = 0;
    loop {
        match UserMode::new(&mut ctx).execute() {
            UserEvent::Syscall => {
                if !crate::nativeabi::dispatch(&proc_cell, None, &mut ctx) {
                    break; // EXIT
                }
            }
            UserEvent::Exception { .. } => fail("native process faulted unexpectedly"),
            UserEvent::Preempted => frame::task::yield_now(),
        }
        traps += 1;
        if traps > 10 {
            fail("native process did not exit");
        }
    }

    // Read the results the program stored in its data page.
    let mut buf = [0u8; 24];
    data.reader().read(&mut buf);
    let read_u64 = |b: &[u8]| {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[..8]);
        u64::from_le_bytes(a)
    };
    let good = read_u64(&buf[8..16]);
    let bad = read_u64(&buf[16..24]);

    frame::mm::activate_kernel_space();

    if good != 4096 {
        fail("MEM_SIZE on a valid handle did not return the page size");
    }
    let Err(error) = ichor_abi::decode(bad) else {
        fail("MEM_SIZE on a forged handle was not rejected");
    };
    println!(
        "ichor: proc: native process ran, MEM_SIZE ok ({good}), forged handle denied (error {error})"
    );
}
