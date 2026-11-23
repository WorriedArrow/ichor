//! The native-ABI syscall personality (ADR-0002 §5).
//!
//! A native process runs in a [`Cell`] and reaches kernel objects only
//! through handles in that cell's CSpace. This dispatcher turns a `syscall`
//! from such a process into a capability operation, enforcing ownership and
//! rights. A forged or foreign handle simply fails to resolve.

use alloc::sync::Arc;

use cap::{Handle, Rights};
use frame::mm::PAGE_SIZE;
use frame::user::UserContext;
use ichor_abi::{Error, sys};

use crate::kcell::{Cell, Object};

/// Dispatches one native syscall against `cell`, writing the result into
/// `ctx.rax`. Returns `false` if the process asked to exit. Version 2's
/// calls (`native.rs`) need the process's address space `mm`; without one
/// (the version-1 self-test maps its pages by hand) they are `NoSys`.
pub(crate) fn dispatch(
    cell: &Arc<Cell>,
    mm: Option<&mut crate::umem::Mm>,
    ctx: &mut UserContext,
) -> bool {
    let (nr, args) = ctx.syscall_args();
    // Spectre v1: the match is a jump table on a number ring 3 chose (as in
    // `linuxabi::dispatch`); every call number is below `NR_LIMIT`.
    const NR_LIMIT: usize = 64;
    let nr = match usize::try_from(nr) {
        Ok(n) if n < NR_LIMIT => frame::nospec::index(n, NR_LIMIT) as u64,
        _ => nr,
    };
    let result = match nr {
        sys::VERSION => Ok(ichor_abi::VERSION),
        sys::MEM_SIZE => mem_size(cell, Handle::from_raw(args[0])),
        sys::HANDLE_DUP => dup(cell, Handle::from_raw(args[0]), Rights(args[1] as u32)),
        sys::HANDLE_CLOSE => {
            if cell.close(Handle::from_raw(args[0])) {
                Ok(0)
            } else {
                Err(Error::BadHandle)
            }
        }
        sys::EXIT => {
            ctx.set_return(0);
            return false;
        }
        _ => match mm {
            Some(mm) => crate::native::call(cell, mm, nr, args),
            None => Err(Error::NoSys),
        },
    };
    ctx.set_return(match result {
        Ok(v) => ichor_abi::ok(v),
        Err(e) => e.to_rax(),
    });
    true
}

fn mem_size(cell: &Arc<Cell>, handle: Handle) -> Result<u64, Error> {
    // The INSPECT right is required to read an object's metadata.
    match cell.object_inspect(handle) {
        Some(Object::Memory(_)) => Ok(PAGE_SIZE),
        Some(_) => Err(Error::BadHandle),
        None => Err(Error::BadHandle),
    }
}

fn dup(cell: &Arc<Cell>, handle: Handle, rights: Rights) -> Result<u64, Error> {
    cell.duplicate(handle, rights)
        .map(|h| h.raw())
        .ok_or(Error::Denied)
}
