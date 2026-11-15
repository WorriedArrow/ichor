//! Raw port I/O. Private to frame: port access is a privilege, and every port
//! frame touches is owned by exactly one frame component. A safe, ownership-
//! checked `IoPort` type for drivers arrives with milestone 1 (see ADR-0001).

use core::arch::asm;

/// Writes one byte to an I/O port.
///
/// # Safety
///
/// The caller must own `port`. Port writes can reconfigure devices, including
/// ones capable of DMA, so writing a port you do not own can corrupt memory.
pub(super) unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller owns the port (function contract). No `nomem`: a
    // port write may have memory-visible side effects, so this also acts as a
    // compiler barrier.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags)) };
}

/// Reads one byte from an I/O port.
///
/// # Safety
///
/// The caller must own `port`. Reads can have side effects (for example,
/// acknowledging a device condition).
pub(super) unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller owns the port (function contract).
    unsafe { asm!("in al, dx", out("al") value, in("dx") port, options(nostack, preserves_flags)) };
    value
}

/// Writes one 32-bit value to an I/O port.
///
/// # Safety
///
/// Same contract as [`outb`].
pub(super) unsafe fn outl(port: u16, value: u32) {
    // SAFETY: the caller owns the port (function contract).
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack, preserves_flags))
    };
}

/// Reads one 32-bit value from an I/O port.
///
/// # Safety
///
/// Same contract as [`inb`].
pub(super) unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: the caller owns the port (function contract).
    unsafe {
        asm!("in eax, dx", out("eax") value, in("dx") port, options(nostack, preserves_flags))
    };
    value
}
