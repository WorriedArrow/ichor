//! QEMU's `isa-debug-exit` device, used by the test harness to end a run with
//! a status code. QEMU exits with `(value << 1) | 1`.

use super::io::outl;

/// I/O port of `-device isa-debug-exit,iobase=0xf4,iosize=0x04`. Frame owns it;
/// it is written only when the boot command line enables `qemu_debug_exit`.
const DEBUG_EXIT_PORT: u16 = 0xF4;

/// Value written for success; QEMU exits with status 33.
pub(crate) const EXIT_SUCCESS: u32 = 0x10;
/// Value written for failure; QEMU exits with status 35.
pub(crate) const EXIT_FAILURE: u32 = 0x11;

/// Asks QEMU to exit. Returns if the device is absent (for example on real
/// hardware), in which case the write was a no-op.
pub(crate) fn exit(value: u32) {
    // SAFETY: frame owns port 0xF4. On QEMU it terminates the VM. On hardware
    // without the device, port 0xF4 is unassigned on PC-compatible chipsets
    // and the write is discarded; the caller only enables this path when the
    // operator asked for it on the command line.
    unsafe { outl(DEBUG_EXIT_PORT, value) };
}
