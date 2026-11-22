//! Raw port I/O. Private to frame: port access is a privilege, and every port
//! frame touches is owned by exactly one frame component. Drivers get a
//! device's own ports as [`IoPorts`](crate::io::IoPorts).

use core::arch::asm;

macro_rules! ports {
    ($($read:ident, $write:ident, $t:ty, $reg:tt;)*) => {
        $(
            /// Writes one value to an I/O port.
            ///
            /// # Safety
            ///
            /// The caller must own `port`. Port writes can reconfigure
            /// devices, including ones capable of DMA, so writing a port you
            /// do not own can corrupt memory.
            pub(crate) unsafe fn $write(port: u16, value: $t) {
                // SAFETY: the caller owns the port (function contract). No
                // `nomem`: a port write may have memory-visible side effects,
                // so this also acts as a compiler barrier.
                unsafe {
                    asm!(concat!("out dx, ", $reg), in("dx") port, in($reg) value,
                        options(nostack, preserves_flags))
                };
            }

            /// Reads one value from an I/O port.
            ///
            /// # Safety
            ///
            /// The caller must own `port`. Reads can have side effects (for
            /// example, acknowledging a device condition).
            pub(crate) unsafe fn $read(port: u16) -> $t {
                let value: $t;
                // SAFETY: the caller owns the port (function contract).
                unsafe {
                    asm!(concat!("in ", $reg, ", dx"), out($reg) value, in("dx") port,
                        options(nostack, preserves_flags))
                };
                value
            }
        )*
    };
}

ports! {
    inb, outb, u8, "al";
    inw, outw, u16, "ax";
    inl, outl, u32, "eax";
}
