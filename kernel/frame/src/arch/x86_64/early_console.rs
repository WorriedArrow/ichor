//! COM1 16550 UART used as the boot and panic console.
//!
//! Every major cloud (AWS Nitro, GCP, Azure) and QEMU expose a 16550-compatible
//! UART at I/O port 0x3F8, and bare-metal servers route it to serial-over-LAN.
//! If no UART is present, reads of the line status register return 0xFF, so
//! the "transmitter empty" bit reads as set and writes fall into the void
//! without blocking.

use super::io::{inb, outb};

/// I/O base of COM1. Frame owns the eight ports `COM1..COM1 + 8` exclusively;
/// nothing else in frame touches them and no API hands them out.
const COM1: u16 = 0x3F8;

const DATA: u16 = 0; // DLAB=0: transmit/receive buffer. DLAB=1: divisor low.
const IER: u16 = 1; // DLAB=0: interrupt enable. DLAB=1: divisor high.
const FCR: u16 = 2; // FIFO control.
const LCR: u16 = 3; // Line control.
const MCR: u16 = 4; // Modem control.
const LSR: u16 = 5; // Line status.

const LSR_THR_EMPTY: u8 = 1 << 5;

/// Upper bound on polls of the line status register per byte. At 115200 baud
/// a byte takes ~87 µs; this is generous enough for any real UART while
/// guaranteeing a broken one cannot wedge the kernel.
const MAX_SPINS: u32 = 1 << 20;

fn write_reg(reg: u16, value: u8) {
    // SAFETY: frame owns COM1..COM1+8 (see `COM1`). Writes reconfigure only
    // the UART, which performs no DMA.
    unsafe { outb(COM1 + reg, value) };
}

fn read_reg(reg: u16) -> u8 {
    // SAFETY: as in `write_reg`; reading UART registers only affects UART
    // state.
    unsafe { inb(COM1 + reg) }
}

/// Programs the UART for 115200 baud, 8 data bits, no parity, one stop bit,
/// with FIFOs enabled and interrupts disabled.
pub(crate) fn init() {
    write_reg(IER, 0x00); // No interrupts: the console is polled.
    write_reg(LCR, 0x80); // DLAB on to set the divisor.
    write_reg(DATA, 0x01); // Divisor 1 => 115200 baud.
    write_reg(IER, 0x00);
    write_reg(LCR, 0x03); // DLAB off, 8N1.
    write_reg(FCR, 0xC7); // Enable and clear FIFOs, 14-byte threshold.
    write_reg(MCR, 0x03); // DTR + RTS. OUT2 stays off: no IRQs.
}

/// Writes one byte, waiting (bounded) for room in the transmitter.
pub(crate) fn write_byte(byte: u8) {
    let mut spins = 0;
    while read_reg(LSR) & LSR_THR_EMPTY == 0 && spins < MAX_SPINS {
        core::hint::spin_loop();
        spins += 1;
    }
    write_reg(DATA, byte);
}
