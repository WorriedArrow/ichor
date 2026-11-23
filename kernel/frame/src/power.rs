//! Halting and shutting down the machine, and the ACPI power button
//! (ADR-0017): a cloud's "stop" presses it, and the machine turns itself
//! off (S5) rather than wait for the cloud to pull the plug.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use acpi::{PM1_PWRBTN, PM1_SCI_EN, PM1_SLP_EN, PM1_SLP_TYP_SHIFT, Pm1};

use crate::arch;
use crate::arch::io::{inw, outb, outw};
use crate::sync::SpinLock;

/// S5's sleep types for PM1a and PM1b.
type SleepTypes = (u8, u8);

/// The fixed-hardware PM1 registers (frame owns their ports from boot)
/// and S5's sleep types, if the firmware has them.
static PM1: SpinLock<Option<(Pm1, Option<SleepTypes>)>> = SpinLock::new(None);

/// Finds the PM1 registers and S5 (whether it did is the answer), and
/// enters ACPI mode if the firmware left the machine outside it. Clears a
/// stale button press and enables the button's event: hardware (QEMU's
/// among it) records a press in the status register only while its enable
/// bit is set. The event's SCI is not taken (the IOAPIC is left masked);
/// [`power_button`] polls the status.
pub(crate) fn init_acpi() -> Option<bool> {
    let fadt = crate::acpi::find_table(b"FACP")?;
    let pm1 = acpi::fadt_pm1(&fadt)?;
    // In the DSDT, or in an SSDT (GCP's is in Google's own).
    let dsdt = acpi::fadt_dsdt(&fadt).and_then(crate::acpi::table_at);
    let s5 = dsdt
        .as_deref()
        .and_then(acpi::s5_sleep_types)
        .or_else(|| crate::acpi::find_in_tables(b"SSDT", |t| acpi::s5_sleep_types(&t)));
    let sci = || {
        // SAFETY: the FADT names this as the PM1 control register, which
        // frame alone uses (ADR-0017), as it does every port below.
        let cnt = unsafe { inw(pm1.cnt_a) };
        cnt & PM1_SCI_EN != 0
    };
    if !sci() && pm1.smi_cmd != 0 {
        // SAFETY: the FADT's SMI command port and its ACPI-enable value.
        unsafe { outb(pm1.smi_cmd, pm1.acpi_enable) };
        let until = crate::time::now() + Duration::from_secs(1);
        while !sci() && crate::time::now() < until {
            core::hint::spin_loop();
        }
    }
    for evt in [Some(pm1.evt_a), pm1.evt_b].into_iter().flatten() {
        // SAFETY: as above; status bits are cleared by writing ones.
        unsafe { outw(evt, PM1_PWRBTN) };
        if pm1.fixed_button {
            // SAFETY: as above; the enable register is the block's second
            // half, and only the power button's event is enabled.
            unsafe { outw(evt + u16::from(pm1.evt_len / 2), PM1_PWRBTN) };
        }
    }
    *PM1.lock() = Some((pm1, s5));
    Some(s5.is_some())
}

/// Whether the power button was pressed since the last call (which clears
/// it). Polled: no interrupt is taken for it.
pub fn power_button() -> bool {
    let Some((pm1, _)) = *PM1.lock() else {
        return false;
    };
    let mut pressed = false;
    for evt in [Some(pm1.evt_a), pm1.evt_b].into_iter().flatten() {
        // SAFETY: the PM1 status register (see `init_acpi`).
        if pm1.fixed_button && unsafe { inw(evt) } & PM1_PWRBTN != 0 {
            // SAFETY: as above; writing the bit clears it.
            unsafe { outw(evt, PM1_PWRBTN) };
            pressed = true;
        }
    }
    pressed
}

/// Turns the machine off (ACPI S5); if it has no way to, halts.
pub fn power_off() -> ! {
    if let Some((pm1, Some((a, b)))) = *PM1.lock() {
        arch::disable_local_interrupts();
        for (cnt, typ) in [(Some(pm1.cnt_a), a), (pm1.cnt_b, b)] {
            let Some(cnt) = cnt else { continue };
            // SAFETY: the PM1 control register (see `init_acpi`).
            let v = unsafe { inw(cnt) } & PM1_SCI_EN | u16::from(typ & 7) << PM1_SLP_TYP_SHIFT;
            // SAFETY: as above: the sleep type, then sleep (S5: off).
            unsafe { outw(cnt, v) };
            // SAFETY: as above.
            unsafe { outw(cnt, v | PM1_SLP_EN) };
        }
    }
    arch::halt_forever()
}

/// Set during boot when the command line contains `qemu_debug_exit`.
static QEMU_DEBUG_EXIT: AtomicBool = AtomicBool::new(false);

pub(crate) fn enable_qemu_debug_exit() {
    QEMU_DEBUG_EXIT.store(true, Ordering::Relaxed);
}

/// Outcome reported when the kernel stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// The kernel finished what it was asked to do (for example, a test run).
    Success,
    /// The kernel stopped because something went wrong.
    Failure,
}

/// Stops the machine.
///
/// Under QEMU with `qemu_debug_exit` on the command line, this terminates the
/// VM with a status the test harness understands. Otherwise every CPU that
/// calls it halts. (ACPI power-off arrives with ACPI support in milestone 1.)
pub fn shutdown(status: ExitStatus) -> ! {
    if QEMU_DEBUG_EXIT.load(Ordering::Relaxed) {
        arch::qemu::exit(match status {
            ExitStatus::Success => arch::qemu::EXIT_SUCCESS,
            ExitStatus::Failure => arch::qemu::EXIT_FAILURE,
        });
    }
    arch::halt_forever()
}
