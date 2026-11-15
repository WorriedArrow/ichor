//! UEFI entry point and the minimal firmware bindings Ichor needs.
//!
//! Ichor uses boot services for exactly four things: reading the firmware
//! identity and configuration tables, locating the volume it was loaded from,
//! reading its command line file, and exiting boot services. These bindings
//! cover only that. They are hand-written from the UEFI 2.10 specification
//! rather than pulled from a crate so that every line of firmware interface in
//! the TCB is in this file.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{MemoryKind, MemoryRegion, Phase, take_boot_state};
use crate::mm::{PAGE_SIZE, PhysAddr};
use crate::power::{self, ExitStatus};
use crate::{arch, println};

// ---------------------------------------------------------------------------
// Raw types (UEFI 2.10, sections 4 and 7).
// ---------------------------------------------------------------------------

type Handle = *mut c_void;
type Status = usize;

const SUCCESS: Status = 0;
const ERROR_BIT: Status = 1 << (usize::BITS - 1);
const INVALID_PARAMETER: Status = ERROR_BIT | 2;
const UNSUPPORTED: Status = ERROR_BIT | 3;
const NOT_FOUND: Status = ERROR_BIT | 14;
const ALREADY_STARTED: Status = ERROR_BIT | 20;

fn check(status: Status) -> Result<(), Status> {
    if status == SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Guid(u32, u16, u16, [u8; 8]);

#[repr(C)]
struct TableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

const SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249; // "IBI SYST"
const BOOT_SERVICES_SIGNATURE: u64 = 0x5652_4553_544f_4f42; // "BOOTSERV"

#[repr(C)]
struct SystemTable {
    hdr: TableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: Handle,
    con_in: *mut c_void,
    console_out_handle: Handle,
    con_out: *mut c_void,
    standard_error_handle: Handle,
    std_err: *mut c_void,
    runtime_services: *mut c_void,
    boot_services: *const BootServices,
    number_of_table_entries: usize,
    configuration_table: *const ConfigurationTable,
}

/// The prefix of `EFI_BOOT_SERVICES` up to `ExitBootServices`. Entries Ichor
/// never calls are typed as opaque `usize` so they cannot be called by
/// accident.
#[repr(C)]
struct BootServices {
    hdr: TableHeader,
    tpl: [usize; 2],
    allocate_pages: usize,
    free_pages: usize,
    get_memory_map: Option<
        unsafe extern "efiapi" fn(
            map_size: *mut usize,
            map: *mut u8,
            map_key: *mut usize,
            descriptor_size: *mut usize,
            descriptor_version: *mut u32,
        ) -> Status,
    >,
    pool: [usize; 2],
    events: [usize; 6],
    protocol_install: [usize; 3],
    handle_protocol: Option<
        unsafe extern "efiapi" fn(
            handle: Handle,
            protocol: *const Guid,
            interface: *mut *mut c_void,
        ) -> Status,
    >,
    reserved: usize,
    protocol_misc: [usize; 4],
    image: [usize; 4],
    exit_boot_services: Option<unsafe extern "efiapi" fn(image: Handle, map_key: usize) -> Status>,
}

#[repr(C)]
struct ConfigurationTable {
    vendor_guid: Guid,
    vendor_table: *mut c_void,
}

const ACPI_20_TABLE_GUID: Guid = Guid(
    0x8868_e871,
    0xe4f1,
    0x11d3,
    [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);
const ACPI_10_TABLE_GUID: Guid = Guid(
    0xeb9d_2d30,
    0x2d88,
    0x11d3,
    [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

/// A protocol interface type and its GUID. Tying them together means a
/// HandleProtocol result can never be cast to the wrong interface type.
trait Protocol {
    const GUID: Guid;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LoadedImage {
    revision: u32,
    parent_handle: Handle,
    system_table: *mut SystemTable,
    device_handle: Handle,
    file_path: *mut c_void,
    reserved: *mut c_void,
    load_options_size: u32,
    load_options: *mut c_void,
    image_base: *mut c_void,
    image_size: u64,
    image_code_type: u32,
    image_data_type: u32,
    unload: usize,
}

impl Protocol for LoadedImage {
    const GUID: Guid = Guid(
        0x5b1b_31a1,
        0x9562,
        0x11d2,
        [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SimpleFileSystem {
    revision: u64,
    open_volume: Option<
        unsafe extern "efiapi" fn(this: *mut SimpleFileSystem, root: *mut *mut File) -> Status,
    >,
}

impl Protocol for SimpleFileSystem {
    const GUID: Guid = Guid(
        0x964e_5b22,
        0x6459,
        0x11d2,
        [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
}

/// The prefix of `EFI_FILE_PROTOCOL` up to `Read`.
#[repr(C)]
#[derive(Clone, Copy)]
struct File {
    revision: u64,
    open: Option<
        unsafe extern "efiapi" fn(
            this: *mut File,
            new: *mut *mut File,
            name: *const u16,
            mode: u64,
            attributes: u64,
        ) -> Status,
    >,
    close: Option<unsafe extern "efiapi" fn(this: *mut File) -> Status>,
    delete: usize,
    read: Option<
        unsafe extern "efiapi" fn(this: *mut File, size: *mut usize, buf: *mut c_void) -> Status,
    >,
}

const FILE_MODE_READ: u64 = 1;

/// Size of `EFI_MEMORY_DESCRIPTOR` in UEFI 2.10. Firmware may report a larger
/// stride; never a smaller one.
const MIN_DESCRIPTOR_SIZE: usize = 40;

// ---------------------------------------------------------------------------
// Boot-time static storage for the raw firmware memory map.
// ---------------------------------------------------------------------------

const MAP_BUF_SIZE: usize = 64 * 1024;

/// Room for the firmware memory map. Lives in `.bss` so that nothing needs
/// allocating between GetMemoryMap and ExitBootServices (allocating would
/// change the memory map key).
#[repr(C, align(8))]
struct MapBuf(UnsafeCell<[u8; MAP_BUF_SIZE]>);

// SAFETY: the contents are only reached through `take_map_buf`, which hands
// out a single `&mut` exactly once.
unsafe impl Sync for MapBuf {}

static MAP_BUF: MapBuf = MapBuf(UnsafeCell::new([0; MAP_BUF_SIZE]));
static MAP_BUF_TAKEN: AtomicBool = AtomicBool::new(false);

fn take_map_buf() -> Option<&'static mut [u8; MAP_BUF_SIZE]> {
    if MAP_BUF_TAKEN.swap(true, Ordering::AcqRel) {
        return None;
    }
    // SAFETY: the swap above succeeds at most once, so this is the only
    // reference ever created to the buffer.
    Some(unsafe { &mut *MAP_BUF.0.get() })
}

/// Builds a NUL-terminated UCS-2 string from ASCII at compile time.
const fn ucs2<const N: usize>(s: &str) -> [u16; N] {
    let bytes = s.as_bytes();
    assert!(bytes.len() + 1 == N, "N must be len + 1");
    let mut out = [0u16; N];
    let mut i = 0;
    while i < bytes.len() {
        assert!(bytes[i].is_ascii() && bytes[i] != 0);
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

/// Where the kernel command line lives on the boot volume.
const CMDLINE_PATH: [u16; 15] = ucs2("\\ichor\\cmdline");

// ---------------------------------------------------------------------------
// Firmware: boot services as a typestate. Holding a `Firmware` means boot
// services are live; `exit_boot_services` consumes it.
// ---------------------------------------------------------------------------

struct Firmware<'a> {
    image: Handle,
    st: &'a SystemTable,
    bs: &'a BootServices,
}

impl<'a> Firmware<'a> {
    /// # Safety
    ///
    /// `image` and `st` must be the values firmware passed to the image entry
    /// point, boot services must not have been exited, and the returned value
    /// must be the only `Firmware` in existence.
    unsafe fn new(image: Handle, st: *const SystemTable) -> Result<Self, Status> {
        if st.is_null() {
            return Err(INVALID_PARAMETER);
        }
        // SAFETY: per the UEFI spec the entry point receives a pointer to a
        // valid system table that stays valid while boot services are live;
        // the caller guarantees they are.
        let st = unsafe { &*st };
        if st.hdr.signature != SYSTEM_TABLE_SIGNATURE || st.boot_services.is_null() {
            return Err(UNSUPPORTED);
        }
        // SAFETY: a valid system table points at a valid boot services table
        // for as long as boot services are live (checked non-null above).
        let bs = unsafe { &*st.boot_services };
        if bs.hdr.signature != BOOT_SERVICES_SIGNATURE {
            return Err(UNSUPPORTED);
        }
        Ok(Self { image, st, bs })
    }

    fn uefi_revision(&self) -> u32 {
        self.st.hdr.revision
    }

    fn firmware_revision(&self) -> u32 {
        self.st.firmware_revision
    }

    /// Copies the firmware vendor string into `out` as ASCII.
    fn vendor<'b>(&self, out: &'b mut [u8]) -> &'b str {
        let p = self.st.firmware_vendor;
        let mut n = 0;
        while !p.is_null() && n < out.len() {
            // SAFETY: `FirmwareVendor` is a NUL-terminated UCS-2 string owned
            // by firmware. We stop at the terminator, so every index read is
            // within the string.
            let c = unsafe { p.wrapping_add(n).read_unaligned() };
            if c == 0 {
                break;
            }
            out[n] = if (0x20..0x7f).contains(&c) {
                c as u8
            } else {
                b'?'
            };
            n += 1;
        }
        core::str::from_utf8(&out[..n]).unwrap_or("")
    }

    fn config_tables(&self) -> &[ConfigurationTable] {
        let ptr = self.st.configuration_table;
        if ptr.is_null() || self.st.number_of_table_entries == 0 {
            return &[];
        }
        // SAFETY: the system table describes an array of
        // `NumberOfTableEntries` configuration tables at `ConfigurationTable`,
        // valid while boot services are live; the borrow is tied to `self`.
        unsafe { core::slice::from_raw_parts(ptr, self.st.number_of_table_entries) }
    }

    fn acpi_rsdp(&self) -> Option<PhysAddr> {
        let find = |guid: Guid| {
            self.config_tables()
                .iter()
                .find(|t| t.vendor_guid == guid && !t.vendor_table.is_null())
                .map(|t| PhysAddr::new(t.vendor_table as u64))
        };
        find(ACPI_20_TABLE_GUID).or_else(|| find(ACPI_10_TABLE_GUID))
    }

    /// Looks up protocol `P` on `handle`. The returned pointer is valid while
    /// boot services are live.
    fn protocol<P: Protocol>(&self, handle: Handle) -> Result<*mut P, Status> {
        let handle_protocol = self.bs.handle_protocol.ok_or(UNSUPPORTED)?;
        let mut iface: *mut c_void = ptr::null_mut();
        // SAFETY: boot services are live (we hold `self`); the GUID and the
        // out-pointer are valid for the duration of the call.
        check(unsafe { handle_protocol(handle, &P::GUID, &mut iface) })?;
        if iface.is_null() {
            return Err(NOT_FOUND);
        }
        Ok(iface.cast())
    }

    fn loaded_image(&self) -> Result<LoadedImage, Status> {
        let li = self.protocol::<LoadedImage>(self.image)?;
        // SAFETY: HandleProtocol returned a valid, initialized
        // EFI_LOADED_IMAGE_PROTOCOL; we copy it out rather than keep a
        // reference into firmware memory.
        Ok(unsafe { li.read() })
    }

    /// Reads up to `buf.len()` bytes of the file at `path` (NUL-terminated
    /// UCS-2) on the volume the kernel was loaded from.
    fn read_boot_file(&self, path: &[u16], buf: &mut [u8]) -> Result<usize, Status> {
        if path.last() != Some(&0) {
            return Err(INVALID_PARAMETER);
        }
        let device = self.loaded_image()?.device_handle;
        let fs = self.protocol::<SimpleFileSystem>(device)?;
        // SAFETY: HandleProtocol returned a valid SimpleFileSystem interface.
        let open_volume = unsafe { fs.read() }.open_volume.ok_or(UNSUPPORTED)?;
        let mut root: *mut File = ptr::null_mut();
        // SAFETY: `fs` is a valid interface and `root` a valid out-pointer.
        check(unsafe { open_volume(fs, &mut root) })?;
        read_and_close(root, |root, f| {
            let open = f.open.ok_or(UNSUPPORTED)?;
            let mut file: *mut File = ptr::null_mut();
            // SAFETY: `root` is an open directory handle; `path` is
            // NUL-terminated (checked above); `file` is a valid out-pointer.
            check(unsafe { open(root, &mut file, path.as_ptr(), FILE_MODE_READ, 0) })?;
            read_and_close(file, |file, f| read_all(file, f, buf))
        })
    }

    /// Fetches the final memory map into `buf` and exits boot services.
    /// Returns `(map_len, descriptor_size)`.
    ///
    /// On error boot services may be partially torn down, so callers must not
    /// return to firmware; they should stop the machine.
    fn exit_boot_services(self, buf: &mut [u8]) -> Result<(usize, usize), Status> {
        let get_memory_map = self.bs.get_memory_map.ok_or(UNSUPPORTED)?;
        let exit = self.bs.exit_boot_services.ok_or(UNSUPPORTED)?;
        // The spec allows ExitBootServices to fail with INVALID_PARAMETER if
        // the map changed since GetMemoryMap (e.g. a timer event allocated);
        // the fix is to fetch the map again and retry.
        for _ in 0..4 {
            let mut size = buf.len();
            let mut key = 0;
            let mut desc_size = 0;
            let mut desc_version = 0;
            // SAFETY: boot services are live; `buf` is writable for `size`
            // bytes and 8-byte aligned (it is `MapBuf`); the out-pointers are
            // valid.
            check(unsafe {
                get_memory_map(
                    &mut size,
                    buf.as_mut_ptr(),
                    &mut key,
                    &mut desc_size,
                    &mut desc_version,
                )
            })?;
            // SAFETY: `self.image` is our image handle and `key` comes from
            // the GetMemoryMap call just above. `self` is consumed, so no
            // reference into boot services survives a successful return.
            let status = unsafe { exit(self.image, key) };
            match status {
                SUCCESS => return Ok((size.min(buf.len()), desc_size)),
                INVALID_PARAMETER => continue,
                err => return Err(err),
            }
        }
        Err(INVALID_PARAMETER)
    }
}

/// Runs `f` on an open file handle, then closes it.
fn read_and_close<T>(
    handle: *mut File,
    f: impl FnOnce(*mut File, &File) -> Result<T, Status>,
) -> Result<T, Status> {
    if handle.is_null() {
        return Err(NOT_FOUND);
    }
    // SAFETY: `handle` is a non-null file handle just returned by firmware;
    // we copy its function table out rather than keep a reference.
    let table = unsafe { handle.read() };
    let result = f(handle, &table);
    if let Some(close) = table.close {
        // SAFETY: `handle` is open and is not used after this call.
        let _ = unsafe { close(handle) };
    }
    result
}

fn read_all(file: *mut File, table: &File, buf: &mut [u8]) -> Result<usize, Status> {
    let read = table.read.ok_or(UNSUPPORTED)?;
    let mut total = 0;
    while total < buf.len() {
        let rest = &mut buf[total..];
        let mut n = rest.len();
        // SAFETY: `file` is an open file handle; `rest` is writable for `n`
        // bytes and firmware writes at most `n`.
        check(unsafe { read(file, &mut n, rest.as_mut_ptr().cast()) })?;
        if n == 0 {
            break;
        }
        total += n.min(rest.len());
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Memory map conversion (safe; only parses bytes).
// ---------------------------------------------------------------------------

fn memory_kind(uefi_type: u32) -> MemoryKind {
    match uefi_type {
        7 => MemoryKind::Usable,
        1 | 2 => MemoryKind::Kernel,
        3 | 4 => MemoryKind::BootServices,
        5 | 6 => MemoryKind::RuntimeServices,
        8 => MemoryKind::Unusable,
        9 => MemoryKind::AcpiReclaimable,
        10 => MemoryKind::AcpiNvs,
        11 | 12 => MemoryKind::Mmio,
        14 => MemoryKind::Persistent,
        15 => MemoryKind::Unaccepted,
        _ => MemoryKind::Reserved,
    }
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    let mut a = [0; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(a)
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Converts raw descriptors into `out`, merging adjacent regions of the same
/// kind. Returns how many regions were written. `desc_size` must be at least
/// `MIN_DESCRIPTOR_SIZE`.
fn convert_memory_map(raw: &[u8], desc_size: usize, out: &mut [MemoryRegion]) -> usize {
    let mut n: usize = 0;
    for d in raw.chunks_exact(desc_size) {
        let kind = memory_kind(le_u32(d, 0));
        let base = le_u64(d, 8);
        let len = le_u64(d, 24).saturating_mul(PAGE_SIZE);
        if len == 0 {
            continue;
        }
        if let Some(prev) = n.checked_sub(1).and_then(|i| out.get_mut(i))
            && prev.kind == kind
            && prev.end().as_u64() == base
        {
            prev.len = prev.len.saturating_add(len);
            continue;
        }
        let Some(slot) = out.get_mut(n) else { break };
        *slot = MemoryRegion {
            base: PhysAddr::new(base),
            len,
            kind,
        };
        n += 1;
    }
    out[..n].sort_unstable_by_key(|r| r.base);
    n
}

// ---------------------------------------------------------------------------
// The entry point.
// ---------------------------------------------------------------------------

fn fatal(what: &str, status: Status) -> ! {
    println!("ichor: frame: fatal: {what} (EFI status {status:#x})");
    power::shutdown(ExitStatus::Failure)
}

#[unsafe(export_name = "efi_main")]
extern "efiapi" fn efi_main(image: Handle, system_table: *const SystemTable) -> Status {
    let (Some(state), Some(map)) = (take_boot_state(Phase::Firmware), take_map_buf()) else {
        return ALREADY_STARTED;
    };
    arch::early_console::init();
    println!();
    println!("ichor: frame: entered from UEFI");

    // SAFETY: these are the arguments firmware passed to the entry point;
    // boot services are live; `take_boot_state` succeeded, so this is the
    // first and only entry and therefore the only `Firmware`.
    let fw = match unsafe { Firmware::new(image, system_table) } {
        Ok(fw) => fw,
        Err(status) => return status,
    };

    state.vendor_len = fw.vendor(&mut state.vendor).len();
    state.firmware_revision = fw.firmware_revision();
    state.uefi_revision = fw.uefi_revision();
    state.acpi_rsdp = fw.acpi_rsdp();
    state.kernel_image = match fw.loaded_image() {
        Ok(li) => MemoryRegion {
            base: PhysAddr::new(li.image_base as u64),
            len: li.image_size.next_multiple_of(PAGE_SIZE),
            kind: MemoryKind::Kernel,
        },
        Err(status) => fatal("cannot locate own loaded image", status),
    };

    let cmdline_len = match fw.read_boot_file(&CMDLINE_PATH, &mut state.cmdline) {
        Ok(n) => n,
        Err(NOT_FOUND) => 0,
        Err(status) => {
            println!(r"ichor: frame: warning: cannot read \ichor\cmdline (EFI status {status:#x})");
            0
        }
    };
    state.cmdline_len = match core::str::from_utf8(&state.cmdline[..cmdline_len]) {
        Ok(s) => s.len(),
        Err(e) => {
            println!("ichor: frame: warning: command line is not UTF-8; truncating");
            e.valid_up_to()
        }
    };
    if cmdline::Cmdline::new(state.cmdline()).flag("qemu_debug_exit") {
        power::enable_qemu_debug_exit();
    }

    let (map_len, desc_size) = match fw.exit_boot_services(map) {
        Ok(v) => v,
        Err(status) => fatal("ExitBootServices failed", status),
    };
    // Boot services are gone. Mask interrupts until frame installs its own
    // IDT; firmware's handlers live in memory we will reclaim.
    arch::disable_local_interrupts();
    println!("ichor: frame: boot services exited");

    if desc_size < MIN_DESCRIPTOR_SIZE {
        fatal("firmware memory descriptor size too small", desc_size);
    }
    state.region_count = convert_memory_map(&map[..map_len], desc_size, &mut state.regions);
    super::start(state)
}
