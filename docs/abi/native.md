# Ichor native ABI (version 2)

The native ABI is the small, capability-based syscall interface used by
Ichor's own services (ADR-0002 §5, ADR-0012 §2). It is defined in
`kernel/abi` and shared by the kernel and the services' runtime,
`services/rt`, whose safe wrappers are how services call it.

Version 1 (milestone 2) proved the model with five calls. Version 2
(milestone 6) adds what the control plane needs: time, logging, memory,
waiting, sockets on the cell's own network stack, images, cells and the
Linux processes in them.

## Calling convention

A native process makes a call with the `syscall` instruction. Registers
follow the Linux convention so the same trap entry serves both personalities:

| Register | Use |
|---|---|
| `rax` | syscall number on entry, result on return |
| `rdi, rsi, rdx, r10, r8, r9` | arguments 0–5 |
| `rcx, r11` | clobbered by `syscall` (return RIP, RFLAGS) |

The kernel dispatches on the calling process's personality, so a Linux
process cannot reach native calls by choosing syscall numbers, and vice
versa.

A handle is a 64-bit value meaningful only inside the calling cell's
capability space: a 32-bit slot index and a 32-bit generation. A handle from
another cell, a closed handle, or one whose capability lacks the call's
right, fails to resolve (`BadHandle`).

Every call returns at once except `OBJECT_WAIT`. A call that cannot make
progress yet returns `WouldBlock`; wait for readiness, then try again.

## Native processes

A native program is a static, non-PIE x86-64 ELF executable (services are
built for `x86_64-unknown-none` with `-C relocation-model=static -C
code-model=small`). It starts with the System V stack layout (`argc`, the
argument pointers, an empty environment, the auxiliary vector). Its memory
is demand-paged and charged to its cell. It has one thread.

At boot the kernel embeds and runs its services in the system cell
(ADR-0012 §1). The boot self-test (`services/nativetest`) is given the
system cell's handle and the switch's, as hexadecimal `argv[1]` and
`argv[2]`. The control plane (`services/control`, started by the
`control=PORT` kernel option) gets those and the CA bundle's blob
handle, then named options (`port=`, `listen=`, `publish=`, `dns=`,
`exit-on-close`, `exit-after=`; see `services/control/src/main.rs`).

## Results

`rax` holds a non-negative value on success. On failure it holds the negated
error code. `ichor_abi::decode` turns `rax` back into `Result<u64, i64>`.

| Code | Name | Meaning |
|---:|---|---|
| 1 | `NoSys` | Unknown syscall number |
| 2 | `BadHandle` | Handle invalid, foreign, revoked, of the wrong type, or lacking the right |
| 3 | `Denied` | The capability lacks a required right (`HANDLE_DUP`) |
| 4 | `Invalid` | An argument was invalid (including a buffer outside the process's memory) |
| 5 | `WouldBlock` | Nothing is ready yet |
| 6 | `NoMemory` | The cell's memory account, or a table, is full |
| 7 | `Refused` | The peer refused the connection |
| 8 | `NotFound` | No such program on the cell's root, or no address |
| 9 | `Failed` | The operation failed (a reset connection, an image that does not verify, ...) |

## Calls

Buffers are `(address, length)` pairs in the caller's memory. One call
moves at most 256 KiB (`LOG`, `RANDOM`, the socket calls, `PROCESS_READ`).

| # | Name | Args | Returns |
|---:|---|---|---|
| 0 | `VERSION` | — | the ABI version (2) |
| 1 | `MEM_SIZE` | memory handle | the object's size in bytes; needs INSPECT |
| 2 | `HANDLE_DUP` | handle, rights mask | a new handle with reduced rights; needs DUPLICATE |
| 3 | `HANDLE_CLOSE` | handle | 0 |
| 4 | `EXIT` | exit code | does not return |
| 5 | `LOG` | buffer | 0; writes one console line tagged with the cell |
| 6 | `CLOCK` | 0 = monotonic, 1 = realtime | nanoseconds since boot, or since the Unix epoch |
| 7 | `RANDOM` | buffer | 0; fills it from the kernel's CSPRNG |
| 8 | `MEM_MAP` | length | the address of that many bytes (rounded up to pages) of zeroed read-write memory |
| 9 | `OBJECT_WAIT` | items, count (≤ 256), timeout ns (`u64::MAX`: none) | how many items are ready; writes each one's `revents` |
| 10 | `TCP_CONNECT` | IPv4 (`u32`, `a.b.c.d` big-endian), port | a socket handle; writable once the outcome is known (`SOCK_ERROR`) |
| 11 | `TCP_LISTEN` | port, backlog, IPv4 (`127.0.0.1`: this cell only; 0: every address it has) | a listener handle; readable with a pending connection |
| 12 | `TCP_ACCEPT` | listener | a socket handle, or `WouldBlock` |
| 13 | `SOCK_SEND` | socket, buffer | bytes taken, or `WouldBlock` |
| 14 | `SOCK_RECV` | socket, buffer | bytes read; 0 is the end of the stream |
| 15 | `UDP_BIND` | port (0: ephemeral) | a UDP socket handle |
| 16 | `UDP_SEND` | socket, buffer, IPv4, port | bytes sent |
| 17 | `UDP_RECV` | socket, buffer, source (6 bytes, or 0) | the datagram's length (truncated to the buffer); the source's address octets and port, network order |
| 18 | `SOCK_ERROR` | socket | 0 once connected, the error if it failed, `WouldBlock` while connecting |
| 19 | `PORT_PUBLISH` | switch, uplink TCP port, cell or container, port | 0; needs WRITE on the switch |
| 20 | `IMAGE_CREATE` | buffer (the Ichor image) | an image handle; the metadata and root hash are checked now, every chunk when read |
| 21 | `CELL_CREATE` | parent cell, image, memory pages (≥ 64) | a container handle: a cell under the parent rooted at the image with an upper layer in memory, attached to the switch; needs CREATE_CELL on the parent and READ on the image |
| 22 | `CELL_SPAWN` | container, spec buffer (≤ 128 KiB) | a process handle; needs WRITE |
| 23 | `PROCESS_READ` | process, buffer | bytes of its stdout and stderr; 0 once it exited and everything was read |
| 24 | `PROCESS_WAIT` | process | its wait status (`code << 8`, or the signal number), or `WouldBlock` while it runs |
| 25 | `CELL_ADDR` | cell or container | the IPv4 address the switch assigned it |
| 26 | `MEM_UNMAP` | address, length | 0; unmaps memory from `MEM_MAP` |
| 27 | `BLOB_READ` | blob, offset, buffer | bytes copied from the blob at the offset (0 past its end); needs READ |
| 28 | `CELL_SIGNAL` | container, signal (1-64) | how many processes it was posted to (every live process of the cell); needs WRITE |
| 29 | `CELL_INSPECT` | container, buffer (40 bytes) | 40; writes a `CellInfo`: pages used and limit, live processes, threads, switch address; needs INSPECT |

### `OBJECT_WAIT` items

Each item is 16 bytes, little-endian: the handle (`u64`), the events
wanted (`u32`) and the events found (`u32`, written by the kernel).
Every handle needs the WAIT right.

| Bit | Event |
|---:|---|
| `0x01` | `READABLE`: data, a pending connection, or (a process) output or exit |
| `0x04` | `WRITABLE`: room to send, or a connection's outcome is known |
| `0x08` | `FAILED`: always reported |
| `0x10` | `HANGUP`: the peer closed, or the process exited; always reported |

### `CELL_SPAWN` specs

NUL-terminated strings: the argv, an empty string, then the environment
(`KEY=value`). `argv[0]` is a path on the container's root, or a name
looked up along the environment's `PATH` (default
`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`); a
missing program is `NotFound`. The process runs through the Linux
personality, as `execve` would start it (`#!` scripts and `PT_INTERP`
included), in `/`, with the console as stdin and one pipe as stdout and
stderr. A program that cannot be loaded exits with status `127 << 8`.

## Objects and rights

| Object | Made by | Rights given |
|---|---|---|
| Memory | (version 1) | as granted |
| Cell | the kernel, at boot (the system cell's own) | all |
| Switch | the kernel, at boot | all |
| Socket | `TCP_*`, `UDP_BIND` | DUPLICATE, INSPECT, WAIT, READ, WRITE |
| Image | `IMAGE_CREATE` | DUPLICATE, INSPECT, READ |
| Container | `CELL_CREATE` | DUPLICATE, INSPECT, WAIT, WRITE |
| Process | `CELL_SPAWN` | DUPLICATE, INSPECT, WAIT, READ |
| Blob | the kernel, at boot (the boot volume's `\ichor\roots.pem`) | DUPLICATE, INSPECT, READ |

An image's pages are charged to the creating cell and kept for the life of
the system (version 2 has no image deletion). A socket closes when its
last handle does; a process's output pipe closes when its handle does.

## Rights

Generic rights occupy the low bits of the 32-bit mask; object-specific rights
the high bits.

| Bit | Right |
|---:|---|
| 0 | `DUPLICATE` |
| 1 | `TRANSFER` |
| 2 | `INSPECT` |
| 3 | `WAIT` |
| 8 | `READ` |
| 9 | `WRITE` |
| 10 | `MAP` |
| 11 | `CREATE_CELL` |

`HANDLE_DUP` can only drop rights, never add them, and only with the
`DUPLICATE` right.
