# ADR-0010: Network stack and the cell switch

- Status: Accepted
- Date: 2026-11-15
- Milestone: 5 ("network stack, virtio-net, inter-cell switching; nginx and
  redis serve traffic from cells")

## Context

Cells need networking with the same properties as the rest of Ichor: no
global state to carve up (ADR-0002), every resource charged to its cell,
and all of it in safe Rust. The brief also asks to beat Linux on
cross-cell networking and to keep protocol logic (it names the TCP state
machine) in host-testable crates that can be fuzzed.

ADR-0002 already fixes the outline: each cell has a **network stack
instance plus its `Port`s**; a `Port` is a virtual interface on the
**cell switch**; `CLONE_NEWNET` makes another stack charged to the cell;
the switch enforces per-`Port` rate limits.

## Decision

### 1. Our own stack, sans-I/O, in safe host-tested crates

The protocols live in `kernel/net` (no_std, `forbid(unsafe_code)`,
host-tested, fuzzable). They are written sans-I/O: pure state machines that
take bytes and the current time and return bytes to send and timers to
arm. They know nothing about devices, threads or the Linux ABI. Layers:
Ethernet II, ARP, IPv4 (no fragmentation reassembly beyond what is needed;
DF set on output), ICMP echo, UDP, TCP. IPv6 follows the same pattern
later.

TCP is a full state machine: three-way handshake, simultaneous open and
close, all eleven states, sequence-number arithmetic modulo 2^32,
retransmission with RTO estimation (RFC 6298), fast retransmit and NewReno
congestion control (RFC 5681/6582), window scaling and timestamps (RFC
7323), SACK later. It is tested against itself (two endpoints over a lossy,
reordering simulated link) and against recorded Linux traces.

### 2. One stack instance per cell

A `Stack` belongs to a cell (and `CLONE_NEWNET` creates another, charged to
the cell). It owns its interfaces (`lo`, plus one interface per `Port` it
holds), its routes, its ARP cache, its sockets and its port numbers. There
is no global socket table, port space, or routing table: two cells can both
bind port 80, and nothing in one stack can name anything in another.
Socket buffers and per-connection state are charged to the cell's account.

### 3. The cell switch

The switch is a kernel object (held by the system cell) with **ports**:
`Port`s handed to cells, and **uplinks** (physical NICs). The control
plane assigns each port its MAC and IPv4 address; the switch never learns
addresses from traffic.

- **Forwarding by assignment.** A frame from a port is delivered to the
  port whose assigned MAC is the destination, or to the uplink. There is no
  flooding: the switch answers ARP for every address it assigned (proxy
  ARP), so broadcasts never reach other cells, and a cell sees only frames
  addressed to it.
- **Anti-spoofing.** A frame whose source MAC or IPv4 address is not the
  port's assigned one is dropped.
- **Rate limits.** Each port has token buckets (packets and bytes) set by
  the control plane (ADR-0002 §4).
- **Cross-cell fast path.** Between two ports on the same host a frame is
  handed from one stack to the other as an owned buffer: no device, no
  copy beyond the one into the receiver's socket buffer. This is where
  Ichor can beat Linux's veth + bridge.
- **Uplink: NAT and published ports.** Cells live in a private subnet. The
  switch translates cells' outbound connections to the uplink's address
  (source NAT, with connection tracking), and forwards published ports
  (`uplink:8080 -> cell:80`) inbound, as Docker's default bridge does.
  The uplink's own address comes from configuration in milestone 5 and
  from DHCP and cloud metadata in milestone 8.

### 4. Linux sockets map onto the stack

`socket(AF_INET, SOCK_STREAM | SOCK_DGRAM)` and the rest of the BSD socket
calls (bind, listen, accept4, connect, send*/recv*, shutdown,
get/setsockopt for the options real servers use, getsockname/getpeername)
become operations on the calling cell's stack, and sockets join the
existing poll/epoll machinery (`poll::Watchers`). `AF_UNIX` sockets
(stream, datagram, seqpacket; `socketpair`; paths in the cell's root;
abstract names per cell; `SCM_RIGHTS`) are a per-cell object outside the IP
stack. `AF_NETLINK` gets only what common tools need, later.

### 5. Devices: virtio-net first

A safe virtio-net driver on frame's `VirtQueue` (as virtio-blk and
virtio-rng are) is the first uplink. A kernel network task per stack
drives receive, transmit and timers. In milestone 5 the driver is polled:
the task spins briefly when traffic is flowing and sleeps when idle, so an
idle machine does not burn a CPU. Interrupt-driven receive (MSI-X in
frame) and cloud NICs (ENA, gVNIC) come with milestone 8 and need their
own frame budget step.

### Amendment (2026-11-15): ports carry IP packets

Both ends of a cell's port are Ichor stacks, so the port carries IPv4
packets, not Ethernet frames: the switch forwards by assigned IP address
(`net::switch`), and there is no ARP between cells at all. Proxy ARP is
therefore unnecessary: a cell cannot broadcast to another, and it never
sees a packet not addressed to it. Anti-spoofing checks the source IP
against the port's assignment; MAC addresses and ARP exist only on the
uplink, which is a real Ethernet interface (`net::iface`). Cells use
10.88.0.0/16 (the switch is .1); NAT and published ports live in
`net::nat`. The cross-cell fast path hands the owned segment buffer from
one stack to the other inside the sending call, with no device and no
copy.

### Amendment (2026-11-15): milestone 5 closed

UDP shares each stack; `AF_UNIX` is `linuxabi/unix.rs` (paths are socket
nodes in the cell's root, abstract names are keyed by cell). Socket
buffers are charged to the cell's account by the page; when the account
runs short a stack caps its connections' buffers where they stand (TCP
windows close, writers wait) and drops datagrams, instead of failing
allocations or growing past the cell's memory. A single operation may
add one write's or segment's worth before the cap takes effect.

## Alternatives considered

- **smoltcp.** A mature no_std stack under a permissive license. Rejected
  as the core: it is a large dependency to audit (ADR-0001 §5), its
  socket model (fixed socket sets, application-provided buffers) differs
  from what Linux sockets need (accept queues, blocking semantics,
  SO_REUSEADDR, half-close), and Ichor's per-cell accounting and the
  cross-cell fast path would have to be bolted onto it. The brief prefers
  writing a component over pulling in a large crate. Its design (sans-I/O,
  explicit time) is the model ours follows.
- **One global stack with namespace filters (Linux).** Rejected by
  ADR-0002: a global table is one missed check from an escape.
- **A learning L2 bridge (Linux bridge, Docker).** Flooding and MAC
  learning let a cell observe other cells' broadcast and unknown-unicast
  traffic and spoof addresses. Assigned addresses with proxy ARP need
  neither.
- **A userspace network service (a cell running the stack).** Every packet
  would cross an address-space boundary twice. It may suit untrusted
  protocol parsers later; not the data path.

## Consequences

- A lot of protocol code to write and test, all of it safe and host-tested;
  correctness rests on the simulated-network tests, Linux interoperability
  tests in QEMU (the host talks to a cell through QEMU's user networking),
  and fuzzing the parsers.
- No global network state exists to leak across cells: ports, routes and
  sockets are per stack, and the switch delivers only addressed frames.
- Off-host traffic is NATed in milestone 5: a cell has no routable address
  of its own until cloud networking (milestone 8) can give it one.
- The polled driver costs latency against Linux's interrupt-driven one;
  the benchmarks will show it, and interrupts are owed.
