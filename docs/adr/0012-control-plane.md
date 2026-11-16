# ADR-0012: The control plane

- Status: Accepted
- Date: 2026-11-15
- Milestone: 6 ("control plane pulls a real OCI image from a registry,
  verifies it, converts it, and runs it through the gRPC API")

## Context

ADR-0002 fixes the frame: at boot the kernel creates one **system cell**,
which runs Ichor's native-ABI services (the control plane) and holds every
root capability; a cell is created by a holder of `CREATE_CELL`; the OCI
lifecycle maps onto `cell_create`/`cell_start`/`cell_signal`/
`cell_inspect`/`cell_destroy`; `services/` crates forbid `unsafe` as the
kernel's do (ADR-0001 §1), because the control plane is in the TCB of every
tenant. The native ABI is version 1: five calls (`docs/abi/native.md`).

Milestone 6 asks for a real pull. Measured on 2026-11-15, Docker Hub's
registry (`registry-1.docker.io`) and token service (`auth.docker.io`)
speak TLS 1.3 with X25519; the registry signs with RSA-PSS on an RSA 2048
chain (Amazon Root CA 1), the token service with ECDSA P-256/P-384 (ISRG
Root X2). Layer blobs redirect to `production.cloudflare.docker.com`, which
speaks **only TLS 1.2** (ECDHE-ECDSA, ChaCha20-Poly1305, X25519). Layers are
gzip'd tars; xtask already converts them into Ichor images on the host
(`inflate.rs`, `rootfs.rs`).

The project has no external dependencies, and writes what it needs (TCP,
BLAKE3, ChaCha20, DEFLATE, GPT, FAT) in host-tested `no_std` crates checked
against official vectors.

## Decision

### 1. A native-ABI service in the system cell, embedded in the kernel image

The control plane is `services/control`: a `no_std` + `alloc` native-ABI
program built by xtask for `x86_64-unknown-none` and embedded in the
kernel image (`include_bytes!`), so the one signed, measured image
(milestone 8) carries it. The kernel loads it into the system cell at boot
with the system cell's root capabilities, as ADR-0002's service loader.
It is single-threaded: one event loop over `OBJECT_WAIT`.

`services/rt` is the services' runtime: entry point, the `syscall`
instruction, the panic handler and a global allocator over the process's
heap. It is the **only `services/` crate allowed `unsafe`**, under the same
rules as frame (one operation per block, `// SAFETY:` comments, a line and
site count reported by `cargo xtask frame-audit`). Everything else in
`services/` is `#![forbid(unsafe_code)]`.

### 2. Native ABI version 2

Calls take handles and user buffers, never paths into another cell or
global ids. New objects and calls (exact numbers in `docs/abi/native.md`):

- **Time and logging:** `CLOCK` (monotonic and wall), `LOG` (to the
  console, tagged with the cell).
- **Waiting:** `OBJECT_WAIT(handles, deadline)` returns which handles are
  ready, so one loop serves sockets and cells.
- **Sockets on the caller's cell stack:** `TCP_CONNECT`, `TCP_LISTEN`,
  `TCP_ACCEPT`, `UDP_BIND`, `SOCK_SEND`, `SOCK_RECV` (and `SEND_TO`/
  `RECV_FROM`), all non-blocking, with readiness through `OBJECT_WAIT`. A
  socket is a handle; closing the handle closes it. They are the same
  per-cell stack the Linux personality uses (ADR-0010), charged to the
  cell.
- **Publishing:** `PORT_PUBLISH(switch, proto, uplink port, cell, port)`
  needs the switch capability, which only the system cell holds.
- **Images:** `IMAGE_CREATE(buffer)` verifies an Ichor image (its root hash
  and metadata, ADR-0006) held in the caller's memory and returns an
  `Image` handle whose pages are charged to the system cell.
- **Cells:** `CELL_CREATE(parent cell, image, memory limit)` (needs
  `CREATE_CELL`) gives a new cell with that image as its root and an upper
  layer in memory, attached to the switch; `CELL_SPAWN(cell, argv, envp,
  cwd)` starts a Linux process from the cell's root and returns a
  `Process` handle with its stdout and stderr captured; `PROCESS_WAIT`,
  `PROCESS_OUTPUT`, `CELL_SIGNAL`, `CELL_INSPECT`, `CELL_DESTROY`.

A Linux process still cannot reach these calls (ADR-0002 §5).

### 3. Protocols in host-tested `no_std` crates, ours

Each is `#![forbid(unsafe_code)]`, has no dependencies outside the
workspace, and is tested on the host against official vectors or recorded
traffic, as `kernel/net` is:

| Crate | What |
|---|---|
| `services/crypto` | SHA-256/384/512, HMAC, HKDF, the TLS 1.2 PRF; X25519 (constant-time field arithmetic); ChaCha20-Poly1305 and AES-GCM (a constant-time bitsliced AES, no tables); RSA PKCS#1 v1.5 and PSS verification; ECDSA P-256 and P-384 verification |
| `services/x509` | DER, X.509 certificates, chain building and verification to a root store, host names (RFC 6125 subset), validity times |
| `services/tls` | A sans-I/O TLS client: TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246 with ECDHE, AEAD suites only, extended master secret, RFC 5746 signalling); no renegotiation, no 0-RTT, no client certificates |
| `services/http` | HTTP/1.1 client (chunked and length bodies, redirects); HTTP/2 server with HPACK, enough for unary and server-streaming gRPC |
| `services/grpc` | Protobuf encoding and the `ichor.v1.Control` messages (`docs/abi/control.proto`), shared with the host test's client |
| `services/oci` | Image references, the registry API (token auth, manifest lists by platform, manifests, configs, blobs), digest verification |
| `services/layer` | gzip + tar into an Ichor image (moved out of xtask, which keeps using it) with OCI whiteouts |
| `services/dns` | A stub resolver over UDP (A records) |

Only public-key *verification* is needed (no signing, no client keys), so
RSA and ECDSA run on public data; the secrets are the X25519 scalar and the
traffic keys, and their code paths are constant-time by construction.

### 4. Trust and verification

- **Transport:** certificates are verified to a root store that is
  configuration, not code: xtask fetches Mozilla's CA bundle (pinned by
  SHA-256, like other artifacts) and puts it on the boot volume; the
  control plane reads it at start. No store means no HTTPS pulls.
- **Content:** a pull names a tag or a digest. The manifest's digest is
  computed and, if the reference carries one, must match; every config
  and layer blob is verified against its manifest digest while it streams
  in. The converted image's BLAKE3 root hash identifies it from then on
  (ADR-0006). Signature verification (cosign/notation) is a later step on
  top of this.
- **The API:** gRPC over h2c on a TCP port published on the uplink, with no
  authentication in milestone 6; TLS and client authentication for the
  API come with milestone 8, before Ichor runs anywhere reachable.

### 5. The API

`ichor.v1.Control`: `PullImage(reference) -> {digest, image_id, size}`,
`CreateCell(image_id, memory) -> cell_id`, `Run(cell_id, argv, env) ->
stream {stdout, stderr, exit}`, `Signal`, `Inspect`, `Destroy`. The
acceptance test, on the host, pulls `docker.io/library/alpine` at a pinned
digest through the API, creates a cell, runs a command in it, and checks
its output and exit code.

## Alternatives considered

- **The control plane as a std Rust Linux program in the system cell**,
  with tonic, tokio, rustls and the RustCrypto crates. Far less code, but
  hundreds of third-party crates in the TCB of every tenant, C and assembly
  in the usual crypto backends, and a Linux process holding native
  capabilities, which ADR-0002 rules out. Rejected.
- **Plain-HTTP pulls from a local registry only.** Avoids TLS, but no real
  registry serves plain HTTP, and the control plane must pull over the
  internet by milestone 8. Rejected; a local registry stays useful for
  offline tests.
- **TLS 1.3 only.** Smaller, but Docker Hub's blob CDN speaks only TLS 1.2
  today. Rejected.
- **Converting images on the host (xtask) and only running them in
  Ichor.** That is what milestones 4 and 5 did; the brief asks the control
  plane to pull and convert. Rejected for milestone 6.

## Consequences

- Several thousand lines of protocol and crypto code are ours to keep
  correct. They are host-tested against RFC and NIST/Wycheproof vectors
  and recorded traffic, and fuzzable like `kernel/net`.
- The native ABI grows from five calls to about thirty; each needs a
  capability check and a test that a cell without the capability is
  refused.
- `services/rt` is a second audited `unsafe` crate with its own budget.
- The kernel image grows by the control plane's size.

## Amendment (2026-11-15): as built

Milestone 6 closed with this design. Where it differs from the text
above:

- AES-GCM was left out of `services/crypto`: every Docker Hub endpoint
  (registry, token service, both blob CDNs) negotiates
  ChaCha20-Poly1305.
- Native ABI v2 has 28 calls, not about thirty, and no `CELL_SIGNAL`,
  `CELL_INSPECT` or `CELL_DESTROY` yet; the API has `PullImage`,
  `CreateCell` and `Run` only. Stdout and stderr share one pipe, so
  `RunEvent` carries one output stream.
- An image handed to `IMAGE_CREATE` is copied into pages served to the
  page cache as a RAM disk (no allocation exceeds `MAX_ORDER`, chunks are
  verified when read) and is kept for the life of the system.
- The CA bundle reaches the service as a read-only Blob capability
  (`BLOB_READ`): frame reads `\ichor\roots.pem` with the command line
  before boot services exit.
- The acceptance test pulls `hello-world` and Alpine 3.20.3 by digest
  from Docker Hub (so it needs the internet) and runs a command in each.

## Amendment (2026-11-16): exposure and authentication

§4's "no authentication in milestone 6" is narrowed before any cloud
boot:

- The API listens on the system cell's loopback by default; other cells
  and the uplink cannot reach it. `control_listen=` and
  `control_publish=` expose it explicitly.
- **Bearer token.** The operator puts a token in `\ichor\apitoken` on the
  boot volume (`cargo xtask disk-image --api-token-file F`). Frame reads
  it with the command line (never logged), and the kernel hands it to the
  service as a read-only Blob. When a token is configured, every call
  must carry `authorization: Bearer <token>`, compared in constant time;
  anything else gets `UNAUTHENTICATED`. Without a token the service
  refuses to listen beyond loopback or to publish, whatever the command
  line asks.
- **Still owed before Ichor runs anywhere reachable from the internet:**
  TLS for the API. The token travels in the clear over h2c, so today it
  protects only on a network the operator controls (a private subnet or
  an SSH tunnel). TLS needs a server side in `services/tls` and signing
  in `services/crypto`.
