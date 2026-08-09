# Architecture

Thumos is a full-Rust small-mobile OS. No C authored, no Linux in the final system. Monolithic kernel. It boots one kernel on two boards:

- **m7** — the AGM M7 feature phone (MT6739 SoC), the field board;
- **virt** — QEMU `-machine virt` (armv7a), the dev board every CI witness boots on (selected by the kernel's `qemu` feature).

Board specifics (MMIO maps, device set, bring-up behavior) live behind the `board::` module seam in the kernel crate — `board::m7` and `board::virt`, selected at one point in `board/mod.rs`. The standing invariant is structural, not prose: no `MT6739_*` identifier exists outside `board::m7`, and no board-MMIO value is re-declared as a constant outside `board/` (`scripts/check-board-seam.sh` reds on drift). Per-subsystem `HwOps` traits remain the driver seam; there is deliberately no mega-HAL, no device-tree parser, and no runtime board detection — two static boards want static config (#534).

## Crate map

The kernel binary plus the workspace crates below make up the full crate
set — verified 1:1 against `Cargo.toml` workspace members (plus the
excluded kernel crate) by `scripts/check-doc-inventory.sh`.

The kernel links `sema-core` (the canonical threat-semantics types) by path
dependency — the first instance of the #545 convergence topology: shared
protocol/policy invariants live in no_std+alloc core crates the kernel and
the workspace both consume; the full pair ledger and the ratchet enforcing
it live in `docs/convergence.toml` + `scripts/check-convergence.sh`.

### Kernel binary (excluded from workspace)

| Crate | Description |
|-------|-------------|
| `thumos` | Bare-metal ARM kernel: MMU, scheduler, syscalls, IPC, VFS, drivers, network stack |

### Workspace library crates

**UI**

| Crate | Description |
|-------|-------------|
| `eidolon` | Framebuffer UI: 240x320 rendering, widgets, T9 input, status bar |

**Input**

| Crate | Description |
|-------|-------------|
| `haphe` | GPIO keypad matrix scan, touchscreen driver, event queue (`no_std`) |

**Telephony**

| Crate | Description |
|-------|-------------|
| `klesis` | AT command parser, CCCI/CLDMA framing, SMS PDU, GSM-7 codec |
| `klesis-core` | Canonical GSM-7 codec, SMS-PDU primitives, and silent-SMS/WAP-Push classification, shared no_std with the kernel (#545, #662) |

**Crypto**

| Crate | Description |
|-------|-------------|
| `krypta` | X3DH key exchange, directional symmetric chain ratchets (NOT the Signal Double Ratchet — no DH ratchet, #543), session management |
| `stegnos` | Encrypted storage: AES-256-XTS block cipher, LUKS key derivation, secure erase |

**Radio**

| Crate | Description |
|-------|-------------|
| `aither` | WiFi MAC driver, WPA2/WPA3 supplicant, EAPOL handshake |
| `pteron` | Bluetooth HCI over STP, BLE scanning, LE Privacy address rotation |
| `kelyphos` | WMT combo chip manager: firmware loading, STP framing, power control |
| `sema` | Radio analysis: WiFi/BT/cell scanning, IMSI catcher detection |
| `sema-core` | no_std+alloc threat semantics (canonical ThreatLevel/Calibration + band invariants, shared with the kernel, #545) |
| `topos` | GPS NMEA parser, geofencing, position logging |
| `topos-core` | Canonical NMEA checksum framing, coordinate/fix-quality semantics, and GGA/RMC sentence parsing, shared no_std with the kernel (#545) |

**Security**

| Crate | Description |
|-------|-------------|
| `asphaleia` | Packet filter firewall, DNS blocklist, capability enforcement |
| `asphaleia-core` | Canonical packet-parse + DNS-policy semantics, shared no_std with the kernel (#545) |
| `leipsanon` | Panic mode: priority-ordered wipe, trigger system, memory scrubbing |

**Cognition bridge**

| Crate | Description |
|-------|-------------|
| `metaxu` | Aletheia/Thumos thin-client bridge protocol: typed tasks, capability grant claims, opaque identity references |
| `metaxu-core` | no_std+alloc envelope framing, signed-grant verification, and typed task/response payloads, shared with the kernel (#544, #545) |

**Build tooling**

| Crate | Description |
|-------|-------------|
| `sphragis` | Boot-image signing tool: streamed Ed25519ph signer producing the payload‖signature layout the kernel's boot gate verifies (#467) |

## Dependency direction

The kernel (`thumos`) is a standalone `no_std` binary with no workspace dependencies. Workspace crates depend on each other as follows:

```
eidolon --> haphe    (UI reads input events)
```

All other workspace crates are independent of each other. External dependencies flow downward: crates use RustCrypto, `nom`, `smoltcp`, `snafu`, etc. but never import from higher layers. `metaxu` is a protocol boundary only; it does not embed the Aletheia runtime or wire a live network transport.

**Rule**: lower layers do not import from higher layers. `haphe` does not depend on `eidolon`. Radio crates do not depend on security crates. The kernel depends on nothing in the workspace.

## Layer diagram

```
+-----------------------------------------------+
|                  eidolon (UI)                  |
+-----------------------------------------------+
|   klesis   |   krypta   |     sema            |
| (telephony)| (crypto)   |  (radio tools)      |
+-----------------------------------------------+
|  aither  |  pteron  |  kelyphos  |   topos    |
|  (WiFi)  |   (BT)   |   (WMT)   |   (GPS)    |
+-----------------------------------------------+
|  asphaleia (firewall) | leipsanon (panic mode)|
|  stegnos (encrypted storage)                  |
+-----------------------------------------------+
|  metaxu (Aletheia/Thumos thin-client bridge)  |
+-----------------------------------------------+
|              haphe (input)                     |
+-----------------------------------------------+
|          thumos (kernel, bare-metal)           |
+-----------------------------------------------+
|        board::m7  |  board::virt (qemu)        |
+-----------------------------------------------+
```

## Extension points

- **New kernel subsystem**: add a module inside `crates/thumos/src/`. The kernel is monolithic; subsystems are modules, not separate crates.
- **New userspace domain**: add a new workspace crate in `crates/`. Register it in `Cargo.toml` workspace members. Follow naming convention (Greek, per `gnomon.md`).
- **New driver**: implement in the kernel crate if it touches hardware registers. Implement as a workspace crate if it operates at a higher abstraction (like `aither` or `pteron` which define protocol logic).
- **Aletheia bridge task**: extend `metaxu` protocol types first. Wire live transports separately through existing network and policy layers; do not bypass firewall boot sequencing or userspace spawn work.

## Build

Workspace crates compile and test on the host: `cargo check --workspace`, `cargo test --workspace`. The kernel cross-compiles for `armv7a-none-eabi` via `cargo build --release` inside `crates/thumos/` — the same source builds both boards: default is the m7 field board, `--features qemu` selects the virt dev board (CI boots that image on every push). Boot image is created with `mkbootimg` and flashed via mtkclient BROM exploit.
