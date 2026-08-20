# Architecture

Thumos is a full-Rust small-mobile OS. No C authored, no Linux in the final system. Its monolithic kernel builds for two static board configurations; only `virt` has a boot receipt:

- **m7** — the AGM M7 feature phone (MT6739 SoC), the unqualified field-board target;
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

### Workspace crates

**UI**

| Crate | Description |
|-------|-------------|
| `eidolon` | Framebuffer UI: 240x320 rendering, widgets, T9 input, status bar |
| `eidolon-core` | Canonical display layout geometry (screen size, the three zone heights, and everything derived from them), shared no_std with the kernel's `ui.rs` (#545, #740) |

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
| `aither` | WiFi library with WPA2/EAPOL logic; WPA3-SAE remains unimplemented under #864 |
| `aither-core` | Canonical EAPOL frame parse/encode, PMK/PTK/MIC derivation, and the WPA2 4-way handshake state machine, shared no_std with the kernel (#545, #819) |
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
| `asphaleia-core` | Canonical DNS parsing and blocklist policy shared no_std with the kernel; IPv4/TCP/UDP packet parsing remains duplicated and tracked for extraction (#545) |
| `leipsanon` | Panic mode: priority-ordered wipe, trigger system, memory scrubbing |

**Cognition bridge**

| Crate | Description |
|-------|-------------|
| `metaxu` | Aletheia/Thumos thin-client bridge protocol: typed tasks, capability grant claims, opaque identity references |
| `metaxu-core` | no_std+alloc envelope framing, signed-grant verification, and typed task/response payloads, shared with the kernel (#544, #545) |

**Build tooling**

| Crate | Description |
|-------|-------------|
| `hypographe` | Boot-image signing tool: streamed Ed25519ph signer producing the payload‖signature layout the kernel's boot gate verifies (#467) |

## Dependency direction

Workspace crates depend on each other as follows:

```
eidolon --> haphe    (UI reads input events)
```

That is the only cross-domain edge. Seven domain crates additionally split off
a `no_std`(+alloc) `-core` sibling that both the workspace crate and the
kernel depend on directly. The semantics actually named by each core have one
implementation (the #545 convergence pattern described above); the firewall
packet parser remains the declared exception in `docs/convergence.toml`:
`aither` ->
`aither-core`, `eidolon` -> `eidolon-core`, `asphaleia` ->
`asphaleia-core`, `klesis` -> `klesis-core`, `sema` -> `sema-core`, `topos`
-> `topos-core`, `metaxu` -> `metaxu-core`.
These are same-layer splits, not cross-layer imports. Beyond `eidolon -->
haphe` and the seven `-core` splits, workspace crates are independent of each
other. External dependencies flow downward: crates use RustCrypto, `nom`,
`smoltcp`, `snafu`, etc. but never import from higher layers. `metaxu` is a
protocol boundary only; it does not embed the Aletheia runtime or wire a
live network transport.

The kernel (`thumos`) is `no_std` and excluded from the workspace, but it is
not dependency-free: it path-links all seven `-core` crates directly as real
`[dependencies]` (compiled into the release build) plus `haphe` as a
`[dev-dependencies]`-only pin used to cross-check `ui.rs`'s local `Key` enum
against the real one in host tests (#615) — excluded from the shipped
armv7a-none-eabi binary.

**Rule**: lower layers do not import from higher layers. `haphe` does not
depend on `eidolon`, radio crates do not depend on security crates, and the
kernel takes no *workspace-crate* dependency beyond the `-core` splits and
its test-only `haphe` pin — each layer compiles and tests without pulling in
the ones above it.

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
- **New workspace domain library**: add a new workspace crate in `crates/`. Register it in `Cargo.toml` workspace members. Follow Kanon's [naming standard](https://github.com/forkwright/kanon/blob/main/crates/basanos/standards/NAMING.md) and [Gnomon structural-color standard](https://github.com/forkwright/kanon/blob/main/crates/basanos/standards/GNOMON.md).
- **New driver**: implement in the kernel crate if it touches hardware registers. Implement as a workspace crate if it operates at a higher abstraction (like `aither` or `pteron` which define protocol logic).
- **Aletheia bridge task**: extend `metaxu` protocol types first. Wire live transports separately through existing network and policy layers; do not bypass firewall boot sequencing or userspace spawn work.

## Build

Workspace libraries and the signing tool compile and test on the host: `cargo check --workspace`, `cargo test --workspace`. The kernel cross-compiles for `armv7a-none-eabi` via `cargo build --release` inside `crates/thumos/`; its build script compiles the embedded `/init`, `/shell`, and probe programs directly for the same bare-metal target. The kernel source builds both boards: default is the m7 field board, while `--features qemu` selects the virt dev board. CI boots that image on pull requests targeting `main`, pushes to `main`, and manual dispatches. QEMU build, boot-witness, and diagnosis procedures live in `RUNBOOK.md`. The repository does not yet produce an Android boot image or scatter-integrated device package; #467 owns that software prerequisite and its subsequent operator-owned device witness.
