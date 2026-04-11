# Architecture

Thumos is a full-Rust mobile OS targeting the AGM M7 (MT6739). No C authored, no Linux in the final system. Monolithic kernel.

## Crate map

13 crates total: 1 bare-metal kernel binary + 12 workspace library crates.

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

**Crypto**

| Crate | Description |
|-------|-------------|
| `krypta` | Signal protocol: X3DH key exchange, double ratchet, session management |
| `stegnos` | Encrypted storage: AES-256-XTS block cipher, LUKS key derivation, secure erase |

**Radio**

| Crate | Description |
|-------|-------------|
| `aither` | WiFi MAC driver, WPA2/WPA3 supplicant, EAPOL handshake |
| `pteron` | Bluetooth HCI over STP, BLE scanning, LE Privacy address rotation |
| `kelyphos` | WMT combo chip manager: firmware loading, STP framing, power control |
| `sema` | Radio analysis: WiFi/BT/cell scanning, IMSI catcher detection |
| `topos` | GPS NMEA parser, geofencing, position logging |

**Security**

| Crate | Description |
|-------|-------------|
| `asphaleia` | Packet filter firewall, DNS blocklist, capability enforcement |
| `leipsanon` | Panic mode: priority-ordered wipe, trigger system, memory scrubbing |

## Dependency direction

The kernel (`thumos`) is a standalone `no_std` binary with no workspace dependencies. Workspace crates depend on each other as follows:

```
eidolon --> haphe    (UI reads input events)
```

All other workspace crates are independent of each other. External dependencies flow downward: crates use `ring`, `nom`, `smoltcp`, `snafu`, etc. but never import from higher layers.

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
|              haphe (input)                     |
+-----------------------------------------------+
|          thumos (kernel, bare-metal)           |
+-----------------------------------------------+
|       MT6739 hardware / vendor blobs          |
+-----------------------------------------------+
```

## Extension points

- **New kernel subsystem**: add a module inside `crates/thumos/src/`. The kernel is monolithic; subsystems are modules, not separate crates.
- **New userspace domain**: add a new workspace crate in `crates/`. Register it in `Cargo.toml` workspace members. Follow naming convention (Greek, per `gnomon.md`).
- **New driver**: implement in the kernel crate if it touches hardware registers. Implement as a workspace crate if it operates at a higher abstraction (like `aither` or `pteron` which define protocol logic).

## Build

Workspace crates compile and test on the host: `cargo check --workspace`, `cargo test --workspace`. The kernel cross-compiles for `armv7a-none-eabi` via `cargo build --release` inside `crates/thumos/`. Boot image is created with `mkbootimg` and flashed via mtkclient BROM exploit.
