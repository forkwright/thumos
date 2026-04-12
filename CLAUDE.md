# CLAUDE.md

Thumos is a custom Rust mobile OS targeting the AGM M7 (MT6739).

## Repository

- GitHub: `forkwright/thumos` (private)
- Target: AGM M7 (MediaTek MT6739, Android 8.1 stock)
- Goal: sovereign, privacy-first OS with counter-surveillance capabilities

## Architecture

Full Rust from kernel to UI. No C we author, no Linux in the final system. Monolithic kernel.

| Layer | Status | Notes |
|-------|--------|-------|
| Kernel (thumos) | Phase 08 complete | MMU, slab allocator, GIC, timer, scheduler, 45 syscalls, IPC (pipe, futex, signals), ELF loader, VFS (Filesystem trait, MountTable, path resolution), LFS (log-structured persistent filesystem with compaction), ramfs (hierarchical, writable), devfs, block cache (LRU, 1MB), 256-fd table, ChaCha20 CSPRNG, watchdog, capabilities, DVFS, network stack (TCP/UDP sockets, DHCP, DNS resolver), firewall (packet filter, DNS blocklist), wall clock, UI framework (3-zone 240x320), telephony (AT modem, voice calls, SMS), audio session manager (MT6357 codec, priority preemption), battery monitor, T9 input, contacts, FM radio, BT A2DP, calendar/alarm/timer/stopwatch (heorte), mic audit log, measured boot (Ed25519), encrypted block device (AES-XTS), key hierarchy (PBKDF2+HKDF), lock screen (passphrase/PIN/duress), security modes (Daily/Sentinel/Panic), HMAC-chain audit log, BFU timer, panic wipe, privacy dashboard, DNS-over-TLS, 95 kernel modules |
| eMMC driver | Phase 03 | MSDC controller, PIO + DMA, GPD/BD descriptors |
| Display driver | Phase 03 | DDP pipeline (OVL→RDMA→DSI→LCM), GC9306 init/sleep/wake/backlight |
| CCCI modem driver | Phase 03 | CLDMA ring buffers, CCIF mailbox, identity containment, packet validation |
| USB driver | Phase 03 | MUSB ACM serial gadget |
| WiFi MAC (aither) | Phase 03 | WiFi gen2 HIF, MAC randomization, passive scanning, WPA supplicant |
| BT HCI (pteron) | Phase 03 | STP transport, LE Privacy address rotation, BLE scanning |
| WMT (kelyphos) | Phase 03 | CONSYS power-on, STP transport, subsystem management |
| Input (haphe) | Phase 03 | GPIO keypad, mtk-tpd touchscreen, T9 |
| Telephony (klesis) | Substantial | AT parser, CCCI/CLDMA framing, SMS PDU, GSM-7 codec |
| UI (eidolon) | Substantial | Framebuffer 240x320, widgets, dialer, status bar |
| Firewall (asphaleia) | Substantial | Packet filter, DNS blocklist, IPv4/TCP/UDP parsing |
| Encrypted storage (stegnos) | Substantial | AES-256-XTS, LUKS key derivation, secure erase |
| Signal protocol (krypta) | Substantial | X3DH, double ratchet, session management |
| Panic mode (leipsanon) | Substantial | Priority-ordered wipe, triggers, memory scrubbing |
| Radio tools (sema) | Substantial | WiFi scanner, IMSI catcher detection, rogue AP detection |
| GPS (topos) | Substantial | NMEA parser, geofencing, multi-constellation |

## Key constraints

- 13 crates (12 workspace userspace + `thumos` kernel binary, excluded from workspace), ~86K LOC (66K kernel + 20K userspace), 1,864 tests (1,386 kernel + 478 workspace), zero clippy warnings. Phase 08 (security) complete.
- 1 GB RAM: every megabyte matters. No unnecessary services.
- 240x320 display: no standard Android UI. Custom framebuffer or TUI.
- Keypad + touchscreen input. T9-style or menu navigation.
- MT6739 vendor blobs: binary-only for modem, WiFi, BT, GPS. Cannot be replaced.
- 32-bit ARM build (armv7-a-neon) despite 64-bit capable SoC.

## Tools

- **mtkclient**: BROM exploit tool for MT6739 bootloader bypass
- **SP Flash Tool**: MediaTek firmware flashing via scatter file
- **adb**: Android Debug Bridge for device probing

## Device identity protection

Thumos treats all hardware identifiers as sensitive. Every radio driver implements identity protection at the register level:

| Identifier | Mitigation |
|---|---|
| WiFi MAC | Random locally-administered MAC per connection via ring CSPRNG |
| BT MAC | LE Privacy with rotating random addresses (15-min interval) |
| IMEI | Filtered at CCCI kernel boundary, audit-logged, capability-gated |
| IMSI | SIM-resident, logged on modem access, removable battery = easy SIM swap |
| Probe requests | Passive WiFi scanning by default, no SSID broadcast |
| BLE advertisements | Non-resolvable private address (NRPA) by default |
| RF fingerprint | Accepted risk on M7 hardware. Custom PCB future addresses this. |

## TODO convention

Format: `TODO(#issue): description` or `TODO(category): description`
Categories: hw (hardware-dependent), crypto (needs crypto primitives), phase07/phase08 (deferred to future phase)

## Build

Workspace compiles on host (`cargo check/test`). Kernel cross-compiles for `armv7a-none-eabi` via `cargo build --release` in `crates/thumos/` (the bare-metal kernel binary, excluded from the main workspace). Boot image created with mkbootimg, flashed via mtkclient BROM exploit.

## Standards

Follow kanon standards (canonical source: `kanon/crates/basanos/standards/`). Key docs: `RUST.md`, `TESTING.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WRITING.md`, `REPO-SETUP.md`.

## Naming

Greek names per gnomon.md. Project name: thumos (θυμός, the fighting spirit).
