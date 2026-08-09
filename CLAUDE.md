<!--
scope: thumos repo conventions (bare-metal Rust kernel + userspace for AGM M7 / MT6739)
defers_to: operator CLAUDE.md (menos-ops) for machine topology; operator global CLAUDE.md for principles; kanon standards for universal engineering policy
tightens: MT6739-specific constraints and device-identity protection discipline that do not apply outside this repo
commit_types: feat,fix,docs,refactor,test,chore,perf,ci
-->

# CLAUDE.md

Thumos is a custom Rust mobile OS targeting the AGM M7 (MT6739).

## Repository

- GitHub: `forkwright/thumos` (private)
- Target: AGM M7 (MediaTek MT6739, Android 8.1 stock)
- Goal: privacy-first OS with counter-surveillance capabilities

## Architecture

Full Rust from kernel to UI. No C we author, no Linux in the final system. Monolithic kernel.

| Layer | Status | Notes |
|-------|--------|-------|
| Kernel (thumos) | Phase 10 compiled/tested surface | MMU, slab allocator, GIC, timer, scheduler, 45 syscalls, IPC (pipe, futex, signals), ELF loader, VFS (Filesystem trait, MountTable, path resolution), LFS (log-structured persistent filesystem with compaction), ramfs (hierarchical, writable), devfs, block cache (LRU, 1MB), 256-fd table, ChaCha20 CSPRNG, watchdog, capabilities, DVFS, network stack (TCP/UDP sockets, DHCP, DNS resolver), firewall (packet filter, DNS blocklist, CCCI modem firewall), wall clock, UI framework (3-zone 240x320), telephony (AT modem, voice calls, SMS), audio session manager (MT6357 codec, priority preemption), battery monitor, T9 input, contacts, FM radio, BT A2DP, calendar/alarm/timer/stopwatch (heorte), mic audit log, measured boot (Ed25519), encrypted block device (AES-XTS), key hierarchy (PBKDF2+HKDF), lock screen (passphrase/PIN/duress), security modes (Daily/Sentinel/Panic), HMAC-chain audit log, BFU timer, panic wipe, privacy dashboard, DNS-over-TLS, HTTP client, JSON parser, Matrix CS API (sync/rooms/send), Matrix E2E (Olm/Megolm), USB provisioning, unified inbox (SMS+Matrix+Briar+Meshtastic), voice-to-text (ekphrasis), action proposals, Briar P2P messaging, Meshtastic LoRa mesh, nous AI entity management (capability presets, chat screen), IMSI catcher scoring, Silent SMS detection, 2G refusal, CCCI traffic logger, modem baseline analysis, modem PMIC power cut, threat monitor screen, per-process image mapping (fork+exec compose; /init + /shell coexist), PROT_NONE guard pages, PID-0 fault supervision (fault ring + audit + rate-limited service restart), 119 kernel modules; end-to-end boot/userspace wiring gaps are tracked in README Known gaps |
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
| E2E encryption (krypta) | Substantial | X3DH, directional symmetric chain ratchets (no DH ratchet, #543), session management |
| Panic mode (leipsanon) | Substantial | Priority-ordered wipe, triggers, memory scrubbing |
| Radio tools (sema) | Substantial | WiFi scanner, IMSI catcher detection, rogue AP detection |
| GPS (topos) | Substantial | NMEA parser, geofencing, multi-constellation |

## Key constraints

- Crate roster: ARCHITECTURE.md's crate map (verified 1:1 against `Cargo.toml` workspace members + the excluded kernel crate by `scripts/check-doc-inventory.sh`). ~138K LOC (111K kernel + 27K userspace), ~2,900 tests (2,234 kernel on i686 + 661 workspace), zero clippy warnings. Phase 10 (radio intelligence + counter-surveillance) compiled/tested surface complete; end-to-end boot/userspace wiring gaps are tracked in README Known gaps. NOTE: LOC/test counts are hand-maintained and drift — measure before quoting (`ls crates/thumos/src/*.rs | wc -l`, `cargo nextest run --bin thumos --target i686-unknown-linux-gnu`).
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

## Git

The repo squash-merges: a PR title becomes `main`'s commit message, and release-please parses that message to build the changelog and compute the version bump. Grammar: `<type>(<scope>)<!>: <description>`. `type` is one of the `commit_types` declared in this file's frontmatter — `.github/workflows/pr-title.yml` (via `scripts/check-pr-title.sh`) derives its accepted list from that same line rather than restating it, so there is one place to update. `scope` is the crate/module name; `!` before the colon marks a breaking change. A bare scope in the type position (`sms: ...`) is rejected — the type must be one of the declared literals, not any word followed by a colon.

## TODO convention

Format: `TODO(#issue): description` or `TODO(category): description`
Categories: hw (hardware-dependent), crypto (needs crypto primitives), phase07/phase08 (deferred to future phase)

## Build

Workspace compiles on host (`cargo check/test`). Kernel cross-compiles for `armv7a-none-eabi` via `cargo build --release` in `crates/thumos/` (the bare-metal kernel binary, excluded from the main workspace). Boot image created with mkbootimg, flashed via mtkclient BROM exploit. Kernel-state debugging entry point: `THUMOS_QEMU_GDB=1` + `scripts/gdb-thumos.sh` (see `scripts/README.md`).

## Standards

Follow kanon standards (canonical source: `kanon/crates/basanos/standards/`). Key docs: `RUST.md`, `TESTING.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WRITING.md`, `REPO-SETUP.md`.

## Naming

Greek names per gnomon.md. Project name: thumos (θυμός, the fighting spirit).
