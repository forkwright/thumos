<!--
scope: thumos repo conventions (bare-metal Rust kernel + embedded programs and domain libraries for AGM M7 / MT6739)
defers_to: operator CLAUDE.md (menos-ops) for machine topology; operator global CLAUDE.md for principles; kanon standards for universal engineering policy
tightens: MT6739-specific constraints and device-identity protection discipline that do not apply outside this repo
commit_types: feat,fix,docs,refactor,test,chore,perf,ci
-->

# CLAUDE.md

Thumos is a custom Rust mobile OS targeting the AGM M7 (MT6739).

## Repository

- GitHub: `forkwright/thumos` (public — CI runs on GitHub-hosted runners with free public-repo minutes; never register a self-hosted runner here, the workflows target none and this box holds operator credentials)
- Target: AGM M7 (MediaTek MT6739, Android 8.1 stock)
- Goal: privacy-first OS with counter-surveillance capabilities

## Architecture

Full Rust from kernel to UI. No C we author, no Linux in the final system. Monolithic kernel.

| Layer | Status | Notes |
|-------|--------|-------|
| Kernel (thumos) | Mixed reachability; Phases 03-11 executing | MMU, slab allocator, GIC, timer, scheduler, syscalls, IPC (pipe, futex, signals), ELF loader, VFS (Filesystem trait, MountTable, path resolution), LFS (log-structured persistent filesystem with compaction), ramfs (hierarchical, writable), devfs, block cache (LRU, 1MB), 256-fd table, ChaCha20 CSPRNG, watchdog, capabilities, test-only CPU power-policy candidate (runtime actuation absent under #879), network stack (TCP/UDP sockets, DHCP, DNS resolver), firewall (packet filter, DNS blocklist, CCCI modem firewall), wall clock, UI framework (3-zone 240x320), telephony (AT modem, voice calls, SMS), audio session manager (MT6357 codec, priority preemption), battery monitor, T9 input, contacts, FM radio, BT A2DP, calendar/alarm/timer/stopwatch (heorte), mic audit log, post-entry image/initramfs signature checks (Ed25519; not measured boot), encrypted block device (AES-XTS), key hierarchy (PBKDF2+HKDF), lock screen (passphrase/PIN/duress), security modes (Daily/Sentinel/Panic), volatile-session HMAC-chain audit log, compiled-only BFU timer, partial panic wipe, privacy dashboard, DNS-over-TLS, HTTP client, JSON parser, Matrix CS API (sync/rooms/send), Matrix E2E (Olm/Megolm), USB provisioning, unified inbox (SMS+Matrix+Briar+Meshtastic), voice-to-text (ekphrasis), action proposals, Briar P2P messaging, Meshtastic LoRa mesh, nous AI entity management (capability presets, chat screen), IMSI catcher scoring, Silent SMS detection, 2G refusal, CCCI traffic logger, modem baseline analysis, fail-closed modem/MT6357 PMIC paths pending #862, threat monitor screen, per-process image mapping (fork+exec compose; /init + /shell coexist), PROT_NONE guard pages, PID-0 fault supervision (fault ring + audit + rate-limited service restart). Consult `docs/capability-inventory.toml` for machine-checked reachability; implementation does not establish phase acceptance. |
| eMMC driver | Partially source-grounded; software gap | MSDC PIO/DMA and GPD/BD surfaces exist, but #870 owns the unverified FIFOCS.RXCNT field before live reads; an operator receipt follows software acceptance |
| Display driver | Transport unresolved; software gap | DDP/GC9306 code exists, but #854 owns the DBI/DSI contradiction and source-grounded command transport before any panel receipt |
| CCCI modem driver | Partial software path | CLDMA/CCIF and filtering code exist; the production telephony transport remains a #398 stub |
| USB driver | Gadget path, IRQ unresolved | MUSB ACM gadget code exists; #676 owns the source/physical IRQ decision |
| WiFi MAC (`aither`) | Shared core + local stub | `aither-core` policy exists; the production WMT/STP backend remains #129 |
| BT HCI (`pteron`) | Workspace library + local stub | No `pteron` runtime is linked; production HCI/ACL transport remains #129 |
| WMT (`kelyphos`) | Workspace library; not linked | Production WiFi/BT/GPS/FM WMT/STP operations remain local #129 stubs |
| Input (`haphe`) | Dev/test dependency + local drivers | Boot keypad logic exists, but #880 owns its placeholder GPIO adapter and #881 owns side-button/PTT events before #753 service-loop delivery or any physical receipt |
| Telephony (`klesis`) | Shared core + local integration | `klesis-core` parsing is reused; production modem operations remain #398 |
| UI (`eidolon`) | Shared core + routed subset | `eidolon-core` and local screens render in QEMU; several screens remain compiled-only under #753 |
| Firewall (`asphaleia`) | Shared policy + local parser | `asphaleia-core` DNS/blocklist policy is reused; packet parsing remains local and unextracted |
| Encrypted storage (`stegnos`) | Workspace library; not linked | The kernel uses its local AES-XTS encrypted-block path; no `stegnos` runtime is credited |
| E2E encryption (`krypta`) | Workspace library; protocol undecided | The kernel's local Matrix-shaped crypto is compiled-only/partial; Phase 09 selects the accepted protocol |
| Panic mode (`leipsanon`) | Workspace library; not linked | Local `panic_wipe` has reachable key/memory actions but persisted effects and reflex integration remain #863 |
| Radio tools (`sema`) | Shared types only | Only `sema-core` types are linked; production observation producers and policy integration remain open |
| GPS (`topos`) | Shared core + local stub | `topos-core` parsing is reused; production WMT/STP access remains #129 |

## Key constraints

- Crate roster: ARCHITECTURE.md's crate map, verified 1:1 against `Cargo.toml` workspace members plus the excluded kernel crate by `scripts/check-doc-inventory.sh`. LOC and test counts are deliberately not stated here — measure them (`cargo nextest run --bin thumos --target i686-unknown-linux-gnu`, `cargo nextest run --workspace`). Syscall and kernel-module counts in the kernel-capability row above are deliberately not stated either, for the same reason — enumerate `crates/thumos/src/syscall.rs`'s `Syscall` enum, or `grep -c '^mod \|^pub mod ' crates/thumos/src/main.rs`. A count written into prose drifts from the tree the moment either changes, and a stale number reads as authoritative.
- Lint surface: the workspace is clean under `cargo clippy --workspace`. The kernel crate (`crates/thumos`) is excluded from the workspace, so no `--workspace` invocation reaches it; `scripts/kernel-clippy.sh` covers it separately and is clean across **every declared feature configuration**, with the pass list parsed from `Cargo.toml`'s `[features]` so a new feature cannot be added without a pass. The `kernel` CI job is a required status check and blocks a merge, which is what makes the above enforceable rather than aspirational.
- Phases 03-11 remain executing. The capability inventory distinguishes compiled-only, kernel-wired, emulated/mock-proven, and hardware-proven surfaces; do not infer acceptance from compilation or unit tests.
- 1 GB RAM: every megabyte matters. No unnecessary services.
- 240x320 display: no standard Android UI. Custom framebuffer, three-zone layout.
- **Physical keys are the primary interaction.** The keypad and its key combinations drive navigation and every routine action, and T9 is the text-entry method. The capacitive touchscreen is present and driven (mtk-tpd, 10-point), but it is reserved for the few surfaces that genuinely want direct manipulation — composing a message is the standard example. The falsifiable form: **a function reachable only by touch is a defect**, because this is a rugged phone that has to work with gloves on, with wet hands, and with the screen unreadable in direct sun. Touch is an accelerator for the cases that deserve it, never the only path to a capability.
- MT6739 vendor blobs: binary-only for modem, WiFi, BT, GPS. Cannot be replaced.
- 32-bit ARM build (armv7-a-neon) despite 64-bit capable SoC.

## Tools

- **mtkclient**: BROM exploit tool for MT6739 bootloader bypass
- **SP Flash Tool**: MediaTek firmware flashing via scatter file
- **adb**: Android Debug Bridge for device probing

## Device identity protection

Thumos treats hardware identifiers as sensitive. The policy and host-tested logic
below are not yet fully applied by production drivers: WiFi/BT WMT operations are
#129 stubs, and CCCI can constrain only AP-visible identity access.

| Identifier | Mitigation |
|---|---|
| WiFi MAC | Policy/host logic generates a locally administered address; production application awaits #129 |
| BT identity | BLE-only private-address rotation is host-tested; production application awaits #129, while Classic BR/EDR identity remains explicit policy work |
| IMEI/IMSI | AP-visible CCCI access is capability-gated/audited where recognized; modem-to-SIM and modem-to-radio traffic is outside this boundary |
| Probe requests | Passive scanning is the intended default; production scan behavior awaits #129 |
| BLE advertisements | Non-resolvable private-address policy is host-tested; production application awaits #129 |
| RF fingerprint | Accepted risk on M7 hardware. Custom PCB future addresses this. |

## Git

The repo squash-merges: a PR title becomes `main`'s commit message, and release-please parses that message to build the changelog and compute the version bump. Grammar: `<type>(<scope>)<!>: <description>`. `type` is one of the `commit_types` declared in this file's frontmatter — `.github/workflows/pr-title.yml` (via `scripts/check-pr-title.sh`) derives its accepted list from that same line rather than restating it, so there is one place to update. `scope` is the crate/module name; `!` before the colon marks a breaking change. A bare scope in the type position (`sms: ...`) is rejected — the type must be one of the declared literals, not any word followed by a colon.

## TODO convention

Format: `TODO(#issue): description` or `TODO(category): description`
Categories: hw (hardware-dependent), crypto (needs crypto primitives), phase07/phase08 (deferred to future phase)

## Build

Workspace libraries and host tooling compile on the host (`cargo check/test`). The kernel cross-compiles for `armv7a-none-eabi` via `cargo build --release` in `crates/thumos/`; its build script compiles embedded `/init`, `/shell`, and probe programs directly for that same target. Kernel-state debugging entry point: `THUMOS_QEMU_GDB=1` + `scripts/gdb-thumos.sh` (see `scripts/README.md`). QEMU build, boot-witness, and diagnosis procedures live in `RUNBOOK.md`. The repository does not yet produce an Android boot image or scatter-integrated device package; #467 owns that software prerequisite and its later operator-owned device witness.

## Standards

Follow kanon standards (canonical source: `kanon/crates/basanos/standards/`). Key docs: `RUST.md`, `TESTING.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WRITING.md`, `REPO-SETUP.md`.

## Naming

Greek project names follow Kanon's `NAMING.md`; structural fit is evaluated through Kanon's `GNOMON.md`. Project name: thumos (θυμός, the fighting spirit).
