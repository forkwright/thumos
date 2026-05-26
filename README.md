# Thumos

Sovereign mobile OS for the AGM M7. Privacy-first, counter-surveillance, hardware-optimized.

## What it is

A custom Rust OS for the AGM M7 (MT6739, 1GB RAM, 240x320 QVGA, IP68) that gives the user complete sovereignty over their device. Full Rust from kernel to UI. Secure communication, counter-surveillance, proactive defense. No backdoors, no telemetry, no trust in infrastructure you don't control.

> **Current status:** The repository contains a broad compiled and tested software surface, but hardware validation and several boot/userspace wiring paths remain open.

## Name

**Thumos** (θυμός): the spirited part of Plato's tripartite soul. Not reason, not appetite. The part that gets angry at injustice and fights back. The force that makes you resist when submission would be easier.

## Target hardware

| Component | Spec |
|-----------|------|
| SoC | MediaTek MT6739 (4x Cortex-A53 @ 1.5GHz) |
| RAM | 1 GB LPDDR3 |
| Storage | 8 GB eMMC, microSD to 128 GB |
| Display | 2.4" IPS, 240x320 QVGA |
| Radios | LTE Cat.4, WiFi a/b/g/n, BT 4.2, GPS/GLONASS/BeiDou |
| Durability | IP68, IP69K, MIL-STD-810H |
| Battery | 2500 mAh, removable |

## Architecture

```
eidolon (framebuffer UI, widget system)
asphaleia (packet filter) + stegnos (encrypted storage) + leipsanon (panic mode)
sema (radio tools) + aither (WiFi) + pteron (BT) + topos (GPS)
klesis (AT commands, CCCI transport, SMS PDU) + krypta (Signal protocol)
kelyphos (WMT combo chip STP framing) + haphe (input routing)
──────────────────────────────────────────────
thumos kernel (MMU, slab allocator, scheduler, IPC, signals, 45 syscalls)
MT6739 hardware (modem on separate core, firewalled at CCCI driver level)
```

## Status

**Phase 11: System Qualification** (canonical tracker last updated 2026-04-20; phase status updated 2026-04-12). Hardware validation is pending on an AGM M7 factory firmware flash. Phase 10 names a compiled/tested code catalog, not a claim that every named capability is boot-wired, reachable from userspace, or hardware-ready.

13 crates (12 userspace workspace members plus the `thumos` kernel binary, excluded from the main workspace for bare-metal builds), 2,313 tests (1,618 kernel + 695 workspace), ~102K LOC (81K kernel, 21K userspace), 107 kernel modules. The kernel has implemented and tested core surfaces including MMU, allocator, GIC/timer, scheduler, IPC, signals, 45 syscalls, VFS with LFS/ramfs/devfs, block cache, CSPRNG, capabilities, DVFS, watchdog, telephony parsing/containment, security modes, lock screen, audit log, panic wipe, measured boot primitives, encryption primitives, and several UI/radio/messaging modules. Named higher-level capabilities such as multi-screen UI routing, calendar/alarm runtime ownership, wall-clock trust selection, Bluetooth/GPS userspace control, BT audio, Matrix/voice assistant flows, and mesh/inbox integrations remain compiled surfaces unless a boot or userspace call path is listed in the wiring audit.

_Phase, test split, LOC, and module totals are aligned to the internal project state record. Crate count was verified with `ls -d crates/*/ | wc -l` on 2026-05-04. A cheap source grep (`rg "#\[test\]" crates/ | wc -l`) reports 2,187 annotated test functions, so the canonical test inventory remains the source of truth without a full cargo listing._

### Known gaps

The Phase 10 / Phase 11 status above describes compiled and tested surfaces, not end-to-end readiness. The following work is open and is not yet wired end-to-end on hardware:

- [#141](https://github.com/forkwright/thumos/issues/141) — aletheia agent runtime bridge is not yet designed or wired
- [#142](https://github.com/forkwright/thumos/issues/142) — boot-time security subsystems are success-without-work placeholders
- [#143](https://github.com/forkwright/thumos/issues/143) — network stack still boots on a firewall-backed loopback path; WiFi driver remains unwired
- Userspace image packaging remains incomplete: boot reports missing `/init` or `/shell` entries instead of spawning kernel-owned idle placeholders.
- [#145](https://github.com/forkwright/thumos/issues/145) — advertised kernel features compiled but unwired: current baseline is 8 crate-level `dead_code` expectations plus 48 item-level suppressions; see [kernel wiring audit](docs/KERNEL-WIRING-AUDIT.md)
- [#146](https://github.com/forkwright/thumos/issues/146) — remaining direct `ring` dependency is isolated to `krypta` protocol crypto

## Related

- [akroasis](https://github.com/forkwright/akroasis): signals intelligence toolkit (thumos as field node)
- [aletheia](https://github.com/forkwright/aletheia): epistemology runtime (philosophical sibling)

## Disclaimer

This software is for research and educational purposes. See [DISCLAIMER.md](DISCLAIMER.md) for details on user responsibility, licensing, and legal considerations. The authors accept no responsibility for any specific use of this software.
