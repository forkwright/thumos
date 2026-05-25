# Thumos

Sovereign mobile OS for the AGM M7. Privacy-first, counter-surveillance, hardware-optimized.

## What it is

A custom Rust OS for the AGM M7 (MT6739, 1GB RAM, 240x320 QVGA, IP68) that gives the user complete sovereignty over their device. Full Rust from kernel to UI. Secure communication, counter-surveillance, proactive defense. No backdoors, no telemetry, no trust in infrastructure you don't control.

> **Current status:** Active phase tracking, blockers, and hardware-validation status are maintained in the internal planning record.

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

**Phase 11: System Qualification** (canonical tracker last updated 2026-04-20; phase status updated 2026-04-12). Hardware validation is pending on an AGM M7 factory firmware flash; all software milestones through Phase 10 are complete and no software blockers remain.

13 crates (12 userspace workspace members plus the `thumos` kernel binary, excluded from the main workspace for bare-metal builds), 2,313 tests (1,618 kernel + 695 workspace), ~102K LOC (81K kernel, 21K userspace), 107 kernel modules. Kernel implements 45 syscalls including fork/exec/waitpid, mmap/brk/mprotect, pipe/futex IPC, POSIX signals (sigaction/kill/sigreturn), clock_gettime/nanosleep, network sockets (TCP/UDP/bind/listen/accept/connect/sendto/recvfrom). Slab allocator (7 size classes), ChaCha20 CSPRNG, capability-based access control, DVFS power management, watchdog timer, VFS with LFS/ramfs/devfs, firewall with DNS blocklist, DHCP client, DNS resolver, 3-zone UI framework (240x320), telephony (AT modem, voice calls, SMS), audio session manager (MT6357 codec, priority preemption), battery monitor, T9 input, contacts, FM radio, BT A2DP, calendar/alarm/timer/stopwatch (heorte), mic audit log, measured boot (Ed25519), encrypted block device (AES-256-XTS), key hierarchy (PBKDF2+HKDF), lock screen (passphrase/PIN/duress), security modes (Daily/Sentinel/Panic/Covert Lock), HMAC-chain audit log, BFU auto-reboot timer, panic wipe, privacy dashboard, DNS-over-TLS, HTTP client, JSON parser, Matrix CS API (sync/rooms/send), Matrix E2E encryption (Olm/Megolm), USB credential provisioning, unified inbox (SMS + Matrix + Briar + Meshtastic with bridge support), voice-to-text (ekphrasis via aletheia STT), action proposals, Briar P2P messaging, Meshtastic LoRa mesh, nous AI entity management (capability presets, chat screen with action proposal cards), IMSI catcher scoring, Silent SMS detection, 2G refusal, CCCI traffic logger, modem baseline analysis, CCCI modem firewall, modem PMIC power cut, threat monitor screen. Hardware drivers: eMMC (MSDC), display (DDP + GC9306), WiFi MAC (randomization), BT HCI (LE Privacy), WMT, CCCI modem containment, USB ACM, GPIO keypad, touchscreen, GPS (NMEA), Bluetooth (STP/HCI).

_Phase, test split, LOC, and module totals are aligned to the internal project state record. Crate count was verified with `ls -d crates/*/ | wc -l` on 2026-05-04. A cheap source grep (`rg "#\[test\]" crates/ | wc -l`) reports 2,187 annotated test functions, so the canonical test inventory remains the source of truth without a full cargo listing._

### Known gaps

The Phase 10 / Phase 11 status above describes the kernel's compiled and tested surface. The following surface is tracked as open work and is not yet wired end-to-end on hardware:

- [#142](https://github.com/forkwright/thumos/issues/142) — boot-time security subsystems are success-without-work placeholders
- [#143](https://github.com/forkwright/thumos/issues/143) — network stack boots on loopback; WiFi driver and firewall unwired
- [#144](https://github.com/forkwright/thumos/issues/144) — userspace process spawn falls back to wfe idle loop (no /init or /shell ELF)
- [#145](https://github.com/forkwright/thumos/issues/145) — ~30 advertised kernel features compiled but unwired (dead-code suppressions)
- [#146](https://github.com/forkwright/thumos/issues/146) — `ring` dependency violates pure-Rust sovereignty policy in 4 crates

## Related

- [akroasis](https://github.com/forkwright/akroasis): signals intelligence toolkit (thumos as field node)
- [aletheia](https://github.com/forkwright/aletheia): epistemology runtime (philosophical sibling)

## Disclaimer

This software is for research and educational purposes. See [DISCLAIMER.md](DISCLAIMER.md) for details on user responsibility, licensing, and legal considerations. The authors accept no responsibility for any specific use of this software.
