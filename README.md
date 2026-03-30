# Thumos

Sovereign mobile OS for the AGM M7. Privacy-first, counter-surveillance, hardware-optimized.

## What it is

A custom Rust OS for the AGM M7 (MT6739, 1GB RAM, 240x320 QVGA, IP68) that gives the user complete sovereignty over their device. Full Rust from kernel (pyknosis) to UI. Secure communication, counter-surveillance, proactive defense. No backdoors, no telemetry, no trust in infrastructure you don't control.

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
phone (AT commands, CCCI transport, SMS PDU) + krypta (Signal protocol)
kelyphos (WMT combo chip STP framing) + haphe (input routing)
──────────────────────────────────────────────
pyknosis (custom Rust kernel: MMU, scheduler, IPC, syscalls)
MT6739 hardware (modem on separate core, firewalled at CCCI driver level)
```

## Status

Phase 03: Kernel and Drivers. Hardware probe complete (bootloader unlocked, firmware dumped, surveillance audit done). Linux bootstrap complete (BSP kernel cross-compiled, hardware interfaces documented). All 13 crates have code, 375+ tests. Kernel has MMU, page allocator, slab heap, interrupts, process model, IPC, ELF loader, syscall dispatch.

## Related

- [akroasis](https://github.com/forkwright/akroasis): signals intelligence toolkit (thumos as field node)
- [aletheia](https://github.com/forkwright/aletheia): epistemology runtime (philosophical sibling)
