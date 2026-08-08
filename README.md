# Thumos

A privacy-first mobile OS for the AGM M7 (MediaTek MT6739), written in Rust from the kernel up.

## What it is

A custom Rust OS for the AGM M7 (MT6739, 1 GB RAM, 240x320 QVGA, IP68). Full Rust from kernel to UI - no C the project authors, no Linux underneath (the MT6739's modem/WiFi/BT/GPS vendor blobs are binary-only and cannot be replaced). The feature surface targets secure communication and counter-surveillance: on-device radio intelligence (IMSI-catcher scoring, silent-SMS detection, 2G refusal), hardware-identifier protection at the register level (WiFi/BT MAC randomization, IMEI/IMSI containment), encrypted storage, and a modem firewalled at the CCCI driver boundary.

Structurally it is a general small-mobile OS, M7 first: one kernel boots two boards behind the `board::` seam - **m7** (the field board) and **virt** (QEMU `-machine virt`, the dev board CI boots on every push). Board facts live only under `board::*`; the kernel core names no SoC directly (#534).

> **Maturity:** a broad compiled-and-tested software surface with an **executable boot** - the kernel boots end-to-end under emulation (see [Status](#status)). Hardware validation and boot/userspace wiring remain open. A named capability is a compiled/tested surface unless a boot or userspace call path reaches it.

## Name

**Thumos** (θυμός): the spirited part of Plato's tripartite soul - not reason, not appetite, but the part that resists.

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
klesis (AT commands, CCCI transport, SMS PDU) + krypta (X3DH + symmetric chain ratchets)
kelyphos (WMT combo chip STP framing) + haphe (input routing)
──────────────────────────────────────────────
thumos kernel (MMU, slab allocator, scheduler, IPC, signals, syscalls,
               boot → kardia service loop)
MT6739 hardware (modem on separate core, firewalled at CCCI driver level)
```

## Status

The kernel **boots end-to-end under QEMU** (`qemu-system-arm -machine virt`, armv7a): MMU and caches, GIC, the scheduler, the first timer interrupt, the CSPRNG, every subsystem's init step (each degrading cleanly where the emulated board lacks the hardware), the boot→service handoff, and a cooperative service loop running as PID 0 off the 100 Hz timer. **CI runs this on every push** and asserts the loop services real ticks - the first executable proof the boot path works, independent of the physical device. Hardware validation on an AGM M7 remains pending.

The system is a bare-metal kernel binary plus a set of userspace crates (input, radios, telephony, security, crypto, UI, radio tools); the kernel is excluded from the Cargo workspace so it can cross-compile to bare metal (`armv7a-none-eabi`). CI gates every push on three things: the kernel's host test suite (i686, with a u32-faithful ABI), the bare-metal cross-compile, and the QEMU boot above. The kernel implements and unit-tests the core of an OS - memory management and allocation, interrupts and scheduling, IPC and signals, syscalls, a VFS over persistent and in-memory filesystems, a CSPRNG, capabilities, power management, a watchdog - under the security, radio, telephony, and UI surfaces the userspace crates build on.

Higher-level capabilities - multi-screen UI routing, Bluetooth/GPS userspace control, BT audio, Matrix and voice flows, mesh and inbox integration - are compiled surfaces **not yet wired to the service loop**. Wiring them onto the loop is tracked work (the boot-wiring epic). `metaxu` is the thin-client protocol surface for Aletheia bridge tasks; it does not embed a live Aletheia runtime.

### Known gaps

thumos is pre-hardware. What is proven is the boot path under emulation and the unit-tested subsystem surfaces; the open work:

- **Hardware validation** on a physical AGM M7 - the frontier. QEMU exercises the boot path, not the MT6739's binary-only modem/WiFi/BT/GPS blobs.
- **Boot-wiring**: implemented capabilities are not all reachable from the boot/service loop or from userspace yet; the wiring lands incrementally. Reachability is machine-checked, not prose: see the [capability inventory](docs/capability-inventory.toml) (every module classified; CI fails on drift).
- **Real radio I/O**: WiFi packet TX/RX, scan, and association over WMT/STP are hardware work; boot degrades to a fail-closed loopback path when the data path is absent.
- **Aletheia live runtime** ([docs/ALETHEIA-BRIDGE.md](docs/ALETHEIA-BRIDGE.md), `metaxu`): grant verification (Ed25519-signed, expiring, identity-bound) and its adversarial witness are implemented and tested; live transport, a live Aletheia-side endpoint, and UI wiring are still future work.

## Related

- [akroasis](https://github.com/forkwright/akroasis): signals intelligence toolkit (thumos as field node)
- [aletheia](https://github.com/forkwright/aletheia): epistemology runtime (remote runtime for the `metaxu` thin-client bridge)

## Disclaimer

This software is for research and educational purposes. See [DISCLAIMER.md](DISCLAIMER.md) for details on user responsibility, licensing, and legal considerations. The authors accept no responsibility for any specific use of this software.
