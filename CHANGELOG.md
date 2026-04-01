# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] -- 2026-04-01

### Added

- **Kernel integration (pyknosis-boot)**: full boot sequence wires all Phase 03 drivers, kernel hands off to userspace after hardware init (PR #15)
- **USB ACM serial gadget (pyknosis-boot)**: MUSB controller driver with CDC-ACM serial gadget for debug console (PR #13)
- **GPIO keypad and touchscreen (haphe)**: GPIO keypad matrix scan and mtk-tpd touchscreen driver with interrupt-driven event delivery (PR #12)
- **BT HCI transport (pteron)**: STP framing layer and LE Privacy address rotation at 15-minute intervals, NRPA by default (PR #11)
- **WiFi MAC driver (aither)**: WiFi gen2 HIF interface with per-connection MAC randomization (locally-administered bit set) and passive scanning by default (PR #10)
- **Display driver (pyknosis-boot)**: DDP pipeline (OVL→RDMA→DSI→LCM) with pluggable `LcmDriver` trait and GC9306 stub (PR #9)
- **WMT connectivity manager (kelyphos)**: CONSYS power-on sequence, STP transport, and subsystem management for WiFi/BT combo chip (PR #8)
- **CCCI modem driver (pyknosis-boot)**: CLDMA ring buffers and CCIF mailbox for AP-modem communication; IMEI/IMSI filtered at kernel boundary, capability-gated, audit-logged (PR #6)
- **Process isolation (pyknosis-boot)**: two-process isolation with separate address spaces and `waitpid` synchronization (PR #5)
- **eMMC block device (pyknosis-boot)**: MSDC controller driver with PIO and DMA modes, GPD/BD descriptor support (PR #4)
- **Syscall expansion (pyknosis-boot)**: syscall interface expanded to 46 calls covering process, memory, IPC, file, time, and signal domains (PR #3)
- **GC9306 init sequence (docs)**: LCM initialization sequence extracted from four public sources (PR #14)
- **Device identity protection threat model**: CLAUDE.md documents per-identifier mitigations at the register level

### Changed

- Architecture pivot documented in CLAUDE.md: full Rust from kernel to UI, Linux removed from final system description

## [0.2.0] -- 2026-03-18

### Added

- Linux bootstrap: BSP kernel (Linux 4.4) cross-compiled for MT6739, all hardware interfaces documented
- Userspace crate stubs: all 13 original crates with initial code, 364 tests
- Kernel modules: 19 modules (~2,500 LOC), MMU, page allocator, slab heap, GIC, timer, basic scheduler

## [0.1.0] -- 2026-03-18

### Added

- Hardware probe complete: BROM access, firmware dump, bootloader unlock, root access
- Surveillance audit: 7 threats identified across 3 nation-state risk profiles
- Kernel module map and modem interface map extracted from stock firmware
- Initial workspace structure: 13 crates scaffolded
