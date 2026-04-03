# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1](https://github.com/forkwright/thumos/compare/v0.1.0...v0.1.1) (2026-04-03)


### Features

* **aither:** add WiFi MAC driver with identity protection ([#10](https://github.com/forkwright/thumos/issues/10)) ([2011007](https://github.com/forkwright/thumos/commit/2011007599446d40a03948ce7383af15a7aae934))
* **aither:** WiFi management — EAPOL parsing, WPA key derivation, network selection ([d72b809](https://github.com/forkwright/thumos/commit/d72b809379a65b909262f828ace9292f396ce58d))
* **asphaleia:** packet filter core — IPv4/TCP/UDP parsing, rule engine, DNS blocklist ([52a64a4](https://github.com/forkwright/thumos/commit/52a64a455d0b893d28b614d48620385e7296d977))
* CI workflows + topos NMEA parser (11 tests) + haphe touch support planned ([f8286e1](https://github.com/forkwright/thumos/commit/f8286e1e055d6eb85809bfd95cda550a0a0ad2d4))
* **eidolon:** framebuffer rendering — color, font, status bar ([fc0696b](https://github.com/forkwright/thumos/commit/fc0696b2e0be3682e6b6b7dea5bf3e7ea1b027de))
* **eidolon:** widget system and menu navigation (W4-02) ([1306cdc](https://github.com/forkwright/thumos/commit/1306cdcce7009f6cfad756fa24b1898cd58ac220))
* **haphe:** add GPIO keypad matrix scan and mtk-tpd touchscreen driver ([#12](https://github.com/forkwright/thumos/issues/12)) ([e27e98b](https://github.com/forkwright/thumos/commit/e27e98b2da5e4c3b44157a901af5444350894b1b))
* **haphe:** input subsystem — keypad, touchscreen, T9 text input ([5759f85](https://github.com/forkwright/thumos/commit/5759f8559cee0e482c3ccd85808a8c940b4187d8))
* **kelyphos:** STP framing protocol for MT6739 combo chip ([02868df](https://github.com/forkwright/thumos/commit/02868df0b6957f881d491208b4d1b92dfc33d209))
* **kelyphos:** WMT power sequencing and STP transport ([#8](https://github.com/forkwright/thumos/issues/8)) ([581d570](https://github.com/forkwright/thumos/commit/581d570132834e052ec0e3c565888ee8c79da530))
* **krypta:** Signal protocol core — X3DH key agreement, symmetric ratchet, session encryption ([1beb9c2](https://github.com/forkwright/thumos/commit/1beb9c2a8f802c62748fc7081920da0b413139fb))
* **leipsanon:** panic mode — wipe targets, secure memory, engine, triggers ([4ae0eb9](https://github.com/forkwright/thumos/commit/4ae0eb994d889bd4dec2935076f557001625c4a5))
* **phone:** add SMS PDU encoding/decoding ([25fa748](https://github.com/forkwright/thumos/commit/25fa7489abf13c1a00130e7138578d7a98586c58))
* **phone:** AT command parser with 12 tests passing ([ce2dd3e](https://github.com/forkwright/thumos/commit/ce2dd3ef6c509d455a59fd5f749cc65177039323))
* **phone:** CCCI modem channel abstraction — ccci, cldma, transport ([8e2d76d](https://github.com/forkwright/thumos/commit/8e2d76d8706cbbb1e8c6277b5ba51ae49a83366c))
* **pteron:** add STP transport layer and LE Privacy address rotation ([#11](https://github.com/forkwright/thumos/issues/11)) ([229a251](https://github.com/forkwright/thumos/commit/229a251f5d0d54a8cb6092fc95b8966d59d81f3c))
* **pyknosis-boot:** add CCCI kernel driver for AP-modem communication ([#6](https://github.com/forkwright/thumos/issues/6)) ([c8cd94d](https://github.com/forkwright/thumos/commit/c8cd94d311ecd620412c59a6ac976947321ac219))
* **pyknosis-boot:** add DDP display driver with pluggable LCM trait ([#9](https://github.com/forkwright/thumos/issues/9)) ([27d0f69](https://github.com/forkwright/thumos/commit/27d0f691ed2233ee198826499e07886c7a12136c))
* **pyknosis-boot:** prove two-process isolation with separate address spaces ([#5](https://github.com/forkwright/thumos/issues/5)) ([9c649d5](https://github.com/forkwright/thumos/commit/9c649d517b99aaf442555723042cf851f27176bf))
* **pyknosis:** add eMMC block device driver for MT6739 MSDC controller ([#4](https://github.com/forkwright/thumos/issues/4)) ([325bdd8](https://github.com/forkwright/thumos/commit/325bdd8775c9ecf06cb96365e13268b4f8d5ceb7))
* **pyknosis:** add MMIO primitives and physical page allocator ([02eedb8](https://github.com/forkwright/thumos/commit/02eedb86873491a2d9adbbb1407eafb52bcffc48))
* **pyknosis:** add MUSB USB controller driver with ACM serial gadget ([#13](https://github.com/forkwright/thumos/issues/13)) ([7e0375e](https://github.com/forkwright/thumos/commit/7e0375e8a168f852b42f6935aa27f00bfff1eaf1))
* **pyknosis:** ARMv7 MMU with identity mapping and cache enable ([bd540d9](https://github.com/forkwright/thumos/commit/bd540d9ad27d4343a1701e7b229d7080c530973c))
* **pyknosis:** bare-metal Rust kernel boots on MT6739 ([7f7930f](https://github.com/forkwright/thumos/commit/7f7930f8701b5b34c5cedb5a82715a478dbe92b0))
* **pyknosis:** device registry with MT6739 hardware addresses ([465ffba](https://github.com/forkwright/thumos/commit/465ffba506de504db72b83ebe52b3d75e49457ff))
* **pyknosis:** ELF32 loader for ARM userspace binaries ([452c666](https://github.com/forkwright/thumos/commit/452c66690740cf5cf3cae72562ef7fb4e4baab01))
* **pyknosis:** exception vector table, IRQ handler, timer tick ([a89efb9](https://github.com/forkwright/thumos/commit/a89efb98ec9ad672df60fa7cf269200a9b28a957))
* **pyknosis:** expand syscall interface to 46 calls with domain grouping ([#3](https://github.com/forkwright/thumos/issues/3)) ([5adaa71](https://github.com/forkwright/thumos/commit/5adaa714e56afc5e34e50dc6154e5c411755d442))
* **pyknosis:** GIC interrupt controller and ARM generic timer ([b9bb3ca](https://github.com/forkwright/thumos/commit/b9bb3ca14daba4cb96c864e2eeee3e4e911076a7))
* **pyknosis:** IPC message passing + SEND/RECV syscalls ([172b8b4](https://github.com/forkwright/thumos/commit/172b8b425c5116440c69591cb073e358f9622dfa))
* **pyknosis:** kernel config — constants, runtime parameters, cmdline parser ([ce80a53](https://github.com/forkwright/thumos/commit/ce80a5323d283d1f8d0f55b6884dbbd1140ea959))
* **pyknosis:** kernel debug console with commands ([c2e7a43](https://github.com/forkwright/thumos/commit/c2e7a4342d199432427436cd677e94b234fb9988))
* **pyknosis:** kernel heap allocator with GlobalAlloc support ([be1f75e](https://github.com/forkwright/thumos/commit/be1f75ecb6aa6f4dd6aadd3d78a54ae7ab513301))
* **pyknosis:** kernel init sequence — ordered subsystem startup ([950d4c1](https://github.com/forkwright/thumos/commit/950d4c135c870578ae2d89fb9f45fc53f46b34fd))
* **pyknosis:** power management — radio kill switches and power modes ([f41bed8](https://github.com/forkwright/thumos/commit/f41bed85e7dbb19989aff75c135736f93110d527))
* **pyknosis:** process abstraction with context switch and round-robin scheduler ([3608d30](https://github.com/forkwright/thumos/commit/3608d3099febb5d7fb27ed3ca34a5573cc8a4156))
* **pyknosis:** ramfs — in-memory filesystem with CPIO parser ([d7894cb](https://github.com/forkwright/thumos/commit/d7894cb94f21305b4c8481258628ff111c6ea193))
* **pyknosis:** syscall interface with 8 initial syscalls ([55b7835](https://github.com/forkwright/thumos/commit/55b78354e54ae724e96aaaa6053af2a81d116358))
* **pyknosis:** wire all Phase 03 drivers into kernel boot sequence ([#15](https://github.com/forkwright/thumos/issues/15)) ([daaaf8b](https://github.com/forkwright/thumos/commit/daaaf8bdb2f70c054766138a5797b2242a4a30ac))
* scaffold Rust workspace with 13 crates ([c7a7d18](https://github.com/forkwright/thumos/commit/c7a7d18898a79b45c73fb603cf28337c9d1fc64a))
* **sema:** WiFi scanner and cell tower analysis with IMSI catcher detection ([608f103](https://github.com/forkwright/thumos/commit/608f103f69d3635c865e881b62fee9293e74df7e))
* **stegnos:** encrypted storage core — key management, AES-256-XTS, secure erase ([2e8aed0](https://github.com/forkwright/thumos/commit/2e8aed0a08780001368b1a889578ad08bc7c26ce))


### Bug Fixes

* **ci:** resolve clippy and cargo-deny failures, enable manual release-please trigger ([fb027f7](https://github.com/forkwright/thumos/commit/fb027f79fa6ed84e2f9a3438e0c587f3d38766c8))
* **clippy:** resolve all workspace clippy warnings ([a4b5431](https://github.com/forkwright/thumos/commit/a4b543165feb06bfea0b397dea00774685a125fb))
* **pyknosis:** make Console::prompt public for kinit ([fde5fe2](https://github.com/forkwright/thumos/commit/fde5fe29081c4666a2005d3d42d14b6d456845c0))
* replace personal email with GitHub security advisories ([2038645](https://github.com/forkwright/thumos/commit/2038645e0c9eacfbca3ab4a771e4e8a8e6111328))
* resolve lint violations via kanon lint --fix ([4ab3450](https://github.com/forkwright/thumos/commit/4ab3450a5490154003e099e9b40846467d116d5b))
* **stegnos:** move hard-coded crypto values to test module (closes [#1](https://github.com/forkwright/thumos/issues/1)) ([6431985](https://github.com/forkwright/thumos/commit/6431985981b0c6cccf8050320b2e51b8930207c4))
* sync standards directory from kanon ([a8aa756](https://github.com/forkwright/thumos/commit/a8aa75639c3448f52ae81ad5493834e29bc110a5))

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
