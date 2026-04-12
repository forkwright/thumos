# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4](https://github.com/forkwright/thumos/compare/v0.1.3...v0.1.4) (2026-04-12)


### Features

* **kernel:** add Briar and Meshtastic transport stubs (Phase 09 Wave 7) ([cfa4a96](https://github.com/forkwright/thumos/commit/cfa4a9634ea364620dd311d4829fc02bf7350d27))
* **kernel:** add CCCI traffic logger, modem baseline, and firewall (Phase 10 Waves 2+3) ([9aadc52](https://github.com/forkwright/thumos/commit/9aadc52fa24a0760c7178ce67213bcb5f9562bc2))
* **kernel:** add IMSI catcher scoring, Silent SMS detection, 2G refusal (Phase 10 Wave 1) ([8750b2a](https://github.com/forkwright/thumos/commit/8750b2a02064ddec697a7f9949bfe1bb577f45aa))
* **kernel:** add Matrix CS API client with sync and rooms (Phase 09 Wave 2) ([797ed0a](https://github.com/forkwright/thumos/commit/797ed0a84854a709f73e96069e833f824265605f))
* **kernel:** add Matrix E2E encryption with Olm/Megolm (Phase 09 Wave 3) ([c9bdcef](https://github.com/forkwright/thumos/commit/c9bdcef8c8bedd98e25324160ede1ce7a406c1ce))
* **kernel:** add nous integration and capability map (Phase 09 Wave 8) ([9581b8b](https://github.com/forkwright/thumos/commit/9581b8b4249e0031440c6d245aac2604e00503e5))
* **kernel:** add threat monitor screen (Phase 10 Wave 5 - partial) ([e91b9de](https://github.com/forkwright/thumos/commit/e91b9de5878bc20c46e99f325a5042f26de412f2))
* **kernel:** add threat monitor screen and Phase 10 integration (Phase 10 Wave 5) ([a5e2dae](https://github.com/forkwright/thumos/commit/a5e2daed43a2b59346173386883b747caca849d9))
* **kernel:** add USB provisioning for Matrix credentials (Phase 09 Wave 4) ([d14e0ef](https://github.com/forkwright/thumos/commit/d14e0ef90be76e75c76df16a523329b7495e6f09))
* **kernel:** add voice-to-text and action proposals (Phase 09 Wave 6) ([9aa8c17](https://github.com/forkwright/thumos/commit/9aa8c17259dcd798fbb7d15b9f27e83188bb1e2a))
* **kernel:** integrate Matrix into unified inbox with transport indicators (Phase 09 Wave 5) ([b7461f9](https://github.com/forkwright/thumos/commit/b7461f934662b8269e2e59c7c1afcaec0cbbf149))
* **kernel:** Phase 04 Wave 1 — slab allocator, CSPRNG, time, signals, watchdog ([b2c8ec8](https://github.com/forkwright/thumos/commit/b2c8ec8cf2603d66170c7f170f094db865524dca))
* **kernel:** Phase 04 Wave 2 — execve, pipe, futex, capabilities ([4a54695](https://github.com/forkwright/thumos/commit/4a54695557fb5e522f4ba4206f7b4916a658dd3b))
* **kernel:** Phase 04 Wave 3 — power management, syscall cleanup, tests ([f692b6b](https://github.com/forkwright/thumos/commit/f692b6ba8f36b0d5f8cb8958f18608f9cebbe24a))
* **kernel:** Phase 05 Wave 5 — LFS write path, compaction, boot integration ([c91cfe3](https://github.com/forkwright/thumos/commit/c91cfe3de54fdb74eca1ae1e7172c6b3a3c8770d))
* **kernel:** Phase 05 Wave 6 — fcntl, ioctl, syscall completion ([4edc910](https://github.com/forkwright/thumos/commit/4edc9106e6f5d96916e403edc80ce3e295002a45))
* **kernel:** Phase 05 Waves 1+2 — BlockDevice, cache, VFS, devfs ([6263a84](https://github.com/forkwright/thumos/commit/6263a841651b54253931be83bfe0c7454671f8f8))
* **kernel:** Phase 05 Waves 3+4 — VFS ramfs, fd table, LFS read path ([65fed61](https://github.com/forkwright/thumos/commit/65fed6173502f8bc4ec5ec0fb41539dc06aa1758))
* **kernel:** Phase 06 Wave 3 — DHCP client + DNS resolver ([4f98c09](https://github.com/forkwright/thumos/commit/4f98c09db5cf8fc3c31ae62006c3385b0558a31c))
* **kernel:** Phase 06 Wave 4 — network socket syscalls ([4a73cda](https://github.com/forkwright/thumos/commit/4a73cda0570d6cf3b99f60d71563693f8e25e80d))
* **kernel:** Phase 06 Waves 1+2 — smoltcp network stack + WiFi adapter ([81d804d](https://github.com/forkwright/thumos/commit/81d804d337906a80f3116e890483d6950ee62f42))
* **kernel:** Phase 06 Waves 5+6 — BT, GPS, clock, firewall ([bdc0eee](https://github.com/forkwright/thumos/commit/bdc0eee4e50d2dc7af12152471bb6ce98f0e8759))
* **kernel:** Phase 07 Wave 3 — SMS, phone dialer, call screens ([4c76f39](https://github.com/forkwright/thumos/commit/4c76f39057e551ff2ca9726d3742255eb18456f2))
* **kernel:** Phase 07 Wave 4 — audio session manager + codec driver ([dcf0dd3](https://github.com/forkwright/thumos/commit/dcf0dd31b027bcc450a1da5edadf532d411d63ed))
* **kernel:** Phase 07 Waves 1+2 — UI framework + telephony ([ffe819e](https://github.com/forkwright/thumos/commit/ffe819e5ee1fc5d592c7a52535ce57e3e64cea38))
* **kernel:** Phase 07 Waves 5+6 — battery, T9, contacts, messages, search, settings ([517d835](https://github.com/forkwright/thumos/commit/517d835b5edac1526914900cf3fecac089d2a4d9))
* **kernel:** Phase 07 Waves 7+8 — calendar, BT audio, FM radio, mic audit ([09f5f8c](https://github.com/forkwright/thumos/commit/09f5f8c2ef48e71a0dcde85a3ef0b52133b6a28b))
* **kernel:** Phase 08 Wave 1 — encryption layer + key hierarchy ([67657f0](https://github.com/forkwright/thumos/commit/67657f0aaf2832404906ecfe348d22a64e557dd3))
* **kernel:** Phase 08 Wave 8 — security integration and boot wiring ([0a0fe61](https://github.com/forkwright/thumos/commit/0a0fe61589a208ccd53637f73818083a2fc41a6d))
* **kernel:** Phase 08 Waves 2+3 — security modes + lock screen ([300cea9](https://github.com/forkwright/thumos/commit/300cea92ef13f65f7f807eb6cb00ba85bec4379c))
* **kernel:** Phase 08 Waves 4+5 — BFU timer, panic wipe, audit log ([ef44ff9](https://github.com/forkwright/thumos/commit/ef44ff91f62ef8acf6510861aa93df9083321b16))
* **kernel:** Phase 08 Waves 6+7 — measured boot, privacy dashboard, DNS-over-TLS ([ba13fb8](https://github.com/forkwright/thumos/commit/ba13fb8e233e64f7bcf6fef2a794ea0701b9b4b5))
* **kernel:** Phase 09 Wave 1 — HTTP client + JSON primitives ([d5d5bb0](https://github.com/forkwright/thumos/commit/d5d5bb04fd15bbd3f082a567fbb724bd002fd7e5))


### Bug Fixes

* **docs:** audit batch 3 — dead refs, doc accuracy, misleading sections ([3256283](https://github.com/forkwright/thumos/commit/32562836eef6991fbe3b79ef8ea8aaabaa8eb519))
* **kernel:** audit batch 2 — cache eviction, IPC routing, WPA timing, key zeroize ([0616a8c](https://github.com/forkwright/thumos/commit/0616a8c078a230443bb3146ee4ba7303e32a1fbe))
* **kernel:** audit batch 4 — Display, must_use, non_exhaustive compliance ([070cc07](https://github.com/forkwright/thumos/commit/070cc0765bf91cf0c6ff84b26605359490b5013b))
* **kernel:** audit batch 6 — ELF tests, error path coverage, proptest ([2e96d33](https://github.com/forkwright/thumos/commit/2e96d331ef34731e239b5e5256d488aca1bedb23))
* **kernel:** audit batch 7 — TODO format, plan gap refs, cleanup ([fea1e6d](https://github.com/forkwright/thumos/commit/fea1e6d75787f964de6763f1dee52d4f04f81556))
* **kernel:** audit-2 — Phase 07 type system, tests, docs, lints, DRY ([016bda1](https://github.com/forkwright/thumos/commit/016bda1d6e314d000ede47b73b00a773b6ff662a))
* **kernel:** correct OFFSET case-corruption in ELF loader ([7079e30](https://github.com/forkwright/thumos/commit/7079e3042f6820328aa81ee25313b1ef6bd34f99))
* **kernel:** fix 3 pre-existing test failures in ccci, csprng, vfs ([91277cd](https://github.com/forkwright/thumos/commit/91277cd5be1ebb27fdff360fe6b70ee029071bf9))
* **kernel:** unsafe audit — SAFETY comments, 2024 edition compliance, case fixes ([f61f1e3](https://github.com/forkwright/thumos/commit/f61f1e3a4a5e48e183ddc74604a9e5683ce38d48))
* Phase 04 kernel issues + resolve all compilation errors ([#34](https://github.com/forkwright/thumos/issues/34)) ([c93be52](https://github.com/forkwright/thumos/commit/c93be5265d078c14bac810cfb7dd6711a1c134a9))
* **repo:** audit batch 1 — lint quality floor + repo infrastructure ([8482905](https://github.com/forkwright/thumos/commit/84829056013483c6bbc834cd65cac816ec8c3f2e))
* **repo:** audit batch 5 — ARCHITECTURE.md, deny(missing_docs), CI gates ([dc32ac0](https://github.com/forkwright/thumos/commit/dc32ac0a7c78f8b35d729c5560ea5ed852132bd1))
* resolve all test compilation errors and clippy warnings ([8593e07](https://github.com/forkwright/thumos/commit/8593e07f74e2fbb9c72a3a9ab86a10a0c37da8a0))
* resolve all test compilation errors and clippy warnings across workspace ([e4dd99f](https://github.com/forkwright/thumos/commit/e4dd99f429c69a1f367efed070bf0feec54d0aa6))

## [0.1.3](https://github.com/forkwright/thumos/compare/v0.1.2...v0.1.3) (2026-04-04)


### Bug Fixes

* resolve lint violations via kanon lint --fix ([d19be4f](https://github.com/forkwright/thumos/commit/d19be4f5c2de4c11865e724523f0fde1455ad21f))

## [0.1.2](https://github.com/forkwright/thumos/compare/v0.1.1...v0.1.2) (2026-04-03)


### Bug Fixes

* resolve lint violations via kanon lint --fix ([7cc3550](https://github.com/forkwright/thumos/commit/7cc35503c342fa96d91b463db97190e1ae60bb27))

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
* resolve 43 lint violations via kanon lint --fix ([#18](https://github.com/forkwright/thumos/issues/18)) ([093fdb4](https://github.com/forkwright/thumos/commit/093fdb478b0986026968ed0137fd5c9288c3a9f5))
* resolve 43 lint violations via kanon lint --fix ([#19](https://github.com/forkwright/thumos/issues/19)) ([370e19e](https://github.com/forkwright/thumos/commit/370e19e28e97c89368c57e7f4c29a35209d6107c))
* resolve 43 lint violations via kanon lint --fix ([#20](https://github.com/forkwright/thumos/issues/20)) ([ce6efdb](https://github.com/forkwright/thumos/commit/ce6efdbf7aa21de067a2b09200ad523577404c5c))
* resolve 43 lint violations via kanon lint --fix ([#21](https://github.com/forkwright/thumos/issues/21)) ([d9728ec](https://github.com/forkwright/thumos/commit/d9728ecbfe6b86fad48272fd64154c3c8e771bcb))
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
