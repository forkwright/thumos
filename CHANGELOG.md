# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5](https://github.com/forkwright/thumos/compare/v0.1.4...v0.1.5) (2026-05-21)


### Features

* **_llm:** add T0 corpus per [#667](https://github.com/forkwright/thumos/issues/667) / [#673](https://github.com/forkwright/thumos/issues/673) fleet rollout ([#12](https://github.com/forkwright/thumos/issues/12)) ([a02a04f](https://github.com/forkwright/thumos/commit/a02a04f35b28fa7b9422bb9bec99b00de5ba95d6))
* QEMU test runner for kernel unit tests (closes [#117](https://github.com/forkwright/thumos/issues/117)) ([#127](https://github.com/forkwright/thumos/issues/127)) ([b2117b1](https://github.com/forkwright/thumos/commit/b2117b10343e16ebbd1e30450c828d4d08945dba))


### Bug Fixes

* **lint:** clear license-spdx + as-cast + allow-not-expect violations ([#5](https://github.com/forkwright/thumos/issues/5)) ([dfbf66c](https://github.com/forkwright/thumos/commit/dfbf66c281f0e1c7d4d57d82cc51cfc3896ffa6b))
* **thumos:** clear kanon lint drift ([#7](https://github.com/forkwright/thumos/issues/7)) ([b0a4238](https://github.com/forkwright/thumos/commit/b0a42389abad22404d6601be219f995924996582))

## [0.1.4](https://github.com/forkwright/thumos/compare/v0.1.3...v0.1.4) (2026-04-13)


### Features

* **aither:** add WiFi MAC driver with identity protection ([#10](https://github.com/forkwright/thumos/issues/10)) ([b7a8e45](https://github.com/forkwright/thumos/commit/b7a8e45fd25e18d3236ec092af4bdf17d1d5474e))
* **aither:** WiFi management — EAPOL parsing, WPA key derivation, network selection ([70a4fad](https://github.com/forkwright/thumos/commit/70a4fadf9f95b99df37134ae2c17a30e9f0a86eb))
* **asphaleia:** packet filter core — IPv4/TCP/UDP parsing, rule engine, DNS blocklist ([9dd6d54](https://github.com/forkwright/thumos/commit/9dd6d545e8fe6e2d5905c149c842d4f9f806c77f))
* CI workflows + topos NMEA parser (11 tests) + haphe touch support planned ([5d176f8](https://github.com/forkwright/thumos/commit/5d176f83401841955452180501a7cc678af493b5))
* **eidolon:** framebuffer rendering — color, font, status bar ([f18305b](https://github.com/forkwright/thumos/commit/f18305be51c72861a17ba9e6cb5794d64ca9c4f6))
* **eidolon:** widget system and menu navigation (UI milestone) ([e1c6d57](https://github.com/forkwright/thumos/commit/e1c6d576fb5f2e4c1e6c4cec8ce3669dede913d4))
* **haphe:** add GPIO keypad matrix scan and mtk-tpd touchscreen driver ([#12](https://github.com/forkwright/thumos/issues/12)) ([90d7494](https://github.com/forkwright/thumos/commit/90d749496c2076197cb89bb02fbadd23634b66c6))
* **haphe:** input subsystem — keypad, touchscreen, T9 text input ([056683d](https://github.com/forkwright/thumos/commit/056683def744515031341e00f1d9f8cdc6072246))
* **kelyphos:** STP framing protocol for MT6739 combo chip ([b1a7437](https://github.com/forkwright/thumos/commit/b1a743741a866af80154592cdb617b2cf5e1f6ff))
* **kelyphos:** WMT power sequencing and STP transport ([#8](https://github.com/forkwright/thumos/issues/8)) ([cebce5f](https://github.com/forkwright/thumos/commit/cebce5f580f7e70ef1fd81f9db86cbd09be8f699))
* **kernel:** add Briar and Meshtastic transport stubs (Phase 09 Wave 7) ([cab6d93](https://github.com/forkwright/thumos/commit/cab6d9375f55ef13644a1045d0971c35e0714c89))
* **kernel:** add CCCI traffic logger, modem baseline, and firewall (Phase 10 Waves 2+3) ([fea1a14](https://github.com/forkwright/thumos/commit/fea1a1450b7a3d43ab4b07c2e77b953f680a5aff))
* **kernel:** add IMSI catcher scoring, Silent SMS detection, 2G refusal (Phase 10 Wave 1) ([134e414](https://github.com/forkwright/thumos/commit/134e414ce6ba737f001a9580e8a0367bd88169e8))
* **kernel:** add Matrix CS API client with sync and rooms (Phase 09 Wave 2) ([da334fa](https://github.com/forkwright/thumos/commit/da334fa31054565d1066759b6bc692e2389d355f))
* **kernel:** add Matrix E2E encryption with Olm/Megolm (Phase 09 Wave 3) ([66ab79b](https://github.com/forkwright/thumos/commit/66ab79b18150fbb37bd02d6d9b9089d1960a7db1))
* **kernel:** add nous integration and capability map (Phase 09 Wave 8) ([7a72eec](https://github.com/forkwright/thumos/commit/7a72eec4bd59f87c272183237834bcdcb6a66b01))
* **kernel:** add threat monitor screen (Phase 10 Wave 5 - partial) ([0503443](https://github.com/forkwright/thumos/commit/0503443d73986de1f8201450bba94357004748ed))
* **kernel:** add threat monitor screen and Phase 10 integration (Phase 10 Wave 5) ([49d0e01](https://github.com/forkwright/thumos/commit/49d0e01fe8fd185dbd919eb88dd57b6ebba95a34))
* **kernel:** add USB provisioning for Matrix credentials (Phase 09 Wave 4) ([d3980a9](https://github.com/forkwright/thumos/commit/d3980a9b7ef513fb8196ffdd3f4f7801d3688d8d))
* **kernel:** add voice-to-text and action proposals (Phase 09 Wave 6) ([08570f5](https://github.com/forkwright/thumos/commit/08570f5f5a0a75787b97834f9b15e7aab5635e8a))
* **kernel:** implement SHA1, HMAC-SHA1, PBKDF2-SHA1, PRF-384 for WPA2 ([1008819](https://github.com/forkwright/thumos/commit/1008819eddba65d6c7b74bec012652c49373324e)), closes [#72](https://github.com/forkwright/thumos/issues/72)
* **kernel:** integrate Matrix into unified inbox with transport indicators (Phase 09 Wave 5) ([b46ad50](https://github.com/forkwright/thumos/commit/b46ad50c6abb995f2cdbcf813fd8ed17bebbefcb))
* **kernel:** Phase 04 Wave 1 — slab allocator, CSPRNG, time, signals, watchdog ([05d4956](https://github.com/forkwright/thumos/commit/05d4956ab0b002264f9e2ffa2938a01dcee6c237))
* **kernel:** Phase 04 Wave 2 — execve, pipe, futex, capabilities ([46b0048](https://github.com/forkwright/thumos/commit/46b0048add3d6b1dc6f82e472a1d8b933a88b2cb))
* **kernel:** Phase 04 Wave 3 — power management, syscall cleanup, tests ([656f7f3](https://github.com/forkwright/thumos/commit/656f7f3943867c400083008c56312d820034fb12))
* **kernel:** Phase 05 Wave 5 — LFS write path, compaction, boot integration ([e23f27b](https://github.com/forkwright/thumos/commit/e23f27b3bb64543233998ef45c6f8bea0fbc3c53))
* **kernel:** Phase 05 Wave 6 — fcntl, ioctl, syscall completion ([9688d3b](https://github.com/forkwright/thumos/commit/9688d3b55d7cb63bb53cedb70e66bd2d732d21a3))
* **kernel:** Phase 05 Waves 1+2 — BlockDevice, cache, VFS, devfs ([ea37ff6](https://github.com/forkwright/thumos/commit/ea37ff6ab52a12d85cd4132edddbccd44c4f863a))
* **kernel:** Phase 05 Waves 3+4 — VFS ramfs, fd table, LFS read path ([99b9f89](https://github.com/forkwright/thumos/commit/99b9f8903c41a0f9e1392754c695159f447f2fbc))
* **kernel:** Phase 06 Wave 3 — DHCP client + DNS resolver ([2caa1ae](https://github.com/forkwright/thumos/commit/2caa1ae54435abfc61d9d1f70a179fca1e3e359a))
* **kernel:** Phase 06 Wave 4 — network socket syscalls ([26f0fec](https://github.com/forkwright/thumos/commit/26f0fec574ac41f5b0d3f99091e27bd452132367))
* **kernel:** Phase 06 Waves 1+2 — smoltcp network stack + WiFi adapter ([2770468](https://github.com/forkwright/thumos/commit/27704689854949aa7ac9ce11fc422d1a871e815e))
* **kernel:** Phase 06 Waves 5+6 — BT, GPS, clock, firewall ([2422d0c](https://github.com/forkwright/thumos/commit/2422d0c452f43e64cdec016b0b7455b0212b0aba))
* **kernel:** Phase 07 Wave 3 — SMS, phone dialer, call screens ([cd4e010](https://github.com/forkwright/thumos/commit/cd4e01092835f99a7e10e80c3ef78a0c3065d698))
* **kernel:** Phase 07 Wave 4 — audio session manager + codec driver ([4407611](https://github.com/forkwright/thumos/commit/44076115a5f11293a66741b86aa50d6209fafaf3))
* **kernel:** Phase 07 Waves 1+2 — UI framework + telephony ([a5e931d](https://github.com/forkwright/thumos/commit/a5e931db5b285c619cf0a5c6e260389c131e503d))
* **kernel:** Phase 07 Waves 5+6 — battery, T9, contacts, messages, search, settings ([30f607c](https://github.com/forkwright/thumos/commit/30f607c1c7fedd67492dd1d6d9614646e07fdf53))
* **kernel:** Phase 07 Waves 7+8 — calendar, BT audio, FM radio, mic audit ([b74df9b](https://github.com/forkwright/thumos/commit/b74df9bfa14bd95c86bb590d4c68e9fb03e791dc))
* **kernel:** Phase 08 Wave 1 — encryption layer + key hierarchy ([24890f5](https://github.com/forkwright/thumos/commit/24890f548a551ef920713fe16ec274cf25c2abcc))
* **kernel:** Phase 08 Wave 8 — security integration and boot wiring ([631c8f4](https://github.com/forkwright/thumos/commit/631c8f40c5be430cab2d9ac0dd60144b01d7ad5c))
* **kernel:** Phase 08 Waves 2+3 — security modes + lock screen ([4295565](https://github.com/forkwright/thumos/commit/429556560496c7b05c37839d980ffc4f306dbdf6))
* **kernel:** Phase 08 Waves 4+5 — BFU timer, panic wipe, audit log ([2ce9c7c](https://github.com/forkwright/thumos/commit/2ce9c7c01e4cf06edcd256fd7ae1d15052a06321))
* **kernel:** Phase 08 Waves 6+7 — measured boot, privacy dashboard, DNS-over-TLS ([30a28c5](https://github.com/forkwright/thumos/commit/30a28c5103fad257dc19329a9ee450d8016b9cda))
* **kernel:** Phase 09 Wave 1 — HTTP client + JSON primitives ([07a1aff](https://github.com/forkwright/thumos/commit/07a1aff205c2232a5b92397d0b08459465742c00))
* **krypta:** Signal protocol core — X3DH key agreement, symmetric ratchet, session encryption ([c19b87b](https://github.com/forkwright/thumos/commit/c19b87b6e935f28f9ebbc07f6b8d7cf287ab38ec))
* **leipsanon:** panic mode — wipe targets, secure memory, engine, triggers ([e7a1877](https://github.com/forkwright/thumos/commit/e7a1877f9297cd00e86573b3fa8eec916140fcce))
* **ops:** add PolyForm Shield license, AI training prohibition, .aiignore ([7f81a12](https://github.com/forkwright/thumos/commit/7f81a12a4bde9fd045bb4f749405fde775e3cf6b)), closes [#17](https://github.com/forkwright/thumos/issues/17)
* **phone:** add SMS PDU encoding/decoding ([51b99c6](https://github.com/forkwright/thumos/commit/51b99c6ebd935319ce2c266621743c08f1e85730))
* **phone:** AT command parser with 12 tests passing ([b807194](https://github.com/forkwright/thumos/commit/b8071946c82a4241d67b25a2104c525156e6e239))
* **phone:** CCCI modem channel abstraction — ccci, cldma, transport ([9ed008c](https://github.com/forkwright/thumos/commit/9ed008cfbdf9e1daf0fe01d4318003482242eebc))
* **pteron:** add STP transport layer and LE Privacy address rotation ([#11](https://github.com/forkwright/thumos/issues/11)) ([f43b352](https://github.com/forkwright/thumos/commit/f43b352a6fa91fbdf96596cf60216d1c207434ec))
* **pyknosis-boot:** add CCCI kernel driver for AP-modem communication ([#6](https://github.com/forkwright/thumos/issues/6)) ([811825b](https://github.com/forkwright/thumos/commit/811825b7f8351742a5359c69bc4a646e1c815907))
* **pyknosis-boot:** add DDP display driver with pluggable LCM trait ([#9](https://github.com/forkwright/thumos/issues/9)) ([408ee00](https://github.com/forkwright/thumos/commit/408ee006f6980e027d79710aadb8bb8c2756a617))
* **pyknosis-boot:** prove two-process isolation with separate address spaces ([#5](https://github.com/forkwright/thumos/issues/5)) ([45c6ec0](https://github.com/forkwright/thumos/commit/45c6ec07465ff504c79c8ebd14c9028ca161f662))
* **pyknosis:** add eMMC block device driver for MT6739 MSDC controller ([#4](https://github.com/forkwright/thumos/issues/4)) ([a45f03b](https://github.com/forkwright/thumos/commit/a45f03b40adce0c0e68ff518003e620bd4b74277))
* **pyknosis:** add MMIO primitives and physical page allocator ([3927af4](https://github.com/forkwright/thumos/commit/3927af4c50f8c37f63ab0280361ba68e776ae7e3))
* **pyknosis:** add MUSB USB controller driver with ACM serial gadget ([#13](https://github.com/forkwright/thumos/issues/13)) ([55f3045](https://github.com/forkwright/thumos/commit/55f30457b57bef23b4341717631e7faed1c62899))
* **pyknosis:** ARMv7 MMU with identity mapping and cache enable ([db9d83f](https://github.com/forkwright/thumos/commit/db9d83f2b4052e66720b0ee740c36072a248d532))
* **pyknosis:** bare-metal Rust kernel boots on MT6739 ([b99d9e1](https://github.com/forkwright/thumos/commit/b99d9e13a019308467378a24d566ce11e8e76dae))
* **pyknosis:** device registry with MT6739 hardware addresses ([2be1b8c](https://github.com/forkwright/thumos/commit/2be1b8c4c28625eaced3731b8a6998be333e2c9c))
* **pyknosis:** ELF32 loader for ARM userspace binaries ([d8e7282](https://github.com/forkwright/thumos/commit/d8e72822a06de6d7c4afad9fb930eb75e8c4041b))
* **pyknosis:** exception vector table, IRQ handler, timer tick ([cf94321](https://github.com/forkwright/thumos/commit/cf94321b8c9ab2d65957ff8220a442d74e66c5e2))
* **pyknosis:** expand syscall interface to 46 calls with domain grouping ([#3](https://github.com/forkwright/thumos/issues/3)) ([6227f65](https://github.com/forkwright/thumos/commit/6227f65eb730e304345a6772d8b41e36adb93526))
* **pyknosis:** GIC interrupt controller and ARM generic timer ([7f5c50f](https://github.com/forkwright/thumos/commit/7f5c50fb7d7261d93b0b20c61ba5ff117fd12dca))
* **pyknosis:** IPC message passing + SEND/RECV syscalls ([f7472bf](https://github.com/forkwright/thumos/commit/f7472bf79549242cb7fc98906c6c3bc1c864952d))
* **pyknosis:** kernel config — constants, runtime parameters, cmdline parser ([4e84dcb](https://github.com/forkwright/thumos/commit/4e84dcb912d80504853cdaf835013aa81f54eb8f))
* **pyknosis:** kernel debug console with commands ([f6eca19](https://github.com/forkwright/thumos/commit/f6eca194c6f0d52d6a098f1c6801c6c39193d513))
* **pyknosis:** kernel heap allocator with GlobalAlloc support ([7f77a56](https://github.com/forkwright/thumos/commit/7f77a56bbf54b2ca23e4510b32cb733ca152d8fa))
* **pyknosis:** kernel init sequence — ordered subsystem startup ([373b2e7](https://github.com/forkwright/thumos/commit/373b2e7273eecc9d27883025d0a4f4de75c2e1c5))
* **pyknosis:** power management — radio kill switches and power modes ([46d9e14](https://github.com/forkwright/thumos/commit/46d9e14dc0d25dec414fcf47940ca6243d2252b2))
* **pyknosis:** process abstraction with context switch and round-robin scheduler ([5553595](https://github.com/forkwright/thumos/commit/55535950d4d62cda0ac22b78b4d4006aabb7166c))
* **pyknosis:** ramfs — in-memory filesystem with CPIO parser ([22e37e5](https://github.com/forkwright/thumos/commit/22e37e50ed24b35cdd70cd5ed0b64b4e7e523eb8))
* **pyknosis:** syscall interface with 8 initial syscalls ([64e95b9](https://github.com/forkwright/thumos/commit/64e95b9214aecd373fe5516337fc79a38d52f226))
* **pyknosis:** wire all Phase 03 drivers into kernel boot sequence ([#15](https://github.com/forkwright/thumos/issues/15)) ([a2978c1](https://github.com/forkwright/thumos/commit/a2978c1a939b6b3e164d9a3f75e20ba121d4b503))
* scaffold Rust workspace with 13 crates ([c22e6cf](https://github.com/forkwright/thumos/commit/c22e6cf2b74574563b804c58b041ded693b59788))
* **sema:** WiFi scanner and cell tower analysis with IMSI catcher detection ([9cc6039](https://github.com/forkwright/thumos/commit/9cc603943c13beacdda24dab367b2a4abcae1acf))
* **stegnos:** encrypted storage core — key management, AES-256-XTS, secure erase ([b4e1dd9](https://github.com/forkwright/thumos/commit/b4e1dd995756bc31f15a9bfa07f34cb58d04eb32))


### Bug Fixes

* **ci:** resolve clippy and cargo-deny failures, enable manual release-please trigger ([d2e26a8](https://github.com/forkwright/thumos/commit/d2e26a8d8bd15492d981988509bc7d260c773b25))
* **clippy:** resolve all workspace clippy warnings ([9685f07](https://github.com/forkwright/thumos/commit/9685f07b52e0465173a08e316f3a92371c220050))
* **docs:** audit batch 3 — dead refs, doc accuracy, misleading sections ([1f66215](https://github.com/forkwright/thumos/commit/1f6621518b7403e39b3db2b455b2e438771c331b))
* **kernel:** audit batch 2 — cache eviction, IPC routing, WPA timing, key zeroize ([654415f](https://github.com/forkwright/thumos/commit/654415fdc6777f8e2e53010bcfcfd9938775ee51))
* **kernel:** audit batch 4 — Display, must_use, non_exhaustive compliance ([677daae](https://github.com/forkwright/thumos/commit/677daaeaaa13c7251ee0041b49c79c75ce7724ab))
* **kernel:** audit batch 6 — ELF tests, error path coverage, proptest ([600ea5f](https://github.com/forkwright/thumos/commit/600ea5f47c4da820c901cf34b2cced66aceace0a))
* **kernel:** audit batch 7 — TODO format, plan gap refs, cleanup ([5625a94](https://github.com/forkwright/thumos/commit/5625a94b11e43e56bd42e75d8731873de408d514))
* **kernel:** audit-2 — Phase 07 type system, tests, docs, lints, DRY ([dc60eab](https://github.com/forkwright/thumos/commit/dc60eabe9b6742591e31fb00aa20887434f77d05))
* **kernel:** correct OFFSET case-corruption in ELF loader ([ecc93e7](https://github.com/forkwright/thumos/commit/ecc93e7c8c5a03c72b79dcf89e9d4a38fee2b950))
* **kernel:** fix 3 pre-existing test failures in ccci, csprng, vfs ([752bdb2](https://github.com/forkwright/thumos/commit/752bdb22114fb4ccd7f8303ecffcbb763c83861b))
* **kernel:** unsafe audit — SAFETY comments, 2024 edition compliance, case fixes ([1573bdf](https://github.com/forkwright/thumos/commit/1573bdfa9baa7bcf00b5885cef29d8d861dbaca9))
* Phase 04 kernel issues + resolve all compilation errors ([#34](https://github.com/forkwright/thumos/issues/34)) ([bcfcc77](https://github.com/forkwright/thumos/commit/bcfcc77a513c9be501778c77ed5142aec99e770c))
* **pyknosis:** make Console::prompt public for kinit ([f915d07](https://github.com/forkwright/thumos/commit/f915d076e3b5658244c572a706b008a545ba54d9))
* replace personal email with GitHub security advisories ([1ddafb0](https://github.com/forkwright/thumos/commit/1ddafb08a9e6cd5eb83c359744733e0707fb8521))
* **repo:** audit batch 1 — lint quality floor + repo infrastructure ([d9299c8](https://github.com/forkwright/thumos/commit/d9299c835dd320c2bb4f10b12118175107b86384))
* **repo:** audit batch 5 — ARCHITECTURE.md, deny(missing_docs), CI gates ([e0cbe0a](https://github.com/forkwright/thumos/commit/e0cbe0ae8e9e6e6539068b187e4724d9747f84ca))
* resolve 43 lint violations via kanon lint --fix ([#18](https://github.com/forkwright/thumos/issues/18)) ([87442fd](https://github.com/forkwright/thumos/commit/87442fdf7729113d9d22bef2d68c60453fec2ce1))
* resolve 43 lint violations via kanon lint --fix ([#19](https://github.com/forkwright/thumos/issues/19)) ([4459c41](https://github.com/forkwright/thumos/commit/4459c416f2a252b769efdb96a28f5a9810f62678))
* resolve 43 lint violations via kanon lint --fix ([#20](https://github.com/forkwright/thumos/issues/20)) ([8d89466](https://github.com/forkwright/thumos/commit/8d894666fbdeafd736f8499f2deb5ba5ac087ae0))
* resolve 43 lint violations via kanon lint --fix ([#21](https://github.com/forkwright/thumos/issues/21)) ([e91538d](https://github.com/forkwright/thumos/commit/e91538d23854b95a04c61e58bbea665dac4942b6))
* resolve all test compilation errors and clippy warnings ([b89fc2c](https://github.com/forkwright/thumos/commit/b89fc2c8392256e0d6b4f84f8c8330eb69ebee81))
* resolve all test compilation errors and clippy warnings across workspace ([2cf668f](https://github.com/forkwright/thumos/commit/2cf668fb089c4cb684d8ba1653abb350151ec23b))
* resolve lint violations via kanon lint --fix ([8be7ea6](https://github.com/forkwright/thumos/commit/8be7ea62232009e5fbf3a8d763746d5f08593b64))
* resolve lint violations via kanon lint --fix ([38d0d90](https://github.com/forkwright/thumos/commit/38d0d90e323c9a0c2d29a4bcfbf3b8261a112fc4))
* resolve lint violations via kanon lint --fix ([93f2974](https://github.com/forkwright/thumos/commit/93f2974fd56e95f796a0695f99e8c2838226f7fe))
* **stegnos:** move hard-coded crypto values to test module (closes [#1](https://github.com/forkwright/thumos/issues/1)) ([4324084](https://github.com/forkwright/thumos/commit/43240841715099c73a30b76e94b4c42faf01343a))
* sync standards directory from kanon ([361b8b0](https://github.com/forkwright/thumos/commit/361b8b04b1452c643dca187f1e710128a28510ab))

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
* **eidolon:** widget system and menu navigation (UI milestone) ([1306cdc](https://github.com/forkwright/thumos/commit/1306cdcce7009f6cfad756fa24b1898cd58ac220))
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
- **GC9306 init sequence (docs)**: LCM initialization sequence documented from four public sources (PR #14)
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
- Kernel module map and modem interface map documented from stock firmware
- Initial workspace structure: 13 crates scaffolded
