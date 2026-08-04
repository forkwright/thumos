# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.16](https://github.com/forkwright/thumos/compare/v0.1.15...v0.1.16) (2026-08-04)


### Bug Fixes

* **thumos:** sync I-cache after D-side writes to freshly-executed user code ([#583](https://github.com/forkwright/thumos/issues/583)) ([4bbd3aa](https://github.com/forkwright/thumos/commit/4bbd3aad47efd9e6b1e359073da3597d9af1f34a))

## [0.1.15](https://github.com/forkwright/thumos/compare/v0.1.14...v0.1.15) (2026-08-04)


### Bug Fixes

* **thumos:** give best-effort boot logging one owner ([#580](https://github.com/forkwright/thumos/issues/580)) ([0634795](https://github.com/forkwright/thumos/commit/0634795524a79bf70c13368998c1924c247014dc))

## [0.1.14](https://github.com/forkwright/thumos/compare/v0.1.13...v0.1.14) (2026-07-29)


### Bug Fixes

* **release:** root eidolon's version jsonpath at [dependencies] ([#578](https://github.com/forkwright/thumos/issues/578)) ([ee31e52](https://github.com/forkwright/thumos/commit/ee31e52f4f7a5e63499614c572e673e51adeb662)), closes [#577](https://github.com/forkwright/thumos/issues/577)

## [0.1.13](https://github.com/forkwright/thumos/compare/v0.1.12...v0.1.13) (2026-07-29)


### Bug Fixes

* **release:** keep Cargo.lock's local packages on the workspace version ([#575](https://github.com/forkwright/thumos/issues/575)) ([e1989d6](https://github.com/forkwright/thumos/commit/e1989d6cce779465cc5f5ea22c7f33dda3533b8d)), closes [#574](https://github.com/forkwright/thumos/issues/574)

## [0.1.12](https://github.com/forkwright/thumos/compare/v0.1.11...v0.1.12) (2026-07-29)


### Bug Fixes

* **release:** keep eidolon's haphe pin in step with the workspace version ([#572](https://github.com/forkwright/thumos/issues/572)) ([3bf8660](https://github.com/forkwright/thumos/commit/3bf8660022d902e98ee6f0186caa1acae9299272)), closes [#571](https://github.com/forkwright/thumos/issues/571)

## [0.1.11](https://github.com/forkwright/thumos/compare/v0.1.10...v0.1.11) (2026-07-28)


### Bug Fixes

* **device:** derive GIC base addresses from kconfig, not a local literal ([#463](https://github.com/forkwright/thumos/issues/463)) ([#564](https://github.com/forkwright/thumos/issues/564)) ([1db37a2](https://github.com/forkwright/thumos/commit/1db37a28eef30646532d445d46bbd06002dd1aef))
* **sema:** bound rapid-reselection detection to a timestamp window ([#570](https://github.com/forkwright/thumos/issues/570)) ([874b59b](https://github.com/forkwright/thumos/commit/874b59b0ce56d26aa0e0b222835019f4e845fe29))
* **thumos:** restore pub(crate) on kinit_plan consts dropped by [#561](https://github.com/forkwright/thumos/issues/561) ([#569](https://github.com/forkwright/thumos/issues/569)) ([3352cef](https://github.com/forkwright/thumos/commit/3352cef887cf8394226d23fb17e2bd7123d18bfc)), closes [#528](https://github.com/forkwright/thumos/issues/528)

## [0.1.10](https://github.com/forkwright/thumos/compare/v0.1.9...v0.1.10) (2026-07-23)


### Bug Fixes

* **thumos:** extract kinit pure logic into host-testable kinit_plan ([#528](https://github.com/forkwright/thumos/issues/528)) ([#561](https://github.com/forkwright/thumos/issues/561)) ([976c071](https://github.com/forkwright/thumos/commit/976c071382415a8a56781bb2ae4336585b0b6b5c))
* **thumos:** faithful mm syscall fixture + sys_brk section shatter ([#533](https://github.com/forkwright/thumos/issues/533)) ([#562](https://github.com/forkwright/thumos/issues/562)) ([7370303](https://github.com/forkwright/thumos/commit/73703032b8b14e1cc769b30011eb4ae2367008ff))

## [0.1.9](https://github.com/forkwright/thumos/compare/v0.1.8...v0.1.9) (2026-07-23)


### Bug Fixes

* **thumos:** repair rustfmt drift in device.rs + kinit.rs (kanon[#2522](https://github.com/forkwright/thumos/issues/2522)) ([#558](https://github.com/forkwright/thumos/issues/558)) ([e7e679d](https://github.com/forkwright/thumos/commit/e7e679d5e9051b923882157b1e5cb743b04c9258))

## [0.1.8](https://github.com/forkwright/thumos/compare/v0.1.7...v0.1.8) (2026-07-16)


### Features

* **thumos:** bridge modem registration to the status bar ([#404](https://github.com/forkwright/thumos/issues/404), closes [#404](https://github.com/forkwright/thumos/issues/404)) ([#509](https://github.com/forkwright/thumos/issues/509)) ([88509f9](https://github.com/forkwright/thumos/commit/88509f98604286249cb31547411e24025b028bb6))
* **thumos:** contiguous multi-page allocation ([#475](https://github.com/forkwright/thumos/issues/475), closes [#475](https://github.com/forkwright/thumos/issues/475)) ([#481](https://github.com/forkwright/thumos/issues/481)) ([755908c](https://github.com/forkwright/thumos/commit/755908c04eb8e04acb0d084890d9ac8989249259))
* **thumos:** firewall packet-audit plumbing (PacketLog + event queue), CI-verified ([#403](https://github.com/forkwright/thumos/issues/403)) ([#520](https://github.com/forkwright/thumos/issues/520)) ([1a9c14d](https://github.com/forkwright/thumos/commit/1a9c14d67077898a981254b3795681da4f0d0f13))
* **thumos:** incoming call -&gt; ringtone audio session, CI-verified ([#398](https://github.com/forkwright/thumos/issues/398)) ([#510](https://github.com/forkwright/thumos/issues/510)) ([6b17db2](https://github.com/forkwright/thumos/commit/6b17db2aed9b25333cdb374adcaaa6c2f6c69f68))
* **thumos:** live UI render loop -- kardia paints the home frame, CI-verified ([#400](https://github.com/forkwright/thumos/issues/400)) ([#503](https://github.com/forkwright/thumos/issues/503)) ([9363cc6](https://github.com/forkwright/thumos/commit/9363cc653f5f39955b862f25f62969a504889d31))
* **thumos:** loop-persistent firewall with runtime policy + audit trail (closes [#403](https://github.com/forkwright/thumos/issues/403)) ([#521](https://github.com/forkwright/thumos/issues/521)) ([2ce7381](https://github.com/forkwright/thumos/commit/2ce73815243e3576fa2cc45060f2eae344417ea7))
* **thumos:** measured userspace -- verified image-resident initramfs may spawn ([#480](https://github.com/forkwright/thumos/issues/480), closes [#480](https://github.com/forkwright/thumos/issues/480)) ([#484](https://github.com/forkwright/thumos/issues/484)) ([9017aae](https://github.com/forkwright/thumos/commit/9017aaeec440222b65b357fbbd70fc5c7dcc50dc))
* **thumos:** parse +CREG &lt;AcT&gt; into a radio access technology, CI-verified ([#404](https://github.com/forkwright/thumos/issues/404)) ([#513](https://github.com/forkwright/thumos/issues/513)) ([29e4899](https://github.com/forkwright/thumos/commit/29e489918b1627ed2969e372f6b51a5aa418a719))
* **thumos:** PID-0 fault supervisor — consume + act on fault reports ([#492](https://github.com/forkwright/thumos/issues/492)) ([#530](https://github.com/forkwright/thumos/issues/530)) ([1238f13](https://github.com/forkwright/thumos/commit/1238f134b373bf5ddc77f0a59954620a2d93cf73))
* **thumos:** PL0 per-process isolation -- /init runs unprivileged ([#482](https://github.com/forkwright/thumos/issues/482)) ([#486](https://github.com/forkwright/thumos/issues/486)) ([1f096e9](https://github.com/forkwright/thumos/commit/1f096e90423605d3226820bb0e512e8895dbec72))
* **thumos:** PROT_NONE user pages via a USER_OWNED page tag ([#496](https://github.com/forkwright/thumos/issues/496)) ([#529](https://github.com/forkwright/thumos/issues/529)) ([43e03ac](https://github.com/forkwright/thumos/commit/43e03ace7483d7e9c0f9b4cb53135ee43df540d8))
* **thumos:** ship /shell — the /init+/shell coexistence witness ([#526](https://github.com/forkwright/thumos/issues/526)) ([#527](https://github.com/forkwright/thumos/issues/527)) ([04e30a2](https://github.com/forkwright/thumos/commit/04e30a2fa34ca390bbc05d92923540b71a370f15))
* **thumos:** UI input dispatch + screen-stack navigation, CI-verified ([#400](https://github.com/forkwright/thumos/issues/400)) ([#504](https://github.com/forkwright/thumos/issues/504)) ([9acb08a](https://github.com/forkwright/thumos/commit/9acb08ab32e07c40a4a9c6ce80bd226dff34187f))
* **thumos:** wire outgoing SMS send over the modem transport, CI-verified (closes [#398](https://github.com/forkwright/thumos/issues/398)) ([#519](https://github.com/forkwright/thumos/issues/519)) ([a230e3f](https://github.com/forkwright/thumos/commit/a230e3fedea76f95311feebd6a56798270b4ed2a))
* **thumos:** wire SIM + SMS managers over the modem transport, CI-verified ([#398](https://github.com/forkwright/thumos/issues/398)) ([#511](https://github.com/forkwright/thumos/issues/511)) ([3e401a7](https://github.com/forkwright/thumos/commit/3e401a7cc1bc5b700df0b1f0c26647054316a8b3))
* **thumos:** wire the audio session manager + mic audit (NullCodec under qemu), CI-verified ([#399](https://github.com/forkwright/thumos/issues/399)) ([#508](https://github.com/forkwright/thumos/issues/508)) ([8ad8d4a](https://github.com/forkwright/thumos/commit/8ad8d4a0c3b7ae970cfe1cd81852a09ad6188552))
* **thumos:** wire the BT A2DP audio profile (NullBtHw under qemu), CI-verified ([#401](https://github.com/forkwright/thumos/issues/401)) ([#512](https://github.com/forkwright/thumos/issues/512)) ([94ac009](https://github.com/forkwright/thumos/commit/94ac0097456713ce1108a4a9e7bcec12031b52eb))
* **thumos:** wire the heorte calendar/alarm/timer manager, CI-verified (closes [#400](https://github.com/forkwright/thumos/issues/400)) ([#516](https://github.com/forkwright/thumos/issues/516)) ([ab1069e](https://github.com/forkwright/thumos/commit/ab1069ece3b823b92b775282e08c49be63476fa3))
* **thumos:** wire the SIM-management API over the modem transport, CI-verified ([#398](https://github.com/forkwright/thumos/issues/398)) ([#515](https://github.com/forkwright/thumos/issues/515)) ([b4dfe41](https://github.com/forkwright/thumos/commit/b4dfe416e31eeff38eff797e63708d57f82fb2ae))
* **thumos:** wire the telephony AT/call stack (mock-backed under qemu), CI-verified ([#398](https://github.com/forkwright/thumos/issues/398)) ([#507](https://github.com/forkwright/thumos/issues/507)) ([85bae35](https://github.com/forkwright/thumos/commit/85bae352ec185cd205d9b426c5a4f160d8c86af3))
* **thumos:** wire the trust-hierarchy clock into the loop + home display ([#402](https://github.com/forkwright/thumos/issues/402)) ([#505](https://github.com/forkwright/thumos/issues/505)) ([a359de5](https://github.com/forkwright/thumos/commit/a359de56b8efc99f4ad5844d8d5339241a98d6e6))


### Bug Fixes

* **thumos:** fail-close fork for PL0 callers -- deny, not corrupt ([#478](https://github.com/forkwright/thumos/issues/478) interim) ([#494](https://github.com/forkwright/thumos/issues/494)) ([aa23b8c](https://github.com/forkwright/thumos/commit/aa23b8c573af0da85cd0923199a66a277b7de057))
* **thumos:** free frames under the kernel L1 in brk/munmap/mmap (fork-aliasing, [#497](https://github.com/forkwright/thumos/issues/497)) ([#522](https://github.com/forkwright/thumos/issues/522)) ([3a9b94a](https://github.com/forkwright/thumos/commit/3a9b94a4047a812e1b009456c9bd565748bbd354))
* **thumos:** per-process image mapping — fork+exec composes ([#502](https://github.com/forkwright/thumos/issues/502)) ([#525](https://github.com/forkwright/thumos/issues/525)) ([93a43ba](https://github.com/forkwright/thumos/commit/93a43baa2130f1a31e4a152d5519bfcfb4779b88))
* **thumos:** userspace sleep really yields -- no busy-wait deadlock ([#477](https://github.com/forkwright/thumos/issues/477), closes [#477](https://github.com/forkwright/thumos/issues/477)) ([#493](https://github.com/forkwright/thumos/issues/493)) ([cc510fc](https://github.com/forkwright/thumos/commit/cc510fc17b568257164923b462f5383f37bcf881))

## [0.1.7](https://github.com/forkwright/thumos/compare/v0.1.6...v0.1.7) (2026-07-06)


### Features

* **thumos:** two-level per-process FD table ([#267](https://github.com/forkwright/thumos/issues/267), closes [#84](https://github.com/forkwright/thumos/issues/84) [#32](https://github.com/forkwright/thumos/issues/32)) ([#470](https://github.com/forkwright/thumos/issues/470)) ([228fef2](https://github.com/forkwright/thumos/commit/228fef2210ee712b8e4a3f464e6eeba3474ee691))
* **thumos:** W^X kernel memory via L2 page mapping ([#417](https://github.com/forkwright/thumos/issues/417), closes [#18](https://github.com/forkwright/thumos/issues/18) wave) ([#473](https://github.com/forkwright/thumos/issues/473)) ([ed65feb](https://github.com/forkwright/thumos/commit/ed65febc57efb2193e9161f18112e26f66188b45))

## [0.1.6](https://github.com/forkwright/thumos/compare/v0.1.5...v0.1.6) (2026-07-06)


### Features

* **metaxu:** add aletheia bridge client ([f102ef3](https://github.com/forkwright/thumos/commit/f102ef3054604c2dccaf49a1dd17255ce55579f3)), closes [#141](https://github.com/forkwright/thumos/issues/141)
* **thumos:** boot the real kernel under QEMU + fix 2 latent boot bugs ([#420](https://github.com/forkwright/thumos/issues/420), [#461](https://github.com/forkwright/thumos/issues/461)) ([#462](https://github.com/forkwright/thumos/issues/462)) ([a561af8](https://github.com/forkwright/thumos/commit/a561af80b4bde2d2aa5303de822d52826a1d3d15))
* **thumos:** boot-&gt;service handoff — KernelState + kardia superloop + reflex fast-path ([#420](https://github.com/forkwright/thumos/issues/420)) ([#464](https://github.com/forkwright/thumos/issues/464)) ([5e68d3c](https://github.com/forkwright/thumos/commit/5e68d3cb19f23861916b591458db1e9ad01cf8ed))
* **thumos:** fail-closed secure boot + build-time trust anchor ([#217](https://github.com/forkwright/thumos/issues/217), [#233](https://github.com/forkwright/thumos/issues/233)) ([#468](https://github.com/forkwright/thumos/issues/468)) ([2a57b66](https://github.com/forkwright/thumos/commit/2a57b66347267e68bac579b1f97a50fd89fa138f))


### Bug Fixes

* **aither,haphe:** replace slice indexing with .get(); annotate shallow-struct and deflection ([#192](https://github.com/forkwright/thumos/issues/192)) ([c81802e](https://github.com/forkwright/thumos/commit/c81802e9ae3b28b7d1c85263219d1d252bb10d33))
* **aither:** replace ring crypto helpers ([#170](https://github.com/forkwright/thumos/issues/170)) ([a064298](https://github.com/forkwright/thumos/commit/a0642980c0ecbf38aa69d19d23742086f154110c)), closes [#146](https://github.com/forkwright/thumos/issues/146)
* cache-flush durability, IMSI neighbor tracking, screen_home DoS + coverage (5 issues) ([#426](https://github.com/forkwright/thumos/issues/426)) ([e918804](https://github.com/forkwright/thumos/commit/e9188045c2c78fd791f2b61668444138770124de)), closes [#375](https://github.com/forkwright/thumos/issues/375) [#377](https://github.com/forkwright/thumos/issues/377) [#379](https://github.com/forkwright/thumos/issues/379) [#355](https://github.com/forkwright/thumos/issues/355) [#423](https://github.com/forkwright/thumos/issues/423)
* **ci:** waive gate-attestation by head branch, not actor ([#469](https://github.com/forkwright/thumos/issues/469)) ([b184b1d](https://github.com/forkwright/thumos/commit/b184b1d936176003d7b02e14983194bb3f042f1d))
* **eidolon:** replace unwrap_or_default with explicit handling; add test assertions ([#189](https://github.com/forkwright/thumos/issues/189)) ([3620342](https://github.com/forkwright/thumos/commit/3620342d06e4d4c544b861f073679b8f529748ac))
* **elf:** harden the ELF loader against a crafted execve image (5 issues) ([#413](https://github.com/forkwright/thumos/issues/413)) ([e9b6768](https://github.com/forkwright/thumos/commit/e9b67681cb8c75c8c0f108e05d57efb53bca4dd4)), closes [#316](https://github.com/forkwright/thumos/issues/316) [#317](https://github.com/forkwright/thumos/issues/317) [#318](https://github.com/forkwright/thumos/issues/318) [#327](https://github.com/forkwright/thumos/issues/327) [#328](https://github.com/forkwright/thumos/issues/328)
* **fuzz:** use standalone fuzz crate name ([#202](https://github.com/forkwright/thumos/issues/202)) ([5076b5e](https://github.com/forkwright/thumos/commit/5076b5e3b74f1b1602fc44ee0c3e5747425d6068))
* **hw:** GIC EOI ordering, WMT regulator lifecycle, DSI init, audio atomicity (8 issues) ([#428](https://github.com/forkwright/thumos/issues/428)) ([e96b2f2](https://github.com/forkwright/thumos/commit/e96b2f241a42003f1ae8fc5951d4bae6b05edcd2)), closes [#341](https://github.com/forkwright/thumos/issues/341) [#349](https://github.com/forkwright/thumos/issues/349) [#352](https://github.com/forkwright/thumos/issues/352) [#362](https://github.com/forkwright/thumos/issues/362) [#389](https://github.com/forkwright/thumos/issues/389) [#391](https://github.com/forkwright/thumos/issues/391) [#387](https://github.com/forkwright/thumos/issues/387) [#390](https://github.com/forkwright/thumos/issues/390)
* **hw:** MediaTek driver register-access correctness (6 issues) ([#419](https://github.com/forkwright/thumos/issues/419)) ([8d14746](https://github.com/forkwright/thumos/commit/8d147467ca017f9b2eb64daf2b451ccf79a845ea)), closes [#227](https://github.com/forkwright/thumos/issues/227) [#286](https://github.com/forkwright/thumos/issues/286) [#261](https://github.com/forkwright/thumos/issues/261) [#262](https://github.com/forkwright/thumos/issues/262) [#221](https://github.com/forkwright/thumos/issues/221) [#293](https://github.com/forkwright/thumos/issues/293)
* **kanon:** restore full main gate ([75b96f5](https://github.com/forkwright/thumos/commit/75b96f5c7856ed5d8301cd1d613b5d7350c33e9e))
* **kernel:** 7 correctness defects (timer, fault, audit, lfs, sms, radio, audio) ([#418](https://github.com/forkwright/thumos/issues/418)) ([d81073a](https://github.com/forkwright/thumos/commit/d81073a80e191de19d7bdbb1b4afe59d54303c04)), closes [#342](https://github.com/forkwright/thumos/issues/342) [#252](https://github.com/forkwright/thumos/issues/252) [#297](https://github.com/forkwright/thumos/issues/297) [#333](https://github.com/forkwright/thumos/issues/333) [#306](https://github.com/forkwright/thumos/issues/306) [#254](https://github.com/forkwright/thumos/issues/254) [#386](https://github.com/forkwright/thumos/issues/386)
* **kernel:** add quadrant tags to TODO markers; annotate intentional result swallows ([#188](https://github.com/forkwright/thumos/issues/188)) ([f870fac](https://github.com/forkwright/thumos/commit/f870facafdc23ebfb379de1d315ddc1f4a51fef6))
* **kernel:** annotate fuzz result swallows; add quadrant tags to socket.rs TODOs ([#197](https://github.com/forkwright/thumos/issues/197)) ([cee4edf](https://github.com/forkwright/thumos/commit/cee4edf41587b11441950573f610469acf9402fa))
* **kernel:** annotate intentional result swallows; fix unwrap_or_default in fd/emmc/gic ([#195](https://github.com/forkwright/thumos/issues/195)) ([701c225](https://github.com/forkwright/thumos/commit/701c2259a0b464e2b55f1347be3c56df4fec1af9))
* **kernel:** close wifi readiness truthfully ([b488b04](https://github.com/forkwright/thumos/commit/b488b048bfb15d6f2aa139733a22f486a6dc0f76))
* **kernel:** fork() child runs on its own stack, not the parent's ([#208](https://github.com/forkwright/thumos/issues/208)) ([#407](https://github.com/forkwright/thumos/issues/407)) ([d4d6626](https://github.com/forkwright/thumos/commit/d4d6626f7bc57b1018e85bc5d960c34f306cbe81))
* **kernel:** process/memory lifecycle safety (12 issues) ([#408](https://github.com/forkwright/thumos/issues/408)) ([18a5930](https://github.com/forkwright/thumos/commit/18a5930f59faef66d75e23fd2179bdc4a675b284)), closes [#232](https://github.com/forkwright/thumos/issues/232) [#224](https://github.com/forkwright/thumos/issues/224) [#218](https://github.com/forkwright/thumos/issues/218) [#225](https://github.com/forkwright/thumos/issues/225) [#226](https://github.com/forkwright/thumos/issues/226) [#222](https://github.com/forkwright/thumos/issues/222) [#251](https://github.com/forkwright/thumos/issues/251) [#264](https://github.com/forkwright/thumos/issues/264) [#255](https://github.com/forkwright/thumos/issues/255) [#220](https://github.com/forkwright/thumos/issues/220) [#269](https://github.com/forkwright/thumos/issues/269) [#249](https://github.com/forkwright/thumos/issues/249)
* **kernel:** render initial home status frame ([f5fef53](https://github.com/forkwright/thumos/commit/f5fef5369dc79e6ec6040bd45b59609ba5301c9a))
* **kernel:** replace unwrap_or_default with explicit EINVAL returns ([#187](https://github.com/forkwright/thumos/issues/187)) ([bdc05e6](https://github.com/forkwright/thumos/commit/bdc05e6a9bdcd545ede625019778c9d0ed142855))
* **kernel:** report missing userspace entries ([86eeacb](https://github.com/forkwright/thumos/commit/86eeacb77f32e763a739dfbb21073879e991253c))
* **kernel:** track wifi network readiness ([#174](https://github.com/forkwright/thumos/issues/174)) ([3c28d8b](https://github.com/forkwright/thumos/commit/3c28d8b2a69df9959d0231c9feae01075cc7637d))
* **kernel:** type Matrix domain identifiers ([#203](https://github.com/forkwright/thumos/issues/203)) ([6f2a33f](https://github.com/forkwright/thumos/commit/6f2a33f3f19a5d64acc1c8996584bf6bcf25be36))
* **kernel:** use mounted ramfs for userspace spawn ([#177](https://github.com/forkwright/thumos/issues/177)) ([59e1790](https://github.com/forkwright/thumos/commit/59e1790d0b3767f526c5f0abbfeedb4c8709c7d9))
* **kernel:** wire firewall into network device path ([ddee88c](https://github.com/forkwright/thumos/commit/ddee88c78162fd9d14c2a7fe1479d9aee9181b7e))
* **kinit:** separate idle fallbacks from userspace count ([abbe3f5](https://github.com/forkwright/thumos/commit/abbe3f500790350202a260a4f225d9dcd6ac193b))
* **kinit:** separate loopback smoke from network readiness ([7449461](https://github.com/forkwright/thumos/commit/7449461832d04091517bedd1161967db130d9145))
* **kinit:** stop marking security placeholders ok ([f1c5c91](https://github.com/forkwright/thumos/commit/f1c5c91ceff0c0eeab3bf7ab724dba423111785d))
* **klesis,leipsanon,krypta,stegnos:** replace unwrap_or_default; add test assertions ([#190](https://github.com/forkwright/thumos/issues/190)) ([1b521c5](https://github.com/forkwright/thumos/commit/1b521c55502da380cd00d9d619bdf09d832e08d6))
* **klesis,thumos,leipsanon,sema,stegnos,eidolon,topos:** close lint quality wave ([6b1aa06](https://github.com/forkwright/thumos/commit/6b1aa066467ea169b9a31a458ed3ac366d6300ca)), closes [#185](https://github.com/forkwright/thumos/issues/185) [#186](https://github.com/forkwright/thumos/issues/186) [#193](https://github.com/forkwright/thumos/issues/193) [#194](https://github.com/forkwright/thumos/issues/194)
* **krypta:** replace ring with rustcrypto primitives ([#175](https://github.com/forkwright/thumos/issues/175)) ([8a4b887](https://github.com/forkwright/thumos/commit/8a4b887d13999efbc8f3839391632a062a5dc807))
* **leipsanon:** emergency wipe skipped block devices + aborted on &gt;4 GiB ([#214](https://github.com/forkwright/thumos/issues/214), [#242](https://github.com/forkwright/thumos/issues/242)) ([#424](https://github.com/forkwright/thumos/issues/424)) ([61e234d](https://github.com/forkwright/thumos/commit/61e234dfa4900171963dbf0c0856b619a0e5fa6d))
* **leipsanon:** replace ring rng ([#167](https://github.com/forkwright/thumos/issues/167)) ([5696c3c](https://github.com/forkwright/thumos/commit/5696c3c1bb5273f43d92d75cd328b1ea30320b8c))
* **lint:** import order, test use-super, config deny-unknown-fields, gitleaks trailing comma, README em-dashes ([#182](https://github.com/forkwright/thumos/issues/182)) ([cb90c53](https://github.com/forkwright/thumos/commit/cb90c539d1c9870492c8c1edac57088a79296390))
* **manifest:** add kanon maturity metadata ([#200](https://github.com/forkwright/thumos/issues/200)) ([ffe61a0](https://github.com/forkwright/thumos/commit/ffe61a04a0a3073ab2175b970fbda1f87a43714d))
* **matrix:** validate typed Matrix identifier format at construction ([#373](https://github.com/forkwright/thumos/issues/373)) ([#427](https://github.com/forkwright/thumos/issues/427)) ([bf1ee6c](https://github.com/forkwright/thumos/commit/bf1ee6c51882ba0a534047ec618cd7e66d9fd228))
* **mmu:** IRQ-safe allocators, PL1-only kernel mapping, L2 reclaim (4 issues) ([#415](https://github.com/forkwright/thumos/issues/415)) ([500f5c1](https://github.com/forkwright/thumos/commit/500f5c1c51d0addc7c2c23c73fa719b4b10969b7)), closes [#322](https://github.com/forkwright/thumos/issues/322) [#323](https://github.com/forkwright/thumos/issues/323) [#330](https://github.com/forkwright/thumos/issues/330) [#331](https://github.com/forkwright/thumos/issues/331)
* **provision:** authenticate USB provisioning bundles with Ed25519 ([#270](https://github.com/forkwright/thumos/issues/270)) ([#412](https://github.com/forkwright/thumos/issues/412)) ([cadcd26](https://github.com/forkwright/thumos/commit/cadcd26e2a540ead221d5f3234fc7651c89137b3))
* **pteron,kelyphos:** replace unwrap_or_default; annotate intentional result swallows ([#191](https://github.com/forkwright/thumos/issues/191)) ([d1f8801](https://github.com/forkwright/thumos/commit/d1f8801eb428a59335da20e8e1bb19bad680f3ba))
* **radio:** driver/parser adversary-safety across BT/WMT/GPS/mesh/CCCI (10 issues) ([#410](https://github.com/forkwright/thumos/issues/410)) ([1f9eb76](https://github.com/forkwright/thumos/commit/1f9eb7610565ad24516ec4acdbf648aedb3a74f9)), closes [#277](https://github.com/forkwright/thumos/issues/277) [#299](https://github.com/forkwright/thumos/issues/299) [#305](https://github.com/forkwright/thumos/issues/305) [#292](https://github.com/forkwright/thumos/issues/292) [#353](https://github.com/forkwright/thumos/issues/353) [#350](https://github.com/forkwright/thumos/issues/350) [#351](https://github.com/forkwright/thumos/issues/351) [#354](https://github.com/forkwright/thumos/issues/354) [#313](https://github.com/forkwright/thumos/issues/313) [#265](https://github.com/forkwright/thumos/issues/265)
* **ramfs:** guard malformed cpio bounds ([#169](https://github.com/forkwright/thumos/issues/169)) ([2de1a18](https://github.com/forkwright/thumos/commit/2de1a18c8c2d27cef4940e5e96fef48288c665a5)), closes [#144](https://github.com/forkwright/thumos/issues/144)
* **ramfs:** normalize dot-prefixed cpio paths ([#168](https://github.com/forkwright/thumos/issues/168)) ([3bef495](https://github.com/forkwright/thumos/commit/3bef4955f89f79844aa7d38f9d0be1c2d6eb4f0b))
* **security:** bound attacker-controlled input + fix the privacy-purge auth gap (8 issues) ([#421](https://github.com/forkwright/thumos/issues/421)) ([0f74966](https://github.com/forkwright/thumos/commit/0f749660efca7f68a2f54ffe8bf075ff03013322)), closes [#363](https://github.com/forkwright/thumos/issues/363) [#364](https://github.com/forkwright/thumos/issues/364) [#365](https://github.com/forkwright/thumos/issues/365) [#393](https://github.com/forkwright/thumos/issues/393) [#394](https://github.com/forkwright/thumos/issues/394) [#396](https://github.com/forkwright/thumos/issues/396) [#359](https://github.com/forkwright/thumos/issues/359) [#395](https://github.com/forkwright/thumos/issues/395)
* **security:** Sentinel-PIN KDF, anomaly-detection evasion, wipe-file coverage ([#411](https://github.com/forkwright/thumos/issues/411)) ([0f38d63](https://github.com/forkwright/thumos/commit/0f38d63114d207676fedd64bddda43407c746163)), closes [#272](https://github.com/forkwright/thumos/issues/272) [#248](https://github.com/forkwright/thumos/issues/248) [#246](https://github.com/forkwright/thumos/issues/246)
* SMS prompt guard, FM screen per-frame heap, mmu pool locking (3 issues) ([#429](https://github.com/forkwright/thumos/issues/429)) ([fc25889](https://github.com/forkwright/thumos/commit/fc25889dc0133924b01b13e7a21edf05c11df7be)), closes [#295](https://github.com/forkwright/thumos/issues/295) [#392](https://github.com/forkwright/thumos/issues/392) [#416](https://github.com/forkwright/thumos/issues/416)
* **stegnos:** replace ring key sealing helpers ([#171](https://github.com/forkwright/thumos/issues/171)) ([441a74c](https://github.com/forkwright/thumos/commit/441a74c1c6f9794733fa18b36c7078be86c10465))
* **thumos:** 3 operator-decided fixes — recall_preset, nous deselect, pteron alloc ([#457](https://github.com/forkwright/thumos/issues/457)) ([65850b2](https://github.com/forkwright/thumos/commit/65850b23392a46fd729df6a4d6d09e8c969175b7))
* **thumos:** kernel low-rollup batch 1 — 17 findings incl. 4 real bugs ([#282](https://github.com/forkwright/thumos/issues/282)) ([#433](https://github.com/forkwright/thumos/issues/433)) ([74543ba](https://github.com/forkwright/thumos/commit/74543baacf9e3bebaa98ceb9eac62bf7a6577658))
* **thumos:** kernel low-rollup batch 2 — 16 findings incl. security fixes ([#282](https://github.com/forkwright/thumos/issues/282)) ([#434](https://github.com/forkwright/thumos/issues/434)) ([b38e2ad](https://github.com/forkwright/thumos/commit/b38e2ad89f7f94873865a70f24f59e01f57cd90c))
* **thumos:** kernel low-rollup batch 3 — 7 fixes + 12 coverage tests ([#282](https://github.com/forkwright/thumos/issues/282)) ([#435](https://github.com/forkwright/thumos/issues/435)) ([1970e66](https://github.com/forkwright/thumos/commit/1970e66fb01ccfe7addcba7e4dca32c64320e09a))
* **thumos:** remainder-B batch 1 — 18 fixes incl. lock-screen + DSI safety ([#397](https://github.com/forkwright/thumos/issues/397)) ([#450](https://github.com/forkwright/thumos/issues/450)) ([84acbab](https://github.com/forkwright/thumos/commit/84acbab39e8ff8398f4275838b9f64f492127b7f))
* **thumos:** remainder-B batch 2 — 16 fixes incl. mic-audit + OOB guards ([#397](https://github.com/forkwright/thumos/issues/397) tail) ([#451](https://github.com/forkwright/thumos/issues/451)) ([21682ca](https://github.com/forkwright/thumos/commit/21682ca5d2ece7acb604b56225a1743eeeedd64e))
* **thumos:** structurally gate the debug console out of ship builds ([#372](https://github.com/forkwright/thumos/issues/372)) ([#460](https://github.com/forkwright/thumos/issues/460)) ([ee377f9](https://github.com/forkwright/thumos/commit/ee377f990712eb0b274fe64a4b201e66307ee43f))
* **thumos:** wave-1 low-rollup batch 1 — 17 fixes across 10 modules ([#384](https://github.com/forkwright/thumos/issues/384)) ([#443](https://github.com/forkwright/thumos/issues/443)) ([00da05c](https://github.com/forkwright/thumos/commit/00da05cdae9c560793af9836a48845003dbe6822))
* **thumos:** wave-1 low-rollup batch 2 — 16 fixes incl. concurrency/safety ([#384](https://github.com/forkwright/thumos/issues/384)) ([#444](https://github.com/forkwright/thumos/issues/444)) ([eab2445](https://github.com/forkwright/thumos/commit/eab244520f211e16da63be6deb46a2eee911ad77))
* **thumos:** wave-1 low-rollup batch 3 — security + coverage ([#384](https://github.com/forkwright/thumos/issues/384) tail) ([#445](https://github.com/forkwright/thumos/issues/445)) ([b216794](https://github.com/forkwright/thumos/commit/b216794517e327d22203212323ffec6798061e9c))
* **thumos:** wave-2 low-rollup batch 1 — 17 fixes across 9 modules ([#314](https://github.com/forkwright/thumos/issues/314)) ([#438](https://github.com/forkwright/thumos/issues/438)) ([3d9c6c9](https://github.com/forkwright/thumos/commit/3d9c6c9374278beb81312ae8ff1df6813700b749))
* **thumos:** wave-2 low-rollup batch 2 — 18 fixes incl. csprng boot-hang ([#314](https://github.com/forkwright/thumos/issues/314)) ([#439](https://github.com/forkwright/thumos/issues/439)) ([7eadc79](https://github.com/forkwright/thumos/commit/7eadc7961202820dd3da6eb414b07ab47ab7df01))
* **thumos:** wave-2 low-rollup batch 3 — 17 fixes incl. 4 security ([#314](https://github.com/forkwright/thumos/issues/314)) ([#440](https://github.com/forkwright/thumos/issues/440)) ([003408e](https://github.com/forkwright/thumos/commit/003408ea7b9362f4577e33ca1bdb8b50ea0537ce))
* **thumos:** wave-3 low-rollup batch 1 — 19 fixes incl. W^X + panic-wipe ([#337](https://github.com/forkwright/thumos/issues/337)) ([#447](https://github.com/forkwright/thumos/issues/447)) ([3999ee6](https://github.com/forkwright/thumos/commit/3999ee60978c6441a92ea76326e7ef40d7edb7ab))
* **toolchain:** align Rust pin to 1.94 ([#155](https://github.com/forkwright/thumos/issues/155)) ([#157](https://github.com/forkwright/thumos/issues/157)) ([37af34c](https://github.com/forkwright/thumos/commit/37af34ceece4c7691e60e38d5c1a1da13da546f9))
* touch off-by-one + non-transactional Matrix sync token ([#348](https://github.com/forkwright/thumos/issues/348), [#358](https://github.com/forkwright/thumos/issues/358)) ([#425](https://github.com/forkwright/thumos/issues/425)) ([8308fbb](https://github.com/forkwright/thumos/commit/8308fbb4a807b91f8cba7d2387008ffe0351672a))
* **trust:** harden adversarial time sources, seal iterations, IPC-to-kinit (6 issues) ([#422](https://github.com/forkwright/thumos/issues/422)) ([b016bb3](https://github.com/forkwright/thumos/commit/b016bb3a1ef495a4083aeb44a73e3b7386cd30fd)), closes [#366](https://github.com/forkwright/thumos/issues/366) [#367](https://github.com/forkwright/thumos/issues/367) [#374](https://github.com/forkwright/thumos/issues/374) [#376](https://github.com/forkwright/thumos/issues/376) [#357](https://github.com/forkwright/thumos/issues/357) [#371](https://github.com/forkwright/thumos/issues/371)
* **workspace:** low-severity rollup across 9 crates (real fixes + coverage) ([#432](https://github.com/forkwright/thumos/issues/432)) ([61a63ec](https://github.com/forkwright/thumos/commit/61a63ecdb73a947b0f654df4f4c239c18d62d660)), closes [#278](https://github.com/forkwright/thumos/issues/278) [#279](https://github.com/forkwright/thumos/issues/279) [#283](https://github.com/forkwright/thumos/issues/283) [#380](https://github.com/forkwright/thumos/issues/380) [#381](https://github.com/forkwright/thumos/issues/381) [#383](https://github.com/forkwright/thumos/issues/383)

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
