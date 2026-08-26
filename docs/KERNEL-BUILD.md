# Kernel Build

Canonical build and boot-witness runbook for the Thumos kernel: the bare-metal
Rust kernel in `crates/thumos/`, targeting the AGM M7 (MT6739). No Linux, no
vendor BSP tree, no cross-gcc, no dtc/mkbootimg tooling.

Every command on this page is an existing repository mechanism exercised by
hosted CI on every PR and push to `main` (`.github/workflows/ci.yml`, job
`kernel`; the local gate equivalent is the `kernel build` stage of
`.kanon-ci.toml`, run via `kanon gate`). If a command here drifts from CI, CI
is authoritative — file an issue.

One caveat governs the whole page: these commands prove the kernel **under
QEMU emulation only**. The physical device path stays unproven — see
[Hardware path: unproven](#hardware-path-unproven).

## Toolchain setup

From a clean checkout:

```bash
# Rust 1.94 is pinned by rust-toolchain.toml at the repo root; rustup selects
# it automatically for any cargo invocation inside this checkout.
rustup target add armv7a-none-eabi i686-unknown-linux-gnu

# Test runner used by CI. Its per-test process isolation is required by tests
# that touch the kernel's static-mut globals.
cargo install cargo-nextest --locked --version ^0.9

# 32-bit crt objects for linking the i686 test binary (Debian/Ubuntu):
sudo apt-get install gcc-multilib

# QEMU boot witness:
sudo dnf install qemu-system-arm      # Fedora
sudo apt-get install qemu-system-arm  # Debian/Ubuntu
brew install qemu                     # macOS
```

The build needs no other system packages: `armv7a-none-eabi` is a bare-metal
Rust target with no external linker or C toolchain dependency.

## Repository layout

- `crates/thumos/` — the kernel crate. Deliberately **excluded** from the
  Cargo workspace (`exclude` in the root `Cargo.toml`) so it can cross-compile
  to bare metal. Workspace-wide invocations (`cargo check --workspace`,
  `cargo nextest run --workspace`) do not touch it.
- `crates/thumos/.cargo/config.toml` — pins the default target
  (`armv7a-none-eabi`), the linker script (`link.ld`, kernel `.text` at
  `0x40008000`), the always-on zero-warning gate (`-D warnings`, #431), and
  the QEMU runner (`scripts/qemu-runner.sh`) for `cargo run` / `cargo test`.
- `crates/thumos/build.rs` — compiles the userspace programs (`init/*.rs`)
  into an image-resident initramfs CPIO, signs it, and embeds the boot trust
  anchor. See [Signing and attestation boundary](#signing-and-attestation-boundary).
- `scripts/qemu-runner.sh` — boots a built kernel under
  `qemu-system-arm -machine virt` and translates the semihosting exit code
  back to the caller. Documented in `scripts/README.md`.

NOTE: cargo discovers `.cargo/config.toml` from the current working directory,
not from `--manifest-path`. Run kernel cargo commands **from `crates/thumos/`**
(exactly as CI does with `working-directory: crates/thumos`). From the repo
root, the target pin, linker script, zero-warning gate, and QEMU runner
silently do not apply. The local gate's kernel stage compensates with an
explicit `RUSTFLAGS` + `--manifest-path` (see `.kanon-ci.toml`) — prefer the
directory-local form when running by hand.

## Host unit tests (i686)

Kernel unit tests run on 32-bit i686 because the kernel's syscall ABI uses
u32 addresses. A 64-bit host truncates real pointers and crashes.

```bash
cd crates/thumos
cargo nextest run --bin thumos --target i686-unknown-linux-gnu
```

CI adds `--build-jobs 8 --test-threads 8`. That is a resource cap on the CI
box, not a requirement.

## Producing the kernel image

```bash
cd crates/thumos
cargo build --release --target armv7a-none-eabi
```

Output: `crates/thumos/target/armv7a-none-eabi/release/thumos` — a single
static armv7a ELF, linked at `0x40008000` by `link.ld`. There is no separate
ramdisk/DTB/boot-image assembly step: `build.rs` embeds the signed
image-resident initramfs (`/init`, `/init2`, `/shell`, `/crasher`) and the
boot trust anchor directly into the kernel image, and QEMU loads the ELF
verbatim via `-kernel`. The always-on `-D warnings` rustflag makes this build
the zero-warning gate (#431): any new warning fails it.

Build features (declared in `crates/thumos/Cargo.toml`, where mutually
exclusive combinations `compile_error!` by design, so `--all-features` never
accidentally produces a shippable-looking binary):

| Feature | Purpose | Mutually exclusive with |
|---------|---------|-------------------------|
| *(default)* | Dev/bring-up build anchored to the committed, deliberately public dev key | — |
| `production` | Shippable image; requires `THUMOS_BOOT_KEY_PUB` (see signing boundary below) | `debug-console`, `qemu`, probes |
| `qemu` | QEMU `-machine virt` bring-up: remaps UART/GIC base addresses, swaps the MTK UART for a PL011, no-ops SoC-only MMIO, skips hardware init the virt board does not model | `production` |
| `debug-console` | Dev-only kernel UART debug shell (#372) | `production` |
| `kfault-probe` | CI fault-injection harness: deliberate PL1 `udf` after boot-complete (#487) | `production` |
| `crashloop-probe` | CI crash-loop harness for the PID 0 restart policy (#492) | `production` |

## QEMU boot witness

Build the QEMU-configuration kernel and boot it through the runner:

```bash
cd crates/thumos
cargo build --release --target armv7a-none-eabi --features qemu
THUMOS_QEMU_TIMEOUT=60 ../../scripts/qemu-runner.sh target/armv7a-none-eabi/release/thumos | tee boot.log
```

The runner boots the ELF under `qemu-system-arm -machine virt -cpu cortex-a7
-m 1024M -nographic` with ARM semihosting enabled. The kernel reports its
outcome via the semihosting `SYS_EXIT` call, and a 60-second watchdog
(`THUMOS_QEMU_TIMEOUT`) guards against a hung guest.

Minimal local witness — the same greps CI asserts:

```bash
grep 'THUMOS v0.1.0' boot.log                     # boot banner
grep 'THUMOS-QEMU: boot-complete' boot.log        # kinit reached boot-complete
grep 'THUMOS-QEMU: service-loop ticks=' boot.log  # PID 0 serviced real ticks
```

Runner exit codes:

| Code | Meaning |
|------|---------|
| 0 | Service loop ran to its tick cap (pass) |
| 1 | Kernel panic or non-zero guest exit |
| 2/3/4 | Guest aborts (data/prefetch/undefined-instruction; 4 is the expected result of the `kfault-probe` harness) |
| 5 | Service-loop stall (#461 tick-source class) |
| 64 | Runner invoked without a binary argument |
| 66 | Binary path does not exist |
| 124 | Hung guest killed by the runner timeout |
| 127 | `qemu-system-arm` not installed |

The CI kernel job asserts the full witness set on every PR, beyond the
minimum above: fail-closed degraded boot with no boot medium (`Secure boot:
DEGRADED`, passphrase refused, audit deferred — #217), signed image-resident
userspace (`image-resident initramfs signature verified`; `/init` and `/shell`
both running from their own per-process frames — #480/#526), UI render and
input/navigation, clock, telephony/audio/SIM/SMS/Bluetooth state machines
against mock transports, and the firewall policy+audit path. It also runs the
dedicated probe harnesses — `THUMOS_INIT_VARIANT=kread|kwrite|kexec|cp15|sleep|fork|exec|forkexec|guard`
and the `kfault-probe` / `crashloop-probe` features — each following the same
build-then-runner pattern above. See the `kernel` job in
`.github/workflows/ci.yml` for the exact invocations; do not copy them into
new scripts.

When the boot witness above fails or a kernel-state question needs more than
grep-able boot-log lines, reach for the GDB workflow in `scripts/README.md`
(`THUMOS_QEMU_GDB=1 scripts/qemu-runner.sh` + `scripts/gdb-thumos.sh`) first,
before adding a UART probe — it attaches a real debugger with symbols against
the same QEMU boot path used above, with no kernel code changes required.

`scripts/README.md` documents a lighter smoke check that needs no kernel
runtime (boot stub + UART write + semihosting exit only) — a convenience
example, not wired into CI:

```bash
cd crates/thumos
cargo run --example qemu_smoke --release   # prints "qemu_smoke: pass"
```

## Boot-image signing (Ed25519ph, #467)

`crates/hypographe` is the boot-image signing tool: it streams an image
through SHA-512 in bounded reads, Ed25519ph-signs with the anchor's seed,
and emits the `payload || zero-pad || signature(64)` sector-aligned layout
the kernel's streamed post-entry image gate
(`secure_boot::verify_image_streamed`) verifies. Because that verifier runs
inside the kernel, it cannot authenticate or measure the kernel that is
already executing:

```
cargo run -p hypographe -- <image-in> <seed-hex-file> <image-out>
```

For mkbootimg assembly, the combined kernel(+ramdisk) image is hypographe's
input, and its output is what gets flashed to the GPT `boot` partition. The
dev anchor (`keys/dev/boot-dev.seed`) signs dev images. A production signing
key requires an operator-owned offline-custody receipt and must never enter
the repo; this repository does not itself prove that such custody currently
exists.

## Signing and attestation boundary

Where trust enters the build — and what is deliberately **not** attested
today:

- **Boot trust anchor (Ed25519).** `crates/thumos/build.rs` (#233) embeds
  exactly one public key into the image. A `--features production` build
  requires `THUMOS_BOOT_KEY_PUB=<file>` naming a hex-encoded 32-byte public
  key provisioned by operator-controlled offline signing infrastructure and
  fails without it. The exact custody mechanism requires a separate operator
  receipt. Refused in every configuration:
  the committed dev key under `production`, the RFC 8032 section 7.1
  test-vector keys (the spec publishes their private halves, so anchors
  built from them are forgeable), and any byte string that is not a
  decompressable curve point.
- **Dev keypair is public by design** (`crates/thumos/keys/dev/`, AOSP
  test-keys pattern): any developer can build and sign dev images, and host
  tests round-trip sign→verify against the real embedded anchor. No
  production key is ever committed (`keys/.gitignore` blocks `production/`
  and `*.pem`).
- **Image-resident initramfs.** `build.rs` compiles `init/*.rs` to static
  armv7a ELFs, packs a newc CPIO, and signs it with the dev seed (#480) so
  signed image-resident userspace works in dev/QEMU builds. This is signature
  verification, not a TPM-style measurement or measurement log. Under a
  production anchor the dev signature does not verify; operator-controlled
  signing infrastructure must sign the production initramfs offline. The
  image then falls back to the eMMC post-entry signature gate (#217), which
  still cannot authenticate the already executing kernel. #467 owns the
  pre-entry chain.
- **Trust stamp.** Every image bakes a grep-able
  `THUMOS-BOOT-TRUST:{PROD|DEV}:<key fingerprint>` into the boot banner, and
  `secure_boot_ok` is only ever set when the anchor is a production key: a
  dev-anchored image can never establish trust on real hardware.
- **CI attestation, stated precisely.** The Gate Attestation workflow
  (`.github/workflows/gate-attestation.yml`, Gate-Passed trailer / hybrid
  full-gate build) attests the **workspace** fmt/check/clippy/nextest stages
  only. Per its own NOTE, it does not attest the excluded kernel crate. The
  kernel's executable witness is the `kernel` job of the CI workflow
  described on this page.
- **Release attestation (#536, fixed by #609).** The `release-please.yml`
  workflow's `release-attest` job attests the **release artifacts**: a
  deterministic `git archive` source tarball of the repo at the release tag
  (`thumos-vX.Y.Z.tar.gz`), plus two CycloneDX SBOMs — one for the workspace
  crates, one for the excluded kernel crate. Both are signed via
  `actions/attest-build-provenance` and `actions/attest-sbom` (SLSA v1
  provenance) and are independently verifiable:
  `gh attestation verify thumos-vX.Y.Z.tar.gz --repo forkwright/thumos`.
  Live and verified on v0.5.1, v0.6.0, v0.6.1, and v0.6.2 — each ships a
  tarball whose published sha256 matches a real, signed provenance
  statement.

  **What this does and does not prove.** The attestation subject is the
  git tree at the tag, not a compiled artifact — it proves the source you
  can rebuild from, and that GitHub Actions (not some other pipeline)
  produced the tarball and SBOMs from that exact commit. It says nothing
  about any specific *flashed* image: nothing in this repo's CI builds,
  signs, or attests a boot image, and the trust anchor described above is
  an independent mechanism (an Ed25519 key baked in at build time, checked
  at boot). Do not present a flashed/on-device boot image as
  release-attested — only the source tarball and its two SBOMs carry that
  attestation.

## Boot passphrase and encrypted userdata (#446)

The boot-time input subsystem behind `passphrase_ok`:

- **Flow.** kinit Step 8c probes the on-disk secrets preamble (#449)
  read-only, right after eMMC bring-up and before any mount. A provisioned
  device (preamble carries a verifier) runs the verify loop: poll the GPIO
  keypad matrix, drive the lock screen, and on submit derive
  PBKDF2-HMAC-SHA256(passphrase, salt, 100_000) and compare
  `HKDF(primary, "thumos-verify-v1")` against the stored verifier
  constant-time. Success derives the partition keys (Step 8c), and Step 8d
  mounts the userdata payload through `EncryptedBlockDevice` (AES-256-XTS)
  one sector past the preamble. An unprovisioned device runs first-boot
  setup instead: enter, confirm, store the verifier, derive, mount
  encrypted. Current source auto-formats on `InvalidSuperblock`, but that result
  also covers damaged/version-incompatible existing metadata; #360 blocks device
  use until an authenticated first-provisioning marker or separately confirmed
  format action distinguishes those states.
- **The verifier is not a fast oracle.** It is a PBKDF2-strength derived
  value, never `SHA-256(passphrase)` — a disk image buys an attacker the
  same per-guess cost as attacking the ciphertext itself.
- **Fail-closed mount.** A provisioned-but-locked payload (passphrase not
  entered: refused, throttled out, or hardware missing) is never
  plain-mounted and never formatted — the boot falls back to the
  initramfs root, and the throttle/wipe state machine (10 attempts →
  panic wipe) applies. The boot logic treats an unreadable preamble as locked.
- **Boot pad binding.** The 4×3 matrix yields digits, Star, Hash only:
  digits append, Star = backspace, Hash = submit/confirm. Boot passphrases
  are digits-only (minimum 6), constrained identically at setup so a
  passphrase is always enterable at boot. Post-boot symbol entry in
  `lock_screen.rs` stays unaffected.
- **One-way transition.** Completing first-boot setup writes the preamble
  sector at the userdata head and formats the payload encrypted. Plain
  pre-provisioning content does NOT migrate — first-boot setup overwrites it.
  qemu and dev-anchor builds never reach the gate (secure boot cannot
  establish trust there), so CI witnesses and dev iteration stay unaffected.
- **Acceptance status.** Host tests prove scan/debounce logic, preamble format,
  verifier derivation, and gate matrices. Software/source prerequisites remain:
  #854 owns the display transport, #841/#872 own accepted unlock/KDF policy,
  #866 retires the plaintext compatibility mount, and #870 owns eMMC RX-count
  semantics. Only after those land do GPIO/panel/eMMC/verify-mount paths enter
  operator-owned AGM M7 qualification.

## Hardware path: unproven

Everything on this page proves the kernel **under QEMU `-machine virt`
only**. This runbook does not upgrade the hardware status:

- The Rust kernel has **never booted on the physical AGM M7 / MT6739**.
  Hardware validation remains pending; the machine-checked
  [`capability-inventory.toml`](capability-inventory.toml) is the canonical
  record of each capability's reachability tier and hardware gate.
- The `qemu` feature exists precisely because the emulated board lacks the
  hardware: it substitutes an observable software countdown for the MT6739
  watchdog, no-ops display operations, and skips eMMC, display (GC9306),
  keypad, USB, and CCCI/modem init. The watchdog witness proves only this
  board-neutral integration seam, never the physical WDT MMIO/reset path. CPU
  DVFS/core-parking actuation is absent from every runtime build pending
  #879's source-grounded transaction. Those drivers have no executed
  on-device path.
- Repository tooling produces **no flashable device package** — no Android
  boot image, no scatter-file integration. There is nothing on this
  page to flash, and operators must not flash the QEMU image to a device.
- The Linux 4.4 BSP build previously documented in this file was exploration
  against a third-party vendor tree. Those images were never flashed either.
  The project retired that path: it is not a fallback, and its steps (vendor
  defconfigs, manual in-tree patches, mkbootimg) are not part of the current
  build. The stock kernel config and hardware probe notes survive only as
  frozen reference records (`docs/kernel-config-stock`, `docs/HARDWARE.md`,
  `docs/PROBE.md`).
