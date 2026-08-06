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
QEMU emulation only**. The physical device path is unproven — see
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

No other system packages are needed: `armv7a-none-eabi` is a bare-metal Rust
target with no external linker or C toolchain dependency.

## Repository layout

- `crates/thumos/` — the kernel crate. Deliberately **excluded** from the
  Cargo workspace (`exclude` in the root `Cargo.toml`) so it can cross-compile
  to bare metal; workspace-wide invocations (`cargo check --workspace`,
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
(exactly as CI does with `working-directory: crates/thumos`); from the repo
root the target pin, linker script, zero-warning gate, and QEMU runner
silently do not apply. The local gate's kernel stage compensates with an
explicit `RUSTFLAGS` + `--manifest-path` (see `.kanon-ci.toml`) — prefer the
directory-local form when running by hand.

## Host unit tests (i686)

Kernel unit tests run on 32-bit i686 because the kernel's syscall ABI uses
u32 addresses; a 64-bit host truncates real pointers and crashes.

```bash
cd crates/thumos
cargo nextest run --bin thumos --target i686-unknown-linux-gnu
```

CI adds `--build-jobs 8 --test-threads 8`; that is a resource cap on the CI
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

Build features (declared in `crates/thumos/Cargo.toml`; mutually exclusive
combinations `compile_error!` by design, so `--all-features` never
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
-m 1024M -nographic` with ARM semihosting enabled; the kernel reports its
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
DEGRADED`, passphrase refused, audit deferred — #217), measured userspace
(`image-resident initramfs signature verified`; `/init` and `/shell` both
running from their own per-process frames — #480/#526), UI render and
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

A lighter smoke check that needs no kernel runtime (boot stub + UART write +
semihosting exit only) is documented in `scripts/README.md` (a convenience
example; not wired into CI):

```bash
cd crates/thumos
cargo run --example qemu_smoke --release   # prints "qemu_smoke: pass"
```

## Boot-image signing (Ed25519ph, #467)

`crates/sphragis` is the boot-image signing tool: it streams an image
through SHA-512 in bounded reads, Ed25519ph-signs with the anchor's seed,
and emits the `payload || zero-pad || signature(64)` sector-aligned layout
the kernel's streamed boot gate (`secure_boot::verify_image_streamed`)
verifies:

```
cargo run -p sphragis -- <image-in> <seed-hex-file> <image-out>
```

For mkbootimg assembly: the combined kernel(+ramdisk) image is sphragis's
input; its output is what gets flashed to the GPT `boot` partition. The
dev anchor (`keys/dev/boot-dev.seed`) signs dev images; production keys
live offline and never enter the repo.

## Signing and attestation boundary

Where trust enters the build — and what is deliberately **not** attested
today:

- **Boot trust anchor (Ed25519).** `crates/thumos/build.rs` (#233) embeds
  exactly one public key into the image. A `--features production` build
  requires `THUMOS_BOOT_KEY_PUB=<file>` naming a hex-encoded 32-byte public
  key provisioned by the offline signing infrastructure (Titan security key /
  air-gapped machine) and fails without it. Refused in every configuration:
  the committed dev key under `production`, the RFC 8032 section 7.1
  test-vector keys (private halves are published, hence forgeable anchors),
  and any byte string that is not a decompressable curve point.
- **Dev keypair is public by design** (`crates/thumos/keys/dev/`, AOSP
  test-keys pattern): any developer can build and sign dev images, and host
  tests round-trip sign→verify against the real embedded anchor. No
  production key is ever committed (`keys/.gitignore` blocks `production/`
  and `*.pem`).
- **Image-resident initramfs.** `build.rs` compiles `init/*.rs` to static
  armv7a ELFs, packs a newc CPIO, and signs it with the dev seed (#480) so
  measured userspace works in dev/QEMU builds. Under a production anchor this
  dev signature does not verify — the production initramfs is signed offline
  by the signing infrastructure — and the image falls back to the eMMC
  secure-boot gate (#217).
- **Trust stamp.** Every image bakes a grep-able
  `THUMOS-BOOT-TRUST:{PROD|DEV}:<key fingerprint>` into the boot banner, and
  `secure_boot_ok` is only ever set when the anchor is a production key: a
  dev-anchored image can never establish trust on real hardware.
- **CI attestation, stated precisely.** The Gate Attestation workflow
  (`.github/workflows/gate-attestation.yml`, Gate-Passed trailer / hybrid
  full-gate build) attests the **workspace** fmt/check/clippy/nextest stages
  only; per its own NOTE it does not attest the excluded kernel crate. The
  kernel's executable witness is the `kernel` job of the CI workflow
  described on this page — there is no cryptographic attestation of a
  released boot image. Release attestation is broken and tracked in #536. Do
  not present any current artifact as release-signed or release-attested.

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
  encrypted (formatting the payload on that first encrypted mount).
- **The verifier is not a fast oracle.** It is a PBKDF2-strength derived
  value, never `SHA-256(passphrase)` — a disk image buys an attacker the
  same per-guess cost as attacking the ciphertext itself.
- **Fail-closed mount.** A provisioned-but-locked payload (passphrase not
  entered: refused, throttled out, or hardware missing) is never
  plain-mounted and never formatted — the boot falls back to the
  initramfs root, and the throttle/wipe state machine (10 attempts →
  panic wipe) applies. An unreadable preamble is treated as locked.
- **Boot pad binding.** The 4×3 matrix yields digits, Star, Hash only:
  digits append, Star = backspace, Hash = submit/confirm. Boot passphrases
  are digits-only (minimum 6), constrained identically at setup so a
  passphrase is always enterable at boot. Post-boot symbol entry in
  `lock_screen.rs` is unaffected.
- **One-way transition.** Completing first-boot setup writes the preamble
  sector at the userdata head and formats the payload encrypted. Plain
  pre-provisioning content does NOT migrate — it is overwritten. qemu and
  dev-anchor builds never reach the gate (secure boot cannot establish
  trust there), so CI witnesses and dev iteration are unaffected.
- **Hardware status.** The live GPIO matrix scan, the display render, and
  the on-device verify/mount path are hardware-gated (pin assignments are
  placeholders pending AGM M7 schematic verification, mirroring haphe);
  host tests prove the scan/debounce logic, the preamble format, the
  verifier derivation, and the gate matrices.

## Hardware path: unproven

Everything on this page proves the kernel **under QEMU `-machine virt`
only**. This runbook does not upgrade the hardware status:

- The Rust kernel has **never booted on the physical AGM M7 / MT6739**.
  Hardware validation remains pending (see README and
  `docs/KERNEL-WIRING-AUDIT.md` for the compiled-but-unwired surface).
- The `qemu` feature exists precisely because the emulated board lacks the
  hardware: it no-ops SoC-only MMIO (watchdog, DVFS, MCDI, DSI) and skips
  eMMC, display (GC9306), keypad, USB, and CCCI/modem init. Those drivers
  have no executed on-device path.
- Repository tooling produces **no flashable device package** — no Android
  boot image, no scatter-file integration. There is nothing on this
  page to flash, and the QEMU image must not be flashed to a device.
- The Linux 4.4 BSP build previously documented in this file was exploration
  against a third-party vendor tree; those images were never flashed either.
  That path is retired: it is not a fallback, and its steps (vendor
  defconfigs, manual in-tree patches, mkbootimg) are not part of the current
  build. The stock kernel config and hardware probe notes survive only as
  frozen reference records (`docs/kernel-config-stock`, `docs/HARDWARE.md`,
  `docs/PROBE.md`).
