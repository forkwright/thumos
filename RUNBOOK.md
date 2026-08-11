# RUNBOOK

Operational procedures for thumos. Every command below is a real repository
mechanism — a script under `scripts/`, a step from `.github/workflows/ci.yml`,
or the local gate (`kanon gate`, `.kanon-ci.toml`) that mirrors it. If a
command here ever drifts from CI, CI is authoritative (same rule as
`docs/KERNEL-BUILD.md`) — file an issue rather than trusting this page.

thumos is not a deployed service: there is no running instance to page for,
no database, and no user traffic. "Operational" here means the kernel's own
QEMU-proven lifecycle — build, boot-witness, and diagnose a failure — plus
the boot-signing material the build depends on. Sections below follow
`OPERATIONS.md`'s runbook shape; sections that do not apply to a bare-metal
kernel project say so rather than being silently dropped.

## Architecture

Full architecture, the crate roster, and current phase status live in
`ARCHITECTURE.md` and `README.md` — this section only orients where to run
things, not what they are (a second description here would drift from
those). Two directories matter operationally:

- `crates/thumos/` — the kernel binary. Deliberately excluded from the
  Cargo workspace (bare-metal target), so its build, its host tests, and
  its lint pass each need their own invocation — see Start/stop and
  Common issues.
- The 19 workspace library crates under `crates/` (`klesis`, `klesis-core`,
  `aither`, `pteron`, ... — full list in `Cargo.toml`'s `members`) — a
  normal `cargo`-buildable workspace, one host toolchain, one test runner.

## Start/stop (build and boot)

From a clean checkout, one-time toolchain setup:

```bash
rustup target add armv7a-none-eabi i686-unknown-linux-gnu
cargo install cargo-nextest --locked --version ^0.9
sudo dnf install qemu-system-arm gcc-multilib   # Fedora: gcc-multilib -> glibc-devel.i686
# Debian/Ubuntu: sudo apt-get install qemu-system-arm gcc-multilib
```

Workspace crates (host):

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace --build-jobs 8 --test-threads 8
cargo test --doc --workspace   # nextest does not run doctests
```

Kernel crate (bare-metal, excluded from the workspace — run its commands
from `crates/thumos/`, since `.cargo/config.toml` is discovered from the
invocation directory, not from `--manifest-path`):

```bash
scripts/kernel-build.sh          # release cross-compile, armv7a-none-eabi, -D warnings gate
scripts/kernel-host-tests.sh     # i686 host unit tests (u32-faithful syscall ABI)
scripts/kernel-clippy.sh         # i686 clippy, zero-warning gate
```

"Stop" has no separate meaning here — there is no long-running process to
signal. A QEMU boot run (below) is bounded by its own timeout and exits on
its own.

## Health check (the QEMU boot witness)

The kernel's only proof of correctness beyond unit tests is booting under
QEMU and asserting on its own log output. Run the full witness matrix in
canonical order (same scripts CI runs step-by-step):

```bash
scripts/witness-run-all.sh
```

Or the boot witness alone:

```bash
cd crates/thumos
cargo build --release --target armv7a-none-eabi --features qemu
THUMOS_QEMU_TIMEOUT=60 ../../scripts/qemu-runner.sh target/armv7a-none-eabi/release/thumos | tee boot.log
```

Minimum "is it alive" check — the same three lines CI asserts first:

```bash
grep 'THUMOS v0.1.0' boot.log                     # boot banner
grep 'THUMOS-QEMU: boot-complete' boot.log        # kinit reached boot-complete
grep 'THUMOS-QEMU: service-loop ticks=' boot.log  # PID 0 serviced real ticks
```

`scripts/witness/boot.sh` asserts far more than that (fail-closed degraded
boot, measured userspace, `/init` + `/shell` per-process isolation, render,
input, clock, telephony/audio/SIM/BT/firewall state machines, and the PL0
isolation probes) — read it directly for the full assertion list rather
than trusting a paraphrase here.

## Common issues

| Symptom | Likely cause | Resolution |
|---|---|---|
| `qemu-runner.sh` exits 127 | `qemu-system-arm` not installed | Install it (command printed by the runner itself); see toolchain setup above |
| `qemu-runner.sh` exits 124 | Guest hung past `THUMOS_QEMU_TIMEOUT` (default 60s) | Not a bare timeout — every real failure path exits with a named code first (0/1/2/3/4/5); 124 alone means the guest never reached any exit path. Attach GDB (below) rather than guessing |
| `qemu-runner.sh` exits 5 | Service-loop stall — the tick source (#461 class) is not advancing | Check `boot.log` for `kardia: timer elapsed_ms=advancing`; a missing line points at a CNTFRQ/CNTPCT regression |
| `qemu-runner.sh` exits 1 | Kernel panic or non-zero guest exit | Read `boot.log` in full (the runner always prints it) for the panic message before the exit |
| `scripts/kernel-build.sh` fails on a new warning | The `-D warnings` gate in `crates/thumos/.cargo/config.toml` is always on (#431) | Fix the warning. Never pass `RUSTFLAGS` through the environment when building the kernel — it clobbers the config's rustflags and silently drops this gate |
| `scripts/kernel-host-tests.sh` fails to link | 32-bit crt objects missing | `gcc-multilib` (Debian/Ubuntu) or `glibc-devel.i686` (Fedora) — the script's own probe step names the fix |
| A PL0 isolation probe (`witness/boot.sh`'s probe loop) fails | The kernel did not fault, kill, and reap the offending process, or a sibling process died with it | Read the specific `FAIL isolation[...]` message — it names which of fault/kill/reap/survive broke |

For anything not covered above: every failure path in the witness scripts
prints a named `FAIL: ...` message (never a bare non-zero exit) — that
message is the starting point, not the exit code alone.

## Credential rotation

No user-facing or service credential exists here; the nearest analog is
the boot-image signing key. `crates/thumos/build.rs` embeds one Ed25519
public key (the boot trust anchor) into every image. The committed dev
keypair (`crates/thumos/keys/dev/`) is deliberately public — anyone can
build and sign a dev image — and no production key is ever committed
(`crates/thumos/keys/.gitignore` blocks it). Rotating to a production key means building
with `--features production` and `THUMOS_BOOT_KEY_PUB=<file>` naming a key
provisioned by offline signing infrastructure; the build refuses to
proceed without it, refuses the dev key, and refuses RFC 8032's published
test-vector keys (their private halves are public, so they cannot
establish trust). Full detail: `docs/KERNEL-BUILD.md` § Signing and
attestation boundary.

## Database inspection

Not applicable. thumos has no external database. The kernel's own
persistent storage (log-structured filesystem, encrypted userdata volume)
is in-kernel state on the target device, not an operable service
component, and is unreachable from this runbook until the hardware path
below is proven.

## Backup/restore

Not applicable in the OPERATIONS.md sense (no deployed data store to back
up). The closest analog — recovering a broken build or a bad commit — is
ordinary git: `git bisect` against `main`, or re-run the exact CI job
(`kernel`, `workspace`, or `fmt` in `.github/workflows/ci.yml`) locally via
its scripted steps above.

## Performance debugging

- **Kernel boot/runtime.** The QEMU witness logs are the only signal
  available pre-hardware; there is no profiler attached to the emulated
  target today. Use the GDB workflow below to inspect state at a specific
  point rather than guessing from log timing.
- **Workspace library code (host).** `benches/` holds Criterion
  benchmarks for the codec paths every SMS PDU runs through
  (`klesis-core`'s GSM-7 and BCD-address encode/decode) — run with
  `cargo bench -p klesis-core`. `cargo clippy --workspace --all-targets`
  already compiles these on every PR, so a benchmark that stops compiling
  is caught immediately even though the timing run itself is not part of
  CI (benchmark timing on shared CI runners is noise, not signal — see
  `TESTING.md` § Benchmarks).

GDB attach (kernel, under QEMU):

```bash
THUMOS_QEMU_GDB=1 scripts/qemu-runner.sh target/armv7a-none-eabi/release/thumos &
scripts/gdb-thumos.sh target/armv7a-none-eabi/release/thumos
```

Drops into a live GDB session with symbols loaded, breakpointed at
`kinit::run`, against the same boot path the witnesses use — no kernel
code changes required. Details and port override: `scripts/README.md`.

## Escalation

No on-call rotation exists for a public open-source kernel project.
Escalation is a GitHub issue on `forkwright/thumos`, same as the standard
"if a command here drifts, file an issue" convention this repo already
follows (`docs/KERNEL-BUILD.md`). For a red required CI check, the job's
own log is authoritative over any local reproduction.

## Hardware bring-up status

Everything above proves the kernel **under QEMU `-machine virt` only**.
The Rust kernel has never booted on the physical AGM M7 / MT6739, and the
repository produces no flashable device package today — no Android boot
image, no scatter-file integration. There is nothing to flash, and no
hardware brick-recovery procedure exists because nothing has been flashed
to a device from this repository. Do not treat any command on this page as
proven beyond the emulator. Full detail, including what the `qemu` feature
deliberately does not model: `docs/KERNEL-BUILD.md` § Hardware path:
unproven.
