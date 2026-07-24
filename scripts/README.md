# scripts

Supporting scripts for thumos development.

## qemu-runner.sh

QEMU test runner for the thumos kernel crate (`crates/thumos/`).

Wired in via `crates/thumos/.cargo/config.toml`:

```toml
[target.armv7a-none-eabi]
runner = "../../scripts/qemu-runner.sh"
```

This means every `cargo run` or `cargo test` invocation inside `crates/thumos/`
dispatches each built binary through the runner. The runner boots it under
`qemu-system-arm -machine virt` with ARM semihosting enabled, forwards the
semihosting exit code back to the caller, and applies a 60-second watchdog
timeout (override via `THUMOS_QEMU_TIMEOUT`).

### Requirements

- `qemu-system-arm`. If missing, the runner prints an install diagnostic and
  exits `127`. CI and `cargo test` then report an infra failure instead of a
  silent false pass.

```bash
# Fedora
sudo dnf install qemu-system-arm

# Debian/Ubuntu
sudo apt-get install qemu-system-arm

# macOS
brew install qemu
```

### Exit codes

| Code | Meaning                                                       |
|------|---------------------------------------------------------------|
| 0    | Guest called semihosting `SYS_EXIT` with status `0` (passed). |
| 1    | Guest panicked or exited with a non-zero status (failed).     |
| 64   | Runner called without a binary argument.                      |
| 66   | Binary path does not exist.                                   |
| 124  | `timeout` killed a hung guest.                                |
| 127  | `qemu-system-arm` not installed.                              |

### Proof-of-concept

`crates/thumos/examples/qemu_smoke.rs` is a self-contained `no_std` / `no_main`
binary that:

1. Runs the ARM boot stub (stack + BSS zero) identical to the kernel.
2. Writes `"qemu_smoke: pass\n"` to the PL011 UART at `0x09000000` (the virt
   board's UART0).
3. Issues ARM semihosting `SYS_EXIT` with status `0` via `bkpt 0xAB`.

Invocation (from the repo root):

```bash
cd crates/thumos
cargo run --example qemu_smoke --release
# Expected:
#   qemu_smoke: pass
#   <qemu exits, cargo reports success>
```

The example deliberately has no dependency on the kernel runtime (kinit, GIC,
MMU). Once it is green, the follow-up is to convert the kernel crate's
`#[cfg(test)]` unit tests to a `custom_test_frameworks` test runner that
dispatches through this same script. That conversion touches every kernel
module and is tracked in issue #124 (follow-up to #117).

## gdb-thumos.sh

GDB attach helper for the thumos kernel under QEMU (#532).

`qemu-runner.sh` free-runs the guest by default; setting `THUMOS_QEMU_GDB=1`
switches it to boot with a GDB stub instead, halted until a debugger attaches:

```bash
THUMOS_QEMU_GDB=1 scripts/qemu-runner.sh target/armv7a-none-eabi/release/thumos &
scripts/gdb-thumos.sh target/armv7a-none-eabi/release/thumos
```

`gdb-thumos.sh` connects to that stub with symbols loaded from the given ELF,
sets a breakpoint at `kinit::run`, and drops into an interactive GDB session.
Override the port with `THUMOS_QEMU_GDB_PORT` (both scripts read the same
variable; default `1234`) or a second positional argument.

### Requirements

- `gdb-multiarch` (preferred) or `arm-none-eabi-gdb`. If neither is on PATH,
  the script prints an install diagnostic and exits `127`.

```bash
# Fedora
sudo dnf install gdb-multiarch

# Debian/Ubuntu
sudo apt-get install gdb-multiarch
```

### Exit codes

| Code | Meaning                                  |
|------|-------------------------------------------|
| 64   | Script called without an ELF argument.     |
| 66   | ELF path does not exist.                   |
| 127  | No ARM-capable gdb installed.              |
