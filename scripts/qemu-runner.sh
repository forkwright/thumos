#!/usr/bin/env bash
set -euo pipefail

# QEMU test runner for thumos kernel binaries.
#
# Purpose: given a bare-metal ARM binary built for armv7a-none-eabi, boot
# it under `qemu-system-arm -machine virt` as the kernel image, pipe
# serial output to the host, and translate the QEMU exit code back to
# the caller.
#
# This is wired in via .cargo/config.toml as the target runner for
# armv7a-none-eabi, so `cargo test` (and `cargo run`) invocations on the
# kernel crate dispatch each test binary through this script.
#
# Exit semantics:
#   - The kernel is expected to trigger a QEMU shutdown via the ARM
#     `semihosting` SYS_EXIT call (via the `semihosting` crate) to
#     communicate pass/fail back to QEMU.
#   - QEMU exit code 0  -> tests passed.
#   - QEMU exit code 1  -> tests failed (panic or explicit non-zero exit).
#   - Anything else     -> runner/infra failure.
#
# Requirements:
#   - qemu-system-arm (Fedora package: qemu-system-arm). If missing, the
#     script prints a diagnostic and exits 127 so CI reports a clear
#     infra failure rather than a silent false pass.
#
# Install on menos (Fedora 43):
#   sudo dnf install qemu-system-arm

BINARY="${1:-}"
if [[ -z "${BINARY}" ]]; then
  echo "qemu-runner: usage: $0 <binary> [extra qemu args...]" >&2
  exit 64
fi
shift || true  # WHY: only the binary argument is valid input, no-op shift is not an error.

if [[ ! -f "${BINARY}" ]]; then
  echo "qemu-runner: binary not found: ${BINARY}" >&2
  exit 66
fi

if ! command -v qemu-system-arm >/dev/null 2>&1; then
  cat >&2 <<'EOF'
qemu-runner: qemu-system-arm not found on PATH.

Install on Fedora:
  sudo dnf install qemu-system-arm

Install on Debian/Ubuntu:
  sudo apt-get install qemu-system-arm

Install on macOS (brew):
  brew install qemu

Skipping kernel test execution.
EOF
  # WHY: exit 127 is the conventional "command not found" status; CI and
  # cargo both surface this as a clear infra failure rather than a test
  # regression.
  exit 127
fi

# -machine virt  : generic ARM virtual platform with PL011 UART at 0x09000000,
#                  GICv2 at 0x08000000/0x08010000, RAM at 0x40000000. The
#                  kernel link script (link.ld) loads .text at 0x40008000,
#                  inside that RAM window.
# -m 1024M       : match kconfig::RAM_END (RAM_START + 1 GB) so the page
#                  allocator's whole range is backed by real RAM -- a frame
#                  handed out beyond the emulated RAM size would data-abort
#                  on first touch.
# -cpu cortex-a7 : matches thumos target CPU (MT6739 is quad Cortex-A53 but
#                  the kernel is built for armv7a-none-eabi, so we pick a
#                  compatible v7-A core QEMU supports in 32-bit mode).
# -nographic     : no GUI; serial + monitor on stdio.
# -semihosting   : enables the ARM semihosting ABI so the test binary can
#                  call SYS_EXIT and write diagnostics. native + on exit
#                  means the guest-side exit code reaches the QEMU exit code.
# -kernel        : load the raw ELF and jump to its entry point.
#
# NOTE: timeout guards against a hung kernel (infinite loop in test setup).
# 60s is generous for the tiny PoC smoke test; tune upward as the kernel
# test harness grows.
TIMEOUT_SECS="${THUMOS_QEMU_TIMEOUT:-60}"

# WHY (#532): THUMOS_QEMU_GDB=1 halts QEMU waiting for a debugger instead of
# free-running — scripts/gdb-thumos.sh attaches to this port. Unset/0
# (the default) leaves every existing invocation, including CI, unchanged.
GDB_ARGS=()
if [[ "${THUMOS_QEMU_GDB:-0}" == "1" ]]; then
  GDB_PORT="${THUMOS_QEMU_GDB_PORT:-1234}"
  GDB_ARGS=(-gdb "tcp::${GDB_PORT}" -S)
fi

exec timeout --kill-after=5 "${TIMEOUT_SECS}" \
  qemu-system-arm \
    -machine virt \
    -cpu cortex-a7 \
    -m 1024M \
    -nographic \
    -semihosting-config enable=on,target=native \
    -kernel "${BINARY}" \
    "${GDB_ARGS[@]}" \
    "$@"
