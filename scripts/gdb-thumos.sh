#!/usr/bin/env bash
set -euo pipefail

# GDB attach helper for the thumos kernel under QEMU.
#
# Purpose: pairs with scripts/qemu-runner.sh's THUMOS_QEMU_GDB=1 opt-in --
# that flag halts QEMU with a GDB stub listening on a TCP port instead of
# free-running; this script attaches a GDB (with ARM symbols) to that port
# and sets a breakpoint at kernel entry.
#
# Usage:
#   THUMOS_QEMU_GDB=1 scripts/qemu-runner.sh <kernel-elf> &
#   scripts/gdb-thumos.sh <kernel-elf> [port]
#
# Requirements:
#   - gdb-multiarch (preferred) or arm-none-eabi-gdb. If neither is on PATH,
#     the script prints an install diagnostic and exits 127.

ELF="${1:-}"
if [[ -z "${ELF}" ]]; then
  echo "gdb-thumos: usage: $0 <kernel-elf> [port]" >&2
  exit 64
fi

PORT="${2:-${THUMOS_QEMU_GDB_PORT:-1234}}"

if [[ ! -f "${ELF}" ]]; then
  echo "gdb-thumos: ELF not found: ${ELF}" >&2
  exit 66
fi

GDB_BIN=""
if command -v gdb-multiarch >/dev/null 2>&1; then
  GDB_BIN="gdb-multiarch"
elif command -v arm-none-eabi-gdb >/dev/null 2>&1; then
  GDB_BIN="arm-none-eabi-gdb"
else
  cat >&2 <<'EOF'
gdb-thumos: no ARM-capable gdb found on PATH (tried gdb-multiarch,
arm-none-eabi-gdb).

Install on Fedora:
  sudo dnf install gdb-multiarch

Install on Debian/Ubuntu:
  sudo apt-get install gdb-multiarch
EOF
  exit 127
fi

exec "${GDB_BIN}" "${ELF}" \
  -ex "target remote :${PORT}" \
  -ex "break kinit::run" \
  -ex "echo ...attached..."
