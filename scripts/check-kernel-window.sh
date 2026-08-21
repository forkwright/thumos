#!/usr/bin/env bash
set -euo pipefail

# check-kernel-window.sh — the kernel image window, enforced rather than
# remembered (#917).
#
# The window is [board::RAM_START, board::KERNEL_END), defined once in
# board/mod.rs as KERNEL_LOAD + KERNEL_RESERVED. build.rs derives the linker's
# copy from it into $OUT_DIR/kernel_window.ld, which link.ld INCLUDEs -- so the
# two cannot disagree by construction.
#
# What this guards is that SHAPE, not the value: it fails if link.ld assigns
# __kernel_end itself, which would silently take precedence over the derived
# fragment and reintroduce a second copy. That copy drifts in a direction whose
# failure is invisible -- a larger bound accepts an image extending past the
# last L1 section mmu maps, and the first report on device is a data abort, not
# a build error.
#
# It also reports the remaining headroom whenever a release ELF is present,
# because the linker's ASSERT is a cliff with no approach: it says nothing at
# 99% and fails the build at 101%. That is how #917 was found -- a dependency
# the operator had already decided on turned out not to fit, and the only
# signal was a link error at the end of CI that read like a misconfiguration.
#
# The headroom half reports whatever the LAST release build produced -- it reads
# the ELF, not the source, and cannot tell a fresh one from a stale one. CI runs
# it immediately after scripts/kernel-build.sh so the two always agree there;
# run locally against an old target/ it will happily describe a tree you no
# longer have.
#
# Usage: check-kernel-window.sh          # drift check, plus headroom if built
#        MIN_HEADROOM=131072 check-...   # raise the floor

REPO_ROOT=$(git rev-parse --show-toplevel)
BOARD="$REPO_ROOT/crates/thumos/src/board/mod.rs"
LINK_LD="$REPO_ROOT/crates/thumos/link.ld"
ELF="$REPO_ROOT/crates/thumos/target/armv7a-none-eabi/release/thumos"

python3 - "$BOARD" "$LINK_LD" "$ELF" "${MIN_HEADROOM:-65536}" <<'PYEOF'
import re, subprocess, sys, os

board_path, link_path, elf_path, min_headroom = sys.argv[1:5]
min_headroom = int(min_headroom)

rc = 0
def fail(msg):
    global rc
    print(f"KERNEL WINDOW DRIFT: {msg}", file=sys.stderr)
    rc = 1

board = open(board_path).read()

def rust_const(name):
    m = re.search(rf'const {name}: usize = (0x[0-9A-Fa-f_]+);', board)
    if not m:
        fail(f"{name} not found in board/mod.rs -- this check cannot see the window it guards")
        return None
    return int(m.group(1).replace("_", ""), 16)

ram_start = rust_const("RAM_START")
kernel_load = rust_const("KERNEL_LOAD")
kernel_reserved = rust_const("KERNEL_RESERVED")
if None in (ram_start, kernel_load, kernel_reserved):
    sys.exit(1)

kernel_end = kernel_load + kernel_reserved
SECTION = 1 << 20

link_src = open(link_path).read()
if re.search(r'^\s*__kernel_end\s*=', link_src, re.M):
    fail(
        "link.ld assigns __kernel_end itself. build.rs derives that symbol from "
        "board::KERNEL_LOAD + KERNEL_RESERVED, and a literal here overrides the derived "
        "value -- which is the second copy this arrangement exists to remove. Delete the "
        "assignment; the INCLUDE supplies it."
    )
if "INCLUDE kernel_window.ld" not in link_src:
    fail(
        "link.ld does not INCLUDE kernel_window.ld, so __kernel_end is undefined and the "
        "image-size ASSERT has no bound to compare against"
    )

span = kernel_end - ram_start
if span % SECTION:
    fail(
        f"the window [{ram_start:#x}, {kernel_end:#x}) is {span} bytes, not a whole number of "
        f"1 MB sections -- coarse L2 tables cannot map the remainder, so the top "
        f"{span % SECTION} bytes would be unmapped rather than rejected"
    )

sections = span // SECTION
if rc == 0:
    print(f"kernel window: [{ram_start:#x}, {kernel_end:#x}) = {sections} section(s), "
          f"link.ld derives its bound")

# --- headroom, when something has been built -------------------------------
if not os.path.exists(elf_path):
    if rc == 0:
        print("kernel window: no release ELF yet -- headroom not measured "
              "(build with scripts/kernel-build.sh to include it)")
    sys.exit(rc)

try:
    out = subprocess.run(["nm", elf_path], capture_output=True, text=True, check=True).stdout
except (OSError, subprocess.CalledProcessError) as e:
    print(f"kernel window: nm unavailable ({e}) -- headroom not measured", file=sys.stderr)
    sys.exit(rc)

m = re.search(r'^([0-9a-fA-F]+)\s+\S+\s+__svc_stack_top$', out, re.M)
if not m:
    fail("__svc_stack_top absent from the ELF -- cannot measure headroom, and that symbol "
         "is what link.ld's ASSERT bounds")
    sys.exit(rc)

top = int(m.group(1), 16)
headroom = kernel_end - top
used = top - ram_start
pct = 100.0 * used / span
print(f"kernel window: image + stacks end at {top:#x}, {used} of {span} bytes used "
      f"({pct:.1f}%), {headroom} bytes free")

if headroom < 0:
    fail(f"image + stacks overrun the window by {-headroom} bytes")
elif headroom < min_headroom:
    fail(
        f"only {headroom} bytes of window left, below the {min_headroom}-byte floor. "
        f"Raise board::KERNEL_RESERVED and link.ld's __kernel_end together by whole "
        f"megabytes (mmu::KERNEL_SECTIONS derives the table count), or reclaim space -- "
        f"nm --size-sort names the largest symbols"
    )

sys.exit(rc)
PYEOF
