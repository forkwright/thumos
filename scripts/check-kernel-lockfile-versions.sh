#!/usr/bin/env bash
# check-kernel-lockfile-versions.sh — the kernel lockfile's first-party crates
# must carry the workspace version.
#
# WHY this exists rather than trusting the release config: crates/thumos is
# excluded from the workspace and keeps its own lockfile so the bare-metal
# dependency graph is reproducible on its own. release-please updates that file
# through an explicit selector, and the selector previously named ONE crate
# literally while the root lockfile used a predicate. Four core crates were
# added without anyone extending the list, so six versions sat three releases
# behind and cargo silently rewrote the file on every build — a lockfile the
# build edits underfoot pins nothing. #650 and #629 each fixed an instance of
# this; the enumeration is what let it return.
#
# An enumeration of things that grow goes stale silently. This check is what
# makes the staleness loud.
#
# WHY `thumos` is exempt: its 0.1.0 in crates/thumos/Cargo.toml is its own
# version, deliberately not workspace-inherited, so it must NOT track releases.
set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)

python3 - "$REPO_ROOT" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])

ws = re.search(
    r'^\[workspace\.package\][^\[]*?^version\s*=\s*"([^"]+)"',
    (root / "Cargo.toml").read_text(),
    re.M | re.S,
)
if not ws:
    print("LOCKFILE DRIFT: cannot read workspace.package.version", file=sys.stderr)
    sys.exit(1)
want = ws.group(1)

lock = (root / "crates" / "thumos" / "Cargo.lock").read_text()

# A first-party crate is one with no `source` line in its [[package]] block.
rc = 0
checked = 0
for block in lock.split("[[package]]")[1:]:
    name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
    ver = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
    if not name or not ver:
        continue
    if re.search(r"^source\s*=", block, re.M):
        continue
    if name.group(1) == "thumos":
        continue
    checked += 1
    if ver.group(1) != want:
        print(
            f"LOCKFILE DRIFT: crates/thumos/Cargo.lock pins {name.group(1)} at "
            f"{ver.group(1)}, workspace is {want} — release-please's selector for "
            f"this file is not covering it (see #688)",
            file=sys.stderr,
        )
        rc = 1

if checked == 0:
    print(
        "LOCKFILE DRIFT: no first-party crates found in crates/thumos/Cargo.lock — "
        "the check matched nothing, which is not the same as passing",
        file=sys.stderr,
    )
    rc = 1

if rc == 0:
    print(f"kernel lockfile: {checked} first-party crates all at {want}")
sys.exit(rc)
PYEOF
