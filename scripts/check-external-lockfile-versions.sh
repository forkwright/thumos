#!/usr/bin/env bash
set -euo pipefail

# check-external-lockfile-versions.sh <path/to/Cargo.lock> — a Cargo.lock
# outside the root workspace (its own standalone resolution root) must both
# resolve cleanly against its manifest AND carry the current workspace
# version on every first-party (no-`source`) entry, itself included.
#
# WHY two checks, not one: `cargo metadata --locked` catches drift `cargo`
# itself would otherwise silently repair (a manifest and lock that disagree
# on structure/deps) but says nothing about STALENESS — a lock that resolves
# fine against its own manifest can still pin a first-party crate several
# releases behind because nothing ever regenerated it. The version scan below
# is what catches that.
#
# WHY generic over the lockfile path rather than one script per lockfile:
# crates/thumos/Cargo.lock was the first standalone lockfile release-please
# had to cover (#629/#650/#688/#757) — its selector once named crates one at
# a time, missed additions by construction, and #650 replaced the enumeration
# with a `$.package[?(!@.source)].version` predicate. fuzz/Cargo.lock is a
# SECOND standalone lockfile that carried the exact enumerated-name mistake
# independently (#768) — the shared shape is what makes this a script
# parameter rather than a second hand copy the next time a standalone
# lockfile shows up.
#
# WHY no per-lockfile self-package exclusion: each such manifest
# (crates/thumos/Cargo.toml, fuzz/Cargo.toml) carries its OWN
# `$.package.version` extra-files entry, so its self-package version already
# equals the workspace version by the time this check runs — there is
# nothing to exempt. An earlier version of the kernel selector tried to
# exclude `thumos` by name (`@.name != 'thumos'`) instead of tracking its
# manifest directly; that exclusion never worked (release-please's TOML
# JSONPath does not evaluate `@.name` string equality/inequality against
# `[[package]]` array entries — see the note in CONTRIBUTING.md's Releases
# section, upstream: googleapis/release-please#2455) and stayed silently
# harmless only because the excluded value coincidentally matched anyway.
# #768 replaces that exclusion with the same direct-tracking fix rather than
# repeating the broken pattern for fuzz/Cargo.toml's `peirama`.

REPO_ROOT=$(git rev-parse --show-toplevel)
LOCKFILE_REL="${1:?usage: check-external-lockfile-versions.sh <path/to/Cargo.lock>}"
LOCKFILE="$REPO_ROOT/$LOCKFILE_REL"
LOCK_DIR=$(dirname "$LOCKFILE")

[[ -f "$LOCKFILE" ]] || {
    echo "LOCKFILE DRIFT: $LOCKFILE_REL does not exist" >&2
    exit 1
}

echo "== $LOCKFILE_REL: resolves against its manifest (--locked) =="
if ! (cd "$LOCK_DIR" && cargo metadata --locked --format-version=1 >/dev/null); then
    echo "LOCKFILE DRIFT: $LOCKFILE_REL disagrees with its manifest — cargo would silently rewrite it without --locked" >&2
    exit 1
fi

echo "== $LOCKFILE_REL: first-party crate versions =="
python3 - "$REPO_ROOT" "$LOCKFILE_REL" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
lockfile_rel = sys.argv[2]

ws = re.search(
    r'^\[workspace\.package\][^\[]*?^version\s*=\s*"([^"]+)"',
    (root / "Cargo.toml").read_text(),
    re.M | re.S,
)
if not ws:
    print("LOCKFILE DRIFT: cannot read workspace.package.version", file=sys.stderr)
    sys.exit(1)
want = ws.group(1)

lock = (root / lockfile_rel).read_text()

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
    checked += 1
    if ver.group(1) != want:
        print(
            f"LOCKFILE DRIFT: {lockfile_rel} pins {name.group(1)} at "
            f"{ver.group(1)}, workspace is {want} — release-please's selector for "
            f"this file is not covering it (see #768)",
            file=sys.stderr,
        )
        rc = 1

if checked == 0:
    print(
        f"LOCKFILE DRIFT: no first-party crates found in {lockfile_rel} — "
        "the check matched nothing, which is not the same as passing",
        file=sys.stderr,
    )
    rc = 1

if rc == 0:
    print(f"{lockfile_rel}: {checked} first-party crates all at {want}")
sys.exit(rc)
PYEOF
