#!/usr/bin/env bash
# check-target-test-ledger.sh — declared-vs-executed audit for the kernel's
# test obligations (#551, restoring #124). Fails when:
#   (a) a module with #[test]s or target-sensitive patterns has no ledger row
#   (b) a 'both'/'target' row names a witness script that does not exist
#   (c) a target-sensitive host-only row carries no fidelity note
#   (d) a row's tests count drifts from the source tree
# Ledger: docs/target-test-ledger.toml. #528/#533 are the proof-by-incident:
# host fixtures green while real-table behavior was broken on every boot.
set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
LEDGER="$REPO_ROOT/docs/target-test-ledger.toml"
SRC="$REPO_ROOT/crates/thumos/src"
WITNESS_DIR="$REPO_ROOT/scripts/witness"

python3 - "$LEDGER" "$SRC" "$WITNESS_DIR" <<'PYEOF'
import re, sys, tomllib, glob, os

ledger_path, src_dir, wit_dir = sys.argv[1:4]
try:
    rows = tomllib.load(open(ledger_path, "rb")).get("module", [])
except Exception as e:
    print(f"LEDGER DRIFT: docs/target-test-ledger.toml is not parseable TOML: {e}", file=sys.stderr)
    sys.exit(1)
by_name = {}
for r in rows:
    n = r.get("name")
    if not n:
        print(f"LEDGER DRIFT: a [[module]] row has no name key: {r}", file=sys.stderr)
        sys.exit(1)
    by_name[n] = r
if len(by_name) != len(rows):
    print("LEDGER DRIFT: duplicate module rows in the ledger", file=sys.stderr); sys.exit(1)

rc = 0
def fail(msg):
    global rc
    print(f"LEDGER DRIFT: {msg}", file=sys.stderr)
    rc = 1

TARGET_PAT = re.compile(r'asm!|core::arch|global_asm|0x[0-9A-Fa-f]{6,}|read_volatile|write_volatile|page_table|l1_section|l2_entry|ttbr|cp15', re.I)

witness_files = {os.path.basename(f) for f in glob.glob(os.path.join(wit_dir, "*.sh"))}

for f in sorted(glob.glob(os.path.join(src_dir, "**", "*.rs"), recursive=True)):
    rel = os.path.relpath(f, src_dir)[:-3]
    m = rel[:-4] if rel.endswith("/mod") else rel  # board/mod.rs -> "board"
    text = open(f, errors="ignore").read()
    tests = len(re.findall(r'#\[test\]', text))
    sensitive = bool(TARGET_PAT.search(text))
    row = by_name.get(m)
    if (tests or sensitive) and row is None:
        fail(f"module '{m}' (tests={tests}, target-sensitive={sensitive}) has no ledger row")
        continue
    if row is None:
        continue
    if row.get("tests", -1) != tests:
        fail(f"module '{m}': ledger says {row.get('tests')} tests, source has {tests}")
    mech = row.get("mechanism", "")
    if mech in ("both", "target"):
        wits = row.get("witness", "")
        named = re.split(r'[+]', wits)
        if not wits or any(w.strip() not in witness_files for w in named if w.strip()):
            fail(f"module '{m}' mechanism={mech} but witness '{wits}' names scripts not in scripts/witness/")
    if mech == "host" and sensitive and not row.get("fidelity"):
        fail(f"module '{m}' is host-only with target-sensitive patterns but carries no fidelity note")

for m in by_name:
    if not (os.path.exists(os.path.join(src_dir, m + ".rs"))
            or os.path.exists(os.path.join(src_dir, m, "mod.rs"))):
        fail(f"ledger row '{m}' has no source file")

if rc == 0:
    n_both = sum(1 for r in rows if r.get("mechanism") == "both")
    n_target = sum(1 for r in rows if r.get("mechanism") == "target")
    print(f"target-test ledger: {len(rows)} rows checked, {n_both} both-mechanism, {n_target} target-only, no drift")
sys.exit(rc)
PYEOF
