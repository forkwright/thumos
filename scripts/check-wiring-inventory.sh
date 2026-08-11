#!/usr/bin/env bash
set -euo pipefail

# check-wiring-inventory.sh [boot.log] — capability-reachability drift check
# (#550). Fails when:
#   (a) a main.rs module is not classified in docs/capability-inventory.toml
#   (b) an inventory witness marker is absent from scripts/witness/*.sh
#       (the witness is claimed but nothing asserts it), or
#   (c) a witness marker is absent from the QEMU boot log (default ./boot.log;
#       pass --no-log to skip (c) when no boot has run yet)
# The inventory is the SSOT for capability reachability; README's capability
# section and docs/KERNEL-WIRING-AUDIT.md's successor point at it.

REPO_ROOT=$(git rev-parse --show-toplevel)
INV="$REPO_ROOT/docs/capability-inventory.toml"
MAIN="$REPO_ROOT/crates/thumos/src/main.rs"
WITNESS_DIR="$REPO_ROOT/scripts/witness"
LOG=""
[[ "${1:-}" == "--no-log" ]] && shift || LOG="${1:-$REPO_ROOT/boot.log}"

python3 - "$INV" "$MAIN" "$WITNESS_DIR" "$LOG" <<'PYEOF'
import re, sys, tomllib, glob, os

inv_path, main_path, wit_dir, log_path = sys.argv[1:5]
inv = tomllib.load(open(inv_path, "rb"))
caps = inv.get("capability", [])

rc = 0
def fail(msg):
    global rc
    print(f"INVENTORY DRIFT: {msg}", file=sys.stderr)
    rc = 1

# (a) every main.rs module classified
mods = set(re.findall(r'^(?:pub )?mod ([a-z_0-9]+);', open(main_path).read(), re.M))
classified = {}
for c in caps:
    for m in c.get("modules", []):
        if m in classified:
            fail(f"module '{m}' classified twice ({classified[m]} and {c['id']})")
        classified[m] = c["id"]
for m in sorted(mods):
    if m not in classified:
        fail(f"main.rs module '{m}' has no [[capability]] entry")
for m in sorted(classified):
    if m not in mods:
        fail(f"inventory lists module '{m}' (capability {classified[m]}) that no longer exists in main.rs")

# (b) witness markers exist in the witness scripts
scripts_text = ""
for f in glob.glob(os.path.join(wit_dir, "*.sh")):
    scripts_text += open(f, errors="ignore").read()
markers = []
for c in caps:
    for w in c.get("witness", []):
        markers.append((c["id"], w))
        if w not in scripts_text:
            fail(f"witness '{w}' (capability {c['id']}) is not asserted by any script in scripts/witness/")

# (c) witness markers fired in the boot logs (when provided). boot.sh
# produces boot.log (main boot) plus probe-*.log (the four PL0 isolation
# probes); both are boot.sh outputs, so markers may live in either.
if log_path:
    if not os.path.exists(log_path):
        fail(f"boot log not found at {log_path} — run scripts/witness/boot.sh first (or pass --no-log)")
    else:
        log = open(log_path, errors="ignore").read()
        for probe in glob.glob(os.path.join(os.path.dirname(log_path) or ".", "probe-*.log")):
            log += open(probe, errors="ignore").read()
        for cid, w in markers:
            # markers carry assertion-regex fragments; match literally except
            # the trailing value patterns (>=, numbers) which are regex-friendly
            if w not in log:
                fail(f"witness '{w}' (capability {cid}) did not fire in the boot log")

if rc == 0:
    print(f"wiring inventory: {len(mods)} modules classified in {len(caps)} capabilities, {len(markers)} witness markers verified")
sys.exit(rc)
PYEOF
