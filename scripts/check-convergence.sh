#!/usr/bin/env bash
set -euo pipefail

# check-convergence.sh — the #545 convergence ratchet. Fails when:
#   (a) a [[pair]] row lacks disposition/canonical/owner, or names a file
#       that no longer exists;
#   (b) a live "ported from" comment names a crate pair with no ledger row;
#   (c) the port-marker or stale-expectation counts INCREASE over the
#       recorded ratchet values (convergence only ever burns down);
#   (d) any lib.rs still points at closed #126 (the pointer must be the
#       live ledger, not a closed issue).

REPO_ROOT=$(git rev-parse --show-toplevel)
LEDGER="$REPO_ROOT/docs/convergence.toml"

python3 - "$LEDGER" "$REPO_ROOT" <<'PYEOF'
import re, sys, tomllib, glob, os

ledger_path, root = sys.argv[1], sys.argv[2]
try:
    doc = tomllib.load(open(ledger_path, "rb"))
except Exception as e:
    print(f"CONVERGENCE DRIFT: docs/convergence.toml is not parseable TOML: {e}", file=sys.stderr)
    sys.exit(1)

pairs = doc.get("pair", [])
ratchet = doc.get("ratchet", {})
rc = 0

def fail(msg):
    global rc
    print(f"CONVERGENCE DRIFT: {msg}", file=sys.stderr)
    rc = 1

# (a) row completeness + file existence.
names = set()
for p in pairs:
    name = p.get("name")
    if not name:
        fail(f"a [[pair]] row has no name: {p}")
        continue
    if name in names:
        fail(f"duplicate pair '{name}'")
    names.add(name)
    for key in ("kernel", "workspace", "disposition", "canonical", "owner"):
        if not p.get(key):
            fail(f"pair '{name}' missing '{key}'")
    if p.get("disposition") not in ("converged", "extract-core", "kernel-owned", "workspace-owned"):
        fail(f"pair '{name}' has invalid disposition '{p.get('disposition')}'")
    for side in ("kernel", "workspace"):
        ref = p.get(side, "")
        for m in re.finditer(r'([a-z0-9_]+\.rs)', ref):
            if not glob.glob(os.path.join(root, "crates", "*", "src", m.group(1))):
                fail(f"pair '{name}' {side} references missing file {m.group(1)}")

# (b) every live "ported from" comment must name a crate the ledger covers.
covered = set()
for p in pairs:
    for m in re.finditer(r'`?([a-z]+(?:-[a-z]+)?)`?(?:\s|$|,|\.|/)', p.get("workspace", "")):
        covered.add(m.group(1))
    covered.add(p.get("workspace", "").split(",")[0].strip())
live_ports = []
for f in glob.glob(os.path.join(root, "crates", "*", "src", "*.rs")):
    for i, line in enumerate(open(f, errors="ignore"), 1):
        m = re.search(r'(?<![a-z])ported from `?(?:crates/)?([a-z-]+)', line)
        if m:
            live_ports.append((f, i, m.group(1)))
            if not any(m.group(1) in p.get("workspace", "") for p in pairs):
                fail(f"{os.path.relpath(f, root)}:{i} 'ported from {m.group(1)}' has no ledger row")

# (c) the ratchet: counts may only decrease.
if len(live_ports) > ratchet.get("ported_from_comments", 0):
    fail(f"'ported from' comments increased: {len(live_ports)} > ratchet {ratchet.get('ported_from_comments')} (convergence only burns down)")

stale = 0
for f in glob.glob(os.path.join(root, "crates", "*", "src", "lib.rs")):
    text = open(f, errors="ignore").read()
    stale += text.count("public API surface for future kernel binary integration (#126)")
if stale > ratchet.get("stale_126_expectations", 0):
    fail(f"stale #126 expectations increased: {stale} > ratchet {ratchet.get('stale_126_expectations')}")

# (e) a declared *-core dependency must actually be consumed in source.
#
# WHY: an extraction that creates the core crate, wires ONE consumer, and adds
# the dependency to the other without ever importing it looks converged at
# every level this script previously checked — the ledger row exists, the
# port-marker count did not rise, and both sides compile. It is not
# convergence; it is a third copy plus an unused dependency. #661 landed in
# exactly that state: `asphaleia-core` was created and consumed by
# `crates/asphaleia`, while `crates/thumos/src/firewall.rs` kept its own
# blocklist and parser and merely gained a dependency it never named.
#
# The unused dependency is the reliable tell, so it is what this checks.
for cargo in glob.glob(os.path.join(root, "crates", "*", "Cargo.toml")):
    crate_dir = os.path.dirname(cargo)
    crate_name = os.path.basename(crate_dir)
    try:
        manifest = tomllib.load(open(cargo, "rb"))
    except Exception as e:
        fail(f"{os.path.relpath(cargo, root)} is not parseable TOML: {e}")
        continue
    deps = manifest.get("dependencies", {})
    # Only OUR extractions: a `-core` crate in this repo, declared by path.
    # A third-party dependency that happens to end in `-core`
    # (embedded-graphics-core) is not an extraction and firing on it would
    # teach a reader to skip this check.
    core_deps = [
        d
        for d, spec in deps.items()
        if d.endswith("-core") and isinstance(spec, dict) and "path" in spec
    ]
    if not core_deps:
        continue
    sources = glob.glob(os.path.join(crate_dir, "src", "**", "*.rs"), recursive=True)
    text = "".join(open(f, errors="ignore").read() for f in sources)
    for dep in core_deps:
        # Rust refers to a hyphenated crate by its underscored name.
        if dep.replace("-", "_") not in text:
            fail(
                f"crate '{crate_name}' declares dependency '{dep}' but no source file "
                f"references it — an extraction wired only one side, so the duplicate "
                f"it was meant to remove is still live (#545)"
            )

# (d) no lib.rs may point at closed #126 at all going forward (the pointer
# is the ledger now).
for f in glob.glob(os.path.join(root, "crates", "*", "src", "lib.rs")):
    text = open(f, errors="ignore").read()
    if "#126" in text:
        fail(f"{os.path.relpath(f, root)} still references closed #126 — point at docs/convergence.toml (#545)")

if rc == 0:
    print(f"convergence ledger: {len(pairs)} pairs classified, {len(live_ports)} port markers, 0 stale #126 pointers, ratchet holding")
sys.exit(rc)
PYEOF
