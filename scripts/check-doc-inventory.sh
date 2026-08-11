#!/usr/bin/env bash
set -euo pipefail

# check-doc-inventory.sh — crate-roster and docs/ manifest drift check.
# Fails when:
#   (a) the crate roster derived from Cargo.toml [workspace] members (plus
#       the excluded kernel crate) disagrees with ARCHITECTURE.md's crate
#       map table, or with _llm/architecture.toml's [[architecture.crates]]
#       array, in either direction
#   (b) `find docs -type f` and docs/MANIFEST.toml disagree in either
#       direction: an undocumented file (orphan), or a manifest entry whose
#       file no longer exists (ghost)
# Cargo.toml is the SSOT for what crates exist; docs/MANIFEST.toml is the
# SSOT for what files live in docs/. No doc may hand-restate either count —
# this script is the only thing allowed to know the number.

REPO_ROOT=$(git rev-parse --show-toplevel)

python3 - "$REPO_ROOT" <<'PYEOF'
import re, subprocess, sys, tomllib, os

repo = sys.argv[1]

rc = 0
def fail(msg):
    global rc
    print(f"DOC DRIFT: {msg}", file=sys.stderr)
    rc = 1

def read_toml(rel):
    with open(os.path.join(repo, rel), "rb") as f:
        return tomllib.load(f)

# --- derive the crate roster from Cargo.toml ---
ws = read_toml("Cargo.toml")["workspace"]
member_paths = list(ws.get("members", [])) + list(ws.get("exclude", []))
roster = {}
for m in member_paths:
    pkg = read_toml(os.path.join(m, "Cargo.toml"))
    roster[pkg["package"]["name"]] = m
kernel_path = ws.get("exclude", [])
kernel_crates = {read_toml(os.path.join(p, "Cargo.toml"))["package"]["name"] for p in kernel_path}

# --- ARCHITECTURE.md's crate map table(s) ---
arch_text = open(os.path.join(repo, "ARCHITECTURE.md")).read()
m = re.search(r'\n## Crate map\n(.*?)\n## ', arch_text, re.S)
if not m:
    fail("ARCHITECTURE.md has no '## Crate map' section (or no '## ' heading follows it)")
    arch_crates = set()
else:
    arch_crates = set(re.findall(r'^\|\s*`([a-z0-9_-]+)`\s*\|', m.group(1), re.M))
for c in sorted(roster):
    if c not in arch_crates:
        fail(f"crate '{c}' ({roster[c]}) is not listed in ARCHITECTURE.md's crate map table")
for c in sorted(arch_crates):
    if c not in roster:
        fail(f"ARCHITECTURE.md's crate map table lists '{c}', which is not a Cargo.toml workspace member")

# --- _llm/architecture.toml's crate array ---
llm = read_toml(os.path.join("_llm", "architecture.toml"))
llm_crates = {c.get("name") for c in llm.get("architecture", {}).get("crates", [])}
for c in sorted(roster):
    if c not in llm_crates:
        fail(f"crate '{c}' ({roster[c]}) is not listed in _llm/architecture.toml's [[architecture.crates]]")
for c in sorted(llm_crates):
    if c not in roster:
        fail(f"_llm/architecture.toml lists crate '{c}', which is not a Cargo.toml workspace member")

# --- docs/ manifest ---
manifest = read_toml(os.path.join("docs", "MANIFEST.toml"))
manifest_files = {d["path"] for d in manifest.get("doc", [])}
found = subprocess.run(
    ["find", "docs", "-type", "f"], cwd=repo, capture_output=True, text=True, check=True
).stdout.splitlines()
actual_files = set(found)

for f in sorted(actual_files):
    if f not in manifest_files:
        fail(f"'{f}' exists under docs/ but has no entry in docs/MANIFEST.toml")
for f in sorted(manifest_files):
    if f not in actual_files:
        fail(f"docs/MANIFEST.toml lists '{f}', which no longer exists")

if rc == 0:
    print(
        f"doc inventory: {len(roster)} crates ({len(roster) - len(kernel_crates)} workspace + "
        f"{len(kernel_crates)} kernel) verified across ARCHITECTURE.md + _llm/architecture.toml, "
        f"{len(manifest_files)} docs/ files verified against MANIFEST.toml"
    )
sys.exit(rc)
PYEOF
