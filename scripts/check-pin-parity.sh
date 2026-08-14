#!/usr/bin/env bash
set -euo pipefail

# check-pin-parity.sh — a crate that pins a dependency LITERALLY must pin the
# same version the workspace declares for it.
#
# WHY this exists: two crates cannot use `{ workspace = true }` for everything.
# `crates/metaxu-core` needs `default-features = false` on several deps and
# cargo refuses a member override of the workspace's `default-features`, so it
# spells six dependencies out by hand. `crates/thumos` is excluded from the
# workspace entirely (it cross-compiles bare-metal), so inheritance is not
# available to it at all. Both therefore restate versions the workspace also
# declares, and metaxu-core's own header asserts the invariant this script
# enforces: "Versions match the workspace pins exactly."
#
# WHY it is a check rather than a comment: that sentence was already written
# and was already false, twice in one day. When the RustCrypto wave moved the
# workspace to ed25519-dalek 3, metaxu-core stayed on 2; when the following
# wave moved compact_str to 0.10, metaxu-core stayed on 0.8. Neither is a
# harmless lag — metaxu and metaxu-core exchange `SignedGrant`, `SigningKey`
# and `CompactString` values, and two majors of the same crate are two
# distinct types that do not typecheck across that boundary. Both were caught
# by noticing duplicate majors in the lockfile, which is luck rather than
# process: a dependency bump that happens not to be exchanged across a crate
# boundary would drift silently and indefinitely.
#
# A grep is not sufficient and was the first thing that failed here: a pattern
# matching `name = "1.2"` misses `name = { version = "1.2", ... }`, which is
# the form every one of these pins actually uses.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$repo_root" <<'PY'
import re
import sys
import pathlib

root = pathlib.Path(sys.argv[1])

def parse_deps(text, section_names):
    """Map dependency name -> literal version string, for one manifest.

    WHY three forms and not two: TOML lets a dependency be declared as a bare
    string (`name = "1"`), an inline table (`name = { version = "1", ... }`),
    OR as its own dotted-header table (`[workspace.dependencies.name]` with
    `version = "1"` beneath). A parser keyed on an exact section name sees only
    the first two and silently drops every dep declared the third way -- which
    is the same shape as the defect this whole check exists to catch, one level
    up: a scanner that misses a valid spelling and reports green. aletheia
    declares `regex` and `serde` this way today, so the form is in live fleet
    use, not hypothetical.
    """
    out = {}
    section = None
    dotted = None          # dep name when inside [<section>.<name>]
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            dotted = None
            for base in section_names:
                if section.startswith(base + "."):
                    dotted = section[len(base) + 1:].strip('"')
            continue
        if dotted is not None:
            vm = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if vm:
                out[dotted] = vm.group(1)
            continue
        if section not in section_names:
            continue
        m = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*(.*)$', line)
        if not m:
            continue
        name, rhs = m.group(1), m.group(2)
        if "workspace" in rhs and "true" in rhs:
            continue
        vm = re.search(r'version\s*=\s*"([^"]+)"', rhs)
        if not vm:
            vm = re.match(r'^"([^"]+)"', rhs)
        if vm:
            out[name] = vm.group(1)
    return out

ws_text = (root / "Cargo.toml").read_text(encoding="utf-8")
workspace = parse_deps(ws_text, {"workspace.dependencies"})
if not workspace:
    sys.exit("check-pin-parity: no [workspace.dependencies] found — refusing to pass vacuously")

manifests = sorted(root.glob("crates/*/Cargo.toml"))
drift = []
checked = 0

for man in manifests:
    text = man.read_text(encoding="utf-8")
    local = parse_deps(text, {"dependencies", "dev-dependencies", "build-dependencies"})
    rel = man.relative_to(root)
    for name, ver in sorted(local.items()):
        if name not in workspace:
            continue          # crate-only dependency; nothing to agree with
        checked += 1
        if ver != workspace[name]:
            drift.append(f"  {rel}: {name} = \"{ver}\"  but workspace declares \"{workspace[name]}\"")

print(f"== pin parity: {checked} literal pin(s) checked against {len(workspace)} workspace declarations ==")

if checked == 0:
    sys.exit("check-pin-parity: zero pins compared — the parser matched nothing, which is a defect in this script rather than a clean tree")

if drift:
    print("PIN DRIFT: a crate pins a version the workspace does not declare.")
    print("These are the same type to a reader and different types to the compiler.")
    print()
    for d in drift:
        print(d)
    sys.exit(1)

print("all literal pins agree with the workspace")
PY
