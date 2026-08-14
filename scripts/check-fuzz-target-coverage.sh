#!/usr/bin/env bash
set -euo pipefail

# check-fuzz-target-coverage.sh — #819. Every fuzz target must exercise code the
# KERNEL links, and every known exception must be listed here with its cause.
#
# WHY: a fuzz target that imports a workspace crate the kernel does not link
# certifies a code path that never runs on a device. That is worse than no
# signal, because a green fuzz run reads as coverage. The protection was paid
# for and landed on the wrong implementation.
#
# The test is per-MODULE, not per-crate. `fuzz_packet.rs` imports three modules
# of one crate: `packet` delegates into asphaleia-core (which the kernel links)
# and is genuinely covered, while `filter` and `rules` delegate to nothing. An
# outer crate importing its own module name proves nothing on its own; whether
# that module reaches the shared core is what decides it.
#
# The exemption table is a RATCHET, not a mute. A gap that is not listed fails.
# A listed gap that is no longer a gap ALSO fails, so the table cannot rot into
# a record of problems someone already fixed.
#
# What this CANNOT see: whether a module that references its core delegates the
# specific function a target actually calls. It proves the module is wired to
# shared code, not that every path through it is. Deeper coverage is the
# convergence ledger's job (docs/convergence.toml), not this check's.

REPO_ROOT=$(git rev-parse --show-toplevel)

python3 - "$REPO_ROOT" <<'PYEOF'
import glob
import os
import re
import sys
import tomllib

root = sys.argv[1]

# Known gaps: (crate, module) -> why it is not yet covered. Each must cite the
# issue that will close it. Remove the row when the gap closes; the check fails
# on a row that no longer describes a gap.
EXEMPT = {
    ("aither", "wpa"): "#819 — no aither-core exists; the kernel parses WPA in crates/thumos/src/wifi.rs",
    ("aither", "eapol"): "#819 — no aither-core exists; the kernel parses EAPOL in crates/thumos/src/wifi.rs",
    ("asphaleia", "filter"): "#819 — the kernel filters packets in crates/thumos/src/firewall.rs",
    ("asphaleia", "rules"): "#819 — the kernel's rule evaluation lives in crates/thumos/src/firewall.rs",
    ("klesis", "ccci"): "#819 — the kernel frames CCCI in crates/thumos/src/ccci.rs (its own CcciHeader)",
}

NOT_A_CRATE = {"libfuzzer_sys", "std", "core", "alloc", "crate", "self", "super"}


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


# The kernel is the authority on what ships. Read the -core crates it links.
kernel_manifest = os.path.join(root, "crates", "thumos", "Cargo.toml")
try:
    with open(kernel_manifest, "rb") as fh:
        kernel = tomllib.load(fh)
except OSError as exc:
    fail(f"cannot read the kernel manifest: {exc}")

kernel_cores = {
    name[: -len("-core")]
    for name in kernel.get("dependencies", {})
    if name.endswith("-core")
}
if not kernel_cores:
    fail("the kernel declares no -core dependencies -- refusing to grade coverage against an empty set")

targets = sorted(glob.glob(os.path.join(root, "fuzz", "fuzz_targets", "*.rs")))
if not targets:
    fail("no fuzz targets found -- refusing to report coverage over nothing")

USE_RE = re.compile(r"^use\s+([a-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)")


def module_of(crate, segment):
    """Resolve an imported path segment to the module that owns it."""
    if segment[0].islower():
        return segment
    # A capitalised segment is a type re-exported at the crate root; find the
    # module it is re-exported FROM, so the check grades the real owner.
    lib = os.path.join(root, "crates", crate, "src", "lib.rs")
    try:
        text = open(lib, encoding="utf-8").read()
    except OSError:
        return None
    m = re.search(rf"pub use\s+([a-z_][a-z0-9_]*)::(?:\w+::)*{re.escape(segment)}\b", text)
    if m:
        return m.group(1)
    for path in glob.glob(os.path.join(root, "crates", crate, "src", "*.rs")):
        body = open(path, encoding="utf-8").read()
        if re.search(rf"pub\s+(?:struct|enum|type|trait)\s+{re.escape(segment)}\b", body):
            return os.path.splitext(os.path.basename(path))[0]
    return None


def module_path(crate, module):
    for candidate in (
        os.path.join(root, "crates", crate, "src", f"{module}.rs"),
        os.path.join(root, "crates", crate, "src", module, "mod.rs"),
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


rows, gaps, resolved = [], set(), 0
for target in targets:
    name = os.path.basename(target)
    seen = set()
    for line in open(target, encoding="utf-8").read().splitlines():
        m = USE_RE.match(line.strip())
        if not m:
            continue
        crate, segment = m.group(1), m.group(2)
        if crate in NOT_A_CRATE:
            continue
        module = module_of(crate, segment)
        if module is None:
            fail(f"{name}: cannot resolve `{crate}::{segment}` to a module -- the check would grade it blind")
        if (crate, module) in seen:
            continue
        seen.add((crate, module))
        resolved += 1

        if crate not in kernel_cores:
            rows.append((name, f"{crate}::{module}", "GAP", f"the kernel links no {crate}-core"))
            gaps.add((crate, module))
            continue
        path = module_path(crate, module)
        if path is None:
            fail(f"{name}: `{crate}::{module}` names no module file -- cannot verify what it exercises")
        refs = len(re.findall(rf"\b{crate}_core\b", open(path, encoding="utf-8").read()))
        if refs:
            rows.append((name, f"{crate}::{module}", "ok", f"{refs} {crate}_core ref(s)"))
        else:
            rows.append((name, f"{crate}::{module}", "GAP", f"no {crate}_core reference"))
            gaps.add((crate, module))

if not resolved:
    fail("no crate imports resolved across any fuzz target -- the import pattern is wrong")

width = max(len(r[1]) for r in rows)
for target_name, path_label, verdict, why in rows:
    mark = "ok  " if verdict == "ok" else "GAP "
    print(f"  {mark} {target_name:<18} {path_label:<{width}}  {why}")

unlisted = sorted(gaps - set(EXEMPT))
stale = sorted(set(EXEMPT) - gaps)

if unlisted:
    print("", file=sys.stderr)
    for crate, module in unlisted:
        print(f"FAIL: {crate}::{module} is fuzzed but the kernel does not link it, and it is not a listed gap", file=sys.stderr)
    print("      A fuzz target must exercise shipped code. Point it at the shared core,", file=sys.stderr)
    print("      or add it to EXEMPT with the issue that will close it.", file=sys.stderr)

if stale:
    print("", file=sys.stderr)
    for crate, module in stale:
        print(f"FAIL: EXEMPT lists {crate}::{module}, but it is no longer a gap -- delete the row", file=sys.stderr)
    print("      A stale exemption reports a problem that is already fixed.", file=sys.stderr)

if unlisted or stale:
    sys.exit(1)

covered = sum(1 for r in rows if r[2] == "ok")
print(f"OK: {covered}/{len(rows)} fuzzed modules exercise kernel-linked code; "
      f"{len(gaps)} known gap(s) listed (see #819)")
PYEOF
