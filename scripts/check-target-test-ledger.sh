#!/usr/bin/env bash
set -euo pipefail

# check-target-test-ledger.sh — declared-vs-executed audit for the kernel's
# test obligations (#551, restoring #124; runnable-derivation #645). Fails
# when:
#   (a) a module with #[test]s or target-sensitive patterns has no ledger row
#   (b) a 'both'/'target' row names a witness script that does not exist
#   (c) a target-sensitive host-only row carries no fidelity note
#   (d) a row's declared tests count does not match the RUNNABLE test count
#       in the compiled i686 host test binary
# Ledger: docs/target-test-ledger.toml. #528/#533 are the proof-by-incident:
# host fixtures green while real-table behavior was broken on every boot.
#
# (d) used to count `#[test]` occurrences in source TEXT (#124's original
# design). #619/#631/#645 are the proof that text is the wrong basis: emmc
# (31 tests) and watchdog (3 tests) were both `#[cfg]`-excluded from every
# test build, so their tests existed as text, were counted as coverage, and
# had never once been compiled. (d) now derives its count from
# `cargo nextest list` — the tests the i686 binary genuinely contains — so a
# module that stops compiling reds immediately instead of reporting its old
# count forever (Done-when in #645).
#
# COST: (d) needs a build. Both ci.yml and .kanon-ci.toml already run the
# "kernel host tests" stage immediately before this one (same target, same
# two feature passes below), so the i686 target is warm and `nextest list`
# here is a cache hit, not a fresh compile — this stage's placement in the
# pipeline is load-bearing, not incidental. Invoked standalone with no prior
# build, this script builds first like any other nextest call.
#
# WHY --locked (#757): crates/thumos keeps its own lockfile; without --locked
# a manifest/lock disagreement here is silently resolved and rewritten
# instead of failing the build.

REPO_ROOT=$(git rev-parse --show-toplevel)
LEDGER="$REPO_ROOT/docs/target-test-ledger.toml"
SRC="$REPO_ROOT/crates/thumos/src"
WITNESS_DIR="$REPO_ROOT/scripts/witness"
KERNEL_DIR="$REPO_ROOT/crates/thumos"
MAIN_RS="$SRC/main.rs"

command -v cargo-nextest >/dev/null || {
    echo "LEDGER DRIFT: cargo-nextest not installed -- cannot derive runnable test counts (#645)" >&2
    exit 1
}

LIST_DEFAULT=$(mktemp)
LIST_DEBUG=$(mktemp)
trap 'rm -f "$LIST_DEFAULT" "$LIST_DEBUG" "$LIST_DEFAULT.err" "$LIST_DEBUG.err"' EXIT

# Two passes mirror kernel-host-tests.sh's two nextest-run passes (#459):
# default features, then --features debug-console (the only feature that
# gates in extra host-testable modules -- console). Their union is the
# runnable set this ledger is checked against.
if ! (cd "$KERNEL_DIR" && cargo nextest list --bin thumos --target i686-unknown-linux-gnu --locked \
        --build-jobs "${THUMOS_BUILD_JOBS:-8}" --message-format json) >"$LIST_DEFAULT" 2>"$LIST_DEFAULT.err"; then
    cat "$LIST_DEFAULT.err" >&2
    echo "LEDGER DRIFT: cargo nextest list (default features) failed -- cannot derive runnable test counts" >&2
    exit 1
fi
if ! (cd "$KERNEL_DIR" && cargo nextest list --bin thumos --target i686-unknown-linux-gnu --locked \
        --features debug-console --build-jobs "${THUMOS_BUILD_JOBS:-8}" --message-format json) >"$LIST_DEBUG" 2>"$LIST_DEBUG.err"; then
    cat "$LIST_DEBUG.err" >&2
    echo "LEDGER DRIFT: cargo nextest list (--features debug-console) failed -- cannot derive runnable test counts" >&2
    exit 1
fi

python3 - "$LEDGER" "$SRC" "$WITNESS_DIR" "$MAIN_RS" "$LIST_DEFAULT" "$LIST_DEBUG" <<'PYEOF'
import re, sys, tomllib, glob, os, json

ledger_path, src_dir, wit_dir, main_rs_path, list_default_path, list_debug_path = sys.argv[1:7]
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

# --- cfg evaluator -----------------------------------------------------------
# main.rs expresses every declared module's availability with `test`,
# `feature = "NAME"`, `not(EXPR)`, `all(EXPR, ...)`, `any(EXPR, ...)` -- the
# exact grammar `#[cfg(...)]` uses on `mod` items in this crate. This walks
# that grammar; it is not a general cfg parser and does not need to be.
TOKEN_RE = re.compile(r'\(|\)|,|[A-Za-z_][A-Za-z0-9_]*|"[^"]*"|=')

def _parse(tokens, env):
    tok = tokens[0]
    rest = tokens[1:]
    if tok in ("not", "all", "any"):
        assert rest and rest[0] == "(", f"expected '(' after {tok}"
        rest = rest[1:]
        args = []
        while True:
            v, rest = _parse(rest, env)
            args.append(v)
            if rest and rest[0] == ",":
                rest = rest[1:]
                continue
            assert rest and rest[0] == ")", f"expected ')' closing {tok}(...)"
            rest = rest[1:]
            break
        return ({"not": not args[0], "all": all(args), "any": any(args)}[tok], rest)
    if tok == "test":
        return (env["test"], rest)
    if tok == "feature":
        assert rest and rest[0] == "=", "expected '=' after feature"
        name = rest[1].strip('"')
        return (name in env["features"], rest[2:])
    raise ValueError(f"unrecognized cfg token {tok!r}")

def eval_cfg(expr, env):
    toks = TOKEN_RE.findall(expr)
    v, rest = _parse(toks, env)
    assert not rest, f"leftover cfg tokens: {rest}"
    return v

# --- mod-declaration extraction ---------------------------------------------
# Groups {ident: [(cfg_expr_or_None, path_override_or_None), ...]} from a
# file's top-level `mod IDENT;` items. An attribute attaches only to the
# `mod` line directly below it across blank/comment lines; any other
# statement in between breaks the pairing. WHY: a naive "last #[cfg] seen"
# scan mis-attributes a `#[cfg(not(test))]` guarding a preceding `use`
# statement to an unrelated later `mod` -- caught while building this check.
MOD_RE = re.compile(r'^(?:pub(?:\(crate\))? )?mod (\w+);')
CFG_RE = re.compile(r'^#\[cfg\((.*)\)\]$')
PATH_RE = re.compile(r'^#\[path\s*=\s*"([^"]+)"\]$')

def extract_mod_decls(path):
    decls = {}
    pending_cfg = None
    pending_path = None
    for line in open(path):
        s = line.strip()
        m = CFG_RE.match(s)
        if m:
            pending_cfg = m.group(1)
            continue
        m = PATH_RE.match(s)
        if m:
            pending_path = m.group(1)
            continue
        if s == "" or s.startswith("//"):
            continue
        m = MOD_RE.match(s)
        if m:
            decls.setdefault(m.group(1), []).append((pending_cfg, pending_path))
            pending_cfg = None
            pending_path = None
            continue
        pending_cfg = None
        pending_path = None
    return decls

def relpath_for(ident, path_override):
    if path_override:
        assert path_override.endswith(".rs"), f"non-.rs #[path] override: {path_override}"
        return path_override[:-3]
    return ident

def active_relpath(decls, ident, env):
    variants = decls.get(ident)
    if not variants:
        return None
    active = [relpath_for(ident, path_override) for (cfg, path_override) in variants
              if cfg is None or eval_cfg(cfg, env)]
    if len(active) > 1:
        raise AssertionError(f"'{ident}' has {len(active)} simultaneously-active mod declarations under {env}: {active}")
    return active[0] if active else None

main_decls = extract_mod_decls(main_rs_path)
# idents main.rs declares more than once (path-swap families, e.g.
# exceptions/exceptions_stub, watchdog/watchdog_qemu) -- only these need
# per-env resolution below; every other module's ledger row name is its
# Rust path with '::' replaced by '/', directly.
overridden_idents = {ident for ident, variants in main_decls.items() if len(variants) > 1}

def module_path_to_row_name(mod_path, env):
    """mod_path is the '::'-joined Rust path before '::tests::<fn>' in a
    nextest test id. Resolve it to the docs/target-test-ledger.toml row it
    corresponds to under this build env. Nested idents that aren't path-swap
    families (board::m7, board::virt -- gated in board/mod.rs, not main.rs,
    and never sharing a name) need no resolution at all: '::' -> '/' on the
    full path already matches their ledger row names directly."""
    segs = mod_path.split("::")
    head = segs[0]
    if head in overridden_idents:
        rp = active_relpath(main_decls, head, env)
        # A test literally compiled under this ident in this env, so some
        # declaration must have been active for it -- anything else means
        # this resolver's model of main.rs disagrees with the binary that
        # actually built, which is a bug in the resolver, not the ledger.
        assert rp is not None, (
            f"'{head}' produced a runnable test under {env} but no #[cfg] "
            f"on its mod declarations evaluates true -- ledger-check cfg "
            f"resolver is out of sync with main.rs"
        )
        segs[0] = rp
    return "/".join(segs)

# --- runnable test-case extraction ------------------------------------------
# WHY no filter-match / ignored filtering: nextest's `filter-match` reflects
# whether a test matches an explicit NAME filter (none is passed here), and
# `ignored` reflects whether a DEFAULT run would skip it -- neither says
# whether the test compiled. An #[ignore]d test is still a compiled,
# individually-invocable test case (`cargo nextest run -- --ignored` runs
# it); the old text-regex count never distinguished it either. Counting
# every entry in `testcases` keeps this check's semantics aligned with what
# it replaces: "how many #[test] fns does this module contain," not "how
# many run by default."
def iter_test_names(list_json_path):
    data = json.load(open(list_json_path))
    suites = data.get("rust-suites") or data.get("rust-binaries") or {}
    for suite in suites.values():
        cases = suite.get("test-cases") or suite.get("testcases") or {}
        yield from cases.keys()

TEST_SUFFIX_RE = re.compile(r'^(.*)::tests::[^:]+$')

def runnable_row_counts(list_json_path, env):
    seen = set()
    for name in iter_test_names(list_json_path):
        m = TEST_SUFFIX_RE.match(name)
        if not m:
            fail(f"nextest test id '{name}' does not match MODULE::tests::FN -- cannot attribute it to a ledger row")
            continue
        row_name = module_path_to_row_name(m.group(1), env)
        seen.add((row_name, name))
    counts = {}
    for row_name, _name in seen:
        counts[row_name] = counts.get(row_name, 0) + 1
    return counts

env_default = {"test": True, "features": frozenset()}
env_debug = {"test": True, "features": frozenset({"debug-console"})}

runnable = {}
for row_name, n in runnable_row_counts(list_default_path, env_default).items():
    runnable[row_name] = max(runnable.get(row_name, 0), n)
for row_name, n in runnable_row_counts(list_debug_path, env_debug).items():
    runnable[row_name] = max(runnable.get(row_name, 0), n)

# --- (a)/(b)/(c)/(e): unchanged, source-level -------------------------------
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

# --- (d): declared tests must match the RUNNABLE count (#645) --------------
for name, row in sorted(by_name.items()):
    declared = row.get("tests", -1)
    actual = runnable.get(name, 0)
    if declared == actual:
        continue
    mech = row.get("mechanism", "")
    if mech in ("host", "both") and declared > 0 and actual == 0:
        fail(
            f"module '{name}' mechanism={mech} claims {declared} host tests but the i686 test "
            f"binary contains zero runnable tests under that name -- the module is not compiled "
            f"under cfg(test) (a #[cfg] gate excludes it; #645)"
        )
    else:
        fail(f"module '{name}': ledger says {declared} tests, i686 test binary has {actual} runnable")

if rc == 0:
    n_both = sum(1 for r in rows if r.get("mechanism") == "both")
    n_target = sum(1 for r in rows if r.get("mechanism") == "target")
    n_runnable = sum(runnable.values())
    print(f"target-test ledger: {len(rows)} rows checked, {n_both} both-mechanism, {n_target} target-only, {n_runnable} runnable host tests, no drift")
sys.exit(rc)
PYEOF
