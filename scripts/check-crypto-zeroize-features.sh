#!/usr/bin/env bash
set -euo pipefail

# check-crypto-zeroize-features.sh — every direct dependency on a keyed-state
# crypto crate must enable its `zeroize` feature (#835/#836).
#
# WHY this needs a check at all: an AES round-key schedule is reversible to the
# key that produced it, and the crates that hold one scrub it ONLY when their
# own `zeroize` feature is on. Without it, everything compiles and behaves
# identically -- the key material is simply left resident after use. There is
# no test that fails, no warning, and no runtime symptom. A new crate added
# with `aes = "0.9"` inherits the defect silently, which is exactly how the
# three existing instances arrived.
#
# WHY the feature is per-crate rather than one switch: `aes-gcm`'s own
# `zeroize` feature does NOT make `Aes256Gcm` zeroize on drop -- read at
# aes-gcm-0.11.0 `src/lib.rs:233`, it clears only the `ghash_key` temporary
# during construction, and `AesGcm` has no `Drop` of its own. Its two keyed
# fields scrub themselves through their OWN features: `aes/zeroize` supplies
# `Aes256: ZeroizeOnDrop`, and `ghash/zeroize` forwards to `polyval/zeroize`,
# which arms the otherwise-empty `Drop` body at polyval-0.7.3
# `src/lib.rs:111-119`. Enabling one and not the others leaves keyed state
# resident, so the check demands all of them.
#
# WHY it reads manifests rather than the resolved graph: `cargo metadata`'s
# resolve is an over-approximation of what any one build enables, so a feature
# it reports as on can still be off for a narrower build -- a check that
# passes while the guarantee is absent. A declared feature on a direct
# dependency is unconditional for that crate. The complementary end-to-end
# proof is the `ZeroizeOnDrop` assertion compiled into stegnos, pteron and the
# kernel crate; this script covers what no type can: a manifest that has not
# been written yet.

REPO_ROOT=$(git rev-parse --show-toplevel)

python3 - "$REPO_ROOT" <<'PY'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])

# Crates whose in-memory state is key-derived and is scrubbed only under their
# own `zeroize` feature.
CRYPTO = {"aes", "aes-gcm", "ghash", "polyval"}
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")

failures = []
checked = 0

for manifest in sorted(root.rglob("Cargo.toml")):
    if "target" in manifest.parts:
        continue
    with manifest.open("rb") as fh:
        data = tomllib.load(fh)

    tables = [(t, data.get(t, {})) for t in DEP_TABLES]
    ws = data.get("workspace", {})
    tables.append(("workspace.dependencies", ws.get("dependencies", {})))

    for table, deps in tables:
        for name, spec in deps.items():
            if name not in CRYPTO:
                continue
            # An inherited spec carries the root's features by definition; the
            # root declaration is checked on its own pass.
            if isinstance(spec, dict) and spec.get("workspace"):
                continue
            checked += 1
            features = spec.get("features", []) if isinstance(spec, dict) else []
            if "zeroize" not in features:
                rel = manifest.relative_to(root)
                failures.append(f"{rel} [{table}] {name}: missing features = [\"zeroize\"]")

if failures:
    print("FAIL: keyed crypto state would be left unzeroized:", file=sys.stderr)
    for f in failures:
        print(f"  {f}", file=sys.stderr)
    print(
        "\nAdd `features = [\"zeroize\"]`, or inherit the root declaration with "
        "`{ workspace = true }`.",
        file=sys.stderr,
    )
    sys.exit(1)

if checked == 0:
    print(
        "FAIL: no direct crypto dependency found — this check is inert and "
        "would pass regardless of what the manifests say",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"ok  crypto zeroize features: {checked} direct spec(s) verified")
PY
