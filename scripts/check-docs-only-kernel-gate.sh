#!/usr/bin/env bash
set -euo pipefail

# check-docs-only-kernel-gate.sh — required-context topology guard (#944).
#
# A docs-only inventory edit may skip the kernel build and QEMU matrix, but it
# must not skip the canonical source inventory checker. This guard proves the
# composition rather than duplicating that checker:
#   (a) the exact branch-protection context keeps an unconditional checkout and
#       source-only checker before its exemption report;
#   (b) every later build/QEMU/full-witness step remains docs-only guarded;
#   (c) the later full checker still consumes the boot log; and
#   (d) the canonical checker itself rejects a deliberately malformed isolated
#       inventory fixture.

REPO_ROOT=$(git rev-parse --show-toplevel)
CI="$REPO_ROOT/.github/workflows/ci.yml"
CHECKER="$REPO_ROOT/scripts/check-wiring-inventory.sh"

python3 - "$CI" <<'PYEOF'
import re
import sys

ci_path = sys.argv[1]
lines = open(ci_path, encoding="utf-8").read().splitlines()


def fail(message):
    print(f"DOCS-ONLY KERNEL GATE: {message}", file=sys.stderr)
    raise SystemExit(1)


def job_block(job_name):
    marker = f"  {job_name}:"
    try:
        start = lines.index(marker)
    except ValueError:
        fail(f"ci.yml has no {job_name!r} job")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.fullmatch(r"  [A-Za-z0-9_-]+:", lines[index]):
            end = index
            break
    return lines[start:end]


def steps(job):
    starts = [
        index
        for index, line in enumerate(job)
        if re.match(r"^      - (?:name|uses): ", line)
    ]
    parsed = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(job)
        block = job[start:end]
        first = block[0].strip()[2:]
        fields = {}
        for line in block[1:]:
            match = re.match(r"^        (if|run|continue-on-error): (.*)$", line)
            if match:
                fields[match.group(1)] = match.group(2)
        parsed.append({"label": first, "block": block, **fields})
    return parsed


kernel = job_block("kernel")
fmt = job_block("fmt")
kernel_text = "\n".join(kernel)
fmt_text = "\n".join(fmt)

if "    name: kernel (i686 tests + armv7a build)" not in kernel:
    fail("kernel job no longer emits the branch-protection-required context name")
if "    needs: docs-only" not in kernel:
    fail("required kernel job no longer consumes the docs-only preflight")
if "    if: ${{ !cancelled() }}" not in kernel:
    fail("required kernel job no longer runs after an indeterminate/failed preflight")
if "needs.docs-only.result == 'success' && needs.docs-only.outputs.docs_only == 'true'" not in kernel_text:
    fail("DOCS_ONLY is no longer fail-closed on success plus literal true")
if "scripts/check-wiring-inventory.sh" in fmt_text:
    fail("canonical inventory checker is duplicated in the unrequired fmt job")

parsed = steps(kernel)


def exactly_one(predicate, description):
    found = [index for index, step in enumerate(parsed) if predicate(step)]
    if len(found) != 1:
        fail(f"expected exactly one {description}, found {len(found)}")
    return found[0]


checkout = exactly_one(
    lambda step: step["label"].startswith("uses: actions/checkout@"),
    "kernel checkout",
)
source = exactly_one(
    lambda step: step.get("run") == "scripts/check-wiring-inventory.sh --no-log",
    "unconditional source inventory check",
)
topology = exactly_one(
    lambda step: step.get("run") == "scripts/check-docs-only-kernel-gate.sh",
    "docs-only kernel topology regression",
)
report = exactly_one(
    lambda step: step["label"] == "name: Report docs-only kernel exemption (#775)",
    "docs-only exemption report",
)
boot = exactly_one(
    lambda step: step.get("run") == "scripts/witness/boot.sh",
    "kernel QEMU boot witness",
)
full = exactly_one(
    lambda step: step.get("run") == "scripts/check-wiring-inventory.sh",
    "post-boot full inventory check",
)

if not checkout < source < topology < report:
    fail("checkout, source check, topology guard, and exemption report are out of order")
for index, description in (
    (checkout, "checkout"),
    (source, "source inventory check"),
    (topology, "topology regression"),
):
    if "if" in parsed[index]:
        fail(f"{description} is conditional; docs-only changes can bypass it")
    if parsed[index].get("continue-on-error") == "true":
        fail(f"{description} is non-blocking")
if parsed[report].get("if") != "env.DOCS_ONLY == 'true'":
    fail("docs-only exemption report does not require literal true")

guard = "env.DOCS_ONLY != 'true'"
for step in parsed[report + 1 :]:
    if step.get("if") != guard:
        fail(f"post-exemption step {step['label']!r} is not guarded by {guard!r}")
if not report < boot < full:
    fail("full inventory checker no longer follows the QEMU boot witness")

print(
    "docs-only kernel topology: required source check precedes exemption; "
    "all later build/QEMU steps remain guarded"
)
PYEOF

FIXTURE_ROOT=$(mktemp -d)
cleanup() {
    rm -rf -- "$FIXTURE_ROOT"
}
trap cleanup EXIT

mkdir -p \
    "$FIXTURE_ROOT/docs" \
    "$FIXTURE_ROOT/crates/thumos/src" \
    "$FIXTURE_ROOT/scripts/witness"
cp "$CHECKER" "$FIXTURE_ROOT/scripts/check-wiring-inventory.sh"
cp "$REPO_ROOT/docs/capability-inventory.toml" "$FIXTURE_ROOT/docs/"
cp "$REPO_ROOT/crates/thumos/src/main.rs" "$FIXTURE_ROOT/crates/thumos/src/"
cp "$REPO_ROOT"/scripts/witness/*.sh "$FIXTURE_ROOT/scripts/witness/"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
git -c init.defaultBranch=main -C "$FIXTURE_ROOT" init -q

python3 - "$FIXTURE_ROOT/docs/capability-inventory.toml" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = '"kinit", '
if text.count(needle) != 1:
    print(
        "DOCS-ONLY KERNEL GATE: malformed fixture cannot remove exactly one kinit classification",
        file=sys.stderr,
    )
    raise SystemExit(1)
path.write_text(text.replace(needle, "", 1), encoding="utf-8")
PYEOF

set +e
fixture_output=$(
    cd "$FIXTURE_ROOT" && \
        env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE \
            bash scripts/check-wiring-inventory.sh --no-log 2>&1
)
fixture_rc=$?
set -e

if [[ "$fixture_rc" -eq 0 ]]; then
    echo "DOCS-ONLY KERNEL GATE: canonical checker accepted an unclassified kinit fixture" >&2
    exit 1
fi
if ! grep -Fq "main.rs module 'kinit' has no [[capability]] entry" <<<"$fixture_output"; then
    echo "DOCS-ONLY KERNEL GATE: malformed fixture failed for an unexpected reason" >&2
    printf '%s\n' "$fixture_output" >&2
    exit 1
fi

echo "docs-only kernel gate: malformed inventory makes the required source step fail; build/QEMU remain skipped"
