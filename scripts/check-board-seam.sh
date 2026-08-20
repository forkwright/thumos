#!/usr/bin/env bash
set -euo pipefail

# INVARIANT: check-board-seam.sh enforces the #534 boundary as source structure,
# not prose. It fails when:
#   (a) an `MT6739_*` identifier appears anywhere in the kernel crate outside
#       board/m7.rs (the whole point of the seam; the ccci family is exempt —
#       its seam is klesis-protocol-vs-kernel-transport, not the board);
#   (b) a canonical board-MMIO hex value is re-DECLARED as a const outside
#       board/ (the pre-#534 duplication class: five CONSYS copies, three
#       UART0 copies). Literal appearances in comments and host-test fault
#       fixtures (arbitrary-MMIO-address probes) are not declarations and are
#       allowed;
#   (c) the exact `PWRAP_BASE` spelling, PWRAP base value, or a common two-literal
#       expression producing that value appears outside board/m7.rs;
#   (d) an ARMPLL_*/MCDI_* identifier spelling, exact deleted ARMPLL/MCDI
#       address or PCW
#       value, or a common two-literal expression producing one appears in
#       kernel Rust. #862/#879 must source-ground complete transactions before
#       these exact-form bans can be narrowed to reviewed modules.
# Board constants live only under board::*; board selection happens once, in
# board/mod.rs.

REPO_ROOT=$(git rev-parse --show-toplevel)
SRC="$REPO_ROOT/crates/thumos/src"

rc=0

# INVARIANT: (a) No MT6739_* identifier outside board/m7.rs and the ccci family.
# The `+` (not `*`) keeps the prose glob "MT6739_*" from self-matching.
hits=$(grep -rn 'MT6739_[A-Z0-9_]\+' "$SRC" --include='*.rs' \
    | grep -v '/board/m7.rs:' \
    | grep -v '/ccci.rs:' | grep -v '/ccci_logger.rs:' || true)
if [[ -n "$hits" ]]; then
    echo "SEAM DRIFT: MT6739_* identifier outside board::m7 (kernel core must name the board seam, not the SoC):" >&2
    echo "$hits" >&2
    rc=1
fi

# INVARIANT: (b) No re-declared board-MMIO const outside board/. Values are the
# canonical set absorbed by board/m7.rs (#534).
for hex in 0x1800_0000 0x180F_0000 0x1123_0000 0x1121_0000 0x1400_0000 \
           0x1400_7000 0x1400_8000 0x1400_D000 0x1400_1000 0x1001_0000 \
           0x1000_7000 0x1000_D000 0x1100_A000 \
           0x1100_3000 0x77EE_0000 0x1100_2000 0x0C00_0000 0x0C00_2000; do
    hits=$(grep -rn "const [A-Z0-9_]*: usize = $hex" "$SRC" --include='*.rs' \
        | grep -v '/board/' || true)
    if [[ -n "$hits" ]]; then
        echo "SEAM DRIFT: board MMIO value $hex re-declared as a const outside board/:" >&2
        echo "$hits" >&2
        rc=1
    fi
done

# WHY: (c/d) Scan recognized Rust integer-form spellings with Unicode-identifier
# and decimal-float boundaries. This catches case, every integer base, arbitrary
# underscore placement, leading zeroes, and type suffixes without matching
# larger unrelated literals or floats. The scan intentionally includes comments
# and strings as a conservative reintroduction ban. Evaluating common whitespace-
# separated two-literal +, -, and | constructions is defense-in-depth; structural
# removal of every reusable constant/call remains the primary boundary.
python3 - "$SRC" <<'PY' || rc=1
import pathlib
import re
import sys

src = pathlib.Path(sys.argv[1])
m7 = (src / "board" / "m7.rs").resolve()

pwrap_value = 0x1000_D000
cpu_values = {
    0x1000_C104,
    0x1000_DC00,
    0x1000_DC04,
    0x0096_0000,
    0x0078_0000,
    0x005A_0000,
    0x003C_0000,
}

integer_suffixes = (
    "usize",
    "isize",
    "u128",
    "i128",
    "u64",
    "i64",
    "u32",
    "i32",
    "u16",
    "i16",
    "u8",
    "i8",
)


def ident_start(char: str) -> bool:
    return bool(char) and (char == "_" or char.isidentifier())


def ident_continue(char: str) -> bool:
    return bool(char) and (char == "_" or f"a{char}".isidentifier())


def known_suffix_end(text: str, start: int, suffixes: tuple[str, ...]) -> int:
    for suffix in suffixes:
        if text.startswith(suffix, start):
            end = start + len(suffix)
            if end == len(text) or not ident_continue(text[end]):
                return end
    return start


def source_atoms(text: str):
    """Yield identifier and integer-form atoms from Rust source text.

    Comments and strings intentionally remain in scope. Decimal floats are
    consumed and omitted so an integer-looking component cannot false-match.
    """
    index = 0
    while index < len(text):
        char = text[index]

        if ident_start(char):
            start = index
            index += 1
            while index < len(text) and ident_continue(text[index]):
                index += 1
            yield ("identifier", start, index, text[start:index], None)
            continue

        if not char.isascii() or not char.isdigit():
            index += 1
            continue

        start = index
        base = 10
        digits = "0123456789"
        if char == "0" and index + 1 < len(text):
            prefix = text[index + 1]
            if prefix in "xX":
                base, digits, index = 16, "0123456789abcdefABCDEF", index + 2
            elif prefix in "bB":
                base, digits, index = 2, "01", index + 2
            elif prefix in "oO":
                base, digits, index = 8, "01234567", index + 2

        if base != 10:
            digit_start = index
            while index < len(text) and (text[index] in digits or text[index] == "_"):
                index += 1
            core_end = index
            if not any(char in digits for char in text[digit_start:core_end]):
                index = max(index, start + 1)
                continue
            index = known_suffix_end(text, index, integer_suffixes)
            if index < len(text) and ident_continue(text[index]):
                while index < len(text) and ident_continue(text[index]):
                    index += 1
                continue
            core = text[start:core_end].replace("_", "")
            yield ("integer", start, index, text[start:index], int(core[2:], base))
            continue

        while index < len(text) and (text[index] in digits or text[index] == "_"):
            index += 1
        core_end = index
        is_float = False

        if index < len(text) and text[index] == ".":
            after_dot = text[index + 1] if index + 1 < len(text) else ""
            if after_dot != "." and not ident_start(after_dot):
                is_float = True
                index += 1
                while index < len(text) and (text[index] in digits or text[index] == "_"):
                    index += 1

        if index < len(text) and text[index] in "eE":
            exponent = index + 1
            if exponent < len(text) and text[exponent] in "+-":
                exponent += 1
            exponent_start = exponent
            while exponent < len(text) and (text[exponent] in digits or text[exponent] == "_"):
                exponent += 1
            if any(char in digits for char in text[exponent_start:exponent]):
                is_float = True
                index = exponent

        float_end = known_suffix_end(text, index, ("f32", "f64"))
        if float_end != index:
            is_float = True
            index = float_end
        elif not is_float:
            index = known_suffix_end(text, index, integer_suffixes)

        if index < len(text) and ident_continue(text[index]):
            while index < len(text) and ident_continue(text[index]):
                index += 1
            continue

        if not is_float:
            core = text[start:core_end].replace("_", "")
            yield ("integer", start, index, text[start:index], int(core, 10))
def classify(text: str, allow_pwrap: bool) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()

    def add(kind: str, start: int, spelling: str) -> None:
        key = (kind, start, spelling)
        if key not in seen:
            seen.add(key)
            findings.append(key)

    integers: list[tuple[int, int, str, int]] = []
    for kind, start, end, spelling, value in source_atoms(text):
        if kind == "identifier":
            upper = spelling.upper()
            if upper.startswith("ARMPLL_") or upper.startswith("MCDI_"):
                add("CPU-power identifier", start, spelling)
            if not allow_pwrap and spelling == "PWRAP_BASE":
                add("PWRAP identifier", start, spelling)
            continue

        integers.append((start, end, spelling, value))
        if value in cpu_values:
            add("CPU-power literal", start, spelling)
        if not allow_pwrap and value == pwrap_value:
            add("PWRAP literal", start, spelling)

    for left, right in zip(integers, integers[1:]):
        left_start, left_end, _left_spelling, left_value = left
        right_start, _right_end, right_spelling, right_value = right
        operator = re.fullmatch(r"\s*([+|\-])\s*", text[left_end:right_start])
        if operator is None:
            continue
        op = operator.group(1)
        value = (
            left_value + right_value
            if op == "+"
            else left_value - right_value
            if op == "-"
            else left_value | right_value
        )
        spelling = text[left_start:right_start] + right_spelling
        if value in cpu_values:
            add("CPU-power expression", left_start, spelling)
        if not allow_pwrap and value == pwrap_value:
            add("PWRAP expression", left_start, spelling)

    return findings


forbidden_fixtures = (
    "ARMPLL_CON0",
    "MCDI_WAKE_CTRL",
    "PWRAP_BASE",
    "0x1_000_c104",
    "0x009_600_00",
    "0x1_000_d000usize",
    "0x1000_c000 + 0x104",
    "0x1000_0000 | 0xc104",
    "268435456 + 49412",
    f"{0x1000_C104:d}u32",
    f"0b{0x1000_C104:b}",
    f"0o{0x1000_D000:o}usize",
    "ARMPLL_Δ",
)
allowed_fixtures = (
    "0x1000_c1040",
    "2684917800",
    "0x9600000",
    f"{0x1000_C104:d}.5",
    f"0.{0x1000_C104:d}",
    f"{0x1000_C104:d}e0",
    f"{0x1000_C104:d}f32",
    f"Δ{0x1000_C104:d}",
)

for fixture in forbidden_fixtures:
    if not classify(fixture, allow_pwrap=False):
        print(
            f"SEAM CHECK BUG: normalized detector missed forbidden fixture: {fixture}",
            file=sys.stderr,
        )
        raise SystemExit(1)
for fixture in allowed_fixtures:
    if classify(fixture, allow_pwrap=False):
        print(
            f"SEAM CHECK BUG: normalized detector false-matched allowed fixture: {fixture}",
            file=sys.stderr,
        )
        raise SystemExit(1)

problems: list[str] = []
for path in sorted(src.rglob("*.rs")):
    text = path.read_text(encoding="utf-8")
    for kind, start, spelling in classify(text, allow_pwrap=path.resolve() == m7):
        line = text.count("\n", 0, start) + 1
        problems.append(f"{path}:{line}: {kind}: {spelling}")

if problems:
    print(
        "SEAM DRIFT: forbidden exact-form PWRAP/CPU-power spelling or common expression present before #862/#879's accepted transaction seams:",
        file=sys.stderr,
    )
    print("\n".join(problems), file=sys.stderr)
    raise SystemExit(1)
PY

[[ "$rc" -eq 0 ]] && echo "board seam: no MT6739_* outside board::m7, no re-declared board consts, forbidden exact-form PWRAP/CPU-power spellings absent"
exit "$rc"
