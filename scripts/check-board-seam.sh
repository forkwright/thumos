#!/usr/bin/env bash
# check-board-seam.sh — the #534 standing invariant, enforced as source
# structure rather than prose. Fails when:
#   (a) an `MT6739_*` identifier appears anywhere in the kernel crate outside
#       board/m7.rs (the whole point of the seam; the ccci family is exempt —
#       its seam is klesis-protocol-vs-kernel-transport, not the board);
#   (b) a canonical board-MMIO hex value is re-DECLARED as a const outside
#       board/ (the pre-#534 duplication class: five CONSYS copies, three
#       UART0 copies). Literal appearances in comments and host-test fault
#       fixtures (arbitrary-MMIIO-address probes) are not declarations and
#       are allowed.
# Board constants live only under board::*; board selection happens once, in
# board/mod.rs.
set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
SRC="$REPO_ROOT/crates/thumos/src"

rc=0

# (a) No MT6739_* identifier outside board/m7.rs and the ccci family.
# The `+` (not `*`) keeps the prose glob "MT6739_*" from self-matching.
hits=$(grep -rn 'MT6739_[A-Z0-9_]\+' "$SRC" --include='*.rs' \
    | grep -v '/board/m7.rs:' \
    | grep -v '/ccci.rs:' | grep -v '/ccci_logger.rs:' || true)
if [ -n "$hits" ]; then
    echo "SEAM DRIFT: MT6739_* identifier outside board::m7 (kernel core must name the board seam, not the SoC):" >&2
    echo "$hits" >&2
    rc=1
fi

# (b) No re-declared board-MMIO const outside board/. Values are the
# canonical set absorbed by board/m7.rs (#534).
for hex in 0x1800_0000 0x180F_0000 0x1123_0000 0x1121_0000 0x1400_0000 \
           0x1400_7000 0x1400_8000 0x1400_D000 0x1400_1000 0x1001_0000 \
           0x1000_7000 0x1000_D000 0x1000_C104 0x1000_DC00 0x1100_A000 \
           0x1100_3000 0x77EE_0000 0x1100_2000 0x0C00_0000 0x0C00_2000; do
    hits=$(grep -rn "const [A-Z0-9_]*: usize = $hex" "$SRC" --include='*.rs' \
        | grep -v '/board/' || true)
    if [ -n "$hits" ]; then
        echo "SEAM DRIFT: board MMIO value $hex re-declared as a const outside board/:" >&2
        echo "$hits" >&2
        rc=1
    fi
done

[ "$rc" -eq 0 ] && echo "board seam: no MT6739_* outside board::m7, no re-declared board consts"
exit "$rc"
