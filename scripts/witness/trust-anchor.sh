#!/usr/bin/env bash
set -euo pipefail

# witness/trust-anchor.sh — trust-anchor build guard (#233), verbatim from
# ci.yml. A production image must FAIL to build without a provisioned key,
# must REFUSE the committed (deliberately public) dev key, and must BUILD
# with a real key — proven here with an ephemeral one. Dev/qemu/host builds
# keep building keylessly.
source "$(dirname "$0")/lib.sh"

cd "$KERNEL_DIR"
if cargo check --release --target armv7a-none-eabi --features production 2>keyless-err.log; then
    echo 'FAIL: production build succeeded without THUMOS_BOOT_KEY_PUB'; exit 1
fi
grep -q 'THUMOS_BOOT_KEY_PUB' keyless-err.log || { echo 'FAIL: keyless production error lacks provisioning message'; cat keyless-err.log; exit 1; }
if THUMOS_BOOT_KEY_PUB=keys/dev/boot-dev.pub cargo check --release --target armv7a-none-eabi --features production 2>devkey-err.log; then
    echo 'FAIL: production build accepted the dev key'; exit 1
fi
openssl genpkey -algorithm ed25519 -out /tmp/ci-boot.pem
openssl pkey -in /tmp/ci-boot.pem -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n' > /tmp/ci-boot.pub
THUMOS_BOOT_KEY_PUB=/tmp/ci-boot.pub cargo check --release --target armv7a-none-eabi --features production
echo "trust-anchor witness: PASS"
