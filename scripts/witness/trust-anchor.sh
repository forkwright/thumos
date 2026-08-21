#!/usr/bin/env bash
set -euo pipefail

# witness/trust-anchor.sh — trust-anchor build guard (#233, #869), verbatim from
# ci.yml. A production image must FAIL to build without a provisioned key,
# must REFUSE the committed (deliberately public) dev key, and must BUILD
# with a real key — proven here with an ephemeral one. Dev/qemu/host builds
# keep building keylessly.
#
# The image carries TWO anchors and each is proved separately: the boot anchor
# (#233) authenticates the kernel image, and the provisioning anchor (#869)
# authenticates credential bundles. They are separate trust domains, so build.rs
# also refuses a provisioning key equal to the boot key — proved below, because
# a guard nobody exercises is a guard nobody knows is wired.
#
# WHY --locked (#757): crates/thumos keeps its own lockfile; without --locked
# a manifest/lock disagreement here is silently resolved and rewritten
# instead of failing the build.
source "$(dirname "$0")/lib.sh"

cd "$KERNEL_DIR"

# WHY every artifact this script writes goes in one private temp dir: the step
# below generates an ed25519 PRIVATE key, and it used a fixed shared-temp path.
# That path is world-predictable -- any process on the box can read the key, and
# one that pre-creates a symlink there redirects the write somewhere of its
# choosing. `mktemp -d` gives an unpredictable 0700 directory instead, and the
# EXIT trap removes it even when a check below fails and exits early. The two
# build logs move here for a duller reason: they were written into the kernel
# directory, are not gitignored, and left the tree dirty after every local run.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if cargo check --release --target armv7a-none-eabi --locked --features production 2>"$work/keyless-err.log"; then
    echo 'FAIL: production build succeeded without THUMOS_BOOT_KEY_PUB'; exit 1
fi
grep -q 'THUMOS_BOOT_KEY_PUB' "$work/keyless-err.log" || { echo 'FAIL: keyless production error lacks provisioning message'; cat "$work/keyless-err.log"; exit 1; }
if THUMOS_BOOT_KEY_PUB=keys/dev/boot-dev.pub cargo check --release --target armv7a-none-eabi --locked --features production 2>"$work/devkey-err.log"; then
    echo 'FAIL: production build accepted the dev key'; exit 1
fi
mint_key() {
    openssl genpkey -algorithm ed25519 -out "$work/ci-$1.pem"
    openssl pkey -in "$work/ci-$1.pem" -pubout -outform DER \
        | tail -c 32 | od -An -tx1 | tr -d ' \n' > "$work/ci-$1.pub"
}
mint_key boot
mint_key provision

# #869: a production image needs a provisioning anchor too. Checked with a valid
# boot key already in hand, so a failure here can only be the provisioning
# guard.
if THUMOS_BOOT_KEY_PUB="$work/ci-boot.pub" cargo check --release --target armv7a-none-eabi --locked --features production 2>"$work/no-provision-err.log"; then
    echo 'FAIL: production build succeeded without THUMOS_PROVISION_KEY_PUB'; exit 1
fi
grep -q 'THUMOS_PROVISION_KEY_PUB' "$work/no-provision-err.log" || { echo 'FAIL: missing-provisioning-anchor error lacks the provisioning message'; cat "$work/no-provision-err.log"; exit 1; }

# #869: the two anchors are separate trust domains. One key serving both would
# let an authority able to sign an image also sign credentials, which is not the
# delegation anyone chose — so build.rs refuses it and this proves it does.
if THUMOS_BOOT_KEY_PUB="$work/ci-boot.pub" THUMOS_PROVISION_KEY_PUB="$work/ci-boot.pub" cargo check --release --target armv7a-none-eabi --locked --features production 2>"$work/same-key-err.log"; then
    echo 'FAIL: production build accepted the boot key as the provisioning anchor'; exit 1
fi

THUMOS_BOOT_KEY_PUB="$work/ci-boot.pub" THUMOS_PROVISION_KEY_PUB="$work/ci-provision.pub" cargo check --release --target armv7a-none-eabi --locked --features production
echo "trust-anchor witness: PASS"
