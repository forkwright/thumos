# Dev boot keypair -- NOT A SECRET, NEVER SHIPPABLE

DEV-ONLY Ed25519 trust anchor for CI / host-test / qemu / bring-up builds.
Both halves are committed ON PURPOSE (the AOSP test-keys pattern): any
developer can sign dev images, and host tests round-trip sign->verify
against the real embedded anchor.

`build.rs` (#233) makes shipping this key structurally impossible: a
`--features production` build refuses it byte-for-byte and requires a real
key via `THUMOS_BOOT_KEY_PUB=<path to 64-hex-char public key file>`. The
production private key lives offline (Titan security key / air-gapped
machine) and its public half is delivered at build time only -- never
committed (`keys/.gitignore` blocks `production/` and `*.pem`).

Even so, a dev-anchored image can never establish trust on real hardware:
the #217 boot gate sets `secure_boot_ok` only when `BOOT_KEY_IS_PRODUCTION`
is true, so a dev/default build boots degraded-locked on a device.

Every image bakes a grep-able stamp: `THUMOS-BOOT-TRUST:{PROD|DEV}:<key
fingerprint>` (also printed on the boot banner), so a dev-keyed image can
never be mistaken for a production-trusted one.
