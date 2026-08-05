#!/usr/bin/env bash
# surveillance-collect.sh — read-only surveillance-audit evidence collection (#556).
set -euo pipefail
# Re-gathers every artifact docs/surveillance/evidence-manifest.toml marks
# non-retained, against the connected device or any firmware image.
#
# READ-ONLY INVARIANT: this script NEVER mutates the device. No
# install/uninstall/disable, no `settings put`, no `input`, no `am`/`pm`
# verbs other than list/dump, no root, no file pushes, no writes outside
# /sdcard-avoiding dumpsys/getprop/cat queries. Every command below is a
# query (getprop, dumpsys, pm list, cat, sha256sum of READ-ONLY APK paths,
# ss/netstat, ps, date). If you add a command, it must keep that invariant.
#
# Usage: scripts/surveillance-collect.sh [outdir]
#   outdir defaults to docs/surveillance/evidence/<build-fingerprint-sanitized>/
# Requires: adb in PATH, a device connected and authorized.

say() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

have adb || { echo "FAIL: adb not in PATH" >&2; exit 1; }
adb get-state 1>/dev/null 2>&1 || { echo "FAIL: no authorized device (adb get-state)" >&2; exit 1; }

FINGERPRINT=$(adb shell getprop ro.build.fingerprint | tr -d '\r')
SAFE=$(printf '%s' "$FINGERPRINT" | tr '/: ' '___')
OUT="${1:-docs/surveillance/evidence/$SAFE}"
mkdir -p "$OUT"
printf 'collecting into %s (fingerprint: %s)\n' "$OUT" "$FINGERPRINT"

# -- Session metadata (tool versions + timestamps, the gap from the 2026-03-18 session)
{
    echo "collection_utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "adb_version: $(adb version | head -1)"
    echo "host_uname: $(uname -a)"
    echo "device_date: $(adb shell date | tr -d '\r')"
    echo "device_uptime: $(adb shell uptime | tr -d '\r')"
} > "$OUT/session.txt"

# -- Firmware identity
adb shell getprop > "$OUT/getprop.txt"
grep -E 'ro.build.fingerprint|ro.build.display.id|ro.build.date.utc|ro.build.version.incremental|ro.product.model' \
    "$OUT/getprop.txt" > "$OUT/firmware-identity.txt" || true # a missing prop line must not abort the whole collection

# -- Partition/block state
adb shell cat /proc/partitions > "$OUT/proc-partitions.txt"
adb shell cat /proc/mounts > "$OUT/proc-mounts.txt"

# -- Package inventory + APK hashes (read-only)
adb shell pm list packages -f -i -U > "$OUT/packages-full.txt"
# SHA-256 every APK path the package manager reports (paths are read by
# hash; nothing is pulled or written).
adb shell 'for p in $(pm list packages -f | sed "s/package://;s/=.*//"); do sha256sum "$p" 2>/dev/null; done' \
    > "$OUT/apk-sha256.txt"

# -- The surveillance-relevant package set from the manifest
PACKAGES=(
com.adups.fota
com.adups.fota.sysoper
com.mediatek.dm
com.mediatek.gpslocationupdate
com.mediatek.location.lppe.main
com.mediatek.location.mtknlp
com.mediatek.nlpservice
com.mediatek.mtklogger
com.mediatek.mtklogger.proxy
com.mediatek.engineermode
com.mediatek.omacp
com.zhiliaoapp.musically
com.whatsapp
com.loudtalks
freeme
com.freeme.provider.badge
com.freeme.factory
)
mkdir -p "$OUT/packages"
for pkg in "${PACKAGES[@]}"; do
    adb shell dumpsys package "$pkg" > "$OUT/packages/$pkg.txt" 2>&1 || true # an absent package must not abort the set; the empty dump records its absence as evidence
done

# -- Runtime state
adb shell dumpsys activity services > "$OUT/activity-services.txt"
adb shell dumpsys jobscheduler > "$OUT/jobscheduler.txt"
adb shell ps -A > "$OUT/ps.txt" 2>/dev/null || adb shell ps > "$OUT/ps.txt"
if adb shell ss -tup > "$OUT/connections.txt" 2>/dev/null; then
    :
else
    adb shell netstat -tup > "$OUT/connections.txt" 2>/dev/null || \
        { echo "NOTE: neither ss nor netstat available" > "$OUT/connections.txt"; }
fi

# -- Hashes of everything collected (deterministic integrity record)
( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )

printf 'done: %s artifacts, hashed in %s\n' "$(find "$OUT" -type f | wc -l)" "$OUT/SHA256SUMS"
printf 'next: scripts/surveillance-render.py %s\n' "$OUT"
