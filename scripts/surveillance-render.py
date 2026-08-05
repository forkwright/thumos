#!/usr/bin/env python3
"""surveillance-render.py — deterministic evidence renderer (issue #556).

Reads an evidence directory produced by scripts/surveillance-collect.sh plus
docs/surveillance/evidence-manifest.toml, and emits SURVEILLANCE-EVIDENCE.md:
derived tables (per-package granted permissions, running services, network
connections, APK hashes) and the claim-coverage report (which manifest
claims are backed by retained/collected evidence and which still need
recollection).

Deterministic: sorted output, no wall clock, no host identity. The audit
narrative stays hand-written; every TABLE in it must trace to this output.
"""
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "docs" / "surveillance" / "evidence-manifest.toml"

# Permissions the audit narrative cares about (its table rows), sorted.
TRACKED_PERMS = sorted({
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.USE_SIP",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.MASTER_CLEAR", "android.permission.REBOOT",
    "android.permission.MODIFY_PHONE_STATE", "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.INTERNET", "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE", "android.permission.CONNECTIVITY_INTERNAL",
    "android.permission.MANAGE_NETWORK_POLICY", "android.permission.INJECT_EVENTS",
    "android.permission.DUMP", "android.permission.FORCE_STOP_PACKAGES",
    "android.permission.STOP_APP_SWITCHES", "android.permission.INTERACT_ACROSS_USERS_FULL",
    "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE", "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.BLUETOOTH_ADMIN", "android.permission.INSTALL_DRM",
    "android.permission.READ_LOGS", "android.permission.READ_FRAME_BUFFER",
    "android.permission.CRYPT_KEEPER", "android.permission.DELETE_PACKAGES",
    "android.permission.MANAGE_PROFILE_AND_DEVICE_OWNERS", "android.permission.OEM_UNLOCK_STATE",
})


def granted_permissions(dump: str) -> list[str]:
    """Granted permissions from a `dumpsys package` text, filtered to the
    tracked set, sorted. Matches both '...: granted=true' and the older
    flat listed style."""
    out = set()
    for m in re.finditer(r"(android\.permission\.[A-Z_]+)(?::\s*granted=(true|false))?", dump):
        name, granted = m.group(1), m.group(2)
        if granted == "false":
            continue
        if name in TRACKED_PERMS:
            out.add(name)
    return sorted(out)


def main() -> int:
    evdir = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if evdir is None or not evdir.is_dir():
        print("usage: surveillance-render.py <evidence-dir>\n"
              "(produce one with scripts/surveillance-collect.sh)", file=sys.stderr)
        return 2

    manifest = tomllib.loads(MANIFEST.read_text())
    lines: list[str] = []
    a = lines.append

    a("# Surveillance evidence report (derived — do not hand-edit)")
    a("")
    a(f"Firmware fingerprint: `{manifest['firmware']['fingerprint']}`")
    a(f"Evidence directory: `{evdir}`")
    a("")

    # -- Firmware identity
    ident = evdir / "firmware-identity.txt"
    if ident.exists():
        a("## Firmware identity")
        a("")
        a("```")
        a(ident.read_text().strip())
        a("```")
        a("")

    # -- Per-package granted permissions
    pkgdir = evdir / "packages"
    if pkgdir.is_dir():
        a("## Granted permissions (tracked set, from dumpsys package)")
        a("")
        for dump_path in sorted(pkgdir.glob("*.txt")):
            perms = granted_permissions(dump_path.read_text(errors="ignore"))
            a(f"### `{dump_path.stem}`")
            if perms:
                for p in perms:
                    short = p.removeprefix("android.permission.")
                    a(f"- {short}")
            else:
                a("- (none of the tracked permissions found — check the dump)")
            a("")

    # -- Running services (lines mentioning the audit's packages)
    svc = evdir / "activity-services.txt"
    if svc.exists():
        names = [c["id"] for c in manifest.get("claim", []) if c["id"] == "S.services-table"]
        a("## Service listing excerpt (audit-relevant packages)")
        a("")
        a("```")
        hits = [
            ln for ln in svc.read_text(errors="ignore").splitlines()
            if any(k in ln for k in ("mediatek", "adups", "freeme", "ServiceRecord"))
        ]
        a("\n".join(hits) if hits else "(no audit-relevant services in the listing)")
        a("```")
        a("")
        del names

    # -- Connections
    conn = evdir / "connections.txt"
    if conn.exists():
        a("## Network connections at collection time")
        a("")
        a("```")
        a(conn.read_text(errors="ignore").strip())
        a("```")
        a("")

    # -- APK hashes
    hashes = evdir / "apk-sha256.txt"
    if hashes.exists():
        a("## APK SHA-256")
        a("")
        a("```")
        a(hashes.read_text(errors="ignore").strip())
        a("```")
        a("")

    # -- Claim coverage
    a("## Claim coverage (from evidence-manifest.toml)")
    a("")
    a("| claim | label | evidence status |")
    a("|---|---|---|")
    for c in manifest.get("claim", []):
        missing = any("not retained" in e for e in c.get("evidence", []))
        status = "recollectable (collector output present)" if missing and pkgdir.is_dir() else (
            "needs recollection" if missing else "retained"
        )
        a(f"| {c['id']} | {c['label']} | {status} |")
    a("")

    out = evdir / "SURVEILLANCE-EVIDENCE.md"
    out.write_text("\n".join(lines))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
