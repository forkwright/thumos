# Surveillance audit: AGM M7 stock firmware

Audit date: 2026-03-18. Read-only ADB inspection of unmodified device.
Firmware: `AGM/Q12_1/Q12_1:8.1.0/OPM1.171019.026/L1635.6.01.01:user/release-keys` (build 2022-03-22, Freeme OS 8.1.1 over Android 8.1.0).

## Epistemics (issue #556)

Every material claim in this document carries one of four labels:

- **[OBSERVED]** — directly measured on THIS device. The 2026-03-18 session predates evidence retention, so the audit marks most raw dumps *not retained — recollect*: they are re-gatherable byte-exactly by `scripts/surveillance-collect.sh` against this or another image, and the claim must be re-checked then.
- **[CAPABILITY]** — the package COULD do this given its granted permissions or privileged position. **Not** a claim of observed execution.
- **[EXTERNAL]** — reported by an outside source (cited in References). Not measured here.
- **[INFERENCE]** — analyst judgment over the above. Carries uncertainty. Stated where it matters.

The claim-to-evidence index (claim IDs below) lives in `docs/surveillance/evidence-manifest.toml`; derived tables come from `scripts/surveillance-render.py`. Session limits are in the manifest: single session, one-instant network listing, and the audit cancelled the Adups jobs during inspection.

## Summary

The stock firmware contains at least 3 distinct surveillance/telemetry systems from different actors. As shipped, privileged system packages compromise the device, holding irrevocable access to SMS, call logs, location, contacts, camera, microphone, and storage **[OBSERVED — permission sets, not retained]**. Without root access the user cannot disable these **[OBSERVED — SYSTEM_FIXED grant flags, not retained]**.

## Threat 1: Adups FOTA (Chinese OTA framework)

**Package**: `com.adups.fota` (v5.24) + `com.adups.fota.sysoper` — `T1.adups-present` **[OBSERVED, not retained]**
**Actor**: Shanghai Adups Technology Co., Ltd.
**Known history**: Flagged by Kryptowire in November 2016 for exfiltrating full SMS message bodies, call logs, contacts, IMEI, IMSI, and installed app lists to servers in China every 72 hours. Found on 700M+ devices worldwide (BLU, ZTE, Archos, myPhone, etc.). The company claimed this was "accidental," but it built the functionality into the firmware at the factory level. — `T1.adups-history` **[EXTERNAL: Kryptowire advisory, Nov 2016]**

**On this device**:
- Installed as system app (the user cannot uninstall it without root) **[OBSERVED, not retained]**
- INTERNET + ACCESS_NETWORK_STATE + ACCESS_WIFI_STATE + RECEIVE_BOOT_COMPLETED granted — `T1.adups-permissions` **[OBSERVED, not retained]**
- Runs scheduled jobs on boot (`MyJobService`, `MyIntentJobService`) **[OBSERVED, not retained]**
- Monitors BOOT_COMPLETED, DATE_CHANGED, ACTION_POWER_DISCONNECTED, MEDIA_MOUNTED events **[OBSERVED, not retained]**
- The sysoper component has REBOOT + RECOVERY permissions (can remotely trigger factory reset) **[CAPABILITY]**
- No network traffic observed in this session (the audit cancelled the jobs), but the scheduled job infrastructure is active and runs on every boot — `T1.adups-no-traffic` **[OBSERVED — one instant only: Adups historically exfiltrates on a 72-hour cycle]**

**Risk**: HIGH — `T1.adups-risk` **[INFERENCE]** over the Kryptowire history **[EXTERNAL]** plus the on-device permission/jobset **[OBSERVED]**. Even if the current version has been "cleaned up" since 2016, the architecture allows silent updates that reintroduce exfiltration. The sysoper package can reboot and flash the device remotely **[CAPABILITY]**.

## Threat 2: MediaTek device management (com.mediatek.dm)

**Package**: `com.mediatek.dm`
**Actor**: MediaTek Inc. (Taiwan, but subject to Chinese government pressure via TSMC supply chain) **[EXTERNAL — supply-chain analysis, not device evidence]**

**Permissions** (all granted, SYSTEM_FIXED, irrevocable) — `T2.dm-permissions` **[OBSERVED, not retained]**:

| Category | Permissions |
|----------|-------------|
| Communications | READ_SMS, RECEIVE_SMS, SEND_SMS, READ_CALL_LOG, WRITE_CALL_LOG, CALL_PHONE, PROCESS_OUTGOING_CALLS, USE_SIP |
| Location | ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION |
| Contacts | READ_CONTACTS, WRITE_CONTACTS, GET_ACCOUNTS |
| Storage | READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE |
| Camera/Mic | CAMERA, RECORD_AUDIO |
| Device | MASTER_CLEAR, REBOOT, MODIFY_PHONE_STATE, WRITE_SECURE_SETTINGS, INTERNET |
| Network | CHANGE_NETWORK_STATE, CHANGE_WIFI_STATE, CONNECTIVITY_INTERNAL, MANAGE_NETWORK_POLICY |
| System | INJECT_EVENTS, DUMP, FORCE_STOP_PACKAGES, STOP_APP_SWITCHES, INTERACT_ACROSS_USERS_FULL |

This single package has total device access: it can read every SMS, record audio, access the camera, track location, make calls, wipe the device, and inject input events (simulate touches/keystrokes). All permissions carry the SYSTEM_FIXED flag, meaning Android's permission manager cannot revoke them. — `T2.dm-total-access` **[CAPABILITY]**

**Risk**: CRITICAL — `T2.dm-risk` **[INFERENCE]**. This is an OMA-DM (Open Mobile Alliance Device Management) client that carriers and the OEM can use for remote device provisioning. But the permission set far exceeds what OMA-DM requires **[INFERENCE — what OMA-DM functionally requires is itself an analyst judgment]**. The INJECT_EVENTS + CAMERA + RECORD_AUDIO combination is indistinguishable from a remote access trojan — `T2.dm-rat-equivalence` **[INFERENCE: a statement about the permission profile, not about observed use]**.

## Threat 3: MediaTek location services

**Packages**:
- `com.mediatek.gpslocationupdate` (GPS location reporting)
- `com.mediatek.location.lppe.main` (LPPe location service, actively running)
- `com.mediatek.location.mtknlp` (MediaTek network location provider, actively running)
- `com.mediatek.nlpservice` (NLP service, actively running)

Three location services are running continuously in the background. — `T3.location-services-running` **[OBSERVED, not retained]**. LPPe (Location Protocol Profile extensions) is a carrier-grade positioning protocol that combines GPS, cell tower, WiFi, and sensor data for enhanced location accuracy **[EXTERNAL — protocol role]**. The device shares this data with the carrier and potentially MediaTek's location services — `T3.location-data-shared` **[INFERENCE: the sharing path is architectural — no traffic capture exists for these services]**.

`com.mediatek.gpslocationupdate` has the same massive permission set as `com.mediatek.dm`, including MASTER_CLEAR, CRYPT_KEEPER, DELETE_PACKAGES, MANAGE_PROFILE_AND_DEVICE_OWNERS, and OEM_UNLOCK_STATE. This is not a location service. It's a full device management agent disguised as a location service. — `T3.gpslocationupdate-agent` **[OBSERVED for the permission set, not retained; the "what it is" framing is CAPABILITY/INFERENCE]**

**Risk**: HIGH — `T3.risk` **[INFERENCE]**. Continuous location tracking with carrier-grade precision **[OBSERVED: services running]**, combined with full device management capabilities **[CAPABILITY]**.

## Threat 4: MediaTek logging and diagnostics

**Packages**:
- `com.mediatek.mtklogger` (READ_LOGS, READ_FRAME_BUFFER, DUMP, system alert window)
- `com.mediatek.mtklogger.proxy` (vendor partition, mediates log access)
- `com.mediatek.engineermode` (hardware diagnostics, IMEI access, radio control)

MTKLogger can read all system logs (including other apps' log output), capture screen contents (READ_FRAME_BUFFER), and runs on boot. Combined with INTERNET access, this is a complete device surveillance capability. — `T4.mtklogger-capability` **[CAPABILITY]**

EngineerMode provides direct hardware access including baseband AT commands, radio parameters, and device identifiers. While primarily a diagnostic tool, it's an attack surface: any app that can launch EngineerMode activities can access radio hardware directly. — `T4.engineermode-surface` **[CAPABILITY]**

**Risk**: MEDIUM — `T4.risk` **[INFERENCE]**. Primarily diagnostic tools, but the permission set enables surveillance if an attacker compromises the packages or remotely updates them **[CAPABILITY]**.

## Threat 5: OMA Client Provisioning (com.mediatek.omacp)

**Package**: `com.mediatek.omacp`
**Purpose**: Allows carriers to remotely configure APN settings, bookmarks, email accounts, and WiFi networks via specially formatted SMS messages (WAP Push) **[EXTERNAL — protocol purpose]**.

**Permissions**: RECEIVE_WAP_PUSH, RECEIVE_SMS, CALL_PHONE, BLUETOOTH_ADMIN, CHANGE_NETWORK_STATE, INSTALL_DRM — `T5.omacp-permissions` **[OBSERVED, not retained]**

**Risk**: MEDIUM — `T5.risk` **[INFERENCE]**. OMA-CP is a known attack vector: a crafted SMS can reconfigure the device's APN to route all traffic through an attacker's proxy. The device will apply the configuration silently. This is a documented technique used by nation-states for targeted surveillance — `T5.omacp-vector` **[EXTERNAL: Check Point Research, 2019]**.

## Threat 6: Pre-installed social media

**Packages**: `com.zhiliaoapp.musically` (TikTok), `com.whatsapp` (WhatsApp), `com.loudtalks` (Zello) — `T6.preinstalled-social` **[OBSERVED, not retained]**

TikTok is pre-installed as a system app. ByteDance (TikTok's parent) is subject to Chinese national security law requiring cooperation with intelligence services — `T6.bytedance-law` **[EXTERNAL: PRC National Intelligence Law, 2017, Art. 7]**. WhatsApp shares metadata with Meta **[EXTERNAL — Meta policy]**. Both have full internet access and broad permissions **[OBSERVED, not retained]**.

**Risk**: MEDIUM **[INFERENCE]**. The user can disable or uninstall these (they're not in /system/priv-app, just /system/app) **[OBSERVED, not retained]**, but their presence as factory defaults indicates the OEM's relationship with these platforms — `T6.oem-relationship` **[INFERENCE]**.

## Threat 7: Freeme OS framework

**Packages**: `freeme` (framework), `com.freeme.provider.badge`, `com.freeme.factory`

Freeme OS is a Chinese Android customization framework (similar to MIUI, ColorOS). It's the UI layer provided by TYD Technology. The `freeme` framework package runs at the framework level, meaning it has access to all Android framework internals. — `T7.freeme-framework` **[OBSERVED, not retained]**. Badge provider and factory test are lower-risk utility apps **[INFERENCE]**.

**Risk**: LOW-MEDIUM **[INFERENCE]**. The framework package runs with system privileges. Without decompiling the APK, no one has verified its exact behavior. Freeme OS has no public security audit history. — `T7.freeme-unknown` **[EXTERNAL: an absence-of-publications claim — this audit did not decompile the APK]**.

## Active services at time of probe

`S.services-table` **[OBSERVED, not retained — one session's listing]**

| Service | Package | Status |
|---------|---------|--------|
| NlpLocationService | com.mediatek.location.mtknlp | Running |
| LPPeServiceWrapper | com.mediatek.location.lppe.main | Running |
| NlpService | com.mediatek.nlpservice | Running |
| MyJobService | com.adups.fota | Scheduled (cancelled in this session) |

## Network connections at time of probe

`N.connections-table` **[OBSERVED, not retained — one instant, not a capture window]**

| Local | Remote | Proto | Purpose |
|-------|--------|-------|---------|
| 21.28.129.209:42318 | 10.166.154.5:5060 | TCP | Carrier IMS/SIP (VoLTE) |
| 21.28.129.209:50001 | 10.166.154.5:65529 | TCP | IMS control |

Only carrier IMS traffic observed. The device stayed connected to WiFi, but no outbound connections to surveillance infrastructure occurred during the probe window — `N.no-surveillance-traffic` **[OBSERVED — does not establish absence of exfiltration across a 72-hour cycle]**. Adups typically exfiltrates on a 72-hour cycle **[EXTERNAL]**, and the device may have been recently powered on.

## Conclusion

`C.device-conclusions` **[INFERENCE]** over the claims above:

The stock AGM M7 firmware contains at minimum:
- A known Chinese data exfiltration framework (Adups) **[EXTERNAL]** with boot persistence and remote reboot capability **[OBSERVED + CAPABILITY]**
- A device management agent (MediaTek DM) with permissions equivalent to a remote access trojan **[OBSERVED the set — CAPABILITY the equivalence]**
- Continuous background location tracking via 3 separate services **[OBSERVED]**
- A carrier remote provisioning system vulnerable to SMS-based APN hijacking **[CAPABILITY + EXTERNAL]**
- Pre-installed Chinese social media (TikTok) subject to national security cooperation requirements **[OBSERVED + EXTERNAL]**

The user cannot disable any of these without root access. All carry the SYSTEM_FIXED flag **[OBSERVED, not retained]**. This is the baseline threat that thumos exists to eliminate **[INFERENCE — project mission framing]**.

## References

- Kryptowire / Adups FOTA disclosure, November 2016 (public reporting — see e.g. contemporaneous coverage of the BLU device findings).
- Check Point Research, "Advanced SMS Phishing — OMA CP Provisioning Messages", 2019.
- PRC National Intelligence Law, 2017 (Article 7).
- LPPe / OMA Location Protocol — public protocol documentation.

## Reproduction

- Evidence manifest + claim index: `docs/surveillance/evidence-manifest.toml`
- Recollect every non-retained artifact (read-only): `scripts/surveillance-collect.sh`
- Derive the evidence report: `scripts/surveillance-render.py <evidence-dir>`
- Retained artifacts (SHA-256 in the manifest): `docs/full-props.txt`, `docs/kernel-config-stock`
