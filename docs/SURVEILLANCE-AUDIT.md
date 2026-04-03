# Surveillance audit: AGM M7 stock firmware

Audit date: 2026-03-18. Read-only ADB inspection of unmodified device.

## Summary

The stock firmware contains at least 3 distinct surveillance/telemetry systems from different actors. The device as shipped is compromised at the system level, with privileged packages that have irrevocable access to SMS, call logs, location, contacts, camera, microphone, and storage. The user cannot disable these without root access.

## Threat 1: Adups FOTA (Chinese OTA framework)

**Package**: `com.adups.fota` (v5.24) + `com.adups.fota.sysoper`
**Actor**: Shanghai Adups Technology Co., Ltd.
**Known history**: Flagged by Kryptowire in November 2016 for exfiltrating full SMS message bodies, call logs, contacts, IMEI, IMSI, and installed app lists to servers in China every 72 hours. Found on 700M+ devices worldwide (BLU, ZTE, Archos, myPhone, etc.). The company claimed this was "accidental" but the functionality was architected into the firmware at the factory level.

**On this device**:
- Installed as system app (cannot be uninstalled without root)
- INTERNET + ACCESS_NETWORK_STATE + ACCESS_WIFI_STATE + RECEIVE_BOOT_COMPLETED granted
- Runs scheduled jobs on boot (`MyJobService`, `MyIntentJobService`)
- Monitors BOOT_COMPLETED, DATE_CHANGED, ACTION_POWER_DISCONNECTED, MEDIA_MOUNTED events
- The sysoper component has REBOOT + RECOVERY permissions (can remotely trigger factory reset)
- No network traffic observed in this session (jobs were cancelled), but the scheduled job infrastructure is active and runs on every boot

**Risk**: HIGH. Known data exfiltration framework with factory-level integration. Even if the current version has been "cleaned up" since 2016, the architecture allows silent updates that reintroduce exfiltration. The sysoper package can reboot and flash the device remotely.

## Threat 2: MediaTek device management (com.mediatek.dm)

**Package**: `com.mediatek.dm`
**Actor**: MediaTek Inc. (Taiwan, but subject to Chinese government pressure via TSMC supply chain)

**Permissions** (all granted, SYSTEM_FIXED, irrevocable):

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

This single package has total device access: it can read every SMS, record audio, access the camera, track location, make calls, wipe the device, and inject input events (simulate touches/keystrokes). All permissions are SYSTEM_FIXED, meaning they cannot be revoked through Android's permission manager.

**Risk**: CRITICAL. This is an OMA-DM (Open Mobile Alliance Device Management) client that carriers and the OEM can use for remote device provisioning. But the permission set far exceeds what OMA-DM requires. The INJECT_EVENTS + CAMERA + RECORD_AUDIO combination is indistinguishable from a remote access trojan.

## Threat 3: MediaTek location services

**Packages**:
- `com.mediatek.gpslocationupdate` (GPS location reporting)
- `com.mediatek.location.lppe.main` (LPPe location service, actively running)
- `com.mediatek.location.mtknlp` (MediaTek network location provider, actively running)
- `com.mediatek.nlpservice` (NLP service, actively running)

Three location services are running continuously in the background. LPPe (Location Protocol Profile extensions) is a carrier-grade positioning protocol that combines GPS, cell tower, WiFi, and sensor data for enhanced location accuracy. This data is shared with the carrier and potentially MediaTek's location services.

`com.mediatek.gpslocationupdate` has the same massive permission set as `com.mediatek.dm`, including MASTER_CLEAR, CRYPT_KEEPER, DELETE_PACKAGES, MANAGE_PROFILE_AND_DEVICE_OWNERS, and OEM_UNLOCK_STATE. This is not a location service. It's a full device management agent disguised as a location service.

**Risk**: HIGH. Continuous location tracking with carrier-grade precision, combined with full device management capabilities.

## Threat 4: MediaTek logging and diagnostics

**Packages**:
- `com.mediatek.mtklogger` (READ_LOGS, READ_FRAME_BUFFER, DUMP, system alert window)
- `com.mediatek.mtklogger.proxy` (vendor partition, mediates log access)
- `com.mediatek.engineermode` (hardware diagnostics, IMEI access, radio control)

MTKLogger can read all system logs (including other apps' log output), capture screen contents (READ_FRAME_BUFFER), and runs on boot. Combined with INTERNET access, this is a complete device surveillance capability.

EngineerMode provides direct hardware access including baseband AT commands, radio parameters, and device identifiers. While primarily a diagnostic tool, it's an attack surface: any app that can launch EngineerMode activities can access radio hardware directly.

**Risk**: MEDIUM. Primarily diagnostic tools, but the permission set enables surveillance if the packages are compromised or remotely updated.

## Threat 5: OMA Client Provisioning (com.mediatek.omacp)

**Package**: `com.mediatek.omacp`
**Purpose**: Allows carriers to remotely configure APN settings, bookmarks, email accounts, and WiFi networks via specially formatted SMS messages (WAP Push).

**Permissions**: RECEIVE_WAP_PUSH, RECEIVE_SMS, CALL_PHONE, BLUETOOTH_ADMIN, CHANGE_NETWORK_STATE, INSTALL_DRM

**Risk**: MEDIUM. OMA-CP is a known attack vector: a crafted SMS can reconfigure the device's APN to route all traffic through an attacker's proxy. The device will apply the configuration silently. This is a documented technique used by nation-states for targeted surveillance (see Checkpoint Research, 2019).

## Threat 6: Pre-installed social media

**Packages**: `com.zhiliaoapp.musically` (TikTok), `com.whatsapp` (WhatsApp), `com.loudtalks` (Zello)

TikTok is pre-installed as a system app. ByteDance (TikTok's parent) is subject to Chinese national security law requiring cooperation with intelligence services. WhatsApp shares metadata with Meta. Both have full internet access and broad permissions.

**Risk**: MEDIUM. These can be disabled or uninstalled (they're not in /system/priv-app, just /system/app), but their presence as factory defaults indicates the OEM's relationship with these platforms.

## Threat 7: Freeme OS framework

**Packages**: `freeme` (framework), `com.freeme.provider.badge`, `com.freeme.factory`

Freeme OS is a Chinese Android customization framework (similar to MIUI, ColorOS). It's the UI layer provided by TYD Technology. The `freeme` framework package runs at the framework level, meaning it has access to all Android framework internals. Badge provider and factory test are lower-risk utility apps.

**Risk**: LOW-MEDIUM. The framework package runs with system privileges. Without decompiling the APK, its exact behavior is unknown. Freeme OS has no public security audit history.

## Active services at time of probe

| Service | Package | Status |
|---------|---------|--------|
| NlpLocationService | com.mediatek.location.mtknlp | Running |
| LPPeServiceWrapper | com.mediatek.location.lppe.main | Running |
| NlpService | com.mediatek.nlpservice | Running |
| MyJobService | com.adups.fota | Scheduled (cancelled in this session) |

## Network connections at time of probe

| Local | Remote | Proto | Purpose |
|-------|--------|-------|---------|
| 21.28.129.209:42318 | 10.166.154.5:5060 | TCP | Carrier IMS/SIP (VoLTE) |
| 21.28.129.209:50001 | 10.166.154.5:65529 | TCP | Carrier IMS control |

Only carrier IMS traffic observed. WiFi was connected but no outbound connections to surveillance infrastructure during the probe window. This does not mean no exfiltration occurs  -  Adups typically exfiltrates on a 72-hour cycle, and the device may have been recently powered on.

## Conclusion

The stock AGM M7 firmware contains at minimum:
- A known Chinese data exfiltration framework (Adups) with boot persistence and remote reboot capability
- A device management agent (MediaTek DM) with permissions equivalent to a remote access trojan
- Continuous background location tracking via 3 separate services
- A carrier remote provisioning system vulnerable to SMS-based APN hijacking
- Pre-installed Chinese social media (TikTok) subject to national security cooperation requirements

None of these can be disabled by the user without root access. All are SYSTEM_FIXED. This is the baseline threat that thumos exists to eliminate.
