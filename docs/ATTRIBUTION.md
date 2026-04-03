# Surveillance attribution: who is responsible for what

Based on APK decompilation and permission analysis of the AGM M7 stock firmware.

## Attribution summary

| Threat | Responsible entity | Nation | Role | Risk |
|--------|-------------------|--------|------|------|
| Adups FOTA + Firebase + Google Ads | Shanghai Adups Technology + Google | China + US | OTA updates, telemetry, ad tracking | CRITICAL |
| MediaTek DM | MediaTek Inc. | Taiwan | Device management, carrier provisioning | CRITICAL |
| MediaTek location stack | MediaTek Inc. | Taiwan | Continuous GPS/cell/WiFi location | HIGH |
| MediaTek logger | MediaTek Inc. | Taiwan | System log collection, screen capture | MEDIUM |
| OMA-CP provisioning | MediaTek Inc. (for carriers) | Carrier-dependent | Remote APN/config via SMS | MEDIUM |
| EngineerMode | MediaTek Inc. | Taiwan | Hardware diagnostics, radio access | MEDIUM |
| Freeme OS framework | TYD Technology Co., Ltd. | China | UI framework, system-level access | LOW-MEDIUM |
| TYD custom apps | TYD Technology Co., Ltd. | China | OEM bloatware (customkey, clean) | LOW |
| TikTok | ByteDance | China | Social media, data collection | MEDIUM |
| WhatsApp | Meta Platforms | US | Messaging, metadata collection | MEDIUM |
| Zello | Zello Inc. | US | Push-to-talk, location sharing | LOW |
| Chrome | Google | US | Browser, search data, history | MEDIUM |
| T9 IME | Marshaltec | Unknown | Keyboard input (keystroke access) | LOW-MEDIUM |

## Detailed attribution

### China-origin threats

**Shanghai Adups Technology Co., Ltd.** (上海矽昌通信技术有限公司)
Packages: `com.adups.fota`, `com.adups.fota.sysoper`

APK decompilation reveals this is far worse than just an OTA update client. The Adups FOTA v5.24 APK contains:

- **Firebase Cloud Messaging** (`com.google.firebase.messaging.FirebaseMessagingService`) for push-triggered data collection
- **Firebase Analytics** / Google App Measurement (`com.google.android.gms.measurement.*`) for telemetry
- **Google Ads SDK** (`com.google.android.gms.ads.*`) including DoubleClick, AdMob, and native ad rendering
- **Firebase Instance ID** for device fingerprinting
- 13 services, 4 receivers, 2 content providers

Hardcoded domains include: `app-measurement.com`, `googleads.g.doubleclick.net`, `ad.doubleclick.net`, `googlesyndication.com`, `googleadservices.com`, `imasdk.googleapis.com`, `google.com/iid`, `pagead2.googlesyndication.com`

This means: a Chinese OTA framework embeds Google's full advertising and analytics stack. Your "OTA updater" is also an ad platform and telemetry beacon. Adups sends data to their servers in China. Google Analytics/Firebase sends data to Google in the US. Both run on every boot via `BOOT_COMPLETED` receiver.

The `sysoper` companion package has `RecoveryService` and `SysService`  -  these can flash firmware and trigger recovery mode. Combined with Firebase Cloud Messaging push, this allows remote code execution: push a message to the device, download a payload, flash it via recovery. This is a remote exploitation chain built into the firmware.

**TYD Technology Co., Ltd.** (天意德科技)
Packages: `com.tyd.customkey`, `com.tydtech.clean`, `freeme` framework, `com.freeme.provider.badge`, `com.freeme.factory`

TYD is the actual ODM (original design manufacturer) behind the AGM M7. AGM is a brand; TYD builds the hardware and software. The `freeme` framework runs at the Android framework level with full system privileges. TYD's `customkey` app handles the physical SOS/function key mapping.

The TYD/Freeme packages themselves appear relatively benign (no network services, no hardcoded URLs), but the Freeme framework running at system level means TYD has the ability to inject behavior into any Android component.

**ByteDance** (字节跳动)
Package: `com.zhiliaoapp.musically` (TikTok)

Pre-installed as a system app. Subject to China's National Security Law (2015), National Intelligence Law (2017), and Cybersecurity Law (2017), all of which require companies to cooperate with intelligence agencies and provide access to data when requested. Regardless of TikTok's public statements about data handling, the legal framework compels cooperation.

### Taiwan-origin threats

**MediaTek Inc.** (聯發科技)
Packages: `com.mediatek.dm`, `com.mediatek.gpslocationupdate`, `com.mediatek.location.lppe.main`, `com.mediatek.location.mtknlp`, `com.mediatek.nlpservice`, `com.mediatek.mtklogger`, `com.mediatek.mtklogger.proxy`, `com.mediatek.engineermode`, `com.mediatek.omacp`, `com.mediatek.mdmconfig`, `com.mediatek.mdmlsample`, `com.mediatek.batterywarning`, `com.mediatek.callrecorder`, `com.mediatek.camera`, `com.mediatek.dataprotection`, `com.mediatek.bluetooth.dtt`, `com.mediatek.simprocessor`, `com.mediatek.thermalmanager`, `com.mediatek.gba`, `com.mediatek.ims`, `com.mediatek.wfo.impl`

MediaTek provides the SoC and the entire board support package (BSP). Their packages are the most deeply embedded and most privileged. The `com.mediatek.dm` package alone has 90+ permissions including MASTER_CLEAR (remote wipe), INJECT_EVENTS (simulate input), CAMERA, RECORD_AUDIO, READ_SMS/CALL_LOG/CONTACTS, and full internet access.

MediaTek is a Taiwanese company, but operates significant R&D in mainland China and manufactures exclusively through Chinese foundries (TSMC is Taiwanese, but supply chain dependencies exist). Taiwan's relationship with China means MediaTek's software could be subject to pressure from either government.

The MediaTek packages serve primarily as carrier provisioning tools (OMA-DM, LPPe location). They're designed to let carriers configure and manage devices. The threat model is: if a carrier is compromised or coerced (by any government), these tools become remote surveillance infrastructure.

### US-origin threats

**Google LLC**
No Google Play Services or GMS installed directly, BUT Google's code is embedded inside the Adups FOTA APK:
- Firebase Analytics (app-measurement.com)
- Firebase Cloud Messaging (push notifications)
- Firebase Instance ID (device fingerprinting)
- Google Ads SDK (DoubleClick, AdMob)
- Google App Measurement

Google receives telemetry and ad data from this device through the Adups wrapper. This is data laundering: China-origin firmware wraps US-origin analytics and delivers device data to both governments' ecosystems simultaneously.

**Meta Platforms (WhatsApp)**
Pre-installed. Shares metadata (who you talk to, when, how often, from where) with Meta. End-to-end encryption protects message content but not metadata. Meta has complied with US government data requests.

**Zello Inc.**
Push-to-talk app. Requires location permission. US-based, subject to US government data requests.

### Unknown origin

**Marshaltec** (`com.marshaltec.ime.t9ime`)
T9 keyboard input method. Has access to every keystroke. No public information about Marshaltec as a company. A compromised or malicious keyboard captures everything typed: passwords, messages, search queries.

**com.example** (`/vendor/app/AutoDialer/AutoDialer.apk`)
Package name is literally `com.example`  -  a placeholder. This is a vendor partition app called "AutoDialer" with a default/test package name. Unknown origin, unknown purpose. The fact that a production device ships with a `com.example` package on the vendor partition suggests minimal QA on the firmware build.

## The dual-exfiltration architecture

The most concerning finding is that Adups FOTA creates a **dual-exfiltration pipeline**:

1. Adups's own collection sends device data (IMEI, IMSI, SMS, call logs per the 2016 Kryptowire findings) to Shanghai
2. The embedded Firebase/Google Analytics sends telemetry data to Google's US infrastructure
3. Firebase Cloud Messaging provides a push-based command channel from Google's servers
4. The sysoper component can flash firmware triggered by push notifications

This means the device is simultaneously reporting to Chinese and American data collection infrastructure, through a single APK, running as a system service that starts on every boot and cannot be disabled.

## What a nation-state sees

| Actor | What they get |
|-------|--------------|
| **China (via Adups)** | IMEI, IMSI, SMS content, call logs, contacts, installed apps, device identifiers (per Kryptowire 2016 report) |
| **China (via TikTok)** | Usage patterns, network info, device fingerprint if app is opened |
| **US (via Google embedded in Adups)** | Firebase analytics events, ad interaction data, device fingerprint via Instance ID, push notification channel |
| **US (via Meta/WhatsApp)** | Communication metadata (who, when, where, frequency), contact graph |
| **Any carrier (via MediaTek DM)** | Location (carrier-grade LPPe), ability to remotely configure device, read SMS, access camera/mic |
| **Anyone who sends a WAP Push SMS (via OMA-CP)** | Ability to silently reconfigure APN routing to intercept all traffic |

## Conclusion

The AGM M7 ships with at minimum Chinese, American, and carrier-level surveillance infrastructure pre-installed at the factory. No single nation-state is solely responsible. The device is a surveillance platform serving multiple actors simultaneously, with the user having no ability to consent to, inspect, or disable any of it.

This is not unique to the AGM M7. This is the standard state of budget Android phones worldwide.
