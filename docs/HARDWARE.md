# Hardware reference: AGM M7

## `SoC`: Mediatek MT6739

- CPU: 4x ARM Cortex-A53 @ 1.5 GHz (28nm)
- GPU: PowerVR GE8100 @ 570 MHz
- Modem: integrated LTE Cat.4 DL / Cat.5 UL
- WiFi: 802.11 a/b/g/n (2.4 + 5 GHz), integrated
- Bluetooth: 4.2, integrated
- GNSS: GPS + GLONASS / GPS + BeiDou, integrated
- Process: 28nm HPC+
- Kernel: Linux 4.4.x (BSP)

The SoC integrates all radios. No discrete connectivity chips exist.

## LTE bands

- FDD: B1/3/5/7/8/20/28AB
- TDD: B38/39/40/41

## Memory

- 1 GB LPDDR3
- 8 GB eMMC 5.1
- microSD up to 128 GB

## Display

- 2.4" IPS LCD
- 240x320 (QVGA), 167 ppi
- Gorilla Glass 5

## Input

- Physical keypad (T9 layout)
- No touchscreen

## Durability

- IP68 (dust/water, 1.5m for 30 min)
- IP69K (high-pressure/steam)
- MIL-STD-810H (drop, shock, vibration, temperature)

## Battery

- 2500 mAh Li-Ion
- Removable

## Stock firmware

- Android 8.1 Oreo (full AOSP, not Go edition)
- ODM: Droi Technology
- Build: `PQ1181CWE25A.AGM.O1.QV.KFS39SST.210623.V3.11`
- 37 partitions (scatter file documented)
- Pre-installed: Facebook, WhatsApp, Skype, TikTok, Zello

## Access paths

| Method | Status | Notes |
|--------|--------|-------|
| ADB | Confirmed | Standard USB debug, works out of box |
| SP Flash Tool | Confirmed | Scatter file available, full partition read/write |
| BROM exploit | Likely | mtkclient supports MT6739, budget OEMs rarely burn eFuses |
| Fastboot OEM unlock | Unlikely | Failed on AGM M5 (same family), AGM doesn't support |
| TWRP | Partial | Device tree exists (github.com/OsciX/twrp_device_agm_m7) |

## Known quirks

- 32-bit build despite 64-bit capable SoC
- Display goes white in bootloader/recovery (missing early-boot display driver)
- Anti-rollback protection present (TWRP tree hacks around it)
- Verified Boot (AVB 2.0) with vbmeta and dm-verity
- TEE partitions (tee1/tee2) for trusted execution

## Kernel sources (from other MT6739 devices)

- OrangePi 4G-IOT BSP: `github.com/Iscle/OrangePi_4G-IOT_Android_8.1_BSP`
- Alcatel: `github.com/deadman96385/android_kernel_alcatel_mt6739`
- Wiite C7S/C8: `github.com/cateajansmedya/android_kernel_mediatek_mt6739`
- Google MTK tree: `android.googlesource.com/kernel/mediatek/`

## Similar devices with custom work

| Device | SoC | Achievement |
|--------|-----|-------------|
| Philips E289 | MT6739 | Full root + bootloader unlock + EMMC dump |
| Alcatel 1 (5033) | MT6739 | Custom ROM on Needrom |
| Wiko View Max | MT6739 | Kernel source on GitHub |
