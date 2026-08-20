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
- Capacitive touchscreen (`mtk-tpd`, 10-point), observed in the 2026-03-18
  read-only device probe (`docs/PROBE.md`)

## Durability

- IP68 (dust/water, 1.5m for 30 min)
- IP69K (high-pressure/steam)
- MIL-STD-810H (drop, shock, vibration, temperature)

## Battery

- 2500 mAh Li-Ion
- Removable

## Stock firmware

- Android 8.1.0 (SDK 27), observed during the 2026-03-18 read-only probe
- ODM: TYD Technology (`ro.fota.oem=tydtech6739_8.1`), not Droi
- Build: `PQ1181WAA39A.AGM.O1.QV.KFS39SST.220323.V3.07`
- 35 observed eMMC partitions; this repository does not contain a scatter file

These are dated observations from `docs/PROBE.md`, not a claim about the
phone's current live firmware or lock state. Re-observe either before relying
on it for a device operation.

## Access paths

| Method | Status | Notes |
|--------|--------|-------|
| ADB | Observed 2026-03-18 | Used for the read-only probe; current authorization/state is not asserted |
| SP Flash Tool | Unverified | No scatter or device-package path exists in this repository (#467) |
| BROM / mtkclient | Historically observed | Used on 2026-03-18 to change the then-observed lock state; this is not a current-state receipt |
| Fastboot OEM unlock | Non-functional in the observed session | The LK confirmation screen did not respond to physical keys |
| TWRP | Unverified third-party lead | #676 records the unresolved provenance of AGM-M7 recovery artifacts |

## Known quirks

- 32-bit build despite 64-bit capable SoC
- A white recovery display was reported in the dated 2026-03-18 session; its
  mechanism and current reproducibility are unverified (#676)
- Anti-rollback behavior is an unverified third-party recovery-tree lead, not
  a local device receipt
- The dated probe observed `verifiedbootstate=green` and
  `veritymode=enforcing`; the AVB version, `vbmeta` layout, and current
  pre-entry verification chain remain unverified (#467)
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
