# Hardware probe: AGM M7 (2026-03-18)

Read-only ADB probe of the actual device. No modifications made.

## Device identity

| Property | Value |
|----------|-------|
| Model | AGM M7 |
| Hardware | MT6739CW |
| Platform | mt6739 |
| Build | `PQ1181WAA39A.AGM.O1.QV.KFS39SST.220323.V3.07` |
| Fingerprint | `AGM/Q12_1/Q12_1:8.1.0/OPM1.171019.026/L1635.6.01.01:user/release-keys` |
| Android | 8.1.0 (SDK 27) |
| Build type | user (not userdebug) |
| Kernel | `Linux 4.4.95+ #1 SMP PREEMPT Tue Mar 22 19:42:21 CST 2022` |
| Compiler | Linaro GCC 6.3-2017.05 |
| Serial | M7H2345001620 |
| ODM | tydtech (visible in `ro.fota.oem: tydtech6739_8.1`) |

Note: ODM is TYD Technology, not Droi as previously reported. Build paths reference `Q12_1` as the internal device codename.

## CPU

4x ARMv7 Cortex-A53 (0xd03) rev 4, 32-bit mode. Hardware AES, SHA1, SHA2, CRC32, NEON.

```
Features: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm aes pmull sha1 sha2 crc32
BogoMIPS: 14.37 (per core)
```

Hardware crypto acceleration present (AES, SHA). Relevant for encrypted storage and communication performance.

## Memory

| Metric | Value |
|--------|-------|
| MemTotal | 935,844 KB (~914 MB) |
| MemFree | 24,784 KB |
| MemAvailable | 514,340 KB (~502 MB) |
| Active | 391,332 KB |
| Active(anon) | 102,704 KB |
| zram swap | 701,880 KB (~685 MB) |

Stock Android 8.1 uses ~412 MB with screen on, idle. 502 MB "available" includes reclaimable cache. Effective free memory for applications: ~100-200 MB under stock.

## Storage

### eMMC layout (7.3 GB total, 35 partitions)

| Partition | Name | Size | Purpose |
|-----------|------|------|---------|
| mmcblk0boot0 | preloader_a | 4 MB | First-stage bootloader (A) |
| mmcblk0boot1 | preloader_b | 4 MB | First-stage bootloader (B) |
| p1 | boot_para | 1 MB | Boot parameters |
| p2 | recovery | 24 MB | Recovery image |
| p3 | para | 512 KB | Parameters |
| p4 | expdb | 20 MB | Exception DB |
| p5 | frp | 1 MB | Factory reset protection |
| p6 | nvcfg | 8 MB | NV config |
| p7 | nvdata | 32 MB | NV data |
| p8 | metadata | 32 MB | Encryption metadata |
| p9 | protect1 | 8 MB | Protected storage 1 |
| p10 | protect2 | 9.5 MB | Protected storage 2 |
| p11 | seccfg | 8 MB | Security config (bootloader lock state) |
| p12 | sec1 | 2 MB | Security 1 |
| p13 | proinfo | 3 MB | Product info |
| p14 | md1img | 64 MB | Modem firmware image |
| p15 | md1dsp | 16 MB | Modem DSP |
| p16 | spmfw | 1 MB | SPM firmware |
| p17 | mcupmfw | 1 MB | MCU PM firmware |
| p18 | gz1 | 16 MB | Guest zone 1 (TEE) |
| p19 | gz2 | 16 MB | Guest zone 2 (TEE) |
| p20 | nvram | 5 MB | NVRAM (radio calibration) |
| p21 | lk | 1 MB | Little Kernel bootloader |
| p22 | lk2 | 1 MB | Little Kernel bootloader (backup) |
| p23 | loader_ext1 | 64 KB | Loader extension 1 |
| p24 | loader_ext2 | 64 KB | Loader extension 2 |
| p25 | boot | 24 MB | Boot image (kernel + ramdisk) |
| p26 | logo | 8 MB | Boot logo |
| p27 | odmdtbo | 16 MB | ODM device tree overlay |
| p28 | tee1 | 5 MB | Trusted execution 1 |
| p29 | tee2 | 13 MB | Trusted execution 2 |
| p30 | vendor | 504 MB | Vendor (HAL blobs) |
| p31 | system | 1.5 GB | System (Android) |
| p32 | cache | 208 MB | Cache |
| p33 | userdata | 4.9 GB | User data (encrypted, dm-0) |
| p34 | flashinfo | 16 MB | Flash info |

### microSD (adoptable storage)

128 GB microSD present, formatted as adoptable storage (dm-1, encrypted). Mounted at `/mnt/expand/25b6de5f-2e86-4058-a705-3d468fb250ac`.

### Filesystem usage

| Mount | Size | Used | Free |
|-------|------|------|------|
| /system | 1.4 GB | 1.2 GB (89%) | 164 MB |
| /vendor | 472 MB | 181 MB (40%) | 276 MB |
| /cache | 185 MB | 732 KB | 179 MB |
| /data | 4.7 GB | 765 MB (17%) | 3.7 GB |
| microSD | 119 GB | 20 GB (18%) | 97 GB |

## Network interfaces

### Cellular (modem)

21 `ccmni` interfaces (MT6739 CCCI network driver). `ccmni0` is active with IP `21.28.129.209/8`.

- Baseband: `MOLY.LR12A.R2.MP.V96.6`
- RIL: `android reference-ril 1.0`
- Dual SIM: `ro.telephony.sim.count: 2`
- Default network: `9,9` (LTE preferred)

### WiFi

- Interface: `wlan0` at `180f0000.wifi` (platform device)
- P2P: `p2p0` (WiFi Direct capable)
- Connected: `Hifi-Wifi 5G` at 5745 MHz, 135 Mbps, RSSI -56 dBm
- MAC: `0c:52:03:1d:9f:06`
- Country: US

### Bluetooth

- Address: `0C:52:03:1D:9F:05`
- Name: AGM M7
- State: OFF

## Security state

| Property | Value | Meaning |
|----------|-------|---------|
| ro.boot.flash.locked | 1 | Bootloader is locked |
| ro.boot.verifiedbootstate | green | Verified boot passing (stock, untampered) |
| ro.boot.veritymode | enforcing | dm-verity enforced on system/vendor |
| ro.secure | 1 | ADB runs as shell, not root |
| ro.debuggable | 0 | Not a debug build |
| ro.adb.secure | 1 | ADB requires authorization |
| ro.crypto.state | encrypted | Block-level encryption active |
| ro.crypto.type | block | Full-disk encryption (not file-based) |
| ro.oem_unlock_supported | 1 | Hardware supports OEM unlock |
| sys.oem_unlock_allowed | 0 | OEM unlock currently disabled |
| persist.radio.unlock | false | Radio unlock disabled |
| SELinux | enforcing | SELinux is enforced |

Critical finding: `ro.oem_unlock_supported: 1` means the hardware/firmware supports OEM unlock. It's just disabled (`sys.oem_unlock_allowed: 0`). If there's an OEM unlock toggle in Developer Options, enabling it and running `fastboot oem unlock` may work. If not, mtkclient BROM bypass is the path.

## Installed packages (notable)

### Bloatware / privacy concerns

| Package | Concern |
|---------|---------|
| `com.adups.fota` | Adups FOTA: known Chinese OTA framework flagged for data exfiltration (Kryptowire 2016 report) |
| `com.adups.fota.sysoper` | Adups system operator service |
| `com.mediatek.dm` | MediaTek device management |
| `com.mediatek.gpslocationupdate` | GPS location reporting |
| `com.mediatek.location.lppe.main` | Location provider |
| `com.mediatek.location.mtknlp` | MediaTek network location provider |
| `com.mediatek.mdmconfig` | MDM configuration |
| `com.mediatek.mtklogger` | MediaTek logging framework |
| `com.tydtech.clean` | TYD Tech cleaner (OEM bloat) |
| `com.zhiliaoapp.musically` | TikTok (pre-installed) |
| `com.whatsapp` | WhatsApp (pre-installed) |
| `com.loudtalks` | Zello push-to-talk |
| `com.android.chrome` | Chrome browser |

### Relevant system packages

| Package | Purpose |
|---------|---------|
| `com.android.phone` | Telephony |
| `com.android.dialer` | Phone dialer |
| `com.android.mms` | SMS/MMS |
| `com.android.bluetooth` | Bluetooth stack |
| `com.android.fmradio` | FM Radio (hardware FM receiver present) |
| `com.mediatek.engineermode` | Engineering mode (hardware diagnostics) |
| `com.mediatek.ygps` | GPS testing tool |
| `com.mediatek.ims` | IMS (VoLTE) |
| `com.marshaltec.ime.t9ime` | T9 input method |

Note: `com.android.fmradio` confirms an FM radio receiver is present. This is additional radio hardware not documented in specs.

## Battery

| Property | Value |
|----------|-------|
| Technology | Li-ion |
| Level | 15% |
| Voltage | 3837 mV |
| Temperature | 34.0 C |
| USB charging | Yes (500 mA) |

## Full property dump

See `full-props.txt` (883 properties).

## Bootloader unlock (2026-03-18)

Unlocked via mtkclient BROM exploit. The fastboot  button confirmation is non-functional on this device (LK bootloader does not respond to any physical key input in fastboot mode).

**Method**: mtkclient  via BROM mode
- Required: Vol Up + Vol Down + Power held while connecting USB
- ModemManager and cdc_acm kernel module must be stopped/removed
- mtkclient detected MT6739, used HACC (Hardware AES) to decrypt seccfg
- V4 lockstate modified and written back

**Post-unlock state**:
- `ro.boot.flash.locked: 0`
- `ro.boot.verifiedbootstate: orange`
- Boot shows "orange state" warning (expected, same as GrapheneOS on Pixel)
- Factory reset occurred (expected)
- Device boots normally to Android 8.1

## Deep audit with root (2026-03-18)

### Kernel modules (7 loaded)

| Module | Size | Purpose |
|--------|------|---------|
| wlan_drv_gen2 | 1.0 MB | WiFi driver (MT6739 integrated) |
| wmt_drv | 919 KB | Wireless Management Task — connectivity core |
| fmradio_drv | 135 KB | FM radio receiver driver |
| bt_drv | 12 KB | Bluetooth driver |
| gps_drv | 11 KB | GPS driver |
| wmt_chrdev_wifi | 6 KB | WMT WiFi character device |
| fpsgo | 3 KB | Frame pacing (GPU scheduling) |

These are the binary kernel modules thumos must preserve. All depend on wmt_drv (connectivity management core).

### Modem interface map

The modem exposes AT command channels via /dev/radio/ pseudo-terminals:
- Dual SIM: pttycmd1-11 (SIM 1), ptty2cmd1-11 (SIM 2)
- AT command interfaces: atci1, atci2
- IMS channels: pttyims, ptty2ims, ptty3ims, ptty4ims
- Notification: pttynoti, ptty2noti
- Network: pttynwcmd, pttynwurc

Direct AT access requires owning the CCCI channel (not sharing with Android RIL). In thumos, the telephony daemon will open /dev/ccci_* directly.

### Kernel command line

bootopt=64S3,32S1,32S1 (64-bit SoC, 32-bit secondary, 32-bit OS)
vmalloc=496M, maxcpus=8, console=ttyMT0,921600n1

### Vendor init services (57 .rc files)

Full MediaTek HAL stack: audio, bluetooth, broadcastradio, camera, configstore, DRM, gatekeeper, graphics, keymaster, media, sensors, wifi. Plus connectivity management, modem init, thermal management, IMS/VoLTE, and FM radio.
