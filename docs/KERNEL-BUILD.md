# Kernel Build

MT6739 Linux 4.4 BSP kernel for AGM M7, compiled from `kernel-wiite/` (cateajansmedya BSP).

---

## W1-02 — Stock config + USB serial initramfs

**Status:** Built. `boot-v2.img` at `~/thumos/boot-v2.img`. Not yet flashed.

### What changed from W1-01

| Item | W1-01 | W1-02 |
|------|-------|-------|
| Base config | `hct6739_36_n1_defconfig` | `kernel-config-stock` (extracted from `/proc/config.gz` on running device) |
| LCM driver | `hct_ili9881p_dsi_vdo_hdp_panda_55_hz` (wrong DSI placeholder) | `gc9306_dbi_c_qvgal` (correct DBI panel, stub — source absent from BSP) |
| Initramfs | Shell only | Shell + USB serial gadget (ACM) |
| CMDLINE | `console=ttyMT0` only | `console=ttyMT0,921600n1 vmalloc=496M` |
| FPSGO | Disabled | Disabled (same root cause: undefined FBT game symbols) |

### Why W1-01 didn't boot visibly

The W1-01 LCM driver (`hct_ili9881p`) is a 1080p DSI panel driver. The AGM M7 uses a
240×320 DBI parallel-interface panel driven by GC9306. The wrong driver left the display
controller unconfigured; the kernel booted but nothing was visible and there was no console.

### GC9306 LCM driver status

**Not found in any BSP tree** (`kernel-wiite`, `kernel-lumi`, `kernel-orangepi`).

A stub driver was created at:
```
drivers/misc/mediatek/lcm/gc9306_dbi_c_qvgal/gc9306_dbi_c_qvgal.c
```

The stub sets DBI parallel interface, 240×320, RGB565, and logs a warning at boot.
Display will not initialize. The actual GC9306 init sequence must be extracted from
the stock system partition (`/system/lib/hw/` or display HAL) in a future sprint.

### Additional patches applied in W1-02

#### CONFIG changes (on top of stock config)

| Option | Stock | W1-02 | Reason |
|--------|-------|-------|--------|
| `CONFIG_CROSS_COMPILE` | `"arm-eabi-"` | `"arm-linux-gnueabihf-"` | Installed toolchain |
| `CONFIG_HARDENED_USERCOPY` | `y` | disabled | `mm/slub.c` references `kmem_cache.red_left_pad` which is absent from this BSP's `slub_def.h` (kernel version skew) |
| `CONFIG_MTK_FPSGO` | `y` | disabled | FBT game symbols (`min_boost_freq`, `cpufreq_notifier_fp`) undefined — same issue as W1-01 |
| `CONFIG_USB_C_SWITCH` | `y` | disabled | `register_typec_switch_callback` defined only in Type-C chip drivers (MT6336/ANX7418), none of which are built; AGM M7 uses micro-USB |
| `CONFIG_BUILD_ARM_APPENDED_DTB_IMAGE_NAMES` | `"mt6739"` | `"hct6739_36_n1"` | No `mt6739.dts` in BSP; `hct6739_36_n1.dts` is the only MT6739 DTS |

#### New code patches (kernel-wiite in-tree edits)

**drivers/usb/gadget/function/u_ether.c — missing rndis.h include**

`u_ether.c` uses `sizeof(struct rndis_packet_msg_type)` but did not include `rndis.h`,
causing an "incomplete type" compile error. Fixed by adding `#include "rndis.h"`.

**drivers/misc/mediatek/lcm/mt65xx_lcm_list.h — gc9306 registration**

Added `extern LCM_DRIVER gc9306_dbi_c_qvgal_lcm_drv` and the corresponding
`#if defined(GC9306_DBI_C_QVGAL)` entry in `lcm_driver_list[]`.

**drivers/misc/mediatek/imgsensor/src/common/v1/gc030amipi_raw/ (stub)**
**drivers/misc/mediatek/imgsensor/src/common/v1/gc02m2_mipi_raw/ (stub)**

Stock config requests sensors `gc030amipi_raw` and `gc02m2_mipi_raw` via
`CONFIG_CUSTOM_KERNEL_IMGSENSOR`. Neither exists in this BSP (BSP has `gc030a_mipi_raw`
with a different name, and `gc02m2` entirely absent). Stub `Makefile` + empty `.c`
files created so the linker finds `built-in.o` objects.

Also note: `Wno-error` flags added for:
- `-Wno-error=builtin-declaration-mismatch` (crypto/xts.c: `free` name collision with GCC built-in)
- `-Wno-error=incompatible-pointer-types` (mm/memcontrol.c: cgroup callback signature mismatch)
- `-Wno-error=unused-function` (USB gadget MTP/accessory functions)

### Configure

```bash
cd ~/thumos/kernel-wiite
cp ~/thumos/kernel-config-stock .config
# Fix CROSS_COMPILE and disable incompatible options:
sed -i 's/CONFIG_CROSS_COMPILE="arm-eabi-"/CONFIG_CROSS_COMPILE="arm-linux-gnueabihf-"/' .config
sed -i 's/^CONFIG_HARDENED_USERCOPY=y/# CONFIG_HARDENED_USERCOPY is not set/' .config
sed -i 's/^CONFIG_MTK_FPSGO=y/# CONFIG_MTK_FPSGO is not set/' .config
sed -i 's/^CONFIG_USB_C_SWITCH=y/# CONFIG_USB_C_SWITCH is not set/' .config
sed -i 's/CONFIG_BUILD_ARM_APPENDED_DTB_IMAGE_NAMES="mt6739"/CONFIG_BUILD_ARM_APPENDED_DTB_IMAGE_NAMES="hct6739_36_n1"/' .config
yes "" | make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- oldconfig
```

### Build

```bash
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- \
  KCFLAGS="-march=armv7-a \
    -Wno-error=address \
    -Wno-error=array-compare \
    -Wno-error=stringop-overread \
    -Wno-error=dangling-pointer \
    -Wno-error=int-to-pointer-cast \
    -Wno-error=enum-int-mismatch \
    -Wno-error=restrict \
    -Wno-error=builtin-declaration-mismatch \
    -Wno-error=incompatible-pointer-types \
    -Wno-error=unused-function" \
  DTC_FLAGS="-f" \
  -j$(nproc) zImage dtbs

cat arch/arm/boot/zImage arch/arm/boot/dts/hct6739_36_n1.dtb \
  > arch/arm/boot/zImage-dtb
```

Produces:

| File | Size | Notes |
|------|------|-------|
| `arch/arm/boot/zImage` | ~7.5 MB | Compressed kernel |
| `arch/arm/boot/dts/hct6739_36_n1.dtb` | ~62 KB | Device tree blob |
| `arch/arm/boot/zImage-dtb` | ~7.5 MB | zImage + DTB appended |

### Initramfs

Static ARM BusyBox 1.36.1. Adds USB ACM gadget setup:

```bash
mkdir -p /tmp/initramfs-v2/{bin,dev,proc,sys,etc,tmp,mnt,root,lib/modules}
cp /tmp/busybox-1.36.1/busybox /tmp/initramfs-v2/bin/
cd /tmp/initramfs-v2/bin && ln -sf busybox sh && ln -sf busybox mount && \
  ln -sf busybox ls && ln -sf busybox cat && ln -sf busybox echo && \
  ln -sf busybox sleep && ln -sf busybox setsid
# write /tmp/initramfs-v2/init (USB gadget + diagnostics + shell)
chmod 755 /tmp/initramfs-v2/init
cd /tmp/initramfs-v2 && find . | cpio -H newc -o | gzip > /tmp/ramdisk-v2.gz
```

The `/init` script:
1. Mounts proc/sysfs/devtmpfs/configfs
2. Configures a USB ACM gadget (`/sys/kernel/config/usb_gadget/g1`) for serial console
3. Spawns a shell on `/dev/ttyGS0` (USB serial, visible on host as `/dev/ttyUSBx`)
4. Prints diagnostics (cpuinfo, meminfo, partitions, CCCI, framebuffer, input, modules)
5. Falls through to an interactive shell on the UART console

### Boot Image

```bash
python3 /tmp/mkbootimg-tools/mkbootimg.py \
  --kernel ~/thumos/kernel-wiite/arch/arm/boot/zImage-dtb \
  --ramdisk /tmp/ramdisk-v2.gz \
  --base 0x40000000 \
  --kernel_offset 0x00008000 \
  --ramdisk_offset 0x05000000 \
  --second_offset 0x00f00000 \
  --tags_offset 0x04000000 \
  --pagesize 2048 \
  --cmdline "bootopt=64S3,32S1,32S1 console=ttyMT0,921600n1 root=/dev/ram vmalloc=496M" \
  -o ~/thumos/boot-v2.img
```

Output: `~/thumos/boot-v2.img` (~8.6 MB)

Header:
```
Magic:         ANDROID!
Page size:     2048
Kernel addr:   0x40008000
Ramdisk addr:  0x45000000
Cmdline:       bootopt=64S3,32S1,32S1 console=ttyMT0,921600n1 root=/dev/ram vmalloc=496M
```

### Observations

- **Stock CMDLINE** uses `console=ttyMT3` (not `ttyMT0`). W1-02 uses `ttyMT0` for
  compatibility with the BSP defconfig pattern. If no console output appears, try
  `ttyMT3` in the next build.
- **GC9306 DBI driver** will need to be reverse-engineered from the stock display HAL
  or extracted from a different BSP that includes it (e.g., MT6739 Android 9 trees).
- **Camera sensors**: `gc030amipi_raw` vs `gc030a_mipi_raw` naming divergence suggests
  the stock firmware may use a downstream vendor BSP not aligned with this tree.
- **vmalloc=496M** in cmdline matches stock config CMDLINE setting (`vmalloc=496M`).

---

# W1-01 — First boot attempt (wrong LCM driver)

## Environment

- Host: Ubuntu 24.04, x86-64
- Toolchain: `arm-linux-gnueabihf-gcc` 13.3.0 (Debian cross package)
- Target: 32-bit ARMv7-A (`armv7-a-neon`), MT6739 / AGM M7

```
sudo apt install gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf \
    bc bison flex libssl-dev libelf-dev cpio python3
```

## Configure

```bash
cd ~/thumos/kernel-wiite
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- hct6739_36_n1_defconfig
```

Post-defconfig `.config` tweaks applied by hand before building:

| Option | Value | Reason |
|--------|-------|--------|
| `CONFIG_CROSS_COMPILE` | `"arm-linux-gnueabihf-"` | Matches installed toolchain |
| `CONFIG_MTK_LCM` | `y` | Required; use placeholder LCM driver |
| `CONFIG_CUSTOM_KERNEL_LCM` | `"hct_ili9881p_dsi_vdo_hdp_panda_55_hz"` | AGM M7 has nt35521 (absent from BSP); this placeholder satisfies the compile-time assertion in `mt65xx_lcm_list.c` |
| `CONFIG_MTK_FPSGO` | `n` | `fpsgo_common.c` calls `fbt_notifier_push_benchmark_hint` unconditionally but that symbol is gated behind `CONFIG_MTK_FPSGO_FBT_GAME`; disabling FPSGO avoids the undefined-reference linker error |

## Build

```bash
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- \
  KCFLAGS="-march=armv7-a \
    -Wno-error=address \
    -Wno-error=array-compare \
    -Wno-error=stringop-overread \
    -Wno-error=dangling-pointer \
    -Wno-error=int-to-pointer-cast \
    -Wno-error=enum-int-mismatch \
    -Wno-error=restrict" \
  DTC_FLAGS="-f" \
  -j$(nproc) zImage
```

Produces:

| File | Size | Notes |
|------|------|-------|
| `arch/arm/boot/zImage` | ~7.8 MB | Compressed kernel |
| `arch/arm/boot/dts/hct6739_36_n1.dtb` | ~62 KB | Device tree blob |
| `vmlinux` | ~172 MB | Unstripped ELF (debug) |

Append DTB manually (defconfig sets `CONFIG_BUILD_ARM_APPENDED_DTB_IMAGE=y` but the top-level `make zImage` target does not invoke the `zImage-dtb` rule):

```bash
cat arch/arm/boot/zImage arch/arm/boot/dts/hct6739_36_n1.dtb \
  > arch/arm/boot/zImage-dtb
```

## Patches Applied

All patches are in-tree edits; none are separate patch files.

### scripts/dtc/Makefile — dtc yylloc multiple definition

GCC 13 / GNU AS 2.44 rejects the `yylloc` symbol appearing in both `.lex.o` and `.tab.o`. Fix:

```makefile
HOSTCFLAGS_dtc-lexer.lex.o  := $(HOSTCFLAGS_DTC) -fcommon
HOSTCFLAGS_dtc-parser.tab.o := $(HOSTCFLAGS_DTC) -fcommon
```

### arch/arm/ — ARM assembly `#alloc`/`#execinstr` section flags

GNU AS 2.44 rejects the historic `#alloc`, `#execinstr` section flag syntax in `.section` directives. Changed all 33 occurrences across `arch/arm/` to string form (`"a"` / `"ax"`).

### arch/arm/Makefile — global MTK include paths + armv7-a march

GCC 13 evaluates `cc-option(-march=armv7-a)` against `arm-linux-gnueabihf-gcc` whose default `-mfloat-abi=hard` causes the test to fail with a hard-float/soft-float ABI mismatch, making the Makefile fall back to `-march=armv5t`. GCC 13 then emits `.arch armv5t` in assembly output, overriding the `-Wa,-march=armv7-a` assembler flag and breaking DSB/ISB instructions.

Fix: pass `KCFLAGS=-march=armv7-a` on the make command line so the last `-march` flag wins.

Also added global `KBUILD_CFLAGS` include paths for MTK vendor drivers that are scattered across too many subdirectories to enumerate in individual Makefiles:

```makefile
MTK_PLATFORM := $(CONFIG_MTK_PLATFORM:"%"=%)
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/include/mt-plat
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/include/mt-plat/$(MTK_PLATFORM)/include
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/base/power/ppm_v3/src/mach/$(MTK_PLATFORM)
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/base/power/ppm_v2/src/mach/$(MTK_PLATFORM)
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/video/common/layering_rule_base/v1
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/uart/$(MTK_PLATFORM)
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/m4u/$(MTK_PLATFORM)
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/eccci
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/cmdq/v3/$(MTK_PLATFORM)
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/performance/fpsgo/fstb
KBUILD_CFLAGS += -I$(srctree)/drivers/misc/mediatek/mmp
```

**Note:** `videox/` and `dispsys/` are intentionally NOT added globally. Adding them caused `videox/debug.h` to shadow `gen2/include/debug.h` for the WiFi driver, breaking the `DBGLOG`/`ASSERT` macros. These paths are added per-driver instead (see below).

### drivers/misc/mediatek/connectivity/wlan/gen2/Makefile — absolute include paths

The gen2 WiFi driver Makefile used `$(src)` for include paths, which resolves incorrectly when objects in subdirectories (hif/ahb/) are compiled from the parent Makefile. Replaced with absolute `$(srctree)` paths:

```makefile
GEN2_DIR := $(srctree)/drivers/misc/mediatek/connectivity/wlan/gen2
ccflags-y += -I$(GEN2_DIR)/os -I$(GEN2_DIR)/os/linux/include \
             -I$(GEN2_DIR)/os/linux/hif/ahb/include \
             -I$(GEN2_DIR)/include -I$(GEN2_DIR)/include/nic \
             -I$(GEN2_DIR)/include/mgmt
```

### drivers/misc/mediatek/video/mt6739/videox/Makefile — self-include path

`videox/` was missing itself from its own include path. When dispsys headers (included by videox source files) in turn include other videox headers (e.g., `disp_drv_log.h` → `display_recorder.h`), the videox directory was not in the search path. Added:

```makefile
-I$(srctree)/drivers/misc/mediatek/video/$(MTK_PLATFORM)/videox/
```

### drivers/misc/mediatek/video/mt6739/dispsys/Makefile — self-include path

Same issue: dispsys files include each other via videox-mediated chains. Added:

```makefile
-I$(srctree)/drivers/misc/mediatek/video/$(MTK_PLATFORM)/dispsys/
```

### arch/arm/boot/dts/cust.dtsi — stub (replaces DrvGen output)

`DrvGen.py` requires Python 2 to generate `cust.dtsi` from `hct6739_36_n1.dws`. Python 2 is unavailable. Created a minimal stub:

```c
/* stub — GPIO/EINT bindings absent; hardware drivers won't probe */
#include <dt-bindings/interrupt-controller/irq.h>
#include <dt-bindings/interrupt-controller/arm-gic.h>
```

Hardware drivers that rely on DTS GPIO bindings will not probe on boot, but the kernel boots.

### vendor/haocheng/drivers/hct_include/hct_project_all_config.h — stub

`include/linux/hct_include` is a broken symlink to `../../../vendor/haocheng/drivers/hct_include`. Created the target directory and a stub header to satisfy `lcm_i2c.h`.

## Initramfs

Static ARM busybox 1.36.1 built and packed:

```bash
# Build busybox
cd /tmp/busybox-1.36.1
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- defconfig
echo "CONFIG_STATIC=y" >> .config
sed -i 's/^CONFIG_TC=y/# CONFIG_TC is not set/' .config  # tc broken with GCC 13
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- -j$(nproc)

# Pack initramfs
mkdir -p /tmp/initramfs/{bin,dev,proc,sys,etc,tmp,mnt,root}
cp busybox /tmp/initramfs/bin/
cd /tmp/initramfs/bin && ln -sf busybox sh
cd /tmp/initramfs && find . | cpio -H newc -o | gzip > /tmp/initramfs.cpio.gz
```

Init script (`/init`) mounts proc/sysfs/devtmpfs, prints CPU info, checks for CCCI nodes, then drops to shell.

## Boot Image

```bash
python3 /tmp/mkbootimg-tools/mkbootimg.py \
  --kernel ~/thumos/kernel-wiite/arch/arm/boot/zImage-dtb \
  --ramdisk /tmp/initramfs.cpio.gz \
  --base 0x40000000 \
  --kernel_offset 0x00008000 \
  --ramdisk_offset 0x05000000 \
  --second_offset 0x00f00000 \
  --tags_offset 0x04000000 \
  --pagesize 2048 \
  --cmdline "bootopt=64S3,32S1,32S1 console=ttyMT0,921600n1 root=/dev/ram" \
  -o ~/thumos/boot.img
```

Output: `~/thumos/boot.img` (~8.9 MB)

Header verification:

```
Magic:         ANDROID!
Page size:     2048
Kernel addr:   0x40008000
Ramdisk addr:  0x45000000
Cmdline:       bootopt=64S3,32S1,32S1 console=ttyMT0,921600n1 root=/dev/ram
```

## Flash

**Backup stock boot partition first.**

```bash
# Via adb (if rooted)
adb shell dd if=/dev/block/platform/*/by-name/boot of=/sdcard/boot_stock.img

# Flash validation image
adb push ~/thumos/boot.img /sdcard/
adb shell dd if=/sdcard/boot.img of=/dev/block/platform/*/by-name/boot

# Or via fastboot if unlocked
fastboot boot ~/thumos/boot.img   # test without flashing
```

## Known Limitations (W1-01 — superseded by W1-02)

- **LCM**: `hct_ili9881p_dsi_vdo_hdp_panda_55_hz` is a placeholder. The AGM M7's actual panel (nt35521) driver is absent from this BSP. Display will not initialize; boot console only.
- **GPIO/EINT**: `cust.dtsi` is a stub (no DrvGen output). Drivers that depend on GPIO bindings will not probe.
- **FPSGO disabled**: Frame Performance Governor not built; no impact on validation.
- **Modem (CCCI)**: CCCI driver built in (`CONFIG_MTK_ECCCI_DRIVER=y`). Device nodes should appear if modem firmware is present in partition.
- **WiFi (gen2)**: Built in. Requires vendor firmware blob at runtime.
