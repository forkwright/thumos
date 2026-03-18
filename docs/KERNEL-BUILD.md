# Kernel Build — W1-01

MT6739 Linux 4.4 BSP kernel for AGM M7, compiled from `kernel-wiite/` (cateajansmedya BSP).

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

## Known Limitations (W1-01)

- **LCM**: `hct_ili9881p_dsi_vdo_hdp_panda_55_hz` is a placeholder. The AGM M7's actual panel (nt35521) driver is absent from this BSP. Display will not initialize; boot console only.
- **GPIO/EINT**: `cust.dtsi` is a stub (no DrvGen output). Drivers that depend on GPIO bindings will not probe.
- **FPSGO disabled**: Frame Performance Governor not built; no impact on validation.
- **Modem (CCCI)**: CCCI driver built in (`CONFIG_MTK_ECCCI_DRIVER=y`). Device nodes should appear if modem firmware is present in partition.
- **WiFi (gen2)**: Built in. Requires vendor firmware blob at runtime.
