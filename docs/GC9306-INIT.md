# GC9306 display init sequence

The GC9306 is a GalaxyCore 240x320 QVGA TFT controller used in the AGM M7. It accepts MIPI DCS commands over SPI or DBI parallel interface. The init sequence configures power rails, voltage references, timing, and gamma correction before bringing the display out of sleep.

## Register sequence

Derived from four independent sources. The core register structure is identical across all four. Gamma values (0xF0-0xF5) vary per panel and may need tuning on the M7.

Each row is one DCS transaction: command byte, then zero or more data bytes, then an optional delay.

| # | Cmd | Data | Delay | Register function |
|---|-----|------|-------|-------------------|
| 1 | `0xFE` | | | Inter register enable 1 |
| 2 | `0xEF` | | | Inter register enable 2 |
| 3 | `0x36` | `0x48` | | Memory access control (MX=1, BGR=1) |
| 4 | `0x3A` | `0x05` | | Pixel format: RGB565, 16-bit |
| 5 | `0xA4` | `0x44 0x44` | | Power control 7 |
| 6 | `0xA5` | `0x42 0x42` | | Power control 8 |
| 7 | `0xAA` | `0x88 0x88` | | Power control (undocumented) |
| 8 | `0xE8` | `0x11 0x0B` | | Frame rate control |
| 9 | `0xE3` | `0x01 0x10` | | Source precharge control |
| 10 | `0xFF` | `0x61` | | Internal register (undocumented) |
| 11 | `0xAC` | `0x00` | | LDO enable |
| 12 | `0xAD` | `0x33` | | VGLO voltage control |
| 13 | `0xAE` | `0x2B` | | Internal power (undocumented) |
| 14 | `0xAF` | `0x55` | | DIG_VREFAD_VRDD control |
| 15 | `0xA6` | `0x2A 0x2A` | | VCOM offset voltage 1 |
| 16 | `0xA7` | `0x2B 0x2B` | | VCOM offset voltage 2 |
| 17 | `0xA8` | `0x18 0x18` | | VCOM offset voltage 3 |
| 18 | `0xA9` | `0x2A 0x2A` | | VCOM offset voltage 4 |
| 19 | `0x2A` | `0x00 0x00 0x00 0xEF` | | Column address set (0-239) |
| 20 | `0x2B` | `0x00 0x00 0x01 0x3F` | | Row address set (0-319) |
| 21 | `0x2C` | | | Memory write (start) |
| 22 | `0xF0` | `0x02 0x00 0x00 0x1B 0x1F 0x0B` | | Positive gamma curve 1 |
| 23 | `0xF1` | `0x01 0x03 0x00 0x28 0x2B 0x0E` | | Positive gamma curve 2 |
| 24 | `0xF2` | `0x0B 0x08 0x3B 0x04 0x03 0x4C` | | Positive gamma curve 3 |
| 25 | `0xF3` | `0x0E 0x07 0x46 0x04 0x05 0x51` | | Positive gamma curve 4 |
| 26 | `0xF4` | `0x08 0x15 0x15 0x1F 0x22 0x0F` | | Negative gamma curve 1 |
| 27 | `0xF5` | `0x0B 0x13 0x11 0x1F 0x21 0x0F` | | Negative gamma curve 2 |
| 28 | `0x11` | | 120 ms | Sleep out |
| 29 | `0x29` | | 20 ms | Display on |
| 30 | `0x2C` | | | Memory write (ready for pixel data) |

### Memory access control (0x36) values by rotation

| Direction | Value | Bits set |
|-----------|-------|----------|
| 0 (normal) | `0x48` | MX, BGR |
| 1 (90 CW) | `0x28` | MV, BGR |
| 2 (180) | `0x88` | MY, BGR |
| 3 (270 CW) | `0xE8` | MY, MX, MV, BGR |

The AGM M7 uses direction 0 (`0x48`).

### Optional commands

Some sources include these. Hardware validation on the M7 has not yet confirmed whether it needs them.

| Cmd | Data | Function | When to use |
|-----|------|----------|-------------|
| `0x35` | `0x00` | Tearing effect line on | If using TE sync for frame timing |
| `0x44` | `0x00 0x01` | Set tear scanline | With 0x35, controls TE trigger line |
| `0xE9` | `0x08` | SPI 2-data control | Only for SPI 2-lane mode |

### Sleep and wake commands

Sleep in (display off):

| Cmd | Delay |
|-----|-------|
| `0xFE` | |
| `0xEF` | |
| `0x28` | 120 ms |
| `0x10` | |

Sleep out (display on):

| Cmd | Delay |
|-----|-------|
| `0xFE` | |
| `0xEF` | |
| `0x11` | 120 ms |
| `0x29` | |

## Gamma tuning

Gamma values differ across all four sources because each vendor tunes gamma for their specific panel supplier. The values in the main table come from the LuatOS and Fibocom drivers, which agree exactly. The Spreadtrum and Actions drivers use different gamma curves tuned for different panels.

If the M7 display looks washed out or has incorrect contrast, gamma registers 0xF0-0xF5 are the adjustment point. Each register takes six bytes. No public documentation exists for the gamma curve encoding. Tuning requires visual iteration on the physical panel.

### Gamma values by source

| Source | F0 | F1 | F2 | F3 | F4 | F5 |
|--------|----|----|----|----|----|----|
| LuatOS / Fibocom | 02 00 00 1B 1F 0B | 01 03 00 28 2B 0E | 0B 08 3B 04 03 4C | 0E 07 46 04 05 51 | 08 15 15 1F 22 0F | 0B 13 11 1F 21 0F |
| Spreadtrum (SPRD) | 02 01 00 0A 10 11 | 01 02 00 14 1C 09 | 12 09 40 03 03 50 | 0B 09 3E 03 04 4B | 0C 1A 1A 22 22 0F | 0B 17 15 18 19 0F |
| Actions (Zephyr) | 02 00 00 00 00 04 | 01 02 00 05 1A 15 | 06 06 20 05 05 31 | 15 0B 55 02 02 65 | 0E 1C 1A 03 05 0F | 06 13 15 33 31 0F |

## Hardware reset sequence

Before sending init commands, assert hardware reset:

1. Drive RST pin low
2. Wait 10 ms minimum
3. Drive RST pin high
4. Wait 20 ms minimum (some sources use 100 ms)
5. Begin init sequence

## Device identification

Read ID command `0x04` returns three bytes. The GC9306 device ID is `0x009306` (id[1]=0x93, id[2]=0x06).

## Interface

The AGM M7 BSP configures `gc9306_dbi_c_qvgal`, indicating DBI (parallel) interface in command mode. Panel init sequence stays the same regardless of physical interface (SPI vs DBI parallel). Transport layer differs but the DCS commands are identical.

## Sources

Four independent driver implementations. **Their licenses differ and one is proprietary** — the
per-source line below is authoritative, not this paragraph. An earlier version of this sentence said
all four were GPL-2.0 or Apache-2.0, which contradicted the list directly beneath it and was wrong in
the permissive direction about a source that grants no reuse rights at all.

Why four are listed when only one is used: **independent convergence is the evidence**. Four unrelated
vendors, on four unrelated host platforms, emitting the same command bytes is what establishes that the
sequence is dictated by the GC9306 controller rather than authored by any of them — a hardware fact,
not expression. The commands that are not GC9306-specific match the public MIPI DCS specification,
reaching the same conclusion a second way.

Where the sources genuinely **disagree** is the gamma table (0xF0–0xF5): three of the four differ, so
those bytes are panel-tuning choices rather than device-mandated. The 36 bytes used here trace to
source 1, LuatOS, which is MIT — permissive, requiring only that notice be kept, which naming it here
does. **No bytes are taken from source 3**, and none may be: RDA Technologies' driver is proprietary
and is cited purely as a convergence witness — evidence that a value is common across the ecosystem,
never as something to copy from.

1. **LuatOS** (`openLuat/luatos-soc-rtt`): `components/lcd/luat_lcd_gc9306.c`
   SPI driver for Air101/Air103 MCUs. MIT license.
   https://github.com/openLuat/luatos-soc-rtt

2. **Spreadtrum u-boot** (`yonglongliu/u-boot15`): `drivers/video/sprdfb/lcd/lcd_gc9306_spi.c`
   SPI driver for SC6531E feature phones. GPL-2.0.
   https://github.com/yonglongliu/u-boot15

3. **Fibocom/RDA** (`VyshakApmTech/fibocom_vts`): `components/lcdpanel/src/panel_gc9306.c`
   SPI driver for RDA8910 LTE modules. Proprietary (RDA Technologies).
   https://github.com/VyshakApmTech/fibocom_vts

4. **Actions Semiconductor** (`kongqj1234/git_kong`): `drivers/display/panel_gc9306_320x240.c`
   SPI driver for Actions S200 Zephyr platform. Apache-2.0.
   https://github.com/kongqj1234/git_kong

Additional reference: Spreadtrum device tree (`iscle/android_kernel_spreadtrum_sc9853`):
`arch/arm/boot/dts/lcd/lcd_gc9306_spi_qvga.dtsi`

## Search methodology

| Strategy | Result |
|----------|--------|
| GitHub code search for `gc9306` | Found four driver implementations and one device tree |
| BSP kernel trees (kernel-wiite, kernel-lumi, kernel-orangepi) | Stub driver only, no init commands |
| Stock firmware binary analysis | Not needed: public sources provided complete sequence |
| GC9306 datasheet | No public datasheet found. GalaxyCore does not publish datasheets |
| Chinese tech forums | Driver code found via LuatOS (Chinese embedded ecosystem) |
| Register compatibility | GC9306 uses MIPI DCS command set. 0xFE/0xEF page commands are GC-specific. Standard commands (0x11, 0x29, 0x2A, 0x2B, 0x2C, 0x36, 0x3A) match MIPI DCS spec |

## On-device validation plan

If the init sequence does not produce a working display on the M7:

1. **Capture live init traffic.** On the stock Android system with root:
   ```
   adb shell "echo 1 > /sys/kernel/debug/mtkfb/debug"
   adb shell "cat /sys/kernel/debug/mtkfb/debug"
   ```
   The MTK framebuffer debug node may log DSI transactions.

2. **Read LCM parameters from stock kernel.**
   ```
   adb shell "cat /proc/cmdline" | grep -o 'lcm=[^ ]*'
   adb shell "cat /sys/class/graphics/fb0/device/lcm_params"
   ```

3. **Dump LCM driver from kernel module.**
   ```
   adb shell "find /vendor/lib/modules -name '*lcm*'"
   adb shell "find /system/lib/modules -name '*lcm*'"
   ```
   If the LCM driver is a loadable module, `strings` on the .ko file may reveal the init table.

4. **Check device tree overlay.**
   ```
   adb shell "cat /proc/device-tree/lcm_params/*" 2>/dev/null
   adb shell "cat /proc/device-tree/chosen/atag,lcm" 2>/dev/null
   ```

5. **MMIO register dump.** With devmem access:
   ```
   adb shell "devmem2 0x14012000 w"  # DSI0 base on MT6739
   ```
   Read back DSI configuration registers to compare against expected values.
