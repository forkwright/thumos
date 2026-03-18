# CLAUDE.md

Thumos is a custom Linux-based mobile OS targeting the AGM M7 (MT6739).

## Repository

- GitHub: `forkwright/thumos` (private)
- Target: AGM M7 (MediaTek MT6739, Android 8.1 stock)
- Goal: sovereign, privacy-first OS with counter-surveillance capabilities

## Architecture

Path B: Linux kernel + vendor HAL + custom userspace. No Android framework above HAL.

| Layer | Status | Notes |
|-------|--------|-------|
| Kernel | Not started | Linux 4.4 from MT6739 BSP sources |
| Vendor blobs | Not extracted | Modem, WiFi, BT, GPS from stock firmware |
| RIL/telephony | Not started | Direct modem interface for calls/SMS |
| WiFi/BT | Not started | wpa_supplicant + bluez or custom |
| UI | Not started | Framebuffer-based, 240x320, keypad input |
| Privacy | Not started | Firewall, DNS filtering, anti-tracking |
| Radio tools | Not started | WiFi scan, BT scan, cell analysis |

## Key constraints

- 1 GB RAM: every megabyte matters. No unnecessary services.
- 240x320 display: no standard Android UI. Custom framebuffer or TUI.
- Keypad input: no touchscreen. T9-style or menu navigation.
- MT6739 vendor blobs: binary-only for modem, WiFi, BT, GPS. Cannot be replaced.
- 32-bit ARM build (armv7-a-neon) despite 64-bit capable SoC.

## Tools

- **mtkclient**: BROM exploit tool for MT6739 bootloader bypass
- **SP Flash Tool**: MediaTek firmware flashing via scatter file
- **adb**: Android Debug Bridge for device probing

## Build

Not yet buildable. Research phase.

## Standards

Follow kanon standards (`standards/STANDARDS.md`, `standards/RUST.md` for any Rust components, `standards/WRITING.md` for docs).

## Naming

Greek names per gnomon.md. Project name: thumos (θυμός, the fighting spirit).
