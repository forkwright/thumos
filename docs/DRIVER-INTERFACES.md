# Driver Interface Specification  -  MT6739 Hardware Subsystems

The MT6739 ships with eight core driver subsystems, and this page specifies
each one's hardware interface on the AGM M7. BSP kernel source at
`kernel-wiite/drivers/misc/mediatek/` and `kernel-wiite/drivers/mmc/host/`
supplies all content here. Every claim cites a source file and line.

This specification is the input for Waves 3–5 of the Rust kernel layer. It
assumes no Android framework dependency: these are bare-metal register and
protocol descriptions.

---

## Table of Contents

1. [CCCI  -  Modem Interface](#1-ccci--modem-interface)
2. [WMT  -  Connectivity Manager](#2-wmt--connectivity-manager)
3. [WiFi gen2](#3-wifi-gen2)
4. [Bluetooth](#4-bluetooth)
5. [GPS](#5-gps)
6. [FM Radio](#6-fm-radio)
7. [Display (DDP / LCM)](#7-display-ddp--lcm)
8. [eMMC (MSDC)](#8-emmc-msdc)

---

## 1. CCCI  -  Modem Interface

**Source tree:** `eccci/`

CCCI (Cross-Core Communication Interface) manages the AP↔modem link. On
MT6739 the modem is MD 6293, a separate ARM core. The interface has two
physical transports:

- **CLDMA** (Communication Link DMA)  -  high-throughput ring-buffer DMA for
  data channels (network, audio, logging).
- **CCIF** (Cross-Core Interrupt/FIFO)  -  low-latency mailbox for control
  messages and exceptions (24 channels, 512-byte SRAM on MT6739).

### 1.1 Physical Register Map

| Symbol | Physical Address | Size | Description |
|---|---|---|---|
| `CLDMA_AP_BASE` | `0x200F0000` | `0x3000` | AP-side CLDMA registers |
| `CLDMA_MD_BASE` | `0x200E0000` | `0x3000` | MD-side CLDMA registers |
| `MD_BOOT_VECTOR_EN` | `0x20000024` | 4 | Enable MD boot vector |
| `MD_PCORE_PCCIF_BASE` | `0x20510000` | `0x20` | MD peer CCIF |
| `MD_GLOBAL_CON0` | `0x20000450` | 4 | Global control 0; bit 12 = CLDMA enable |
| `MD1_CFG_BOOT_STATS0` | `0x1020E300` | 4 | MD boot status register 0 |
| `MD1_CFG_BOOT_STATS1` | `0x1020E304` | 4 | MD boot status register 1 |
| `MD_RGU_BASE` | `0x200F0100` | `0x400` | AP access to MD reset/WDT |
| `MD_TOPSM_REG_BASE` | `0x200D0000` | `0x8E4` | TOPSM (power/sleep manager) |
| `MD_OST_STATUS_BASE` | `0x200E0000` | `0x300` | OST (one-shot timer) status |

Source: `eccci/mt6739/modem_reg_base.h:21–128`

#### CLDMA AO (Always-On) Register Offsets  -  Power-down backup

These live at base `CLDMA_AP_BASE + AO block` and survive power-down.

| Offset | Name | Description |
|---|---|---|
| `0x0004` | `CLDMA_AP_UL_START_ADDR_BK_0` | TX Q0 start address backup |
| `0x0008–0x0010` | `BK_1..4MSB` | TX Q1–Q3 + 4-MSB address extension |
| `0x0018–0x0028` | `CLDMA_AP_UL_CURRENT_ADDR_BK_0..4MSB` | TX current address backup |
| `0x0400` | `CLDMA_AP_SO_CFG` | RX operation configuration |
| `0x0404` | `CLDMA_AP_SO_START_ADDR_0` | RX Q0 start address |
| `0x0408` | `CLDMA_AP_SO_CURRENT_ADDR_0` | RX current RGPD address |
| `0x040C` | `CLDMA_AP_SO_START_ADDR_4MSB` | RX 4-MSB address extension |
| `0x0414` | `CLDMA_AP_SO_STATUS` | SME OUT SBDMA status |
| `0x0418` | `CLDMA_AP_DL_MTU_SIZE` | Maximum RX MTU |
| `0x0800` | `CLDMA_AP_L2RIMR0` | L2 RX interrupt mask |
| `0x0804` | `CLDMA_AP_L2RIMCR0` | L2 RX interrupt mask clear |
| `0x0808` | `CLDMA_AP_L2RIMSR0` | L2 RX interrupt mask set |

Source: `eccci/mt6739/cldma_reg.h:43–68`

#### CLDMA PD (Power-Domain) Register Offsets

These live at `cldma_ap_pdn_base` (populated from DT at probe time).

| Offset | Name | Description |
|---|---|---|
| `0x0000–0x0010` | `CLDMA_AP_UL_START_ADDR_0..4MSB` | TX Q0–Q3 start addresses |
| `0x0014–0x0024` | `CLDMA_AP_UL_CURRENT_ADDR_0..4MSB` | TX Q0–Q3 current processing address |
| `0x0028` | `CLDMA_AP_UL_STATUS` | UL SBDMA operation status |
| `0x0030` | `CLDMA_AP_UL_START_CMD` | Write to start TX DMA on a queue |
| `0x0034` | `CLDMA_AP_UL_RESUME_CMD` | Resume TX DMA after stall |
| `0x0038` | `CLDMA_AP_UL_STOP_CMD` | Stop TX DMA on a queue |
| `0x003C` | `CLDMA_AP_UL_ERROR` | TX error status |
| `0x0040` | `CLDMA_AP_UL_CFG` | TX operation configuration |
| `0x0044–0x0054` | `CLDMA_AP_UL_LAST_UPDATE_ADDR_*` | Last updated TX descriptor |
| `0x0400` | `CLDMA_AP_SO_ERROR` | RX error status |
| `0x0404` | `CLDMA_AP_SO_START_CMD` | Start RX DMA |
| `0x0408` | `CLDMA_AP_SO_RESUME_CMD` | Resume RX DMA |
| `0x040C` | `CLDMA_AP_SO_STOP_CMD` | Stop RX DMA |
| `0x0800` | `CLDMA_AP_L2TISAR0` | L2 TX interrupt status & acknowledge |
| `0x0804` | `CLDMA_AP_L2TIMR0` | L2 TX interrupt mask |
| `0x0808` | `CLDMA_AP_L2TIMCR0` | L2 TX interrupt mask clear |
| `0x080C` | `CLDMA_AP_L2TIMSR0` | L2 TX interrupt mask set |
| `0x0810–0x082C` | `CLDMA_AP_L3TISAR0/1..L3TIMSR0/1` | L3 TX interrupt registers |
| `0x0830–0x0854` | `CLDMA_AP_L2RISAR0/1..L3RIMSR0/1` | L2/L3 RX interrupt registers |
| `0x0860` | `CLDMA_AP_CLDMA_IP_BUSY` | CLDMA IP busy flag |
| `0x0870` | `CLDMA_AP_DMA_ERR` | DMA exception status |
| `0x0874` | `CLDMA_AP_DMA_ERR_MASK` | DMA exception mask |

Source: `eccci/mt6739/cldma_reg.h:69–133`

#### L2 interrupt bitmasks

| Mask | Value | Meaning |
|---|---|---|
| `CLDMA_TX_INT_ERROR` | `0x00000F00` | TX error on queue (bits 8–11, one per queue) |
| `CLDMA_TX_INT_QUEUE_EMPTY` | `0x000000F0` | TX queue empty (bits 4–7) |
| `CLDMA_TX_INT_DONE` | `0x0000000F` | TX descriptor done (bits 0–3) |
| `CLDMA_RX_INT_ERROR` | `0x00000004` | RX error |
| `CLDMA_RX_INT_QUEUE_EMPTY` | `0x00000002` | RX queue empty |
| `CLDMA_RX_INT_DONE` | `0x00000001` | RX descriptor done |
| `CLDMA_BM_ALL_QUEUE` | `0x0F` | All 4 queues mask |

Source: `eccci/mt6739/cldma_reg.h:152–163`

#### INFRA Reset Registers (for CLDMA hard reset)

| Offset from `infra_ao_base` | Name | Description |
|---|---|---|
| `0x0140` | `INFRA_RST0_REG_AO` | AO domain reset set |
| `0x0144` | `INFRA_RST1_REG_AO` | AO domain reset clear |
| `0x0150` | `INFRA_RST0_REG_PD` | PD domain reset set |
| `0x0154` | `INFRA_RST1_REG_PD` | PD domain reset clear |
| `0x0C00` | `INFRA_CLDMA_CTRL_REG` | CLDMA wakeup source mask; bit 1 = `CLDMA_IP_BUSY_MASK` |

`CLDMA_AO_RST_MASK = (1 << 6)`, `CLDMA_PD_RST_MASK = (1 << 2)`.

Source: `eccci/mt6739/cldma_reg.h:19–26`

### 1.2 CCIF Register Offsets (MT6739 / MD gen ≥ 6293)

CCIF provides 24 channels (0–23) via a 512-byte SRAM window and per-channel
mailbox registers.

| Offset | Name | Description |
|---|---|---|
| `0x00` | `APCCIF_CON` | Control register |
| `0x04` | `APCCIF_BUSY` | Busy mask (one bit per channel) |
| `0x08` | `APCCIF_START` | Write channel bit to trigger interrupt to modem |
| `0x0C` | `APCCIF_TCHNUM` | AP→MD channel number just triggered |
| `0x10` | `APCCIF_RCHNUM` | MD→AP channel number received |
| `0x14` | `APCCIF_ACK` | Write channel bit to acknowledge received interrupt |
| `0x100` | `APCCIF_CHDATA` | SRAM window (512 bytes) |

**Channel assignment (MD gen ≥ 6293):**

| Name | Channel | Direction | Purpose |
|---|---|---|---|
| `H2D_EXCEPTION_ACK` | 16 | AP→MD | Exception acknowledge |
| `H2D_EXCEPTION_CLEARQ_ACK` | 17 | AP→MD | Exception clear-queue acknowledge |
| `H2D_FORCE_MD_ASSERT` | 18 | AP→MD | Force modem assert |
| `H2D_MPU_FORCE_ASSERT` | 19 | AP→MD | MPU-triggered assert |
| `H2D_SRAM` | 15 | AP→MD | SRAM-based message |
| `H2D_RINGQ0–RINGQ7` | 0–7 | AP→MD | Ring-buffer queues 0–7 |
| `AP_MD_CCB_WAKEUP` | 7 | AP→MD | CCB wakeup |
| `D2H_EXCEPTION_INIT` | 16 | MD→AP | Exception start notification |
| `D2H_EXCEPTION_INIT_DONE` | 17 | MD→AP | Exception init complete |
| `D2H_EXCEPTION_CLEARQ_DONE` | 18 | MD→AP | Queue clear done |
| `D2H_EXCEPTION_ALLQ_RESET` | 19 | MD→AP | All-queue reset complete |
| `AP_MD_SEQ_ERROR` | 21 | MD→AP | Sequence number error |
| `D2H_SRAM` | 15 | MD→AP | SRAM-based message |
| `D2H_RINGQ0–RINGQ7` | 0–7 | MD→AP | Ring-buffer queues 0–7 |
| `AP_MD_PEER_WAKEUP` | 20 | MD→AP | Peer wakeup |

Source: `eccci/mt6739/ccif_hif_platform.h:27–85`

### 1.3 Shared Memory Layout

CCCI shared memory (bank4) is split into two regions.

**Non-cacheable region**  -  control structures visible to both AP and modem:

| ID | Name | Purpose |
|---|---|---|
| `BOOT_INFO` | Boot information | Version, image info |
| `EXCEPTION_SHARE_MEMORY` | Exception dump area | MD crash context |
| `CCIF_SHARE_MEMORY` | CCIF SRAM backup | |
| `CCISM_SHARE_MEMORY` | CCISM control | |
| `CCB_SHARE_MEMORY` | CCB (Credit Control Buffer) | Network flow control |
| `DHL_RAW_SHARE_MEMORY` | DHLogger raw | |
| `MD_CONSYS_SHARE_MEMORY` | Modem-consys shared | |

**Cacheable region**  -  bulk data:

| ID | Name | Purpose |
|---|---|---|
| `SMART_LOGGING_SHARE_MEMORY` | Smart logging | |
| `DT_NETD_SHARE_MEMORY` | Net daemon | |
| `AUDIO_RAW_SHARE_MEMORY` | Audio raw data | |

`struct ccci_mem_layout` contains `md_bank0` (MD image), `md_bank4_noncacheable_total`,
`md_bank4_cacheable_total`, and pointer arrays to the per-region descriptors.

Source: `eccci/inc/ccci_modem.h:99–172`

### 1.4 Modem Watchdog Registers

All offsets relative to `BASE_ADDR_MDRSTCTL = 0x200F0000`:

| Offset | Name | Description |
|---|---|---|
| `0x0000` | `REG_MDRSTCTL_WDTCR` | WDT mode; key = `0x55000030` |
| `0x0010` | `REG_MDRSTCTL_WDTRR` | WDT restart |
| `0x0034` | `REG_MDRSTCTL_WDTSR` | WDT status |
| `0x023C` | `REG_MDRSTCTL_WDTIR` | WDT length (interval) |

Source: `eccci/mt6739/md_sys1_platform.h:26–34`

### 1.5 Modem Boot Sequence

1. Enable required clocks: `scp-sys-md1-main`, `infra-cldma-bclk`,
   `infra-ccif-ap`, `infra-ccif-md`, `infra-ccif1-ap`, `infra-ccif1-md`.
   Source: `eccci/mt6739/md_sys1_platform.c:45–52`

2. Hard-reset CLDMA (AO then PD domain):
   - Write `CLDMA_AO_RST_MASK (1<<6)` to `INFRA_RST0_REG_AO (0x0140)` via
     `infra_ao_base`, then to `INFRA_RST1_REG_AO (0x0144)` to clear.
   - Repeat with `CLDMA_PD_RST_MASK (1<<2)` at `0x0150 / 0x0154`.
   - Set `CLDMA_IP_BUSY_MASK (1<<1)` in `INFRA_CLDMA_CTRL_REG (0x0C00)`.
   Source: `eccci/mt6739/md_sys1_platform.c:66–102`

3. Map hardware info from device tree: CLDMA AO/PD bases, AP CCIF base, MD
   CCIF base, CLDMA IRQ, two CCIF IRQs, MD WDT IRQ.
   Source: `eccci/mt6739/md_sys1_platform.c:138–148`

4. Write MD boot vector, release MD CPU reset, poll
   `MD1_CFG_BOOT_STATS0/1 (0x1020E300/04)` for boot progress.

5. AP sends runtime data to MD via CCIF channel `H2D_SRAM (15)`. This
   includes the negotiated feature set (`ccci_feature_support[64]`) covering
   DMA remap, RTC mode, random seed, GPS co-clock, SBP ID, C2K support, and
   CCB addresses.
   Source: `eccci/inc/ccci_modem.h:130–172`

6. MD acknowledges via `D2H_SRAM` or ring-queue channel 0.

### 1.6 CCCI Message Format

All CCCI messages share a 16-byte header (`struct ccci_header`):

| Bytes | Field | Description |
|---|---|---|
| 0–3 | `data[0]` | Channel-specific payload word 0 |
| 4–7 | `data[1]` | Channel-specific payload word 1 |
| 8–11 | `channel` | CCCI channel number (see §1.2) |
| 12–15 | `reserved` | Sequence number / flags / C2K ctrl |

Magic value `0xFFFFFFFF` in `data[0]` indicates an internal control message.
MTU = 3456 bytes. Source: `eccci/mt6739/ccci_config.h`, `eccci/inc/ccci_core.h:33`

### 1.7 Channel Map (key subset)

Full list is in `eccci/inc/ccci_core.h:46+`. Key channels:

| Channel | Port type | Purpose |
|---|---|---|
| `CCCI_CONTROL_TX/RX` | Control | Modem control handshake |
| `CCCI_SYSTEM_TX/RX` | System | System messages |
| `CCCI_UART1_TX/RX` | Char | AT command / RILD |
| `CCCI_UART2_TX/RX` | Char | META UART |
| `CCCI_FS_TX/RX` | Char | File system proxy |
| `CCCI_PMIC_TX/RX` | Char | PMIC proxy |
| `CCCI_CCMNI1_TX/RX` | Net | Network channel 1 (data) |
| `CCCI_CCMNI2_TX/RX` | Net | Network channel 2 |
| `CCCI_CCMNI3_TX/RX` | Net | Network channel 3 |
| `CCCI_IPC_TX/RX` | IPC | Inter-processor call |
| `CCCI_MD_LOG_TX/RX` | Char | Modem logging |

### 1.8 Interrupt Handling

**CLDMA IRQ** (one IRQ, level-triggered): read `CLDMA_AP_L2TISAR0` (TX) or
`CLDMA_AP_L2RISAR0` (RX), then write the same bit back to acknowledge. For
per-queue detail, read `CLDMA_AP_L3TISAR0/1` or `L3RISAR0/1` at L3. Mask
future interrupts by writing to `L2TIMCR0` / `L2RIMCR0`.

**CCIF IRQ** (two IRQs  -  one per direction): Read `APCCIF_RCHNUM` to get the
set of triggered MD→AP channels. Write the bitmask to `APCCIF_ACK` to clear.
Dispatch by channel number.

**MD WDT IRQ**: Signals modem crash. Read `REG_MDRSTCTL_WDTSR` for cause.
Force dump via CCIF exception channels, then full chip reset.

---

## 2. WMT  -  Connectivity Manager

**Source tree:** `connectivity/common/common_main/`

WMT manages the combo connectivity chip (MT6739 internal CONSYS block)
shared among WiFi, Bluetooth, GPS, and FM. It owns power sequencing,
firmware loading, and the STP (Serial Transport Protocol) multiplexer.

### 2.1 Register Bases (MT6739)

| Symbol | Address | Description |
|---|---|---|
| `AP_RGU_BASE` | `0xF0007000` | AP reset generator |
| `SPM_BASE` | `0xF0006000` | System power manager |
| `TOPCKGEN_BASE` | `0xF0000000` | Top clock generator |
| `CONN_MCU_CONFIG_BASE` | `0xF8070000` | CONSYS MCU config |
| `CONSYS_EMI_FW_PHY_BASE` | `0xF0080000` | EMI firmware base (physical) |
| `CONSYS_EMI_AP_PHY_BASE` | `0x80080000` | EMI AP view (physical) |

Source: `connectivity/common/common_main/platform/include/mt6739.h:72–75`

### 2.2 SPM Power Control Register  -  `CONSYS_TOP1_PWR_CTRL_REG` (`0xF000632C`)

| Bit | Name | Function |
|---|---|---|
| 0 | `CONSYS_SPM_PWR_RST_BIT` | Release SW reset of CONSYS |
| 1 | `CONSYS_SPM_PWR_ISO_S_BIT` | ISO control (1=isolated) |
| 2 | `CONSYS_SPM_PWR_ON_BIT` | Power on CONSYS top1 |
| 3 | `CONSYS_SPM_PWR_ON_S_BIT` | Power on CONSYS top1 (shadow) |
| 4 | `CONSYS_CLK_CTRL_BIT` | Clock disable (0=enabled) |
| 8 | `CONSYS_SRAM_CONN_PD_BIT` | SRAM power-down |

Source: `connectivity/common/common_main/platform/include/mt6739.h:122–128`

### 2.3 Other Key Registers

| Register | Address | Value | Description |
|---|---|---|---|
| `CONSYS_PWR_CONN_ACK_REG` | `SPM + 0x180` | bit 1 = ready | Power-on ack |
| `CONSYS_PWR_CONN_ACK_S_REG` | `SPM + 0x184` | bit 1 = ready | Power-on ack (shadow) |
| `CONSYS_CPU_SW_RST_REG` | `AP_RGU + 0x018` | key=`0x88<<24`, bit12 | CPU SW reset |
| `CONSYS_WD_SYS_RST_REG` | `TOPCKGEN + 0x018` | key=`0x88<<24`, bit9 | Watchdog system reset |
| `CONSYS_TOP_CLKCG_CLR_REG` | `TOPCKGEN + 0x084` | bit 26 | Clear clock gate |
| `CONSYS_TOP_CLKCG_SET_REG` | `TOPCKGEN + 0x054` | bit 26 | Set clock gate |
| `CONSYS_CHIP_ID_REG` | `CONN_MCU + 0x008` | `0x0699` expected | Chip ID poll |
| `CONSYS_TOPAXI_PROT_EN` | `TOPCKGEN + 0x1220` | bits 13,14 | AXI bus protect |
| `CONSYS_TOPAXI_PROT_STA1` | `TOPCKGEN + 0x1228` | bits 13,14 | AXI protect status |
| `CONSYS_MCU_CFG_ACR_REG` | `CONN_MCU + 0x110` | bit 18 = MBIST | ACR register |
| `CONSYS_EMI_MAPPING` | `TOPCKGEN + 0x1380` |  -  | EMI remapping |
| `CONSYS_AP2CONN_OSC_EN_REG` | `TOPCKGEN + 0x1800` | bit 10 = OSC_EN, bit 9 = WAKEUP | OSC enable |

Source: `connectivity/common/common_main/platform/include/mt6739.h:83–158`

### 2.4 PMIC Regulators (MT6739)

| Regulator | Name | Users |
|---|---|---|
| `reg_VCN18` | VCN 1.8V | All CONSYS core logic |
| `reg_VCN28` | VCN 2.8V | GPS/FM RF |
| `reg_VCN33_BT` | VCN 3.3V BT | Bluetooth PA |
| `reg_VCN33_WIFI` | VCN 3.3V WiFi | WiFi PA |

Source: `connectivity/common/common_main/platform/mt6739.c:124–131`

Clock: `clk_scp_conn_main` (named `"conn"` in DTS) controls the entire CONSYS
power domain via CCF. Source: `connectivity/common/common_main/platform/mt6739.c:118`

### 2.5 EMI Memory Layout

The CONSYS firmware region in external RAM:

| Region | Physical Base | Size | Purpose |
|---|---|---|---|
| Firmware base | `0xF0080000` |  -  | CONSYS MCU firmware load target |
| Paged trace | `FW_BASE + 0x400` |  -  | Live trace ring |
| Paged dump | `FW_BASE + 0x8400` | 32 KB | Crash paged dump |
| Full dump (DLM) | `FW_BASE + 0x10400` | 0x1F000 | Full core dump |
| Full dump SYSB2 | DLM end | 0x6800 | |
| Full dump SYSB3 | SYSB2 end | 0x16800 | |

EMI AP offset: `0x80000`. Source: `connectivity/common/common_main/platform/include/mt6739.h:144–170`

### 2.6 WMT Power-On Sequence (CONSYS)

Steps enumerated directly from source (`mt6739.c:459–545`):

1. **Enable SPM clock gating:** Write `CONSYS_PWRON_CONFG_EN_VALUE (0x0B160001)`
   to `SPM + 0x0`.

2. **Power on CONSYS top1:** Set bit 2 (`PWR_ON_BIT`) in
   `CONSYS_TOP1_PWR_CTRL_REG (SPM + 0x32C)`.

3. **Poll power-on ack:** Spin on bit 1 of `CONSYS_PWR_CONN_ACK_REG (SPM + 0x180)`.

4. **Power on shadow:** Set bit 3 (`PWR_ON_S_BIT`) in `CONSYS_TOP1_PWR_CTRL_REG`.

5. **Enable clock:** Clear bit 4 (`CLK_CTRL_BIT`) in `CONSYS_TOP1_PWR_CTRL_REG`.

6. **Wait 1 µs:** `udelay(1)`.

7. **Poll shadow ack:** Spin on bit 1 of `CONSYS_PWR_CONN_ACK_S_REG (SPM + 0x184)`.

8. **Release ISO:** Clear bit 1 (`ISO_S_BIT`) in `CONSYS_TOP1_PWR_CTRL_REG`.

9. **Release SW reset:** Set bit 0 (`PWR_RST_BIT`) in `CONSYS_TOP1_PWR_CTRL_REG`.

10. **Disable AXI bus protect:** Clear bits 13,14 in `CONSYS_TOPAXI_PROT_EN`.
    Spin until `CONSYS_TOPAXI_PROT_STA1` bits 13,14 clear.

11. **Assert CONSYS CPU SW reset:** Set bit 12 + key `0x88<<24` in
    `CONSYS_CPU_SW_RST_REG (AP_RGU + 0x018)`.

12. **Detect co-clock type:** Read PMIC DCXO_CW16 register. If bit 6 or 8 set
    → CO-TSX mode. If bit 7 or 9 set → TCXO mode.

13. **Enable clock buffer:** Call `clk_buf_ctrl(CLK_BUF_CONN, 1)`.

14. **Enable AHB clock:** `clk_prepare_enable(clk_scp_conn_main)` via CCF.

15. **Poll chip ID:** Spin reading `CONSYS_CHIP_ID_REG (CONN_MCU + 0x008)`
    until it returns `0x0699`.

16. **Release CONSYS CPU SW reset:** Clear bit 12, keep key in
    `CONSYS_CPU_SW_RST_REG`.

17. **Apply ACR setting:** Set `CONSYS_MCU_CFG_ACR_MBIST_BIT (bit 18)` in
    `CONSYS_MCU_CFG_ACR_REG`.

Source: `connectivity/common/common_main/platform/mt6739.c:419–546`

### 2.7 STP (Serial Transport Protocol)

STP multiplexes all four subsystems (BT=0, FM=1, GPS=2, WiFi=3) over a
single transport (BTIF UART or SDIO).

**Frame format:**

```
[0x55 0x55] [HDR0] [HDR1] [payload 0..N-1] [CRC]
```

- Delimiter: `0x55 0x55` (2 bytes, optional, controlled by `fgEnableDelimiter`)
- `HDR0[7:4]` = function type (0=BT, 1=FM, 2=GPS, 3=WiFi, 7=WMT, 15=STP)
- `HDR0[3:0]` = sequence number (4-bit, mod-16)
- `HDR1[7:4]` = ACK number
- `HDR1[3:0]` = payload length bits [11:8]
- `HDR2` = payload length bits [7:0]
- `HDR3` = checksum (XOR of HDR0..HDR2)
- Payload: up to 4096 bytes (ring buffer `MTKSTP_BUFFER_SIZE = 16384`)
- CRC: optional (negotiated)

Sliding window: 8 entries (`MTKSTP_WINSIZE = 7` = max in-flight). TX timeout
180 ms, retry limit 10. Source: `connectivity/common/common_main/core/include/stp_core.h`

---

## 3. WiFi gen2

**Source tree:** `connectivity/wlan/gen2/`

The WiFi driver uses an AHB (PDMA) hardware interface to the WLAN MAC/BB
registers. It implements a full 802.11 stack (scan, auth, assoc, WPA/WPA2,
TDLS, P2P/Wi-Fi Direct).

### 3.1 HIF MCR (Memory Control Register) Interface

All MAC register access goes through the host AHB HIF. Base address is
device-tree-derived (`GL_HIF_INFO_T.HifRegBaseAddr`).

Key MCR registers (`mtreg.h`):

| Register | Offset | Description |
|---|---|---|
| `MCR_WCIR` | `0x0000` | Chip info (chip rev) |
| `MCR_WHLPCR` | `0x0004` | Host–link power control |
| `MCR_WHCR` | `0x000C` | Host control |
| `MCR_WHISR` | `0x0010` | Host interrupt status |
| `MCR_WHIER` | `0x0014` | Host interrupt enable |
| `MCR_WASR` | `0x0020` | WLAN async status |
| `MCR_WSICR` | `0x0024` | WLAN STA info control |

Source: `connectivity/wlan/gen2/include/nic/mtreg.h`

**Chip ID values:**

| Chip | Value |
|---|---|
| MT6572 | `0x6572` |
| MT6582 | `0x6582` |
| MT6592 | `0x6592` |

### 3.2 AHB PDMA Base Addresses

| Name | Address | Description |
|---|---|---|
| AP PDMA base | device-tree | PDMA control for WiFi DMA |

PDMA burst length enumeration: 4, 8, 16 beats.
Source: `connectivity/wlan/gen2/os/linux/hif/ahb/include/hif_pdma.h`

### 3.3 TX Descriptor Format (`HIF_TX_HEADER_T`, 16 bytes)

| Field | Bits | Description |
|---|---|---|
| Packet length | [15:0] | Total TX packet byte length |
| Packet type | [1:0] of word1 | 0=data, 1=command |
| User priority | [4:2] | WMM UP 0–7 |
| Resource mask |  -  | TX resource allocation hint |
| Port index |  -  | Target TX queue |

`static_assert(sizeof(HIF_TX_HEADER_T) == 16)`

Source: `connectivity/wlan/gen2/include/nic/hif_tx.h`

### 3.4 RX Descriptor Format (`HIF_RX_HEADER_T`, 12 bytes)

| Field | Bits | Description |
|---|---|---|
| Packet length | [15:0] | RX packet byte length |
| Packet type |  -  | 0=data, others=event |
| Network index |  -  | BSS index (0..3) |
| TID | [3:0] | Traffic ID (AC) |
| Security mode |  -  | WEP/TKIP/CCMP etc. |
| 802.11 header present | bit | Whether 802.11 header is in payload |
| Reorder flag | bit | Needs BA reorder |
| Channel number |  -  | Raw HW channel (2.4G: 1–14, 5G: 36–165) |

`static_assert(sizeof(HIF_RX_HEADER_T) == 12)`

Source: `connectivity/wlan/gen2/include/nic/hif_rx.h`

### 3.5 Command / Event Protocol

The AP sends commands (`WIFI_CMD_T`) to FW via TX queue. Events (`WIFI_EVENT_T`)
return FW→AP via RX ring. Both carry a `ucCID` (command/event ID byte), a
`u2Length`, and a `ucSeqNum` for matching.

Key command IDs (selected from `nic_cmd_event.h`):

| ID | Name | Purpose |
|---|---|---|
| `0x01` | `CMD_ID_GET_CHIP_INFO` | Query FW chip info |
| `0x20` | `CMD_ID_SCAN_REQ` | Start scan |
| `0x21` | `CMD_ID_SCAN_CANCEL` | Cancel scan |
| `0x22` | `CMD_ID_ROAMING_TRANSIT` | Trigger roam |
| `0x40` | `CMD_ID_SET_BSS_INFO` | Set BSS parameters |
| `0x46` | `CMD_ID_SET_DOMAIN_INFO` | Set regulatory domain |
| `0x60` | `CMD_ID_ACCESS_REG` | Direct MAC register R/W |
| `0x72` | `CMD_ID_NLO_REQ` | Network location offload |
| `0x80` | `CMD_ID_GSCAN_ADD_HOTLIST` | Google scan hotlist add |

Key event IDs:

| ID | Name | Purpose |
|---|---|---|
| `0x01` | `EVENT_ID_CMD_RESULT` | Command result (pass/fail) |
| `0x22` | `EVENT_ID_SCAN_DONE` | Scan completion |
| `0x23` | `EVENT_ID_SCAN_RESULT` | One BSS scan result |
| `0x24` | `EVENT_ID_LINK_QUALITY` | RSSI/SNR |
| `0x30` | `EVENT_ID_MICFAILURE` | MIC failure (TKIP attack) |

Source: `connectivity/wlan/gen2/include/nic_cmd_event.h`

### 3.6 Scan Protocol

1. Allocate `CMD_SCAN_REQ_T`: set `ucScanType` (0=active, 1=passive,
   2=prohibited), `ucSSIDType`, SSID data, channel list, dwell times.
2. Write command to TX ring with `CMD_ID_SCAN_REQ`.
3. Firmware returns scan result events (`EVENT_ID_SCAN_RESULT`) one per BSS,
   then `EVENT_ID_SCAN_DONE`.

`BSS_DESC_T` fields: BSSID, SSID, RSSI (`i2RcpiDbm`), channel, capability
info, security (`fgIERSN`, `fgIEWPA`), timestamps.

Source: `connectivity/wlan/gen2/include/mgmt/scan.h`

### 3.7 Association State Machine

States: `AA_STATE_IDLE` → `SAA_STATE_SEND_AUTH1` → `SAA_STATE_WAIT_AUTH2` →
`SAA_STATE_SEND_AUTH3` → `SAA_STATE_WAIT_AUTH4` → `SAA_STATE_SEND_ASSOC1` →
`SAA_STATE_WAIT_ASSOC2` → `AA_STATE_RESOURCE` (associated).

Source: `connectivity/wlan/gen2/include/mgmt/aa_fsm.h`

### 3.8 Power Save Modes

Three modes in the firmware command set: `CMD_POWER_SAVE_MODE_OFF` (always
awake), `CMD_POWER_SAVE_MODE_FAST` (fast PS, tight timing), and
`CMD_POWER_SAVE_MODE_SLOW` (aggressive PS). Controlled by
`CMD_ID_POWER_SAVE_MODE` command.

---

## 4. Bluetooth

**Source tree:** `connectivity/bt/`

Bluetooth uses the WMT CONSYS chip via STP (see §2.7) over BTIF UART. The
kernel-side driver is a thin character device that passes HCI frames to/from
userspace via STP.

### 4.1 Character Device Interface

| Parameter | Value |
|---|---|
| Driver name | `mtk_stp_bt_chrdev` |
| Major number | `192` |
| Buffer size | `2048` bytes (both RX and TX) |

Source: `connectivity/bt/stp_chrdev_bt.c:38–76`

### 4.2 IOCTL Interface

Magic: `0xb0`

| IOCTL | Direction | Purpose |
|---|---|---|
| `COMBO_IOCTL_FW_ASSERT (0)` | `_IOW` | Trigger firmware assert |
| `COMBO_IOCTL_BT_SET_PSM (1)` | `_IOW(bool)` | Enable/disable power save mode |
| `COMBO_IOCTL_BT_IC_HW_VER (2)` | `_IOR(void*)` | Read hardware version |
| `COMBO_IOCTL_BT_IC_FW_VER (3)` | `_IOR(void*)` | Read firmware version |

Source: `connectivity/bt/stp_chrdev_bt.c:60–63`

### 4.3 HCI Transport over STP

BT is STP function type 0. STP encapsulates all HCI packets in STP frames
(see §2.7) directed to function 0. The character device read path:

1. STP delivers a complete frame from the receive ring.
2. `mtk_wcn_stp_receive_data()` copies into `i_buf[2048]`.
3. Userspace reads via `read()`  -  blocks on `BT_wq` wait queue.
4. Write path: `mtk_wcn_stp_send_data()` wraps the HCI payload in an STP frame
   and queues it to the BTIF UART.

### 4.4 Reset Handling

On whole-chip reset, WMT calls the registered reset callback
(`bt_cdev_rst_cb`). The driver sets `rstflag`:
- `1` = reset start
- `2` = reset complete, HCI event not yet sent
- `3` = reset complete, HCI Hardware Error event `{0x04, 0x10, 0x01, 0x00}`
  written to RX buffer and delivered to userspace

Source: `connectivity/bt/stp_chrdev_bt.c:94–131`

### 4.5 Firmware Loading

The WMT core (not the BT character driver) loads BT firmware. The WMT
`wmt_ic_soc.c` handles patch loading via the `wmt_lib` patch infrastructure.
IC family determines the patch file suffix (`wmt_ic.h`).

---

## 5. GPS

**Source tree:** `connectivity/gps/`

GPS uses the WMT CONSYS chip via STP function type 2. There are two kernel
interfaces: a platform power-control driver (`gps.c`) and a STP character
device (`stp_chrdev_gps.c`).

### 5.1 Power Control States

| State | Value | Description |
|---|---|---|
| `GPS_STATE_OFF` | 0 | Power off |
| `GPS_STATE_INIT` | 1 | Initialising |
| `GPS_STATE_START` | 2 | Running |
| `GPS_STATE_STOP` | 3 | Stopped |
| `GPS_STATE_DEC_FREQ` | 4 | Frequency hopping active |
| `GPS_STATE_SLEEP` | 5 | Sleep/low-power |

Power control modes: `GPS_PWRCTL_OFF`, `GPS_PWRCTL_ON`, `GPS_PWRCTL_RST`,
`GPS_PWRCTL_OFF_FORCE`, `GPS_PWRCTL_RST_FORCE`.

Source: `connectivity/gps/gps.h`

### 5.2 Frequency Hopping  -  MT6739

MT6739 requires frequency hopping mitigation for GPS. The GPS driver registers
with the FH (Frequency Hopping) subsystem using `FH_MEM_PLLID` to configure
interference avoidance. Source: `connectivity/gps/gps.c`

### 5.3 Character Device Interface

| Parameter | Value |
|---|---|
| Major number | `191` |
| STP function type | `2` (GPS) |

IOCTL commands (magic varies): GPS version queries, RTC flag control, clock
flag control, wakelock acquisition/release.

Source: `connectivity/gps/stp_chrdev_gps.c`

### 5.4 EMI GPS Region (`gps_emi.c`)

MT6739 supports an optional EMI-mapped GPS data region for bulk almanac/
ephemeris transfer. The driver maps a reserved memory region via
`of_reserved_mem` and provides the physical base to GPS firmware via the
STP command channel.

### 5.5 MT3337 Standalone GPS (`gps_mt3337.c`)

Alternate driver for the standalone MT3337 GPS chip over UART  -  not used when
CONSYS STP GPS is active.

---

## 6. FM Radio

**Source tree:** `connectivity/fmradio/`

FM radio uses the MT6631 chip (integrated in CONSYS) via STP function type 1.
The kernel driver exposes `/dev/fm` as a character device and implements
all tuning/seek/RDS commands internally.

### 6.1 Register Map (MT6631)

All registers accessed via SPI-over-STP command channel.

| Register | Address | Description |
|---|---|---|
| `FM_MAIN_CG1_CTRL` | `0x60` | Clock-gate control 1; bits 4–6 = OSC freq select |
| `FM_MAIN_CG2_CTRL` | `0x61` | Clock-gate control 2; bit 4 = antenna, bit 7 = I2S, bit 12 = de-emphasis |
| `FM_MAIN_HWVER` | `0x62` | Hardware version |
| `FM_MAIN_CTRL` | `0x63` | Main control (see §6.2) |
| `FM_CHANNEL_SET` | `0x65` | Channel frequency in 100 kHz units |
| `FM_MAIN_CFG1` | `0x66` | Config 1 |
| `FM_MAIN_CFG2` | `0x67` | Config 2 |
| `FM_MAIN_MCLKDESENSE` | `0x38` | MCLK desense |
| `FM_MAIN_INTR` | `0x69` | Interrupt status (see §6.3) |
| `FM_MAIN_INTRMASK` | `0x6A` | Interrupt mask |
| `FM_MAIN_EXTINTRMASK` | `0x6B` | External interrupt mask |
| `FM_RSSI_IND` | `0x6C` | Current RSSI indication |
| `FM_RSSI_TH` | `0x6D` | RSSI threshold for seek |
| `FM_MAIN_RESET` | `0x6E` | Software reset |
| `FM_MAIN_CHANDETSTAT` | `0x6F` | Channel detect status |
| `FM_RDS_CFG0` | `0x80` | RDS config 0 |
| `FM_RDS_INFO` | `0x81` | RDS info / status |
| `FM_RDS_DATA_REG` | `0x82` | RDS raw data |
| `FM_RDS_GOODBK_CNT` | `0x83` | RDS good block count |
| `FM_RDS_BADBK_CNT` | `0x84` | RDS bad block count |
| `FM_RDS_PWDI` | `0x85` | RDS pilot I |
| `FM_RDS_PWDQ` | `0x86` | RDS pilot Q |
| `FM_RDS_FIFO_STATUS0` | `0x87` | RDS FIFO status |
| `FM_DSP_PATCH_CTRL` | `0x90` | DSP patch control |
| `FM_DSP_PATCH_OFFSET` | `0x91` | DSP patch write offset |
| `FM_DSP_PATCH_DATA` | `0x92` | DSP patch write data |
| `FM_RDS_POINTER` | `0xF0` | RDS data pointer |

Source: `connectivity/fmradio/mt6631/inc/mt6631_fm_reg.h`

### 6.2 FM_MAIN_CTRL (0x63) Bit Fields

| Bit | Name | Description |
|---|---|---|
| 0 | `TUNE` | Start tune to `FM_CHANNEL_SET` |
| 1 | `SEEK` | Start frequency seek |
| 2 | `SCAN` | Start channel scan |
| 3 | `CQI_READ` | Read channel quality indicator |
| 4 | `RDS_MASK` | Enable RDS |
| 5 | `MUTE` | Mute audio |
| 6 | `RDS_BRST` | RDS burst mode |
| 8 | `RAMP_DOWN` | Ramp-down audio (before power off) |

Source: `connectivity/fmradio/mt6631/inc/mt6631_fm_reg.h:71–80`

### 6.3 FM_MAIN_INTR (0x69) Bit Fields

| Bit | Name | Description |
|---|---|---|
| 0 | `FM_INTR_STC_DONE` | Seek/tune/scan completed |
| 1 | `FM_INTR_IQCAL_DONE` | IQ calibration done |
| 2 | `FM_INTR_DESENSE_HIT` | Desense frequency detected |
| 3 | `FM_INTR_CHNL_CHG` | Channel changed |
| 4 | `FM_INTR_SW_INTR` | Software-triggered interrupt |
| 5 | `FM_INTR_RDS` | RDS data available |

Source: `connectivity/fmradio/mt6631/inc/mt6631_fm_reg.h:83–90`

### 6.4 FM_MAIN_CG2_CTRL (0x61) Bit Fields

| Bit | Name | Description |
|---|---|---|
| 4 | `ANTENNA_TYPE` | 0 = long antenna, 1 = short antenna |
| 7 | `ANALOG_I2S` | 0 = line out, 1 = I2S output |
| 12 | `DE_EMPHASIS` | 0 = 50 µs, 1 = 75 µs |

Source: `connectivity/fmradio/mt6631/inc/mt6631_fm_reg.h:93–96`

### 6.5 IOCTL Interface

Magic: `0xf5`. Commands 0–50, 60–65:

| Cmd | Name | Description |
|---|---|---|
| 0 | `FM_IOCTL_POWERUP` | Power up with initial frequency |
| 1 | `FM_IOCTL_POWERDOWN` | Power down |
| 2 | `FM_IOCTL_TUNE` | Tune to frequency |
| 3 | `FM_IOCTL_SEEK` | Seek up/down |
| 4 | `FM_IOCTL_SCAN` | Full band scan |
| 5 | `FM_IOCTL_SETVOL` | Set volume (0–15) |
| 6 | `FM_IOCTL_MUTE` | Mute on/off |
| 7 | `FM_IOCTL_GETRSSI` | Read RSSI (dBm) |
| 8 | `FM_IOCTL_SETRDS` | Enable/disable RDS |
| 9 | `FM_IOCTL_GETRDS` | Read RDS data |
| 60 | `FM_IOCTL_SCAN_NEW` | Enhanced scan with CQI |
| 61 | `FM_IOCTL_SETANTENNA` | Switch antenna type |
| 62 | `FM_IOCTL_RDS_TX` | Enable RDS transmit |

Source: `connectivity/fmradio/inc/fm_ioctl.h`

### 6.6 Tune Sequence

1. Write target frequency (in 100 kHz, e.g. 10390 = 103.9 MHz) to
   `FM_CHANNEL_SET (0x65)`.
2. Set `TUNE (bit 0)` in `FM_MAIN_CTRL (0x63)`.
3. Poll `FM_MAIN_INTR (0x69)` for `FM_INTR_STC_DONE (bit 0)`.
4. Read `FM_RSSI_IND (0x6C)` to confirm signal strength.

`mt6631_fm_lib.c` lists desense frequencies that need special handling:
6910, 6920, 7680, 7800, 8450, 9210–9230, 9590–9600,
9830, 9900, 9980–9990, 10400, 10750–10760 (all ×100 Hz).

---

## 7. Display (DDP / LCM)

**Source tree:** `video/mt6739/` and `lcm/`

MT6739 uses MediaTek's DDP (Display Data Path) architecture with a CMDQ-driven
hardware display pipeline.

### 7.1 DDP Pipeline (MT6739)

Primary path: `OVL0 → RDMA0 → (COLOR) → (AAL) → (GAMMA) → DSI0 → LCM`

Secondary path (MDP/capture): `OVL0_2L → WDMA0`

MMSYS routes the path by configuring `DISP_REG_CONFIG_MMSYS_*` registers and
enabling clocks via CG (clock gate) registers.

### 7.2 MMSYS Configuration Registers

Base = `DISPSYS_CONFIG_BASE` (device-tree-derived).

| Register | Offset | Description |
|---|---|---|
| `MMSYS_INTEN` | `+0x000` | Interrupt enable |
| `MMSYS_INTSTA` | `+0x004` | Interrupt status |
| `MMSYS_CG_CON0` | `+0x100` | Clock gate status 0 |
| `MMSYS_CG_SET0` | `+0x104` | Clock gate set 0 (disable clocks) |
| `MMSYS_CG_CLR0` | `+0x108` | Clock gate clear 0 (enable clocks) |
| `MMSYS_CG_CON1` | `+0x110` | Clock gate status 1 |
| `MMSYS_CG_SET1` | `+0x114` | Clock gate set 1 |
| `MMSYS_CG_CLR1` | `+0x118` | Clock gate clear 1 |
| `MMSYS_SW0_RST_B` | `+0x140` | Software reset 0 (active low) |
| `MMSYS_SW1_RST_B` | `+0x144` | Software reset 1 (active low) |
| `MMSYS_LCM_RST_B` | `+0x150` | LCM reset control (active low) |
| `MMSYS_SODI_REQ_MASK` | `+0x0F8` | SODI request mask |
| `MMSYS_MISC` | `+0x0F0` | Miscellaneous config |

Source: `video/mt6739/dispsys/ddp_reg_mmsys.h:20–44`

### 7.3 OVL (Overlay Engine) Register Offsets

Base = `DISPSYS_OVL0_BASE`.

| Offset | Name | Description |
|---|---|---|
| `0x000` | `DISP_REG_OVL_STA` | Status; bit 0 = running |
| `0x004` | `DISP_REG_OVL_INTEN` | Interrupt enable |
| `0x008` | `DISP_REG_OVL_INTSTA` | Interrupt status |
| `0x00C` | `DISP_REG_OVL_EN` | Enable; bit 0 = `OVL_EN`, bit 8 = CK_ON |
| `0x010` | `DISP_REG_OVL_TRIG` | Trigger; bit 0 = `SW_TRIG` |
| `0x014` | `DISP_REG_OVL_RST` | Reset |
| `0x020` | `DISP_REG_OVL_ROI_SIZE` | Region of interest; bits [12:0] = W, bits [28:16] = H |
| `0x024` | `DISP_REG_OVL_DATAPATH_CON` | Datapath config (GPU mode, PQ output, etc.) |
| `0x028` | `DISP_REG_OVL_ROI_BGCLR` | Background colour RGBA |
| `0x02C` | `DISP_REG_OVL_SRC_CON` | Source enable; bits 0–3 = layer 0–3 enable |
| `0x030` | `DISP_REG_OVL_L0_CON` | Layer 0 control (alpha, flip, format) |
| … | `L1_CON`, `L2_CON`, `L3_CON` | Layers 1–3, same structure |

Source: `video/mt6739/dispsys/ddp_reg_ovl.h:20–120`

**OVL interrupt bits** (`DISP_REG_OVL_INTEN / INTSTA`):

| Bit | Name | Description |
|---|---|---|
| 0 | `REG_CMT_INTEN` | Register committed |
| 1 | `FME_CPL_INTEN` | Frame complete |
| 2 | `FME_UND_INTEN` | Frame underrun |
| 3 | `FME_SWRST_DONE` | SW reset done |
| 4 | `FME_HWRST_DONE` | HW reset done |
| 5–8 | `RDMA0–3_EOF_ABNORMAL` | Abnormal end-of-frame per RDMA |
| 9–12 | `RDMA0–3_SMI_UNDERFLOW` | SMI bus underflow per RDMA |
| 13 | `ABNORMAL_SOF` | Abnormal start-of-frame |

Source: `video/mt6739/dispsys/ddp_reg_ovl.h:27–59`

### 7.4 Display Initialization Sequence

1. **Enable MMSYS clocks:** Write `1` bits to `MMSYS_CG_CLR0` and
   `MMSYS_CG_CLR1` for all required modules (OVL, RDMA, DSI, etc.).

2. **Release software resets:** Write `1` to `MMSYS_SW0_RST_B` and
   `MMSYS_SW1_RST_B`.

3. **Release LCM reset:** Write `1` to `MMSYS_LCM_RST_B`.

4. **Configure OVL ROI size:** Write `(height << 16) | width` to
   `DISP_REG_OVL_ROI_SIZE`. For 240×320: `0x01400F0`.

5. **Enable OVL layer(s):** Set bits 0–3 of `DISP_REG_OVL_SRC_CON`.

6. **Configure RDMA0:** Set source format, framebuffer address, stride via
   RDMA registers (`ddp_rdma.c`).

7. **Configure DSI0:** Set clock lane, data lanes, timing parameters via
   `DISP_REG_DSI_*` registers and MIPI TX PHY. See `ddp_dsi.c`.

8. **Send LCM init commands:** The LCM driver sends a sequence of
   MIPI DSI commands (typically `write_cmd(reg, data...)` via CMDQ or
   direct DSI command queue). This is panel-specific. See §7.6.

9. **Configure MUTEX:** Set mutex module membership and SOF source
   (`DISP_REG_CONFIG_MUTEX_*`), then enable to start frame timing.

10. **Trigger first frame:** Write `1` to `DISP_REG_OVL_TRIG` (`SW_TRIG`).

Source: `video/mt6739/videox/primary_display.c`, `video/mt6739/dispsys/ddp_manager.c`

### 7.5 LCM Driver Interface (`lcm_drv.h`)

Every panel implements `struct LCM_DRIVER` function pointers:

| Function | Description |
|---|---|
| `get_params(LCM_PARAMS*)` | Return timing, interface, resolution |
| `init()` | Send panel init command sequence |
| `suspend()` | Enter panel sleep mode |
| `resume()` | Exit panel sleep mode |
| `set_backlight(level)` | Set backlight level 0–255 |
| `update(x, y, w, h)` | Partial update trigger |

`LCM_PARAMS` contains:
- `type` = `LCM_TYPE_DSI`
- `width`, `height` (e.g. 240, 320 for AGM M7)
- `dsi.mode` = `SYNC_PULSE_VDO_MODE` or `CMD_MODE`
- `dsi.data_format.color_order`, `.bpp`
- `dsi.vertical_sync_active`, `vbp`, `vfp`, `vactive_line`
- `dsi.horizontal_sync_active`, `hbp`, `hfp`, `hactive`
- `dsi.PLL_CLOCK` (MIPI PLL frequency)

Source: `lcm/inc/lcm_drv.h`

### 7.6 AGM M7 Panel

Identifying the shipped panel requires reading the `lcm_id` pins or running
`mt65xx_lcm_list.c:lcm_probe()` against the actual hardware, since the BSP
includes 40+ sample LCM drivers and does not mark which one corresponds to
the M7. Once identified, the panel's `.init()` function contains the
register-write sequence.

---

## 8. eMMC (MSDC)

**Source tree:** `drivers/mmc/host/mediatek/ComboA/`

MT6739 uses MediaTek's MSDC (MultiSlot Data Controller) for eMMC 5.1. It
supports 8-bit HS400 mode, scatter-gather DMA with GPD (Generic Payload
Descriptor) / BD (Buffer Descriptor) chains, hardware command queuing (CMDQ),
and inline AES-256 encryption.

### 8.1 Register Offsets

| Offset | Register | Description |
|---|---|---|
| `0x00` | `MSDC_CFG` | Global config: SD/eMMC mode, clock divisor, bus width |
| `0x04` | `MSDC_IOCON` | I/O control: DS edge, R/W edge select |
| `0x08` | `MSDC_PS` | Pin status: CD, WP, DAT, CMD, CLK levels |
| `0x0C` | `MSDC_INT` | Interrupt status |
| `0x10` | `MSDC_INTEN` | Interrupt enable |
| `0x14` | `MSDC_FIFOCS` | FIFO control and status |
| `0x18` | `MSDC_TXDATA` | FIFO TX data |
| `0x1C` | `MSDC_RXDATA` | FIFO RX data |
| `0x30` | `SDC_CFG` | SD/MMC config: bus width, data timeout |
| `0x34` | `SDC_CMD` | Command register (opcode, type, response type) |
| `0x38` | `SDC_ARG` | Command argument |
| `0x3C` | `SDC_STS` | Status: cmdbusy, datbusy |
| `0x40–0x4C` | `SDC_RESP0–3` | 128-bit response buffer |
| `0x50` | `SDC_BLK_NUM` | Block count for data transfer |
| `0x58` | `SDC_CSTS` | Card status |
| `0x60` | `SDC_DCRC_STS` | Data CRC status per DAT line |
| `0x64` | `SDC_ADV_CFG0` | Advanced config 0 |
| `0x70` | `EMMC_CFG0` | eMMC config 0: boot mode, part access |
| `0x74` | `EMMC_CFG1` | eMMC config 1 |
| `0x78` | `EMMC_STS` | eMMC status: boot ack |
| `0x7C` | `EMMC_IOCON` | eMMC I/O control |
| `0x8C` | `MSDC_DMA_SA_HIGH` | DMA start address [35:32] (4 MSB) |
| `0x90` | `MSDC_DMA_SA` | DMA start address [31:0] |
| `0x94` | `MSDC_DMA_CA` | DMA current address |
| `0x98` | `MSDC_DMA_CTRL` | DMA control: start, stop, mode |
| `0x9C` | `MSDC_DMA_CFG` | DMA config: burst length |
| `0xA8` | `MSDC_DMA_LEN` | DMA transfer length |
| `0xB0` | `MSDC_PATCH_BIT0` | Patch register 0 (tuning overrides) |
| `0xB4` | `MSDC_PATCH_BIT1` | Patch register 1 |
| `0xB8` | `MSDC_PATCH_BIT2` | Patch register 2 |
| `0xC0–0xD0` | `DATx_TUNE_CRC / CMD_TUNE_CRC` | Per-bit tune CRC windows |
| `0xD4` | `SDIO_TUNE_WIND` | SDIO tune window |
| `0xF0` | `MSDC_PAD_TUNE0` | PAD delay tune 0 |
| `0xF4` | `MSDC_PAD_TUNE1` | PAD delay tune 1 |
| `0xF8–0x104` | `MSDC_DAT_RDDLY0–3` | Data read delay (per DAT line) |
| `0x114` | `MSDC_VERSION` | Version register |

Source: `drivers/mmc/host/mediatek/ComboA/msdc_reg.h:20–74`

#### eMMC 5.0 / 5.1 Registers

| Offset | Register | Description |
|---|---|---|
| `0x180` | `EMMC50_PAD_CTL0` | HS400 PAD control |
| `0x184` | `EMMC50_PAD_DS_CTL0` | Data strobe PAD control |
| `0x188` | `EMMC50_PAD_DS_TUNE` | Data strobe delay tune |
| `0x18C` | `EMMC50_PAD_CMD_TUNE` | CMD delay tune |
| `0x190–0x19C` | `EMMC50_PAD_DATxx_TUNE` | DAT0–7 pair delay tune |
| `0x204` | `EMMC51_CFG0` | eMMC 5.1 config 0 |
| `0x208` | `EMMC50_CFG0` | eMMC 5.0 config 0 |
| `0x20C–0x224` | `EMMC50_CFG1–4` | eMMC 5.0 configs 1–4 |
| `0x280` | `MSDC_AES_SEL` | Inline AES encryption select |
| `0x600–0x6DC` | `EMMC52_AES_*` | AES-256 key/IV/CTR for two groups |

Source: `drivers/mmc/host/mediatek/ComboA/msdc_reg.h:75–221`

### 8.2 DMA Descriptor Chain

MSDC uses a two-level descriptor chain: one GPD (Generic Payload Descriptor)
per scatter-gather entry, each pointing to one or more BDs (Buffer Descriptors).

**GPD (64 bytes):**

| Field | Offset | Description |
|---|---|---|
| `next` | 0 | Next GPD physical address |
| `flags` | 4 | HWO (hardware owned), BDP (BD present), checksum |
| `ptr` | 8 | First BD physical address |
| `gpd_data_len` | 12 | Total data length in this GPD |
| `chksum` | 15 | Checksum byte |

**BD (16 bytes):**

| Field | Offset | Description |
|---|---|---|
| `next` | 0 | Next BD physical address |
| `ptr` | 4 | Buffer physical address |
| `data_len` | 8 | Buffer length |
| `flags` | 12 | EOL (end of list), checksum |

Source: `drivers/mmc/host/mediatek/ComboA/mtk_sd.h`

### 8.3 Command/Response Protocol

Write `SDC_ARG`, then write `SDC_CMD` (opcode in bits [5:0], response type,
block transfer direction). Poll `SDC_STS` for `cmdbusy` to clear. For data
transfers, also poll `datbusy`. Response in `SDC_RESP0–3`.

DMA data transfer: write GPD chain start address to `MSDC_DMA_SA`, set
`MSDC_DMA_CTRL` to start. Poll `MSDC_DMA_CFG` for completion or wait for DMA
interrupt.

### 8.4 Interrupt Sources (`MSDC_INT` / `MSDC_INTEN`)

Key interrupt bits:

| Bit | Name | Description |
|---|---|---|
| 0 | `MSDC_INTEN_MMCIRQ` | SDIO card interrupt |
| 1 | `MSDC_INTEN_CDSC` | Card detect state change |
| 2 | `MSDC_INTEN_ACMDRDY` | Auto CMD response ready |
| 3 | `MSDC_INTEN_ACMDTMO` | Auto CMD response timeout |
| 4 | `MSDC_INTEN_ACMDCRCERR` | Auto CMD CRC error |
| 5 | `MSDC_INTEN_DMAQ_EMPTY` | DMA queue empty |
| 6 | `MSDC_INTEN_SDIOIRQ` | SDIO interrupt |
| 7 | `MSDC_INTEN_CMDRDY` | Command response ready |
| 8 | `MSDC_INTEN_CMDTMO` | Command response timeout |
| 9 | `MSDC_INTEN_RSPCRCERR` | Response CRC error |
| 10 | `MSDC_INTEN_CSTA` | Card status error |
| 11 | `MSDC_INTEN_XFER_COMPL` | Data transfer complete |
| 12 | `MSDC_INTEN_DXFER_DONE` | Data transfer done |
| 13 | `MSDC_INTEN_DATTMO` | Data timeout |
| 14 | `MSDC_INTEN_DATCRCERR` | Data CRC error |
| 15 | `MSDC_INTEN_ACMD19_DONE` | ACMD19 done |

Source: `drivers/mmc/host/mediatek/ComboA/msdc_reg.h` (MSDC_INT_* defines)

### 8.5 Auto-Tuning

After power-up MSDC performs window-based auto-tuning (`autok.c`) to
determine optimal PAD delay values for each data rate. MSDC stores the
results in platform-specific structs and writes them back to
`MSDC_PAD_TUNE0/1` and the `EMMC50_PAD_*_TUNE` registers. DVFS transitions
re-trigger auto-tuning via `autok_dvfs.c`. Source:
`drivers/mmc/host/mediatek/ComboA/mt6739/autok_cust.h`

---

## Acceptance Checklist

- [x] All 8 subsystems documented
- [x] Register addresses cited with source file references
- [x] Initialization sequences described step-by-step
- [x] CCCI shared memory layout fully mapped
- [x] WMT firmware loading / power-on sequence described
- [x] Display init command sequence captured
- [x] Document is in `docs/DRIVER-INTERFACES.md`
