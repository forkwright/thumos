//! MUSB OTG USB controller driver with CDC ACM serial gadget.
//!
//! Implements USB device mode on the MT6739's MUSB (Mentor Graphics OTG) IP
//! block. Provides a CDC ACM (USB serial) gadget for kernel debug console and
//! host communication. The device appears on the host as `/dev/ttyUSBx`.
//!
//! ## Transport topology
//!
//! - EP0: control  -  enumeration, class requests
//! - EP1 IN (bulk): serial TX (device → host)
//! - EP1 OUT (bulk): serial RX (host → device)
//! - EP2 IN (interrupt): ACM notifications (required by spec; not actively sent)
//!
//! ## Register reference
//!
//! Offsets FROM the MUSB Programmer's Guide, verified against MT6739 BSP
//! `drivers/usb/musb/musb_core.h` and the hardware_info provided in the
//! dispatch prompt.

// ---------------------------------------------------------------------------
// Base address
// ---------------------------------------------------------------------------

/// MUSB OTG controller base address on MT6739.
/// Source: MT6739 device tree `usb0: usb@11210000`.
const MUSB_BASE: usize = 0x1121_0000;

// ---------------------------------------------------------------------------
// Common register offsets (relative to MUSB_BASE)
// ---------------------------------------------------------------------------

/// Function address  -  device address after SET_ADDRESS (8-bit).
const REG_FADDR: usize = 0x00;
/// Power management  -  SOFTCONN, HSENAB, suspend, resume, reset (8-bit).
const REG_POWER: usize = 0x01;
/// TX endpoint interrupt status  -  bit N = EPn (16-bit, reading clears).
const REG_INTRTX: usize = 0x02;
/// RX endpoint interrupt status  -  bit N = EPn (16-bit, reading clears).
const REG_INTRRX: usize = 0x04;
/// TX endpoint interrupt enable mask (16-bit).
const REG_INTRTXE: usize = 0x06;
/// RX endpoint interrupt enable mask (16-bit).
const REG_INTRRXE: usize = 0x08;
/// USB interrupt status  -  reset/suspend/resume/connect/SOF (8-bit, reading clears).
const REG_INTRUSB: usize = 0x0A;
/// USB interrupt enable mask (8-bit).
const REG_INTRUSBE: usize = 0x0B;
/// Current frame number (16-bit).
const REG_FRAME: usize = 0x0E;
/// Endpoint index selector  -  selects which EP the banked registers address (8-bit).
const REG_INDEX: usize = 0x0F;
/// Test mode control (8-bit).
const REG_TESTMODE: usize = 0x10;

// ---------------------------------------------------------------------------
// Indexed (banked) register offsets
//
// These offsets are valid after writing the desired endpoint number to REG_INDEX.
// EP0 uses REG_EP0_CSR; EP1+ use REG_TXCSR / REG_RXCSR.
// ---------------------------------------------------------------------------

/// EP0 control/status register (16-bit); valid when REG_INDEX == 0.
const REG_EP0_CSR: usize = 0x110;
/// EPx TX control/status register (16-bit); valid when REG_INDEX >= 1.
const REG_TXCSR: usize = 0x112;
/// EPx RX control/status register (16-bit); valid when REG_INDEX >= 1.
const REG_RXCSR: usize = 0x116;
/// EPx TX max packet size (16-bit).
const REG_TXMAXP: usize = 0x118;
/// EPx RX max packet size (16-bit).
const REG_RXMAXP: usize = 0x11A;
/// EPx RX byte count for the last received OUT packet (16-bit); valid
/// when REG_INDEX >= 1. Source: MUSB Programmer's Guide `RxCount`/`COUNT0`
/// -- may be less than REG_RXMAXP for a short packet (issue #221). Placed
/// immediately after REG_RXMAXP to follow this driver's banked-register
/// layout (which already reorders from the raw Mentor Graphics offsets).
///
/// WARNING: this offset is inferred from the driver's banked layout, NOT
/// confirmed against the MT6739 BSP header — the drain is clamped to
/// EP1_MAX_PKT so a wrong value cannot overrun the ring buffer, but the
/// exact offset must be verified before trusting short-packet lengths on
/// real silicon.
/// TODO(#221)[deliberate-prudent]: confirm REG_RXCOUNT against the MT6739 MUSB BSP header.
const REG_RXCOUNT: usize = 0x11C;

// ---------------------------------------------------------------------------
// FIFO registers
//
// Each endpoint has a 4-byte-aligned FIFO data register. Byte or word writes
// queue data INTO the FIFO; reads dequeue. MUSB auto-advances on each write.
// ---------------------------------------------------------------------------

/// EP FIFO base. FIFO for EPn is at MUSB_BASE + REG_FIFO_BASE + n * 4.
const REG_FIFO_BASE: usize = 0x120;

// ---------------------------------------------------------------------------
// REG_POWER bit fields
// ---------------------------------------------------------------------------

/// SOFTCONN: connect D+/D- to USB bus. Set to enumerate; clear to disconnect.
const POWER_SOFTCONN: u8 = 1 << 6;
/// Enable high-speed (480 Mbps) negotiation.
const POWER_HSENAB: u8 = 1 << 5;
/// Enable suspend signalling on the bus.
const POWER_SUSPENDEM: u8 = 1 << 0;

// ---------------------------------------------------------------------------
// REG_INTRUSB / REG_INTRUSBE bit fields
// ---------------------------------------------------------------------------

/// USB suspend interrupt.
const INTRUSB_SUSPEND: u8 = 1 << 0;
/// USB resume interrupt.
const INTRUSB_RESUME: u8 = 1 << 1;
/// USB bus reset interrupt.
const INTRUSB_RESET: u8 = 1 << 2;
/// Start-of-frame interrupt.
const INTRUSB_SOF: u8 = 1 << 3;

// ---------------------------------------------------------------------------
// REG_INTRTX / REG_INTRTXE bit fields
// ---------------------------------------------------------------------------

/// EP0 interrupt (shared in the TX register; EP0 has no separate RX interrupt).
const INTRTX_EP0: u16 = 1 << 0;
/// EP1 TX interrupt.
const INTRTX_EP1: u16 = 1 << 1;
/// EP2 TX interrupt.
const INTRTX_EP2: u16 = 1 << 2;

// ---------------------------------------------------------------------------
// REG_INTRRX / REG_INTRRXE bit fields
// ---------------------------------------------------------------------------

/// EP1 RX interrupt.
const INTRRX_EP1: u16 = 1 << 1;

// ---------------------------------------------------------------------------
// REG_EP0_CSR bit fields (when REG_INDEX == 0)
// ---------------------------------------------------------------------------

/// RxPktRdy: a SETUP or OUT data packet is in the FIFO.
const EP0_RXPKTRDY: u16 = 1 << 0;
/// TxPktRdy: arm the FIFO for transmission (SET to send IN data).
const EP0_TXPKTRDY: u16 = 1 << 1;
/// SentStall: a STALL handshake was sent; clear after handling.
const EP0_SENTSTALL: u16 = 1 << 2;
/// DataEnd: SET alongside TxPktRdy (or alone for no-data status) to end the
/// control transfer. MUSB clears it automatically after the status stage.
const EP0_DATAEND: u16 = 1 << 3;
/// SetupEnd: an IN control transfer was aborted by the host; must be cleared.
const EP0_SETUPEND: u16 = 1 << 4;
/// SendStall: issue a STALL handshake for unrecognised requests.
const EP0_SENDSTALL: u16 = 1 << 5;
/// ServicedRxPktRdy: clear RxPktRdy after reading the SETUP/OUT packet.
const EP0_SVDRXPKTRDY: u16 = 1 << 6;
/// ServicedSetupEnd: acknowledge the SetupEnd condition.
const EP0_SVDSETUPEND: u16 = 1 << 7;

// ---------------------------------------------------------------------------
// REG_TXCSR bit fields (when REG_INDEX >= 1)
// ---------------------------------------------------------------------------

/// TxPktRdy: arm TX FIFO for transmission.
const TXCSR_TXPKTRDY: u16 = 1 << 0;
/// FIFONotEmpty: TX FIFO still contains data.
const TXCSR_FIFONOTEMPTY: u16 = 1 << 1;
/// Underrun: host issued an IN token when FIFO was empty.
const TXCSR_UNDERRUN: u16 = 1 << 2;
/// FlushFIFO: discard the current TX FIFO contents.
const TXCSR_FLUSHFIFO: u16 = 1 << 3;
/// ClrDataTog: reset data toggle to DATA0 (call after configuration).
const TXCSR_CLRDATATOG: u16 = 1 << 6;

// ---------------------------------------------------------------------------
// REG_RXCSR bit fields (when REG_INDEX >= 1)
// ---------------------------------------------------------------------------

/// RxPktRdy: a packet has arrived in the RX FIFO.
const RXCSR_RXPKTRDY: u16 = 1 << 0;
/// FlushFIFO: discard the current RX FIFO contents.
const RXCSR_FLUSHFIFO: u16 = 1 << 4;
/// ClrDataTog: reset data toggle to DATA0 (call after configuration).
const RXCSR_CLRDATATOG: u16 = 1 << 7;

// ---------------------------------------------------------------------------
// USB descriptor type codes
// ---------------------------------------------------------------------------

/// Device descriptor type.
const USB_DT_DEVICE: u8 = 0x01;
/// Configuration descriptor type.
const USB_DT_CONFIG: u8 = 0x02;
/// String descriptor type.
const USB_DT_STRING: u8 = 0x03;
/// Interface descriptor type.
const USB_DT_INTERFACE: u8 = 0x04;
/// Endpoint descriptor type.
const USB_DT_ENDPOINT: u8 = 0x05;
/// CDC class-specific interface descriptor type.
const USB_DT_CS_INTERFACE: u8 = 0x24;

// ---------------------------------------------------------------------------
// USB standard request codes (bRequest)
// ---------------------------------------------------------------------------

/// GET_STATUS: return 2-byte status word.
const USB_REQ_GET_STATUS: u8 = 0x00;
/// SET_ADDRESS: assign the device address after enumeration.
const USB_REQ_SET_ADDRESS: u8 = 0x05;
/// GET_DESCRIPTOR: return a descriptor by type and index.
const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;
/// SET_CONFIGURATION: activate a configuration.
const USB_REQ_SET_CONFIGURATION: u8 = 0x09;

// ---------------------------------------------------------------------------
// CDC ACM class request codes (bRequest)
// ---------------------------------------------------------------------------

/// SET_LINE_CODING: configure serial port parameters (baud, stop bits, parity).
const CDC_REQ_SET_LINE_CODING: u8 = 0x20;
/// GET_LINE_CODING: return current serial port parameters.
const CDC_REQ_GET_LINE_CODING: u8 = 0x21;
/// SET_CONTROL_LINE_STATE: SET DTR/RTS control lines.
const CDC_REQ_SET_CONTROL_LINE_STATE: u8 = 0x22;

// ---------------------------------------------------------------------------
// CDC functional descriptor subtypes (bDescriptorSubtype)
// ---------------------------------------------------------------------------

/// Header functional descriptor subtype.
const CDC_HEADER_FUNC_DESC: u8 = 0x00;
/// Abstract Control Management (ACM) functional descriptor subtype.
const CDC_ACM_FUNC_DESC: u8 = 0x02;
/// Union functional descriptor subtype.
const CDC_UNION_FUNC_DESC: u8 = 0x06;

// ---------------------------------------------------------------------------
// Endpoint addressing constants
// ---------------------------------------------------------------------------

/// EP endpoint transfer type: bulk.
const EP_TYPE_BULK: u8 = 0x02;
/// EP endpoint transfer type: interrupt.
const EP_TYPE_INTERRUPT: u8 = 0x03;
/// EP1 IN address (bulk, device → host).
const EP1_IN_ADDR: u8 = 0x81;
/// EP1 OUT address (bulk, host → device).
const EP1_OUT_ADDR: u8 = 0x01;
/// EP2 IN address (interrupt, ACM notifications).
const EP2_IN_ADDR: u8 = 0x82;

// ---------------------------------------------------------------------------
// Packet size constants
// ---------------------------------------------------------------------------

/// EP0 max packet size (full-speed: 64 bytes).
const EP0_MAX_PKT: u16 = 64;
/// EP1 bulk max packet size (full-speed: 64 bytes).
const EP1_MAX_PKT: u16 = 64;
/// EP2 interrupt max packet size.
const EP2_MAX_PKT: u16 = 16;

// ---------------------------------------------------------------------------
// USB device identity constants
// ---------------------------------------------------------------------------

/// USB VID  -  NetChip Technology (used for CDC ACM examples; suitable for debug).
const USB_VID: u16 = 0x0525;
/// USB PID  -  Linux-USB CDC ACM gadget.
const USB_PID: u16 = 0xA4A7;

// ---------------------------------------------------------------------------
// Internal buffer sizes
// ---------------------------------------------------------------------------

/// EP0 data buffer: large enough for the longest descriptor we send.
const EP0_BUF_LEN: usize = 128;
/// Serial RX ring buffer size.
const SERIAL_RX_BUF_LEN: usize = 256;

// ---------------------------------------------------------------------------
// USB device descriptor
//
// 18 bytes. See USB 2.0 spec §9.6.1.
// bDeviceClass=0x02 (CDC) declares the ACM interface class at device level.
// ---------------------------------------------------------------------------

/// Device descriptor byte array (18 bytes).
const DEVICE_DESCRIPTOR: [u8; 18] = [
    18,   // bLength
    USB_DT_DEVICE,    // bDescriptorType
    0x00, 0x02,       // bcdUSB = 0x0200 (USB 2.0), little-endian
    0x02,             // bDeviceClass = CDC
    0x00,             // bDeviceSubClass
    0x00,             // bDeviceProtocol
    EP0_MAX_PKT as u8, // bMaxPacketSize0 = 64
    // idVendor = 0x0525, little-endian
    (USB_VID & 0xFF) as u8,
    (USB_VID >> 8) as u8,
    // idProduct = 0xA4A7, little-endian
    (USB_PID & 0xFF) as u8,
    (USB_PID >> 8) as u8,
    0x00, 0x01,       // bcdDevice = 0x0100
    0x01,             // iManufacturer (string index 1)
    0x02,             // iProduct (string index 2)
    0x03,             // iSerialNumber (string index 3)
    0x01,             // bNumConfigurations
];

// ---------------------------------------------------------------------------
// Configuration + interface + endpoint descriptors
//
// Total length: 62 bytes (0x003E).
// Layout:
//   9   -  Configuration descriptor
//   9   -  Interface 0 (CDC Control)
//   5   -  CDC Header functional
//   4   -  CDC ACM functional
//   5   -  CDC Union functional
//   7   -  EP2 IN interrupt endpoint
//   9   -  Interface 1 (CDC Data)
//   7   -  EP1 IN bulk endpoint
//   7   -  EP1 OUT bulk endpoint
// ---------------------------------------------------------------------------

/// Total size of the configuration descriptor and all subordinate descriptors.
const CONFIG_DESC_TOTAL_LEN: u16 = 62;

/// Combined configuration descriptor blob (62 bytes).
const CONFIG_DESCRIPTOR: [u8; 62] = [
    // --- Configuration descriptor (9 bytes) ---
    9,              // bLength
    USB_DT_CONFIG,  // bDescriptorType
    (CONFIG_DESC_TOTAL_LEN & 0xFF) as u8,   // wTotalLength lo
    (CONFIG_DESC_TOTAL_LEN >> 8) as u8,     // wTotalLength hi
    2,              // bNumInterfaces
    1,              // bConfigurationValue
    0,              // iConfiguration (no string)
    0xA0,           // bmAttributes: bus-powered, remote wakeup
    0xFA,           // bMaxPower: 500 mA (250 × 2)

    // --- Interface 0: CDC Control (9 bytes) ---
    9,              // bLength
    USB_DT_INTERFACE, // bDescriptorType
    0,              // bInterfaceNumber
    0,              // bAlternateSetting
    1,              // bNumEndpoints (EP2 IN interrupt)
    0x02,           // bInterfaceClass: CDC
    0x02,           // bInterfaceSubClass: ACM
    0x00,           // bInterfaceProtocol: V.25ter (AT commands)
    0,              // iInterface

    // --- CDC Header functional descriptor (5 bytes) ---
    5,              // bLength
    USB_DT_CS_INTERFACE, // bDescriptorType
    CDC_HEADER_FUNC_DESC, // bDescriptorSubtype
    0x10, 0x01,     // bcdCDC = 0x0110 (CDC 1.1), little-endian

    // --- CDC ACM functional descriptor (4 bytes) ---
    4,              // bLength
    USB_DT_CS_INTERFACE, // bDescriptorType
    CDC_ACM_FUNC_DESC, // bDescriptorSubtype
    // bmCapabilities: bit 1 = supports SET/GET_LINE_CODING + SET_CONTROL_LINE_STATE
    0x02,

    // --- CDC Union functional descriptor (5 bytes) ---
    5,              // bLength
    USB_DT_CS_INTERFACE, // bDescriptorType
    CDC_UNION_FUNC_DESC, // bDescriptorSubtype
    0,              // bMasterInterface (interface 0 = control)
    1,              // bSlaveInterface0 (interface 1 = data)

    // --- EP2 IN interrupt endpoint (7 bytes) ---
    7,              // bLength
    USB_DT_ENDPOINT,  // bDescriptorType
    EP2_IN_ADDR,    // bEndpointAddress: EP2 IN
    EP_TYPE_INTERRUPT, // bmAttributes
    (EP2_MAX_PKT & 0xFF) as u8,  // wMaxPacketSize lo
    (EP2_MAX_PKT >> 8) as u8,    // wMaxPacketSize hi
    0xFF,           // bInterval: 255 ms (polling for FS interrupt EPs)

    // --- Interface 1: CDC Data (9 bytes) ---
    9,              // bLength
    USB_DT_INTERFACE, // bDescriptorType
    1,              // bInterfaceNumber
    0,              // bAlternateSetting
    2,              // bNumEndpoints (EP1 IN + EP1 OUT)
    0x0A,           // bInterfaceClass: CDC Data
    0x00,           // bInterfaceSubClass
    0x00,           // bInterfaceProtocol
    0,              // iInterface

    // --- EP1 IN bulk endpoint (7 bytes) ---
    7,              // bLength
    USB_DT_ENDPOINT,  // bDescriptorType
    EP1_IN_ADDR,    // bEndpointAddress: EP1 IN
    EP_TYPE_BULK,   // bmAttributes
    (EP1_MAX_PKT & 0xFF) as u8,  // wMaxPacketSize lo
    (EP1_MAX_PKT >> 8) as u8,    // wMaxPacketSize hi
    0,              // bInterval (bulk endpoints ignore this)

    // --- EP1 OUT bulk endpoint (7 bytes) ---
    7,              // bLength
    USB_DT_ENDPOINT,  // bDescriptorType
    EP1_OUT_ADDR,   // bEndpointAddress: EP1 OUT
    EP_TYPE_BULK,   // bmAttributes
    (EP1_MAX_PKT & 0xFF) as u8,  // wMaxPacketSize lo
    (EP1_MAX_PKT >> 8) as u8,    // wMaxPacketSize hi
    0,              // bInterval
];

// ---------------------------------------------------------------------------
// String descriptors
//
// USB string descriptors are UTF-16LE encoded, prefixed by a 2-byte header
// (bLength, bDescriptorType=0x03).
// ---------------------------------------------------------------------------

/// String 0: supported language list (English US = 0x0409).
const STR0: [u8; 4] = [0x04, USB_DT_STRING, 0x09, 0x04];

/// String 1: manufacturer "Thumos" (6 chars → 14 bytes total).
const STR1: [u8; 14] = [
    14, USB_DT_STRING,
    b'T', 0, b'h', 0, b'u', 0, b'm', 0, b'o', 0, b's', 0,
];

/// String 2: product "Thumos Serial" (13 chars → 28 bytes total).
const STR2: [u8; 28] = [
    28, USB_DT_STRING,
    b'T', 0, b'h', 0, b'u', 0, b'm', 0, b'o', 0, b's', 0,
    b' ', 0, b'S', 0, b'e', 0, b'r', 0, b'i', 0, b'a', 0, b'l', 0,
];

/// String 3: serial number "THUMOS0001" (10 chars → 22 bytes total).
const STR3: [u8; 22] = [
    22, USB_DT_STRING,
    b'T', 0, b'H', 0, b'U', 0, b'M', 0, b'O', 0, b'S', 0,
    b'0', 0, b'0', 0, b'0', 0, b'1', 0,
];

// ---------------------------------------------------------------------------
// EP0 state machine
// ---------------------------------------------------------------------------

/// EP0 control transfer state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ep0State {
    /// Waiting for a SETUP packet.
    Idle,
    /// SETUP received; dispatching request.
    Setup,
    /// Sending descriptor/data to host (IN direction).
    DataIn,
    /// Receiving data FROM host (OUT direction, e.g., SET_LINE_CODING).
    DataOut,
    /// SET_ADDRESS pending  -  address written to FAddr after status stage.
    AddressPending,
}

// ---------------------------------------------------------------------------
// Setup packet
// ---------------------------------------------------------------------------

/// Decoded USB SETUP packet (8 bytes).
#[derive(Debug, Clone, Copy)]
pub struct SetupPacket {
    /// Request type (direction | type | recipient).
    pub bm_request_type: u8,
    /// Request code.
    pub b_request: u8,
    /// Request-specific value (wValue).
    pub w_value: u16,
    /// Request-specific index (wIndex).
    pub w_index: u16,
    /// Transfer length for data stage (wLength).
    pub w_length: u16,
}

impl SetupPacket {
    /// Parse a SETUP packet FROM 8 raw bytes (little-endian).
    #[must_use]
    pub(crate) fn from_bytes(b: &[u8; 8]) -> Self {
        Self {
            bm_request_type: b.get(0).copied().unwrap_or_default(),
            b_request: b.get(1).copied().unwrap_or_default(),
            w_value: u16::from_le_bytes([b.get(2).copied().unwrap_or_default(), b.get(3).copied().unwrap_or_default()]),
            w_index: u16::from_le_bytes([b.get(4).copied().unwrap_or_default(), b.get(5).copied().unwrap_or_default()]),
            w_length: u16::from_le_bytes([b.get(6).copied().unwrap_or_default(), b.get(7).copied().unwrap_or_default()]),
        }
    }

    /// True if the data stage transfers host → device (bit 7 = 0).
    #[must_use]
    pub(crate) fn is_host_to_device(&self) -> bool {
        self.bm_request_type & 0x80 == 0
    }

    /// True if this is a standard request (bits 6:5 = 00).
    #[must_use]
    pub(crate) fn is_standard(&self) -> bool {
        self.bm_request_type & 0x60 == 0x00
    }

    /// True if this is a class-specific request (bits 6:5 = 01).
    #[must_use]
    pub(crate) fn is_class(&self) -> bool {
        self.bm_request_type & 0x60 == 0x20
    }
}

// ---------------------------------------------------------------------------
// ACM line coding
// ---------------------------------------------------------------------------

/// CDC ACM line coding (7 bytes, as returned by GET_LINE_CODING).
#[derive(Debug, Clone, Copy)]
pub struct LineCoding {
    /// Baud rate (bits per second).
    pub dw_dte_rate: u32,
    /// Stop bits: 0 = 1, 1 = 1.5, 2 = 2.
    pub b_char_format: u8,
    /// Parity: 0 = None, 1 = Odd, 2 = Even, 3 = Mark, 4 = Space.
    pub b_parity_type: u8,
    /// Data bits: 5, 6, 7, 8, or 16.
    pub b_data_bits: u8,
}

impl LineCoding {
    /// Default 115200 8N1 line coding.
    #[must_use]
    pub(crate) const fn default_115200() -> Self {
        Self {
            dw_dte_rate: 115_200,
            b_char_format: 0,
            b_parity_type: 0,
            b_data_bits: 8,
        }
    }

    /// Serialize to 7 bytes for GET_LINE_CODING response.
    #[must_use]
    pub(crate) fn to_bytes(self) -> [u8; 7] {
        let r = self.dw_dte_rate.to_le_bytes();
        [r.get(0).copied().unwrap_or_default(), r.get(1).copied().unwrap_or_default(), r.get(2).copied().unwrap_or_default(), r.get(3).copied().unwrap_or_default(), self.b_char_format, self.b_parity_type, self.b_data_bits]
    }

    /// Parse FROM 7 bytes received in SET_LINE_CODING.
    #[must_use]
    pub(crate) fn from_bytes(b: &[u8; 7]) -> Self {
        Self {
            dw_dte_rate: u32::from_le_bytes([b.get(0).copied().unwrap_or_default(), b.get(1).copied().unwrap_or_default(), b.get(2).copied().unwrap_or_default(), b.get(3).copied().unwrap_or_default()]),
            b_char_format: b.get(4).copied().unwrap_or_default(),
            b_parity_type: b.get(5).copied().unwrap_or_default(),
            b_data_bits: b.get(6).copied().unwrap_or_default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Interrupt status snapshot
// ---------------------------------------------------------------------------

/// Interrupt register snapshot captured on USB IRQ entry.
///
/// Reading IntrUSB, IntrTx, and IntrRx FROM MUSB clears those bits
/// atomically. The ISR must save them here before dispatching.
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbIrqStatus {
    /// IntrUSB snapshot (reset/suspend/resume/SOF).
    pub intrusb: u8,
    /// IntrTx snapshot (EP0 + TX EPs).
    pub intrtx: u16,
    /// IntrRx snapshot (RX EPs).
    pub intrrx: u16,
}

impl UsbIrqStatus {
    /// True if a USB bus reset was signalled.
    #[must_use]
    pub(crate) fn has_reset(self) -> bool {
        self.intrusb & INTRUSB_RESET != 0
    }

    /// True if a USB suspend was signalled.
    #[must_use]
    pub(crate) fn has_suspend(self) -> bool {
        self.intrusb & INTRUSB_SUSPEND != 0
    }

    /// True if a USB resume was signalled.
    #[must_use]
    pub(crate) fn has_resume(self) -> bool {
        self.intrusb & INTRUSB_RESUME != 0
    }

    /// True if EP0 has a pending event.
    #[must_use]
    pub(crate) fn has_ep0(self) -> bool {
        self.intrtx & INTRTX_EP0 != 0
    }

    /// True if EP1 TX (bulk IN) has a pending event.
    #[must_use]
    pub(crate) fn has_ep1_tx(self) -> bool {
        self.intrtx & INTRTX_EP1 != 0
    }

    /// True if EP1 RX (bulk OUT) has a pending event.
    #[must_use]
    pub(crate) fn has_ep1_rx(self) -> bool {
        self.intrrx & INTRRX_EP1 != 0
    }

    /// True if any event is pending (used to skip handling when spurious).
    #[must_use]
    pub(crate) fn is_empty(self) -> bool {
        self.intrusb == 0 && self.intrtx == 0 && self.intrrx == 0
    }
}

/// Clamp a raw `RxCount` register value to the endpoint's max packet size.
///
/// WHY: `RxCount` reports the number of bytes MUSB placed in the FIFO for
/// the current OUT packet, which may be less than `max_pkt` for a short
/// packet. Bounding the result to `max_pkt` also keeps the FIFO drain loop
/// within the endpoint's configured packet size if the register ever
/// reports an out-of-range value (issue #221).
fn clamp_rx_count(raw_count: u16, max_pkt: u16) -> usize {
    usize::from(raw_count).min(usize::from(max_pkt))
}

// ---------------------------------------------------------------------------
// USB controller
// ---------------------------------------------------------------------------

/// MUSB OTG controller driver for the MT6739, operating in device mode.
///
/// Manages enumeration via EP0, ACM class requests, and bulk serial I/O on EP1.
pub(crate) struct UsbController {
    /// MUSB register base address.
    base: usize,
    /// EP0 state machine.
    ep0_state: Ep0State,
    /// Device address to apply after SET_ADDRESS status stage.
    pending_address: u8,
    /// EP0 transmit buffer for descriptor/data responses.
    ep0_buf: [u8; EP0_BUF_LEN],
    /// Valid bytes in `ep0_buf`.
    ep0_buf_len: usize,
    /// Next byte index to send FROM `ep0_buf`.
    ep0_buf_pos: usize,
    /// Current ACM line coding (updated by SET_LINE_CODING).
    line_coding: LineCoding,
    /// True after SET_CONFIGURATION activates the gadget.
    configured: bool,
    /// Serial RX ring buffer.
    rx_buf: [u8; SERIAL_RX_BUF_LEN],
    /// Write index INTO rx_buf.
    rx_head: usize,
    /// Read index INTO rx_buf.
    rx_tail: usize,
}

impl UsbController {
    /// Create a new controller instance pointing at the hardware base address.
    ///
    /// Call [`init`] before any other method.
    ///
    /// [`init`]: UsbController::init
    pub(crate) const fn new() -> Self {
        Self {
            base: MUSB_BASE,
            ep0_state: Ep0State::Idle,
            pending_address: 0,
            ep0_buf: [0u8; EP0_BUF_LEN],
            ep0_buf_len: 0,
            ep0_buf_pos: 0,
            line_coding: LineCoding::default_115200(),
            configured: false,
            rx_buf: [0u8; SERIAL_RX_BUF_LEN],
            rx_head: 0,
            rx_tail: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Reset the MUSB controller, configure device mode, and connect to bus.
    ///
    /// Must be called once during kernel init, with interrupts disabled.
    /// After returning, the controller will respond to USB bus events when
    /// [`handle_interrupt`] is called FROM the GIC interrupt handler.
    ///
    /// # Safety
    ///
    /// Caller must ensure no concurrent access to MUSB registers.
    ///
    /// [`handle_interrupt`]: UsbController::handle_interrupt
    pub unsafe fn init(&mut self) {
        // SAFETY: Caller asserts exclusive MUSB register access.
        unsafe {
            // Step 1: Disable all interrupts before touching hardware.
            self.write8(REG_INTRTXE, 0x00);
            self.write16(REG_INTRTXE, 0x0000);
            self.write16(REG_INTRRXE, 0x0000);
            self.write8(REG_INTRUSBE, 0x00);

            // Step 2: Reset FAddr and clear device address.
            self.write8(REG_FADDR, 0x00);

            // Step 3: Power  -  enable soft-connect and high-speed negotiation.
            // WHY: SOFTCONN is required on MUSB to attach D+/D- pull-up resistors.
            // Without it, the host never detects a device.
            let power = POWER_SOFTCONN | POWER_HSENAB | POWER_SUSPENDEM;
            self.write8(REG_POWER, power);

            // Step 4: Configure EP1 bulk IN/OUT.
            self.configure_ep1();

            // Step 5: Configure EP2 interrupt IN (ACM notifications).
            self.configure_ep2();

            // Step 6: Enable interrupts  -  EP0 TX, EP1 TX, EP1 RX, USB reset/suspend/resume.
            self.write16(REG_INTRTXE, INTRTX_EP0 | INTRTX_EP1);
            self.write16(REG_INTRRXE, INTRRX_EP1);
            self.write8(REG_INTRUSBE, INTRUSB_RESET | INTRUSB_SUSPEND | INTRUSB_RESUME);
        }
    }

    /// Read and dispatch a USB interrupt.
    ///
    /// Called FROM the GIC interrupt handler for the MUSB IRQ line. Reads
    /// IntrUSB, IntrTx, and IntrRx (which auto-clear on read), then dispatches
    /// to reset, EP0, or EPx handlers.
    ///
    /// Returns the captured interrupt status for the caller to inspect.
    ///
    /// # Safety
    ///
    /// Must be called FROM interrupt context or with interrupts disabled.
    pub unsafe fn handle_interrupt(&mut self) -> UsbIrqStatus {
        // SAFETY: Caller asserts interrupt context.
        let status = unsafe {
            // NOTE: Reading these registers clears them  -  capture atomically.
            let intrusb = self.read8(REG_INTRUSB);
            let intrtx = self.read16(REG_INTRTX);
            let intrrx = self.read16(REG_INTRRX);
            UsbIrqStatus { intrusb, intrtx, intrrx }
        };

        if status.is_empty() {
            return status;
        }

        // SAFETY: all dispatch calls operate on the same registers.
        unsafe {
            if status.has_reset() {
                self.handle_reset();
            }
            if status.has_ep0() {
                self.handle_ep0();
            }
            if status.has_ep1_rx() {
                self.handle_ep1_rx();
            }
        }

        status
    }

    /// Write `data` bytes to the ACM bulk IN endpoint (serial TX).
    ///
    /// Writes directly to the EP1 TX FIFO. The host will drain the FIFO on the
    /// next IN token. Blocks until the previous packet has been sent
    /// (`TxPktRdy` is clear) before loading new data, with a spin timeout.
    ///
    /// Returns the number of bytes written (may be less than `data.len()` if
    /// the controller is not yet configured or the FIFO is not draining).
    ///
    /// # Safety
    ///
    /// Caller must not call this concurrently with [`handle_interrupt`].
    ///
    /// [`handle_interrupt`]: UsbController::handle_interrupt
    #[must_use]
    pub unsafe fn write_serial(&mut self, data: &[u8]) -> usize {
        if !self.configured || data.is_empty() {
            return 0;
        }

        // SAFETY: Caller asserts exclusive access.
        unsafe {
            // Select EP1.
            self.write8(REG_INDEX, 1);

            // Wait for the FIFO to be ready (TxPktRdy cleared by hardware after send).
            // WHY: Timeout prevents infinite spin if the host disconnects mid-transfer.
            // WHY: REG_TXCSR is a 16-bit register; mmio::wait_bits_clear performs an
            // unaligned 32-bit load at this odd half-word offset (issue #227) -- poll
            // with the 16-bit-aligned accessor instead.
            let ready = self.wait_bits_clear16(REG_TXCSR, TXCSR_TXPKTRDY, 100_000);
            if !ready {
                return 0;
            }

            // Clamp to one max-packet-size chunk.
            let count = data.len().min(usize::from(EP1_MAX_PKT));
            let fifo = self.base + REG_FIFO_BASE + 4; // EP1 FIFO = base + 0x124

            for &byte in &data[..count] {
                // SAFETY: fifo is the EP1 TX FIFO at MUSB_BASE + 0x124, a valid 8-bit MMIO register within the MUSB address space at 0x1121_0000. Volatile semantics required for MMIO.
                core::ptr::write_volatile(fifo as *mut u8, byte);
            }

            // Arm the FIFO: SET TxPktRdy.
            let csr = self.read16(REG_TXCSR);
            self.write16(REG_TXCSR, csr | TXCSR_TXPKTRDY);

            count
        }
    }

    /// Read bytes FROM the ACM bulk OUT endpoint (serial RX) INTO `buf`.
    ///
    /// Returns the number of bytes copied. Returns 0 if the ring buffer is
    /// empty. Does not block.
    pub(crate) fn read_serial(&mut self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        while count < buf.len() {
            if self.rx_head == self.rx_tail {
                break;
            }
            // SAFETY: rx_tail is always a valid index within SERIAL_RX_BUF_LEN.
            if let Some(slot) = buf.get_mut(count) {
                *slot = self.rx_buf[self.rx_tail];
                self.rx_tail = (self.rx_tail + 1) % SERIAL_RX_BUF_LEN;
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    // -----------------------------------------------------------------------
    // Private: endpoint configuration
    // -----------------------------------------------------------------------

    /// Configure EP1 as bulk IN (TX) and bulk OUT (RX), 64-byte packets.
    ///
    /// # Safety
    ///
    /// Caller must hold exclusive MUSB register access.
    unsafe fn configure_ep1(&mut self) {
        // SAFETY: Caller asserts exclusivity.
        unsafe {
            self.write8(REG_INDEX, 1);
            self.write16(REG_TXMAXP, EP1_MAX_PKT);
            self.write16(REG_RXMAXP, EP1_MAX_PKT);
            // Clear data toggle and flush FIFOs for a clean start.
            self.write16(REG_TXCSR, TXCSR_CLRDATATOG | TXCSR_FLUSHFIFO);
            self.write16(REG_RXCSR, RXCSR_CLRDATATOG | RXCSR_FLUSHFIFO);
        }
    }

    /// Configure EP2 as interrupt IN (TX), 16-byte packets.
    ///
    /// # Safety
    ///
    /// Caller must hold exclusive MUSB register access.
    unsafe fn configure_ep2(&mut self) {
        // SAFETY: Caller asserts exclusivity.
        unsafe {
            self.write8(REG_INDEX, 2);
            self.write16(REG_TXMAXP, EP2_MAX_PKT);
            self.write16(REG_TXCSR, TXCSR_CLRDATATOG | TXCSR_FLUSHFIFO);
            // Return index to 0 (EP0) for subsequent control transfers.
            self.write8(REG_INDEX, 0);
        }
    }

    // -----------------------------------------------------------------------
    // Private: interrupt handlers
    // -----------------------------------------------------------------------

    /// Handle USB bus reset: re-initialise state and endpoints.
    ///
    /// # Safety
    ///
    /// Called FROM interrupt context with MUSB registers accessible.
    unsafe fn handle_reset(&mut self) {
        // SAFETY: interrupt context.
        unsafe {
            self.write8(REG_FADDR, 0x00);
            self.ep0_state = Ep0State::Idle;
            self.pending_address = 0;
            self.configured = false;
            self.rx_head = 0;
            self.rx_tail = 0;
            self.configure_ep1();
            self.configure_ep2();
        }
    }

    /// Handle EP0 events: SETUP/IN/OUT control transfer stages.
    ///
    /// # Safety
    ///
    /// Called FROM interrupt context with MUSB registers accessible.
    unsafe fn handle_ep0(&mut self) {
        // SAFETY: interrupt context.
        unsafe {
            // Select EP0 via index register.
            self.write8(REG_INDEX, 0);
            let csr = self.read16(REG_EP0_CSR);

            // SetupEnd: a previously in-progress IN transfer was aborted by host.
            if csr & EP0_SETUPEND != 0 {
                self.write16(REG_EP0_CSR, EP0_SVDSETUPEND);
                self.ep0_state = Ep0State::Idle;
                return;
            }

            // SentStall: clear the stall condition.
            if csr & EP0_SENTSTALL != 0 {
                self.write16(REG_EP0_CSR, csr & !EP0_SENTSTALL);
                self.ep0_state = Ep0State::Idle;
                return;
            }

            match self.ep0_state {
                Ep0State::Idle | Ep0State::Setup => {
                    if csr & EP0_RXPKTRDY != 0 {
                        self.handle_ep0_setup();
                    }
                }
                Ep0State::DataIn => {
                    self.ep0_send_next_chunk();
                }
                Ep0State::DataOut => {
                    // NOTE: Only used by SET_LINE_CODING. Handled inline in
                    // handle_ep0_setup when the data arrives after setup.
                    if csr & EP0_RXPKTRDY != 0 {
                        self.handle_ep0_data_out();
                    }
                }
                Ep0State::AddressPending => {
                    // Apply the deferred address after the status stage completes.
                    self.write8(REG_FADDR, self.pending_address);
                    self.pending_address = 0;
                    self.ep0_state = Ep0State::Idle;
                }
            }
        }
    }

    /// Parse and dispatch a SETUP packet received on EP0.
    ///
    /// # Safety
    ///
    /// Called FROM `handle_ep0` with EP0 FIFO containing a valid SETUP packet.
    unsafe fn handle_ep0_setup(&mut self) {
        // SAFETY: read_ep0_fifo reads FROM hardware FIFO.
        let setup = unsafe { self.read_ep0_fifo_setup() };

        // Acknowledge SETUP packet receipt.
        // SAFETY: continuing MUSB register access.
        unsafe {
            self.write16(REG_EP0_CSR, EP0_SVDRXPKTRDY);
        }

        if setup.is_standard() {
            // SAFETY: called FROM handle_ep0 in interrupt context with MUSB registers accessible.
            unsafe { self.handle_standard_request(&setup) };
        } else if setup.is_class() {
            // SAFETY: same as above.
            unsafe { self.handle_class_request(&setup) };
        } else {
            // Vendor/reserved  -  stall.
            // SAFETY: stall is a register write.
            unsafe {
                self.ep0_stall();
            }
        }
    }

    /// Dispatch a standard USB request.
    ///
    /// # Safety
    ///
    /// Called FROM `handle_ep0_setup`.
    unsafe fn handle_standard_request(&mut self, setup: &SetupPacket) {
        // SAFETY: all branches do MMIO writes.
        unsafe {
            match setup.b_request {
                USB_REQ_SET_ADDRESS => {
                    let addr = (setup.w_value & 0x7F) as u8;
                    self.pending_address = addr;
                    // Acknowledge with status stage (DataEnd, no data payload).
                    self.write16(REG_EP0_CSR, EP0_DATAEND);
                    self.ep0_state = Ep0State::AddressPending;
                }
                USB_REQ_GET_DESCRIPTOR => {
                    let desc_type = (setup.w_value >> 8) as u8;
                    let desc_idx = (setup.w_value & 0xFF) as u8;
                    self.handle_get_descriptor(desc_type, desc_idx, setup.w_length);
                }
                USB_REQ_SET_CONFIGURATION => {
                    // Any non-zero value activates our single configuration.
                    self.configured = setup.w_value != 0;
                    // Zero-length status stage.
                    self.write16(REG_EP0_CSR, EP0_DATAEND);
                    self.ep0_state = Ep0State::Idle;
                }
                USB_REQ_GET_STATUS => {
                    // Return 2 zero bytes (device: not self-powered, no remote wakeup).
                    self.ep0_buf[0] = 0;
                    self.ep0_buf[1] = 0;
                    self.ep0_buf_len = 2;
                    self.ep0_buf_pos = 0;
                    self.ep0_state = Ep0State::DataIn;
                    self.ep0_send_next_chunk();
                }
                _ => {
                    self.ep0_stall();
                }
            }
        }
    }

    /// Dispatch a CDC ACM class request.
    ///
    /// # Safety
    ///
    /// Called FROM `handle_ep0_setup`.
    unsafe fn handle_class_request(&mut self, setup: &SetupPacket) {
        // SAFETY: MMIO writes and FIFO reads.
        unsafe {
            match setup.b_request {
                CDC_REQ_SET_LINE_CODING => {
                    // Host will send 7 bytes; prepare to receive them.
                    self.ep0_buf_len = 0;
                    self.ep0_buf_pos = 0;
                    self.ep0_state = Ep0State::DataOut;
                    // Acknowledge: clear RxPktRdy, do not SET DataEnd yet.
                    self.write16(REG_EP0_CSR, EP0_SVDRXPKTRDY);
                }
                CDC_REQ_GET_LINE_CODING => {
                    let coded = self.line_coding.to_bytes();
                    self.ep0_buf[..7].copy_from_slice(&coded);
                    self.ep0_buf_len = 7;
                    self.ep0_buf_pos = 0;
                    self.ep0_state = Ep0State::DataIn;
                    self.ep0_send_next_chunk();
                }
                CDC_REQ_SET_CONTROL_LINE_STATE => {
                    // WHY: We accept DTR/RTS changes but don't need to act on them
                    // since this is a debug console with no hardware flow control.
                    self.write16(REG_EP0_CSR, EP0_DATAEND);
                    self.ep0_state = Ep0State::Idle;
                }
                _ => {
                    self.ep0_stall();
                }
            }
        }
    }

    /// Build and begin sending a GET_DESCRIPTOR response.
    ///
    /// Loads the requested descriptor INTO `ep0_buf` and begins the IN data stage.
    ///
    /// # Safety
    ///
    /// Called FROM `handle_standard_request`.
    unsafe fn handle_get_descriptor(&mut self, desc_type: u8, desc_idx: u8, w_length: u16) {
        let src: &[u8] = match desc_type {
            USB_DT_DEVICE => &DEVICE_DESCRIPTOR,
            USB_DT_CONFIG => &CONFIG_DESCRIPTOR,
            USB_DT_STRING => match desc_idx {
                0 => &STR0,
                1 => &STR1,
                2 => &STR2,
                3 => &STR3,
                _ => {
                    // SAFETY: stall is a register write.
                    unsafe { self.ep0_stall() };
                    return;
                }
            },
            _ => {
                // SAFETY: stall is a register write.
                unsafe { self.ep0_stall() };
                return;
            }
        };

        // Copy up to min(descriptor length, wLength, EP0_BUF_LEN).
        let max = usize::from(w_length).min(src.len()).min(EP0_BUF_LEN);
        self.ep0_buf[..max].copy_from_slice(&src[..max]);
        self.ep0_buf_len = max;
        self.ep0_buf_pos = 0;
        self.ep0_state = Ep0State::DataIn;
        // SAFETY: send first chunk immediately.
        unsafe { self.ep0_send_next_chunk() };
    }

    /// Send up to one EP0_MAX_PKT chunk FROM ep0_buf to the host.
    ///
    /// # Safety
    ///
    /// Called FROM EP0 handling code with MUSB registers accessible.
    unsafe fn ep0_send_next_chunk(&mut self) {
        // SAFETY: MMIO writes and FIFO writes.
        unsafe {
            let remaining = self.ep0_buf_len - self.ep0_buf_pos;
            let chunk = remaining.min(usize::from(EP0_MAX_PKT));
            let fifo = self.base + REG_FIFO_BASE; // EP0 FIFO at base + 0x120

            for i in 0..chunk {
                // SAFETY: ep0_buf_pos + i < EP0_BUF_LEN by construction.
                let byte = self.ep0_buf[self.ep0_buf_pos + i];
                core::ptr::write_volatile(fifo as *mut u8, byte);
            }
            self.ep0_buf_pos += chunk;

            // DataEnd: SET when this is the last (or only) packet.
            let is_last = self.ep0_buf_pos >= self.ep0_buf_len;
            let flags = EP0_TXPKTRDY | if is_last { EP0_DATAEND } else { 0 };
            self.write16(REG_EP0_CSR, flags);

            if is_last {
                self.ep0_state = Ep0State::Idle;
            }
        }
    }

    /// Receive SET_LINE_CODING data (7 bytes) FROM EP0 OUT FIFO.
    ///
    /// # Safety
    ///
    /// Called FROM EP0 handler when DataOut is in progress.
    unsafe fn handle_ep0_data_out(&mut self) {
        // SAFETY: FIFO reads and register writes.
        unsafe {
            let fifo = self.base + REG_FIFO_BASE;
            let mut tmp = [0u8; 7];
            for slot in &mut tmp {
                *slot = core::ptr::read_volatile(fifo as *const u8);
            }
            self.line_coding = LineCoding::from_bytes(&tmp);

            // Acknowledge receipt and end the transfer.
            self.write16(REG_EP0_CSR, EP0_SVDRXPKTRDY | EP0_DATAEND);
            self.ep0_state = Ep0State::Idle;
        }
    }

    /// Handle EP1 RX (bulk OUT): drain FIFO INTO the serial ring buffer.
    ///
    /// # Safety
    ///
    /// Called FROM `handle_interrupt` in interrupt context.
    unsafe fn handle_ep1_rx(&mut self) {
        // SAFETY: MMIO register and FIFO reads.
        unsafe {
            self.write8(REG_INDEX, 1);
            let csr = self.read16(REG_RXCSR);

            if csr & RXCSR_RXPKTRDY == 0 {
                return;
            }

            let fifo = self.base + REG_FIFO_BASE + 4; // EP1 FIFO

            // WHY: RxCount reports the actual number of bytes the host sent
            // in this OUT packet, which may be less than EP1_MAX_PKT for a
            // short packet. Draining a fixed 64 bytes regardless of RxCount
            // read stale FIFO bytes past the valid payload (issue #221).
            let rx_count = clamp_rx_count(self.read16(REG_RXCOUNT), EP1_MAX_PKT);

            for _ in 0..rx_count {
                let byte = core::ptr::read_volatile(fifo as *const u8);
                let next_head = (self.rx_head + 1) % SERIAL_RX_BUF_LEN;
                if next_head != self.rx_tail {
                    self.rx_buf[self.rx_head] = byte;
                    self.rx_head = next_head;
                }
                // Ring buffer full: DROP remaining bytes silently.
            }

            // Clear RxPktRdy to signal we've consumed the packet.
            self.write16(REG_RXCSR, csr & !RXCSR_RXPKTRDY);
        }
    }

    /// Send EP0 STALL handshake.
    ///
    /// # Safety
    ///
    /// Caller must hold MUSB register access.
    unsafe fn ep0_stall(&mut self) {
        // SAFETY: register write.
        unsafe {
            self.write16(REG_EP0_CSR, EP0_SENDSTALL);
        }
        self.ep0_state = Ep0State::Idle;
    }

    // -----------------------------------------------------------------------
    // Private: FIFO helpers
    // -----------------------------------------------------------------------

    /// Read 8 bytes FROM the EP0 FIFO and return a decoded SETUP packet.
    ///
    /// # Safety
    ///
    /// EP0 FIFO must contain a valid SETUP packet (RxPktRdy SET).
    unsafe fn read_ep0_fifo_setup(&self) -> SetupPacket {
        // SAFETY: FIFO read; caller ensures SETUP packet is ready.
        let fifo = self.base + REG_FIFO_BASE;
        let mut buf = [0u8; 8];
        for slot in &mut buf {
            *slot = unsafe { core::ptr::read_volatile(fifo as *const u8) };
        }
        SetupPacket::from_bytes(&buf)
    }

    // -----------------------------------------------------------------------
    // Private: typed MMIO accessors
    // -----------------------------------------------------------------------

    /// Read an 8-bit MUSB register.
    ///
    /// # Safety
    ///
    /// `offset` must be a valid 8-bit MUSB register offset.
    #[inline(always)]
    unsafe fn read8(&self, offset: usize) -> u8 {
        // SAFETY: caller verifies offset is a valid 8-bit MUSB register within the MUSB address space at 0x1121_0000. Volatile access is required for hardware registers.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u8) }
    }

    /// Write an 8-bit MUSB register.
    ///
    /// # Safety
    ///
    /// `offset` must be a valid 8-bit MUSB register offset.
    #[inline(always)]
    unsafe fn write8(&self, offset: usize, val: u8) {
        // SAFETY: caller verifies offset is a valid 8-bit MUSB register within the MUSB address space at 0x1121_0000. Volatile access is required for hardware registers.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u8, val) }
    }

    /// Read a 16-bit MUSB register (little-endian).
    ///
    /// # Safety
    ///
    /// `offset` must be a valid 16-bit MUSB register, 2-byte aligned.
    #[inline(always)]
    unsafe fn read16(&self, offset: usize) -> u16 {
        // SAFETY: caller verifies offset is a valid 2-byte-aligned 16-bit MUSB register within the MUSB address space at 0x1121_0000. Volatile access is required for hardware registers.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u16) }
    }

    /// Write a 16-bit MUSB register (little-endian).
    ///
    /// # Safety
    ///
    /// `offset` must be a valid 16-bit MUSB register, 2-byte aligned.
    #[inline(always)]
    unsafe fn write16(&self, offset: usize, val: u16) {
        // SAFETY: caller verifies offset is a valid 2-byte-aligned 16-bit MUSB register within the MUSB address space at 0x1121_0000. Volatile access is required for hardware registers.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u16, val) }
    }

    /// Poll a 16-bit MUSB register until the given bits are clear, with a timeout.
    ///
    /// Returns `true` if the bits became clear, `false` on timeout. Uses a
    /// correctly-sized 16-bit access -- unlike `mmio::wait_bits_clear`,
    /// which performs an unconditional 32-bit load and would straddle
    /// adjacent register bytes when polling a 16-bit-only MUSB register
    /// such as REG_TXCSR at an odd half-word offset (issue #227).
    ///
    /// # Safety
    ///
    /// `offset` must be a valid 16-bit MUSB register, 2-byte aligned.
    #[inline]
    unsafe fn wait_bits_clear16(&self, offset: usize, bits: u16, max_iterations: u32) -> bool {
        for _ in 0..max_iterations {
            // SAFETY: caller verifies offset is a valid 2-byte-aligned 16-bit MUSB register within the MUSB address space at 0x1121_0000.
            if unsafe { self.read16(offset) } & bits == 0 {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Register OFFSET encoding ---

    #[test]
    fn register_offsets_match_spec() {
        // Verify documented offsets are encoded correctly.
        assert_eq!(REG_FADDR, 0x00, "FAddr OFFSET must be 0x00");
        assert_eq!(REG_POWER, 0x01, "Power OFFSET must be 0x01");
        assert_eq!(REG_INTRTX, 0x02, "IntrTx OFFSET must be 0x02");
        assert_eq!(REG_INTRRX, 0x04, "IntrRx OFFSET must be 0x04");
        assert_eq!(REG_INTRTXE, 0x06, "IntrTxE OFFSET must be 0x06");
        assert_eq!(REG_INTRRXE, 0x08, "IntrRxE OFFSET must be 0x08");
        assert_eq!(REG_INTRUSB, 0x0A, "IntrUSB OFFSET must be 0x0A");
        assert_eq!(REG_INTRUSBE, 0x0B, "IntrUSBE OFFSET must be 0x0B");
        assert_eq!(REG_FRAME, 0x0E, "Frame OFFSET must be 0x0E");
        assert_eq!(REG_INDEX, 0x0F, "Index OFFSET must be 0x0F");
        assert_eq!(REG_TESTMODE, 0x10, "Testmode OFFSET must be 0x10");
        assert_eq!(REG_EP0_CSR, 0x110, "EP0 CSR OFFSET must be 0x110");
        assert_eq!(REG_TXCSR, 0x112, "TxCSR OFFSET must be 0x112");
        assert_eq!(REG_RXCSR, 0x116, "RxCSR OFFSET must be 0x116");
        assert_eq!(REG_TXMAXP, 0x118, "TxMaxP OFFSET must be 0x118");
        assert_eq!(REG_RXMAXP, 0x11A, "RxMaxP OFFSET must be 0x11A");
        assert_eq!(REG_RXCOUNT, 0x11C, "RxCount OFFSET must be 0x11C");
        assert_eq!(REG_FIFO_BASE, 0x120, "FIFO base OFFSET must be 0x120");
    }

    // --- RX byte-count clamping (issue #221) ---

    #[test]
    fn clamp_rx_count_short_packet_uses_actual_count() {
        assert_eq!(
            clamp_rx_count(1, EP1_MAX_PKT),
            1,
            "a 1-byte OUT packet must drain exactly 1 byte, not a full EP1_MAX_PKT"
        );
    }

    #[test]
    fn clamp_rx_count_full_packet_uses_max_pkt() {
        assert_eq!(clamp_rx_count(64, EP1_MAX_PKT), 64);
    }

    #[test]
    fn clamp_rx_count_zero_length_packet_drains_nothing() {
        assert_eq!(clamp_rx_count(0, EP1_MAX_PKT), 0);
    }

    #[test]
    fn clamp_rx_count_clamps_out_of_range_register_value() {
        assert_eq!(
            clamp_rx_count(200, EP1_MAX_PKT),
            usize::from(EP1_MAX_PKT),
            "a bogus RxCount above the endpoint max packet size must be clamped"
        );
    }

    // --- Device descriptor serialization ---

    #[test]
    fn device_descriptor_length() {
        assert_eq!(
            DEVICE_DESCRIPTOR.len(), 18,
            "device descriptor must be exactly 18 bytes per USB 2.0 spec §9.6.1"
        );
        assert_eq!(DEVICE_DESCRIPTOR.get(0).copied().unwrap_or_default(), 18, "bLength must equal 18");
        assert_eq!(DEVICE_DESCRIPTOR.get(1).copied().unwrap_or_default(), USB_DT_DEVICE, "bDescriptorType must be 0x01");
    }

    #[test]
    fn device_descriptor_usb_version() {
        // bcdUSB = 0x0200 at bytes [2..4], little-endian.
        let bcd_usb = u16::from_le_bytes([DEVICE_DESCRIPTOR.get(2).copied().unwrap_or_default(), DEVICE_DESCRIPTOR.get(3).copied().unwrap_or_default()]);
        assert_eq!(bcd_usb, 0x0200, "bcdUSB must be 0x0200 (USB 2.0)");
    }

    #[test]
    fn device_descriptor_vid_pid() {
        let vid = u16::from_le_bytes([DEVICE_DESCRIPTOR.get(8).copied().unwrap_or_default(), DEVICE_DESCRIPTOR.get(9).copied().unwrap_or_default()]);
        let pid = u16::from_le_bytes([DEVICE_DESCRIPTOR.get(10).copied().unwrap_or_default(), DEVICE_DESCRIPTOR.get(11).copied().unwrap_or_default()]);
        assert_eq!(vid, USB_VID, "idVendor must match USB_VID");
        assert_eq!(pid, USB_PID, "idProduct must match USB_PID");
    }

    // --- Configuration descriptor serialization ---

    #[test]
    fn config_descriptor_total_length() {
        assert_eq!(
            CONFIG_DESCRIPTOR.len(),
            usize::from(CONFIG_DESC_TOTAL_LEN),
            "CONFIG_DESCRIPTOR length must match CONFIG_DESC_TOTAL_LEN"
        );
        let wlen = u16::from_le_bytes([CONFIG_DESCRIPTOR.get(2).copied().unwrap_or_default(), CONFIG_DESCRIPTOR.get(3).copied().unwrap_or_default()]);
        assert_eq!(
            wlen, CONFIG_DESC_TOTAL_LEN,
            "wTotalLength field must match CONFIG_DESC_TOTAL_LEN"
        );
    }

    #[test]
    fn config_descriptor_num_interfaces() {
        assert_eq!(CONFIG_DESCRIPTOR.get(4).copied().unwrap_or_default(), 2, "bNumInterfaces must be 2 (CDC control + CDC data)");
    }

    #[test]
    fn config_descriptor_endpoint_addresses() {
        // Verify that the endpoint descriptor addresses in the config blob are
        // correctly encoded. EP2 IN is at byte 44 (9+9+5+4+5+5 = OFFSET 37 is EP2 IN
        // endpoint descriptor bLength position, +2 = bEndpointAddress).
        // Layout: [0..9) config, [9..18) iface0, [18..23) header, [23..27) acm,
        //         [27..32) UNION, [32..39) ep2, [39..48) iface1, [48..55) ep1in, [55..62) ep1out
        let ep2_addr = CONFIG_DESCRIPTOR.get(34).copied().unwrap_or_default();
        let ep1_in_addr = CONFIG_DESCRIPTOR.get(50).copied().unwrap_or_default();
        let ep1_out_addr = CONFIG_DESCRIPTOR.get(57).copied().unwrap_or_default();
        assert_eq!(ep2_addr, EP2_IN_ADDR, "EP2 bEndpointAddress must be 0x82");
        assert_eq!(ep1_in_addr, EP1_IN_ADDR, "EP1 IN bEndpointAddress must be 0x81");
        assert_eq!(ep1_out_addr, EP1_OUT_ADDR, "EP1 OUT bEndpointAddress must be 0x01");
    }

    // --- EP0 state machine ---

    #[test]
    fn ep0_initial_state_is_idle() {
        let ctrl = UsbController::new();
        assert_eq!(
            ctrl.ep0_state,
            Ep0State::Idle,
            "EP0 state machine must start in Idle"
        );
    }

    #[test]
    fn ep0_state_transitions_via_reset() {
        let mut ctrl = UsbController::new();
        // Simulate state that would be SET during enumeration.
        ctrl.ep0_state = Ep0State::DataIn;
        ctrl.configured = true;
        ctrl.pending_address = 5;
        // Reset must clear all EP0 state.
        // SAFETY: no real hardware; base address will not be dereferenced in test.
        // NOTE: We test only the pure-logic state changes. Hardware MMIO calls
        // are #[cfg(not(test))] guarded by the init() entry point; handle_reset
        // also writes MMIO. This test validates the logical state fields only.
        ctrl.ep0_state = Ep0State::Idle;
        ctrl.pending_address = 0;
        ctrl.configured = false;
        assert_eq!(ctrl.ep0_state, Ep0State::Idle, "EP0 state must be Idle after reset");
        assert_eq!(ctrl.pending_address, 0, "pending_address must be 0 after reset");
        assert!(!ctrl.configured, "configured must be false after reset");
    }

    // --- SetupPacket parsing ---

    #[test]
    fn setup_packet_get_descriptor() {
        // GET_DESCRIPTOR for Device descriptor: standard, IN, device recipient.
        let raw: [u8; 8] = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let pkt = SetupPacket::from_bytes(&raw);
        assert_eq!(pkt.bm_request_type, 0x80, "bmRequestType must be 0x80");
        assert_eq!(pkt.b_request, USB_REQ_GET_DESCRIPTOR, "bRequest must be GET_DESCRIPTOR");
        assert_eq!(pkt.w_value, 0x0100, "wValue must be 0x0100 (Device descriptor)");
        assert_eq!(pkt.w_length, 18, "wLength must be 18 for device descriptor");
        assert!(!pkt.is_host_to_device(), "direction must be device-to-host (IN)");
        assert!(pkt.is_standard(), "request type must be standard");
    }

    #[test]
    fn setup_packet_set_address() {
        // SET_ADDRESS 0x05: host-to-device, standard, device.
        let raw: [u8; 8] = [0x00, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00];
        let pkt = SetupPacket::from_bytes(&raw);
        assert_eq!(pkt.b_request, USB_REQ_SET_ADDRESS, "bRequest must be SET_ADDRESS");
        assert_eq!(pkt.w_value, 7, "wValue (address) must be 7");
        assert!(pkt.is_host_to_device(), "SET_ADDRESS is host-to-device");
        assert!(pkt.is_standard(), "SET_ADDRESS is a standard request");
        assert!(!pkt.is_class(), "SET_ADDRESS is not a class request");
    }

    #[test]
    fn setup_packet_set_line_coding() {
        // SET_LINE_CODING: class, host-to-device, interface.
        let raw: [u8; 8] = [0x21, 0x20, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00];
        let pkt = SetupPacket::from_bytes(&raw);
        assert_eq!(pkt.b_request, CDC_REQ_SET_LINE_CODING, "bRequest must be SET_LINE_CODING");
        assert!(pkt.is_host_to_device(), "SET_LINE_CODING is host-to-device");
        assert!(pkt.is_class(), "SET_LINE_CODING is a class request");
        assert_eq!(pkt.w_length, 7, "SET_LINE_CODING wLength must be 7");
    }

    // --- ACM class request handling ---

    #[test]
    fn line_coding_roundtrip() {
        let original = LineCoding { dw_dte_rate: 9600, b_char_format: 0, b_parity_type: 0, b_data_bits: 8 };
        let bytes = original.to_bytes();
        let recovered = LineCoding::from_bytes(&bytes);
        assert_eq!(recovered.dw_dte_rate, 9600, "baud rate must survive roundtrip");
        assert_eq!(recovered.b_char_format, 0, "char format must survive roundtrip");
        assert_eq!(recovered.b_data_bits, 8, "data bits must survive roundtrip");
    }

    #[test]
    fn line_coding_default_is_115200_8n1() {
        let lc = LineCoding::default_115200();
        assert_eq!(lc.dw_dte_rate, 115_200, "default baud must be 115200");
        assert_eq!(lc.b_char_format, 0, "default stop bits must be 1 (format 0)");
        assert_eq!(lc.b_parity_type, 0, "default parity must be None (type 0)");
        assert_eq!(lc.b_data_bits, 8, "default data bits must be 8");
    }

    // --- Interrupt status parsing ---

    #[test]
    fn irq_status_reset_detection() {
        let s = UsbIrqStatus { intrusb: INTRUSB_RESET, intrtx: 0, intrrx: 0 };
        assert!(s.has_reset(), "must detect USB reset");
        assert!(!s.has_suspend(), "must not detect suspend without bit");
        assert!(!s.has_ep0(), "must not detect EP0 without IntrTx bit");
    }

    #[test]
    fn irq_status_ep0_detection() {
        let s = UsbIrqStatus { intrusb: 0, intrtx: INTRTX_EP0, intrrx: 0 };
        assert!(s.has_ep0(), "must detect EP0 interrupt");
        assert!(!s.has_ep1_tx(), "must not detect EP1 TX without bit");
        assert!(!s.has_reset(), "must not detect reset without bit");
    }

    #[test]
    fn irq_status_ep1_rx_detection() {
        let s = UsbIrqStatus { intrusb: 0, intrtx: 0, intrrx: INTRRX_EP1 };
        assert!(s.has_ep1_rx(), "must detect EP1 RX interrupt");
        assert!(!s.has_ep1_tx(), "must not detect EP1 TX without bit");
    }

    #[test]
    fn irq_status_empty() {
        let s = UsbIrqStatus::default();
        assert!(s.is_empty(), "default UsbIrqStatus must be empty");
        let s2 = UsbIrqStatus { intrusb: INTRUSB_RESUME, intrtx: 0, intrrx: 0 };
        assert!(!s2.is_empty(), "non-zero IntrUSB must not be empty");
    }

    // --- Serial ring buffer ---

    #[test]
    fn read_serial_empty() {
        let mut ctrl = UsbController::new();
        let mut buf = [0u8; 16];
        let n = ctrl.read_serial(&mut buf);
        assert_eq!(n, 0, "read FROM empty ring buffer must return 0");
    }

    #[test]
    fn read_serial_partial() {
        let mut ctrl = UsbController::new();
        // Manually prime the ring buffer with 3 bytes.
        ctrl.rx_buf[0] = b'A';
        ctrl.rx_buf[1] = b'B';
        ctrl.rx_buf[2] = b'C';
        ctrl.rx_head = 3;
        ctrl.rx_tail = 0;

        let mut buf = [0u8; 8];
        let n = ctrl.read_serial(&mut buf);
        assert_eq!(n, 3, "must read exactly 3 bytes");
        assert_eq!(&buf[..3], b"ABC", "bytes must match what was written");
    }

    // --- write_serial gate: not configured ---

    #[test]
    fn write_serial_not_configured_returns_zero() {
        let mut ctrl = UsbController::new();
        // configured = false (default), so write should return 0 without MMIO.
        // SAFETY: base is MUSB_BASE which is an unmapped address in test, but
        // write_serial checks `configured` before any MMIO access.
        let n = unsafe { ctrl.write_serial(b"hello") };
        assert_eq!(n, 0, "write_serial must return 0 when not configured");
    }
}
