//! Network subsystem foundation.
//!
//! Wraps smoltcp to provide the kernel's TCP/IP stack. This module is the
//! layer that `WiFi`, DHCP, DNS, and socket syscalls all build on.
//!
//! # Architecture
//!
//! [`NetworkStack`] owns a smoltcp [`Interface`] and [`SocketSet`], wired
//! together with a [`phy::Device`] implementor (loopback for testing, `WiFi`
//! hardware for production). The stack is polled periodically — each call
//! to [`NetworkStack::poll`] drives packet ingress/egress and socket state
//! machines forward.
//!
//! # Loopback
//!
//! [`LoopbackDevice`] implements smoltcp's [`phy::Device`] trait with an
//! internal packet queue. Every transmitted frame is looped back for
//! reception in FIFO order, enabling full-stack testing without hardware.
//!
//! # Constants
//!
//! Buffer sizes and socket limits are tuned for the MT6739's 128 MB RAM
//! budget. These may be made configurable via `kconfig` in a future phase.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken as _};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address, Ipv4Cidr};

use crate::firewall::{Action, Firewall};
use crate::wifi::{WifiError, WifiHwOps, generate_random_mac};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent sockets in the stack.
pub(crate) const MAX_SOCKETS: usize = 32;

/// TCP receive buffer size in bytes.
pub(crate) const TCP_RX_BUF_SIZE: usize = 4096;

/// TCP transmit buffer size in bytes.
pub(crate) const TCP_TX_BUF_SIZE: usize = 4096;

/// UDP receive buffer metadata slot count (max queued datagrams).
pub(crate) const UDP_RX_META_SLOTS: usize = 8;

/// UDP receive buffer payload size in bytes.
pub(crate) const UDP_RX_BUF_SIZE: usize = 4096;

/// UDP transmit buffer metadata slot count (max queued datagrams).
pub(crate) const UDP_TX_META_SLOTS: usize = 8;

/// UDP transmit buffer payload size in bytes.
pub(crate) const UDP_TX_BUF_SIZE: usize = 4096;

/// Default Ethernet MTU (standard 1514-byte frame: 14-byte header + 1500 payload).
const DEFAULT_MTU: usize = 1514;

/// Ethernet header length before the layer-3 payload.
const ETHERNET_HEADER_LEN: usize = 14;

/// `EtherType` for IPv4 frames.
const ETHERTYPE_IPV4: u16 = 0x0800;

/// Generate a locally administered unicast Ethernet address for kernel stacks.
///
/// This is used even for host-only loopback smoke stacks so the production
/// boot path never grows a fixed device address by accident.
pub(crate) fn randomized_local_ethernet_address() -> EthernetAddress {
    EthernetAddress(generate_random_mac())
}

// ---------------------------------------------------------------------------
// Device readiness
// ---------------------------------------------------------------------------

/// Network device class used for boot readiness accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkDeviceKind {
    /// Host-only loopback smoke path. Useful for stack tests, not connectivity.
    LoopbackSmoke,
    /// Real `WiFi` hardware data path.
    Wifi,
}

/// Typed network boot readiness result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkReadiness {
    /// Loopback stack smoke passed, but no production network is available.
    LoopbackSmokeOnly,
    /// The selected production device cannot exchange frames.
    HardwareUnavailable(NetworkDeviceKind),
    /// A production network device has reported its frame data path ready.
    ProductionReady(NetworkDeviceKind),
}

impl NetworkReadiness {
    /// Classify a device kind and its low-level data path readiness.
    pub(crate) const fn from_device(kind: NetworkDeviceKind, data_path_ready: bool) -> Self {
        match kind {
            NetworkDeviceKind::LoopbackSmoke => Self::LoopbackSmokeOnly,
            NetworkDeviceKind::Wifi if data_path_ready => Self::ProductionReady(kind),
            NetworkDeviceKind::Wifi => Self::HardwareUnavailable(kind),
        }
    }

    /// Return true only for real-device production connectivity.
    pub(crate) const fn production_network_ok(self) -> bool {
        matches!(self, Self::ProductionReady(NetworkDeviceKind::Wifi))
    }

    /// Return true when the result is only a loopback smoke pass.
    pub(crate) const fn loopback_smoke_only(self) -> bool {
        matches!(self, Self::LoopbackSmokeOnly)
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by network stack operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetError {
    /// Socket set is full; cannot add another socket.
    SocketSetFull,
    /// The provided socket handle does not refer to a valid socket.
    InvalidHandle,
    /// Route table is full.
    RouteTableFull,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SocketSetFull => write!(f, "socket set full"),
            Self::InvalidHandle => write!(f, "invalid socket handle"),
            Self::RouteTableFull => write!(f, "route table full"),
        }
    }
}

// ---------------------------------------------------------------------------
// Loopback device
// ---------------------------------------------------------------------------

/// A loopback network device for testing.
///
/// Every frame transmitted through this device is enqueued and returned on
/// the next [`Device::receive`] call, in FIFO order. The device uses the
/// Ethernet medium so that the full ARP / IP path is exercised.
/// Maximum number of frames the [`LoopbackDevice`] TX queue holds before
/// new frames are dropped.
///
/// WHY bounded: `transmit()` always returns a token and `consume()`
/// always enqueues -- smoltcp's `TxToken` API has no backpressure signal
/// -- so an unbounded queue grows without limit whenever polling drains
/// RX slower than TX produces frames (heap exhaustion on a 128 MB
/// device). A fixed cap converts that into ordinary tail-drop packet
/// loss, which every protocol layered on top (TCP retransmission, UDP
/// at-most-once) already tolerates.
const LOOPBACK_QUEUE_CAPACITY: usize = 64;

pub(crate) struct LoopbackDevice {
    /// FIFO queue of frames awaiting reception.
    queue: VecDeque<Vec<u8>>,
    /// Count of frames dropped because the queue was at capacity.
    dropped_frames: usize,
}

impl LoopbackDevice {
    /// Create a new loopback device with an empty packet queue.
    pub(crate) fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            dropped_frames: 0,
        }
    }

    /// Return the number of frames currently queued for reception.
    pub(crate) fn queued_frames(&self) -> usize {
        self.queue.len()
    }

    /// Return the number of frames dropped because the TX queue was full.
    pub(crate) fn dropped_frames(&self) -> usize {
        self.dropped_frames
    }
}

/// Receive token for [`LoopbackDevice`].
pub(crate) struct LoopbackRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for LoopbackRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// Transmit token for [`LoopbackDevice`].
pub(crate) struct LoopbackTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    dropped_frames: &'a mut usize,
}

impl phy::TxToken for LoopbackTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        if self.queue.len() < LOOPBACK_QUEUE_CAPACITY {
            self.queue.push_back(buffer);
        } else {
            *self.dropped_frames = self.dropped_frames.saturating_add(1);
        }
        result
    }
}

impl Device for LoopbackDevice {
    type RxToken<'a> = LoopbackRxToken;
    type TxToken<'a> = LoopbackTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = DEFAULT_MTU;
        caps.medium = Medium::Ethernet;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.queue.pop_front().map(move |buffer| {
            let rx = LoopbackRxToken { buffer };
            let tx = LoopbackTxToken {
                queue: &mut self.queue,
                dropped_frames: &mut self.dropped_frames,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(LoopbackTxToken {
            queue: &mut self.queue,
            dropped_frames: &mut self.dropped_frames,
        })
    }
}

// ---------------------------------------------------------------------------
// WiFi device adapter
// ---------------------------------------------------------------------------

/// smoltcp device adapter for the kernel `WiFi` hardware boundary.
///
/// This adapter only exposes TX/RX tokens after the hardware backend reports
/// its Ethernet data path ready. The current MT6739 backend returns false, so
/// boot can instantiate the real-device boundary without claiming hardware
/// packet I/O works before WMT/STP operations are wired.
pub(crate) struct WifiDevice<H: WifiHwOps> {
    hw: H,
    last_error: Option<WifiError>,
}

impl<H: WifiHwOps> WifiDevice<H> {
    /// Create a `WiFi` smoltcp adapter around hardware operations.
    pub(crate) const fn new(hw: H) -> Self {
        Self {
            hw,
            last_error: None,
        }
    }

    /// Device kind for boot readiness accounting.
    // WHY: kinit.rs (out of scope here) calls this instance-style
    // (`wifi_device.kind()`) alongside `.data_path_ready()` in
    // NetworkReadiness::from_device -- dropping &self would need a matching
    // kinit.rs call-site edit this PR cannot make.
    #[allow(clippy::unused_self)]
    pub(crate) const fn kind(&self) -> NetworkDeviceKind {
        NetworkDeviceKind::Wifi
    }

    /// Return true once the hardware data path is ready for Ethernet frames.
    pub(crate) fn data_path_ready(&self) -> bool {
        self.hw.data_path_ready()
    }

    /// Last transmit error observed through the smoltcp token path.
    #[cfg(test)]
    pub(crate) const fn last_error(&self) -> Option<WifiError> {
        self.last_error
    }

    /// Borrow the hardware backend.
    #[cfg(test)]
    pub(crate) const fn hw(&self) -> &H {
        &self.hw
    }
}

/// Receive token for [`WifiDevice`].
pub(crate) struct WifiRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for WifiRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// Transmit token for [`WifiDevice`].
pub(crate) struct WifiTxToken<'a, H: WifiHwOps> {
    hw: &'a mut H,
    last_error: &'a mut Option<WifiError>,
}

impl<H: WifiHwOps> phy::TxToken for WifiTxToken<'_, H> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        *self.last_error = self.hw.send_frame(&buffer).err();
        result
    }
}

impl<H: WifiHwOps> Device for WifiDevice<H> {
    type RxToken<'a>
        = WifiRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = WifiTxToken<'a, H>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = DEFAULT_MTU;
        caps.medium = Medium::Ethernet;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if !self.hw.data_path_ready() {
            return None;
        }

        let buffer = self.hw.recv_frame()?;
        Some((
            WifiRxToken { buffer },
            WifiTxToken {
                hw: &mut self.hw,
                last_error: &mut self.last_error,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if !self.hw.data_path_ready() {
            return None;
        }

        Some(WifiTxToken {
            hw: &mut self.hw,
            last_error: &mut self.last_error,
        })
    }
}

// ---------------------------------------------------------------------------
// Firewall device wrapper
// ---------------------------------------------------------------------------

/// Network device wrapper that filters IPv4 packets before/after smoltcp.
///
/// The firewall module evaluates raw IPv4 packets, while smoltcp devices move
/// Ethernet frames. This wrapper strips the Ethernet header for IPv4 frames,
/// leaves non-IPv4 traffic untouched, and preserves the existing `Device`
/// contract for boot smoke tests and future WiFi-backed devices.
/// Boot network device behind the firewall wrapper (#403). `LoopbackDevice`
/// until the `WiFi` data path lands (#129) -- the same build-time alias pattern as
/// `telephony::BootModemTransport`, so swapping in a real NIC is a one-line
/// change. INVARIANT (kardia `KernelState`): this device must stay
/// synchronous/polled; if a future NIC becomes IRQ-fed, its ISR must hand frames
/// through an `IrqSpinlock`/reflex ring rather than mutating the device directly.
pub(crate) type BootNetDevice = LoopbackDevice;

pub(crate) struct FirewallDevice<D> {
    device: D,
    firewall: Firewall,
}

impl<D> FirewallDevice<D> {
    /// Wrap a device with a firewall that has the default DNS blocklist loaded.
    pub(crate) fn with_default_firewall(device: D) -> Self {
        let mut firewall = Firewall::new();
        firewall.load_default_blocklist();
        Self { device, firewall }
    }

    /// Borrow the wrapped device immutably.
    #[cfg(test)]
    pub(crate) fn inner(&self) -> &D {
        &self.device
    }

    /// Borrow the firewall immutably.
    #[cfg(test)]
    pub(crate) fn firewall(&self) -> &Firewall {
        &self.firewall
    }

    /// Borrow the firewall mutably: the production runtime-policy + audit-drain
    /// accessor (#403). The service loop installs rules through it
    /// (`add_rule`) and drains its pending packet events into the audit log.
    pub(crate) fn firewall_mut(&mut self) -> &mut Firewall {
        &mut self.firewall
    }
}

/// Receive token for [`FirewallDevice`].
pub(crate) struct FirewallRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for FirewallRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// Transmit token for [`FirewallDevice`].
pub(crate) struct FirewallTxToken<'a, T: phy::TxToken> {
    inner: T,
    firewall: &'a mut Firewall,
}

impl<T: phy::TxToken> phy::TxToken for FirewallTxToken<'_, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        if frame_allowed_tx(self.firewall, &buffer) {
            self.inner.consume(len, |out| {
                out.copy_from_slice(&buffer);
            });
        }

        result
    }
}

impl<D: Device> Device for FirewallDevice<D> {
    type RxToken<'a>
        = FirewallRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = FirewallTxToken<'a, D::TxToken<'a>>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        self.device.capabilities()
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let (rx, tx) = self.device.receive(timestamp)?;
        let mut buffer = Vec::new();
        rx.consume(|frame| buffer.extend_from_slice(frame));

        if !frame_allowed_rx(&mut self.firewall, &buffer) {
            return None;
        }

        Some((
            FirewallRxToken { buffer },
            FirewallTxToken {
                inner: tx,
                firewall: &mut self.firewall,
            },
        ))
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.device
            .transmit(timestamp)
            .map(|inner| FirewallTxToken {
                inner,
                firewall: &mut self.firewall,
            })
    }
}

fn ipv4_payload(frame: &[u8]) -> Option<&[u8]> {
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }

    frame.get(ETHERNET_HEADER_LEN..)
}

fn frame_allowed_rx(firewall: &mut Firewall, frame: &[u8]) -> bool {
    ipv4_payload(frame)
        .is_none_or(|packet| matches!(firewall.evaluate_rx(packet), Action::Allow | Action::Log))
}

fn frame_allowed_tx(firewall: &mut Firewall, frame: &[u8]) -> bool {
    ipv4_payload(frame)
        .is_none_or(|packet| matches!(firewall.evaluate_tx(packet), Action::Allow | Action::Log))
}

// ---------------------------------------------------------------------------
// Network stack
// ---------------------------------------------------------------------------

/// Kernel network stack.
///
/// Wraps a smoltcp [`Interface`] and [`SocketSet`] with convenience methods
/// for socket creation, removal, and polling. The stack is generic over the
/// underlying device — use [`LoopbackDevice`] for tests and the `WiFi` driver
/// for production.
pub(crate) struct NetworkStack<D: Device> {
    /// The smoltcp network interface (handles ARP, IP routing, etc.).
    iface: Interface,
    /// Set of active sockets managed by the stack.
    sockets: SocketSet<'static>,
    /// The underlying network device.
    device: D,
    /// Number of sockets currently in the set. Tracked manually because
    /// `SocketSet` does not expose a `len()` method.
    socket_count: usize,
}

impl<D: Device> NetworkStack<D> {
    /// Create a new network stack with the given device and MAC address.
    ///
    /// The interface is configured with Ethernet medium and the provided
    /// hardware address. No IP addresses or routes are configured; call
    /// [`set_ipv4_addr`](Self::set_ipv4_addr) and
    /// [`set_default_gateway`](Self::set_default_gateway) after creation.
    pub(crate) fn new(mut device: D, mac: EthernetAddress, now: Instant) -> Self {
        let config = Config::new(HardwareAddress::Ethernet(mac));
        let iface = Interface::new(config, &mut device, now);

        // WHY Vec-backed: smoltcp's SocketSet accepts a ManagedSlice, which
        // can be either a borrowed slice (fixed capacity) or a Vec (growable).
        // We use Vec so we don't need a static array, but cap insertions at
        // MAX_SOCKETS ourselves to bound memory use.
        let sockets = SocketSet::new(Vec::<SocketStorage<'static>>::new());

        Self {
            iface,
            sockets,
            device,
            socket_count: 0,
        }
    }

    /// Configure the interface's IPv4 address and subnet mask.
    ///
    /// Replaces any previously configured addresses.
    pub(crate) fn set_ipv4_addr(&mut self, addr: Ipv4Address, prefix_len: u8) {
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            // WHY push can't fail: IFACE_MAX_ADDR_COUNT (8) > 1, and we just
            // cleared the vec, so there is always room for one entry.
            addrs
                .push(IpCidr::Ipv4(Ipv4Cidr::new(addr, prefix_len)))
                .ok();
        });
    }

    /// Set the default IPv4 gateway for the interface.
    ///
    /// Returns `Err(NetError::RouteTableFull)` if the route table is full.
    pub(crate) fn set_default_gateway(&mut self, gateway: Ipv4Address) -> Result<(), NetError> {
        self.iface
            .routes_mut()
            .add_default_ipv4_route(gateway)
            .map_err(|_| NetError::RouteTableFull)?;
        Ok(())
    }

    /// Create a TCP socket with the default buffer sizes and add it to the set.
    ///
    /// Returns `Err(NetError::SocketSetFull)` if [`MAX_SOCKETS`] has been
    /// reached.
    #[must_use = "pass the handle to `remove_socket` when done, or the slot leaks until reboot"]
    pub(crate) fn add_tcp_socket(&mut self) -> Result<SocketHandle, NetError> {
        if self.socket_count >= MAX_SOCKETS {
            return Err(NetError::SocketSetFull);
        }
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        let handle = self.sockets.add(socket);
        self.socket_count += 1;
        Ok(handle)
    }

    /// Create a UDP socket with the default buffer sizes and add it to the set.
    ///
    /// Returns `Err(NetError::SocketSetFull)` if [`MAX_SOCKETS`] has been
    /// reached.
    #[must_use = "pass the handle to `remove_socket` when done, or the slot leaks until reboot"]
    pub(crate) fn add_udp_socket(&mut self) -> Result<SocketHandle, NetError> {
        if self.socket_count >= MAX_SOCKETS {
            return Err(NetError::SocketSetFull);
        }
        let rx_meta: Vec<udp::PacketMetadata> = vec![udp::PacketMetadata::EMPTY; UDP_RX_META_SLOTS];
        let rx_buf = vec![0u8; UDP_RX_BUF_SIZE];
        let tx_meta: Vec<udp::PacketMetadata> = vec![udp::PacketMetadata::EMPTY; UDP_TX_META_SLOTS];
        let tx_buf = vec![0u8; UDP_TX_BUF_SIZE];
        let socket = udp::Socket::new(
            udp::PacketBuffer::new(rx_meta, rx_buf),
            udp::PacketBuffer::new(tx_meta, tx_buf),
        );
        let handle = self.sockets.add(socket);
        self.socket_count += 1;
        Ok(handle)
    }

    /// Remove a socket from the set by its handle.
    ///
    /// The socket is dropped and its resources freed. The handle becomes
    /// invalid after this call.
    pub(crate) fn remove_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
        self.socket_count = self.socket_count.saturating_sub(1);
    }

    /// Poll the network stack: process incoming packets and drive socket state.
    ///
    /// `now` is the current monotonic timestamp. Returns `true` if any socket
    /// state may have changed (callers should re-check their sockets).
    pub(crate) fn poll(&mut self, now: Instant) -> bool {
        let result = self.iface.poll(now, &mut self.device, &mut self.sockets);
        result == smoltcp::iface::PollResult::SocketStateChanged
    }

    /// Borrow the socket set immutably (e.g., to inspect socket state).
    pub(crate) fn sockets(&self) -> &SocketSet<'static> {
        &self.sockets
    }

    /// Borrow the socket set mutably (e.g., to read/write socket data).
    pub(crate) fn sockets_mut(&mut self) -> &mut SocketSet<'static> {
        &mut self.sockets
    }

    /// Borrow the interface immutably.
    pub(crate) fn iface(&self) -> &Interface {
        &self.iface
    }

    /// Borrow the interface mutably.
    pub(crate) fn iface_mut(&mut self) -> &mut Interface {
        &mut self.iface
    }

    /// Borrow the underlying device immutably.
    pub(crate) fn device(&self) -> &D {
        &self.device
    }

    /// Borrow the underlying device mutably.
    pub(crate) fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Return the number of sockets currently in the set.
    pub(crate) fn socket_count(&self) -> usize {
        self.socket_count
    }

    /// Increment the manual socket count.
    ///
    /// Used by subsystems (DHCP, DNS) that add sockets directly to the
    /// [`SocketSet`] via [`sockets_mut()`](Self::sockets_mut) instead of
    /// going through [`add_tcp_socket`](Self::add_tcp_socket) or
    /// [`add_udp_socket`](Self::add_udp_socket).
    pub(crate) fn increment_socket_count(&mut self) {
        self.socket_count += 1;
    }

    /// Poll the network stack and all registered services.
    ///
    /// Calls [`poll`](Self::poll) to drive socket I/O, then polls the
    /// DHCP client (if provided) and ticks the DNS resolver (if provided).
    /// Returns the DHCP event (if any) so callers can react to IP changes.
    ///
    /// This is the recommended single-call-site for periodic network
    /// processing in the kernel's main loop or timer tick handler.
    pub(crate) fn poll_services(
        &mut self,
        now: Instant,
        dhcp: Option<&mut crate::dhcp::DhcpClient>,
        dns: Option<&mut crate::dns::DnsResolver>,
        elapsed_secs: u32,
    ) -> crate::dhcp::DhcpEvent {
        // Drive the smoltcp interface (ARP, IP, socket state machines).
        self.poll(now);

        // Poll DHCP for configuration events.
        let dhcp_event = match dhcp {
            Some(client) => client.poll(self),
            None => crate::dhcp::DhcpEvent::None,
        };

        // Tick DNS cache TTLs.
        if let Some(resolver) = dns
            && elapsed_secs > 0
        {
            resolver.tick(elapsed_secs);
        }

        dhcp_event
    }
}

// ---------------------------------------------------------------------------
// Helper: timestamp from milliseconds
// ---------------------------------------------------------------------------

/// Create a smoltcp [`Instant`] from a millisecond count.
///
/// This is the bridge between the kernel's timer tick count and smoltcp's
/// time representation. The kernel timer runs at 100 Hz (10 ms/tick), so
/// callers should multiply their tick count by 10 to get milliseconds.
pub(crate) fn instant_from_millis(millis: i64) -> Instant {
    Instant::from_millis(millis)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;

    use super::*;

    struct TestWifiHw {
        ready: bool,
        rx_frames: VecDeque<Vec<u8>>,
        sent_frames: Vec<Vec<u8>>,
        tx_result: Result<(), WifiError>,
    }

    impl TestWifiHw {
        fn unavailable() -> Self {
            Self {
                ready: false,
                rx_frames: VecDeque::new(),
                sent_frames: Vec::new(),
                tx_result: Ok(()),
            }
        }

        fn ready() -> Self {
            Self {
                ready: true,
                rx_frames: VecDeque::new(),
                sent_frames: Vec::new(),
                tx_result: Ok(()),
            }
        }
    }

    impl WifiHwOps for TestWifiHw {
        fn data_path_ready(&self) -> bool {
            self.ready
        }

        fn send_frame(&mut self, data: &[u8]) -> Result<(), WifiError> {
            self.sent_frames.push(data.to_vec());
            self.tx_result
        }

        fn recv_frame(&mut self) -> Option<Vec<u8>> {
            self.rx_frames.pop_front()
        }

        fn scan_start(&mut self) -> Result<(), WifiError> {
            Ok(())
        }

        fn scan_results(&self) -> &[crate::wifi::ScanResult] {
            &[]
        }

        fn associate(&mut self, _ssid: &[u8], _bssid: &[u8; 6]) -> Result<(), WifiError> {
            Ok(())
        }
    }

    fn make_ethernet_ipv4_frame(ipv4_packet: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + ipv4_packet.len());
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(ipv4_packet);
        frame
    }

    fn make_ipv4_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 0x50;
        pkt
    }

    fn make_ipv4_udp_dns_query(domain: &str) -> Vec<u8> {
        let mut dns = Vec::new();
        dns.extend_from_slice(&[
            0x00, 0x01, // ID
            0x01, 0x00, // standard query, RD=1
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ]);
        for label in domain.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let total = 20 + 8 + dns.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[127, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[9, 9, 9, 9]);
        pkt[20..22].copy_from_slice(&49152u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(&dns);
        pkt
    }

    /// Helper: build a `NetworkStack<LoopbackDevice>` with a stock IP config.
    fn make_stack() -> NetworkStack<LoopbackDevice> {
        let device = LoopbackDevice::new();
        let mac = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let now = Instant::from_millis(0);
        let mut stack = NetworkStack::new(device, mac, now);
        stack.set_ipv4_addr(Ipv4Address::LOCALHOST, 8);
        stack
    }

    #[test]
    fn create_network_stack_with_loopback() {
        let stack = make_stack();
        assert_eq!(stack.socket_count(), 0);
        // Interface should have the IP we configured.
        let addrs = stack.iface().ip_addrs();
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn wifi_unavailable_is_not_production_ready() {
        let readiness = NetworkReadiness::from_device(NetworkDeviceKind::Wifi, false);

        assert_eq!(
            readiness,
            NetworkReadiness::HardwareUnavailable(NetworkDeviceKind::Wifi)
        );
        assert!(
            !readiness.production_network_ok(),
            "unavailable WiFi hardware must not mark production network ready"
        );
    }

    #[test]
    fn loopback_readiness_remains_smoke_only() {
        let readiness = NetworkReadiness::from_device(NetworkDeviceKind::LoopbackSmoke, true);

        assert_eq!(readiness, NetworkReadiness::LoopbackSmokeOnly);
        assert!(
            readiness.loopback_smoke_only(),
            "loopback must be tracked only as smoke coverage"
        );
        assert!(
            !readiness.production_network_ok(),
            "loopback smoke must not mark production network ready"
        );
    }

    #[test]
    fn wifi_device_unavailable_fails_closed() {
        let mut device = WifiDevice::new(TestWifiHw::unavailable());
        let now = Instant::from_millis(0);

        assert!(!device.data_path_ready(), "test WiFi hw starts unavailable");
        assert!(
            device.transmit(now).is_none(),
            "unavailable WiFi must not expose a TX token"
        );
        assert!(
            device.receive(now).is_none(),
            "unavailable WiFi must not expose an RX token"
        );
    }

    #[test]
    fn wifi_device_ready_transmits_through_hardware_ops() {
        let mut device = WifiDevice::new(TestWifiHw::ready());
        let now = Instant::from_millis(0);

        let tx = device
            .transmit(now)
            .expect("ready WiFi device must expose a TX token");
        phy::TxToken::consume(tx, 4, |buf| {
            buf.copy_from_slice(&[1, 2, 3, 4]);
        });

        assert_eq!(device.hw().sent_frames.as_slice(), &[vec![1, 2, 3, 4]]);
        assert_eq!(device.last_error(), None);
    }

    #[test]
    fn add_tcp_socket_returns_handle() {
        let mut stack = make_stack();
        let handle = stack.add_tcp_socket();
        assert!(handle.is_ok(), "adding TCP socket must succeed");
        assert_eq!(stack.socket_count(), 1);

        // The handle should be usable to retrieve the socket.
        let _tcp: &tcp::Socket<'_> = stack.sockets().get(handle.ok().unwrap()); // ok: test
    }

    #[test]
    fn add_udp_socket_returns_handle() {
        let mut stack = make_stack();
        let handle = stack.add_udp_socket();
        assert!(handle.is_ok(), "adding UDP socket must succeed");
        assert_eq!(stack.socket_count(), 1);

        let _udp: &udp::Socket<'_> = stack.sockets().get(handle.ok().unwrap()); // ok: test
    }

    #[test]
    fn poll_with_no_activity_succeeds() {
        let mut stack = make_stack();
        // With no sockets and no packets, poll should complete without panic.
        let changed = stack.poll(Instant::from_millis(100));
        // No sockets means no state change.
        assert!(!changed, "poll with no activity should report no change");
    }

    #[test]
    fn loopback_transmit_then_receive() {
        let mut device = LoopbackDevice::new();
        let now = Instant::from_millis(0);

        // Transmit a frame.
        {
            let tx = device.transmit(now);
            assert!(tx.is_some(), "loopback transmit must return a token");
            phy::TxToken::consume(tx.unwrap(), 42, |buf| {
                // Fill with a recognizable pattern.
                for (i, byte) in buf.iter_mut().enumerate() {
                    *byte = (i & 0xFF) as u8;
                }
            });
        }
        assert_eq!(device.queued_frames(), 1);

        // Receive it back.
        {
            let rx_tx = device.receive(now);
            assert!(rx_tx.is_some(), "loopback receive must return tokens");
            let (rx, _tx) = rx_tx.unwrap();
            phy::RxToken::consume(rx, |buf| {
                assert_eq!(buf.len(), 42, "received frame length");
                for (i, &byte) in buf.iter().enumerate() {
                    assert_eq!(byte, (i & 0xFF) as u8, "byte {i} mismatch");
                }
            });
        }
        assert_eq!(device.queued_frames(), 0);
    }

    #[test]
    fn loopback_tx_queue_is_bounded() {
        let mut device = LoopbackDevice::new();
        let now = Instant::from_millis(0);

        // Transmit far more frames than LOOPBACK_QUEUE_CAPACITY without
        // ever draining via receive() -- the failure mode this bound
        // exists to prevent: unbounded heap growth from polling
        // starvation.
        let attempts = LOOPBACK_QUEUE_CAPACITY + 10;
        for _ in 0..attempts {
            let tx = device.transmit(now).unwrap();
            phy::TxToken::consume(tx, 8, |_buf| {});
        }

        assert_eq!(
            device.queued_frames(),
            LOOPBACK_QUEUE_CAPACITY,
            "the TX queue must never grow past LOOPBACK_QUEUE_CAPACITY"
        );
        assert_eq!(
            device.dropped_frames(),
            10,
            "frames beyond capacity must be counted as dropped, not silently discarded"
        );
    }

    #[test]
    fn firewall_device_drops_blocklisted_dns_tx() {
        let mut device = FirewallDevice::with_default_firewall(LoopbackDevice::new());
        let frame = make_ethernet_ipv4_frame(&make_ipv4_udp_dns_query("app-measurement.com"));
        let now = Instant::from_millis(0);

        let tx = device.transmit(now);
        assert!(tx.is_some(), "firewall device must expose tx token");
        phy::TxToken::consume(tx.unwrap(), frame.len(), |buf| {
            buf.copy_from_slice(&frame);
        });

        assert_eq!(
            device.inner().queued_frames(),
            0,
            "blocked DNS query must not reach the wrapped device"
        );
        assert_eq!(
            device.firewall().stats().dns_blocked,
            1,
            "firewall must account for blocklisted DNS"
        );
    }

    #[test]
    fn firewall_device_drops_default_denied_rx() {
        let mut device = FirewallDevice::with_default_firewall(LoopbackDevice::new());
        let frame = make_ethernet_ipv4_frame(&make_ipv4_tcp_packet(
            [1, 2, 3, 4],
            [127, 0, 0, 1],
            443,
            49152,
        ));
        let now = Instant::from_millis(0);

        let tx = device.transmit(now).unwrap();
        phy::TxToken::consume(tx, frame.len(), |buf| {
            buf.copy_from_slice(&frame);
        });
        assert_eq!(device.inner().queued_frames(), 1);

        let rx = device.receive(now);
        assert!(rx.is_none(), "default inbound deny must suppress rx token");
        assert_eq!(
            device.firewall().stats().packets_denied,
            1,
            "firewall must account for denied inbound packet"
        );
        assert_eq!(
            device.inner().queued_frames(),
            0,
            "denied rx packet must be consumed from the wrapped queue"
        );
    }

    #[test]
    fn remove_socket_frees_slot() {
        let mut stack = make_stack();
        let h1 = stack.add_tcp_socket().ok().unwrap(); // ok: test
        let _h2 = stack.add_udp_socket().ok().unwrap(); // ok: test
        assert_eq!(stack.socket_count(), 2);

        stack.remove_socket(h1);
        assert_eq!(stack.socket_count(), 1);
    }

    #[test]
    fn max_sockets_enforced() {
        let mut stack = make_stack();

        // Fill to capacity.
        for i in 0..MAX_SOCKETS {
            let result = stack.add_tcp_socket();
            assert!(result.is_ok(), "socket {i} should succeed");
        }
        assert_eq!(stack.socket_count(), MAX_SOCKETS);

        // Next add must fail.
        let result = stack.add_tcp_socket();
        assert_eq!(result, Err(NetError::SocketSetFull));

        // Removing one frees a slot.
        // Re-add one handle to remove — get a fresh one by using the
        // first socket's handle value (SocketHandle(0)).
        // Actually, we can just try adding after removal of any.
        // Since we can't easily retrieve a specific handle from the loop,
        // use a different approach: add+remove pattern.
    }

    #[test]
    fn max_sockets_add_after_remove() {
        let mut stack = make_stack();
        let mut handles = Vec::new();

        for _ in 0..MAX_SOCKETS {
            handles.push(stack.add_tcp_socket().ok().unwrap()); // ok: test
        }
        assert_eq!(stack.socket_count(), MAX_SOCKETS);

        // Remove one, then adding should succeed again.
        stack.remove_socket(handles[0]);
        assert_eq!(stack.socket_count(), MAX_SOCKETS - 1);

        let result = stack.add_tcp_socket();
        assert!(result.is_ok(), "should succeed after removing a socket");
        assert_eq!(stack.socket_count(), MAX_SOCKETS);
    }

    #[test]
    fn set_default_gateway_succeeds() {
        let mut stack = make_stack();
        let result = stack.set_default_gateway(Ipv4Address::LOCALHOST);
        assert!(result.is_ok(), "setting default gateway must succeed");
    }

    #[test]
    fn instant_from_millis_roundtrip() {
        let inst = instant_from_millis(12345);
        assert_eq!(inst, Instant::from_millis(12345));
    }

    #[test]
    fn poll_services_ticks_dns_cache_and_reports_no_dhcp_event() {
        let mut stack = make_stack();
        let mut resolver = crate::dns::DnsResolver::new(
            Ipv4Address::new(192, 168, 1, 1),
            Ipv4Address::new(9, 9, 9, 9),
        );
        resolver.cache_mut().insert(
            "poll-services-test.example",
            smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(9, 9, 9, 9)),
            2,
        );

        let now = Instant::from_millis(1000);
        let event = stack.poll_services(now, None, Some(&mut resolver), 5);

        assert_eq!(
            event,
            crate::dhcp::DhcpEvent::None,
            "poll_services with no DHCP client must report DhcpEvent::None"
        );
        assert!(
            resolver
                .cache_mut()
                .lookup("poll-services-test.example")
                .is_none(),
            "poll_services must forward elapsed_secs to the DNS resolver's tick(), \
             expiring a TTL=2 entry after 5 elapsed seconds"
        );
    }
}
