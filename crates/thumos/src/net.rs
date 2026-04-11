//! Network subsystem foundation.
//!
//! Wraps smoltcp to provide the kernel's TCP/IP stack. This module is the
//! layer that WiFi, DHCP, DNS, and socket syscalls all build on.
//!
//! # Architecture
//!
//! [`NetworkStack`] owns a smoltcp [`Interface`] and [`SocketSet`], wired
//! together with a [`phy::Device`] implementor (loopback for testing, WiFi
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
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address, Ipv4Cidr};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent sockets in the stack.
pub const MAX_SOCKETS: usize = 32;

/// TCP receive buffer size in bytes.
pub const TCP_RX_BUF_SIZE: usize = 4096;

/// TCP transmit buffer size in bytes.
pub const TCP_TX_BUF_SIZE: usize = 4096;

/// UDP receive buffer metadata slot count (max queued datagrams).
pub const UDP_RX_META_SLOTS: usize = 8;

/// UDP receive buffer payload size in bytes.
pub const UDP_RX_BUF_SIZE: usize = 4096;

/// UDP transmit buffer metadata slot count (max queued datagrams).
pub const UDP_TX_META_SLOTS: usize = 8;

/// UDP transmit buffer payload size in bytes.
pub const UDP_TX_BUF_SIZE: usize = 4096;

/// Default Ethernet MTU (standard 1514-byte frame: 14-byte header + 1500 payload).
const DEFAULT_MTU: usize = 1514;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by network stack operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// Socket set is full; cannot add another socket.
    SocketSetFull,
    /// The provided socket handle does not refer to a valid socket.
    InvalidHandle,
    /// Route table is full.
    RouteTableFull,
}

// ---------------------------------------------------------------------------
// Loopback device
// ---------------------------------------------------------------------------

/// A loopback network device for testing.
///
/// Every frame transmitted through this device is enqueued and returned on
/// the next [`Device::receive`] call, in FIFO order. The device uses the
/// Ethernet medium so that the full ARP / IP path is exercised.
pub struct LoopbackDevice {
    /// FIFO queue of frames awaiting reception.
    queue: VecDeque<Vec<u8>>,
}

impl LoopbackDevice {
    /// Create a new loopback device with an empty packet queue.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    /// Return the number of frames currently queued for reception.
    pub fn queued_frames(&self) -> usize {
        self.queue.len()
    }
}

/// Receive token for [`LoopbackDevice`].
pub struct LoopbackRxToken {
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
pub struct LoopbackTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for LoopbackTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
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
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(LoopbackTxToken {
            queue: &mut self.queue,
        })
    }
}

// ---------------------------------------------------------------------------
// Network stack
// ---------------------------------------------------------------------------

/// Kernel network stack.
///
/// Wraps a smoltcp [`Interface`] and [`SocketSet`] with convenience methods
/// for socket creation, removal, and polling. The stack is generic over the
/// underlying device — use [`LoopbackDevice`] for tests and the WiFi driver
/// for production.
pub struct NetworkStack<D: Device> {
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
    pub fn new(mut device: D, mac: EthernetAddress, now: Instant) -> Self {
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
    pub fn set_ipv4_addr(&mut self, addr: Ipv4Address, prefix_len: u8) {
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
    pub fn set_default_gateway(&mut self, gateway: Ipv4Address) -> Result<(), NetError> {
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
    pub fn add_tcp_socket(&mut self) -> Result<SocketHandle, NetError> {
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
    pub fn add_udp_socket(&mut self) -> Result<SocketHandle, NetError> {
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
    pub fn remove_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
        self.socket_count = self.socket_count.saturating_sub(1);
    }

    /// Poll the network stack: process incoming packets and drive socket state.
    ///
    /// `now` is the current monotonic timestamp. Returns `true` if any socket
    /// state may have changed (callers should re-check their sockets).
    pub fn poll(&mut self, now: Instant) -> bool {
        let result = self.iface.poll(now, &mut self.device, &mut self.sockets);
        result == smoltcp::iface::PollResult::SocketStateChanged
    }

    /// Borrow the socket set immutably (e.g., to inspect socket state).
    pub fn sockets(&self) -> &SocketSet<'static> {
        &self.sockets
    }

    /// Borrow the socket set mutably (e.g., to read/write socket data).
    pub fn sockets_mut(&mut self) -> &mut SocketSet<'static> {
        &mut self.sockets
    }

    /// Borrow the interface immutably.
    pub fn iface(&self) -> &Interface {
        &self.iface
    }

    /// Borrow the interface mutably.
    pub fn iface_mut(&mut self) -> &mut Interface {
        &mut self.iface
    }

    /// Borrow the underlying device immutably.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Borrow the underlying device mutably.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Return the number of sockets currently in the set.
    pub fn socket_count(&self) -> usize {
        self.socket_count
    }

    /// Increment the manual socket count.
    ///
    /// Used by subsystems (DHCP, DNS) that add sockets directly to the
    /// [`SocketSet`] via [`sockets_mut()`](Self::sockets_mut) instead of
    /// going through [`add_tcp_socket`](Self::add_tcp_socket) or
    /// [`add_udp_socket`](Self::add_udp_socket).
    pub fn increment_socket_count(&mut self) {
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
    pub fn poll_services(
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
        if let Some(resolver) = dns {
            if elapsed_secs > 0 {
                resolver.tick(elapsed_secs);
            }
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
pub fn instant_from_millis(millis: i64) -> Instant {
    Instant::from_millis(millis)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a `NetworkStack<LoopbackDevice>` with a stock IP config.
    fn make_stack() -> NetworkStack<LoopbackDevice> {
        let device = LoopbackDevice::new();
        let mac = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let now = Instant::from_millis(0);
        let mut stack = NetworkStack::new(device, mac, now);
        stack.set_ipv4_addr(Ipv4Address::new(127, 0, 0, 1), 8);
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
        let result = stack.set_default_gateway(Ipv4Address::new(127, 0, 0, 1));
        assert!(result.is_ok(), "setting default gateway must succeed");
    }

    #[test]
    fn instant_from_millis_roundtrip() {
        let inst = instant_from_millis(12345);
        assert_eq!(inst, Instant::from_millis(12345));
    }
}
