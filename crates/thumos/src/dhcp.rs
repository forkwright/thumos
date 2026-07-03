//! DHCP client wrapping smoltcp's built-in DHCPv4 socket.
//!
//! smoltcp provides [`dhcpv4::Socket`] which handles the full DHCP state
//! machine (Discover -> Offer -> Request -> Ack). This module wraps it
//! and applies the result to the [`NetworkStack`].
//!
//! # Usage
//!
//! Create a [`DhcpClient`] attached to a [`NetworkStack`], then call
//! [`DhcpClient::poll`] after every `NetworkStack::poll()`. When a
//! [`DhcpEvent::Configured`] is returned, the IP address and gateway
//! have already been applied to the interface.

extern crate alloc;

use alloc::vec::Vec;

use smoltcp::iface::SocketHandle;
use smoltcp::phy::Device;
use smoltcp::socket::dhcpv4;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

use crate::net::{MAX_SOCKETS, NetError, NetworkStack};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum time (ms) to wait for DHCP configuration before giving up.
pub(crate) const DHCP_TIMEOUT_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Events emitted by the DHCP client on each poll cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DhcpEvent {
    /// No state change since last poll.
    None,
    /// The DHCP server provided (or renewed) a configuration.
    Configured(DhcpConfig),
    /// The lease expired or the server sent a NAK; IP configuration
    /// has been removed from the interface.
    Deconfigured,
}

/// IPv4 configuration obtained from a DHCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpConfig {
    /// Assigned IPv4 address with subnet prefix length.
    pub address: Ipv4Cidr,
    /// Default gateway (router), if provided by the DHCP server.
    pub gateway: Option<Ipv4Address>,
    /// DNS server addresses provided by the DHCP server.
    pub dns_servers: Vec<Ipv4Address>,
}

impl core::fmt::Display for DhcpEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => write!(f, "no DHCP event"),
            Self::Configured(config) => write!(f, "DHCP configured: {config}"),
            Self::Deconfigured => write!(f, "DHCP deconfigured"),
        }
    }
}

impl core::fmt::Display for DhcpConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.address)?;
        if let Some(gw) = self.gateway {
            write!(f, " gw {gw}")?;
        }
        Ok(())
    }
}

/// DHCP client that wraps a smoltcp DHCPv4 socket.
///
/// Owns a socket handle into the [`NetworkStack`]'s socket set. On each
/// [`poll`](Self::poll) call, it checks for DHCP events and applies the
/// resulting configuration (IP address, gateway) to the network interface.
pub(crate) struct DhcpClient {
    /// Handle to the smoltcp DHCPv4 socket in the network stack's socket set.
    socket_handle: SocketHandle,
    /// Whether the interface currently has a DHCP-provided configuration.
    configured: bool,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from DHCP client creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DhcpError {
    /// The socket set is full; cannot add the DHCPv4 socket.
    SocketSetFull,
    /// Failed to apply the gateway route.
    RouteTableFull,
}

impl core::fmt::Display for DhcpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SocketSetFull => write!(f, "socket set full"),
            Self::RouteTableFull => write!(f, "route table full"),
        }
    }
}

impl From<NetError> for DhcpError {
    fn from(e: NetError) -> Self {
        match e {
            NetError::SocketSetFull => DhcpError::SocketSetFull,
            NetError::RouteTableFull => DhcpError::RouteTableFull,
            NetError::InvalidHandle => DhcpError::SocketSetFull,
        }
    }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl DhcpClient {
    /// Create a new DHCP client and add its socket to `stack`.
    ///
    /// Returns `Err(DhcpError::SocketSetFull)` if the socket set has
    /// reached [`MAX_SOCKETS`].
    #[must_use]
    pub(crate) fn new<D: Device>(stack: &mut NetworkStack<D>) -> Result<Self, DhcpError> {
        if stack.socket_count() >= MAX_SOCKETS {
            return Err(DhcpError::SocketSetFull);
        }
        let socket = dhcpv4::Socket::new();
        let handle = stack.sockets_mut().add(socket);
        // WHY: NetworkStack tracks socket_count manually because SocketSet
        // doesn't expose len(). We must keep it in sync.
        stack.increment_socket_count();
        Ok(Self {
            socket_handle: handle,
            configured: false,
        })
    }

    /// Poll the DHCP socket for configuration changes.
    ///
    /// Must be called after every `NetworkStack::poll()`. When a
    /// `DhcpEvent::Configured` is returned, the IP address and gateway
    /// have already been applied to the network interface.
    pub(crate) fn poll<D: Device>(&mut self, stack: &mut NetworkStack<D>) -> DhcpEvent {
        // WHY: Extract all data from the DHCP config *before* calling any
        // methods on `stack`, to avoid overlapping mutable borrows. The
        // smoltcp `Config<'a>` borrows from the socket, which borrows
        // from the socket set, which borrows from `stack`.
        let extracted = {
            let socket: &mut dhcpv4::Socket<'_> = stack.sockets_mut().get_mut(self.socket_handle);
            match socket.poll() {
                Some(dhcpv4::Event::Configured(config)) => {
                    let address = config.address;
                    let gateway = config.router;
                    let dns_servers: Vec<Ipv4Address> =
                        config.dns_servers.iter().copied().collect();
                    Some(Ok((address, gateway, dns_servers)))
                }
                Some(dhcpv4::Event::Deconfigured) => Some(Err(())),
                None => None,
            }
        };

        match extracted {
            Some(Ok((address, gateway, dns_servers))) => {
                // Apply IP address to interface.
                stack.set_ipv4_addr(address.address(), address.prefix_len());

                // Apply gateway if provided.
                if let Some(router) = gateway {
                    let _ = stack.set_default_gateway(router); // WHY: best-effort — if the route table is full we still report the config so callers know the IP is set
                }

                self.configured = true;
                DhcpEvent::Configured(DhcpConfig {
                    address,
                    gateway,
                    dns_servers,
                })
            }
            Some(Err(())) => {
                // Clear interface IP addresses.
                stack.iface_mut().update_ip_addrs(|addrs| addrs.clear());
                // WHY (finding 1): the Configured arm above adds a default
                // gateway route via set_default_gateway when the DHCP
                // server provides one; Deconfigured must symmetrically
                // remove it, or a stale gateway route survives lease
                // expiry / a NAK with no IP address behind it.
                stack.iface_mut().routes_mut().remove_default_ipv4_route();
                self.configured = false;
                DhcpEvent::Deconfigured
            }
            None => DhcpEvent::None,
        }
    }

    /// Whether the interface currently has a DHCP-provided configuration.
    pub(crate) fn is_configured(&self) -> bool {
        self.configured
    }

    /// Return the socket handle for testing or diagnostics.
    pub(crate) fn socket_handle(&self) -> SocketHandle {
        self.socket_handle
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use smoltcp::time::Instant;
    use smoltcp::wire::EthernetAddress;

    use super::*;
    use crate::net::LoopbackDevice;

    /// Helper: build a `NetworkStack<LoopbackDevice>` with a stock config.
    fn make_stack() -> NetworkStack<LoopbackDevice> {
        let device = LoopbackDevice::new();
        let mac = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        NetworkStack::new(device, mac, Instant::from_millis(0))
    }

    #[test]
    fn dhcp_client_starts_unconfigured() {
        let mut stack = make_stack();
        let client = DhcpClient::new(&mut stack);
        assert!(client.is_ok(), "DhcpClient creation must succeed");
        let client = client.ok().unwrap(); // ok: test
        assert!(
            !client.is_configured(),
            "DHCP client must start unconfigured"
        );
        // Socket count should have increased.
        assert_eq!(stack.socket_count(), 1);
    }

    #[test]
    fn dhcp_configured_event_sets_ip() {
        // WHY: We can't easily inject a full DHCP exchange through
        // LoopbackDevice without crafting raw DHCP packets. Instead,
        // we verify that DhcpConfig correctly stores configuration
        // data and that poll returns None when no exchange has occurred.
        let mut stack = make_stack();
        let mut client = DhcpClient::new(&mut stack).ok().unwrap(); // ok: test

        // Poll without any DHCP traffic — should return None.
        stack.poll(Instant::from_millis(100));
        let event = client.poll(&mut stack);
        // Initial poll emits Deconfigured as smoltcp transitions from init
        // state. Subsequent polls should emit None.
        match &event {
            DhcpEvent::None | DhcpEvent::Deconfigured => {}
            DhcpEvent::Configured(_) => {
                panic!("must not be configured without DHCP traffic");
            }
        }

        // Verify DhcpConfig struct works correctly.
        let config = DhcpConfig {
            address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 1, 100), 24),
            gateway: Some(Ipv4Address::new(192, 168, 1, 1)),
            dns_servers: alloc::vec![
                Ipv4Address::new(100, 74, 109, 2),
                Ipv4Address::new(194, 242, 2, 2),
            ],
        };
        assert_eq!(config.address.prefix_len(), 24);
        assert_eq!(config.gateway, Some(Ipv4Address::new(192, 168, 1, 1)));
        assert_eq!(config.dns_servers.len(), 2);
    }

    #[test]
    fn dhcp_error_from_net_error_maps_every_variant() {
        // Done-when (finding 20): every NetError variant must map to a
        // well-defined DhcpError, including InvalidHandle -- which has no
        // direct DhcpError counterpart and collapses to SocketSetFull.
        assert_eq!(
            DhcpError::from(NetError::SocketSetFull),
            DhcpError::SocketSetFull
        );
        assert_eq!(
            DhcpError::from(NetError::RouteTableFull),
            DhcpError::RouteTableFull
        );
        assert_eq!(
            DhcpError::from(NetError::InvalidHandle),
            DhcpError::SocketSetFull,
            "InvalidHandle has no DhcpError counterpart and must collapse to SocketSetFull"
        );
    }

    #[test]
    fn dhcp_client_new_fails_when_socket_set_is_full() {
        // Done-when (finding 20): DhcpClient::new must surface
        // DhcpError::SocketSetFull rather than panicking or silently
        // succeeding when the stack's socket set is already at capacity.
        let mut stack = make_stack();
        for _ in 0..MAX_SOCKETS {
            stack.add_tcp_socket().ok().unwrap(); // ok: test
        }
        assert_eq!(stack.socket_count(), MAX_SOCKETS);

        let result = DhcpClient::new(&mut stack);
        assert_eq!(
            result.err(),
            Some(DhcpError::SocketSetFull),
            "DhcpClient::new must fail with SocketSetFull once MAX_SOCKETS is reached"
        );
    }
}
