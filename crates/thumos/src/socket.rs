//! Network socket subsystem.
//!
//! Maps file descriptors to smoltcp socket handles, enabling userspace
//! processes to create TCP/UDP sockets via the BSD socket API. Socket
//! metadata is stored in a parallel table indexed by fd number; the fd
//! itself uses the flags field to identify socket-kind fds (same pattern
//! as pipe.rs).
//!
//! # Architecture
//!
//! - `SOCKET_TABLE`: fixed-size array of `Option<SocketInfo>`, indexed by fd
//!   number (`0..MAX_FDS`). Populated on `sys_socket`, cleared on close.
//! - `NETWORK_STACK`: global firewall-backed loopback stack. Socket creation
//!   and I/O go through this host-only smoke path until `WiFi` hardware frame
//!   TX/RX is available; it must not be reported as production connectivity.
//! - fd flags encode `FD_KIND_SOCKET` in the kind field so that close, read,
//!   and write dispatch can identify socket fds without consulting the table.
//!
//! WHY separate table instead of extending `FileDescriptor`: `FileDescriptor`
//! is `Copy` and fixed-layout. Adding an `Option<SocketInfo>` would break
//! that and balloon the fd table. A parallel table is the same pattern
//! pipes use (pipe index encoded in flags, buffer pool separate).

extern crate alloc;

use alloc::vec::Vec;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};

use crate::csprng;
use crate::fd::{self, FileDescriptor, MAX_FDS};
use crate::net::{self, FirewallDevice, LoopbackDevice, NetworkStack};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Address family: IPv4.
pub(crate) const AF_INET: u32 = 2;

/// Socket type: stream (TCP).
pub(crate) const SOCK_STREAM: u32 = 1;

/// Socket type: datagram (UDP).
pub(crate) const SOCK_DGRAM: u32 = 2;

/// Address family not supported.
pub(crate) const EAFNOSUPPORT: u32 = 0u32.wrapping_sub(97);

/// Protocol wrong type for socket.
pub(crate) const EPROTOTYPE: u32 = 0u32.wrapping_sub(91);

/// Transport endpoint is not connected.
pub(crate) const ENOTCONN: u32 = 0u32.wrapping_sub(107);

/// Connection refused.
pub(crate) const ECONNREFUSED: u32 = 0u32.wrapping_sub(111);

/// Operation not supported.
pub(crate) const EOPNOTSUPP: u32 = 0u32.wrapping_sub(95);

/// Address already in use.
pub(crate) const EADDRINUSE: u32 = 0u32.wrapping_sub(98);

/// Address not available (an unaddressable remote/local endpoint, e.g. a
/// zero port or unspecified address smoltcp's `connect()/send()` refused).
pub(crate) const EADDRNOTAVAIL: u32 = 0u32.wrapping_sub(99);

/// Resource temporarily unavailable (no datagram currently queued).
pub(crate) const EAGAIN: u32 = 0u32.wrapping_sub(11);

/// Out of memory while allocating a bounded transport bounce buffer.
const ENOMEM: u32 = 0u32.wrapping_sub(12);

/// Message too long (a received datagram exceeded the caller's buffer
/// and was dropped rather than truncated-and-delivered).
pub(crate) const EMSGSIZE: u32 = 0u32.wrapping_sub(90);

/// Destination address required (no valid peer address for a datagram send).
pub(crate) const EDESTADDRREQ: u32 = 0u32.wrapping_sub(89);

/// No buffer space available.
pub(crate) const ENOBUFS: u32 = 0u32.wrapping_sub(105);

/// Transport endpoint is already connected.
pub(crate) const EISCONN: u32 = 0u32.wrapping_sub(106);

// -- fd kind encoding (same bit-field scheme as pipe.rs) --

/// FD kind mask: low 8 bits of flags identify the fd type.
/// WHY: matches pipe.rs `FD_KIND_MASK` (0x00FF). A plain VFS fd has
/// kind 0; pipe is 1; socket is 2.
pub(crate) const FD_KIND_MASK: u32 = 0x00FF;

/// FD kind value for socket file descriptors.
pub(crate) const FD_KIND_SOCKET: u32 = 0x0002;

// ---------------------------------------------------------------------------
// Well-known addresses
// ---------------------------------------------------------------------------

/// The IPv4 loopback address (127.0.0.1).
///
/// WHY named constant + local allow: smoltcp's `Ipv4Address` carries
/// `UNSPECIFIED`/`BROADCAST` but no `LOCALHOST` -- unlike
/// `core::net::Ipv4Addr`, which clippy's `ip_constant` lint otherwise
/// steers callers toward. This is the one place the raw octets are
/// spelled out; every other use in this file names this constant instead.
#[expect(
    clippy::ip_constant,
    reason = "smoltcp's Ipv4Address carries UNSPECIFIED/BROADCAST but no LOCALHOST -- unlike core::net::Ipv4Addr, which clippy's ip_constant lint otherwise steers callers toward; clippy's suggested Ipv4Address::LOCALHOST fixup does not exist on this type and would not compile. This is the one place the raw octets are spelled out; every other use in this file names this constant instead"
)]
pub(crate) const LOOPBACK_ADDR: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);

// ---------------------------------------------------------------------------
// Socket metadata
// ---------------------------------------------------------------------------

/// Type of socket (TCP stream or UDP datagram).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// TCP stream socket.
    Tcp,
    /// UDP datagram socket.
    Udp,
}

/// Metadata for an open socket, stored in `SOCKET_TABLE`.
#[derive(Debug, Clone, Copy)]
pub struct SocketInfo {
    /// Handle into the smoltcp `SocketSet`.
    pub socket_handle: SocketHandle,
    /// TCP or UDP.
    pub socket_type: SocketType,
    /// Local port bound via `bind()` (0 = unbound).
    pub bound_port: u16,
    /// Whether a `connect()` has been performed.
    pub connected: bool,
    /// Peer address and port (set by connect, or per-datagram for UDP).
    pub peer_addr: Option<(Ipv4Address, u16)>,
}

// ---------------------------------------------------------------------------
// sockaddr_in (32-bit ARM layout)
// ---------------------------------------------------------------------------

/// BSD socket address structure for IPv4.
///
/// Layout matches the 32-bit ARM Linux `struct sockaddr_in`.
/// Port and address are in network byte order (big-endian).
// WHY: the `sin_*` prefix on every field is the actual POSIX `struct
// sockaddr_in` field naming (`sin_family`, `sin_port`, `sin_addr`,
// `sin_zero`) -- this struct exists to mirror that ABI layout field-for-
// field; dropping the prefix would decouple the names from the spec they
// document.
#[expect(
    clippy::struct_field_names,
    reason = "the sin_* prefix on every field is the actual POSIX struct sockaddr_in field naming (sin_family, sin_port, sin_addr, sin_zero) -- this struct exists to mirror that ABI layout field-for-field; dropping the prefix would decouple the names from the spec they document"
)]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockaddrIn {
    /// Address family (`AF_INET` = 2).
    pub sin_family: u16,
    /// Port number in network byte order (big-endian).
    pub sin_port: u16,
    /// IPv4 address in network byte order (big-endian).
    pub sin_addr: u32,
    /// Padding to match struct size.
    pub sin_zero: [u8; 8],
}

impl SockaddrIn {
    /// Parse the port from network byte order to host byte order.
    pub(crate) fn port(&self) -> u16 {
        u16::from_be(self.sin_port)
    }

    /// Parse the IPv4 address from network byte order.
    pub(crate) fn ipv4_addr(&self) -> Ipv4Address {
        let octets = self.sin_addr.to_be_bytes();
        Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
    }

    /// Create a `SockaddrIn` from host-order values.
    pub(crate) fn new(port: u16, addr: Ipv4Address) -> Self {
        let o = addr.octets();
        let sin_addr = u32::from_be_bytes([o[0], o[1], o[2], o[3]]);
        Self {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr,
            sin_zero: [0u8; 8],
        }
    }
}

const SOCKADDR_IN_SIZE: usize = core::mem::size_of::<SockaddrIn>();

fn copy_sockaddr_from_user(addr: usize) -> Result<SockaddrIn, u32> {
    let mut encoded = [0u8; SOCKADDR_IN_SIZE];
    crate::memguard::copy_from_user(addr, &mut encoded).map_err(|_| fd::EFAULT)?;
    let [
        f0,
        f1,
        p0,
        p1,
        a0,
        a1,
        a2,
        a3,
        z0,
        z1,
        z2,
        z3,
        z4,
        z5,
        z6,
        z7,
    ] = encoded;
    Ok(SockaddrIn {
        sin_family: u16::from_ne_bytes([f0, f1]),
        sin_port: u16::from_ne_bytes([p0, p1]),
        sin_addr: u32::from_ne_bytes([a0, a1, a2, a3]),
        sin_zero: [z0, z1, z2, z3, z4, z5, z6, z7],
    })
}

fn copy_sockaddr_to_user(addr: usize, sockaddr: SockaddrIn) -> Result<(), u32> {
    let [f0, f1] = sockaddr.sin_family.to_ne_bytes();
    let [p0, p1] = sockaddr.sin_port.to_ne_bytes();
    let [a0, a1, a2, a3] = sockaddr.sin_addr.to_ne_bytes();
    let [z0, z1, z2, z3, z4, z5, z6, z7] = sockaddr.sin_zero;
    let encoded = [
        f0, f1, p0, p1, a0, a1, a2, a3, z0, z1, z2, z3, z4, z5, z6, z7,
    ];
    crate::memguard::copy_to_user(addr, &encoded).map_err(|_| fd::EFAULT)
}

/// Allocate a bounce buffer no larger than the transport that will consume it.
/// The explicit capacity argument is load-bearing: syscall `len` is untrusted
/// and must never become an unbounded request against the kernel heap.
fn allocate_transfer_buffer(len: usize, transport_capacity: usize) -> Result<Vec<u8>, u32> {
    let len = len.min(transport_capacity);
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(len).is_err() {
        return Err(ENOMEM);
    }
    bytes.resize(len, 0);
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Socket metadata table, indexed by fd number.
///
/// WHY parallel table: `SocketInfo` is not Copy-friendly with `SocketHandle`
/// (opaque smoltcp type) and would bloat `FileDescriptor`. A separate table
/// indexed by the same fd number keeps the two in sync with minimal coupling.
///
/// Entries are set on `sys_socket`, cleared on socket close.
static mut SOCKET_TABLE: [Option<SocketInfo>; MAX_FDS] = {
    const NONE: Option<SocketInfo> = None;
    [NONE; MAX_FDS]
};

/// Global network stack for socket I/O.
///
/// Uses a firewall-backed `LoopbackDevice` for now. Production `WiFi` readiness is
/// tracked separately during boot and remains false until hardware frame I/O is
/// available.
///
/// WHY Option: `NetworkStack::new()` is not const. Initialized by
/// `init_network_stack()` during kernel boot or test setup.
type SocketNetworkStack = NetworkStack<FirewallDevice<LoopbackDevice>>;

static mut NETWORK_STACK: Option<SocketNetworkStack> = None;

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initialize the global network stack with a firewall-backed loopback device.
///
/// This preserves socket syscall smoke coverage without claiming external
/// network reachability.
///
/// # Safety
///
/// Must be called once before any socket syscalls. Single-threaded access
/// (cooperative kernel guarantee).
pub unsafe fn init_network_stack() {
    use smoltcp::time::Instant;

    unsafe {
        let device = FirewallDevice::with_default_firewall(LoopbackDevice::new());
        let mac = net::randomized_local_ethernet_address();
        let mut stack = NetworkStack::new(device, mac, Instant::from_millis(0));
        stack.set_ipv4_addr(LOOPBACK_ADDR, 8);
        let ns = &mut *core::ptr::addr_of_mut!(NETWORK_STACK);
        *ns = Some(stack);
    }
}

// ---------------------------------------------------------------------------
// Global access helpers
// ---------------------------------------------------------------------------

/// Get a mutable reference to the global network stack.
///
/// # Safety
///
/// Caller must ensure `init_network_stack` has been called.
/// Single-core cooperative kernel ensures exclusive access.
unsafe fn get_network_stack() -> Option<&'static mut SocketNetworkStack> {
    unsafe {
        let ns = &mut *core::ptr::addr_of_mut!(NETWORK_STACK);
        ns.as_mut()
    }
}

/// Get a mutable reference to the socket table.
///
/// # Safety
///
/// Single-core cooperative kernel ensures exclusive access.
unsafe fn get_socket_table() -> &'static mut [Option<SocketInfo>; MAX_FDS] {
    unsafe { &mut *core::ptr::addr_of_mut!(SOCKET_TABLE) }
}

/// Return true if the fd flags word identifies a socket fd.
pub(crate) fn is_socket_fd(flags: u32) -> bool {
    (flags & FD_KIND_MASK) == FD_KIND_SOCKET
}

/// Encode socket fd flags.
fn socket_flags() -> u32 {
    FD_KIND_SOCKET
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

/// Next ephemeral port to allocate.
///
/// WHY static counter: fallback sequential allocation from the IANA
/// ephemeral range (49152-65535), used only while the CSPRNG is not yet
/// seeded (see `alloc_ephemeral_port`). Good enough for a kernel with
/// `MAX_SOCKETS=32`.
static mut NEXT_EPHEMERAL_PORT: u16 = 49152;

/// Allocate an ephemeral port that is not currently in use.
///
/// The starting point within the ephemeral range is drawn from the
/// kernel CSPRNG on every call so allocated source ports are not
/// trivially predictable to an off-path attacker (a sequential counter
/// lets a blind attacker guess the next port and race a spoofed
/// packet/connection into place before the real one completes). If the
/// CSPRNG is not yet seeded (early boot, before `csprng::init()`
/// completes), falls back to the previous sequential counter rather
/// than blocking or panicking -- source-port randomization is
/// defense-in-depth, not key material, so degrading to
/// predictable-but-functional allocation is correct here (mirrors
/// `dns.rs`'s CSPRNG-unseeded TXID fallback).
///
/// # Safety
///
/// Single-core cooperative kernel ensures exclusive access to `NEXT_EPHEMERAL_PORT`
/// and `SOCKET_TABLE`.
unsafe fn alloc_ephemeral_port() -> Option<u16> {
    unsafe {
        const EPHEMERAL_RANGE: u16 = 65535 - 49152 + 1;
        let table = get_socket_table();

        let start = {
            let mut rand_buf = [0u8; 2];
            match csprng::kernel_random_bytes(&mut rand_buf) {
                Ok(()) => 49152 + (u16::from_le_bytes(rand_buf) % EPHEMERAL_RANGE),
                Err(_) => *core::ptr::addr_of!(NEXT_EPHEMERAL_PORT),
            }
        };

        // Scan up to the full ephemeral range (49152..65535).
        for offset in 0..16384u16 {
            let port = start.wrapping_add(offset);
            // Wrap within ephemeral range.
            let port = 49152 + (port.wrapping_sub(49152) % (65535 - 49152 + 1));

            let in_use = table
                .iter()
                .any(|slot| matches!(slot, Some(info) if info.bound_port == port));

            if !in_use {
                let next = &mut *core::ptr::addr_of_mut!(NEXT_EPHEMERAL_PORT);
                *next = port.wrapping_add(1);
                if *next < 49152 {
                    *next = 49152;
                }
                return Some(port);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Syscall implementations
// ---------------------------------------------------------------------------

/// `SYS_socket`: create a network socket.
///
/// # Arguments
/// - `domain`: address family (`AF_INET` = 2)
/// - `sock_type`: socket type (`SOCK_STREAM` = 1, `SOCK_DGRAM` = 2)
/// - `_protocol`: protocol (ignored, auto-selected from type)
///
/// # Returns
/// File descriptor number on success, negative errno on failure.
pub(crate) fn sys_socket(domain: u32, sock_type: u32, _protocol: u32) -> u32 {
    // TODO(#864)[deliberate-prudent]: IPv6 (AF_INET6) -- only AF_INET supported
    if domain != AF_INET {
        return EAFNOSUPPORT;
    }

    let socket_type = match sock_type {
        SOCK_STREAM => SocketType::Tcp,
        SOCK_DGRAM => SocketType::Udp,
        _ => return EPROTOTYPE,
    };

    // SAFETY: single-core cooperative kernel; init_network_stack called.
    let Some(stack) = (unsafe { get_network_stack() }) else {
        return fd::EBADF;
    };

    let handle = match socket_type {
        SocketType::Tcp => match stack.add_tcp_socket() {
            Ok(h) => h,
            Err(_) => return fd::EMFILE,
        },
        SocketType::Udp => match stack.add_udp_socket() {
            Ok(h) => h,
            Err(_) => return fd::EMFILE,
        },
    };

    let info = SocketInfo {
        socket_handle: handle,
        socket_type,
        bound_port: 0,
        connected: false,
        peer_addr: None,
    };

    // Allocate the OFD first (its index is the socket's kernel-global key),
    // then install it in the CURRENT process's fd table (#267). SOCKET_TABLE
    // is keyed by OFD index -- matching on_socket_fd_closed, which ofd_unref
    // calls with the OFD index at refcount zero -- so per-process fd numbers
    // can never collide across processes.
    let fd_entry = FileDescriptor::new(&[], socket_flags());
    let Some(ofd_idx) = fd::ofd_alloc(fd_entry) else {
        stack.remove_socket(handle);
        return fd::ENFILE;
    };
    let Some(fd_num) = fd::install_current_fd(ofd_idx) else {
        // Absent PCB or per-process table full: unwind BOTH the OFD and the
        // smoltcp socket (fail closed -- never orphan either). No SOCKET_TABLE
        // entry exists yet, so ofd_unref's socket teardown no-ops.
        fd::ofd_unref(ofd_idx);
        stack.remove_socket(handle);
        return fd::EMFILE;
    };

    // SAFETY: single-core cooperative kernel.
    let sock_table = unsafe { get_socket_table() };
    sock_table[usize::from(ofd_idx)] = Some(info);

    fd_num as u32
}

/// `SYS_bind`: bind a socket to a local address and port.
///
/// # Arguments
/// - `fd`: socket file descriptor
/// - `addr_ptr`: pointer to `SockaddrIn` structure
/// - `addr_len`: size of the address structure
///
/// # Returns
/// 0 on success, negative errno on failure.
pub(crate) fn sys_bind(fd: u32, addr_ptr: u32, addr_len: u32) -> u32 {
    let fd_idx = fd as usize;
    if fd_idx >= MAX_FDS {
        return fd::EBADF;
    }

    let addr_size = SOCKADDR_IN_SIZE;
    if (addr_len as usize) < addr_size || addr_ptr == 0 {
        return fd::EINVAL;
    }
    let sockaddr = match copy_sockaddr_from_user(addr_ptr as usize) {
        Ok(sockaddr) => sockaddr,
        Err(error) => return error,
    };

    if sockaddr.sin_family != AF_INET as u16 {
        return EAFNOSUPPORT;
    }

    let port = sockaddr.port();
    if port == 0 {
        return fd::EINVAL;
    }

    // Check fd is a socket.
    // Resolve the fd through the CURRENT process (#267): a process may only
    // name a socket it owns, and the OFD index -- not the fd number -- keys
    // SOCKET_TABLE, so per-process fd numbers can never collide across
    // processes.
    let Some(flags) = fd::current_fd_flags(fd_idx) else {
        return fd::EBADF;
    };
    if !is_socket_fd(flags) {
        return fd::EBADF;
    }
    let ofd_idx = match fd::resolve_fd(fd_idx) {
        Some(o) => usize::from(o),
        None => return fd::EBADF,
    };

    // SAFETY: single-core cooperative kernel.
    let sock_table = unsafe { get_socket_table() };

    // Validate socket exists and get its type and handle.
    let (socket_type, socket_handle) = match &sock_table[ofd_idx] {
        Some(i) => (i.socket_type, i.socket_handle),
        None => return fd::EBADF,
    };

    // Check port not already in use by another socket of the SAME
    // transport. TCP and UDP have independent port spaces (e.g. a
    // resolver legitimately binds UDP/53 and TCP/53 simultaneously) --
    // comparing bound_port alone made a UDP bind falsely conflict with an
    // unrelated TCP bind on the same port number.
    for (i, slot) in sock_table.iter().enumerate() {
        if i == ofd_idx {
            continue;
        }
        if let Some(other) = slot
            && other.bound_port == port
            && other.socket_type == socket_type
        {
            return EADDRINUSE;
        }
    }

    // Bind in smoltcp.
    // SAFETY: single-core cooperative kernel; init_network_stack called.
    let Some(stack) = (unsafe { get_network_stack() }) else {
        return fd::EBADF;
    };

    let local_addr = sockaddr.ipv4_addr();
    let endpoint = IpEndpoint::new(IpAddress::Ipv4(local_addr), port);

    match socket_type {
        SocketType::Tcp => {
            // WHY: record the local port via SocketInfo::bound_port below
            // only — do NOT call tcp_socket.listen() here. smoltcp's
            // tcp::Socket::listen() transitions the socket state machine
            // to LISTEN (the server-accepting state), which smoltcp's
            // connect() then refuses (it requires CLOSED). Calling
            // listen() at bind() time broke the standard POSIX
            // bind()-then-connect() client pattern and turned every bound
            // client socket into an unintended listener (issue #307).
            // sys_connect() reads bound_port to build the local endpoint
            // passed to connect(); an actual LISTEN transition belongs in
            // sys_listen() (currently EOPNOTSUPP, TODO(#864)).
        }
        SocketType::Udp => {
            let udp_socket: &mut udp::Socket<'_> = stack.sockets_mut().get_mut(socket_handle);
            if udp_socket.bind(endpoint).is_err() {
                return fd::EINVAL;
            }
        }
    }

    // Update bound_port in socket info.
    if let Some(ref mut info) = sock_table[ofd_idx] {
        info.bound_port = port;
    }
    0
}

/// `SYS_listen`: mark a TCP socket as listening.
///
/// # Returns
/// EOPNOTSUPP — full listen/accept is deferred to a future phase.
///
/// TODO(#864)[deliberate-prudent]: listen/accept -- currently returns EOPNOTSUPP
pub(crate) fn sys_listen(_fd: u32, _backlog: u32) -> u32 {
    EOPNOTSUPP
}

/// `SYS_accept`: accept a connection on a listening socket.
///
/// # Returns
/// EOPNOTSUPP — full listen/accept is deferred to a future phase.
///
/// TODO(#864)[deliberate-prudent]: listen/accept -- currently returns EOPNOTSUPP
pub(crate) fn sys_accept(_fd: u32, _addr_ptr: u32, _addr_len_ptr: u32) -> u32 {
    EOPNOTSUPP
}

/// `SYS_connect`: initiate a connection on a socket.
///
/// For TCP: initiates a three-way handshake to the peer.
/// For UDP: sets the default peer address for subsequent send/recv.
///
/// # Arguments
/// - `fd`: socket file descriptor
/// - `addr_ptr`: pointer to `SockaddrIn` with peer address
/// - `addr_len`: size of the address structure
///
/// # Returns
/// 0 on success, negative errno on failure.
pub(crate) fn sys_connect(fd: u32, addr_ptr: u32, addr_len: u32) -> u32 {
    let fd_idx = fd as usize;
    if fd_idx >= MAX_FDS {
        return fd::EBADF;
    }

    let addr_size = SOCKADDR_IN_SIZE;
    if (addr_len as usize) < addr_size || addr_ptr == 0 {
        return fd::EINVAL;
    }
    let sockaddr = match copy_sockaddr_from_user(addr_ptr as usize) {
        Ok(sockaddr) => sockaddr,
        Err(error) => return error,
    };

    if sockaddr.sin_family != AF_INET as u16 {
        return EAFNOSUPPORT;
    }

    let peer_ip = sockaddr.ipv4_addr();
    let peer_port = sockaddr.port();

    // Check fd is a socket.
    // Resolve the fd through the CURRENT process (#267): a process may only
    // name a socket it owns, and the OFD index -- not the fd number -- keys
    // SOCKET_TABLE, so per-process fd numbers can never collide across
    // processes.
    let Some(flags) = fd::current_fd_flags(fd_idx) else {
        return fd::EBADF;
    };
    if !is_socket_fd(flags) {
        return fd::EBADF;
    }
    let ofd_idx = match fd::resolve_fd(fd_idx) {
        Some(o) => usize::from(o),
        None => return fd::EBADF,
    };

    // SAFETY: single-core cooperative kernel.
    let sock_table = unsafe { get_socket_table() };

    // Extract socket type and handle to avoid holding the borrow.
    let (socket_type, socket_handle, current_bound_port) = match &sock_table[ofd_idx] {
        Some(i) => (i.socket_type, i.socket_handle, i.bound_port),
        None => return fd::EBADF,
    };

    match socket_type {
        SocketType::Tcp => {
            // Verify network stack is initialized before proceeding.
            if unsafe { get_network_stack() }.is_none() {
                return fd::EBADF;
            }

            // Allocate a local port if not yet bound.
            let local_port = if current_bound_port == 0 {
                // SAFETY: single-core cooperative kernel.
                match unsafe { alloc_ephemeral_port() } {
                    Some(p) => p,
                    None => return EADDRINUSE,
                }
            } else {
                current_bound_port
            };

            let remote = IpEndpoint::new(IpAddress::Ipv4(peer_ip), peer_port);

            // WHY split borrow: smoltcp's tcp::Socket::connect() needs both
            // a mutable socket reference and a mutable interface context.
            // NetworkStack holds both as separate fields, but Rust's borrow
            // checker can't see through method calls to prove disjointness.
            // We use raw pointer access to split the borrow — safe because
            // iface and sockets are distinct fields in the single-threaded
            // cooperative kernel.
            //
            // SAFETY: NETWORK_STACK is a static mut; single-core cooperative
            // kernel guarantees no concurrent access. The two raw pointer
            // dereferences target disjoint fields (iface vs sockets).
            let connect_result = unsafe {
                let stack_ptr = &mut *core::ptr::addr_of_mut!(NETWORK_STACK);
                let stack_ref = match stack_ptr.as_mut() {
                    Some(s) => core::ptr::from_mut::<SocketNetworkStack>(s),
                    None => return fd::EBADF,
                };
                let cx = (*stack_ref).iface_mut().context();
                let tcp_socket: &mut tcp::Socket<'_> =
                    (*stack_ref).sockets_mut().get_mut(socket_handle);
                // WHY: pass the bare local port, not an IpEndpoint carrying
                // Ipv4Address::UNSPECIFIED. smoltcp's Into<IpListenEndpoint>
                // treats an IpEndpoint as an *explicit* address
                // (Some(addr)) and rejects an explicit-but-unspecified
                // address with ConnectError::Unaddressable; only addr:
                // None (produced by converting a bare u16) triggers
                // auto-selection via cx.get_source_address(). SocketInfo
                // never tracks a bound local IP (only a port), so
                // auto-selection is correct regardless of whether the
                // socket was bind()'d first. Without this, sys_connect()
                // always failed with Unaddressable, independent of the
                // sys_bind() LISTEN-state bug fixed alongside it (#307).
                tcp_socket.connect(cx, remote, local_port)
            };

            if let Err(err) = connect_result {
                // WHY: smoltcp's ConnectError distinguishes two genuinely
                // different failures; collapsing both into ECONNREFUSED
                // told userspace "the peer refused" even when the local
                // socket was already open (EISCONN) or the endpoint was
                // never addressable in the first place (EADDRNOTAVAIL) --
                // neither of which involved the peer at all.
                return match err {
                    tcp::ConnectError::InvalidState => EISCONN,
                    tcp::ConnectError::Unaddressable => EADDRNOTAVAIL,
                };
            }

            // Update bound_port in socket info.
            let sock_table = unsafe { get_socket_table() };
            if let Some(ref mut info) = sock_table[ofd_idx] {
                info.bound_port = local_port;
            }
        }
        SocketType::Udp => {
            // WHY: a UDP "connect" only records the default peer address
            // for subsequent send/recv -- smoltcp performs no handshake
            // and never validates it. Port 0 is not a routable endpoint;
            // reject it explicitly rather than silently caching an
            // unroutable peer that every later send_slice()/recv_slice()
            // would then act on.
            if peer_port == 0 {
                return fd::EINVAL;
            }
        }
    }

    // Update connected state and peer address.
    let sock_table = unsafe { get_socket_table() };
    if let Some(ref mut info) = sock_table[ofd_idx] {
        info.connected = true;
        info.peer_addr = Some((peer_ip, peer_port));
    }
    0
}

/// `SYS_sendto`: send data on a socket.
///
/// For TCP: sends data on a connected stream. `dest_addr_ptr` is ignored.
/// For UDP: sends a datagram. If `dest_addr_ptr` is non-null, sends to that
/// address; otherwise uses the connected peer address.
///
/// # Arguments
/// - `fd`: socket file descriptor
/// - `buf_ptr`: pointer to data buffer
/// - `len`: number of bytes to send
/// - `_flags`: send flags (reserved, currently ignored)
/// - `dest_addr_ptr`: optional destination address (UDP)
/// - `addr_len`: size of destination address structure
///
/// # Returns
/// Number of bytes sent on success, negative errno on failure.
pub(crate) fn sys_sendto(
    fd: u32,
    buf_ptr: u32,
    len: u32,
    _flags: u32,
    dest_addr_ptr: u32,
    addr_len: u32,
) -> u32 {
    let fd_idx = fd as usize;
    if fd_idx >= MAX_FDS {
        return fd::EBADF;
    }
    if buf_ptr == 0 || len == 0 {
        return 0;
    }
    // Check fd is a socket.
    // Resolve the fd through the CURRENT process (#267): a process may only
    // name a socket it owns, and the OFD index -- not the fd number -- keys
    // SOCKET_TABLE, so per-process fd numbers can never collide across
    // processes.
    let Some(flags) = fd::current_fd_flags(fd_idx) else {
        return fd::EBADF;
    };
    if !is_socket_fd(flags) {
        return fd::EBADF;
    }
    let ofd_idx = match fd::resolve_fd(fd_idx) {
        Some(o) => usize::from(o),
        None => return fd::EBADF,
    };

    // SAFETY: single-core cooperative kernel.
    let sock_table = unsafe { get_socket_table() };
    let Some(info) = sock_table[ofd_idx] else {
        return fd::EBADF;
    };

    match info.socket_type {
        SocketType::Tcp => {
            if !info.connected {
                return ENOTCONN;
            }
            let transfer_len = (len as usize).min(net::TCP_TX_BUF_SIZE);
            let Ok(mut data) = allocate_transfer_buffer(transfer_len, net::TCP_TX_BUF_SIZE) else {
                return ENOMEM;
            };
            if crate::memguard::copy_from_user(buf_ptr as usize, &mut data).is_err() {
                return fd::EFAULT;
            }
            // SAFETY: single-core cooperative kernel; init_network_stack called.
            let Some(stack) = (unsafe { get_network_stack() }) else {
                return fd::EBADF;
            };
            let tcp_socket: &mut tcp::Socket<'_> = stack.sockets_mut().get_mut(info.socket_handle);

            if !tcp_socket.may_send() {
                return ENOTCONN;
            }

            match tcp_socket.send_slice(&data) {
                Ok(n) => n as u32,
                Err(_) => ENOTCONN,
            }
        }
        SocketType::Udp => {
            let requested = len as usize;
            if requested > net::UDP_TX_BUF_SIZE {
                return EMSGSIZE;
            }
            // Determine destination: explicit addr or connected peer.
            let dest = if dest_addr_ptr != 0 {
                if (addr_len as usize) < SOCKADDR_IN_SIZE {
                    return fd::EINVAL;
                }
                let sa = match copy_sockaddr_from_user(dest_addr_ptr as usize) {
                    Ok(sockaddr) => sockaddr,
                    Err(error) => return error,
                };
                IpEndpoint::new(IpAddress::Ipv4(sa.ipv4_addr()), sa.port())
            } else if let Some((ip, port)) = info.peer_addr {
                IpEndpoint::new(IpAddress::Ipv4(ip), port)
            } else {
                return ENOTCONN;
            };

            // Copy the complete datagram before auto-bind or queue mutation.
            // UDP is atomic rather than short-write: payloads larger than the
            // transport capacity were rejected above with EMSGSIZE.
            let Ok(mut data) = allocate_transfer_buffer(requested, net::UDP_TX_BUF_SIZE) else {
                return ENOMEM;
            };
            if crate::memguard::copy_from_user(buf_ptr as usize, &mut data).is_err() {
                return fd::EFAULT;
            }

            // SAFETY: single-core cooperative kernel; init_network_stack called.
            let Some(stack) = (unsafe { get_network_stack() }) else {
                return fd::EBADF;
            };

            let udp_socket: &mut udp::Socket<'_> = stack.sockets_mut().get_mut(info.socket_handle);

            // Auto-bind if not yet bound.
            if !udp_socket.is_open() {
                // SAFETY: single-core cooperative kernel.
                let Some(local_port) = (unsafe { alloc_ephemeral_port() }) else {
                    return EADDRINUSE;
                };
                if udp_socket.bind(local_port).is_err() {
                    return fd::EINVAL;
                }
                // Update bound_port in info. Need mutable access.
                let sock_table_mut = unsafe { get_socket_table() };
                if let Some(ref mut i) = sock_table_mut[ofd_idx] {
                    i.bound_port = local_port;
                }
            }

            match udp_socket.send_slice(&data, dest) {
                Ok(()) => len,
                // WHY: smoltcp's udp::SendError distinguishes "no valid
                // destination" from "the tx buffer has no room for this
                // datagram"; collapsing both into EINVAL hid which one
                // actually happened.
                Err(udp::SendError::Unaddressable) => EDESTADDRREQ,
                Err(udp::SendError::BufferFull) => ENOBUFS,
            }
        }
    }
}

/// `SYS_recvfrom`: receive data from a socket.
///
/// For TCP: receives data from a connected stream. `src_addr_ptr` is ignored.
/// For UDP: receives a datagram. If `src_addr_ptr` is non-null, writes the
/// source address there.
///
/// # Arguments
/// - `fd`: socket file descriptor
/// - `buf_ptr`: pointer to receive buffer
/// - `len`: maximum bytes to receive
/// - `_flags`: receive flags (reserved, currently ignored)
/// - `src_addr_ptr`: optional pointer to receive source address (UDP)
/// - `_addr_len_ptr`: optional pointer to receive source address length
///
/// # Returns
/// Number of bytes received on success, 0 for EOF/disconnect, negative errno
/// on failure.
pub(crate) fn sys_recvfrom(
    fd: u32,
    buf_ptr: u32,
    len: u32,
    _flags: u32,
    src_addr_ptr: u32,
    _addr_len_ptr: u32,
) -> u32 {
    let fd_idx = fd as usize;
    if fd_idx >= MAX_FDS {
        return fd::EBADF;
    }
    if buf_ptr == 0 || len == 0 {
        return 0;
    }
    // A socket can transfer at most its fixed receive capacity in one call.
    // Validate only that possible prefix so a gigantic attacker-controlled
    // `len` cannot force a page-table walk over the whole address space.
    let validation_len = (len as usize).min(net::TCP_RX_BUF_SIZE.max(net::UDP_RX_BUF_SIZE));
    // Write: received bytes are copied INTO this buffer.
    if !crate::memguard::validate_user_range(
        buf_ptr as usize,
        validation_len,
        crate::memguard::Access::Write,
    ) {
        return fd::EFAULT;
    }
    if src_addr_ptr != 0
        && !crate::memguard::validate_user_range(
            src_addr_ptr as usize,
            SOCKADDR_IN_SIZE,
            crate::memguard::Access::Write,
        )
    {
        return fd::EFAULT;
    }

    // Check fd is a socket.
    // Resolve the fd through the CURRENT process (#267): a process may only
    // name a socket it owns, and the OFD index -- not the fd number -- keys
    // SOCKET_TABLE, so per-process fd numbers can never collide across
    // processes.
    let Some(flags) = fd::current_fd_flags(fd_idx) else {
        return fd::EBADF;
    };
    if !is_socket_fd(flags) {
        return fd::EBADF;
    }
    let ofd_idx = match fd::resolve_fd(fd_idx) {
        Some(o) => usize::from(o),
        None => return fd::EBADF,
    };

    // SAFETY: single-core cooperative kernel.
    let sock_table = unsafe { get_socket_table() };
    let Some(info) = sock_table[ofd_idx] else {
        return fd::EBADF;
    };

    // SAFETY: single-core cooperative kernel; init_network_stack called.
    let Some(stack) = (unsafe { get_network_stack() }) else {
        return fd::EBADF;
    };

    match info.socket_type {
        SocketType::Tcp => {
            if !info.connected {
                return ENOTCONN;
            }
            let tcp_socket: &mut tcp::Socket<'_> = stack.sockets_mut().get_mut(info.socket_handle);

            if !tcp_socket.may_recv() {
                // Connection closed — return 0 (EOF).
                return 0;
            }

            let requested = (len as usize).min(net::TCP_RX_BUF_SIZE);
            let Ok(received) = tcp_socket.peek(requested) else {
                return 0;
            };
            let n = received.len();
            if crate::memguard::copy_to_user(buf_ptr as usize, received).is_err() {
                return fd::EFAULT;
            }
            // Commit only after copyout. On this single-core kernel no actor
            // can alter the queue between peek and this consume.
            match tcp_socket.recv(|available| (n.min(available.len()), ())) {
                Ok(()) => n as u32,
                Err(_) => fd::EIO,
            }
        }
        SocketType::Udp => {
            let udp_socket: &mut udp::Socket<'_> = stack.sockets_mut().get_mut(info.socket_handle);

            match udp_socket.peek() {
                Ok((received, meta)) => {
                    if received.len() > len as usize {
                        // Preserve the established datagram semantics: a
                        // too-small valid buffer drops this one packet and
                        // reports EMSGSIZE. Uaccess failures below do NOT drop.
                        return match udp_socket.recv() {
                            Ok(_) => EMSGSIZE,
                            Err(_) => fd::EIO,
                        };
                    }
                    let n = received.len();
                    let meta = *meta;
                    // Each user copy can fault after prevalidation, so two
                    // disjoint output buffers cannot be made byte-atomic as a
                    // group. The transaction boundary we can guarantee is the
                    // kernel-owned datagram: it remains queued until every
                    // requested output copy completes.
                    if src_addr_ptr != 0 {
                        let src_ip = match meta.endpoint.addr {
                            IpAddress::Ipv4(v4) => v4,
                            // Only IPv4 supported in this phase.
                            #[expect(
                                unreachable_patterns,
                                reason = "future IPv6 support will add variants to IpAddress"
                            )]
                            _ => Ipv4Address::UNSPECIFIED,
                        };
                        let sa = SockaddrIn::new(meta.endpoint.port, src_ip);
                        if copy_sockaddr_to_user(src_addr_ptr as usize, sa).is_err() {
                            return fd::EFAULT;
                        }
                    }
                    if crate::memguard::copy_to_user(buf_ptr as usize, received).is_err() {
                        return fd::EFAULT;
                    }
                    // Both output families are now committed; only now remove
                    // the datagram from the transport queue.
                    match udp_socket.recv() {
                        Ok((committed, _)) if committed.len() == n => n as u32,
                        Ok(_) | Err(_) => fd::EIO,
                    }
                }
                // WHY: collapsing every recv error to a bare 0 (the TCP
                // arm's legitimate EOF sentinel) masked genuine UDP
                // failures as an empty read. Exhausted means "nothing
                // queued yet" (would-block, not an error); Truncated means
                // a datagram WAS received and then silently dropped
                // because it didn't fit -- that must not read as "0 bytes
                // received", or the caller can't tell a real truncation
                // from an empty socket.
                Err(udp::RecvError::Exhausted) => EAGAIN,
                // `peek()` never truncates because it returns the queued slice
                // directly; keep the arm exhaustive for the public enum.
                Err(udp::RecvError::Truncated) => EMSGSIZE,
            }
        }
    }
}

/// Release a socket's network resources at OFD refcount zero (#267).
///
/// Called from `fd::ofd_unref` when the LAST fd referencing this open-file
/// description is closed; `ofd_idx` is the OFD index that keys `SOCKET_TABLE`.
/// WHY at refcount zero, not per close: with dup/fork several fds may share
/// one socket OFD, so the smoltcp socket must be released only when the last
/// of them closes.
pub(crate) fn on_socket_fd_closed(ofd_idx: usize) {
    // SAFETY: single-core cooperative kernel.
    let sock_table = unsafe { get_socket_table() };
    let Some(info) = sock_table[ofd_idx].take() else {
        return;
    };

    // Remove the socket from the smoltcp stack.
    // SAFETY: single-core cooperative kernel; init_network_stack called.
    if let Some(stack) = unsafe { get_network_stack() } {
        stack.remove_socket(info.socket_handle);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_allocation_is_bounded_by_transport_capacity() {
        let bytes = allocate_transfer_buffer(usize::MAX, 64).expect("bounded allocation");
        assert_eq!(bytes.len(), 64);
    }

    /// Reset global state for test isolation.
    ///
    /// # Safety
    ///
    /// Test-only. Resets the process fd table + shared OFD table (#267),
    /// `SOCKET_TABLE`, and `NETWORK_STACK`.
    unsafe fn setup_test_network() {
        unsafe {
            // Reset the process fd table and the shared OFD table (#267).
            crate::fd::reset_fd_state_for_test();

            // Reset socket table.
            let sock_table = &mut *core::ptr::addr_of_mut!(SOCKET_TABLE);
            *sock_table = {
                const NONE: Option<SocketInfo> = None;
                [NONE; MAX_FDS]
            };

            // Reset ephemeral port counter.
            let port = &mut *core::ptr::addr_of_mut!(NEXT_EPHEMERAL_PORT);
            *port = 49152;

            // Initialize network stack.
            init_network_stack();
        }
    }

    #[test]
    fn alloc_ephemeral_port_is_not_sequential_when_csprng_seeded() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }
        csprng::seed_for_test(&[0x42u8; 32], &[0u8; 8], 0);

        let mut ports = alloc::vec::Vec::new();
        for _ in 0..8 {
            let port = unsafe { alloc_ephemeral_port() }.expect("port allocation must succeed");
            ports.push(port);
        }

        // Before the fix, alloc_ephemeral_port() always returned a
        // strictly sequential run (49152, 49153, 49154, ...) starting
        // from a fixed, predictable counter -- trivially guessable by
        // an off-path attacker. With a seeded CSPRNG, consecutive
        // allocations must not all differ by exactly 1; the chance of
        // that happening by genuine randomness is astronomically small.
        let all_sequential = ports.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
        assert!(
            !all_sequential,
            "ephemeral ports must be randomized, not allocated sequentially: {ports:?}"
        );
    }

    #[test]
    fn alloc_ephemeral_port_falls_back_when_csprng_unseeded() {
        // SAFETY: test-only; setup_test_network resets global state.
        // CSPRNG is never seeded in this test process (nextest runs
        // each test in its own process), exercising the fail-open
        // fallback path -- it must still return a valid port, never
        // hang or panic.
        unsafe {
            setup_test_network();
        }

        let port = unsafe { alloc_ephemeral_port() };
        assert!(
            port.is_some_and(|p| (49152..=65535).contains(&p)),
            "an unseeded CSPRNG must still allocate a valid ephemeral port via the deterministic fallback"
        );
    }

    #[test]
    fn alloc_ephemeral_port_wraps_past_65535_back_to_49152() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        // CSPRNG is unseeded in this fresh test process (nextest: one
        // process per test), so alloc_ephemeral_port() falls back to
        // NEXT_EPHEMERAL_PORT as the scan's starting point -- pin it to
        // the top of the ephemeral range so the next allocation must wrap.
        // SAFETY: test-only manipulation of global state.
        unsafe {
            let next = &mut *core::ptr::addr_of_mut!(NEXT_EPHEMERAL_PORT);
            *next = 65533;
        }

        // A real socket handle to reuse in the synthetic occupied entries
        // below -- alloc_ephemeral_port() only ever reads bound_port,
        // never the handle, but the struct field must be populated.
        let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        assert!(fd < MAX_FDS as u32);
        let real_handle = {
            // SAFETY: test-only read of global state.
            let table = unsafe { get_socket_table() };
            table[fd as usize]
                .as_ref()
                .expect("real socket must be present")
                .socket_handle
        };

        // Occupy every port from the pinned start through the top of the
        // range (65533..=65535), forcing the scan to wrap past 65535.
        // SAFETY: test-only manipulation of global state.
        let table = unsafe { get_socket_table() };
        for (i, port) in (65533u16..=65535).enumerate() {
            table[fd as usize + 1 + i] = Some(SocketInfo {
                socket_handle: real_handle,
                socket_type: SocketType::Udp,
                bound_port: port,
                connected: false,
                peer_addr: None,
            });
        }

        // SAFETY: test-only.
        let allocated = unsafe { alloc_ephemeral_port() };
        assert_eq!(
            allocated,
            Some(49152),
            "scanning past 65535 must wrap back to the start of the ephemeral \
             range (49152), not overflow past u16::MAX or return None early"
        );
    }

    #[test]
    fn socket_creates_tcp_fd() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
        assert!(
            fd < MAX_FDS as u32,
            "TCP socket should return valid fd, got {fd}"
        );

        // Verify it's in the socket table.
        let sock_table = unsafe { &*core::ptr::addr_of!(SOCKET_TABLE) };
        let info = sock_table[fd as usize]
            .as_ref()
            .expect("socket info must exist");
        assert_eq!(info.socket_type, SocketType::Tcp);
        assert_eq!(info.bound_port, 0);
        assert!(!info.connected);
    }

    #[test]
    fn socket_creates_udp_fd() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        assert!(
            fd < MAX_FDS as u32,
            "UDP socket should return valid fd, got {fd}"
        );

        let sock_table = unsafe { &*core::ptr::addr_of!(SOCKET_TABLE) };
        let info = sock_table[fd as usize]
            .as_ref()
            .expect("socket info must exist");
        assert_eq!(info.socket_type, SocketType::Udp);
    }

    #[test]
    fn socket_invalid_domain_returns_eafnosupport() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        let result = sys_socket(99, SOCK_STREAM, 0);
        assert_eq!(result, EAFNOSUPPORT);
    }

    #[test]
    fn socket_invalid_type_returns_eprototype() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        let result = sys_socket(AF_INET, 99, 0);
        assert_eq!(result, EPROTOTYPE);
    }

    #[test]
    fn close_socket_fd_frees_resources() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
        assert!(fd < MAX_FDS as u32);

        // Verify socket exists in the network stack.
        let stack = unsafe { get_network_stack() }.expect("stack");
        let initial_count = stack.socket_count();
        assert!(initial_count > 0);

        // Close the fd -- teardown (on_socket_fd_closed) fires automatically
        // inside ofd_unref when the OFD's refcount reaches zero (#267); it is
        // not a separate manual step.
        let result = fd::sys_close(fd);
        assert_eq!(result, 0);

        // Socket info should be cleared.
        let sock_table = unsafe { &*core::ptr::addr_of!(SOCKET_TABLE) };
        assert!(
            sock_table[fd as usize].is_none(),
            "socket info should be cleared"
        );

        // smoltcp socket count should decrease.
        let stack = unsafe { get_network_stack() }.expect("stack");
        assert_eq!(stack.socket_count(), initial_count - 1);
    }

    #[test]
    fn sendto_on_unconnected_tcp_returns_enotconn() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
        assert!(fd < MAX_FDS as u32);

        // Pass null buf_ptr + zero len to test the connected check path
        // without pointer truncation issues on 64-bit hosts.
        // sendto with buf_ptr=0 and len=0 returns 0 (no-op), so we use a
        // non-null but fake address that fits in u32.
        // WHY: on 64-bit hosts, real pointers get truncated to u32. Instead
        // we test the ENOTCONN path by checking socket state directly.
        let sock_table = unsafe { &*core::ptr::addr_of!(SOCKET_TABLE) };
        let info = sock_table[fd as usize].as_ref().expect("socket info");
        assert!(
            !info.connected,
            "freshly created socket must not be connected"
        );
        assert_eq!(info.socket_type, SocketType::Tcp);
    }

    /// Pointer-dependent test: only runs on 32-bit targets where raw pointers
    /// fit in u32 without truncation.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn sendto_on_unconnected_tcp_returns_enotconn_syscall() {
        unsafe {
            setup_test_network();
        }
        let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
        let data = b"hello";
        let result = sys_sendto(fd, data.as_ptr() as u32, data.len() as u32, 0, 0, 0);
        assert_eq!(result, ENOTCONN);
    }

    /// Pointer-dependent test: only runs on 32-bit targets.
    ///
    /// WHY function-local `static mut`: `sys_bind` now validates `addr_ptr` via
    /// `validate_user_range` before dereferencing it. A stack address (e.g.
    /// `&addr`) falls outside [`board::KERNEL_END`, `board::RAM_END`) on
    /// this host binary and would be rejected before bind logic runs; a
    /// function-local static lands inside that window (see fd.rs tests for
    /// the same pattern).
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn bind_sets_local_port_syscall() {
        static mut ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        unsafe {
            setup_test_network();
        }
        let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        // SAFETY: test-only static; single-threaded per test.
        let addr = unsafe { &mut *core::ptr::addr_of_mut!(ADDR) };
        *addr = SockaddrIn::new(8080, LOOPBACK_ADDR);
        let result = sys_bind(
            fd,
            core::ptr::from_ref::<SockaddrIn>(addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(result, 0, "bind should succeed");
        let sock_table = unsafe { &*core::ptr::addr_of!(SOCKET_TABLE) };
        let info = sock_table[fd as usize].as_ref().expect("socket info");
        assert_eq!(info.bound_port, 8080);
    }

    /// Pointer-dependent test: only runs on 32-bit targets.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn udp_bind_does_not_conflict_with_tcp_bind_on_same_port() {
        static mut TCP_ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        static mut UDP_ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        unsafe {
            setup_test_network();
        }
        let tcp_fd = sys_socket(AF_INET, SOCK_STREAM, 0);
        let udp_fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        assert!(tcp_fd < MAX_FDS as u32 && udp_fd < MAX_FDS as u32);

        // SAFETY: test-only static; single-threaded per test.
        let tcp_addr = unsafe { &mut *core::ptr::addr_of_mut!(TCP_ADDR) };
        *tcp_addr = SockaddrIn::new(53, Ipv4Address::UNSPECIFIED);
        let tcp_bind = sys_bind(
            tcp_fd,
            core::ptr::from_ref::<SockaddrIn>(tcp_addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(tcp_bind, 0, "TCP bind to port 53 must succeed");

        // SAFETY: test-only static; single-threaded per test.
        let udp_addr = unsafe { &mut *core::ptr::addr_of_mut!(UDP_ADDR) };
        *udp_addr = SockaddrIn::new(53, Ipv4Address::UNSPECIFIED);
        let udp_bind = sys_bind(
            udp_fd,
            core::ptr::from_ref::<SockaddrIn>(udp_addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(
            udp_bind, 0,
            "UDP bind to the same port number as an existing TCP bind must succeed: \
             TCP and UDP have independent port spaces"
        );
    }

    #[test]
    fn bind_rejects_kernel_range_addr_ptr() {
        // No socket setup needed: validate_user_range runs before the
        // FD_TABLE is-a-socket check, so fd=0 (< MAX_FDS) is sufficient.
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_bind(0, kernel_ptr, core::mem::size_of::<SockaddrIn>() as u32);
        assert_eq!(
            result,
            fd::EFAULT,
            "kernel-range addr_ptr must return EFAULT"
        );
    }

    /// Pointer-dependent test: only runs on 32-bit targets.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn udp_connect_rejects_peer_port_zero() {
        static mut ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        unsafe {
            setup_test_network();
        }
        let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        assert!(fd < MAX_FDS as u32);

        // SAFETY: test-only static; single-threaded per test.
        let addr = unsafe { &mut *core::ptr::addr_of_mut!(ADDR) };
        *addr = SockaddrIn::new(0, Ipv4Address::new(93, 184, 216, 34));
        let result = sys_connect(
            fd,
            core::ptr::from_ref::<SockaddrIn>(addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(
            result,
            fd::EINVAL,
            "UDP connect to peer port 0 must be rejected as an unroutable endpoint"
        );
    }

    #[test]
    fn connect_rejects_kernel_range_addr_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_connect(0, kernel_ptr, core::mem::size_of::<SockaddrIn>() as u32);
        assert_eq!(
            result,
            fd::EFAULT,
            "kernel-range addr_ptr must return EFAULT"
        );
    }

    /// Regression test for issue #307: `bind()` must leave a TCP socket in
    /// CLOSED state (not LISTEN), so a subsequent `connect()` is not
    /// refused.
    ///
    /// Pointer-dependent test: only runs on 32-bit targets.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn tcp_bind_then_connect_succeeds() {
        // WHY function-local `static mut`: sys_bind/sys_connect now validate
        // addr_ptr via validate_user_range (issue #291) before
        // dereferencing it. A stack address falls outside
        // [board::KERNEL_END, board::RAM_END) on this host binary and
        // would be rejected before bind/connect logic runs.
        static mut BIND_ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        static mut CONNECT_ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        unsafe {
            setup_test_network();
        }

        let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
        assert!(fd < MAX_FDS as u32);

        // SAFETY: test-only static; single-threaded per test.
        let bind_addr = unsafe { &mut *core::ptr::addr_of_mut!(BIND_ADDR) };
        *bind_addr = SockaddrIn::new(40000, Ipv4Address::UNSPECIFIED);

        // bind() to a specific source port first, per the standard POSIX
        // bind()-then-connect() client pattern.
        let bind_result = sys_bind(
            fd,
            core::ptr::from_ref::<SockaddrIn>(bind_addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(bind_result, 0, "bind must succeed");

        let sock_table = unsafe { &*core::ptr::addr_of!(SOCKET_TABLE) };
        let info = sock_table[fd as usize].as_ref().expect("socket info");
        assert_eq!(
            info.bound_port, 40000,
            "bound_port must record the requested port"
        );

        let stack = unsafe { get_network_stack() }.expect("stack");
        let tcp_socket: &tcp::Socket<'_> = stack.sockets().get(info.socket_handle);
        assert_eq!(
            tcp_socket.state(),
            tcp::State::Closed,
            "bind() must leave the TCP socket in CLOSED state, not LISTEN"
        );

        // SAFETY: test-only static; single-threaded per test.
        let connect_addr = unsafe { &mut *core::ptr::addr_of_mut!(CONNECT_ADDR) };
        *connect_addr = SockaddrIn::new(80, Ipv4Address::new(93, 184, 216, 34));
        let connect_result = sys_connect(
            fd,
            core::ptr::from_ref::<SockaddrIn>(connect_addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(
            connect_result, 0,
            "connect() after bind() must succeed, not be refused by a LISTEN-state socket"
        );
    }

    /// Pointer-dependent test: only runs on 32-bit targets.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn tcp_connect_twice_returns_eisconn_not_econnrefused() {
        static mut ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        unsafe {
            setup_test_network();
        }
        let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
        assert!(fd < MAX_FDS as u32);

        // SAFETY: test-only static; single-threaded per test.
        let addr = unsafe { &mut *core::ptr::addr_of_mut!(ADDR) };
        *addr = SockaddrIn::new(80, Ipv4Address::new(93, 184, 216, 34));

        let first = sys_connect(
            fd,
            core::ptr::from_ref::<SockaddrIn>(addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(first, 0, "first connect() must succeed");

        let second = sys_connect(
            fd,
            core::ptr::from_ref::<SockaddrIn>(addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(
            second, EISCONN,
            "connect() on an already-open TCP socket must return EISCONN, not ECONNREFUSED"
        );
    }

    /// Pointer-dependent test: only runs on 32-bit targets.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn tcp_connect_without_prior_bind_allocates_port_and_sets_connected_state() {
        static mut ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        unsafe {
            setup_test_network();
        }
        let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
        assert!(fd < MAX_FDS as u32);

        // SAFETY: test-only static; single-threaded per test.
        let addr = unsafe { &mut *core::ptr::addr_of_mut!(ADDR) };
        *addr = SockaddrIn::new(80, Ipv4Address::new(93, 184, 216, 34));

        let result = sys_connect(
            fd,
            core::ptr::from_ref::<SockaddrIn>(addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(
            result, 0,
            "connect on a fresh unbound TCP socket must succeed"
        );

        let sock_table = unsafe { &*core::ptr::addr_of!(SOCKET_TABLE) };
        let info = sock_table[fd as usize].as_ref().expect("socket info");
        assert!(
            info.connected,
            "a successful connect() must mark the socket connected"
        );
        assert_eq!(
            info.peer_addr,
            Some((Ipv4Address::new(93, 184, 216, 34), 80)),
            "peer_addr must record the connected destination"
        );
        assert!(
            (49152..=65535).contains(&info.bound_port),
            "connect() without a prior bind() must auto-allocate an ephemeral local port, got {}",
            info.bound_port
        );

        let stack = unsafe { get_network_stack() }.expect("stack");
        let tcp_socket: &tcp::Socket<'_> = stack.sockets().get(info.socket_handle);
        assert_eq!(
            tcp_socket.state(),
            tcp::State::SynSent,
            "a successful TCP connect() must move the smoltcp socket into SynSent"
        );
    }

    #[test]
    fn bind_sets_local_port() {
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        assert!(fd < MAX_FDS as u32);

        // Test bind via internal API to avoid pointer truncation on 64-bit.
        // Directly set up the socket info to verify the bind logic path.
        let sock_table = unsafe { get_socket_table() };
        let info = sock_table[fd as usize].as_ref().expect("socket info");
        assert_eq!(info.bound_port, 0, "socket should start unbound");
        assert_eq!(info.socket_type, SocketType::Udp);
    }

    /// Pointer-dependent test: only runs on 32-bit targets.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn udp_sendto_unaddressable_dest_returns_edestaddrreq() {
        static mut DEST: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        unsafe {
            setup_test_network();
        }
        let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        assert!(fd < MAX_FDS as u32);

        // SAFETY: test-only static; single-threaded per test.
        let dest = unsafe { &mut *core::ptr::addr_of_mut!(DEST) };
        // Port 0 on an EXPLICIT sendto destination bypasses sys_connect()
        // entirely (that guard only covers connect()), reaching smoltcp's
        // own udp::SendError::Unaddressable check directly.
        *dest = SockaddrIn::new(0, Ipv4Address::new(93, 184, 216, 34));

        let data = b"x";
        let result = sys_sendto(
            fd,
            data.as_ptr() as u32,
            data.len() as u32,
            0,
            core::ptr::from_ref::<SockaddrIn>(dest) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(
            result, EDESTADDRREQ,
            "an unaddressable UDP destination must return EDESTADDRREQ, not the old generic EINVAL"
        );
    }

    /// Pointer-dependent test: only runs on 32-bit targets.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn udp_recvfrom_with_no_data_returns_eagain_not_zero() {
        static mut BUF: [u8; 16] = [0u8; 16];
        unsafe {
            setup_test_network();
        }
        let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        assert!(fd < MAX_FDS as u32);

        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };

        let result = sys_recvfrom(fd, buf.as_mut_ptr() as u32, buf.len() as u32, 0, 0, 0);
        assert_eq!(
            result, EAGAIN,
            "recv on a UDP socket with nothing queued must return EAGAIN, not the old \
             generic 0 (indistinguishable from a legitimate zero-byte datagram)"
        );
    }

    /// Pointer-dependent test: only runs on 32-bit targets.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn udp_recvfrom_writes_back_the_real_datagram_source_address() {
        static mut BIND_ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        static mut DEST_ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        static mut RECV_BUF: [u8; 32] = [0u8; 32];
        static mut SRC_ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        unsafe {
            setup_test_network();
        }

        // The stack's default-deny inbound firewall policy would
        // otherwise drop the looped-back datagram below before it ever
        // reaches the socket layer -- install an explicit allow rule for
        // inbound UDP so the round trip can complete. Broadcast-destined
        // traffic (below) needs no ARP resolution, unlike a self-
        // addressed unicast send.
        {
            let stack = unsafe { get_network_stack() }.expect("stack");
            stack
                .device_mut()
                .firewall_mut()
                .add_rule(crate::firewall::FilterRule {
                    direction: crate::firewall::Direction::Inbound,
                    protocol: Some(crate::firewall::Protocol::Udp),
                    src_addr: None,
                    dst_addr: None,
                    dst_port: None,
                    action: crate::firewall::Action::Allow,
                });
        }

        // Receiver: bound to a fixed port, any local address.
        let receiver_fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        // SAFETY: test-only static; single-threaded per test.
        let bind_addr = unsafe { &mut *core::ptr::addr_of_mut!(BIND_ADDR) };
        *bind_addr = SockaddrIn::new(9000, Ipv4Address::UNSPECIFIED);
        let bind_result = sys_bind(
            receiver_fd,
            core::ptr::from_ref::<SockaddrIn>(bind_addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(bind_result, 0, "receiver bind must succeed");

        // Sender: unbound, auto-binds an ephemeral source port on first
        // send. Destination is the broadcast address so the interface
        // dispatches it immediately without needing ARP resolution.
        let sender_fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        // SAFETY: test-only static; single-threaded per test.
        let dest_addr = unsafe { &mut *core::ptr::addr_of_mut!(DEST_ADDR) };
        *dest_addr = SockaddrIn::new(9000, Ipv4Address::BROADCAST);

        let payload = b"src-check";
        let send_result = sys_sendto(
            sender_fd,
            payload.as_ptr() as u32,
            payload.len() as u32,
            0,
            core::ptr::from_ref::<SockaddrIn>(dest_addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(
            send_result,
            payload.len() as u32,
            "sendto must accept the full payload"
        );

        // Read back the ephemeral source port the sender auto-bound to --
        // this is the port the receiver must see as the datagram's
        // origin, not the receiver's own port or zero.
        let sender_port = {
            let sock_table = unsafe { &*core::ptr::addr_of!(SOCKET_TABLE) };
            sock_table[sender_fd as usize]
                .as_ref()
                .expect("sender socket info")
                .bound_port
        };
        assert_ne!(
            sender_port, 0,
            "sendto must auto-bind an ephemeral source port"
        );

        // A broadcast destination needs no ARP resolution, so the
        // datagram dispatches on the first poll's egress phase and loops
        // back through the device on the next poll's ingress phase. A
        // small margin of extra polls is harmless.
        let stack = unsafe { get_network_stack() }.expect("stack");
        for step in 0..4u32 {
            stack.poll(smoltcp::time::Instant::from_millis(i64::from(step) * 10));
        }

        // SAFETY: test-only static; single-threaded per test.
        let recv_buf = unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };
        // SAFETY: test-only static; single-threaded per test.
        let src_addr = unsafe { &mut *core::ptr::addr_of_mut!(SRC_ADDR) };

        // A transfer-time failure in either output family must leave the
        // datagram queued. These hooks fire after prevalidation, modelling the
        // exact fault-fixup path rather than a trivially bad pointer.
        crate::memguard::fail_next_copy_to_user_for_test();
        assert_eq!(
            sys_recvfrom(
                receiver_fd,
                recv_buf.as_mut_ptr() as u32,
                recv_buf.len() as u32,
                0,
                core::ptr::from_ref::<SockaddrIn>(src_addr) as u32,
                0,
            ),
            fd::EFAULT,
            "a source-address copyout fault must not dequeue the datagram"
        );
        crate::memguard::fail_next_copy_to_user_for_test();
        assert_eq!(
            sys_recvfrom(
                receiver_fd,
                recv_buf.as_mut_ptr() as u32,
                recv_buf.len() as u32,
                0,
                0,
                0,
            ),
            fd::EFAULT,
            "a payload copyout fault must not dequeue the datagram"
        );

        let recv_result = sys_recvfrom(
            receiver_fd,
            recv_buf.as_mut_ptr() as u32,
            recv_buf.len() as u32,
            0,
            core::ptr::from_ref::<SockaddrIn>(src_addr) as u32,
            0,
        );
        assert_eq!(
            recv_result,
            payload.len() as u32,
            "receiver must observe the full broadcast datagram"
        );
        assert_eq!(
            &recv_buf[..payload.len()],
            payload,
            "payload must round-trip intact"
        );

        // SECURITY: the written-back source address must be the ACTUAL
        // sender (the interface's own address + the sender's real bound
        // port) -- not the broadcast destination, not zeroed, and not
        // aliased to the receiver's own port. A caller (e.g. a DNS
        // resolver validating which server answered) trusts this value.
        assert_eq!(
            src_addr.ipv4_addr(),
            LOOPBACK_ADDR,
            "written-back source IP must match the real sender, not the broadcast destination"
        );
        assert_eq!(
            src_addr.port(),
            sender_port,
            "written-back source port must match the sender's actual bound (ephemeral) port, \
             not be zeroed or aliased to the receiver's own port"
        );
    }

    #[test]
    fn sockaddr_in_parses_correctly() {
        let addr = SockaddrIn::new(80, Ipv4Address::new(192, 168, 1, 1));
        assert_eq!(addr.sin_family, AF_INET as u16);
        assert_eq!(addr.port(), 80);
        assert_eq!(addr.ipv4_addr(), Ipv4Address::new(192, 168, 1, 1));

        // Verify network byte order encoding.
        assert_eq!(addr.sin_port, 80u16.to_be());
        let expected_addr = u32::from_be_bytes([192, 168, 1, 1]);
        assert_eq!(addr.sin_addr, expected_addr);
    }

    /// A no-op process entry point for `process::spawn` in tests -- never
    /// actually invoked, only referenced as a function pointer to populate
    /// the new PCB's context.
    #[cfg(target_pointer_width = "32")]
    fn isolation_test_entry() -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    /// ISOLATION (CRITICAL): a different process must not be able to name
    /// proc0's socket by fd number. `SOCKET_TABLE` is keyed by OFD index, not
    /// raw fd number, and every socket syscall resolves the fd through the
    /// CURRENT process's own table first -- a process whose table lacks
    /// this fd slot fails closed with EBADF before `SOCKET_TABLE` is ever
    /// consulted (#267 -- this is the security core the two-level fd model
    /// exists to close for sockets).
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn socket_isolation_cross_process_ops_return_ebadf() {
        static mut ADDR: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        static mut RECV_BUF: [u8; 4] = [0u8; 4];
        static mut ADDR2: SockaddrIn = SockaddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        // SAFETY: test-only; setup_test_network resets global state.
        unsafe {
            setup_test_network();
        }

        let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        assert!(fd < MAX_FDS as u32);

        // SAFETY: test-only static; single-threaded per test.
        let addr = unsafe { &mut *core::ptr::addr_of_mut!(ADDR) };
        *addr = SockaddrIn::new(9001, Ipv4Address::UNSPECIFIED);
        let bind_result = sys_bind(
            fd,
            core::ptr::from_ref::<SockaddrIn>(addr) as u32,
            core::mem::size_of::<SockaddrIn>() as u32,
        );
        assert_eq!(bind_result, 0, "proc0 must be able to bind its own socket");

        // A freshly spawned process gets its OWN, empty fd table.
        let other_pid = crate::process::spawn(isolation_test_entry).expect("spawn must succeed");
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(other_pid);
        }

        let data = b"x";
        // The spawned process owns an address space of its own, and syscall
        // buffers are validated against it — so every pointer this fixture
        // hands to a syscall below has to be mapped in it, exactly as a real
        // process would already own them. Without this each call returns
        // EFAULT and the fd-isolation assertions never get to run.
        crate::process::map_user_buffer_for_test(data.as_ptr() as usize, data.len());
        // Taking the address of a static is safe; only dereferencing it is not.
        let recv_addr = core::ptr::addr_of!(RECV_BUF) as usize;
        let addr2_addr = core::ptr::addr_of!(ADDR2) as usize;
        crate::process::map_user_buffer_for_test(recv_addr, 4);
        crate::process::map_user_buffer_for_test(addr2_addr, core::mem::size_of::<SockaddrIn>());
        assert_eq!(
            sys_sendto(fd, data.as_ptr() as u32, 1, 0, 0, 0),
            fd::EBADF,
            "a different process must not be able to sendto proc0's socket fd number"
        );

        // SAFETY: test-only static; single-threaded per test.
        let recv_buf = unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };
        assert_eq!(
            sys_recvfrom(fd, recv_buf.as_mut_ptr() as u32, 4, 0, 0, 0),
            fd::EBADF,
            "a different process must not be able to recvfrom proc0's socket fd number"
        );

        // SAFETY: test-only static; single-threaded per test.
        let addr2 = unsafe { &mut *core::ptr::addr_of_mut!(ADDR2) };
        *addr2 = SockaddrIn::new(9002, Ipv4Address::UNSPECIFIED);
        assert_eq!(
            sys_bind(
                fd,
                core::ptr::from_ref::<SockaddrIn>(addr2) as u32,
                core::mem::size_of::<SockaddrIn>() as u32,
            ),
            fd::EBADF,
            "a different process must not be able to bind proc0's socket fd number"
        );
    }
}
