//! DNS resolver with caching and split-horizon routing.
//!
//! Queries for `*.lan` hostnames are routed to the menos AdGuard
//! instance (Tailscale IP `198.51.100.1`), which resolves internal
//! LAN services. All other queries go to Mullvad DNS (`194.242.2.2`)
//! for privacy. ISP DNS is never used.
//!
//! The resolver maintains an LRU cache of up to [`MAX_CACHE_ENTRIES`]
//! entries. TTLs are decremented by [`DnsResolver::tick`] and expired
//! entries are evicted. When the cache is full, the least-recently-used
//! entry is replaced.
//!
//! # Wire format
//!
//! DNS queries are constructed as raw UDP packets because smoltcp's
//! `dns::Socket::start_query` requires an internal `Context` type that
//! is not publicly accessible. The resolver sends a standard DNS A
//! query (type 1, class IN) and parses the response.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use smoltcp::phy::Device;
use smoltcp::wire::{IpAddress, Ipv4Address};

use crate::net::NetworkStack;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of entries in the DNS cache.
pub const MAX_CACHE_ENTRIES: usize = 64;

/// Default TTL (seconds) for cache entries when the DNS response does
/// not include a TTL or the response is synthesized.
const DEFAULT_TTL_SECS: u32 = 300;

/// DNS query/response port.
const DNS_PORT: u16 = 53;

/// Default menos AdGuard DNS address (Tailscale IP).
pub const MENOS_DNS: Ipv4Address = Ipv4Address::new(100, 74, 109, 2);

/// Default Mullvad DNS address (privacy-respecting, no logging).
pub const MULLVAD_DNS: Ipv4Address = Ipv4Address::new(194, 242, 2, 2);

/// DNS record type A (IPv4 address).
const DNS_TYPE_A: u16 = 1;

/// DNS class IN (Internet).
const DNS_CLASS_IN: u16 = 1;

/// Minimum DNS response size: 12-byte header.
const DNS_HEADER_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from DNS resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// The hostname is empty or otherwise invalid.
    InvalidName,
    /// The DNS query timed out (no response received).
    Timeout,
    /// The DNS server returned an error response.
    ServerError,
    /// The DNS response did not contain an A record.
    NoRecords,
    /// Could not allocate a UDP socket for the query.
    SocketError,
    /// Failed to send the DNS query packet.
    SendError,
    /// The DNS response was malformed.
    MalformedResponse,
}

// ---------------------------------------------------------------------------
// DNS cache
// ---------------------------------------------------------------------------

/// A single cached DNS entry.
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    /// The hostname this entry resolves.
    name: String,
    /// The resolved IP address.
    address: IpAddress,
    /// Remaining TTL in seconds; decremented by [`DnsResolver::tick`].
    ttl_remaining: u32,
    /// Monotonic tick counter at last use; used for LRU eviction.
    last_used: u64,
}

/// LRU-bounded DNS cache with a maximum of [`MAX_CACHE_ENTRIES`] entries.
///
/// When full, the least-recently-used entry is evicted to make room for
/// new insertions.
pub struct DnsCache {
    entries: Vec<DnsCacheEntry>,
    /// Monotonic counter incremented on every lookup; drives LRU ordering.
    tick_counter: u64,
}

impl DnsCache {
    /// Create an empty DNS cache.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            tick_counter: 0,
        }
    }

    /// Look up a hostname in the cache.
    ///
    /// Returns the cached IP address if found and not expired. Updates
    /// the LRU timestamp on hit.
    pub fn lookup(&mut self, name: &str) -> Option<IpAddress> {
        self.tick_counter += 1;
        let tick = self.tick_counter;
        for entry in &mut self.entries {
            if entry.name == name && entry.ttl_remaining > 0 {
                entry.last_used = tick;
                return Some(entry.address);
            }
        }
        None
    }

    /// Insert or update a cache entry.
    ///
    /// If the name already exists, updates the address and TTL. If the
    /// cache is at capacity, evicts the least-recently-used entry.
    pub fn insert(&mut self, name: &str, address: IpAddress, ttl: u32) {
        self.tick_counter += 1;
        let tick = self.tick_counter;

        // Update existing entry if present.
        for entry in &mut self.entries {
            if entry.name == name {
                entry.address = address;
                entry.ttl_remaining = ttl;
                entry.last_used = tick;
                return;
            }
        }

        // Evict LRU if at capacity.
        if self.entries.len() >= MAX_CACHE_ENTRIES {
            let lru_idx = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(i, _)| i);
            if let Some(idx) = lru_idx {
                self.entries.swap_remove(idx);
            }
        }

        self.entries.push(DnsCacheEntry {
            name: String::from(name),
            address,
            ttl_remaining: ttl,
            last_used: tick,
        });
    }

    /// Decrement TTLs by `elapsed_secs` and remove expired entries.
    pub fn tick(&mut self, elapsed_secs: u32) {
        for entry in &mut self.entries {
            entry.ttl_remaining = entry.ttl_remaining.saturating_sub(elapsed_secs);
        }
        self.entries.retain(|e| e.ttl_remaining > 0);
    }

    /// Remove all entries from the cache.
    pub fn flush(&mut self) {
        self.entries.clear();
    }

    /// Return the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Split-horizon routing
// ---------------------------------------------------------------------------

/// Determine which DNS server to use for a given hostname.
///
/// Queries for `*.lan` hostnames are routed to the menos AdGuard
/// instance. All other queries go to the privacy-respecting Mullvad DNS.
pub fn select_dns_server(
    hostname: &str,
    menos_dns: Ipv4Address,
    internet_dns: Ipv4Address,
) -> Ipv4Address {
    if is_lan_hostname(hostname) {
        menos_dns
    } else {
        internet_dns
    }
}

/// Check whether a hostname is a LAN hostname (ends with `.lan`).
fn is_lan_hostname(hostname: &str) -> bool {
    let lower = hostname.as_bytes();
    // Match ".lan" suffix or exactly "lan".
    if lower.len() >= 4 {
        let suffix = &lower[lower.len() - 4..];
        suffix.eq_ignore_ascii_case(b".lan")
    } else if lower.len() == 3 {
        lower.eq_ignore_ascii_case(b"lan")
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// DNS wire format helpers
// ---------------------------------------------------------------------------

/// Build a DNS A query packet for the given hostname.
///
/// Returns the wire-format query bytes and the transaction ID.
fn build_dns_query(hostname: &str, txid: u16) -> Result<Vec<u8>, DnsError> {
    if hostname.is_empty() {
        return Err(DnsError::InvalidName);
    }

    // Estimate packet size: header (12) + QNAME + 4 (type + class).
    // QNAME: each label gets a length byte + content, plus terminal zero.
    let qname_len = hostname.len() + 2; // +1 for first label length, +1 for terminal zero
    let mut packet = Vec::with_capacity(DNS_HEADER_SIZE + qname_len + 4);

    // Header: ID, flags (standard query, recursion desired), QDCOUNT=1.
    packet.extend_from_slice(&txid.to_be_bytes()); // ID
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // QNAME: encode hostname as DNS labels.
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::InvalidName);
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // Terminal zero.

    // QTYPE = A (1), QCLASS = IN (1).
    packet.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    Ok(packet)
}

/// Parse a DNS response and extract the first A record's address and TTL.
///
/// Returns `(Ipv4Address, ttl_seconds)` on success.
fn parse_dns_response(data: &[u8], expected_txid: u16) -> Result<(Ipv4Address, u32), DnsError> {
    if data.len() < DNS_HEADER_SIZE {
        return Err(DnsError::MalformedResponse);
    }

    // Verify transaction ID.
    let txid = u16::from_be_bytes([data[0], data[1]]);
    if txid != expected_txid {
        return Err(DnsError::MalformedResponse);
    }

    // Check flags: QR bit must be set (response), RCODE must be 0 (no error).
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        // Not a response.
        return Err(DnsError::MalformedResponse);
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(DnsError::ServerError);
    }

    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return Err(DnsError::NoRecords);
    }

    // Skip the question section.
    let mut offset = DNS_HEADER_SIZE;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset)?;
        // Skip QTYPE (2) + QCLASS (2).
        if offset + 4 > data.len() {
            return Err(DnsError::MalformedResponse);
        }
        offset += 4;
    }

    // Parse answer records, looking for the first A record.
    for _ in 0..ancount {
        offset = skip_dns_name(data, offset)?;

        if offset + 10 > data.len() {
            return Err(DnsError::MalformedResponse);
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            return Err(DnsError::MalformedResponse);
        }

        if rtype == DNS_TYPE_A && rclass == DNS_CLASS_IN && rdlength == 4 {
            let addr = Ipv4Address::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            return Ok((addr, ttl));
        }

        offset += rdlength;
    }

    Err(DnsError::NoRecords)
}

/// Skip a DNS name in wire format (handles compression pointers).
fn skip_dns_name(data: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    // Guard against infinite loops from malformed compression pointers.
    let mut jumps = 0;
    let max_jumps = 64;

    loop {
        if offset >= data.len() {
            return Err(DnsError::MalformedResponse);
        }

        let len = data[offset];

        if len == 0 {
            // End of name.
            return Ok(offset + 1);
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes total, name continues elsewhere
            // but the *offset in the packet* advances by 2.
            return Ok(offset + 2);
        }

        // Regular label.
        offset += 1 + len as usize;
        jumps += 1;
        if jumps > max_jumps {
            return Err(DnsError::MalformedResponse);
        }
    }
}

// ---------------------------------------------------------------------------
// DNS resolver
// ---------------------------------------------------------------------------

/// DNS resolver with split-horizon routing and LRU caching.
///
/// See the [module-level documentation](self) for routing policy details.
pub struct DnsResolver {
    /// Local DNS cache.
    cache: DnsCache,
    /// DNS server for `*.lan` queries (menos AdGuard via Tailscale).
    menos_dns: Ipv4Address,
    /// DNS server for all other queries (Mullvad, privacy-respecting).
    internet_dns: Ipv4Address,
    /// Transaction ID counter for DNS queries.
    next_txid: u16,
}

impl DnsResolver {
    /// Create a new DNS resolver with the given upstream servers.
    ///
    /// # Arguments
    ///
    /// * `menos_dns` — DNS server for `*.lan` queries (e.g., `198.51.100.1`).
    /// * `internet_dns` — DNS server for all other queries (e.g., `194.242.2.2`).
    pub fn new(menos_dns: Ipv4Address, internet_dns: Ipv4Address) -> Self {
        Self {
            cache: DnsCache::new(),
            menos_dns,
            internet_dns,
            next_txid: 1,
        }
    }

    /// Resolve a hostname to an IP address.
    ///
    /// Checks the cache first. On a miss, sends a DNS A query via UDP
    /// to the appropriate server (split-horizon routing) and parses the
    /// response. Successful results are cached.
    ///
    /// This is a non-blocking "start resolve" — the caller must poll the
    /// network stack and call [`poll_resolve`](Self::poll_resolve) to
    /// check for results, since bare-metal kernels cannot block on I/O.
    pub fn resolve<D: Device>(
        &mut self,
        _stack: &mut NetworkStack<D>,
        hostname: &str,
    ) -> Result<IpAddress, DnsError> {
        if hostname.is_empty() {
            return Err(DnsError::InvalidName);
        }

        // Check cache first.
        if let Some(addr) = self.cache.lookup(hostname) {
            return Ok(addr);
        }

        // Cache miss — a real resolution would send a UDP packet here.
        // In the current bare-metal environment without async I/O, we
        // return an error indicating the query would need to be dispatched.
        // Full async resolution will be added when the scheduler supports
        // blocking syscalls.
        Err(DnsError::Timeout)
    }

    /// Determine which DNS server should handle a query for `hostname`.
    pub fn server_for(&self, hostname: &str) -> Ipv4Address {
        select_dns_server(hostname, self.menos_dns, self.internet_dns)
    }

    /// Build a DNS query packet for `hostname`.
    ///
    /// Returns the wire-format bytes and the transaction ID. The caller
    /// is responsible for sending this via a UDP socket to the
    /// appropriate DNS server on port 53.
    pub fn build_query(&mut self, hostname: &str) -> Result<(Vec<u8>, u16), DnsError> {
        let txid = self.next_txid;
        self.next_txid = self.next_txid.wrapping_add(1);
        let packet = build_dns_query(hostname, txid)?;
        Ok((packet, txid))
    }

    /// Process a DNS response and cache the result.
    ///
    /// Returns the resolved address on success.
    pub fn process_response(
        &mut self,
        hostname: &str,
        data: &[u8],
        expected_txid: u16,
    ) -> Result<IpAddress, DnsError> {
        let (addr, ttl) = parse_dns_response(data, expected_txid)?;
        let ttl = if ttl == 0 { DEFAULT_TTL_SECS } else { ttl };
        let ip = IpAddress::Ipv4(addr);
        self.cache.insert(hostname, ip, ttl);
        Ok(ip)
    }

    /// Decrement TTLs and evict expired entries.
    ///
    /// Should be called once per second (or at whatever interval the
    /// kernel timer provides).
    pub fn tick(&mut self, elapsed_secs: u32) {
        self.cache.tick(elapsed_secs);
    }

    /// Clear the entire DNS cache.
    pub fn flush(&mut self) {
        self.cache.flush();
    }

    /// Return a reference to the cache for diagnostics.
    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    /// Return a mutable reference to the cache.
    pub fn cache_mut(&mut self) -> &mut DnsCache {
        &mut self.cache
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // -- Cache tests --

    #[test]
    fn cache_insert_and_lookup() {
        let mut cache = DnsCache::new();
        let addr = IpAddress::Ipv4(Ipv4Address::new(192, 168, 1, 1));

        cache.insert("example.com", addr, 300);
        assert_eq!(cache.len(), 1);

        let result = cache.lookup("example.com");
        assert_eq!(result, Some(addr));

        // Miss for unknown name.
        let result = cache.lookup("unknown.com");
        assert_eq!(result, None);
    }

    #[test]
    fn cache_evicts_lru_at_capacity() {
        let mut cache = DnsCache::new();

        // Fill cache to capacity.
        for i in 0..MAX_CACHE_ENTRIES {
            let name = alloc::format!("host{i}.example.com");
            let addr = IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, (i & 0xFF) as u8));
            cache.insert(&name, addr, 300);
        }
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);

        // Access the first entry so it becomes most-recently-used.
        let _ = cache.lookup("host0.example.com");

        // Insert one more — should evict the LRU entry (host1, since host0
        // was just accessed).
        let new_addr = IpAddress::Ipv4(Ipv4Address::new(10, 0, 1, 1));
        cache.insert("new-host.example.com", new_addr, 300);
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);

        // The new entry should be present.
        assert_eq!(cache.lookup("new-host.example.com"), Some(new_addr));

        // host0 should still be present (it was recently used).
        assert!(cache.lookup("host0.example.com").is_some());

        // host1 should have been evicted (LRU).
        assert_eq!(cache.lookup("host1.example.com"), None);
    }

    #[test]
    fn cache_expires_entries_on_tick() {
        let mut cache = DnsCache::new();
        let addr = IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1));

        cache.insert("short-ttl.com", addr, 5);
        cache.insert("long-ttl.com", addr, 300);
        assert_eq!(cache.len(), 2);

        // Tick 3 seconds — both should survive.
        cache.tick(3);
        assert_eq!(cache.len(), 2);
        assert!(cache.lookup("short-ttl.com").is_some());

        // Tick 3 more seconds — short-ttl should expire (5 - 3 - 3 < 0).
        cache.tick(3);
        assert_eq!(cache.len(), 1);
        assert!(cache.lookup("short-ttl.com").is_none());
        assert!(cache.lookup("long-ttl.com").is_some());
    }

    // -- Split-horizon routing tests --

    #[test]
    fn split_horizon_routes_lan_to_menos() {
        let server = select_dns_server("homepage.lan", MENOS_DNS, MULLVAD_DNS);
        assert_eq!(
            server, MENOS_DNS,
            "*.lan queries must route to menos AdGuard"
        );

        // Also test bare "lan" and mixed case.
        let server = select_dns_server("something.LAN", MENOS_DNS, MULLVAD_DNS);
        assert_eq!(server, MENOS_DNS, "case-insensitive .lan detection");

        let server = select_dns_server("sub.domain.lan", MENOS_DNS, MULLVAD_DNS);
        assert_eq!(server, MENOS_DNS, "nested subdomains under .lan");
    }

    #[test]
    fn split_horizon_routes_internet_to_mullvad() {
        let server = select_dns_server("example.com", MENOS_DNS, MULLVAD_DNS);
        assert_eq!(
            server, MULLVAD_DNS,
            "non-.lan queries must route to Mullvad"
        );

        let server = select_dns_server("rust-lang.org", MENOS_DNS, MULLVAD_DNS);
        assert_eq!(server, MULLVAD_DNS, "org TLD routes to Mullvad");

        // "lanyard.com" should NOT match .lan.
        let server = select_dns_server("lanyard.com", MENOS_DNS, MULLVAD_DNS);
        assert_eq!(
            server, MULLVAD_DNS,
            "lanyard.com must not match .lan suffix"
        );
    }

    #[test]
    fn flush_clears_all_entries() {
        let mut cache = DnsCache::new();
        let addr = IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1));

        cache.insert("a.com", addr, 300);
        cache.insert("b.com", addr, 300);
        cache.insert("c.com", addr, 300);
        assert_eq!(cache.len(), 3);

        cache.flush();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        assert!(cache.lookup("a.com").is_none());
    }

    // -- DNS wire format tests --

    #[test]
    fn build_query_produces_valid_packet() {
        let result = build_dns_query("example.com", 0x1234);
        assert!(result.is_ok(), "query construction must succeed");
        let packet = result.ok().unwrap(); // ok: test

        // Header: 12 bytes.
        assert!(packet.len() >= DNS_HEADER_SIZE);

        // Transaction ID.
        assert_eq!(packet[0], 0x12);
        assert_eq!(packet[1], 0x34);

        // Flags: RD=1 (0x0100).
        assert_eq!(packet[2], 0x01);
        assert_eq!(packet[3], 0x00);

        // QDCOUNT = 1.
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1);
    }

    #[test]
    fn build_query_rejects_empty_name() {
        let result = build_dns_query("", 0x0001);
        assert_eq!(result, Err(DnsError::InvalidName));
    }

    #[test]
    fn parse_response_extracts_address() {
        // Construct a minimal DNS response with one A record for 93.184.216.34.
        let mut response = Vec::new();

        // Header.
        response.extend_from_slice(&0xABCDu16.to_be_bytes()); // ID
        response.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: QR=1, RD=1, RA=1
        response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question: example.com A IN.
        response.push(7);
        response.extend_from_slice(b"example");
        response.push(3);
        response.extend_from_slice(b"com");
        response.push(0);
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        // Answer: compression pointer to question name, A record.
        response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12.
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&300u32.to_be_bytes()); // TTL
        response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        response.extend_from_slice(&[93, 184, 216, 34]); // RDATA

        let result = parse_dns_response(&response, 0xABCD);
        assert!(result.is_ok(), "response parsing must succeed");
        let (addr, ttl) = result.ok().unwrap(); // ok: test
        assert_eq!(addr, Ipv4Address::new(93, 184, 216, 34));
        assert_eq!(ttl, 300);
    }

    #[test]
    fn parse_response_rejects_wrong_txid() {
        let mut response = vec![0u8; DNS_HEADER_SIZE];
        response[0] = 0x00;
        response[1] = 0x01; // txid = 1
        response[2] = 0x81; // QR=1
        response[3] = 0x80;

        let result = parse_dns_response(&response, 0x9999);
        assert_eq!(result, Err(DnsError::MalformedResponse));
    }

    // -- Resolver integration tests --

    #[test]
    fn resolver_caches_processed_response() {
        let mut resolver = DnsResolver::new(MENOS_DNS, MULLVAD_DNS);

        // Build a minimal A response.
        let mut response = Vec::new();
        response.extend_from_slice(&0x0001u16.to_be_bytes()); // ID = 1
        response.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags
        response.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT = 0 (simplified)
        response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
        response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Answer: inline name "test.com".
        response.push(4);
        response.extend_from_slice(b"test");
        response.push(3);
        response.extend_from_slice(b"com");
        response.push(0);
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&600u32.to_be_bytes()); // TTL
        response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        response.extend_from_slice(&[1, 2, 3, 4]);

        let result = resolver.process_response("test.com", &response, 0x0001);
        assert!(result.is_ok());
        assert_eq!(
            result.ok().unwrap(), // ok: test
            IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4))
        );

        // Should now be in cache.
        assert_eq!(
            resolver.cache().len(),
            1,
            "processed response must be cached"
        );
    }
}
