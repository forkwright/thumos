#![no_std]
#![deny(missing_docs)]
//! aither-core: the canonical WPA2-Personal EAPOL and 4-way-handshake
//! semantics (#545, #819).
//!
//! This crate is the single home of EAPOL frame parsing/encoding (IEEE
//! 802.1X-2020), PMK/PTK derivation and MIC computation (IEEE 802.11-2020),
//! and the supplicant-side 4-way handshake state machine, shared by the
//! `aither` workspace crate (`WiFi` driver and WPA2/3 supplicant) and the
//! thumos kernel (`wifi.rs`, the path actually reached on the device).
//!
//! It exists because the two sides had already diverged (#819, #837):
//!
//! - `aither::eapol::parse` accepted any EAPOL-Key descriptor-type byte
//!   unchecked; the kernel rejected anything but RSN (0x02). A non-RSN or
//!   malformed descriptor would have parsed as trusted key material on the
//!   side with no hardware to actually exploit it.
//! - `aither::eapol::encode` declared a truncated `body_len`/`key_data_len`
//!   field when the input exceeded `u16::MAX`, but wrote the FULL untruncated
//!   bytes anyway -- the declared length and the actual frame body diverged.
//!   The kernel's port (audit #282 finding 5) had already fixed this; the
//!   fix never reached the crate `fuzz_eapol`/`fuzz_wpa` actually exercise.
//! - the kernel's PBKDF2-HMAC-SHA1 PMK derivation truncated an over-32-byte
//!   SSID salt to 32 bytes before use (`salt.len().min(32)`), silently
//!   deriving a different PMK than a compliant supplicant would for the same
//!   passphrase/SSID pair. `aither`'s PBKDF2 call had no such cap.
//! - the kernel had a supplicant-side 4-way handshake state machine
//!   (`HandshakeState`/`WpaHandshake`) with no equivalent in `aither` at
//!   all -- the highest-value protocol logic in the pair was fuzzed nowhere.
//!
//! Both `fuzz_wpa` and `fuzz_eapol` import the OUTER `aither` crate; `aither`
//! now delegates into this crate, so fuzzing reaches the same code the
//! kernel links instead of a parallel implementation that never ships.
//!
//! `no_std` + alloc so the bare-metal kernel can link it via a path
//! dependency; nothing here performs I/O, and nothing here generates
//! entropy -- [`wpa::WpaHandshake::process_message`] takes a
//! caller-supplied `SNonce` rather than drawing one itself, because the
//! kernel's fail-closed CSPRNG (`csprng::kernel_random_bytes`) is
//! hardware-bound and has no equivalent this crate could link.
//!
//! # Module map
//!
//! - [`eapol`] -- EAPOL frame types, parsing, and encoding.
//! - [`wpa`] -- PMK/PTK derivation, MIC, replay-counter enforcement, and the
//!   4-way handshake state machine.

extern crate alloc;

pub mod eapol;
pub mod wpa;
