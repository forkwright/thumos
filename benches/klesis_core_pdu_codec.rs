//! Criterion benchmarks for `klesis-core`'s GSM-7 and BCD-address codecs
//! (TESTING/no-benchmarks, thumos#718).
//!
//! WHY these two paths: every inbound and outbound SMS on the device runs
//! through both. `encode`/`decode` walk `char_to_septet`, which does a
//! *linear scan* over the extension table and then the 128-entry base
//! GSM-7 table for every character (`crates/klesis-core/src/lib.rs`) — an
//! O(n * 128) cost paid per message, not per byte. `decode_bcd_address`
//! runs on every sender/recipient address in every PDU. Both are called
//! from `klesis::pdu::decode_deliver` (the workspace telephony daemon) and,
//! once #126 lands, from the kernel's own `sms.rs` — the path actually
//! reached on the device.
//!
//! Registered on `klesis-core` via `[[bench]]` in its `Cargo.toml` with an
//! explicit `path` into this directory (TESTING/no-benchmarks expects a
//! workspace-root `benches/` sibling to the root `Cargo.toml`; Cargo itself
//! has no opinion on where a `[[bench]]` target's source file lives).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use klesis_core::{decode, decode_bcd_address, encode, encode_bcd_address};

/// 3GPP TS 23.038 single-segment SMS cap: 160 septets.
const SMS_BODY_MAX_CHARS: usize = 160;

/// Unwrap a benchmark input built from a known-good, hand-verified literal.
///
/// Centralizes the one `.expect()` this file needs so a codec regression
/// still panics loudly (a benchmark that silently timed an error path
/// would be worse than no benchmark at all) without scattering
/// `#[expect(clippy::expect_used)]` across every call site.
#[inline]
#[expect(
    clippy::expect_used,
    reason = "benchmark inputs are known-good by construction; a failure here is a real codec regression"
)]
fn must<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    result.expect("benchmark input must be valid by construction")
}

/// A representative single-segment SMS body: ordinary prose, not repeated
/// bytes, so the septet-table scan sees the same character mix real traffic
/// does.
fn representative_sms_body() -> String {
    let phrase = "The kernel booted, the service loop ticked, and the modem \
        reported LTE registration with nonzero signal bars and a ready SIM. ";
    phrase.chars().cycle().take(SMS_BODY_MAX_CHARS).collect()
}

fn bench_gsm7_codec(c: &mut Criterion) {
    let text = representative_sms_body();
    let packed = must(encode(&text));
    let num_septets = SMS_BODY_MAX_CHARS;

    let mut group = c.benchmark_group("gsm7_codec");
    group.bench_function("encode_160_char_sms", |b| {
        b.iter(|| must(encode(black_box(&text))));
    });
    group.bench_function("decode_160_septet_sms", |b| {
        b.iter(|| must(decode(black_box(&packed), black_box(num_septets))));
    });
    group.finish();
}

fn bench_bcd_address_codec(c: &mut Criterion) {
    // WHY this input: a 15-digit E.164 international MSISDN is the common
    // case for both the originating- and destination-address fields of a
    // real PDU.
    let msisdn = "+447700900123456";
    let (type_of_address, packed) = must(encode_bcd_address(msisdn));
    let len_digits = must(u8::try_from(msisdn.len() - 1));

    let mut group = c.benchmark_group("bcd_address_codec");
    group.bench_function("encode_15_digit_msisdn", |b| {
        b.iter(|| must(encode_bcd_address(black_box(msisdn))));
    });
    group.bench_function("decode_15_digit_msisdn", |b| {
        let type_of_address = black_box(type_of_address);
        let packed = black_box(&packed);
        b.iter(|| {
            must(decode_bcd_address(
                black_box(len_digits),
                type_of_address,
                packed,
            ))
        });
    });
    group.finish();
}

criterion_group!(benches, bench_gsm7_codec, bench_bcd_address_codec);
criterion_main!(benches);
