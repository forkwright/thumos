# Hostile-input parser inventory (#548)

Every parser that consumes untrusted bytes, its fuzz disposition, and its
witness. Re-derived from the actual call-graph roots (modem/CCCI, WiFi/EAPOL/
WPA, SMS/PDU/GSM-7, DNS, ELF loader, JSON/HTTP, mesh), not from #116's stale
list. Dispositions: **workspace** (fuzzed via the peirama fuzz crate),
**kernel-host** (kernel no_std modules, fuzzed host-side under the i686 stub
shims), **hardware-gated** (cannot exercise without the device — reason named).

## Workspace-fuzzable (peirama crate)

| Parser | Surface | Target | Status |
|--------|---------|--------|--------|
| asphaleia::dns (QNAME extract + blocklist eval) | untrusted UDP payloads | fuzz_dns | landed (#116); visibility fixed (#548) |
| aither::eapol (frame parse + round-trip) | WiFi association frames | fuzz_eapol | landed (#116); visibility fixed (#548) |
| klesis::pdu (SMS-DELIVER decode / SMS-SUBMIT encode, GSM-7 end-to-end) | modem SMS PDUs | fuzz_gsm7 | landed (#116); visibility fixed (#548) |
| klesis::at (3GPP 27.007 response/URC parser) | every modem byte | fuzz_at | landed (#548) |
| klesis::ccci (CCCI frame/HDLC decode) | modem control channel | fuzz_ccci | landed (#548) |
| klesis::pdu full surface (concat, OMA-CP/WAP-Push rejection, validity periods) | modem SMS PDUs | fuzz_pdu | landed (#548) |
| aither::wpa (4-way handshake derivation, MIC, replay session) | WiFi auth frames | fuzz_wpa | landed (#548) |
| asphaleia::packet + filter + rules (packet parse → rule eval) | all IP traffic | fuzz_packet | landed (#548) |

Gate: `.github/workflows/fuzz.yml` — weekly (Sun 11:47 UTC) + workflow_dispatch,
8-target matrix, 300s/target from `corpus/<target>` seeds, crash artifacts
uploaded on failure. Visibility contract: the fuzzed parser entry points are
`pub` (the integration surface the crates were always meant to expose —
`pub(crate)` had made the original three targets uncompilable, E0603, and no
gate existed to catch it).

## Kernel-host-fuzzable (kernel no_std modules under i686 stub shims)

The kernel carries its OWN parser modules (the workspace crates are not
linked into it). Until #545's convergence makes the kernel consume the
fuzzed libraries, these need kernel-side harnesses — a lib target exposing
the parser modules to a kernel-fuzz crate under cfg(fuzz), mirroring the
exceptions/timer/uart stub pattern used by the i686 suite.

| Kernel module | Surface | Disposition |
|---------------|---------|-------------|
| elf.rs | execve'd ELF images (userspace programs) | kernel-host |
| sms.rs / gsm7.rs | modem SMS path | kernel-host |
| dns.rs / dns_tls.rs | resolver + DoT frames | kernel-host |
| ccci.rs / telephony_parser.rs | modem control channel | kernel-host |
| meshtastic.rs | mesh packets | kernel-host |
| json_mini.rs / http_client.rs | Matrix/HTTP responses | kernel-host |

## Hardware-gated (no fuzz disposition until the device exists)

| Surface | Reason |
|---------|--------|
| CCCI wire protocol against the live modem | needs the MT6739 modem; QEMU models no CCCI |
| WMT/STP combo-chip framing (kelyphos) | needs the combo chip |
| NMEA from the live GPS | needs RF; parser itself is host-fuzzable if a module emerges |
