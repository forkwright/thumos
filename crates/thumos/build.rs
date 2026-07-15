//! Boot trust-anchor provisioning and build-time key guard (#233).
//!
//! Sources the Ed25519 boot public key WITHOUT ever committing a production
//! key to the repo:
//!
//! - `--features production`: `THUMOS_BOOT_KEY_PUB` must name a hex-encoded
//!   32-byte public-key file provisioned by the offline signing
//!   infrastructure. The build FAILS without it and REFUSES the committed
//!   dev key.
//! - otherwise (CI / host tests / qemu / dev): defaults to the committed,
//!   deliberately-public dev keypair (`keys/dev/`) and stamps the image
//!   non-production.
//!
//! Refused in EVERY configuration: any RFC 8032 section 7.1 test-vector
//! public key (their private halves are published in the RFC -- forgeable
//! anchors) and any byte string that is not a decompressable curve point
//! (the corruption class that previously shipped an unverifiable key). The
//! deny-list is a known-weak-key backstop, NOT a completeness guarantee:
//! under `production` the provenance of the provisioned key is the builder's
//! responsibility.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Ed25519 public key / seed length in bytes.
const KEY_LEN: usize = 32;

/// RFC 8032 section 7.1 test-vector PUBLIC keys (TEST 1/2/3/1024/abc). Each
/// has its private half published in the RFC, so all are forgeable and are
/// refused as a trust anchor unconditionally. TEST 1 is the exact placeholder
/// this change removes from secure_boot.rs.
const RFC8032_TEST_PUBLIC_KEYS: [[u8; KEY_LEN]; 5] = [
    // TEST 1: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ],
    // TEST 2: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ],
    // TEST 3: fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
    [
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0,
        0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90,
        0x80, 0x25,
    ],
    // TEST 1024: 278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e
    [
        0x27, 0x81, 0x17, 0xfc, 0x14, 0x4c, 0x72, 0x34, 0x0f, 0x67, 0xd0, 0xf2, 0x31, 0x6e, 0x83,
        0x86, 0xce, 0xff, 0xbf, 0x2b, 0x24, 0x28, 0xc9, 0xc5, 0x1f, 0xef, 0x7c, 0x59, 0x7f, 0x1d,
        0x42, 0x6e,
    ],
    // TEST abc: ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf
    [
        0xec, 0x17, 0x2b, 0x93, 0xad, 0x5e, 0x56, 0x3b, 0xf4, 0x93, 0x2c, 0x70, 0xe1, 0x24, 0x50,
        0x34, 0xc3, 0x54, 0x67, 0xef, 0x2e, 0xfd, 0x4d, 0x64, 0xeb, 0xf8, 0x19, 0x68, 0x34, 0x67,
        0xe2, 0xbf,
    ],
];

/// Env var naming the provisioned public-key file (64 hex chars).
const KEY_ENV: &str = "THUMOS_BOOT_KEY_PUB";

fn main() {
    println!("cargo:rerun-if-env-changed={KEY_ENV}");

    let manifest_dir = PathBuf::from(env_or_die("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env_or_die("OUT_DIR"));
    let dev_pub_path = manifest_dir.join("keys/dev/boot-dev.pub");
    let dev_seed_path = manifest_dir.join("keys/dev/boot-dev.seed");
    println!("cargo:rerun-if-changed={}", dev_pub_path.display());
    println!("cargo:rerun-if-changed={}", dev_seed_path.display());

    let production = env::var_os("CARGO_FEATURE_PRODUCTION").is_some();
    let dev_key = read_hex_key(&dev_pub_path);

    let (key, key_path) = match env::var(KEY_ENV) {
        Ok(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            (read_hex_key(&path), path)
        }
        Err(_) if production => die(&format!(
            "#233: a production image needs a real trust anchor. Set {KEY_ENV} to the \
             hex-encoded Ed25519 public key file produced by the offline signing \
             infrastructure (Titan / air-gapped machine). The committed dev key and \
             the RFC 8032 placeholder are refused for production builds; no \
             production key is ever committed to this repo."
        )),
        Err(_) => (dev_key, dev_pub_path.clone()),
    };

    if RFC8032_TEST_PUBLIC_KEYS.contains(&key) {
        die(&format!(
            "#233: {} is an RFC 8032 section 7.1 test-vector public key -- its private \
             half is published in the RFC, so this anchor is forgeable by anyone. \
             Refused in every configuration.",
            key_path.display()
        ));
    }
    if production && key == dev_key {
        die(&format!(
            "#233: {} is the committed dev key -- its seed is public by design and it \
             must never anchor a production image. Provision a real key via {KEY_ENV}.",
            key_path.display()
        ));
    }
    if VerifyingKey::from_bytes(&key).is_err() {
        die(&format!(
            "#233: {} is not a decompressable Ed25519 point -- a corrupted anchor \
             would make every image unverifiable.",
            key_path.display()
        ));
    }

    // WHY: the dev seed is emitted (test-only) so host tests can sign
    // round-trips against the real embedded anchor; its derivation is
    // re-checked here so a corrupted committed keypair fails the build, not
    // the test suite.
    let dev_seed = if key == dev_key {
        let seed = read_hex_key(&dev_seed_path);
        if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != dev_key {
            die(
                "#233: keys/dev/boot-dev.seed does not derive keys/dev/boot-dev.pub -- the committed dev keypair is corrupted",
            );
        }
        Some(seed)
    } else {
        None
    };

    let trust = if production { "PROD" } else { "DEV" };
    let fingerprint = hex(key.get(..8).unwrap_or(&[]));
    let rendered = render_boot_key_rs(&key, production, trust, &fingerprint, dev_seed.as_ref());
    if let Err(e) = fs::write(out_dir.join("boot_key.rs"), rendered) {
        die(&format!("#233: cannot write boot_key.rs: {e}"));
    }

    generate_initramfs(&manifest_dir, &out_dir);
}

/// Compile the userspace /init (#474) to a static armv7a ELF linked at
/// 0x40100000 (kconfig::KERNEL_END) and wrap it in a newc CPIO the kernel
/// embeds and mounts as the image-resident boot root ramfs.
///
/// WHY rustc-direct (not a sub-crate): /init is one no_std no_main file, so a
/// raw rustc invocation for armv7a-none-eabi produces the ET_EXEC ELF
/// elf::load parses without a nested cargo build or workspace membership.
/// -Ttext places all PT_LOAD >= KERNEL_END so the identity-mapping loader
/// writes them into the sanctioned user-DRAM window [KERNEL_END, RAM_END).
/// Compile one userspace program (init.rs / init2.rs) to a static armv7a ELF
/// linked by init.ld (#474/#489). `variant_cfg` optionally adds a
/// `thumos_init_<variant>` cfg.
fn compile_init_binary(
    rustc: &str,
    src: &Path,
    init_ld: &Path,
    out_elf: &Path,
    variant_cfg: Option<&str>,
) {
    // kanon:ignore RUST/no-direct-process-command -- build script compiles the userspace binaries; the rule targets runtime/kernel code and there is no build-time compiler wrapper to route through
    let mut cmd = std::process::Command::new(rustc);
    cmd.args([
        "--edition",
        "2024",
        "--target",
        "armv7a-none-eabi",
        "--crate-type",
        "bin",
        "-C",
        "panic=abort",
        "-C",
        "opt-level=s",
        "-C",
        "relocation-model=static",
    ])
    .arg("-C")
    .arg(format!("link-arg=-T{}", init_ld.display()))
    // WHY 0x100: the armv7a default max-page-size (64 KB) pads the ELF file to a
    // 0x10000 first-segment offset (~66 KB of zeros); a 0x100 page size drops it
    // to 256 B, keeping the image small.
    .arg("-C")
    .arg("link-arg=-z")
    .arg("-C")
    .arg("link-arg=max-page-size=0x100")
    // WHY (#487): declare the probe cfgs so a direct rustc compile does not warn.
    .arg("--check-cfg")
    .arg("cfg(thumos_init_kread, thumos_init_kwrite, thumos_init_kexec, thumos_init_cp15, thumos_init_sleep, thumos_init_fork, thumos_init_exec, thumos_init_forkexec)");
    if let Some(cfg) = variant_cfg {
        cmd.arg("--cfg").arg(cfg);
    }
    match cmd.arg("-o").arg(out_elf).arg(src).status() {
        Ok(s) if s.success() => {}
        Ok(s) => die(&format!(
            "#474: rustc failed to build {}: {s}",
            src.display()
        )),
        Err(e) => die(&format!(
            "#474: cannot invoke rustc for {}: {e}",
            src.display()
        )),
    }
}

fn generate_initramfs(manifest_dir: &Path, out_dir: &Path) {
    let init_src = manifest_dir.join("init/init.rs");
    let init_ld = manifest_dir.join("init/init.ld");
    println!("cargo:rerun-if-changed={}", init_src.display());
    println!("cargo:rerun-if-changed={}", init_ld.display());
    let init_elf = out_dir.join("init.elf");

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());

    // WHY (#487): THUMOS_INIT_VARIANT selects an /init probe variant so CI can
    // permanently prove PL0 isolation / fault handling / fork / exec. Each
    // variant compiles a different `_start` body via `--cfg thumos_init_<v>`
    // (see init/init.rs); build.rs re-runs when the env changes. Unset = the
    // normal write+exit /init. The name is validated so a typo fails the build.
    println!("cargo:rerun-if-env-changed=THUMOS_INIT_VARIANT");
    let variant_cfg = match env::var("THUMOS_INIT_VARIANT") {
        Ok(v) if !v.is_empty() => {
            if ![
                "kread", "kwrite", "kexec", "cp15", "sleep", "fork", "exec", "forkexec",
            ]
            .contains(&v.as_str())
            {
                die(&format!(
                    "#487: unknown THUMOS_INIT_VARIANT '{v}' (expected kread|kwrite|kexec|cp15|sleep|fork|exec|forkexec)"
                ));
            }
            Some(format!("thumos_init_{v}"))
        }
        _ => None,
    };

    compile_init_binary(
        &rustc,
        &init_src,
        &init_ld,
        &init_elf,
        variant_cfg.as_deref(),
    );

    // #489: a SECOND userspace program the exec /init variant execs. Always
    // embedded (tiny; unused unless /init execs it -- kinit only spawns /init
    // and /shell by name). NOT named "shell": kinit auto-spawns /shell, and this
    // program deliberately UNDEF-faults on a cp15 probe (its PL0 proof), so
    // auto-spawning it would fault at boot. NOTE (#502): the old reason -- that a
    // /shell would "clobber /init's same-VA image" -- no longer holds now that
    // every process loads into its OWN per-process image frame; a real /shell
    // that coexists with /init is unblocked (tracked as a follow-up).
    let init2_src = manifest_dir.join("init/init2.rs");
    println!("cargo:rerun-if-changed={}", init2_src.display());
    let init2_elf = out_dir.join("init2.elf");
    compile_init_binary(&rustc, &init2_src, &init_ld, &init2_elf, None);

    let elf = match fs::read(&init_elf) {
        Ok(b) => b,
        Err(e) => die(&format!("#474: cannot read built /init ELF: {e}")),
    };
    let elf2 = match fs::read(&init2_elf) {
        Ok(b) => b,
        Err(e) => die(&format!("#489: cannot read built /init2 ELF: {e}")),
    };

    let mut archive = cpio_newc_entry("init", &elf, 0o100_755);
    archive.extend_from_slice(&cpio_newc_entry("init2", &elf2, 0o100_755));
    archive.extend_from_slice(&cpio_newc_entry("TRAILER!!!", &[], 0));
    if let Err(e) = fs::write(out_dir.join("initramfs.cpio"), &archive) {
        die(&format!("#474: cannot write initramfs.cpio: {e}"));
    }

    // WHY (#480): sign the initramfs with the dev seed so the kernel can
    // establish `userspace_image_verified` and spawn this image-resident
    // userspace even on a boot with no verified medium (secure_boot_ok=false,
    // e.g. the eMMC-less QEMU boot). The signature verifies under the dev/qemu
    // anchor (BOOT_PUBLIC_KEY = the committed dev key); under a production
    // anchor it does NOT verify (build.rs has no production seal), so a
    // production image correctly falls back to the eMMC secure-boot gate. The
    // real signing infrastructure signs the production initramfs offline.
    let seed = read_hex_key(&manifest_dir.join("keys/dev/boot-dev.seed"));
    let signature = SigningKey::from_bytes(&seed).sign(&archive);
    if let Err(e) = fs::write(out_dir.join("initramfs_sig.bin"), signature.to_bytes()) {
        die(&format!("#480: cannot write initramfs_sig.bin: {e}"));
    }
}

/// One newc (070701) CPIO entry, byte-identical to the kernel's tested
/// `build_cpio_entry` (kinit tests) so ramfs::from_cpio parses it: 110-byte
/// header, name+NUL padded to 4, data padded to 4.
fn cpio_newc_entry(name: &str, data: &[u8], mode: u32) -> Vec<u8> {
    let mut e = Vec::new();
    let namesize = name.len() + 1;
    e.extend_from_slice(b"070701");
    e.extend_from_slice(b"00000001"); // ino
    e.extend_from_slice(format!("{mode:08X}").as_bytes());
    e.extend_from_slice(b"00000000"); // uid
    e.extend_from_slice(b"00000000"); // gid
    e.extend_from_slice(b"00000001"); // nlink
    e.extend_from_slice(b"00000000"); // mtime
    e.extend_from_slice(format!("{:08X}", data.len()).as_bytes());
    e.extend_from_slice(b"00000000"); // devmajor
    e.extend_from_slice(b"00000000"); // devminor
    e.extend_from_slice(b"00000000"); // rdevmajor
    e.extend_from_slice(b"00000000"); // rdevminor
    e.extend_from_slice(format!("{namesize:08X}").as_bytes());
    e.extend_from_slice(b"00000000"); // check
    e.extend_from_slice(name.as_bytes());
    e.push(0);
    while e.len() % 4 != 0 {
        e.push(0);
    }
    e.extend_from_slice(data);
    while e.len() % 4 != 0 {
        e.push(0);
    }
    e
}

fn render_boot_key_rs(
    key: &[u8; KEY_LEN],
    production: bool,
    trust: &str,
    fingerprint: &str,
    dev_seed: Option<&[u8; KEY_LEN]>,
) -> String {
    let mut out = String::from("// build.rs (#233) writes this file; do not edit by hand.\n\n");
    out.push_str("/// Embedded Ed25519 public key for kernel signature verification.\n");
    out.push_str(&format!(
        "pub(crate) const BOOT_PUBLIC_KEY: [u8; PUBLIC_KEY_LEN] = [{}];\n\n",
        byte_list(key)
    ));
    out.push_str("/// True only when the anchor was provisioned for a production image.\n");
    out.push_str(&format!(
        "pub(crate) const BOOT_KEY_IS_PRODUCTION: bool = {production};\n\n"
    ));
    out.push_str("/// Grep-able image trust stamp (printed on the boot banner).\n");
    out.push_str(&format!(
        "pub(crate) const BOOT_TRUST_STAMP: &str = \"THUMOS-BOOT-TRUST:{trust}:{fingerprint}\";\n\n"
    ));
    out.push_str("/// Dev signing seed (test-only; the dev keypair is deliberately public).\n");
    out.push_str("/// `None` when this build's anchor is not the committed dev key.\n");
    out.push_str("#[cfg(test)]\n");
    match dev_seed {
        Some(seed) => out.push_str(&format!(
            "pub(crate) const BOOT_KEY_DEV_SEED: Option<[u8; PUBLIC_KEY_LEN]> = Some([{}]);\n",
            byte_list(seed)
        )),
        None => out
            .push_str("pub(crate) const BOOT_KEY_DEV_SEED: Option<[u8; PUBLIC_KEY_LEN]> = None;\n"),
    }
    out
}

fn read_hex_key(path: &Path) -> [u8; KEY_LEN] {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => die(&format!(
            "#233: cannot read key file {}: {e}",
            path.display()
        )),
    };
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() != KEY_LEN * 2 {
        die(&format!(
            "#233: {} must be exactly {} hex chars (got {})",
            path.display(),
            KEY_LEN * 2,
            compact.len()
        ));
    }
    let mut key = [0u8; KEY_LEN];
    for (i, byte) in key.iter_mut().enumerate() {
        match u8::from_str_radix(&compact[i * 2..i * 2 + 2], 16) {
            Ok(b) => *byte = b,
            Err(_) => die(&format!("#233: {} is not valid hex", path.display())),
        }
    }
    key
}

fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("{b:#04x}")).collect();
    items.join(", ")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn env_or_die(name: &str) -> String {
    match env::var(name) {
        Ok(v) => v,
        Err(_) => die(&format!("#233: cargo did not set {name}")),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    exit(1);
}
