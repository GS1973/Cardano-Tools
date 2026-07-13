//! Uniform loader for cardano-cli signing-key files.
//!
//! Cardano-cli writes every signing key as a small JSON document with
//! three fields: `type`, `description`, `cborHex`. The cborHex field is a
//! CBOR-encoded byte string of the raw key material; the `type` field indicates
//! *which* algorithm and key role it is for.
//!
//! This module reads any of those JSON files and returns a strongly-typed
//! [`CardanoKey`] enum, so the rest of the workspace can pattern-match on
//! key role without re-implementing the same JSON+CBOR dance every time.
//!
//! Key types currently understood:
//! - StakePoolSigningKey_ed25519 (cold key, 32-byte plain Ed25519 seed —
//!   cardano-cli `node key-gen`. The extended 64-byte form (HD-derived or
//!   mnemonic-export) is also accepted; only the first 32 bytes — the seed
//!   half — are used.)
//! - VrfSigningKey_PraosVRF (VRF, 64-byte extended)
//! - StakeSigningKeyShelley_ed25519 (stake, 32-byte plain Ed25519)
//! - PaymentSigningKeyShelley_ed25519 (payment, 32-byte plain Ed25519)
//! - PaymentExtendedSigningKeyShelley_ed25519_bip32 (payment, 128-byte
//!   extended BIP32-Ed25519, from a mnemonic wallet exported via
//!   cardano-address + cardano-cli)
//! - StakeExtendedSigningKeyShelley_ed25519_bip32 (stake, same form)
//! - DRepSigningKey_ed25519 (DRep, 32-byte plain Ed25519 — cardano-cli
//!   `conway governance drep key-gen`)
//! - DRepExtendedSigningKey_ed25519_bip32 (DRep, 128-byte extended
//!   BIP32-Ed25519, from a mnemonic wallet derived at CIP-105 path
//!   1852'/1815'/account'/3/0)
//!
//! KES (`KesSigningKey_ed25519_kes_2^6`) is not handled here — its
//! multi-period structure is managed by the KES rotation module.

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Strongly-typed signing key loaded from a cardano-cli skey JSON file.
/// `ZeroizeOnDrop` overwrites the seed bytes when this value is dropped,
/// reducing the window in which a stray secret sits in freed memory
/// (defends against core dumps, swap-out, and same-uid `/proc/<pid>/mem`
/// reads). Best-effort: ed25519-dalek's `SigningKey` and vrf-dalek's
/// `SecretKey03` keep their own internal copies that are not zeroized
/// here; this covers these buffers.
///
/// `Debug` is implemented by hand (see below) to print only the key role:
/// the derived `Debug` would have copied the raw seed/esk arrays into a
/// non-zeroized formatter buffer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum CardanoKey {
    /// Pool operator cold signing key. Always 32-byte plain Ed25519 seed
    /// (the rare 64-byte extended form is collapsed to its first 32 bytes
    /// at load time, since opcert signing only uses the seed half).
    PoolCold { seed_32: [u8; 32] },
    /// VRF signing key. cborHex is 64 bytes; first 32 = seed for vrf-dalek.
    Vrf { extended_64: [u8; 64] },
    /// Plain Ed25519 stake signing key (32 bytes).
    Stake { seed_32: [u8; 32] },
    /// Plain Ed25519 payment signing key (32 bytes).
    Payment { seed_32: [u8; 32] },
    /// Extended (BIP32-Ed25519) payment signing key from a mnemonic
    /// wallet. `esk_64` is the 64-byte extended secret (kL‖kR) used for
    /// scalar-based signing; `pubkey_32` is the public key embedded in
    /// the skey envelope, kept for an at-load integrity cross-check.
    /// Never fed to seed-based Ed25519.
    PaymentExtended { esk_64: [u8; 64], pubkey_32: [u8; 32] },
    /// Extended (BIP32-Ed25519) stake signing key from a mnemonic wallet.
    /// Same layout and handling as [`CardanoKey::PaymentExtended`].
    StakeExtended { esk_64: [u8; 64], pubkey_32: [u8; 32] },
    /// Plain Ed25519 DRep signing key (32 bytes). Its verification key
    /// hashes (blake2b-224) to the DRep id used in governance certs and
    /// `Voter::DRepKey` votes.
    DRep { seed_32: [u8; 32] },
    /// Extended (BIP32-Ed25519) DRep signing key from a mnemonic wallet.
    /// Same layout and handling as [`CardanoKey::PaymentExtended`].
    DRepExtended { esk_64: [u8; 64], pubkey_32: [u8; 32] },
}

impl CardanoKey {
    /// 32-byte Ed25519/VRF signing seed, wrapped in `Zeroizing` so the
    /// returned copy is wiped when the caller drops it. For the 64-byte
    /// extended VRF key the first 32 bytes are returned (the part vrf-dalek
    /// expects).
    ///
    /// Valid only for the seed-bearing variants. Extended (BIP32) keys
    /// carry an already-clamped scalar (kL), not a seed, and must sign
    /// through their `esk_64` scalar path; calling this on an extended key
    /// is a programming error and panics rather than silently returning a
    /// non-seed that must never be fed to seed-based Ed25519.
    pub fn seed_32(&self) -> Zeroizing<[u8; 32]> {
        let mut s = Zeroizing::new([0u8; 32]);
        match self {
            CardanoKey::PoolCold { seed_32 }
            | CardanoKey::Stake { seed_32 }
            | CardanoKey::Payment { seed_32 }
            | CardanoKey::DRep { seed_32 } => s.copy_from_slice(seed_32),
            CardanoKey::Vrf { extended_64 } => s.copy_from_slice(&extended_64[..32]),
            CardanoKey::PaymentExtended { .. }
            | CardanoKey::StakeExtended { .. }
            | CardanoKey::DRepExtended { .. } => unreachable!(
                "seed_32() called on an extended (BIP32) key; extended keys have no \
                 Ed25519 seed — sign via the esk_64 scalar path"
            ),
        }
        s
    }

    /// Human-readable key role, for diagnostics and error messages. Never
    /// includes any key material.
    pub fn role_name(&self) -> &'static str {
        match self {
            CardanoKey::PoolCold { .. } => "PoolCold",
            CardanoKey::Vrf { .. } => "Vrf",
            CardanoKey::Stake { .. } => "Stake",
            CardanoKey::Payment { .. } => "Payment",
            CardanoKey::PaymentExtended { .. } => "PaymentExtended",
            CardanoKey::StakeExtended { .. } => "StakeExtended",
            CardanoKey::DRep { .. } => "DRep",
            CardanoKey::DRepExtended { .. } => "DRepExtended",
        }
    }
}

/// Redacted `Debug`: prints only the key role, never the secret bytes, so a
/// stray `{:?}` (log line, error message, panic) can never copy key material
/// into a non-zeroized `String`.
impl std::fmt::Debug for CardanoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CardanoKey::{} {{ <redacted> }}", self.role_name())
    }
}

#[derive(Debug, Error)]
pub enum KeyLoadError {
    #[error("could not read skey file: {0}")]
    Io(#[from] std::io::Error),
    #[error("skey file is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cborHex is not valid hex: {0}")]
    Hex(String),
    #[error(
        "cborHex header does not match expected CBOR byte-string of {expected} bytes (got header bytes 0x{got_hex})"
    )]
    BadCborHeader { expected: usize, got_hex: String },
    #[error("cborHex payload length is {actual}, expected {expected}")]
    BadLength { expected: usize, actual: usize },
    #[error(
        "cold key cborHex must be 32 or 64 bytes (header 5820 or 5840); got header 0x{got_hex}"
    )]
    BadColdLength { got_hex: String },
    #[error("unsupported skey type: {0}")]
    UnsupportedType(String),
    #[error("skey file is readable by group or other (mode 0o{mode:o}); chmod 600 before retrying")]
    InsecureMode { mode: u32 },
}

#[derive(Deserialize)]
struct SkeyFile {
    #[serde(rename = "type")]
    ty: String,
    #[serde(rename = "cborHex")]
    cbor_hex: String,
}

/// Decode a CBOR byte-string of exactly `expected` bytes from its hex
/// representation. cardano-cli always uses the short-form CBOR encoding:
///
///   0x58, len_byte, ...payload    (lengths 24..=255 bytes)
///
/// For these key sizes the expected header bytes are:
///   - 32 bytes payload → 0x58, 0x20
///   - 64 bytes payload → 0x58, 0x40
fn decode_cbor_byte_string(cbor_hex: &str, expected: usize) -> Result<Zeroizing<Vec<u8>>, KeyLoadError> {
    let raw = Zeroizing::new(hex::decode(cbor_hex.trim()).map_err(|e| KeyLoadError::Hex(e.to_string()))?);
    if raw.len() < 2 || raw[0] != 0x58 || raw[1] as usize != expected {
        let got_hex = raw.iter().take(2).fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        return Err(KeyLoadError::BadCborHeader { expected, got_hex });
    }
    let payload = &raw[2..];
    if payload.len() != expected {
        return Err(KeyLoadError::BadLength {
            expected,
            actual: payload.len(),
        });
    }
    Ok(Zeroizing::new(payload.to_vec()))
}

/// Decode the cold-key cborHex, accepting either the 32-byte plain seed
/// (header 5820) or the 64-byte extended form (header 5840). Returns the
/// 32-byte signing seed in either case (first half of the extended form).
fn decode_cold_seed(cbor_hex: &str) -> Result<[u8; 32], KeyLoadError> {
    let raw = Zeroizing::new(hex::decode(cbor_hex.trim()).map_err(|e| KeyLoadError::Hex(e.to_string()))?);
    if raw.len() < 2 || raw[0] != 0x58 {
        let got_hex = raw.iter().take(2).fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        return Err(KeyLoadError::BadColdLength { got_hex });
    }
    let mut seed = [0u8; 32];
    match raw[1] {
        0x20 if raw.len() == 2 + 32 => seed.copy_from_slice(&raw[2..]),
        0x40 if raw.len() == 2 + 64 => seed.copy_from_slice(&raw[2..2 + 32]),
        _ => {
            let got_hex = raw.iter().take(2).fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });
            return Err(KeyLoadError::BadColdLength { got_hex });
        }
    }
    Ok(seed)
}

/// Decode a cardano-cli extended (BIP32-Ed25519) signing-key cborHex.
/// The envelope is a 128-byte CBOR byte string (header 5880) laid out as
/// `[ extended_secret(64) | public_key(32) | chain_code(32) ]` — the
/// cardano-crypto XPrv serialisation (offsets verified against
/// `Cardano.Crypto.Wallet.Encrypted`: esk 0, pubkey 64, chaincode 96).
/// Returns the 64-byte extended secret (kL‖kR) used for signing and the
/// 32-byte embedded public key used for the at-load integrity check. The
/// chain code is for HD derivation only and is dropped.
fn decode_extended_key(cbor_hex: &str) -> Result<([u8; 64], [u8; 32]), KeyLoadError> {
    let payload = decode_cbor_byte_string(cbor_hex, 128)?;
    let mut esk = [0u8; 64];
    esk.copy_from_slice(&payload[..64]);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&payload[64..96]);
    Ok((esk, pk))
}

/// Load any supported cardano-cli `.skey` file and return it as a typed
/// [`CardanoKey`]. The `type` field of the JSON drives which variant is
/// returned and which CBOR byte-string size is expected. The file mode
/// is checked first: any group-or-other access bits (`mode & 0o077`)
/// cause `InsecureMode` to be returned without reading the file.
/// cardano-cli writes 0600 by default, but the operator's
/// LUKS-mount-and-copy workflow can produce 0644 by accident; this
/// check turns that into a clear up-front error instead of silently
/// loading a world-readable secret.
pub fn load_skey(path: &Path) -> Result<CardanoKey, KeyLoadError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(KeyLoadError::InsecureMode { mode: mode & 0o7777 });
    }
    let content = Zeroizing::new(std::fs::read_to_string(path)?);
    let file: SkeyFile = serde_json::from_str(&content)?;
    // Move the secret-bearing fields out of the deserialised struct into a
    // Zeroizing wrapper so the hex copy is wiped when this function returns,
    // not left in freed heap.
    let SkeyFile { ty, cbor_hex } = file;
    let cbor_hex = Zeroizing::new(cbor_hex);
    match ty.as_str() {
        "StakePoolSigningKey_ed25519" => {
            let seed_32 = decode_cold_seed(&cbor_hex)?;
            Ok(CardanoKey::PoolCold { seed_32 })
        }
        "VrfSigningKey_PraosVRF" => {
            let bytes = decode_cbor_byte_string(&cbor_hex, 64)?;
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(CardanoKey::Vrf { extended_64: arr })
        }
        "StakeSigningKeyShelley_ed25519" => {
            let bytes = decode_cbor_byte_string(&cbor_hex, 32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(CardanoKey::Stake { seed_32: arr })
        }
        "PaymentSigningKeyShelley_ed25519" => {
            let bytes = decode_cbor_byte_string(&cbor_hex, 32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(CardanoKey::Payment { seed_32: arr })
        }
        "PaymentExtendedSigningKeyShelley_ed25519_bip32" => {
            let (esk_64, pubkey_32) = decode_extended_key(&cbor_hex)?;
            Ok(CardanoKey::PaymentExtended { esk_64, pubkey_32 })
        }
        "StakeExtendedSigningKeyShelley_ed25519_bip32" => {
            let (esk_64, pubkey_32) = decode_extended_key(&cbor_hex)?;
            Ok(CardanoKey::StakeExtended { esk_64, pubkey_32 })
        }
        "DRepSigningKey_ed25519" => {
            let bytes = decode_cbor_byte_string(&cbor_hex, 32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(CardanoKey::DRep { seed_32: arr })
        }
        "DRepExtendedSigningKey_ed25519_bip32" => {
            let (esk_64, pubkey_32) = decode_extended_key(&cbor_hex)?;
            Ok(CardanoKey::DRepExtended { esk_64, pubkey_32 })
        }
        other => Err(KeyLoadError::UnsupportedType(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(json.as_bytes()).expect("write");
        f
    }

    #[test]
    fn parses_payment_skey() {
        let cbor_hex = format!("5820{}", "42".repeat(32));
        let json = format!(
            r#"{{"type":"PaymentSigningKeyShelley_ed25519","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let key = load_skey(f.path()).expect("parse");
        match key {
            CardanoKey::Payment { seed_32 } => assert_eq!(seed_32, [0x42u8; 32]),
            other => panic!("expected Payment, got {other:?}"),
        }
    }

    #[test]
    fn parses_vrf_skey_extended() {
        let cbor_hex = format!("5840{}", "ab".repeat(64));
        let json = format!(
            r#"{{"type":"VrfSigningKey_PraosVRF","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let key = load_skey(f.path()).expect("parse");
        match &key {
            CardanoKey::Vrf { extended_64 } => assert_eq!(*extended_64, [0xabu8; 64]),
            other => panic!("expected Vrf, got {other:?}"),
        }
        assert_eq!(*key.seed_32(), [0xabu8; 32]);
    }

    #[test]
    fn parses_cold_skey_32_byte_form() {
        // Modern cardano-cli `node key-gen` writes the cold skey as 32 bytes.
        let cbor_hex = format!("5820{}", "11".repeat(32));
        let json = format!(
            r#"{{"type":"StakePoolSigningKey_ed25519","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let key = load_skey(f.path()).expect("parse");
        match key {
            CardanoKey::PoolCold { seed_32 } => assert_eq!(seed_32, [0x11u8; 32]),
            other => panic!("expected PoolCold, got {other:?}"),
        }
    }

    #[test]
    fn parses_cold_skey_64_byte_extended_form() {
        // The extended 64-byte form (HD-derived or mnemonic-export) is
        // accepted; only the first 32 bytes — the seed half — are used.
        let mut hex_payload = String::new();
        hex_payload.push_str(&"22".repeat(32));
        hex_payload.push_str(&"33".repeat(32));
        let cbor_hex = format!("5840{hex_payload}");
        let json = format!(
            r#"{{"type":"StakePoolSigningKey_ed25519","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let key = load_skey(f.path()).expect("parse");
        match key {
            CardanoKey::PoolCold { seed_32 } => assert_eq!(seed_32, [0x22u8; 32]),
            other => panic!("expected PoolCold, got {other:?}"),
        }
    }


    #[test]
    fn parses_payment_extended_skey() {
        // 128-byte payload: esk(64) | pubkey(32) | chaincode(32).
        let esk = "11".repeat(64);
        let pk = "22".repeat(32);
        let cc = "33".repeat(32);
        let cbor_hex = format!("5880{esk}{pk}{cc}");
        let json = format!(
            r#"{{"type":"PaymentExtendedSigningKeyShelley_ed25519_bip32","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let key = load_skey(f.path()).expect("parse");
        match key {
            CardanoKey::PaymentExtended { esk_64, pubkey_32 } => {
                assert_eq!(esk_64, [0x11u8; 64]);
                assert_eq!(pubkey_32, [0x22u8; 32]);
            }
            other => panic!("expected PaymentExtended, got {other:?}"),
        }
    }

    #[test]
    fn parses_drep_skey() {
        let cbor_hex = format!("5820{}", "55".repeat(32));
        let json = format!(
            r#"{{"type":"DRepSigningKey_ed25519","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let key = load_skey(f.path()).expect("parse");
        match key {
            CardanoKey::DRep { seed_32 } => assert_eq!(seed_32, [0x55u8; 32]),
            other => panic!("expected DRep, got {other:?}"),
        }
    }

    #[test]
    fn parses_drep_extended_skey() {
        let esk = "66".repeat(64);
        let pk = "77".repeat(32);
        let cc = "88".repeat(32);
        let cbor_hex = format!("5880{esk}{pk}{cc}");
        let json = format!(
            r#"{{"type":"DRepExtendedSigningKey_ed25519_bip32","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let key = load_skey(f.path()).expect("parse");
        match key {
            CardanoKey::DRepExtended { esk_64, pubkey_32 } => {
                assert_eq!(esk_64, [0x66u8; 64]);
                assert_eq!(pubkey_32, [0x77u8; 32]);
            }
            other => panic!("expected DRepExtended, got {other:?}"),
        }
    }

    #[test]
    fn rejects_extended_skey_wrong_length() {
        // 96 bytes where 128 expected -> BadCborHeader.
        let cbor_hex = format!("5860{}", "11".repeat(96));
        let json = format!(
            r#"{{"type":"StakeExtendedSigningKeyShelley_ed25519_bip32","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let err = load_skey(f.path()).expect_err("must reject");
        assert!(matches!(err, KeyLoadError::BadCborHeader { .. }));
    }
    #[test]
    fn rejects_wrong_length() {
        let cbor_hex = format!("5820{}", "00".repeat(32));
        let json = format!(
            r#"{{"type":"VrfSigningKey_PraosVRF","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let err = load_skey(f.path()).expect_err("must reject");
        assert!(matches!(err, KeyLoadError::BadCborHeader { .. }));
    }


    #[test]
    fn accepts_unknown_extra_field_for_forward_compat() {
        // future cardano-cli might add a new top-level field. The parser keeps
        // accepting the file so an upgraded cli does not break the signer.
        let cbor_hex = format!("5820{}", "42".repeat(32));
        let json = format!(
            r#"{{"type":"PaymentSigningKeyShelley_ed25519","description":"x","cborHex":"{cbor_hex}","futureField":42}}"#
        );
        let f = write_temp(&json);
        load_skey(f.path()).expect("forward-compat: unknown fields must not block parsing");
    }
    #[test]
    fn rejects_unknown_type() {
        let cbor_hex = format!("5820{}", "00".repeat(32));
        let json = format!(
            r#"{{"type":"SomeFutureKey_v9","description":"x","cborHex":"{cbor_hex}"}}"#
        );
        let f = write_temp(&json);
        let err = load_skey(f.path()).expect_err("must reject");
        assert!(matches!(err, KeyLoadError::UnsupportedType(t) if t == "SomeFutureKey_v9"));
    }
}
