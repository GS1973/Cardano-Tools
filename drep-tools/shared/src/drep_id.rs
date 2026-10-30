//! DRep id decoding: bech32 `drep1...` to the 28-byte credential hash.
//!
//! A key-based DRep is identified on-chain by `blake2b-224(drep_vkey)`, a
//! 28-byte key hash, carried in certs and votes as
//! `StakeCredential::AddrKeyhash(hash)`. The operator-facing `drep1...`
//! bech32 string comes in two shapes:
//!
//! - **CIP-105 (legacy):** `bech32("drep", 28-byte hash)`: the bare key
//!   hash, no header.
//! - **CIP-129 (current):** `bech32("drep", header_byte ++ 28-byte hash)`
//!   where the header is `0x22` for a key-hash DRep and `0x23` for a
//!   script-hash DRep.
//!
//! cardano-cli has emitted both over time, so this accepts either and
//! always returns the 28-byte key hash. Script-hash DReps (`0x23`) are
//! rejected: this tool manages a key-based DRep only.

use thiserror::Error;

const HRP: &str = "drep";
const HASH_LEN: usize = 28;
/// CIP-129 header byte for a key-hash DRep credential
/// (high nibble `0010` = DRep, low nibble `0010` = key hash).
const CIP129_KEY_HEADER: u8 = 0x22;
/// CIP-129 header byte for a script-hash DRep credential.
const CIP129_SCRIPT_HEADER: u8 = 0x23;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DrepIdError {
    #[error("invalid bech32 `{0}`: {1}")]
    Bech32(String, String),
    #[error("wrong bech32 prefix: expected `drep1...`, got `{0}1...`")]
    WrongHrp(String),
    #[error("script-hash DReps are not supported (this tool manages a key-based DRep)")]
    ScriptDrep,
    #[error("unexpected DRep id length {len} (expected 28 raw bytes or 29 with a CIP-129 header)")]
    BadLength { len: usize },
    #[error("unknown CIP-129 DRep header byte 0x{0:02x}")]
    BadHeader(u8),
}

/// Decode a `drep1...` bech32 (CIP-105 or CIP-129) to its 28-byte key
/// hash. Rejects script-hash DReps.
pub fn drep_id_to_keyhash(bech32_str: &str) -> Result<[u8; HASH_LEN], DrepIdError> {
    let (hrp, data) = bech32::decode(bech32_str)
        .map_err(|e| DrepIdError::Bech32(bech32_str.to_string(), e.to_string()))?;
    if hrp.as_str() != HRP {
        return Err(DrepIdError::WrongHrp(hrp.as_str().to_string()));
    }
    let hash = match data.len() {
        // CIP-105: bare 28-byte key hash.
        HASH_LEN => &data[..],
        // CIP-129: 1 header byte + 28-byte hash.
        n if n == HASH_LEN + 1 => match data[0] {
            CIP129_KEY_HEADER => &data[1..],
            CIP129_SCRIPT_HEADER => return Err(DrepIdError::ScriptDrep),
            other => return Err(DrepIdError::BadHeader(other)),
        },
        n => return Err(DrepIdError::BadLength { len: n }),
    };
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hash);
    Ok(out)
}

/// Render a 28-byte DRep key hash as a CIP-129 `drep1...` bech32 string:
/// the key-hash header byte `0x22`, then the hash. This is the form recent
/// cardano-cli emits.
pub fn keyhash_to_cip129(keyhash: &[u8; HASH_LEN]) -> String {
    let mut data = Vec::with_capacity(1 + HASH_LEN);
    data.push(CIP129_KEY_HEADER);
    data.extend_from_slice(keyhash);
    let hrp = bech32::Hrp::parse(HRP).expect("static hrp");
    bech32::encode::<bech32::Bech32>(hrp, &data).expect("bech32 encode")
}

/// Render a 28-byte DRep key hash as a legacy CIP-105 `drep1...` bech32
/// string (the bare key hash, no header byte).
pub fn keyhash_to_cip105(keyhash: &[u8; HASH_LEN]) -> String {
    let hrp = bech32::Hrp::parse(HRP).expect("static hrp");
    bech32::encode::<bech32::Bech32>(hrp, keyhash).expect("bech32 encode")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(hrp: &str, data: &[u8]) -> String {
        let hrp = bech32::Hrp::parse(hrp).unwrap();
        bech32::encode::<bech32::Bech32>(hrp, data).unwrap()
    }

    #[test]
    fn decodes_cip105_bare_hash() {
        let key = [0xABu8; 28];
        let s = encode("drep", &key);
        assert_eq!(drep_id_to_keyhash(&s).unwrap(), key);
    }

    #[test]
    fn decodes_cip129_key_header() {
        let key = [0x11u8; 28];
        let mut data = vec![CIP129_KEY_HEADER];
        data.extend_from_slice(&key);
        let s = encode("drep", &data);
        assert_eq!(drep_id_to_keyhash(&s).unwrap(), key);
    }

    #[test]
    fn rejects_cip129_script_header() {
        let key = [0x22u8; 28];
        let mut data = vec![CIP129_SCRIPT_HEADER];
        data.extend_from_slice(&key);
        let s = encode("drep", &data);
        assert_eq!(drep_id_to_keyhash(&s), Err(DrepIdError::ScriptDrep));
    }

    #[test]
    fn rejects_unknown_header() {
        let key = [0x33u8; 28];
        let mut data = vec![0x99u8];
        data.extend_from_slice(&key);
        let s = encode("drep", &data);
        assert_eq!(drep_id_to_keyhash(&s), Err(DrepIdError::BadHeader(0x99)));
    }

    #[test]
    fn rejects_wrong_hrp() {
        let s = encode("pool", &[0u8; 28]);
        assert!(matches!(
            drep_id_to_keyhash(&s),
            Err(DrepIdError::WrongHrp(_))
        ));
    }

    #[test]
    fn rejects_bad_length() {
        let s = encode("drep", &[0u8; 20]);
        assert!(matches!(
            drep_id_to_keyhash(&s),
            Err(DrepIdError::BadLength { len: 20 })
        ));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            drep_id_to_keyhash("not-bech32"),
            Err(DrepIdError::Bech32(_, _))
        ));
    }

    // A synthetic CIP-129 DRep id and its 28-byte keyhash (header 0x22 +
    // hash) form a fixed known-answer vector for the decoder. Not a real DRep.
    #[test]
    fn matches_known_answer_pair() {
        let drep = "drep1ygqpzg3ng32kvaugnx4thnxaamlsqyfzxdz92enh3zv64wc0h3n2d";
        let expected =
            hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabb").unwrap();
        assert_eq!(
            drep_id_to_keyhash(drep).unwrap().as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn encoders_round_trip_with_decoder() {
        let keyhash = [0x7Cu8; 28];
        let c129 = keyhash_to_cip129(&keyhash);
        let c105 = keyhash_to_cip105(&keyhash);
        assert!(c129.starts_with("drep1") && c105.starts_with("drep1"));
        assert_eq!(drep_id_to_keyhash(&c129).unwrap(), keyhash);
        assert_eq!(drep_id_to_keyhash(&c105).unwrap(), keyhash);
    }
}
