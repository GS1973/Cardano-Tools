//! UR (Uniform Resources) encoding for the QR transport between the
//! online tool and the offline signer.
//!
//! Bytes are wrapped into one or more UR strings (`ur:type/...`). The
//! browser turns those strings into QR codes; the signer's webcam reads
//! them back into strings, which this module decodes into bytes.
//!
//! Multi-part / fountain encoding inside the `ur` crate handles robustness
//! across animated frames — if a frame is missed, the receiver eventually
//! recovers from later frames.
//!
//! Two UR type tags are in active use:
//!
//!   * `spo-tools-action-v2` — operational payloads (withdrawal, leaderlog,
//!     drep, pool update, kes rotation). The body is sealed via
//!     [`crate::crypto::seal`]: `nonce(24) || XChaCha20-Poly1305(plaintext)`.
//!   * `spo-tools-pairing-v1` — one-shot pubkey-exchange payloads, plain
//!     bytes (the pubkey itself is public; physical co-presence + the
//!     pairing fingerprint are what authenticate the channel).
//!
//! Only `spo-tools-action-v2` is accepted as the action UR type tag.
//! An unknown or mismatched tag surfaces as a clean TypeMismatch so the
//! receiver can refuse the payload before any crypto runs.

use thiserror::Error;

use crate::crypto::{self, KEY_LEN};

/// UR type tag for encrypted operational payloads.
pub const UR_TYPE_ACTION: &str = "spo-tools-action-v2";
/// UR type tag for plaintext pairing payloads.
pub const UR_TYPE_PAIRING: &str = "spo-tools-pairing-v1";

/// Direction of an encrypted action frame, bound into the AEAD as
/// associated data so a request frame and a response frame are not
/// interchangeable at the crypto layer even though they share the
/// static-static channel key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    fn tag(self) -> u8 {
        match self {
            Direction::Request => 0x01,
            Direction::Response => 0x02,
        }
    }
}

/// Associated data bound into every encrypted action frame: a direction
/// byte followed by the UR type tag. The AEAD tag then covers both the
/// message direction and the payload type, so neither can be swapped under
/// a valid tag.
fn action_aad(direction: Direction) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + UR_TYPE_ACTION.len());
    aad.push(direction.tag());
    aad.extend_from_slice(UR_TYPE_ACTION.as_bytes());
    aad
}

/// Maximum bytes per UR fragment. UR is base32-encoded so the resulting
/// QR string is roughly 1.6× the byte length; a value around 200 keeps each
/// frame well below the practical QR-V40 capacity and easy for cameras to
/// decode at frame-rate.
const MAX_FRAGMENT_LEN: usize = 200;

/// Hard upper bound on the number of UR fragments a single payload may
/// span. Realistic SPO payloads (the largest is a pool-update tx body
/// with full relay/metadata) fit in a few dozen fragments at MAX_FRAGMENT_LEN.
/// Capping prevents a malicious payload from causing the decoder to
/// allocate unbounded memory before failing.
const MAX_FRAGMENTS: usize = 256;

#[derive(Debug, Error)]
pub enum QrError {
    #[error("UR encoding error: {0}")]
    Encode(String),
    #[error("UR decoding error: {0}")]
    Decode(String),
    #[error("UR type mismatch: expected `{expected}`, got `{got}`")]
    TypeMismatch { expected: String, got: String },
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
}

/// Inspect the first UR fragment string and pull its type prefix out.
/// Each fragment looks like `ur:<type>/...`; this returns the `<type>`.
fn type_of_fragment(fragment: &str) -> Option<&str> {
    let rest = fragment.strip_prefix("ur:")?;
    let slash = rest.find('/')?;
    Some(&rest[..slash])
}

/// Internal encoder shared by the action and pairing paths.
fn encode_with_tag(bytes: &[u8], ur_type: &str) -> Result<Vec<String>, QrError> {
    let mut encoder = ur::Encoder::new(bytes, MAX_FRAGMENT_LEN, ur_type)
        .map_err(|e| QrError::Encode(e.to_string()))?;
    let count = encoder.fragment_count();
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        parts.push(
            encoder
                .next_part()
                .map_err(|e| QrError::Encode(e.to_string()))?,
        );
    }
    Ok(parts)
}

/// Internal decoder shared by the action and pairing paths. Verifies the
/// caller-expected UR type tag before feeding bytes into the decoder.
fn decode_with_tag(parts: &[String], expected_type: &str) -> Result<Option<Vec<u8>>, QrError> {
    // Verify the UR type tag on EVERY fragment, not just the first. The
    // ur decoder infers the type from the first part it sees, so a mixed
    // set (e.g. a pairing fragment smuggled into an action sequence) would
    // otherwise pass this gate on the strength of fragment 0 alone.
    for part in parts {
        match type_of_fragment(part) {
            Some(t) if t == expected_type => {}
            Some(other) => {
                return Err(QrError::TypeMismatch {
                    expected: expected_type.into(),
                    got: other.to_string(),
                });
            }
            None => {
                return Err(QrError::Decode(format!(
                    "fragment is not a UR string: {part}"
                )));
            }
        }
    }

    if parts.len() > MAX_FRAGMENTS {
        return Err(QrError::Decode(format!(
            "too many fragments: {} > MAX_FRAGMENTS={MAX_FRAGMENTS}",
            parts.len()
        )));
    }
    let mut decoder = ur::Decoder::default();
    for part in parts {
        decoder
            .receive(part)
            .map_err(|e| QrError::Decode(e.to_string()))?;
        if decoder.complete() {
            let maybe_message = decoder
                .message()
                .map_err(|e| QrError::Decode(e.to_string()))?;
            return match maybe_message {
                Some(message) => Ok(Some(message)),
                None => Err(QrError::Decode(
                    "decoder reported complete but produced no message".into(),
                )),
            };
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Encrypted action payloads (the operational path)
// ---------------------------------------------------------------------------

/// Seal `plaintext` for the peer and wrap the resulting bytes in UR
/// fragments tagged `spo-tools-action-v2`. Caller renders each string as
/// a QR frame; an animated sequence cycles through them.
pub fn encode_encrypted_payload(
    plaintext: &[u8],
    peer_pk: &[u8; KEY_LEN],
    own_sk: &[u8; KEY_LEN],
    direction: Direction,
) -> Result<Vec<String>, QrError> {
    let wire = crypto::seal(plaintext, peer_pk, own_sk, &action_aad(direction))?;
    encode_with_tag(&wire, UR_TYPE_ACTION)
}

/// Decode a sequence of `spo-tools-action-v2` UR fragments and unseal the
/// inner bytes. Returns `Ok(Some(plaintext))` once the full message is
/// reconstructed and decryption succeeds, `Ok(None)` if more frames are
/// still needed.
pub fn decode_encrypted_parts(
    parts: &[String],
    peer_pk: &[u8; KEY_LEN],
    own_sk: &[u8; KEY_LEN],
    direction: Direction,
) -> Result<Option<Vec<u8>>, QrError> {
    match decode_with_tag(parts, UR_TYPE_ACTION)? {
        None => Ok(None),
        Some(wire) => {
            let plaintext = crypto::unseal(&wire, peer_pk, own_sk, &action_aad(direction))?;
            Ok(Some(plaintext))
        }
    }
}

// ---------------------------------------------------------------------------
// Plaintext pairing payloads (the bootstrap path)
// ---------------------------------------------------------------------------

/// Wrap a pairing payload (typically a JSON blob carrying the pubkey) in
/// UR fragments tagged `spo-tools-pairing-v1`. Pairing payloads are
/// plaintext on purpose — pubkeys are public and the integrity check is
/// the visual fingerprint comparison the SPO performs after pairing.
pub fn encode_pairing_payload(plaintext: &[u8]) -> Result<Vec<String>, QrError> {
    encode_with_tag(plaintext, UR_TYPE_PAIRING)
}

/// Decode a `spo-tools-pairing-v1` UR fragment sequence back into the
/// original plaintext bytes.
pub fn decode_pairing_parts(parts: &[String]) -> Result<Option<Vec<u8>>, QrError> {
    decode_with_tag(parts, UR_TYPE_PAIRING)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
        let kp = crypto::generate_keypair().unwrap();
        (*kp.secret, kp.public)
    }

    #[test]
    fn encrypted_roundtrip_small_payload() {
        let (alice_sk, alice_pk) = keypair();
        let (bob_sk, bob_pk) = keypair();
        let original = b"hello bob from alice";
        let parts = encode_encrypted_payload(original, &bob_pk, &alice_sk, Direction::Request).expect("encode");
        assert!(!parts.is_empty());
        let decoded = decode_encrypted_parts(&parts, &alice_pk, &bob_sk, Direction::Request)
            .expect("decode")
            .expect("complete");
        assert_eq!(decoded.as_slice(), original);
    }

    #[test]
    fn encrypted_roundtrip_multi_part_payload() {
        let (alice_sk, _alice_pk) = keypair();
        let (bob_sk, bob_pk) = keypair();
        let alice_pk = crypto::public_from_secret(&alice_sk);
        let original: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
        let parts = encode_encrypted_payload(&original, &bob_pk, &alice_sk, Direction::Request).expect("encode");
        assert!(parts.len() > 1, "expected multi-part, got {}", parts.len());
        let decoded = decode_encrypted_parts(&parts, &alice_pk, &bob_sk, Direction::Request)
            .expect("decode")
            .expect("complete");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encrypted_rejects_decryption_with_wrong_peer() {
        let (alice_sk, _alice_pk) = keypair();
        let (bob_sk, bob_pk) = keypair();
        let (_mallory_sk, mallory_pk) = keypair();
        let parts = encode_encrypted_payload(b"private", &bob_pk, &alice_sk, Direction::Request).unwrap();
        let err = decode_encrypted_parts(&parts, &mallory_pk, &bob_sk, Direction::Request).unwrap_err();
        assert!(matches!(err, QrError::Crypto(_)));
    }

    #[test]
    fn decode_rejects_direction_mismatch() {
        let (alice_sk, alice_pk) = keypair();
        let (bob_sk, bob_pk) = keypair();
        // Sealed as a request; replaying it as a response frame must fail at
        // the AEAD layer because the bound associated data differs.
        let parts =
            encode_encrypted_payload(b"req-only", &bob_pk, &alice_sk, Direction::Request).unwrap();
        let err =
            decode_encrypted_parts(&parts, &alice_pk, &bob_sk, Direction::Response).unwrap_err();
        assert!(matches!(err, QrError::Crypto(_)));
    }

    #[test]
    fn pairing_roundtrip() {
        let original = br#"{"role":"signer","pubkey_hex":"deadbeef"}"#;
        let parts = encode_pairing_payload(original).expect("encode");
        let decoded = decode_pairing_parts(&parts).expect("decode").expect("complete");
        assert_eq!(decoded.as_slice(), original);
    }

    #[test]
    fn rejects_wrong_action_type() {
        let bad = vec!["ur:spo-tools-pairing-v1/abc".to_string()];
        let (alice_sk, _) = keypair();
        let (_, bob_pk) = keypair();
        match decode_encrypted_parts(&bad, &bob_pk, &alice_sk, Direction::Request) {
            Err(QrError::TypeMismatch { expected, got }) => {
                assert_eq!(expected, UR_TYPE_ACTION);
                assert_eq!(got, UR_TYPE_PAIRING);
            }
            other => panic!("expected TypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_mixed_fragment_types() {
        // Fragment 0 carries the expected action type; a later fragment is
        // a pairing fragment. Every fragment is tag-checked, so the set is
        // rejected even though fragment 0 looks right on its own.
        let (alice_sk, _) = keypair();
        let (_, bob_pk) = keypair();
        let mixed = vec![
            "ur:spo-tools-action-v2/1-2/abc".to_string(),
            "ur:spo-tools-pairing-v1/2-2/def".to_string(),
        ];
        match decode_encrypted_parts(&mixed, &bob_pk, &alice_sk, Direction::Request) {
            Err(QrError::TypeMismatch { expected, got }) => {
                assert_eq!(expected, UR_TYPE_ACTION);
                assert_eq!(got, UR_TYPE_PAIRING);
            }
            other => panic!("expected TypeMismatch on the mixed fragment, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_pairing_type() {
        let bad = vec!["ur:spo-tools-action-v2/abc".to_string()];
        match decode_pairing_parts(&bad) {
            Err(QrError::TypeMismatch { expected, got }) => {
                assert_eq!(expected, UR_TYPE_PAIRING);
                assert_eq!(got, UR_TYPE_ACTION);
            }
            other => panic!("expected TypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage_input() {
        let bad = vec!["not-a-ur-string".to_string()];
        assert!(decode_pairing_parts(&bad).is_err());
    }
}
