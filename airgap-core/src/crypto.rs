//! Channel-encryption layer between online tool and signer.
//!
//! On first run each side generates an X25519 static keypair and saves
//! it on disk. During pairing each side scans the other's pubkey QR; the
//! resulting fingerprint (derived from both pubkeys, byte-canonicalised
//! so both sides land on the same 16 bytes / 128 bits) is compared
//! visually so any MITM substitution is caught.
//!
//! Once paired, every operational UR payload is sealed:
//!   `[24-byte nonce || XChaCha20-Poly1305(plaintext, key=KDF(ECDH(...)))]`
//!
//! Threat-model coverage:
//!   * Passive observer of the QR channel: nothing useful in the bytes.
//!   * Active QR substitution after pairing: AEAD tag fails to verify.
//!   * MITM during pairing: fingerprint mismatch surfaces visually.
//!
//! Out of scope: a fully compromised endpoint (the holder of the static
//! secret can encrypt or decrypt by definition; the body validator in
//! `tx_validator` is the right defence for that scenario).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// Fixed-output 32-byte Blake2b. The fixed-output API keeps init and
/// finalize infallible, so callers do not need to handle a runtime
/// panic from those steps.
type Blake2b256 = Blake2b<U32>;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Length of an X25519 secret or public key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of the AEAD tag (Poly1305) in bytes.
pub const TAG_LEN: usize = 16;
/// Bytes every wire frame adds to its plaintext: the 24-byte nonce in
/// front and the 16-byte Poly1305 tag after the ciphertext.
pub const WIRE_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
/// Length of the human-comparable fingerprint, in bytes (32 hex chars,
/// rendered as eight groups of four). 2^128 search-space puts realtime
/// keypair-grinding during the pairing window cryptographically out of
/// reach.
pub const FINGERPRINT_LEN: usize = 16;

/// Domain separator for the AEAD-key derivation. Including a fixed string
/// means the same X25519 keypair could safely be reused for a different
/// purpose later without key collisions.
const KDF_DOMAIN: &[u8] = b"spo-tools/v1/channel-aead-key";
/// Domain separator for the pairing fingerprint.
const FINGERPRINT_DOMAIN: &[u8] = b"spo-tools/v1/pairing-fingerprint";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("system entropy unavailable: {0}")]
    Entropy(String),
    #[error("AEAD encryption failed")]
    Encrypt,
    #[error("AEAD decryption failed (wrong peer key, tampered ciphertext, or pairing mismatch)")]
    Decrypt,
    #[error(
        "ciphertext too short ({0} bytes, need at least {NONCE_LEN}+{TAG_LEN}={WIRE_OVERHEAD})"
    )]
    ShortCiphertext(usize),
    #[error("invalid key length: expected {KEY_LEN}, got {0}")]
    BadKeyLength(usize),
    #[error("invalid hex: {0}")]
    BadHex(String),
    #[error("peer public key is low-order: rejected to prevent the all-zero shared-secret attack")]
    LowOrderPeerPubkey,
}

/// A freshly-generated static X25519 keypair, ready to be persisted. The
/// secret is held in a `Zeroizing` wrapper so the in-RAM copy is wiped when
/// dropped; the caller persists it (hex, under a 0600 file: plaintext on
/// disk by design) and uses it to derive the channel AEAD key.
pub struct GeneratedKeypair {
    pub secret: Zeroizing<[u8; KEY_LEN]>,
    pub public: [u8; KEY_LEN],
}

/// Generate a new X25519 static keypair using OS entropy. The caller is
/// responsible for persisting the secret to disk; the public part is what
/// gets shown in the pairing QR.
pub fn generate_keypair() -> Result<GeneratedKeypair, CryptoError> {
    let mut sk_bytes = [0u8; KEY_LEN];
    getrandom::getrandom(&mut sk_bytes).map_err(|e| CryptoError::Entropy(e.to_string()))?;
    let secret = StaticSecret::from(sk_bytes);
    let public = PublicKey::from(&secret);
    let out = GeneratedKeypair {
        secret: Zeroizing::new(sk_bytes),
        public: public.to_bytes(),
    };
    sk_bytes.zeroize();
    Ok(out)
}

/// Re-derive the public key for a stored secret. Used at boot when the
/// secret is loaded from config.
pub fn public_from_secret(secret: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Reject a peer X25519 public key whose ECDH with this side's secret
/// produces an all-zero shared secret. That happens for the eight known
/// low-order Curve25519 points (and any tampered key sharing the same
/// property), where an attacker can force the AEAD key to a fixed
/// deterministic value. Called from the pairing handler before the
/// pubkey is persisted, so even an SPO who skips the visual fingerprint
/// compare cannot end up paired with a degenerate peer.
pub fn validate_peer_pubkey(
    peer_pk: &[u8; KEY_LEN],
    own_sk: &[u8; KEY_LEN],
) -> Result<(), CryptoError> {
    let secret = StaticSecret::from(*own_sk);
    let peer = PublicKey::from(*peer_pk);
    let shared = secret.diffie_hellman(&peer);
    if shared.as_bytes() == &[0u8; KEY_LEN] {
        return Err(CryptoError::LowOrderPeerPubkey);
    }
    Ok(())
}

/// Derive the channel AEAD key from ECDH(own_sk, peer_pk). Returned in a
/// `Zeroizing` wrapper: the key carries the same authority as the static
/// secret, so it gets the same wipe-on-drop treatment.
fn derive_aead_key(own_sk: &[u8; KEY_LEN], peer_pk: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let secret = StaticSecret::from(*own_sk);
    let peer = PublicKey::from(*peer_pk);
    let shared = secret.diffie_hellman(&peer);
    let mut hasher = Blake2b256::new();
    hasher.update(KDF_DOMAIN);
    hasher.update(shared.as_bytes());
    let result = hasher.finalize();
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&result);
    key
}

/// Encrypt `plaintext` for the peer identified by `peer_pk`, using the
/// caller's `own_sk`. Output layout: `nonce(24) || ciphertext_with_tag`.
/// `aad` is authenticated but not encrypted: it is bound into the tag so a
/// frame sealed for one context (e.g. a request) cannot be reinterpreted in
/// another (a response). `unseal` must pass the same `aad` or decryption
/// fails closed.
pub fn seal(
    plaintext: &[u8],
    peer_pk: &[u8; KEY_LEN],
    own_sk: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_aead_key(own_sk, peer_pk);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .expect("XChaCha20Poly1305 expects exactly 32-byte key");
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| CryptoError::Entropy(e.to_string()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a wire frame produced by [`seal`]. Input layout:
/// `nonce(24) || ciphertext_with_tag`. `aad` must match the value passed to
/// `seal`; a mismatch fails closed as [`CryptoError::Decrypt`].
pub fn unseal(
    wire: &[u8],
    peer_pk: &[u8; KEY_LEN],
    own_sk: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if wire.len() < WIRE_OVERHEAD {
        return Err(CryptoError::ShortCiphertext(wire.len()));
    }
    let (nonce_bytes, ct) = wire.split_at(NONCE_LEN);
    let key = derive_aead_key(own_sk, peer_pk);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .expect("XChaCha20Poly1305 expects exactly 32-byte key");
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Decrypt)
}

/// 16-byte (128-bit) pairing fingerprint, derived from both pubkeys
/// with a canonical byte-order so both sides compute the same value.
/// `FINGERPRINT_LEN` is the source of truth.
pub fn fingerprint(p_a: &[u8; KEY_LEN], p_b: &[u8; KEY_LEN]) -> [u8; FINGERPRINT_LEN] {
    let (low, high) = if p_a <= p_b { (p_a, p_b) } else { (p_b, p_a) };
    let mut hasher = Blake2b256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(low);
    hasher.update(high);
    let result = hasher.finalize();
    let mut out = [0u8; FINGERPRINT_LEN];
    out.copy_from_slice(&result[..FINGERPRINT_LEN]);
    out
}

/// Derive the (paired, fingerprint_display) pair from the two
/// hex-encoded keys stored in the binary's config. Returns
/// `(false, None)` when either key is missing or unparseable:
/// matches the behaviour both binaries' setup responses expect when
/// pairing has not been completed yet.
pub fn pairing_status(
    own_skey_hex: Option<&str>,
    peer_pubkey_hex: Option<&str>,
) -> (bool, Option<String>) {
    let (Some(own), Some(peer)) = (own_skey_hex, peer_pubkey_hex) else {
        return (false, None);
    };
    let (Ok(own_sk), Ok(peer_pk)) = (key_from_hex(own), key_from_hex(peer)) else {
        return (false, None);
    };
    let own_pk = public_from_secret(&own_sk);
    let fp = fingerprint(&own_pk, &peer_pk);
    (true, Some(fingerprint_display(&fp)))
}

/// Format a fingerprint as `a37f-2c91-5be2-c8d4` (groups of 4 hex chars
/// separated by hyphens) for visual comparison on screen.
pub fn fingerprint_display(fp: &[u8; FINGERPRINT_LEN]) -> String {
    let hex = hex::encode(fp);
    let mut out = String::with_capacity(hex.len() + (hex.len() / 4) - 1);
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// Parse a 32-byte hex string into a key. Used for both X25519 secrets
/// and public keys at config boundary.
pub fn key_from_hex(hex_str: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let bytes = hex::decode(hex_str).map_err(|e| CryptoError::BadHex(e.to_string()))?;
    if bytes.len() != KEY_LEN {
        return Err(CryptoError::BadKeyLength(bytes.len()));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &[u8] = b"unit-test-aad";

    #[test]
    fn keypair_roundtrip_via_public_from_secret() {
        let kp = generate_keypair().unwrap();
        assert_eq!(public_from_secret(&kp.secret), kp.public);
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let alice = generate_keypair().unwrap();
        let bob = generate_keypair().unwrap();
        let plaintext = b"hello bob, this is alice's secret";
        let wire = seal(plaintext, &bob.public, &alice.secret, AAD).unwrap();
        // Wire must carry at least the 40-byte overhead.
        assert!(wire.len() >= WIRE_OVERHEAD);
        let recovered = unseal(&wire, &alice.public, &bob.secret, AAD).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn unseal_with_wrong_peer_fails() {
        let alice = generate_keypair().unwrap();
        let bob = generate_keypair().unwrap();
        let mallory = generate_keypair().unwrap();
        let wire = seal(b"private", &bob.public, &alice.secret, AAD).unwrap();
        // Bob tries to decrypt thinking it came from Mallory: AEAD tag fails.
        let err = unseal(&wire, &mallory.public, &bob.secret, AAD).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn unseal_rejects_short_input() {
        let alice = generate_keypair().unwrap();
        let bob = generate_keypair().unwrap();
        let err = unseal(&[1u8; 10], &alice.public, &bob.secret, AAD).unwrap_err();
        assert!(matches!(err, CryptoError::ShortCiphertext(10)));
    }

    #[test]
    fn unseal_rejects_tampered_ciphertext() {
        let alice = generate_keypair().unwrap();
        let bob = generate_keypair().unwrap();
        let mut wire = seal(b"clean", &bob.public, &alice.secret, AAD).unwrap();
        // Flip a bit in the ciphertext region (after the nonce).
        wire[NONCE_LEN + 1] ^= 0x01;
        let err = unseal(&wire, &alice.public, &bob.secret, AAD).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn unseal_rejects_aad_mismatch() {
        let alice = generate_keypair().unwrap();
        let bob = generate_keypair().unwrap();
        let wire = seal(b"ctx-bound", &bob.public, &alice.secret, b"request").unwrap();
        // Same keys, but a different aad (e.g. a response context): rejected.
        let err = unseal(&wire, &alice.public, &bob.secret, b"response").unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn fingerprint_is_canonical_in_argument_order() {
        let alice = generate_keypair().unwrap();
        let bob = generate_keypair().unwrap();
        let fp_ab = fingerprint(&alice.public, &bob.public);
        let fp_ba = fingerprint(&bob.public, &alice.public);
        assert_eq!(fp_ab, fp_ba, "fingerprint must be order-invariant");
    }

    #[test]
    fn fingerprint_changes_when_either_pubkey_changes() {
        let alice = generate_keypair().unwrap();
        let bob = generate_keypair().unwrap();
        let mallory = generate_keypair().unwrap();
        let fp_ab = fingerprint(&alice.public, &bob.public);
        let fp_am = fingerprint(&alice.public, &mallory.public);
        let fp_mb = fingerprint(&mallory.public, &bob.public);
        assert_ne!(fp_ab, fp_am);
        assert_ne!(fp_ab, fp_mb);
        assert_ne!(fp_am, fp_mb);
    }

    #[test]
    fn fingerprint_display_groups_of_four() {
        let fp = [
            0xa3, 0x7f, 0x2c, 0x91, 0x5b, 0xe2, 0xc8, 0xd4, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
            0x70, 0x80,
        ];
        assert_eq!(
            fingerprint_display(&fp),
            "a37f-2c91-5be2-c8d4-1020-3040-5060-7080",
        );
    }

    #[test]
    fn key_from_hex_round_trip() {
        let kp = generate_keypair().unwrap();
        let s = hex::encode(kp.public);
        assert_eq!(key_from_hex(&s).unwrap(), kp.public);
    }

    #[test]
    fn key_from_hex_rejects_wrong_length() {
        let err = key_from_hex("deadbeef").unwrap_err();
        assert!(matches!(err, CryptoError::BadKeyLength(4)));
    }

    #[test]
    fn key_from_hex_rejects_invalid_chars() {
        let err = key_from_hex("zzzz").unwrap_err();
        assert!(matches!(err, CryptoError::BadHex(_)));
    }

    #[test]
    fn rejects_low_order_peer_pubkey() {
        let alice = generate_keypair().unwrap();
        // Curve25519 small-subgroup point: order 1, ECDH always 0.
        let evil = [0u8; 32];
        let err = validate_peer_pubkey(&evil, &alice.secret).unwrap_err();
        assert!(matches!(err, CryptoError::LowOrderPeerPubkey));
    }

    #[test]
    fn accepts_normal_peer_pubkey() {
        let alice = generate_keypair().unwrap();
        let bob = generate_keypair().unwrap();
        validate_peer_pubkey(&bob.public, &alice.secret).expect("normal pubkey ok");
    }
}
