//! Operator-PIN proof helper.
//!
//! Each sign-request carries an 8-byte `operator_pin_proof` derived from
//! the operator's 4-digit PIN, the operation kind, the
//! `chain_context.built_at_unix` of the request, and a fingerprint of the
//! request body (computed with the proof field itself blanked). The online
//! tool computes the proof at QR-build time; the signer recomputes it over
//! the body it received and refuses to sign on a mismatch.
//!
//! Request-bound on three axes, each domain-separated:
//!   * `kind` — a withdrawal proof does not satisfy a DRep verifier.
//!   * `built_at_unix` — a stale proof from a prior request does not match.
//!   * `body_fp` — a proof for one request body does not match a different
//!     body.
//!
//! What this layer does and does not defend against:
//!
//!   * It IS an operator-*presence* factor: the signer refuses to sign
//!     unless a human at the air-gapped machine retypes the PIN for every
//!     signature, so an unattended signer cannot be driven by feeding it
//!     requests alone.
//!   * It IS a mistake catcher: a request of the wrong kind, a stale
//!     request, or a body corrupted or mixed up in transit fails
//!     verification in code rather than relying on the operator to notice.
//!   * It is NOT code-enforced body integrity against an attacker. Every
//!     preimage input except the PIN (kind, built_at_unix, the body that
//!     body_fp is computed from) travels inside the request, so anyone who
//!     can read one request — e.g. after the static channel secret leaks
//!     from disk — can enumerate all 10^4 PINs offline against the observed
//!     proof, recover the PIN in microseconds, and then mint a valid proof
//!     for any swapped body. A salt would not change this: it would have to
//!     ship with the request too. No hash construction over a 4-digit
//!     secret and on-the-wire inputs can resist an offline attacker.
//!
//! The only defence against a body swap by an attacker who holds the
//! channel secret — or against a fully compromised online tool, which sees
//! the PIN directly — is the operator's out-of-band visual fingerprint
//! comparison against the signer's decrypted preview.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

/// Bytes of the truncated proof. 8 bytes (2^64) makes blindly guessing a
/// proof value infeasible, but the secret it attests is only a 4-digit
/// PIN — a 10^4 space, recoverable offline by anyone who observes one
/// valid proof (see module docs). The PIN is a proof of operator
/// *presence* (re-typed on the signer), not a brute-force-resistant
/// secret; `verify_pin` is constant-time.
pub const PIN_PROOF_LEN: usize = 8;

/// Domain-separation tag. Bumped to v3 when the proof gained the
/// request-body fingerprint (kind + built_at_unix + body_fp). A proof
/// computed under an older domain cannot satisfy a v3 verifier because the
/// domain bytes differ.
const PIN_DOMAIN: &[u8] = b"spo-tools-pin-v3\0";

/// Compute the hex-encoded operator-PIN proof for the given PIN, bound
/// to the request scope. Inputs are domain-separated and length-prefixed
/// so concatenation collisions across types are impossible.
pub fn pin_proof_hex(pin: &str, kind: &str, built_at_unix: u64, body_fp: &[u8]) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
    Update::update(&mut hasher, PIN_DOMAIN);
    Update::update(&mut hasher, &(kind.len() as u64).to_be_bytes());
    Update::update(&mut hasher, kind.as_bytes());
    Update::update(&mut hasher, &built_at_unix.to_be_bytes());
    Update::update(&mut hasher, &(body_fp.len() as u64).to_be_bytes());
    Update::update(&mut hasher, body_fp);
    Update::update(&mut hasher, &(pin.len() as u64).to_be_bytes());
    Update::update(&mut hasher, pin.as_bytes());
    let mut full = [0u8; 32];
    hasher.finalize_variable(&mut full).expect("blake2b finalize");
    let mut truncated = [0u8; PIN_PROOF_LEN];
    truncated.copy_from_slice(&full[..PIN_PROOF_LEN]);
    hex::encode(truncated)
}

/// Verify a typed PIN against an expected proof. Constant-time so the
/// signer's PIN dialog cannot be timed for brute-force attacks.
pub fn verify_pin(
    pin: &str,
    kind: &str,
    built_at_unix: u64,
    body_fp: &[u8],
    expected_proof_hex: &str,
) -> bool {
    let computed = pin_proof_hex(pin, kind, built_at_unix, body_fp);
    if computed.len() != expected_proof_hex.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (a, b) in computed.bytes().zip(expected_proof_hex.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Validate an operator-typed PIN. Must be exactly 4 ASCII digits.
pub fn validate_pin(pin: &str) -> Result<(), &'static str> {
    if pin.len() != 4 {
        return Err("operator PIN must be exactly 4 digits");
    }
    if !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("operator PIN must contain only digits 0-9");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &[u8] = b"\x01\x02\x03\x04\x05\x06\x07\x08";

    #[test]
    fn deterministic() {
        assert_eq!(
            pin_proof_hex("1234", "withdrawal", 1700000000, FP),
            pin_proof_hex("1234", "withdrawal", 1700000000, FP)
        );
    }

    #[test]
    fn different_pins_diverge() {
        assert_ne!(
            pin_proof_hex("1234", "withdrawal", 1700000000, FP),
            pin_proof_hex("1235", "withdrawal", 1700000000, FP)
        );
    }

    #[test]
    fn different_kinds_diverge() {
        assert_ne!(
            pin_proof_hex("1234", "withdrawal", 1700000000, FP),
            pin_proof_hex("1234", "drep_delegation", 1700000000, FP)
        );
    }

    #[test]
    fn different_built_at_diverge() {
        assert_ne!(
            pin_proof_hex("1234", "withdrawal", 1700000000, FP),
            pin_proof_hex("1234", "withdrawal", 1700000001, FP)
        );
    }

    #[test]
    fn different_body_fp_diverge() {
        assert_ne!(
            pin_proof_hex("1234", "withdrawal", 1700000000, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
            pin_proof_hex("1234", "withdrawal", 1700000000, b"\x08\x07\x06\x05\x04\x03\x02\x01")
        );
    }

    #[test]
    fn proof_len_is_16_hex_chars() {
        assert_eq!(pin_proof_hex("0000", "withdrawal", 0, FP).len(), 16);
    }

    #[test]
    fn verify_accepts_correct_pin() {
        let proof = pin_proof_hex("4321", "kes_rotation", 42, FP);
        assert!(verify_pin("4321", "kes_rotation", 42, FP, &proof));
    }

    #[test]
    fn verify_rejects_wrong_pin() {
        let proof = pin_proof_hex("4321", "kes_rotation", 42, FP);
        assert!(!verify_pin("4322", "kes_rotation", 42, FP, &proof));
    }

    #[test]
    fn verify_rejects_wrong_kind() {
        let proof = pin_proof_hex("4321", "kes_rotation", 42, FP);
        assert!(!verify_pin("4321", "withdrawal", 42, FP, &proof));
    }

    #[test]
    fn verify_rejects_wrong_built_at() {
        let proof = pin_proof_hex("4321", "kes_rotation", 42, FP);
        assert!(!verify_pin("4321", "kes_rotation", 43, FP, &proof));
    }

    #[test]
    fn verify_rejects_wrong_body_fp() {
        let proof = pin_proof_hex("4321", "kes_rotation", 42, FP);
        assert!(!verify_pin("4321", "kes_rotation", 42, b"\xff\xff\xff\xff\xff\xff\xff\xff", &proof));
    }

    #[test]
    fn verify_rejects_empty_proof() {
        assert!(!verify_pin("1234", "withdrawal", 0, FP, ""));
    }

    #[test]
    fn validate_accepts_valid_pin() {
        assert!(validate_pin("1234").is_ok());
        assert!(validate_pin("0000").is_ok());
    }

    #[test]
    fn validate_rejects_wrong_length() {
        assert!(validate_pin("123").is_err());
        assert!(validate_pin("12345").is_err());
        assert!(validate_pin("").is_err());
    }

    #[test]
    fn validate_rejects_non_digits() {
        assert!(validate_pin("12a4").is_err());
        assert!(validate_pin("abcd").is_err());
    }

    /// Cross-implementation known-answer vectors. The expected proofs were
    /// produced independently by Python's `hashlib.blake2b(data,
    /// digest_size=32)` over the exact domain-separated, length-prefixed
    /// preimage (`spo-tools-pin-v3\0` ‖ be64(len kind) ‖ kind ‖
    /// be64(built_at) ‖ be64(len body_fp) ‖ body_fp ‖ be64(len pin) ‖ pin).
    /// They pin the byte-exact proof contract shared by the online tool
    /// (which builds the proof) and the signer (which verifies it): a silent
    /// change to PIN_DOMAIN, the field order, or the truncation width — none
    /// of which the relational tests above would catch — is caught here.
    #[test]
    fn known_answer_vectors() {
        assert_eq!(pin_proof_hex("1234", "withdrawal", 1_700_000_000, FP), "0609cf5c27c7d0d4");
        assert_eq!(pin_proof_hex("4321", "kes_rotation", 42, FP), "9c521709410343b6");
        assert_eq!(pin_proof_hex("0000", "vote", 0, FP), "27beed34193d8f15");
    }
}
