//! Per-request fingerprint helper.
//!
//! Same blake2b-256-then-truncate pattern as the pairing fingerprint
//! (which keeps 16 bytes), but truncated to 8 bytes and applied
//! per-operation: the online tool computes it over the canonical
//! request bytes and shows it next to the QR; the signer recomputes it
//! after decrypting and shows it next to the preview. The operator
//! visually compares the two.
//!
//! Goal is operator-visible coupling between the request the online
//! tool *built* and the request the signer *received*. A compromised
//! signer state-file or a swapped UR fragment cannot match a
//! visually-verified fingerprint, because the operator only signs
//! after the two agree.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

/// Truncated blake2b-256 over the canonical request bytes. 8 bytes —
/// half the width of the 16-byte pairing fingerprint — gives 2^64
/// search space: enough to defeat any realistic on-the-fly forgery
/// while staying short enough for an operator to visually compare in
/// one glance.
pub fn request_fingerprint(json_bytes: &[u8]) -> [u8; 8] {
    let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
    Update::update(&mut hasher, json_bytes);
    let mut full = [0u8; 32];
    hasher.finalize_variable(&mut full).expect("blake2b finalize");
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}

/// Format an 8-byte fingerprint as four hex pairs separated by dashes
/// (`a37f-2c91-5be2-c8d4`). Same shape as the pairing fingerprint
/// display so operators do not have to learn two formats.
pub fn format_fingerprint(fp: &[u8; 8]) -> String {
    format!(
        "{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}",
        fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = request_fingerprint(b"{\"kind\":\"withdrawal\"}");
        let b = request_fingerprint(b"{\"kind\":\"withdrawal\"}");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_diverge() {
        let a = request_fingerprint(b"{\"kind\":\"withdrawal\",\"fee\":1}");
        let b = request_fingerprint(b"{\"kind\":\"withdrawal\",\"fee\":2}");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_input_is_stable() {
        let a = request_fingerprint(b"");
        let b = request_fingerprint(b"");
        assert_eq!(a, b);
    }

    #[test]
    fn format_shape() {
        let s = format_fingerprint(&[0xa3, 0x7f, 0x2c, 0x91, 0x5b, 0xe2, 0xc8, 0xd4]);
        assert_eq!(s, "a37f-2c91-5be2-c8d4");
    }

    /// Cross-implementation known-answer vectors. The expected bytes were
    /// produced independently by Python's `hashlib.blake2b(data,
    /// digest_size=32)` — a different BLAKE2b implementation than the
    /// `blake2` crate used here — so this pins the byte-exact output of the
    /// request-fingerprint contract that the online tool and the signer must
    /// agree on. A change to the hash, the digest length, or the truncation
    /// that the relational tests above would not catch is caught here.
    #[test]
    fn known_answer_vectors() {
        // blake2b-256(`{"kind":"withdrawal"}`)[..8]
        let fp = request_fingerprint(b"{\"kind\":\"withdrawal\"}");
        assert_eq!(fp, [0xb7, 0x52, 0x4b, 0x42, 0x64, 0xc4, 0x21, 0xe0]);
        assert_eq!(format_fingerprint(&fp), "b752-4b42-64c4-21e0");

        // blake2b-256("")[..8] — the canonical empty-input BLAKE2b-256 prefix.
        let empty = request_fingerprint(b"");
        assert_eq!(empty, [0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2]);
        assert_eq!(format_fingerprint(&empty), "0e57-51c0-26e5-43b2");
    }
}
