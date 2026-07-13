//! Handler-side wire I/O shared by both binaries: UR-encode and UR-decode
//! wrappers, a pairing-pubkey extractor, a one-shot request-build helper,
//! and a small non-empty assertion. Each pre-maps protocol errors to
//! [`ErrorEnvelope`] so call sites can `?` straight through.

use crate::crypto::KEY_LEN;
use crate::error::ErrorEnvelope;

/// Encode an encrypted payload as UR fragments. UR encoding only fails on
/// impossible inputs from this side, so failures surface as Internal.
/// Translate a QrError::TypeMismatch into a user-actionable envelope.
/// A mismatched UR type tag almost always means one side is on a newer
/// (or older) protocol version than the other, so the actionable
/// message names the upgrade path.
fn tag_mismatch_envelope(expected: &str, got: &str) -> ErrorEnvelope {
    tracing::error!(expected = %expected, got = %got, "UR tag mismatch (version skew?)");
    ErrorEnvelope::invalid(
        "this UR fragment was produced by a different version of these tools — upgrade both the online tool and the signer to matching releases",
    )
}

pub fn ur_encode(
    plaintext: &[u8],
    peer_pk: &[u8; KEY_LEN],
    own_sk: &[u8; KEY_LEN],
    direction: crate::qr::Direction,
) -> Result<Vec<String>, ErrorEnvelope> {
    crate::qr::encode_encrypted_payload(plaintext, peer_pk, own_sk, direction).map_err(|e| {
        tracing::error!(error = %e, "ur encode failed");
        ErrorEnvelope::internal("failed to encode UR fragments")
    })
}

/// Decode encrypted UR fragments and treat incomplete payload as
/// invalid input. Returns the decrypted plaintext on success.
pub fn ur_decode_required(
    parts: &[String],
    peer_pk: &[u8; KEY_LEN],
    own_sk: &[u8; KEY_LEN],
    direction: crate::qr::Direction,
) -> Result<Vec<u8>, ErrorEnvelope> {
    match crate::qr::decode_encrypted_parts(parts, peer_pk, own_sk, direction) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(ErrorEnvelope::invalid("incomplete UR fragments")),
        Err(crate::qr::QrError::TypeMismatch { expected, got }) => {
            Err(tag_mismatch_envelope(&expected, &got))
        }
        Err(e) => {
            tracing::error!(error = %e, "ur decode failed");
            Err(ErrorEnvelope::invalid("could not decode UR fragments"))
        }
    }
}

/// Pull a 32-byte X25519 pubkey out of a single `spo-tools-pairing-v1` UR
/// fragment. Pairing payloads are tiny (32 bytes plaintext + UR overhead)
/// so they always fit in one fragment; rejecting multi-fragment input
/// removes a parser ambiguity that would otherwise let a caller smuggle
/// extra fragments through the pairing decoder.
pub fn decode_pairing_pubkey(parts: &[String]) -> Result<[u8; KEY_LEN], ErrorEnvelope> {
    if parts.len() != 1 {
        return Err(ErrorEnvelope::invalid(
            "pairing UR must arrive as a single fragment",
        ));
    }
    let plaintext = match crate::qr::decode_pairing_parts(parts) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(ErrorEnvelope::invalid("incomplete UR fragments")),
        Err(crate::qr::QrError::TypeMismatch { expected, got }) => {
            return Err(tag_mismatch_envelope(&expected, &got));
        }
        Err(e) => {
            tracing::error!(error = %e, "pairing UR decode failed");
            return Err(ErrorEnvelope::invalid("could not decode pairing UR"));
        }
    };
    if plaintext.len() != KEY_LEN {
        return Err(ErrorEnvelope::invalid(format!(
            "expected {KEY_LEN}-byte pubkey, got {} bytes",
            plaintext.len()
        )));
    }
    let mut peer_pub = [0u8; KEY_LEN];
    peer_pub.copy_from_slice(&plaintext);
    Ok(peer_pub)
}

/// One-shot helper for online-tool /start handlers: serialize the request,
/// UR-encode the encrypted payload, and compute the operator-visible
/// fingerprint. Returns `(json_bytes, ur_fragments, fingerprint_hex)`.
/// Generic over any `serde::Serialize` request type so all five flows
/// (withdrawal, drep, kes, leaderlog, pool-update) share the identical
/// boundary code path.
pub fn build_sign_request<R: serde::Serialize>(
    request: &R,
    own_sk: &[u8; KEY_LEN],
    peer_pk: &[u8; KEY_LEN],
) -> Result<(Vec<u8>, Vec<String>, String), ErrorEnvelope> {
    let json_bytes = serde_json::to_vec(request).map_err(|e| {
        tracing::error!(error = %e, "JSON encode request failed");
        ErrorEnvelope::internal("internal encoding error")
    })?;
    let ur_fragments = ur_encode(&json_bytes, peer_pk, own_sk, crate::qr::Direction::Request)?;
    let fingerprint = crate::fingerprint::format_fingerprint(
        &crate::fingerprint::request_fingerprint(&json_bytes),
    );
    Ok((json_bytes, ur_fragments, fingerprint))
}

/// Reject an empty slice with a uniform `invalid_input` envelope. Pulls
/// the small "no X provided" boilerplate out of every handler that
/// receives a list-shaped JSON body.
pub fn require_non_empty<T>(items: &[T], field: &str) -> Result<(), ErrorEnvelope> {
    if items.is_empty() {
        return Err(ErrorEnvelope::invalid(format!("no {field} provided")));
    }
    Ok(())
}
