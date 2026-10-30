//! Wire types for the pairing dance.
//!
//! Both online tool and signer expose the same four pairing endpoints
//! and exchange the same JSON shapes. The structs live here so the two
//! binaries cannot drift in field names, capitalisation, or ordering.
//! State-access patterns differ between the binaries (online holds
//! `Arc<RwLock<OnlineConfig>>`, signer reads from `config::load`), so
//! the request handlers themselves stay binary-local; only the
//! request/response types and the pure compute helpers are shared.

use serde::{Deserialize, Serialize};

use crate::crypto::KEY_LEN;
use crate::error::ErrorEnvelope;

#[derive(Serialize)]
pub struct PairingInfoResponse {
    /// Hex-encoded X25519 public key (diagnostics only; UR is canonical).
    pub own_pubkey_hex: String,
    /// Same own pubkey wrapped as `spo-tools-pairing-v1` UR fragments.
    /// The frontend renders this as a QR for the peer to scan.
    pub own_pubkey_ur: Vec<String>,
    /// Whether a peer pubkey is already configured. False after first boot.
    pub paired: bool,
    /// The peer's pubkey hex once paired. None if `paired` is false.
    pub peer_pubkey_hex: Option<String>,
    /// Human-comparable fingerprint of `min(own, peer) || max(own, peer)`
    /// in `a37f-2c91-5be2-c8d4` format. None when not paired.
    pub fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingPreviewBody {
    /// `spo-tools-pairing-v1` UR fragments scanned from the peer.
    pub ur_fragments: Vec<String>,
}

#[derive(Serialize)]
pub struct PairingPreviewResponse {
    /// Decoded peer pubkey hex (diagnostics only).
    pub peer_pubkey_hex: String,
    /// Fingerprint the SPO compares visually with the other side before
    /// clicking Confirm.
    pub fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingSetPeerBody {
    /// Same UR fragments as the preview call.
    pub ur_fragments: Vec<String>,
    /// Fingerprint the client just confirmed visually. The server
    /// recomputes and aborts on mismatch BEFORE the peer pubkey is
    /// persisted, closing the trust-sequencing gap where a tampered
    /// server could write the wrong peer key without the client noticing.
    pub expected_fingerprint: String,
}

#[derive(Serialize)]
pub struct PairingSetPeerResponse {
    pub paired: bool,
    pub fingerprint: String,
}

/// Build the `PairingInfoResponse` from the binary's freshly-ensured own
/// X25519 secret and the optionally-stored peer pubkey hex. Pure: no I/O.
/// Both binaries call this after their crate-local config-load and
/// ensure-own-skey paths complete.
pub fn build_pairing_info_response(
    own_secret: &[u8; KEY_LEN],
    peer_pubkey_hex: Option<&str>,
) -> Result<PairingInfoResponse, ErrorEnvelope> {
    let own_pub = crate::crypto::public_from_secret(own_secret);
    let (paired, peer_hex_out, fingerprint) = match peer_pubkey_hex {
        Some(hex_str) => match crate::crypto::key_from_hex(hex_str) {
            Ok(peer_pub) => {
                let fp = crate::crypto::fingerprint(&own_pub, &peer_pub);
                (
                    true,
                    Some(hex_str.to_string()),
                    Some(crate::crypto::fingerprint_display(&fp)),
                )
            }
            Err(_) => (false, None, None),
        },
        None => (false, None, None),
    };
    let own_pubkey_ur = crate::qr::encode_pairing_payload(&own_pub).map_err(|e| {
        tracing::error!(error = %e, "failed to encode own pubkey UR");
        ErrorEnvelope::internal("failed to encode pubkey")
    })?;
    Ok(PairingInfoResponse {
        own_pubkey_hex: hex::encode(own_pub),
        own_pubkey_ur,
        paired,
        peer_pubkey_hex: peer_hex_out,
        fingerprint,
    })
}

/// Validate a freshly-decoded peer pubkey against the binary's own
/// secret and return the displayable fingerprint. Used by both
/// `pairing_preview` (to surface the fingerprint to the operator before
/// confirm) and `pairing_set_peer` (to recompute it before persist).
/// Rejects low-order points up-front so a malicious peer cannot force
/// an all-zero ECDH shared secret past pairing.
pub fn validate_peer_and_fingerprint(
    own_secret: &[u8; KEY_LEN],
    peer_pub: &[u8; KEY_LEN],
) -> Result<String, ErrorEnvelope> {
    crate::crypto::validate_peer_pubkey(peer_pub, own_secret).map_err(|e| {
        tracing::error!(error = %e, "peer pubkey rejected");
        ErrorEnvelope::invalid("peer pubkey rejected")
    })?;
    let own_pub = crate::crypto::public_from_secret(own_secret);
    let fp = crate::crypto::fingerprint(&own_pub, peer_pub);
    Ok(crate::crypto::fingerprint_display(&fp))
}
