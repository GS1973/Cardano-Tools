//! Pairing API: bootstraps the encrypted channel between signer and
//! online tool.
//!
//! On first contact each side generates a static X25519 keypair,
//! shows its public key as a UR-encoded fingerprint, and the operator
//! visually compares them between the two devices before committing.

use crate::config;
use shared::error::ErrorEnvelope;
use shared::pairing::{
    PairingInfoResponse, PairingPreviewBody, PairingPreviewResponse, PairingSetPeerBody,
    PairingSetPeerResponse,
};
use shared::wire_io::decode_pairing_pubkey;

/// Looks up the paired-keys (own X25519 secret + peer X25519 public)
/// from the signer's on-disk config. Returns a 428 telling the SPO to
/// pair before any operational request can be processed. 428
/// (Precondition Required) is distinct from the 412 returned for
/// skey-paths-not-set, so the frontend can route to a Pairing card
/// instead of a Setup card.
pub(crate) fn paired_keys_or_err(
    cfg: &config::SignerConfig,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), ErrorEnvelope> {
    config::paired_keys(cfg).ok_or(ErrorEnvelope::not_paired(
        "signer is not paired with an online tool. Open Pairing first",
    ))
}

pub(crate) async fn pairing_info() -> Result<axum::Json<PairingInfoResponse>, ErrorEnvelope> {
    let mut cfg = config::load_or_err()?;
    let own_secret =
        config::ensure_own_crypto_skey(&config::config_path(), &mut cfg).map_err(|e| {
            tracing::error!(error = %e, "keypair initialisation failed");
            ErrorEnvelope::internal("keypair initialisation failed")
        })?;
    let response = shared::pairing::build_pairing_info_response(
        &own_secret,
        cfg.peer_crypto_pubkey_hex.as_deref(),
    )?;
    Ok(axum::Json(response))
}

pub(crate) async fn pairing_preview(
    axum::Json(body): axum::Json<PairingPreviewBody>,
) -> Result<axum::Json<PairingPreviewResponse>, ErrorEnvelope> {
    let peer_pub = decode_pairing_pubkey(&body.ur_fragments)?;
    let mut cfg = config::load_or_err()?;
    let own_secret =
        config::ensure_own_crypto_skey(&config::config_path(), &mut cfg).map_err(|e| {
            tracing::error!(error = %e, "keypair initialisation failed");
            ErrorEnvelope::internal("keypair initialisation failed")
        })?;
    let fingerprint = shared::pairing::validate_peer_and_fingerprint(&own_secret, &peer_pub)?;
    Ok(axum::Json(PairingPreviewResponse {
        peer_pubkey_hex: hex::encode(peer_pub),
        fingerprint,
    }))
}

pub(crate) async fn pairing_set_peer(
    axum::Json(body): axum::Json<PairingSetPeerBody>,
) -> Result<axum::Json<PairingSetPeerResponse>, ErrorEnvelope> {
    let peer_pub = decode_pairing_pubkey(&body.ur_fragments)?;
    let mut cfg = config::load_or_err()?;
    let own_secret =
        config::ensure_own_crypto_skey(&config::config_path(), &mut cfg).map_err(|e| {
            tracing::error!(error = %e, "keypair initialisation failed");
            ErrorEnvelope::internal("keypair initialisation failed")
        })?;
    let fp_display = shared::pairing::validate_peer_and_fingerprint(&own_secret, &peer_pub)?;
    if fp_display != body.expected_fingerprint.trim() {
        return Err(ErrorEnvelope::invalid(
            "fingerprint mismatch: pairing aborted, on-disk pairing untouched",
        ));
    }
    cfg.peer_crypto_pubkey_hex = Some(hex::encode(peer_pub));
    config::save(&config::config_path(), &cfg).map_err(|e| {
        tracing::error!(error = %e, "failed to persist state");
        ErrorEnvelope::internal("failed to persist state")
    })?;
    Ok(axum::Json(PairingSetPeerResponse {
        paired: true,
        fingerprint: fp_display,
    }))
}

pub(crate) async fn pairing_clear() -> Result<axum::Json<serde_json::Value>, ErrorEnvelope> {
    let mut cfg = config::load_or_err()?;
    cfg.peer_crypto_pubkey_hex = None;
    config::save(&config::config_path(), &cfg).map_err(|e| {
        tracing::error!(error = %e, "failed to persist state");
        ErrorEnvelope::internal("failed to persist state")
    })?;
    Ok(axum::Json(serde_json::json!({ "paired": false })))
}
