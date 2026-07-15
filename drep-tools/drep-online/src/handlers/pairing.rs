use crate::{config, AppState};
use shared::pairing::{
    PairingInfoResponse, PairingPreviewBody, PairingPreviewResponse,
    PairingSetPeerBody, PairingSetPeerResponse,
};
use shared::error::ErrorEnvelope;
use shared::wire_io::decode_pairing_pubkey;
use axum::{extract::State, Json};
use std::sync::Arc;
use tracing::error;

// Every handler below holds the config write lock across its whole
// read-modify-write: mutating a clone and writing it back afterwards would
// race concurrent config handlers and silently resurrect stale key state.

pub(crate) async fn pairing_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PairingInfoResponse>, ErrorEnvelope> {
    let mut cfg = state.config.write().unwrap();
    let own_secret = config::ensure_own_crypto_skey(&state.config_path, &mut cfg).map_err(|e| {
        error!(error = %e, "keypair initialisation failed");
        ErrorEnvelope::internal("keypair initialisation failed")
    })?;
    let response = shared::pairing::build_pairing_info_response(
        &own_secret,
        cfg.peer_crypto_pubkey_hex.as_deref(),
    )?;
    Ok(Json(response))
}

pub(crate) async fn pairing_preview(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PairingPreviewBody>,
) -> Result<Json<PairingPreviewResponse>, ErrorEnvelope> {
    let peer_pub = decode_pairing_pubkey(&body.ur_fragments)?;
    let own_secret = {
        let mut cfg = state.config.write().unwrap();
        config::ensure_own_crypto_skey(&state.config_path, &mut cfg).map_err(|e| {
            error!(error = %e, "keypair initialisation failed");
            ErrorEnvelope::internal("keypair initialisation failed")
        })?
    };
    let fingerprint = shared::pairing::validate_peer_and_fingerprint(&own_secret, &peer_pub)?;
    Ok(Json(PairingPreviewResponse {
        peer_pubkey_hex: hex::encode(peer_pub),
        fingerprint,
    }))
}

pub(crate) async fn pairing_set_peer(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PairingSetPeerBody>,
) -> Result<Json<PairingSetPeerResponse>, ErrorEnvelope> {
    let peer_pub = decode_pairing_pubkey(&body.ur_fragments)?;
    let mut cfg = state.config.write().unwrap();
    let own_secret = config::ensure_own_crypto_skey(&state.config_path, &mut cfg).map_err(|e| {
        error!(error = %e, "keypair initialisation failed");
        ErrorEnvelope::internal("keypair initialisation failed")
    })?;
    // Recompute the fingerprint and verify it matches the client preview
    // BEFORE persisting the peer key. On mismatch the existing pairing
    // (if any) stays untouched.
    let fp_display = shared::pairing::validate_peer_and_fingerprint(&own_secret, &peer_pub)?;
    if fp_display != body.expected_fingerprint.trim() {
        return Err(ErrorEnvelope::invalid("fingerprint mismatch — pairing aborted, on-disk pairing untouched"));
    }
    // Persist before mutating the shared state so a failed save leaves the
    // in-memory pairing matching what is on disk.
    let mut new = cfg.clone();
    new.peer_crypto_pubkey_hex = Some(hex::encode(peer_pub));
    config::save(&state.config_path, &new)
        .map_err(|e| { error!(error = %e, "failed to persist state"); ErrorEnvelope::internal("failed to persist state") })?;
    *cfg = new;
    Ok(Json(PairingSetPeerResponse {
        paired: true,
        fingerprint: fp_display,
    }))
}

pub(crate) async fn pairing_clear(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ErrorEnvelope> {
    let mut cfg = state.config.write().unwrap();
    let mut new = cfg.clone();
    new.peer_crypto_pubkey_hex = None;
    config::save(&state.config_path, &new)
        .map_err(|e| { error!(error = %e, "failed to persist state"); ErrorEnvelope::internal("failed to persist state") })?;
    *cfg = new;
    Ok(Json(serde_json::json!({ "paired": false })))
}
