//! New-address receive: decodes the `NewAddressExport` the operator
//! carries back from the air-gapped signer after generating a fresh wallet
//! key pair.
//!
//! Generation itself happens entirely on the signer (the secrets never
//! leave the offline host); the online side only ingests the public export
//! so the new base/stake address can be displayed, funded, and watched. The
//! export carries no secret, so it travels in the same encrypted UR channel
//! as the signing results.

use crate::AppState;
use axum::{extract::State, Json};
use serde::Deserialize;
use shared::error::ErrorEnvelope;
use shared::wire_io::ur_decode_required;
use std::sync::Arc;
use tracing::error;

#[derive(Deserialize)]
pub(crate) struct NewAddressReceiveBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn new_address_receive(
    State(app): State<Arc<AppState>>,
    Json(body): Json<NewAddressReceiveBody>,
) -> Result<Json<shared::new_address::NewAddressExport>, ErrorEnvelope> {
    if body.ur_fragments.is_empty() {
        return Err(ErrorEnvelope::invalid("no UR fragments"));
    }
    let (own_sk, peer_pk) = crate::util::paired_keys_or_err(&app)?;
    let json_bytes = ur_decode_required(
        &body.ur_fragments,
        &peer_pk,
        &own_sk,
        shared::qr::Direction::Response,
    )?;
    let export: shared::new_address::NewAddressExport = serde_json::from_slice(&json_bytes)
        .map_err(|e| {
            error!(error = %e, "invalid new-address export payload");
            ErrorEnvelope::invalid("invalid new-address export payload")
        })?;
    if !export.is_consistent() {
        error!("new-address export does not match its own keys");
        return Err(ErrorEnvelope::invalid(
            "the new-address export does not match its own keys. Generate the address again on the signer",
        ));
    }
    Ok(Json(export))
}
