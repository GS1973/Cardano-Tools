//! Rationale-witness handlers: `/api/witness/start` and
//! `/api/witness/result`.
//!
//! `witness_start` takes the CIP-100 canonical body the frontend produced
//! (URDNA2015 of the rationale body), wraps it in an `SpoWitnessRequest`,
//! and returns the encrypted UR fragments. `witness_result` decodes the
//! signer's reply into the CIP-100 witness the frontend injects into the
//! authors block. No transaction is built or submitted here.

use crate::{
    koios, state,
    util::{chain_context_from, paired_keys_or_err, start_handler_ctx, StartHandlerCtx},
    AppState,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use shared::error::ErrorEnvelope;
use shared::wire_io::ur_decode_required;
use std::sync::Arc;
use tracing::error;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WitnessStartBody {
    /// CIP-100 canonical body (N-Quads) produced by the frontend.
    pub canonical_body: String,
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct WitnessStartResponse {
    request: shared::witness_doc::SpoWitnessRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

pub(crate) async fn witness_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<WitnessStartBody>,
) -> Result<Json<WitnessStartResponse>, ErrorEnvelope> {
    let StartHandlerCtx {
        params,
        own_sk,
        peer_pk,
        cfg: _,
        pool_id,
        payment_address: _,
    } = start_handler_ctx(&app, &body.pin)?;
    shared::validate::assert_canonical_body_nquads(body.canonical_body.as_bytes())
        .map_err(|e| ErrorEnvelope::invalid(format!("not a canonical CIP-100 body: {e}")))?;
    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start)?;
    let body_hash_hex = hex::encode(pallas_crypto::hash::Hasher::<256>::hash(
        body.canonical_body.as_bytes(),
    ));
    let mut request = shared::witness_doc::SpoWitnessRequest {
        kind: shared::wire_kind::WireKind::WitnessDoc,
        canonical_body: body.canonical_body,
        pool_id_bech32: pool_id,
        operator_pin_proof: String::new(),
        chain_context,
    };
    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof = shared::pin::pin_proof_hex(
        &body.pin,
        request.kind.wire_str(),
        request.chain_context.built_at_unix,
        &body_fp,
    );
    let (_json, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;
    Ok(Json(WitnessStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
pub(crate) struct WitnessResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn witness_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<WitnessResultBody>,
) -> Result<Json<shared::witness_doc::SpoWitnessResult>, ErrorEnvelope> {
    if body.ur_fragments.is_empty() {
        return Err(ErrorEnvelope::invalid("no UR fragments"));
    }
    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;
    let json_bytes = ur_decode_required(
        &body.ur_fragments,
        &peer_pk,
        &own_sk,
        shared::qr::Direction::Response,
    )?;
    let result = serde_json::from_slice(&json_bytes).map_err(|e| {
        error!(error = %e, "invalid result payload");
        ErrorEnvelope::invalid("invalid result payload")
    })?;
    Ok(Json(result))
}
