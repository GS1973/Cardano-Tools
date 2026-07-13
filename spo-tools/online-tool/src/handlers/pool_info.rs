use crate::{koios, AppState};
use shared::error::ErrorEnvelope;
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;
use tracing::error;

#[derive(Serialize)]
pub(crate) struct PoolInfoPending {
    tx_hash: String,
    active_epoch_no: u64,
    active_epoch_first_unix: u64,
    pledge: Option<String>,
    margin: Option<f64>,
    fixed_cost: Option<String>}

#[derive(Serialize)]
pub(crate) struct PoolInfoResponse {
    #[serde(flatten)]
    info: koios::PoolInfo,
    /// Latest registration with active_epoch_no in the future, if any.
    pending: Option<PoolInfoPending>}

pub(crate) async fn pool_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PoolInfoResponse>, ErrorEnvelope> {
    let params = state.require_genesis()?;
    let pool_id = state.require_pool_id()?;

    let mut info = koios::pool_info(&state.http, &state.koios_base_url, &pool_id).await.map_err(|e| {
        error!(error = %e, "koios pool_info failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;

    let tip = koios::tip(&state.http, &state.koios_base_url).await.map_err(|e| {
        error!(error = %e, "koios tip failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;

    // Koios pool_info returns the latest registration values regardless
    // of activation epoch — so margin / fixed_cost / pledge can already
    // show the *pending* values for a not-yet-active update. Override
    // those three with what the current_update from /pool_updates says
    // is actually live, and surface the pending row separately.
    let updates = koios::pool_updates(&state.http, &state.koios_base_url, &pool_id)
        .await
        .unwrap_or_default();
    // Same selection (including the same-epoch block_time tie-break) as
    // /api/pool/current, so both endpoints show the same certificate.
    let (current_update, pending_update) =
        super::pool::select_registrations(&updates, tip.epoch_no);
    if let Some(u) = current_update {
        if let Some(m) = u.margin {
            info.margin = Some(m);
        }
        if let Some(fc) = u.fixed_cost.clone() {
            info.fixed_cost = Some(fc);
        }
        if let Some(p) = u.pledge.clone() {
            info.pledge = Some(p);
        }
    }
    let pending = pending_update.map(|u| {
        let active_first_slot = params.epoch_first_slot(u.active_epoch_no);
        PoolInfoPending {
            tx_hash: u.tx_hash.clone(),
            active_epoch_no: u.active_epoch_no,
            active_epoch_first_unix: koios::slot_to_unix_time(active_first_slot),
            pledge: u.pledge.clone(),
            margin: u.margin,
            fixed_cost: u.fixed_cost.clone()}
    });

    Ok(Json(PoolInfoResponse { info, pending }))
}

