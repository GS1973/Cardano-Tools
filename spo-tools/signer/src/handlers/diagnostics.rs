//! `/api/status` and `/api/health` handlers.
//!
//! Read-only endpoints that report the current chain-context snapshot
//! and the air-gap heuristic. Health is a fixed `"ok"` so a basic
//! liveness probe can hit the binary without exercising any state.

use crate::{airgap, state};
use std::sync::atomic::Ordering;

#[derive(serde::Serialize)]
pub(crate) struct SignerStatus {
    /// True when no active non-loopback network adapter is detected.
    air_gapped: bool,
    /// Last-known chain snapshot, persisted from the most recent request
    /// the signer received. None until the first signing session.
    chain_context: Option<shared::chain_context::ChainContext>,
    /// Unix seconds when `chain_context` was last refreshed.
    last_synced_unix: Option<u64>,
}


pub(crate) async fn signer_status() -> axum::Json<SignerStatus> {
    let s = state::load(&state::state_path());
    axum::Json(SignerStatus {
        air_gapped: airgap::AIR_GAPPED.load(Ordering::Relaxed),
        chain_context: s.last_chain_context,
        last_synced_unix: s.last_synced_unix,
    })
}


pub(crate) async fn signer_health() -> &'static str {
    "ok"
}
