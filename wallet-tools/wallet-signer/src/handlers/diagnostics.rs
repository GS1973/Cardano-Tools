//! `/api/status` and `/api/health` handlers.
//!
//! Read-only endpoints that report the current chain-context snapshot
//! and the air-gap heuristic. Health is a fixed `"ok"` so a basic
//! liveness probe can hit the binary without exercising any state.

use crate::{airgap, state};

#[derive(serde::Serialize)]
pub(crate) struct SignerStatus {
    /// True when the last sample saw no traffic on a connected interface,
    /// false when it did, and absent (null) before the first sample.
    air_gapped: Option<bool>,
    /// Last-known chain snapshot, persisted from the most recent request
    /// the signer received. None until the first signing session.
    chain_context: Option<shared::chain_context::ChainContext>,
    /// Unix seconds when `chain_context` was last refreshed.
    last_synced_unix: Option<u64>,
}

pub(crate) async fn signer_status() -> axum::Json<SignerStatus> {
    // Display only: a damaged state file shows as "never synced" here and
    // is refused where it matters, in the signing path.
    let s = state::load(&state::state_path()).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load signer state for status");
        state::SignerState::default()
    });
    axum::Json(SignerStatus {
        air_gapped: airgap::air_gapped(),
        chain_context: s.last_chain_context,
        last_synced_unix: s.last_synced_unix,
    })
}

pub(crate) async fn signer_health() -> &'static str {
    "ok"
}
