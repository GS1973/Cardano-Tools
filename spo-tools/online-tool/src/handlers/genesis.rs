use crate::{koios, AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use shared::error::ErrorEnvelope;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Serialize)]
pub(crate) struct GenesisStatus {
    /// Whether protocol params are currently available. If `false`, KES
    /// endpoints will return 503: call `POST /api/genesis/refresh` to
    /// retry the Koios fetch.
    loaded: bool,
    params: Option<koios::GenesisParams>,
}

pub(crate) async fn genesis_status(State(state): State<Arc<AppState>>) -> Json<GenesisStatus> {
    let params = *state.genesis.lock().unwrap_or_else(|e| e.into_inner());
    Json(GenesisStatus {
        loaded: params.is_some(),
        params,
    })
}

/// POST /api/genesis/refresh: retry the Koios `/genesis` fetch and
/// install the result. Used by the UI when the initial startup fetch
/// failed and Koios has since come back online.
pub(crate) async fn genesis_refresh(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GenesisStatus>, ErrorEnvelope> {
    let params = koios::fetch_genesis_params(&state.http, &state.koios_base_url).await.map_err(|e| {
        error!(error = %e, "manual genesis refresh failed");
        match e {
            koios::KoiosError::NotMainnetGenesis(_) => ErrorEnvelope::upstream(
                "the chain-data provider returned genesis values that are not mainnet's. Not using them.",
            ),
            _ => ErrorEnvelope::upstream("upstream service unavailable"),
        }
    })?;
    let mut prev = state.genesis.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = *prev {
        if old.kes_max_evolutions != params.kes_max_evolutions
            || old.slots_per_kes_period != params.slots_per_kes_period
            || old.epoch_length != params.epoch_length
            || (old.active_slots_coeff - params.active_slots_coeff).abs() > f64::EPSILON
        {
            tracing::warn!(?old, ?params, "genesis params changed since last fetch");
        }
    }
    *prev = Some(params);
    // See comment in main.rs:fetch_genesis_params caller: `?params` is
    // safe today because GenesisParams contains only public Cardano
    // protocol constants. Curate the field list if that ever changes.
    info!(?params, "genesis params refreshed");
    Ok(Json(GenesisStatus {
        loaded: true,
        params: Some(params),
    }))
}

// GenesisParams must be Serialize for the genesis_status endpoint.
impl Serialize for koios::GenesisParams {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("GenesisParams", 4)?;
        s.serialize_field("active_slots_coeff", &self.active_slots_coeff)?;
        s.serialize_field("epoch_length", &self.epoch_length)?;
        s.serialize_field("slots_per_kes_period", &self.slots_per_kes_period)?;
        s.serialize_field("kes_max_evolutions", &self.kes_max_evolutions)?;
        s.end()
    }
}
