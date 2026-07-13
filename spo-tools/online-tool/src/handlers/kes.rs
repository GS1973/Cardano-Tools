use crate::{koios, state, util::{now_unix_ts, paired_keys_or_err}, AppState};
use shared::error::ErrorEnvelope;
use shared::{
    chain_context::ChainContext,
    kes::{KesRotationRequest, KesRotationResult},
    wire_io::ur_decode_required};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

/// Snapshot of everything the UI needs to display the current KES state and
/// build a rotation request — current chain tip plus the latest block this
/// pool produced (which carries the on-chain op-cert counter).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct KesStatus {
    pool_id_bech32: String,
    current_slot: u64,
    current_epoch: u64,
    current_kes_period: u64,
    /// Unix seconds when the current epoch ends (= start of next epoch).
    epoch_ends_at_unix: u64,
    /// Highest op-cert counter the chain has seen for this pool, taken from
    /// the latest block they produced. 0 if the pool has never minted.
    on_chain_counter: u64,
    /// `on_chain_counter + 1` — what the next rotation will pin to.
    suggested_new_counter: u64,
    /// Hash of the latest block produced by this pool, if any. Lets the UI
    /// link back to a chain explorer for visual confirmation.
    latest_block_hash: Option<String>,
    /// Absolute slot of that latest block.
    latest_block_slot: Option<u64>,
    /// KES period in which that latest block was minted.
    latest_block_kes_period: Option<u64>,
    /// Sum6Kes validity window (64 KES periods on mainnet).
    kes_validity_periods: u64,
    /// Mainnet constant: 129_600.
    slots_per_kes_period: u64,

    // ---- Local state about the SPO's *currently deployed* opcert.
    // These are populated from the local state file (bootstrapped once by
    // the SPO via POST /api/kes/state, and self-updating on every rotation
    // through this tool). When the state file is empty all four fields are
    // null and the UI falls back to "please set your current start_kes_period".
    /// `start_kes_period` of the opcert currently active on the BP node.
    opcert_start_kes_period: Option<u64>,
    /// Counter of that opcert. Lets the UI flag a mismatch with the
    /// chain's `on_chain_counter` (e.g. BP not yet restarted after
    /// rotation, or someone rotated outside the tool).
    opcert_local_counter: Option<u64>,
    /// Last KES period the current opcert is still valid (= start + 61, since maxKESEvolutions = 62 on mainnet).
    opcert_end_kes_period: Option<u64>,
    /// Unix seconds when the current opcert expires.
    opcert_expires_at_unix: Option<u64>,
    /// Seconds remaining until expiry. Negative if already expired.
    opcert_seconds_remaining: Option<i64>,
    /// Unix seconds the local state file was last updated.
    state_last_updated_unix: Option<u64>}

pub(crate) async fn gather_kes_status(
    client: &reqwest::Client,
    base_url: &str,
    pool_id_bech32: &str,
    params: &koios::GenesisParams,
) -> Result<KesStatus, koios::KoiosError> {
    let tip = koios::tip(client, base_url).await?;
    let blocks = koios::pool_blocks(client, base_url, pool_id_bech32, 1).await?;
    let (on_chain_counter, latest_block_hash, latest_block_slot, latest_block_kes_period) =
        if let Some(latest) = blocks.first() {
            let info = koios::block_info(client, base_url, &latest.block_hash).await?;
            (
                info.op_cert_counter,
                Some(latest.block_hash.clone()),
                Some(latest.abs_slot),
                Some(params.slot_to_kes_period(latest.abs_slot)),
            )
        } else {
            (0, None, None, None)
        };
    let local_state = state::load(&state::state_path());
    let opcert_end_kes_period = local_state
        .opcert_start_kes_period
        .map(|s| params.opcert_end_kes_period(s));
    let opcert_expires_at_unix = local_state
        .opcert_start_kes_period
        .map(|s| params.opcert_expires_at_unix(s));
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Signed countdown: positive = seconds until expiry, negative =
    // seconds since expiry. Computed via u64 saturating-sub then `try_from`
    // so the silent `as i64` cast on a future-far timestamp can't wrap.
    let opcert_seconds_remaining: Option<i64> = opcert_expires_at_unix.map(|e| {
        match e.checked_sub(now_unix) {
            Some(diff) => i64::try_from(diff).unwrap_or(i64::MAX),
            None => i64::try_from(now_unix.saturating_sub(e))
                .map(|d| -d)
                .unwrap_or(i64::MIN),
        }
    });

    Ok(KesStatus {
        pool_id_bech32: pool_id_bech32.into(),
        current_slot: tip.abs_slot,
        current_epoch: tip.epoch_no,
        current_kes_period: params.slot_to_kes_period(tip.abs_slot),
        epoch_ends_at_unix: koios::slot_to_unix_time(
            params.epoch_first_slot(tip.epoch_no.saturating_add(1)),
        ),
        on_chain_counter,
        // Saturating increment: u64::MAX is unreachable on a real chain
        // (would require ~2^64 opcert rotations on this pool); guarding
        // against panic/wrap on garbage Koios input rather than a real
        // counter at the limit.
        suggested_new_counter: on_chain_counter.saturating_add(1),
        latest_block_hash,
        latest_block_slot,
        latest_block_kes_period,
        kes_validity_periods: params.kes_max_evolutions,
        slots_per_kes_period: params.slots_per_kes_period,
        opcert_start_kes_period: local_state.opcert_start_kes_period,
        opcert_local_counter: local_state.opcert_counter,
        opcert_end_kes_period,
        opcert_expires_at_unix,
        opcert_seconds_remaining,
        state_last_updated_unix: local_state.last_updated_unix})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KesSetStateRequestBody {
    /// `start_kes_period` of your CURRENT (already-deployed) opcert. Find
    /// it on the BP node with `cardano-cli query kes-period-info
    /// --op-cert-file node.cert` (look at "qKesStartKesInterval"), or in
    /// your own rotation log.
    opcert_start_kes_period: u64,
    /// Counter of that current opcert (matches the on-chain counter for
    /// blocks signed by it).
    opcert_counter: u64}

/// POST /api/kes/state
///
/// Manually bootstraps the local KES app. After the first call, the
/// state file is auto-maintained: every successful POST /api/kes/result
/// replaces these values with the freshly issued opcert's.
pub(crate) async fn kes_set_state(
    State(app): State<Arc<AppState>>,
    Json(body): Json<KesSetStateRequestBody>,
) -> Result<Json<KesStatus>, ErrorEnvelope> {
    let params = app.require_genesis()?;
    let new_state = state::KesState {
        opcert_start_kes_period: Some(body.opcert_start_kes_period),
        opcert_counter: Some(body.opcert_counter),
        last_updated_unix: None};
    state::save(&state::state_path(), new_state).map_err(|e| {
        error!(error = %e, "save kes state failed");
        ErrorEnvelope::internal("failed to persist state")
    })?;
    let pool_id = app.require_pool_id()?;
    gather_kes_status(&app.http, &app.koios_base_url, &pool_id, &params)
        .await
        .map(Json)
        .map_err(|e| {
            error!(error = %e, "koios kes status failed after state save");
            ErrorEnvelope::upstream("upstream service unavailable")
        })
}

/// GET /api/kes/status
pub(crate) async fn kes_status(
    State(app): State<Arc<AppState>>,
) -> Result<Json<KesStatus>, ErrorEnvelope> {
    let params = app.require_genesis()?;
    let pool_id = app.require_pool_id()?;
    gather_kes_status(&app.http, &app.koios_base_url, &pool_id, &params)
        .await
        .map(Json)
        .map_err(|e| {
            error!(error = %e, "koios kes status failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })
}

#[derive(Serialize)]
pub(crate) struct KesStartResponse {
    request: KesRotationRequest,
    status: KesStatus,
    ur_fragments: Vec<String>,
    /// 8-byte request-payload fingerprint, blake2b256 truncated
    /// and rendered as 4 hex pairs (operator visually compares with the
    /// signer-side display before signing).
    request_fingerprint: String,
}

/// POST /api/kes/start
///
/// Builds a KES rotation request pinned to `(suggested_new_counter,
/// current_kes_period)`. Returns a JSON envelope with the request
/// itself (so the UI can preview it), the chain status it is derived
/// from, and UR fragments for the animated QR display.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KesStartBody {
    /// 4-digit operator PIN.
    pub pin: String,
}

pub(crate) async fn kes_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<KesStartBody>,
) -> Result<Json<KesStartResponse>, ErrorEnvelope> {
    shared::pin::validate_pin(&body.pin).map_err(ErrorEnvelope::invalid)?;
    let params = app.require_genesis()?;
    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;
    let pool_id = app.require_pool_id()?;
    let status = gather_kes_status(&app.http, &app.koios_base_url, &pool_id, &params)
        .await
        .map_err(|e| {
            error!(error = %e, "koios kes start failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;

    let chain_context = ChainContext {
        current_epoch: status.current_epoch,
        current_slot: status.current_slot,
        current_kes_period: status.current_kes_period,
        epoch_ends_at_unix: status.epoch_ends_at_unix,
        opcert_expires_at_unix: status.opcert_expires_at_unix,
        built_at_unix: now_unix_ts()};

    let mut request = KesRotationRequest {
        kind: shared::wire_kind::WireKind::KesRotation,
        pool_id_bech32: status.pool_id_bech32.clone(),
        new_counter: status.suggested_new_counter,
        kes_period: status.current_kes_period,
        operator_pin_proof: String::new(),
        chain_context};

    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof =
        shared::pin::pin_proof_hex(&body.pin, request.kind.wire_str(), request.chain_context.built_at_unix, &body_fp);

    let (_json_bytes, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;

    Ok(Json(KesStartResponse {
        request,
        status,
        ur_fragments,
        request_fingerprint}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KesResultRequestBody {
    ur_fragments: Vec<String>}

#[derive(Serialize)]
pub(crate) struct KesResultResponse {
    pool_id_bech32: String,
    counter: u64,
    kes_period: u64,
    kes_vkey_hex: String,
    /// Absolute directory on the signer where the new files were written.
    output_dir: String,
    kes_skey_filename: String,
    node_cert_filename: String,
    cold_counter_filename: String,
}

/// POST /api/kes/result
///
/// Accepts UR fragments scanned from the offline signer and surfaces the
/// signer-written file paths (the signer wrote the JSON contents to its own
/// disk to keep fresh `kes.skey` material out of the online tool).
pub(crate) async fn kes_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<KesResultRequestBody>,
) -> Result<Json<KesResultResponse>, ErrorEnvelope> {
    shared::wire_io::require_non_empty(&body.ur_fragments, "ur_fragments")?;
    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;
    let payload = ur_decode_required(&body.ur_fragments, &peer_pk, &own_sk, shared::qr::Direction::Response)?;

    let result: KesRotationResult = serde_json::from_slice(&payload).map_err(|e| {
        error!(error = %e, "JSON decode of kes result failed");
        ErrorEnvelope::invalid("invalid request payload")
    })?;

    if let Err(e) = state::save(&state::state_path(), state::KesState {
        opcert_start_kes_period: Some(result.kes_period),
        opcert_counter: Some(result.counter),
        last_updated_unix: None}) {
        error!(error = %e, "could not persist kes state after rotation");
    }

    Ok(Json(KesResultResponse {
        pool_id_bech32: result.pool_id_bech32,
        counter: result.counter,
        kes_period: result.kes_period,
        kes_vkey_hex: result.kes_vkey_hex,
        output_dir: result.output_dir,
        kes_skey_filename: result.kes_skey_filename,
        node_cert_filename: result.node_cert_filename,
        cold_counter_filename: result.cold_counter_filename,
    }))
}

