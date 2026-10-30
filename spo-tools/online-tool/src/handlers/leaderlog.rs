use crate::{
    koios, state,
    util::{chain_context_from, now_unix_ts, paired_keys_or_err},
    AppState,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use shared::error::ErrorEnvelope;
use shared::{
    leaderlog::{LeaderlogRequest, LeaderlogResult},
    wire_io::ur_decode_required,
};
use std::sync::Arc;
use tracing::error;

#[derive(Serialize)]
pub(crate) struct LeaderlogStartResponse {
    request: LeaderlogRequest,
    ur_fragments: Vec<String>,
    /// 8-byte request-payload fingerprint, blake2b256 truncated and
    /// rendered as 4 hex pairs (operator visually compares with the
    /// signer-side display before signing).
    request_fingerprint: String,
    /// The epoch the returned leaderlog actually targets after any
    /// stability-window fallback. Either "current" or "next".
    effective_epoch_kind: &'static str,
    /// Set when the originally requested epoch could not be honoured,
    /// typically because `next` was asked for before the chain reached
    /// the current epoch's stability window. UI should surface this.
    fallback_notice: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaderlogStartBody {
    /// "current" → Set snapshot, "next" → Mark snapshot (provided the
    /// stability window has been reached, otherwise the handler falls
    /// back to Set with a notice). Default: "next".
    pub epoch: Option<String>,
    /// 4-digit operator PIN.
    pub pin: String,
}

pub(crate) async fn leaderlog_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<LeaderlogStartBody>,
) -> Result<Json<LeaderlogStartResponse>, ErrorEnvelope> {
    shared::pin::validate_pin(&body.pin).map_err(ErrorEnvelope::invalid)?;
    let params = app.require_genesis()?;
    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;

    let pool_id = app.require_pool_id()?;

    // Tip is needed up-front to evaluate the stability-window check.
    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;

    let snapshots = koios::pool_stake_snapshot(&app.http, &app.koios_base_url, &pool_id)
        .await
        .map_err(|e| {
            error!(error = %e, "koios pool_stake_snapshot failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;

    // Koios snapshot kinds (per /pool_stake_snapshot):
    //   Mark = upcoming epoch (epoch_no = current + 1), nonce null until
    //          chain enters the stability window of the current epoch
    //   Set  = currently active epoch (epoch_no = current), nonce final
    //          since start of epoch
    //   Go   = previous epoch (epoch_no = current - 1), already past
    //
    // The Mark → Set → Go progression follows the snapshot through time.
    // Leaderlog of `current` reads from Set; `next` reads from Mark and
    // falls back to Set with a notice when Mark's nonce is not yet
    // finalised (i.e. the chain has not reached the current epoch's
    // randomness-stabilisation window: the final 4k/f slots, ~48 h on
    // mainnet; see `stability_window_slots` in koios.rs).
    enum RequestedKind {
        Current,
        Next,
    }
    let requested_kind = match body.epoch.as_deref() {
        Some("current") => RequestedKind::Current,
        _ => RequestedKind::Next,
    };

    let window_ready = params.next_epoch_leaderlog_ready(tip.abs_slot, tip.epoch_no);

    let (snapshot_kind, effective_epoch_kind, fallback_notice): (
        koios::SnapshotKind,
        &'static str,
        Option<String>,
    ) = match requested_kind {
        RequestedKind::Current => (koios::SnapshotKind::Set, "current", None),
        RequestedKind::Next if window_ready => (koios::SnapshotKind::Mark, "next", None),
        RequestedKind::Next => {
            let unlock_slot = params.next_nonce_finalised_slot(tip.epoch_no);
            let unlock_unix = koios::slot_to_unix_time(unlock_slot);
            let now = now_unix_ts()?;
            let hours_until = unlock_unix.saturating_sub(now) / 3600;
            let notice = format!(
                "The next-epoch nonce is not yet finalised. Cardano fixes the \
                     next epoch's leadership nonce only once the chain enters the \
                     current epoch's randomness-stabilisation window: the final \
                     ~48 hours of the epoch. Showing the current epoch's leaderlog \
                     as a substitute. Next-epoch data will become available in \
                     approximately {hours_until} hour(s)."
            );
            (koios::SnapshotKind::Set, "current", Some(notice))
        }
    };

    let snap = koios::extract_snapshot(&snapshots, snapshot_kind).map_err(|e| {
        error!(error = %e, snapshot = snapshot_kind.as_str(), "extract snapshot failed");
        match e {
            koios::KoiosError::MissingSnapshot(koios::SnapshotKind::Mark) => {
                ErrorEnvelope::snapshot_not_ready(
                    "The next-epoch stake snapshot is not yet published by Koios. \
                 This is unusual once the stability window has been reached: \
                 please retry shortly."
                        .to_string(),
                )
            }
            koios::KoiosError::MissingSnapshot(koios::SnapshotKind::Set) => {
                ErrorEnvelope::snapshot_not_ready(
                    "The current-epoch stake snapshot is not yet available from Koios. \
                 This is rare: please retry in a few minutes."
                        .to_string(),
                )
            }
            _ => ErrorEnvelope::upstream("snapshot fetch failed"),
        }
    })?;
    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start)?;

    // Active slots coefficient is f64 from Koios genesis. Mainnet is 0.05;
    // it is encoded as a 4-decimal rational (numer = round(coeff * 10000),
    // denom = 10000) so it crosses the wire as exact integers.
    // Guard against garbage Koios genesis values: NaN, Inf, negative, or
    // out-of-range coefficients would silently wrap to 0 or u64::MAX in
    // the `as u64` cast, producing a leaderlog with 0 leader slots.
    if !params.active_slots_coeff.is_finite()
        || params.active_slots_coeff <= 0.0
        || params.active_slots_coeff > 1.0
    {
        error!(
            coeff = params.active_slots_coeff,
            "active_slots_coeff outside (0, 1]"
        );
        return Err(ErrorEnvelope::upstream(
            "upstream genesis params have an unusable active_slots_coeff",
        ));
    }
    let f_numer = (params.active_slots_coeff * 10_000.0).round() as u64;
    let f_denom = 10_000u64;
    let mut request = LeaderlogRequest {
        kind: shared::wire_kind::WireKind::Leaderlog,
        pool_id_bech32: pool_id.clone(),
        epoch: snap.epoch_no,
        epoch_nonce_hex: snap.nonce_hex,
        pool_stake: snap.pool_stake,
        total_active_stake: snap.active_stake,
        active_slots_coeff_numer: f_numer,
        active_slots_coeff_denom: f_denom,
        epoch_first_slot: params.epoch_first_slot(snap.epoch_no),
        epoch_length: params.epoch_length,
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

    let (_json_bytes, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;

    Ok(Json(LeaderlogStartResponse {
        request,
        ur_fragments,
        request_fingerprint,
        effective_epoch_kind,
        fallback_notice,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaderlogResultRequest {
    ur_fragments: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/handlers.ts")]
pub(crate) struct ScheduledSlot {
    #[ts(type = "number")]
    slot_no: u64,
    #[ts(type = "number")]
    unix_time: u64,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/handlers.ts")]
pub(crate) struct LeaderlogResultResponse {
    pool_id_bech32: String,
    #[ts(type = "number")]
    epoch: u64,
    #[ts(type = "number")]
    count: usize,
    slots: Vec<ScheduledSlot>,
}

pub(crate) async fn leaderlog_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<LeaderlogResultRequest>,
) -> Result<Json<LeaderlogResultResponse>, ErrorEnvelope> {
    shared::wire_io::require_non_empty(&body.ur_fragments, "ur_fragments")?;

    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;
    let payload = ur_decode_required(
        &body.ur_fragments,
        &peer_pk,
        &own_sk,
        shared::qr::Direction::Response,
    )?;

    let result: LeaderlogResult = serde_json::from_slice(&payload).map_err(|e| {
        error!(error = %e, "JSON decode of leaderlog result failed");
        ErrorEnvelope::invalid("invalid request payload")
    })?;

    let slots = result
        .slots
        .iter()
        .map(|&slot_no| ScheduledSlot {
            slot_no,
            unix_time: koios::slot_to_unix_time(slot_no),
        })
        .collect::<Vec<_>>();

    Ok(Json(LeaderlogResultResponse {
        pool_id_bech32: result.pool_id_bech32,
        epoch: result.epoch,
        count: result.slots.len(),
        slots,
    }))
}
