use crate::{
    handlers::payment::map_build_err,
    koios, tx_builder,
    util::{
        build_request_inputs, chain_context_from_tip, fetch_owned_utxos, start_ctx, tip_and_params,
        utxo_summaries, StartCtx, UtxoSummary, TTL_MARGIN_SLOTS,
    },
    AppState,
};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use shared::chain_context::ChainContext;
use shared::delegate::DrepTarget;
use shared::error::ErrorEnvelope;
use shared::wire_io::ur_decode_required;
use std::sync::Arc;
use tracing::error;

/// Parse the operator's DRep-delegation target string. `abstain` and
/// `no_confidence` are the predefined DReps; anything else must be a
/// `drep1…` id.
fn parse_target(raw: &str) -> Result<DrepTarget, ErrorEnvelope> {
    match raw.trim() {
        "" => Err(ErrorEnvelope::invalid("a DRep target is required")),
        "abstain" => Ok(DrepTarget::Abstain),
        "no_confidence" => Ok(DrepTarget::NoConfidence),
        id => {
            crate::config::validate_bech32(id, "drep").map_err(|_| {
                ErrorEnvelope::invalid("target must be `abstain`, `no_confidence`, or a drep1… id")
            })?;
            Ok(DrepTarget::Drep(id.to_string()))
        }
    }
}

struct RegistrationState {
    register_stake: bool,
    deposit_lovelace: u64,
    currently_delegated_drep: Option<String>,
}

async fn registration_state(
    app: &Arc<AppState>,
    stake_address: &str,
    key_deposit: u64,
) -> Result<RegistrationState, ErrorEnvelope> {
    let info = koios::account_info(&app.http, &app.koios_base_url, stake_address)
        .await
        .map_err(|e| {
            error!(error = %e, "koios account_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let registered = info.as_ref().map(|i| i.is_registered()).unwrap_or(false);
    Ok(RegistrationState {
        register_stake: !registered,
        deposit_lovelace: if registered { 0 } else { key_deposit },
        currently_delegated_drep: info.and_then(|i| i.delegated_drep),
    })
}

#[derive(Serialize)]
pub(crate) struct DrepDelegatePreview {
    payment_address: String,
    stake_address: String,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    register_stake: bool,
    deposit_lovelace: u64,
    currently_delegated_drep: Option<String>,
    chain_context: ChainContext,
}

pub(crate) async fn drep_delegate_preview(
    State(app): State<Arc<AppState>>,
    Query(q): Query<crate::util::SourceQuery>,
) -> Result<Json<DrepDelegatePreview>, ErrorEnvelope> {
    let payment_address = {
        let cfg = app.config.read().unwrap();
        crate::util::resolve_source(&cfg, q.source.as_deref())?
    };
    let stake_address = crate::util::stake_address_from_base(&payment_address)?;

    let (owned, total) =
        fetch_owned_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    let (tip, params) = tip_and_params(&app).await?;
    let reg = registration_state(&app, &stake_address, params.key_deposit).await?;

    Ok(Json(DrepDelegatePreview {
        payment_address,
        stake_address,
        payment_utxos: utxo_summaries(&owned),
        payment_utxo_total_lovelace: total,
        register_stake: reg.register_stake,
        deposit_lovelace: reg.deposit_lovelace,
        currently_delegated_drep: reg.currently_delegated_drep,
        chain_context: chain_context_from_tip(&tip)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DrepDelegateStartBody {
    /// Which own wallet funds this delegation. Omitted = the single own wallet.
    #[serde(default)]
    pub source_address: Option<String>,
    /// `abstain`, `no_confidence`, or a `drep1…` id.
    pub target: String,
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct DrepDelegateStartResponse {
    request: shared::delegate::DrepDelegateRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

pub(crate) async fn drep_delegate_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<DrepDelegateStartBody>,
) -> Result<Json<DrepDelegateStartResponse>, ErrorEnvelope> {
    let StartCtx {
        own_sk,
        peer_pk,
        payment_address,
        stake_address,
    } = start_ctx(&app, &body.pin, body.source_address.as_deref())?;
    let stake_address = stake_address.ok_or_else(|| {
        ErrorEnvelope::invalid(
            "this wallet is an enterprise address (no stake) and cannot delegate",
        )
    })?;
    let target = parse_target(&body.target)?;

    let (tip, params) = tip_and_params(&app).await?;
    let ttl_slot = tip.abs_slot.saturating_add(TTL_MARGIN_SLOTS);
    let reg = registration_state(&app, &stake_address, params.key_deposit).await?;
    let (owned, _total) =
        fetch_owned_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    if owned.is_empty() {
        return Err(ErrorEnvelope::insufficient_funds(
            "no UTXOs at payment address",
        ));
    }

    let built = tx_builder::build_drep_delegation_body(
        &payment_address,
        &stake_address,
        &target,
        reg.register_stake,
        reg.deposit_lovelace,
        &owned,
        ttl_slot,
        params.min_fee_a,
        params.min_fee_b,
        params.utxo_cost_per_byte,
    )
    .map_err(map_build_err)?;

    crate::util::guard_tx_size(built.body_cbor.len(), 2, params.max_tx_size)?;

    crate::util::guard_fee(built.fee_lovelace)?;

    let body_hash_hex = hex::encode(pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor));
    let chain_context = chain_context_from_tip(&tip)?;
    let inputs = build_request_inputs(&built.inputs, &owned, &payment_address);
    let mut request = shared::delegate::DrepDelegateRequest {
        kind: shared::wire_kind::WalletWireKind::DrepDelegate,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        target,
        register_stake: reg.register_stake,
        deposit_lovelace: reg.deposit_lovelace,
        fee_lovelace: built.fee_lovelace,
        change_lovelace: built.change_lovelace,
        change_assets: built.change_assets,
        ttl_slot,
        payment_address_bech32: payment_address,
        stake_address_bech32: stake_address,
        inputs,
        operator_pin_proof: String::new(),
        chain_context,
    };
    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof = shared::pin::pin_proof_hex(
        &body.pin,
        shared::wire_kind::WalletWireKind::DrepDelegate.wire_str(),
        request.chain_context.built_at_unix,
        &body_fp,
    );

    let (_json, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;
    Ok(Json(DrepDelegateStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
pub(crate) struct DrepDelegateResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn drep_delegate_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<DrepDelegateResultBody>,
) -> Result<Json<shared::delegate::DelegateResult>, ErrorEnvelope> {
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
    let result = serde_json::from_slice(&json_bytes).map_err(|e| {
        error!(error = %e, "invalid result payload");
        ErrorEnvelope::invalid("invalid result payload")
    })?;
    Ok(Json(result))
}
