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
use shared::error::ErrorEnvelope;
use shared::wire_io::ur_decode_required;
use std::sync::Arc;
use tracing::error;

/// Whether the wallet's stake key is already registered on-chain, and the
/// current key-deposit (folded into the cert when it is not).
struct RegistrationState {
    register_stake: bool,
    deposit_lovelace: u64,
    currently_delegated_pool: Option<String>,
}

/// Read account state + protocol key-deposit. An unregistered stake key
/// means the delegation must fold in a registration cert with its deposit.
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
        currently_delegated_pool: info.and_then(|i| i.delegated_pool),
    })
}

#[derive(Serialize)]
pub(crate) struct PoolDelegatePreview {
    payment_address: String,
    stake_address: String,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    /// Whether a registration cert (+ deposit) will be folded into the tx.
    register_stake: bool,
    /// Key deposit locked when registering (0 when already registered).
    deposit_lovelace: u64,
    /// Pool the stake key is currently delegated to, if any.
    currently_delegated_pool: Option<String>,
    chain_context: ChainContext,
}

pub(crate) async fn pool_delegate_preview(
    State(app): State<Arc<AppState>>,
    Query(q): Query<crate::util::SourceQuery>,
) -> Result<Json<PoolDelegatePreview>, ErrorEnvelope> {
    let payment_address = {
        let cfg = app.config.read().unwrap();
        crate::util::resolve_source(&cfg, q.source.as_deref())?
    };
    let stake_address = crate::util::stake_address_from_base(&payment_address)?;

    let (owned, total) =
        fetch_owned_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    let (tip, params) = tip_and_params(&app).await?;
    let reg = registration_state(&app, &stake_address, params.key_deposit).await?;

    Ok(Json(PoolDelegatePreview {
        payment_address,
        stake_address,
        payment_utxos: utxo_summaries(&owned),
        payment_utxo_total_lovelace: total,
        register_stake: reg.register_stake,
        deposit_lovelace: reg.deposit_lovelace,
        currently_delegated_pool: reg.currently_delegated_pool,
        chain_context: chain_context_from_tip(&tip)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolDelegateStartBody {
    /// Which own wallet funds this delegation. Omitted = the single own wallet.
    #[serde(default)]
    pub source_address: Option<String>,
    pub pool_id: String,
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct PoolDelegateStartResponse {
    request: shared::delegate::PoolDelegateRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

pub(crate) async fn pool_delegate_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<PoolDelegateStartBody>,
) -> Result<Json<PoolDelegateStartResponse>, ErrorEnvelope> {
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
    let pool_id = body.pool_id.trim().to_string();
    crate::config::validate_bech32(&pool_id, "pool")
        .map_err(|_| ErrorEnvelope::invalid("pool id is not a valid pool1… id"))?;

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

    let built = tx_builder::build_pool_delegation_body(
        &payment_address,
        &stake_address,
        &pool_id,
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
    let mut request = shared::delegate::PoolDelegateRequest {
        kind: shared::wire_kind::WalletWireKind::PoolDelegate,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        pool_id_bech32: pool_id,
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
        shared::wire_kind::WalletWireKind::PoolDelegate.wire_str(),
        request.chain_context.built_at_unix,
        &body_fp,
    );

    let (_json, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;
    Ok(Json(PoolDelegateStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
pub(crate) struct PoolDelegateResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn pool_delegate_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<PoolDelegateResultBody>,
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
