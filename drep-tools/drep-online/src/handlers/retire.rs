use crate::{
    koios, tx_builder,
    util::{
        build_request_inputs, chain_context_from_tip, check_supply_bound, fetch_payment_utxos,
        start_ctx, StartCtx, UtxoSummary, TTL_MARGIN_SLOTS,
    },
    AppState,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use shared::chain_context::ChainContext;
use shared::error::ErrorEnvelope;
use shared::wire_io::ur_decode_required;
use std::sync::Arc;
use tracing::error;

/// Read the locked deposit (refund amount) from Koios `drep_info`. Errors
/// if the DRep is not registered or Koios reports no deposit: retiring
/// without a deposit to refund would be a malformed cert.
async fn deposit_refund(app: &Arc<AppState>, drep_id: &str) -> Result<u64, ErrorEnvelope> {
    let info = koios::drep_info(&app.http, &app.koios_base_url, drep_id)
        .await
        .map_err(|e| {
            error!(error = %e, "koios drep_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let info = info.ok_or(ErrorEnvelope::invalid(
        "DRep is not registered: nothing to retire",
    ))?;
    let refund_str = info.deposit.ok_or(ErrorEnvelope::invalid(
        "Koios reports no locked deposit for this DRep",
    ))?;
    let refund = refund_str
        .parse::<u64>()
        .map_err(|_| ErrorEnvelope::upstream("drep_info.deposit is not a u64"))?;
    check_supply_bound(refund, "drep_info.deposit")?;
    Ok(refund)
}

#[derive(Serialize)]
pub(crate) struct RetirePreview {
    drep_id: String,
    payment_address: String,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    deposit_refund_lovelace: u64,
    estimated_fee_lovelace: u64,
    can_cover: bool,
    chain_context: ChainContext,
}

pub(crate) async fn retire_preview(
    State(app): State<Arc<AppState>>,
) -> Result<Json<RetirePreview>, ErrorEnvelope> {
    let cfg = app.config.read().unwrap().clone();
    let drep_id = cfg
        .drep_id
        .clone()
        .ok_or(ErrorEnvelope::not_configured("DRep id not configured"))?;
    let payment_address = cfg
        .payment_address
        .clone()
        .ok_or(ErrorEnvelope::not_configured(
            "payment_address not configured",
        ))?;
    let (utxos, amounts, total) =
        fetch_payment_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    let payment_utxos = utxos
        .iter()
        .zip(amounts.iter())
        .map(|(u, &lovelace)| UtxoSummary {
            tx_hash: u.tx_hash.clone(),
            tx_index: u.tx_index,
            lovelace,
        })
        .collect();
    let refund = deposit_refund(&app, &drep_id).await?;
    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let fee_params = crate::util::fee_params(&app).await?;
    let estimated_fee = tx_builder::preview_fee_lovelace(
        utxos.len(),
        crate::util::input_assets(&utxos)?.len(),
        &fee_params,
    );
    Ok(Json(RetirePreview {
        drep_id,
        payment_address,
        payment_utxos,
        payment_utxo_total_lovelace: total,
        deposit_refund_lovelace: refund,
        estimated_fee_lovelace: estimated_fee,
        can_cover: total >= estimated_fee,
        chain_context: chain_context_from_tip(&tip)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetireStartBody {
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct RetireStartResponse {
    request: shared::retire::DRepRetireRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

pub(crate) async fn retire_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<RetireStartBody>,
) -> Result<Json<RetireStartResponse>, ErrorEnvelope> {
    let StartCtx {
        own_sk,
        peer_pk,
        drep_id_bech32,
        drep_keyhash,
        payment_address,
    } = start_ctx(&app, &body.pin)?;
    let refund = deposit_refund(&app, &drep_id_bech32).await?;

    let (utxos, amounts, total) =
        fetch_payment_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    let utxo_inputs: Vec<tx_builder::TxInput> = utxos
        .iter()
        .map(|u| tx_builder::TxInput {
            tx_hash_hex: u.tx_hash.clone(),
            tx_index: u.tx_index,
        })
        .collect();
    if utxo_inputs.is_empty() {
        return Err(ErrorEnvelope::insufficient_funds(
            "no UTXOs at payment address",
        ));
    }
    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let ttl_slot = tip.abs_slot.saturating_add(TTL_MARGIN_SLOTS);

    let change_assets = crate::util::input_assets(&utxos)?;

    // The fee is computed from the encoded body size inside the builder; an
    // underfunded wallet surfaces here as a clear insufficient-funds error,
    // before anything reaches the signer.
    let fee_params = crate::util::fee_params(&app).await?;
    let built = tx_builder::build_retire_body(&tx_builder::RetireInputs {
        fee_params,
        utxo_inputs: &utxo_inputs,
        utxo_total_lovelace: total,
        change_assets: &change_assets,
        payment_address_bech32: &payment_address,
        drep_keyhash,
        deposit_refund_lovelace: refund,
        ttl_slot,
    })
    .map_err(|e| match e {
        tx_builder::TxBuildError::InsufficientInputs { .. } => {
            ErrorEnvelope::insufficient_funds("payment address cannot cover fee + min-ADA change")
        }
        e => {
            error!(error = %e, "retire body build failed");
            ErrorEnvelope::internal("transaction build failed")
        }
    })?;
    let fee = built.fee_lovelace;
    crate::util::guard_fee(fee)?;

    let body_hash_hex = hex::encode(pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor));
    let chain_context = chain_context_from_tip(&tip)?;
    let request_inputs = build_request_inputs(&utxo_inputs, &amounts, &payment_address);
    let mut request = shared::retire::DRepRetireRequest {
        kind: shared::wire_kind::DrepWireKind::DrepRetire,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        fee_lovelace: fee,
        change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
        deposit_refund_lovelace: refund,
        ttl_slot,
        payment_address_bech32: payment_address,
        drep_id_bech32,
        inputs: request_inputs,
        operator_pin_proof: String::new(),
        chain_context,
    };
    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof = shared::pin::pin_proof_hex(
        &body.pin,
        "drep_retire",
        request.chain_context.built_at_unix,
        &body_fp,
    );
    let (_json, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;
    Ok(Json(RetireStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
pub(crate) struct RetireResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn retire_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<RetireResultBody>,
) -> Result<Json<shared::retire::DRepRetireResult>, ErrorEnvelope> {
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
