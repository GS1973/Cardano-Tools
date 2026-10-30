use crate::{
    tx_builder,
    util::{
        build_request_inputs, chain_context_from_tip, fetch_owned_utxos, fetch_payment_preview,
        start_ctx, tip_and_params, utxo_summaries, HeldAsset, StartCtx, UtxoSummary,
        TTL_MARGIN_SLOTS,
    },
    AppState,
};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use shared::asset::Asset;
use shared::chain_context::ChainContext;
use shared::error::ErrorEnvelope;
use shared::wire_io::ur_decode_required;
use std::sync::Arc;
use tracing::error;

#[derive(Serialize)]
pub(crate) struct PaymentPreview {
    payment_address: String,
    payment_utxos: Vec<UtxoSummary>,
    payment_assets: Vec<HeldAsset>,
    payment_utxo_total_lovelace: u64,
    chain_context: ChainContext,
}

pub(crate) async fn payment_preview(
    State(app): State<Arc<AppState>>,
    Query(q): Query<crate::util::SourceQuery>,
) -> Result<Json<PaymentPreview>, ErrorEnvelope> {
    let payment_address = {
        let cfg = app.config.read().unwrap();
        crate::util::resolve_source(&cfg, q.source.as_deref())?
    };
    let (owned, total, held) =
        fetch_payment_preview(&app.http, &app.koios_base_url, &payment_address).await?;
    let tip = crate::koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    Ok(Json(PaymentPreview {
        payment_address,
        payment_utxos: utxo_summaries(&owned),
        payment_assets: held,
        payment_utxo_total_lovelace: total,
        chain_context: chain_context_from_tip(&tip)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PaymentStartBody {
    /// Which own wallet funds this payment. Omitted = the single own wallet.
    #[serde(default)]
    pub source_address: Option<String>,
    pub destination_address: String,
    /// ADA to send, in lovelace. A plain JSON number (not the DisplayFromStr
    /// string form the wire types use): the frontend sends a Number.
    pub amount_lovelace: u64,
    /// Native assets to send (empty for a pure-ADA send).
    #[serde(default)]
    pub assets_sent: Vec<Asset>,
    pub pin: String,
    /// Optional CIP-20 (label 674) message lines, each <=64 bytes UTF-8.
    #[serde(default)]
    pub metadata_msg: Option<Vec<String>>,
}

#[derive(Serialize)]
pub(crate) struct PaymentStartResponse {
    request: shared::payment::PaymentRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

pub(crate) async fn payment_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<PaymentStartBody>,
) -> Result<Json<PaymentStartResponse>, ErrorEnvelope> {
    let StartCtx {
        own_sk,
        peer_pk,
        payment_address,
        stake_address: _,
    } = start_ctx(&app, &body.pin, body.source_address.as_deref())?;

    let destination_address = body.destination_address.trim().to_string();
    crate::config::validate_bech32(&destination_address, "addr")
        .map_err(|_| ErrorEnvelope::invalid("destination address is not a valid addr1… address"))?;
    if shared::tx_validator::payment_part_is_script(&destination_address)
        .map_err(|_| ErrorEnvelope::invalid("destination address is not a valid addr1… address"))?
    {
        return Err(ErrorEnvelope::invalid(format!(
            "Destination refused: {}",
            shared::tx_validator::SCRIPT_DESTINATION_REFUSED
        )));
    }

    let (tip, params) = tip_and_params(&app).await?;
    let ttl_slot = tip.abs_slot.saturating_add(TTL_MARGIN_SLOTS);
    let (owned, _total) =
        fetch_owned_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    if owned.is_empty() {
        return Err(ErrorEnvelope::insufficient_funds(
            "no UTXOs at payment address",
        ));
    }

    let built = tx_builder::build_payment_body(
        &payment_address,
        &destination_address,
        body.amount_lovelace,
        &body.assets_sent,
        &owned,
        ttl_slot,
        params.min_fee_a,
        params.min_fee_b,
        params.utxo_cost_per_byte,
        body.metadata_msg.as_deref(),
    )
    .map_err(map_build_err)?;

    crate::util::guard_tx_size(
        built.body_cbor.len() + built.aux_data_cbor.as_ref().map_or(0, |c| c.len()),
        1,
        params.max_tx_size,
    )?;

    crate::util::guard_fee(built.fee_lovelace)?;

    let body_hash_hex = hex::encode(pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor));
    let chain_context = chain_context_from_tip(&tip)?;
    let inputs = build_request_inputs(&built.inputs, &owned, &payment_address);
    let mut request = shared::payment::PaymentRequest {
        kind: shared::wire_kind::WalletWireKind::Payment,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        destination_address_bech32: destination_address,
        amount_lovelace: body.amount_lovelace,
        assets_sent: body.assets_sent,
        fee_lovelace: built.fee_lovelace,
        change_lovelace: built.change_lovelace,
        change_assets: built.change_assets,
        ttl_slot,
        payment_address_bech32: payment_address,
        inputs,
        operator_pin_proof: String::new(),
        chain_context,
        metadata_msg: body.metadata_msg,
    };
    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof = shared::pin::pin_proof_hex(
        &body.pin,
        shared::wire_kind::WalletWireKind::Payment.wire_str(),
        request.chain_context.built_at_unix,
        &body_fp,
    );

    let (_json, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;
    Ok(Json(PaymentStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
pub(crate) struct PaymentResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn payment_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<PaymentResultBody>,
) -> Result<Json<shared::payment::PaymentResult>, ErrorEnvelope> {
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

/// Map a tx-builder error onto an operator-actionable envelope: funding
/// shortfalls become 409 insufficient-funds, anything else is a 400 with a
/// short reason (no chain detail leaks).
pub(crate) fn map_build_err(e: tx_builder::WalletTxError) -> ErrorEnvelope {
    use tx_builder::WalletTxError::*;
    match e {
        InsufficientLovelace { .. } => {
            ErrorEnvelope::insufficient_funds("payment address cannot cover amount + fee + change")
        }
        Tx(shared::tx::TxBuildError::InsufficientAsset { .. }) => {
            ErrorEnvelope::insufficient_funds(
                "payment address does not hold enough of a sent asset",
            )
        }
        OutputBelowMinAda { need, .. } => ErrorEnvelope::invalid(format!(
            "amount is below the minimum-ADA for this output ({need} lovelace)"
        )),
        other => {
            error!(error = %other, "payment body build failed");
            ErrorEnvelope::invalid("transaction build failed")
        }
    }
}
