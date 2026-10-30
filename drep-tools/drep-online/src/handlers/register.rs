use crate::{
    koios, tx_builder,
    util::{
        build_request_inputs, chain_context_from_tip, check_supply_bound, drep_is_registered,
        fetch_payment_utxos, parse_anchor, start_ctx, StartCtx, UtxoSummary, TTL_MARGIN_SLOTS,
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

#[derive(Serialize)]
pub(crate) struct RegisterPreview {
    drep_id: String,
    payment_address: String,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    deposit_lovelace: u64,
    estimated_fee_lovelace: u64,
    can_cover: bool,
    /// True when Koios already reports this DRep as registered: registering
    /// again would be rejected on-chain.
    already_registered: bool,
    /// Configured manifest base URL, so the form can offer file-name entry.
    manifest_base_url: Option<String>,
    chain_context: ChainContext,
}

pub(crate) async fn register_preview(
    State(app): State<Arc<AppState>>,
) -> Result<Json<RegisterPreview>, ErrorEnvelope> {
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

    let deposit = koios::drep_deposit_lovelace(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios epoch_params failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    check_supply_bound(deposit, "drep_deposit")?;
    let info = koios::drep_info(&app.http, &app.koios_base_url, &drep_id)
        .await
        .map_err(|e| {
            error!(error = %e, "koios drep_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let already_registered = drep_is_registered(info.as_ref());

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
    Ok(Json(RegisterPreview {
        drep_id,
        payment_address,
        payment_utxos,
        payment_utxo_total_lovelace: total,
        deposit_lovelace: deposit,
        estimated_fee_lovelace: estimated_fee,
        can_cover: total >= estimated_fee.saturating_add(deposit),
        already_registered,
        manifest_base_url: cfg.manifest_base_url.clone(),
        chain_context: chain_context_from_tip(&tip)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterStartBody {
    pub anchor_url: Option<String>,
    pub anchor_hash: Option<String>,
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct RegisterStartResponse {
    request: shared::register::DRepRegisterRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

pub(crate) async fn register_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<RegisterStartBody>,
) -> Result<Json<RegisterStartResponse>, ErrorEnvelope> {
    let StartCtx {
        own_sk,
        peer_pk,
        drep_id_bech32,
        drep_keyhash,
        payment_address,
    } = start_ctx(&app, &body.pin)?;
    let anchor_pair = parse_anchor(&body.anchor_url, &body.anchor_hash)?;

    let deposit = koios::drep_deposit_lovelace(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios epoch_params failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    check_supply_bound(deposit, "drep_deposit")?;
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
    let built = tx_builder::build_register_body(&tx_builder::RegisterInputs {
        fee_params,
        utxo_inputs: &utxo_inputs,
        utxo_total_lovelace: total,
        change_assets: &change_assets,
        payment_address_bech32: &payment_address,
        drep_keyhash,
        deposit_lovelace: deposit,
        anchor: anchor_pair.as_ref().map(|(u, h)| tx_builder::AnchorInput {
            url: u.clone(),
            hash_hex: h.clone(),
        }),
        ttl_slot,
    })
    .map_err(|e| match e {
        tx_builder::TxBuildError::InsufficientInputs { .. } => ErrorEnvelope::insufficient_funds(
            "payment address cannot cover fee + deposit + min-ADA change",
        ),
        e => {
            error!(error = %e, "register body build failed");
            ErrorEnvelope::internal("transaction build failed")
        }
    })?;
    let fee = built.fee_lovelace;
    crate::util::guard_fee(fee)?;

    let body_hash_hex = hex::encode(pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor));
    let chain_context = chain_context_from_tip(&tip)?;
    let request_inputs = build_request_inputs(&utxo_inputs, &amounts, &payment_address);
    let mut request = shared::register::DRepRegisterRequest {
        kind: shared::wire_kind::DrepWireKind::DrepRegister,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        fee_lovelace: fee,
        change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
        deposit_lovelace: deposit,
        ttl_slot,
        payment_address_bech32: payment_address,
        drep_id_bech32,
        anchor: anchor_pair.map(|(u, h)| shared::anchor::GovAnchor {
            url: u,
            hash_hex: h,
        }),
        inputs: request_inputs,
        operator_pin_proof: String::new(),
        chain_context,
    };
    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof = shared::pin::pin_proof_hex(
        &body.pin,
        "drep_register",
        request.chain_context.built_at_unix,
        &body_fp,
    );

    let (_json, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;
    Ok(Json(RegisterStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
pub(crate) struct RegisterResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn register_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<RegisterResultBody>,
) -> Result<Json<shared::register::DRepRegisterResult>, ErrorEnvelope> {
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
