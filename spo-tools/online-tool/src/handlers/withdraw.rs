use crate::{
    koios, state, tx_builder,
    util::{chain_context_from, paired_keys_or_err, UtxoSummary, TTL_MARGIN_SLOTS},
    AppState,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use shared::error::ErrorEnvelope;
use shared::{chain_context::ChainContext, wire_io::ur_decode_required};
use std::sync::Arc;
use tracing::error;

#[derive(Serialize)]
pub(crate) struct WithdrawPreview {
    pool_id_bech32: String,
    pool_reward_address: String,
    reward_receive_address: String,
    payment_address: String,
    rewards_available_lovelace: u64,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    estimated_fee_lovelace: u64,
    net_to_reward_address_lovelace: u64,
    change_to_payment_address_lovelace: u64,
    /// True iff payment_address has enough to cover the fee.
    can_cover_fee: bool,
    /// True iff there is anything to withdraw.
    has_rewards: bool,
    chain_context: ChainContext,
}

pub(crate) async fn withdraw_preview(
    State(app): State<Arc<AppState>>,
) -> Result<Json<WithdrawPreview>, ErrorEnvelope> {
    let params = app.require_genesis()?;
    let cfg = app.config.read().unwrap_or_else(|e| e.into_inner()).clone();
    let pool_id = cfg
        .pool_id
        .clone()
        .ok_or(ErrorEnvelope::not_configured("pool not configured"))?;
    let payment_address = cfg
        .payment_address
        .clone()
        .ok_or(ErrorEnvelope::not_configured(
            "payment_address not configured",
        ))?;
    let reward_receive_address =
        cfg.reward_receive_address
            .clone()
            .ok_or(ErrorEnvelope::not_configured(
                "reward_receive_address not configured",
            ))?;

    let pool = koios::pool_info(&app.http, &app.koios_base_url, &pool_id)
        .await
        .map_err(|e| {
            error!(error = %e, "koios pool_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let pool_reward_address = pool.reward_addr.ok_or(ErrorEnvelope::upstream(
        "pool reward address missing from Koios response",
    ))?;

    let acct = koios::account_info(&app.http, &app.koios_base_url, &pool_reward_address)
        .await
        .map_err(|e| {
            error!(error = %e, "koios account_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?
        .ok_or(ErrorEnvelope::upstream(
            "pool reward stake account not found on chain",
        ))?;
    let rewards_available_lovelace: u64 = acct.rewards_available.parse().map_err(|_| {
        ErrorEnvelope::upstream("unexpected rewards_available format from upstream")
    })?;

    let (utxos, amounts, payment_utxo_total_lovelace) =
        crate::util::fetch_payment_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    let payment_utxos: Vec<UtxoSummary> = utxos
        .iter()
        .zip(amounts.iter())
        .map(|(u, &lovelace)| UtxoSummary {
            tx_hash: u.tx_hash.clone(),
            tx_index: u.tx_index,
            lovelace,
        })
        .collect();

    let fee_params = crate::util::fee_params(&app).await?;
    let estimated_fee_lovelace = tx_builder::preview_fee_lovelace(
        tx_builder::TxKind::Withdrawal,
        utxos.len(),
        crate::util::input_assets(&utxos)?.len(),
        &fee_params,
    );
    let can_cover_fee = payment_utxo_total_lovelace >= estimated_fee_lovelace;
    let has_rewards = rewards_available_lovelace > 0;
    let net_to_reward_address_lovelace = rewards_available_lovelace;
    let change_to_payment_address_lovelace =
        payment_utxo_total_lovelace.saturating_sub(estimated_fee_lovelace);

    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start)?;

    Ok(Json(WithdrawPreview {
        pool_id_bech32: pool_id,
        pool_reward_address,
        reward_receive_address,
        payment_address,
        rewards_available_lovelace,
        payment_utxos,
        payment_utxo_total_lovelace,
        estimated_fee_lovelace,
        net_to_reward_address_lovelace,
        change_to_payment_address_lovelace,
        can_cover_fee,
        has_rewards,
        chain_context,
    }))
}

#[derive(Serialize)]
pub(crate) struct WithdrawStartResponse {
    /// The full request to be sent to the signer.
    request: shared::withdrawal::WithdrawalRequest,
    /// Body hash (Blake2b-256). Convenience for the UI / logs.
    body_hash_hex: String,
    /// UR fragments encoding the request: this is what the QR animation shows.
    ur_fragments: Vec<String>,
    /// 8-byte request-payload fingerprint, blake2b256 truncated
    /// and rendered as 4 hex pairs (operator visually compares with the
    /// signer-side display before signing).
    request_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WithdrawStartBody {
    /// 4-digit operator PIN typed in the pre-send confirmation modal.
    /// Hashed into the request's operator_pin_proof so the signer can
    /// verify operator presence at sign time.
    pub pin: String,
}

pub(crate) async fn withdraw_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<WithdrawStartBody>,
) -> Result<Json<WithdrawStartResponse>, ErrorEnvelope> {
    let crate::util::StartHandlerCtx {
        params,
        own_sk,
        peer_pk,
        cfg,
        pool_id,
        payment_address,
    } = crate::util::start_handler_ctx(&app, &body.pin)?;
    let reward_receive_address =
        cfg.reward_receive_address
            .clone()
            .ok_or(ErrorEnvelope::not_configured(
                "reward_receive_address not configured",
            ))?;

    let pool = koios::pool_info(&app.http, &app.koios_base_url, &pool_id)
        .await
        .map_err(|e| {
            error!(error = %e, "koios pool_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let pool_reward_address = pool.reward_addr.ok_or(ErrorEnvelope::upstream(
        "pool reward address missing from Koios response",
    ))?;

    let acct = koios::account_info(&app.http, &app.koios_base_url, &pool_reward_address)
        .await
        .map_err(|e| {
            error!(error = %e, "koios account_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?
        .ok_or(ErrorEnvelope::upstream("stake account not found"))?;
    let rewards_lovelace: u64 = acct
        .rewards_available
        .parse()
        .map_err(|_| ErrorEnvelope::upstream("rewards_available not a u64"))?;
    if rewards_lovelace == 0 {
        return Err(ErrorEnvelope::no_rewards(
            "no rewards available to withdraw",
        ));
    }

    let (utxos, utxo_amounts, utxo_total) =
        crate::util::fetch_payment_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
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

    let fee_params = crate::util::fee_params(&app).await?;

    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let ttl_slot = tip.abs_slot.saturating_add(TTL_MARGIN_SLOTS);

    let change_assets = crate::util::input_assets(&utxos)?;

    let inputs = tx_builder::WithdrawalInputs {
        utxo_inputs: &utxo_inputs,
        change_assets: &change_assets,
        utxo_total_lovelace: utxo_total,
        payment_address_bech32: &payment_address,
        reward_receive_address_bech32: &reward_receive_address,
        pool_reward_address_bech32: &pool_reward_address,
        rewards_lovelace,
        fee_params,
        ttl_slot,
    };
    let built = tx_builder::build_withdrawal_body(&inputs).map_err(|e| match e {
        tx_builder::TxBuildError::InsufficientInputs { .. } => ErrorEnvelope::insufficient_funds(
            "rewards and change must each cover their output's min-ADA on top of the fee",
        ),
        e => {
            error!(error = %e, "tx body build failed");
            ErrorEnvelope::internal("transaction build failed")
        }
    })?;
    let fee_lovelace = built.fee_lovelace;

    let body_hash = pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor);
    let body_hash_hex = hex::encode(body_hash);

    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start)?;

    let request_inputs =
        crate::util::build_request_inputs(&utxo_inputs, &utxo_amounts, &payment_address);
    let mut request = shared::withdrawal::WithdrawalRequest {
        kind: shared::wire_kind::WireKind::Withdrawal,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        fee_lovelace,
        net_to_reward_address_lovelace: built.net_to_reward_address_lovelace,
        change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
        ttl_slot,
        payment_address_bech32: payment_address,
        reward_receive_address_bech32: reward_receive_address,
        pool_reward_address_bech32: pool_reward_address,
        inputs: request_inputs,
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

    Ok(Json(WithdrawStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WithdrawResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn withdraw_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<WithdrawResultBody>,
) -> Result<Json<shared::withdrawal::WithdrawalResult>, ErrorEnvelope> {
    if body.ur_fragments.is_empty() {
        return Err(ErrorEnvelope::invalid("no UR fragments"));
    }
    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;
    let json_bytes = ur_decode_required(
        &body.ur_fragments,
        &peer_pk,
        &own_sk,
        shared::qr::Direction::Response,
    )?;
    let result: shared::withdrawal::WithdrawalResult = serde_json::from_slice(&json_bytes)
        .map_err(|e| {
            error!(error = %e, "decode WithdrawalResult JSON failed");
            ErrorEnvelope::invalid("invalid request payload")
        })?;
    Ok(Json(result))
}
