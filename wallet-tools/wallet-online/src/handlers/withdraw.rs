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

/// What the chain says about the wallet's reward account: whether it exists,
/// what can be withdrawn, and whether the ledger will allow it.
struct RewardState {
    registered: bool,
    rewards_lovelace: u64,
    delegated_pool: Option<String>,
    delegated_drep: Option<String>,
}

impl RewardState {
    /// Why a withdrawal cannot be built right now, if it cannot. The ledger
    /// refuses a withdrawal from a key-controlled reward account that is not
    /// delegated to a DRep, judged on the state before the transaction's own
    /// certificates, so the vote delegation has to be on chain first.
    fn blocker(&self) -> Option<&'static str> {
        if !self.registered {
            Some("this stake key is not registered, so it has no reward account to withdraw from")
        } else if self.rewards_lovelace == 0 {
            Some("there are no rewards to withdraw")
        } else if self.delegated_drep.is_none() {
            Some("rewards can only be withdrawn once the vote is delegated to a DRep. Use Delegate vote first, then withdraw")
        } else {
            None
        }
    }
}

async fn reward_state(
    app: &Arc<AppState>,
    stake_address: &str,
) -> Result<RewardState, ErrorEnvelope> {
    let info = koios::account_info(&app.http, &app.koios_base_url, stake_address)
        .await
        .map_err(|e| {
            error!(error = %e, "koios account_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let Some(info) = info else {
        return Ok(RewardState {
            registered: false,
            rewards_lovelace: 0,
            delegated_pool: None,
            delegated_drep: None,
        });
    };
    let rewards_lovelace = info.rewards_available().map_err(|e| {
        error!(error = %e, "koios rewards_available parse failed");
        ErrorEnvelope::upstream("reward balance not a u64")
    })?;
    Ok(RewardState {
        registered: info.is_registered(),
        rewards_lovelace,
        delegated_pool: info.delegated_pool,
        delegated_drep: info.delegated_drep,
    })
}

#[derive(Serialize)]
pub(crate) struct WithdrawPreview {
    payment_address: String,
    stake_address: String,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    registered: bool,
    rewards_lovelace: u64,
    currently_delegated_pool: Option<String>,
    currently_delegated_drep: Option<String>,
    /// Why a withdrawal cannot be built right now; null when it can.
    blocker: Option<&'static str>,
    chain_context: ChainContext,
}

pub(crate) async fn withdraw_preview(
    State(app): State<Arc<AppState>>,
    Query(q): Query<crate::util::SourceQuery>,
) -> Result<Json<WithdrawPreview>, ErrorEnvelope> {
    let payment_address = {
        let cfg = app.config.read().unwrap();
        crate::util::resolve_source(&cfg, q.source.as_deref())?
    };
    let stake_address = crate::util::stake_address_from_base(&payment_address)?;

    let (owned, total) =
        fetch_owned_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let state = reward_state(&app, &stake_address).await?;

    Ok(Json(WithdrawPreview {
        payment_address,
        stake_address,
        payment_utxos: utxo_summaries(&owned),
        payment_utxo_total_lovelace: total,
        registered: state.registered,
        rewards_lovelace: state.rewards_lovelace,
        blocker: state.blocker(),
        currently_delegated_pool: state.delegated_pool,
        currently_delegated_drep: state.delegated_drep,
        chain_context: chain_context_from_tip(&tip)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WithdrawStartBody {
    /// Which own wallet withdraws its rewards. Omitted = the single own wallet.
    #[serde(default)]
    pub source_address: Option<String>,
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct WithdrawStartResponse {
    request: shared::withdraw::WithdrawRewardsRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

pub(crate) async fn withdraw_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<WithdrawStartBody>,
) -> Result<Json<WithdrawStartResponse>, ErrorEnvelope> {
    let StartCtx {
        own_sk,
        peer_pk,
        payment_address,
        stake_address,
    } = start_ctx(&app, &body.pin, body.source_address.as_deref())?;
    let stake_address = stake_address.ok_or_else(|| {
        ErrorEnvelope::invalid(
            "this wallet is an enterprise address (no stake) and earns no rewards",
        )
    })?;

    let (tip, params) = tip_and_params(&app).await?;
    let ttl_slot = tip.abs_slot.saturating_add(TTL_MARGIN_SLOTS);
    let state = reward_state(&app, &stake_address).await?;
    if let Some(why) = state.blocker() {
        return Err(ErrorEnvelope::invalid(why));
    }
    let (owned, _total) =
        fetch_owned_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    if owned.is_empty() {
        return Err(ErrorEnvelope::insufficient_funds(
            "no UTXOs at payment address: a withdrawal needs one to spend",
        ));
    }

    let built = tx_builder::build_withdraw_rewards_body(
        &payment_address,
        &stake_address,
        state.rewards_lovelace,
        &owned,
        ttl_slot,
        params.min_fee_a,
        params.min_fee_b,
        params.utxo_cost_per_byte,
    )
    .map_err(|e| match e {
        tx_builder::WalletTxError::InsufficientLovelace { .. } => {
            ErrorEnvelope::insufficient_funds(
                "payment address plus rewards cannot cover the fee and a minimum-ADA change output",
            )
        }
        other => map_build_err(other),
    })?;

    crate::util::guard_tx_size(built.body_cbor.len(), 2, params.max_tx_size)?;

    crate::util::guard_fee(built.fee_lovelace)?;

    let body_hash_hex = hex::encode(pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor));
    let chain_context = chain_context_from_tip(&tip)?;
    let inputs = build_request_inputs(&built.inputs, &owned, &payment_address);
    let mut request = shared::withdraw::WithdrawRewardsRequest {
        kind: shared::wire_kind::WalletWireKind::WithdrawRewards,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        rewards_lovelace: state.rewards_lovelace,
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
        shared::wire_kind::WalletWireKind::WithdrawRewards.wire_str(),
        request.chain_context.built_at_unix,
        &body_fp,
    );

    let (_json, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;
    Ok(Json(WithdrawStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
pub(crate) struct WithdrawResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn withdraw_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<WithdrawResultBody>,
) -> Result<Json<shared::withdraw::WithdrawRewardsResult>, ErrorEnvelope> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn state(registered: bool, rewards: u64, drep: Option<&str>) -> RewardState {
        RewardState {
            registered,
            rewards_lovelace: rewards,
            delegated_pool: None,
            delegated_drep: drep.map(str::to_string),
        }
    }

    #[test]
    fn blocker_names_the_first_reason_a_withdrawal_would_fail() {
        assert!(state(false, 5, Some("drep1x"))
            .blocker()
            .unwrap()
            .contains("not registered"));
        assert!(state(true, 0, Some("drep1x"))
            .blocker()
            .unwrap()
            .contains("no rewards"));
        assert!(state(true, 5, None).blocker().unwrap().contains("DRep"));
        assert!(state(true, 5, Some("drep1x")).blocker().is_none());
        // The predefined DReps count as a vote delegation too.
        assert!(state(true, 5, Some("drep_always_abstain"))
            .blocker()
            .is_none());
    }
}
