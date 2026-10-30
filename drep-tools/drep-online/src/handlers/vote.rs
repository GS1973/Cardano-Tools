use crate::{
    koios, tx_builder,
    util::{
        build_request_inputs, chain_context_from_tip, fetch_payment_utxos, parse_anchor, start_ctx,
        StartCtx, UtxoSummary, TTL_MARGIN_SLOTS,
    },
    AppState,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use shared::chain_context::ChainContext;
use shared::error::ErrorEnvelope;
use shared::vote::VoteChoice;
use shared::wire_io::ur_decode_required;
use std::sync::Arc;
use tracing::error;

/// One open governance action, distilled for the operator's picker. The
/// action id (`action_tx_hash` + `action_index`) is the source of truth.
#[derive(Serialize)]
pub(crate) struct VoteProposalSummary {
    proposal_id: Option<String>,
    action_tx_hash: String,
    action_index: u32,
    proposal_type: String,
    title: Option<String>,
    proposed_epoch: Option<u64>,
    expiration_epoch: Option<u64>,
    target_protocol_major: Option<u64>,
}

fn summarize(p: koios::Proposal) -> VoteProposalSummary {
    let title = p
        .meta_json
        .as_ref()
        .and_then(|m| m.get("body"))
        .and_then(|b| b.get("title"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    let target_protocol_major = p
        .proposal_description
        .as_ref()
        .and_then(|d| d.get("contents"))
        .and_then(|c| c.get(1))
        .and_then(|v| v.get("major"))
        .and_then(|m| m.as_u64());
    VoteProposalSummary {
        proposal_id: p.proposal_id,
        action_tx_hash: p.proposal_tx_hash,
        action_index: p.proposal_index,
        proposal_type: p.proposal_type,
        title,
        proposed_epoch: p.proposed_epoch,
        expiration_epoch: p.expiration,
        target_protocol_major,
    }
}

#[derive(Serialize)]
pub(crate) struct VotePreview {
    drep_id: String,
    payment_address: String,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    estimated_fee_lovelace: u64,
    can_cover: bool,
    /// Whether Koios reports this DRep as currently registered. A vote from
    /// an unregistered DRep is rejected by the ledger; the UI warns on this
    /// and `vote_start` hard-blocks it.
    registered: bool,
    /// Every open governance action: a DRep votes on all action types, so
    /// nothing is filtered out (unlike the SPO tool).
    proposals: Vec<VoteProposalSummary>,
    /// Configured manifest base URL, so the form can offer file-name entry.
    manifest_base_url: Option<String>,
    chain_context: ChainContext,
}

/// Whether Koios reports this DRep as currently registered. A DRep must be
/// registered to vote, the ledger rejects a vote from an unregistered
/// credential, so preview warns on it and start hard-blocks on it. Uses
/// the same predicate as the register / update previews.
async fn is_drep_registered(app: &Arc<AppState>, drep_id: &str) -> Result<bool, ErrorEnvelope> {
    let info = koios::drep_info(&app.http, &app.koios_base_url, drep_id)
        .await
        .map_err(|e| {
            error!(error = %e, "koios drep_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    Ok(crate::util::drep_is_registered(info.as_ref()))
}

pub(crate) async fn vote_preview(
    State(app): State<Arc<AppState>>,
) -> Result<Json<VotePreview>, ErrorEnvelope> {
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
    let proposals: Vec<VoteProposalSummary> = koios::proposal_list(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios proposal_list failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?
        .into_iter()
        .map(summarize)
        .collect();
    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let registered = is_drep_registered(&app, &drep_id).await?;
    let fee_params = crate::util::fee_params(&app).await?;
    let estimated_fee = tx_builder::preview_fee_lovelace(
        utxos.len(),
        crate::util::input_assets(&utxos)?.len(),
        &fee_params,
    );
    Ok(Json(VotePreview {
        drep_id,
        payment_address,
        payment_utxos,
        payment_utxo_total_lovelace: total,
        estimated_fee_lovelace: estimated_fee,
        can_cover: total >= estimated_fee,
        registered,
        proposals,
        manifest_base_url: cfg.manifest_base_url.clone(),
        chain_context: chain_context_from_tip(&tip)?,
    }))
}

fn parse_vote_choice(raw: &str) -> Result<VoteChoice, ErrorEnvelope> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "yes" => Ok(VoteChoice::Yes),
        "no" => Ok(VoteChoice::No),
        "abstain" => Ok(VoteChoice::Abstain),
        other => Err(ErrorEnvelope::invalid(format!(
            "unknown vote choice: {other} (expected yes / no / abstain)"
        ))),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VoteStartBody {
    pub action_tx_hash: String,
    pub action_index: u32,
    pub vote: String,
    pub anchor_url: Option<String>,
    pub anchor_hash: Option<String>,
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct VoteStartResponse {
    request: shared::vote::DRepVoteRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

pub(crate) async fn vote_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<VoteStartBody>,
) -> Result<Json<VoteStartResponse>, ErrorEnvelope> {
    let StartCtx {
        own_sk,
        peer_pk,
        drep_id_bech32,
        drep_keyhash,
        payment_address,
    } = start_ctx(&app, &body.pin)?;
    let vote = parse_vote_choice(&body.vote)?;
    let action_tx_hash = body.action_tx_hash.trim().to_string();
    if action_tx_hash.len() != 64 || !action_tx_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ErrorEnvelope::invalid(
            "action_tx_hash must be 64 hex chars (32-byte tx hash)",
        ));
    }
    let anchor_pair = parse_anchor(&body.anchor_url, &body.anchor_hash)?;

    // A vote from an unregistered DRep is rejected by the ledger: block it
    // here so a doomed transaction never reaches the signer.
    if !is_drep_registered(&app, &drep_id_bech32).await? {
        return Err(ErrorEnvelope::invalid(
            "DRep is not registered: register it before voting",
        ));
    }

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
    let built = tx_builder::build_vote_body(&tx_builder::VoteInputs {
        fee_params,
        utxo_inputs: &utxo_inputs,
        utxo_total_lovelace: total,
        change_assets: &change_assets,
        payment_address_bech32: &payment_address,
        drep_keyhash,
        action_tx_hash_hex: &action_tx_hash,
        action_index: body.action_index,
        vote,
        anchor: anchor_pair.as_ref().map(|(u, h)| tx_builder::AnchorInput {
            url: u.clone(),
            hash_hex: h.clone(),
        }),
        ttl_slot,
    })
    .map_err(|e| match e {
        tx_builder::TxBuildError::InsufficientInputs { .. } => {
            ErrorEnvelope::insufficient_funds("payment address cannot cover fee + min-ADA change")
        }
        e => {
            error!(error = %e, "vote body build failed");
            ErrorEnvelope::internal("transaction build failed")
        }
    })?;
    let fee = built.fee_lovelace;
    crate::util::guard_fee(fee)?;

    let body_hash_hex = hex::encode(pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor));
    let chain_context = chain_context_from_tip(&tip)?;
    let request_inputs = build_request_inputs(&utxo_inputs, &amounts, &payment_address);
    let mut request = shared::vote::DRepVoteRequest {
        kind: shared::wire_kind::DrepWireKind::DrepVote,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        fee_lovelace: fee,
        change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
        ttl_slot,
        payment_address_bech32: payment_address,
        drep_id_bech32,
        action_tx_hash_hex: action_tx_hash,
        action_index: body.action_index,
        vote,
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
        "drep_vote",
        request.chain_context.built_at_unix,
        &body_fp,
    );
    let (_json, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;
    Ok(Json(VoteStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
pub(crate) struct VoteResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn vote_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<VoteResultBody>,
) -> Result<Json<shared::vote::DRepVoteResult>, ErrorEnvelope> {
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
