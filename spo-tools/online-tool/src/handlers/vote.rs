use crate::{
    koios, state, tx_builder,
    util::{chain_context_from, paired_keys_or_err, UtxoSummary, TTL_MARGIN_SLOTS},
    AppState};
use shared::{chain_context::ChainContext, wire_io::ur_decode_required};
use shared::error::ErrorEnvelope;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

/// SPO governance vote is a tiny tx: 1 fee input, 1 change output, 1
/// voting procedure, 2 witnesses. Same flat overestimate as the other
/// single-cert flows.
pub(crate) const ESTIMATED_VOTE_FEE_LOVELACE: u64 = 200_000;

/// One open governance action, distilled for the operator's picker. The
/// action id (`action_tx_hash` + `action_index`) is the source of truth;
/// the title / type / target version are presentation only.
#[derive(Serialize)]
pub(crate) struct VoteProposalSummary {
    /// CIP-129 `gov_action1...` bech32, shown for cross-checking.
    pub proposal_id: Option<String>,
    pub action_tx_hash: String,
    pub action_index: u32,
    pub proposal_type: String,
    pub title: Option<String>,
    pub proposed_epoch: Option<u64>,
    pub expiration_epoch: Option<u64>,
    /// For HardForkInitiation: the target major protocol version.
    pub target_protocol_major: Option<u64>,
}

/// Conway SecurityGroup parameters — the only parameter-change group an
/// SPO may cast a counting vote on. JSON key names verified against
/// cardano-ledger Conway PParams (the `ppName` registry / ToJSON). A
/// `ParameterChange` is SPO-votable iff it touches at least one of these.
const SECURITY_GROUP_PARAMS: &[&str] = &[
    "txFeePerByte",
    "txFeeFixed",
    "maxBlockBodySize",
    "maxTxSize",
    "maxBlockHeaderSize",
    "utxoCostPerByte",
    "maxBlockExecutionUnits",
    "maxValueSize",
    "govActionDeposit",
    "minFeeRefScriptCostPerByte",
];

/// Whether an SPO (stake-pool credential) may cast a counting vote on a
/// proposal of this type, per cardano-ledger
/// `votingStakePoolThresholdInternal`:
/// - TreasuryWithdrawals / NewConstitution: never (NoVotingAllowed).
/// - ParameterChange: only if it changes a SecurityGroup parameter.
/// - everything else (HardForkInitiation, NoConfidence, NewCommittee,
///   InfoAction, or any unrecognised type): votable.
///
/// Fail-open: an unparseable ParameterChange description, or an
/// unrecognised type, is treated as votable so a parsing gap or a future
/// action type never silently hides a legitimate SPO vote.
fn is_spo_votable(p: &koios::Proposal) -> bool {
    is_spo_votable_type(&p.proposal_type, p.proposal_description.as_ref())
}

fn is_spo_votable_type(proposal_type: &str, description: Option<&serde_json::Value>) -> bool {
    match proposal_type {
        "TreasuryWithdrawals" | "NewConstitution" => false,
        "ParameterChange" => description
            .and_then(param_change_touches_security_group)
            .unwrap_or(true),
        _ => true,
    }
}

/// `Some(true/false)` when the changed-parameter set could be read from
/// the proposal description, `None` when it could not (caller fails open).
/// Description shape:
/// `{ "tag":"ParameterChange", "contents":[ <prev-id>, { <param>:<val>, .. }, <policy?> ] }`.
fn param_change_touches_security_group(description: &serde_json::Value) -> Option<bool> {
    let params = description.get("contents")?.get(1)?.as_object()?;
    Some(
        params
            .keys()
            .any(|k| SECURITY_GROUP_PARAMS.contains(&k.as_str())),
    )
}

fn summarize_proposal(p: koios::Proposal) -> VoteProposalSummary {
    let title = p
        .meta_json
        .as_ref()
        .and_then(|m| m.get("body"))
        .and_then(|b| b.get("title"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    // HardForkInitiation description shape: { "contents": [ <prev id>, { "major": N, "minor": M } ] }
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
    pool_id_bech32: String,
    payment_address: String,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    estimated_fee_lovelace: u64,
    can_cover_fee: bool,
    /// Open governance actions for the picker — already filtered to those
    /// an SPO can cast a counting vote on.
    proposals: Vec<VoteProposalSummary>,
    /// How many open actions were hidden because they are not in the SPO
    /// chamber (TreasuryWithdrawals / NewConstitution / non-security
    /// ParameterChange — DRep/CC only).
    non_spo_open_count: usize,
    chain_context: ChainContext,
    /// Operator's configured base URL for rationale documents, if any. The
    /// vote view composes the full anchor URL as `base + filename`.
    manifest_base_url: Option<String>,
}

pub(crate) async fn vote_preview(
    State(app): State<Arc<AppState>>,
) -> Result<Json<VotePreview>, ErrorEnvelope> {
    let params = app.require_genesis()?;
    let cfg = app.config.read().unwrap_or_else(|e| e.into_inner()).clone();
    let pool_id = cfg
        .pool_id
        .clone()
        .ok_or(ErrorEnvelope::not_configured("pool not configured"))?;
    let payment_address = cfg
        .payment_address
        .clone()
        .ok_or(ErrorEnvelope::not_configured("payment_address not configured"))?;

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

    let estimated_fee_lovelace = ESTIMATED_VOTE_FEE_LOVELACE;
    let can_cover_fee = payment_utxo_total_lovelace >= estimated_fee_lovelace;

    let proposals_all = koios::proposal_list(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios proposal_list failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let total_open = proposals_all.len();
    let proposals: Vec<VoteProposalSummary> = proposals_all
        .into_iter()
        .filter(is_spo_votable)
        .map(summarize_proposal)
        .collect();
    let non_spo_open_count = total_open - proposals.len();

    let tip = koios::tip(&app.http, &app.koios_base_url).await.map_err(|e| {
        error!(error = %e, "koios tip failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;
    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start);

    Ok(Json(VotePreview {
        pool_id_bech32: pool_id,
        payment_address,
        payment_utxos,
        payment_utxo_total_lovelace,
        estimated_fee_lovelace,
        can_cover_fee,
        proposals,
        non_spo_open_count,
        chain_context,
        manifest_base_url: cfg.manifest_base_url.clone(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VoteStartBody {
    /// 64-char hex of the governance action's proposal tx hash.
    pub action_tx_hash: String,
    pub action_index: u32,
    /// "yes" | "no" | "abstain".
    pub vote: String,
    /// Optional rationale document URL (paired with anchor_hash).
    pub anchor_url: Option<String>,
    /// Optional 64-char hex blake2b-256 hash of the rationale document.
    pub anchor_hash: Option<String>,
    /// 4-digit operator PIN.
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct VoteStartResponse {
    request: shared::vote::VoteRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    request_fingerprint: String,
}

fn parse_vote_choice(raw: &str) -> Result<shared::vote::VoteChoice, ErrorEnvelope> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "yes" => Ok(shared::vote::VoteChoice::Yes),
        "no" => Ok(shared::vote::VoteChoice::No),
        "abstain" => Ok(shared::vote::VoteChoice::Abstain),
        other => Err(ErrorEnvelope::invalid(format!(
            "unknown vote choice: {other} (expected yes / no / abstain)"
        ))),
    }
}

/// Validate the optional rationale anchor. Both URL and hash must be
/// present together (or both absent). The hash must be 64 hex chars.
fn parse_anchor(
    url: &Option<String>,
    hash: &Option<String>,
) -> Result<Option<(String, String)>, ErrorEnvelope> {
    match (url.as_deref().map(str::trim), hash.as_deref().map(str::trim)) {
        (None, None) | (Some(""), Some("")) | (Some(""), None) | (None, Some("")) => Ok(None),
        (Some(u), Some(h)) if !u.is_empty() && !h.is_empty() => {
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ErrorEnvelope::invalid(
                    "rationale hash must be 64 hex chars (32-byte blake2b-256)",
                ));
            }
            Ok(Some((u.to_string(), h.to_string())))
        }
        _ => Err(ErrorEnvelope::invalid(
            "rationale needs both a document URL and its 32-byte hash, or neither",
        )),
    }
}

pub(crate) async fn vote_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<VoteStartBody>,
) -> Result<Json<VoteStartResponse>, ErrorEnvelope> {
    let crate::util::StartHandlerCtx { params, own_sk, peer_pk, cfg: _, pool_id, payment_address } =
        crate::util::start_handler_ctx(&app, &body.pin)?;

    let vote_choice = parse_vote_choice(&body.vote)?;
    let builder_vote = match vote_choice {
        shared::vote::VoteChoice::No => tx_builder::VoteChoice::No,
        shared::vote::VoteChoice::Yes => tx_builder::VoteChoice::Yes,
        shared::vote::VoteChoice::Abstain => tx_builder::VoteChoice::Abstain,
    };

    let action_tx_hash = body.action_tx_hash.trim().to_string();
    if action_tx_hash.len() != 64 || !action_tx_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ErrorEnvelope::invalid(
            "action_tx_hash must be 64 hex chars (32-byte tx hash)",
        ));
    }

    let anchor_pair = parse_anchor(&body.anchor_url, &body.anchor_hash)?;
    let builder_anchor = anchor_pair.as_ref().map(|(u, h)| tx_builder::VoteAnchorInput {
        url: u.clone(),
        hash_hex: h.clone(),
    });
    let request_anchor = anchor_pair.as_ref().map(|(u, h)| shared::vote::VoteAnchor {
        url: u.clone(),
        hash_hex: h.clone(),
    });

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
        return Err(ErrorEnvelope::insufficient_funds("no UTXOs at payment address"));
    }

    let fee_lovelace = ESTIMATED_VOTE_FEE_LOVELACE;
    if utxo_total < fee_lovelace {
        return Err(ErrorEnvelope::insufficient_funds("payment address cannot cover fee"));
    }

    let tip = koios::tip(&app.http, &app.koios_base_url).await.map_err(|e| {
        error!(error = %e, "koios tip failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;
    let ttl_slot = tip.abs_slot.saturating_add(TTL_MARGIN_SLOTS);

    let change_assets = crate::util::input_assets(&utxos)?;

    let inputs = tx_builder::VoteInputs {
        utxo_inputs: &utxo_inputs,
        change_assets: &change_assets,
        utxo_total_lovelace: utxo_total,
        payment_address_bech32: &payment_address,
        pool_id_bech32: &pool_id,
        action_tx_hash_hex: &action_tx_hash,
        action_index: body.action_index,
        vote: builder_vote,
        anchor: builder_anchor,
        fee_lovelace,
        ttl_slot,
    };
    let built = tx_builder::build_vote_body(&inputs).map_err(|e| match e {
        tx_builder::TxBuildError::InsufficientInputs { .. } => ErrorEnvelope::insufficient_funds(
            "payment address cannot cover fee + min-ADA change",
        ),
        // Anchor URL over the CDDL cap: operator-typed input, so surface
        // the actionable message as invalid_input instead of an opaque
        // internal error.
        e => match tx_builder::cddl_len_violation(&e) {
            Some(msg) => ErrorEnvelope::invalid(msg),
            None => {
                error!(error = %e, "vote tx body build failed");
                ErrorEnvelope::internal("transaction build failed")
            }
        },
    })?;

    let body_hash = pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor);
    let body_hash_hex = hex::encode(body_hash);

    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start);

    let request_inputs =
        crate::util::build_request_inputs(&utxo_inputs, &utxo_amounts, &payment_address);
    let mut request = shared::vote::VoteRequest {
        kind: shared::wire_kind::WireKind::Vote,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        fee_lovelace,
        change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
        ttl_slot,
        payment_address_bech32: payment_address,
        pool_id_bech32: pool_id,
        action_tx_hash_hex: action_tx_hash,
        action_index: body.action_index,
        vote: vote_choice,
        anchor: request_anchor,
        inputs: request_inputs,
        operator_pin_proof: String::new(),
        chain_context,
    };

    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof =
        shared::pin::pin_proof_hex(&body.pin, request.kind.wire_str(), request.chain_context.built_at_unix, &body_fp);

    let (_json_bytes, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;

    Ok(Json(VoteStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VoteResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn vote_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<VoteResultBody>,
) -> Result<Json<shared::vote::VoteResult>, ErrorEnvelope> {
    if body.ur_fragments.is_empty() {
        return Err(ErrorEnvelope::invalid("no UR fragments"));
    }
    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;
    let json_bytes = ur_decode_required(&body.ur_fragments, &peer_pk, &own_sk, shared::qr::Direction::Response)?;
    let result: shared::vote::VoteResult = serde_json::from_slice(&json_bytes).map_err(|e| {
        error!(error = %e, "invalid request payload");
        ErrorEnvelope::invalid("invalid request payload")
    })?;
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::{is_spo_votable_type};
    use serde_json::json;

    #[test]
    fn hides_treasury_and_constitution() {
        assert!(!is_spo_votable_type("TreasuryWithdrawals", None));
        assert!(!is_spo_votable_type("NewConstitution", None));
    }

    #[test]
    fn shows_hardfork_noconfidence_committee_info() {
        for t in ["HardForkInitiation", "NoConfidence", "NewCommittee", "InfoAction"] {
            assert!(is_spo_votable_type(t, None), "{t} should be votable");
        }
    }

    #[test]
    fn param_change_security_group_is_votable() {
        let sec = json!({"tag":"ParameterChange","contents":[null,{"maxTxSize":20000},null]});
        assert!(is_spo_votable_type("ParameterChange", Some(&sec)));
    }

    #[test]
    fn param_change_governance_group_is_hidden() {
        // committeeMinSize is GovGroup, not SecurityGroup.
        let gov = json!({"tag":"ParameterChange","contents":[{"txId":"ab","govActionIx":0},{"committeeMinSize":5},"hash"]});
        assert!(!is_spo_votable_type("ParameterChange", Some(&gov)));
    }

    #[test]
    fn param_change_fail_open_when_unparseable() {
        assert!(is_spo_votable_type("ParameterChange", None));
        let weird = json!({"tag":"ParameterChange","contents":[]});
        assert!(is_spo_votable_type("ParameterChange", Some(&weird)));
    }

    #[test]
    fn unknown_type_shown() {
        assert!(is_spo_votable_type("SomeFutureAction", None));
    }
}
