use crate::{
    koios, state, tx_builder,
    util::{chain_context_from, paired_keys_or_err, TTL_MARGIN_SLOTS},
    AppState};
use shared::{chain_context::ChainContext, wire_io::ur_decode_required};
use shared::error::ErrorEnvelope;
use axum::{extract::{Query, State}, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

pub(crate) const ESTIMATED_POOL_UPDATE_FEE_LOVELACE: u64 = 250_000;

#[derive(Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/handlers.ts")]
pub(crate) struct PoolParamsCurrent {
    pool_id_bech32: String,
    vrf_key_hash: String,
    /// Bech32 stake addresses of all on-chain owners. v1.0 supports
    /// single-owner pools only — `is_single_owner` flags multi-owner cases.
    owners: Vec<String>,
    is_single_owner: bool,
    #[ts(type = "number")]
    pledge_lovelace: u64,
    margin: f64,
    /// Exact margin rational recovered from the Koios float (which is all
    /// Koios exposes — see `margin_rational_from_f64`). The build request
    /// takes an exact numerator/denominator back, so prefilling an
    /// unedited margin from these keeps it stable across a
    /// re-registration instead of drifting to a re-rounded percent
    /// (e.g. 1/3 silently becoming 333333/1000000). `None` when no
    /// rational reproduces the float — the UI must then warn that
    /// re-registering may alter the margin.
    #[ts(type = "number | null")]
    margin_numerator: Option<u64>,
    #[ts(type = "number | null")]
    margin_denominator: Option<u64>,
    #[ts(type = "number")]
    fixed_cost_lovelace: u64,
    reward_address: String,
    relays: Vec<koios::Relay>,
    metadata_url: Option<String>,
    metadata_hash: Option<String>,
    payment_address: String,
    #[ts(type = "number")]
    payment_utxo_total_lovelace: u64,
    #[ts(type = "number")]
    estimated_fee_lovelace: u64,
    can_cover_fee: bool,
    chain_context: ChainContext,
    /// Latest pending pool-param update from the chain (if any). Populated
    /// from /pool_updates rows whose `active_epoch_no` is in the future.
    /// The frontend renders this as a banner above the current-state table.
    pending: Option<PoolParamsPending>,
    /// True when Koios `/pool_updates` was unreachable; `pending` will be
    /// `None` but the operator should not interpret that as "no pending
    /// update" — it just means the check could not be performed.
    pending_updates_unavailable: bool,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/handlers.ts")]
pub(crate) struct PoolParamsPending {
    tx_hash: String,
    #[ts(type = "number")]
    active_epoch_no: u64,
    /// Absolute slot at which the pending update goes live (= first slot
    /// of `active_epoch_no`). Used by the UI for a countdown.
    #[ts(type = "number")]
    active_epoch_first_slot: u64,
    /// Unix timestamp at which `active_epoch_first_slot` occurs.
    #[ts(type = "number")]
    active_epoch_first_unix: u64,
    #[ts(type = "number | null")]
    pledge_lovelace: Option<u64>,
    margin: Option<f64>,
    #[ts(type = "number | null")]
    fixed_cost_lovelace: Option<u64>,
    reward_address: Option<String>,
    owners: Vec<String>,
    relays: Vec<koios::Relay>,
    metadata_url: Option<String>,
    metadata_hash: Option<String>}

/// Mutable pool registration params extracted from either the most
/// recent on-chain registration (via `/pool_updates`) or the
/// `/pool_info` snapshot when the updates feed is unavailable. Both
/// sources expose the same fields, just with different parsed types,
/// so the handler can destructure a single `PoolParamsExtract`
/// regardless of which source it came from.
struct PoolParamsExtract {
    vrf_key_hash: String,
    pledge_lovelace: u64,
    margin: f64,
    fixed_cost_lovelace: u64,
    reward_address: String,
    owners: Vec<String>,
    relays: Vec<koios::Relay>,
    metadata_url: Option<String>,
    metadata_hash: Option<String>,
}

fn pool_params_from_update(u: &koios::PoolUpdate) -> Result<PoolParamsExtract, ErrorEnvelope> {
    Ok(PoolParamsExtract {
        vrf_key_hash: u.vrf_key_hash.clone().ok_or(ErrorEnvelope::upstream("vrf_key_hash missing in pool_updates"))?,
        pledge_lovelace: u.pledge
            .as_ref()
            .and_then(|s| s.parse().ok())
            .ok_or(ErrorEnvelope::upstream("pledge missing in pool_updates"))?,
        margin: u.margin.ok_or(ErrorEnvelope::upstream("margin missing in pool_updates"))?,
        fixed_cost_lovelace: u.fixed_cost
            .as_ref()
            .and_then(|s| s.parse().ok())
            .ok_or(ErrorEnvelope::upstream("fixed_cost missing in pool_updates"))?,
        reward_address: u.reward_addr.clone().ok_or(ErrorEnvelope::upstream("reward_addr missing in pool_updates"))?,
        owners: u.owners.clone(),
        relays: u.relays.clone(),
        metadata_url: u.meta_url.clone(),
        metadata_hash: u.meta_hash.clone(),
    })
}

fn pool_params_from_info(p: &koios::PoolInfo) -> Result<PoolParamsExtract, ErrorEnvelope> {
    Ok(PoolParamsExtract {
        vrf_key_hash: p.vrf_key_hash.clone().ok_or(ErrorEnvelope::upstream("vrf_key_hash missing from Koios response"))?,
        pledge_lovelace: p.pledge
            .as_ref()
            .and_then(|s| s.parse().ok())
            .ok_or(ErrorEnvelope::upstream("pledge missing or not a u64"))?,
        margin: p.margin.ok_or(ErrorEnvelope::upstream("margin missing from Koios response"))?,
        fixed_cost_lovelace: p.fixed_cost
            .as_ref()
            .and_then(|s| s.parse().ok())
            .ok_or(ErrorEnvelope::upstream("fixed_cost missing or not a u64"))?,
        reward_address: p.reward_addr.clone().ok_or(ErrorEnvelope::upstream("reward_addr missing from Koios response"))?,
        owners: p.owners.clone(),
        relays: p.relays.clone(),
        metadata_url: p.meta_url.clone(),
        metadata_hash: p.meta_hash.clone(),
    })
}

/// Denominator ceiling for [`margin_rational_from_f64`]. An f64 carries
/// ~15-16 significant digits, so rationals needing more than 9 digits of
/// denominator are indistinguishable from float noise.
const MAX_MARGIN_DENOMINATOR: u64 = 1_000_000_000;

/// Recover the smallest-denominator rational `p/q` (0 ≤ p/q ≤ 1) whose
/// f64 quotient reproduces `margin` bit-for-bit, by walking the
/// continued-fraction convergents of the float. Koios reports pool
/// margin only as a float computed from the on-chain rational, so the
/// first convergent that divides back to the identical float is the best
/// reconstruction available (fl(1/3) → 1/3, fl(1/20) → 1/20). Returns
/// `None` when no denominator ≤ [`MAX_MARGIN_DENOMINATOR`] reproduces
/// the float; the response then carries no rational and the UI warns
/// that a re-registration may alter the margin.
fn margin_rational_from_f64(margin: f64) -> Option<(u64, u64)> {
    if !margin.is_finite() || !(0.0..=1.0).contains(&margin) {
        return None;
    }
    // Convergent recurrence p_n = a_n·p_{n-1} + p_{n-2} (likewise q_n),
    // seeded with the standard (0/1, 1/0) pair.
    let (mut p_prev, mut q_prev) = (0u64, 1u64);
    let (mut p_last, mut q_last) = (1u64, 0u64);
    let mut x = margin;
    loop {
        let a_floor = x.floor();
        // `as u64` saturates on huge/inf values; the checked arithmetic
        // below then bails out instead of wrapping.
        let a = a_floor as u64;
        let p = a.checked_mul(p_last)?.checked_add(p_prev)?;
        let q = a.checked_mul(q_last)?.checked_add(q_prev)?;
        if q > MAX_MARGIN_DENOMINATOR {
            return None;
        }
        // p ≤ q ≤ 1e9, so both convert to f64 exactly.
        if q != 0 && p as f64 / q as f64 == margin {
            return Some((p, q));
        }
        let frac = x - a_floor;
        if frac <= 0.0 {
            // Expansion exhausted without reproducing the float.
            return None;
        }
        p_prev = p_last;
        q_prev = q_last;
        p_last = p;
        q_last = q;
        x = 1.0 / frac;
    }
}

/// Split a `/pool_updates` history into the registration currently in
/// effect at `tip_epoch` and the latest not-yet-active one. Both picks
/// tie-break on `block_time` when two registrations activate in the same
/// epoch: a same-epoch resubmission supersedes the earlier one on
/// Cardano, so the one that landed last wins. (The pick stays
/// order-independent — `/pool_updates` is paged with an explicit
/// `order` only to keep pagination stable — so the activation epoch
/// alone is not a total pick.)
pub(crate) fn select_registrations(
    updates: &[koios::PoolUpdate],
    tip_epoch: u64,
) -> (Option<&koios::PoolUpdate>, Option<&koios::PoolUpdate>) {
    let current = updates
        .iter()
        .filter(|u| u.update_type == "registration" && u.active_epoch_no <= tip_epoch)
        .max_by_key(|u| (u.active_epoch_no, u.block_time));
    let pending = updates
        .iter()
        .filter(|u| u.update_type == "registration" && u.active_epoch_no > tip_epoch)
        .max_by_key(|u| (u.active_epoch_no, u.block_time));
    (current, pending)
}

pub(crate) async fn pool_current(
    State(app): State<Arc<AppState>>,
) -> Result<Json<PoolParamsCurrent>, ErrorEnvelope> {
    let params = app.require_genesis()?;
    let cfg = app.config.read().unwrap_or_else(|e| e.into_inner()).clone();
    let pool_id = cfg
        .pool_id
        .clone()
        .ok_or(ErrorEnvelope::not_configured("pool not configured"))?;
    let payment_address = cfg.payment_address.clone().ok_or(ErrorEnvelope::not_configured("payment_address not configured",))?;

    let pool = koios::pool_info(&app.http, &app.koios_base_url, &pool_id).await.map_err(|e| {
        error!(error = %e, "koios pool_info failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;

    // Fetch tip up-front: the current epoch is needed to split the
    // pool_updates history into "currently active" and "pending".
    let tip = koios::tip(&app.http, &app.koios_base_url).await.map_err(|e| {
        error!(error = %e, "koios tip failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;

    // Koios `/pool_info` returns the LATEST registration values regardless
    // of whether the registration is active yet. With a pending update
    // that means pool.fixed_cost / pledge / margin / etc. show the
    // *future* values, not what the chain currently honours. To split
    // current vs pending, `/pool_updates` is traversed to pick the
    // latest registration whose active_epoch_no has already been reached.
    let mut pending_updates_unavailable = false;
    let updates: Vec<koios::PoolUpdate> = match koios::pool_updates(&app.http, &app.koios_base_url, &pool_id).await {
        Ok(u) => u,
        Err(e) => {
            error!(error = %e, "koios pool_updates failed (falling back to pool_info)");
            // Surface the gap to the operator so a real pending update is
            // not invisible during a Koios incident — the UI shows a
            // "pending update info unavailable" banner above the
            // current-state table.
            pending_updates_unavailable = true;
            Vec::new()
        }
    };
    let (current_update, pending_update) = select_registrations(&updates, tip.epoch_no);
    let pending_update = pending_update.cloned();

    // Source the mutable params from current_update when available; if
    // pool_updates was empty or failed, fall back to pool_info (which is
    // accurate for pools that have no pending update, and at least
    // non-broken otherwise).
    let extract = if let Some(u) = current_update {
        pool_params_from_update(u)?
    } else {
        pool_params_from_info(&pool)?
    };
    let PoolParamsExtract {
        vrf_key_hash,
        pledge_lovelace,
        margin,
        fixed_cost_lovelace,
        reward_address,
        owners,
        relays,
        metadata_url,
        metadata_hash,
    } = extract;

    let is_single_owner = owners.len() == 1;
    let margin_rational = margin_rational_from_f64(margin);

    let (_utxos, _amounts, payment_utxo_total_lovelace) =
        crate::util::fetch_payment_utxos(&app.http, &app.koios_base_url, &payment_address).await?;

    let estimated_fee_lovelace = ESTIMATED_POOL_UPDATE_FEE_LOVELACE;
    let can_cover_fee = payment_utxo_total_lovelace >= estimated_fee_lovelace;

    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start);

    let pending = pending_update.map(|u| {
        let active_first_slot = params.epoch_first_slot(u.active_epoch_no);
        let active_first_unix = koios::slot_to_unix_time(active_first_slot);
        PoolParamsPending {
            tx_hash: u.tx_hash,
            active_epoch_no: u.active_epoch_no,
            active_epoch_first_slot: active_first_slot,
            active_epoch_first_unix: active_first_unix,
            pledge_lovelace: u.pledge.as_ref().and_then(|s| s.parse().ok()),
            margin: u.margin,
            fixed_cost_lovelace: u.fixed_cost.as_ref().and_then(|s| s.parse().ok()),
            reward_address: u.reward_addr,
            owners: u.owners,
            relays: u.relays,
            metadata_url: u.meta_url,
            metadata_hash: u.meta_hash}
    });

    Ok(Json(PoolParamsCurrent {
        pool_id_bech32: pool_id,
        vrf_key_hash,
        owners,
        is_single_owner,
        pledge_lovelace,
        margin,
        margin_numerator: margin_rational.map(|(n, _)| n),
        margin_denominator: margin_rational.map(|(_, d)| d),
        fixed_cost_lovelace,
        reward_address,
        relays,
        metadata_url,
        metadata_hash,
        payment_address,
        payment_utxo_total_lovelace,
        estimated_fee_lovelace,
        can_cover_fee,
        chain_context,
        pending,
        pending_updates_unavailable,
    }))
}

#[derive(Serialize)]
pub(crate) struct PoolMetadataHashResponse {
    hash_hex: String,
    size_bytes: usize}

/// Compute Blake2b-256 over the raw request body. The hash MUST match the
/// bytes that will be served at the metadata URL — hashing exactly what
/// the SPO uploaded, no re-serialization.
pub(crate) async fn pool_metadata_hash(
    body: axum::body::Bytes,
) -> Result<Json<PoolMetadataHashResponse>, ErrorEnvelope> {
    if body.is_empty() {
        return Err(ErrorEnvelope::invalid("empty metadata body"));
    }
    let hash = pallas_crypto::hash::Hasher::<256>::hash(&body);
    Ok(Json(PoolMetadataHashResponse {
        hash_hex: hex::encode(hash),
        size_bytes: body.len()}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolBuildBody {
    pledge_lovelace: u64,
    fixed_cost_lovelace: u64,
    margin_numerator: u64,
    margin_denominator: u64,
    reward_account_bech32: String,
    relays: Vec<shared::pool_update::RelaySpec>,
    metadata_url: Option<String>,
    metadata_hash_hex: Option<String>,
    /// 4-digit operator PIN.
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct PoolBuildResponse {
    request: shared::pool_update::PoolUpdateRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    /// 8-byte request-payload fingerprint, blake2b256 truncated
    /// and rendered as 4 hex pairs (operator visually compares with the
    /// signer-side display before signing).
    request_fingerprint: String,
}

#[derive(Deserialize)]
pub(crate) struct PoolPledgePrecheckQuery {
    pledge_lovelace: u64}

#[derive(Serialize)]
pub(crate) struct PoolPledgePrecheckResponse {
    owner_stake_address: String,
    /// Owner's total balance (UTxO + rewards) reported by Koios for the
    /// stake account. This is the **current** balance — the actual
    /// pledge check at epoch boundary uses the active stake snapshot
    /// taken earlier, so a recent funding event may not yet be reflected.
    owner_balance_lovelace: u64,
    pledge_lovelace: u64,
    meets_pledge: bool,
    shortfall_lovelace: u64}

/// Pre-submit check: does the (first) owner's current stake-account
/// balance cover the proposed new pledge? A pool re-registration that
/// raises pledge takes effect at the next epoch boundary, but the
/// protocol verifies the pledge against the active stake snapshot —
/// which was taken one or two epochs earlier. If the owner just funded
/// the wallet to cover the new pledge, the snapshot may not yet
/// reflect that, and the pool drops out of the leader rotation for
/// at least one epoch. This check warns the operator before submission.
///
/// v1.0 single-owner only. For multi-owner pools the protocol sums
/// across owners; this would require fanning out account_info per owner.
pub(crate) async fn pool_pledge_precheck(
    State(app): State<Arc<AppState>>,
    Query(q): Query<PoolPledgePrecheckQuery>,
) -> Result<Json<PoolPledgePrecheckResponse>, ErrorEnvelope> {
    let cfg = app.config.read().unwrap_or_else(|e| e.into_inner()).clone();
    let pool_id = cfg.pool_id.clone().ok_or(ErrorEnvelope::not_configured("pool not configured",))?;

    let pool = koios::pool_info(&app.http, &app.koios_base_url, &pool_id).await.map_err(|e| {
        error!(error = %e, "koios pool_info failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;
    let owner = pool.owners.into_iter().next().ok_or(ErrorEnvelope::upstream("pool has no owners on chain",))?;

    let acct_opt = koios::account_info(&app.http, &app.koios_base_url, &owner)
        .await
        .map_err(|e| {
            error!(error = %e, "koios account_info(owner) failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let acct = acct_opt.ok_or(ErrorEnvelope::upstream("owner stake address not found on Koios",))?;
    let owner_balance: u64 = acct.total_balance.parse().map_err(|_| {
        ErrorEnvelope::upstream("unexpected total_balance format from upstream")
    })?;

    let meets_pledge = owner_balance >= q.pledge_lovelace;
    let shortfall_lovelace = q.pledge_lovelace.saturating_sub(owner_balance);

    Ok(Json(PoolPledgePrecheckResponse {
        owner_stake_address: owner,
        owner_balance_lovelace: owner_balance,
        pledge_lovelace: q.pledge_lovelace,
        meets_pledge,
        shortfall_lovelace}))
}

pub(crate) async fn pool_build(
    State(app): State<Arc<AppState>>,
    Json(body): Json<PoolBuildBody>,
) -> Result<Json<PoolBuildResponse>, ErrorEnvelope> {
    let crate::util::StartHandlerCtx { params, own_sk, peer_pk, cfg: _, pool_id, payment_address } =
        crate::util::start_handler_ctx(&app, &body.pin)?;

    if body.margin_denominator == 0 || body.margin_numerator > body.margin_denominator {
        return Err(ErrorEnvelope::invalid("margin must satisfy 0 ≤ numerator ≤ denominator and denominator > 0",));
    }

    let (metadata_url, metadata_hash_hex) =
        match parse_pool_metadata(&body.metadata_url, &body.metadata_hash_hex)? {
            Some((url, hash)) => (Some(url), Some(hash)),
            None => (None, None),
        };

    // Current on-chain pool params: operator + vrf_keyhash + owners are
    // taken as-is (read-only in v1.0).
    let pool = koios::pool_info(&app.http, &app.koios_base_url, &pool_id).await.map_err(|e| {
        error!(error = %e, "koios pool_info failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;
    let vrf_keyhash_hex = pool.vrf_key_hash.clone().ok_or(ErrorEnvelope::upstream("vrf_key_hash missing from Koios response",))?;
    if pool.owners.len() != 1 {
        return Err(ErrorEnvelope::invalid(format!(
                "v1.0 supports single-owner pools only (chain has {} owners)",
                pool.owners.len()
            ),));
    }
    let owners = pool.owners.clone();

    let relay_inputs = translate_relays(&body.relays)?;

    // Payment UTXOs (consume all to keep this simple for v1.0).
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

    let fee_lovelace = ESTIMATED_POOL_UPDATE_FEE_LOVELACE;
    if utxo_total < fee_lovelace {
        return Err(ErrorEnvelope::insufficient_funds("payment address cannot cover fee"));
    }

    let tip = koios::tip(&app.http, &app.koios_base_url).await.map_err(|e| {
        error!(error = %e, "koios tip failed");
        ErrorEnvelope::upstream("upstream service unavailable")
    })?;
    let ttl_slot = tip.abs_slot.saturating_add(TTL_MARGIN_SLOTS);

    let change_assets = crate::util::input_assets(&utxos)?;

    let inputs = tx_builder::PoolUpdateInputs {
        utxo_inputs: &utxo_inputs,
        change_assets: &change_assets,
        utxo_total_lovelace: utxo_total,
        payment_address_bech32: &payment_address,
        pool_id_bech32: &pool_id,
        vrf_keyhash_hex: &vrf_keyhash_hex,
        pledge_lovelace: body.pledge_lovelace,
        fixed_cost_lovelace: body.fixed_cost_lovelace,
        margin_numerator: body.margin_numerator,
        margin_denominator: body.margin_denominator,
        reward_account_bech32: &body.reward_account_bech32,
        pool_owner_stake_addresses: &owners,
        relays: &relay_inputs,
        metadata_url: metadata_url.as_deref(),
        metadata_hash_hex: metadata_hash_hex.as_deref(),
        fee_lovelace,
        ttl_slot};
    let built = tx_builder::build_pool_update_body(&inputs).map_err(|e| match e {
        tx_builder::TxBuildError::InsufficientInputs { .. } => ErrorEnvelope::insufficient_funds(
            "payment address cannot cover fee + min-ADA change",
        ),
        // Relay DNS name / metadata URL over the CDDL cap: operator-typed
        // input, so surface the actionable message as invalid_input
        // instead of an opaque internal error.
        e => match tx_builder::cddl_len_violation(&e) {
            Some(msg) => ErrorEnvelope::invalid(msg),
            None => {
                error!(error = %e, "pool update tx body build failed");
                ErrorEnvelope::internal("transaction build failed")
            }
        },
    })?;

    let body_hash = pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor);
    let body_hash_hex = hex::encode(body_hash);

    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start);

    let request_inputs = crate::util::build_request_inputs(&utxo_inputs, &utxo_amounts, &payment_address);
    let mut request = shared::pool_update::PoolUpdateRequest {
        kind: shared::wire_kind::WireKind::PoolUpdate,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        fee_lovelace,
        change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
        ttl_slot,
        payment_address_bech32: payment_address,
        pool_id_bech32: pool_id,
        vrf_keyhash_hex,
        pledge_lovelace: body.pledge_lovelace,
        fixed_cost_lovelace: body.fixed_cost_lovelace,
        margin_numerator: body.margin_numerator,
        margin_denominator: body.margin_denominator,
        reward_account_bech32: body.reward_account_bech32,
        pool_owner_stake_addresses: owners,
        relays: body.relays,
        metadata_url,
        metadata_hash_hex,
        inputs: request_inputs,
        operator_pin_proof: String::new(),
        chain_context};

    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof =
        shared::pin::pin_proof_hex(&body.pin, request.kind.wire_str(), request.chain_context.built_at_unix, &body_fp);

    let (_json_bytes, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;

    Ok(Json(PoolBuildResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint}))
}

pub(crate) fn parse_ipv4(s: &str) -> Result<[u8; 4], ErrorEnvelope> {
    s.parse::<std::net::Ipv4Addr>()
        .map(|a| a.octets())
        .map_err(|_| ErrorEnvelope::invalid(format!("invalid IPv4 `{s}`")))
}

pub(crate) fn parse_ipv6(s: &str) -> Result<[u8; 16], ErrorEnvelope> {
    s.parse::<std::net::Ipv6Addr>()
        .map(|a| a.octets())
        .map_err(|_| ErrorEnvelope::invalid(format!("invalid IPv6 `{s}`")))
}

/// Translate operator-supplied `RelaySpec` (wire shape) into the
/// `RelayInput` shape that `tx_builder::build_pool_update_body`
/// expects. Each `SingleHostAddr` entry parses its dotted-quad and
/// hex IPv6 fields up-front so an invalid IP surfaces as an
/// invalid_input envelope instead of a tx body that won't sign.
fn translate_relays(
    specs: &[shared::pool_update::RelaySpec],
) -> Result<Vec<tx_builder::RelayInput>, ErrorEnvelope> {
    let mut out = Vec::with_capacity(specs.len());
    for r in specs {
        match r {
            shared::pool_update::RelaySpec::SingleHostAddr { port, ipv4, ipv6 } => {
                let ipv4_arr = ipv4.as_deref().map(parse_ipv4).transpose()?;
                let ipv6_arr = ipv6.as_deref().map(parse_ipv6).transpose()?;
                out.push(tx_builder::RelayInput::SingleHostAddr {
                    port: *port,
                    ipv4: ipv4_arr,
                    ipv6: ipv6_arr,
                });
            }
            shared::pool_update::RelaySpec::SingleHostName { port, dns } => {
                out.push(tx_builder::RelayInput::SingleHostName {
                    port: *port,
                    dns: dns.clone(),
                });
            }
            shared::pool_update::RelaySpec::MultiHostName { dns } => {
                out.push(tx_builder::RelayInput::MultiHostName { dns: dns.clone() });
            }
        }
    }
    Ok(out)
}

/// Validate the optional pool-metadata pair: URL and hash must be present
/// together (or both absent), and the hash must be 64 hex chars. Mirrors
/// `parse_anchor` in `vote.rs`. `tx_builder::build_pool_update_body` also
/// rejects a partial pair, but only as an opaque internal error — catching
/// it here surfaces an operator-actionable invalid_input before the
/// signing ceremony.
fn parse_pool_metadata(
    url: &Option<String>,
    hash_hex: &Option<String>,
) -> Result<Option<(String, String)>, ErrorEnvelope> {
    match (url.as_deref().map(str::trim), hash_hex.as_deref().map(str::trim)) {
        (None, None) | (Some(""), Some("")) | (Some(""), None) | (None, Some("")) => Ok(None),
        (Some(u), Some(h)) if !u.is_empty() && !h.is_empty() => {
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ErrorEnvelope::invalid(
                    "metadata hash must be 64 hex chars (32-byte blake2b-256)",
                ));
            }
            Ok(Some((u.to_string(), h.to_string())))
        }
        _ => Err(ErrorEnvelope::invalid(
            "pool metadata needs both a URL and its 32-byte hash, or neither",
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolResultBody {
    ur_fragments: Vec<String>}

pub(crate) async fn pool_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<PoolResultBody>,
) -> Result<Json<shared::pool_update::PoolUpdateResult>, ErrorEnvelope> {
    if body.ur_fragments.is_empty() {
        return Err(ErrorEnvelope::invalid("no UR fragments"));
    }
    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;
    let json_bytes = ur_decode_required(&body.ur_fragments, &peer_pk, &own_sk, shared::qr::Direction::Response)?;
    let result: shared::pool_update::PoolUpdateResult = serde_json::from_slice(&json_bytes).map_err(|e| {
        error!(error = %e, "invalid request payload");
        ErrorEnvelope::invalid("invalid request payload")
    })?;
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(update_type: &str, active_epoch_no: u64, block_time: u64) -> koios::PoolUpdate {
        serde_json::from_value(serde_json::json!({
            "tx_hash": format!("tx-{active_epoch_no}-{block_time}"),
            "block_time": block_time,
            "pool_id_bech32": "pool1x",
            "active_epoch_no": active_epoch_no,
            "update_type": update_type,
        }))
        .unwrap()
    }

    #[test]
    fn same_epoch_resubmission_supersedes_earlier_cert() {
        // Two registrations activating in the same epoch: the one that
        // landed last (block_time) wins, for current and pending alike.
        let updates = vec![
            update("registration", 500, 100),
            update("registration", 500, 200),
            update("registration", 510, 60),
            update("registration", 510, 50),
        ];
        let (current, pending) = select_registrations(&updates, 505);
        assert_eq!(current.unwrap().block_time, 200);
        assert_eq!(pending.unwrap().block_time, 60);
    }

    #[test]
    fn activation_epoch_outranks_block_time() {
        let updates = vec![
            update("registration", 490, 900),
            update("registration", 500, 100),
        ];
        let (current, pending) = select_registrations(&updates, 505);
        assert_eq!(current.unwrap().active_epoch_no, 500);
        assert!(pending.is_none());
    }

    #[test]
    fn non_registration_rows_are_ignored() {
        let updates = vec![
            update("registration", 500, 100),
            update("deregistration", 502, 300),
            update("deregistration", 510, 400),
        ];
        let (current, pending) = select_registrations(&updates, 505);
        assert_eq!(current.unwrap().active_epoch_no, 500);
        assert!(pending.is_none());
    }

    #[test]
    fn margin_rational_recovers_exact_thirds() {
        // fl(1/3) is not representable at any fixed decimal precision;
        // the convergent walk must recover the original 1/3.
        assert_eq!(margin_rational_from_f64(1.0 / 3.0), Some((1, 3)));
    }

    #[test]
    fn margin_rational_recovers_common_margins() {
        assert_eq!(margin_rational_from_f64(0.0), Some((0, 1)));
        assert_eq!(margin_rational_from_f64(1.0), Some((1, 1)));
        assert_eq!(margin_rational_from_f64(0.5), Some((1, 2)));
        assert_eq!(margin_rational_from_f64(0.05), Some((1, 20)));
        assert_eq!(margin_rational_from_f64(0.03), Some((3, 100)));
    }

    #[test]
    fn margin_rational_preserves_upstream_decimal_precision() {
        // A margin Koios reports as a truncated decimal (not fl(1/3))
        // reconstructs to exactly that decimal, not to 1/3.
        assert_eq!(
            margin_rational_from_f64(0.33333333),
            Some((33_333_333, 100_000_000))
        );
    }

    #[test]
    fn margin_rational_rejects_out_of_range() {
        assert_eq!(margin_rational_from_f64(f64::NAN), None);
        assert_eq!(margin_rational_from_f64(f64::INFINITY), None);
        assert_eq!(margin_rational_from_f64(-0.1), None);
        assert_eq!(margin_rational_from_f64(1.5), None);
    }

    #[test]
    fn pool_metadata_both_or_neither() {
        let hash = "ab".repeat(32);
        assert_eq!(parse_pool_metadata(&None, &None).unwrap(), None);
        assert_eq!(
            parse_pool_metadata(&Some(" ".into()), &Some("".into())).unwrap(),
            None
        );
        assert_eq!(
            parse_pool_metadata(&Some("https://x/meta.json".into()), &Some(hash.clone()))
                .unwrap(),
            Some(("https://x/meta.json".into(), hash.clone()))
        );
        assert!(parse_pool_metadata(&Some("https://x/meta.json".into()), &None).is_err());
        assert!(parse_pool_metadata(&None, &Some(hash)).is_err());
    }

    #[test]
    fn pool_metadata_rejects_bad_hash() {
        let url = Some("https://x/meta.json".to_string());
        assert!(parse_pool_metadata(&url, &Some("abcd".into())).is_err());
        assert!(parse_pool_metadata(&url, &Some("zz".repeat(32))).is_err());
    }
}

