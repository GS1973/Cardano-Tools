//! Sign-view handlers: `/api/sign/receive` and `/api/sign/execute`.
//!
//! `sign_receive` decodes UR fragments, checks the transaction body against
//! the request and previews the parsed request.
//! `sign_execute` re-decodes, runs the persistent request ledger
//! (exactly-once + wrong-PIN lockout + in-flight duplicate), asserts
//! freshness + operator-PIN,
//! selects the configured key pair whose derived address matches the
//! request, loads it, and dispatches into the matching `sign_core::*`.

use crate::sign_core::{
    check_drep_delegation_body, check_payment_body, check_pool_delegation_body,
    check_withdraw_rewards_body, load_payment_material_from_path, load_stake_material_from_path,
    sign_drep_delegation_core, sign_payment_core, sign_pool_delegation_core,
    sign_withdraw_rewards_core, SignError, SigningKeyMaterial,
};
use crate::{config, state};
use shared::error::ErrorEnvelope;
use shared::wire_io::{ur_decode_required, ur_encode};
use shared::wire_kind::WalletWireKind;
use tracing::warn;

#[derive(serde::Deserialize)]
pub(crate) struct SignReceiveBody {
    ur_fragments: Vec<String>,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum ParsedRequest {
    Payment {
        request: shared::payment::PaymentRequest,
    },
    PoolDelegate {
        request: shared::delegate::PoolDelegateRequest,
    },
    DrepDelegate {
        request: shared::delegate::DrepDelegateRequest,
    },
    WithdrawRewards {
        request: shared::withdraw::WithdrawRewardsRequest,
    },
}

#[derive(serde::Serialize)]
pub(crate) struct SignReceiveResponse {
    #[serde(flatten)]
    request: ParsedRequest,
    request_fingerprint: String,
}

pub(crate) async fn sign_receive(
    axum::Json(body): axum::Json<SignReceiveBody>,
) -> Result<axum::Json<SignReceiveResponse>, ErrorEnvelope> {
    if body.ur_fragments.is_empty() {
        return Err(ErrorEnvelope::invalid("no UR fragments"));
    }
    let cfg = config::load_or_err()?;
    let (own_sk, peer_pk) = crate::handlers::pairing::paired_keys_or_err(&cfg)?;
    let json_bytes = ur_decode_required(
        &body.ur_fragments,
        &peer_pk,
        &own_sk,
        shared::qr::Direction::Request,
    )?;
    let request_fingerprint = shared::fingerprint::format_fingerprint(
        &shared::fingerprint::request_fingerprint(&json_bytes),
    );

    let kind = shared::wire_kind::detect_kind(&json_bytes).map_err(|e| {
        tracing::error!(error = %e, "sign_receive: payload missing kind discriminator");
        ErrorEnvelope::invalid("payload is not a known Wallet Tools request")
    })?;
    // Decode the transaction body and hold it against the request before
    // anything is shown: the preview renders the request's fields, so a
    // request that misdescribes its body must never reach the screen.
    let parsed = match kind {
        WalletWireKind::Payment => {
            let request: shared::payment::PaymentRequest = decode_typed(&json_bytes, "payment")?;
            check_payment_body(&request).map_err(preview_refusal)?;
            ParsedRequest::Payment { request }
        }
        WalletWireKind::PoolDelegate => {
            let request: shared::delegate::PoolDelegateRequest =
                decode_typed(&json_bytes, "pool-delegate")?;
            check_pool_delegation_body(&request).map_err(preview_refusal)?;
            ParsedRequest::PoolDelegate { request }
        }
        WalletWireKind::DrepDelegate => {
            let request: shared::delegate::DrepDelegateRequest =
                decode_typed(&json_bytes, "drep-delegate")?;
            check_drep_delegation_body(&request).map_err(preview_refusal)?;
            ParsedRequest::DrepDelegate { request }
        }
        WalletWireKind::WithdrawRewards => {
            let request: shared::withdraw::WithdrawRewardsRequest =
                decode_typed(&json_bytes, "withdraw-rewards")?;
            check_withdraw_rewards_body(&request).map_err(preview_refusal)?;
            ParsedRequest::WithdrawRewards { request }
        }
    };
    Ok(axum::Json(SignReceiveResponse {
        request: parsed,
        request_fingerprint,
    }))
}

/// The refusal shown when a request's transaction body does not match what
/// the request says about it. The detail goes to the log; the operator gets
/// one actionable line instead of a preview.
fn preview_refusal(e: SignError) -> ErrorEnvelope {
    warn!(detail = %e, "sign_receive: transaction body does not match the request");
    ErrorEnvelope::invalid(
        "the transaction in this request does not match its description. Do not sign. Rebuild it on the online tool",
    )
}

#[derive(serde::Deserialize)]
pub(crate) struct SignExecuteBody {
    ur_fragments: Vec<String>,
    pin: String,
}

#[derive(serde::Serialize)]
pub(crate) struct SignExecuteResponse {
    kind: &'static str,
    ur_fragments: Vec<String>,
}

/// Maximum age of a request's chain_context snapshot, beyond which the
/// signer refuses to sign. Catches replay of stale requests (a
/// compromised online tool retransmitting a still-valid TTL signed
/// transaction long after the operator approved it) and the obvious
/// case of an operator forgetting an open browser tab overnight.
const MAX_CHAIN_CONTEXT_AGE_SECS: u64 = 24 * 60 * 60;

/// A Unix-timestamp floor below which the signer's clock is treated as
/// unset rather than as a real time. An air-gapped machine with a dead
/// RTC battery boots to a bogus near-epoch time, against which the
/// freshness check is meaningless: every genuine request then looks far
/// in the future. 2024-01-01 UTC predates this tool, so any real signing
/// session is comfortably above it.
const MIN_PLAUSIBLE_NOW_UNIX: u64 = 1_704_067_200; // 2024-01-01T00:00:00Z

/// Read the signer's wall clock as Unix seconds. Returns a distinct,
/// operator-actionable error (never a silent 0) when SystemTime is before
/// the UNIX epoch, or when the clock reads before 2024 and is therefore
/// almost certainly unset. Keeping these cases out of the freshness path
/// means a broken clock surfaces as "set the clock", not the misleading
/// "request is older than 24 hours".
fn now_unix() -> Result<u64, ErrorEnvelope> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| {
            tracing::error!("signer system clock is before the UNIX epoch");
            ErrorEnvelope::invalid(
                "signer system clock is not set (reads before 1970). Set the air-gapped machine's clock, then retry",
            )
        })?;
    if secs < MIN_PLAUSIBLE_NOW_UNIX {
        tracing::error!(
            now = secs,
            "signer system clock predates 2024: treating as unset"
        );
        return Err(ErrorEnvelope::invalid(
            "signer system clock looks unset (reads before 2024). Set the air-gapped machine's clock, then retry",
        ));
    }
    Ok(secs)
}

/// blake2b-256 of the decrypted request payload, hex-encoded. Identifies
/// the exact request for the per-request authorization ledger so a
/// byte-identical resubmission maps to the same row.
fn request_id(payload: &[u8]) -> String {
    hex::encode(shared::validate::blake2b256(payload))
}

/// Refuse a transaction whose TTL lies more than three hours past this signer's
/// own clock (`airgap_core::validate::assert_ttl_within_window`). The
/// request's `current_slot` comes from the online tool and cannot bound the
/// TTL. The signer's own clock can.
fn assert_ttl_in_window(ttl_slot: u64, now: u64) -> Result<(), ErrorEnvelope> {
    shared::validate::assert_ttl_within_window(ttl_slot, now).map_err(|_| {
        tracing::warn!(ttl_slot, now, "refusing a ttl more than three hours past the signer clock");
        ErrorEnvelope::invalid(
            "this transaction would stay valid for more than three hours past this signer's clock. Rebuild it on the online tool, or check the signer's clock.",
        )
    })
}

fn decode_typed<T: serde::de::DeserializeOwned>(
    payload: &[u8],
    label: &'static str,
) -> Result<T, ErrorEnvelope> {
    serde_json::from_slice(payload).map_err(|e| {
        tracing::error!(error = %e, kind = label, "typed decode failed");
        ErrorEnvelope::invalid(format!("invalid {label} payload"))
    })
}

fn assert_chain_context_fresh(
    chain_context: &shared::chain_context::ChainContext,
    now: u64,
) -> Result<(), ErrorEnvelope> {
    if chain_context.is_stale(now, MAX_CHAIN_CONTEXT_AGE_SECS) {
        return Err(ErrorEnvelope::invalid(format!(
            "request chain_context is older than {} hours. Rebuild on the online tool first",
            MAX_CHAIN_CONTEXT_AGE_SECS / 3600
        )));
    }
    Ok(())
}

fn assert_operator_pin_matches(
    typed_pin: &str,
    kind: WalletWireKind,
    operator_pin_proof: &str,
    chain_context: &shared::chain_context::ChainContext,
    body_fp: &[u8],
) -> Result<(), ErrorEnvelope> {
    shared::pin::validate_pin(typed_pin).map_err(ErrorEnvelope::invalid)?;
    if !shared::pin::verify_pin(
        typed_pin,
        kind.wire_str(),
        chain_context.built_at_unix,
        body_fp,
        operator_pin_proof,
    ) {
        return Err(ErrorEnvelope::invalid(
            "PIN mismatch: the PIN you typed does not match the PIN entered on the online tool",
        ));
    }
    Ok(())
}

/// Run the full pre-sign authorization: the persistent ledger gate
/// (exactly-once + wrong-PIN lockout + in-flight duplicate), then
/// freshness, then the PIN proof. A failed PIN is recorded so repeated
/// wrong attempts on the same request lock it out and force a rebuild on
/// the online tool. On success returns the request's in-flight claim; the
/// caller must hold it until the outcome has been recorded so a duplicate
/// concurrent submission cannot race the signing work.
fn assert_request_authorized(
    typed_pin: &str,
    kind: WalletWireKind,
    operator_pin_proof: &str,
    chain_context: &shared::chain_context::ChainContext,
    body_fp: &[u8],
    request_id: &str,
    now: u64,
) -> Result<state::InFlightClaim, ErrorEnvelope> {
    let state_path = state::state_path();
    let gate = state::request_gate(&state_path, request_id, now).map_err(|e| {
        tracing::error!(error = %e, "failed to load signer state");
        ErrorEnvelope::internal(
            "failed to load the signer state file. Fix or remove it, then try again.",
        )
    })?;
    let claim = match gate {
        state::RequestGate::AlreadySigned => {
            return Err(ErrorEnvelope::invalid(
                "this request has already been signed. Rebuild it on the online tool",
            ));
        }
        state::RequestGate::LockedOut => {
            return Err(ErrorEnvelope::invalid(
                "too many PIN attempts for this request. Rebuild it on the online tool",
            ));
        }
        state::RequestGate::InFlight => {
            return Err(ErrorEnvelope::invalid(
                "this request is already being signed. Wait for it to finish",
            ));
        }
        state::RequestGate::Ok(claim) => claim,
    };
    assert_chain_context_fresh(chain_context, now)?;
    if let Err(e) =
        assert_operator_pin_matches(typed_pin, kind, operator_pin_proof, chain_context, body_fp)
    {
        if let Err(io) =
            state::note_pin_failure(&state_path, request_id, chain_context.built_at_unix, now)
        {
            warn!(error = %io, "could not persist PIN-failure count");
        }
        return Err(e);
    }
    Ok(claim)
}

fn build_response<R: serde::Serialize>(
    result: &R,
    chain_context: shared::chain_context::ChainContext,
    kind: &'static str,
    own_sk: &[u8; 32],
    peer_pk: &[u8; 32],
    request_id: &str,
    now: u64,
) -> Result<axum::Json<SignExecuteResponse>, ErrorEnvelope> {
    let bytes = serde_json::to_vec(result).map_err(|e| {
        tracing::error!(error = %e, "internal encoding error");
        ErrorEnvelope::internal("internal encoding error")
    })?;
    let fragments = ur_encode(&bytes, peer_pk, own_sk, shared::qr::Direction::Response)?;
    // Mark the request consumed (exactly-once) and advance the display
    // watermark. Done only once the witnesses are built and encoded, so a
    // mid-sign failure does not burn the request.
    if let Err(e) = state::note_consumed(&state::state_path(), request_id, chain_context, now) {
        warn!(error = %e, "could not persist request ledger after sign");
    }
    Ok(axum::Json(SignExecuteResponse {
        kind,
        ur_fragments: fragments,
    }))
}

/// Select the configured key pair whose derived base address equals the
/// request's `payment_address_bech32`, and load its payment + stake material.
///
/// Selection is by **derived address**, each entry's payment + stake
/// verification keys are hashed into a base address and compared, never by a
/// label or any value the online tool supplied. Combined with the per-op
/// `assert_payment_address_is_own` guard downstream, a compromised online tool
/// can only get a signature for an address this signer actually controls.
///
/// Returns the entry's label too, for the operator-facing confirmation. If no
/// entry matches, surfaces a key-load error encountered along the way (e.g. an
/// unmounted drive) in preference to the generic "no key" error, so the
/// operator sees the actionable cause.
fn select_materials(
    cfg: &config::SignerConfig,
    payment_address_bech32: &str,
) -> Result<(String, SigningKeyMaterial, Option<SigningKeyMaterial>), SignError> {
    if cfg.keys.is_empty() {
        return Err(SignError::PaymentNotConfigured);
    }
    let mut last_load_err: Option<SignError> = None;
    for entry in &cfg.keys {
        let payment =
            match load_payment_material_from_path(std::path::Path::new(&entry.payment_skey_path)) {
                Ok(m) => m,
                Err(e) => {
                    last_load_err = Some(e);
                    continue;
                }
            };
        let pay_vk = match payment.verifying_key() {
            Ok(v) => v,
            Err(_) => continue,
        };
        // No stake key path = an enterprise (payment-only) wallet: derive the
        // addr1v from the payment key alone, no stake material.
        if entry.stake_skey_path.trim().is_empty() {
            if let Ok(addr) = shared::address::enterprise_address_bech32(&pay_vk) {
                if addr == payment_address_bech32 {
                    return Ok((entry.label.clone(), payment, None));
                }
            }
            continue;
        }
        let stake =
            match load_stake_material_from_path(std::path::Path::new(&entry.stake_skey_path)) {
                Ok(m) => m,
                Err(e) => {
                    last_load_err = Some(e);
                    continue;
                }
            };
        let stake_vk = match stake.verifying_key() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Ok(addr) = shared::address::base_address_bech32(&pay_vk, &stake_vk) {
            if addr == payment_address_bech32 {
                return Ok((entry.label.clone(), payment, Some(stake)));
            }
        }
    }
    Err(last_load_err.unwrap_or(SignError::NoMatchingKey))
}

pub(crate) async fn sign_execute(
    axum::Json(body): axum::Json<SignExecuteBody>,
) -> Result<axum::Json<SignExecuteResponse>, ErrorEnvelope> {
    shared::wire_io::require_non_empty(&body.ur_fragments, "ur_fragments")?;
    let cfg = config::load_or_err()?;
    let (own_sk, peer_pk) = crate::handlers::pairing::paired_keys_or_err(&cfg)?;
    let payload = ur_decode_required(
        &body.ur_fragments,
        &peer_pk,
        &own_sk,
        shared::qr::Direction::Request,
    )?;

    let kind = shared::wire_kind::detect_kind(&payload).map_err(|e| {
        tracing::error!(error = %e, "sign_execute: payload missing kind discriminator");
        ErrorEnvelope::invalid("payload is not a known Wallet Tools request")
    })?;

    let now = now_unix()?;
    let req_id = request_id(&payload);

    match kind {
        WalletWireKind::Payment => {
            let mut req: shared::payment::PaymentRequest = decode_typed(&payload, "payment")?;
            assert_ttl_in_window(req.ttl_slot, now)?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_request_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let (_label, payment, stake) = select_materials(&cfg, &req.payment_address_bech32)?;
            let chain_context = req.chain_context;
            let result = sign_payment_core(&req, payment, stake)?;
            build_response(
                &result,
                chain_context,
                "payment",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WalletWireKind::PoolDelegate => {
            let mut req: shared::delegate::PoolDelegateRequest =
                decode_typed(&payload, "pool-delegate")?;
            assert_ttl_in_window(req.ttl_slot, now)?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_request_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let (_label, payment, stake) = select_materials(&cfg, &req.payment_address_bech32)?;
            let chain_context = req.chain_context;
            let stake = stake.ok_or(SignError::EnterpriseCannotDelegate)?;
            let result = sign_pool_delegation_core(&req, payment, stake)?;
            build_response(
                &result,
                chain_context,
                "pool-delegate",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WalletWireKind::DrepDelegate => {
            let mut req: shared::delegate::DrepDelegateRequest =
                decode_typed(&payload, "drep-delegate")?;
            assert_ttl_in_window(req.ttl_slot, now)?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_request_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let (_label, payment, stake) = select_materials(&cfg, &req.payment_address_bech32)?;
            let chain_context = req.chain_context;
            let stake = stake.ok_or(SignError::EnterpriseCannotDelegate)?;
            let result = sign_drep_delegation_core(&req, payment, stake)?;
            build_response(
                &result,
                chain_context,
                "drep-delegate",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WalletWireKind::WithdrawRewards => {
            let mut req: shared::withdraw::WithdrawRewardsRequest =
                decode_typed(&payload, "withdraw-rewards")?;
            assert_ttl_in_window(req.ttl_slot, now)?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_request_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let (_label, payment, stake) = select_materials(&cfg, &req.payment_address_bech32)?;
            let chain_context = req.chain_context;
            let stake = stake.ok_or(SignError::EnterpriseCannotWithdraw)?;
            let result = sign_withdraw_rewards_core(&req, payment, stake)?;
            build_response(
                &result,
                chain_context,
                "withdraw-rewards",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
    }
}
