//! Sign-view handlers: `/api/sign/receive` and `/api/sign/execute`.
//!
//! `sign_receive` decodes UR fragments, checks a transaction body against
//! its request (and reads a rationale back from the bytes to be signed), and
//! previews the parsed request for the operator. `sign_execute` re-runs the same decode, asserts the
//! request is fresh, asserts the operator-PIN matches, and dispatches
//! into the matching `sign_core::*_core` for actual key use.

use crate::sign_core::{
    assert_vrf_matches, check_drep_delegation_body, check_pool_update_body, check_vote_body,
    check_withdrawal_body, check_witness_body, compute_leaderlog_core, load_cold_seed_from_path,
    load_payment_material_from_path, load_stake_material_from_path, load_vrf_from_path,
    rotate_kes_core, sign_drep_delegation_core, sign_pool_update_core, sign_vote_core,
    sign_withdrawal_core, sign_witness_core, SignExecuteError,
};
use crate::{config, state};
use shared::error::ErrorEnvelope;
use shared::wire_io::{ur_decode_required, ur_encode};
use shared::wire_kind::WireKind;
use tracing::warn;

// ============================================================
// Sign view: receive an incoming request via UR fragments and parse it
// ============================================================

#[derive(serde::Deserialize)]
pub(crate) struct SignReceiveBody {
    ur_fragments: Vec<String>,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum ParsedRequest {
    Leaderlog {
        request: shared::leaderlog::LeaderlogRequest,
    },
    KesRotation {
        request: shared::kes::KesRotationRequest,
    },
    Withdrawal {
        request: shared::withdrawal::WithdrawalRequest,
    },
    DrepDelegation {
        request: shared::drep::DRepDelegationRequest,
        /// The whole CIP-129 `drep1...` id of a specific DRep, worked out
        /// by the signer from the hash in the request.
        drep_id: Option<String>,
    },
    PoolUpdate {
        request: shared::pool_update::PoolUpdateRequest,
        /// True when a VRF key is set up on this signer, so the VRF key hash
        /// is checked against it before signing.
        vrf_checked: bool,
    },
    Vote {
        request: shared::vote::VoteRequest,
    },
    WitnessDoc {
        request: shared::witness_doc::SpoWitnessRequest,
        /// The canonical body read back line by line from the exact bytes
        /// that will be signed, so the operator can read the rationale
        /// itself instead of raw N-Quads.
        rationale: Vec<shared::nquads::BodyLine>,
    },
}

/// The refusal shown when a request's payload does not match what the
/// request says about it. The detail goes to the log; the operator gets one
/// actionable line instead of a preview.
fn preview_refusal(e: SignExecuteError) -> ErrorEnvelope {
    warn!(detail = %e, "sign_receive: request payload does not match its description");
    ErrorEnvelope::invalid(
        "the transaction in this request does not match its description. Do not sign. Rebuild it on the online tool",
    )
}

#[derive(serde::Serialize)]
pub(crate) struct SignReceiveResponse {
    /// Discriminated request payload: tagged by request type.
    #[serde(flatten)]
    request: ParsedRequest,
    /// 8-byte request-payload fingerprint, blake2b256 truncated and
    /// rendered as 4 hex pairs. The operator visually compares this
    /// with the same fingerprint shown next to the QR on the online
    /// tool side; identical fingerprints prove the encrypted payload
    /// arrived intact.
    request_fingerprint: String,
}

/// Turn a decrypted request payload into what the preview shows, or refuse.
/// For the transaction kinds the body is decoded and held against the
/// request before anything is shown: the preview renders the request's
/// fields, so a request that misdescribes its body must never reach the
/// screen. Leaderlog and KES rotation carry no transaction.
pub(crate) fn parse_and_check(json_bytes: &[u8]) -> Result<ParsedRequest, ErrorEnvelope> {
    // Detect the wire kind discriminator first, then full-decode that
    // single variant. Replaces an older speculative cascade that tried
    // every type in turn and could surface confusing serde error chains.
    let kind = shared::wire_kind::detect_kind(json_bytes).map_err(|e| {
        tracing::error!(error = %e, "sign_receive: payload missing kind discriminator");
        ErrorEnvelope::invalid("payload is not a known SPO Tools request")
    })?;
    let parsed = match kind {
        WireKind::Leaderlog => ParsedRequest::Leaderlog {
            request: serde_json::from_slice(json_bytes).map_err(|e| {
                tracing::error!(error = %e, kind = ?kind, "sign_receive: leaderlog decode");
                ErrorEnvelope::invalid("invalid leaderlog payload")
            })?,
        },
        WireKind::KesRotation => ParsedRequest::KesRotation {
            request: serde_json::from_slice(json_bytes).map_err(|e| {
                tracing::error!(error = %e, kind = ?kind, "sign_receive: kes decode");
                ErrorEnvelope::invalid("invalid kes-rotation payload")
            })?,
        },
        WireKind::Withdrawal => {
            let request: shared::withdrawal::WithdrawalRequest = serde_json::from_slice(json_bytes)
                .map_err(|e| {
                    tracing::error!(error = %e, kind = ?kind, "sign_receive: withdrawal decode");
                    ErrorEnvelope::invalid("invalid withdrawal payload")
                })?;
            check_withdrawal_body(&request).map_err(preview_refusal)?;
            ParsedRequest::Withdrawal { request }
        }
        WireKind::DrepDelegation => {
            let request: shared::drep::DRepDelegationRequest = serde_json::from_slice(json_bytes)
                .map_err(|e| {
                tracing::error!(error = %e, kind = ?kind, "sign_receive: drep decode");
                ErrorEnvelope::invalid("invalid drep-delegation payload")
            })?;
            check_drep_delegation_body(&request).map_err(preview_refusal)?;
            let drep_id = request.drep_choice.cip129_id();
            ParsedRequest::DrepDelegation { request, drep_id }
        }
        WireKind::PoolUpdate => {
            let request: shared::pool_update::PoolUpdateRequest =
                serde_json::from_slice(json_bytes).map_err(|e| {
                    tracing::error!(error = %e, kind = ?kind, "sign_receive: pool decode");
                    ErrorEnvelope::invalid("invalid pool-update payload")
                })?;
            check_pool_update_body(&request).map_err(preview_refusal)?;
            ParsedRequest::PoolUpdate {
                request,
                vrf_checked: false,
            }
        }
        WireKind::Vote => {
            let request: shared::vote::VoteRequest =
                serde_json::from_slice(json_bytes).map_err(|e| {
                    tracing::error!(error = %e, kind = ?kind, "sign_receive: vote decode");
                    ErrorEnvelope::invalid("invalid vote payload")
                })?;
            check_vote_body(&request).map_err(preview_refusal)?;
            ParsedRequest::Vote { request }
        }
        WireKind::WitnessDoc => {
            let request: shared::witness_doc::SpoWitnessRequest =
                serde_json::from_slice(json_bytes).map_err(|e| {
                    tracing::error!(error = %e, kind = ?kind, "sign_receive: witness decode");
                    ErrorEnvelope::invalid("invalid witness payload")
                })?;
            check_witness_body(&request).map_err(preview_refusal)?;
            let rationale = shared::nquads::read_canonical_body(&request.canonical_body);
            ParsedRequest::WitnessDoc { request, rationale }
        }
    };

    Ok(parsed)
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

    let mut parsed = parse_and_check(&json_bytes)?;
    if let ParsedRequest::PoolUpdate { vrf_checked, .. } = &mut parsed {
        *vrf_checked = cfg.vrf_skey.is_some();
    }
    Ok(axum::Json(SignReceiveResponse {
        request: parsed,
        request_fingerprint,
    }))
}

#[derive(serde::Deserialize)]
pub(crate) struct SignExecuteBody {
    ur_fragments: Vec<String>,
    /// 4-digit operator PIN, retyped on the signer screen after the
    /// payload has been decrypted. Hashed and compared against the
    /// request's `operator_pin_proof` to verify operator presence.
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
    kind: WireKind,
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

/// Decode `payload` as the typed request `T`. Centralises the
/// `tracing::error! + ErrorEnvelope::invalid` boilerplate so each arm
/// of `sign_execute` reduces to one line for this step.
fn decode_typed_request<T: serde::de::DeserializeOwned>(
    payload: &[u8],
    kind_label: &'static str,
) -> Result<T, ErrorEnvelope> {
    serde_json::from_slice(payload).map_err(|e| {
        tracing::error!(error = %e, kind = kind_label, "sign_execute typed decode failed");
        ErrorEnvelope::invalid(format!("invalid {kind_label} payload"))
    })
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
    kind: WireKind,
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

/// Common tail of every sign_execute arm: JSON-encode the result, UR-
/// encode the encrypted payload, persist the request's chain_context,
/// and return the SignExecuteResponse with the operator-visible kind
/// label.
fn build_sign_response<R: serde::Serialize>(
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

fn join_internal_error(e: tokio::task::JoinError) -> ErrorEnvelope {
    tracing::error!(error = %e, "spawn_blocking join failed");
    ErrorEnvelope::internal("signing failed")
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
        ErrorEnvelope::invalid("payload is not a known SPO Tools request")
    })?;

    let now = now_unix()?;
    let req_id = request_id(&payload);

    match kind {
        WireKind::Leaderlog => {
            let mut req: shared::leaderlog::LeaderlogRequest =
                decode_typed_request(&payload, "leaderlog")?;
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
            let path = cfg.vrf_skey.ok_or(SignExecuteError::VrfNotConfigured)?;
            let vrf = load_vrf_from_path(std::path::Path::new(&path))?;
            let chain_context = req.chain_context;
            let result = tokio::task::spawn_blocking(move || compute_leaderlog_core(&req, &vrf))
                .await
                .map_err(join_internal_error)??;
            build_sign_response(
                &result,
                chain_context,
                "leaderlog",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WireKind::KesRotation => {
            let mut req: shared::kes::KesRotationRequest =
                decode_typed_request(&payload, "kes-rotation")?;
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
            let path = cfg.cold_skey.ok_or(SignExecuteError::ColdNotConfigured)?;
            let cold_pb = std::path::PathBuf::from(&path);
            let output_dir = cold_pb.parent().map(|p| p.to_path_buf()).ok_or_else(|| {
                tracing::error!(
                    cold_skey_path_len = path.len(),
                    "cold.skey path has no parent dir"
                );
                ErrorEnvelope::internal(
                    "cold.skey path is unrooted, cannot derive rotation output directory",
                )
            })?;
            let cold_seed = load_cold_seed_from_path(&cold_pb)?;
            let chain_context = req.chain_context;
            let result =
                tokio::task::spawn_blocking(move || rotate_kes_core(&req, cold_seed, &output_dir))
                    .await
                    .map_err(join_internal_error)??;
            build_sign_response(
                &result,
                chain_context,
                "kes-rotation",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WireKind::Withdrawal => {
            let mut req: shared::withdrawal::WithdrawalRequest =
                decode_typed_request(&payload, "withdrawal")?;
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
            let payment_path = cfg
                .payment_skey
                .clone()
                .ok_or(SignExecuteError::PaymentNotConfigured)?;
            let reward_path = cfg
                .reward_skey
                .clone()
                .ok_or(SignExecuteError::RewardNotConfigured)?;
            let payment_seed =
                load_payment_material_from_path(std::path::Path::new(&payment_path))?;
            let reward_seed = load_stake_material_from_path(std::path::Path::new(&reward_path))?;
            let chain_context = req.chain_context;
            let result = sign_withdrawal_core(&req, payment_seed, reward_seed)?;
            build_sign_response(
                &result,
                chain_context,
                "withdrawal",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WireKind::DrepDelegation => {
            let mut req: shared::drep::DRepDelegationRequest =
                decode_typed_request(&payload, "drep-delegation")?;
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
            let payment_path = cfg
                .payment_skey
                .clone()
                .ok_or(SignExecuteError::PaymentNotConfigured)?;
            let owner_path = cfg
                .owner_skey
                .clone()
                .ok_or(SignExecuteError::OwnerNotConfigured)?;
            let payment_seed =
                load_payment_material_from_path(std::path::Path::new(&payment_path))?;
            let owner_seed = load_stake_material_from_path(std::path::Path::new(&owner_path))?;
            let chain_context = req.chain_context;
            let result = sign_drep_delegation_core(&req, payment_seed, owner_seed)?;
            build_sign_response(
                &result,
                chain_context,
                "drep-delegation",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WireKind::PoolUpdate => {
            let mut req: shared::pool_update::PoolUpdateRequest =
                decode_typed_request(&payload, "pool-update")?;
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
            let payment_path = cfg
                .payment_skey
                .clone()
                .ok_or(SignExecuteError::PaymentNotConfigured)?;
            let cold_path = cfg
                .cold_skey
                .clone()
                .ok_or(SignExecuteError::ColdNotConfigured)?;
            let owner_path = cfg
                .owner_skey
                .clone()
                .ok_or(SignExecuteError::OwnerNotConfigured)?;
            let payment_seed =
                load_payment_material_from_path(std::path::Path::new(&payment_path))?;
            let cold_seed = load_cold_seed_from_path(std::path::Path::new(&cold_path))?;
            let owner_seed = load_stake_material_from_path(std::path::Path::new(&owner_path))?;
            if let Some(vrf_path) = cfg.vrf_skey.clone() {
                let vrf = load_vrf_from_path(std::path::Path::new(&vrf_path))?;
                assert_vrf_matches(&req.vrf_keyhash_hex, &vrf)?;
            }
            let chain_context = req.chain_context;
            let result = sign_pool_update_core(&req, payment_seed, cold_seed, owner_seed)?;
            build_sign_response(
                &result,
                chain_context,
                "pool-update",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WireKind::Vote => {
            let mut req: shared::vote::VoteRequest = decode_typed_request(&payload, "vote")?;
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
            let payment_path = cfg
                .payment_skey
                .clone()
                .ok_or(SignExecuteError::PaymentNotConfigured)?;
            let cold_path = cfg
                .cold_skey
                .clone()
                .ok_or(SignExecuteError::ColdNotConfigured)?;
            let payment_seed =
                load_payment_material_from_path(std::path::Path::new(&payment_path))?;
            let cold_seed = load_cold_seed_from_path(std::path::Path::new(&cold_path))?;
            let chain_context = req.chain_context;
            let result = sign_vote_core(&req, payment_seed, cold_seed)?;
            build_sign_response(
                &result,
                chain_context,
                "vote",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        WireKind::WitnessDoc => {
            let mut req: shared::witness_doc::SpoWitnessRequest =
                decode_typed_request(&payload, "witness")?;
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
            let cold_path = cfg
                .cold_skey
                .clone()
                .ok_or(SignExecuteError::ColdNotConfigured)?;
            let cold_seed = load_cold_seed_from_path(std::path::Path::new(&cold_path))?;
            let chain_context = req.chain_context;
            let result = sign_witness_core(&req, cold_seed)?;
            build_sign_response(
                &result,
                chain_context,
                "witness",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
    }
}

// CSRF + DNS-rebinding guard lives in `shared::csrf`; both binaries share
// the same logic and the allowed origins are computed at startup from the
// listener address chosen via `--listen`.
