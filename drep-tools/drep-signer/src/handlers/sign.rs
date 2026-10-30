//! Sign-view handlers: `/api/sign/receive` and `/api/sign/execute`.
//!
//! `sign_receive` decodes UR fragments, checks the payload against the
//! request (and reads a rationale back from the bytes to be signed), and
//! previews the parsed request.
//! `sign_execute` re-decodes, runs the per-request ledger gate
//! (exactly-once + wrong-PIN lockout + in-flight duplicate), asserts
//! freshness + operator-PIN, loads the payment + DRep keys, and dispatches
//! into the matching `sign_core::*`.

use crate::sign_core::{
    check_register_body, check_retire_body, check_update_body, check_vote_body, check_witness_body,
    load_drep_material_from_path, load_payment_material_from_path, sign_register_core,
    sign_retire_core, sign_update_core, sign_vote_core, sign_witness_core, SignExecuteError,
};
use crate::{config, state};
use shared::error::ErrorEnvelope;
use shared::wire_io::{ur_decode_required, ur_encode};
use shared::wire_kind::DrepWireKind;
use tracing::warn;

#[derive(serde::Deserialize)]
pub(crate) struct SignReceiveBody {
    ur_fragments: Vec<String>,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)] // the Drep prefix names the operation domain
pub(crate) enum ParsedRequest {
    DrepRegister {
        request: shared::register::DRepRegisterRequest,
    },
    DrepUpdate {
        request: shared::update::DRepUpdateRequest,
    },
    DrepRetire {
        request: shared::retire::DRepRetireRequest,
    },
    DrepVote {
        request: shared::vote::DRepVoteRequest,
    },
    DrepWitness {
        request: shared::witness_doc::DRepWitnessRequest,
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
    #[serde(flatten)]
    request: ParsedRequest,
    request_fingerprint: String,
}

/// Turn a decrypted request payload into what the preview shows, or refuse.
/// Nothing is returned for a request whose payload does not match its own
/// description.
pub(crate) fn parse_and_check(json_bytes: &[u8]) -> Result<ParsedRequest, ErrorEnvelope> {
    let kind = shared::wire_kind::detect_kind(json_bytes).map_err(|e| {
        tracing::error!(error = %e, "sign_receive: payload missing kind discriminator");
        ErrorEnvelope::invalid("payload is not a known DRep Tools request")
    })?;
    // Decode the transaction body and hold it against the request before
    // anything is shown: the preview renders the request's fields, so a
    // request that misdescribes its body must never reach the screen.
    let parsed = match kind {
        DrepWireKind::DrepRegister => {
            let request: shared::register::DRepRegisterRequest =
                decode_typed(json_bytes, "drep-register")?;
            check_register_body(&request).map_err(preview_refusal)?;
            ParsedRequest::DrepRegister { request }
        }
        DrepWireKind::DrepUpdate => {
            let request: shared::update::DRepUpdateRequest =
                decode_typed(json_bytes, "drep-update")?;
            check_update_body(&request).map_err(preview_refusal)?;
            ParsedRequest::DrepUpdate { request }
        }
        DrepWireKind::DrepRetire => {
            let request: shared::retire::DRepRetireRequest =
                decode_typed(json_bytes, "drep-retire")?;
            check_retire_body(&request).map_err(preview_refusal)?;
            ParsedRequest::DrepRetire { request }
        }
        DrepWireKind::DrepVote => {
            let request: shared::vote::DRepVoteRequest = decode_typed(json_bytes, "drep-vote")?;
            check_vote_body(&request).map_err(preview_refusal)?;
            ParsedRequest::DrepVote { request }
        }
        DrepWireKind::DrepWitnessDoc => {
            let request: shared::witness_doc::DRepWitnessRequest =
                decode_typed(json_bytes, "drep-witness")?;
            check_witness_body(&request).map_err(preview_refusal)?;
            let rationale = shared::nquads::read_canonical_body(&request.canonical_body);
            ParsedRequest::DrepWitness { request, rationale }
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

    let parsed = parse_and_check(&json_bytes)?;
    Ok(axum::Json(SignReceiveResponse {
        request: parsed,
        request_fingerprint,
    }))
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

fn assert_operator_pin_matches(
    typed_pin: &str,
    kind: DrepWireKind,
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
fn assert_authorized(
    typed_pin: &str,
    kind: DrepWireKind,
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
    if chain_context.is_stale(now, MAX_CHAIN_CONTEXT_AGE_SECS) {
        return Err(ErrorEnvelope::invalid(format!(
            "request chain_context is older than {} hours. Rebuild on the online tool first",
            MAX_CHAIN_CONTEXT_AGE_SECS / 3600
        )));
    }
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

/// Load the payment + DRep signing materials from the configured paths.
fn load_materials(
    cfg: &config::SignerConfig,
) -> Result<
    (
        crate::sign_core::SigningKeyMaterial,
        crate::sign_core::SigningKeyMaterial,
    ),
    SignExecuteError,
> {
    let payment_path = cfg
        .payment_skey
        .clone()
        .ok_or(SignExecuteError::PaymentNotConfigured)?;
    let drep_path = cfg
        .drep_skey
        .clone()
        .ok_or(SignExecuteError::DrepNotConfigured)?;
    let payment = load_payment_material_from_path(std::path::Path::new(&payment_path))?;
    let drep = load_drep_material_from_path(std::path::Path::new(&drep_path))?;
    Ok((payment, drep))
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
        ErrorEnvelope::invalid("payload is not a known DRep Tools request")
    })?;

    let now = now_unix()?;
    let req_id = request_id(&payload);

    match kind {
        DrepWireKind::DrepRegister => {
            let mut req: shared::register::DRepRegisterRequest =
                decode_typed(&payload, "drep-register")?;
            assert_ttl_in_window(req.ttl_slot, now)?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let (payment, drep) = load_materials(&cfg)?;
            let chain_context = req.chain_context;
            let result = sign_register_core(&req, payment, drep)?;
            build_response(
                &result,
                chain_context,
                "drep-register",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        DrepWireKind::DrepUpdate => {
            let mut req: shared::update::DRepUpdateRequest = decode_typed(&payload, "drep-update")?;
            assert_ttl_in_window(req.ttl_slot, now)?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let (payment, drep) = load_materials(&cfg)?;
            let chain_context = req.chain_context;
            let result = sign_update_core(&req, payment, drep)?;
            build_response(
                &result,
                chain_context,
                "drep-update",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        DrepWireKind::DrepRetire => {
            let mut req: shared::retire::DRepRetireRequest = decode_typed(&payload, "drep-retire")?;
            assert_ttl_in_window(req.ttl_slot, now)?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let (payment, drep) = load_materials(&cfg)?;
            let chain_context = req.chain_context;
            let result = sign_retire_core(&req, payment, drep)?;
            build_response(
                &result,
                chain_context,
                "drep-retire",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        DrepWireKind::DrepVote => {
            let mut req: shared::vote::DRepVoteRequest = decode_typed(&payload, "drep-vote")?;
            assert_ttl_in_window(req.ttl_slot, now)?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let (payment, drep) = load_materials(&cfg)?;
            let chain_context = req.chain_context;
            let result = sign_vote_core(&req, payment, drep)?;
            build_response(
                &result,
                chain_context,
                "drep-vote",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
        DrepWireKind::DrepWitnessDoc => {
            let mut req: shared::witness_doc::DRepWitnessRequest =
                decode_typed(&payload, "drep-witness")?;
            let pin_proof = std::mem::take(&mut req.operator_pin_proof);
            let body_fp = shared::request_body_fp(&req);
            let _claim = assert_authorized(
                &body.pin,
                req.kind,
                &pin_proof,
                &req.chain_context,
                &body_fp,
                &req_id,
                now,
            )?;
            let drep_path = cfg
                .drep_skey
                .clone()
                .ok_or(SignExecuteError::DrepNotConfigured)?;
            let drep = load_drep_material_from_path(std::path::Path::new(&drep_path))?;
            let chain_context = req.chain_context;
            let result = sign_witness_core(&req, drep)?;
            build_response(
                &result,
                chain_context,
                "drep-witness",
                &own_sk,
                &peer_pk,
                &req_id,
                now,
            )
        }
    }
}
