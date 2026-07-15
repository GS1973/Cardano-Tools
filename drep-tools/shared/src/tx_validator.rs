//! Pre-sign body validators for the four DRep operations.
//!
//! Before the air-gapped signer hashes a Conway `TransactionBody` and
//! signs it with the DRep key, it must verify the body does exactly what
//! the matching request says. Each validator decodes the body and binds
//! every critical field to its request; any mismatch aborts before the key
//! is used. The role-neutral checks (forbidden-field guard, input binding,
//! output reading, anchor comparison) come from `airgap_core::validate`,
//! shared with SPO Tools; the DRep-specific cert/voter shape is checked
//! here.

use pallas_codec::utils::Nullable;
use pallas_primitives::conway::{Anchor, Certificate, TransactionBody, Vote, Voter};
use pallas_primitives::StakeCredential;

use crate::anchor::GovAnchor;
use crate::drep_id::drep_id_to_keyhash;
use crate::register::DRepRegisterRequest;
use crate::retire::DRepRetireRequest;
use crate::update::DRepUpdateRequest;
use crate::validate::{
    addr_bytes, anchor_matches_parts, assert_inputs_bind_to_request, assert_no_extra_fields_inner,
    blake2b224, decode_body, output_pair, ValidationError,
};
use crate::vote::{DRepVoteRequest, VoteChoice};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Decode the request's `drep1...` id to its 28-byte key hash.
fn drep_keyhash(bech32: &str) -> Result<[u8; 28], ValidationError> {
    drep_id_to_keyhash(bech32)
        .map_err(|e| ValidationError::BadAddress(bech32.to_string(), e.to_string()))
}

/// Fee equals request, TTL equals request and is not already in the past.
fn check_fee_ttl(
    body: &TransactionBody,
    req_fee: u64,
    req_ttl: u64,
    current_slot: u64,
) -> Result<(), ValidationError> {
    if body.fee != req_fee {
        return Err(ValidationError::Mismatch("fee"));
    }
    if body.ttl != Some(req_ttl) {
        return Err(ValidationError::Mismatch("ttl"));
    }
    if req_ttl <= current_slot {
        return Err(ValidationError::Mismatch("ttl_in_past"));
    }
    Ok(())
}

/// Exactly one output, to the payment address, carrying the expected change.
fn single_change_output(
    body: &TransactionBody,
    payment_bech32: &str,
    expected: u64,
) -> Result<(), ValidationError> {
    if body.outputs.len() != 1 {
        return Err(ValidationError::Mismatch("output count"));
    }
    let payment_b = addr_bytes(payment_bech32)?;
    let (out_addr, out_coin) = output_pair(&body.outputs[0])?;
    if out_addr != payment_b.as_slice() {
        return Err(ValidationError::Mismatch("output address"));
    }
    if out_coin != expected {
        return Err(ValidationError::Mismatch("change-to-payment amount"));
    }
    Ok(())
}

/// Exactly one certificate; returns it.
fn single_cert(body: &TransactionBody) -> Result<&Certificate, ValidationError> {
    let certs = body
        .certificates
        .as_ref()
        .ok_or(ValidationError::Mismatch("missing certificates"))?;
    if certs.len() != 1 {
        return Err(ValidationError::Mismatch("certificate count"));
    }
    Ok(&certs[0])
}

/// The cert credential is a key hash equal to the request's DRep key hash.
fn cred_matches(cred: &StakeCredential, keyhash: &[u8; 28]) -> bool {
    match cred {
        StakeCredential::AddrKeyhash(h) => h.as_ref() == keyhash,
        StakeCredential::ScriptHash(_) => false,
    }
}

fn anchor_matches(
    req: &Option<GovAnchor>,
    on_chain: &Nullable<Anchor>,
) -> Result<bool, ValidationError> {
    anchor_matches_parts(
        req.as_ref().map(|a| (a.url.as_str(), a.hash_hex.as_str())),
        on_chain,
    )
}

/// Common preamble shared by the three certificate operations: decode,
/// forbidden-field guard (no voting_procedures), input binding, fee/ttl,
/// no withdrawals, single change output, and the request's key hash.
// Binds many body fields to the request in one place; the parameter count is inherent.
#[allow(clippy::too_many_arguments)]
fn cert_op_preamble(
    body_bytes: &[u8],
    payment_bech32: &str,
    drep_id_bech32: &str,
    inputs: &[crate::utxo::UtxoInput],
    fee: u64,
    ttl: u64,
    change: u64,
    current_slot: u64,
) -> Result<(TransactionBody, [u8; 28]), ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields_inner(&body, false, false)?;
    assert_inputs_bind_to_request(&body.inputs, inputs, payment_bech32)?;
    check_fee_ttl(&body, fee, ttl, current_slot)?;
    if body.withdrawals.is_some() {
        return Err(ValidationError::Mismatch("unexpected withdrawals"));
    }
    single_change_output(&body, payment_bech32, change)?;
    let keyhash = drep_keyhash(drep_id_bech32)?;
    Ok((body, keyhash))
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

/// Verify a `DRepRegisterRequest`'s body: exactly one `RegDRepCert` whose
/// credential is the request's DRep key hash, whose deposit equals the
/// request, and whose anchor matches; one change output; no withdrawals;
/// fee and TTL match.
pub fn validate_register_body(
    body_bytes: &[u8],
    req: &DRepRegisterRequest,
) -> Result<(), ValidationError> {
    let (body, keyhash) = cert_op_preamble(
        body_bytes,
        &req.payment_address_bech32,
        &req.drep_id_bech32,
        &req.inputs,
        req.fee_lovelace,
        req.ttl_slot,
        req.change_to_payment_address_lovelace,
        req.chain_context.current_slot,
    )?;
    match single_cert(&body)? {
        Certificate::RegDRepCert(cred, coin, anchor) => {
            if !cred_matches(cred, &keyhash) {
                return Err(ValidationError::Mismatch("drep credential"));
            }
            if *coin != req.deposit_lovelace {
                return Err(ValidationError::Mismatch("deposit"));
            }
            if !anchor_matches(&req.anchor, anchor)? {
                return Err(ValidationError::Mismatch("anchor"));
            }
        }
        _ => return Err(ValidationError::Mismatch("not a RegDRepCert")),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Update / refresh
// ---------------------------------------------------------------------------

/// Verify a `DRepUpdateRequest`'s body: exactly one `UpdateDRepCert` whose
/// credential is the request's DRep key hash and whose anchor matches; no
/// deposit; one change output; no withdrawals; fee and TTL match.
pub fn validate_update_body(
    body_bytes: &[u8],
    req: &DRepUpdateRequest,
) -> Result<(), ValidationError> {
    let (body, keyhash) = cert_op_preamble(
        body_bytes,
        &req.payment_address_bech32,
        &req.drep_id_bech32,
        &req.inputs,
        req.fee_lovelace,
        req.ttl_slot,
        req.change_to_payment_address_lovelace,
        req.chain_context.current_slot,
    )?;
    match single_cert(&body)? {
        Certificate::UpdateDRepCert(cred, anchor) => {
            if !cred_matches(cred, &keyhash) {
                return Err(ValidationError::Mismatch("drep credential"));
            }
            if !anchor_matches(&req.anchor, anchor)? {
                return Err(ValidationError::Mismatch("anchor"));
            }
        }
        _ => return Err(ValidationError::Mismatch("not an UpdateDRepCert")),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Retire
// ---------------------------------------------------------------------------

/// Verify a `DRepRetireRequest`'s body: exactly one `UnRegDRepCert` whose
/// credential is the request's DRep key hash and whose refund equals the
/// request; one change output; no withdrawals; fee and TTL match.
pub fn validate_retire_body(
    body_bytes: &[u8],
    req: &DRepRetireRequest,
) -> Result<(), ValidationError> {
    let (body, keyhash) = cert_op_preamble(
        body_bytes,
        &req.payment_address_bech32,
        &req.drep_id_bech32,
        &req.inputs,
        req.fee_lovelace,
        req.ttl_slot,
        req.change_to_payment_address_lovelace,
        req.chain_context.current_slot,
    )?;
    match single_cert(&body)? {
        Certificate::UnRegDRepCert(cred, coin) => {
            if !cred_matches(cred, &keyhash) {
                return Err(ValidationError::Mismatch("drep credential"));
            }
            if *coin != req.deposit_refund_lovelace {
                return Err(ValidationError::Mismatch("deposit refund"));
            }
        }
        _ => return Err(ValidationError::Mismatch("not an UnRegDRepCert")),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Vote
// ---------------------------------------------------------------------------

/// Verify a `DRepVoteRequest`'s body: exactly one `Voter::DRepKey` whose
/// 28-byte hash equals the request's DRep key hash, casting exactly one
/// vote on the requested governance action id, with the requested vote and
/// rationale anchor; one change output; no certificates or withdrawals; fee
/// and TTL match.
pub fn validate_vote_body(body_bytes: &[u8], req: &DRepVoteRequest) -> Result<(), ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields_inner(&body, true, false)?;
    assert_inputs_bind_to_request(&body.inputs, &req.inputs, &req.payment_address_bech32)?;
    check_fee_ttl(&body, req.fee_lovelace, req.ttl_slot, req.chain_context.current_slot)?;
    if body.certificates.is_some() {
        return Err(ValidationError::Mismatch("unexpected certificates"));
    }
    if body.withdrawals.is_some() {
        return Err(ValidationError::Mismatch("unexpected withdrawals"));
    }
    single_change_output(&body, &req.payment_address_bech32, req.change_to_payment_address_lovelace)?;
    let keyhash = drep_keyhash(&req.drep_id_bech32)?;

    let vps = body
        .voting_procedures
        .as_ref()
        .ok_or(ValidationError::Mismatch("missing voting_procedures"))?;
    if vps.len() != 1 {
        return Err(ValidationError::Mismatch("voter count"));
    }
    let (voter, votes) = &vps[0];
    let voter_hash = match voter {
        Voter::DRepKey(h) => h,
        _ => return Err(ValidationError::Mismatch("voter is not a drep key")),
    };
    if voter_hash.as_ref() != keyhash {
        return Err(ValidationError::Mismatch("voter drep hash"));
    }

    if votes.len() != 1 {
        return Err(ValidationError::Mismatch("gov action count"));
    }
    let (gov_action_id, procedure) = &votes[0];
    let action_hash = hex::decode(&req.action_tx_hash_hex)
        .map_err(|e| ValidationError::BadHex(req.action_tx_hash_hex.clone(), e.to_string()))?;
    if action_hash.len() != 32 || action_hash.as_slice() != gov_action_id.transaction_id.as_ref() {
        return Err(ValidationError::Mismatch("gov action tx hash"));
    }
    if gov_action_id.action_index != req.action_index {
        return Err(ValidationError::Mismatch("gov action index"));
    }

    let want_vote = match req.vote {
        VoteChoice::No => Vote::No,
        VoteChoice::Yes => Vote::Yes,
        VoteChoice::Abstain => Vote::Abstain,
    };
    if procedure.vote != want_vote {
        return Err(ValidationError::Mismatch("vote"));
    }
    if !anchor_matches(&req.anchor, &procedure.anchor)? {
        return Err(ValidationError::Mismatch("anchor"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Defense-in-depth: bind the signing key to the DRep id
// ---------------------------------------------------------------------------

/// Mirror of SPO Tools' `assert_cold_vkey_matches_pool`. The validators
/// prove the body acts on the DRep id named in the request; this proves
/// that DRep id is the operator's own key by hashing the loaded DRep
/// verification key (blake2b-224) and checking it equals the request's
/// DRep id. Without it a compromised online tool could craft a body acting
/// as some DRep id and label the request with that id; the signer would
/// bind body to request and sign — but the DRep key would not actually
/// authorise that DRep on-chain. Checking here makes the signer refuse
/// before the DRep key ever touches the body.
pub fn assert_drep_vkey_matches_id(
    drep_id_bech32: &str,
    drep_vkey: &[u8; 32],
) -> Result<(), ValidationError> {
    let keyhash = drep_keyhash(drep_id_bech32)?;
    if blake2b224(drep_vkey) != keyhash {
        return Err(ValidationError::Mismatch("drep key does not match drep id"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_context::ChainContext;
    use crate::utxo::UtxoInput;
    use crate::wire_kind::DrepWireKind;

    use pallas_codec::minicbor;
    use pallas_codec::utils::{Bytes, NonEmptyKeyValuePairs, NonEmptySet, Set};
    use pallas_primitives::conway::{
        GovActionId, PseudoTransactionOutput, TransactionInput, TransactionOutput, Value,
        VotingProcedure,
    };
    use pallas_primitives::{Hash, NetworkId};

    const PAYMENT_ADDR: &str = "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw";
    const KEYHASH: [u8; 28] = [0x42u8; 28];
    const DEPOSIT: u64 = 500_000_000;
    const CHANGE: u64 = 9_500_000;
    const FEE: u64 = 200_000;
    const TTL: u64 = 2_000_000;

    fn drep_id() -> String {
        // CIP-129 key-DRep: header 0x22 ++ 28-byte hash.
        let mut data = vec![0x22u8];
        data.extend_from_slice(&KEYHASH);
        let hrp = bech32::Hrp::parse("drep").unwrap();
        bech32::encode::<bech32::Bech32>(hrp, &data).unwrap()
    }

    fn chain_context() -> ChainContext {
        ChainContext {
            current_epoch: 1,
            current_slot: 100,
            current_kes_period: 0,
            epoch_ends_at_unix: 0,
            opcert_expires_at_unix: None,
            built_at_unix: 0,
        }
    }

    fn dummy_input() -> UtxoInput {
        UtxoInput {
            tx_hash_hex: "00".repeat(32),
            tx_index: 0,
            amount_lovelace: 0,
            address_bech32: PAYMENT_ADDR.into(),
        }
    }

    fn coin_output(lovelace: u64) -> TransactionOutput {
        let addr = pallas_addresses::Address::from_bech32(PAYMENT_ADDR).unwrap();
        PseudoTransactionOutput::PostAlonzo(
            pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(addr.to_vec()),
                value: Value::Coin(lovelace),
                datum_option: None,
                script_ref: None,
            },
        )
    }

    fn empty_input() -> TransactionInput {
        TransactionInput { transaction_id: Hash::from([0u8; 32]), index: 0 }
    }

    fn base_body(certs: Option<NonEmptySet<Certificate>>, vps: Option<NonEmptyKeyValuePairs<Voter, NonEmptyKeyValuePairs<GovActionId, VotingProcedure>>>, change: u64) -> Vec<u8> {
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![coin_output(change)],
            fee: FEE,
            ttl: Some(TTL),
            certificates: certs,
            withdrawals: None,
            auxiliary_data_hash: None,
            validity_interval_start: None,
            mint: None,
            script_data_hash: None,
            collateral: None,
            required_signers: None,
            network_id: Some(NetworkId::Mainnet),
            collateral_return: None,
            total_collateral: None,
            reference_inputs: None,
            voting_procedures: vps,
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    fn cred() -> StakeCredential {
        StakeCredential::AddrKeyhash(Hash::from(KEYHASH))
    }

    fn anchor_some() -> Nullable<Anchor> {
        Nullable::Some(Anchor {
            url: "https://example.com/drep.jsonld".into(),
            content_hash: Hash::from([0x5Au8; 32]),
        })
    }
    fn gov_anchor() -> GovAnchor {
        GovAnchor {
            url: "https://example.com/drep.jsonld".into(),
            hash_hex: hex::encode([0x5Au8; 32]),
        }
    }

    // -- Register --
    fn register_req(anchor: Option<GovAnchor>) -> DRepRegisterRequest {
        DRepRegisterRequest {
            kind: DrepWireKind::DrepRegister,
            tx_body_cbor_hex: String::new(),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE,
            deposit_lovelace: DEPOSIT,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT_ADDR.into(),
            drep_id_bech32: drep_id(),
            anchor,
            inputs: vec![dummy_input()],
            operator_pin_proof: "0000000000000000".into(),
            chain_context: chain_context(),
        }
    }
    fn register_body(cred: StakeCredential, deposit: u64, anchor: Nullable<Anchor>) -> Vec<u8> {
        let cert = Certificate::RegDRepCert(cred, deposit, anchor);
        base_body(Some(NonEmptySet::try_from(vec![cert]).unwrap()), None, CHANGE)
    }

    #[test]
    fn register_happy_path() {
        let body = register_body(cred(), DEPOSIT, anchor_some());
        validate_register_body(&body, &register_req(Some(gov_anchor()))).expect("matches");
    }
    #[test]
    fn register_rejects_wrong_deposit() {
        let body = register_body(cred(), 1, anchor_some());
        let err = validate_register_body(&body, &register_req(Some(gov_anchor()))).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("deposit")));
    }
    #[test]
    fn register_rejects_wrong_credential() {
        let body = register_body(StakeCredential::AddrKeyhash(Hash::from([0x99u8; 28])), DEPOSIT, anchor_some());
        let err = validate_register_body(&body, &register_req(Some(gov_anchor()))).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("drep credential")));
    }
    #[test]
    fn register_rejects_anchor_present_when_none_requested() {
        let body = register_body(cred(), DEPOSIT, anchor_some());
        let err = validate_register_body(&body, &register_req(None)).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("anchor")));
    }
    #[test]
    fn register_rejects_script_credential() {
        let body = register_body(StakeCredential::ScriptHash(Hash::from(KEYHASH)), DEPOSIT, anchor_some());
        let err = validate_register_body(&body, &register_req(Some(gov_anchor()))).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("drep credential")));
    }

    // -- Update --
    fn update_req(anchor: Option<GovAnchor>) -> DRepUpdateRequest {
        DRepUpdateRequest {
            kind: DrepWireKind::DrepUpdate,
            tx_body_cbor_hex: String::new(),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT_ADDR.into(),
            drep_id_bech32: drep_id(),
            anchor,
            inputs: vec![dummy_input()],
            operator_pin_proof: "0000000000000000".into(),
            chain_context: chain_context(),
        }
    }
    #[test]
    fn update_happy_path_keepalive_null_anchor() {
        let cert = Certificate::UpdateDRepCert(cred(), Nullable::Null);
        let body = base_body(Some(NonEmptySet::try_from(vec![cert]).unwrap()), None, CHANGE);
        validate_update_body(&body, &update_req(None)).expect("matches");
    }
    #[test]
    fn update_happy_path_new_manifest() {
        let cert = Certificate::UpdateDRepCert(cred(), anchor_some());
        let body = base_body(Some(NonEmptySet::try_from(vec![cert]).unwrap()), None, CHANGE);
        validate_update_body(&body, &update_req(Some(gov_anchor()))).expect("matches");
    }
    #[test]
    fn update_rejects_reg_cert() {
        let body = register_body(cred(), DEPOSIT, Nullable::Null);
        let err = validate_update_body(&body, &update_req(None)).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("not an UpdateDRepCert")));
    }

    // -- Retire --
    fn retire_req() -> DRepRetireRequest {
        DRepRetireRequest {
            kind: DrepWireKind::DrepRetire,
            tx_body_cbor_hex: String::new(),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE + DEPOSIT,
            deposit_refund_lovelace: DEPOSIT,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT_ADDR.into(),
            drep_id_bech32: drep_id(),
            inputs: vec![dummy_input()],
            operator_pin_proof: "0000000000000000".into(),
            chain_context: chain_context(),
        }
    }
    #[test]
    fn retire_happy_path() {
        let cert = Certificate::UnRegDRepCert(cred(), DEPOSIT);
        let body = base_body(Some(NonEmptySet::try_from(vec![cert]).unwrap()), None, CHANGE + DEPOSIT);
        validate_retire_body(&body, &retire_req()).expect("matches");
    }
    #[test]
    fn retire_rejects_wrong_refund() {
        let cert = Certificate::UnRegDRepCert(cred(), 1);
        let body = base_body(Some(NonEmptySet::try_from(vec![cert]).unwrap()), None, CHANGE + DEPOSIT);
        let err = validate_retire_body(&body, &retire_req()).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("deposit refund")));
    }

    // -- Vote --
    const ACTION_HASH: [u8; 32] = [0xABu8; 32];
    fn vote_req(vote: VoteChoice, anchor: Option<GovAnchor>) -> DRepVoteRequest {
        DRepVoteRequest {
            kind: DrepWireKind::DrepVote,
            tx_body_cbor_hex: String::new(),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT_ADDR.into(),
            drep_id_bech32: drep_id(),
            action_tx_hash_hex: hex::encode(ACTION_HASH),
            action_index: 0,
            vote,
            anchor,
            inputs: vec![dummy_input()],
            operator_pin_proof: "0000000000000000".into(),
            chain_context: chain_context(),
        }
    }
    fn vote_body(voter_hash: [u8; 28], vote: Vote, anchor: Nullable<Anchor>, idx: u32) -> Vec<u8> {
        let voter = Voter::DRepKey(Hash::from(voter_hash));
        let gid = GovActionId { transaction_id: Hash::from(ACTION_HASH), action_index: idx };
        let proc = VotingProcedure { vote, anchor };
        let inner = NonEmptyKeyValuePairs::Def(vec![(gid, proc)]);
        let vps = NonEmptyKeyValuePairs::Def(vec![(voter, inner)]);
        base_body(None, Some(vps), CHANGE)
    }
    #[test]
    fn vote_happy_path() {
        let body = vote_body(KEYHASH, Vote::Yes, Nullable::Null, 0);
        validate_vote_body(&body, &vote_req(VoteChoice::Yes, None)).expect("matches");
    }
    #[test]
    fn vote_rejects_vote_mismatch() {
        let body = vote_body(KEYHASH, Vote::Yes, Nullable::Null, 0);
        let err = validate_vote_body(&body, &vote_req(VoteChoice::No, None)).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("vote")));
    }
    #[test]
    fn vote_rejects_wrong_drep() {
        let body = vote_body([0x99u8; 28], Vote::Yes, Nullable::Null, 0);
        let err = validate_vote_body(&body, &vote_req(VoteChoice::Yes, None)).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("voter drep hash")));
    }
    #[test]
    fn vote_rejects_action_index_mismatch() {
        let body = vote_body(KEYHASH, Vote::Yes, Nullable::Null, 7);
        let err = validate_vote_body(&body, &vote_req(VoteChoice::Yes, None)).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("gov action index")));
    }
    #[test]
    fn vote_rejects_anchor_when_none_requested() {
        let body = vote_body(KEYHASH, Vote::Yes, anchor_some(), 0);
        let err = validate_vote_body(&body, &vote_req(VoteChoice::Yes, None)).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("anchor")));
    }

    // -- assert_drep_vkey_matches_id --
    #[test]
    fn vkey_matches_id_accepts_correct_key() {
        // Construct a vkey whose blake2b224 equals KEYHASH by searching is
        // impractical; instead verify the function agrees with blake2b224.
        let vkey = [0x07u8; 32];
        let id_hash = blake2b224(&vkey);
        let mut data = vec![0x22u8];
        data.extend_from_slice(&id_hash);
        let hrp = bech32::Hrp::parse("drep").unwrap();
        let id = bech32::encode::<bech32::Bech32>(hrp, &data).unwrap();
        assert_drep_vkey_matches_id(&id, &vkey).expect("key matches its own id");
    }
    #[test]
    fn vkey_matches_id_rejects_wrong_key() {
        let err = assert_drep_vkey_matches_id(&drep_id(), &[0x07u8; 32]).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("drep key does not match drep id")));
    }
}
