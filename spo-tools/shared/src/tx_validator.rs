//! Pre-sign body validators.
//!
//! Before the signer hashes a Conway `TransactionBody` and produces an
//! Ed25519 signature, it must verify that the body actually does what
//! the corresponding request says it does. Without this check, the
//! signer is a generic "sign-whatever-you-receive" oracle: a malicious
//! online tool could swap the body for a different transaction
//! (e.g. emptying the payment address) while the QR-side preview the
//! user sees still matches the request they approved.
//!
//! Each validator decodes the body as `pallas_primitives::conway::TransactionBody`
//! and compares every critical field against its request type. Any
//! mismatch aborts the signing path with a [`ValidationError`].

use pallas_addresses::{Address, StakePayload};
use pallas_codec::utils::Nullable;
use pallas_primitives::conway::{Anchor, Certificate, DRep, TransactionBody, Vote, Voter};
use pallas_primitives::Relay;

// Role-neutral validation primitives, shared with DREP Tools via airgap-core.
pub use crate::validate::ValidationError;
use crate::validate::{
    addr_bytes, anchor_matches_parts, assert_inputs_bind_to_request,
    assert_no_extra_fields_inner, blake2b224, decode_body, output_pair,
    stake_credential_from_bech32,
};

use crate::drep::{DRepChoice, DRepDelegationRequest};
use crate::pool_update::{PoolUpdateRequest, RelaySpec};
use crate::vote::{VoteAnchor, VoteChoice, VoteRequest};
use crate::withdrawal::WithdrawalRequest;


/// Reject every Conway TransactionBody field that no SPO-tools operation
/// uses. An attacker controlling the online-tool's body construction
/// must not be able to wedge in e.g. a treasury donation, a vote-cast
/// from the SPO\'s stake credential, or a mint by leaving the field
/// unchecked. They are enumerated once here so each operation\'s validator
/// just calls into this list.
fn assert_no_extra_fields(body: &TransactionBody) -> Result<(), ValidationError> {
    assert_no_extra_fields_inner(body, false, false)
}


// ---------------------------------------------------------------------------
// Withdrawal
// ---------------------------------------------------------------------------


/// Verify a `WithdrawalRequest`'s body claims exactly the operation the
/// request describes: rewards are drawn from the pool's reward account,
/// outputs go only to the user's payment + reward-receive addresses,
/// the fee and TTL match, and there are no certificates.
pub fn validate_withdrawal_body(
    body_bytes: &[u8],
    req: &WithdrawalRequest,
) -> Result<(), ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields(&body)?;
    assert_inputs_bind_to_request(&body.inputs, &req.inputs, &req.payment_address_bech32)?;

    if body.fee != req.fee_lovelace {
        return Err(ValidationError::Mismatch("fee"));
    }
    if body.ttl != Some(req.ttl_slot) {
        return Err(ValidationError::Mismatch("ttl"));
    }
    if req.ttl_slot <= req.chain_context.current_slot {
        return Err(ValidationError::Mismatch("ttl_in_past"));
    }
    if body.certificates.is_some() {
        return Err(ValidationError::Mismatch("unexpected certificates"));
    }

    // Outputs: exactly two — one to reward_receive_addr (net amount),
    // one to payment_addr (change). Matched by address membership so the
    // build order is not pinned. When the operator withdraws into the same
    // wallet that funds the fee (reward_receive == payment), the builder
    // still emits two outputs to that one address, so that case is matched
    // as an unordered amount pair rather than by two distinct addresses.
    if body.outputs.len() != 2 {
        return Err(ValidationError::Mismatch("output count"));
    }
    let payment_b = addr_bytes(&req.payment_address_bech32)?;
    let reward_recv_b = addr_bytes(&req.reward_receive_address_bech32)?;

    if payment_b == reward_recv_b {
        // Single-wallet withdrawal: both outputs go to the one approved
        // address. Validate them as an unordered pair whose amounts are
        // exactly {change, net} — every lovelace still lands at the
        // approved address and the split is pinned.
        let mut coins = Vec::with_capacity(body.outputs.len());
        for o in &body.outputs {
            let (addr, coin) = output_pair(o)?;
            if addr != payment_b.as_slice() {
                return Err(ValidationError::Mismatch("output to unexpected address"));
            }
            coins.push(coin);
        }
        let mut got = [coins[0], coins[1]];
        let mut want = [
            req.change_to_payment_address_lovelace,
            req.net_to_reward_address_lovelace,
        ];
        got.sort_unstable();
        want.sort_unstable();
        if got != want {
            return Err(ValidationError::Mismatch("single-wallet output amounts"));
        }
    } else {
        let mut saw_payment = false;
        let mut saw_reward = false;
        for o in &body.outputs {
            let (addr, coin) = output_pair(o)?;
            if addr == payment_b.as_slice() {
                if saw_payment {
                    return Err(ValidationError::Mismatch("duplicate payment-address output"));
                }
                if coin != req.change_to_payment_address_lovelace {
                    return Err(ValidationError::Mismatch("payment-address output amount"));
                }
                saw_payment = true;
            } else if addr == reward_recv_b.as_slice() {
                if saw_reward {
                    return Err(ValidationError::Mismatch("duplicate reward-address output"));
                }
                if coin != req.net_to_reward_address_lovelace {
                    return Err(ValidationError::Mismatch("reward-address output amount"));
                }
                saw_reward = true;
            } else {
                return Err(ValidationError::Mismatch("output to unexpected address"));
            }
        }
        if !(saw_payment && saw_reward) {
            return Err(ValidationError::Mismatch("missing expected output"));
        }
    }

    // Withdrawals: exactly one entry, key = pool reward account, value
    // = net_to_reward_address_lovelace.
    let withdrawals = body
        .withdrawals
        .as_ref()
        .ok_or(ValidationError::Mismatch("missing withdrawals"))?;
    if withdrawals.len() != 1 {
        return Err(ValidationError::Mismatch("withdrawal entry count"));
    }
    let pool_reward_b = addr_bytes(&req.pool_reward_address_bech32)?;
    let (key, amount) = &withdrawals[0];
    if key.as_slice() != pool_reward_b.as_slice() {
        return Err(ValidationError::Mismatch("withdrawal reward account"));
    }
    if *amount != req.net_to_reward_address_lovelace {
        return Err(ValidationError::Mismatch("withdrawal amount"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DRep delegation
// ---------------------------------------------------------------------------


fn drep_choice_matches_drep(choice: &DRepChoice, drep: &DRep) -> Result<bool, ValidationError> {
    Ok(match (choice, drep) {
        (DRepChoice::Abstain, DRep::Abstain) => true,
        (DRepChoice::NoConfidence, DRep::NoConfidence) => true,
        (DRepChoice::KeyHash { hash_hex }, DRep::Key(h)) => {
            let req_bytes = hex::decode(hash_hex)
                .map_err(|e| ValidationError::BadHex(hash_hex.clone(), e.to_string()))?;
            req_bytes.as_slice() == h.as_ref()
        }
        (DRepChoice::ScriptHash { hash_hex }, DRep::Script(h)) => {
            let req_bytes = hex::decode(hash_hex)
                .map_err(|e| ValidationError::BadHex(hash_hex.clone(), e.to_string()))?;
            req_bytes.as_slice() == h.as_ref()
        }
        _ => false,
    })
}

/// Verify a `DRepDelegationRequest`'s body. Exactly one VoteDeleg cert
/// whose stake credential matches the request and DRep matches the
/// requested choice; one change output to the payment address; no
/// withdrawals; fee and TTL match.
pub fn validate_drep_body(
    body_bytes: &[u8],
    req: &DRepDelegationRequest,
) -> Result<(), ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields(&body)?;
    assert_inputs_bind_to_request(&body.inputs, &req.inputs, &req.payment_address_bech32)?;

    if body.fee != req.fee_lovelace {
        return Err(ValidationError::Mismatch("fee"));
    }
    if body.ttl != Some(req.ttl_slot) {
        return Err(ValidationError::Mismatch("ttl"));
    }
    if req.ttl_slot <= req.chain_context.current_slot {
        return Err(ValidationError::Mismatch("ttl_in_past"));
    }
    if body.withdrawals.is_some() {
        return Err(ValidationError::Mismatch("unexpected withdrawals"));
    }

    // Single output — change to payment address.
    if body.outputs.len() != 1 {
        return Err(ValidationError::Mismatch("output count"));
    }
    let payment_b = addr_bytes(&req.payment_address_bech32)?;
    let (out_addr, out_coin) = output_pair(&body.outputs[0])?;
    if out_addr != payment_b.as_slice() {
        return Err(ValidationError::Mismatch("output address"));
    }
    if out_coin != req.change_to_payment_address_lovelace {
        return Err(ValidationError::Mismatch("change-to-payment amount"));
    }

    // Exactly one VoteDeleg cert.
    let certs = body
        .certificates
        .as_ref()
        .ok_or(ValidationError::Mismatch("missing certificates"))?;
    if certs.len() != 1 {
        return Err(ValidationError::Mismatch("certificate count"));
    }
    let (body_cred, body_drep) = match &certs[0] {
        Certificate::VoteDeleg(c, d) => (c, d),
        _ => return Err(ValidationError::Mismatch("not a VoteDeleg certificate")),
    };
    let req_cred = stake_credential_from_bech32(&req.stake_credential_bech32)?;
    if &req_cred != body_cred {
        return Err(ValidationError::Mismatch("stake credential"));
    }
    if !drep_choice_matches_drep(&req.drep_choice, body_drep)? {
        return Err(ValidationError::Mismatch("DRep choice"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pool registration / re-registration (parameter update)
// ---------------------------------------------------------------------------

fn relay_spec_matches(spec: &RelaySpec, on_chain: &Relay) -> bool {
    match (spec, on_chain) {
        (
            RelaySpec::SingleHostAddr { port, ipv4, ipv6 },
            Relay::SingleHostAddr(p, v4, v6),
        ) => {
            let port_ok = match (port, p) {
                (Some(a), Nullable::Some(b)) => *a as u32 == *b,
                (None, Nullable::Null) => true,
                _ => false,
            };
            let v4_ok = match (ipv4, v4) {
                (Some(a), Nullable::Some(b)) => {
                    if let Ok(parsed) = a.parse::<std::net::Ipv4Addr>() {
                        let oct: [u8; 4] = parsed.octets();
                        oct.as_slice() == b.as_slice()
                    } else {
                        false
                    }
                }
                (None, Nullable::Null) => true,
                _ => false,
            };
            let v6_ok = match (ipv6, v6) {
                (Some(a), Nullable::Some(b)) => {
                    if let Ok(parsed) = a.parse::<std::net::Ipv6Addr>() {
                        let oct: [u8; 16] = parsed.octets();
                        oct.as_slice() == b.as_slice()
                    } else {
                        false
                    }
                }
                (None, Nullable::Null) => true,
                _ => false,
            };
            port_ok && v4_ok && v6_ok
        }
        (RelaySpec::SingleHostName { port, dns }, Relay::SingleHostName(p, d)) => {
            let port_ok = match (port, p) {
                (Some(a), Nullable::Some(b)) => *a as u32 == *b,
                (None, Nullable::Null) => true,
                _ => false,
            };
            port_ok && dns == d
        }
        (RelaySpec::MultiHostName { dns }, Relay::MultiHostName(d)) => dns == d,
        _ => false,
    }
}

/// Verify a `PoolUpdateRequest`'s body. Exactly one PoolRegistration
/// cert whose every parameter matches the request; one change output
/// to the payment address; no withdrawals; fee and TTL match.
pub fn validate_pool_update_body(
    body_bytes: &[u8],
    req: &PoolUpdateRequest,
) -> Result<(), ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields(&body)?;
    assert_inputs_bind_to_request(&body.inputs, &req.inputs, &req.payment_address_bech32)?;

    if body.fee != req.fee_lovelace {
        return Err(ValidationError::Mismatch("fee"));
    }
    if body.ttl != Some(req.ttl_slot) {
        return Err(ValidationError::Mismatch("ttl"));
    }
    if req.ttl_slot <= req.chain_context.current_slot {
        return Err(ValidationError::Mismatch("ttl_in_past"));
    }
    if body.withdrawals.is_some() {
        return Err(ValidationError::Mismatch("unexpected withdrawals"));
    }

    // Single change output to payment address.
    if body.outputs.len() != 1 {
        return Err(ValidationError::Mismatch("output count"));
    }
    let payment_b = addr_bytes(&req.payment_address_bech32)?;
    let (out_addr, out_coin) = output_pair(&body.outputs[0])?;
    if out_addr != payment_b.as_slice() {
        return Err(ValidationError::Mismatch("output address"));
    }
    if out_coin != req.change_to_payment_address_lovelace {
        return Err(ValidationError::Mismatch("change-to-payment amount"));
    }

    // Exactly one PoolRegistration cert.
    let certs = body
        .certificates
        .as_ref()
        .ok_or(ValidationError::Mismatch("missing certificates"))?;
    if certs.len() != 1 {
        return Err(ValidationError::Mismatch("certificate count"));
    }
    let (operator, vrf_keyhash, pledge, cost, margin, reward_account, pool_owners, relays, pool_metadata) =
        match &certs[0] {
            Certificate::PoolRegistration {
                operator,
                vrf_keyhash,
                pledge,
                cost,
                margin,
                reward_account,
                pool_owners,
                relays,
                pool_metadata,
            } => (operator, vrf_keyhash, *pledge, *cost, margin, reward_account, pool_owners, relays, pool_metadata),
            _ => return Err(ValidationError::Mismatch("not a PoolRegistration certificate")),
        };

    // Operator (pool ID) — 28 bytes from "pool1..." bech32.
    let (hrp, pool_id_bytes) = bech32::decode(&req.pool_id_bech32).map_err(|e| {
        ValidationError::BadAddress(req.pool_id_bech32.clone(), e.to_string())
    })?;
    if hrp.as_str() != "pool" {
        return Err(ValidationError::Mismatch("pool ID is not pool1... bech32"));
    }
    if pool_id_bytes.len() != 28 || pool_id_bytes.as_slice() != operator.as_ref() {
        return Err(ValidationError::Mismatch("pool operator hash"));
    }

    // VRF keyhash — 32-byte hex.
    let vrf_bytes = hex::decode(&req.vrf_keyhash_hex)
        .map_err(|e| ValidationError::BadHex(req.vrf_keyhash_hex.clone(), e.to_string()))?;
    if vrf_bytes.len() != 32 || vrf_bytes.as_slice() != vrf_keyhash.as_ref() {
        return Err(ValidationError::Mismatch("VRF keyhash"));
    }

    if pledge != req.pledge_lovelace {
        return Err(ValidationError::Mismatch("pledge"));
    }
    if cost != req.fixed_cost_lovelace {
        return Err(ValidationError::Mismatch("fixed cost"));
    }
    if margin.numerator != req.margin_numerator || margin.denominator != req.margin_denominator {
        return Err(ValidationError::Mismatch("margin"));
    }

    // Reward account — 29 bytes from "stake1..." bech32 (header + 28 hash).
    let reward_acct_b = addr_bytes(&req.reward_account_bech32)?;
    if reward_account.as_slice() != reward_acct_b.as_slice() {
        return Err(ValidationError::Mismatch("reward account"));
    }

    // Pool owners — Set<Hash<28>> compared as sorted byte arrays.
    let mut req_owners: Vec<[u8; 28]> = Vec::with_capacity(req.pool_owner_stake_addresses.len());
    for sa in &req.pool_owner_stake_addresses {
        let parsed = Address::from_bech32(sa)
            .map_err(|e| ValidationError::BadAddress(sa.clone(), e.to_string()))?;
        let stake = match parsed {
            Address::Stake(s) => s,
            _ => return Err(ValidationError::Mismatch("pool owner is not a stake address")),
        };
        match stake.payload() {
            StakePayload::Stake(h) => {
                let mut a = [0u8; 28];
                a.copy_from_slice(h.as_ref());
                req_owners.push(a);
            }
            StakePayload::Script(_) => {
                return Err(ValidationError::Mismatch("pool owner is script (not key)"));
            }
        }
    }
    req_owners.sort();
    let mut body_owners: Vec<[u8; 28]> = pool_owners
        .iter()
        .map(|h| {
            let mut a = [0u8; 28];
            a.copy_from_slice(h.as_ref());
            a
        })
        .collect();
    body_owners.sort();
    if req_owners != body_owners {
        return Err(ValidationError::Mismatch("pool owners"));
    }

    // Relays — compared positionally (tx_builder preserves request order
    // and the wire is order-significant).
    if relays.len() != req.relays.len() {
        return Err(ValidationError::Mismatch("relay count"));
    }
    for (spec, on_chain) in req.relays.iter().zip(relays.iter()) {
        if !relay_spec_matches(spec, on_chain) {
            return Err(ValidationError::Mismatch("relay"));
        }
    }

    // Metadata — both-Null or both-Some-and-equal.
    match (pool_metadata, req.metadata_url.as_deref(), req.metadata_hash_hex.as_deref()) {
        (Nullable::Null, None, None) => {}
        (Nullable::Some(meta), Some(url), Some(hash_hex)) => {
            if meta.url != url {
                return Err(ValidationError::Mismatch("metadata URL"));
            }
            let req_hash = hex::decode(hash_hex)
                .map_err(|e| ValidationError::BadHex(hash_hex.to_string(), e.to_string()))?;
            if req_hash.len() != 32 || req_hash.as_slice() != meta.hash.as_ref() {
                return Err(ValidationError::Mismatch("metadata hash"));
            }
        }
        _ => return Err(ValidationError::Mismatch("metadata presence")),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SPO governance vote
// ---------------------------------------------------------------------------


/// Verify a `VoteRequest`'s body. Exactly one voter — a `StakePoolKey`
/// whose 28-byte hash equals the request's pool id — casts exactly one
/// vote on the requested governance action id, with the requested vote
/// and rationale anchor; one change output to the payment address; no
/// certificates or withdrawals; fee and TTL match.
///
/// The cold key signs this body, so the binding here is what stops a
/// compromised online tool from making the pool vote on a different
/// action, with a different ballot, or as a different pool: the
/// signer additionally checks that the cold key it loads hashes to this
/// same pool id (see `sign_vote_core`).
pub fn validate_vote_body(body_bytes: &[u8], req: &VoteRequest) -> Result<(), ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields_inner(&body, true, false)?;
    assert_inputs_bind_to_request(&body.inputs, &req.inputs, &req.payment_address_bech32)?;

    if body.fee != req.fee_lovelace {
        return Err(ValidationError::Mismatch("fee"));
    }
    if body.ttl != Some(req.ttl_slot) {
        return Err(ValidationError::Mismatch("ttl"));
    }
    if req.ttl_slot <= req.chain_context.current_slot {
        return Err(ValidationError::Mismatch("ttl_in_past"));
    }
    if body.certificates.is_some() {
        return Err(ValidationError::Mismatch("unexpected certificates"));
    }
    if body.withdrawals.is_some() {
        return Err(ValidationError::Mismatch("unexpected withdrawals"));
    }

    // Single change output to the payment address.
    if body.outputs.len() != 1 {
        return Err(ValidationError::Mismatch("output count"));
    }
    let payment_b = addr_bytes(&req.payment_address_bech32)?;
    let (out_addr, out_coin) = output_pair(&body.outputs[0])?;
    if out_addr != payment_b.as_slice() {
        return Err(ValidationError::Mismatch("output address"));
    }
    if out_coin != req.change_to_payment_address_lovelace {
        return Err(ValidationError::Mismatch("change-to-payment amount"));
    }

    // Voting procedures: exactly one voter casting exactly one vote.
    let vps = body
        .voting_procedures
        .as_ref()
        .ok_or(ValidationError::Mismatch("missing voting_procedures"))?;
    if vps.len() != 1 {
        return Err(ValidationError::Mismatch("voter count"));
    }
    let (voter, votes) = &vps[0];

    // Voter must be this pool's stake-pool key.
    let pool_hash = match voter {
        Voter::StakePoolKey(h) => h,
        _ => return Err(ValidationError::Mismatch("voter is not a stake pool key")),
    };
    let (hrp, pool_id_bytes) = bech32::decode(&req.pool_id_bech32)
        .map_err(|e| ValidationError::BadAddress(req.pool_id_bech32.clone(), e.to_string()))?;
    if hrp.as_str() != "pool" {
        return Err(ValidationError::Mismatch("pool ID is not pool1... bech32"));
    }
    if pool_id_bytes.len() != 28 || pool_id_bytes.as_slice() != pool_hash.as_ref() {
        return Err(ValidationError::Mismatch("voter pool hash"));
    }

    if votes.len() != 1 {
        return Err(ValidationError::Mismatch("gov action count"));
    }
    let (gov_action_id, procedure) = &votes[0];

    // Governance action id == request (tx hash + index).
    let action_hash = hex::decode(&req.action_tx_hash_hex)
        .map_err(|e| ValidationError::BadHex(req.action_tx_hash_hex.clone(), e.to_string()))?;
    if action_hash.len() != 32 || action_hash.as_slice() != gov_action_id.transaction_id.as_ref() {
        return Err(ValidationError::Mismatch("gov action tx hash"));
    }
    if gov_action_id.action_index != req.action_index {
        return Err(ValidationError::Mismatch("gov action index"));
    }

    // Ballot matches.
    let want_vote = match req.vote {
        VoteChoice::No => Vote::No,
        VoteChoice::Yes => Vote::Yes,
        VoteChoice::Abstain => Vote::Abstain,
    };
    if procedure.vote != want_vote {
        return Err(ValidationError::Mismatch("vote"));
    }

    // Rationale anchor matches.
    if !anchor_matches(&req.anchor, &procedure.anchor)? {
        return Err(ValidationError::Mismatch("anchor"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------


/// Compare the request's optional rationale anchor to the on-chain
/// `Nullable<Anchor>` via the shared role-neutral comparator.
fn anchor_matches(
    req: &Option<VoteAnchor>,
    on_chain: &Nullable<Anchor>,
) -> Result<bool, ValidationError> {
    anchor_matches_parts(
        req.as_ref().map(|a| (a.url.as_str(), a.hash_hex.as_str())),
        on_chain,
    )
}

/// Defense-in-depth binding between the request and the key that signs.
///
/// `validate_vote_body` proves the body's single voter is the pool id
/// named in the request. This proves that pool id is the operator's own
/// cold key: it hashes the cold verification key (blake2b-224, the pool-id
/// derivation) and checks it equals the request pool id. Without this a
/// compromised online tool could craft a body voting as some pool id and
/// label the request with that same id; the signer would bind body to
/// request and sign — but the cold key would not actually authorise that
/// pool's vote on-chain. Checking here makes the signer refuse before the
/// cold key ever touches the body.
pub fn assert_cold_vkey_matches_pool(
    pool_id_bech32: &str,
    cold_vkey: &[u8; 32],
) -> Result<(), ValidationError> {
    let (hrp, pool_id_bytes) = bech32::decode(pool_id_bech32)
        .map_err(|e| ValidationError::BadAddress(pool_id_bech32.to_string(), e.to_string()))?;
    if hrp.as_str() != "pool" {
        return Err(ValidationError::Mismatch("pool ID is not pool1... bech32"));
    }
    let pool_hash = blake2b224(cold_vkey);
    if pool_id_bytes.len() != 28 || pool_id_bytes.as_slice() != pool_hash {
        return Err(ValidationError::Mismatch("cold key does not match pool id"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::UtxoInput;
    use pallas_codec::minicbor;
    use crate::chain_context::ChainContext;
    use crate::drep::DRepChoice;
    use crate::vote::{VoteAnchor, VoteChoice, VoteRequest};
    use crate::wire_kind::WireKind;
    use crate::pool_update::RelaySpec;
    
    use pallas_codec::utils::{Bytes, NonEmptyKeyValuePairs, NonEmptySet, Nullable, Set};
    use pallas_primitives::conway::{
        Anchor, Certificate, DRep, GovActionId, PseudoTransactionOutput, TransactionBody,
        TransactionOutput, Value, Vote, Voter, VotingProcedure,
    };
    use pallas_primitives::{Hash, NetworkId, RationalNumber, StakeCredential, TransactionInput};

    const PAYMENT_ADDR: &str =
        "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw";
    const REWARD_RECV_ADDR: &str =
        "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am";
    const POOL_REWARD_ADDR: &str =
        "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u";
    const STAKE_ADDR: &str =
        "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u";

    fn dummy_chain_context() -> ChainContext {
        ChainContext {
            current_epoch: 1,
            current_slot: 100,
            current_kes_period: 0,
            epoch_ends_at_unix: 0,
            opcert_expires_at_unix: None,
            built_at_unix: 0,
        }
    }

    fn coin_output(addr_bech: &str, lovelace: u64) -> TransactionOutput {
        let addr = Address::from_bech32(addr_bech).unwrap();
        PseudoTransactionOutput::PostAlonzo(
            pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(addr.to_vec()),
                value: Value::Coin(lovelace),
                datum_option: None,
                script_ref: None,
            },
        )
    }

    fn dummy_utxo_input() -> UtxoInput {
        UtxoInput {
            tx_hash_hex: "00".repeat(32),
            tx_index: 0,
            amount_lovelace: 0,
            address_bech32: PAYMENT_ADDR.into(),
        }
    }

    fn empty_input() -> TransactionInput {
        TransactionInput {
            transaction_id: Hash::from([0u8; 32]),
            index: 0,
        }
    }

    fn make_withdrawal_body(fee: u64, ttl: u64, net: u64, change: u64) -> Vec<u8> {
        let pool_reward_b = Address::from_bech32(POOL_REWARD_ADDR).unwrap().to_vec();
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![
                coin_output(REWARD_RECV_ADDR, net),
                coin_output(PAYMENT_ADDR, change),
            ],
            fee,
            ttl: Some(ttl),
            certificates: None,
            withdrawals: Some(NonEmptyKeyValuePairs::Def(vec![(
                Bytes::from(pool_reward_b),
                net,
            )])),
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
            voting_procedures: None,
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    fn make_withdrawal_request(fee: u64, ttl: u64, net: u64, change: u64) -> WithdrawalRequest {
        WithdrawalRequest {
            kind: WireKind::Withdrawal,
            tx_body_cbor_hex: String::new(),
            fee_lovelace: fee,
            net_to_reward_address_lovelace: net,
            change_to_payment_address_lovelace: change,
            ttl_slot: ttl,
            payment_address_bech32: PAYMENT_ADDR.into(),
            reward_receive_address_bech32: REWARD_RECV_ADDR.into(),
            pool_reward_address_bech32: POOL_REWARD_ADDR.into(),
            inputs: vec![dummy_utxo_input()],
            operator_pin_proof: "0000000000000000".into(),
            chain_context: dummy_chain_context(),
        }
    }

    #[test]
    fn withdrawal_happy_path() {
        let body = make_withdrawal_body(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        validate_withdrawal_body(&body, &req).expect("body matches request");
    }

    /// A change output carrying native assets must validate. When the operator's
    /// wallet holds a token, every spent UTxO's assets return in the change
    /// output, making it multi-asset. The validator reads it for its lovelace
    /// and accepts it; token preservation is enforced structurally (no mint +
    /// fixed output count + all outputs at operator addresses), so the assets
    /// can only land back at the payment address.
    #[test]
    fn withdrawal_accepts_multiasset_change() {
        let (net, change, fee, ttl) = (1_000_000_000u64, 33_909_103u64, 200_000u64, 2_000_000u64);
        let pool_reward_b = Address::from_bech32(POOL_REWARD_ADDR).unwrap().to_vec();
        let payment_b = Address::from_bech32(PAYMENT_ADDR).unwrap().to_vec();
        let assets = [airgap_core::asset::Asset {
            policy_hex: "00112233445566778899aabbccddeeff00112233445566778899aabb".into(),
            asset_name_hex: "4e49474854".into(),
            quantity: 42,
        }];
        let change_out = airgap_core::tx::make_asset_output(payment_b, change, &assets).unwrap();
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![coin_output(REWARD_RECV_ADDR, net), change_out],
            fee,
            ttl: Some(ttl),
            certificates: None,
            withdrawals: Some(NonEmptyKeyValuePairs::Def(vec![(Bytes::from(pool_reward_b), net)])),
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
            voting_procedures: None,
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        let req = make_withdrawal_request(fee, ttl, net, change);
        validate_withdrawal_body(&buf, &req).expect("multi-asset change output must validate");
    }

    /// Single-wallet body: both outputs go to PAYMENT_ADDR (the builder's
    /// shape when reward_receive == payment).
    fn make_single_wallet_body(net: u64, change: u64, fee: u64, ttl: u64) -> Vec<u8> {
        let pool_reward_b = Address::from_bech32(POOL_REWARD_ADDR).unwrap().to_vec();
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![
                coin_output(PAYMENT_ADDR, net),
                coin_output(PAYMENT_ADDR, change),
            ],
            fee,
            ttl: Some(ttl),
            certificates: None,
            withdrawals: Some(NonEmptyKeyValuePairs::Def(vec![(
                Bytes::from(pool_reward_b),
                net,
            )])),
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
            voting_procedures: None,
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    #[test]
    fn withdrawal_accepts_single_wallet_payment_equals_reward() {
        // reward_receive == payment: two outputs to the one address,
        // amounts {net, change}. Must be accepted, not false-rejected as a
        // duplicate-address output.
        let body = make_single_wallet_body(1_000_000_000, 33_909_103, 200_000, 2_000_000);
        let mut req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        req.reward_receive_address_bech32 = PAYMENT_ADDR.into();
        validate_withdrawal_body(&body, &req).expect("single-wallet withdrawal is valid");
    }

    #[test]
    fn withdrawal_single_wallet_rejects_wrong_amounts() {
        // Same single-wallet topology, but the two amounts do not form the
        // {change, net} pair -> rejected.
        let body = make_single_wallet_body(1_000_000_000, 33_909_104, 200_000, 2_000_000);
        let mut req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        req.reward_receive_address_bech32 = PAYMENT_ADDR.into();
        let err = validate_withdrawal_body(&body, &req).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("single-wallet output amounts")
        ));
    }

    #[test]
    fn withdrawal_rejects_fee_mismatch() {
        let body = make_withdrawal_body(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let req = make_withdrawal_request(999_999, 2_000_000, 1_000_000_000, 33_909_103);
        let err = validate_withdrawal_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("fee")));
    }

    #[test]
    fn withdrawal_rejects_ttl_mismatch() {
        let body = make_withdrawal_body(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let req = make_withdrawal_request(200_000, 9_999_999, 1_000_000_000, 33_909_103);
        let err = validate_withdrawal_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("ttl")));
    }

    #[test]
    fn withdrawal_rejects_amount_mismatch() {
        let body = make_withdrawal_body(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 1);
        let err = validate_withdrawal_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch(_)));
    }

    #[test]
    fn withdrawal_rejects_extra_certificate() {
        let pool_reward_b = Address::from_bech32(POOL_REWARD_ADDR).unwrap().to_vec();
        let stake_cred = StakeCredential::AddrKeyhash(Hash::from([1u8; 28]));
        let cert = Certificate::VoteDeleg(stake_cred, DRep::Abstain);
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![
                coin_output(REWARD_RECV_ADDR, 1_000_000_000),
                coin_output(PAYMENT_ADDR, 33_909_103),
            ],
            fee: 200_000,
            ttl: Some(2_000_000),
            certificates: Some(NonEmptySet::try_from(vec![cert]).unwrap()),
            withdrawals: Some(NonEmptyKeyValuePairs::Def(vec![(
                Bytes::from(pool_reward_b),
                1_000_000_000,
            )])),
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
            voting_procedures: None,
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        let req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let err = validate_withdrawal_body(&buf, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("unexpected certificates")));
    }

    #[test]
    fn withdrawal_rejects_input_address_mismatch() {
        let body = make_withdrawal_body(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let mut req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        req.inputs = vec![UtxoInput {
            tx_hash_hex: "00".repeat(32),
            tx_index: 0,
            amount_lovelace: 0,
            address_bech32: REWARD_RECV_ADDR.into(),
        }];
        let err = validate_withdrawal_body(&body, &req).unwrap_err();
        match err {
            ValidationError::Mismatch(s) => {
                assert!(s.contains("input address"), "got: {s}")
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn withdrawal_rejects_input_hash_mismatch() {
        let body = make_withdrawal_body(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let mut req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        req.inputs = vec![UtxoInput {
            tx_hash_hex: "ff".repeat(32),
            tx_index: 0,
            amount_lovelace: 0,
            address_bech32: PAYMENT_ADDR.into(),
        }];
        let err = validate_withdrawal_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch(s) if s.contains("body inputs do not match")));
    }

    #[test]
    fn withdrawal_rejects_input_count_mismatch() {
        let body = make_withdrawal_body(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let mut req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        req.inputs = vec![dummy_utxo_input(), dummy_utxo_input()];
        let err = validate_withdrawal_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("input count")));
    }

    #[test]
    fn withdrawal_rejects_empty_inputs() {
        let body = make_withdrawal_body(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        let mut req = make_withdrawal_request(200_000, 2_000_000, 1_000_000_000, 33_909_103);
        req.inputs = vec![];
        let err = validate_withdrawal_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch(s) if s.contains("empty")));
    }

    fn make_drep_body(drep: DRep) -> Vec<u8> {
        let stake_cred = stake_credential_from_bech32(STAKE_ADDR).unwrap();
        let cert = Certificate::VoteDeleg(stake_cred, drep);
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![coin_output(PAYMENT_ADDR, 33_909_103)],
            fee: 200_000,
            ttl: Some(2_000_000),
            certificates: Some(NonEmptySet::try_from(vec![cert]).unwrap()),
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
            voting_procedures: None,
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    fn make_drep_request(choice: DRepChoice) -> DRepDelegationRequest {
        DRepDelegationRequest {
            kind: WireKind::DrepDelegation,
            tx_body_cbor_hex: String::new(),
            fee_lovelace: 200_000,
            change_to_payment_address_lovelace: 33_909_103,
            ttl_slot: 2_000_000,
            payment_address_bech32: PAYMENT_ADDR.into(),
            stake_credential_bech32: STAKE_ADDR.into(),
            drep_choice: choice,
            inputs: vec![dummy_utxo_input()],
            operator_pin_proof: "0000000000000000".into(),
            chain_context: dummy_chain_context(),
        }
    }

    #[test]
    fn drep_abstain_happy_path() {
        let body = make_drep_body(DRep::Abstain);
        let req = make_drep_request(DRepChoice::Abstain);
        validate_drep_body(&body, &req).expect("body matches request");
    }

    #[test]
    fn drep_rejects_choice_mismatch() {
        let body = make_drep_body(DRep::Abstain);
        let req = make_drep_request(DRepChoice::NoConfidence);
        let err = validate_drep_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("DRep choice")));
    }

    #[test]
    fn drep_keyhash_happy_path() {
        let key = [42u8; 28];
        let body = make_drep_body(DRep::Key(Hash::from(key)));
        let req = make_drep_request(DRepChoice::KeyHash {
            hash_hex: hex::encode(key),
        });
        validate_drep_body(&body, &req).expect("body matches request");
    }

    #[test]
    fn drep_rejects_keyhash_mismatch() {
        let body = make_drep_body(DRep::Key(Hash::from([42u8; 28])));
        let req = make_drep_request(DRepChoice::KeyHash {
            hash_hex: hex::encode([99u8; 28]),
        });
        let err = validate_drep_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("DRep choice")));
    }

    fn pool_id_b28() -> [u8; 28] { [11u8; 28] }
    fn vrf_b32() -> [u8; 32] { [22u8; 32] }
    fn owner_b28() -> [u8; 28] { [33u8; 28] }

    fn pool_id_bech32() -> String {
        let hrp = bech32::Hrp::parse("pool").unwrap();
        bech32::encode::<bech32::Bech32>(hrp, &pool_id_b28()).unwrap()
    }

    fn owner_stake_bech32() -> String {
        // network=1 (mainnet), key-stake header = 0xe1
        let mut bytes = Vec::with_capacity(29);
        bytes.push(0xe1);
        bytes.extend_from_slice(&owner_b28());
        let hrp = bech32::Hrp::parse("stake").unwrap();
        bech32::encode::<bech32::Bech32>(hrp, &bytes).unwrap()
    }

    fn make_pool_request() -> PoolUpdateRequest {
        PoolUpdateRequest {
            kind: WireKind::PoolUpdate,
            tx_body_cbor_hex: String::new(),
            fee_lovelace: 500_000,
            change_to_payment_address_lovelace: 1_000_000,
            ttl_slot: 2_000_000,
            payment_address_bech32: PAYMENT_ADDR.into(),
            pool_id_bech32: pool_id_bech32(),
            vrf_keyhash_hex: hex::encode(vrf_b32()),
            pledge_lovelace: 30_000_000_000,
            fixed_cost_lovelace: 170_000_000,
            margin_numerator: 1,
            margin_denominator: 100,
            reward_account_bech32: POOL_REWARD_ADDR.into(),
            pool_owner_stake_addresses: vec![owner_stake_bech32()],
            relays: vec![RelaySpec::SingleHostName {
                port: Some(6000),
                dns: "relay.example.com".into(),
            }],
            metadata_url: Some("https://example.com/m.json".into()),
            metadata_hash_hex: Some(hex::encode([7u8; 32])),
            inputs: vec![dummy_utxo_input()],
            operator_pin_proof: "0000000000000000".into(),
            chain_context: dummy_chain_context(),
        }
    }

    fn make_pool_body_from(req: &PoolUpdateRequest) -> Vec<u8> {
        let reward_acct_b = Address::from_bech32(&req.reward_account_bech32).unwrap().to_vec();
        let cert = Certificate::PoolRegistration {
            operator: Hash::from(pool_id_b28()),
            vrf_keyhash: Hash::from(vrf_b32()),
            pledge: req.pledge_lovelace,
            cost: req.fixed_cost_lovelace,
            margin: RationalNumber {
                numerator: req.margin_numerator,
                denominator: req.margin_denominator,
            },
            reward_account: Bytes::from(reward_acct_b),
            pool_owners: Set::from(vec![Hash::from(owner_b28())]),
            relays: vec![Relay::SingleHostName(
                Nullable::Some(6000),
                "relay.example.com".into(),
            )],
            pool_metadata: Nullable::Some(pallas_primitives::PoolMetadata {
                url: req.metadata_url.clone().unwrap(),
                hash: Hash::from([7u8; 32]),
            }),
        };
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![coin_output(PAYMENT_ADDR, req.change_to_payment_address_lovelace)],
            fee: req.fee_lovelace,
            ttl: Some(req.ttl_slot),
            certificates: Some(NonEmptySet::try_from(vec![cert]).unwrap()),
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
            voting_procedures: None,
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    #[test]
    fn pool_update_happy_path() {
        let req = make_pool_request();
        let body = make_pool_body_from(&req);
        validate_pool_update_body(&body, &req).expect("body matches request");
    }

    #[test]
    fn pool_update_rejects_pledge_mismatch() {
        let req = make_pool_request();
        let body = make_pool_body_from(&req);
        let mut tampered = req;
        tampered.pledge_lovelace = 1;
        let err = validate_pool_update_body(&body, &tampered).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("pledge")));
    }

    #[test]
    fn pool_update_rejects_relay_mismatch() {
        let req = make_pool_request();
        let body = make_pool_body_from(&req);
        let mut tampered = req;
        tampered.relays = vec![RelaySpec::SingleHostName {
            port: Some(7000),
            dns: "relay.example.com".into(),
        }];
        let err = validate_pool_update_body(&body, &tampered).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("relay")));
    }

    #[test]
    fn relay_ipv4_matches_on_chain_octets() {
        let spec = RelaySpec::SingleHostAddr {
            port: Some(6000),
            ipv4: Some("1.2.3.4".into()),
            ipv6: None,
        };
        let on_chain = Relay::SingleHostAddr(
            Nullable::Some(6000),
            Nullable::Some(Bytes::from(vec![1, 2, 3, 4])),
            Nullable::Null,
        );
        assert!(relay_spec_matches(&spec, &on_chain));
    }

    /// The preview string must be the literal address registered on-chain:
    /// malformed IPv4 strings whose salvageable octets happen to number
    /// four ("999.1.2.3.4", "1.2..3.4", ...) must be rejected, mirroring
    /// the strict IPv6 branch.
    #[test]
    fn relay_rejects_malformed_ipv4_strings() {
        let on_chain = Relay::SingleHostAddr(
            Nullable::Some(6000),
            Nullable::Some(Bytes::from(vec![1, 2, 3, 4])),
            Nullable::Null,
        );
        for bad in ["999.1.2.3.4", "1.2..3.4", "1.2.3.4.", "01.2.3.4", " 1.2.3.4"] {
            let spec = RelaySpec::SingleHostAddr {
                port: Some(6000),
                ipv4: Some(bad.into()),
                ipv6: None,
            };
            assert!(
                !relay_spec_matches(&spec, &on_chain),
                "malformed ipv4 {bad:?} must not match"
            );
        }
    }

    #[test]
    fn relay_ipv4_rejects_octet_mismatch() {
        let spec = RelaySpec::SingleHostAddr {
            port: Some(6000),
            ipv4: Some("1.2.3.5".into()),
            ipv6: None,
        };
        let on_chain = Relay::SingleHostAddr(
            Nullable::Some(6000),
            Nullable::Some(Bytes::from(vec![1, 2, 3, 4])),
            Nullable::Null,
        );
        assert!(!relay_spec_matches(&spec, &on_chain));
    }

    #[test]
    fn pool_update_rejects_metadata_mismatch() {
        let req = make_pool_request();
        let body = make_pool_body_from(&req);
        let mut tampered = req;
        tampered.metadata_hash_hex = Some(hex::encode([0xffu8; 32]));
        let err = validate_pool_update_body(&body, &tampered).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("metadata hash")));
    }

    const ACTION_HASH: [u8; 32] = [0xABu8; 32];

    fn make_vote_body(vote: Vote, anchor: Nullable<Anchor>) -> Vec<u8> {
        let voter = Voter::StakePoolKey(Hash::from(pool_id_b28()));
        let gov_action_id = GovActionId {
            transaction_id: Hash::from(ACTION_HASH),
            action_index: 0,
        };
        let procedure = VotingProcedure { vote, anchor };
        let inner = NonEmptyKeyValuePairs::Def(vec![(gov_action_id, procedure)]);
        let vps = NonEmptyKeyValuePairs::Def(vec![(voter, inner)]);
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![coin_output(PAYMENT_ADDR, 33_909_103)],
            fee: 200_000,
            ttl: Some(2_000_000),
            certificates: None,
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
            voting_procedures: Some(vps),
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    fn make_vote_request(vote: VoteChoice, anchor: Option<VoteAnchor>) -> VoteRequest {
        VoteRequest {
            kind: WireKind::Vote,
            tx_body_cbor_hex: String::new(),
            fee_lovelace: 200_000,
            change_to_payment_address_lovelace: 33_909_103,
            ttl_slot: 2_000_000,
            payment_address_bech32: PAYMENT_ADDR.into(),
            pool_id_bech32: pool_id_bech32(),
            action_tx_hash_hex: hex::encode(ACTION_HASH),
            action_index: 0,
            vote,
            anchor,
            inputs: vec![dummy_utxo_input()],
            operator_pin_proof: "0000000000000000".into(),
            chain_context: dummy_chain_context(),
        }
    }

    #[test]
    fn vote_yes_happy_path() {
        let body = make_vote_body(Vote::Yes, Nullable::Null);
        let req = make_vote_request(VoteChoice::Yes, None);
        validate_vote_body(&body, &req).expect("body matches request");
    }

    #[test]
    fn vote_rejects_vote_mismatch() {
        let body = make_vote_body(Vote::Yes, Nullable::Null);
        let req = make_vote_request(VoteChoice::No, None);
        let err = validate_vote_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("vote")));
    }

    #[test]
    fn vote_rejects_wrong_pool() {
        // Body voter is a different pool than the request's pool id.
        let voter = Voter::StakePoolKey(Hash::from([0x99u8; 28]));
        let gov_action_id = GovActionId {
            transaction_id: Hash::from(ACTION_HASH),
            action_index: 0,
        };
        let procedure = VotingProcedure { vote: Vote::Yes, anchor: Nullable::Null };
        let inner = NonEmptyKeyValuePairs::Def(vec![(gov_action_id, procedure)]);
        let vps = NonEmptyKeyValuePairs::Def(vec![(voter, inner)]);
        let body = TransactionBody {
            inputs: Set::from(vec![empty_input()]),
            outputs: vec![coin_output(PAYMENT_ADDR, 33_909_103)],
            fee: 200_000,
            ttl: Some(2_000_000),
            certificates: None,
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
            voting_procedures: Some(vps),
            proposal_procedures: None,
            treasury_value: None,
            donation: None,
        };
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        let req = make_vote_request(VoteChoice::Yes, None);
        let err = validate_vote_body(&buf, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("voter pool hash")));
    }

    #[test]
    fn vote_rejects_action_id_mismatch() {
        let body = make_vote_body(Vote::Yes, Nullable::Null);
        let mut req = make_vote_request(VoteChoice::Yes, None);
        req.action_index = 7;
        let err = validate_vote_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("gov action index")));
    }

    #[test]
    fn vote_anchor_happy_path() {
        let anchor_hash = [0x5Au8; 32];
        let body = make_vote_body(
            Vote::No,
            Nullable::Some(Anchor {
                url: "ipfs://rationale".into(),
                content_hash: Hash::from(anchor_hash),
            }),
        );
        let req = make_vote_request(
            VoteChoice::No,
            Some(VoteAnchor {
                url: "ipfs://rationale".into(),
                hash_hex: hex::encode(anchor_hash),
            }),
        );
        validate_vote_body(&body, &req).expect("body matches request");
    }

    #[test]
    fn vote_rejects_anchor_present_when_request_has_none() {
        let body = make_vote_body(
            Vote::Yes,
            Nullable::Some(Anchor {
                url: "ipfs://sneaky".into(),
                content_hash: Hash::from([0x11u8; 32]),
            }),
        );
        let req = make_vote_request(VoteChoice::Yes, None);
        let err = validate_vote_body(&body, &req).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch("anchor")));
    }
}
