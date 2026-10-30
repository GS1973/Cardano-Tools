//! Pre-sign body validators for the wallet operations.
//!
//! Before the air-gapped signer hashes a Conway `TransactionBody` and signs
//! it, it re-decodes the body and binds every critical field to the
//! matching request; any mismatch aborts before a key is used. This is the
//! defense-in-depth layer, and it carries the **change-guard**: change must
//! return to the wallet's own payment address (the request's
//! `payment_address`, which the signer separately confirms is its own).
//!
//! Role-neutral checks (forbidden-field guard, input binding, address
//! decode, stake-credential decode) come from `airgap_core::validate`,
//! shared with SPO/DRep Tools; the multi-asset value reading and the
//! payment/delegation/withdrawal shapes are checked here.

use std::collections::BTreeMap;

use pallas_codec::utils::NonEmptyKeyValuePairs;
use pallas_primitives::conway::{
    Certificate, DRep, PseudoTransactionOutput, TransactionBody, TransactionOutput, Value,
};
use pallas_primitives::{Hash, StakeCredential};

use crate::asset::Asset;
use crate::delegate::{DrepDelegateRequest, DrepTarget, PoolDelegateRequest};
use crate::payment::PaymentRequest;
use crate::tx::build_cip20_aux_data_cbor;
use crate::validate::{
    addr_bytes, assert_fee_within_ceiling, assert_inputs_bind_to_request,
    assert_no_extra_fields_inner, decode_body, stake_credential_from_bech32, ValidationError,
};
use crate::withdraw::WithdrawRewardsRequest;

/// Bind the request's optional CIP-20 message to the body's
/// `auxiliary_data_hash`: recompute the metadata CBOR and its blake2b-256
/// and require the body to commit exactly that hash. No message means the
/// body must carry no auxiliary_data_hash (the field guard enforces that).
fn validate_aux_data_binding(
    body: &TransactionBody,
    metadata_msg: &Option<Vec<String>>,
) -> Result<(), ValidationError> {
    match metadata_msg {
        None => Ok(()),
        Some(lines) => {
            let aux_cbor = build_cip20_aux_data_cbor(lines)
                .map_err(|_| ValidationError::Mismatch("aux data encode failed"))?;
            let h = pallas_crypto::hash::Hasher::<256>::hash(&aux_cbor);
            match &body.auxiliary_data_hash {
                None => Err(ValidationError::Mismatch(
                    "missing auxiliary_data_hash for metadata",
                )),
                Some(bh) if &bh[..] == h.as_ref() => Ok(()),
                _ => Err(ValidationError::Mismatch("auxiliary_data_hash mismatch")),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output + asset reading
// ---------------------------------------------------------------------------

/// Read an output's address bytes, lovelace, and native assets.
///
/// Outputs carrying a `datum_option` or `script_ref` are refused: no wallet
/// operation produces either, and neither is ever shown to the operator, so
/// they must not ride along on a signed body (mirrors
/// `airgap_core::validate::output_pair`).
fn read_output(out: &TransactionOutput) -> Result<(Vec<u8>, u64, Vec<Asset>), ValidationError> {
    let p = match out {
        PseudoTransactionOutput::PostAlonzo(p) => p,
        _ => return Err(ValidationError::Mismatch("legacy output shape")),
    };
    if p.datum_option.is_some() {
        return Err(ValidationError::Mismatch(
            "unexpected datum_option in output",
        ));
    }
    if p.script_ref.is_some() {
        return Err(ValidationError::Mismatch("unexpected script_ref in output"));
    }
    let addr = p.address[..].to_vec();
    match &p.value {
        Value::Coin(c) => Ok((addr, *c, Vec::new())),
        Value::Multiasset(c, ma) => {
            let mut assets = Vec::new();
            let policies = match ma {
                NonEmptyKeyValuePairs::Def(v) | NonEmptyKeyValuePairs::Indef(v) => v,
            };
            for (policy, inner) in policies {
                let names = match inner {
                    NonEmptyKeyValuePairs::Def(v) | NonEmptyKeyValuePairs::Indef(v) => v,
                };
                for (name, qty) in names {
                    assets.push(Asset {
                        policy_hex: hex::encode(AsRef::<[u8]>::as_ref(policy)),
                        asset_name_hex: hex::encode(&name[..]),
                        quantity: u64::from(qty),
                    });
                }
            }
            Ok((addr, *c, assets))
        }
    }
}

fn aggregate(assets: &[Asset]) -> BTreeMap<(String, String), u128> {
    let mut m: BTreeMap<(String, String), u128> = BTreeMap::new();
    for a in assets {
        *m.entry((a.policy_hex.clone(), a.asset_name_hex.clone()))
            .or_insert(0) += a.quantity as u128;
    }
    m
}

/// Order-independent native-asset equality.
fn assets_equal(a: &[Asset], b: &[Asset]) -> bool {
    aggregate(a) == aggregate(b)
}

// ---------------------------------------------------------------------------
// Shared field checks
// ---------------------------------------------------------------------------

/// The fee ceiling every signer in the suite applies, defined once in
/// airgap-core so the tools cannot drift apart on it.
pub use crate::validate::MAX_FEE_LOVELACE;

fn check_fee_ttl(
    body: &TransactionBody,
    req_fee: u64,
    req_ttl: u64,
    current_slot: u64,
) -> Result<(), ValidationError> {
    if body.fee != req_fee {
        return Err(ValidationError::Mismatch("fee"));
    }
    assert_fee_within_ceiling(req_fee)?;
    if body.ttl != Some(req_ttl) {
        return Err(ValidationError::Mismatch("ttl"));
    }
    if req_ttl <= current_slot {
        return Err(ValidationError::Mismatch("ttl_in_past"));
    }
    Ok(())
}

/// Exactly one output, to the payment address, with the expected change
/// (lovelace + native assets). This is the change-guard for cert ops. A
/// declared zero change (full sweep: the sub-min-ADA remainder was folded
/// into the fee) means the body must carry no outputs at all: a 0-lovelace
/// change output could never be valid on-chain.
fn single_change_output(
    body: &TransactionBody,
    payment_bech32: &str,
    expected_lovelace: u64,
    expected_assets: &[Asset],
) -> Result<(), ValidationError> {
    if expected_lovelace == 0 && expected_assets.is_empty() {
        if !body.outputs.is_empty() {
            return Err(ValidationError::Mismatch("output count"));
        }
        return Ok(());
    }
    if body.outputs.len() != 1 {
        return Err(ValidationError::Mismatch("output count"));
    }
    let (addr, lovelace, assets) = read_output(&body.outputs[0])?;
    if addr != addr_bytes(payment_bech32)? {
        return Err(ValidationError::Mismatch("change address (change-guard)"));
    }
    if lovelace != expected_lovelace {
        return Err(ValidationError::Mismatch("change amount"));
    }
    if !assets_equal(&assets, expected_assets) {
        return Err(ValidationError::Mismatch("change assets"));
    }
    Ok(())
}

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

fn cred_eq(a: &StakeCredential, b: &StakeCredential) -> bool {
    match (a, b) {
        (StakeCredential::AddrKeyhash(x), StakeCredential::AddrKeyhash(y)) => x == y,
        (StakeCredential::ScriptHash(x), StakeCredential::ScriptHash(y)) => x == y,
        _ => false,
    }
}

fn pool_keyhash(bech32: &str) -> Result<Hash<28>, ValidationError> {
    let (hrp, data) = bech32::decode(bech32)
        .map_err(|e| ValidationError::BadAddress(bech32.to_string(), e.to_string()))?;
    if hrp.as_str() != "pool" {
        return Err(ValidationError::Mismatch("pool hrp"));
    }
    if data.len() != 28 {
        return Err(ValidationError::Mismatch("pool id length"));
    }
    let mut h = [0u8; 28];
    h.copy_from_slice(&data);
    Ok(Hash::from(h))
}

/// Decode a `drep1…` id to (is_script, 28-byte hash), accepting CIP-105 and
/// CIP-129 encodings. Independent of the online tool's decode: the signer
/// must not trust it.
fn decode_drep(bech32: &str) -> Result<(bool, [u8; 28]), ValidationError> {
    let (hrp, data) = bech32::decode(bech32)
        .map_err(|e| ValidationError::BadAddress(bech32.to_string(), e.to_string()))?;
    if hrp.as_str() != "drep" {
        return Err(ValidationError::Mismatch("drep hrp"));
    }
    let (is_script, hash) = match data.len() {
        28 => (false, &data[..]),
        29 => match data[0] {
            0x22 => (false, &data[1..]),
            0x23 => (true, &data[1..]),
            _ => return Err(ValidationError::Mismatch("drep header")),
        },
        _ => return Err(ValidationError::Mismatch("drep id length")),
    };
    let mut h = [0u8; 28];
    h.copy_from_slice(hash);
    Ok((is_script, h))
}

fn drep_matches(target: &DrepTarget, on_chain: &DRep) -> Result<bool, ValidationError> {
    Ok(match (target, on_chain) {
        (DrepTarget::Abstain, DRep::Abstain) => true,
        (DrepTarget::NoConfidence, DRep::NoConfidence) => true,
        (DrepTarget::Drep(id), DRep::Key(h)) => {
            let (is_script, kh) = decode_drep(id)?;
            !is_script && *h == Hash::from(kh)
        }
        (DrepTarget::Drep(id), DRep::Script(h)) => {
            let (is_script, kh) = decode_drep(id)?;
            is_script && *h == Hash::from(kh)
        }
        _ => false,
    })
}

// ---------------------------------------------------------------------------
// Payment
// ---------------------------------------------------------------------------

/// The reason a payment to a script address is refused, shown by the online
/// tool and the signer alike.
pub const SCRIPT_DESTINATION_REFUSED: &str =
    "this is a script address. This wallet cannot attach a datum, so funds sent here may be locked for good.";

/// True when the payment part of a Shelley address is a script hash: header
/// types 1, 3, 5 and 7 (addr1z, addr1x, the script pointer form and addr1w).
/// This wallet attaches no datum, so it never pays to such an address. A key
/// payment part with a script stake part (addr1y) is an ordinary payment.
pub fn payment_part_is_script(bech32: &str) -> Result<bool, ValidationError> {
    let bytes = addr_bytes(bech32)?;
    let kind = bytes.first().map_or(0, |header| header >> 4);
    Ok(kind <= 7 && kind % 2 == 1)
}

/// Verify a payment body matches its request: two outputs (destination +
/// change to the payment address), or a single destination output when the
/// request declares zero change (an exact-match / full-sweep send whose
/// sub-min-ADA remainder was folded into the fee), the right amount and
/// assets to the destination, the right change back, the right fee/TTL, the
/// declared inputs, and no certificates/withdrawals or other dangerous
/// fields.
pub fn validate_payment_body(
    body_bytes: &[u8],
    req: &PaymentRequest,
    current_slot: u64,
) -> Result<(), ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields_inner(&body, false, req.metadata_msg.is_some())?;
    validate_aux_data_binding(&body, &req.metadata_msg)?;
    if body.certificates.is_some() {
        return Err(ValidationError::Mismatch("unexpected certificates"));
    }
    if body.withdrawals.is_some() {
        return Err(ValidationError::Mismatch("unexpected withdrawals"));
    }
    assert_inputs_bind_to_request(&body.inputs, &req.inputs, &req.payment_address_bech32)?;
    check_fee_ttl(&body, req.fee_lovelace, req.ttl_slot, current_slot)?;

    let dest_b = addr_bytes(&req.destination_address_bech32)?;
    if payment_part_is_script(&req.destination_address_bech32)? {
        return Err(ValidationError::Mismatch(SCRIPT_DESTINATION_REFUSED));
    }
    // Zero declared change (and no change assets) is the exact-match /
    // full-sweep shape: the remainder rode into the fee and the body carries
    // only the destination output. A 0-lovelace change output could never be
    // valid on-chain, so the two shapes cannot be confused.
    if req.change_lovelace == 0 && req.change_assets.is_empty() {
        if body.outputs.len() != 1 {
            return Err(ValidationError::Mismatch("output count"));
        }
        let (addr, lovelace, assets) = read_output(&body.outputs[0])?;
        if addr != dest_b {
            return Err(ValidationError::Mismatch("output addresses"));
        }
        if lovelace != req.amount_lovelace {
            return Err(ValidationError::Mismatch("amount"));
        }
        if !assets_equal(&assets, &req.assets_sent) {
            return Err(ValidationError::Mismatch("assets_sent"));
        }
        return Ok(());
    }

    if body.outputs.len() != 2 {
        return Err(ValidationError::Mismatch("output count"));
    }
    let payment_b = addr_bytes(&req.payment_address_bech32)?;
    let o0 = read_output(&body.outputs[0])?;
    let o1 = read_output(&body.outputs[1])?;
    let (dest, change) = if o0.0 == dest_b && o1.0 == payment_b {
        (o0, o1)
    } else if o1.0 == dest_b && o0.0 == payment_b {
        (o1, o0)
    } else {
        return Err(ValidationError::Mismatch("output addresses"));
    };

    if dest.1 != req.amount_lovelace {
        return Err(ValidationError::Mismatch("amount"));
    }
    if !assets_equal(&dest.2, &req.assets_sent) {
        return Err(ValidationError::Mismatch("assets_sent"));
    }
    if change.1 != req.change_lovelace {
        return Err(ValidationError::Mismatch("change amount"));
    }
    if !assets_equal(&change.2, &req.change_assets) {
        return Err(ValidationError::Mismatch("change assets"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

// Binds many body fields to the request in one place; the parameter count is inherent.
#[allow(clippy::too_many_arguments)]
fn cert_op_preamble(
    body_bytes: &[u8],
    payment_bech32: &str,
    inputs: &[crate::utxo::UtxoInput],
    fee: u64,
    ttl: u64,
    change_lovelace: u64,
    change_assets: &[Asset],
    current_slot: u64,
) -> Result<TransactionBody, ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields_inner(&body, false, false)?;
    if body.withdrawals.is_some() {
        return Err(ValidationError::Mismatch("unexpected withdrawals"));
    }
    assert_inputs_bind_to_request(&body.inputs, inputs, payment_bech32)?;
    check_fee_ttl(&body, fee, ttl, current_slot)?;
    single_change_output(&body, payment_bech32, change_lovelace, change_assets)?;
    Ok(body)
}

/// Verify a pool-delegation body: one `StakeDelegation` (or, when
/// registering, `StakeRegDeleg` with the deposit) whose credential is the
/// request's stake key and whose pool key-hash is the request's pool; one
/// change output to the payment address.
pub fn validate_pool_delegation_body(
    body_bytes: &[u8],
    req: &PoolDelegateRequest,
    current_slot: u64,
) -> Result<(), ValidationError> {
    let body = cert_op_preamble(
        body_bytes,
        &req.payment_address_bech32,
        &req.inputs,
        req.fee_lovelace,
        req.ttl_slot,
        req.change_lovelace,
        &req.change_assets,
        current_slot,
    )?;
    let cred = stake_credential_from_bech32(&req.stake_address_bech32)?;
    let pool = pool_keyhash(&req.pool_id_bech32)?;
    match single_cert(&body)? {
        Certificate::StakeDelegation(c, p) if !req.register_stake => {
            if !cred_eq(c, &cred) {
                return Err(ValidationError::Mismatch("stake credential"));
            }
            if *p != pool {
                return Err(ValidationError::Mismatch("pool key-hash"));
            }
        }
        Certificate::StakeRegDeleg(c, p, dep) if req.register_stake => {
            if !cred_eq(c, &cred) {
                return Err(ValidationError::Mismatch("stake credential"));
            }
            if *p != pool {
                return Err(ValidationError::Mismatch("pool key-hash"));
            }
            if *dep != req.deposit_lovelace {
                return Err(ValidationError::Mismatch("deposit"));
            }
        }
        _ => return Err(ValidationError::Mismatch("certificate shape")),
    }
    Ok(())
}

/// Verify a DRep-delegation body: one `VoteDeleg` (or `VoteRegDeleg` with
/// the deposit when registering) whose credential is the request's stake
/// key and whose DRep matches the request's target; one change output to
/// the payment address.
pub fn validate_drep_delegation_body(
    body_bytes: &[u8],
    req: &DrepDelegateRequest,
    current_slot: u64,
) -> Result<(), ValidationError> {
    let body = cert_op_preamble(
        body_bytes,
        &req.payment_address_bech32,
        &req.inputs,
        req.fee_lovelace,
        req.ttl_slot,
        req.change_lovelace,
        &req.change_assets,
        current_slot,
    )?;
    let cred = stake_credential_from_bech32(&req.stake_address_bech32)?;
    match single_cert(&body)? {
        Certificate::VoteDeleg(c, drep) if !req.register_stake => {
            if !cred_eq(c, &cred) {
                return Err(ValidationError::Mismatch("stake credential"));
            }
            if !drep_matches(&req.target, drep)? {
                return Err(ValidationError::Mismatch("drep target"));
            }
        }
        Certificate::VoteRegDeleg(c, drep, dep) if req.register_stake => {
            if !cred_eq(c, &cred) {
                return Err(ValidationError::Mismatch("stake credential"));
            }
            if !drep_matches(&req.target, drep)? {
                return Err(ValidationError::Mismatch("drep target"));
            }
            if *dep != req.deposit_lovelace {
                return Err(ValidationError::Mismatch("deposit"));
            }
        }
        _ => return Err(ValidationError::Mismatch("certificate shape")),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reward withdrawal
// ---------------------------------------------------------------------------

/// Raw reward-account bytes (header + 28-byte key-hash) of a mainnet,
/// key-controlled `stake1…` address: the key of the body's withdrawals map.
/// A script reward account is refused: the signer authorises a withdrawal
/// with a stake key, never a script.
fn reward_account_bytes(stake_bech32: &str) -> Result<Vec<u8>, ValidationError> {
    use pallas_addresses::{Address, Network, StakePayload};
    let parsed = Address::from_bech32(stake_bech32)
        .map_err(|e| ValidationError::BadAddress(stake_bech32.to_string(), e.to_string()))?;
    let stake = match &parsed {
        Address::Stake(s) => s,
        _ => {
            return Err(ValidationError::Mismatch(
                "reward account is not a stake address",
            ))
        }
    };
    if !matches!(parsed.network(), Some(Network::Mainnet)) {
        return Err(ValidationError::Mismatch(
            "reward account is not a mainnet address",
        ));
    }
    if !matches!(stake.payload(), StakePayload::Stake(_)) {
        return Err(ValidationError::Mismatch(
            "reward account is script-controlled",
        ));
    }
    Ok(parsed.to_vec())
}

/// Verify a reward-withdrawal body: exactly one withdrawal, from the
/// request's reward account, of the request's (non-zero) amount; no
/// certificates; exactly one output, to the payment address, carrying the
/// declared change. The declared figures must also balance (funding inputs
/// plus rewards equals change plus fee), so the amounts the operator reads
/// account for every lovelace: the rewards can only land in the change
/// output.
pub fn validate_withdraw_rewards_body(
    body_bytes: &[u8],
    req: &WithdrawRewardsRequest,
    current_slot: u64,
) -> Result<(), ValidationError> {
    let body = decode_body(body_bytes)?;
    assert_no_extra_fields_inner(&body, false, false)?;
    if body.certificates.is_some() {
        return Err(ValidationError::Mismatch("unexpected certificates"));
    }
    assert_inputs_bind_to_request(&body.inputs, &req.inputs, &req.payment_address_bech32)?;
    check_fee_ttl(&body, req.fee_lovelace, req.ttl_slot, current_slot)?;

    if req.rewards_lovelace == 0 {
        return Err(ValidationError::Mismatch("withdrawal amount is zero"));
    }
    let withdrawals = body
        .withdrawals
        .as_ref()
        .ok_or(ValidationError::Mismatch("missing withdrawals"))?;
    if withdrawals.len() != 1 {
        return Err(ValidationError::Mismatch("withdrawal entry count"));
    }
    let (account, amount) = &withdrawals[0];
    if account[..] != reward_account_bytes(&req.stake_address_bech32)?[..] {
        return Err(ValidationError::Mismatch("withdrawal reward account"));
    }
    if *amount != req.rewards_lovelace {
        return Err(ValidationError::Mismatch("withdrawal amount"));
    }

    // The rewards have nowhere to go but the change output, so a body
    // without one is never a valid withdrawal.
    if body.outputs.len() != 1 {
        return Err(ValidationError::Mismatch("output count"));
    }
    let (addr, lovelace, assets) = read_output(&body.outputs[0])?;
    if addr != addr_bytes(&req.payment_address_bech32)? {
        return Err(ValidationError::Mismatch("change address (change-guard)"));
    }
    if lovelace != req.change_lovelace {
        return Err(ValidationError::Mismatch("change amount"));
    }
    if !assets_equal(&assets, &req.change_assets) {
        return Err(ValidationError::Mismatch("change assets"));
    }

    let funded: u128 = req.inputs.iter().map(|i| i.amount_lovelace as u128).sum();
    if funded + req.rewards_lovelace as u128
        != req.change_lovelace as u128 + req.fee_lovelace as u128
    {
        return Err(ValidationError::Mismatch(
            "inputs + rewards do not equal change + fee",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn script_payment_parts_are_recognised_by_header_type() {
        let addr = |header: u8, len: usize| {
            let mut bytes = vec![header];
            bytes.extend(std::iter::repeat_n(0x55, len));
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("addr").unwrap(), &bytes).unwrap()
        };
        // Script payment part: addr1z, addr1x, script pointer, addr1w.
        for header in [0x11, 0x31, 0x51, 0x71] {
            let len = if header == 0x51 {
                31
            } else if header == 0x71 {
                28
            } else {
                56
            };
            assert!(
                super::payment_part_is_script(&addr(header, len)).unwrap(),
                "{header:#x}"
            );
        }
        // Key payment part: addr1q, addr1y (script stake part), pointer, addr1v.
        for header in [0x01, 0x21, 0x41, 0x61] {
            let len = if header == 0x41 {
                31
            } else if header == 0x61 {
                28
            } else {
                56
            };
            assert!(
                !super::payment_part_is_script(&addr(header, len)).unwrap(),
                "{header:#x}"
            );
        }
    }

    use super::*;

    #[test]
    fn assets_equal_is_order_independent() {
        let a = vec![
            Asset {
                policy_hex: "aa".into(),
                asset_name_hex: "01".into(),
                quantity: 3,
            },
            Asset {
                policy_hex: "bb".into(),
                asset_name_hex: "".into(),
                quantity: 9,
            },
        ];
        let b = vec![
            Asset {
                policy_hex: "bb".into(),
                asset_name_hex: "".into(),
                quantity: 9,
            },
            Asset {
                policy_hex: "aa".into(),
                asset_name_hex: "01".into(),
                quantity: 3,
            },
        ];
        assert!(assets_equal(&a, &b));
        assert!(!assets_equal(&a, &b[..1]));
    }

    #[test]
    fn read_output_rejects_datum_option() {
        use pallas_codec::utils::Bytes;
        use pallas_primitives::babbage::PseudoDatumOption;
        let out: TransactionOutput = PseudoTransactionOutput::PostAlonzo(
            pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(vec![0u8; 29]),
                value: Value::Coin(1_000_000),
                datum_option: Some(PseudoDatumOption::Hash(Hash::from([0u8; 32]))),
                script_ref: None,
            },
        );
        let err = read_output(&out).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("unexpected datum_option in output")
        ));
    }

    #[test]
    fn read_output_rejects_script_ref() {
        use pallas_codec::utils::{Bytes, CborWrap};
        use pallas_primitives::alonzo::NativeScript;
        use pallas_primitives::conway::PseudoScript;
        let out: TransactionOutput = PseudoTransactionOutput::PostAlonzo(
            pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(vec![0u8; 29]),
                value: Value::Coin(1_000_000),
                datum_option: None,
                script_ref: Some(CborWrap(PseudoScript::NativeScript(
                    NativeScript::InvalidBefore(0),
                ))),
            },
        );
        let err = read_output(&out).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("unexpected script_ref in output")
        ));
    }
}
