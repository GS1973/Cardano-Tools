//! Pallas-based Conway transaction building for the wallet.
//!
//! The role-neutral pieces (address decode, coin-only output, input parse,
//! signed-tx assembly) come from `airgap_core::tx` (via `shared::tx`).
//! This module adds what a wallet needs on top: multi-asset output values,
//! native-asset change arithmetic, min-ADA and fee computed from the live
//! protocol parameters, coin-selection, and the body builders. Bodies are
//! unsigned; the signer returns witnesses and `shared::tx::assemble_signed_tx`
//! re-assembles the signed tx for submission.

use pallas_addresses::{Address, StakePayload};
use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptyKeyValuePairs, NonEmptySet, Set};
use pallas_primitives::conway::{
    Certificate, DRep, TransactionBody, TransactionOutput, Withdrawals,
};
use pallas_primitives::{Hash, NetworkId, StakeCredential, TransactionInput};

pub use airgap_core::tx::{change_assets, make_asset_output, min_ada_for_output};
pub use airgap_core::utxo::OwnedUtxo;
use shared::asset::Asset;
use shared::delegate::DrepTarget;
use shared::tx::{build_cip20_aux_data_cbor, decode_address, parse_input, TxBuildError, TxInput};

#[derive(Debug, thiserror::Error)]
pub enum WalletTxError {
    #[error(transparent)]
    Tx(#[from] shared::tx::TxBuildError),
    #[error("output holds {got} lovelace but min-ADA is {need}")]
    OutputBelowMinAda { need: u64, got: u64 },
    #[error("insufficient lovelace: need {need}, have {have}")]
    InsufficientLovelace { need: u64, have: u64 },
    #[error("{0} has an unexpected byte length")]
    BadLength(&'static str),
    #[error("unsupported DRep id header byte 0x{0:02x}")]
    DrepHeader(u8),
    #[error("fee does not fit in a u64 (fee coefficients {min_fee_a}, {min_fee_b})")]
    FeeOverflow { min_fee_a: u64, min_fee_b: u64 },
}

// ---------------------------------------------------------------------------
// Fee, from live protocol parameters
// ---------------------------------------------------------------------------

/// Conservative per-witness wire size: array tag + (len+vkey 32) + (len+sig 64).
const WITNESS_BYTES: u64 = 100;
/// Witness-set map + outer 4-element tx array + a small safety margin.
const TX_WRAP_OVERHEAD: u64 = 32;

/// Estimated wire size of the fully signed transaction (body + witnesses +
/// wrapper). Drives both the fee and the max-size guard. `n_witnesses` is 1
/// for a payment, 2 for a delegation or a reward withdrawal (payment + stake).
pub fn estimate_signed_size(body_cbor_len: usize, n_witnesses: u64) -> u64 {
    body_cbor_len as u64 + n_witnesses * WITNESS_BYTES + TX_WRAP_OVERHEAD
}

/// Linear Cardano fee: `min_fee_a × size + min_fee_b`. The coefficients come
/// from the chain-data provider, so the arithmetic is checked: a product or
/// sum that does not fit is a build error, never a panic or a wrapped fee.
pub fn estimate_fee(
    body_cbor_len: usize,
    n_witnesses: u64,
    min_fee_a: u64,
    min_fee_b: u64,
) -> Result<u64, WalletTxError> {
    min_fee_a
        .checked_mul(estimate_signed_size(body_cbor_len, n_witnesses))
        .and_then(|v| v.checked_add(min_fee_b))
        .ok_or(WalletTxError::FeeOverflow {
            min_fee_a,
            min_fee_b,
        })
}

// ---------------------------------------------------------------------------
// Body encoding
// ---------------------------------------------------------------------------

fn encode_body(
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee_lovelace: u64,
    ttl_slot: u64,
    certificates: Option<NonEmptySet<Certificate>>,
    auxiliary_data_hash: Option<Bytes>,
    withdrawals: Option<Withdrawals>,
) -> Result<Vec<u8>, WalletTxError> {
    let body = TransactionBody {
        inputs: Set::from(inputs),
        outputs,
        fee: fee_lovelace,
        ttl: Some(ttl_slot),
        certificates,
        withdrawals,
        auxiliary_data_hash,
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
    minicbor::encode(&body, &mut buf)
        .map_err(|e| WalletTxError::Tx(shared::tx::TxBuildError::Cbor(e.to_string())))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Payment (send) body
// ---------------------------------------------------------------------------

/// A built (unsigned) body plus what the request needs to carry, shared by
/// the payment and delegation builders.
pub struct BuiltBody {
    pub body_cbor: Vec<u8>,
    pub inputs: Vec<TxInput>,
    pub fee_lovelace: u64,
    pub change_lovelace: u64,
    pub change_assets: Vec<Asset>,
    /// CIP-20 auxiliary-data CBOR, when a metadata message was attached. The
    /// body already commits its hash; the submit step splices these bytes in.
    pub aux_data_cbor: Option<Vec<u8>>,
}

fn to_txinputs(utxos: &[OwnedUtxo]) -> Vec<TxInput> {
    utxos
        .iter()
        .map(|u| TxInput {
            tx_hash_hex: u.tx_hash_hex.clone(),
            tx_index: u.tx_index,
        })
        .collect()
}

fn parse_all(utxos: &[OwnedUtxo]) -> Result<Vec<TransactionInput>, WalletTxError> {
    utxos
        .iter()
        .map(|u| {
            parse_input(&TxInput {
                tx_hash_hex: u.tx_hash_hex.clone(),
                tx_index: u.tx_index,
            })
        })
        .collect::<Result<_, _>>()
        .map_err(WalletTxError::Tx)
}

/// Build the unsigned body for a send of `out_lovelace` (+ optional native
/// `out_assets`) to `destination`, funding it from `available` UTxOs at the
/// wallet's `payment` address. Inputs that hold a required asset are taken
/// first (largest holding first, stopping once the sent quantities are
/// covered), then ADA-bearing UTxOs are added largest-first until lovelace
/// covers amount + fee + the min-ADA change. When every UTxO is in, only the
/// min-ADA change is short, and no asset change is needed, the remainder is
/// folded into the fee and the body carries no change output (exact-match /
/// full-sweep sends). The fee is taken from the actual encoded body size;
/// native assets not being sent are preserved as change back to the payment
/// address.
#[allow(clippy::too_many_arguments)]
pub fn build_payment_body(
    payment_address_bech32: &str,
    destination_address_bech32: &str,
    out_lovelace: u64,
    out_assets: &[Asset],
    available: &[OwnedUtxo],
    ttl_slot: u64,
    min_fee_a: u64,
    min_fee_b: u64,
    utxo_cost_per_byte: u64,
    metadata_msg: Option<&[String]>,
) -> Result<BuiltBody, WalletTxError> {
    let payment_bytes = decode_address(payment_address_bech32, "addr")?;
    let dest_bytes = decode_address(destination_address_bech32, "addr")?;

    // CIP-20 metadata: encode once, commit its blake2b-256 in the body, and
    // count its wire bytes (the aux data rides as the tx's 4th element) so
    // the fee covers them.
    let (aux_cbor, aux_hash): (Option<Vec<u8>>, Option<Bytes>) = match metadata_msg {
        None => (None, None),
        Some(lines) => {
            let c = build_cip20_aux_data_cbor(lines)?;
            let h = pallas_crypto::hash::Hasher::<256>::hash(&c);
            (Some(c), Some(Bytes::from(h.as_ref().to_vec())))
        }
    };
    let aux_len = aux_cbor.as_ref().map(|c| c.len()).unwrap_or(0);

    let dest_output = make_asset_output(dest_bytes, out_lovelace, out_assets)?;
    let dest_min = min_ada_for_output(&dest_output, utxo_cost_per_byte)?;
    if out_lovelace < dest_min {
        return Err(WalletTxError::OutputBelowMinAda {
            need: dest_min,
            got: out_lovelace,
        });
    }

    // Pass 1: cover the sent assets. Candidates are taken largest required
    // holding first, and selection stops once every sent quantity is met:
    // pulling in every holder of a sent asset would grow the fee with each
    // extra input and, for a token spread over many UTxOs, push the body
    // past maxTxSize however small the send.
    let mut need: std::collections::BTreeMap<(String, String), u64> =
        std::collections::BTreeMap::new();
    for a in out_assets {
        let q = need
            .entry((a.policy_hex.clone(), a.asset_name_hex.clone()))
            .or_insert(0);
        *q = q.saturating_add(a.quantity);
    }
    let required_qty = |u: &OwnedUtxo| -> u128 {
        u.assets
            .iter()
            .filter(|a| need.contains_key(&(a.policy_hex.clone(), a.asset_name_hex.clone())))
            .map(|a| a.quantity as u128)
            .sum()
    };
    let mut candidates: Vec<OwnedUtxo> = available
        .iter()
        .filter(|u| required_qty(u) > 0)
        .cloned()
        .collect();
    let mut rest: Vec<OwnedUtxo> = available
        .iter()
        .filter(|u| required_qty(u) == 0)
        .cloned()
        .collect();
    candidates.sort_by_key(|u| std::cmp::Reverse(required_qty(u)));
    let mut selected: Vec<OwnedUtxo> = Vec::new();
    for u in candidates {
        let contributes = u.assets.iter().any(|a| {
            need.get(&(a.policy_hex.clone(), a.asset_name_hex.clone()))
                .is_some_and(|q| *q > 0)
        });
        if !contributes {
            // Every quantity it holds is already covered: keep it available
            // to pass 2 as a plain ADA source.
            rest.push(u);
            continue;
        }
        for a in &u.assets {
            if let Some(q) = need.get_mut(&(a.policy_hex.clone(), a.asset_name_hex.clone())) {
                *q = q.saturating_sub(a.quantity);
            }
        }
        selected.push(u);
    }
    rest.sort_by_key(|u| std::cmp::Reverse(u.lovelace));
    if selected.is_empty() && !rest.is_empty() {
        selected.push(rest.remove(0));
    }

    // Pass 2: add ADA-bearing UTxOs until lovelace covers out + fee + min-change.
    let mut ri = 0usize;
    loop {
        let sel_lovelace: u64 = selected
            .iter()
            .fold(0u64, |acc, u| acc.saturating_add(u.lovelace));
        let sel_assets: Vec<Asset> = selected.iter().flat_map(|u| u.assets.clone()).collect();
        // Required assets are all in `selected` (pass 1); this only errors if
        // the wallet genuinely lacks the asset being sent.
        let change_asset_vec = change_assets(&sel_assets, out_assets)?;

        let inputs = parse_all(&selected)?;
        // Size the body (and thus the fee) with a representative change output.
        let change_tmp = make_asset_output(payment_bytes.clone(), sel_lovelace, &change_asset_vec)?;
        let min_change = min_ada_for_output(&change_tmp, utxo_cost_per_byte)?;
        let body_tmp = encode_body(
            inputs.clone(),
            vec![dest_output.clone(), change_tmp],
            0,
            ttl_slot,
            None,
            aux_hash.clone(),
            None,
        )?;
        let fee = estimate_fee(body_tmp.len() + aux_len, 1, min_fee_a, min_fee_b)?;

        // `out_lovelace` comes straight from the request JSON, so the cover
        // check is overflow-checked: a near-u64::MAX amount must fail as
        // insufficient funds, not wrap and false-pass.
        let need_lovelace = out_lovelace
            .checked_add(fee)
            .and_then(|v| v.checked_add(min_change));
        if need_lovelace.is_some_and(|need| sel_lovelace >= need) {
            // The cover check guarantees sel >= out + fee without overflow,
            // so this cannot underflow.
            let change_lovelace = sel_lovelace - out_lovelace - fee;
            let change_out =
                make_asset_output(payment_bytes.clone(), change_lovelace, &change_asset_vec)?;
            let body = encode_body(
                inputs,
                vec![dest_output, change_out],
                fee,
                ttl_slot,
                None,
                aux_hash.clone(),
                None,
            )?;
            return Ok(BuiltBody {
                body_cbor: body,
                inputs: to_txinputs(&selected),
                fee_lovelace: fee,
                change_lovelace,
                change_assets: change_asset_vec,
                aux_data_cbor: aux_cbor,
            });
        }
        if ri < rest.len() {
            selected.push(rest[ri].clone());
            ri += 1;
        } else {
            // Every UTxO is in and only the min-ADA change is short. When no
            // native assets need a change output to ride back, fold the
            // sub-min-ADA remainder into the fee and build a change-less
            // body: the exact-match / full-sweep case. The folded fee is
            // what the request carries, so the operator reviews the true cost.
            if change_asset_vec.is_empty() {
                let body_nc = encode_body(
                    inputs.clone(),
                    vec![dest_output.clone()],
                    0,
                    ttl_slot,
                    None,
                    aux_hash.clone(),
                    None,
                )?;
                let fee_nc = estimate_fee(body_nc.len() + aux_len, 1, min_fee_a, min_fee_b)?;
                if out_lovelace
                    .checked_add(fee_nc)
                    .is_some_and(|need| sel_lovelace >= need)
                {
                    let fee_all = sel_lovelace - out_lovelace;
                    let body = encode_body(
                        inputs,
                        vec![dest_output],
                        fee_all,
                        ttl_slot,
                        None,
                        aux_hash.clone(),
                        None,
                    )?;
                    return Ok(BuiltBody {
                        body_cbor: body,
                        inputs: to_txinputs(&selected),
                        fee_lovelace: fee_all,
                        change_lovelace: 0,
                        change_assets: Vec::new(),
                        aux_data_cbor: aux_cbor,
                    });
                }
            }
            return Err(WalletTxError::InsufficientLovelace {
                need: need_lovelace.unwrap_or(u64::MAX),
                have: sel_lovelace,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Delegation (pool + DRep) bodies
// ---------------------------------------------------------------------------

/// Stake credential (key or script) from a `stake1…` reward address.
fn stake_credential(stake_address_bech32: &str) -> Result<StakeCredential, WalletTxError> {
    let parsed = Address::from_bech32(stake_address_bech32)
        .map_err(|e| TxBuildError::Bech32(stake_address_bech32.to_string(), e.to_string()))?;
    let stake = match parsed {
        Address::Stake(s) => s,
        _ => return Err(TxBuildError::WrongHrp("stake", "addr".into()).into()),
    };
    Ok(match stake.payload() {
        StakePayload::Stake(h) => StakeCredential::AddrKeyhash(*h),
        StakePayload::Script(h) => StakeCredential::ScriptHash(*h),
    })
}

/// 28-byte pool key-hash from a `pool1…` bech32 id.
fn pool_keyhash(pool_id_bech32: &str) -> Result<Hash<28>, WalletTxError> {
    let (hrp, data) = bech32::decode(pool_id_bech32)
        .map_err(|e| TxBuildError::Bech32(pool_id_bech32.to_string(), e.to_string()))?;
    if hrp.as_str() != "pool" {
        return Err(TxBuildError::WrongHrp("pool", hrp.as_str().to_string()).into());
    }
    if data.len() != 28 {
        return Err(WalletTxError::BadLength("pool id"));
    }
    let mut h = [0u8; 28];
    h.copy_from_slice(&data);
    Ok(Hash::from(h))
}

/// Map a delegation target to the on-chain `DRep`. A specific DRep id
/// accepts both CIP-105 (bare 28-byte hash) and CIP-129 (header byte +
/// hash) encodings, key or script.
fn drep_from_target(target: &DrepTarget) -> Result<DRep, WalletTxError> {
    let id = match target {
        DrepTarget::Abstain => return Ok(DRep::Abstain),
        DrepTarget::NoConfidence => return Ok(DRep::NoConfidence),
        DrepTarget::Drep(id) => id,
    };
    let (hrp, data) =
        bech32::decode(id).map_err(|e| TxBuildError::Bech32(id.to_string(), e.to_string()))?;
    if hrp.as_str() != "drep" {
        return Err(TxBuildError::WrongHrp("drep", hrp.as_str().to_string()).into());
    }
    let (is_script, hash) = match data.len() {
        28 => (false, &data[..]),
        29 => match data[0] {
            0x22 => (false, &data[1..]),
            0x23 => (true, &data[1..]),
            other => return Err(WalletTxError::DrepHeader(other)),
        },
        _ => return Err(WalletTxError::BadLength("drep id")),
    };
    let mut h = [0u8; 28];
    h.copy_from_slice(hash);
    Ok(if is_script {
        DRep::Script(Hash::from(h))
    } else {
        DRep::Key(Hash::from(h))
    })
}

fn one_cert(cert: Certificate) -> Result<NonEmptySet<Certificate>, WalletTxError> {
    NonEmptySet::try_from(vec![cert])
        .map_err(|_| TxBuildError::Cbor("could not build NonEmptySet for certs".into()).into())
}

/// Build the unsigned body for a single-certificate transaction (pool or
/// DRep delegation, optionally folding in stake registration). Funds the
/// fee + `deposit_lovelace` from `available` UTxOs, returns the remainder
/// as change to the payment address (preserving any native assets pulled
/// in); a sub-min-ADA remainder with no assets to return is folded into
/// the fee instead (the body then has no outputs). Two witnesses are
/// expected at signing: payment + stake.
#[allow(clippy::too_many_arguments)]
fn build_cert_body(
    payment_address_bech32: &str,
    cert: Certificate,
    deposit_lovelace: u64,
    available: &[OwnedUtxo],
    ttl_slot: u64,
    min_fee_a: u64,
    min_fee_b: u64,
    utxo_cost_per_byte: u64,
) -> Result<BuiltBody, WalletTxError> {
    let payment_bytes = decode_address(payment_address_bech32, "addr")?;

    let mut rest: Vec<OwnedUtxo> = available.to_vec();
    rest.sort_by_key(|u| std::cmp::Reverse(u.lovelace));
    let mut selected: Vec<OwnedUtxo> = Vec::new();
    if !rest.is_empty() {
        selected.push(rest.remove(0));
    }

    let mut ri = 0usize;
    loop {
        let sel_lovelace: u64 = selected
            .iter()
            .fold(0u64, |acc, u| acc.saturating_add(u.lovelace));
        let sel_assets: Vec<Asset> = selected.iter().flat_map(|u| u.assets.clone()).collect();
        let change_asset_vec = change_assets(&sel_assets, &[])?; // delegation sends no assets

        let inputs = parse_all(&selected)?;
        let change_tmp = make_asset_output(payment_bytes.clone(), sel_lovelace, &change_asset_vec)?;
        let min_change = min_ada_for_output(&change_tmp, utxo_cost_per_byte)?;
        let body_tmp = encode_body(
            inputs.clone(),
            vec![change_tmp],
            0,
            ttl_slot,
            Some(one_cert(cert.clone())?),
            None,
            None,
        )?;
        let fee = estimate_fee(body_tmp.len(), 2, min_fee_a, min_fee_b)?;

        // Checked cover math, mirroring build_payment_body: never trust the
        // upstream-supplied deposit not to make the sums wrap.
        let need_lovelace = deposit_lovelace
            .checked_add(fee)
            .and_then(|v| v.checked_add(min_change));
        if need_lovelace.is_some_and(|need| sel_lovelace >= need) {
            // The cover check guarantees sel >= deposit + fee without
            // overflow, so this cannot underflow.
            let change_lovelace = sel_lovelace - deposit_lovelace - fee;
            let change_out =
                make_asset_output(payment_bytes.clone(), change_lovelace, &change_asset_vec)?;
            let body = encode_body(
                inputs,
                vec![change_out],
                fee,
                ttl_slot,
                Some(one_cert(cert)?),
                None,
                None,
            )?;
            return Ok(BuiltBody {
                body_cbor: body,
                inputs: to_txinputs(&selected),
                fee_lovelace: fee,
                change_lovelace,
                change_assets: change_asset_vec,
                aux_data_cbor: None,
            });
        }
        if ri < rest.len() {
            selected.push(rest[ri].clone());
            ri += 1;
        } else {
            // Every UTxO is in and only the min-ADA change is short. With no
            // native assets to return, fold the sub-min-ADA remainder into
            // the fee and emit a body with no outputs: the wallet is spent
            // down to exactly deposit + fee, which the operator reviews.
            if change_asset_vec.is_empty() {
                let body_nc = encode_body(
                    inputs.clone(),
                    Vec::new(),
                    0,
                    ttl_slot,
                    Some(one_cert(cert.clone())?),
                    None,
                    None,
                )?;
                let fee_nc = estimate_fee(body_nc.len(), 2, min_fee_a, min_fee_b)?;
                if deposit_lovelace
                    .checked_add(fee_nc)
                    .is_some_and(|need| sel_lovelace >= need)
                {
                    let fee_all = sel_lovelace - deposit_lovelace;
                    let body = encode_body(
                        inputs,
                        Vec::new(),
                        fee_all,
                        ttl_slot,
                        Some(one_cert(cert)?),
                        None,
                        None,
                    )?;
                    return Ok(BuiltBody {
                        body_cbor: body,
                        inputs: to_txinputs(&selected),
                        fee_lovelace: fee_all,
                        change_lovelace: 0,
                        change_assets: Vec::new(),
                        aux_data_cbor: None,
                    });
                }
            }
            return Err(WalletTxError::InsufficientLovelace {
                need: need_lovelace.unwrap_or(u64::MAX),
                have: sel_lovelace,
            });
        }
    }
}

/// Delegate the stake key to a pool. When `register_stake`, a registration
/// is folded in (Conway `StakeRegDeleg`, locking `deposit_lovelace`);
/// otherwise a plain `StakeDelegation`.
#[allow(clippy::too_many_arguments)]
pub fn build_pool_delegation_body(
    payment_address_bech32: &str,
    stake_address_bech32: &str,
    pool_id_bech32: &str,
    register_stake: bool,
    deposit_lovelace: u64,
    available: &[OwnedUtxo],
    ttl_slot: u64,
    min_fee_a: u64,
    min_fee_b: u64,
    utxo_cost_per_byte: u64,
) -> Result<BuiltBody, WalletTxError> {
    let cred = stake_credential(stake_address_bech32)?;
    let pool = pool_keyhash(pool_id_bech32)?;
    let (cert, deposit) = if register_stake {
        (
            Certificate::StakeRegDeleg(cred, pool, deposit_lovelace),
            deposit_lovelace,
        )
    } else {
        (Certificate::StakeDelegation(cred, pool), 0)
    };
    build_cert_body(
        payment_address_bech32,
        cert,
        deposit,
        available,
        ttl_slot,
        min_fee_a,
        min_fee_b,
        utxo_cost_per_byte,
    )
}

/// Delegate the stake key's voting power to a DRep (or Abstain /
/// NoConfidence). When `register_stake`, registration is folded in (Conway
/// `VoteRegDeleg`); otherwise a plain `VoteDeleg`.
#[allow(clippy::too_many_arguments)]
pub fn build_drep_delegation_body(
    payment_address_bech32: &str,
    stake_address_bech32: &str,
    target: &DrepTarget,
    register_stake: bool,
    deposit_lovelace: u64,
    available: &[OwnedUtxo],
    ttl_slot: u64,
    min_fee_a: u64,
    min_fee_b: u64,
    utxo_cost_per_byte: u64,
) -> Result<BuiltBody, WalletTxError> {
    let cred = stake_credential(stake_address_bech32)?;
    let drep = drep_from_target(target)?;
    let (cert, deposit) = if register_stake {
        (
            Certificate::VoteRegDeleg(cred, drep, deposit_lovelace),
            deposit_lovelace,
        )
    } else {
        (Certificate::VoteDeleg(cred, drep), 0)
    };
    build_cert_body(
        payment_address_bech32,
        cert,
        deposit,
        available,
        ttl_slot,
        min_fee_a,
        min_fee_b,
        utxo_cost_per_byte,
    )
}

// ---------------------------------------------------------------------------
// Reward withdrawal body
// ---------------------------------------------------------------------------

/// Build the unsigned body that withdraws `rewards_lovelace` from the
/// wallet's reward account into its own payment address. The ledger accepts
/// only a withdrawal of the exact account balance, so the caller passes the
/// balance it read from the chain. The rewards join the funding inputs in a
/// single change output (preserving any native assets pulled in); a
/// transaction needs at least one input, so the largest UTxO is always
/// spent, and more are added only while rewards + inputs fall short of the
/// fee plus a min-ADA change. Unlike the other builders nothing is ever
/// folded into the fee: a withdrawal that cannot leave a valid change output
/// is refused. Two witnesses are expected at signing: payment + stake.
#[allow(clippy::too_many_arguments)]
pub fn build_withdraw_rewards_body(
    payment_address_bech32: &str,
    stake_address_bech32: &str,
    rewards_lovelace: u64,
    available: &[OwnedUtxo],
    ttl_slot: u64,
    min_fee_a: u64,
    min_fee_b: u64,
    utxo_cost_per_byte: u64,
) -> Result<BuiltBody, WalletTxError> {
    let payment_bytes = decode_address(payment_address_bech32, "addr")?;
    let reward_account = decode_address(stake_address_bech32, "stake")?;
    let withdrawals = || -> Result<Withdrawals, WalletTxError> {
        NonEmptyKeyValuePairs::try_from(vec![(
            Bytes::from(reward_account.clone()),
            rewards_lovelace,
        )])
        .map_err(|_| TxBuildError::Cbor("could not build withdrawals map".into()).into())
    };

    let mut rest: Vec<OwnedUtxo> = available.to_vec();
    rest.sort_by_key(|u| std::cmp::Reverse(u.lovelace));
    if rest.is_empty() {
        return Err(WalletTxError::InsufficientLovelace { need: 0, have: 0 });
    }
    let mut selected: Vec<OwnedUtxo> = vec![rest.remove(0)];

    let mut ri = 0usize;
    loop {
        let sel_lovelace: u64 = selected
            .iter()
            .fold(0u64, |acc, u| acc.saturating_add(u.lovelace));
        // Upstream-supplied figures: a sum that does not fit is a build
        // error, never a wrapped total.
        let total = sel_lovelace.checked_add(rewards_lovelace).ok_or(
            WalletTxError::InsufficientLovelace {
                need: u64::MAX,
                have: sel_lovelace,
            },
        )?;
        let sel_assets: Vec<Asset> = selected.iter().flat_map(|u| u.assets.clone()).collect();
        let change_asset_vec = change_assets(&sel_assets, &[])?; // a withdrawal sends no assets

        let inputs = parse_all(&selected)?;
        let change_tmp = make_asset_output(payment_bytes.clone(), total, &change_asset_vec)?;
        let min_change = min_ada_for_output(&change_tmp, utxo_cost_per_byte)?;
        let body_tmp = encode_body(
            inputs.clone(),
            vec![change_tmp],
            0,
            ttl_slot,
            None,
            None,
            Some(withdrawals()?),
        )?;
        let fee = estimate_fee(body_tmp.len(), 2, min_fee_a, min_fee_b)?;

        let need_lovelace = fee.checked_add(min_change);
        if need_lovelace.is_some_and(|need| total >= need) {
            // The cover check guarantees total >= fee, so this cannot underflow.
            let change_lovelace = total - fee;
            let change_out =
                make_asset_output(payment_bytes.clone(), change_lovelace, &change_asset_vec)?;
            let body = encode_body(
                inputs,
                vec![change_out],
                fee,
                ttl_slot,
                None,
                None,
                Some(withdrawals()?),
            )?;
            return Ok(BuiltBody {
                body_cbor: body,
                inputs: to_txinputs(&selected),
                fee_lovelace: fee,
                change_lovelace,
                change_assets: change_asset_vec,
                aux_data_cbor: None,
            });
        }
        if ri < rest.len() {
            selected.push(rest[ri].clone());
            ri += 1;
        } else {
            return Err(WalletTxError::InsufficientLovelace {
                need: need_lovelace.unwrap_or(u64::MAX),
                have: total,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_A: &str = "0691b2fecca1ac4f53cb6dfb00b7013e561d1f34403b957cbb5af1fa";
    const ADDR: [u8; 57] = [0x01; 57];

    fn asset(policy: &str, name: &str, q: u64) -> Asset {
        Asset {
            policy_hex: policy.into(),
            asset_name_hex: name.into(),
            quantity: q,
        }
    }
    fn pay_addr() -> String {
        shared::address::base_address_bech32(&[0x11; 32], &[0x22; 32]).unwrap()
    }
    fn dest_addr() -> String {
        shared::address::base_address_bech32(&[0x33; 32], &[0x44; 32]).unwrap()
    }
    fn utxo(h: &str, ix: u32, lov: u64, assets: Vec<Asset>) -> OwnedUtxo {
        OwnedUtxo {
            tx_hash_hex: h.repeat(64 / h.len()),
            tx_index: ix,
            lovelace: lov,
            assets,
        }
    }

    #[test]
    fn fee_formula_is_linear() {
        assert_eq!(
            estimate_fee(200, 2, 44, 155381).unwrap(),
            44 * (200 + 200 + 32) + 155381
        );
    }

    #[test]
    fn fee_overflow_is_an_error_not_a_panic() {
        assert!(matches!(
            estimate_fee(200, 2, u64::MAX, 155381),
            Err(WalletTxError::FeeOverflow { .. })
        ));
        assert!(matches!(
            estimate_fee(200, 2, 44, u64::MAX),
            Err(WalletTxError::FeeOverflow { .. })
        ));
        // And through a builder: an absurd coefficient fails the build cleanly.
        let utxos = vec![utxo("a", 0, 5_000_000, vec![])];
        let err = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            1_000_000,
            &[],
            &utxos,
            100,
            u64::MAX,
            155381,
            4310,
            None,
        );
        assert!(matches!(err, Err(WalletTxError::FeeOverflow { .. })));
    }

    #[test]
    fn min_ada_is_sane_for_coin_only_output() {
        let out = make_asset_output(ADDR.to_vec(), 1_000_000, &[]).unwrap();
        let min = min_ada_for_output(&out, 4310).unwrap();
        assert!((800_000..=1_200_000).contains(&min), "min was {min}");
    }

    #[test]
    fn ada_only_payment_balances() {
        let utxos = vec![
            utxo("a", 0, 2_000_000, vec![]),
            utxo("b", 1, 3_000_000, vec![]),
        ];
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            1_500_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        let sel: u64 = 2_000_000 + 3_000_000; // both may be used; check conservation over used inputs
        let used: u64 = out
            .inputs
            .iter()
            .map(|i| {
                if i.tx_index == 0 {
                    2_000_000
                } else {
                    3_000_000
                }
            })
            .sum();
        assert_eq!(used, 1_500_000 + out.fee_lovelace + out.change_lovelace);
        assert!(out.change_assets.is_empty());
        assert!(used <= sel);
        // body decodes to two outputs (dest + change).
        let body: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert_eq!(body.outputs.len(), 2);
        assert_eq!(body.fee, out.fee_lovelace);
    }

    #[test]
    fn multiasset_payment_preserves_change_assets() {
        // One UTxO holds the asset + ADA; sending part of the asset.
        let utxos = vec![utxo("c", 0, 5_000_000, vec![asset(POLICY_A, "aa", 10)])];
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            2_000_000,
            &[asset(POLICY_A, "aa", 4)],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        assert_eq!(out.change_assets, vec![asset(POLICY_A, "aa", 6)]);
        assert_eq!(
            5_000_000,
            2_000_000 + out.fee_lovelace + out.change_lovelace
        );
        let body: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert_eq!(body.outputs.len(), 2);
    }

    #[test]
    fn asset_selection_stops_once_quantities_covered() {
        // The sent asset sits in five UTxOs; a small send must not pull in
        // every holder: that inflates the fee per extra input and, at
        // airdrop scale, pushes the body past maxTxSize.
        let names = ["a", "b", "c", "d", "e"];
        let utxos: Vec<OwnedUtxo> = names
            .iter()
            .enumerate()
            .map(|(i, h)| utxo(h, i as u32, 5_000_000, vec![asset(POLICY_A, "aa", 10)]))
            .collect();
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            2_000_000,
            &[asset(POLICY_A, "aa", 4)],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        assert_eq!(out.inputs.len(), 1, "one 10-unit UTxO covers a 4-unit send");
        assert_eq!(out.change_assets, vec![asset(POLICY_A, "aa", 6)]);
    }

    #[test]
    fn asset_selection_spans_utxos_until_covered() {
        let names = ["a", "b", "c"];
        let utxos: Vec<OwnedUtxo> = names
            .iter()
            .enumerate()
            .map(|(i, h)| utxo(h, i as u32, 5_000_000, vec![asset(POLICY_A, "aa", 10)]))
            .collect();
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            2_000_000,
            &[asset(POLICY_A, "aa", 15)],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        assert_eq!(
            out.inputs.len(),
            2,
            "two 10-unit UTxOs cover a 15-unit send"
        );
        assert_eq!(out.change_assets, vec![asset(POLICY_A, "aa", 5)]);
    }

    #[test]
    fn full_sweep_folds_remainder_into_fee() {
        // Sending close to the whole balance leaves less than the min-ADA
        // change: the remainder becomes fee and the body has no change output.
        let utxos = vec![utxo("a", 0, 5_000_000, vec![])];
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            4_500_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        assert_eq!(out.change_lovelace, 0);
        assert!(out.change_assets.is_empty());
        assert_eq!(out.fee_lovelace, 500_000); // amount + fee consume the input exactly
        let body: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert_eq!(body.outputs.len(), 1);
        assert_eq!(body.fee, 500_000);
    }

    #[test]
    fn sweep_short_of_fee_errors() {
        // Amount so close to the balance that even a change-less body cannot
        // pay its fee.
        let utxos = vec![utxo("b", 0, 5_000_000, vec![])];
        let err = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            4_950_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        );
        assert!(matches!(
            err,
            Err(WalletTxError::InsufficientLovelace { .. })
        ));
    }

    #[test]
    fn sweep_with_asset_change_still_requires_min_ada_change() {
        // Native assets not being sent must ride back on a change output, so
        // the remainder cannot be folded into the fee.
        let utxos = vec![utxo("c", 0, 5_000_000, vec![asset(POLICY_A, "aa", 10)])];
        let err = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            4_500_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        );
        assert!(matches!(
            err,
            Err(WalletTxError::InsufficientLovelace { .. })
        ));
    }

    #[test]
    fn huge_amount_is_insufficient_not_wrapping() {
        // amount_lovelace arrives from JSON up to u64::MAX; the cover check
        // must fail cleanly instead of wrapping (release) or panicking (debug).
        let utxos = vec![utxo("d", 0, 5_000_000, vec![])];
        let err = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            u64::MAX,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        );
        assert!(matches!(
            err,
            Err(WalletTxError::InsufficientLovelace { .. })
        ));
    }

    #[test]
    fn insufficient_lovelace_errors() {
        let utxos = vec![utxo("d", 0, 1_000_000, vec![])];
        let err = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            5_000_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        );
        assert!(matches!(
            err,
            Err(WalletTxError::InsufficientLovelace { .. })
        ));
    }

    #[test]
    fn insufficient_asset_errors() {
        let utxos = vec![utxo("e", 0, 5_000_000, vec![asset(POLICY_A, "aa", 3)])];
        let err = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            2_000_000,
            &[asset(POLICY_A, "aa", 5)],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        );
        assert!(matches!(
            err,
            Err(WalletTxError::Tx(
                shared::tx::TxBuildError::InsufficientAsset { .. }
            ))
        ));
    }

    // --- delegation ---

    fn stake_addr() -> String {
        shared::address::stake_address_bech32(&[0x55; 32]).unwrap()
    }
    fn pool_id() -> String {
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("pool").unwrap(), &[0xAB; 28]).unwrap()
    }
    fn drep_id() -> String {
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("drep").unwrap(), &[0xCD; 28]).unwrap()
    }

    fn one_cert_of(body_cbor: &[u8]) -> Certificate {
        let body: TransactionBody = minicbor::decode(body_cbor).unwrap();
        let certs = body.certificates.expect("certificates present");
        assert_eq!(certs.len(), 1);
        certs[0].clone()
    }

    #[test]
    fn pool_delegation_plain() {
        let utxos = vec![utxo("a", 0, 5_000_000, vec![])];
        let out = build_pool_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &pool_id(),
            false,
            0,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        assert!(matches!(
            one_cert_of(&out.body_cbor),
            Certificate::StakeDelegation(_, _)
        ));
        assert_eq!(5_000_000, out.fee_lovelace + out.change_lovelace); // no deposit
        let body: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert_eq!(body.outputs.len(), 1); // change only
    }

    #[test]
    fn pool_delegation_with_registration() {
        let utxos = vec![utxo("b", 0, 5_000_000, vec![])];
        let out = build_pool_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &pool_id(),
            true,
            2_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        assert!(matches!(
            one_cert_of(&out.body_cbor),
            Certificate::StakeRegDeleg(_, _, 2_000_000)
        ));
        assert_eq!(
            5_000_000,
            2_000_000 + out.fee_lovelace + out.change_lovelace
        );
    }

    #[test]
    fn drep_delegation_abstain() {
        let utxos = vec![utxo("c", 0, 5_000_000, vec![])];
        let out = build_drep_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &DrepTarget::Abstain,
            false,
            0,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        assert!(matches!(
            one_cert_of(&out.body_cbor),
            Certificate::VoteDeleg(_, DRep::Abstain)
        ));
    }

    #[test]
    fn drep_delegation_specific_and_registration() {
        let utxos = vec![utxo("d", 0, 5_000_000, vec![])];
        let out = build_drep_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &DrepTarget::Drep(drep_id()),
            true,
            2_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        match one_cert_of(&out.body_cbor) {
            Certificate::VoteRegDeleg(_, DRep::Key(_), 2_000_000) => {}
            _ => panic!("expected VoteRegDeleg to a key DRep with the deposit"),
        }
    }

    #[test]
    fn delegation_insufficient_for_deposit() {
        let utxos = vec![utxo("e", 0, 1_000_000, vec![])];
        let err = build_pool_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &pool_id(),
            true,
            2_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        );
        assert!(matches!(
            err,
            Err(WalletTxError::InsufficientLovelace { .. })
        ));
    }

    #[test]
    fn delegation_sweep_folds_remainder_into_fee() {
        // Deposit + fee leave less than the min-ADA change: the remainder
        // becomes fee and the body carries no outputs at all.
        let utxos = vec![utxo("f", 0, 2_500_000, vec![])];
        let out = build_pool_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &pool_id(),
            true,
            2_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        assert_eq!(out.change_lovelace, 0);
        assert!(out.change_assets.is_empty());
        assert_eq!(out.fee_lovelace, 500_000); // deposit + fee consume the input exactly
        let body: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert!(body.outputs.is_empty());
        assert_eq!(body.fee, 500_000);
        assert!(matches!(
            one_cert_of(&out.body_cbor),
            Certificate::StakeRegDeleg(_, _, 2_000_000)
        ));
    }

    // --- build → validate round-trips (tx_builder ↔ shared::tx_validator) ---

    fn cc() -> shared::chain_context::ChainContext {
        shared::chain_context::ChainContext {
            current_epoch: 0,
            current_slot: 0,
            current_kes_period: 0,
            epoch_ends_at_unix: 0,
            opcert_expires_at_unix: None,
            built_at_unix: 0,
        }
    }

    fn to_utxo_inputs(
        used: &[TxInput],
        owned: &[OwnedUtxo],
        payment: &str,
    ) -> Vec<shared::utxo::UtxoInput> {
        used.iter()
            .map(|i| {
                let o = owned
                    .iter()
                    .find(|o| o.tx_hash_hex == i.tx_hash_hex && o.tx_index == i.tx_index)
                    .unwrap();
                shared::utxo::UtxoInput {
                    tx_hash_hex: i.tx_hash_hex.clone(),
                    tx_index: i.tx_index,
                    amount_lovelace: o.lovelace,
                    address_bech32: payment.to_string(),
                }
            })
            .collect()
    }

    #[test]
    fn payment_body_validates_against_its_request() {
        let utxos = vec![
            utxo("a", 0, 3_000_000, vec![]),
            utxo("b", 1, 2_000_000, vec![]),
        ];
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            1_500_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        let req = shared::payment::PaymentRequest {
            kind: shared::wire_kind::WalletWireKind::Payment,
            tx_body_cbor_hex: hex::encode(&out.body_cbor),
            destination_address_bech32: dest_addr(),
            amount_lovelace: 1_500_000,
            assets_sent: vec![],
            fee_lovelace: out.fee_lovelace,
            change_lovelace: out.change_lovelace,
            change_assets: out.change_assets.clone(),
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            inputs: to_utxo_inputs(&out.inputs, &utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
            metadata_msg: None,
        };
        shared::tx_validator::validate_payment_body(&out.body_cbor, &req, 0).expect("valid");

        // Tampering the claimed amount makes the body no longer match.
        let mut bad = req.clone();
        bad.amount_lovelace = 999;
        assert!(shared::tx_validator::validate_payment_body(&out.body_cbor, &bad, 0).is_err());
        // Tampering the destination likewise.
        let mut bad2 = req.clone();
        bad2.destination_address_bech32 = pay_addr();
        assert!(shared::tx_validator::validate_payment_body(&out.body_cbor, &bad2, 0).is_err());
    }

    #[test]
    fn payment_to_a_script_address_is_refused_by_the_signer_check() {
        let mut script = vec![0x71];
        script.extend([0x55; 28]);
        let script_addr =
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("addr").unwrap(), &script).unwrap();
        let utxos = vec![utxo("a", 0, 3_000_000, vec![])];
        let out = build_payment_body(
            &pay_addr(),
            &script_addr,
            1_500_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        let req = shared::payment::PaymentRequest {
            kind: shared::wire_kind::WalletWireKind::Payment,
            tx_body_cbor_hex: hex::encode(&out.body_cbor),
            destination_address_bech32: script_addr,
            amount_lovelace: 1_500_000,
            assets_sent: vec![],
            fee_lovelace: out.fee_lovelace,
            change_lovelace: out.change_lovelace,
            change_assets: out.change_assets.clone(),
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            inputs: to_utxo_inputs(&out.inputs, &utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
            metadata_msg: None,
        };
        let err = shared::tx_validator::validate_payment_body(&out.body_cbor, &req, 0).unwrap_err();
        assert!(err.to_string().contains("script address"), "{err}");
    }

    #[test]
    fn sweep_payment_body_validates_against_its_request() {
        // A change-less (full-sweep) body passes the signer-side validator
        // when the request declares zero change, and the critical fields
        // stay bound.
        let utxos = vec![utxo("a", 0, 5_000_000, vec![])];
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            4_500_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        assert_eq!(out.change_lovelace, 0);
        let req = shared::payment::PaymentRequest {
            kind: shared::wire_kind::WalletWireKind::Payment,
            tx_body_cbor_hex: hex::encode(&out.body_cbor),
            destination_address_bech32: dest_addr(),
            amount_lovelace: 4_500_000,
            assets_sent: vec![],
            fee_lovelace: out.fee_lovelace,
            change_lovelace: 0,
            change_assets: vec![],
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            inputs: to_utxo_inputs(&out.inputs, &utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
            metadata_msg: None,
        };
        shared::tx_validator::validate_payment_body(&out.body_cbor, &req, 0).expect("valid");

        // A tampered amount still fails on the change-less path.
        let mut bad = req.clone();
        bad.amount_lovelace = 999;
        assert!(shared::tx_validator::validate_payment_body(&out.body_cbor, &bad, 0).is_err());
        // Claiming non-zero change against a change-less body fails too.
        let mut bad2 = req.clone();
        bad2.change_lovelace = 1_000_000;
        assert!(shared::tx_validator::validate_payment_body(&out.body_cbor, &bad2, 0).is_err());
    }

    #[test]
    fn payment_with_metadata_binds_and_validates() {
        let utxos = vec![
            utxo("a", 0, 3_000_000, vec![]),
            utxo("b", 1, 2_000_000, vec![]),
        ];
        let msg = vec!["Invoice 42".to_string(), "paid in full".to_string()];
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            1_500_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            Some(&msg),
        )
        .unwrap();

        // The body commits exactly the blake2b-256 of the CIP-20 aux data.
        let aux = out.aux_data_cbor.clone().expect("aux data present");
        let want = pallas_crypto::hash::Hasher::<256>::hash(&aux);
        let body: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert_eq!(
            body.auxiliary_data_hash.as_ref().map(|b| &b[..]),
            Some(want.as_ref())
        );

        let mk = |m: Option<Vec<String>>| shared::payment::PaymentRequest {
            kind: shared::wire_kind::WalletWireKind::Payment,
            tx_body_cbor_hex: hex::encode(&out.body_cbor),
            destination_address_bech32: dest_addr(),
            amount_lovelace: 1_500_000,
            assets_sent: vec![],
            fee_lovelace: out.fee_lovelace,
            change_lovelace: out.change_lovelace,
            change_assets: out.change_assets.clone(),
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            inputs: to_utxo_inputs(&out.inputs, &utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
            metadata_msg: m,
        };

        // Correct metadata validates against the committed hash.
        shared::tx_validator::validate_payment_body(&out.body_cbor, &mk(Some(msg.clone())), 0)
            .expect("valid");
        // Tampered metadata no longer matches the committed hash.
        assert!(shared::tx_validator::validate_payment_body(
            &out.body_cbor,
            &mk(Some(vec!["different".to_string()])),
            0
        )
        .is_err());
        // Claiming no metadata while the body commits a hash is rejected.
        assert!(shared::tx_validator::validate_payment_body(&out.body_cbor, &mk(None), 0).is_err());
    }

    #[test]
    fn pool_delegation_body_validates_against_its_request() {
        let utxos = vec![utxo("a", 0, 5_000_000, vec![])];
        let out = build_pool_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &pool_id(),
            true,
            2_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        let req = shared::delegate::PoolDelegateRequest {
            kind: shared::wire_kind::WalletWireKind::PoolDelegate,
            tx_body_cbor_hex: hex::encode(&out.body_cbor),
            pool_id_bech32: pool_id(),
            register_stake: true,
            deposit_lovelace: 2_000_000,
            fee_lovelace: out.fee_lovelace,
            change_lovelace: out.change_lovelace,
            change_assets: out.change_assets.clone(),
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            stake_address_bech32: stake_addr(),
            inputs: to_utxo_inputs(&out.inputs, &utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
        };
        shared::tx_validator::validate_pool_delegation_body(&out.body_cbor, &req, 0)
            .expect("valid");

        // A different pool id no longer matches the cert in the body.
        let mut bad = req.clone();
        bad.pool_id_bech32 =
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("pool").unwrap(), &[0x01; 28])
                .unwrap();
        assert!(
            shared::tx_validator::validate_pool_delegation_body(&out.body_cbor, &bad, 0).is_err()
        );
    }

    #[test]
    fn delegation_sweep_body_validates_against_its_request() {
        // A no-output (full-sweep) delegation body passes the signer-side
        // validator when the request declares zero change.
        let utxos = vec![utxo("f", 0, 2_500_000, vec![])];
        let out = build_pool_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &pool_id(),
            true,
            2_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        assert_eq!(out.change_lovelace, 0);
        let req = shared::delegate::PoolDelegateRequest {
            kind: shared::wire_kind::WalletWireKind::PoolDelegate,
            tx_body_cbor_hex: hex::encode(&out.body_cbor),
            pool_id_bech32: pool_id(),
            register_stake: true,
            deposit_lovelace: 2_000_000,
            fee_lovelace: out.fee_lovelace,
            change_lovelace: 0,
            change_assets: vec![],
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            stake_address_bech32: stake_addr(),
            inputs: to_utxo_inputs(&out.inputs, &utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
        };
        shared::tx_validator::validate_pool_delegation_body(&out.body_cbor, &req, 0)
            .expect("valid");

        // Claiming non-zero change against a no-output body fails.
        let mut bad = req.clone();
        bad.change_lovelace = 1_000_000;
        assert!(
            shared::tx_validator::validate_pool_delegation_body(&out.body_cbor, &bad, 0).is_err()
        );
    }

    #[test]
    fn drep_delegation_body_validates_against_its_request() {
        let utxos = vec![utxo("a", 0, 4_000_000, vec![])];
        let out = build_drep_delegation_body(
            &pay_addr(),
            &stake_addr(),
            &DrepTarget::Drep(drep_id()),
            false,
            0,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        let req = shared::delegate::DrepDelegateRequest {
            kind: shared::wire_kind::WalletWireKind::DrepDelegate,
            tx_body_cbor_hex: hex::encode(&out.body_cbor),
            target: DrepTarget::Drep(drep_id()),
            register_stake: false,
            deposit_lovelace: 0,
            fee_lovelace: out.fee_lovelace,
            change_lovelace: out.change_lovelace,
            change_assets: out.change_assets.clone(),
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            stake_address_bech32: stake_addr(),
            inputs: to_utxo_inputs(&out.inputs, &utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
        };
        shared::tx_validator::validate_drep_delegation_body(&out.body_cbor, &req, 0)
            .expect("valid");

        // Switching the target to Abstain no longer matches the body's cert.
        let mut bad = req.clone();
        bad.target = DrepTarget::Abstain;
        assert!(
            shared::tx_validator::validate_drep_delegation_body(&out.body_cbor, &bad, 0).is_err()
        );
    }

    // --- reward withdrawal ---

    fn withdraw_request(
        out: &BuiltBody,
        utxos: &[OwnedUtxo],
        rewards: u64,
    ) -> shared::withdraw::WithdrawRewardsRequest {
        shared::withdraw::WithdrawRewardsRequest {
            kind: shared::wire_kind::WalletWireKind::WithdrawRewards,
            tx_body_cbor_hex: hex::encode(&out.body_cbor),
            rewards_lovelace: rewards,
            fee_lovelace: out.fee_lovelace,
            change_lovelace: out.change_lovelace,
            change_assets: out.change_assets.clone(),
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            stake_address_bech32: stake_addr(),
            inputs: to_utxo_inputs(&out.inputs, utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
        }
    }

    #[test]
    fn withdrawal_adds_rewards_to_change() {
        let utxos = vec![
            utxo("a", 0, 5_000_000, vec![]),
            utxo("b", 1, 9_000_000, vec![]),
        ];
        let out = build_withdraw_rewards_body(
            &pay_addr(),
            &stake_addr(),
            12_345_678,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        // Only the largest UTxO is spent; the rewards land in the change.
        assert_eq!(out.inputs.len(), 1);
        assert_eq!(out.inputs[0].tx_index, 1);
        assert_eq!(
            9_000_000 + 12_345_678,
            out.change_lovelace + out.fee_lovelace
        );
        let body: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert!(body.certificates.is_none());
        assert_eq!(body.outputs.len(), 1);
        let w = body.withdrawals.expect("withdrawals present");
        assert_eq!(w.len(), 1);
        assert_eq!(
            w[0].0[..],
            decode_address(&stake_addr(), "stake").unwrap()[..]
        );
        assert_eq!(w[0].0.len(), 29);
        assert_eq!(w[0].1, 12_345_678);
    }

    #[test]
    fn withdrawal_fee_covers_the_signed_size() {
        // The fee must be at least the ledger's linear minimum for the tx as
        // it goes on the wire: body + two real-size witnesses + wrapper.
        let utxos = vec![utxo("a", 0, 5_000_000, vec![asset(POLICY_A, "aa", 10)])];
        let out = build_withdraw_rewards_body(
            &pay_addr(),
            &stake_addr(),
            777_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        let wit = || shared::tx::RawVkeyWitness {
            vkey: vec![7u8; 32],
            signature: vec![9u8; 64],
        };
        let signed = shared::tx::assemble_signed_tx(&out.body_cbor, &[wit(), wit()]).unwrap();
        // Two distinct keys in practice; the set here holds two equal-size entries.
        let min_fee = 44 * signed.len() as u64 + 155381;
        assert!(
            out.fee_lovelace >= min_fee,
            "fee {} < min {}",
            out.fee_lovelace,
            min_fee
        );
        assert!(
            out.fee_lovelace - min_fee < 5_000,
            "fee overshoots: {}",
            out.fee_lovelace - min_fee
        );
        assert_eq!(out.change_assets, vec![asset(POLICY_A, "aa", 10)]);
    }

    #[test]
    fn withdrawal_pulls_more_inputs_when_change_is_short() {
        // Tiny rewards + a tiny UTxO cannot pay fee + min-ADA change alone.
        let utxos = vec![utxo("a", 0, 600_000, vec![]), utxo("b", 1, 500_000, vec![])];
        let out = build_withdraw_rewards_body(
            &pay_addr(),
            &stake_addr(),
            100_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        assert_eq!(out.inputs.len(), 2);
        assert_eq!(1_100_000 + 100_000, out.change_lovelace + out.fee_lovelace);
    }

    #[test]
    fn withdrawal_never_folds_into_the_fee() {
        // Not enough for fee + min-ADA change: refused, not swept into the fee.
        let utxos = vec![utxo("a", 0, 300_000, vec![])];
        let err = build_withdraw_rewards_body(
            &pay_addr(),
            &stake_addr(),
            100_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        );
        assert!(matches!(
            err,
            Err(WalletTxError::InsufficientLovelace { .. })
        ));
        let none = build_withdraw_rewards_body(
            &pay_addr(),
            &stake_addr(),
            5_000_000,
            &[],
            100,
            44,
            155381,
            4310,
        );
        assert!(matches!(
            none,
            Err(WalletTxError::InsufficientLovelace { .. })
        ));
    }

    #[test]
    fn withdrawal_rejects_a_non_stake_reward_account() {
        let utxos = vec![utxo("a", 0, 5_000_000, vec![])];
        let err = build_withdraw_rewards_body(
            &pay_addr(),
            &pay_addr(),
            1_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        );
        assert!(err.is_err());
    }

    #[test]
    fn withdrawal_body_validates_against_its_request() {
        let utxos = vec![utxo("a", 0, 5_000_000, vec![asset(POLICY_A, "aa", 10)])];
        let out = build_withdraw_rewards_body(
            &pay_addr(),
            &stake_addr(),
            42_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        let req = withdraw_request(&out, &utxos, 42_000_000);
        let check = |r: &shared::withdraw::WithdrawRewardsRequest| {
            shared::tx_validator::validate_withdraw_rewards_body(&out.body_cbor, r, 0)
        };
        check(&req).expect("valid");

        // Another reward account than the one in the body.
        let mut bad = req.clone();
        bad.stake_address_bech32 = shared::address::stake_address_bech32(&[0x66; 32]).unwrap();
        assert!(check(&bad).is_err());
        // Another amount than the one in the body.
        let mut bad = req.clone();
        bad.rewards_lovelace -= 1;
        assert!(check(&bad).is_err());
        // Change declared to another address than the output's.
        let mut bad = req.clone();
        bad.payment_address_bech32 = dest_addr();
        assert!(check(&bad).is_err());
        // An understated input amount: the declared figures no longer balance.
        let mut bad = req.clone();
        bad.inputs[0].amount_lovelace -= 1;
        assert!(matches!(
            check(&bad),
            Err(shared::validate::ValidationError::Mismatch(
                "inputs + rewards do not equal change + fee"
            ))
        ));
        // Dropped change assets.
        let mut bad = req.clone();
        bad.change_assets.clear();
        assert!(check(&bad).is_err());
        // Expired.
        assert!(
            shared::tx_validator::validate_withdraw_rewards_body(&out.body_cbor, &req, 100)
                .is_err()
        );
    }

    #[test]
    fn withdrawal_validator_refuses_foreign_shapes() {
        let utxos = vec![utxo("a", 0, 5_000_000, vec![])];
        let out = build_withdraw_rewards_body(
            &pay_addr(),
            &stake_addr(),
            42_000_000,
            &utxos,
            100,
            44,
            155381,
            4310,
        )
        .unwrap();
        let req = withdraw_request(&out, &utxos, 42_000_000);
        let reencode = |b: &TransactionBody| {
            let mut buf = Vec::new();
            minicbor::encode(b, &mut buf).unwrap();
            buf
        };
        let base: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        let check = |b: &TransactionBody| {
            shared::tx_validator::validate_withdraw_rewards_body(&reencode(b), &req, 0)
        };
        check(&base).expect("the re-encoded body is still valid");

        // A certificate riding along.
        let mut b = base.clone();
        b.certificates = Some(
            one_cert(Certificate::StakeDelegation(
                stake_credential(&stake_addr()).unwrap(),
                pool_keyhash(&pool_id()).unwrap(),
            ))
            .unwrap(),
        );
        assert!(check(&b).is_err());
        // No withdrawal at all.
        let mut b = base.clone();
        b.withdrawals = None;
        assert!(check(&b).is_err());
        // A second withdrawal next to the approved one.
        let mut b = base.clone();
        let other = decode_address(
            &shared::address::stake_address_bech32(&[0x66; 32]).unwrap(),
            "stake",
        )
        .unwrap();
        let own = decode_address(&stake_addr(), "stake").unwrap();
        b.withdrawals = Some(
            NonEmptyKeyValuePairs::try_from(vec![
                (Bytes::from(own), 42_000_000u64),
                (Bytes::from(other), 1u64),
            ])
            .unwrap(),
        );
        assert!(check(&b).is_err());
        // A second output: rewards diverted next to the change.
        let mut b = base.clone();
        b.outputs.push(
            make_asset_output(
                decode_address(&dest_addr(), "addr").unwrap(),
                1_000_000,
                &[],
            )
            .unwrap(),
        );
        assert!(check(&b).is_err());
        // No output at all: everything into the fee.
        let mut b = base.clone();
        b.outputs.clear();
        assert!(check(&b).is_err());
        // The delegation and payment validators do not accept a withdrawal body.
        let preq = shared::payment::PaymentRequest {
            kind: shared::wire_kind::WalletWireKind::Payment,
            tx_body_cbor_hex: req.tx_body_cbor_hex.clone(),
            destination_address_bech32: pay_addr(),
            amount_lovelace: req.change_lovelace,
            assets_sent: vec![],
            fee_lovelace: req.fee_lovelace,
            change_lovelace: 0,
            change_assets: vec![],
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            inputs: req.inputs.clone(),
            operator_pin_proof: String::new(),
            chain_context: cc(),
            metadata_msg: None,
        };
        assert!(shared::tx_validator::validate_payment_body(&out.body_cbor, &preq, 0).is_err());
    }

    // --- fee ceiling ---

    #[test]
    fn honest_fees_stay_far_below_the_signer_ceiling() {
        // The largest honest fee is a full sweep: the linear fee plus a
        // sub-min-ADA remainder folded in. Even then it is under the ceiling.
        let utxos = vec![utxo("a", 0, 2_100_000, vec![])];
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            1_000_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        assert_eq!(
            out.change_lovelace, 0,
            "expected the remainder to fold into the fee"
        );
        assert!(out.fee_lovelace > 1_000_000, "fee {}", out.fee_lovelace);
        assert!(out.fee_lovelace < shared::tx_validator::MAX_FEE_LOVELACE);
    }

    #[test]
    fn validators_refuse_a_fee_above_the_ceiling() {
        // A body and a request that agree on a fee above the ceiling: every
        // field matches, and the signer still refuses.
        let utxos = vec![utxo("a", 0, 5_000_000, vec![])];
        let out = build_payment_body(
            &pay_addr(),
            &dest_addr(),
            1_000_000,
            &[],
            &utxos,
            100,
            44,
            155381,
            4310,
            None,
        )
        .unwrap();
        let mut body: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        let fee = shared::tx_validator::MAX_FEE_LOVELACE + 1;
        body.fee = fee;
        let mut cbor = Vec::new();
        minicbor::encode(&body, &mut cbor).unwrap();
        let mk = |fee: u64, cbor: &[u8]| shared::payment::PaymentRequest {
            kind: shared::wire_kind::WalletWireKind::Payment,
            tx_body_cbor_hex: hex::encode(cbor),
            destination_address_bech32: dest_addr(),
            amount_lovelace: 1_000_000,
            assets_sent: vec![],
            fee_lovelace: fee,
            change_lovelace: out.change_lovelace,
            change_assets: vec![],
            ttl_slot: 100,
            payment_address_bech32: pay_addr(),
            inputs: to_utxo_inputs(&out.inputs, &utxos, &pay_addr()),
            operator_pin_proof: String::new(),
            chain_context: cc(),
            metadata_msg: None,
        };
        // Control: the untouched body with its own fee validates.
        shared::tx_validator::validate_payment_body(
            &out.body_cbor,
            &mk(out.fee_lovelace, &out.body_cbor),
            0,
        )
        .expect("valid");
        assert!(matches!(
            shared::tx_validator::validate_payment_body(&cbor, &mk(fee, &cbor), 0),
            Err(shared::validate::ValidationError::Mismatch(
                "fee above the signer's ceiling"
            ))
        ));
    }
}
