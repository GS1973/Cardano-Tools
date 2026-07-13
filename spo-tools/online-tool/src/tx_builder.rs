//! Pallas-based transaction body construction for the online tool.
//!
//! Builds Conway-era `TransactionBody` CBOR for SPO operations:
//! - Reward withdrawal (1 input UTXO, 2 outputs, 1 withdrawal entry).
//! - DRep vote-delegation (Abstain / NoConfidence / specific DRep cert).
//! - Pool re-registration (full PoolRegistration cert with relays/metadata).
//!
//! The body is just the *unsigned* transaction body; the signer returns
//! witnesses, and `assemble_signed_tx` (here in this module) re-assembles
//! the signed transaction CBOR ready for submission.

use pallas_addresses::{Address, StakePayload};
use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptyKeyValuePairs, NonEmptySet, Nullable, Set};
use pallas_primitives::conway::{
    Anchor, Certificate, DRep, GovActionId, TransactionBody, TransactionOutput, Vote, Voter,
    VotingProcedure,
};
use pallas_primitives::{Hash, NetworkId, StakeCredential, TransactionInput};

// Role-neutral tx primitives, shared with DREP Tools via airgap-core.
pub use shared::tx::{
    assemble_signed_tx, check_tx_hash_hex_len, decode_address, make_output, parse_input,
    RawVkeyWitness, TxBuildError, TxInput,
};
use shared::asset::Asset;
use shared::tx::{make_asset_output, min_ada_for_output};


/// Inputs to build a withdrawal transaction body.
///
/// All amounts are in lovelace.
const UTXO_COST_PER_BYTE: u64 = 4310;

/// Shelley/Conway CDDL size caps: pool-metadata `url` and relay `dns_name`
/// are `text .size (0..64)`; a governance anchor `url` is
/// `text .size (0..128)`. Enforced at build time so an oversized value
/// fails before the signing ceremony instead of with an opaque decode
/// error at submission.
const MAX_POOL_METADATA_URL_BYTES: usize = 64;
const MAX_RELAY_DNS_BYTES: usize = 64;
const MAX_ANCHOR_URL_BYTES: usize = 128;

/// Marker embedded in the CDDL length-cap messages below. `TxBuildError`
/// is defined in airgap-core and has no dedicated variant for these
/// operator-input rejections, so `cddl_len_violation` recognises them by
/// this marker instead.
const CDDL_LIMIT_MARKER: &str = "CDDL limit";

/// When `e` is one of this module's CDDL length-cap rejections (relay
/// DNS name, pool metadata URL, vote anchor URL), return its message so
/// the handler can surface it as `ErrorEnvelope::invalid` — these are
/// operator-typed values, and the actionable "exceeds the N-byte CDDL
/// limit" text must reach the operator, not just the server log. `None`
/// for every other build error (those stay internal).
pub(crate) fn cddl_len_violation(e: &TxBuildError) -> Option<&str> {
    match e {
        TxBuildError::Cbor(msg) if msg.contains(CDDL_LIMIT_MARKER) => Some(msg.as_str()),
        _ => None,
    }
}

/// Change output back to the payment address, preserving any native assets the
/// spent UTxOs carry (spo sends no assets, so all of them return as change).
/// Guards that the change ADA covers the output's min-ADA — coin-only change
/// included — so the node will not reject an under-funded output.
fn change_output(
    payment: Vec<u8>,
    change: u64,
    assets: &[Asset],
) -> Result<TransactionOutput, TxBuildError> {
    let out = make_asset_output(payment, change, assets)?;
    let need = min_ada_for_output(&out, UTXO_COST_PER_BYTE)?;
    if change < need {
        return Err(TxBuildError::InsufficientInputs { fee: need, utxo_total: change });
    }
    Ok(out)
}

pub struct WithdrawalInputs<'a> {
    pub utxo_inputs: &'a [TxInput],
    pub utxo_total_lovelace: u64,
    pub change_assets: &'a [Asset],
    pub payment_address_bech32: &'a str,
    pub reward_receive_address_bech32: &'a str,
    pub pool_reward_address_bech32: &'a str,
    pub rewards_lovelace: u64,
    pub fee_lovelace: u64,
    pub ttl_slot: u64,
}


#[derive(Debug)]
pub struct WithdrawalTxBody {
    pub body_cbor: Vec<u8>,
    pub net_to_reward_address_lovelace: u64,
    pub change_to_payment_address_lovelace: u64,
}

pub fn build_withdrawal_body(input: &WithdrawalInputs) -> Result<WithdrawalTxBody, TxBuildError> {
    let payment_addr_bytes = decode_address(input.payment_address_bech32, "addr")?;
    let reward_addr_bytes = decode_address(input.reward_receive_address_bech32, "addr")?;
    let pool_reward_account_bytes = decode_address(input.pool_reward_address_bech32, "stake")?;

    let net_to_reward_address_lovelace = input.rewards_lovelace;
    let change_to_payment_address_lovelace = input
        .utxo_total_lovelace
        .checked_sub(input.fee_lovelace)
        .ok_or(TxBuildError::InsufficientInputs {
            fee: input.fee_lovelace,
            utxo_total: input.utxo_total_lovelace,
        })?;

    let inputs: Vec<TransactionInput> = input
        .utxo_inputs
        .iter()
        .map(|u| {
            check_tx_hash_hex_len(&u.tx_hash_hex)?;
            let mut h = [0u8; 32];
            let bytes = hex::decode(&u.tx_hash_hex)
                .map_err(|_| TxBuildError::HashHex(u.tx_hash_hex.clone()))?;
            if bytes.len() != 32 {
                return Err(TxBuildError::HashHex(u.tx_hash_hex.clone()));
            }
            h.copy_from_slice(&bytes);
            Ok(TransactionInput {
                transaction_id: Hash::from(h),
                index: u.tx_index as u64,
            })
        })
        .collect::<Result<_, _>>()?;

    // The reward output must itself satisfy min-ADA: tiny accumulated
    // rewards (e.g. 0.5 ADA) pass the handler's has-rewards check but would
    // build a tx the ledger rejects with OutputTooSmallUTxO after the full
    // signing ceremony.
    let reward_output = make_output(reward_addr_bytes.clone(), net_to_reward_address_lovelace);
    let reward_min = min_ada_for_output(&reward_output, UTXO_COST_PER_BYTE)?;
    if net_to_reward_address_lovelace < reward_min {
        return Err(TxBuildError::InsufficientInputs {
            fee: reward_min,
            utxo_total: net_to_reward_address_lovelace,
        });
    }

    let outputs: Vec<TransactionOutput> = vec![
        reward_output,
        change_output(
            payment_addr_bytes.clone(),
            change_to_payment_address_lovelace,
            input.change_assets,
        )?,
    ];

    let withdrawals = NonEmptyKeyValuePairs::Def(vec![(
        Bytes::from(pool_reward_account_bytes),
        input.rewards_lovelace,
    )]);

    let body = TransactionBody {
        inputs: Set::from(inputs),
        outputs,
        fee: input.fee_lovelace,
        ttl: Some(input.ttl_slot),
        certificates: None,
        withdrawals: Some(withdrawals),
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
    minicbor::encode(&body, &mut buf).map_err(|e| TxBuildError::Cbor(e.to_string()))?;

    Ok(WithdrawalTxBody {
        body_cbor: buf,
        net_to_reward_address_lovelace,
        change_to_payment_address_lovelace,
    })
}


// ---------------------------------------------------------------------------
// DRep delegation
// ---------------------------------------------------------------------------

/// User-facing DRep choice. Mapped to `pallas_primitives::conway::DRep`
/// at body-build time.
#[derive(Debug, Clone)]
pub enum DRepChoice {
    Abstain,
    NoConfidence,
    /// Specific DRep credential, key-based (28-byte hash from drep1... bech32).
    KeyHash([u8; 28]),
    /// Specific DRep credential, script-based.
    ScriptHash([u8; 28]),
}

pub struct DRepDelegationInputs<'a> {
    pub utxo_inputs: &'a [TxInput],
    pub utxo_total_lovelace: u64,
    pub change_assets: &'a [Asset],
    pub payment_address_bech32: &'a str,
    pub stake_credential_bech32: &'a str,
    pub drep_choice: DRepChoice,
    pub fee_lovelace: u64,
    pub ttl_slot: u64,
}

#[derive(Debug)]
pub struct DRepDelegationTxBody {
    pub body_cbor: Vec<u8>,
    pub change_to_payment_address_lovelace: u64,
}

pub fn build_drep_delegation_body(
    input: &DRepDelegationInputs,
) -> Result<DRepDelegationTxBody, TxBuildError> {
    let payment_addr_bytes = decode_address(input.payment_address_bech32, "addr")?;
    let stake_cred = stake_credential_from_bech32(input.stake_credential_bech32)?;

    let change_to_payment_address_lovelace = input
        .utxo_total_lovelace
        .checked_sub(input.fee_lovelace)
        .ok_or(TxBuildError::InsufficientInputs {
            fee: input.fee_lovelace,
            utxo_total: input.utxo_total_lovelace,
        })?;

    let inputs: Vec<TransactionInput> = input
        .utxo_inputs
        .iter()
        .map(parse_input)
        .collect::<Result<_, _>>()?;

    let outputs: Vec<TransactionOutput> = vec![change_output(
        payment_addr_bytes.clone(),
        change_to_payment_address_lovelace,
        input.change_assets,
    )?];

    let drep = match input.drep_choice {
        DRepChoice::Abstain => DRep::Abstain,
        DRepChoice::NoConfidence => DRep::NoConfidence,
        DRepChoice::KeyHash(h) => DRep::Key(Hash::from(h)),
        DRepChoice::ScriptHash(h) => DRep::Script(Hash::from(h)),
    };
    let cert = Certificate::VoteDeleg(stake_cred, drep);
    let certificates = NonEmptySet::try_from(vec![cert])
        .map_err(|_| TxBuildError::Cbor("could not build NonEmptySet for certs".into()))?;

    let body = TransactionBody {
        inputs: Set::from(inputs),
        outputs,
        fee: input.fee_lovelace,
        ttl: Some(input.ttl_slot),
        certificates: Some(certificates),
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
    minicbor::encode(&body, &mut buf).map_err(|e| TxBuildError::Cbor(e.to_string()))?;
    Ok(DRepDelegationTxBody {
        body_cbor: buf,
        change_to_payment_address_lovelace,
    })
}


fn stake_credential_from_bech32(bech32: &str) -> Result<StakeCredential, TxBuildError> {
    let parsed = Address::from_bech32(bech32)
        .map_err(|e| TxBuildError::Bech32(bech32.to_string(), e.to_string()))?;
    let stake = match parsed {
        Address::Stake(s) => s,
        _ => return Err(TxBuildError::WrongHrp("stake", "addr".into())),
    };
    Ok(match stake.payload() {
        StakePayload::Stake(h) => StakeCredential::AddrKeyhash(*h),
        StakePayload::Script(h) => StakeCredential::ScriptHash(*h),
    })
}

// ---------------------------------------------------------------------------
// Pool re-registration (parameter update)
// ---------------------------------------------------------------------------

/// Per-relay user input. Maps 1:1 to the on-chain Relay enum.
#[derive(Clone, Debug)]
pub enum RelayInput {
    /// IPv4 / IPv6 + port (mapped to Relay::SingleHostAddr).
    SingleHostAddr {
        port: Option<u16>,
        ipv4: Option<[u8; 4]>,
        ipv6: Option<[u8; 16]>,
    },
    /// DNS A record + port (mapped to Relay::SingleHostName).
    SingleHostName {
        port: Option<u16>,
        dns: String,
    },
    /// DNS SRV record (mapped to Relay::MultiHostName).
    MultiHostName { dns: String },
}

/// Reject a relay `dns_name` over the Shelley CDDL's 64-byte cap.
fn check_relay_dns_len(dns: &str) -> Result<(), TxBuildError> {
    if dns.len() > MAX_RELAY_DNS_BYTES {
        return Err(TxBuildError::Cbor(format!(
            "relay DNS name exceeds the {MAX_RELAY_DNS_BYTES}-byte {CDDL_LIMIT_MARKER} ({} bytes)",
            dns.len()
        )));
    }
    Ok(())
}

pub struct PoolUpdateInputs<'a> {
    pub utxo_inputs: &'a [TxInput],
    pub utxo_total_lovelace: u64,
    pub change_assets: &'a [Asset],
    pub payment_address_bech32: &'a str,
    /// Pool ID bech32 (`pool1...`) — 28-byte operator hash.
    pub pool_id_bech32: &'a str,
    /// Current VRF keyhash hex (32 bytes). Read-only in v1.0.
    pub vrf_keyhash_hex: &'a str,
    pub pledge_lovelace: u64,
    pub fixed_cost_lovelace: u64,
    /// Margin as a rational. Frontend converts user-entered percent
    /// to numerator/denominator with chosen precision.
    pub margin_numerator: u64,
    pub margin_denominator: u64,
    /// Reward stake address (`stake1...`) — 29 bytes on the wire.
    pub reward_account_bech32: &'a str,
    /// Pool owner stake addresses (`stake1...`). v1.0 enforces single owner
    /// at the route level; this slice may carry one or more for tests.
    pub pool_owner_stake_addresses: &'a [String],
    pub relays: &'a [RelayInput],
    pub metadata_url: Option<&'a str>,
    pub metadata_hash_hex: Option<&'a str>,
    pub fee_lovelace: u64,
    pub ttl_slot: u64,
}

#[derive(Debug)]
pub struct PoolUpdateTxBody {
    pub body_cbor: Vec<u8>,
    pub change_to_payment_address_lovelace: u64,
}

pub fn build_pool_update_body(
    input: &PoolUpdateInputs,
) -> Result<PoolUpdateTxBody, TxBuildError> {
    let payment_addr_bytes = decode_address(input.payment_address_bech32, "addr")?;

    // Pool ID (operator) — 28-byte hash from bech32 "pool1..."
    let (hrp, pool_id_bytes) = bech32::decode(input.pool_id_bech32)
        .map_err(|e| TxBuildError::Bech32(input.pool_id_bech32.to_string(), e.to_string()))?;
    if hrp.as_str() != "pool" {
        return Err(TxBuildError::WrongHrp("pool", hrp.as_str().to_string()));
    }
    if pool_id_bytes.len() != 28 {
        return Err(TxBuildError::HashHex(format!(
            "pool_id not 28 bytes (got {})",
            pool_id_bytes.len()
        )));
    }
    let mut operator = [0u8; 28];
    operator.copy_from_slice(&pool_id_bytes);

    // VRF keyhash — 32-byte hash from hex
    let vrf_bytes = hex::decode(input.vrf_keyhash_hex)
        .map_err(|_| TxBuildError::HashHex(input.vrf_keyhash_hex.to_string()))?;
    if vrf_bytes.len() != 32 {
        return Err(TxBuildError::HashHex(format!(
            "vrf_keyhash not 32 bytes (got {})",
            vrf_bytes.len()
        )));
    }
    let mut vrf_arr = [0u8; 32];
    vrf_arr.copy_from_slice(&vrf_bytes);

    // Reward account — 29 bytes (header + 28 hash) from bech32 "stake1..."
    let reward_account_bytes = decode_address(input.reward_account_bech32, "stake")?;

    // Pool owners — 28-byte AddrKeyhash from each "stake1..." (key only, not script)
    let mut pool_owners_vec: Vec<Hash<28>> =
        Vec::with_capacity(input.pool_owner_stake_addresses.len());
    for sa in input.pool_owner_stake_addresses {
        let parsed = Address::from_bech32(sa)
            .map_err(|e| TxBuildError::Bech32(sa.to_string(), e.to_string()))?;
        let stake = match parsed {
            Address::Stake(s) => s,
            _ => return Err(TxBuildError::WrongHrp("stake", "addr".into())),
        };
        match stake.payload() {
            StakePayload::Stake(h) => pool_owners_vec.push(*h),
            StakePayload::Script(_) => {
                return Err(TxBuildError::WrongHrp("stake (key)", "stake (script)".into()));
            }
        }
    }

    // Relays — translate user-input variants to on-chain Relay enum.
    // dns_name is capped at 64 bytes by the Shelley CDDL; an oversized name
    // would encode and sign fine but be rejected at submission.
    let relays: Vec<pallas_primitives::Relay> = input
        .relays
        .iter()
        .map(|r| match r {
            RelayInput::SingleHostAddr { port, ipv4, ipv6 } => {
                let port_n = match port {
                    Some(p) => Nullable::Some(*p as u32),
                    None => Nullable::Null,
                };
                let ipv4_n = match ipv4 {
                    Some(v) => Nullable::Some(Bytes::from(v.to_vec())),
                    None => Nullable::Null,
                };
                let ipv6_n = match ipv6 {
                    Some(v) => Nullable::Some(Bytes::from(v.to_vec())),
                    None => Nullable::Null,
                };
                Ok(pallas_primitives::Relay::SingleHostAddr(port_n, ipv4_n, ipv6_n))
            }
            RelayInput::SingleHostName { port, dns } => {
                check_relay_dns_len(dns)?;
                let port_n = match port {
                    Some(p) => Nullable::Some(*p as u32),
                    None => Nullable::Null,
                };
                Ok(pallas_primitives::Relay::SingleHostName(port_n, dns.clone()))
            }
            RelayInput::MultiHostName { dns } => {
                check_relay_dns_len(dns)?;
                Ok(pallas_primitives::Relay::MultiHostName(dns.clone()))
            }
        })
        .collect::<Result<_, _>>()?;

    // Pool metadata — Nullable<PoolMetadata>. URL and hash must be provided
    // together: silently dropping a partial pair would strip the pool's
    // on-chain metadata while the sign request still carries it, a mismatch
    // the signer only rejects after the full QR round-trip.
    let pool_metadata = match (input.metadata_url, input.metadata_hash_hex) {
        (Some(url), Some(hash_hex)) => {
            if url.len() > MAX_POOL_METADATA_URL_BYTES {
                return Err(TxBuildError::Cbor(format!(
                    "pool metadata URL exceeds the {MAX_POOL_METADATA_URL_BYTES}-byte {CDDL_LIMIT_MARKER} ({} bytes)",
                    url.len()
                )));
            }
            let h_bytes =
                hex::decode(hash_hex).map_err(|_| TxBuildError::HashHex(hash_hex.to_string()))?;
            if h_bytes.len() != 32 {
                return Err(TxBuildError::HashHex(format!(
                    "metadata hash not 32 bytes (got {})",
                    h_bytes.len()
                )));
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&h_bytes);
            Nullable::Some(pallas_primitives::PoolMetadata {
                url: url.to_string(),
                hash: Hash::from(h),
            })
        }
        (None, None) => Nullable::Null,
        _ => {
            return Err(TxBuildError::Cbor(
                "pool metadata URL and hash must be provided together, or neither".into(),
            ))
        }
    };

    let cert = Certificate::PoolRegistration {
        operator: Hash::from(operator),
        vrf_keyhash: Hash::from(vrf_arr),
        pledge: input.pledge_lovelace,
        cost: input.fixed_cost_lovelace,
        margin: pallas_primitives::RationalNumber {
            numerator: input.margin_numerator,
            denominator: input.margin_denominator,
        },
        reward_account: Bytes::from(reward_account_bytes),
        pool_owners: Set::from(pool_owners_vec),
        relays,
        pool_metadata,
    };

    let certificates = NonEmptySet::try_from(vec![cert])
        .map_err(|_| TxBuildError::Cbor("could not build NonEmptySet for certs".into()))?;

    let inputs: Vec<TransactionInput> = input
        .utxo_inputs
        .iter()
        .map(parse_input)
        .collect::<Result<_, _>>()?;

    let change_to_payment_address_lovelace = input
        .utxo_total_lovelace
        .checked_sub(input.fee_lovelace)
        .ok_or(TxBuildError::InsufficientInputs {
            fee: input.fee_lovelace,
            utxo_total: input.utxo_total_lovelace,
        })?;

    let outputs: Vec<TransactionOutput> = vec![change_output(
        payment_addr_bytes.clone(),
        change_to_payment_address_lovelace,
        input.change_assets,
    )?];

    let body = TransactionBody {
        inputs: Set::from(inputs),
        outputs,
        fee: input.fee_lovelace,
        ttl: Some(input.ttl_slot),
        certificates: Some(certificates),
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
    minicbor::encode(&body, &mut buf).map_err(|e| TxBuildError::Cbor(e.to_string()))?;

    Ok(PoolUpdateTxBody {
        body_cbor: buf,
        change_to_payment_address_lovelace,
    })
}

// ---------------------------------------------------------------------------
// SPO governance vote
// ---------------------------------------------------------------------------

/// Operator's ballot on a governance action. Mapped to
/// `pallas_primitives::conway::Vote` at body-build time.
#[derive(Debug, Clone, Copy)]
pub enum VoteChoice {
    No,
    Yes,
    Abstain,
}

/// Optional rationale anchor: a public document URL plus the 32-byte
/// blake2b-256 hash of its contents.
#[derive(Debug, Clone)]
pub struct VoteAnchorInput {
    pub url: String,
    pub hash_hex: String,
}

pub struct VoteInputs<'a> {
    pub utxo_inputs: &'a [TxInput],
    pub utxo_total_lovelace: u64,
    pub change_assets: &'a [Asset],
    pub payment_address_bech32: &'a str,
    /// Pool ID (`pool1...`) whose cold key authorises this vote. Its
    /// 28-byte hash becomes the `Voter::StakePoolKey` on-chain.
    pub pool_id_bech32: &'a str,
    /// 64-char hex of the governance action's proposal tx hash.
    pub action_tx_hash_hex: &'a str,
    pub action_index: u32,
    pub vote: VoteChoice,
    pub anchor: Option<VoteAnchorInput>,
    pub fee_lovelace: u64,
    pub ttl_slot: u64,
}

#[derive(Debug)]
pub struct VoteTxBody {
    pub body_cbor: Vec<u8>,
    pub change_to_payment_address_lovelace: u64,
}

pub fn build_vote_body(input: &VoteInputs) -> Result<VoteTxBody, TxBuildError> {
    let payment_addr_bytes = decode_address(input.payment_address_bech32, "addr")?;

    // Pool ID (operator / cold-key hash) — 28 bytes from "pool1..." bech32.
    let (hrp, pool_id_bytes) = bech32::decode(input.pool_id_bech32)
        .map_err(|e| TxBuildError::Bech32(input.pool_id_bech32.to_string(), e.to_string()))?;
    if hrp.as_str() != "pool" {
        return Err(TxBuildError::WrongHrp("pool", hrp.as_str().to_string()));
    }
    if pool_id_bytes.len() != 28 {
        return Err(TxBuildError::HashHex(format!(
            "pool_id not 28 bytes (got {})",
            pool_id_bytes.len()
        )));
    }
    let mut pool_id = [0u8; 28];
    pool_id.copy_from_slice(&pool_id_bytes);

    // Governance action id — 32-byte proposal tx hash from hex + index.
    check_tx_hash_hex_len(input.action_tx_hash_hex)?;
    let action_hash_bytes = hex::decode(input.action_tx_hash_hex)
        .map_err(|_| TxBuildError::HashHex(input.action_tx_hash_hex.to_string()))?;
    if action_hash_bytes.len() != 32 {
        return Err(TxBuildError::HashHex(input.action_tx_hash_hex.to_string()));
    }
    let mut action_hash = [0u8; 32];
    action_hash.copy_from_slice(&action_hash_bytes);

    let vote = match input.vote {
        VoteChoice::No => Vote::No,
        VoteChoice::Yes => Vote::Yes,
        VoteChoice::Abstain => Vote::Abstain,
    };

    let anchor = match &input.anchor {
        Some(a) => {
            // Conway CDDL caps an anchor url at 128 bytes; oversized values
            // must fail here, not at submission after the signing ceremony.
            if a.url.len() > MAX_ANCHOR_URL_BYTES {
                return Err(TxBuildError::Cbor(format!(
                    "anchor URL exceeds the {MAX_ANCHOR_URL_BYTES}-byte {CDDL_LIMIT_MARKER} ({} bytes)",
                    a.url.len()
                )));
            }
            let h_bytes =
                hex::decode(&a.hash_hex).map_err(|_| TxBuildError::HashHex(a.hash_hex.clone()))?;
            if h_bytes.len() != 32 {
                return Err(TxBuildError::HashHex(format!(
                    "anchor hash not 32 bytes (got {})",
                    h_bytes.len()
                )));
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&h_bytes);
            Nullable::Some(Anchor {
                url: a.url.clone(),
                content_hash: Hash::from(h),
            })
        }
        None => Nullable::Null,
    };

    let voting_procedure = VotingProcedure { vote, anchor };
    let gov_action_id = GovActionId {
        transaction_id: Hash::from(action_hash),
        action_index: input.action_index,
    };
    let inner = NonEmptyKeyValuePairs::Def(vec![(gov_action_id, voting_procedure)]);
    let voter = Voter::StakePoolKey(Hash::from(pool_id));
    let voting_procedures = NonEmptyKeyValuePairs::Def(vec![(voter, inner)]);

    let change_to_payment_address_lovelace = input
        .utxo_total_lovelace
        .checked_sub(input.fee_lovelace)
        .ok_or(TxBuildError::InsufficientInputs {
            fee: input.fee_lovelace,
            utxo_total: input.utxo_total_lovelace,
        })?;

    let inputs: Vec<TransactionInput> = input
        .utxo_inputs
        .iter()
        .map(parse_input)
        .collect::<Result<_, _>>()?;

    let outputs: Vec<TransactionOutput> = vec![change_output(
        payment_addr_bytes.clone(),
        change_to_payment_address_lovelace,
        input.change_assets,
    )?];

    let body = TransactionBody {
        inputs: Set::from(inputs),
        outputs,
        fee: input.fee_lovelace,
        ttl: Some(input.ttl_slot),
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
        voting_procedures: Some(voting_procedures),
        proposal_procedures: None,
        treasury_value: None,
        donation: None,
    };

    let mut buf = Vec::new();
    minicbor::encode(&body, &mut buf).map_err(|e| TxBuildError::Cbor(e.to_string()))?;
    Ok(VoteTxBody {
        body_cbor: buf,
        change_to_payment_address_lovelace,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_withdrawal_body_that_round_trips() {
        let input = WithdrawalInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            reward_receive_address_bech32:
                "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am",
            pool_reward_address_bech32:
                "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            rewards_lovelace: 1_000_000_000,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        };
        let out = build_withdrawal_body(&input).unwrap();
        assert!(!out.body_cbor.is_empty());
        assert_eq!(out.net_to_reward_address_lovelace, 1_000_000_000);
        assert_eq!(out.change_to_payment_address_lovelace, 33_909_103);
        // Sanity: decode back.
        let decoded: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.outputs.len(), 2);
        assert_eq!(decoded.fee, 200_000);
        assert_eq!(decoded.ttl, Some(2_000_000));
        assert!(decoded.withdrawals.is_some());
    }

    #[test]
    fn assembles_signed_tx_with_2_witnesses() {
        let input = WithdrawalInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            reward_receive_address_bech32:
                "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am",
            pool_reward_address_bech32:
                "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            rewards_lovelace: 1_000_000_000,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        };
        let built = build_withdrawal_body(&input).unwrap();
        let witnesses = vec![
            RawVkeyWitness { vkey: vec![0u8; 32], signature: vec![0u8; 64] },
            RawVkeyWitness { vkey: vec![1u8; 32], signature: vec![1u8; 64] },
        ];
        let signed = assemble_signed_tx(&built.body_cbor, &witnesses).unwrap();
        // Signed tx must start with array(4) header.
        assert_eq!(signed[0], 0x84);
        // ...and end with success=true (0xf5) + null aux (0xf6).
        assert_eq!(signed[signed.len() - 2], 0xf5);
        assert_eq!(signed[signed.len() - 1], 0xf6);
        // Signed tx must contain the body bytes verbatim.
        assert!(
            signed.windows(built.body_cbor.len()).any(|w| w == built.body_cbor),
            "body bytes should appear verbatim in signed tx"
        );
        // Round-trip via Pallas.
        let _: pallas_primitives::conway::Tx = minicbor::decode(&signed).unwrap();
    }

    #[test]
    fn builds_drep_delegation_body_to_abstain() {
        let input = DRepDelegationInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            stake_credential_bech32: "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            drep_choice: DRepChoice::Abstain,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        };
        let out = build_drep_delegation_body(&input).unwrap();
        assert!(!out.body_cbor.is_empty());
        assert_eq!(out.change_to_payment_address_lovelace, 33_909_103);

        let decoded: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.outputs.len(), 1);
        assert_eq!(decoded.fee, 200_000);
        assert!(decoded.certificates.is_some());
        assert!(decoded.withdrawals.is_none());
    }

    #[test]
    fn builds_vote_body_yes_no_anchor() {
        let pool_hrp = bech32::Hrp::parse("pool").unwrap();
        let pool_id_bech32 =
            bech32::encode::<bech32::Bech32>(pool_hrp, &[11u8; 28]).unwrap();
        let input = VoteInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            pool_id_bech32: &pool_id_bech32,
            action_tx_hash_hex:
                "fdd468da5cc4ac8431dcd7e2b3211666c73bc229f85879469f67f1d9d51d344d",
            action_index: 0,
            vote: VoteChoice::Yes,
            anchor: None,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        };
        let out = build_vote_body(&input).unwrap();
        assert!(!out.body_cbor.is_empty());
        assert_eq!(out.change_to_payment_address_lovelace, 33_909_103);

        let decoded: TransactionBody = minicbor::decode(&out.body_cbor).unwrap();
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.outputs.len(), 1);
        assert_eq!(decoded.fee, 200_000);
        assert!(decoded.certificates.is_none());
        assert!(decoded.withdrawals.is_none());
        let vps = decoded.voting_procedures.expect("voting_procedures present");
        assert_eq!(vps.len(), 1);
    }

    #[test]
    fn rejects_wrong_hrp_for_payment_address() {
        let input = WithdrawalInputs {
            utxo_inputs: &[],
            utxo_total_lovelace: 0,
            change_assets: &[],
            payment_address_bech32:
                "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            reward_receive_address_bech32: "addr1q...",
            pool_reward_address_bech32:
                "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            rewards_lovelace: 0,
            fee_lovelace: 0,
            ttl_slot: 0,
        };
        let err = build_withdrawal_body(&input).unwrap_err();
        assert!(matches!(err, TxBuildError::WrongHrp("addr", _)));
    }

    #[test]
    fn drep_delegation_preserves_change_assets() {
        let assets = [Asset {
            policy_hex: "00112233445566778899aabbccddeeff00112233445566778899aabb".into(),
            asset_name_hex: "4e49474854".into(),
            quantity: 42,
        }];
        let with_a = build_drep_delegation_body(&DRepDelegationInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &assets,
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            stake_credential_bech32: "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            drep_choice: DRepChoice::Abstain,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        }).unwrap();
        let without = build_drep_delegation_body(&DRepDelegationInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            stake_credential_bech32: "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            drep_choice: DRepChoice::Abstain,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        }).unwrap();
        assert!(with_a.body_cbor.len() > without.body_cbor.len());
    }

    #[test]
    fn drep_delegation_guards_min_ada_for_asset_change() {
        let assets = [Asset {
            policy_hex: "00112233445566778899aabbccddeeff00112233445566778899aabb".into(),
            asset_name_hex: "4e49474854".into(),
            quantity: 42,
        }];
        // change = total - fee = 1 lovelace, far below an asset output's min-ADA.
        let mut bad = DRepDelegationInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &assets,
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            stake_credential_bech32: "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            drep_choice: DRepChoice::Abstain,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        };
        bad.utxo_total_lovelace = bad.fee_lovelace + 1;
        assert!(build_drep_delegation_body(&bad).is_err());
    }

    #[test]
    fn withdrawal_preserves_change_assets_keeping_reward_output() {
        let assets = [Asset {
            policy_hex: "00112233445566778899aabbccddeeff00112233445566778899aabb".into(),
            asset_name_hex: "4e49474854".into(),
            quantity: 42,
        }];
        // the asset rides in the change output; the reward output stays ADA-only.
        let with_a = build_withdrawal_body(&WithdrawalInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &assets,
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            reward_receive_address_bech32:
                "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am",
            pool_reward_address_bech32:
                "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            rewards_lovelace: 1_000_000_000,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        }).unwrap();
        let without = build_withdrawal_body(&WithdrawalInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            reward_receive_address_bech32:
                "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am",
            pool_reward_address_bech32:
                "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            rewards_lovelace: 1_000_000_000,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        }).unwrap();
        assert!(with_a.body_cbor.len() > without.body_cbor.len());
    }

    #[test]
    fn coin_only_change_below_min_ada_is_rejected() {
        // 0.5 ADA of change after the fee passes the fee arithmetic but is
        // below the ~0.86 ADA min-UTxO for a coin-only output — must fail at
        // build time, not at the node after the signing ceremony.
        let err = build_drep_delegation_body(&DRepDelegationInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 700_000,
            change_assets: &[],
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            stake_credential_bech32: "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            drep_choice: DRepChoice::Abstain,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        })
        .unwrap_err();
        assert!(matches!(err, TxBuildError::InsufficientInputs { .. }));
    }

    #[test]
    fn withdrawal_rejects_reward_output_below_min_ada() {
        // 0.5 ADA of accumulated rewards passes the handler's has-rewards
        // check but builds a reward output below min-UTxO, which the ledger
        // rejects with OutputTooSmallUTxO only after the QR/PIN/sign dance.
        let err = build_withdrawal_body(&WithdrawalInputs {
            utxo_inputs: &[TxInput {
                tx_hash_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                tx_index: 0,
            }],
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            reward_receive_address_bech32:
                "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am",
            pool_reward_address_bech32:
                "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            rewards_lovelace: 500_000,
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        })
        .unwrap_err();
        assert!(matches!(err, TxBuildError::InsufficientInputs { .. }));
    }

    // -----------------------------------------------------------------------
    // Pool update
    // -----------------------------------------------------------------------

    const PAYMENT: &str = "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw";
    const STAKE: &str = "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u";
    const VRF_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const META_HASH: &str = "fdd468da5cc4ac8431dcd7e2b3211666c73bc229f85879469f67f1d9d51d344d";

    fn test_pool_id() -> String {
        let hrp = bech32::Hrp::parse("pool").unwrap();
        bech32::encode::<bech32::Bech32>(hrp, &[11u8; 28]).unwrap()
    }

    fn test_utxo() -> Vec<TxInput> {
        vec![TxInput {
            tx_hash_hex: "0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            tx_index: 0,
        }]
    }

    fn pool_update_inputs<'a>(
        utxo_inputs: &'a [TxInput],
        pool_id_bech32: &'a str,
        owners: &'a [String],
        relays: &'a [RelayInput],
        metadata_url: Option<&'a str>,
        metadata_hash_hex: Option<&'a str>,
    ) -> PoolUpdateInputs<'a> {
        PoolUpdateInputs {
            utxo_inputs,
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: PAYMENT,
            pool_id_bech32,
            vrf_keyhash_hex: VRF_HEX,
            pledge_lovelace: 100_000_000,
            fixed_cost_lovelace: 340_000_000,
            margin_numerator: 1,
            margin_denominator: 20,
            reward_account_bech32: STAKE,
            pool_owner_stake_addresses: owners,
            relays,
            metadata_url,
            metadata_hash_hex,
            fee_lovelace: 250_000,
            ttl_slot: 2_000_000,
        }
    }

    #[test]
    fn pool_update_builds_with_and_without_metadata() {
        let pool_id = test_pool_id();
        let owners = [STAKE.to_string()];
        let utxo = test_utxo();
        let with = build_pool_update_body(&pool_update_inputs(
            &utxo,
            &pool_id,
            &owners,
            &[],
            Some("https://example.com/pool.json"),
            Some(META_HASH),
        ))
        .unwrap();
        let decoded: TransactionBody = minicbor::decode(&with.body_cbor).unwrap();
        assert!(decoded.certificates.is_some());
        let without =
            build_pool_update_body(&pool_update_inputs(&utxo, &pool_id, &owners, &[], None, None))
                .unwrap();
        assert!(with.body_cbor.len() > without.body_cbor.len());
    }

    #[test]
    fn pool_update_rejects_partial_metadata_pair() {
        let pool_id = test_pool_id();
        let owners = [STAKE.to_string()];
        let utxo = test_utxo();
        // URL without hash: must error, not silently drop the metadata from
        // the certificate while the sign request still carries it.
        assert!(build_pool_update_body(&pool_update_inputs(
            &utxo,
            &pool_id,
            &owners,
            &[],
            Some("https://example.com/pool.json"),
            None,
        ))
        .is_err());
        // Hash without URL: same.
        assert!(build_pool_update_body(&pool_update_inputs(
            &utxo,
            &pool_id,
            &owners,
            &[],
            None,
            Some(META_HASH),
        ))
        .is_err());
    }

    #[test]
    fn pool_update_enforces_metadata_url_cddl_limit() {
        let pool_id = test_pool_id();
        let owners = [STAKE.to_string()];
        let utxo = test_utxo();
        // 64 bytes is the CDDL maximum — accepted.
        let url_64 = "a".repeat(64);
        assert!(build_pool_update_body(&pool_update_inputs(
            &utxo,
            &pool_id,
            &owners,
            &[],
            Some(&url_64),
            Some(META_HASH),
        ))
        .is_ok());
        // 65 bytes — rejected at build time, before the signing ceremony.
        let url_65 = "a".repeat(65);
        assert!(build_pool_update_body(&pool_update_inputs(
            &utxo,
            &pool_id,
            &owners,
            &[],
            Some(&url_65),
            Some(META_HASH),
        ))
        .is_err());
    }

    #[test]
    fn pool_update_enforces_relay_dns_cddl_limit() {
        let pool_id = test_pool_id();
        let owners = [STAKE.to_string()];
        let utxo = test_utxo();
        // 64-byte dns_name is the CDDL maximum — accepted.
        let dns_64 = "a".repeat(64);
        let ok_relay = [RelayInput::SingleHostName { port: Some(3001), dns: dns_64 }];
        assert!(build_pool_update_body(&pool_update_inputs(
            &utxo, &pool_id, &owners, &ok_relay, None, None,
        ))
        .is_ok());
        // Over 64 bytes — rejected for both DNS relay kinds.
        let long_dns = "a".repeat(65);
        let single = [RelayInput::SingleHostName { port: Some(3001), dns: long_dns.clone() }];
        assert!(build_pool_update_body(&pool_update_inputs(
            &utxo, &pool_id, &owners, &single, None, None,
        ))
        .is_err());
        let multi = [RelayInput::MultiHostName { dns: long_dns }];
        assert!(build_pool_update_body(&pool_update_inputs(
            &utxo, &pool_id, &owners, &multi, None, None,
        ))
        .is_err());
    }

    #[test]
    fn vote_anchor_url_over_cddl_limit_is_rejected() {
        let pool_id_bech32 = test_pool_id();
        let utxo = test_utxo();
        let vote_inputs = |url: String| VoteInputs {
            utxo_inputs: &utxo,
            utxo_total_lovelace: 34_109_103,
            change_assets: &[],
            payment_address_bech32: PAYMENT,
            pool_id_bech32: &pool_id_bech32,
            action_tx_hash_hex:
                "fdd468da5cc4ac8431dcd7e2b3211666c73bc229f85879469f67f1d9d51d344d",
            action_index: 0,
            vote: VoteChoice::Yes,
            anchor: Some(VoteAnchorInput { url, hash_hex: META_HASH.into() }),
            fee_lovelace: 200_000,
            ttl_slot: 2_000_000,
        };
        // 128 bytes is the Conway maximum — accepted.
        assert!(build_vote_body(&vote_inputs("a".repeat(128))).is_ok());
        // 129 bytes — rejected at build time.
        let err = build_vote_body(&vote_inputs("a".repeat(129))).unwrap_err();
        // ... and classified as operator input, so the handler surfaces
        // the actionable message as invalid_input.
        let msg = cddl_len_violation(&err).expect("anchor cap must classify as operator input");
        assert!(msg.contains("128-byte"), "{msg}");
    }

    #[test]
    fn cddl_len_violations_are_classified_as_operator_input() {
        let pool_id = test_pool_id();
        let owners = [STAKE.to_string()];
        let utxo = test_utxo();
        // Oversized relay DNS name -> classified: the handler maps it to
        // ErrorEnvelope::invalid with the specific message.
        let long_dns = [RelayInput::MultiHostName { dns: "a".repeat(65) }];
        let err = build_pool_update_body(&pool_update_inputs(
            &utxo, &pool_id, &owners, &long_dns, None, None,
        ))
        .unwrap_err();
        let msg = cddl_len_violation(&err).expect("dns cap must classify as operator input");
        assert!(msg.contains("64-byte"), "{msg}");
        // Oversized metadata URL -> classified too.
        let long_url = "a".repeat(65);
        let err = build_pool_update_body(&pool_update_inputs(
            &utxo, &pool_id, &owners, &[], Some(&long_url), Some(META_HASH),
        ))
        .unwrap_err();
        assert!(cddl_len_violation(&err).is_some());
        // A different Cbor-variant build error (partial metadata pair)
        // must NOT classify — it stays an internal envelope.
        let err = build_pool_update_body(&pool_update_inputs(
            &utxo, &pool_id, &owners, &[], Some("https://example.com/pool.json"), None,
        ))
        .unwrap_err();
        assert!(cddl_len_violation(&err).is_none());
    }
}
