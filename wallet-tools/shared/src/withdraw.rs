//! Reward-withdrawal request/result: wire format between online tool and
//! signer.
//!
//! Moves the stake key's accumulated rewards from its reward account to the
//! wallet's own payment address. The ledger only accepts a withdrawal of the
//! exact account balance, so the amount is not an operator choice: it is the
//! full balance the online tool read from the chain. The rewards join the
//! funding inputs in the single change output back to the payment address,
//! so nothing in this transaction can leave the wallet except the fee.
//! Signed by Payment (spends the funding inputs) + Stake (authorises the
//! withdrawal).

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

use crate::asset::Asset;
use crate::chain_context::ChainContext;
use crate::utxo::UtxoInput;
use crate::wire_kind::WalletWireKind;
use crate::witness::VkeyWitness;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct WithdrawRewardsRequest {
    /// Always [`WalletWireKind::WithdrawRewards`].
    pub kind: WalletWireKind,
    pub tx_body_cbor_hex: String,
    /// Rewards withdrawn from the reward account (its full balance).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub rewards_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    /// ADA returned to the payment address: funding inputs + rewards - fee.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_lovelace: u64,
    /// Native assets on the funding inputs, returned to the payment address.
    pub change_assets: Vec<Asset>,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    pub payment_address_bech32: String,
    /// The reward account being emptied (`stake1...`).
    pub stake_address_bech32: String,
    pub inputs: Vec<UtxoInput>,
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct WithdrawRewardsResult {
    pub body_hash_hex: String,
    /// Payment + Stake witnesses over the body hash.
    pub witnesses: Vec<VkeyWitness>,
}
