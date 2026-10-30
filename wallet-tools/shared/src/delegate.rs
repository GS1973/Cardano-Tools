//! Pool- and DRep-delegation request/result: wire format between online
//! tool and signer.
//!
//! Both delegate the wallet's stake key and are signed by Payment + Stake.
//! When the stake key is not yet registered on-chain, the online tool folds
//! a stake-registration certificate (with its key deposit) into the same
//! Conway transaction, so registration and delegation happen in one signing
//! (`register_stake = true`, `deposit_lovelace` set).

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
pub struct PoolDelegateRequest {
    /// Always [`WalletWireKind::PoolDelegate`].
    pub kind: WalletWireKind,
    pub tx_body_cbor_hex: String,
    /// The stake pool to delegate to (`pool1...`).
    pub pool_id_bech32: String,
    /// Whether a stake-registration certificate is folded into this tx.
    pub register_stake: bool,
    /// Stake-key deposit locked by the registration cert (0 when not registering).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub deposit_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_lovelace: u64,
    /// Native-asset change returned to the payment address (if coin-selection
    /// pulled an asset-bearing UTxO to fund the fee/deposit).
    pub change_assets: Vec<Asset>,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    pub payment_address_bech32: String,
    /// The stake address being delegated (`stake1...`).
    pub stake_address_bech32: String,
    pub inputs: Vec<UtxoInput>,
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

/// Where a DRep delegation points the stake key's voting power.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum DrepTarget {
    /// Always abstain (predefined DRep).
    Abstain,
    /// Vote no-confidence on everything (predefined DRep).
    NoConfidence,
    /// A specific registered DRep (`drep1...`).
    Drep(String),
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct DrepDelegateRequest {
    /// Always [`WalletWireKind::DrepDelegate`].
    pub kind: WalletWireKind,
    pub tx_body_cbor_hex: String,
    /// Where voting power is delegated.
    pub target: DrepTarget,
    pub register_stake: bool,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub deposit_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_lovelace: u64,
    /// Native-asset change returned to the payment address (if coin-selection
    /// pulled an asset-bearing UTxO to fund the fee/deposit).
    pub change_assets: Vec<Asset>,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    pub payment_address_bech32: String,
    pub stake_address_bech32: String,
    pub inputs: Vec<UtxoInput>,
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct DelegateResult {
    pub body_hash_hex: String,
    /// Payment + Stake witnesses over the body hash.
    pub witnesses: Vec<VkeyWitness>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drep_target_round_trips() {
        for t in [
            DrepTarget::Abstain,
            DrepTarget::NoConfidence,
            DrepTarget::Drep("drep1abc".into()),
        ] {
            let json = serde_json::to_string(&t).unwrap();
            let back: DrepTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn predefined_targets_serialise_snake_case() {
        assert_eq!(
            serde_json::to_string(&DrepTarget::Abstain).unwrap(),
            "\"abstain\""
        );
        assert_eq!(
            serde_json::to_string(&DrepTarget::NoConfidence).unwrap(),
            "\"no_confidence\""
        );
    }
}
