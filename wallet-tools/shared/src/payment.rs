//! Payment (send) request/result: wire format between online tool and
//! signer.
//!
//! Sends ADA and/or native assets from the wallet's payment address to a
//! destination. The online tool selects inputs, computes the fee and the
//! min-ADA change back to the payment address, and builds the unsigned
//! Conway body. The signer re-decodes that body, shows the destination,
//! amount, assets and fee on its own air-gapped screen for the operator to
//! verify, and produces a single Payment witness.

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
pub struct PaymentRequest {
    /// Always [`WalletWireKind::Payment`].
    pub kind: WalletWireKind,
    /// Hex-encoded CBOR of the Conway TransactionBody.
    pub tx_body_cbor_hex: String,
    /// Where the funds go.
    pub destination_address_bech32: String,
    /// ADA sent to the destination.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub amount_lovelace: u64,
    /// Native assets sent to the destination (empty for a pure-ADA send).
    pub assets_sent: Vec<Asset>,
    /// Network fee.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    /// ADA returned to the payment address as change.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_lovelace: u64,
    /// Native-asset change returned to the payment address.
    pub change_assets: Vec<Asset>,
    /// Time-to-live (absolute slot) after which the tx is invalid.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    /// The wallet's own address: source of inputs and recipient of change.
    pub payment_address_bech32: String,
    /// UTxOs the online tool selected to fund this transaction.
    pub inputs: Vec<UtxoInput>,
    /// Operator-presence proof: blake2b PIN proof bound to this body.
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
    /// Optional CIP-20 (label 674) transaction message: one or more lines,
    /// each <=64 bytes UTF-8. When present, the body commits its
    /// blake2b-256 in `auxiliary_data_hash` and the submit step splices the
    /// metadata into the signed transaction. Absent: no auxiliary data. A
    /// signer that predates this field rejects any request carrying it
    /// (deny_unknown_fields), since it cannot verify the binding.
    #[serde(default)]
    pub metadata_msg: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct PaymentResult {
    pub body_hash_hex: String,
    /// A single Payment witness over the body hash.
    pub witnesses: Vec<VkeyWitness>,
}
