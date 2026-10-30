//! DRep retirement request/result: wire format between online tool and
//! signer.
//!
//! One `UnRegDRepCert` carrying the deposit being refunded. The refund
//! must equal what was locked at registration (the protocol checks this),
//! so the online tool reads it from Koios `drep_info.deposit`, not from
//! the current `drep_deposit` param: they can differ if the param changed
//! meanwhile. Change = inputs − fee + refund. Witnesses are Payment +
//! DRep.

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

use crate::chain_context::ChainContext;
use crate::utxo::UtxoInput;
use crate::wire_kind::DrepWireKind;
use crate::witness::VkeyWitness;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct DRepRetireRequest {
    /// Always [`DrepWireKind::DrepRetire`].
    pub kind: DrepWireKind,
    pub tx_body_cbor_hex: String,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_to_payment_address_lovelace: u64,
    /// Deposit refunded by the cert (read from Koios `drep_info.deposit`).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub deposit_refund_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    pub payment_address_bech32: String,
    pub drep_id_bech32: String,
    pub inputs: Vec<UtxoInput>,
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct DRepRetireResult {
    pub body_hash_hex: String,
    pub witnesses: Vec<VkeyWitness>,
}
