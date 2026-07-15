//! DRep update / refresh request/result — wire format between online tool
//! and signer.
//!
//! One `UpdateDRepCert` (no deposit). Two uses in one cert: point the
//! on-chain anchor at an updated CIP-119 manifest, and reset the activity
//! counter (a DRep that does not vote or refresh for `drep_activity`
//! epochs goes dormant). An update with the same anchor is a valid
//! keep-alive. Witnesses are Payment + DRep.

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

use crate::anchor::GovAnchor;
use crate::chain_context::ChainContext;
use crate::utxo::UtxoInput;
use crate::witness::VkeyWitness;
use crate::wire_kind::DrepWireKind;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct DRepUpdateRequest {
    /// Always [`DrepWireKind::DrepUpdate`].
    pub kind: DrepWireKind,
    pub tx_body_cbor_hex: String,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_to_payment_address_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    pub payment_address_bech32: String,
    pub drep_id_bech32: String,
    /// Optional new CIP-119 manifest anchor; absent → on-chain anchor is
    /// null (a bare keep-alive).
    pub anchor: Option<GovAnchor>,
    pub inputs: Vec<UtxoInput>,
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct DRepUpdateResult {
    pub body_hash_hex: String,
    pub witnesses: Vec<VkeyWitness>,
}
