//! DRep registration request/result — wire format between online tool and
//! signer.
//!
//! The request carries the unsigned Conway tx body (one `RegDRepCert`,
//! one fee input, one change output) plus everything the offline signer
//! needs to render and re-validate it. The 500 ADA deposit is consumed by
//! the cert; witnesses are Payment + DRep.

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
pub struct DRepRegisterRequest {
    /// Always [`DrepWireKind::DrepRegister`].
    pub kind: DrepWireKind,
    /// Hex-encoded CBOR of the Conway TransactionBody.
    pub tx_body_cbor_hex: String,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_to_payment_address_lovelace: u64,
    /// Deposit locked by the cert (read from Koios `epoch_params.drep_deposit`).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub deposit_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    pub payment_address_bech32: String,
    /// The DRep being registered (`drep1...`). The body's cert credential
    /// must equal this id's 28-byte key hash, and the DRep key that signs
    /// must hash to it.
    pub drep_id_bech32: String,
    /// Optional CIP-119 manifest anchor; absent → on-chain anchor is null.
    pub anchor: Option<GovAnchor>,
    /// UTxOs the online tool selected to fund this transaction.
    pub inputs: Vec<UtxoInput>,
    /// Hex-encoded blake2b-256(PIN) truncated to 4 bytes (operator-presence
    /// proof typed at QR-build time and re-typed on the signer).
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct DRepRegisterResult {
    pub body_hash_hex: String,
    pub witnesses: Vec<VkeyWitness>,
}
