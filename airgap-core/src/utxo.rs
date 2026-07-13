//! Shared UtxoInput type used by all 3 sign-request types.
//!
//! The signer cannot independently see the chain. To validate that the
//! body's TransactionInputs were chosen from the operator's own payment
//! address (not, say, from a separate base-form pledge address that
//! shares the same payment.skey — see SECURITY.md "Assumptions"), the
//! online tool sends the inputs alongside the body. The signer's
//! tx_validator then cross-checks two things:
//!
//! 1. each (tx_hash, tx_index) in `request.inputs` appears in
//!    `body.inputs`, and vice-versa,
//! 2. every `request.inputs[i].address` equals the request's
//!    `payment_address_bech32`.
//!
//! Architectural limit: a compromised online tool can lie about the
//! `address` field (signer is air-gapped, cannot consult the chain).
//! The signer-UI surfaces inputs prominently with a red label on
//! address-mismatch so the operator notices visually.

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../frontend/src/types/core-wire.ts")]
#[serde(deny_unknown_fields)]
pub struct UtxoInput {
    /// 64-char hex of the funding tx hash. Bounded by tx-builder via
    /// `hex::decode` + len-32 check.
    pub tx_hash_hex: String,
    pub tx_index: u32,
    /// Lovelace at this UTxO. Wire-encoded as string (industry pattern
    /// for Cardano/NEAR/Solana — JS Number loses precision >2^53).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub amount_lovelace: u64,
    /// Bech32 address that holds this UTxO. Per the body validator,
    /// this MUST equal the request's `payment_address_bech32`.
    pub address_bech32: String,
}

/// A wallet UTxO available to fund a transaction, with the native assets it
/// carries. Builder-internal (not a wire type): the online tool selects from
/// these and the change builder preserves their assets.
#[derive(Debug, Clone)]
pub struct OwnedUtxo {
    pub tx_hash_hex: String,
    pub tx_index: u32,
    pub lovelace: u64,
    pub assets: Vec<crate::asset::Asset>,
}
