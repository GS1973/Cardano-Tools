//! Reward-withdrawal request/result types — wire format between online
//! tool and signer.
//!
//! The signer is *pure crypto*. Everything Cardano-protocol-shaped (the
//! transaction body itself) arrives pre-built as raw CBOR bytes. The
//! signer decodes the body, validates that every critical field matches
//! the request fields below (see crate::tx_validator),
//! then hashes and signs.
//!
//! Amount and address fields are not just preview hints — they are the
//! authoritative description of the operation. The validator rejects any
//! body that does not match them, so a tampered body cannot be signed.

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use serde_with::{serde_as, DisplayFromStr};

use crate::chain_context::ChainContext;
use crate::utxo::UtxoInput;
use crate::witness::VkeyWitness;

/// Wire-level discriminator for WithdrawalRequest. The signer rejects payloads
/// whose `kind` does not deserialize to exactly this variant, eliminating
/// the type-confusion risk from the previous untagged JSON layout.

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct WithdrawalRequest {
    /// Wire-level discriminator. Always [`crate::wire_kind::WireKind::Withdrawal`].
    pub kind: crate::wire_kind::WireKind,
    /// Hex-encoded CBOR of the Conway TransactionBody. The signer
    /// decodes this with pallas to sanity-check + extract Blake2b-256.
    pub tx_body_cbor_hex: String,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub net_to_reward_address_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_to_payment_address_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    /// Bech32 of the addresses involved — purely for signer-side
    /// preview; the signer does not act on these strings.
    pub payment_address_bech32: String,
    pub reward_receive_address_bech32: String,
    pub pool_reward_address_bech32: String,
    /// UTxOs the online-tool selected to fund this transaction.
    /// Validator cross-checks each (tx_hash, tx_index) against
    /// body.inputs and verifies inputs[i].address ==
    /// payment_address_bech32 (operator-visible binding).
    pub inputs: Vec<UtxoInput>,
    /// Operator-PIN proof: 8 bytes (16 hex chars) of blake2b-256 over a
    /// domain-separated, length-prefixed preimage of the request kind,
    /// `chain_context.built_at_unix`, the request-body fingerprint
    /// (computed with this field blanked) and the operator's 4-digit PIN
    /// — see [`crate::pin`]. The operator types the PIN at QR-build time
    /// on the online tool; the signer prompts for the same PIN after
    /// decrypt and refuses to sign on mismatch. Operator-presence gate at
    /// the moment of signing.
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct WithdrawalResult {
    pub body_hash_hex: String,
    pub witnesses: Vec<VkeyWitness>,
}

