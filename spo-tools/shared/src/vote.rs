//! SPO governance vote request/result types: wire format between online
//! tool and signer.
//!
//! Same structure as the DRep-delegation flow: the request carries the
//! unsigned Conway tx body CBOR, and the signer hashes it and signs with
//! the payment skey (fee input) plus the cold skey (the pool's voting
//! authority: the cold key's hash is the pool id that the on-chain
//! `Voter::StakePoolKey` names).

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

use crate::chain_context::ChainContext;
use crate::utxo::UtxoInput;
use crate::witness::VkeyWitness;

/// Operator's ballot on a governance action. Maps 1:1 to
/// `pallas_primitives::conway::Vote` at body-build time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum VoteChoice {
    No,
    Yes,
    Abstain,
}

/// Optional public rationale for the vote: a document URL plus the
/// 32-byte hash of its contents, the same shape as pool metadata. When
/// absent the on-chain `VotingProcedure.anchor` is null, which is valid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct VoteAnchor {
    pub url: String,
    /// 64-char hex of the 32-byte blake2b-256 hash of the document.
    pub hash_hex: String,
}

/// Wire-level discriminator for VoteRequest. The signer rejects payloads
/// whose `kind` does not deserialize to exactly this variant, eliminating
/// type-confusion across the five other request shapes.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct VoteRequest {
    /// Wire-level discriminator. Always [`crate::wire_kind::WireKind::Vote`].
    pub kind: crate::wire_kind::WireKind,
    /// Hex-encoded CBOR of the Conway TransactionBody.
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
    /// Bech32 strings for signer-side preview.
    pub payment_address_bech32: String,
    /// Pool whose cold key casts this vote (`pool1...`). The body's
    /// single `Voter::StakePoolKey(hash)` must equal this pool id, and
    /// the cold key that signs must hash to it.
    pub pool_id_bech32: String,
    /// Governance action being voted on: 64-char hex of the proposal tx
    /// hash plus the proposal index. Together they are the action id the
    /// protocol uses: the source of truth, shown to the operator.
    pub action_tx_hash_hex: String,
    pub action_index: u32,
    pub vote: VoteChoice,
    /// Optional rationale anchor; absent → on-chain anchor is null.
    pub anchor: Option<VoteAnchor>,
    /// UTxOs the online-tool selected to fund this transaction.
    /// Validator cross-checks each (tx_hash, tx_index) against
    /// body.inputs and verifies inputs[i].address ==
    /// payment_address_bech32 (operator-visible binding).
    pub inputs: Vec<UtxoInput>,
    /// Operator-PIN proof: 8 bytes (16 hex chars) of blake2b-256 over a
    /// domain-separated, length-prefixed preimage of the request kind,
    /// `chain_context.built_at_unix`, the request-body fingerprint
    /// (computed with this field blanked) and the operator's 4-digit PIN:
    /// see [`crate::pin`]. The operator types the PIN at QR-build time
    /// on the online tool; the signer prompts for the same PIN after
    /// decrypt and refuses to sign on mismatch. Operator-presence gate at
    /// the moment of signing.
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct VoteResult {
    pub body_hash_hex: String,
    pub witnesses: Vec<VkeyWitness>,
}
