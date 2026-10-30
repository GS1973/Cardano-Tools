//! DRep governance vote request/result: wire format between online tool
//! and signer.
//!
//! One `Voter::DRepKey(keyhash)` casting one vote on one governance action,
//! signed by the DRep key. Unlike the SPO vote, the picker offers **all**
//! open proposals: a DRep votes on every action type, including the
//! parameter changes an SPO cannot touch. Witnesses are Payment + DRep.

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

use crate::anchor::GovAnchor;
use crate::chain_context::ChainContext;
use crate::utxo::UtxoInput;
use crate::wire_kind::DrepWireKind;
use crate::witness::VkeyWitness;

/// The DRep's ballot on a governance action. Maps 1:1 to
/// `pallas_primitives::conway::Vote` at body-build time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum VoteChoice {
    No,
    Yes,
    Abstain,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct DRepVoteRequest {
    /// Always [`DrepWireKind::DrepVote`].
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
    /// The DRep casting this vote (`drep1...`). The body's single
    /// `Voter::DRepKey(keyhash)` must equal this id's 28-byte key hash, and
    /// the DRep key that signs must hash to it.
    pub drep_id_bech32: String,
    /// Governance action being voted on: 64-char hex of the proposal tx
    /// hash plus the proposal index: the action id the protocol uses.
    pub action_tx_hash_hex: String,
    pub action_index: u32,
    pub vote: VoteChoice,
    /// Optional CIP-136 rationale anchor; absent → on-chain anchor is null.
    pub anchor: Option<GovAnchor>,
    pub inputs: Vec<UtxoInput>,
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct DRepVoteResult {
    pub body_hash_hex: String,
    pub witnesses: Vec<VkeyWitness>,
}
