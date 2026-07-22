//! DRep rationale-witness request/result: wire format between the online
//! tool and the signer.
//!
//! Unlike the four transaction operations, this request carries no
//! transaction. It asks the signer to produce a CIP-100 author witness over
//! a governance-metadata canonical body (the N-Quads a vote rationale
//! serialises to). The signer signs blake2b-256 of that body with the DRep
//! key, but only after checking the payload is a canonical body and that the
//! key hashes to the request's DRep id, so the witness publicKey is
//! verifiably the operator's DRep.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::chain_context::ChainContext;
use crate::wire_kind::DrepWireKind;

/// A CIP-100 author witness, embedded in an author entry of governance
/// metadata (CIP-108 / CIP-119 / CIP-136).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct Cip100Witness {
    /// Always "ed25519".
    pub witness_algorithm: String,
    /// 32-byte ed25519 verification key, hex.
    pub public_key_hex: String,
    /// 64-byte ed25519 signature over blake2b-256 of the canonical body, hex.
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct DRepWitnessRequest {
    /// Always [`DrepWireKind::DrepWitnessDoc`].
    pub kind: DrepWireKind,
    /// CIP-100 canonical body (N-Quads). Its blake2b-256 is the payload the
    /// witness signs. The signer refuses anything that is not a canonical
    /// body, so this key cannot be steered into signing a transaction hash.
    pub canonical_body: String,
    /// The DRep whose key witnesses the document. The signing key must hash
    /// (blake2b-224) to this id; its vkey becomes the witness publicKey.
    pub drep_id_bech32: String,
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct DRepWitnessResult {
    pub body_hash_hex: String,
    pub witness: Cip100Witness,
}
