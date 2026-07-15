//! Governance metadata anchor — a public document URL plus the 32-byte
//! blake2b-256 hash of its contents.
//!
//! Used in three places: the CIP-119 manifest anchored by a register or
//! update cert, and the CIP-136 rationale anchored in a vote's
//! `VotingProcedure`. When absent the on-chain anchor is null, which is
//! valid. The on-chain anchor stores the hash, so the host need not be
//! trusted — the hash makes the document tamper-evident.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct GovAnchor {
    pub url: String,
    /// 64-char hex of the 32-byte blake2b-256 hash of the document.
    pub hash_hex: String,
}
