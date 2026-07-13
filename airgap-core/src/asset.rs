//! Native-asset amount on the wire.
//!
//! A Cardano native asset is identified by its 28-byte minting policy id
//! and an asset name (0-32 bytes). Quantities are indivisible on-chain
//! integers; an asset's display decimals are a UI concern, not encoded
//! here. Defined once here so every tool shares the exact shape.

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../frontend/src/types/core-wire.ts")]
pub struct Asset {
    /// 28-byte minting policy id, hex-encoded.
    pub policy_hex: String,
    /// Asset name, hex-encoded (may be empty).
    pub asset_name_hex: String,
    /// Quantity in indivisible units.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub quantity: u64,
}
