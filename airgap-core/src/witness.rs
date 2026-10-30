//! SPO Tools witness role + vkey witness wire types.
//!
//! This module defines **SPO Tools'** witness-role enum (Payment /
//! OwnerStake / RewardStake / Cold) and its `VkeyWitness` wire type,
//! consumed via the spo-tools shared crate's re-export
//! (`pub use airgap_core::{.., witness}`). SPO's three feature-specific
//! request/result modules (withdrawal, drep, pool_update) all carry a
//! list of `VkeyWitness` items keyed by a `WitnessRole`.
//!
//! It is not a suite-wide single source of truth: Wallet Tools and DRep
//! Tools deliberately define their own product-local role enums
//! (`WalletWitnessRole` in wallet-tools' shared crate, `DrepWitnessRole`
//! in drep-tools'), since each enumerates product-specific operations.
//!
//! v1.0 design note: each SPO feature uses only a subset of the variants
//! (withdrawal: Payment + RewardStake; drep: Payment + OwnerStake;
//! pool_update: Payment + Cold + OwnerStake). The single shared enum
//! keeps the wire format flat and the signer dispatcher simple, at the
//! cost that the type system does not enforce per-feature subsets:
//! producing code is the gate. A future revision could split into
//! three feature-specific enums to lift this into the type system; the
//! cost is more wire types and more `From`-style boilerplate, so the
//! trade-off is intentional for v1.0.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../frontend/src/types/core-wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum WitnessRole {
    /// Spends the input UTXO at the configured payment_address.
    Payment,
    /// Authorises an action on the pool's stake credential (DRep
    /// delegation, pool registration with pledge).
    OwnerStake,
    /// Authorises a reward-account withdrawal. For single-owner pools this is typically the
    /// same key as `OwnerStake`; the wire name stays distinct so the
    /// signer's preview can label the operation correctly.
    RewardStake,
    /// Pool operator (cold) key: used only for pool registration /
    /// re-registration.
    Cold,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../frontend/src/types/core-wire.ts")]
pub struct VkeyWitness {
    pub role: WitnessRole,
    /// 32-byte ed25519 public key, hex-encoded.
    pub vkey_hex: String,
    /// 64-byte ed25519 signature over the body hash, hex-encoded.
    pub signature_hex: String,
}
