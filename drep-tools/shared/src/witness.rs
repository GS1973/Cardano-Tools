//! DRep witness-role label + vkey witness wire type.
//!
//! Every DRep operation produces exactly two vkey witnesses: the
//! **Payment** key spends the fee input, and the **Drep** key authorises
//! the action (cert or vote). The role is carried on the wire so the
//! signer's preview and the online tool can label each witness; the role
//! is presentation only — submission re-wraps both as role-agnostic raw
//! witnesses (`airgap_core::tx::RawVkeyWitness`).
//!
//! This is DRep Tools' own witness role, deliberately separate from SPO
//! Tools' (Payment / OwnerStake / RewardStake / Cold), which lives in
//! `airgap_core::witness` and is re-exported by spo-tools. DRep Tools
//! does not use that module: its role enum and `VkeyWitness` are defined
//! here because they enumerate DRep-specific operations.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum DrepWitnessRole {
    /// Spends the input UTXO at the configured payment_address.
    Payment,
    /// The DRep key — authorises the registration, update, retirement, or
    /// vote. Its verification key hashes (blake2b-224) to the DRep id.
    Drep,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct VkeyWitness {
    pub role: DrepWitnessRole,
    /// 32-byte ed25519 public key, hex-encoded.
    pub vkey_hex: String,
    /// 64-byte ed25519 signature over the body hash, hex-encoded.
    pub signature_hex: String,
}
