//! Wallet witness-role label + vkey witness wire type.
//!
//! A payment produces a single **Payment** witness (spending the input
//! UTxOs). A delegation produces **Payment** + **Stake**: the payment key
//! pays the fee, the stake key authorises the (registration and)
//! delegation certificate. The role is carried on the wire so the signer's
//! preview and the online tool can label each witness; it is presentation
//! only: submission re-wraps every witness as a role-agnostic raw witness
//! (`airgap_core::tx::RawVkeyWitness`).
//!
//! This is Wallet Tools' own witness role, deliberately separate from SPO
//! Tools' (Payment / OwnerStake / RewardStake / Cold), which lives in
//! `airgap_core::witness` and is re-exported by spo-tools, and from DRep
//! Tools' product-local (Payment / Drep). Wallet Tools does not use that
//! module: its role enum and `VkeyWitness` are defined here because they
//! enumerate wallet-specific operations.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum WalletWitnessRole {
    /// Spends the input UTxOs at the wallet's payment address.
    Payment,
    /// The stake key: authorises stake registration, pool/DRep delegation
    /// and reward withdrawal.
    Stake,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct VkeyWitness {
    pub role: WalletWitnessRole,
    /// 32-byte ed25519 public key, hex-encoded.
    pub vkey_hex: String,
    /// 64-byte ed25519 signature over the body hash, hex-encoded.
    pub signature_hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_round_trips() {
        let w = VkeyWitness {
            role: WalletWitnessRole::Stake,
            vkey_hex: "aa".repeat(32),
            signature_hex: "bb".repeat(64),
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: VkeyWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(back.role, WalletWitnessRole::Stake);
        assert_eq!(back.vkey_hex, w.vkey_hex);
        assert_eq!(back.signature_hex, w.signature_hex);
    }

    #[test]
    fn role_serialises_snake_case() {
        assert_eq!(
            serde_json::to_string(&WalletWitnessRole::Payment).unwrap(),
            "\"payment\""
        );
        assert_eq!(
            serde_json::to_string(&WalletWitnessRole::Stake).unwrap(),
            "\"stake\""
        );
    }
}
