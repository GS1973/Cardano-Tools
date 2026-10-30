//! New-address export: signer → online.
//!
//! The signer generates the payment + stake key pair locally (the secrets
//! never leave the offline host) and exports only the public material, so
//! the online tool can display, fund, and watch the new wallet address.
//! Nothing here is secret; it is the result the operator carries back to
//! the online machine after creating an address on the air-gapped signer.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct NewAddressExport {
    /// Mainnet base address (`addr1q…`): fund and watch this.
    pub base_address_bech32: String,
    /// Mainnet stake/reward address (`stake1…`).
    pub stake_address_bech32: String,
    /// 32-byte payment verification key, hex.
    pub payment_vkey_hex: String,
    /// 32-byte stake verification key, hex.
    pub stake_vkey_hex: String,
    /// blake2b-224 of the payment vkey, hex.
    pub payment_keyhash_hex: String,
    /// blake2b-224 of the stake vkey, hex.
    pub stake_keyhash_hex: String,
}

impl NewAddressExport {
    /// True when every address and key hash in the export is the one its
    /// two verification keys derive. The export comes over the encrypted
    /// channel, but the check is cheap and keeps a garbled or mismatched
    /// export out of the address book.
    pub fn is_consistent(&self) -> bool {
        let key = |h: &str| -> Option<[u8; 32]> { hex::decode(h).ok()?.try_into().ok() };
        let (Some(payment), Some(stake)) = (key(&self.payment_vkey_hex), key(&self.stake_vkey_hex))
        else {
            return false;
        };
        crate::address::base_address_bech32(&payment, &stake)
            .ok()
            .as_deref()
            == Some(self.base_address_bech32.as_str())
            && crate::address::stake_address_bech32(&stake).ok().as_deref()
                == Some(self.stake_address_bech32.as_str())
            && hex::encode(crate::address::key_hash_bytes(&payment)) == self.payment_keyhash_hex
            && hex::encode(crate::address::key_hash_bytes(&stake)) == self.stake_keyhash_hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export_of(payment: [u8; 32], stake: [u8; 32]) -> NewAddressExport {
        NewAddressExport {
            base_address_bech32: crate::address::base_address_bech32(&payment, &stake).unwrap(),
            stake_address_bech32: crate::address::stake_address_bech32(&stake).unwrap(),
            payment_vkey_hex: hex::encode(payment),
            stake_vkey_hex: hex::encode(stake),
            payment_keyhash_hex: hex::encode(crate::address::key_hash_bytes(&payment)),
            stake_keyhash_hex: hex::encode(crate::address::key_hash_bytes(&stake)),
        }
    }

    #[test]
    fn an_export_must_match_its_own_keys() {
        assert!(export_of([1; 32], [2; 32]).is_consistent());
        let other = export_of([3; 32], [4; 32]);
        let mut e = export_of([1; 32], [2; 32]);
        e.base_address_bech32 = other.base_address_bech32.clone();
        assert!(!e.is_consistent());
        let mut e = export_of([1; 32], [2; 32]);
        e.stake_address_bech32 = other.stake_address_bech32.clone();
        assert!(!e.is_consistent());
        let mut e = export_of([1; 32], [2; 32]);
        e.payment_keyhash_hex = other.payment_keyhash_hex.clone();
        assert!(!e.is_consistent());
        let mut e = export_of([1; 32], [2; 32]);
        e.stake_vkey_hex = "zz".into();
        assert!(!e.is_consistent());
    }
}
