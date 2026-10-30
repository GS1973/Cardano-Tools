//! Cardano address derivation for the wallet.
//!
//! Builds the mainnet base address (`addr1q…`) and the stake/reward
//! address (`stake1…`) from a payment and a stake Ed25519 verification
//! key, using `pallas-addresses` so the encoding follows the ledger spec
//! exactly. A credential key-hash is blake2b-224 of the raw 32-byte
//! verification key: identical for plain and BIP32-extended keys, since
//! both expose a 32-byte public key.

use pallas_addresses::{
    Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart, StakeAddress,
};
use pallas_crypto::hash::Hash;

use crate::validate::blake2b224;

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("address encoding failed: {0}")]
    Encode(#[from] pallas_addresses::Error),
}

/// blake2b-224 of a 32-byte Ed25519 verification key: the on-chain
/// credential key-hash, as raw bytes.
pub fn key_hash_bytes(vkey: &[u8; 32]) -> [u8; 28] {
    blake2b224(vkey)
}

/// The same key-hash as a pallas `Hash<28>`, ready for address/cert
/// construction.
pub fn key_hash(vkey: &[u8; 32]) -> Hash<28> {
    Hash::from(key_hash_bytes(vkey))
}

/// Mainnet base address (`addr1q…`): payment key-hash + stake key-hash,
/// both key-controlled (never a script).
pub fn base_address_bech32(
    payment_vkey: &[u8; 32],
    stake_vkey: &[u8; 32],
) -> Result<String, AddressError> {
    let addr = ShelleyAddress::new(
        Network::Mainnet,
        ShelleyPaymentPart::key_hash(key_hash(payment_vkey)),
        ShelleyDelegationPart::key_hash(key_hash(stake_vkey)),
    );
    Ok(addr.to_bech32()?)
}

/// Mainnet enterprise address (`addr1v…`): a payment key-hash with no stake
/// part. Spendable, but cannot delegate (no stake credential). Used for
/// payment-only ("enterprise") wallets that hold a payment key but no stake key.
pub fn enterprise_address_bech32(payment_vkey: &[u8; 32]) -> Result<String, AddressError> {
    let addr = ShelleyAddress::new(
        Network::Mainnet,
        ShelleyPaymentPart::key_hash(key_hash(payment_vkey)),
        ShelleyDelegationPart::Null,
    );
    Ok(addr.to_bech32()?)
}

/// Mainnet stake/reward address (`stake1…`) for a stake verification key.
pub fn stake_address_bech32(stake_vkey: &[u8; 32]) -> Result<String, AddressError> {
    // pallas exposes no public `StakeAddress` constructor; build a Shelley
    // address whose delegation part is this stake key-hash and convert. The
    // conversion reads only the delegation part, the payment part is
    // discarded, so reusing the same hash there is harmless.
    let shelley = ShelleyAddress::new(
        Network::Mainnet,
        ShelleyPaymentPart::key_hash(key_hash(stake_vkey)),
        ShelleyDelegationPart::key_hash(key_hash(stake_vkey)),
    );
    let stake: StakeAddress = shelley.try_into()?;
    Ok(stake.to_bech32()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_addresses::Address;

    // Two distinct fixed verification keys. The bytes are hashed directly,
    // so they need not be valid curve points for key-hash derivation.
    const PAY_VKEY: [u8; 32] = [0x11; 32];
    const STAKE_VKEY: [u8; 32] = [0x22; 32];

    #[test]
    fn enterprise_has_addr1v_and_no_stake() {
        let ent = enterprise_address_bech32(&PAY_VKEY).unwrap();
        assert!(ent.starts_with("addr1v"), "ent = {ent}");
        let Address::Shelley(sh) = Address::from_bech32(&ent).unwrap() else {
            panic!("expected a Shelley address");
        };
        assert_eq!(*sh.payment().as_hash(), key_hash(&PAY_VKEY));
        assert!(
            sh.delegation().as_hash().is_none(),
            "enterprise has no stake part"
        );
        assert!(!sh.has_script());
    }

    #[test]
    fn base_and_stake_have_mainnet_prefixes() {
        let base = base_address_bech32(&PAY_VKEY, &STAKE_VKEY).unwrap();
        let stake = stake_address_bech32(&STAKE_VKEY).unwrap();
        assert!(base.starts_with("addr1q"), "base = {base}");
        assert!(stake.starts_with("stake1"), "stake = {stake}");
        assert_ne!(base, stake);
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            base_address_bech32(&PAY_VKEY, &STAKE_VKEY).unwrap(),
            base_address_bech32(&PAY_VKEY, &STAKE_VKEY).unwrap()
        );
    }

    #[test]
    fn base_address_round_trips_through_pallas_decoder() {
        let base = base_address_bech32(&PAY_VKEY, &STAKE_VKEY).unwrap();
        let Address::Shelley(sh) = Address::from_bech32(&base).unwrap() else {
            panic!("expected a Shelley address");
        };
        // The decoded credentials match exactly what we hashed in.
        assert_eq!(*sh.payment().as_hash(), key_hash(&PAY_VKEY));
        assert_eq!(*sh.delegation().as_hash().unwrap(), key_hash(&STAKE_VKEY));
        assert!(!sh.has_script(), "must be key-controlled, not a script");
    }

    #[test]
    fn stake_address_carries_the_stake_credential() {
        let stake = stake_address_bech32(&STAKE_VKEY).unwrap();
        let Address::Stake(st) = Address::from_bech32(&stake).unwrap() else {
            panic!("expected a stake address");
        };
        assert_eq!(*st.payload().as_hash(), key_hash(&STAKE_VKEY));
        assert!(!st.is_script());
    }
}
