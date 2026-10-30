//! Online tool's persistent wallet configuration.
//!
//! Persists to `~/.config/wallet-tools/online.json`. Holds only public
//! information: an address book of wallet + destination addresses, an
//! optional Koios API key, and the X25519 pairing keys. No private keys.
//!
//! The address book mixes the operator's **own** wallets (signable; their
//! signing keys live on the air-gapped signer) with **external** destination
//! addresses (watch / send-to only). Own entries are the source a payment or
//! delegation funds from; any entry, own or external, can be a destination.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of own (signable) wallet addresses. External destinations
/// are not capped.
pub const MAX_OWN_ADDRESSES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressKind {
    /// One of the operator's own wallets: signable, a valid funding source.
    Own,
    /// A destination address only: no signing key, send-to / watch only.
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    pub label: String,
    pub address: String,
    pub kind: AddressKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OnlineConfig {
    /// Labelled wallet + destination addresses.
    #[serde(default)]
    pub address_book: Vec<AddressEntry>,
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub koios_api_key: Option<String>,

    /// Hex-encoded X25519 secret key for the encrypted-channel layer.
    /// Generated locally on first boot, never leaves this machine.
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub own_crypto_skey_hex: Option<String>,
    /// Hex-encoded X25519 public key of the paired signer. None = not paired.
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub peer_crypto_pubkey_hex: Option<String>,

    /// Legacy single-wallet field, read only for one-time migration into
    /// `address_book` (see [`normalize`]). Never written back.
    #[serde(
        default,
        skip_serializing,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub payment_address: Option<String>,
}

/// Fold a legacy single-wallet config (`payment_address`) into a one-entry
/// `address_book` (an Own wallet labelled "Wallet"), so configs written before
/// the address-book change keep their wallet. Once the book is populated the
/// legacy field is dropped.
pub fn normalize(c: &mut OnlineConfig) {
    if c.address_book.is_empty() {
        if let Some(addr) = c.payment_address.take() {
            c.address_book.push(AddressEntry {
                label: "Wallet".to_string(),
                address: addr,
                kind: AddressKind::Own,
            });
        }
    } else {
        c.payment_address = None;
    }
}

pub fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".config/wallet-tools")
        .join("online.json")
}

/// Load the on-disk config. A missing file is a normal first run and yields
/// the default config. Any other failure, an unreadable file or corrupt
/// JSON, is an error: silently substituting the default would let the next
/// `save` overwrite the operator's address book and pairing keys.
pub fn load(path: &Path) -> std::io::Result<OnlineConfig> {
    let mut c = match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "config file {} is corrupt (fix or remove it): {e}",
                    path.display()
                ),
            )
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => OnlineConfig::default(),
        Err(e) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("cannot read config file {}: {e}", path.display()),
            ))
        }
    };
    normalize(&mut c);
    Ok(c)
}

/// Addresses of the operator's own (signable) wallets, in book order.
pub fn own_addresses(c: &OnlineConfig) -> Vec<&str> {
    c.address_book
        .iter()
        .filter(|e| e.kind == AddressKind::Own)
        .map(|e| e.address.as_str())
        .collect()
}

/// True iff at least one own (signable) wallet is configured.
pub fn is_configured(c: &OnlineConfig) -> bool {
    c.address_book.iter().any(|e| e.kind == AddressKind::Own)
}

pub fn save(path: &Path, c: &OnlineConfig) -> std::io::Result<()> {
    shared::config_helpers::save_secure(path, c)
}

/// Validate a bech32 string and check its HRP.
pub fn validate_bech32(s: &str, expected_hrp: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty".into());
    }
    let (hrp, _data) = bech32::decode(s).map_err(|e| format!("invalid bech32: {e}"))?;
    if hrp.as_str() != expected_hrp {
        return Err(format!(
            "wrong prefix: expected `{expected_hrp}1...`, got `{}1...`",
            hrp.as_str()
        ));
    }
    Ok(())
}

pub fn ensure_own_crypto_skey(
    path: &Path,
    c: &mut OnlineConfig,
) -> std::io::Result<Zeroizing<[u8; 32]>> {
    if let Some(hex_str) = &c.own_crypto_skey_hex {
        if let Ok(mut bytes) = hex::decode(hex_str) {
            if bytes.len() == 32 {
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(&bytes);
                bytes.zeroize();
                return Ok(out);
            }
            bytes.zeroize();
        }
        // Stored value is corrupt: regenerate.
    }
    let kp =
        shared::crypto::generate_keypair().map_err(|e| std::io::Error::other(e.to_string()))?;
    c.own_crypto_skey_hex = Some(hex::encode(&kp.secret[..]));
    save(path, c)?;
    Ok(kp.secret)
}

pub fn paired_keys(c: &OnlineConfig) -> Option<(Zeroizing<[u8; 32]>, [u8; 32])> {
    shared::config_helpers::paired_keys_from_hex(
        c.own_crypto_skey_hex.as_deref(),
        c.peer_crypto_pubkey_hex.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn round_trips_through_disk() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("online.json");
        let mut c = OnlineConfig::default();
        c.address_book.push(AddressEntry {
            label: "Main".into(),
            address: "addr1xyz".into(),
            kind: AddressKind::Own,
        });
        save(&path, &c).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.address_book.len(), 1);
        assert_eq!(own_addresses(&loaded), vec!["addr1xyz"]);
        assert!(is_configured(&loaded));
    }

    #[test]
    fn migrates_legacy_payment_address() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("online.json");
        std::fs::write(&path, r#"{"payment_address":"addr1legacy"}"#).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.address_book.len(), 1);
        assert_eq!(loaded.address_book[0].label, "Wallet");
        assert_eq!(loaded.address_book[0].address, "addr1legacy");
        assert_eq!(loaded.address_book[0].kind, AddressKind::Own);
        assert!(loaded.payment_address.is_none());
        assert!(is_configured(&loaded));
    }

    #[test]
    fn missing_file_is_a_first_run_default() {
        let tmp = TempDir::new().unwrap();
        let loaded = load(&tmp.path().join("online.json")).unwrap();
        assert!(loaded.address_book.is_empty());
        assert!(!is_configured(&loaded));
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_default() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("online.json");
        std::fs::write(&path, "{not valid json").unwrap();
        let err = load(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn external_only_is_not_configured() {
        let mut c = OnlineConfig::default();
        c.address_book.push(AddressEntry {
            label: "Exchange".into(),
            address: "addr1ext".into(),
            kind: AddressKind::External,
        });
        assert!(!is_configured(&c));
        assert!(own_addresses(&c).is_empty());
    }

    #[test]
    fn validates_addr_hrp() {
        let addr = shared::address::base_address_bech32(&[0x11; 32], &[0x22; 32]).unwrap();
        assert!(validate_bech32(&addr, "addr").is_ok());
        assert!(validate_bech32(&addr, "stake").is_err());
    }
}
