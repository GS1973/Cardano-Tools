//! Online tool's persistent DRep configuration.
//!
//! Persists to `~/.config/drep-tools/online.json`. Holds only public
//! information: the DRep id, the payment address, an optional Koios API
//! key. No private keys.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OnlineConfig {
    /// The operator's DRep id (`drep1...`, CIP-105 or CIP-129). The action
    /// authority for every operation; its 28-byte key hash is the on-chain
    /// credential.
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub drep_id: Option<String>,
    /// Address that funds fees + the registration deposit and receives
    /// change.
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub payment_address: Option<String>,
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub koios_api_key: Option<String>,
    /// Base URL where the operator hosts their DRep manifest documents.
    /// Register/Update compose the full anchor URL as `base + filename`, so
    /// the operator only types the file name per manifest.
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub manifest_base_url: Option<String>,

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
}

pub fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".config/drep-tools")
        .join("online.json")
}

/// Load the on-disk config. A missing file is a normal first run and yields
/// the default config. Any other failure, an unreadable file or corrupt
/// JSON, is an error: silently substituting the default would let the next
/// `save` overwrite the operator's setup and pairing keys.
pub fn load(path: &Path) -> std::io::Result<OnlineConfig> {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "config file {} is corrupt (fix or remove it): {e}",
                    path.display()
                ),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(OnlineConfig::default()),
        Err(e) => Err(std::io::Error::new(
            e.kind(),
            format!("cannot read config file {}: {e}", path.display()),
        )),
    }
}

/// True iff drep_id and payment_address are configured.
pub fn is_configured(c: &OnlineConfig) -> bool {
    c.drep_id.is_some() && c.payment_address.is_some()
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
        let c = OnlineConfig {
            drep_id: Some("drep1abc".into()),
            payment_address: Some("addr1xyz".into()),
            ..OnlineConfig::default()
        };
        save(&path, &c).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.drep_id.as_deref(), Some("drep1abc"));
        assert_eq!(loaded.payment_address.as_deref(), Some("addr1xyz"));
        assert!(is_configured(&loaded));
    }

    #[test]
    fn validates_drep_hrp() {
        let drep = {
            let mut d = vec![0x22u8];
            d.extend_from_slice(&[0x11u8; 28]);
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("drep").unwrap(), &d).unwrap()
        };
        assert!(validate_bech32(&drep, "drep").is_ok());
        assert!(validate_bech32(&drep, "addr").is_err());
    }

    #[test]
    fn corrupt_file_is_an_error_and_is_left_alone() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("online.json");
        assert!(load(&path).is_ok(), "a missing file is a first run");
        std::fs::write(&path, "{not valid json").unwrap();
        let err = load(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("fix or remove it"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not valid json");
    }
}
