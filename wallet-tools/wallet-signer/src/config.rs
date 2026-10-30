//! Wallet signer's persistent key configuration.
//!
//! Persists to `~/.config/wallet-tools/signer.json` (mode 0600 on save).
//!
//! Key-isolation by construction: every entry holds **only** a payment key
//! path and a stake key path (plus the shared X25519 pairing keys). There is
//! no `cold_skey` and no `drep_skey` field: this binary cannot name, let
//! alone load, the pool cold key or a DRep key. A compromise of this signer
//! cannot reach the SPO or DRep roles' keys.
//!
//! The signer manages up to [`MAX_KEYS`] wallet key pairs. At signing time the
//! matching pair is selected by the base address derived from each pair's
//! verification keys, never by a label or any value the online tool supplies,
//! so a compromised online tool can only ask this signer to sign for an
//! address it actually controls.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of wallet key pairs the signer holds.
pub const MAX_KEYS: usize = 10;

/// One wallet's signing key pair: a human label plus the payment and stake
/// signing-key file paths. The label is for display only; key selection at
/// signing time is always by derived address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyEntry {
    pub label: String,
    pub payment_skey_path: String,
    pub stake_skey_path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignerConfig {
    /// The configured wallet key pairs (`≤ MAX_KEYS`).
    #[serde(default)]
    pub keys: Vec<KeyEntry>,

    /// Hex-encoded X25519 secret key for the encrypted-channel layer.
    /// Generated locally on first boot, never leaves this machine.
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub own_crypto_skey_hex: Option<String>,
    /// Hex-encoded X25519 public key of the paired online tool. Set during
    /// the pairing dance; cleared by re-pair. None means "not paired".
    #[serde(
        default,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub peer_crypto_pubkey_hex: Option<String>,

    /// Legacy single-wallet fields, read only for one-time migration into
    /// `keys` (see [`normalize`]). Never written back (`skip_serializing`).
    #[serde(
        default,
        skip_serializing,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub payment_skey_path: Option<String>,
    #[serde(
        default,
        skip_serializing,
        deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none"
    )]
    pub stake_skey_path: Option<String>,
}

/// Fold a legacy single-wallet config (`payment_skey_path` + `stake_skey_path`)
/// into a one-entry `keys` list, so configs written, or posted by a
/// pre-multi-wallet frontend, before this change keep working. Once `keys`
/// is populated the legacy fields are dropped.
pub fn normalize(c: &mut SignerConfig) {
    if c.keys.is_empty() {
        let pay = c.payment_skey_path.take();
        let stake = c.stake_skey_path.take();
        if pay.is_some() || stake.is_some() {
            c.keys.push(KeyEntry {
                label: "Wallet".to_string(),
                payment_skey_path: pay.unwrap_or_default(),
                stake_skey_path: stake.unwrap_or_default(),
            });
        }
    } else {
        c.payment_skey_path = None;
        c.stake_skey_path = None;
    }
}

pub fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".config/wallet-tools")
        .join("signer.json")
}

/// Load the on-disk config. A missing file is a normal first run and yields
/// the default config. Any other failure, an unreadable file or corrupt
/// JSON, is an error: silently substituting the default would let the next
/// `save` overwrite the operator's key paths and pairing keys.
pub fn load(path: &Path) -> std::io::Result<SignerConfig> {
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SignerConfig::default(),
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

/// [`load`] for a request handler: maps a corrupt or unreadable config file
/// to a 500 envelope instead of letting it become a silent default. The
/// signer's handlers load-then-save the config per request, so a defaulted
/// load here would let the next save destroy the pairing and key paths.
pub fn load_or_err() -> Result<SignerConfig, shared::error::ErrorEnvelope> {
    load(&config_path()).map_err(|e| {
        tracing::error!(error = %e, "failed to load signer config");
        shared::error::ErrorEnvelope::internal(
            "failed to load signer config. Fix or remove the corrupt config file",
        )
    })
}

/// True iff at least one key pair is configured. Proxy for "has been through
/// Setup at least once" → the locked-after-save UI.
pub fn is_configured(c: &SignerConfig) -> bool {
    !c.keys.is_empty()
}

pub fn save(path: &Path, c: &SignerConfig) -> std::io::Result<()> {
    shared::config_helpers::save_secure(path, c)
}

/// Ensure `own_crypto_skey_hex` is set; generate + persist if missing.
/// Returns the secret bytes either way. Called at boot and from pairing.
pub fn ensure_own_crypto_skey(
    path: &Path,
    c: &mut SignerConfig,
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

/// Returns `(own_skey, peer_pubkey)` if both are set, else `None`.
pub fn paired_keys(c: &SignerConfig) -> Option<(Zeroizing<[u8; 32]>, [u8; 32])> {
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
        let path = tmp.path().join("signer.json");
        let mut c = SignerConfig::default();
        c.keys.push(KeyEntry {
            label: "Main".into(),
            payment_skey_path: "/secure/payment.skey".into(),
            stake_skey_path: "/secure/stake.skey".into(),
        });
        save(&path, &c).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys[0].payment_skey_path, "/secure/payment.skey");
        assert_eq!(loaded.keys[0].stake_skey_path, "/secure/stake.skey");
        assert!(is_configured(&loaded));
    }

    #[test]
    fn migrates_legacy_single_wallet() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer.json");
        std::fs::write(
            &path,
            r#"{"payment_skey_path":"/k/p.skey","stake_skey_path":"/k/s.skey"}"#,
        )
        .unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys[0].label, "Wallet");
        assert_eq!(loaded.keys[0].payment_skey_path, "/k/p.skey");
        assert_eq!(loaded.keys[0].stake_skey_path, "/k/s.skey");
        assert!(loaded.payment_skey_path.is_none());
        assert!(is_configured(&loaded));
    }

    #[test]
    fn missing_file_is_a_first_run_default() {
        let tmp = TempDir::new().unwrap();
        let c = load(&tmp.path().join("signer.json")).unwrap();
        assert!(!is_configured(&c));
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_default() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer.json");
        std::fs::write(&path, "{not valid json").unwrap();
        let err = load(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
