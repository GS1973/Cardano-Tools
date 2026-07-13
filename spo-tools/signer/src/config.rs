//! Signer's persistent key-path configuration.
//!
//! Persists to `~/.config/spo-tools/signer.json`. JSON instead of TOML
//! to avoid pulling a new crate just for human-edit aesthetics — this
//! file is GUI-managed anyway.
//!
//! The file is created with mode `0600` on save. Hand-editing is allowed
//! but not the primary UX; the Setup view writes/reads this file.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignerConfig {
    #[serde(default, deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none")]
    pub vrf_skey: Option<String>,
    #[serde(default, deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none")]
    pub cold_skey: Option<String>,
    #[serde(default, deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none")]
    pub owner_skey: Option<String>,
    #[serde(default, deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none")]
    pub reward_skey: Option<String>,
    #[serde(default, deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none")]
    pub payment_skey: Option<String>,

    /// Hex-encoded X25519 secret key for the encrypted-channel layer.
    /// Generated locally on first boot, never leaves this machine.
    #[serde(default, deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none")]
    pub own_crypto_skey_hex: Option<String>,
    /// Hex-encoded X25519 public key of the paired online tool. Set during
    /// the pairing dance; cleared by re-pair. None means "not paired".
    #[serde(default, deserialize_with = "shared::config_helpers::deserialize_empty_string_as_none")]
    pub peer_crypto_pubkey_hex: Option<String>,
}

/// The canonical on-disk location for this binary's config. Resolved
/// once at boot from `main`; handlers receive the resolved path through
/// AppState so the load/save helpers stay pure.
pub fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/spo-tools").join("signer.json")
}

pub fn load(path: &Path) -> SignerConfig {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => SignerConfig::default(),
    }
}

/// Fail-closed load for request handlers that then save (or persist a freshly
/// generated channel key). A corrupt or unreadable config becomes a 500
/// envelope instead of a silent default: the signer's handlers load-then-save
/// per request, so a defaulted load here would let the next save overwrite the
/// operator's key paths and pairing keys. A genuinely missing file is still a
/// normal first run and yields the default.
pub fn load_or_err() -> Result<SignerConfig, shared::error::ErrorEnvelope> {
    match fs::read_to_string(config_path()) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| {
            tracing::error!(error = %e, "signer config file is corrupt");
            shared::error::ErrorEnvelope::internal(
                "failed to load signer config — fix or remove the corrupt config file",
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SignerConfig::default()),
        Err(e) => {
            tracing::error!(error = %e, "cannot read signer config");
            Err(shared::error::ErrorEnvelope::internal(
                "failed to load signer config — cannot read the config file",
            ))
        }
    }
}

/// True iff at least one key is configured. Used as a proxy for
/// "has been through Setup at least once" → the locked-after-save UI.
pub fn is_configured(c: &SignerConfig) -> bool {
    c.vrf_skey.is_some()
        || c.cold_skey.is_some()
        || c.owner_skey.is_some()
        || c.reward_skey.is_some()
        || c.payment_skey.is_some()
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
        // Stored value is corrupt — regenerate.
    }
    let kp = shared::crypto::generate_keypair()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    c.own_crypto_skey_hex = Some(hex::encode(&kp.secret[..]));
    save(path, c)?;
    Ok(kp.secret)
}

/// Returns `(own_skey, peer_pubkey)` if both are set, else `None`. Used
/// as the pre-flight check in operational handlers — operations refuse
/// to run unpaired.
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

        let c = SignerConfig {
            vrf_skey: Some("/secure/vrf.skey".into()),
            cold_skey: Some("/secure/cold.skey".into()),
            ..SignerConfig::default()
        };
        save(&path, &c).unwrap();

        let loaded = load(&path);
        assert_eq!(loaded.vrf_skey.as_deref(), Some("/secure/vrf.skey"));
        assert_eq!(loaded.cold_skey.as_deref(), Some("/secure/cold.skey"));
        assert!(is_configured(&loaded));
    }

    #[test]
    fn missing_file_returns_default() {
        let c = load(Path::new("/nonexistent/path.json"));
        assert!(!is_configured(&c));
    }
}
