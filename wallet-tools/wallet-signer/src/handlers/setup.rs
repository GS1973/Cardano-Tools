//! Setup endpoints: read / write signer config + per-key validation.
//!
//! `/api/signer-config` returns a redacted, per-wallet view (paths / hex
//! secrets are never reflected back). `/api/test-load` validates a single key
//! path the operator typed, gated by the same `list_dir` allow-list; saved
//! key paths are gated by it too.
//! `/api/generate-wallet-keys` derives a fresh payment + stake key pair onto
//! the operator-chosen removable drive.

use crate::{config, validate};
use shared::error::ErrorEnvelope;

#[derive(serde::Serialize)]
pub(crate) struct SignerConfigResponse {
    /// Whether at least one wallet key pair is configured.
    pub saved: bool,
    pub paired: bool,
    pub pairing_fingerprint: Option<String>,
    /// Per-wallet status, one entry per configured key pair.
    pub wallets: Vec<WalletStatus>,
}

#[derive(serde::Serialize)]
pub(crate) struct WalletStatus {
    pub label: String,
    /// Configured key paths, echoed so the Setup form can edit the list.
    /// These are file locations, not secrets; the skey contents never leave
    /// the signer.
    pub payment_skey_path: String,
    pub stake_skey_path: String,
    pub payment_skey: validate::ValidationResult,
    pub stake_skey: validate::ValidationResult,
    /// Wallet address derived from this entry's payment + stake keys. Public,
    /// so the operator can re-read it without re-running keygen. None when the
    /// two keys are not both validly configured.
    pub wallet_address: Option<WalletAddressInfo>,
}

#[derive(serde::Serialize)]
pub(crate) struct WalletAddressInfo {
    /// Mainnet base address (`addr1q…`): fund and watch this.
    pub base_address_bech32: String,
    /// Mainnet stake/reward address (`stake1…`). None for an enterprise wallet.
    pub stake_address_bech32: Option<String>,
    pub payment_keyhash_hex: String,
    /// None for an enterprise (payment-only) wallet.
    pub stake_keyhash_hex: Option<String>,
}

/// Read the public verification key from a configured skey path, accepting
/// both plain and extended payment/stake keys. None when absent, unreadable,
/// or the wrong role.
fn vkey_of(path: Option<&str>, want_payment: bool) -> Option<[u8; 32]> {
    let p = path?;
    let key = shared::cardano_keys::load_skey(std::path::Path::new(p)).ok()?;
    match (key, want_payment) {
        (shared::cardano_keys::CardanoKey::Payment { seed_32 }, true) => Some(
            ed25519_dalek::SigningKey::from_bytes(&seed_32)
                .verifying_key()
                .to_bytes(),
        ),
        (shared::cardano_keys::CardanoKey::PaymentExtended { pubkey_32, .. }, true) => {
            Some(pubkey_32)
        }
        (shared::cardano_keys::CardanoKey::Stake { seed_32 }, false) => Some(
            ed25519_dalek::SigningKey::from_bytes(&seed_32)
                .verifying_key()
                .to_bytes(),
        ),
        (shared::cardano_keys::CardanoKey::StakeExtended { pubkey_32, .. }, false) => {
            Some(pubkey_32)
        }
        _ => None,
    }
}

/// Derive the wallet address (base + stake) from a payment + stake skey path.
/// Both must be present and the right role. None otherwise.
fn derive_wallet_address(payment_path: &str, stake_path: &str) -> Option<WalletAddressInfo> {
    let pay_vkey = vkey_of(Some(payment_path), true)?;
    if stake_path.trim().is_empty() {
        // Enterprise (payment-only) wallet: addr1v from the payment key, no stake.
        return Some(WalletAddressInfo {
            base_address_bech32: shared::address::enterprise_address_bech32(&pay_vkey).ok()?,
            stake_address_bech32: None,
            payment_keyhash_hex: hex::encode(shared::address::key_hash_bytes(&pay_vkey)),
            stake_keyhash_hex: None,
        });
    }
    let stake_vkey = vkey_of(Some(stake_path), false)?;
    Some(WalletAddressInfo {
        base_address_bech32: shared::address::base_address_bech32(&pay_vkey, &stake_vkey).ok()?,
        stake_address_bech32: Some(shared::address::stake_address_bech32(&stake_vkey).ok()?),
        payment_keyhash_hex: hex::encode(shared::address::key_hash_bytes(&pay_vkey)),
        stake_keyhash_hex: Some(hex::encode(shared::address::key_hash_bytes(&stake_vkey))),
    })
}

fn wallet_status(entry: &config::KeyEntry) -> WalletStatus {
    WalletStatus {
        label: entry.label.clone(),
        payment_skey_path: entry.payment_skey_path.clone(),
        stake_skey_path: entry.stake_skey_path.clone(),
        payment_skey: validate::validate(
            Some(&entry.payment_skey_path),
            validate::KeyKind::Payment,
        ),
        stake_skey: validate::validate(Some(&entry.stake_skey_path), validate::KeyKind::Stake),
        wallet_address: derive_wallet_address(&entry.payment_skey_path, &entry.stake_skey_path),
    }
}

pub(crate) fn build_signer_config_response(c: &config::SignerConfig) -> SignerConfigResponse {
    let (paired, pairing_fingerprint) = shared::crypto::pairing_status(
        c.own_crypto_skey_hex.as_deref(),
        c.peer_crypto_pubkey_hex.as_deref(),
    );
    SignerConfigResponse {
        saved: config::is_configured(c),
        paired,
        pairing_fingerprint,
        wallets: c.keys.iter().map(wallet_status).collect(),
    }
}

pub(crate) async fn signer_config_get() -> Result<axum::Json<SignerConfigResponse>, ErrorEnvelope> {
    let c = config::load_or_err()?;
    Ok(axum::Json(build_signer_config_response(&c)))
}

/// Merge a Setup POST body over the existing on-disk config. The X25519
/// crypto fields are never accepted from the body, the pairing handlers
/// are their only writers (they reject low-order peer points and require
/// the operator-confirmed fingerprint), so they are always carried over
/// from disk, and anything the client supplied is discarded.
fn merge_setup_body(
    body: config::SignerConfig,
    existing: config::SignerConfig,
) -> config::SignerConfig {
    let mut merged = body;
    // Accept a legacy single-wallet body (or one from a pre-multi frontend).
    config::normalize(&mut merged);
    merged.own_crypto_skey_hex = existing.own_crypto_skey_hex;
    merged.peer_crypto_pubkey_hex = existing.peer_crypto_pubkey_hex;
    merged
}

/// Canonicalize one Setup-form key path in place and enforce the same
/// allow-list as `/api/test-load` and `/api/list-dir`. Persisting an
/// unvetted path would make the saved config a validation oracle for any
/// path the signer process can read (every GET `/api/signer-config`
/// re-runs `validate::validate` on it) and would let sign-time key loads
/// escape the vetted roots. The field is replaced with the canonicalised
/// path so later opens cannot be redirected by a symlink chain that
/// re-resolves elsewhere (same hygiene as `signer_test_load`).
fn vetted_key_path(field: &str, value: &mut String) -> Result<(), ErrorEnvelope> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        value.clear();
        return Ok(());
    }
    let canonical = std::path::PathBuf::from(trimmed)
        .canonicalize()
        .map_err(|e| {
            tracing::error!(error = %e, field, "signer-config canonicalize failed");
            ErrorEnvelope::invalid(format!("{field}: path does not exist"))
        })?;
    let allowed = crate::handlers::list_dir::list_dir_allowed_roots();
    if !allowed.iter().any(|root| canonical.starts_with(root)) {
        tracing::error!(path = %canonical.display(), field, "signer-config path outside allow-list");
        return Err(ErrorEnvelope::invalid(format!(
            "{field}: path is outside the allowed roots (/media, /mnt, /run/media)"
        )));
    }
    match canonical.into_os_string().into_string() {
        Ok(s) => {
            *value = s;
            Ok(())
        }
        Err(_) => Err(ErrorEnvelope::invalid(format!(
            "{field}: path is not valid UTF-8"
        ))),
    }
}

pub(crate) async fn signer_config_post(
    axum::Json(body): axum::Json<config::SignerConfig>,
) -> Result<axum::Json<SignerConfigResponse>, ErrorEnvelope> {
    let existing = config::load_or_err()?;
    let mut merged = merge_setup_body(body, existing);

    if merged.keys.len() > config::MAX_KEYS {
        return Err(ErrorEnvelope::invalid(format!(
            "at most {} wallets are supported",
            config::MAX_KEYS
        )));
    }
    for (i, k) in merged.keys.iter_mut().enumerate() {
        if k.label.trim().is_empty() {
            return Err(ErrorEnvelope::invalid(format!(
                "wallet {} is missing a label",
                i + 1
            )));
        }
        if k.payment_skey_path.trim().is_empty() {
            return Err(ErrorEnvelope::invalid(format!(
                "wallet '{}' needs a payment key path",
                k.label.trim()
            )));
        }
        // Every key path gets the same canonicalize + allowed-roots guard as
        // `/api/test-load`; an out-of-root path rejects the whole save.
        let label = k.label.trim().to_string();
        vetted_key_path(
            &format!("wallet '{label}' payment key"),
            &mut k.payment_skey_path,
        )?;
        vetted_key_path(
            &format!("wallet '{label}' stake key"),
            &mut k.stake_skey_path,
        )?;
    }

    config::save(&config::config_path(), &merged).map_err(|e| {
        tracing::error!(error = %e, "save signer config failed");
        ErrorEnvelope::internal("failed to persist state")
    })?;
    Ok(axum::Json(build_signer_config_response(&merged)))
}

#[derive(serde::Deserialize)]
pub(crate) struct TestLoadBody {
    kind: validate::KeyKind,
    path: String,
}

pub(crate) async fn signer_test_load(
    axum::Json(body): axum::Json<TestLoadBody>,
) -> axum::Json<validate::ValidationResult> {
    let trimmed = body.path.trim();
    if trimmed.is_empty() {
        return axum::Json(validate::ValidationResult::Missing);
    }
    let pb = std::path::PathBuf::from(trimmed);
    let canonical = match pb.canonicalize() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "test-load canonicalize failed");
            return axum::Json(validate::ValidationResult::Error {
                message: "path does not exist".into(),
            });
        }
    };
    let allowed = crate::handlers::list_dir::list_dir_allowed_roots();
    if !allowed.iter().any(|root| canonical.starts_with(root)) {
        tracing::error!(path = %canonical.display(), "test-load path outside allow-list");
        return axum::Json(validate::ValidationResult::Error {
            message: "path is outside the allowed roots (/media, /mnt, /run/media)".into(),
        });
    }
    let canonical_str = match canonical.to_str() {
        Some(s) => s,
        None => {
            return axum::Json(validate::ValidationResult::Error {
                message: "path is not valid UTF-8".into(),
            })
        }
    };
    axum::Json(validate::validate(Some(canonical_str), body.kind))
}

#[derive(serde::Deserialize)]
pub(crate) struct GenerateWalletKeysBody {
    output_dir: String,
}

#[derive(serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum GenerateWalletKeysResponse {
    Ok {
        /// Mainnet base address (`addr1q…`): carry this to the online tool.
        base_address: String,
        /// Mainnet stake/reward address (`stake1…`).
        stake_address: String,
        payment_keyhash_hex: String,
        stake_keyhash_hex: String,
        payment_skey_path: String,
        stake_skey_path: String,
        /// Encrypted UR fragments carrying the public `NewAddressExport`,
        /// for the online tool to scan back via `/api/new-address/receive`.
        ur_fragments: Vec<String>,
    },
    Error {
        message: String,
    },
}

/// Generate a fresh payment + stake key pair into the operator-chosen
/// directory, gated by the same allow-list as the file browser (keys belong
/// on the LUKS-mounted removable drive, never an arbitrary path). Requires
/// pairing: the public address export travels back to the online tool over
/// the same encrypted UR channel as a signing result.
pub(crate) async fn generate_wallet_keys(
    axum::Json(body): axum::Json<GenerateWalletKeysBody>,
) -> axum::Json<GenerateWalletKeysResponse> {
    let trimmed = body.output_dir.trim();
    if trimmed.is_empty() {
        return axum::Json(GenerateWalletKeysResponse::Error {
            message: "output directory is required".into(),
        });
    }
    let canonical = match std::path::PathBuf::from(trimmed).canonicalize() {
        Ok(c) => c,
        Err(_) => {
            return axum::Json(GenerateWalletKeysResponse::Error {
                message: "directory does not exist".into(),
            })
        }
    };
    let allowed = crate::handlers::list_dir::list_dir_allowed_roots();
    if !allowed.iter().any(|root| canonical.starts_with(root)) {
        return axum::Json(GenerateWalletKeysResponse::Error {
            message: "directory is outside the allowed roots (/media, /mnt, /run/media)".into(),
        });
    }

    let cfg = match config::load(&config::config_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to load signer config");
            return axum::Json(GenerateWalletKeysResponse::Error {
                message: "failed to load signer config. Fix or remove the corrupt config file"
                    .into(),
            });
        }
    };
    let (own_sk, peer_pk) = match config::paired_keys(&cfg) {
        Some(keys) => keys,
        None => {
            return axum::Json(GenerateWalletKeysResponse::Error {
                message: "signer is not paired with an online tool. Open Pairing first".into(),
            })
        }
    };

    let g = match crate::keygen::generate_and_write(&canonical) {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(error = %e, "wallet keygen failed");
            return axum::Json(GenerateWalletKeysResponse::Error {
                message: e.to_string(),
            });
        }
    };

    // Re-read the freshly written verification keys to assemble the public
    // export. Errors here are internal (the files were just written).
    let pay_vkey = vkey_of(Some(&g.payment_skey_path), true);
    let stake_vkey = vkey_of(Some(&g.stake_skey_path), false);
    let (pay_vkey, stake_vkey) = match (pay_vkey, stake_vkey) {
        (Some(p), Some(s)) => (p, s),
        _ => {
            return axum::Json(GenerateWalletKeysResponse::Error {
                message: "could not re-read generated keys".into(),
            })
        }
    };
    let export = shared::new_address::NewAddressExport {
        base_address_bech32: g.base_address.clone(),
        stake_address_bech32: g.stake_address.clone(),
        payment_vkey_hex: hex::encode(pay_vkey),
        stake_vkey_hex: hex::encode(stake_vkey),
        payment_keyhash_hex: g.payment_keyhash_hex.clone(),
        stake_keyhash_hex: g.stake_keyhash_hex.clone(),
    };
    let bytes = match serde_json::to_vec(&export) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "new-address export encode failed");
            return axum::Json(GenerateWalletKeysResponse::Error {
                message: "internal encoding error".into(),
            });
        }
    };
    let ur_fragments = match shared::wire_io::ur_encode(
        &bytes,
        &peer_pk,
        &own_sk,
        shared::qr::Direction::Response,
    ) {
        Ok(f) => f,
        Err(e) => {
            return axum::Json(GenerateWalletKeysResponse::Error { message: e.message });
        }
    };

    axum::Json(GenerateWalletKeysResponse::Ok {
        base_address: g.base_address,
        stake_address: g.stake_address,
        payment_keyhash_hex: g.payment_keyhash_hex,
        stake_keyhash_hex: g.stake_keyhash_hex,
        payment_skey_path: g.payment_skey_path,
        stake_skey_path: g.stake_skey_path,
        ur_fragments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_wallet_address_matches_keygen() {
        let dir = tempfile::tempdir().unwrap();
        let gen = crate::keygen::generate_and_write(dir.path()).expect("keygen");
        let info = derive_wallet_address(&gen.payment_skey_path, &gen.stake_skey_path)
            .expect("derives from generated keys");
        assert_eq!(info.base_address_bech32, gen.base_address);
        assert_eq!(info.stake_address_bech32, Some(gen.stake_address));
        assert_eq!(info.payment_keyhash_hex, gen.payment_keyhash_hex);
        assert_eq!(info.stake_keyhash_hex, Some(gen.stake_keyhash_hex));
    }

    #[test]
    fn derive_wallet_address_none_when_unset() {
        assert!(derive_wallet_address("", "").is_none());
    }

    #[test]
    fn setup_body_cannot_set_or_replace_crypto_fields() {
        // A body supplying its own X25519 secret / peer pubkey must not be
        // able to bypass the pairing flow's low-order rejection and
        // fingerprint confirmation: the on-disk values always win.
        let own = "11".repeat(32);
        let peer = "22".repeat(32);
        let body = config::SignerConfig {
            keys: vec![config::KeyEntry {
                label: "Main".into(),
                payment_skey_path: "/secure/payment.skey".into(),
                stake_skey_path: "/secure/stake.skey".into(),
            }],
            own_crypto_skey_hex: Some("aa".repeat(32)),
            peer_crypto_pubkey_hex: Some("bb".repeat(32)),
            ..Default::default()
        };
        let existing = config::SignerConfig {
            own_crypto_skey_hex: Some(own.clone()),
            peer_crypto_pubkey_hex: Some(peer.clone()),
            ..Default::default()
        };
        let merged = merge_setup_body(body, existing);
        assert_eq!(merged.own_crypto_skey_hex, Some(own));
        assert_eq!(merged.peer_crypto_pubkey_hex, Some(peer));
        // The wallet list is what the endpoint actually manages.
        assert_eq!(merged.keys.len(), 1);
        assert_eq!(merged.keys[0].payment_skey_path, "/secure/payment.skey");
    }

    #[test]
    fn vetted_key_path_blanks_whitespace() {
        let mut blank = "   ".to_string();
        vetted_key_path("payment key", &mut blank).expect("blank path is fine");
        assert_eq!(blank, "");
    }

    #[test]
    fn vetted_key_path_rejects_nonexistent_path() {
        let mut path = "/nonexistent/wallet-tools-test/payment.skey".to_string();
        let err = vetted_key_path("payment key", &mut path).expect_err("must reject");
        assert!(
            err.message.contains("does not exist"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn vetted_key_path_rejects_existing_path_outside_roots() {
        // An existing, readable file outside /media, /mnt, /run/media:
        // exactly the probe shape the allow-list forecloses.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("payment.skey");
        std::fs::write(&file, "{}").unwrap();
        let mut path = file.to_str().unwrap().to_string();
        let err = vetted_key_path("payment key", &mut path).expect_err("must reject");
        assert!(
            err.message.contains("outside the allowed roots"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn setup_body_cannot_clear_pairing() {
        // Omitting the crypto fields (the normal frontend body) keeps the
        // existing pairing intact across Setup re-saves.
        let existing = config::SignerConfig {
            own_crypto_skey_hex: Some("11".repeat(32)),
            peer_crypto_pubkey_hex: Some("22".repeat(32)),
            ..Default::default()
        };
        let merged = merge_setup_body(config::SignerConfig::default(), existing);
        assert!(merged.own_crypto_skey_hex.is_some());
        assert!(merged.peer_crypto_pubkey_hex.is_some());
    }
}
