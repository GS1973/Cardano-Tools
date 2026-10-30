//! Setup endpoints: read / write signer config + per-key validation.
//!
//! `/api/signer-config` returns a redacted view (paths / hex secrets are
//! never reflected back). `/api/test-load` validates a single key path the
//! operator typed, gated by the same `list_dir` allow-list.

use crate::{config, validate};
use shared::error::ErrorEnvelope;

#[derive(serde::Serialize)]
pub(crate) struct SignerConfigResponse {
    /// Whether both key paths are configured and parseable.
    pub saved: bool,
    pub paired: bool,
    pub pairing_fingerprint: Option<String>,
    pub validation: ValidationByField,
    /// DRep id derived from the configured DRep signing key. Public (the
    /// blake2b-224 of its verification key), so the operator can re-read it
    /// without re-running keygen. None when no valid DRep key is configured.
    pub drep_id: Option<DRepIdInfo>,
}

#[derive(serde::Serialize)]
pub(crate) struct DRepIdInfo {
    /// CIP-129 `drep1...` (header byte + hash): the modern form.
    pub cip129: String,
    /// Legacy CIP-105 `drep1...` (bare hash).
    pub cip105: String,
    pub keyhash_hex: String,
}

/// Derive the DRep id (both encodings) from the configured DRep signing key.
/// Reads the public verification key out of the secret; the id itself is
/// public. None when the key is absent, unreadable, or not a DRep key.
fn derive_drep_id(c: &config::SignerConfig) -> Option<DRepIdInfo> {
    let path = c.drep_skey.as_deref()?;
    let vkey: [u8; 32] = match shared::cardano_keys::load_skey(std::path::Path::new(path)).ok()? {
        shared::cardano_keys::CardanoKey::DRep { seed_32 } => {
            ed25519_dalek::SigningKey::from_bytes(&seed_32)
                .verifying_key()
                .to_bytes()
        }
        shared::cardano_keys::CardanoKey::DRepExtended { pubkey_32, .. } => pubkey_32,
        _ => return None,
    };
    let keyhash = shared::validate::blake2b224(&vkey);
    Some(DRepIdInfo {
        cip129: shared::drep_id::keyhash_to_cip129(&keyhash),
        cip105: shared::drep_id::keyhash_to_cip105(&keyhash),
        keyhash_hex: hex::encode(keyhash),
    })
}

#[derive(serde::Serialize)]
pub(crate) struct ValidationByField {
    drep_skey: validate::ValidationResult,
    payment_skey: validate::ValidationResult,
}

pub(crate) fn validate_all_fields(c: &config::SignerConfig) -> ValidationByField {
    ValidationByField {
        drep_skey: validate::validate(c.drep_skey.as_deref(), validate::KeyKind::Drep),
        payment_skey: validate::validate(c.payment_skey.as_deref(), validate::KeyKind::Payment),
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
        validation: validate_all_fields(c),
        drep_id: derive_drep_id(c),
    }
}

pub(crate) async fn signer_config_get() -> axum::Json<SignerConfigResponse> {
    let c = config::load(&config::config_path());
    axum::Json(build_signer_config_response(&c))
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
fn vetted_key_path(field: &'static str, value: &mut Option<String>) -> Result<(), ErrorEnvelope> {
    // Take the raw input out; only a vetted canonical path is put back.
    let Some(raw) = value.take() else {
        return Ok(());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
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
            *value = Some(s);
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
    // Every key path gets the same canonicalize + allowed-roots guard as
    // `/api/test-load`; an out-of-root path rejects the whole save.
    vetted_key_path("drep_skey", &mut merged.drep_skey)?;
    vetted_key_path("payment_skey", &mut merged.payment_skey)?;
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
pub(crate) struct GenerateDrepKeyBody {
    output_dir: String,
}

#[derive(serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum GenerateDrepKeyResponse {
    Ok {
        /// CIP-129 `drep1...`: carry this to the online tool's Setup.
        drep_id: String,
        /// Legacy CIP-105 `drep1...`.
        drep_id_legacy: String,
        keyhash_hex: String,
        skey_path: String,
        vkey_path: String,
    },
    Error {
        message: String,
    },
}

/// Generate a fresh DRep key pair into the operator-chosen directory,
/// gated by the same allow-list as the file browser (keys belong on the
/// LUKS-mounted removable drive, never an arbitrary path).
pub(crate) async fn generate_drep_key(
    axum::Json(body): axum::Json<GenerateDrepKeyBody>,
) -> axum::Json<GenerateDrepKeyResponse> {
    let trimmed = body.output_dir.trim();
    if trimmed.is_empty() {
        return axum::Json(GenerateDrepKeyResponse::Error {
            message: "output directory is required".into(),
        });
    }
    let canonical = match std::path::PathBuf::from(trimmed).canonicalize() {
        Ok(c) => c,
        Err(_) => {
            return axum::Json(GenerateDrepKeyResponse::Error {
                message: "directory does not exist".into(),
            })
        }
    };
    let allowed = crate::handlers::list_dir::list_dir_allowed_roots();
    if !allowed.iter().any(|root| canonical.starts_with(root)) {
        return axum::Json(GenerateDrepKeyResponse::Error {
            message: "directory is outside the allowed roots (/media, /mnt, /run/media)".into(),
        });
    }
    match crate::keygen::generate_and_write(&canonical) {
        Ok(g) => axum::Json(GenerateDrepKeyResponse::Ok {
            drep_id: g.drep_id_cip129,
            drep_id_legacy: g.drep_id_cip105,
            keyhash_hex: g.keyhash_hex,
            skey_path: g.skey_path,
            vkey_path: g.vkey_path,
        }),
        Err(e) => {
            tracing::warn!(error = %e, "drep keygen failed");
            axum::Json(GenerateDrepKeyResponse::Error {
                message: e.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_drep_id_matches_keygen() {
        let dir = tempfile::tempdir().unwrap();
        let gen = crate::keygen::generate_and_write(dir.path()).expect("keygen");
        let cfg = config::SignerConfig {
            drep_skey: Some(gen.skey_path.clone()),
            ..Default::default()
        };
        let id = derive_drep_id(&cfg).expect("derives from configured key");
        assert_eq!(id.cip129, gen.drep_id_cip129);
        assert_eq!(id.cip105, gen.drep_id_cip105);
        assert_eq!(id.keyhash_hex, gen.keyhash_hex);
    }

    #[test]
    fn derive_drep_id_none_when_unset() {
        assert!(derive_drep_id(&config::SignerConfig::default()).is_none());
    }

    #[test]
    fn setup_body_cannot_set_or_replace_crypto_fields() {
        // A body supplying its own X25519 secret / peer pubkey must not be
        // able to bypass the pairing flow's low-order rejection and
        // fingerprint confirmation: the on-disk values always win.
        let own = "11".repeat(32);
        let peer = "22".repeat(32);
        let body = config::SignerConfig {
            drep_skey: Some("/secure/drep.skey".into()),
            payment_skey: Some("/secure/payment.skey".into()),
            own_crypto_skey_hex: Some("aa".repeat(32)),
            peer_crypto_pubkey_hex: Some("bb".repeat(32)),
        };
        let existing = config::SignerConfig {
            own_crypto_skey_hex: Some(own.clone()),
            peer_crypto_pubkey_hex: Some(peer.clone()),
            ..Default::default()
        };
        let merged = merge_setup_body(body, existing);
        assert_eq!(merged.own_crypto_skey_hex, Some(own));
        assert_eq!(merged.peer_crypto_pubkey_hex, Some(peer));
        // The key paths are what the endpoint actually manages.
        assert_eq!(merged.drep_skey.as_deref(), Some("/secure/drep.skey"));
        assert_eq!(merged.payment_skey.as_deref(), Some("/secure/payment.skey"));
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

    #[test]
    fn vetted_key_path_keeps_absent_and_blanks_whitespace() {
        let mut absent: Option<String> = None;
        vetted_key_path("drep_skey", &mut absent).expect("absent path is fine");
        assert_eq!(absent, None);

        let mut blank = Some("   ".to_string());
        vetted_key_path("drep_skey", &mut blank).expect("blank path is fine");
        assert_eq!(blank, None);
    }

    #[test]
    fn vetted_key_path_rejects_nonexistent_path() {
        let mut path = Some("/nonexistent/drep-tools-test/drep.skey".to_string());
        let err = vetted_key_path("drep_skey", &mut path).expect_err("must reject");
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
        let file = dir.path().join("drep.skey");
        std::fs::write(&file, "{}").unwrap();
        let mut path = Some(file.to_str().unwrap().to_string());
        let err = vetted_key_path("drep_skey", &mut path).expect_err("must reject");
        assert!(
            err.message.contains("outside the allowed roots"),
            "got: {}",
            err.message
        );
    }
}
