//! Setup endpoints — read / write signer config + per-key validation.
//!
//! `/api/signer-config` returns a redacted view (paths / hex secrets are
//! never reflected back to the client). `/api/test-load` validates a
//! single key path the operator typed in the Setup form, gated by the
//! same `list_dir` allow-list; saved key paths are gated by it too.

use crate::{config, validate};
use shared::error::ErrorEnvelope;

// ============================================================
// Setup endpoints — read / write signer config + per-key validation
// ============================================================

#[derive(serde::Serialize)]
pub(crate) struct SignerConfigResponse {
    /// Whether all five required key paths are configured and parseable.
    pub saved: bool,
    /// Whether the encrypted channel to the online tool is paired.
    pub paired: bool,
    /// Hex-grouped pairing fingerprint when paired.
    pub pairing_fingerprint: Option<String>,
    /// Per-field validation status. Statuses are coarse (Missing / Valid /
    /// WrongRole / Error) and never include the path itself, so a
    /// compromised loopback observer cannot read the LUKS-mount paths.
    pub validation: ValidationByField,
}

#[derive(serde::Serialize)]
pub(crate) struct ValidationByField {
    vrf_skey: validate::ValidationResult,
    cold_skey: validate::ValidationResult,
    owner_skey: validate::ValidationResult,
    reward_skey: validate::ValidationResult,
    payment_skey: validate::ValidationResult,
}

pub(crate) fn validate_all_fields(c: &config::SignerConfig) -> ValidationByField {
    ValidationByField {
        vrf_skey: validate::validate(c.vrf_skey.as_deref(), validate::KeyKind::Vrf),
        cold_skey: validate::validate(c.cold_skey.as_deref(), validate::KeyKind::Cold),
        owner_skey: validate::validate(c.owner_skey.as_deref(), validate::KeyKind::Stake),
        reward_skey: validate::validate(c.reward_skey.as_deref(), validate::KeyKind::Stake),
        payment_skey: validate::validate(c.payment_skey.as_deref(), validate::KeyKind::Payment),
    }
}

pub(crate) fn build_signer_config_response(c: &config::SignerConfig) -> SignerConfigResponse {
    let saved = config::is_configured(c);
    let validation = validate_all_fields(c);
    let (paired, pairing_fingerprint) = shared::crypto::pairing_status(
        c.own_crypto_skey_hex.as_deref(),
        c.peer_crypto_pubkey_hex.as_deref(),
    );
    SignerConfigResponse {
        saved,
        paired,
        pairing_fingerprint,
        validation,
    }
}

pub(crate) async fn signer_config_get() -> axum::Json<SignerConfigResponse> {
    let c = config::load(&config::config_path());
    axum::Json(build_signer_config_response(&c))
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
    let canonical = std::path::PathBuf::from(trimmed).canonicalize().map_err(|e| {
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

/// Merge a Setup POST body over the existing on-disk config. The X25519
/// crypto fields are never accepted from the body — the pairing handlers
/// are their only writers (they reject low-order peer points and require
/// the operator-confirmed fingerprint) — so they are always carried over
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

pub(crate) async fn signer_config_post(
    axum::Json(body): axum::Json<config::SignerConfig>,
) -> Result<axum::Json<SignerConfigResponse>, ErrorEnvelope> {
    let existing = config::load_or_err()?;
    let mut merged = merge_setup_body(body, existing);
    // Every key path gets the same canonicalize + allowed-roots guard as
    // `/api/test-load`; an out-of-root path rejects the whole save.
    vetted_key_path("vrf_skey", &mut merged.vrf_skey)?;
    vetted_key_path("cold_skey", &mut merged.cold_skey)?;
    vetted_key_path("owner_skey", &mut merged.owner_skey)?;
    vetted_key_path("reward_skey", &mut merged.reward_skey)?;
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
    // Open the canonicalised path, not the raw input: a symlink chain that
    // resolved inside the allow-list at canonicalize time could otherwise
    // resolve elsewhere when validate::validate re-opens body.path.
    let canonical_str = match canonical.to_str() {
        Some(s) => s,
        None => {
            return axum::Json(validate::ValidationResult::Error {
                message: "path is not valid UTF-8".into(),
            });
        }
    };
    axum::Json(validate::validate(Some(canonical_str), body.kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_body_cannot_set_or_replace_crypto_fields() {
        // A body supplying its own X25519 secret / peer pubkey must not be
        // able to bypass the pairing flow's low-order rejection and
        // fingerprint confirmation: the on-disk values always win.
        let own = "11".repeat(32);
        let peer = "22".repeat(32);
        let body = config::SignerConfig {
            vrf_skey: Some("/secure/vrf.skey".into()),
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
        // The key paths are what the endpoint actually manages.
        assert_eq!(merged.vrf_skey, Some("/secure/vrf.skey".to_string()));
    }

    #[test]
    fn vetted_key_path_keeps_absent_and_blanks_whitespace() {
        let mut absent: Option<String> = None;
        vetted_key_path("vrf_skey", &mut absent).expect("absent path is fine");
        assert_eq!(absent, None);

        let mut blank = Some("   ".to_string());
        vetted_key_path("vrf_skey", &mut blank).expect("blank path is fine");
        assert_eq!(blank, None);
    }

    #[test]
    fn vetted_key_path_rejects_nonexistent_path() {
        let mut path = Some("/nonexistent/spo-tools-test/vrf.skey".to_string());
        let err = vetted_key_path("vrf_skey", &mut path).expect_err("must reject");
        assert!(
            err.message.contains("does not exist"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn vetted_key_path_rejects_existing_path_outside_roots() {
        // An existing, readable file outside /media, /mnt, /run/media —
        // exactly the probe shape the allow-list forecloses.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vrf.skey");
        std::fs::write(&file, "{}").unwrap();
        let mut path = Some(file.to_str().unwrap().to_string());
        let err = vetted_key_path("vrf_skey", &mut path).expect_err("must reject");
        assert!(
            err.message.contains("outside the allowed roots"),
            "got: {}",
            err.message
        );
    }
}

