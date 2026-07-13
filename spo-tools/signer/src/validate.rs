//! Per-key validation for the Setup flow.
//!
//! "Validation" means: open the file, parse as cardano-cli skey JSON,
//! verify it has the right key role (cold / VRF / stake / payment), and
//! verify the byte-length matches what that role expects.
//!
//! This is the same path as the actual signing flow takes when it loads
//! a key — so a successful validation is a strong "this WILL load when
//! you sign" signal.

use serde::Serialize;
use shared::cardano_keys::{load_skey, CardanoKey, KeyLoadError};
use std::path::Path;

/// What this validator was asked to check. Drives the role-mismatch logic
/// (e.g. validating `vrf_skey` field as `KeyKind::Vrf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    Vrf,
    Cold,
    Stake,
    Payment,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ValidationResult {
    /// Path was empty / not configured.
    Missing,
    /// File loaded and parsed correctly for the requested role.
    Valid,
    /// File loaded but the role inside the JSON does not match.
    /// The HTTP response carries no `found`/`expected` detail because
    /// asymmetric labelling would let an attacker (chaining a same-
    /// origin XSS) probe `path -> "this is a Cold key"` and enumerate
    /// the operator's LUKS-mounted skey layout. The variant string
    /// distinction is preserved in tracing logs for operator debugging.
    WrongRole,
    /// Anything else (file not found, invalid JSON, bad CBOR, wrong length).
    Error { message: String },
}

pub fn validate(path: Option<&str>, expected: KeyKind) -> ValidationResult {
    let Some(p) = path.filter(|s| !s.trim().is_empty()) else {
        return ValidationResult::Missing;
    };
    match load_skey(Path::new(p)) {
        Ok(key) => match key_kind_of(&key) {
            Some(actual) if actual == expected => ValidationResult::Valid,
            other => {
                tracing::warn!(
                    found = other.map(KeyKind::label).unwrap_or("non-SPO key (DRep)"),
                    expected = expected.label(),
                    "skey at configured path has the wrong role"
                );
                ValidationResult::WrongRole
            }
        }
        Err(e) => ValidationResult::Error {
            message: friendly_error(&e),
        },
    }
}

fn key_kind_of(k: &CardanoKey) -> Option<KeyKind> {
    match k {
        CardanoKey::PoolCold { .. } => Some(KeyKind::Cold),
        CardanoKey::Vrf { .. } => Some(KeyKind::Vrf),
        CardanoKey::Stake { .. } | CardanoKey::StakeExtended { .. } => Some(KeyKind::Stake),
        CardanoKey::Payment { .. } | CardanoKey::PaymentExtended { .. } => Some(KeyKind::Payment),
        // DRep keys are not an SPO Tools role; treated as wrong-role here.
        CardanoKey::DRep { .. } | CardanoKey::DRepExtended { .. } => None,
    }
}

impl KeyKind {
    fn label(self) -> &'static str {
        match self {
            KeyKind::Vrf => "VRF signing key",
            KeyKind::Cold => "cold signing key",
            KeyKind::Stake => "stake signing key",
            KeyKind::Payment => "payment signing key",
        }
    }
}

fn friendly_error(e: &KeyLoadError) -> String {
    match e {
        KeyLoadError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            "file not found".into()
        }
        KeyLoadError::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => {
            "permission denied — is the encrypted USB mounted with read access?".into()
        }
        // Redact serde_json error detail — it can echo a snippet of the
        // file contents at the parse-error location, which an attacker
        // chaining a same-origin XSS could turn into a file-content
        // oracle for arbitrary paths the signer process can read.
        KeyLoadError::Json(_) => "file is not valid cardano-cli skey JSON".into(),
        KeyLoadError::InsecureMode { mode } => format!(
            "skey file is readable by group or other (mode 0o{mode:o}); chmod 600 before retrying"
        ),
        _ => e.to_string(),
    }
}
