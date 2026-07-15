//! Per-key validation for the Setup flow.
//!
//! Opens the file, parses it as cardano-cli skey JSON, and verifies it has
//! the right key role (DRep / Payment) for the field being configured.
//! This is the same load path the signing flow takes, so a successful
//! validation is a strong "this WILL load when you sign" signal.

use serde::Serialize;
use shared::cardano_keys::{load_skey, CardanoKey, KeyLoadError};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    Drep,
    Payment,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ValidationResult {
    /// Path was empty / not configured.
    Missing,
    /// File loaded and parsed correctly for the requested role.
    Valid,
    /// File loaded but the role inside the JSON does not match. The HTTP
    /// response carries no found/expected detail (an asymmetric label would
    /// let an attacker chaining a same-origin XSS enumerate the operator's
    /// skey layout); the distinction is preserved in tracing logs.
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
                    found = other.map(KeyKind::label).unwrap_or("non-DRep key"),
                    expected = expected.label(),
                    "skey at configured path has the wrong role"
                );
                ValidationResult::WrongRole
            }
        },
        Err(e) => ValidationResult::Error { message: friendly_error(&e) },
    }
}

fn key_kind_of(k: &CardanoKey) -> Option<KeyKind> {
    match k {
        CardanoKey::DRep { .. } | CardanoKey::DRepExtended { .. } => Some(KeyKind::Drep),
        CardanoKey::Payment { .. } | CardanoKey::PaymentExtended { .. } => Some(KeyKind::Payment),
        // Cold / VRF / Stake keys are not a DRep Tools role.
        CardanoKey::PoolCold { .. }
        | CardanoKey::Vrf { .. }
        | CardanoKey::Stake { .. }
        | CardanoKey::StakeExtended { .. } => None,
    }
}

impl KeyKind {
    fn label(self) -> &'static str {
        match self {
            KeyKind::Drep => "DRep signing key",
            KeyKind::Payment => "payment signing key",
        }
    }
}

fn friendly_error(e: &KeyLoadError) -> String {
    match e {
        KeyLoadError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => "file not found".into(),
        KeyLoadError::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => {
            "permission denied — is the encrypted USB mounted with read access?".into()
        }
        // Redact serde_json detail — it can echo file contents at the parse
        // error location, a file-content oracle for an XSS-chaining attacker.
        KeyLoadError::Json(_) => "file is not valid cardano-cli skey JSON".into(),
        KeyLoadError::InsecureMode { mode } => format!(
            "skey file is readable by group or other (mode 0o{mode:o}); chmod 600 before retrying"
        ),
        _ => e.to_string(),
    }
}
