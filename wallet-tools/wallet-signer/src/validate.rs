//! Per-key validation for the Setup flow.
//!
//! Opens the file, parses it as cardano-cli skey JSON, and verifies it has
//! the right key role (Payment / Stake) for the field being configured.
//! This is the same load path the signing flow takes, so a successful
//! validation is a strong "this WILL load when you sign" signal.

use serde::Serialize;
use shared::cardano_keys::{load_skey, CardanoKey, KeyLoadError};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    Payment,
    Stake,
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
                    found = other.map(KeyKind::label).unwrap_or("non-wallet key"),
                    expected = expected.label(),
                    "skey at configured path has the wrong role"
                );
                ValidationResult::WrongRole
            }
        },
        Err(e) => ValidationResult::Error {
            message: friendly_error(&e),
        },
    }
}

fn key_kind_of(k: &CardanoKey) -> Option<KeyKind> {
    match k {
        CardanoKey::Payment { .. } | CardanoKey::PaymentExtended { .. } => Some(KeyKind::Payment),
        CardanoKey::Stake { .. } | CardanoKey::StakeExtended { .. } => Some(KeyKind::Stake),
        // Cold / VRF / DRep keys are not a Wallet Tools role.
        CardanoKey::PoolCold { .. }
        | CardanoKey::Vrf { .. }
        | CardanoKey::DRep { .. }
        | CardanoKey::DRepExtended { .. } => None,
    }
}

impl KeyKind {
    fn label(self) -> &'static str {
        match self {
            KeyKind::Payment => "payment signing key",
            KeyKind::Stake => "stake signing key",
        }
    }
}

/// The one description of a key-load failure, used by Setup and by the
/// signing path alike. It never echoes file content: everything except the
/// permission hint comes from the loader's own redacted form (a parse error
/// can quote the file, a hex error the offending character, and a header
/// mismatch the first bytes of what may be a raw key).
pub(crate) fn friendly_error(e: &KeyLoadError) -> String {
    match e {
        KeyLoadError::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => {
            "permission denied: is the encrypted USB mounted with read access?".into()
        }
        _ => e.redacted(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const MARK: &str = "c0ffee11";

    fn skey_file(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    fn message_for(content: &str) -> String {
        let f = skey_file(content);
        match validate(Some(f.path().to_str().unwrap()), KeyKind::Payment) {
            ValidationResult::Error { message } => message,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn load_errors_never_echo_file_content() {
        // Not JSON: serde would quote the offending token.
        let m = message_for(&format!("{MARK} is not json"));
        assert!(!m.contains(MARK), "{m}");
        // A raw key without its CBOR header: the header bytes are key bytes.
        let m = message_for(&format!(
            r#"{{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"{MARK}{}"}}"#,
            "ab".repeat(28)
        ));
        assert!(!m.contains("c0ff") && !m.contains(MARK), "{m}");
        assert!(m.contains("CBOR header"), "{m}");
        // Not hex.
        let m = message_for(
            r#"{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820zz"}"#,
        );
        assert_eq!(m, "cborHex is not valid hex");
        // An unknown type label is not echoed either.
        let m = message_for(&format!(
            r#"{{"type":"{MARK}","description":"","cborHex":"5820"}}"#
        ));
        assert!(!m.contains(MARK), "{m}");
    }

    #[test]
    fn missing_file_and_missing_path_are_told_apart() {
        assert!(matches!(
            validate(None, KeyKind::Payment),
            ValidationResult::Missing
        ));
        match validate(Some("/nonexistent/payment.skey"), KeyKind::Payment) {
            ValidationResult::Error { message } => assert_eq!(message, "file not found"),
            other => panic!("expected an error, got {other:?}"),
        }
    }
}
