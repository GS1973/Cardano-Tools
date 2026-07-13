//! Wire-level discriminator shared by all sign-request types.
//!
//! Each request carries a `kind: WireKind` tag so the signer can route
//! the payload to the correct handler without speculative deserialisation.
//! The string values match the cardano-cli action names used elsewhere in
//! the codebase and were the per-feature enum variants before this
//! consolidation.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum WireKind {
    Leaderlog,
    KesRotation,
    Withdrawal,
    DrepDelegation,
    PoolUpdate,
    Vote,
}

impl WireKind {
    /// Snake-case wire string used in `pin_proof_hex`, equivalent to the
    /// serde-rendered form (pinned by `wire_str_matches_serde_form`).
    /// Signer-side PIN verification calls this; online-tool producers
    /// must feed `pin_proof_hex` the same string — call
    /// `request.kind.wire_str()` there rather than repeating the literal,
    /// or a renamed variant makes every request of that kind fail PIN
    /// verification on the signer.
    pub fn wire_str(&self) -> &'static str {
        match self {
            WireKind::Leaderlog => "leaderlog",
            WireKind::KesRotation => "kes_rotation",
            WireKind::Withdrawal => "withdrawal",
            WireKind::DrepDelegation => "drep_delegation",
            WireKind::PoolUpdate => "pool_update",
            WireKind::Vote => "vote",
        }
    }
}

/// Minimal helper for `sign_receive` and friends: deserialize only the
/// `kind` field so the caller can dispatch into the right full-decode
/// arm without trying every variant in turn.
#[derive(Deserialize)]
struct KindOnly {
    kind: WireKind,
}

pub fn detect_kind(json_bytes: &[u8]) -> Result<WireKind, serde_json::Error> {
    let parsed: KindOnly = serde_json::from_slice(json_bytes)?;
    Ok(parsed.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_each_variant() {
        for k in [
            WireKind::Leaderlog,
            WireKind::KesRotation,
            WireKind::Withdrawal,
            WireKind::DrepDelegation,
            WireKind::PoolUpdate,
            WireKind::Vote,
        ] {
            let json = serde_json::to_string(&k).expect("serialize");
            let back: WireKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(k, back);
        }
    }

    #[test]
    fn wire_strings_match_existing_format() {
        assert_eq!(
            serde_json::to_string(&WireKind::Leaderlog).unwrap(),
            "\"leaderlog\""
        );
        assert_eq!(
            serde_json::to_string(&WireKind::KesRotation).unwrap(),
            "\"kes_rotation\""
        );
        assert_eq!(
            serde_json::to_string(&WireKind::Withdrawal).unwrap(),
            "\"withdrawal\""
        );
        assert_eq!(
            serde_json::to_string(&WireKind::DrepDelegation).unwrap(),
            "\"drep_delegation\""
        );
        assert_eq!(
            serde_json::to_string(&WireKind::PoolUpdate).unwrap(),
            "\"pool_update\""
        );
        assert_eq!(
            serde_json::to_string(&WireKind::Vote).unwrap(),
            "\"vote\""
        );
    }

    #[test]
    fn detect_kind_works() {
        let json = br#"{"kind":"withdrawal","other":"ignored"}"#;
        assert_eq!(detect_kind(json).unwrap(), WireKind::Withdrawal);
    }

    #[test]
    fn wire_str_matches_serde_form() {
        for k in [
            WireKind::Leaderlog,
            WireKind::KesRotation,
            WireKind::Withdrawal,
            WireKind::DrepDelegation,
            WireKind::PoolUpdate,
            WireKind::Vote,
        ] {
            let serde_form = serde_json::to_string(&k).unwrap();
            // serde wraps in quotes
            assert_eq!(serde_form, format!("\"{}\"", k.wire_str()));
        }
    }
}
