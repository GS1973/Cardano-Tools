//! Wire-level discriminator shared by all DRep sign-request types.
//!
//! Each request carries a `kind: DrepWireKind` tag so the signer can route
//! the payload to the correct handler without speculative deserialisation.
//! The string values match the cardano-cli DRep action names.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum DrepWireKind {
    DrepRegister,
    DrepUpdate,
    DrepRetire,
    DrepVote,
    DrepWitnessDoc,
}

impl DrepWireKind {
    /// Snake-case wire string used in `pin_proof_hex` and equivalent to
    /// the serde-rendered form. Centralises the literal so signer-side
    /// PIN verification cannot drift from online-side PIN computation.
    pub fn wire_str(&self) -> &'static str {
        match self {
            DrepWireKind::DrepRegister => "drep_register",
            DrepWireKind::DrepUpdate => "drep_update",
            DrepWireKind::DrepRetire => "drep_retire",
            DrepWireKind::DrepVote => "drep_vote",
            DrepWireKind::DrepWitnessDoc => "drep_witness_doc",
        }
    }
}

/// Minimal helper for the signer's receive/execute path: deserialize only
/// the `kind` field so the caller can dispatch into the right full-decode
/// arm without trying every variant in turn.
#[derive(Deserialize)]
struct KindOnly {
    kind: DrepWireKind,
}

pub fn detect_kind(json_bytes: &[u8]) -> Result<DrepWireKind, serde_json::Error> {
    let parsed: KindOnly = serde_json::from_slice(json_bytes)?;
    Ok(parsed.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_each_variant() {
        for k in [
            DrepWireKind::DrepRegister,
            DrepWireKind::DrepUpdate,
            DrepWireKind::DrepRetire,
            DrepWireKind::DrepVote,
            DrepWireKind::DrepWitnessDoc,
        ] {
            let json = serde_json::to_string(&k).expect("serialize");
            let back: DrepWireKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(k, back);
        }
    }

    #[test]
    fn wire_strings_match_serde_form() {
        for k in [
            DrepWireKind::DrepRegister,
            DrepWireKind::DrepUpdate,
            DrepWireKind::DrepRetire,
            DrepWireKind::DrepVote,
            DrepWireKind::DrepWitnessDoc,
        ] {
            let serde_form = serde_json::to_string(&k).unwrap();
            assert_eq!(serde_form, format!("\"{}\"", k.wire_str()));
        }
    }

    #[test]
    fn detect_kind_works() {
        let json = br#"{"kind":"drep_vote","other":"ignored"}"#;
        assert_eq!(detect_kind(json).unwrap(), DrepWireKind::DrepVote);
    }
}
