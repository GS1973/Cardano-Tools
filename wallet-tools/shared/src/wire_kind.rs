//! Wire-level discriminator shared by all wallet sign-request types.
//!
//! Each request carries a `kind: WalletWireKind` tag so the signer can
//! route the payload to the correct handler without speculative
//! deserialisation. Stake registration is not a kind of its own: when a
//! stake key is not yet registered, the online tool folds the registration
//! certificate into the same delegation transaction (Conway combined
//! register+delegate), so it signs in one step.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(rename_all = "snake_case")]
pub enum WalletWireKind {
    /// Send ADA and/or native assets to a destination address.
    Payment,
    /// Delegate the stake key to a stake pool (registering it first if needed).
    PoolDelegate,
    /// Delegate the stake key's voting power to a DRep (registering if needed).
    DrepDelegate,
    /// Withdraw the stake key's accumulated rewards to the wallet's own
    /// payment address.
    WithdrawRewards,
}

impl WalletWireKind {
    /// Snake-case wire string used in `pin_proof_hex`, equivalent to the
    /// serde-rendered form. Centralises the literal so signer-side PIN
    /// verification cannot drift from online-side PIN computation.
    pub fn wire_str(&self) -> &'static str {
        match self {
            WalletWireKind::Payment => "payment",
            WalletWireKind::PoolDelegate => "pool_delegate",
            WalletWireKind::DrepDelegate => "drep_delegate",
            WalletWireKind::WithdrawRewards => "withdraw_rewards",
        }
    }
}

/// Minimal helper for the signer's receive/execute path: deserialize only
/// the `kind` field so the caller can dispatch into the right full-decode
/// arm without trying every variant in turn.
#[derive(Deserialize)]
struct KindOnly {
    kind: WalletWireKind,
}

pub fn detect_kind(json_bytes: &[u8]) -> Result<WalletWireKind, serde_json::Error> {
    let parsed: KindOnly = serde_json::from_slice(json_bytes)?;
    Ok(parsed.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [WalletWireKind; 4] = [
        WalletWireKind::Payment,
        WalletWireKind::PoolDelegate,
        WalletWireKind::DrepDelegate,
        WalletWireKind::WithdrawRewards,
    ];

    #[test]
    fn round_trips_each_variant() {
        for k in ALL {
            let json = serde_json::to_string(&k).expect("serialize");
            let back: WalletWireKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(k, back);
        }
    }

    #[test]
    fn wire_strings_match_serde_form() {
        for k in ALL {
            let serde_form = serde_json::to_string(&k).unwrap();
            assert_eq!(serde_form, format!("\"{}\"", k.wire_str()));
        }
    }

    #[test]
    fn detect_kind_works() {
        let json = br#"{"kind":"pool_delegate","other":"ignored"}"#;
        assert_eq!(detect_kind(json).unwrap(), WalletWireKind::PoolDelegate);
    }
}
