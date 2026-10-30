//! This signer's local persistent state. The state itself (the last
//! chain-context snapshot and the exactly-once request ledger) is shared by
//! every signer and lives in `airgap-core` (`signer_state`); this file only
//! names where this signer keeps it.

pub use shared::signer_state::*;
use std::path::PathBuf;

/// The canonical on-disk location for this binary's state. Resolved at
/// each call site; the helpers stay pure.
pub fn state_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".wallet-tools")
        .join("signer-state.json")
}
