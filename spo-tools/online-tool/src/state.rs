//! Persisted KES rotation state.
//!
//! The blockchain exposes the *counter* of a pool's current operational
//! certificate (via Koios `block_info.op_cert_counter`), but it does not
//! expose the cert's `start_kes_period` — the field that pins down exactly
//! when the opcert expires (`start + maxKESEvolutions` = `start + 62`
//! periods on Cardano mainnet).
//!
//! Rather than scraping a third-party API or running a dedicated cardano-node
//! just for one integer, a tiny local file is kept with what the SPO
//! already knows about their *own* most recently issued opcert. The file
//! is bootstrapped by the SPO entering the value once (POST /api/kes/state)
//! and is then maintained automatically: every successful rotation through
//! this tool updates it with the new (start_kes_period, counter) pair.
//!
//! Default location: `$HOME/.spo-tools/state.json`.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KesState {
    /// The KES period at which the SPO's *current* opcert became valid.
    /// Combined with mainnet `maxKESEvolutions = 62`, gives the exact
    /// period after which the opcert no longer signs blocks.
    pub opcert_start_kes_period: Option<u64>,
    /// The opcert's issue counter. Used to cross-check against the value
    /// reported by Koios for the latest produced block.
    pub opcert_counter: Option<u64>,
    /// Unix seconds when this state file was last written.
    pub last_updated_unix: Option<u64>,
}

/// The canonical on-disk location for this binary's KES state. Resolved
/// at each call site in `main`; the load/save helpers stay pure.
pub fn state_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".spo-tools").join("state.json")
}

/// Load from `path`. Never panics: an unreadable or malformed file
/// returns the empty default so the UI can re-bootstrap.
pub fn load(path: &Path) -> KesState {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => KesState::default(),
    }
}

/// Save to `path`. Stamps `last_updated_unix` to "now" before writing.
/// Creates the parent directory if needed.
pub fn save(path: &Path, mut state: KesState) -> std::io::Result<KesState> {
    state.last_updated_unix = Some(now_unix());
    shared::config_helpers::save_secure(path, &state)?;
    Ok(state)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_default_when_file_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let s = load(&path);
        assert!(s.opcert_start_kes_period.is_none());
        assert!(s.opcert_counter.is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let s = KesState {
            opcert_start_kes_period: Some(1372),
            opcert_counter: Some(28),
            last_updated_unix: None,
        };
        let saved = save(&path, s).expect("save");
        assert!(saved.last_updated_unix.is_some());

        let loaded = load(&path);
        assert_eq!(loaded.opcert_start_kes_period, Some(1372));
        assert_eq!(loaded.opcert_counter, Some(28));
        assert_eq!(loaded.last_updated_unix, saved.last_updated_unix);
    }

    #[test]
    fn corrupt_file_returns_default_not_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        std::fs::write(&path, "this is not json").unwrap();
        let s = load(&path);
        assert!(s.opcert_start_kes_period.is_none());
    }

    #[test]
    fn save_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b").join("state.json");
        let s = KesState {
            opcert_start_kes_period: Some(99),
            opcert_counter: Some(1),
            last_updated_unix: None,
        };
        save(&nested, s).expect("save through nested dir");
        assert!(nested.exists());
    }
}
