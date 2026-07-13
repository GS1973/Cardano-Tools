//! Signer's local persistent state.
//!
//! Two jobs:
//!   1. Remember the last-known `ChainContext` snapshot so the signer's
//!      top-bar can show meaningful values (epoch / KES period) between
//!      sessions even though the signer cannot reach the network.
//!   2. Keep a small per-request authorization ledger so the signing
//!      boundary can enforce exactly-once signing and wrong-PIN lockout
//!      across separate `/api/sign/execute` calls.
//!
//! A single JSON file in `~/.spo-tools/`, loaded at startup and on each
//! request, written when a request is authorized or rejected. axum runs
//! handlers concurrently, so every read-modify-write of the file is
//! serialized behind a process-wide lock, and [`request_gate`] claims the
//! request id in an in-memory in-flight set so duplicate concurrent
//! submissions of the same request cannot both reach the signing keys.

use serde::{Deserialize, Serialize};
use shared::chain_context::ChainContext;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Wrong-PIN attempts tolerated for a single request before the signer
/// locks it out and forces the operator to rebuild on the online tool.
pub const MAX_PIN_ATTEMPTS: u32 = 5;

/// Records strictly older than this (by their request's `built_at_unix`)
/// are pruned from the ledger on every access. A record is retained for
/// exactly as long as its request can still pass the chain-context
/// freshness gate in `sign.rs` (`ChainContext::is_stale` rejects only when
/// strictly older than the window): once a request can no longer be fresh,
/// its ledger record can no longer matter, so the ledger stays bounded.
const LEDGER_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Serializes every read-modify-write of the state file within this
/// process. axum runs handlers concurrently; without this, two racing
/// ledger writes could each load, modify and save, silently losing one
/// update. Held only across the synchronous file round-trip.
static STATE_LOCK: Mutex<()> = Mutex::new(());

/// Request ids currently being signed. An id is claimed by
/// [`request_gate`] before any key use and released when the returned
/// [`InFlightClaim`] drops, so a duplicate concurrent submission of the
/// same request (a double-clicked Sign button) is rejected instead of
/// racing the first execution's signing work and ledger writes. Kept in
/// memory rather than in the ledger file: a crash mid-sign then clears
/// the claim instead of wedging the request until its record is pruned.
static IN_FLIGHT: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// A poisoned lock only means another thread panicked while holding it;
/// neither guarded value (a unit, a list of ids) can be left half-updated
/// by our critical sections, so recover the guard rather than cascade.
fn lock_unpoisoned<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Per-request authorization record. Identified by a hash of the decrypted
/// request payload, so a byte-identical resubmission maps to the same row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRecord {
    /// Hex blake2b-256 of the decrypted request payload.
    pub id: String,
    /// `built_at_unix` of the request's chain_context — used for pruning.
    pub built_at_unix: u64,
    /// Wrong-PIN attempts seen for this request so far.
    #[serde(default)]
    pub failed_pin_attempts: u32,
    /// Set once the request has been successfully signed (exactly-once).
    #[serde(default)]
    pub consumed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignerState {
    pub last_chain_context: Option<ChainContext>,
    pub last_synced_unix: Option<u64>,
    /// Bounded per-request authorization ledger (see [`RequestRecord`]).
    #[serde(default)]
    pub request_ledger: Vec<RequestRecord>,
}

/// Outcome of the pre-sign ledger check.
#[derive(Debug)]
pub enum RequestGate {
    /// Request may proceed to PIN verification + signing. Carries the
    /// in-flight claim: hold it until the outcome has been recorded,
    /// drop it to let the request be attempted again.
    Ok(InFlightClaim),
    /// Request was already signed — refuse to sign it a second time.
    AlreadySigned,
    /// Too many wrong-PIN attempts for this request — refuse until rebuild.
    LockedOut,
    /// A concurrent execution of this exact request is still running.
    InFlight,
}

/// RAII claim on a request id, created by [`request_gate`]. While the
/// claim is alive, `request_gate` answers [`RequestGate::InFlight`] for
/// the same id. Released on drop, so every exit path of the handler —
/// success, wrong PIN, signing error, cancelled connection — frees the
/// id for a later attempt.
#[derive(Debug)]
pub struct InFlightClaim {
    id: String,
}

impl Drop for InFlightClaim {
    fn drop(&mut self) {
        lock_unpoisoned(&IN_FLIGHT).retain(|claimed| *claimed != self.id);
    }
}

/// The canonical on-disk location for this binary's state. Resolved at
/// each call site in `main`; the helpers stay pure.
pub fn state_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".spo-tools").join("signer-state.json")
}

pub fn load(path: &Path) -> SignerState {
    match fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => SignerState::default(),
    }
}

pub fn save(path: &Path, state: &SignerState) -> std::io::Result<()> {
    shared::config_helpers::save_secure(path, state)
}

fn prune_ledger(state: &mut SignerState, now: u64) {
    state
        .request_ledger
        .retain(|r| now.saturating_sub(r.built_at_unix) <= LEDGER_MAX_AGE_SECS);
}

/// Pre-sign gate: has this exact request already been signed, has it
/// exhausted its wrong-PIN budget, or is a concurrent execution of it
/// still running? Never writes the state file (prunes only the in-memory
/// copy it loads), but does claim the id in the in-flight set: the ledger
/// records outcomes only after signing completes, so the claim is what
/// stops two concurrent submissions of the same request from both
/// passing this gate.
pub fn request_gate(path: &Path, id: &str, now: u64) -> RequestGate {
    let mut in_flight = lock_unpoisoned(&IN_FLIGHT);
    if in_flight.iter().any(|claimed| claimed == id) {
        return RequestGate::InFlight;
    }
    let _guard = lock_unpoisoned(&STATE_LOCK);
    let mut s = load(path);
    prune_ledger(&mut s, now);
    match s.request_ledger.iter().find(|r| r.id == id) {
        Some(r) if r.consumed => RequestGate::AlreadySigned,
        Some(r) if r.failed_pin_attempts >= MAX_PIN_ATTEMPTS => RequestGate::LockedOut,
        _ => {
            in_flight.push(id.to_string());
            RequestGate::Ok(InFlightClaim { id: id.to_string() })
        }
    }
}

/// Record one wrong-PIN attempt against a request, creating its row if it
/// is the first failure. After [`MAX_PIN_ATTEMPTS`] the request is locked
/// out by [`request_gate`].
pub fn note_pin_failure(
    path: &Path,
    id: &str,
    built_at_unix: u64,
    now: u64,
) -> std::io::Result<()> {
    let _guard = lock_unpoisoned(&STATE_LOCK);
    let mut s = load(path);
    prune_ledger(&mut s, now);
    match s.request_ledger.iter_mut().find(|r| r.id == id) {
        Some(r) => r.failed_pin_attempts = r.failed_pin_attempts.saturating_add(1),
        None => s.request_ledger.push(RequestRecord {
            id: id.to_string(),
            built_at_unix,
            failed_pin_attempts: 1,
            consumed: false,
        }),
    }
    save(path, &s)
}

/// Mark a request consumed (it has just been signed) and advance the
/// display watermark. The watermark is monotonic *for display only* — an
/// older snapshot simply does not advance it; replay protection is the
/// `consumed` flag enforced by [`request_gate`], not this watermark.
pub fn note_consumed(
    path: &Path,
    id: &str,
    ctx: ChainContext,
    now: u64,
) -> std::io::Result<()> {
    let _guard = lock_unpoisoned(&STATE_LOCK);
    let mut s = load(path);
    prune_ledger(&mut s, now);
    match s.request_ledger.iter_mut().find(|r| r.id == id) {
        Some(r) => r.consumed = true,
        None => s.request_ledger.push(RequestRecord {
            id: id.to_string(),
            built_at_unix: ctx.built_at_unix,
            failed_pin_attempts: 0,
            consumed: true,
        }),
    }
    let advance = s
        .last_chain_context
        .as_ref()
        .is_none_or(|prev| ctx.built_at_unix >= prev.built_at_unix);
    if advance {
        s.last_chain_context = Some(ctx);
        s.last_synced_unix = Some(now);
    }
    save(path, &s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn ctx(built_at: u64) -> ChainContext {
        ChainContext {
            current_epoch: 100,
            current_slot: 1_500_000,
            current_kes_period: 50,
            epoch_ends_at_unix: 1_000_000_000,
            opcert_expires_at_unix: Some(1_001_000_000),
            built_at_unix: built_at,
        }
    }

    #[test]
    fn load_missing_returns_default() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer-state.json");
        let s = load(&path);
        assert!(s.last_chain_context.is_none());
        assert!(s.request_ledger.is_empty());
    }

    #[test]
    fn consumed_request_is_gated_as_already_signed() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer-state.json");
        let now = 1_000_000;
        assert!(matches!(request_gate(&path, "abc", now), RequestGate::Ok(_)));
        note_consumed(&path, "abc", ctx(now), now).unwrap();
        assert!(matches!(
            request_gate(&path, "abc", now),
            RequestGate::AlreadySigned
        ));
        // A different request is unaffected.
        assert!(matches!(request_gate(&path, "xyz", now), RequestGate::Ok(_)));
    }

    #[test]
    fn pin_failures_lock_out_after_max_attempts() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer-state.json");
        let now = 1_000_000;
        for _ in 0..MAX_PIN_ATTEMPTS {
            assert!(matches!(request_gate(&path, "id", now), RequestGate::Ok(_)));
            note_pin_failure(&path, "id", now, now).unwrap();
        }
        assert!(matches!(
            request_gate(&path, "id", now),
            RequestGate::LockedOut
        ));
    }

    #[test]
    fn consume_advances_watermark_monotonically() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer-state.json");
        let now = 1_000_000;
        note_consumed(&path, "a", ctx(999_000_000), now).unwrap();
        assert_eq!(load(&path).last_chain_context, Some(ctx(999_000_000)));
        // An older snapshot does not roll the watermark back.
        note_consumed(&path, "b", ctx(999_000_000 - 1), now).unwrap();
        assert_eq!(load(&path).last_chain_context, Some(ctx(999_000_000)));
    }

    #[test]
    fn ledger_prunes_stale_records() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer-state.json");
        let old_built = 1_000_000u64;
        note_consumed(&path, "old", ctx(old_built), old_built).unwrap();
        // Far in the future: the old record is now beyond the freshness window.
        let now = old_built + LEDGER_MAX_AGE_SECS + 1;
        assert!(matches!(request_gate(&path, "old", now), RequestGate::Ok(_)));
    }

    #[test]
    fn ledger_retains_record_at_exact_freshness_boundary() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer-state.json");
        let built = 1_000_000u64;
        note_consumed(&path, "edge", ctx(built), built).unwrap();
        // At exactly LEDGER_MAX_AGE_SECS the request still passes the
        // chain-context freshness gate (`is_stale` rejects only strictly
        // older), so its exactly-once record must survive pruning too.
        let now = built + LEDGER_MAX_AGE_SECS;
        assert!(matches!(
            request_gate(&path, "edge", now),
            RequestGate::AlreadySigned
        ));
    }

    #[test]
    fn in_flight_claim_blocks_duplicate_until_dropped() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("signer-state.json");
        let now = 1_000_000;
        let claim = match request_gate(&path, "dup", now) {
            RequestGate::Ok(claim) => claim,
            other => panic!("expected Ok gate, got {other:?}"),
        };
        // The same request is refused while the first execution runs...
        assert!(matches!(
            request_gate(&path, "dup", now),
            RequestGate::InFlight
        ));
        // ...but a different request is unaffected.
        assert!(matches!(
            request_gate(&path, "other", now),
            RequestGate::Ok(_)
        ));
        // Dropping the claim (any handler exit path) frees the id again.
        drop(claim);
        assert!(matches!(request_gate(&path, "dup", now), RequestGate::Ok(_)));
    }
}
