//! Chain context — the snapshot of mainnet state that the online tool
//! attaches to every request crossing the QR/clipboard to the signer.
//!
//! The signer is air-gapped and therefore has no live source of chain
//! truth. Instead of hardcoding protocol constants and computing
//! epoch / KES from a system clock, every request the online tool sends
//! includes a `ChainContext` snapshot. The signer reads this for its
//! header / preview rendering, and persists the latest snapshot locally
//! so the header continues to show "last-known" values between sessions.
//!
//! This means:
//!   * Signer is purely a crypto tool — no Cardano protocol knowledge baked in.
//!   * A hard fork that changes epoch_length etc. is absorbed by the online
//!     tool's runtime fetch from Koios; signer needs no recompile.
//!   * The signer's view of "what epoch is it" is honest — it reflects
//!     the moment of the last received request, not a wall-clock guess.

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../frontend/src/types/core-wire.ts")]
pub struct ChainContext {
    /// Cardano mainnet epoch when the request was built.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub current_epoch: u64,
    /// Absolute slot number when the request was built.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub current_slot: u64,
    /// KES period when the request was built (= current_slot / slots_per_kes_period).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub current_kes_period: u64,
    /// Unix seconds when the current epoch ends (= start of next epoch).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub epoch_ends_at_unix: u64,
    /// Unix seconds when the SPO's currently-deployed opcert expires, or
    /// `None` when the online tool has no local state on it (SPO hasn't
    /// bootstrapped opcert tracking yet).
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[ts(type = "string | null")]
    pub opcert_expires_at_unix: Option<u64>,
    /// Unix seconds when this snapshot was taken on the online tool side.
    /// Lets the signer flag "stale snapshot" if old.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub built_at_unix: u64,
}

/// Maximum forward clock skew tolerated between online tool and signer.
/// Beyond this, a request stamped `built_at_unix > now` is rejected as
/// stale — closes the saturating-subtract bypass where a future-dated
/// request would silently appear fresh forever.
const MAX_FORWARD_CLOCK_SKEW_SECS: u64 = 60;

impl ChainContext {
    /// Returns true when the snapshot is older than `max_age_secs` relative
    /// to `now_unix`, OR when `built_at_unix` is more than 60 seconds in
    /// the future of `now_unix`. Used by the signer to flag preview
    /// screens whose "current epoch / KES period" values may have drifted
    /// out of sync with the live chain.
    pub fn is_stale(&self, now_unix: u64, max_age_secs: u64) -> bool {
        if self.built_at_unix > now_unix.saturating_add(MAX_FORWARD_CLOCK_SKEW_SECS) {
            return true;
        }
        now_unix.saturating_sub(self.built_at_unix) > max_age_secs
    }
}
