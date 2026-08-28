//! Thin Koios API client.
//!
//! Koios is a free, community-run public Cardano API, used for read-only
//! chain data (pool info, stake snapshots) and later for transaction submit.
//! No API key needed.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Deserialize a field Koios may send as JSON `null` (e.g. `owners` / `relays`
/// on a pool deregistration row in `/pool_updates`) into the type's default.
/// serde's `default` covers an absent key but not an explicit null.
fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + serde::Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Cardano stake-snapshot rolling window kinds consumed by this tool.
/// Koios returns three rolling snapshots (Mark = upcoming epoch, Set =
/// currently active epoch, Go = previous epoch); only Mark and Set are
/// asked for here, so Go is intentionally absent from the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    Mark,
    Set,
}

impl SnapshotKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapshotKind::Mark => "Mark",
            SnapshotKind::Set => "Set",
        }
    }
}

#[derive(Debug, Error)]
pub enum KoiosError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("pool not found: {0}")]
    PoolNotFound(String),
    #[error("missing snapshot kind `{}` in pool stake snapshots", .0.as_str())]
    MissingSnapshot(SnapshotKind),
    #[error("snapshot field `{0}` was null or unparseable")]
    BadSnapshotField(&'static str),
    #[error("field `{0}` was null or unparseable")]
    BadField(&'static str),
    #[error("response body decode failed: {0}")]
    Decode(String),
}

// ---------------------------------------------------------------------------
// pool_info
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PoolInfo {
    pub pool_id_bech32: String,
    pub meta_json: Option<serde_json::Value>,
    pub meta_url: Option<String>,
    pub meta_hash: Option<String>,
    pub pool_status: String,
    pub active_stake: Option<String>,
    pub live_stake: Option<String>,
    pub live_pledge: Option<String>,
    pub pledge: Option<String>,
    pub margin: Option<f64>,
    pub fixed_cost: Option<String>,
    pub live_saturation: Option<f64>,
    pub live_delegators: Option<u64>,
    pub block_count: Option<u64>,
    pub vrf_key_hash: Option<String>,
    pub reward_addr: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub owners: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub relays: Vec<Relay>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/handlers.ts")]
pub struct Relay {
    #[serde(default)]
    pub dns: Option<String>,
    #[serde(default)]
    pub srv: Option<String>,
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Serialize)]
struct PoolBech32IdsRequest<'a> {
    _pool_bech32_ids: &'a [&'a str],
}

// ---------------------------------------------------------------------------
// Transient-failure retry. Koios's public endpoint rate-limits bursts with
// HTTP 429, and the online tool fires several calls per action, so a single
// 429 would otherwise fail the whole operation. `.send_retry()` is a drop-in
// for `.send()` that retries 429 / 5xx / connection timeouts with exponential
// backoff (honouring `Retry-After` when present). Re-submitting the same
// signed transaction is safe (identical hash; the ledger cannot apply it
// twice).
// ---------------------------------------------------------------------------

/// Total send attempts before giving up (initial try + retries).
const MAX_ATTEMPTS: u32 = 4;

/// Longest single pause between attempts. `Retry-After` comes from an
/// unauthenticated upstream; without a cap a hostile or misconfigured
/// Koios URL replying `429 Retry-After: 999999999` would park the handler
/// future — and the operator's browser request — indefinitely.
const MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

trait SendRetry {
    fn send_retry(
        self,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>;
}

impl SendRetry for reqwest::RequestBuilder {
    // The explicit `impl Future` return mirrors the trait declaration; clippy's
    // async-fn rewrite is intentionally not adopted to keep the two symmetric.
    #[allow(clippy::manual_async_fn)]
    fn send_retry(
        self,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        async move {
            let mut attempt: u32 = 1;
            loop {
                let this = self
                    .try_clone()
                    .expect("Koios requests carry cloneable bodies");
                match this.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if (status.as_u16() == 429 || status.is_server_error())
                            && attempt < MAX_ATTEMPTS
                        {
                            let wait = retry_after(&resp)
                                .unwrap_or_else(|| backoff(attempt))
                                .min(MAX_RETRY_DELAY);
                            tokio::time::sleep(wait).await;
                            attempt += 1;
                            continue;
                        }
                        return Ok(resp);
                    }
                    Err(e) => {
                        if (e.is_timeout() || e.is_connect()) && attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(backoff(attempt)).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(e);
                    }
                }
            }
        }
    }
}

/// Exponential backoff: 300ms, 600ms, 1200ms, ...
fn backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(300u64 * 2u64.saturating_pow(attempt - 1))
}

/// Parse a `Retry-After: <seconds>` header, if present and integer-valued.
fn retry_after(resp: &reqwest::Response) -> Option<std::time::Duration> {
    let secs: u64 = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(std::time::Duration::from_secs(secs))
}

pub async fn pool_info(
    client: &reqwest::Client,
    base_url: &str,
    pool_id_bech32: &str,
) -> Result<PoolInfo, KoiosError> {
    let url = format!("{base_url}/pool_info");
    let body = PoolBech32IdsRequest {
        _pool_bech32_ids: &[pool_id_bech32],
    };
    let pools: Vec<PoolInfo> = client
        .post(&url)
        .json(&body)
        .send_retry()
        .await?
        .error_for_status()?
        .json_capped()
        .await?;
    pools
        .into_iter()
        .next()
        .ok_or_else(|| KoiosError::PoolNotFound(pool_id_bech32.to_string()))
}

// ---------------------------------------------------------------------------
// pool_updates — full history of registration/retirement certs for a pool.
// ---------------------------------------------------------------------------
//
// Used to detect pending pool parameter updates: rows whose
// `active_epoch_no` is strictly greater than the current tip's epoch are
// not yet in effect. The latest such row (by `block_time`) is what the
// chain will activate next, since later registrations supersede earlier
// ones with the same activation epoch.

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PoolUpdate {
    pub tx_hash: String,
    pub block_time: u64,
    pub pool_id_bech32: String,
    pub active_epoch_no: u64,
    pub vrf_key_hash: Option<String>,
    pub margin: Option<f64>,
    pub fixed_cost: Option<String>,
    pub pledge: Option<String>,
    pub reward_addr: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub owners: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub relays: Vec<Relay>,
    pub meta_url: Option<String>,
    pub meta_hash: Option<String>,
    pub update_type: String,
    pub retiring_epoch: Option<u64>,
}

pub async fn pool_updates(
    client: &reqwest::Client,
    base_url: &str,
    pool_id_bech32: &str,
) -> Result<Vec<PoolUpdate>, KoiosError> {
    // Koios caps array responses at 1000 rows; a long-lived pool with a
    // deep registration history would be silently truncated, and the
    // dropped rows could include the currently-active registration. Page
    // via `offset` until a short page marks the end; the explicit `order`
    // keeps pagination stable (the consumer's pick is order-independent).
    let mut all: Vec<PoolUpdate> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let url = format!(
            "{base_url}/pool_updates?_pool_bech32={pool_id_bech32}&order=block_time.asc&limit={PAGE_ROWS}&offset={offset}"
        );
        let page: Vec<PoolUpdate> = client
            .get(&url)
            .send_retry()
            .await?
            .error_for_status()?
            .json_capped()
            .await?;
        let short_page = page.len() < PAGE_ROWS;
        all.extend(page);
        if short_page {
            return Ok(all);
        }
        offset += PAGE_ROWS;
    }
}

// ---------------------------------------------------------------------------
// pool_stake_snapshot
// ---------------------------------------------------------------------------

/// One row from `pool_stake_snapshot`. Koios returns three rows per pool —
/// one for each of the rolling Cardano stake snapshots (Mark, Set, Go).
///
/// `epoch_no` reports the **target** epoch the snapshot is used for. The
/// names track the snapshot through time as it progresses Mark → Set → Go:
///
/// - `Mark`: stake snapshot for the *next epoch* (`epoch_no = current + 1`).
///   Its nonce is null until the chain enters the current epoch's
///   randomness-stabilisation window (final 4k/f slots ≈ 48 h on mainnet);
///   after that the next-epoch nonce is finalised and Koios populates the
///   field.
/// - `Set`: stake snapshot for the *currently active epoch* (`epoch_no = current`).
///   Its nonce was finalised at the previous epoch's stability window
///   and is therefore always present once Set has rolled over.
/// - `Go`: stake snapshot for the *previous epoch* (`epoch_no = current - 1`).
///   Already past — useful only for historical analysis.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct StakeSnapshot {
    pub snapshot: String,
    pub epoch_no: u64,
    pub nonce: Option<String>,
    pub pool_stake: String,
    pub active_stake: String,
}

#[derive(Serialize)]
struct PoolBech32SingleRequest<'a> {
    _pool_bech32: &'a str,
}

/// Fetch all three (Mark/Set/Go) stake-snapshot rows for a pool.
pub async fn pool_stake_snapshot(
    client: &reqwest::Client,
    base_url: &str,
    pool_id_bech32: &str,
) -> Result<Vec<StakeSnapshot>, KoiosError> {
    let url = format!("{base_url}/pool_stake_snapshot");
    let body = PoolBech32SingleRequest {
        _pool_bech32: pool_id_bech32,
    };
    let snapshots: Vec<StakeSnapshot> = client
        .post(&url)
        .json(&body)
        .send_retry()
        .await?
        .error_for_status()?
        .json_capped()
        .await?;
    Ok(snapshots)
}

/// Convenience: pull the named snapshot and parse pool_stake /
/// active_stake into integers. Returns the raw lovelace values plus the
/// epoch number and nonce — sigma is left to the consumer so the full
/// FixedDecimal precision is preserved through the wire format.
pub fn extract_snapshot(
    snapshots: &[StakeSnapshot],
    kind: SnapshotKind,
) -> Result<ExtractedSnapshot, KoiosError> {
    let snap = snapshots
        .iter()
        .find(|s| s.snapshot.eq_ignore_ascii_case(kind.as_str()))
        .ok_or(KoiosError::MissingSnapshot(kind))?;

    let pool_stake: u64 = snap
        .pool_stake
        .parse()
        .map_err(|_| KoiosError::BadSnapshotField("pool_stake"))?;
    let active_stake: u64 = snap
        .active_stake
        .parse()
        .map_err(|_| KoiosError::BadSnapshotField("active_stake"))?;
    if active_stake == 0 {
        return Err(KoiosError::BadSnapshotField("active_stake"));
    }
    let nonce_hex = snap
        .nonce
        .clone()
        .ok_or(KoiosError::BadSnapshotField("nonce"))?;

    Ok(ExtractedSnapshot {
        epoch_no: snap.epoch_no,
        nonce_hex,
        pool_stake,
        active_stake,
    })
}

#[derive(Debug, Clone)]
pub struct ExtractedSnapshot {
    pub epoch_no: u64,
    pub nonce_hex: String,
    pub pool_stake: u64,
    pub active_stake: u64,
}

// ---------------------------------------------------------------------------
// Shelley era anchors (immutable boundary constants)
// ---------------------------------------------------------------------------
//
// The Shelley boundary slot/epoch/unix-timestamp can never change — they
// were fixed when Shelley activated on 29 July 2020. Cardano protocol
// parameters that *can* in principle change live in `GenesisParams`,
// loaded from Koios.

/// First absolute slot of the Shelley era on mainnet. Slot 4_492_800 was the
/// boundary into epoch 208 when Shelley activated.
pub const SHELLEY_FIRST_SLOT: u64 = 4_492_800;

/// First Shelley epoch number on mainnet.
pub const SHELLEY_FIRST_EPOCH: u64 = 208;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_update_tolerates_null_owners_and_relays() {
        // Koios sends owners: null and relays: null on a pool deregistration
        // row in /pool_updates; serde(default) alone does not cover null.
        let json = r#"{"tx_hash":"aa","block_time":1,"pool_id_bech32":"pool1x",
            "active_epoch_no":500,"update_type":"deregistration",
            "owners":null,"relays":null}"#;
        let u: PoolUpdate = serde_json::from_str(json).unwrap();
        assert!(u.owners.is_empty());
        assert!(u.relays.is_empty());
    }

    /// Tests that need protocol parameters use the values that were live
    /// on mainnet during development. They are NOT runtime defaults — at
    /// runtime they are always fetched from Koios.
    pub(super) fn test_params() -> GenesisParams {
        GenesisParams {
            active_slots_coeff: 0.05,
            epoch_length: 432_000,
            slots_per_kes_period: 129_600,
            kes_max_evolutions: 62,
        }
    }

    /// Sanity check on the slot-time helper. Epoch 208 is the Shelley boundary,
    /// and each subsequent epoch advances by exactly the epoch length.
    #[test]
    fn epoch_first_slot_math() {
        let p = test_params();
        assert_eq!(p.epoch_first_slot(208), SHELLEY_FIRST_SLOT);
        assert_eq!(
            p.epoch_first_slot(209),
            SHELLEY_FIRST_SLOT + p.epoch_length
        );
        // Synthetic distant-epoch check
        assert_eq!(
            p.epoch_first_slot(628),
            SHELLEY_FIRST_SLOT + 420 * p.epoch_length
        );
    }

    /// Praos (post-Vasil) finalises the next-epoch nonce 4k/f slots before
    /// the epoch boundary (48 h on mainnet), not the TPraos-era 3k/f (36 h).
    /// A 3k/f window would refuse "next" leaderlogs for ~12 h while the
    /// Mark nonce is in fact already final.
    #[test]
    fn stability_window_is_4k_over_f() {
        let p = test_params();
        assert_eq!(p.stability_window_slots(), 172_800);
    }

    #[test]
    fn next_epoch_leaderlog_ready_exactly_at_window_start() {
        let p = test_params();
        let unlock = p.next_nonce_finalised_slot(300);
        assert_eq!(unlock, p.epoch_first_slot(301) - 172_800);
        assert!(!p.next_epoch_leaderlog_ready(unlock - 1, 300));
        assert!(p.next_epoch_leaderlog_ready(unlock, 300));
    }

    /// extract_snapshot on a synthetic payload modelling a typical
    /// pool_stake_snapshot reply with all three rolling snapshots.
    #[test]
    fn extract_snapshot_handles_set() {
        let snapshots = vec![
            StakeSnapshot {
                snapshot: "Go".into(),
                epoch_no: 99,
                nonce: Some(
                    "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdee".into(),
                ),
                pool_stake: "1000000000".into(),
                active_stake: "20000000000000".into(),
            },
            StakeSnapshot {
                snapshot: "Set".into(),
                epoch_no: 100,
                nonce: Some(
                    "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcded".into(),
                ),
                pool_stake: "1100000000".into(),
                active_stake: "21000000000000".into(),
            },
            StakeSnapshot {
                snapshot: "Mark".into(),
                epoch_no: 101,
                nonce: None,
                pool_stake: "1200000000".into(),
                active_stake: "22000000000000".into(),
            },
        ];
        let set = extract_snapshot(&snapshots, SnapshotKind::Set).expect("Set snapshot present");
        assert_eq!(set.epoch_no, 100);
        assert_eq!(set.pool_stake, 1_100_000_000);
        assert_eq!(set.active_stake, 21_000_000_000_000);
    }

    /// Mark snapshot has nonce=null because next-next-epoch nonce is not
    /// finalised yet. extract_snapshot must reject it explicitly so callers
    /// do not silently get a bad request later.
    #[test]
    fn extract_snapshot_rejects_mark_with_null_nonce() {
        let snapshots = vec![StakeSnapshot {
            snapshot: "Mark".into(),
            epoch_no: 101,
            nonce: None,
            pool_stake: "1200000000".into(),
            active_stake: "22000000000000".into(),
        }];
        assert!(matches!(
            extract_snapshot(&snapshots, SnapshotKind::Mark),
            Err(KoiosError::BadSnapshotField("nonce"))
        ));
    }
}

// ---------------------------------------------------------------------------
// Slot <-> wall-clock time
// ---------------------------------------------------------------------------
//
// Shelley activated on mainnet at absolute slot 4_492_800. From that point
// on, one slot equals one second. Slot 4_492_800 mapped to UTC timestamp
// 1596059091 (2020-07-29 21:44:51 UTC).

/// UNIX timestamp (seconds since epoch) for the first Shelley slot.
pub const SHELLEY_FIRST_SLOT_UNIX: u64 = 1_596_059_091;

/// Convert a mainnet absolute slot number to UNIX seconds. Only valid for
/// slots in the Shelley era and later (slot >= SHELLEY_FIRST_SLOT).
/// Pre-Shelley slots are nonsensical for this flow (Koios would have to
/// return a tip from the Byron era). The subtraction saturates to the
/// Shelley boundary and the addition saturates at u64::MAX, so an
/// out-of-range or hostile slot can neither panic (debug / overflow-checks)
/// nor wrap.
pub fn slot_to_unix_time(slot: u64) -> u64 {
    SHELLEY_FIRST_SLOT_UNIX.saturating_add(slot.saturating_sub(SHELLEY_FIRST_SLOT))
}

#[cfg(test)]
mod time_tests {
    use super::*;

    #[test]
    fn shelley_first_slot_maps_to_genesis_timestamp() {
        assert_eq!(slot_to_unix_time(SHELLEY_FIRST_SLOT), SHELLEY_FIRST_SLOT_UNIX);
    }

    #[test]
    fn next_slot_advances_one_second() {
        assert_eq!(
            slot_to_unix_time(SHELLEY_FIRST_SLOT + 1),
            SHELLEY_FIRST_SLOT_UNIX + 1
        );
    }
}

// ---------------------------------------------------------------------------
// KES — chain tip, pool blocks, block info
// ---------------------------------------------------------------------------
//
// Rotating KES requires:
//   1. The current absolute slot   (from /tip), to compute the current
//      KES period for the new opcert.
//   2. The on-chain op_cert_counter  (from the latest block this pool
//      produced; read via /pool_blocks then /block_info), so that a
//      counter strictly greater than what the chain has already seen can be picked.

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tip {
    pub hash: String,
    pub epoch_no: u64,
    pub abs_slot: u64,
    pub block_height: u64,
    pub block_time: u64,
}

/// Fetch the current chain tip from Koios.
pub async fn tip(client: &reqwest::Client, base_url: &str) -> Result<Tip, KoiosError> {
    let url = format!("{base_url}/tip");
    let tips: Vec<Tip> = client
        .get(&url)
        .send_retry()
        .await?
        .error_for_status()?
        .json_capped()
        .await?;
    tips.into_iter()
        .next()
        .ok_or(KoiosError::BadSnapshotField("tip"))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PoolBlock {
    pub block_hash: String,
    pub abs_slot: u64,
    pub epoch_no: u64,
    pub epoch_slot: u64,
    pub block_height: u64,
    pub block_time: u64,
}

/// Fetch the most recent blocks produced by `pool_id_bech32`. Pulls a
/// small window (`limit`) ordered by absolute slot descending; the caller
/// picks the head.
pub async fn pool_blocks(
    client: &reqwest::Client,
    base_url: &str,
    pool_id_bech32: &str,
    limit: usize,
) -> Result<Vec<PoolBlock>, KoiosError> {
    let url = format!(
        "{base_url}/pool_blocks?_pool_bech32={pool_id_bech32}&order=abs_slot.desc&limit={limit}"
    );
    let rows: Vec<PoolBlock> = client
        .get(&url)
        .send_retry()
        .await?
        .error_for_status()?
        .json_capped()
        .await?;
    Ok(rows)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockInfo {
    pub hash: String,
    pub epoch_no: u64,
    pub abs_slot: u64,
    pub block_height: u64,
    pub block_time: u64,
    /// 32-byte hex of the hot KES verification key for the producing pool.
    pub op_cert: String,
    /// Issue counter of the operational certificate that produced this block.
    pub op_cert_counter: u64,
    pub pool: Option<String>,
}

/// Look up a single block by hash and return its op_cert_counter etc.
pub async fn block_info(
    client: &reqwest::Client,
    base_url: &str,
    block_hash: &str,
) -> Result<BlockInfo, KoiosError> {
    #[derive(Serialize)]
    struct Req<'a> {
        _block_hashes: &'a [&'a str],
    }
    let url = format!("{base_url}/block_info");
    let body = Req {
        _block_hashes: &[block_hash],
    };
    let rows: Vec<BlockInfo> = client
        .post(&url)
        .json(&body)
        .send_retry()
        .await?
        .error_for_status()?
        .json_capped()
        .await?;
    rows.into_iter()
        .next()
        .ok_or_else(|| KoiosError::PoolNotFound(block_hash.to_string()))
}

#[cfg(test)]
mod kes_tests {
    use super::tests::test_params;

    #[test]
    fn slot_to_kes_period_math() {
        let p = test_params();
        assert_eq!(p.slot_to_kes_period(0), 0);
        assert_eq!(p.slot_to_kes_period(p.slots_per_kes_period - 1), 0);
        assert_eq!(p.slot_to_kes_period(p.slots_per_kes_period), 1);
        // Synthetic check that slot/period math is consistent:
        // slot 1_510_000 / slots_per_kes_period (129_600) = period 11.
        assert_eq!(p.slot_to_kes_period(1_510_000), 11);
    }
}

#[cfg(test)]
mod opcert_validity_tests {
    use super::*;
    use super::tests::test_params;

    #[test]
    fn end_period_is_start_plus_61() {
        let p = test_params();
        assert_eq!(p.opcert_end_kes_period(1372), 1433);
        assert_eq!(p.opcert_end_kes_period(0), 61);
    }

    #[test]
    fn expires_at_slot_is_start_plus_62_periods() {
        let p = test_params();
        // Start period 1372 → first slot of period 1434 = 1434 * 129600
        assert_eq!(p.opcert_expires_at_slot(1372), 1434 * p.slots_per_kes_period);
    }

    #[test]
    fn expires_at_unix_matches_slot_translation() {
        let p = test_params();
        let start = 1372;
        let expiry_slot = p.opcert_expires_at_slot(start);
        assert_eq!(p.opcert_expires_at_unix(start), slot_to_unix_time(expiry_slot));
    }
}
// ---------------------------------------------------------------------------
// Cardano protocol parameters (fetched from chain at startup)
// ---------------------------------------------------------------------------
//
// These are never hardcoded. If Koios is unreachable when fetching
// them, the tool refuses to do period math rather than silently using
// stale or assumed values. Helpers that depend on them are methods on
// `GenesisParams`, so the type system forces every caller to obtain the
// real values first.

#[derive(Debug, Clone, Copy)]
pub struct GenesisParams {
    /// Active slots coefficient (`f`) — fraction of slots in which a leader
    /// is expected to be elected. Mainnet: 0.05.
    pub active_slots_coeff: f64,
    /// Slots per epoch. Mainnet: 432_000 (5 days at 1 slot/sec).
    pub epoch_length: u64,
    /// Slots per KES period. Mainnet: 129_600 (1.5 days at 1 slot/sec).
    pub slots_per_kes_period: u64,
    /// Maximum number of KES evolutions per opcert. Mainnet: 62
    /// (Sum6Kes itself supports 64 cryptographically; the protocol caps
    /// each opcert at 62 to leave headroom).
    pub kes_max_evolutions: u64,
}

impl GenesisParams {
    /// Compute the absolute first slot of the given mainnet epoch.
    pub fn epoch_first_slot(&self, epoch: u64) -> u64 {
        SHELLEY_FIRST_SLOT.saturating_add(
            epoch
                .saturating_sub(SHELLEY_FIRST_EPOCH)
                .saturating_mul(self.epoch_length),
        )
    }

    /// Map an absolute mainnet slot to its KES period index.
    pub fn slot_to_kes_period(&self, slot: u64) -> u64 {
        slot / self.slots_per_kes_period
    }

    /// Last KES period in which an opcert with `start_kes_period = start`
    /// is still valid (inclusive).
    pub fn opcert_end_kes_period(&self, start_kes_period: u64) -> u64 {
        start_kes_period
            .saturating_add(self.kes_max_evolutions)
            .saturating_sub(1)
    }

    /// Absolute slot at which the opcert expires (= the first slot of the
    /// period immediately after the validity window).
    pub fn opcert_expires_at_slot(&self, start_kes_period: u64) -> u64 {
        start_kes_period
            .saturating_add(self.kes_max_evolutions)
            .saturating_mul(self.slots_per_kes_period)
    }

    /// Unix seconds at which the opcert expires.
    pub fn opcert_expires_at_unix(&self, start_kes_period: u64) -> u64 {
        slot_to_unix_time(self.opcert_expires_at_slot(start_kes_period))
    }

    /// Length of the randomness-stabilisation window in slots (4k/f).
    /// During the final stability_window slots of an epoch, no further
    /// VRF outputs contribute to the next epoch's nonce — so the
    /// next-epoch nonce is finalised once the chain enters this window.
    /// TPraos used 3k/f; since the Babbage/Praos era (post-Vasil) the
    /// window is 4k/f. On mainnet: 4 × 2160 / 0.05 = 172_800 slots
    /// = 48 hours.
    pub fn stability_window_slots(&self) -> u64 {
        ((4.0 * MAINNET_SECURITY_PARAM as f64) / self.active_slots_coeff).round() as u64
    }

    /// Slot at which the stability window of `current_epoch` begins —
    /// equivalently, the slot at which the nonce for `current_epoch + 1`
    /// becomes final.
    pub fn next_nonce_finalised_slot(&self, current_epoch: u64) -> u64 {
        self.epoch_first_slot(current_epoch.saturating_add(1))
            .saturating_sub(self.stability_window_slots())
    }

    /// True when `current_slot` is at or beyond the start of the current
    /// epoch's stability window — i.e. a leaderlog for the next epoch
    /// can be safely computed.
    pub fn next_epoch_leaderlog_ready(&self, current_slot: u64, current_epoch: u64) -> bool {
        current_slot >= self.next_nonce_finalised_slot(current_epoch)
    }
}

/// Cardano mainnet security parameter `k`. Set at Shelley launch
/// (2020-07-29) and only changeable by hard fork. Not exposed in Koios
/// `/genesis`, so it lives here as a constant rather than runtime
/// configuration.
pub const MAINNET_SECURITY_PARAM: u64 = 2160;

#[derive(Deserialize)]
struct GenesisRow {
    activeslotcoeff: String,
    epochlength: String,
    slotsperkesperiod: String,
    maxkesrevolutions: String,
}

/// Fetch the four chain-tunable mainnet parameters of interest from
/// Koios `/genesis`. Caller stores the result in the app state.
pub async fn fetch_genesis_params(client: &reqwest::Client, base_url: &str) -> Result<GenesisParams, KoiosError> {
    let url = format!("{base_url}/genesis");
    let rows: Vec<GenesisRow> = client
        .get(&url)
        .send_retry()
        .await?
        .error_for_status()?
        .json_capped()
        .await?;
    let r = rows
        .into_iter()
        .next()
        .ok_or(KoiosError::BadSnapshotField("genesis"))?;
    Ok(GenesisParams {
        active_slots_coeff: r
            .activeslotcoeff
            .parse()
            .map_err(|_| KoiosError::BadSnapshotField("activeslotcoeff"))?,
        epoch_length: r
            .epochlength
            .parse()
            .map_err(|_| KoiosError::BadSnapshotField("epochlength"))?,
        slots_per_kes_period: r
            .slotsperkesperiod
            .parse()
            .map_err(|_| KoiosError::BadSnapshotField("slotsperkesperiod"))?,
        kes_max_evolutions: r
            .maxkesrevolutions
            .parse()
            .map_err(|_| KoiosError::BadSnapshotField("maxkesrevolutions"))?,
    })
}

// ---------------------------------------------------------------------------
// address_utxos — UTXOs at a given payment address. Used for tx-input
// selection (e.g. funding a withdrawal tx fee).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Utxo {
    pub tx_hash: String,
    pub tx_index: u32,
    pub value: String,
    #[serde(default)]
    pub block_time: Option<u64>,
    /// Native assets at this UTxO. Koios sends `null` for a pure-ADA UTxO.
    #[serde(default)]
    pub asset_list: Option<Vec<KoiosAsset>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KoiosAsset {
    pub policy_id: String,
    #[serde(default)]
    pub asset_name: Option<String>,
    pub quantity: String,
}

impl Utxo {
    /// Native assets at this UTxO as shared `Asset`s. spo spends every UTxO and
    /// all of these must come back in the change output, so silently dropping
    /// one would build an unbalanced transaction that the ledger only rejects
    /// at submission.
    pub fn assets(&self) -> Result<Vec<shared::asset::Asset>, KoiosError> {
        self.asset_list
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|a| {
                Ok(shared::asset::Asset {
                    policy_hex: a.policy_id.clone(),
                    asset_name_hex: a.asset_name.clone().unwrap_or_default(),
                    quantity: a
                        .quantity
                        .parse()
                        .map_err(|_| KoiosError::BadField("asset quantity"))?,
                })
            })
            .collect()
    }
}

#[derive(Serialize)]
struct AddressesRequest<'a> {
    _addresses: &'a [&'a str],
    _extended: bool,
}

/// Rows per page when paginating Koios array responses (its PostgREST cap).
const PAGE_ROWS: usize = 1000;

pub async fn address_utxos(
    client: &reqwest::Client,
    base_url: &str,
    address: &str,
) -> Result<Vec<Utxo>, KoiosError> {
    // `_extended: true` is required: Koios only populates `asset_list` in the
    // extended response, and the change output must preserve those assets.
    let body = AddressesRequest {
        _addresses: &[address],
        _extended: true,
    };
    // Koios caps array responses at 1000 rows, so a single request silently
    // truncates the UTxO set of a busy address — and with it the spendable
    // total and the change output. Page via `offset` until a short page
    // marks the end; the explicit `order` keeps pagination stable
    // (PostgREST row order is unspecified otherwise, so pages could
    // duplicate or skip rows between requests).
    let mut all: Vec<Utxo> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let url = format!(
            "{base_url}/address_utxos?order=tx_hash.asc,tx_index.asc&limit={PAGE_ROWS}&offset={offset}"
        );
        let page: Vec<Utxo> = client
            .post(&url)
            .json(&body)
            .send_retry()
            .await?
            .error_for_status()?
            .json_capped()
            .await?;
        let short_page = page.len() < PAGE_ROWS;
        all.extend(page);
        if short_page {
            return Ok(all);
        }
        offset += PAGE_ROWS;
    }
}

#[cfg(test)]
mod address_utxos_tests {
    use super::*;

    #[test]
    fn address_utxos_requests_extended() {
        // Koios returns asset_list only when _extended is true; guard against
        // a regression to false that would silently drop every native asset.
        let body = AddressesRequest { _addresses: &["addr1"], _extended: true };
        let j = serde_json::to_string(&body).unwrap();
        assert!(j.contains("\"_extended\":true"), "{j}");
    }

    #[test]
    fn assets_reject_unparseable_quantity() {
        // spo spends every UTxO; a silently dropped asset would build an
        // unbalanced tx rejected only at ledger submission (parity with drep/wallet).
        let json = r#"{
            "tx_hash":"dd","tx_index":0,"value":"999",
            "asset_list":[
              {"quantity":"42","policy_id":"0691b2fe","asset_name":"4e49474854"},
              {"quantity":"-1","policy_id":"abcd","asset_name":null}
            ]
        }"#;
        let u: Utxo = serde_json::from_str(json).unwrap();
        assert!(matches!(u.assets(), Err(KoiosError::BadField("asset quantity"))));
    }
}

// ---------------------------------------------------------------------------
// account_info — stake-account state (delegation, rewards, withdrawals).
// Used for: how much can be withdrawn right now.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountInfo {
    pub stake_address: String,
    pub status: String,
    #[serde(default)]
    pub delegated_pool: Option<String>,
    #[serde(default)]
    pub delegated_drep: Option<String>,
    pub total_balance: String,
    pub utxo: String,
    pub rewards: String,
    pub withdrawals: String,
    pub rewards_available: String,
    pub deposit: String,
}

#[derive(Serialize)]
struct StakeAddressesRequest<'a> {
    _stake_addresses: &'a [&'a str],
}

pub async fn account_info(
    client: &reqwest::Client,
    base_url: &str,
    stake_address: &str,
) -> Result<Option<AccountInfo>, KoiosError> {
    let url = format!("{base_url}/account_info");
    let body = StakeAddressesRequest {
        _stake_addresses: &[stake_address],
    };
    let rows: Vec<AccountInfo> = client
        .post(&url)
        .json(&body)
        .send_retry()
        .await?
        .error_for_status()?
        .json_capped()
        .await?;
    Ok(rows.into_iter().next())
}

// ---------------------------------------------------------------------------
// proposal_list — open governance actions, for the SPO vote picker.
// ---------------------------------------------------------------------------
//
// Koios returns every proposal ever submitted; the query filters to those
// still open (not ratified / enacted / dropped / expired) so the picker
// only offers actions an operator can still vote on. The action id the
// protocol uses is (proposal_tx_hash, proposal_index).

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proposal {
    /// CIP-129 `gov_action1...` bech32 identifier.
    pub proposal_id: Option<String>,
    pub proposal_tx_hash: String,
    pub proposal_index: u32,
    pub proposal_type: String,
    #[serde(default)]
    pub proposal_description: Option<serde_json::Value>,
    #[serde(default)]
    pub proposed_epoch: Option<u64>,
    #[serde(default)]
    pub expiration: Option<u64>,
    #[serde(default)]
    pub ratified_epoch: Option<u64>,
    #[serde(default)]
    pub enacted_epoch: Option<u64>,
    #[serde(default)]
    pub dropped_epoch: Option<u64>,
    #[serde(default)]
    pub expired_epoch: Option<u64>,
    #[serde(default)]
    pub meta_url: Option<String>,
    #[serde(default)]
    pub meta_json: Option<serde_json::Value>,
}

pub async fn proposal_list(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<Vec<Proposal>, KoiosError> {
    // Koios caps array responses at 1000 rows; page via `offset` until a
    // short page marks the end so an open action can never silently fall
    // off the picker (the existing `order` keeps pagination stable).
    let mut all: Vec<Proposal> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let url = format!(
            "{base_url}/proposal_list?ratified_epoch=is.null&enacted_epoch=is.null&dropped_epoch=is.null&expired_epoch=is.null&order=block_time.desc&limit={PAGE_ROWS}&offset={offset}"
        );
        let page: Vec<Proposal> = client
            .get(&url)
            .send_retry()
            .await?
            .error_for_status()?
            .json_capped()
            .await?;
        let short_page = page.len() < PAGE_ROWS;
        all.extend(page);
        if short_page {
            return Ok(all);
        }
        offset += PAGE_ROWS;
    }
}

// ---------------------------------------------------------------------------
// submittx — broadcast a signed transaction to the chain.
// Koios accepts raw CBOR with content-type application/cbor and returns
// the tx hash as a JSON string.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("submit rejected ({status}): {body}")]
    Rejected { status: u16, body: String },
}

/// Read at most `max` bytes from a response body, streaming chunk by
/// chunk and stopping (dropping the rest of the connection) once the cap
/// is reached. Unlike `Response::bytes`, which buffers the entire body
/// into memory before returning, this bounds how much a misbehaving or
/// malicious upstream can force the process to allocate.
pub(crate) async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, reqwest::Error> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        let remaining = max.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break;
        }
    }
    Ok(buf)
}

/// Generous byte cap for a Koios JSON response. The largest bodies this
/// tool reads (a full pool update history, a stake-snapshot set) sit far
/// below this; the cap bounds what a misbehaving or malicious upstream can
/// force the process to allocate, complementing the client request timeout.
const MAX_JSON_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Decode a JSON response body with the byte cap applied, reusing
/// `read_capped` so `Response::json`'s unbounded buffering is never used on
/// an untrusted upstream body. Mirrors the `SendRetry` return-type style.
trait JsonCapped {
    fn json_capped<T: serde::de::DeserializeOwned>(
        self,
    ) -> impl std::future::Future<Output = Result<T, KoiosError>>;
}

impl JsonCapped for reqwest::Response {
    fn json_capped<T: serde::de::DeserializeOwned>(
        self,
    ) -> impl std::future::Future<Output = Result<T, KoiosError>> {
        async move {
            let bytes = read_capped(self, MAX_JSON_RESPONSE_BYTES).await?;
            serde_json::from_slice(&bytes).map_err(|e| KoiosError::Decode(e.to_string()))
        }
    }
}

pub async fn submit_tx(client: &reqwest::Client, base_url: &str, tx_cbor: &[u8]) -> Result<String, SubmitError> {
    /// Hard cap on bytes read from a Koios response. A Cardano tx_hash is
    /// 64 hex chars; without a cap, an HTML error page or a malicious
    /// upstream could stream unbounded data into process memory. The body
    /// is read chunk by chunk and reading stops once this many bytes have
    /// been collected.
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;
    let url = format!("{base_url}/submittx");
    let resp = client
        .post(&url)
        .header("content-type", "application/cbor")
        .body(tx_cbor.to_vec())
        .send_retry()
        .await?;
    let status = resp.status();
    let bytes = read_capped(resp, MAX_RESPONSE_BYTES).await?;
    let body = String::from_utf8_lossy(&bytes).into_owned();
    if !status.is_success() {
        return Err(SubmitError::Rejected {
            status: status.as_u16(),
            body,
        });
    }
    // Koios returns the tx hash as a JSON string ("\"deadbeef…\"") or
    // sometimes plain text — strip any surrounding quotes/whitespace.
    let cleaned = body.trim().trim_matches('"').to_string();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SubmitError::Rejected {
            status: 200,
            body: format!("upstream returned 200 but body is not a 64-char hex tx hash: {cleaned:?}"),
        });
    }
    Ok(cleaned)
}
