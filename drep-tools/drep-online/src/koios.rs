//! Thin Koios API client for the DRep online tool.
//!
//! Koios is a free, community-run public Cardano API used for read-only
//! chain data (tip, UTxOs, epoch params, DRep info, open proposals) and
//! transaction submission. No API key required (an optional key raises
//! rate limits).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KoiosError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("field `{0}` was null or unparseable")]
    BadField(&'static str),
}

// ---------------------------------------------------------------------------
// Transient-failure retry. Koios's public endpoint rate-limits bursts with
// HTTP 429, and the online tool fires several calls per action, so a single
// 429 would otherwise fail the whole operation. Retries 429 / 5xx /
// connection timeouts with exponential backoff (honouring `Retry-After` when
// present). Re-submitting the same signed transaction is safe (identical tx
// hash, the ledger cannot apply it twice).
// ---------------------------------------------------------------------------

/// Total send attempts before giving up (initial try + retries).
const MAX_ATTEMPTS: u32 = 4;

/// Longest single pause between attempts. `Retry-After` comes from an
/// unauthenticated upstream; without a cap a hostile or misconfigured
/// Koios URL replying `429 Retry-After: 999999999` would park the handler
/// future — and the operator's browser request — indefinitely.
const MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

async fn send_with_retry(
    req: reqwest::RequestBuilder,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut attempt: u32 = 1;
    loop {
        let this = req
            .try_clone()
            .expect("Koios requests carry cloneable bodies");
        match this.send().await {
            Ok(resp) => {
                let status = resp.status();
                let retryable = status.as_u16() == 429 || status.is_server_error();
                if retryable && attempt < MAX_ATTEMPTS {
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

// ---------------------------------------------------------------------------
// tip
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tip {
    pub hash: String,
    pub epoch_no: u64,
    pub abs_slot: u64,
    pub block_height: u64,
    pub block_time: u64,
}

pub async fn tip(client: &reqwest::Client, base_url: &str) -> Result<Tip, KoiosError> {
    let url = format!("{base_url}/tip");
    let tips: Vec<Tip> = send_with_retry(client.get(&url)).await?.error_for_status()?.json().await?;
    tips.into_iter().next().ok_or(KoiosError::BadField("tip"))
}

// ---------------------------------------------------------------------------
// address_utxos
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
    /// Native assets at this UTxO as shared `Asset`s. An unparseable
    /// quantity is a hard error: every input asset must come back in the
    /// change output, so silently dropping one would build an unbalanced
    /// transaction that the ledger only rejects at submission.
    pub fn assets(&self) -> Result<Vec<airgap_core::asset::Asset>, KoiosError> {
        self.asset_list
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|a| {
                Ok(airgap_core::asset::Asset {
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
    let body = AddressesRequest { _addresses: &[address], _extended: true };
    // Koios caps array responses at 1000 rows, so a single request silently
    // truncates the UTxO set of a busy address — and with it the spendable
    // total and the change output. Page via `offset` until a short page
    // marks the end.
    let mut all: Vec<Utxo> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let url = format!(
            "{base_url}/address_utxos?order=tx_hash.asc,tx_index.asc&limit={PAGE_ROWS}&offset={offset}"
        );
        let page: Vec<Utxo> =
            send_with_retry(client.post(&url).json(&body)).await?.error_for_status()?.json().await?;
        let short_page = page.len() < PAGE_ROWS;
        all.extend(page);
        if short_page {
            return Ok(all);
        }
        offset += PAGE_ROWS;
    }
}

// ---------------------------------------------------------------------------
// epoch_params — current protocol parameters (drep_deposit, drep_activity)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EpochParams {
    /// DRep registration deposit, lovelace (string on the wire). Null in
    /// pre-Conway epochs, hence Option — Koios returns a row per epoch.
    #[serde(default)]
    pub drep_deposit: Option<String>,
    /// Epochs of inactivity before a DRep goes dormant.
    #[serde(default)]
    pub drep_activity: Option<u64>,
}

pub async fn epoch_params(client: &reqwest::Client, base_url: &str) -> Result<EpochParams, KoiosError> {
    // Fetch only the latest epoch. Koios returns a row for every epoch and the
    // pre-Conway rows carry null DRep params, which would otherwise break
    // decoding the whole array into a non-null `drep_deposit`.
    let url = format!("{base_url}/epoch_params?order=epoch_no.desc&limit=1");
    let rows: Vec<EpochParams> =
        send_with_retry(client.get(&url)).await?.error_for_status()?.json().await?;
    rows.into_iter().next().ok_or(KoiosError::BadField("epoch_params"))
}

/// Current DRep registration deposit in lovelace, parsed from epoch_params.
pub async fn drep_deposit_lovelace(client: &reqwest::Client, base_url: &str) -> Result<u64, KoiosError> {
    let p = epoch_params(client, base_url).await?;
    p.drep_deposit
        .ok_or(KoiosError::BadField("drep_deposit"))?
        .parse()
        .map_err(|_| KoiosError::BadField("drep_deposit"))
}

// ---------------------------------------------------------------------------
// drep_info — registration state of a DRep (deposit, status, voting power)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DrepInfo {
    pub drep_id: String,
    pub hex: String,
    #[serde(default)]
    pub has_script: bool,
    /// "registered" | "deregistered" | …
    #[serde(default)]
    pub drep_status: Option<String>,
    /// Deposit currently locked, lovelace (null when not registered). This
    /// is the refund amount on retirement.
    #[serde(default)]
    pub deposit: Option<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub expires_epoch_no: Option<u64>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub meta_url: Option<String>,
    #[serde(default)]
    pub meta_hash: Option<String>,
}

#[derive(Serialize)]
struct DrepIdsRequest<'a> {
    _drep_ids: &'a [&'a str],
}

pub async fn drep_info(
    client: &reqwest::Client,
    base_url: &str,
    drep_id_bech32: &str,
) -> Result<Option<DrepInfo>, KoiosError> {
    let url = format!("{base_url}/drep_info");
    let body = DrepIdsRequest { _drep_ids: &[drep_id_bech32] };
    let rows: Vec<DrepInfo> =
        send_with_retry(client.post(&url).json(&body)).await?.error_for_status()?.json().await?;
    Ok(rows.into_iter().next())
}

// ---------------------------------------------------------------------------
// proposal_list — open governance actions, for the DRep vote picker.
// A DRep votes on every action type, so unlike the SPO tool nothing is
// filtered out here.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proposal {
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
    pub meta_url: Option<String>,
    #[serde(default)]
    pub meta_json: Option<serde_json::Value>,
}

pub async fn proposal_list(client: &reqwest::Client, base_url: &str) -> Result<Vec<Proposal>, KoiosError> {
    let url = format!(
        "{base_url}/proposal_list?ratified_epoch=is.null&enacted_epoch=is.null&dropped_epoch=is.null&expired_epoch=is.null&order=block_time.desc"
    );
    let rows: Vec<Proposal> = send_with_retry(client.get(&url)).await?.error_for_status()?.json().await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// submittx — broadcast a signed transaction.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("submit rejected ({status}): {body}")]
    Rejected { status: u16, body: String },
}

/// Read at most `max` bytes from a response body, chunk by chunk, dropping
/// the rest once the cap is reached — bounds how much a misbehaving or
/// malicious upstream can force the process to allocate. Also used by the
/// manifest-hash handler in `util.rs` (same cap-the-untrusted-body concern).
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

pub async fn submit_tx(client: &reqwest::Client, base_url: &str, tx_cbor: &[u8]) -> Result<String, SubmitError> {
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;
    let url = format!("{base_url}/submittx");
    let resp = send_with_retry(
        client
            .post(&url)
            .header("content-type", "application/cbor")
            .body(tx_cbor.to_vec()),
    )
    .await?;
    let status = resp.status();
    let bytes = read_capped(resp, MAX_RESPONSE_BYTES).await?;
    let body = String::from_utf8_lossy(&bytes).into_owned();
    if !status.is_success() {
        return Err(SubmitError::Rejected { status: status.as_u16(), body });
    }
    let cleaned = body.trim().trim_matches('"').to_string();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SubmitError::Rejected {
            status: 200,
            body: format!("upstream returned 200 but body is not a 64-char hex tx hash: {cleaned:?}"),
        });
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_params_tolerates_null_drep_deposit() {
        // Koios returns a row per epoch; pre-Conway epochs carry null DRep
        // params. The whole array must still decode (regression: a non-null
        // `drep_deposit: String` broke this with "error decoding response body").
        let json = r#"[
            {"epoch_no":400,"drep_deposit":null,"drep_activity":null},
            {"epoch_no":638,"drep_deposit":"500000000","drep_activity":20}
        ]"#;
        let rows: Vec<EpochParams> = serde_json::from_str(json).expect("decodes despite null rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].drep_deposit, None);
        assert_eq!(rows[1].drep_deposit.as_deref(), Some("500000000"));
        assert_eq!(rows[1].drep_activity, Some(20));
    }

    #[test]
    fn parses_utxo_with_assets_ignoring_extra_fields() {
        // Shape mirrors Koios /address_utxos (extra fields present + ignored).
        let json = r#"{
            "tx_hash":"aa","tx_index":2,"address":"addr1...","value":"1500000",
            "stake_address":"stake1...","is_spent":false,
            "asset_list":[
              {"decimals":6,"quantity":"42","policy_id":"0691b2fe","asset_name":"4e49474854","fingerprint":"asset1x"},
              {"decimals":0,"quantity":"7","policy_id":"abcd","asset_name":null,"fingerprint":"asset1y"}
            ]
        }"#;
        let u: Utxo = serde_json::from_str(json).unwrap();
        let assets = u.assets().unwrap();
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0].policy_hex, "0691b2fe");
        assert_eq!(assets[0].asset_name_hex, "4e49474854");
        assert_eq!(assets[0].quantity, 42);
        // null asset_name becomes the empty string.
        assert_eq!(assets[1].asset_name_hex, "");
        assert_eq!(assets[1].quantity, 7);
    }

    #[test]
    fn utxo_without_assets_parses_empty() {
        let json = r#"{"tx_hash":"bb","tx_index":0,"value":"999"}"#;
        let u: Utxo = serde_json::from_str(json).unwrap();
        assert!(u.assets().unwrap().is_empty());
    }

    #[test]
    fn utxo_with_null_asset_list_parses_empty() {
        // Real Koios returns `asset_list: null` (not an absent key) for a
        // pure-ADA UTxO; `#[serde(default)]` alone does not cover null.
        let json = r#"{"tx_hash":"cc","tx_index":0,"value":"999","asset_list":null}"#;
        let u: Utxo = serde_json::from_str(json).unwrap();
        assert!(u.assets().unwrap().is_empty());
    }

    #[test]
    fn unparseable_asset_quantity_is_an_error_not_a_skip() {
        // A garbage/negative quantity must fail hard: every input asset has
        // to reappear in the change output, so a silently dropped asset
        // would produce an unbalanced body rejected only at submission.
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

    #[test]
    fn address_utxos_requests_extended() {
        // Koios returns asset_list only when _extended is true; guard against
        // a regression to false that would silently drop every native asset.
        let body = AddressesRequest { _addresses: &["addr1"], _extended: true };
        let j = serde_json::to_string(&body).unwrap();
        assert!(j.contains("\"_extended\":true"), "{j}");
    }
}
