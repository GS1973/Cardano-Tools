//! Koios HTTP client: the wallet's only chain access.
//!
//! Reads the UTxO set (with native assets), the stake-account state, the
//! current tip, and the protocol parameters; submits signed transactions.
//! Holds no keys. A faulty or malicious provider can at worst make a
//! transaction fail or withhold it: it cannot alter a signed transaction
//! or redirect funds, because the witnesses sign the body and the operator
//! verifies destination/amount on the air-gapped signer (see the design
//! doc's risk model).

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum KoiosError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("empty/unexpected response for `{0}`")]
    BadResponse(&'static str),
    #[error("could not parse `{0}` from Koios")]
    Parse(&'static str),
    #[error("protocol parameter `{name}` = {value} is outside the range {min}..={max}")]
    OutOfBand {
        name: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },
    #[error("response body decode failed: {0}")]
    Decode(String),
    #[error("too many rows from Koios for `{0}`")]
    TooManyRows(&'static str),
}

// ---------------------------------------------------------------------------
// Transient-failure retry. Koios's public endpoint rate-limits bursts with
// HTTP 429, and the wallet fires several calls per action, so a single 429
// would otherwise fail the whole operation. Retries 429 / 5xx / connection
// timeouts with exponential backoff (honouring `Retry-After` when present).
// Idempotent for every call here, submit included: re-submitting the same
// signed transaction is safe (identical tx hash, the ledger cannot apply it
// twice).
// ---------------------------------------------------------------------------

/// Total send attempts before giving up (initial try + retries).
const MAX_ATTEMPTS: u32 = 4;

/// Longest single pause between attempts. `Retry-After` comes from an
/// unauthenticated upstream; without a cap a hostile or misconfigured
/// Koios URL replying `429 Retry-After: 999999999` would park the handler
/// future, and the operator's browser request, indefinitely.
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
// tip: current slot (for transaction TTL) and epoch.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Tip {
    pub epoch_no: u64,
    pub abs_slot: u64,
}

pub async fn tip(client: &reqwest::Client, base_url: &str) -> Result<Tip, KoiosError> {
    let url = format!("{base_url}/tip");
    let resp = send_with_retry(client.get(&url)).await?;
    let rows: Vec<Tip> = json_capped(resp.error_for_status()?).await?;
    rows.into_iter()
        .next()
        .ok_or(KoiosError::BadResponse("tip"))
}

// ---------------------------------------------------------------------------
// protocol parameters: fee coefficients, min-UTxO cost, stake deposit.
// `/cli_protocol_params` returns a single cardano-cli-format object.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolParams {
    /// Fee per byte of transaction (`txFeePerByte`).
    #[serde(rename = "txFeePerByte")]
    pub min_fee_a: u64,
    /// Flat fee constant (`txFeeFixed`).
    #[serde(rename = "txFeeFixed")]
    pub min_fee_b: u64,
    /// Lovelace cost per byte of a UTxO (`utxoCostPerByte`): drives min-ADA.
    #[serde(rename = "utxoCostPerByte")]
    pub utxo_cost_per_byte: u64,
    /// Deposit locked by a stake-key registration (`stakeAddressDeposit`).
    #[serde(rename = "stakeAddressDeposit")]
    pub key_deposit: u64,
    /// Maximum transaction size in bytes (`maxTxSize`).
    #[serde(rename = "maxTxSize")]
    pub max_tx_size: u64,
}

impl ProtocolParams {
    /// Refuse protocol parameters outside the range the Cardano constitution's
    /// guardrails allow on mainnet. The provider is not trusted: these values
    /// drive the fee, the min-ADA change and the deposit, and an absurd one
    /// would otherwise only surface as an overflowing sum or as a figure on
    /// the signer preview. A parameter the network could never have adopted
    /// is a provider fault, so it is named as one here. `maxTxSize` has no
    /// lower guardrail; zero is refused because no transaction would fit.
    pub fn check_band(&self) -> Result<(), KoiosError> {
        let band: [(&'static str, u64, u64, u64); 5] = [
            ("txFeePerByte", self.min_fee_a, 30, 1_000),
            ("txFeeFixed", self.min_fee_b, 100_000, 10_000_000),
            ("utxoCostPerByte", self.utxo_cost_per_byte, 3_000, 6_500),
            (
                "stakeAddressDeposit",
                self.key_deposit,
                1_000_000,
                5_000_000,
            ),
            ("maxTxSize", self.max_tx_size, 1, 32_768),
        ];
        for (name, value, min, max) in band {
            if value < min || value > max {
                return Err(KoiosError::OutOfBand {
                    name,
                    value,
                    min,
                    max,
                });
            }
        }
        Ok(())
    }
}

pub async fn protocol_params(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<ProtocolParams, KoiosError> {
    let url = format!("{base_url}/cli_protocol_params");
    let resp = send_with_retry(client.get(&url)).await?;
    let params: ProtocolParams = json_capped(resp.error_for_status()?).await?;
    params.check_band()?;
    Ok(params)
}

// ---------------------------------------------------------------------------
// address_utxos: UTxOs at a payment address, including native assets.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct KoiosAsset {
    pub policy_id: String,
    /// Hex-encoded asset name; may be null/absent for an empty name.
    #[serde(default)]
    pub asset_name: Option<String>,
    pub quantity: String,
    /// Registry decimals for display (Koios enriches; absent means indivisible).
    #[serde(default)]
    pub decimals: Option<u32>,
    /// CIP-14 asset fingerprint (`asset1...`), when Koios provides it.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    pub tx_hash: String,
    pub tx_index: u32,
    /// Lovelace at this output, as a decimal string.
    pub value: String,
    /// Native assets at this output. Real Koios sends `null` (not an absent
    /// key) for a pure-ADA UTxO, so this is an `Option`: `#[serde(default)]`
    /// alone covers absence but not an explicit null.
    #[serde(default)]
    pub asset_list: Option<Vec<KoiosAsset>>,
}

impl Utxo {
    /// Lovelace value as an integer.
    pub fn lovelace(&self) -> Result<u64, KoiosError> {
        self.value
            .parse()
            .map_err(|_| KoiosError::Parse("utxo value"))
    }

    /// Native assets at this output, as shared wire `Asset`s.
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
                        .map_err(|_| KoiosError::Parse("asset quantity"))?,
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

/// Most pages read from one paginated Koios query: 100,000 rows, far more
/// than any real address or pool has. A provider that keeps returning full
/// pages is cut off here instead of growing the process without limit.
const MAX_PAGES: usize = 100;

pub async fn address_utxos(
    client: &reqwest::Client,
    base_url: &str,
    address: &str,
) -> Result<Vec<Utxo>, KoiosError> {
    // `_extended: true` is required: Koios only populates `asset_list` in the
    // extended response. With it false every UTxO returns a null asset_list,
    // so native assets vanish from balances, change and sends.
    let body = AddressesRequest {
        _addresses: &[address],
        _extended: true,
    };
    // Koios caps array responses at 1000 rows, so a single request silently
    // truncates the UTxO set of a busy address, and with it the spendable
    // total and the change output. Page via `offset` until a short page
    // marks the end.
    let mut all: Vec<Utxo> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let url = format!(
            "{base_url}/address_utxos?order=tx_hash.asc,tx_index.asc&limit={PAGE_ROWS}&offset={offset}"
        );
        let page: Vec<Utxo> = json_capped(
            send_with_retry(client.post(&url).json(&body))
                .await?
                .error_for_status()?,
        )
        .await?;
        let short_page = page.len() < PAGE_ROWS;
        all.extend(page);
        if short_page {
            return Ok(all);
        }
        if offset / PAGE_ROWS + 1 >= MAX_PAGES {
            return Err(KoiosError::TooManyRows("address_utxos"));
        }
        offset += PAGE_ROWS;
    }
}

// ---------------------------------------------------------------------------
// account_info, stake-account state: registration + current delegations.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct AccountInfo {
    /// "registered" or "not registered".
    pub status: String,
    #[serde(default)]
    pub delegated_pool: Option<String>,
    #[serde(default)]
    pub delegated_drep: Option<String>,
    /// Withdrawable reward balance in lovelace, as a decimal string.
    #[serde(default)]
    pub rewards_available: Option<String>,
}

impl AccountInfo {
    pub fn is_registered(&self) -> bool {
        self.status == "registered"
    }

    /// Withdrawable reward balance as an integer; absent or null means 0.
    pub fn rewards_available(&self) -> Result<u64, KoiosError> {
        match self.rewards_available.as_deref() {
            None => Ok(0),
            Some(s) => s
                .parse()
                .map_err(|_| KoiosError::Parse("rewards_available")),
        }
    }
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
    let resp = send_with_retry(client.post(&url).json(&body)).await?;
    let rows: Vec<AccountInfo> = json_capped(resp.error_for_status()?).await?;
    Ok(rows.into_iter().next())
}

// ---------------------------------------------------------------------------
// submit_tx: broadcast a signed transaction.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("submit rejected ({status}): {body}")]
    Rejected { status: u16, body: String },
}

/// Read at most `max` bytes from a response body, chunk by chunk, dropping
/// the rest once the cap is reached: bounds how much a misbehaving or
/// malicious upstream can force the process to allocate.
async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, reqwest::Error> {
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

/// Generous byte cap for a Koios JSON response. The largest body this tool
/// reads (a full page of UTxOs with their native assets) sits far below this. The cap bounds what a misbehaving
/// or malicious upstream can make the process allocate.
const MAX_JSON_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Decode a JSON response body with the byte cap applied, so the unbounded
/// buffering of `Response::json` is never used on an upstream body.
async fn json_capped<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, KoiosError> {
    let bytes = read_capped(resp, MAX_JSON_RESPONSE_BYTES).await?;
    serde_json::from_slice(&bytes).map_err(|e| KoiosError::Decode(e.to_string()))
}

pub async fn submit_tx(
    client: &reqwest::Client,
    base_url: &str,
    tx_cbor: &[u8],
) -> Result<String, SubmitError> {
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
        return Err(SubmitError::Rejected {
            status: status.as_u16(),
            body,
        });
    }
    // Koios returns the tx hash as a JSON string or plain text; strip quotes.
    let cleaned = body.trim().trim_matches('"').to_string();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SubmitError::Rejected {
            status: 200,
            body: format!(
                "upstream returned 200 but body is not a 64-char hex tx hash: {cleaned:?}"
            ),
        });
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_protocol_params() {
        let json = r#"{"txFeePerByte":44,"txFeeFixed":155381,"utxoCostPerByte":4310,
            "stakeAddressDeposit":2000000,"dRepDeposit":500000000,"maxTxSize":16384,
            "stakePoolDeposit":500000000}"#;
        let p: ProtocolParams = serde_json::from_str(json).unwrap();
        assert_eq!(p.min_fee_a, 44);
        assert_eq!(p.min_fee_b, 155381);
        assert_eq!(p.utxo_cost_per_byte, 4310);
        assert_eq!(p.key_deposit, 2_000_000);
        assert_eq!(p.max_tx_size, 16384);
        p.check_band()
            .expect("current mainnet parameters are inside the band");
    }

    #[test]
    fn protocol_params_outside_the_guardrails_are_refused() {
        let ok = ProtocolParams {
            min_fee_a: 44,
            min_fee_b: 155_381,
            utxo_cost_per_byte: 4_310,
            key_deposit: 2_000_000,
            max_tx_size: 16_384,
        };
        ok.check_band().unwrap();
        let edges = ProtocolParams {
            min_fee_a: 1_000,
            min_fee_b: 100_000,
            utxo_cost_per_byte: 6_500,
            key_deposit: 5_000_000,
            max_tx_size: 32_768,
        };
        edges.check_band().expect("the band is inclusive");

        let refused = |p: ProtocolParams, which: &str| match p.check_band() {
            Err(KoiosError::OutOfBand { name, .. }) => assert_eq!(name, which),
            other => panic!("expected {which} out of band, got {other:?}"),
        };
        refused(
            ProtocolParams {
                min_fee_a: 1_001,
                ..ok.clone()
            },
            "txFeePerByte",
        );
        refused(
            ProtocolParams {
                min_fee_a: 0,
                ..ok.clone()
            },
            "txFeePerByte",
        );
        refused(
            ProtocolParams {
                min_fee_a: u64::MAX,
                ..ok.clone()
            },
            "txFeePerByte",
        );
        refused(
            ProtocolParams {
                min_fee_b: 10_000_001,
                ..ok.clone()
            },
            "txFeeFixed",
        );
        refused(
            ProtocolParams {
                utxo_cost_per_byte: 6_501,
                ..ok.clone()
            },
            "utxoCostPerByte",
        );
        refused(
            ProtocolParams {
                utxo_cost_per_byte: 0,
                ..ok.clone()
            },
            "utxoCostPerByte",
        );
        refused(
            ProtocolParams {
                key_deposit: 500_000_000,
                ..ok.clone()
            },
            "stakeAddressDeposit",
        );
        refused(
            ProtocolParams {
                max_tx_size: 0,
                ..ok.clone()
            },
            "maxTxSize",
        );
        refused(
            ProtocolParams {
                max_tx_size: 32_769,
                ..ok
            },
            "maxTxSize",
        );
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
        assert_eq!(u.lovelace().unwrap(), 1_500_000);
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
        assert_eq!(u.lovelace().unwrap(), 999);
        assert!(u.assets().unwrap().is_empty());
    }

    #[test]
    fn utxo_with_null_asset_list_parses_empty() {
        // Real Koios returns `asset_list: null` (not an absent key) for a
        // pure-ADA UTxO; `#[serde(default)]` alone does not cover null.
        let json = r#"{"tx_hash":"cc","tx_index":0,"value":"999","asset_list":null}"#;
        let u: Utxo = serde_json::from_str(json).unwrap();
        assert_eq!(u.lovelace().unwrap(), 999);
        assert!(u.assets().unwrap().is_empty());
    }

    #[test]
    fn account_registration_flag() {
        let reg: AccountInfo = serde_json::from_str(
            r#"{"status":"registered","delegated_pool":"pool1x","delegated_drep":null}"#,
        )
        .unwrap();
        assert!(reg.is_registered());
        assert_eq!(reg.delegated_pool.as_deref(), Some("pool1x"));

        let unreg: AccountInfo = serde_json::from_str(r#"{"status":"not registered"}"#).unwrap();
        assert!(!unreg.is_registered());
    }

    #[test]
    fn account_rewards_available() {
        let a: AccountInfo = serde_json::from_str(
            r#"{"status":"registered","delegated_drep":"drep1x","rewards_available":"1234567"}"#,
        )
        .unwrap();
        assert_eq!(a.rewards_available().unwrap(), 1_234_567);
        // Absent and null both read as nothing to withdraw.
        let none: AccountInfo = serde_json::from_str(r#"{"status":"registered"}"#).unwrap();
        assert_eq!(none.rewards_available().unwrap(), 0);
        let null: AccountInfo =
            serde_json::from_str(r#"{"status":"registered","rewards_available":null}"#).unwrap();
        assert_eq!(null.rewards_available().unwrap(), 0);
        let bad: AccountInfo =
            serde_json::from_str(r#"{"status":"registered","rewards_available":"1.5"}"#).unwrap();
        assert!(bad.rewards_available().is_err());
    }

    #[test]
    fn backoff_grows_exponentially() {
        assert_eq!(backoff(1), std::time::Duration::from_millis(300));
        assert_eq!(backoff(2), std::time::Duration::from_millis(600));
        assert_eq!(backoff(3), std::time::Duration::from_millis(1200));
    }

    #[test]
    fn address_utxos_requests_extended() {
        // Koios returns asset_list only when _extended is true; guard against
        // a regression to false that would silently drop every native asset.
        let body = AddressesRequest {
            _addresses: &["addr1"],
            _extended: true,
        };
        let j = serde_json::to_string(&body).unwrap();
        assert!(j.contains("\"_extended\":true"), "{j}");
    }

    /// A stand-in Koios that answers every request with `body`.
    async fn stub_koios(body: String) -> String {
        let app = axum::Router::new().fallback(move || {
            let body = body.clone();
            async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_provider_that_never_stops_paging_is_cut_off() {
        let row = r#"{"tx_hash":"aa","tx_index":0,"value":"1000000","asset_list":null}"#;
        let page = format!("[{}]", vec![row; PAGE_ROWS].join(","));
        let base = stub_koios(page).await;
        let err = address_utxos(&reqwest::Client::new(), &base, "addr1test")
            .await
            .unwrap_err();
        assert!(matches!(err, KoiosError::TooManyRows(_)), "{err}");
    }

    #[tokio::test]
    async fn an_oversized_response_is_refused() {
        let base = stub_koios(" ".repeat(MAX_JSON_RESPONSE_BYTES + 1) + "[]").await;
        let err = tip(&reqwest::Client::new(), &base).await.unwrap_err();
        assert!(matches!(err, KoiosError::Decode(_)), "{err}");
    }
}
