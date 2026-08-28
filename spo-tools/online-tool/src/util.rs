use crate::{config, koios, tx_builder, AppState};
use shared::chain_context::ChainContext;
use shared::error::ErrorEnvelope;
use serde::Serialize;
use std::sync::Arc;
use tracing::error;

/// Look up the paired-keys (own X25519 secret + peer X25519 public) from
/// shared config state, or return [`ErrorCode::NotPaired`] so the frontend
/// routes to the Pairing card.
pub(crate) fn paired_keys_or_err(
    state: &Arc<AppState>,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), ErrorEnvelope> {
    let cfg = state.config.read().unwrap_or_else(|e| e.into_inner());
    config::paired_keys(&cfg).ok_or_else(|| {
        ErrorEnvelope::not_paired(
            "online tool is not paired with a signer — open Pairing first",
        )
    })
}

pub(crate) fn now_unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a ChainContext snapshot from a freshly-fetched tip plus the
/// already-loaded genesis params and local opcert state. This is what
/// every signer-bound request carries so the offline signer can render
/// chain status without ever touching the network itself.
pub(crate) fn chain_context_from(
    tip: &koios::Tip,
    params: &koios::GenesisParams,
    opcert_start_kes_period: Option<u64>,
) -> ChainContext {
    ChainContext {
        current_epoch: tip.epoch_no,
        current_slot: tip.abs_slot,
        current_kes_period: params.slot_to_kes_period(tip.abs_slot),
        epoch_ends_at_unix: koios::slot_to_unix_time(
            params.epoch_first_slot(tip.epoch_no.saturating_add(1)),
        ),
        opcert_expires_at_unix: opcert_start_kes_period.map(|s| params.opcert_expires_at_unix(s)),
        built_at_unix: now_unix_ts(),
    }
}

/// Fetch all UTXOs at the given payment address, parse each `value`
/// string into a `u64`, and return the raw UTXOs alongside a parallel
/// `Vec<u64>` of amounts and the running total in lovelace. Common
/// upstream for both `*_preview` (which maps to UtxoSummary) and
/// `*_start` (which maps to tx_builder::TxInput) handler flows.
/// Empty-handling is the caller's responsibility because preview
/// tolerates 0 UTXOs while start rejects 0 UTXOs.
pub(crate) async fn fetch_payment_utxos(
    http: &reqwest::Client,
    koios_base_url: &str,
    payment_address: &str,
) -> Result<(Vec<koios::Utxo>, Vec<u64>, u64), ErrorEnvelope> {
    let utxos = koios::address_utxos(http, koios_base_url, payment_address)
        .await
        .map_err(|e| {
            error!(error = %e, "koios address_utxos failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let mut amounts: Vec<u64> = Vec::with_capacity(utxos.len());
    let mut total: u64 = 0;
    for u in &utxos {
        let v: u64 = u.value.parse().map_err(|_| {
            ErrorEnvelope::upstream("utxo value not a u64")
        })?;
        total = total.saturating_add(v);
        amounts.push(v);
    }
    Ok((utxos, amounts, total))
}

/// Aggregate the native assets across all the wallet's UTxOs. spo spends every
/// UTxO, so all of these must return in the change output; summed via the
/// shared change primitive (nothing is sent out).
pub(crate) fn input_assets(
    utxos: &[koios::Utxo],
) -> Result<Vec<shared::asset::Asset>, ErrorEnvelope> {
    let mut all: Vec<shared::asset::Asset> = Vec::new();
    for u in utxos {
        all.extend(
            u.assets().map_err(|_| ErrorEnvelope::upstream("utxo asset quantity not a u64"))?,
        );
    }
    shared::tx::change_assets(&all, &[])
        .map_err(|_| ErrorEnvelope::upstream("utxo asset list malformed"))
}

/// Combine the parallel `tx_builder::TxInput` inputs and lovelace amounts
/// with a single payment address into the wire-shaped
/// `Vec<shared::utxo::UtxoInput>` that the start handlers feed into the
/// sign request. Centralises the zip + clone pattern that was repeated
/// in withdraw, drep, and pool start handlers.
pub(crate) fn build_request_inputs(
    utxo_inputs: &[tx_builder::TxInput],
    utxo_amounts: &[u64],
    payment_address: &str,
) -> Vec<shared::utxo::UtxoInput> {
    utxo_inputs
        .iter()
        .zip(utxo_amounts.iter())
        .map(|(u, &amount)| shared::utxo::UtxoInput {
            tx_hash_hex: u.tx_hash_hex.clone(),
            tx_index: u.tx_index,
            amount_lovelace: amount,
            address_bech32: payment_address.to_string(),
        })
        .collect()
}

/// Mainnet block-explorer URL template for transaction lookups. The
/// `{tx_hash}` placeholder is substituted via `format!` at call sites.
pub(crate) const EXPLORER_TX_URL_BASE: &str = "https://explorer.cardano.org/en/transaction?id=";

/// Slots of TTL margin added on top of the current tip when building a
/// withdrawal tx. 7 200 slots ≈ 2 hours on mainnet (1 slot/s).
pub(crate) const TTL_MARGIN_SLOTS: u64 = 7_200;

/// Bundle of context every operational `*_start` handler needs before
/// any flow-specific work. Computed once via `start_handler_ctx` so the
/// 6-step preamble (validate PIN → genesis → pairing → config snapshot
/// → pool_id → payment_address) appears in just one place.
pub(crate) struct StartHandlerCtx {
    pub params: koios::GenesisParams,
    pub own_sk: zeroize::Zeroizing<[u8; 32]>,
    pub peer_pk: [u8; 32],
    pub cfg: config::OnlineConfig,
    pub pool_id: String,
    pub payment_address: String,
}

pub(crate) fn start_handler_ctx(
    app: &Arc<AppState>,
    pin: &str,
) -> Result<StartHandlerCtx, ErrorEnvelope> {
    shared::pin::validate_pin(pin).map_err(ErrorEnvelope::invalid)?;
    let params = app.require_genesis()?;
    let (own_sk, peer_pk) = paired_keys_or_err(app)?;
    let cfg = app.config.read().unwrap_or_else(|e| e.into_inner()).clone();
    let pool_id = cfg
        .pool_id
        .clone()
        .ok_or(ErrorEnvelope::not_configured("pool not configured"))?;
    let payment_address = cfg
        .payment_address
        .clone()
        .ok_or(ErrorEnvelope::not_configured("payment_address not configured"))?;
    Ok(StartHandlerCtx {
        params,
        own_sk,
        peer_pk,
        cfg,
        pool_id,
        payment_address,
    })
}

#[derive(Serialize)]
pub(crate) struct UtxoSummary {
    pub(crate) tx_hash: String,
    pub(crate) tx_index: u32,
    pub(crate) lovelace: u64,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/handlers.ts")]
pub(crate) struct WithdrawSubmitResponse {
    pub(crate) tx_hash: String,
    pub(crate) explorer_url: String,
    pub(crate) signed_tx_size_bytes: usize,
}


/// Witness pair as it arrives over the HTTP wire (hex-encoded). Common
/// shape across withdraw/drep/pool submit endpoints.
#[derive(serde::Deserialize)]
pub(crate) struct SubmitWitnessHex {
    pub vkey_hex: String,
    pub signature_hex: String,
}

/// Common /api/*/submit body: a built tx body in hex + a list of witnesses.
/// Same shape across withdraw/drep/pool — only the surrounding handler
/// differs in role-validation, which lives in shared::witness now.
#[derive(serde::Deserialize)]
pub(crate) struct SubmitTxBody {
    pub tx_body_cbor_hex: String,
    pub witnesses: Vec<SubmitWitnessHex>,
}

/// Shared submit handler for `/api/withdraw/submit`, `/api/drep/submit`,
/// and `/api/pool/submit`. The three flows produce identically-shaped
/// witness bundles (role-checking happens earlier on the signer side via
/// `shared::witness`), so submission is one code path. Registered three
/// times in main.rs to keep the per-flow URL paths the operator's UI
/// expects.
pub(crate) async fn submit_tx_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::Json(body): axum::Json<SubmitTxBody>,
) -> Result<axum::Json<WithdrawSubmitResponse>, ErrorEnvelope> {
    let _ = paired_keys_or_err(&state)?;
    let res = submit_signed_tx(&state, &body).await?;
    Ok(axum::Json(res))
}

/// Assemble + submit a signed tx via Koios. Maps validation/upstream
/// errors to ErrorEnvelope. Caller is expected to have already gated
/// on `paired_keys_or_err`. Returns the standard SubmittedTx envelope.
pub(crate) async fn submit_signed_tx(
    state: &std::sync::Arc<crate::AppState>,
    body: &SubmitTxBody,
) -> Result<WithdrawSubmitResponse, shared::error::ErrorEnvelope> {
    use shared::error::ErrorEnvelope;
    use tracing::error;

    shared::wire_io::require_non_empty(&body.witnesses, "witnesses")?;
    let body_cbor = hex::decode(&body.tx_body_cbor_hex).map_err(|e| {
        error!(error = %e, "invalid hex in tx_body_cbor_hex");
        ErrorEnvelope::invalid("invalid hex in tx_body_cbor_hex")
    })?;
    let witnesses: Vec<crate::tx_builder::RawVkeyWitness> = body
        .witnesses
        .iter()
        .map(|w| {
            Ok::<_, ErrorEnvelope>(crate::tx_builder::RawVkeyWitness {
                vkey: hex::decode(&w.vkey_hex).map_err(|e| {
                    error!(error = %e, "invalid hex in witness vkey");
                    ErrorEnvelope::invalid("invalid hex in witness vkey")
                })?,
                signature: hex::decode(&w.signature_hex).map_err(|e| {
                    error!(error = %e, "invalid hex in witness signature");
                    ErrorEnvelope::invalid("invalid hex in witness signature")
                })?,
            })
        })
        .collect::<Result<_, _>>()?;

    let signed_tx = crate::tx_builder::assemble_signed_tx(&body_cbor, &witnesses).map_err(|e| {
        error!(error = %e, "transaction assemble failed");
        ErrorEnvelope::internal("transaction assemble failed")
    })?;

    let tx_hash = crate::koios::submit_tx(&state.http, &state.koios_base_url, &signed_tx)
        .await
        .map_err(|e| {
            error!(error = %e, "koios submit_tx failed");
            ErrorEnvelope::submit_rejected("upstream rejected the transaction")
        })?;

    Ok(WithdrawSubmitResponse {
        explorer_url: format!("{EXPLORER_TX_URL_BASE}{tx_hash}"),
        tx_hash,
        signed_tx_size_bytes: signed_tx.len(),
    })
}


// ---------------------------------------------------------------------------
// Rationale anchor-hash helper. Ported from DRep Tools' manifest-hash handler
// so the SPO vote view has the same "Compute hash" button: fetch the rationale
// document at `url` and return the blake2b-256 of its raw bytes (the CIP-100
// anchor hash). Hashes the document content, never the URL string.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(crate) struct RationaleHashBody {
    pub url: String,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum RationaleHashResponse {
    Ok { hash_hex: String, byte_len: usize },
    Error { message: String },
}

pub(crate) async fn rationale_hash_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::Json(body): axum::Json<RationaleHashBody>,
) -> axum::Json<RationaleHashResponse> {
    const MAX_RATIONALE_BYTES: usize = 1024 * 1024;
    let url = body.url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return axum::Json(RationaleHashResponse::Error {
            message: "URL must start with http:// or https://".into(),
        });
    }
    let resp = match state.http.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "rationale fetch failed");
            return axum::Json(RationaleHashResponse::Error {
                message: "could not fetch the rationale URL".into(),
            });
        }
    };
    if !resp.status().is_success() {
        return axum::Json(RationaleHashResponse::Error {
            message: format!("rationale URL returned HTTP {}", resp.status().as_u16()),
        });
    }
    if resp
        .content_length()
        .map(|l| l as usize > MAX_RATIONALE_BYTES)
        .unwrap_or(false)
    {
        return axum::Json(RationaleHashResponse::Error {
            message: "rationale is larger than 1 MiB".into(),
        });
    }
    let bytes = match koios::read_capped(resp, MAX_RATIONALE_BYTES + 1).await {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "rationale body read failed");
            return axum::Json(RationaleHashResponse::Error {
                message: "could not read the rationale body".into(),
            });
        }
    };
    if bytes.len() > MAX_RATIONALE_BYTES {
        return axum::Json(RationaleHashResponse::Error {
            message: "rationale is larger than 1 MiB".into(),
        });
    }
    let hash = pallas_crypto::hash::Hasher::<256>::hash(&bytes);
    axum::Json(RationaleHashResponse::Ok {
        hash_hex: hex::encode(hash),
        byte_len: bytes.len(),
    })
}
