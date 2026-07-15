use crate::{config, koios, tx_builder, AppState};
use shared::chain_context::ChainContext;
use shared::drep_id::drep_id_to_keyhash;
use shared::error::ErrorEnvelope;
use serde::Serialize;
use std::sync::Arc;
use tracing::error;

/// Slots of TTL margin added on top of the current tip. 7 200 slots ≈ 2 h.
pub(crate) const TTL_MARGIN_SLOTS: u64 = 7_200;

/// Conway caps an anchor URL at 128 bytes (`text .size (0..128)`); a longer
/// one would sail through signing and be rejected at submission.
pub(crate) const MAX_ANCHOR_URL_BYTES: usize = 128;

/// Total lovelace supply (45B ADA): sanity ceiling for Koios-supplied
/// deposit / refund amounts. Anything larger is a corrupt or hostile
/// upstream value and would poison the funds arithmetic.
pub(crate) const MAX_SUPPLY_LOVELACE: u64 = 45_000_000_000_000_000;

pub(crate) const EXPLORER_TX_URL_BASE: &str = "https://explorer.cardano.org/en/transaction?id=";

pub(crate) fn now_unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Guard a Koios-supplied lovelace amount (DRep deposit / retire refund)
/// against corrupt or hostile values above the total supply.
pub(crate) fn check_supply_bound(lovelace: u64, field: &'static str) -> Result<(), ErrorEnvelope> {
    if lovelace > MAX_SUPPLY_LOVELACE {
        return Err(ErrorEnvelope::upstream(format!("{field} exceeds the total lovelace supply")));
    }
    Ok(())
}

/// The one "is this DRep registered?" predicate, shared by the register /
/// update previews (warn) and the vote flow (hard-block). Koios marks a
/// registered DRep with `active` and/or `drep_status == "registered"`;
/// accept either signal so the three flows can never drift apart.
pub(crate) fn drep_is_registered(info: Option<&koios::DrepInfo>) -> bool {
    info.map(|i| i.active || i.drep_status.as_deref() == Some("registered")).unwrap_or(false)
}

pub(crate) fn paired_keys_or_err(
    state: &Arc<AppState>,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), ErrorEnvelope> {
    let cfg = state.config.read().unwrap();
    config::paired_keys(&cfg).ok_or_else(|| {
        ErrorEnvelope::not_paired("online tool is not paired with a signer — open Pairing first")
    })
}

/// Minimal chain-context snapshot. The DRep flow needs no KES/opcert data;
/// only `current_slot` (TTL sanity) and `built_at_unix` (signer replay
/// window) are load-bearing. Epoch + slot are real (from the tip) for the
/// signer's top-bar display.
pub(crate) fn chain_context_from_tip(tip: &koios::Tip) -> ChainContext {
    ChainContext {
        current_epoch: tip.epoch_no,
        current_slot: tip.abs_slot,
        current_kes_period: 0,
        epoch_ends_at_unix: 0,
        opcert_expires_at_unix: None,
        built_at_unix: now_unix_ts(),
    }
}

/// Fetch UTxOs at `payment_address`, parse each `value` to u64, return the
/// raw UTxOs + a parallel amount vec + the running total.
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
        let v: u64 = u.value.parse().map_err(|_| ErrorEnvelope::upstream("utxo value not a u64"))?;
        total = total.saturating_add(v);
        amounts.push(v);
    }
    Ok((utxos, amounts, total))
}

/// Aggregate the native assets across all the wallet's UTxOs. drep spends
/// every UTxO, so all of these must come back in the change output; they are
/// summed via the shared change primitive (nothing is sent out).
pub(crate) fn input_assets(
    utxos: &[koios::Utxo],
) -> Result<Vec<airgap_core::asset::Asset>, ErrorEnvelope> {
    let mut all: Vec<airgap_core::asset::Asset> = Vec::new();
    for u in utxos {
        all.extend(
            u.assets().map_err(|_| ErrorEnvelope::upstream("utxo asset quantity not a u64"))?,
        );
    }
    airgap_core::tx::change_assets(&all, &[])
        .map_err(|_| ErrorEnvelope::upstream("utxo asset list malformed"))
}

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

/// Parse the optional rationale/manifest anchor. URL and hash must be
/// present together (or both absent); the URL must fit the Conway 128-byte
/// anchor limit; the hash must be 64 hex chars.
pub(crate) fn parse_anchor(
    url: &Option<String>,
    hash: &Option<String>,
) -> Result<Option<(String, String)>, ErrorEnvelope> {
    match (url.as_deref().map(str::trim), hash.as_deref().map(str::trim)) {
        (None, None) | (Some(""), Some("")) | (Some(""), None) | (None, Some("")) => Ok(None),
        (Some(u), Some(h)) if !u.is_empty() && !h.is_empty() => {
            if u.len() > MAX_ANCHOR_URL_BYTES {
                return Err(ErrorEnvelope::invalid(
                    "anchor URL must be at most 128 bytes (Conway ledger limit)",
                ));
            }
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ErrorEnvelope::invalid(
                    "anchor hash must be 64 hex chars (32-byte blake2b-256)",
                ));
            }
            Ok(Some((u.to_string(), h.to_string())))
        }
        _ => Err(ErrorEnvelope::invalid(
            "anchor needs both a document URL and its 32-byte hash, or neither",
        )),
    }
}

/// Context every `*_start` handler needs: validated PIN, paired keys, the
/// DRep id (bech32 + decoded 28-byte hash) and the payment address.
pub(crate) struct StartCtx {
    pub own_sk: zeroize::Zeroizing<[u8; 32]>,
    pub peer_pk: [u8; 32],
    pub drep_id_bech32: String,
    pub drep_keyhash: [u8; 28],
    pub payment_address: String,
}

pub(crate) fn start_ctx(app: &Arc<AppState>, pin: &str) -> Result<StartCtx, ErrorEnvelope> {
    shared::pin::validate_pin(pin).map_err(ErrorEnvelope::invalid)?;
    let (own_sk, peer_pk) = paired_keys_or_err(app)?;
    let cfg = app.config.read().unwrap().clone();
    let drep_id_bech32 = cfg
        .drep_id
        .clone()
        .ok_or(ErrorEnvelope::not_configured("DRep id not configured"))?;
    let payment_address = cfg
        .payment_address
        .clone()
        .ok_or(ErrorEnvelope::not_configured("payment_address not configured"))?;
    let drep_keyhash = drep_id_to_keyhash(&drep_id_bech32)
        .map_err(|e| ErrorEnvelope::invalid(format!("configured DRep id is invalid: {e}")))?;
    Ok(StartCtx { own_sk, peer_pk, drep_id_bech32, drep_keyhash, payment_address })
}

#[derive(Serialize)]
pub(crate) struct UtxoSummary {
    pub(crate) tx_hash: String,
    pub(crate) tx_index: u32,
    pub(crate) lovelace: u64,
}

#[derive(Serialize)]
pub(crate) struct SubmitResponse {
    pub(crate) tx_hash: String,
    pub(crate) explorer_url: String,
    pub(crate) signed_tx_size_bytes: usize,
}

#[derive(serde::Deserialize)]
pub(crate) struct SubmitWitnessHex {
    pub vkey_hex: String,
    pub signature_hex: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct SubmitTxBody {
    pub tx_body_cbor_hex: String,
    pub witnesses: Vec<SubmitWitnessHex>,
}

/// Shared submit handler for every `/api/*/submit` route: assemble the
/// signed tx from the body + witnesses and broadcast via Koios.
pub(crate) async fn submit_tx_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::Json(body): axum::Json<SubmitTxBody>,
) -> Result<axum::Json<SubmitResponse>, ErrorEnvelope> {
    let _ = paired_keys_or_err(&state)?;
    shared::wire_io::require_non_empty(&body.witnesses, "witnesses")?;
    let body_cbor = hex::decode(&body.tx_body_cbor_hex).map_err(|e| {
        error!(error = %e, "invalid hex in tx_body_cbor_hex");
        ErrorEnvelope::invalid("invalid hex in tx_body_cbor_hex")
    })?;
    let witnesses: Vec<shared::tx::RawVkeyWitness> = body
        .witnesses
        .iter()
        .map(|w| {
            Ok::<_, ErrorEnvelope>(shared::tx::RawVkeyWitness {
                vkey: hex::decode(&w.vkey_hex)
                    .map_err(|_| ErrorEnvelope::invalid("invalid hex in witness vkey"))?,
                signature: hex::decode(&w.signature_hex)
                    .map_err(|_| ErrorEnvelope::invalid("invalid hex in witness signature"))?,
            })
        })
        .collect::<Result<_, _>>()?;
    let signed_tx = shared::tx::assemble_signed_tx(&body_cbor, &witnesses).map_err(|e| {
        error!(error = %e, "transaction assemble failed");
        ErrorEnvelope::internal("transaction assemble failed")
    })?;
    let tx_hash = koios::submit_tx(&state.http, &state.koios_base_url, &signed_tx)
        .await
        .map_err(|e| {
            error!(error = %e, "koios submit_tx failed");
            ErrorEnvelope::submit_rejected("upstream rejected the transaction")
        })?;
    Ok(axum::Json(SubmitResponse {
        explorer_url: format!("{EXPLORER_TX_URL_BASE}{tx_hash}"),
        tx_hash,
        signed_tx_size_bytes: signed_tx.len(),
    }))
}

#[derive(serde::Deserialize)]
pub(crate) struct ManifestHashBody {
    pub url: String,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum ManifestHashResponse {
    Ok { hash_hex: String, byte_len: usize },
    Error { message: String },
}

/// Fetch the manifest document at `url` and return the blake2b-256 of its raw
/// bytes — the CIP-119/CIP-100 anchor hash. Hashes the document content, never
/// the URL string. Operator-local convenience: the same loopback operator
/// could `curl` the URL themselves.
pub(crate) async fn manifest_hash_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::Json(body): axum::Json<ManifestHashBody>,
) -> axum::Json<ManifestHashResponse> {
    const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
    let url = body.url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return axum::Json(ManifestHashResponse::Error {
            message: "URL must start with http:// or https://".into(),
        });
    }
    let resp = match state.http.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "manifest fetch failed");
            return axum::Json(ManifestHashResponse::Error { message: "could not fetch the manifest URL".into() });
        }
    };
    if !resp.status().is_success() {
        return axum::Json(ManifestHashResponse::Error {
            message: format!("manifest URL returned HTTP {}", resp.status().as_u16()),
        });
    }
    if resp.content_length().map(|l| l as usize > MAX_MANIFEST_BYTES).unwrap_or(false) {
        return axum::Json(ManifestHashResponse::Error { message: "manifest is larger than 1 MiB".into() });
    }
    // The Content-Length header is attacker-controlled (and absent on chunked
    // transfer), so the read itself is capped: one byte past the limit is
    // enough to tell "too large" from "exactly at the limit".
    let bytes = match koios::read_capped(resp, MAX_MANIFEST_BYTES + 1).await {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "manifest body read failed");
            return axum::Json(ManifestHashResponse::Error { message: "could not read the manifest body".into() });
        }
    };
    if bytes.len() > MAX_MANIFEST_BYTES {
        return axum::Json(ManifestHashResponse::Error { message: "manifest is larger than 1 MiB".into() });
    }
    let hash = pallas_crypto::hash::Hasher::<256>::hash(&bytes);
    axum::Json(ManifestHashResponse::Ok { hash_hex: hex::encode(hash), byte_len: bytes.len() })
}
