use crate::{config, koios, tx_builder, AppState};
use serde::Serialize;
use shared::chain_context::ChainContext;
use shared::error::ErrorEnvelope;
use std::sync::Arc;
use tracing::error;

/// Slots of TTL margin added on top of the current tip. 7 200 slots ≈ 2 h.
pub(crate) const TTL_MARGIN_SLOTS: u64 = 7_200;

pub(crate) const EXPLORER_TX_URL_BASE: &str = "https://explorer.cardano.org/en/transaction?id=";

/// A Unix-timestamp floor below which the clock is treated as unset rather
/// than as a real time (2024-01-01 UTC, the same floor the signer uses).
const MIN_PLAUSIBLE_NOW_UNIX: u64 = 1_704_067_200;

/// Accept a wall-clock reading only when it can be a real time. `None` is a
/// clock before the UNIX epoch. A request stamped by an unset clock would be
/// refused by the signer as stale after the air-gap round trip; refusing it
/// here names the actual cause.
fn plausible_now(secs: Option<u64>) -> Result<u64, ErrorEnvelope> {
    match secs {
        Some(s) if s >= MIN_PLAUSIBLE_NOW_UNIX => Ok(s),
        other => {
            error!(now = ?other, "system clock is unset or implausible");
            Err(ErrorEnvelope::internal(
                "this machine's clock looks unset (reads before 2024). Set the clock, then retry",
            ))
        }
    }
}

pub(crate) fn now_unix_ts() -> Result<u64, ErrorEnvelope> {
    plausible_now(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs()),
    )
}

pub(crate) fn paired_keys_or_err(
    state: &Arc<AppState>,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), ErrorEnvelope> {
    let cfg = state.config.read().unwrap();
    config::paired_keys(&cfg).ok_or_else(|| {
        ErrorEnvelope::not_paired("online tool is not paired with a signer. Open Pairing first")
    })
}

/// Minimal chain-context snapshot. Only `current_slot` (TTL sanity) and
/// `built_at_unix` (signer replay window) are load-bearing for the wallet;
/// epoch + slot are real (from the tip) for the signer's top-bar display.
pub(crate) fn chain_context_from_tip(tip: &koios::Tip) -> Result<ChainContext, ErrorEnvelope> {
    Ok(ChainContext {
        current_epoch: tip.epoch_no,
        current_slot: tip.abs_slot,
        current_kes_period: 0,
        epoch_ends_at_unix: 0,
        opcert_expires_at_unix: None,
        built_at_unix: now_unix_ts()?,
    })
}

/// Derive the stake/reward address (`stake1...`) embedded in a base
/// (`addr1...`) address. The wallet's stake credential, the one the pool /
/// DRep delegation certificates target, is the delegation part of the
/// configured payment address, so it is read directly from there rather
/// than configured separately.
pub(crate) fn stake_address_from_base(base_bech32: &str) -> Result<String, ErrorEnvelope> {
    use pallas_addresses::{Address, ShelleyDelegationPart, StakeAddress};
    let addr = Address::from_bech32(base_bech32)
        .map_err(|e| ErrorEnvelope::invalid(format!("invalid payment address: {e}")))?;
    let shelley = match addr {
        Address::Shelley(s) => s,
        _ => {
            return Err(ErrorEnvelope::invalid(
                "payment address is not a Shelley base address",
            ))
        }
    };
    if let ShelleyDelegationPart::Null | ShelleyDelegationPart::Pointer(_) = shelley.delegation() {
        return Err(ErrorEnvelope::invalid(
            "payment address has no stake part. Use a base address (addr1q…) for delegation",
        ));
    }
    let stake: StakeAddress = shelley
        .clone()
        .try_into()
        .map_err(|e| ErrorEnvelope::invalid(format!("could not derive stake address: {e}")))?;
    stake
        .to_bech32()
        .map_err(|e| ErrorEnvelope::internal(format!("stake address encode failed: {e}")))
}

/// Fetch UTxOs at `payment_address` and map each to a `tx_builder::OwnedUtxo`
/// the body builders consume, with the running lovelace total for the
/// preview / can-cover checks.
pub(crate) async fn fetch_owned_utxos(
    http: &reqwest::Client,
    koios_base_url: &str,
    payment_address: &str,
) -> Result<(Vec<tx_builder::OwnedUtxo>, u64), ErrorEnvelope> {
    let utxos = address_utxos(http, koios_base_url, payment_address).await?;
    owned_from_utxos(&utxos)
}

/// Fetch UTxOs once and derive both the spendable set (for tx building) and
/// the aggregated held-asset list (for the send-payment picker). The picker
/// needs the decimals/fingerprint a plain `OwnedUtxo` does not carry, so the
/// held list is summarised straight from the raw Koios rows here.
pub(crate) async fn fetch_payment_preview(
    http: &reqwest::Client,
    koios_base_url: &str,
    payment_address: &str,
) -> Result<(Vec<tx_builder::OwnedUtxo>, u64, Vec<HeldAsset>), ErrorEnvelope> {
    let utxos = address_utxos(http, koios_base_url, payment_address).await?;
    let (owned, total) = owned_from_utxos(&utxos)?;
    let held = held_assets_from_utxos(&utxos);
    Ok((owned, total, held))
}

async fn address_utxos(
    http: &reqwest::Client,
    koios_base_url: &str,
    payment_address: &str,
) -> Result<Vec<koios::Utxo>, ErrorEnvelope> {
    koios::address_utxos(http, koios_base_url, payment_address)
        .await
        .map_err(|e| {
            error!(error = %e, "koios address_utxos failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })
}

fn owned_from_utxos(
    utxos: &[koios::Utxo],
) -> Result<(Vec<tx_builder::OwnedUtxo>, u64), ErrorEnvelope> {
    let mut owned: Vec<tx_builder::OwnedUtxo> = Vec::with_capacity(utxos.len());
    let mut total: u64 = 0;
    for u in utxos {
        let lovelace = u.lovelace().map_err(|e| {
            error!(error = %e, "utxo value parse failed");
            ErrorEnvelope::upstream("utxo value not a u64")
        })?;
        let assets = u.assets().map_err(|e| {
            error!(error = %e, "utxo asset parse failed");
            ErrorEnvelope::upstream("utxo asset list malformed")
        })?;
        total = total.saturating_add(lovelace);
        owned.push(tx_builder::OwnedUtxo {
            tx_hash_hex: u.tx_hash.clone(),
            tx_index: u.tx_index,
            lovelace,
            assets,
        });
    }
    Ok((owned, total))
}

/// Map the inputs the builder actually selected back onto the wire
/// `UtxoInput` shape (each tagged with the payment address), looking the
/// lovelace amount up in the owned-UTxO set the builder chose from.
pub(crate) fn build_request_inputs(
    selected: &[shared::tx::TxInput],
    owned: &[tx_builder::OwnedUtxo],
    payment_address: &str,
) -> Vec<shared::utxo::UtxoInput> {
    selected
        .iter()
        .map(|i| {
            let amount = owned
                .iter()
                .find(|o| o.tx_hash_hex == i.tx_hash_hex && o.tx_index == i.tx_index)
                .map(|o| o.lovelace)
                .unwrap_or(0);
            shared::utxo::UtxoInput {
                tx_hash_hex: i.tx_hash_hex.clone(),
                tx_index: i.tx_index,
                amount_lovelace: amount,
                address_bech32: payment_address.to_string(),
            }
        })
        .collect()
}

/// Fetch the current tip + protocol params together: every `*_start`
/// handler needs both (params drive the fee/min-ADA, the tip drives TTL).
pub(crate) async fn tip_and_params(
    app: &Arc<AppState>,
) -> Result<(koios::Tip, koios::ProtocolParams), ErrorEnvelope> {
    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let params = koios::protocol_params(&app.http, &app.koios_base_url).await.map_err(|e| {
        error!(error = %e, "koios protocol_params failed");
        match e {
            koios::KoiosError::OutOfBand { name, .. } => ErrorEnvelope::upstream(format!(
                "the chain-data provider returned a protocol parameter ({name}) outside the range the network allows. Not building a transaction from it"
            )),
            _ => ErrorEnvelope::upstream("upstream service unavailable"),
        }
    })?;
    Ok((tip, params))
}

/// Reject a transaction whose estimated signed size exceeds the network
/// maximum (`maxTxSize`). Caught here, before the operator signs, an oversized
/// transaction is a clear up-front error instead of a cryptic submit rejection
/// after the air-gap round trip. `n_witnesses` is 1 for a payment, 2 for a
/// delegation or a reward withdrawal.
pub(crate) fn guard_tx_size(
    body_cbor_len: usize,
    n_witnesses: u64,
    max_tx_size: u64,
) -> Result<(), ErrorEnvelope> {
    let size = tx_builder::estimate_signed_size(body_cbor_len, n_witnesses);
    if size > max_tx_size {
        return Err(ErrorEnvelope::invalid(format!(
            "transaction is too large ({size} bytes, network maximum {max_tx_size}). Split it into smaller sends"
        )));
    }
    Ok(())
}

/// Reject a transaction whose fee is above the ceiling the signer accepts
/// (`shared::tx_validator::MAX_FEE_LOVELACE`). The signer would refuse it
/// anyway; caught here it is a clear up-front error instead of a refusal
/// after the air-gap round trip. An honest build never comes near the
/// ceiling, so hitting it means the protocol parameters the chain-data
/// provider returned are not to be trusted.
pub(crate) fn guard_fee(fee_lovelace: u64) -> Result<(), ErrorEnvelope> {
    let max = shared::tx_validator::MAX_FEE_LOVELACE;
    if fee_lovelace > max {
        error!(
            fee = fee_lovelace,
            max, "computed fee is above the signer's ceiling"
        );
        return Err(ErrorEnvelope::upstream(format!(
            "computed fee ({fee_lovelace} lovelace) is above the {max} lovelace the signer accepts: the protocol parameters from the chain-data provider look wrong"
        )));
    }
    Ok(())
}

/// Context every `*_start` handler needs: validated PIN, paired keys, the
/// payment address (+ derived stake address).
pub(crate) struct StartCtx {
    pub own_sk: zeroize::Zeroizing<[u8; 32]>,
    pub peer_pk: [u8; 32],
    pub payment_address: String,
    /// None for an enterprise (payment-only) source: it has no stake address.
    pub stake_address: Option<String>,
}

/// Optional `?source=addr1…` query selecting which own wallet funds a preview.
#[derive(serde::Deserialize)]
pub(crate) struct SourceQuery {
    #[serde(default)]
    pub source: Option<String>,
}

/// Resolve which own wallet address funds an operation. An explicit
/// `requested` must be one of the operator's own (signable) addresses. When
/// omitted it defaults to the single own wallet; with more than one wallet
/// configured an explicit choice is required, so funds are never spent from
/// the wrong wallet by accident.
pub(crate) fn resolve_source(
    cfg: &config::OnlineConfig,
    requested: Option<&str>,
) -> Result<String, ErrorEnvelope> {
    let own = config::own_addresses(cfg);
    if own.is_empty() {
        return Err(ErrorEnvelope::not_configured(
            "no wallet configured. Add one in the Address book",
        ));
    }
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(a) => {
            if own.contains(&a) {
                Ok(a.to_string())
            } else {
                Err(ErrorEnvelope::invalid(
                    "source is not one of your own wallet addresses",
                ))
            }
        }
        None => {
            if own.len() == 1 {
                Ok(own[0].to_string())
            } else {
                Err(ErrorEnvelope::invalid(
                    "multiple wallets configured. Select a source wallet",
                ))
            }
        }
    }
}

pub(crate) fn start_ctx(
    app: &Arc<AppState>,
    pin: &str,
    source: Option<&str>,
) -> Result<StartCtx, ErrorEnvelope> {
    shared::pin::validate_pin(pin).map_err(ErrorEnvelope::invalid)?;
    let (own_sk, peer_pk) = paired_keys_or_err(app)?;
    let cfg = app.config.read().unwrap().clone();
    let payment_address = resolve_source(&cfg, source)?;
    let stake_address = stake_address_from_base(&payment_address).ok();
    Ok(StartCtx {
        own_sk,
        peer_pk,
        payment_address,
        stake_address,
    })
}

/// One distinct native asset the wallet holds, summed across its UTxOs: the
/// choices the send-payment picker offers. `decimals`/`fingerprint` are display
/// aids from Koios; `quantity` is the raw indivisible total (string, JS
/// precision-safe) and stays the unit the air-gapped signer verifies.
#[derive(Serialize)]
pub(crate) struct HeldAsset {
    pub(crate) policy_hex: String,
    pub(crate) asset_name_hex: String,
    pub(crate) fingerprint: String,
    pub(crate) decimals: u32,
    pub(crate) quantity: String,
}

/// Aggregate the wallet's native assets across all its UTxOs, keyed by
/// (policy, asset name), summing quantities. Decimals/fingerprint are taken
/// from the first row seen for each asset (Koios reports them per asset).
pub(crate) fn held_assets_from_utxos(utxos: &[koios::Utxo]) -> Vec<HeldAsset> {
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<(String, String), (u64, u32, String)> = BTreeMap::new();
    for u in utxos {
        for a in u.asset_list.as_deref().unwrap_or(&[]) {
            let name = a.asset_name.clone().unwrap_or_default();
            let qty: u64 = a.quantity.parse().unwrap_or(0);
            let entry = acc.entry((a.policy_id.clone(), name)).or_insert((
                0,
                a.decimals.unwrap_or(0),
                a.fingerprint.clone().unwrap_or_default(),
            ));
            entry.0 = entry.0.saturating_add(qty);
        }
    }
    acc.into_iter()
        .map(
            |((policy_hex, asset_name_hex), (qty, decimals, fingerprint))| HeldAsset {
                policy_hex,
                asset_name_hex,
                fingerprint,
                decimals,
                quantity: qty.to_string(),
            },
        )
        .collect()
}

#[derive(Serialize)]
pub(crate) struct UtxoSummary {
    pub(crate) tx_hash: String,
    pub(crate) tx_index: u32,
    pub(crate) lovelace: u64,
    pub(crate) assets: Vec<shared::asset::Asset>,
}

pub(crate) fn utxo_summaries(owned: &[tx_builder::OwnedUtxo]) -> Vec<UtxoSummary> {
    owned
        .iter()
        .map(|u| UtxoSummary {
            tx_hash: u.tx_hash_hex.clone(),
            tx_index: u.tx_index,
            lovelace: u.lovelace,
            assets: u.assets.clone(),
        })
        .collect()
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
    /// Optional CIP-20 message lines; must match the auxiliary_data_hash the
    /// signed body already commits, or the node rejects the assembled tx.
    #[serde(default)]
    pub metadata_msg: Option<Vec<String>>,
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
    let aux_data = match &body.metadata_msg {
        None => None,
        Some(lines) => Some(shared::tx::build_cip20_aux_data_cbor(lines).map_err(|e| {
            error!(error = %e, "invalid metadata_msg");
            ErrorEnvelope::invalid("invalid metadata_msg")
        })?),
    };
    let signed_tx =
        shared::tx::assemble_signed_tx_with_aux(&body_cbor, &witnesses, aux_data.as_deref())
            .map_err(|e| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_stake_from_base_address() {
        let base = shared::address::base_address_bech32(&[0x11; 32], &[0x22; 32]).unwrap();
        let expected = shared::address::stake_address_bech32(&[0x22; 32]).unwrap();
        assert_eq!(stake_address_from_base(&base).unwrap(), expected);
    }

    #[test]
    fn an_unset_clock_is_an_error_not_a_zero_timestamp() {
        assert_eq!(plausible_now(Some(1_790_000_000)).unwrap(), 1_790_000_000);
        assert_eq!(
            plausible_now(Some(MIN_PLAUSIBLE_NOW_UNIX)).unwrap(),
            MIN_PLAUSIBLE_NOW_UNIX
        );
        assert!(plausible_now(Some(MIN_PLAUSIBLE_NOW_UNIX - 1)).is_err());
        assert!(plausible_now(Some(0)).is_err());
        assert!(plausible_now(None).is_err());
        assert!(now_unix_ts().is_ok(), "this machine's clock is set");
    }

    #[test]
    fn fee_guard_follows_the_signer_ceiling() {
        let max = shared::tx_validator::MAX_FEE_LOVELACE;
        assert!(guard_fee(170_000).is_ok());
        assert!(guard_fee(max).is_ok());
        assert!(guard_fee(max + 1).is_err());
    }

    #[test]
    fn stake_address_input_is_rejected() {
        let stake = shared::address::stake_address_bech32(&[0x22; 32]).unwrap();
        assert!(stake_address_from_base(&stake).is_err());
    }

    #[test]
    fn aggregates_held_assets_with_decimals() {
        let utxos: Vec<koios::Utxo> = serde_json::from_str(
            r#"[
              {"tx_hash":"aa","tx_index":0,"value":"1000000","asset_list":[
                {"policy_id":"0691b2fe","asset_name":"4e49474854","quantity":"40","decimals":6,"fingerprint":"asset1ni"}
              ]},
              {"tx_hash":"bb","tx_index":1,"value":"1000000","asset_list":[
                {"policy_id":"0691b2fe","asset_name":"4e49474854","quantity":"2","decimals":6,"fingerprint":"asset1ni"},
                {"policy_id":"abcd","asset_name":null,"quantity":"7"}
              ]}
            ]"#,
        )
        .unwrap();
        let held = held_assets_from_utxos(&utxos);
        assert_eq!(held.len(), 2);
        // BTreeMap key order: ("0691b2fe", ...) sorts before ("abcd", "").
        let night = &held[0];
        assert_eq!(night.policy_hex, "0691b2fe");
        assert_eq!(night.asset_name_hex, "4e49474854");
        assert_eq!(night.quantity, "42"); // 40 + 2 summed across UTxOs
        assert_eq!(night.decimals, 6);
        assert_eq!(night.fingerprint, "asset1ni");
        let other = &held[1];
        assert_eq!(other.policy_hex, "abcd");
        assert_eq!(other.asset_name_hex, ""); // null name decodes to empty
        assert_eq!(other.quantity, "7");
        assert_eq!(other.decimals, 0); // absent decimals default to 0
        assert_eq!(other.fingerprint, "");
    }

    #[test]
    fn tx_size_guard_rejects_oversized() {
        // 16384 = mainnet maxTxSize. A small body passes; a body at the limit
        // plus witness/overhead exceeds it.
        assert!(guard_tx_size(100, 1, 16_384).is_ok());
        assert!(guard_tx_size(16_384, 1, 16_384).is_err());
    }
}
