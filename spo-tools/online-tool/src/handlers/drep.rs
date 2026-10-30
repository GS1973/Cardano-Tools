use crate::{
    koios, state, tx_builder,
    util::{chain_context_from, paired_keys_or_err, UtxoSummary, TTL_MARGIN_SLOTS},
    AppState,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use shared::error::ErrorEnvelope;
use shared::{chain_context::ChainContext, wire_io::ur_decode_required};
use std::sync::Arc;
use tracing::error;

#[derive(Serialize)]
pub(crate) struct DRepPreview {
    pool_id_bech32: String,
    /// Pool's reward account (= the stake credential being voted-delegated).
    pool_reward_address: String,
    payment_address: String,
    /// Current DRep delegation, as reported by Koios. None = not yet
    /// delegated, which means rewards-withdrawal is currently blocked.
    current_drep: Option<String>,
    payment_utxos: Vec<UtxoSummary>,
    payment_utxo_total_lovelace: u64,
    estimated_fee_lovelace: u64,
    can_cover_fee: bool,
    chain_context: ChainContext,
}

pub(crate) async fn drep_preview(
    State(app): State<Arc<AppState>>,
) -> Result<Json<DRepPreview>, ErrorEnvelope> {
    let params = app.require_genesis()?;
    let cfg = app.config.read().unwrap_or_else(|e| e.into_inner()).clone();
    let pool_id = cfg
        .pool_id
        .clone()
        .ok_or(ErrorEnvelope::not_configured("pool not configured"))?;
    let payment_address = cfg
        .payment_address
        .clone()
        .ok_or(ErrorEnvelope::not_configured(
            "payment_address not configured",
        ))?;

    let pool = koios::pool_info(&app.http, &app.koios_base_url, &pool_id)
        .await
        .map_err(|e| {
            error!(error = %e, "koios pool_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let pool_reward_address = pool.reward_addr.ok_or(ErrorEnvelope::upstream(
        "pool reward address missing from Koios response",
    ))?;

    let acct = koios::account_info(&app.http, &app.koios_base_url, &pool_reward_address)
        .await
        .map_err(|e| {
            error!(error = %e, "koios account_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let current_drep = acct.and_then(|a| a.delegated_drep.clone());

    let (utxos, amounts, payment_utxo_total_lovelace) =
        crate::util::fetch_payment_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    let payment_utxos: Vec<UtxoSummary> = utxos
        .iter()
        .zip(amounts.iter())
        .map(|(u, &lovelace)| UtxoSummary {
            tx_hash: u.tx_hash.clone(),
            tx_index: u.tx_index,
            lovelace,
        })
        .collect();

    let fee_params = crate::util::fee_params(&app).await?;
    let estimated_fee_lovelace = tx_builder::preview_fee_lovelace(
        tx_builder::TxKind::DrepDelegation,
        utxos.len(),
        crate::util::input_assets(&utxos)?.len(),
        &fee_params,
    );
    let can_cover_fee = payment_utxo_total_lovelace >= estimated_fee_lovelace;

    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start)?;

    Ok(Json(DRepPreview {
        pool_id_bech32: pool_id,
        pool_reward_address,
        payment_address,
        current_drep,
        payment_utxos,
        payment_utxo_total_lovelace,
        estimated_fee_lovelace,
        can_cover_fee,
        chain_context,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DRepStartBody {
    /// "abstain" (default), "no_confidence", "key:<hex>", "script:<hex>".
    pub drep: Option<String>,
    /// 4-digit operator PIN.
    pub pin: String,
}

#[derive(Serialize)]
pub(crate) struct DRepStartResponse {
    request: shared::drep::DRepDelegationRequest,
    body_hash_hex: String,
    ur_fragments: Vec<String>,
    /// 8-byte request-payload fingerprint, blake2b256 truncated
    /// and rendered as 4 hex pairs (operator visually compares with the
    /// signer-side display before signing).
    request_fingerprint: String,
}

pub(crate) fn parse_drep_choice(raw: &str) -> Result<shared::drep::DRepChoice, ErrorEnvelope> {
    let s = raw.trim();
    if s.eq_ignore_ascii_case("abstain") {
        return Ok(shared::drep::DRepChoice::Abstain);
    }
    if s.eq_ignore_ascii_case("no_confidence") || s.eq_ignore_ascii_case("noconfidence") {
        return Ok(shared::drep::DRepChoice::NoConfidence);
    }
    // Accept bech32 DRep ids in both encodings:
    //   - CIP-105: bare 28-byte hash, hrp `drep` (key) or `drep_script` (script).
    //   - CIP-129: hrp `drep` with a 1-byte header (0x22 key / 0x23 script)
    //     prepended to the 28-byte hash: what cardano-cli, gov.tools and the
    //     wallets emit by default now.
    if let Ok((hrp, bytes)) = bech32::decode(s) {
        match (hrp.as_str(), bytes.len()) {
            ("drep", 28) => {
                return Ok(shared::drep::DRepChoice::KeyHash {
                    hash_hex: hex::encode(&bytes),
                });
            }
            ("drep_script", 28) => {
                return Ok(shared::drep::DRepChoice::ScriptHash {
                    hash_hex: hex::encode(&bytes),
                });
            }
            ("drep", 29) => match bytes[0] {
                0x22 => {
                    return Ok(shared::drep::DRepChoice::KeyHash {
                        hash_hex: hex::encode(&bytes[1..]),
                    })
                }
                0x23 => {
                    return Ok(shared::drep::DRepChoice::ScriptHash {
                        hash_hex: hex::encode(&bytes[1..]),
                    })
                }
                _ => {}
            },
            _ => {}
        }
    }
    // Backwards-compat: explicit hex forms with `key:` / `script:` prefix.
    // Both DRep credential variants are 28-byte hashes -> 56 hex chars.
    fn assert_drep_hex_shape(hex_str: &str, label: &str) -> Result<(), ErrorEnvelope> {
        if hex_str.len() != 56 || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ErrorEnvelope::invalid(format!(
                "{label} hex must be 56 hex chars (28 bytes), got {}",
                hex_str.len()
            )));
        }
        Ok(())
    }
    if let Some(rest) = s.strip_prefix("key:") {
        assert_drep_hex_shape(rest, "drep key hash")?;
        return Ok(shared::drep::DRepChoice::KeyHash {
            hash_hex: rest.to_string(),
        });
    }
    if let Some(rest) = s.strip_prefix("script:") {
        assert_drep_hex_shape(rest, "drep script hash")?;
        return Ok(shared::drep::DRepChoice::ScriptHash {
            hash_hex: rest.to_string(),
        });
    }
    Err(ErrorEnvelope::invalid(format!("unknown drep choice: {s} (expected abstain / no_confidence / drep1… / drep_script1… / key:<hex> / script:<hex>)"),))
}

pub(crate) async fn drep_start(
    State(app): State<Arc<AppState>>,
    Json(body): Json<DRepStartBody>,
) -> Result<Json<DRepStartResponse>, ErrorEnvelope> {
    let crate::util::StartHandlerCtx {
        params,
        own_sk,
        peer_pk,
        cfg: _,
        pool_id,
        payment_address,
    } = crate::util::start_handler_ctx(&app, &body.pin)?;

    let drep_choice = parse_drep_choice(body.drep.as_deref().unwrap_or("abstain"))?;
    let drep_choice_for_builder = match &drep_choice {
        shared::drep::DRepChoice::Abstain => tx_builder::DRepChoice::Abstain,
        shared::drep::DRepChoice::NoConfidence => tx_builder::DRepChoice::NoConfidence,
        shared::drep::DRepChoice::KeyHash { hash_hex } => {
            let bytes = hex::decode(hash_hex).map_err(|e| {
                error!(error = %e, "invalid drep key hex");
                ErrorEnvelope::invalid("invalid drep key hex")
            })?;
            if bytes.len() != 28 {
                return Err(ErrorEnvelope::invalid(format!(
                    "drep key hash must be 28 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut h = [0u8; 28];
            h.copy_from_slice(&bytes);
            tx_builder::DRepChoice::KeyHash(h)
        }
        shared::drep::DRepChoice::ScriptHash { hash_hex } => {
            let bytes = hex::decode(hash_hex).map_err(|e| {
                error!(error = %e, "invalid drep script hex");
                ErrorEnvelope::invalid("invalid drep script hex")
            })?;
            if bytes.len() != 28 {
                return Err(ErrorEnvelope::invalid(format!(
                    "drep script hash must be 28 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut h = [0u8; 28];
            h.copy_from_slice(&bytes);
            tx_builder::DRepChoice::ScriptHash(h)
        }
    };

    let pool = koios::pool_info(&app.http, &app.koios_base_url, &pool_id)
        .await
        .map_err(|e| {
            error!(error = %e, "koios pool_info failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let pool_reward_address = pool.reward_addr.ok_or(ErrorEnvelope::upstream(
        "pool reward address missing from Koios response",
    ))?;

    let (utxos, utxo_amounts, utxo_total) =
        crate::util::fetch_payment_utxos(&app.http, &app.koios_base_url, &payment_address).await?;
    let utxo_inputs: Vec<tx_builder::TxInput> = utxos
        .iter()
        .map(|u| tx_builder::TxInput {
            tx_hash_hex: u.tx_hash.clone(),
            tx_index: u.tx_index,
        })
        .collect();
    if utxo_inputs.is_empty() {
        return Err(ErrorEnvelope::insufficient_funds(
            "no UTXOs at payment address",
        ));
    }

    let fee_params = crate::util::fee_params(&app).await?;

    let tip = koios::tip(&app.http, &app.koios_base_url)
        .await
        .map_err(|e| {
            error!(error = %e, "koios tip failed");
            ErrorEnvelope::upstream("upstream service unavailable")
        })?;
    let ttl_slot = tip.abs_slot.saturating_add(TTL_MARGIN_SLOTS);

    let change_assets = crate::util::input_assets(&utxos)?;

    let inputs = tx_builder::DRepDelegationInputs {
        utxo_inputs: &utxo_inputs,
        change_assets: &change_assets,
        utxo_total_lovelace: utxo_total,
        payment_address_bech32: &payment_address,
        stake_credential_bech32: &pool_reward_address,
        drep_choice: drep_choice_for_builder,
        fee_params,
        ttl_slot,
    };
    let built = tx_builder::build_drep_delegation_body(&inputs).map_err(|e| match e {
        tx_builder::TxBuildError::InsufficientInputs { .. } => {
            ErrorEnvelope::insufficient_funds("payment address cannot cover fee + min-ADA change")
        }
        e => {
            error!(error = %e, "drep tx body build failed");
            ErrorEnvelope::internal("transaction build failed")
        }
    })?;
    let fee_lovelace = built.fee_lovelace;

    let body_hash = pallas_crypto::hash::Hasher::<256>::hash(&built.body_cbor);
    let body_hash_hex = hex::encode(body_hash);

    let opcert_start = state::load(&state::state_path()).opcert_start_kes_period;
    let chain_context = chain_context_from(&tip, &params, opcert_start)?;

    let request_inputs =
        crate::util::build_request_inputs(&utxo_inputs, &utxo_amounts, &payment_address);
    let mut request = shared::drep::DRepDelegationRequest {
        kind: shared::wire_kind::WireKind::DrepDelegation,
        tx_body_cbor_hex: hex::encode(&built.body_cbor),
        fee_lovelace,
        change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
        ttl_slot,
        payment_address_bech32: payment_address,
        stake_credential_bech32: pool_reward_address,
        drep_choice,
        inputs: request_inputs,
        operator_pin_proof: String::new(),
        chain_context,
    };

    let body_fp = shared::request_body_fp(&request);
    request.operator_pin_proof = shared::pin::pin_proof_hex(
        &body.pin,
        request.kind.wire_str(),
        request.chain_context.built_at_unix,
        &body_fp,
    );

    let (_json_bytes, ur_fragments, request_fingerprint) =
        shared::wire_io::build_sign_request(&request, &own_sk, &peer_pk)?;

    Ok(Json(DRepStartResponse {
        request,
        body_hash_hex,
        ur_fragments,
        request_fingerprint,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DRepResultBody {
    ur_fragments: Vec<String>,
}

pub(crate) async fn drep_result(
    State(app): State<Arc<AppState>>,
    Json(body): Json<DRepResultBody>,
) -> Result<Json<shared::drep::DRepDelegationResult>, ErrorEnvelope> {
    if body.ur_fragments.is_empty() {
        return Err(ErrorEnvelope::invalid("no UR fragments"));
    }
    let (own_sk, peer_pk) = paired_keys_or_err(&app)?;
    let json_bytes = ur_decode_required(
        &body.ur_fragments,
        &peer_pk,
        &own_sk,
        shared::qr::Direction::Response,
    )?;
    let result: shared::drep::DRepDelegationResult =
        serde_json::from_slice(&json_bytes).map_err(|e| {
            error!(error = %e, "invalid request payload");
            ErrorEnvelope::invalid("invalid request payload")
        })?;
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::drep::DRepChoice;

    // Same DRep, both encodings: CIP-105 bare hash vs CIP-129 header+hash.
    // Synthetic test vector, not a real registered DRep.
    const CRED_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabb";
    const CIP105: &str = "drep1qqgjyv6y24n80zye42aueh0wluqpzg3ng32kvaugnx4tkmygcvj";
    const CIP129: &str = "drep1ygqpzg3ng32kvaugnx4thnxaamlsqyfzxdz92enh3zv64wc0h3n2d";

    #[test]
    fn accepts_cip105_and_cip129_to_same_keyhash() {
        for id in [CIP105, CIP129] {
            let choice = parse_drep_choice(id).expect("parses");
            let DRepChoice::KeyHash { hash_hex } = choice else {
                panic!("expected KeyHash for {id}");
            };
            assert_eq!(hash_hex, CRED_HEX, "id {id} decoded to the wrong keyhash");
        }
    }
}
