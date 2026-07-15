use crate::{config, AppState};
use shared::error::ErrorEnvelope;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

#[derive(Serialize)]
pub(crate) struct OnlineConfigResponse {
    /// Whether drep_id + payment_address are persisted and valid.
    pub saved: bool,
    /// Whether the encrypted channel to the signer is paired.
    pub paired: bool,
    pub pairing_fingerprint: Option<String>,
    /// Stored values, echoed so the Setup form can pre-populate. Both are
    /// public-on-chain, so echoing them on a loopback endpoint is not a
    /// meaningful disclosure.
    pub drep_id: Option<String>,
    pub payment_address: Option<String>,
    /// Base URL the operator hosts manifests under; Register/Update compose
    /// the full anchor URL from this plus a file name.
    pub manifest_base_url: Option<String>,
    /// Whether a Koios API key is stored. The value itself is never echoed.
    pub has_koios_api_key: bool,
    /// Present when the POST just changed the stored Koios API key. The
    /// upstream HTTP client bakes the Authorization header in once at
    /// startup (main.rs) and is never rebuilt, so a changed key only
    /// reaches Koios after the binary restarts — without this notice the
    /// operator sees "key configured" while calls keep going out with
    /// the old credentials. Always `None` on GET.
    pub koios_api_key_restart_notice: Option<String>,
}

fn build_response(cfg: &config::OnlineConfig) -> OnlineConfigResponse {
    let (paired, pairing_fingerprint) = shared::crypto::pairing_status(
        cfg.own_crypto_skey_hex.as_deref(),
        cfg.peer_crypto_pubkey_hex.as_deref(),
    );
    OnlineConfigResponse {
        saved: config::is_configured(cfg),
        paired,
        pairing_fingerprint,
        drep_id: cfg.drep_id.clone(),
        payment_address: cfg.payment_address.clone(),
        manifest_base_url: cfg.manifest_base_url.clone(),
        has_koios_api_key: cfg.koios_api_key.as_deref().map(|k| !k.is_empty()).unwrap_or(false),
        koios_api_key_restart_notice: None,
    }
}

pub(crate) async fn online_config_get(State(state): State<Arc<AppState>>) -> Json<OnlineConfigResponse> {
    Json(build_response(&state.config.read().unwrap()))
}

#[derive(Deserialize)]
pub(crate) struct OnlineConfigPostBody {
    drep_id: Option<String>,
    payment_address: Option<String>,
    koios_api_key: Option<String>,
    manifest_base_url: Option<String>,
}

pub(crate) async fn online_config_post(
    State(state): State<Arc<AppState>>,
    Json(body): Json<OnlineConfigPostBody>,
) -> Result<Json<OnlineConfigResponse>, ErrorEnvelope> {
    const MAX_BECH32_FIELD_LEN: usize = 200;
    const MAX_KOIOS_API_KEY_LEN: usize = 1024;
    fn cap(name: &'static str, s: &str, max: usize) -> Result<(), ErrorEnvelope> {
        if s.len() > max {
            return Err(ErrorEnvelope::invalid(format!("{name} exceeds {max}-character limit")));
        }
        Ok(())
    }
    fn require<'a>(name: &'static str, v: Option<&'a str>) -> Result<&'a str, ErrorEnvelope> {
        let s = v.map(str::trim).unwrap_or("");
        if s.is_empty() {
            return Err(ErrorEnvelope::invalid(format!("{name} is required")));
        }
        cap(name, s, MAX_BECH32_FIELD_LEN)?;
        Ok(s)
    }
    // payment_address is required — every operation funds fees and the
    // registration deposit from it. drep_id is optional at save time so the
    // online tool can be configured and paired before the signer has
    // generated the DRep key; each operation re-checks it and reports
    // "DRep id not configured" until it is filled in.
    let payment_address = require("payment_address", body.payment_address.as_deref())?.to_string();
    let drep_id: Option<String> = {
        let s = body.drep_id.as_deref().map(str::trim).unwrap_or("");
        if s.is_empty() {
            None
        } else {
            cap("drep_id", s, MAX_BECH32_FIELD_LEN)?;
            // HRP check, then the full DRep-id decode (CIP-105/129, key-DRep only).
            config::validate_bech32(s, "drep")
                .map_err(|e| { error!(error = %e, "invalid drep_id"); ErrorEnvelope::invalid("invalid drep_id") })?;
            shared::drep_id::drep_id_to_keyhash(s)
                .map_err(|e| { error!(error = %e, "invalid drep_id"); ErrorEnvelope::invalid(format!("invalid drep_id: {e}")) })?;
            Some(s.to_string())
        }
    };
    let posted_koios = {
        let s = body.koios_api_key.as_deref().map(str::trim).unwrap_or("");
        cap("koios_api_key", s, MAX_KOIOS_API_KEY_LEN)?;
        if s.is_empty() { None } else { Some(s.to_string()) }
    };
    // Manifest base URL is optional; when present it must be an http(s) URL.
    const MAX_URL_LEN: usize = 500;
    let manifest_base_url: Option<String> = {
        let s = body.manifest_base_url.as_deref().map(str::trim).unwrap_or("");
        if s.is_empty() {
            None
        } else {
            cap("manifest_base_url", s, MAX_URL_LEN)?;
            if !(s.starts_with("https://") || s.starts_with("http://")) {
                return Err(ErrorEnvelope::invalid("manifest_base_url must start with http:// or https://"));
            }
            Some(s.to_string())
        }
    };

    config::validate_bech32(&payment_address, "addr")
        .map_err(|e| { error!(error = %e, "invalid payment_address"); ErrorEnvelope::invalid("invalid payment_address") })?;

    // Hold the write lock across the whole read-modify-write: a snapshot
    // taken outside the lock would race a concurrent pairing handler and
    // write back its stale own/peer crypto keys, silently un-pairing.
    let mut guard = state.config.write().unwrap();
    // A key change is persisted but does NOT reach the running reqwest
    // client — its Authorization header was baked in at startup — so the
    // response carries a restart notice below.
    let koios_key_changed = match &posted_koios {
        Some(new_key) => guard
            .koios_api_key
            .as_deref()
            .map(|old| old != new_key.as_str())
            .unwrap_or(true),
        None => false,
    };
    let koios_api_key = posted_koios.or(guard.koios_api_key.clone());
    let new = config::OnlineConfig {
        drep_id,
        payment_address: Some(payment_address),
        koios_api_key,
        manifest_base_url,
        own_crypto_skey_hex: guard.own_crypto_skey_hex.clone(),
        peer_crypto_pubkey_hex: guard.peer_crypto_pubkey_hex.clone(),
    };
    config::save(&state.config_path, &new).map_err(|e| {
        error!(error = %e, "save online config failed");
        ErrorEnvelope::internal("failed to persist state")
    })?;
    *guard = new;
    let mut response = build_response(&guard);
    if koios_key_changed {
        response.koios_api_key_restart_notice = Some(
            "Koios API key saved. Restart drep-tools-online for the new key to \
             take effect — the running process keeps using the previous \
             credentials until then."
                .to_string(),
        );
    }
    Ok(Json(response))
}
