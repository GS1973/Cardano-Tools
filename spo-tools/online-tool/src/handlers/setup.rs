use crate::{config, AppState};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use shared::error::ErrorEnvelope;
use std::sync::Arc;
use tracing::error;

#[derive(Serialize)]
pub(crate) struct OnlineConfigResponse {
    /// Whether all three required fields (pool_id, payment_address,
    /// reward_receive_address) are persisted and bech32-valid.
    pub saved: bool,
    /// Whether the encrypted channel to the signer is paired.
    pub paired: bool,
    /// Hex-grouped pairing fingerprint (`a37f-2c91-5be2-c8d4`) when paired,
    /// or `None`. Same fingerprint as shown during the visual pairing dance,
    /// so operators can confirm the channel without re-running setup.
    pub pairing_fingerprint: Option<String>,
    /// Currently-stored pool_id, payment_address, reward_receive_address.
    /// Returned so the Setup form can pre-populate on edit, allowing the
    /// operator to change a single field without retyping the rest. These
    /// values are public-on-chain (any Koios-style query can derive them
    /// from the pool_id), so echoing them on a loopback-only endpoint is
    /// not a meaningful information disclosure.
    pub pool_id: Option<String>,
    pub payment_address: Option<String>,
    pub reward_receive_address: Option<String>,
    /// Base URL the operator hosts rationale documents under; the
    /// governance-vote view composes the full anchor URL from this plus a
    /// file name.
    pub manifest_base_url: Option<String>,
    /// Whether a Koios API key is stored. The key value itself is never
    /// returned (it is operator-secret, possibly billed).
    pub has_koios_api_key: bool,
    /// Present when the POST just changed the stored Koios API key. The
    /// upstream HTTP client bakes the Authorization header in once at
    /// startup (main.rs) and is never rebuilt, so a changed key only
    /// reaches Koios after the binary restarts, without this notice the
    /// operator sees "key configured" while calls keep going out with
    /// the old credentials. Always `None` on GET.
    pub koios_api_key_restart_notice: Option<String>,
}

fn build_response(cfg: &config::OnlineConfig) -> OnlineConfigResponse {
    let saved = config::is_configured(cfg);
    let (paired, pairing_fingerprint) = shared::crypto::pairing_status(
        cfg.own_crypto_skey_hex.as_deref(),
        cfg.peer_crypto_pubkey_hex.as_deref(),
    );
    OnlineConfigResponse {
        saved,
        paired,
        pairing_fingerprint,
        pool_id: cfg.pool_id.clone(),
        payment_address: cfg.payment_address.clone(),
        reward_receive_address: cfg.reward_receive_address.clone(),
        manifest_base_url: cfg.manifest_base_url.clone(),
        has_koios_api_key: cfg
            .koios_api_key
            .as_deref()
            .map(|k| !k.is_empty())
            .unwrap_or(false),
        koios_api_key_restart_notice: None,
    }
}

pub(crate) async fn online_config_get(
    State(state): State<Arc<AppState>>,
) -> Json<OnlineConfigResponse> {
    Json(build_response(
        &state.config.read().unwrap_or_else(|e| e.into_inner()),
    ))
}

#[derive(Deserialize)]
pub(crate) struct OnlineConfigPostBody {
    pool_id: Option<String>,
    payment_address: Option<String>,
    reward_receive_address: Option<String>,
    koios_api_key: Option<String>,
    manifest_base_url: Option<String>,
}

pub(crate) async fn online_config_post(
    State(state): State<Arc<AppState>>,
    Json(body): Json<OnlineConfigPostBody>,
) -> Result<Json<OnlineConfigResponse>, ErrorEnvelope> {
    /// Hard ceiling on bech32 setup fields (pool_id ~56 chars,
    /// addresses ~103 chars on mainnet). Longer strings are user-error
    /// or attacker-probing and are rejected before running any parser.
    const MAX_BECH32_FIELD_LEN: usize = 200;
    /// Hard ceiling on the optional Koios API key. Koios issues
    /// JWT-style tokens (header.payload.signature) which routinely run
    /// 300-500 characters; 1024 leaves comfortable headroom while still
    /// bounding memory exposure on garbage input.
    const MAX_KOIOS_API_KEY_LEN: usize = 1024;
    fn cap_length(name: &'static str, s: &str, max: usize) -> Result<(), ErrorEnvelope> {
        if s.len() > max {
            return Err(ErrorEnvelope::invalid(format!(
                "{name} exceeds {max}-character limit"
            )));
        }
        Ok(())
    }
    fn require_bech32_field<'a>(
        name: &'static str,
        v: Option<&'a str>,
    ) -> Result<&'a str, ErrorEnvelope> {
        let s = v.map(str::trim).unwrap_or("");
        if s.is_empty() {
            return Err(ErrorEnvelope::invalid(format!("{name} is required")));
        }
        cap_length(name, s, MAX_BECH32_FIELD_LEN)?;
        Ok(s)
    }
    fn optional_field<'a>(
        name: &'static str,
        v: Option<&'a str>,
        max: usize,
    ) -> Result<Option<&'a str>, ErrorEnvelope> {
        let s = v.map(str::trim).unwrap_or("");
        cap_length(name, s, max)?;
        Ok(if s.is_empty() { None } else { Some(s) })
    }
    let pool_id = require_bech32_field("pool_id", body.pool_id.as_deref())?.to_string();
    let payment_address =
        require_bech32_field("payment_address", body.payment_address.as_deref())?.to_string();
    let reward_receive_address = require_bech32_field(
        "reward_receive_address",
        body.reward_receive_address.as_deref(),
    )?
    .to_string();
    let posted_koios = optional_field(
        "koios_api_key",
        body.koios_api_key.as_deref(),
        MAX_KOIOS_API_KEY_LEN,
    )?
    .map(str::to_string);
    // Manifest base URL is optional; when present it must be an https URL.
    const MAX_URL_LEN: usize = 500;
    let manifest_base_url: Option<String> = match optional_field(
        "manifest_base_url",
        body.manifest_base_url.as_deref(),
        MAX_URL_LEN,
    )? {
        Some(s) => {
            require_https_base(s)?;
            Some(s.to_string())
        }
        None => None,
    };

    config::validate_bech32(&pool_id, "pool").map_err(|e| {
        error!(error = %e, "invalid pool_id");
        ErrorEnvelope::invalid("invalid pool_id")
    })?;
    config::validate_bech32(&payment_address, "addr").map_err(|e| {
        error!(error = %e, "invalid payment_address");
        ErrorEnvelope::invalid("invalid payment_address")
    })?;
    config::validate_bech32(&reward_receive_address, "addr").map_err(|e| {
        error!(error = %e, "invalid reward_receive_address");
        ErrorEnvelope::invalid("invalid reward_receive_address")
    })?;

    // Preserve crypto fields across Setup re-saves: losing the pairing
    // every time the SPO edits the Koios key would be a UX trap. Same
    // preserve-semantic for the Koios API key itself: the GET response
    // does not echo the key (it is operator-secret), so the form is
    // blank on edit; an empty POST therefore means "operator did not
    // touch the key field, keep the stored one". A non-empty POST
    // overwrites. Clearing an existing key is intentionally not
    // exposed via this endpoint: operators clear by editing the
    // config file directly.
    //
    // Hold the write lock across the whole read-modify-write: a snapshot
    // taken outside the lock would race a concurrent pairing handler and
    // write back its stale own/peer crypto keys, silently un-pairing.
    let mut guard = state.config.write().unwrap_or_else(|e| e.into_inner());
    // A key change is persisted but does NOT reach the running reqwest
    // client, its Authorization header was baked in at startup, so the
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
        pool_id: Some(pool_id),
        payment_address: Some(payment_address),
        reward_receive_address: Some(reward_receive_address),
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
            "Koios API key saved. Restart spo-tools-online for the new key to \
             take effect: the running process keeps using the previous \
             credentials until then."
                .to_string(),
        );
    }
    Ok(Json(response))
}

/// The manifest base URL is the prefix of every anchor URL the tool
/// composes, and the document behind such a URL is what the hash helper
/// fetches. Plain http is refused for both reasons: an anchored document
/// served over http can be altered on the network path, and the hash helper
/// only fetches https.
fn require_https_base(url: &str) -> Result<(), ErrorEnvelope> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(ErrorEnvelope::invalid(
            "manifest_base_url must start with https://",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_base_url_must_be_https() {
        assert!(require_https_base("https://example.org/governance/").is_ok());
        for bad in [
            "http://example.org/governance/",
            "ftp://example.org/",
            "example.org/governance/",
            "//example.org/",
            "",
        ] {
            let err = match require_https_base(bad) {
                Err(e) => e,
                Ok(()) => panic!("{bad:?} must be refused"),
            };
            assert!(err.message.contains("https://"), "{}", err.message);
        }
    }
}
