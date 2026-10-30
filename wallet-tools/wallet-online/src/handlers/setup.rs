use crate::{config, AppState};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use shared::error::ErrorEnvelope;
use std::sync::Arc;
use tracing::error;

#[derive(Serialize)]
pub(crate) struct AddressEntryView {
    pub label: String,
    pub address: String,
    pub kind: config::AddressKind,
    /// For Own entries, the stake address derived from the base address (the
    /// delegation target). None for External destinations.
    pub stake_address: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct OnlineConfigResponse {
    /// Whether at least one own (signable) wallet is configured.
    pub saved: bool,
    /// Whether the encrypted channel to the signer is paired.
    pub paired: bool,
    pub pairing_fingerprint: Option<String>,
    /// Whether a Koios API key is stored. The value itself is never echoed.
    pub has_koios_api_key: bool,
    /// Present when the POST just changed the stored Koios API key. The
    /// upstream HTTP client bakes the Authorization header in once at
    /// startup (main.rs) and is never rebuilt, so a changed key only
    /// reaches Koios after the binary restarts, without this notice the
    /// operator sees "key configured" while calls keep going out with
    /// the old credentials. Always `None` on GET.
    pub koios_api_key_restart_notice: Option<String>,
    /// The full address book, each own entry carrying its derived stake address.
    pub address_book: Vec<AddressEntryView>,
}

fn entry_view(e: &config::AddressEntry) -> AddressEntryView {
    let stake_address = if e.kind == config::AddressKind::Own {
        crate::util::stake_address_from_base(&e.address).ok()
    } else {
        None
    };
    AddressEntryView {
        label: e.label.clone(),
        address: e.address.clone(),
        kind: e.kind,
        stake_address,
    }
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
        has_koios_api_key: cfg
            .koios_api_key
            .as_deref()
            .map(|k| !k.is_empty())
            .unwrap_or(false),
        koios_api_key_restart_notice: None,
        address_book: cfg.address_book.iter().map(entry_view).collect(),
    }
}

pub(crate) async fn online_config_get(
    State(state): State<Arc<AppState>>,
) -> Json<OnlineConfigResponse> {
    Json(build_response(&state.config.read().unwrap()))
}

#[derive(Deserialize)]
pub(crate) struct OnlineConfigPostBody {
    koios_api_key: Option<String>,
}

/// Setup now holds only the Koios API key (the wallet addresses live in the
/// address book). Leaving the field blank keeps the stored key; sending a
/// value replaces it.
pub(crate) async fn online_config_post(
    State(state): State<Arc<AppState>>,
    Json(body): Json<OnlineConfigPostBody>,
) -> Result<Json<OnlineConfigResponse>, ErrorEnvelope> {
    const MAX_KOIOS_API_KEY_LEN: usize = 1024;
    let posted_koios = {
        let s = body.koios_api_key.as_deref().map(str::trim).unwrap_or("");
        if s.len() > MAX_KOIOS_API_KEY_LEN {
            return Err(ErrorEnvelope::invalid(format!(
                "koios_api_key exceeds {MAX_KOIOS_API_KEY_LEN}-character limit"
            )));
        }
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };

    // Hold the write lock across the whole read-modify-write: a snapshot taken
    // outside the lock would race a concurrent pairing handler and write back
    // its stale own/peer crypto keys, silently un-pairing.
    let mut guard = state.config.write().unwrap();
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
    let mut new = guard.clone();
    new.koios_api_key = posted_koios.or_else(|| new.koios_api_key.clone());
    config::save(&state.config_path, &new).map_err(|e| {
        error!(error = %e, "save online config failed");
        ErrorEnvelope::internal("failed to persist state")
    })?;
    *guard = new;
    let mut response = build_response(&guard);
    if koios_key_changed {
        response.koios_api_key_restart_notice = Some(
            "Koios API key saved. Restart wallet-tools-online for the new key to \
             take effect: the running process keeps using the previous \
             credentials until then."
                .to_string(),
        );
    }
    Ok(Json(response))
}

#[derive(Deserialize)]
pub(crate) struct AddressBookEntryBody {
    label: String,
    address: String,
    kind: config::AddressKind,
}

#[derive(Deserialize)]
pub(crate) struct AddressBookPostBody {
    entries: Vec<AddressBookEntryBody>,
}

/// Replace the entire address book. Validates every entry; own wallets may be
/// base addresses (`addr1q…`, delegatable) or enterprise addresses (`addr1v…`,
/// payment-only) and are capped at [`config::MAX_OWN_ADDRESSES`]; external
/// destinations may be any valid `addr1…` whose payment part is a key, and
/// are uncapped.
pub(crate) async fn address_book_post(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddressBookPostBody>,
) -> Result<Json<OnlineConfigResponse>, ErrorEnvelope> {
    const MAX_LABEL_LEN: usize = 64;
    const MAX_BECH32_FIELD_LEN: usize = 200;

    let mut book: Vec<config::AddressEntry> = Vec::with_capacity(body.entries.len());
    let mut own_count = 0usize;
    for (i, e) in body.entries.iter().enumerate() {
        let label = e.label.trim();
        let address = e.address.trim();
        if label.is_empty() {
            return Err(ErrorEnvelope::invalid(format!(
                "entry {} is missing a label",
                i + 1
            )));
        }
        if label.chars().count() > MAX_LABEL_LEN {
            return Err(ErrorEnvelope::invalid(format!(
                "a label exceeds the {MAX_LABEL_LEN}-character limit"
            )));
        }
        if address.len() > MAX_BECH32_FIELD_LEN {
            return Err(ErrorEnvelope::invalid(
                "an address exceeds the length limit",
            ));
        }
        config::validate_bech32(address, "addr").map_err(|_| {
            ErrorEnvelope::invalid(format!("'{label}' is not a valid addr1… address"))
        })?;
        if shared::tx_validator::payment_part_is_script(address).map_err(|_| {
            ErrorEnvelope::invalid(format!("'{label}' is not a valid addr1… address"))
        })? {
            return Err(ErrorEnvelope::invalid(format!(
                "'{label}' refused: {}",
                shared::tx_validator::SCRIPT_DESTINATION_REFUSED
            )));
        }
        if e.kind == config::AddressKind::Own {
            // An own wallet may be a base address (addr1q…, delegatable) or an
            // enterprise address (addr1v…, payment-only). Either is valid here.
            own_count += 1;
        }
        book.push(config::AddressEntry {
            label: label.to_string(),
            address: address.to_string(),
            kind: e.kind,
        });
    }
    if own_count > config::MAX_OWN_ADDRESSES {
        return Err(ErrorEnvelope::invalid(format!(
            "at most {} own wallets are supported",
            config::MAX_OWN_ADDRESSES
        )));
    }

    // Hold the write lock across the whole read-modify-write so a concurrent
    // pairing handler's own/peer crypto keys cannot be clobbered by a stale
    // snapshot written back here.
    let mut guard = state.config.write().unwrap();
    let mut new = guard.clone();
    new.address_book = book;
    config::save(&state.config_path, &new).map_err(|e| {
        error!(error = %e, "save address book failed");
        ErrorEnvelope::internal("failed to persist state")
    })?;
    *guard = new;
    Ok(Json(build_response(&guard)))
}
