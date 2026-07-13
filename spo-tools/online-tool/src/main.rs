//! SPO Tools — online tool.
//!
//! Internet-connected web backend. Talks to Koios for chain data, builds
//! unsigned transactions, hands them off to the signer via QR, and submits
//! signed transactions back to Koios. Holds no keys.
//!
//! This binary listens on a loopback interface only — never on a public
//! address. The loopback constraint is enforced at startup (see
//! `parse_listen_addr`); a non-loopback `--listen` is rejected unless the
//! operator explicitly passes `--allow-non-loopback`.

mod config;
mod tx_builder;
mod koios;
mod state;
mod util;
mod handlers;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use shared::error::ErrorEnvelope;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

/// Locked-down CSP for an offline single-binary webapp:
/// - everything must be same-origin,
/// - inline `<style>` allowed because Vuetify injects scoped CSS at runtime,
/// - `img-src 'self' data:` to permit the QR data: URLs,
/// - `frame-ancestors 'none'` so the page cannot be iframed.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USAGE: &str = "spo-tools-online --listen 127.0.0.1:PORT [--koios-url URL] [--debug]";
const DEFAULT_KOIOS_BASE_URL: &str = "https://api.koios.rest/api/v1";

/// Parse `--listen ADDR:PORT` from the process arguments. The flag is
/// required: there is no default port, both for security (no fixed port
/// to scan) and to enable side-by-side instances on the same host.
///
/// The parsed address is enforced to be loopback (`127.0.0.0/8` or `::1`):
/// this tool must never listen on a public interface. A non-loopback
/// address is rejected unless `--allow-non-loopback` is explicitly passed,
/// which is strongly discouraged — the online tool holds Koios access and
/// builds/submits transactions.
///
/// Wildcard addresses (`0.0.0.0` / `[::]`) are rejected even with the
/// override: the CSRF guard's Host/Origin allow-list is derived from the
/// bound address (`CsrfConfig::for_listener`), and no client ever sends a
/// wildcard in its Host header, so every request would be answered 403.
fn parse_listen_addr(args: &[String]) -> Result<SocketAddr, String> {
    let allow_non_loopback = args.iter().any(|a| a == "--allow-non-loopback");
    let mut iter = args.iter().skip(1);
    let mut addr: Option<SocketAddr> = None;
    while let Some(arg) = iter.next() {
        if arg == "--listen" {
            let val = iter.next().ok_or_else(|| {
                format!("--listen requires an ADDR:PORT value\nUsage: {USAGE}")
            })?;
            addr = Some(val.parse().map_err(|e| {
                format!("invalid --listen value `{val}`: {e}\nUsage: {USAGE}")
            })?);
            break;
        }
        if let Some(val) = arg.strip_prefix("--listen=") {
            addr = Some(val.parse().map_err(|e| {
                format!("invalid --listen value `{val}`: {e}\nUsage: {USAGE}")
            })?);
            break;
        }
    }
    let addr = addr.ok_or_else(|| format!("missing required --listen flag\nUsage: {USAGE}"))?;
    if addr.ip().is_unspecified() {
        return Err(format!(
            "refusing to bind wildcard address `{addr}`: the CSRF guard derives its allowed \
             Host values from the bound address, and no browser sends a wildcard Host, so every \
             request would get 403. Bind a specific interface address instead (e.g. \
             `--listen 127.0.0.1:PORT`).\nUsage: {USAGE}"
        ));
    }
    if !addr.ip().is_loopback() && !allow_non_loopback {
        return Err(format!(
            "refusing to bind non-loopback address `{addr}`: this tool is designed to \
             listen on a loopback address (127.0.0.1) only. Re-run with `--listen 127.0.0.1:PORT`, \
             or pass `--allow-non-loopback` to override (strongly discouraged — it exposes Koios \
             access and transaction building/submission to the network).\nUsage: {USAGE}"
        ));
    }
    Ok(addr)
}

/// Parse `--koios-url URL` from the process arguments. Optional; defaults
/// to mainnet (`https://api.koios.rest/api/v1`). Useful for self-hosted /
/// custom *mainnet* Koios deployments and integration tests. Not a preprod
/// switch: the binary is hard-wired to mainnet (tx bodies set
/// `NetworkId::Mainnet`, address decoding accepts `addr1`/`stake1` HRPs
/// only, and the Shelley-era slot/epoch anchors in `koios.rs` are mainnet
/// constants), so pointing this at a preprod/preview Koios yields wrong
/// timings and unsignable transactions.
fn parse_koios_url(args: &[String]) -> String {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--koios-url" {
            if let Some(val) = iter.next() {
                return val.clone();
            }
        }
        if let Some(val) = arg.strip_prefix("--koios-url=") {
            return val.to_string();
        }
    }
    DEFAULT_KOIOS_BASE_URL.to_string()
}

pub(crate) struct AppState {
    pub(crate) http: reqwest::Client,
    /// Cardano protocol parameters, fetched from Koios `/genesis`. `None`
    /// means they have not yet been successfully retrieved — every endpoint
    /// that needs them refuses with [`ErrorCode::SnapshotNotReady`] in that
    /// state, and the UI offers a retry button (`POST /api/genesis/refresh`).
    pub(crate) genesis: Mutex<Option<koios::GenesisParams>>,
    /// Pool/payment configuration. Loaded from disk at startup, refreshed
    /// on POST /api/online-config. Endpoints needing pool_id refuse with
    /// [`ErrorCode::NotConfigured`] until configured.
    pub(crate) config: RwLock<config::OnlineConfig>,
    /// Resolved on-disk path used by every load/save site. Captured once
    /// in `main` so handlers do not repeat the path resolution.
    pub(crate) config_path: std::path::PathBuf,
    /// Base URL for every Koios call. Defaults to mainnet, overridable
    /// via `--koios-url` for self-hosted mainnet Koios / integration
    /// tests (never preprod — see `parse_koios_url`).
    pub(crate) koios_base_url: String,
}

impl AppState {
    /// Snapshot the current genesis params, or [`ErrorCode::SnapshotNotReady`]
    /// if they have never been loaded.
    pub(crate) fn require_genesis(&self) -> Result<koios::GenesisParams, ErrorEnvelope> {
        self.genesis.lock().unwrap_or_else(|e| e.into_inner()).ok_or_else(|| {
            ErrorEnvelope::snapshot_not_ready(
                "Cardano protocol parameters not available — Koios was unreachable when this binary started. Use POST /api/genesis/refresh to retry.",
            )
        })
    }

    /// Pool ID from configuration, or [`ErrorCode::NotConfigured`] if Setup
    /// has not been completed — UI renders the "configure your pool" prompt.
    pub(crate) fn require_pool_id(&self) -> Result<String, ErrorEnvelope> {
        self.config
            .read()
            .unwrap()
            .pool_id
            .clone()
            .ok_or_else(|| ErrorEnvelope::not_configured("Pool not configured — complete Setup first."))
    }
}

#[derive(Serialize)]
struct Health {
    ok: bool,
}

#[derive(Serialize)]
struct Status {
    name: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health { ok: true })
}

async fn status() -> Json<Status> {
    Json(Status {
        name: "spo-tools-online",
        version: VERSION,
    })
}

/// Build the application router.
///
/// The frontend fallback is registered BEFORE the middleware stack so that
/// every served response — including the SPA fallback document and any 404 —
/// passes through the CSRF guard and the CSP / X-Frame-Options /
/// X-Content-Type-Options / Referrer-Policy response-header layers.
/// Registered after `.layer(...)` it would leave the served HTML/JS/CSS
/// with none of these headers.
fn build_app(state: Arc<AppState>, listen_addr: SocketAddr) -> Router {
    let csrf_cfg = shared::csrf::CsrfConfig::for_listener(listen_addr);
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/api/pool/info", get(handlers::pool_info::pool_info))
        .route("/api/pool/current", get(handlers::pool::pool_current))
        .route("/api/pool/pledge-precheck", get(handlers::pool::pool_pledge_precheck))
        .route("/api/pool/metadata-hash", post(handlers::pool::pool_metadata_hash))
        .route("/api/pool/build", post(handlers::pool::pool_build))
        .route("/api/pool/result", post(handlers::pool::pool_result))
        .route("/api/pool/submit", post(util::submit_tx_handler))
        .route("/api/leaderlog/start", post(handlers::leaderlog::leaderlog_start))
        .route("/api/leaderlog/result", post(handlers::leaderlog::leaderlog_result))
        .route("/api/kes/status", get(handlers::kes::kes_status))
        .route("/api/kes/state", post(handlers::kes::kes_set_state))
        .route("/api/kes/start", post(handlers::kes::kes_start))
        .route("/api/kes/result", post(handlers::kes::kes_result))
        .route("/api/genesis/status", get(handlers::genesis::genesis_status))
        .route("/api/genesis/refresh", post(handlers::genesis::genesis_refresh))
        .route("/api/online-config", get(handlers::setup::online_config_get).post(handlers::setup::online_config_post))
        .route("/api/withdraw/preview", get(handlers::withdraw::withdraw_preview))
        .route("/api/withdraw/start", post(handlers::withdraw::withdraw_start))
        .route("/api/withdraw/result", post(handlers::withdraw::withdraw_result))
        .route("/api/withdraw/submit", post(util::submit_tx_handler))
        .route("/api/drep/preview", get(handlers::drep::drep_preview))
        .route("/api/drep/start", post(handlers::drep::drep_start))
        .route("/api/drep/result", post(handlers::drep::drep_result))
        .route("/api/drep/submit", post(util::submit_tx_handler))
        .route("/api/vote/preview", get(handlers::vote::vote_preview))
        .route("/api/vote/start", post(handlers::vote::vote_start))
        .route("/api/vote/result", post(handlers::vote::vote_result))
        .route("/api/vote/submit", post(util::submit_tx_handler))
        .route("/api/pairing/info", get(handlers::pairing::pairing_info))
        .route("/api/pairing/preview", post(handlers::pairing::pairing_preview))
        .route("/api/pairing/set-peer", post(handlers::pairing::pairing_set_peer))
        .route("/api/pairing/clear", post(handlers::pairing::pairing_clear))
        .fallback(handlers::frontend::frontend_handler)
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(axum::middleware::from_fn_with_state(csrf_cfg, shared::csrf::csrf_guard))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<String> = std::env::args().collect();
    let debug_mode = argv.iter().any(|a| a == "--debug");
    let listen_addr = parse_listen_addr(&argv).map_err(|e| {
        eprintln!("{e}");
        Box::<dyn std::error::Error>::from("invalid arguments")
    })?;
    let koios_base_url = parse_koios_url(&argv);
    let default_filter = if debug_mode { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .init();
    if debug_mode {
        info!("debug mode active — verbose logging enabled");
    }
    if !listen_addr.ip().is_loopback() {
        tracing::warn!(
            addr = %listen_addr,
            "SECURITY: binding to a non-loopback address — the online tool is reachable beyond \
             localhost; this exposes Koios access and transaction building/submission. \
             Strongly discouraged."
        );
    }

    let cfg_path = config::config_path();
    let mut initial_config = config::load(&cfg_path);

    // Pre-generate the X25519 channel keypair at startup so it exists
    // before any request arrives. Without this, the first
    // GET /api/pairing/info would generate and persist it — a
    // state-mutating GET. Pre-generating makes every pairing handler,
    // including the GET, read-only against the on-disk keypair. A failure
    // here is non-fatal: the handlers keep their lazy fallback.
    if let Err(e) = config::ensure_own_crypto_skey(&cfg_path, &mut initial_config) {
        tracing::warn!(error = %e, "could not initialise channel keypair at startup; pairing endpoints will generate it lazily on first use");
    }

    // Generic User-Agent: do not advertise the tool name to Koios. A
    // tool-specific UA gives any Koios-side observer (or self-hosted
    // Koios proxy) a one-line attribution that "this account uses
    // spo-tools", which combines with pool_id + address lookups into a
    // stronger fingerprint than necessary. The built-in reqwest UA is
    // shared by many Rust clients and provides cover.
    let mut http_builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30));
    if let Some(api_key) = initial_config
        .koios_api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        let header_value = format!("Bearer {api_key}");
        match reqwest::header::HeaderValue::from_str(&header_value) {
            Ok(value) => {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(reqwest::header::AUTHORIZATION, value);
                http_builder = http_builder.default_headers(headers);
                info!("Koios API key configured — Authorization header attached to upstream calls");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Koios API key contains invalid characters; ignoring");
            }
        }
    }
    let http = http_builder.build()?;

    // Try to fetch Cardano protocol params from Koios at startup. If Koios
    // is unreachable, KES endpoints return 503 until a manual
    // POST /api/genesis/refresh succeeds.
    let initial_genesis = match koios::fetch_genesis_params(&http, &koios_base_url).await {
        Ok(params) => {
            // GenesisParams must remain operator-non-identifying (only
            // public Cardano protocol constants like active_slots_coeff,
            // epoch_length, slots_per_kes_period). If a future field is
            // added that could fingerprint the operator, log a curated
            // subset instead of `?params`.
            info!(?params, "loaded genesis params from Koios");
            Some(params)
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not fetch genesis from Koios at startup; KES endpoints will be unavailable until POST /api/genesis/refresh succeeds");
            None
        }
    };
    info!(
        path = %cfg_path.display(),
        configured = config::is_configured(&initial_config),
        "loaded online config"
    );

    let state = Arc::new(AppState {
        http,
        genesis: Mutex::new(initial_genesis),
        config: RwLock::new(initial_config),
        config_path: cfg_path,
        koios_base_url,
    });
    let app = build_app(state, listen_addr);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let bound = listener.local_addr()?;
    println!("Online tool listening on http://{bound}");
    info!(addr = %bound, version = VERSION, "spo-tools-online listening (frontend embedded)");

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex, RwLock};

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            http: reqwest::Client::new(),
            genesis: Mutex::new(None),
            config: RwLock::new(config::OnlineConfig::default()),
            config_path: std::path::PathBuf::from("/nonexistent/online.json"),
            koios_base_url: "http://127.0.0.1:1".to_string(),
        })
    }

    fn args(parts: &[&str]) -> Vec<String> {
        std::iter::once("spo-tools-online")
            .chain(parts.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn loopback_addresses_are_accepted() {
        assert!(parse_listen_addr(&args(&["--listen", "127.0.0.1:8200"])).is_ok());
        assert!(parse_listen_addr(&args(&["--listen", "127.0.0.5:8200"])).is_ok());
        assert!(parse_listen_addr(&args(&["--listen", "[::1]:8200"])).is_ok());
    }

    #[test]
    fn non_loopback_is_rejected_without_override() {
        assert!(parse_listen_addr(&args(&["--listen", "0.0.0.0:8200"])).is_err());
        assert!(parse_listen_addr(&args(&["--listen", "192.168.1.10:8200"])).is_err());
    }

    #[test]
    fn non_loopback_allowed_only_with_explicit_flag() {
        assert!(parse_listen_addr(&args(&[
            "--listen",
            "192.168.1.10:8200",
            "--allow-non-loopback"
        ]))
        .is_ok());
    }

    /// A wildcard bind can never serve a request — no client sends
    /// `0.0.0.0` / `[::]` as its Host header, so the derived CSRF
    /// allow-list would reject everything with 403. Rejected up front,
    /// even with the non-loopback override.
    #[test]
    fn wildcard_bind_is_rejected_even_with_override() {
        assert!(parse_listen_addr(&args(&[
            "--listen",
            "0.0.0.0:8200",
            "--allow-non-loopback"
        ]))
        .is_err());
        assert!(parse_listen_addr(&args(&[
            "--listen",
            "[::]:8200",
            "--allow-non-loopback"
        ]))
        .is_err());
    }

    /// Regression guard for the IPv6-loopback CSRF bug: the guard's
    /// Host/Origin allow-list is derived from the actual listen address,
    /// so a server bound to `[::1]` must serve a request carrying the
    /// bracketed Host form the browser sends — not 403 every request.
    #[tokio::test]
    async fn ipv6_loopback_listener_accepts_its_own_host() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let addr: SocketAddr = "[::1]:8200".parse().unwrap();
        let app = build_app(test_state(), addr);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::HOST, "[::1]:8200")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The `--allow-non-loopback` escape hatch must actually be usable:
    /// bound to a specific non-loopback address, the server accepts the
    /// Host form a remote client sends for that address.
    #[tokio::test]
    async fn non_loopback_listener_accepts_its_bound_host() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let addr: SocketAddr = "192.168.1.10:8200".parse().unwrap();
        let app = build_app(test_state(), addr);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::HOST, "192.168.1.10:8200")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Regression guard for the layer-ordering bug: the frontend fallback must
    /// be wrapped by the response-header layers, so even a served document (or
    /// a 404 from the fallback) carries CSP and framing headers.
    #[tokio::test]
    async fn frontend_fallback_carries_security_headers() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let addr: SocketAddr = "127.0.0.1:8200".parse().unwrap();
        let app = build_app(test_state(), addr);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/index.html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.headers().contains_key("content-security-policy"),
            "frontend response is missing Content-Security-Policy"
        );
        assert_eq!(
            resp.headers().get("x-frame-options").unwrap().to_str().unwrap(),
            "DENY"
        );
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff"
        );
    }
}
