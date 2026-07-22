//! DRep Tools — online tool.
//!
//! Internet-connected web backend. Talks to Koios for chain data, builds
//! unsigned DRep transactions, hands them to the air-gapped signer via QR,
//! and submits signed transactions back to Koios. Holds no keys.
//!
//! Listens on a loopback interface only — never a public address. The
//! loopback constraint is enforced at startup (see `parse_listen_addr`);
//! a non-loopback `--listen` is rejected unless the operator explicitly
//! passes `--allow-non-loopback`.

mod config;
mod handlers;
mod koios;
mod tx_builder;
mod util;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USAGE: &str = "drep-tools-online --listen 127.0.0.1:PORT [--koios-url URL] [--debug]";
const DEFAULT_KOIOS_BASE_URL: &str = "https://api.koios.rest/api/v1";

/// Parse `--listen ADDR:PORT` from the process arguments.
///
/// The parsed address is enforced to be loopback (`127.0.0.0/8` or `::1`):
/// this tool must never listen on a public interface. A non-loopback
/// address is rejected unless `--allow-non-loopback` is explicitly passed,
/// which is strongly discouraged — the online tool holds Koios access and
/// builds/submits transactions.
fn parse_listen_addr(args: &[String]) -> Result<SocketAddr, String> {
    let allow_non_loopback = args.iter().any(|a| a == "--allow-non-loopback");
    let mut iter = args.iter().skip(1);
    let mut addr: Option<SocketAddr> = None;
    while let Some(arg) = iter.next() {
        if arg == "--listen" {
            let val = iter
                .next()
                .ok_or_else(|| format!("--listen requires an ADDR:PORT value\nUsage: {USAGE}"))?;
            addr = Some(
                val.parse()
                    .map_err(|e| format!("invalid --listen value `{val}`: {e}\nUsage: {USAGE}"))?,
            );
            break;
        }
        if let Some(val) = arg.strip_prefix("--listen=") {
            addr = Some(
                val.parse()
                    .map_err(|e| format!("invalid --listen value `{val}`: {e}\nUsage: {USAGE}"))?,
            );
            break;
        }
    }
    let addr = addr.ok_or_else(|| format!("missing required --listen flag\nUsage: {USAGE}"))?;
    if addr.ip().is_unspecified() {
        return Err(format!(
            "refusing to bind wildcard address `{addr}`: the CSRF guard derives its allowed \
             Host values from the bound address, and no browser sends a wildcard Host, so every \
             request would be answered 403 (re-run with a concrete address such as \
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

fn parse_koios_url(args: &[String]) -> Result<String, String> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--koios-url" {
            let val = iter
                .next()
                .ok_or_else(|| format!("--koios-url requires a URL value\nUsage: {USAGE}"))?;
            return Ok(val.clone());
        }
        if let Some(val) = arg.strip_prefix("--koios-url=") {
            return Ok(val.to_string());
        }
    }
    Ok(DEFAULT_KOIOS_BASE_URL.to_string())
}

pub(crate) struct AppState {
    pub(crate) http: reqwest::Client,
    pub(crate) config: RwLock<config::OnlineConfig>,
    pub(crate) config_path: std::path::PathBuf,
    pub(crate) koios_base_url: String,
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
    Json(Status { name: "drep-tools-online", version: VERSION })
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
        .route("/api/drep-config", get(handlers::setup::online_config_get).post(handlers::setup::online_config_post))
        .route("/api/manifest-hash", post(util::manifest_hash_handler))
        .route("/api/register/preview", get(handlers::register::register_preview))
        .route("/api/register/start", post(handlers::register::register_start))
        .route("/api/register/result", post(handlers::register::register_result))
        .route("/api/register/submit", post(util::submit_tx_handler))
        .route("/api/update/preview", get(handlers::update::update_preview))
        .route("/api/update/start", post(handlers::update::update_start))
        .route("/api/update/result", post(handlers::update::update_result))
        .route("/api/update/submit", post(util::submit_tx_handler))
        .route("/api/retire/preview", get(handlers::retire::retire_preview))
        .route("/api/retire/start", post(handlers::retire::retire_start))
        .route("/api/retire/result", post(handlers::retire::retire_result))
        .route("/api/retire/submit", post(util::submit_tx_handler))
        .route("/api/vote/preview", get(handlers::vote::vote_preview))
        .route("/api/vote/start", post(handlers::vote::vote_start))
        .route("/api/vote/result", post(handlers::vote::vote_result))
        .route("/api/vote/submit", post(util::submit_tx_handler))
        .route("/api/witness/start", post(handlers::witness::witness_start))
        .route("/api/witness/result", post(handlers::witness::witness_result))
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
    let koios_base_url = parse_koios_url(&argv).map_err(|e| {
        eprintln!("{e}");
        Box::<dyn std::error::Error>::from("invalid arguments")
    })?;
    let default_filter = if debug_mode { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .init();
    if !listen_addr.ip().is_loopback() {
        tracing::warn!(
            addr = %listen_addr,
            "SECURITY: binding to a non-loopback address — the online tool is reachable beyond \
             localhost; this exposes Koios access and transaction building/submission. \
             Strongly discouraged."
        );
    }

    let cfg_path = config::config_path();
    let initial_config = config::load(&cfg_path);

    let mut http_builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30));
    if let Some(api_key) = initial_config
        .koios_api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        match reqwest::header::HeaderValue::from_str(&format!("Bearer {api_key}")) {
            Ok(value) => {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(reqwest::header::AUTHORIZATION, value);
                http_builder = http_builder.default_headers(headers);
                info!("Koios API key configured");
            }
            Err(e) => tracing::warn!(error = %e, "Koios API key contains invalid characters; ignoring"),
        }
    }
    let http = http_builder.build()?;

    info!(
        path = %cfg_path.display(),
        configured = config::is_configured(&initial_config),
        "loaded online config"
    );

    let state = Arc::new(AppState {
        http,
        config: RwLock::new(initial_config),
        config_path: cfg_path,
        koios_base_url,
    });
    let app = build_app(state, listen_addr);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let bound = listener.local_addr()?;
    println!("DRep online tool listening on http://{bound}");
    info!(addr = %bound, version = VERSION, "drep-tools-online listening (frontend embedded)");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            http: reqwest::Client::new(),
            config: RwLock::new(config::OnlineConfig::default()),
            config_path: std::path::PathBuf::from("/nonexistent/online.json"),
            koios_base_url: "http://127.0.0.1:1".to_string(),
        })
    }

    fn args(parts: &[&str]) -> Vec<String> {
        std::iter::once("drep-tools-online")
            .chain(parts.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn loopback_addresses_are_accepted() {
        assert!(parse_listen_addr(&args(&["--listen", "127.0.0.1:9300"])).is_ok());
        assert!(parse_listen_addr(&args(&["--listen", "127.0.0.5:9300"])).is_ok());
        assert!(parse_listen_addr(&args(&["--listen", "[::1]:9300"])).is_ok());
    }

    #[test]
    fn non_loopback_is_rejected_without_override() {
        assert!(parse_listen_addr(&args(&["--listen", "0.0.0.0:9300"])).is_err());
        assert!(parse_listen_addr(&args(&["--listen", "192.168.1.10:9300"])).is_err());
    }

    #[test]
    fn non_loopback_allowed_only_with_explicit_flag() {
        assert!(parse_listen_addr(&args(&[
            "--listen",
            "192.168.1.10:9300",
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
            "0.0.0.0:9300",
            "--allow-non-loopback"
        ]))
        .is_err());
        assert!(parse_listen_addr(&args(&[
            "--listen",
            "[::]:9300",
            "--allow-non-loopback"
        ]))
        .is_err());
    }

    /// Regression guard for the layer-ordering bug: the frontend fallback must
    /// be wrapped by the response-header layers, so even a served document (or
    /// a 404 from the fallback) carries CSP and framing headers. Exercised
    /// over a real loopback listener with the existing reqwest dependency.
    #[tokio::test]
    async fn frontend_fallback_carries_security_headers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let app = build_app(test_state(), bound);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // no_proxy: a proxy env var must not divert the loopback request.
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let resp = client
            .get(format!("http://{bound}/index.html"))
            .send()
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

    #[test]
    fn koios_url_flag_requires_value() {
        assert!(parse_koios_url(&args(&["--listen", "127.0.0.1:9300", "--koios-url"])).is_err());
        assert_eq!(
            parse_koios_url(&args(&["--koios-url", "http://127.0.0.1:8080/api/v1"])).unwrap(),
            "http://127.0.0.1:8080/api/v1"
        );
        assert_eq!(
            parse_koios_url(&args(&["--koios-url=http://127.0.0.1:8080/api/v1"])).unwrap(),
            "http://127.0.0.1:8080/api/v1"
        );
        assert_eq!(parse_koios_url(&args(&[])).unwrap(), DEFAULT_KOIOS_BASE_URL);
    }
}
