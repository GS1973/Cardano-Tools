//! Wallet Tools: online tool.
//!
//! Internet-connected web backend. Talks to Koios for chain data, builds
//! unsigned wallet transactions (payment, pool delegation, DRep
//! delegation), hands them to the air-gapped signer via QR, and submits
//! signed transactions back to Koios. Holds no keys.
//!
//! Listens on a loopback interface only, never a public address. The
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
const USAGE: &str = "wallet-tools-online --listen 127.0.0.1:PORT [--koios-url URL] [--debug]";
const DEFAULT_KOIOS_BASE_URL: &str = "https://api.koios.rest/api/v1";

/// Parse `--listen ADDR:PORT` from the process arguments.
///
/// The parsed address is enforced to be loopback (`127.0.0.0/8` or `::1`):
/// this tool must never listen on a public interface. A non-loopback
/// address is rejected unless `--allow-non-loopback` is explicitly passed,
/// which is strongly discouraged: the online tool holds Koios access and
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
             or pass `--allow-non-loopback` to override (strongly discouraged: it exposes Koios \
             access and transaction building/submission to the network).\nUsage: {USAGE}"
        ));
    }
    Ok(addr)
}

fn parse_koios_url(args: &[String]) -> Result<String, String> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        let val = if arg == "--koios-url" {
            iter.next()
                .ok_or_else(|| format!("--koios-url requires a URL value\nUsage: {USAGE}"))?
                .clone()
        } else if let Some(val) = arg.strip_prefix("--koios-url=") {
            val.to_string()
        } else {
            continue;
        };
        check_koios_url(&val)?;
        return Ok(val);
    }
    Ok(DEFAULT_KOIOS_BASE_URL.to_string())
}

/// The Koios URL must be https, so the Koios API key and the chain data
/// never cross the network in the clear. Plain http is accepted only for a
/// Koios on this machine (localhost, 127.0.0.1 or ::1).
fn check_koios_url(val: &str) -> Result<(), String> {
    if val.is_empty() {
        return Err(format!("--koios-url requires a URL value\nUsage: {USAGE}"));
    }
    let url = reqwest::Url::parse(val)
        .map_err(|e| format!("--koios-url `{val}` is not a valid URL: {e}\nUsage: {USAGE}"))?;
    let host = url.host_str().unwrap_or("");
    let on_this_machine = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(()),
        "http" if on_this_machine => Ok(()),
        _ => Err(format!(
            "--koios-url `{val}` must be an https URL. Plain http is accepted only for a \
             Koios on this machine (localhost, 127.0.0.1 or ::1).\nUsage: {USAGE}"
        )),
    }
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
    Json(Status {
        name: "wallet-tools-online",
        version: VERSION,
    })
}

/// Build the application router.
///
/// The frontend fallback is registered BEFORE the middleware stack so that
/// every served response, including the SPA fallback document and any 404,
/// passes through the CSRF guard and the CSP / X-Frame-Options /
/// X-Content-Type-Options / Referrer-Policy response-header layers.
/// Registered after `.layer(...)` it would leave the served HTML/JS/CSS
/// with none of these headers.
fn build_app(state: Arc<AppState>, listen_addr: SocketAddr) -> Router {
    let csrf_cfg = shared::csrf::CsrfConfig::for_listener(listen_addr);
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route(
            "/api/wallet-config",
            get(handlers::setup::online_config_get).post(handlers::setup::online_config_post),
        )
        .route(
            "/api/address-book",
            post(handlers::setup::address_book_post),
        )
        .route(
            "/api/payment/preview",
            get(handlers::payment::payment_preview),
        )
        .route("/api/payment/start", post(handlers::payment::payment_start))
        .route(
            "/api/payment/result",
            post(handlers::payment::payment_result),
        )
        .route("/api/payment/submit", post(util::submit_tx_handler))
        .route(
            "/api/pool-delegate/preview",
            get(handlers::pool_delegate::pool_delegate_preview),
        )
        .route(
            "/api/pool-delegate/start",
            post(handlers::pool_delegate::pool_delegate_start),
        )
        .route(
            "/api/pool-delegate/result",
            post(handlers::pool_delegate::pool_delegate_result),
        )
        .route("/api/pool-delegate/submit", post(util::submit_tx_handler))
        .route(
            "/api/drep-delegate/preview",
            get(handlers::drep_delegate::drep_delegate_preview),
        )
        .route(
            "/api/drep-delegate/start",
            post(handlers::drep_delegate::drep_delegate_start),
        )
        .route(
            "/api/drep-delegate/result",
            post(handlers::drep_delegate::drep_delegate_result),
        )
        .route("/api/drep-delegate/submit", post(util::submit_tx_handler))
        .route(
            "/api/withdraw/preview",
            get(handlers::withdraw::withdraw_preview),
        )
        .route(
            "/api/withdraw/start",
            post(handlers::withdraw::withdraw_start),
        )
        .route(
            "/api/withdraw/result",
            post(handlers::withdraw::withdraw_result),
        )
        .route("/api/withdraw/submit", post(util::submit_tx_handler))
        .route(
            "/api/new-address/receive",
            post(handlers::new_address::new_address_receive),
        )
        .route("/api/pairing/info", get(handlers::pairing::pairing_info))
        .route(
            "/api/pairing/preview",
            post(handlers::pairing::pairing_preview),
        )
        .route(
            "/api/pairing/set-peer",
            post(handlers::pairing::pairing_set_peer),
        )
        .route("/api/pairing/clear", post(handlers::pairing::pairing_clear))
        .fallback(handlers::frontend::frontend_handler)
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(axum::middleware::from_fn_with_state(
            csrf_cfg,
            shared::csrf::csrf_guard,
        ))
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
            "SECURITY: binding to a non-loopback address, the online tool is reachable beyond \
             localhost. This exposes Koios access and transaction building/submission. \
             Strongly discouraged."
        );
    }

    let cfg_path = config::config_path();
    // Fail closed: a corrupt or unreadable config must not be silently
    // replaced with defaults: the next save() would overwrite the
    // operator's address book and pairing keys.
    let mut initial_config = config::load(&cfg_path).map_err(|e| {
        eprintln!("{e}");
        Box::<dyn std::error::Error>::from("failed to load config")
    })?;
    // Create the X25519 channel keypair now, so it exists before any request
    // arrives and GET /api/pairing/info only ever reads it. A failure here is
    // not fatal: the pairing handlers keep their own fallback.
    if let Err(e) = config::ensure_own_crypto_skey(&cfg_path, &mut initial_config) {
        tracing::warn!(error = %e, "could not create the channel keypair at startup. Pairing will create it on first use");
    }

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
            Err(e) => {
                tracing::warn!(error = %e, "Koios API key contains invalid characters. Ignoring")
            }
        }
    }
    let http = http_builder.build()?;

    info!(
        path = %cfg_path.display(),
        configured = config::is_configured(&initial_config),
        koios = %koios_base_url,
        "loaded online config"
    );

    let state = Arc::new(AppState {
        http,
        config: RwLock::new(initial_config),
        config_path: cfg_path,
        koios_base_url,
    });
    let app = build_app(state, listen_addr);

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| {
            eprintln!("{}", shared::listen::listen_error(listen_addr, &e));
            Box::<dyn std::error::Error>::from("cannot listen")
        })?;
    let bound = listener.local_addr()?;
    println!("Wallet online tool listening on http://{bound}");
    info!(addr = %bound, version = VERSION, "wallet-tools-online listening (frontend embedded)");
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
        std::iter::once("wallet-tools-online")
            .chain(parts.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn loopback_addresses_are_accepted() {
        assert!(parse_listen_addr(&args(&["--listen", "127.0.0.1:8400"])).is_ok());
        assert!(parse_listen_addr(&args(&["--listen", "127.0.0.5:8400"])).is_ok());
        assert!(parse_listen_addr(&args(&["--listen", "[::1]:8400"])).is_ok());
    }

    #[test]
    fn non_loopback_is_rejected_without_override() {
        assert!(parse_listen_addr(&args(&["--listen", "0.0.0.0:8400"])).is_err());
        assert!(parse_listen_addr(&args(&["--listen", "192.168.1.10:8400"])).is_err());
    }

    #[test]
    fn non_loopback_allowed_only_with_explicit_flag() {
        assert!(parse_listen_addr(&args(&[
            "--listen",
            "192.168.1.10:8400",
            "--allow-non-loopback"
        ]))
        .is_ok());
    }

    /// A wildcard bind can never serve a request: no client sends
    /// `0.0.0.0` / `[::]` as its Host header, so the derived CSRF
    /// allow-list would reject everything with 403. Rejected up front,
    /// even with the non-loopback override.
    #[test]
    fn wildcard_bind_is_rejected_even_with_override() {
        assert!(
            parse_listen_addr(&args(&["--listen", "0.0.0.0:8400", "--allow-non-loopback"]))
                .is_err()
        );
        assert!(
            parse_listen_addr(&args(&["--listen", "[::]:8400", "--allow-non-loopback"])).is_err()
        );
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
            resp.headers()
                .get("x-frame-options")
                .unwrap()
                .to_str()
                .unwrap(),
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
    fn koios_url_must_be_https_unless_on_this_machine() {
        let parse = |u: &str| parse_koios_url(&args(&["--koios-url", u]));
        assert_eq!(
            parse("https://api.koios.rest/api/v1").unwrap(),
            "https://api.koios.rest/api/v1"
        );
        for local in [
            "http://127.0.0.1:8080/api/v1",
            "http://localhost:8080/api/v1",
            "http://[::1]:8080/api/v1",
        ] {
            assert_eq!(parse(local).unwrap(), local);
            assert_eq!(
                parse_koios_url(&args(&[&format!("--koios-url={local}")])).unwrap(),
                local
            );
        }
        for refused in [
            "http://api.koios.rest/api/v1",
            "http://192.0.2.10:8080/api/v1",
            "http://localhost.example.org/api/v1",
            "ftp://127.0.0.1/api/v1",
            "api.koios.rest/api/v1",
            "",
        ] {
            assert!(parse(refused).is_err(), "{refused}");
        }
        assert!(parse_koios_url(&args(&["--koios-url="])).is_err());
        assert!(parse_koios_url(&args(&["--listen", "127.0.0.1:9300", "--koios-url"])).is_err());
        assert_eq!(parse_koios_url(&args(&[])).unwrap(), DEFAULT_KOIOS_BASE_URL);
    }
}
