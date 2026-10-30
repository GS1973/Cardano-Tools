//! SPO Tools: offline signer.
//!
//! Air-gapped signing app. Runs a local web UI on http://127.0.0.1:8201
//! that accepts UR-encoded fragments scanned from QR codes on the online
//! machine, performs the requested signing operation locally with the
//! configured cardano-cli signing keys, and emits UR-encoded fragments
//! back as QR codes for the online machine to scan in.

mod airgap;
mod config;
mod handlers;
mod sign_core;
mod state;
mod validate;

use axum::http::{header, HeaderName, HeaderValue};
use std::process::ExitCode;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{error, info};

/// CSP for an air-gapped single-binary webapp. Same shape as online-tool's:
/// strictly same-origin for everything, inline `<style>` allowed for Vuetify
/// runtime CSS, `data:` for QR images, and no framing.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

const USAGE: &str = "spo-tools-signer --listen 127.0.0.1:PORT [--debug]";

/// Parse `--listen ADDR:PORT` from the process arguments. Required: there
/// is no default port: gives the SPO an explicit choice and lets two
/// instances coexist on the same host without collision.
///
/// The parsed address is enforced to be loopback (`127.0.0.0/8` or `::1`):
/// the signer must never listen on a public interface. A non-loopback
/// address is rejected unless `--allow-non-loopback` is explicitly passed.
fn parse_listen_addr(args: &[String]) -> Result<std::net::SocketAddr, String> {
    let allow_non_loopback = args.iter().any(|a| a == "--allow-non-loopback");
    let mut iter = args.iter().skip(1);
    let mut addr: Option<std::net::SocketAddr> = None;
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
    if !addr.ip().is_loopback() && !allow_non_loopback {
        return Err(format!(
            "refusing to bind non-loopback address `{addr}`: the signer is designed to listen on \
             a loopback address (127.0.0.1) only. Re-run with `--listen 127.0.0.1:PORT`, or pass \
             `--allow-non-loopback` to override (strongly discouraged).\nUsage: {USAGE}"
        ));
    }
    Ok(addr)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let debug_mode = argv.iter().any(|a| a == "--debug");
    let listen_addr = match parse_listen_addr(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let default_filter = if debug_mode { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .with_writer(std::io::stderr)
        .init();
    if debug_mode {
        info!("debug mode active: verbose logging enabled");
    }
    if !listen_addr.ip().is_loopback() {
        tracing::warn!(
            addr = %listen_addr,
            "SECURITY: binding the signer to a non-loopback address, strongly discouraged on an air-gapped host"
        );
    }

    match run_serve(listen_addr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "serve failed");
            ExitCode::FAILURE
        }
    }
}

// ============================================================
// run_serve, Axum on 127.0.0.1:<port chosen at startup>
// ============================================================

#[derive(rust_embed::RustEmbed)]
#[folder = "frontend/dist/"]
struct SignerFrontend;

async fn signer_frontend_handler(uri: axum::http::Uri) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::{header, StatusCode};

    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = SignerFrontend::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return axum::response::Response::builder()
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(Body::from(file.data.into_owned()))
            .unwrap();
    }

    // SPA fallback: any unknown route → index.html (Vue router takes over).
    if let Some(file) = SignerFrontend::get("index.html") {
        return axum::response::Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::from(file.data.into_owned()))
            .unwrap();
    }

    axum::response::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not found"))
        .unwrap()
}

fn run_serve(listen_addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    use axum::routing::{get, post};
    use axum::Router;

    let csrf_cfg = shared::csrf::CsrfConfig::for_listener(listen_addr);
    let app = Router::new()
        .route("/api/health", get(handlers::diagnostics::signer_health))
        .route("/api/status", get(handlers::diagnostics::signer_status))
        .route(
            "/api/signer-config",
            get(handlers::setup::signer_config_get).post(handlers::setup::signer_config_post),
        )
        .route("/api/test-load", post(handlers::setup::signer_test_load))
        .route("/api/list-dir", get(handlers::list_dir::list_dir))
        .route("/api/sign/receive", post(handlers::sign::sign_receive))
        .route("/api/sign/execute", post(handlers::sign::sign_execute))
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
        .fallback(signer_frontend_handler)
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576))
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
        ));

    // Create the X25519 channel keypair now, so GET /api/pairing/info only
    // ever reads it. Not fatal: the pairing handlers keep their own fallback,
    // and a corrupt config is reported by every handler that loads it.
    if let Ok(mut cfg) = config::load_or_err() {
        if let Err(e) = config::ensure_own_crypto_skey(&config::config_path(), &mut cfg) {
            tracing::warn!(error = %e, "could not create the channel keypair at startup. Pairing will create it on first use");
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        airgap::spawn_air_gap_monitor();
        let listener = tokio::net::TcpListener::bind(listen_addr)
            .await
            .map_err(|e| shared::listen::listen_error(listen_addr, &e))?;
        let bound = listener.local_addr()?;
        println!("Signer listening on http://{bound}");
        info!(
            addr = %bound,
            config_path = %config::config_path().display(),
            "signer serving (frontend embedded)"
        );
        axum::serve(listener, app).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        std::iter::once("spo-tools-signer")
            .chain(parts.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn loopback_enforced_unless_overridden() {
        assert!(parse_listen_addr(&args(&["--listen", "127.0.0.1:8201"])).is_ok());
        assert!(parse_listen_addr(&args(&["--listen", "[::1]:8201"])).is_ok());
        assert!(parse_listen_addr(&args(&["--listen", "0.0.0.0:8201"])).is_err());
        assert!(
            parse_listen_addr(&args(&["--listen", "0.0.0.0:8201", "--allow-non-loopback"])).is_ok()
        );
    }
}
