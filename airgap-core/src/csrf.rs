//! CSRF + DNS-rebinding guard middleware shared by both binaries.
//!
//! Both servers bind to loopback only and embed their own frontend, so
//! the guard's only job is to reject (a) cross-origin POSTs from a
//! malicious tab the SPO might open, and (b) requests carrying a
//! mis-pointed Host header (DNS-rebinding). The allowed origin/host
//! values are computed at startup from the listener address chosen via
//! `--listen` so the same code serves any port and any loopback form.

use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

/// Allowed Origin and Host header values for a given listener address.
/// Holds both `127.0.0.1` and `localhost` forms so the SPO can reach
/// the binary by either name in their browser, plus the actually-bound
/// address form: the binaries' `parse_listen_addr` accepts any loopback
/// address (`[::1]:PORT`, `127.0.0.5:PORT`, ...), and the browser sends
/// exactly that form in Host/Origin, so omitting it would make the
/// guard reject every request on such a listener.
#[derive(Clone, Debug)]
pub struct CsrfConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_hosts: Vec<String>,
}

impl CsrfConfig {
    pub fn for_listener(addr: SocketAddr) -> Self {
        let port = addr.port();
        let mut allowed_hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")];
        // `SocketAddr` displays as `127.0.0.1:8200` / `[::1]:8200`: the
        // same forms the browser puts in the Host header.
        let bound = addr.to_string();
        if !allowed_hosts.contains(&bound) {
            allowed_hosts.push(bound);
        }
        let allowed_origins = allowed_hosts
            .iter()
            .map(|h| format!("http://{h}"))
            .collect();
        Self {
            allowed_origins,
            allowed_hosts,
        }
    }
}

/// CSRF + DNS-rebinding guard. Use as an Axum middleware via
/// `from_fn_with_state(cfg, csrf_guard)`. Rejects requests whose Host
/// header is unrecognised (defeats DNS-rebinding) and rejects state-
/// changing methods whose Origin header is unrecognised (defeats
/// cross-origin attacks from a malicious tab).
pub async fn csrf_guard(
    State(cfg): State<CsrfConfig>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| cfg.allowed_hosts.iter().any(|a| a == h))
        .unwrap_or(false);
    if !host_ok {
        return Err(StatusCode::FORBIDDEN);
    }
    // Origin policy: if header is present it MUST match allowed_origins
    // (regardless of method: a malicious tab can send GET requests too).
    // If absent, only allow GET/HEAD: those are the only methods a
    // top-level navigation produces, and a top-level navigation does not
    // carry Origin. POST/PUT/DELETE without an Origin header is either a
    // misconfigured client or a forgery and is rejected.
    match req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        Some(o) => {
            if !cfg.allowed_origins.iter().any(|a| a == o) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        None => {
            if !matches!(req.method(), &Method::GET | &Method::HEAD) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::routing::any;
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn for_listener_includes_both_loopback_forms() {
        let cfg = CsrfConfig::for_listener("127.0.0.1:8200".parse().unwrap());
        assert!(cfg
            .allowed_origins
            .contains(&"http://127.0.0.1:8200".to_string()));
        assert!(cfg
            .allowed_origins
            .contains(&"http://localhost:8200".to_string()));
        assert!(cfg.allowed_hosts.contains(&"127.0.0.1:8200".to_string()));
        assert!(cfg.allowed_hosts.contains(&"localhost:8200".to_string()));
    }

    #[test]
    fn for_listener_uses_chosen_port() {
        let cfg = CsrfConfig::for_listener("127.0.0.1:9999".parse().unwrap());
        assert!(cfg.allowed_origins.iter().all(|o| o.ends_with(":9999")));
        assert!(cfg.allowed_hosts.iter().all(|h| h.ends_with(":9999")));
    }

    #[test]
    fn for_listener_includes_bound_ipv6_form() {
        let cfg = CsrfConfig::for_listener("[::1]:8200".parse().unwrap());
        assert!(cfg.allowed_hosts.contains(&"[::1]:8200".to_string()));
        assert!(cfg
            .allowed_origins
            .contains(&"http://[::1]:8200".to_string()));
        // The canonical forms stay available regardless of the bound IP.
        assert!(cfg.allowed_hosts.contains(&"127.0.0.1:8200".to_string()));
        assert!(cfg.allowed_hosts.contains(&"localhost:8200".to_string()));
    }

    #[test]
    fn for_listener_includes_bound_nonstandard_loopback_form() {
        let cfg = CsrfConfig::for_listener("127.0.0.5:8200".parse().unwrap());
        assert!(cfg.allowed_hosts.contains(&"127.0.0.5:8200".to_string()));
        assert!(cfg
            .allowed_origins
            .contains(&"http://127.0.0.5:8200".to_string()));
    }

    #[test]
    fn for_listener_does_not_duplicate_canonical_form() {
        let cfg = CsrfConfig::for_listener("127.0.0.1:8200".parse().unwrap());
        assert_eq!(cfg.allowed_hosts.len(), 2);
        assert_eq!(cfg.allowed_origins.len(), 2);
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn router_for(addr: &str) -> Router {
        Router::new()
            .route("/api/anything", any(ok_handler))
            .layer(middleware::from_fn_with_state(
                CsrfConfig::for_listener(addr.parse().unwrap()),
                csrf_guard,
            ))
    }

    fn router() -> Router {
        router_for("127.0.0.1:8200")
    }

    fn req(method: Method, host: &str, origin: Option<&str>) -> HttpRequest<Body> {
        let mut b = HttpRequest::builder()
            .method(method)
            .uri("/api/anything")
            .header(header::HOST, host);
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn rejects_get_with_wrong_origin() {
        let res = router()
            .oneshot(req(
                Method::GET,
                "127.0.0.1:8200",
                Some("http://evil.example"),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn allows_get_with_no_origin() {
        let res = router()
            .oneshot(req(Method::GET, "127.0.0.1:8200", None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_post_with_no_origin() {
        let res = router()
            .oneshot(req(Method::POST, "127.0.0.1:8200", None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn allows_post_with_matching_origin() {
        let res = router()
            .oneshot(req(
                Method::POST,
                "127.0.0.1:8200",
                Some("http://127.0.0.1:8200"),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_post_with_wrong_origin() {
        let res = router()
            .oneshot(req(
                Method::POST,
                "127.0.0.1:8200",
                Some("http://evil.example"),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_unknown_host() {
        let res = router()
            .oneshot(req(Method::GET, "evil.example", None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ipv6_listener_allows_get_with_bound_host() {
        let res = router_for("[::1]:8200")
            .oneshot(req(Method::GET, "[::1]:8200", None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv6_listener_allows_post_with_bound_origin() {
        let res = router_for("[::1]:8200")
            .oneshot(req(Method::POST, "[::1]:8200", Some("http://[::1]:8200")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv4_listener_still_rejects_unbound_ipv6_host() {
        let res = router()
            .oneshot(req(Method::GET, "[::1]:8200", None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }
}
