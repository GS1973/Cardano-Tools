//! Guarded fetch of an operator-supplied document URL.
//!
//! The online tools fetch a URL the operator typed (a DRep manifest, a vote
//! rationale) and return the blake2b-256 of the bytes, which the operator
//! then anchors on-chain. Unguarded, that fetch can be aimed at the machine
//! itself, at the local network or at a cloud metadata endpoint; sent
//! through a tool's Koios client it would carry the Koios API key to the
//! document host; and over plain http the document, and with it the hash,
//! can be altered on the way. This crate gives the fetch a client of its
//! own: no default headers, https only, and every connection it opens, the
//! first request and each redirect hop, may only go to a public internet
//! address (`airgap_core::netguard`).
//!
//! One copy for every online tool, so the guard cannot drift between them.
//! It lives beside airgap-core, not in it: the air-gapped signers link
//! airgap-core and must not carry an HTTP client.

use airgap_core::netguard::{host_literal_is_public, is_public_ip};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;
use std::sync::Arc;

/// Redirect hops followed before giving up (reqwest's own default).
const MAX_REDIRECTS: usize = 10;

const NOT_HTTPS: &str = "URL must start with https://";
const NOT_PUBLIC: &str = "URL points at a local or private address, which this tool does not fetch";

/// Why a URL is refused before any request is made. `None` means it may be
/// fetched: an https URL whose host is a name or a public IP literal. Plain
/// http is refused because the result is a hash the operator anchors
/// on-chain: over http anyone on the network path can alter the document,
/// and the hash would then be that of the altered document.
pub fn url_refusal(url: &reqwest::Url) -> Option<&'static str> {
    if url.scheme() != "https" {
        return Some(NOT_HTTPS);
    }
    match url.host_str() {
        None => Some("URL has no host"),
        Some(host) => match host_literal_is_public(host) {
            Some(false) => Some(NOT_PUBLIC),
            _ => None,
        },
    }
}

/// Keep only the public addresses a name resolved to.
fn public_only(addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addrs.filter(|a| is_public_ip(a.ip())).collect()
}

/// DNS resolver that hands the client only public addresses, so a name that
/// resolves to an internal address (directly, or by rebinding between a
/// check and the connection) cannot be connected to.
struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let public = public_only(resolved);
            if public.is_empty() {
                return Err("name resolves to no public address".into());
            }
            Ok(Box::new(public.into_iter()) as Addrs)
        })
    }
}

/// True when the environment routes this process's HTTP through a proxy. A
/// proxy resolves the target name itself, so the resolver above would only
/// ever see (and wrongly filter) the proxy's own address.
fn proxy_in_use() -> bool {
    [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()))
}

/// The client for document fetches. Unlike the Koios client it carries no
/// default headers (so no API key reaches a document host), speaks https
/// only (also across redirects), refuses a redirect to a non-public IP
/// literal, and, when no proxy is in use, resolves names to public
/// addresses only. Behind a proxy the proxy resolves every redirect target
/// itself, out of this client's sight, so there a redirect is not followed
/// at all and the operator sees the redirect status instead.
pub fn client() -> Result<reqwest::Client, reqwest::Error> {
    if proxy_in_use() {
        return client_with(reqwest::redirect::Policy::none(), false);
    }
    let redirects = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        match url_refusal(attempt.url()) {
            Some(why) => attempt.error(why),
            None => attempt.follow(),
        }
    });
    client_with(redirects, true)
}

/// Build the document client with `redirects` and, when `public_dns`, the
/// resolver that hands out public addresses only.
fn client_with(
    redirects: reqwest::redirect::Policy,
    public_dns: bool,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .https_only(true)
        .redirect(redirects);
    if public_dns {
        builder = builder.dns_resolver(Arc::new(PublicOnlyResolver));
    }
    builder.build()
}

/// Parse and vet `raw`, then make sure the name it points at does not
/// resolve to an internal address. The lookup here is the check that still
/// holds behind a proxy; without one the client's resolver enforces the
/// same rule on the connection itself. A name that does not resolve at all
/// is left to the request, which then fails on its own.
pub async fn vet(raw: &str) -> Result<reqwest::Url, &'static str> {
    let url = reqwest::Url::parse(raw).map_err(|_| NOT_HTTPS)?;
    if let Some(why) = url_refusal(&url) {
        return Err(why);
    }
    if let Some(host) = url.host_str() {
        if host_literal_is_public(host).is_none() {
            if let Ok(resolved) = tokio::net::lookup_host((host, 0)).await {
                let all: Vec<SocketAddr> = resolved.collect();
                if !all.is_empty() && public_only(all.iter().copied()).len() != all.len() {
                    return Err(NOT_PUBLIC);
                }
            }
        }
    }
    Ok(url)
}

/// The most a governance document may weigh: 1 MiB.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Why a document could not be hashed.
#[derive(Debug)]
pub enum DocumentError {
    /// The URL is not one the guard lets through, with the reason.
    Refused(&'static str),
    /// The request could not be sent or was not answered.
    Fetch(reqwest::Error),
    /// The server answered with a status other than success.
    Status(u16),
    /// The document is larger than [`MAX_DOCUMENT_BYTES`].
    TooLarge,
    /// The body could not be read.
    Read(reqwest::Error),
}

impl DocumentError {
    /// The message for the operator, naming the document as `what` (for
    /// example "manifest" or "rationale").
    pub fn describe(&self, what: &str) -> String {
        match self {
            DocumentError::Refused(why) => (*why).to_string(),
            DocumentError::Fetch(_) => format!("could not fetch the {what} URL"),
            DocumentError::Status(code) => format!("{what} URL returned HTTP {code}"),
            DocumentError::TooLarge => format!("{what} is larger than 1 MiB"),
            DocumentError::Read(_) => format!("could not read the {what} body"),
        }
    }
}

/// Fetch the document at `raw_url` through `client` (built by [`client`])
/// and return the blake2b-256 of its raw bytes, the CIP-100 / CIP-119 anchor
/// hash, with the byte count. Hashes the document content, never the URL
/// string. The URL is vetted first ([`vet`]). The Content-Length header is
/// set by the server (and absent on a chunked transfer), so the read itself
/// stops one chunk past [`MAX_DOCUMENT_BYTES`].
pub async fn document_hash(
    client: &reqwest::Client,
    raw_url: &str,
) -> Result<([u8; 32], usize), DocumentError> {
    let url = vet(raw_url.trim()).await.map_err(DocumentError::Refused)?;
    let mut resp = client.get(url).send().await.map_err(DocumentError::Fetch)?;
    if !resp.status().is_success() {
        return Err(DocumentError::Status(resp.status().as_u16()));
    }
    if resp
        .content_length()
        .is_some_and(|len| len as usize > MAX_DOCUMENT_BYTES)
    {
        return Err(DocumentError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(DocumentError::Read)? {
        if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Err(DocumentError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((airgap_core::validate::blake2b256(&bytes), bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_errors_read_as_before_for_each_document() {
        assert_eq!(
            DocumentError::Status(404).describe("manifest"),
            "manifest URL returned HTTP 404"
        );
        assert_eq!(
            DocumentError::TooLarge.describe("rationale"),
            "rationale is larger than 1 MiB"
        );
        assert_eq!(
            DocumentError::Refused(NOT_HTTPS).describe("manifest"),
            NOT_HTTPS
        );
    }

    #[tokio::test]
    async fn a_refused_url_is_never_fetched() {
        let c = client().unwrap();
        assert!(matches!(
            document_hash(&c, "http://example.org/doc.jsonld").await,
            Err(DocumentError::Refused(_))
        ));
        assert!(matches!(
            document_hash(&c, "https://127.0.0.1/doc.jsonld").await,
            Err(DocumentError::Refused(_))
        ));
    }

    fn refusal(u: &str) -> Option<&'static str> {
        url_refusal(&reqwest::Url::parse(u).unwrap())
    }

    #[test]
    fn public_https_urls_pass() {
        assert_eq!(refusal("https://example.org/rationale.jsonld"), None);
        assert_eq!(refusal("https://1.1.1.1/x"), None);
        assert_eq!(refusal("https://[2606:4700:4700::1111]/x"), None);
    }

    #[test]
    fn plain_http_and_other_schemes_are_refused() {
        // Over http the document, and with it the anchored hash, can be
        // altered on the network path.
        for u in [
            "http://example.org/rationale.jsonld",
            "http://1.1.1.1/x",
            "file:///etc/passwd",
            "ftp://example.org/x",
            "gopher://example.org/x",
        ] {
            assert_eq!(refusal(u), Some(NOT_HTTPS), "{u}");
        }
    }

    #[test]
    fn internal_targets_are_refused() {
        // All https, so the refusal can only be about the address.
        for u in [
            "https://127.0.0.1:8200/api/config",
            "https://127.1/",
            "https://2130706433/",
            "https://0x7f.0.0.1/",
            "https://[::1]:8400/",
            "https://[::ffff:127.0.0.1]/",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.5:5432/",
            "https://192.168.1.1/",
            "https://0.0.0.0/",
        ] {
            assert_eq!(
                refusal(u),
                Some(NOT_PUBLIC),
                "{u} must be refused for its address"
            );
        }
    }

    #[test]
    fn resolver_filter_drops_internal_addresses() {
        let addrs: Vec<SocketAddr> = [
            "127.0.0.1:0",
            "93.184.216.34:0",
            "10.0.0.5:0",
            "[::1]:0",
            "[2606:4700:4700::1111]:0",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let kept = public_only(addrs.into_iter());
        assert_eq!(
            kept,
            vec![
                "93.184.216.34:0".parse::<SocketAddr>().unwrap(),
                "[2606:4700:4700::1111]:0".parse().unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn vet_refuses_a_name_that_resolves_to_loopback() {
        assert_eq!(vet("https://localhost:1/x").await.unwrap_err(), NOT_PUBLIC);
        assert_eq!(vet("https://127.0.0.1:1/x").await.unwrap_err(), NOT_PUBLIC);
        assert_eq!(vet("http://example.org/x").await.unwrap_err(), NOT_HTTPS);
        assert_eq!(vet("not a url").await.unwrap_err(), NOT_HTTPS);
    }

    /// End to end against a real loopback listener: the guarded client must
    /// not connect to it, by literal or by name, while a plain client can.
    #[tokio::test]
    async fn guarded_client_does_not_reach_a_loopback_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });
        // Control: the listener is reachable without the guard.
        let plain = reqwest::Client::builder().no_proxy().build().unwrap();
        let r = plain
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.text().await.unwrap(), "ok");
        // By name: the guarded resolver hands back no address for localhost.
        let guarded = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(Arc::new(PublicOnlyResolver))
            .build()
            .unwrap();
        assert!(guarded
            .get(format!("http://localhost:{port}/"))
            .send()
            .await
            .is_err());
        // By literal: refused before any request.
        assert_eq!(
            vet(&format!("https://127.0.0.1:{port}/"))
                .await
                .unwrap_err(),
            NOT_PUBLIC
        );
        // The production client speaks https only: a plain-http URL is
        // refused by the client itself, before any connection.
        let production = client().unwrap();
        assert!(production.get("http://example.org/").send().await.is_err());
    }
}
