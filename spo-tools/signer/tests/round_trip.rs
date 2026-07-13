//! Cross-binary integration test: spawns the online tool and the signer
//! as subprocesses with isolated `HOME` directories, points them at a
//! Koios stub running in the test process, and exercises the wire format
//! end-to-end.
//!
//! What this catches that unit tests do not:
//! - online↔signer UR encoding/decoding drift (different sides may evolve
//!   the wire types out of lockstep).
//! - ts-rs / serde tag drift in the Rust↔Rust crossing.
//! - HTTP routing + CSRF middleware + ErrorEnvelope wire format on real
//!   requests.
//!
//! What this does NOT do: produce a chain-valid transaction. Real Cardano skey files
//! are not generated, so signing-execution paths that
//! need keys are exercised through their failure mode (NotConfigured)
//! rather than a happy submit. End-to-end signing with real keys is
//! covered by manual browser tests on a configured signer.
//!
//! Run with: `cargo test -p signer --test round_trip`. Requires both
//! binaries to be built first: `cargo build --bin spo-tools-online
//! --bin spo-tools-signer`.

use axum::{routing::{get, post}, Json, Router};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_POLL: Duration = Duration::from_millis(50);

/// Path to the workspace's compiled binaries. Cargo sets
/// `CARGO_BIN_EXE_<name>` for the test's own crate (signer); this is lifted
/// to the parent target dir to find sibling binaries (online-tool).
fn target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_spo-tools-signer"))
        .parent()
        .expect("CARGO_BIN_EXE has parent")
        .to_path_buf()
}

/// Bind a fresh TCP listener at port 0 (kernel picks), capture the port,
/// drop the listener. Small TOCTOU race window before the spawned binary
/// rebinds, in practice fine for tests.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
}

/// Block until the online tool's `/health` endpoint returns its JSON body,
/// or the timeout elapses. Asserts the body, not just 2xx: with an embedded
/// frontend the SPA fallback answers 200 index.html for any unknown path,
/// which would pass a status-only gate without proving the API layer is
/// routed.
async fn wait_for_online_health(port: u16) {
    let url = format!("http://127.0.0.1:{port}/health");
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + HEALTH_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if let Ok(r) = client.get(&url).send().await {
            if r.status().is_success() {
                let ok = r
                    .json::<Value>()
                    .await
                    .ok()
                    .and_then(|v| v.get("ok").and_then(Value::as_bool));
                if ok == Some(true) {
                    return;
                }
            }
        }
        tokio::time::sleep(HEALTH_POLL).await;
    }
    panic!("online tool on port {port} did not become healthy within {HEALTH_TIMEOUT:?}");
}

/// Same gate for the signer, which registers `/api/health` (it serves no
/// `/health` route — polling that would only ever hit the SPA fallback).
async fn wait_for_signer_health(port: u16) {
    let url = format!("http://127.0.0.1:{port}/api/health");
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + HEALTH_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if let Ok(r) = client.get(&url).send().await {
            if r.status().is_success() && r.text().await.map(|t| t == "ok").unwrap_or(false) {
                return;
            }
        }
        tokio::time::sleep(HEALTH_POLL).await;
    }
    panic!("signer on port {port} did not become healthy within {HEALTH_TIMEOUT:?}");
}

/// Owns a child process and SIGKILLs it on Drop so a panicking test never
/// leaves orphaned binaries.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Build a minimal Koios stub that returns canned responses for every
/// endpoint the online tool calls during startup + handler dispatch.
/// Hard-coded values are a coherent mainnet-shaped snapshot frozen in
/// time; nothing on chain is read.
fn koios_stub_router() -> Router {
    Router::new()
        .route("/genesis", get(|| async {
            Json(json!([{
                "networkmagic": "764824073",
                "networkid": "Mainnet",
                "epoch_no": "555",
                "epochlength": "432000",
                "slotlength": "1",
                "maxblocksize": "90112",
                "maxtxsize": "16384",
                "systemstart": "1506203091",
                "activeslotcoeff": "0.05",
                "slotsperkesperiod": "129600",
                "maxkesrevolutions": "62",
                "securityparam": "2160",
                "updatequorum": "5",
                "alonzogenesis": "{}"
            }]))
        }))
        .route("/tip", get(|| async {
            Json(json!([{
                "abs_slot": 152_000_000_u64,
                "epoch_no": 555_u64,
                "epoch_slot": 100_000_u64,
                "block_no": 11_000_000_u64,
                "block_time": 1_700_000_000_u64,
                "hash": "00".repeat(32),
            }]))
        }))
        .route("/pool_info", post(|Json(_b): Json<Value>| async {
            Json(json!([{
                "pool_id_bech32": "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d",
                "pool_id_hex": "00".repeat(28),
                "vrf_key_hash": "00".repeat(32),
                "margin": 0.01,
                "fixed_cost": "340000000",
                "pledge": "100000000000",
                "deposit": "500000000",
                "reward_addr": "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
                "owners": ["stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u"],
                "relays": [],
                "active_epoch_no": 555,
                "active_stake": "1000000000000",
                "live_stake": "1000000000000",
                "live_pledge": "100000000000",
                "live_delegators": 1,
                "live_saturation": 0.1,
                "block_count": 100,
                "pool_status": "registered"
            }]))
        }))
        .route("/pool_updates", post(|Json(_b): Json<Value>| async {
            Json(json!([]))
        }))
        .route("/account_info", post(|Json(_b): Json<Value>| async {
            Json(json!([{
                "stake_address": "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
                "status": "registered",
                "delegated_pool": "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d",
                "total_balance": "0",
                "utxo": "0",
                "rewards_available": "0",
                "withdrawals": "0",
                "reserves": "0",
                "treasury": "0",
            }]))
        }))
        .route("/address_utxos", post(|Json(_b): Json<Value>| async {
            Json(json!([]))
        }))
        .route("/submittx", post(|_body: axum::body::Bytes| async {
            "\"deadbeefcafe1234567890abcdef1234567890abcdef1234567890abcdef1234\""
        }))
}

/// Spawn the Koios stub on a chosen port. Returns the URL the online
/// tool should use as `--koios-url`.
async fn spawn_koios_stub() -> (String, tokio::task::JoinHandle<()>) {
    let port = pick_free_port();
    let app = koios_stub_router();
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind koios stub");
    let url = format!("http://127.0.0.1:{port}");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, h)
}

/// Spawn the online-tool binary with a tempdir HOME so its config writes
/// stay isolated, and an explicit Koios stub URL.
fn spawn_online(home: &TempDir, koios_url: &str) -> (ChildGuard, u16) {
    let port = pick_free_port();
    let bin = target_dir().join("spo-tools-online");
    assert!(
        bin.exists(),
        "online binary missing at {bin:?}; run `cargo build --bin spo-tools-online` first"
    );
    let child = Command::new(&bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--koios-url")
        .arg(koios_url)
        .env("HOME", home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn online-tool");
    (ChildGuard(child), port)
}

/// Spawn the signer binary with a tempdir HOME.
fn spawn_signer(home: &TempDir) -> (ChildGuard, u16) {
    let port = pick_free_port();
    let bin = target_dir().join("spo-tools-signer");
    assert!(
        bin.exists(),
        "signer binary missing at {bin:?}; run `cargo build --bin spo-tools-signer` first"
    );
    let child = Command::new(&bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .env("HOME", home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn signer");
    (ChildGuard(child), port)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn online_returns_not_configured_envelope_before_setup() {
    let (koios_url, _kh) = spawn_koios_stub().await;
    let online_home = TempDir::new().expect("tempdir");
    let (_g, online_port) = spawn_online(&online_home, &koios_url);
    wait_for_online_health(online_port).await;

    let r = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{online_port}/api/pool/current"))
        .send()
        .await
        .expect("GET pool/current");

    assert_eq!(r.status().as_u16(), 412);
    let env: Value = r.json().await.expect("envelope JSON");
    assert_eq!(env.get("code").and_then(Value::as_str), Some("not_configured"));
    assert!(env.get("message").and_then(Value::as_str).is_some());
}

#[tokio::test]
async fn online_returns_not_paired_envelope_after_config_without_pairing() {
    let (koios_url, _kh) = spawn_koios_stub().await;
    let online_home = TempDir::new().expect("tempdir");
    let (_g, online_port) = spawn_online(&online_home, &koios_url);
    wait_for_online_health(online_port).await;

    // Configure pool + addresses but skip pairing.
    let r = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{online_port}/api/online-config"))
        .header("Origin", format!("http://127.0.0.1:{online_port}"))
        .json(&json!({
            "pool_id": "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d",
            "payment_address": "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            "reward_receive_address": "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am"
        }))
        .send()
        .await
        .expect("POST online-config");
    assert!(r.status().is_success(), "config POST status {}", r.status());

    let r = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{online_port}/api/withdraw/start"))
        .header("Origin", format!("http://127.0.0.1:{online_port}"))
        .json(&json!({ "pin": "1234" }))
        .send()
        .await
        .expect("POST withdraw/start");

    assert_eq!(r.status().as_u16(), 428);
    let env: Value = r.json().await.expect("envelope JSON");
    assert_eq!(env.get("code").and_then(Value::as_str), Some("not_paired"));
}

#[tokio::test]
async fn online_returns_invalid_input_envelope_for_empty_pool_id() {
    let (koios_url, _kh) = spawn_koios_stub().await;
    let online_home = TempDir::new().expect("tempdir");
    let (_g, online_port) = spawn_online(&online_home, &koios_url);
    wait_for_online_health(online_port).await;

    let r = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{online_port}/api/online-config"))
        .header("Origin", format!("http://127.0.0.1:{online_port}"))
        .json(&json!({
            "pool_id": "",
            "payment_address": "",
            "reward_receive_address": ""
        }))
        .send()
        .await
        .expect("POST online-config");

    assert_eq!(r.status().as_u16(), 400);
    let env: Value = r.json().await.expect("envelope JSON");
    assert_eq!(env.get("code").and_then(Value::as_str), Some("invalid_input"));
}

#[tokio::test]
async fn pairing_round_trip_persists_peer_pubkey_on_both_sides() {
    let (koios_url, _kh) = spawn_koios_stub().await;
    let online_home = TempDir::new().expect("tempdir");
    let signer_home = TempDir::new().expect("tempdir");
    let (_og, online_port) = spawn_online(&online_home, &koios_url);
    let (_sg, signer_port) = spawn_signer(&signer_home);
    wait_for_online_health(online_port).await;
    wait_for_signer_health(signer_port).await;

    let client = reqwest::Client::new();

    // Step 1: online → /api/pairing/info returns its own pubkey + UR fragments.
    let r = client
        .get(format!("http://127.0.0.1:{online_port}/api/pairing/info"))
        .send()
        .await
        .expect("GET online pairing/info");
    assert!(r.status().is_success());
    let online_info: Value = r.json().await.expect("online pairing/info JSON");
    let online_fragments = online_info
        .get("own_pubkey_ur")
        .and_then(Value::as_array)
        .expect("own_pubkey_ur in online info")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();

    // Step 2: signer → /api/pairing/info returns its own pubkey + UR fragments.
    let r = client
        .get(format!("http://127.0.0.1:{signer_port}/api/pairing/info"))
        .send()
        .await
        .expect("GET signer pairing/info");
    assert!(r.status().is_success());
    let signer_info: Value = r.json().await.expect("signer pairing/info JSON");
    let signer_fragments = signer_info
        .get("own_pubkey_ur")
        .and_then(Value::as_array)
        .expect("own_pubkey_ur in signer info")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();

    // Step 3: feed signer's UR fragments into online's preview, capture fingerprint.
    let r = client
        .post(format!("http://127.0.0.1:{online_port}/api/pairing/preview"))
        .header("Origin", format!("http://127.0.0.1:{online_port}"))
        .json(&json!({ "ur_fragments": signer_fragments }))
        .send()
        .await
        .expect("POST online pairing/preview");
    assert!(r.status().is_success(), "online preview status {}", r.status());
    let online_preview: Value = r.json().await.expect("preview JSON");
    let online_fingerprint = online_preview
        .get("fingerprint")
        .and_then(Value::as_str)
        .expect("fingerprint")
        .to_string();

    // Step 4: feed online's UR fragments into signer's preview; fingerprints must match.
    let r = client
        .post(format!("http://127.0.0.1:{signer_port}/api/pairing/preview"))
        .header("Origin", format!("http://127.0.0.1:{signer_port}"))
        .json(&json!({ "ur_fragments": online_fragments }))
        .send()
        .await
        .expect("POST signer pairing/preview");
    assert!(r.status().is_success(), "signer preview status {}", r.status());
    let signer_preview: Value = r.json().await.expect("signer preview JSON");
    let signer_fingerprint = signer_preview
        .get("fingerprint")
        .and_then(Value::as_str)
        .expect("fingerprint");
    assert_eq!(
        online_fingerprint, signer_fingerprint,
        "fingerprints differ — peer pubkey or hash function mismatched between binaries"
    );

    // Step 5: persist on both sides.
    let r = client
        .post(format!("http://127.0.0.1:{online_port}/api/pairing/set-peer"))
        .header("Origin", format!("http://127.0.0.1:{online_port}"))
        .json(&json!({
            "ur_fragments": signer_fragments,
            "expected_fingerprint": online_fingerprint,
        }))
        .send()
        .await
        .expect("POST online pairing/set-peer");
    assert!(r.status().is_success(), "online set-peer status {}", r.status());

    let r = client
        .post(format!("http://127.0.0.1:{signer_port}/api/pairing/set-peer"))
        .header("Origin", format!("http://127.0.0.1:{signer_port}"))
        .json(&json!({
            "ur_fragments": online_fragments,
            "expected_fingerprint": online_fingerprint,
        }))
        .send()
        .await
        .expect("POST signer pairing/set-peer");
    assert!(r.status().is_success(), "signer set-peer status {}", r.status());

    // Step 6: a subsequent /api/withdraw/start no longer returns NotPaired.
    // Configure online first.
    let r = client
        .post(format!("http://127.0.0.1:{online_port}/api/online-config"))
        .header("Origin", format!("http://127.0.0.1:{online_port}"))
        .json(&json!({
            "pool_id": "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d",
            "payment_address": "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
            "reward_receive_address": "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am"
        }))
        .send()
        .await
        .expect("POST online-config");
    assert!(r.status().is_success());

    let r = client
        .post(format!("http://127.0.0.1:{online_port}/api/withdraw/start"))
        .header("Origin", format!("http://127.0.0.1:{online_port}"))
        .json(&json!({ "pin": "1234" }))
        .send()
        .await
        .expect("POST withdraw/start");
    // After pairing, withdraw/start no longer returns 428. It may still
    // return some other code (e.g. no_rewards), but `not_paired` is what
    // is asserted against here.
    if !r.status().is_success() {
        let env: Value = r.json().await.expect("envelope");
        let code = env.get("code").and_then(Value::as_str).unwrap_or("");
        assert_ne!(code, "not_paired", "still NotPaired after set-peer dance");
    }
}
