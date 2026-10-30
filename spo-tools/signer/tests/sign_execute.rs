//! End-to-end integration test for the signer's `/api/sign/execute`
//! authorization glue, driven through the real binary.
//!
//! `round_trip.rs` proves the wire/pairing crossing but stops every signing
//! path at `NotConfigured`, because it never supplies channel keys: it can
//! pair the binaries but cannot encrypt a request the signer will decrypt.
//! This test supplies the keys. It generates both X25519 keypairs itself,
//! writes the signer's config so the signer decrypts with a secret the test
//! controls, and encrypts real requests with the production `airgap-core`
//! channel. That exercises, as a composed whole, the orchestration the unit
//! tests can only reach piecemeal:
//!
//!   decrypt -> kind detect -> exactly-once / wrong-PIN-lockout ledger ->
//!   chain-context freshness -> operator-PIN proof
//!
//! across separate HTTP calls against the real on-disk request ledger.
//!
//! The tx-signing kinds (withdrawal, drep-delegation, pool-update, vote)
//! deliberately get *no* signing key, so a fully-authorized request stops
//! at key-load with `not_configured`: the observable marker that the
//! entire authorization sequence passed. Producing a chain-valid witness
//! for those kinds additionally needs real Cardano keys and a valid tx
//! body and is covered by `sign_core`'s unit tests plus manual signer
//! testing (see the `round_trip.rs` note). Leaderlog and KES rotation
//! need no tx body, so those two run their signing cores for real against
//! fabricated keys, which is what lets the exactly-once (replay-refusal)
//! half of the ledger and the opcert-counter gate be asserted end-to-end.
//!
//! Run with: `cargo test -p signer --test sign_execute`. The signer binary
//! is built automatically by the test harness.

use serde_json::{json, Value};
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

use shared::chain_context::ChainContext;
use shared::crypto::{generate_keypair, GeneratedKeypair};
use shared::drep::{DRepChoice, DRepDelegationRequest};
use shared::kes::{KesRotationRequest, KesRotationResult};
use shared::leaderlog::LeaderlogRequest;
use shared::pool_update::PoolUpdateRequest;
use shared::vote::{VoteChoice, VoteRequest};
use shared::wire_kind::WireKind;
use shared::withdrawal::WithdrawalRequest;
use shared::witness_doc::SpoWitnessRequest;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_POLL: Duration = Duration::from_millis(50);

/// Deterministic cold seed with its precomputed pool id: bech32 ("pool")
/// of blake2b-224 over the Ed25519 verification key derived from the
/// seed: the same fixture as `sign_core`'s unit tests. The rotation
/// path re-derives and checks this binding before signing.
const TEST_COLD_SEED: [u8; 32] = [7u8; 32];
const TEST_POOL_ID: &str = "pool13vscgf9dwn0jt56u965wp99ychz6avktk3pyrye326f3xctz4nm";

fn signer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_spo-tools-signer"))
}

/// Bind port 0 (kernel picks), capture the port, drop the listener. Small
/// TOCTOU window before the binary rebinds; fine for tests.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
}

/// Start the binary `build` sets up for a port, and wait until that very
/// process reports it is listening. A port from `pick_free_port` can be
/// taken by another test between the pick and the child's own bind, and the
/// test's requests would then reach that other test's binary, paired with
/// other keys. A child that exits before it reports is therefore started
/// again on a new port.
fn spawn_listening(what: &str, mut build: impl FnMut(u16) -> Command) -> (ChildGuard, u16) {
    use std::io::BufRead;
    for _ in 0..5 {
        let port = pick_free_port();
        let mut child = build(port)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {what}: {e}"));
        let mut lines = std::io::BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        if lines.any(|l| l.is_ok_and(|l| l.contains("listening on http://"))) {
            // Keep reading, so the child never blocks on a full pipe.
            std::thread::spawn(move || lines.for_each(drop));
            return (ChildGuard(child), port);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    panic!("{what} did not start on a free port");
}

async fn wait_for_health(port: u16) {
    let url = format!("http://127.0.0.1:{port}/api/health");
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + HEALTH_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if let Ok(r) = client.get(&url).send().await {
            // Assert the health body, not just 2xx: with an embedded
            // frontend the SPA fallback answers 200 index.html for any
            // unknown path, which would pass a status-only gate without
            // proving the API layer is routed.
            if r.status().is_success() && r.text().await.map(|t| t == "ok").unwrap_or(false) {
                return;
            }
        }
        tokio::time::sleep(HEALTH_POLL).await;
    }
    panic!("signer on port {port} did not become healthy within {HEALTH_TIMEOUT:?}");
}

/// SIGKILLs the child on Drop so a panicking test never leaks a binary.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The two ends of the paired channel. `online` is the sender (the role the
/// test plays); `signer` is the recipient, whose secret the signer binary
/// loads from the config the test writes.
struct PairedKeys {
    online: GeneratedKeypair,
    signer: GeneratedKeypair,
}

fn paired_keys() -> PairedKeys {
    PairedKeys {
        online: generate_keypair().expect("online keypair"),
        signer: generate_keypair().expect("signer keypair"),
    }
}

/// Write the signer's config (paired with the test's online key, plus any
/// extra fields (signing-key paths) from `extra_config`) then spawn it
/// with an isolated HOME. The config and state directories are pre-created
/// so the request ledger persists across the calls of the lockout and
/// replay tests.
fn spawn_signer_with_config(
    home: &TempDir,
    keys: &PairedKeys,
    extra_config: Value,
) -> (ChildGuard, u16) {
    let cfg_dir = home.path().join(".config/spo-tools");
    std::fs::create_dir_all(&cfg_dir).expect("create config dir");
    std::fs::create_dir_all(home.path().join(".spo-tools")).expect("create state dir");
    let mut cfg = json!({
        "own_crypto_skey_hex": hex::encode(&keys.signer.secret[..]),
        "peer_crypto_pubkey_hex": hex::encode(keys.online.public),
    });
    if let Some(extra) = extra_config.as_object() {
        let base = cfg.as_object_mut().expect("config is a JSON object");
        for (k, v) in extra {
            base.insert(k.clone(), v.clone());
        }
    }
    std::fs::File::create(cfg_dir.join("signer.json"))
        .expect("create config")
        .write_all(cfg.to_string().as_bytes())
        .expect("write config");

    let bin = signer_bin();
    assert!(
        bin.exists(),
        "signer binary missing at {bin:?}; run `cargo build --bin spo-tools-signer` first"
    );
    spawn_listening("signer", |port| {
        let mut c = Command::new(&bin);
        c.arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .env("HOME", home.path());
        c
    })
}

/// Paired signer with no signing keys configured: every fully-authorized
/// request stops at key-load with `not_configured`.
fn spawn_paired_signer(home: &TempDir, keys: &PairedKeys) -> (ChildGuard, u16) {
    spawn_signer_with_config(home, keys, json!({}))
}

/// Write a cardano-cli skey envelope at mode 0600 (`load_skey` refuses
/// group/other-readable files) and return its path for the config JSON.
fn write_skey(dir: &std::path::Path, name: &str, type_field: &str, cbor_hex: &str) -> String {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(name);
    let envelope = json!({
        "type": type_field,
        "description": "",
        "cborHex": cbor_hex,
    });
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("create skey")
        .write_all(envelope.to_string().as_bytes())
        .expect("write skey");
    path.to_str().expect("skey path is UTF-8").to_string()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Chain snapshot whose freshness window is anchored at `built_at`.
fn fresh_chain_context(built_at: u64) -> ChainContext {
    ChainContext {
        current_epoch: 555,
        current_slot: 152_000_000,
        current_kes_period: 1180,
        epoch_ends_at_unix: built_at.saturating_add(100_000),
        opcert_expires_at_unix: None,
        built_at_unix: built_at,
    }
}

/// Bind `pin` to a blank-proof request exactly as the online tool does
/// (blank proof -> body_fp -> proof over (pin, kind, built_at, body_fp)),
/// store the proof via `set_proof`, then UR-encrypt the request for the
/// signer with the test's online key.
fn seal_request<T: serde::Serialize>(
    keys: &PairedKeys,
    pin: &str,
    kind: WireKind,
    built_at: u64,
    mut req: T,
    set_proof: impl FnOnce(&mut T, String),
) -> Vec<String> {
    let body_fp = shared::request_body_fp(&req);
    set_proof(
        &mut req,
        shared::pin::pin_proof_hex(pin, kind.wire_str(), built_at, &body_fp),
    );
    let bytes = serde_json::to_vec(&req).expect("serialize request");
    shared::wire_io::ur_encode(
        &bytes,
        &keys.signer.public,
        &keys.online.secret,
        shared::qr::Direction::Request,
    )
    .expect("ur encode")
}

/// Leaderlog request over `epoch_length` slots. Parameterized because the
/// replay test runs the VRF evaluation for real: a mainnet-sized epoch
/// (432_000 slots) is minutes of VRF work, and the ledger under test keys
/// requests by payload hash, indifferent to the range size.
fn leaderlog_request(built_at: u64, epoch_length: u64) -> LeaderlogRequest {
    LeaderlogRequest {
        kind: WireKind::Leaderlog,
        pool_id_bech32: "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d".into(),
        epoch: 555,
        epoch_nonce_hex: "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef".into(),
        pool_stake: 2_000_000_000,
        total_active_stake: 20_000_000_000_000,
        active_slots_coeff_numer: 1,
        active_slots_coeff_denom: 20,
        epoch_first_slot: 1_000_000,
        epoch_length,
        operator_pin_proof: String::new(),
        chain_context: fresh_chain_context(built_at),
    }
}

fn encrypted_leaderlog(keys: &PairedKeys, pin: &str, built_at: u64) -> Vec<String> {
    seal_request(
        keys,
        pin,
        WireKind::Leaderlog,
        built_at,
        leaderlog_request(built_at, 432_000),
        |r, p| r.operator_pin_proof = p,
    )
}

fn kes_rotation_request(built_at: u64, new_counter: u64) -> KesRotationRequest {
    KesRotationRequest {
        kind: WireKind::KesRotation,
        pool_id_bech32: TEST_POOL_ID.into(),
        new_counter,
        kes_period: 1180,
        operator_pin_proof: String::new(),
        chain_context: fresh_chain_context(built_at),
    }
}

// The four tx-signing request builders below carry dummy preview values:
// their tests stop at key-load, before any body validation runs.

fn withdrawal_request(built_at: u64) -> WithdrawalRequest {
    WithdrawalRequest {
        kind: WireKind::Withdrawal,
        tx_body_cbor_hex: "a0".into(),
        fee_lovelace: 170_000,
        net_to_reward_address_lovelace: 5_000_000,
        change_to_payment_address_lovelace: 8_330_000,
        ttl_slot: 152_100_000,
        payment_address_bech32: "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
        reward_receive_address_bech32:
            "addr1qxqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".into(),
        pool_reward_address_bech32: "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
        inputs: vec![],
        operator_pin_proof: String::new(),
        chain_context: fresh_chain_context(built_at),
    }
}

fn drep_delegation_request(built_at: u64) -> DRepDelegationRequest {
    DRepDelegationRequest {
        kind: WireKind::DrepDelegation,
        tx_body_cbor_hex: "a0".into(),
        fee_lovelace: 170_000,
        change_to_payment_address_lovelace: 8_330_000,
        ttl_slot: 152_100_000,
        payment_address_bech32: "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
        stake_credential_bech32: "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
        drep_choice: DRepChoice::Abstain,
        inputs: vec![],
        operator_pin_proof: String::new(),
        chain_context: fresh_chain_context(built_at),
    }
}

fn pool_update_request(built_at: u64) -> PoolUpdateRequest {
    PoolUpdateRequest {
        kind: WireKind::PoolUpdate,
        tx_body_cbor_hex: "a0".into(),
        fee_lovelace: 170_000,
        change_to_payment_address_lovelace: 8_330_000,
        ttl_slot: 152_100_000,
        payment_address_bech32: "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
        pool_id_bech32: TEST_POOL_ID.into(),
        vrf_keyhash_hex: "ab".repeat(32),
        pledge_lovelace: 1_000_000_000,
        fixed_cost_lovelace: 170_000_000,
        margin_numerator: 1,
        margin_denominator: 100,
        reward_account_bech32: "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".into(),
        pool_owner_stake_addresses: vec![],
        relays: vec![],
        metadata_url: None,
        metadata_hash_hex: None,
        inputs: vec![],
        operator_pin_proof: String::new(),
        chain_context: fresh_chain_context(built_at),
    }
}

fn vote_request(built_at: u64) -> VoteRequest {
    VoteRequest {
        kind: WireKind::Vote,
        tx_body_cbor_hex: "a0".into(),
        fee_lovelace: 170_000,
        change_to_payment_address_lovelace: 8_330_000,
        ttl_slot: 152_100_000,
        payment_address_bech32: "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
        pool_id_bech32: TEST_POOL_ID.into(),
        action_tx_hash_hex: "cd".repeat(32),
        action_index: 0,
        vote: VoteChoice::Yes,
        anchor: None,
        inputs: vec![],
        operator_pin_proof: String::new(),
        chain_context: fresh_chain_context(built_at),
    }
}

fn witness_request(built_at: u64) -> SpoWitnessRequest {
    SpoWitnessRequest {
        kind: WireKind::WitnessDoc,
        canonical_body: "_:c14n0 <https://example.com/#body> _:c14n1 .\n".into(),
        pool_id_bech32: TEST_POOL_ID.into(),
        operator_pin_proof: String::new(),
        chain_context: fresh_chain_context(built_at),
    }
}

async fn post_execute(port: u16, fragments: &[String], pin: &str) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/api/sign/execute"))
        .header("Origin", format!("http://127.0.0.1:{port}"))
        .json(&json!({ "ur_fragments": fragments, "pin": pin }))
        .send()
        .await
        .expect("POST sign/execute");
    let status = r.status().as_u16();
    let body: Value = r.json().await.expect("response JSON");
    (status, body)
}

fn message(body: &Value) -> String {
    body.get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The whole authorization sequence passes for a fresh, correctly-PINned
/// request and the call reaches key-load, surfacing `not_configured`
/// (no VRF key) rather than any authorization-gate rejection. This is the
/// positive control: decrypt + kind + ledger + freshness + PIN all green.
#[tokio::test]
async fn accepts_authorized_request_and_stops_at_key_load() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    let fragments = encrypted_leaderlog(&keys, "1234", now_unix());
    let (status, body) = post_execute(port, &fragments, "1234").await;

    assert_eq!(status, 412, "expected not_configured, got {status}: {body}");
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("not_configured"),
        "body: {body}"
    );
}

/// Every other wire kind crosses the same composed authorization path
/// (decrypt -> kind detect -> ledger -> freshness -> PIN proof) and stops
/// at key-load with `not_configured`. Because the PIN proof is bound to
/// `kind.wire_str()`, reaching key-load per kind also proves the wire
/// string has not drifted between the online builder (played by this
/// test) and the signer for any of them, and that each request shape
/// survives the Rust<->Rust serde crossing.
#[tokio::test]
async fn every_wire_kind_crosses_authorization_to_key_load() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    let built_at = now_unix();
    let cases: Vec<(&str, Vec<String>)> = vec![
        (
            "kes-rotation",
            seal_request(
                &keys,
                "1234",
                WireKind::KesRotation,
                built_at,
                kes_rotation_request(built_at, 7),
                |r, p| r.operator_pin_proof = p,
            ),
        ),
        (
            "withdrawal",
            seal_request(
                &keys,
                "1234",
                WireKind::Withdrawal,
                built_at,
                withdrawal_request(built_at),
                |r, p| r.operator_pin_proof = p,
            ),
        ),
        (
            "drep-delegation",
            seal_request(
                &keys,
                "1234",
                WireKind::DrepDelegation,
                built_at,
                drep_delegation_request(built_at),
                |r, p| r.operator_pin_proof = p,
            ),
        ),
        (
            "pool-update",
            seal_request(
                &keys,
                "1234",
                WireKind::PoolUpdate,
                built_at,
                pool_update_request(built_at),
                |r, p| r.operator_pin_proof = p,
            ),
        ),
        (
            "vote",
            seal_request(
                &keys,
                "1234",
                WireKind::Vote,
                built_at,
                vote_request(built_at),
                |r, p| r.operator_pin_proof = p,
            ),
        ),
        (
            "witness-doc",
            seal_request(
                &keys,
                "1234",
                WireKind::WitnessDoc,
                built_at,
                witness_request(built_at),
                |r, p| r.operator_pin_proof = p,
            ),
        ),
    ];

    for (label, fragments) in cases {
        let (status, body) = post_execute(port, &fragments, "1234").await;
        assert_eq!(
            status, 412,
            "{label}: expected not_configured, got {status}: {body}"
        );
        assert_eq!(
            body.get("code").and_then(Value::as_str),
            Some("not_configured"),
            "{label}: {body}"
        );
    }
}

/// A request whose proof is bound to PIN "1234" is rejected when the
/// operator types a different PIN: the proof gate fires.
#[tokio::test]
async fn rejects_wrong_pin() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    let fragments = encrypted_leaderlog(&keys, "1234", now_unix());
    let (status, body) = post_execute(port, &fragments, "9999").await;

    assert_eq!(status, 400, "expected invalid_input, got {status}: {body}");
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("invalid_input")
    );
    let msg = message(&body);
    assert!(
        msg.contains("PIN"),
        "expected a PIN-mismatch message, got: {msg}"
    );
}

/// A request whose chain_context is older than the freshness window is
/// rejected by the freshness gate, which runs before the PIN check (the PIN
/// here is correct, so the rejection can only be staleness).
#[tokio::test]
async fn rejects_stale_chain_context() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    let stale = now_unix() - 25 * 60 * 60; // 25h: past the 24h window.
    let fragments = encrypted_leaderlog(&keys, "1234", stale);
    let (status, body) = post_execute(port, &fragments, "1234").await;

    assert_eq!(status, 400, "expected invalid_input, got {status}: {body}");
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("invalid_input")
    );
    let msg = message(&body);
    assert!(
        msg.contains("older than"),
        "expected a staleness message, got: {msg}"
    );
}

/// The persistent wrong-PIN ledger composes across separate HTTP calls: the
/// same request (same payload -> same ledger row) tolerates a bounded number
/// of wrong-PIN attempts as mismatches, then is locked out outright, even
/// for the correct PIN. Proves the ledger keys requests by payload hash and
/// survives request boundaries.
#[tokio::test]
async fn locks_out_after_repeated_wrong_pin() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    // One request, re-submitted with a wrong PIN every time.
    let fragments = encrypted_leaderlog(&keys, "1234", now_unix());

    // The signer's `state::MAX_PIN_ATTEMPTS` (signer/src/state.rs) is 5;
    // the first 5 are mismatches. The 5 is a hard-coded copy: integration
    // tests cannot import a binary crate's modules.
    for attempt in 1..=5 {
        let (status, body) = post_execute(port, &fragments, "0000").await;
        assert_eq!(
            status, 400,
            "attempt {attempt}: expected invalid_input: {body}"
        );
        let msg = message(&body);
        assert!(
            msg.contains("PIN") && msg.contains("mismatch"),
            "attempt {attempt}: expected PIN mismatch, got: {msg}"
        );
    }

    // The next attempt is refused by the lockout, not the PIN comparison.
    let (status, body) = post_execute(port, &fragments, "0000").await;
    assert_eq!(status, 400, "lockout: expected invalid_input: {body}");
    let msg = message(&body);
    assert!(
        msg.contains("too many PIN attempts"),
        "expected the lockout message, got: {msg}"
    );

    // Lockout binds to the request, not the last-typed PIN: once the
    // budget is spent even the CORRECT PIN is refused: the property that
    // matters against a PIN-guessing adversary.
    let (status, body) = post_execute(port, &fragments, "1234").await;
    assert_eq!(
        status, 400,
        "lockout with correct PIN: expected invalid_input: {body}"
    );
    let msg = message(&body);
    assert!(
        msg.contains("too many PIN attempts"),
        "correct PIN after lockout must still be refused, got: {msg}"
    );
}

/// The exactly-once half of the ledger, asserted end-to-end: with a VRF
/// key configured, a fully-authorized leaderlog request signs for real,
/// and a byte-identical resubmission with the correct PIN is refused by
/// the AlreadySigned gate instead of being signed twice.
#[tokio::test]
async fn refuses_to_sign_the_same_request_twice() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let key_dir = TempDir::new().expect("key dir");
    // Any 64 bytes are structurally-valid VRF material (the first 32 seed
    // vrf-dalek); chain validity does not matter to the ledger under test.
    let vrf_path = write_skey(
        key_dir.path(),
        "vrf.skey",
        "VrfSigningKey_PraosVRF",
        &format!("5840{}", "42".repeat(64)),
    );
    let (_g, port) = spawn_signer_with_config(&home, &keys, json!({ "vrf_skey": vrf_path }));
    wait_for_health(port).await;

    // 32 slots keeps the real VRF evaluation fast.
    let built_at = now_unix();
    let fragments = seal_request(
        &keys,
        "1234",
        WireKind::Leaderlog,
        built_at,
        leaderlog_request(built_at, 32),
        |r, p| r.operator_pin_proof = p,
    );

    let (status, body) = post_execute(port, &fragments, "1234").await;
    assert_eq!(status, 200, "first submission should sign: {body}");
    assert_eq!(
        body.get("kind").and_then(Value::as_str),
        Some("leaderlog"),
        "body: {body}"
    );
    assert!(
        body.get("ur_fragments")
            .and_then(Value::as_array)
            .is_some_and(|f| !f.is_empty()),
        "expected response UR fragments: {body}"
    );

    let (status, body) = post_execute(port, &fragments, "1234").await;
    assert_eq!(status, 400, "replay: expected invalid_input: {body}");
    let msg = message(&body);
    assert!(
        msg.contains("already been signed"),
        "expected the exactly-once refusal, got: {msg}"
    );
}

/// KES rotation crosses the whole composed path with a fabricated cold
/// key: authorization, cold-key/pool-id binding, opcert-counter gate,
/// real Sum6Kes keygen, the three-file bundle on disk next to cold.skey,
/// and an encrypted response the online side can decode. A byte-identical
/// replay is then refused by the exactly-once gate, a counter regression
/// in a fresh request by the counter gate, and a counter advance (the
/// control) rotates again.
#[tokio::test]
async fn rotates_kes_end_to_end_and_enforces_counter_monotonicity() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let key_dir = TempDir::new().expect("key dir");
    let cold_path = write_skey(
        key_dir.path(),
        "cold.skey",
        "StakePoolSigningKey_ed25519",
        &format!("5820{}", hex::encode(TEST_COLD_SEED)),
    );
    let (_g, port) = spawn_signer_with_config(&home, &keys, json!({ "cold_skey": cold_path }));
    wait_for_health(port).await;

    let built_at = now_unix();
    let fragments = seal_request(
        &keys,
        "1234",
        WireKind::KesRotation,
        built_at,
        kes_rotation_request(built_at, 7),
        |r, p| r.operator_pin_proof = p,
    );
    let (status, body) = post_execute(port, &fragments, "1234").await;
    assert_eq!(status, 200, "rotation should sign: {body}");
    assert_eq!(
        body.get("kind").and_then(Value::as_str),
        Some("kes-rotation"),
        "body: {body}"
    );

    // The response decrypts on the online side and carries the rotation
    // metadata (never the fresh KES secret).
    let response_fragments: Vec<String> = body
        .get("ur_fragments")
        .and_then(Value::as_array)
        .expect("response UR fragments")
        .iter()
        .map(|f| f.as_str().expect("fragment is a string").to_string())
        .collect();
    let plaintext = shared::wire_io::ur_decode_required(
        &response_fragments,
        &keys.signer.public,
        &keys.online.secret,
        shared::qr::Direction::Response,
    )
    .expect("decode response");
    let result: KesRotationResult = serde_json::from_slice(&plaintext).expect("kes result decodes");
    assert_eq!(result.counter, 7);
    assert_eq!(result.kes_period, 1180);
    assert_eq!(result.pool_id_bech32, TEST_POOL_ID);

    // The staged bundle lands next to cold.skey, and cold.counter stores
    // the NEXT issue number (cardano-cli semantics: last issued + 1).
    for name in ["kes.skey", "node.cert", "cold.counter"] {
        assert!(
            key_dir.path().join(name).exists(),
            "{name} missing from output dir"
        );
    }
    let counter_file: Value = serde_json::from_str(
        &std::fs::read_to_string(key_dir.path().join("cold.counter")).expect("read cold.counter"),
    )
    .expect("cold.counter JSON");
    assert_eq!(
        counter_file.get("description").and_then(Value::as_str),
        Some("Next certificate issue number: 8"),
        "cold.counter: {counter_file}"
    );

    // Byte-identical replay: refused by the exactly-once gate, before any
    // key or counter work.
    let (status, body) = post_execute(port, &fragments, "1234").await;
    assert_eq!(status, 400, "replay: expected invalid_input: {body}");
    assert!(
        message(&body).contains("already been signed"),
        "expected the exactly-once refusal, got: {}",
        message(&body)
    );

    // A fresh request whose counter regresses behind the last issued (7)
    // is refused by the counter gate. Authorization is all green (fresh
    // payload -> fresh ledger row, correct PIN, fresh context) and KES
    // rotation validates no tx body, so the redacted invalid_input can
    // only be the counter monotonicity check, as the control below
    // confirms.
    let regress = seal_request(
        &keys,
        "1234",
        WireKind::KesRotation,
        built_at,
        kes_rotation_request(built_at, 6),
        |r, p| r.operator_pin_proof = p,
    );
    let (status, body) = post_execute(port, &regress, "1234").await;
    assert_eq!(
        status, 400,
        "counter regression: expected invalid_input: {body}"
    );
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("invalid_input"),
        "body: {body}"
    );

    // Control: the next counter (8) is accepted, proving the refusal above
    // was the regression and not some broader failure.
    let advance = seal_request(
        &keys,
        "1234",
        WireKind::KesRotation,
        built_at,
        kes_rotation_request(built_at, 8),
        |r, p| r.operator_pin_proof = p,
    );
    let (status, body) = post_execute(port, &advance, "1234").await;
    assert_eq!(status, 200, "counter advance should sign: {body}");
}
