//! End-to-end integration test for the signer's `/api/sign/execute`
//! authorization glue, driven through the real binary.
//!
//! The test generates both X25519 keypairs itself, writes the signer's
//! config so the signer decrypts with a secret the test controls, and
//! encrypts a real payment request with the production `airgap-core`
//! channel. That exercises, as a composed whole, the orchestration the
//! unit tests can only reach piecemeal:
//!
//!   decrypt -> kind detect -> exactly-once / wrong-PIN-lockout ledger ->
//!   chain-context freshness -> operator-PIN proof
//!
//! across separate HTTP calls against the real on-disk request ledger. It
//! also drives `/api/sign/receive`, which must show a preview only for a
//! request whose transaction body matches its description.
//!
//! It deliberately configures *no* signing key, so a fully-authorized
//! request stops at key-load with `not_configured`. That is the observable
//! marker that the entire authorization sequence passed: the only thing
//! left is the key. Producing a chain-valid signature additionally needs
//! real Cardano keys and a valid tx body and is covered by `sign_core`'s
//! unit tests plus manual signer testing.
//!
//! Run with: `cargo test -p wallet-signer --test sign_execute`. The signer
//! binary is built automatically by the test harness.

use serde_json::{json, Value};
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

use shared::chain_context::ChainContext;
use shared::crypto::{generate_keypair, GeneratedKeypair};
use shared::payment::PaymentRequest;
use shared::wire_kind::WalletWireKind;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_POLL: Duration = Duration::from_millis(50);

fn signer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wallet-tools-signer"))
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
            if r.status().is_success() {
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

/// Write the signer's config so it is paired with the test's online key and
/// has no signing keys, then spawn it with an isolated HOME. The config and
/// state directories are pre-created so the request ledger persists across
/// the calls of the lockout test.
fn spawn_paired_signer(home: &TempDir, keys: &PairedKeys) -> (ChildGuard, u16) {
    let cfg_dir = home.path().join(".config/wallet-tools");
    std::fs::create_dir_all(&cfg_dir).expect("create config dir");
    std::fs::create_dir_all(home.path().join(".wallet-tools")).expect("create state dir");
    let cfg = json!({
        "own_crypto_skey_hex": hex::encode(&keys.signer.secret[..]),
        "peer_crypto_pubkey_hex": hex::encode(keys.online.public),
    });
    std::fs::File::create(cfg_dir.join("signer.json"))
        .expect("create config")
        .write_all(cfg.to_string().as_bytes())
        .expect("write config");

    let bin = signer_bin();
    assert!(
        bin.exists(),
        "signer binary missing at {bin:?}; run `cargo build --bin wallet-tools-signer` first"
    );
    spawn_listening("signer", |port| {
        let mut c = Command::new(&bin);
        c.arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .env("HOME", home.path());
        c
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Build a payment request carrying a correct operator-PIN proof for
/// `pin`, then UR-encrypt it for the signer with the test's online key.
/// `built_at` controls the chain-context freshness. The proof is bound to
/// the body exactly as the online tool binds it: blank proof -> body_fp ->
/// proof over (pin, kind, built_at, body_fp).
fn encrypted_payment(keys: &PairedKeys, pin: &str, built_at: u64) -> Vec<String> {
    let mut req = PaymentRequest {
        kind: WalletWireKind::Payment,
        tx_body_cbor_hex: "a0".into(),
        destination_address_bech32: "addr1qxqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
        amount_lovelace: 1_500_000,
        assets_sent: vec![],
        fee_lovelace: 170_000,
        change_lovelace: 8_330_000,
        change_assets: vec![],
        ttl_slot: 152_100_000,
        payment_address_bech32: "addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
        inputs: vec![],
        operator_pin_proof: String::new(),
        chain_context: ChainContext {
            current_epoch: 555,
            current_slot: 152_000_000,
            current_kes_period: 0,
            epoch_ends_at_unix: built_at.saturating_add(100_000),
            opcert_expires_at_unix: None,
            built_at_unix: built_at,
        },
        metadata_msg: None,
    };
    let body_fp = shared::request_body_fp(&req);
    req.operator_pin_proof =
        shared::pin::pin_proof_hex(pin, WalletWireKind::Payment.wire_str(), built_at, &body_fp);
    let bytes = serde_json::to_vec(&req).expect("serialize request");
    shared::wire_io::ur_encode(
        &bytes,
        &keys.signer.public,
        &keys.online.secret,
        shared::qr::Direction::Request,
    )
    .expect("ur encode")
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

async fn post_receive(port: u16, fragments: &[String]) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/api/sign/receive"))
        .header("Origin", format!("http://127.0.0.1:{port}"))
        .json(&json!({ "ur_fragments": fragments }))
        .send()
        .await
        .expect("POST sign/receive");
    let status = r.status().as_u16();
    let body: Value = r.json().await.expect("response JSON");
    (status, body)
}

/// A payment request whose transaction body really is the payment it
/// describes (one input, destination + change outputs), UR-encrypted for
/// the signer. `body_fee` is the fee written into the body; the request
/// always declares 170 000, so any other value makes the request
/// misdescribe its body.
fn encrypted_real_payment(keys: &PairedKeys, body_fee: u64) -> Vec<String> {
    use pallas_codec::utils::{Bytes, Set};
    use pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput;
    use pallas_primitives::conway::{PseudoTransactionOutput, TransactionBody, Value as TxValue};
    use pallas_primitives::{Hash, NetworkId, TransactionInput};

    let own = shared::address::base_address_bech32(&[0x11; 32], &[0x22; 32]).expect("own address");
    let dest =
        shared::address::base_address_bech32(&[0x33; 32], &[0x44; 32]).expect("dest address");
    let out = |addr: &str, coin: u64| {
        PseudoTransactionOutput::PostAlonzo(PseudoPostAlonzoTransactionOutput {
            address: Bytes::from(shared::validate::addr_bytes(addr).expect("address bytes")),
            value: TxValue::Coin(coin),
            datum_option: None,
            script_ref: None,
        })
    };
    let body = TransactionBody {
        inputs: Set::from(vec![TransactionInput {
            transaction_id: Hash::from([9u8; 32]),
            index: 0,
        }]),
        outputs: vec![out(&dest, 1_500_000), out(&own, 8_330_000)],
        fee: body_fee,
        ttl: Some(152_100_000),
        certificates: None,
        withdrawals: None,
        auxiliary_data_hash: None,
        validity_interval_start: None,
        mint: None,
        script_data_hash: None,
        collateral: None,
        required_signers: None,
        network_id: Some(NetworkId::Mainnet),
        collateral_return: None,
        total_collateral: None,
        reference_inputs: None,
        voting_procedures: None,
        proposal_procedures: None,
        treasury_value: None,
        donation: None,
    };
    let mut body_cbor = Vec::new();
    pallas_codec::minicbor::encode(&body, &mut body_cbor).expect("encode body");

    let built_at = now_unix();
    let mut req = PaymentRequest {
        kind: WalletWireKind::Payment,
        tx_body_cbor_hex: hex::encode(&body_cbor),
        destination_address_bech32: dest,
        amount_lovelace: 1_500_000,
        assets_sent: vec![],
        fee_lovelace: 170_000,
        change_lovelace: 8_330_000,
        change_assets: vec![],
        ttl_slot: 152_100_000,
        payment_address_bech32: own.clone(),
        inputs: vec![shared::utxo::UtxoInput {
            tx_hash_hex: "09".repeat(32),
            tx_index: 0,
            amount_lovelace: 10_000_000,
            address_bech32: own,
        }],
        operator_pin_proof: String::new(),
        chain_context: ChainContext {
            current_epoch: 555,
            current_slot: 152_000_000,
            current_kes_period: 0,
            epoch_ends_at_unix: built_at.saturating_add(100_000),
            opcert_expires_at_unix: None,
            built_at_unix: built_at,
        },
        metadata_msg: None,
    };
    let body_fp = shared::request_body_fp(&req);
    req.operator_pin_proof = shared::pin::pin_proof_hex(
        "1234",
        WalletWireKind::Payment.wire_str(),
        built_at,
        &body_fp,
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
/// (no wallet keys) rather than any authorization-gate rejection. This is
/// the positive control: decrypt + kind + ledger + freshness + PIN all green.
#[tokio::test]
async fn accepts_authorized_request_and_stops_at_key_load() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    let fragments = encrypted_payment(&keys, "1234", now_unix());
    let (status, body) = post_execute(port, &fragments, "1234").await;

    assert_eq!(status, 412, "expected not_configured, got {status}: {body}");
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("not_configured"),
        "body: {body}"
    );
}

/// A request whose proof is bound to PIN "1234" is rejected when the
/// operator types a different PIN: the proof gate fires.
#[tokio::test]
async fn rejects_wrong_pin() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    let fragments = encrypted_payment(&keys, "1234", now_unix());
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
    let fragments = encrypted_payment(&keys, "1234", stale);
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
/// of wrong-PIN attempts as mismatches, then is locked out outright. Proves
/// the ledger keys requests by payload hash and survives request boundaries.
#[tokio::test]
async fn locks_out_after_repeated_wrong_pin() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    // One request, re-submitted with a wrong PIN every time.
    let fragments = encrypted_payment(&keys, "1234", now_unix());

    // wallet-signer's state::MAX_PIN_ATTEMPTS is 5; the first 5 are mismatches.
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
}

/// The preview is shown for a request whose transaction body is exactly the
/// payment it describes.
#[tokio::test]
async fn previews_a_request_whose_body_matches() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    let fragments = encrypted_real_payment(&keys, 170_000);
    let (status, body) = post_receive(port, &fragments).await;

    assert_eq!(status, 200, "expected a preview, got {status}: {body}");
    assert_eq!(
        body.get("kind").and_then(Value::as_str),
        Some("payment"),
        "body: {body}"
    );
    assert_eq!(
        body.pointer("/request/fee_lovelace")
            .and_then(Value::as_str),
        Some("170000"),
        "body: {body}"
    );
}

/// A request that misdescribes its transaction body is refused before any
/// preview is shown: the operator must never read figures the body does not
/// carry. Here the body pays a fee twenty times the one the request states.
#[tokio::test]
async fn refuses_to_preview_a_request_that_misdescribes_its_body() {
    let keys = paired_keys();
    let home = TempDir::new().expect("tempdir");
    let (_g, port) = spawn_paired_signer(&home, &keys);
    wait_for_health(port).await;

    let fragments = encrypted_real_payment(&keys, 3_400_000);
    let (status, body) = post_receive(port, &fragments).await;

    assert_eq!(status, 400, "expected a refusal, got {status}: {body}");
    assert!(
        body.get("request").is_none(),
        "no preview may be returned: {body}"
    );
    let msg = message(&body);
    assert!(
        msg.contains("does not match"),
        "expected the mismatch refusal, got: {msg}"
    );

    // The same holds for a body that is no transaction at all.
    let fragments = encrypted_payment(&keys, "1234", now_unix());
    let (status, body) = post_receive(port, &fragments).await;
    assert_eq!(status, 400, "expected a refusal, got {status}: {body}");
    assert!(
        body.get("request").is_none(),
        "no preview may be returned: {body}"
    );
}
