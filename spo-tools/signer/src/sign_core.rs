//! Pure-compute helpers for signing operations.
//!
//! Witness-building, leaderlog VRF eval, and KES rotation. Path-sourced
//! signing keys are loaded once and consumed; nothing here writes config.
//! All errors flow through `SignExecuteError` which has a central
//! `impl From<_> for ErrorEnvelope` mapping for the HTTP layer.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ed25519_dalek::{Signer, SigningKey};
use pallas_crypto::key::ed25519::SecretKeyExtended;
use kes_summed_ed25519::{kes::Sum6Kes, traits::KesSk};
use shared::error::ErrorEnvelope;
use tracing::debug;
use vrf_dalek::vrf03::{PublicKey03, SecretKey03, VrfProof03};
use zeroize::Zeroizing;

// ============================================================
// Sign-execute helpers — pure compute / rotate cores, callable from the
// web handler with paths sourced from signer config (instead of the env
// vars the CLI uses).
// ============================================================

/// Signing-key material the core signers consume. Plain keys are
/// standard 32-byte Ed25519 seeds; extended keys are BIP32-Ed25519
/// (kL‖kR) from a converted mnemonic wallet, signed scalar-based.
pub(crate) enum SigningKeyMaterial {
    Plain(Zeroizing<[u8; 32]>),
    Extended {
        esk: Zeroizing<[u8; 64]>,
        /// Public key embedded in the skey envelope; the loader verified
        /// it equals the key derived from `esk`.
        expected_pubkey: [u8; 32],
    },
}

/// Validate an extended (BIP32-Ed25519) key and wrap it as signing
/// material. Checks the Ed25519-BIP32 bit structure and that the embedded
/// public key matches the one derived from the secret — an integrity
/// cross-check that catches a corrupted or inconsistent extended skey
/// before it is ever used to sign.
fn extended_material(
    esk_64: [u8; 64],
    pubkey_32: [u8; 32],
) -> Result<SigningKeyMaterial, SignExecuteError> {
    let sk = SecretKeyExtended::from_bytes(esk_64).map_err(|_| {
        SignExecuteError::WrongRole("extended key failed Ed25519-BIP32 structure check".into())
    })?;
    let derived = sk.public_key();
    if derived.as_ref() != pubkey_32.as_slice() {
        return Err(SignExecuteError::WrongRole(
            "extended key public-key mismatch (corrupt skey?)".into(),
        ));
    }
    Ok(SigningKeyMaterial::Extended {
        esk: Zeroizing::new(esk_64),
        expected_pubkey: pubkey_32,
    })
}

impl From<SignExecuteError> for ErrorEnvelope {
    fn from(e: SignExecuteError) -> ErrorEnvelope {
        let msg = e.to_string();
        match e {
            SignExecuteError::VrfNotConfigured
            | SignExecuteError::ColdNotConfigured
            | SignExecuteError::PaymentNotConfigured
            | SignExecuteError::RewardNotConfigured
            | SignExecuteError::OwnerNotConfigured => ErrorEnvelope::not_configured(msg),
            // The bad-request variants share a redacted HTTP message (the
            // signer does not leak request-shape detail to a potentially
            // compromised online tool), but the variant-specific message
            // is logged here so the operator can debug from signer logs.
            SignExecuteError::BodyValidation(_)
            | SignExecuteError::BadCborHex(_)
            | SignExecuteError::BadNonce(_)
            | SignExecuteError::BadParam(_)
            | SignExecuteError::PoolMismatch(_)
            | SignExecuteError::OpcertCounter(_) => {
                tracing::warn!(detail = %msg, "rejecting request as invalid");
                ErrorEnvelope::invalid("invalid request payload")
            }
            SignExecuteError::WrongRole(_) => ErrorEnvelope::invalid("configured key has wrong role"),
            SignExecuteError::LoadVrf { source, .. }
            | SignExecuteError::LoadCold { source, .. }
            | SignExecuteError::LoadPayment { source, .. }
            | SignExecuteError::LoadStake { source, .. } => {
                tracing::error!(error = %source, "key load failed");
                ErrorEnvelope::internal("key load failed")
            }
            SignExecuteError::Entropy(_) | SignExecuteError::Encode(_) => {
                tracing::error!(error = %msg, "sign_execute internal failure");
                ErrorEnvelope::internal("signing failed")
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SignExecuteError {
    #[error("VRF signing key path not configured — visit Setup")]
    VrfNotConfigured,
    #[error("cold signing key path not configured — visit Setup")]
    ColdNotConfigured,
    #[error("payment signing key path not configured — visit Setup")]
    PaymentNotConfigured,
    #[error("reward stake signing key path not configured — visit Setup")]
    RewardNotConfigured,
    #[error("owner stake signing key path not configured — visit Setup")]
    OwnerNotConfigured,
    #[error("could not load VRF key from {path}: {source}")]
    LoadVrf { path: String, source: Box<dyn std::error::Error + Send + Sync> },
    #[error("could not load cold key from {path}: {source}")]
    LoadCold { path: String, source: Box<dyn std::error::Error + Send + Sync> },
    #[error("could not load payment key from {path}: {source}")]
    LoadPayment { path: String, source: Box<dyn std::error::Error + Send + Sync> },
    #[error("could not load stake key from {path}: {source}")]
    LoadStake { path: String, source: Box<dyn std::error::Error + Send + Sync> },
    #[error("epoch_nonce_hex is invalid: {0}")]
    BadNonce(String),
    #[error("invalid leaderlog parameter: {0}")]
    BadParam(String),
    #[error("tx body does not match request: {0}")]
    BodyValidation(String),
    #[error("tx body cbor hex is invalid: {0}")]
    BadCborHex(String),
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("key file is not the expected role: {0}")]
    WrongRole(String),
    #[error("cold key does not match the request's pool id: {0}")]
    PoolMismatch(String),
    #[error("opcert counter check failed: {0}")]
    OpcertCounter(String),
    #[error("system entropy unavailable: {0}")]
    Entropy(String),
}

pub(crate) fn load_vrf_from_path(path: &std::path::Path) -> Result<SecretKey03, SignExecuteError> {
    let key = shared::cardano_keys::load_skey(path).map_err(|e| SignExecuteError::LoadVrf {
        path: path.display().to_string(),
        source: Box::new(e),
    })?;
    match key {
        shared::cardano_keys::CardanoKey::Vrf { .. } => {
            let seed = key.seed_32();
            // Log only the SHA256 of the seed to avoid leaking key material
            // while still distinguishing two skey files at a glance.
            use sha2::{Digest, Sha256};
            let fp = hex::encode(&Sha256::digest(&seed[..])[..4]);
            debug!(fingerprint = %fp, "loaded VRF skey");
            Ok(SecretKey03::from_bytes(&seed))
        }
        other => Err(SignExecuteError::WrongRole(format!(
            "expected VRF key, got {}",
            other.role_name()
        ))),
    }
}

pub(crate) fn load_cold_seed_from_path(path: &std::path::Path) -> Result<Zeroizing<[u8; 32]>, SignExecuteError> {
    let key = shared::cardano_keys::load_skey(path).map_err(|e| SignExecuteError::LoadCold {
        path: path.display().to_string(),
        source: Box::new(e),
    })?;
    match key {
        shared::cardano_keys::CardanoKey::PoolCold { seed_32 } => Ok(Zeroizing::new(seed_32)),
        other => Err(SignExecuteError::WrongRole(format!(
            "expected cold key, got {}",
            other.role_name()
        ))),
    }
}

pub(crate) fn load_payment_material_from_path(
    path: &std::path::Path,
) -> Result<SigningKeyMaterial, SignExecuteError> {
    let key = shared::cardano_keys::load_skey(path).map_err(|e| SignExecuteError::LoadPayment {
        path: path.display().to_string(),
        source: Box::new(e),
    })?;
    match key {
        shared::cardano_keys::CardanoKey::Payment { seed_32 } => {
            Ok(SigningKeyMaterial::Plain(Zeroizing::new(seed_32)))
        }
        shared::cardano_keys::CardanoKey::PaymentExtended { esk_64, pubkey_32 } => {
            extended_material(esk_64, pubkey_32)
        }
        other => Err(SignExecuteError::WrongRole(format!(
            "expected payment key, got {}",
            other.role_name()
        ))),
    }
}

pub(crate) fn load_stake_material_from_path(
    path: &std::path::Path,
) -> Result<SigningKeyMaterial, SignExecuteError> {
    let key = shared::cardano_keys::load_skey(path).map_err(|e| SignExecuteError::LoadStake {
        path: path.display().to_string(),
        source: Box::new(e),
    })?;
    match key {
        shared::cardano_keys::CardanoKey::Stake { seed_32 } => {
            Ok(SigningKeyMaterial::Plain(Zeroizing::new(seed_32)))
        }
        shared::cardano_keys::CardanoKey::StakeExtended { esk_64, pubkey_32 } => {
            extended_material(esk_64, pubkey_32)
        }
        other => Err(SignExecuteError::WrongRole(format!(
            "expected stake key, got {}",
            other.role_name()
        ))),
    }
}

/// Sign `body_hash` with `seed` and wrap as a `VkeyWitness` tagged with
/// `role`. Takes the seed by reference so the caller's `Zeroizing<[u8;
/// 32]>` is the only owned copy and gets wiped on its own drop, instead
/// of one extra owned copy living on this stack frame.
fn build_vkey_witness(
    role: shared::witness::WitnessRole,
    material: &SigningKeyMaterial,
    body_hash: &[u8; 32],
) -> Result<shared::witness::VkeyWitness, SignExecuteError> {
    let (vkey_hex, signature_hex) = match material {
        SigningKeyMaterial::Plain(seed) => {
            let sk = SigningKey::from_bytes(seed);
            let sig = sk.sign(body_hash);
            (
                hex::encode(sk.verifying_key().to_bytes()),
                hex::encode(sig.to_bytes()),
            )
        }
        SigningKeyMaterial::Extended { esk, expected_pubkey } => {
            // BIP32-Ed25519: sign with the scalar directly (pallas
            // SecretKeyExtended / cryptoxide), never as a 32-byte seed.
            let sk = SecretKeyExtended::from_bytes(**esk).map_err(|_| {
                SignExecuteError::WrongRole(
                    "extended key failed Ed25519-BIP32 structure check".into(),
                )
            })?;
            let derived = sk.public_key();
            // Re-check the derived key against the envelope's embedded
            // public key at signing time (also checked at load) so a
            // compromised path cannot swap in a different extended key.
            if derived.as_ref() != expected_pubkey.as_slice() {
                return Err(SignExecuteError::WrongRole(
                    "extended key public-key drift".into(),
                ));
            }
            let sig = sk.sign(body_hash);
            (hex::encode(derived.as_ref()), hex::encode(sig.as_ref()))
        }
    };
    Ok(shared::witness::VkeyWitness {
        role,
        vkey_hex,
        signature_hex,
    })
}

/// Sign the body hash of a withdrawal tx with the supplied seeds, producing
/// vkey witnesses for the input UTXO and the reward-account authorisation.
pub(crate) fn sign_withdrawal_core(
    req: &shared::withdrawal::WithdrawalRequest,
    payment_material: SigningKeyMaterial,
    reward_material: SigningKeyMaterial,
) -> Result<shared::withdrawal::WithdrawalResult, SignExecuteError> {
    let body_bytes = hex::decode(&req.tx_body_cbor_hex)
        .map_err(|e| SignExecuteError::BadCborHex(e.to_string()))?;
    shared::tx_validator::validate_withdrawal_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;

    let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
    hasher.update(&body_bytes);
    let mut body_hash = [0u8; 32];
    hasher
        .finalize_variable(&mut body_hash)
        .expect("blake2b 256 fin");

    let witnesses = vec![
        build_vkey_witness(shared::witness::WitnessRole::Payment, &payment_material, &body_hash)?,
        build_vkey_witness(shared::witness::WitnessRole::RewardStake, &reward_material, &body_hash)?,
    ];

    Ok(shared::withdrawal::WithdrawalResult {
        body_hash_hex: hex::encode(body_hash),
        witnesses,
    })
}

/// Sign a DRep-delegation tx body with payment + owner stake skeys.
pub(crate) fn sign_drep_delegation_core(
    req: &shared::drep::DRepDelegationRequest,
    payment_material: SigningKeyMaterial,
    owner_material: SigningKeyMaterial,
) -> Result<shared::drep::DRepDelegationResult, SignExecuteError> {
    let body_bytes = hex::decode(&req.tx_body_cbor_hex)
        .map_err(|e| SignExecuteError::BadCborHex(e.to_string()))?;
    shared::tx_validator::validate_drep_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;

    let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
    hasher.update(&body_bytes);
    let mut body_hash = [0u8; 32];
    hasher
        .finalize_variable(&mut body_hash)
        .expect("blake2b 256 fin");

    let witnesses = vec![
        build_vkey_witness(shared::witness::WitnessRole::Payment, &payment_material, &body_hash)?,
        build_vkey_witness(shared::witness::WitnessRole::OwnerStake, &owner_material, &body_hash)?,
    ];

    Ok(shared::drep::DRepDelegationResult {
        body_hash_hex: hex::encode(body_hash),
        witnesses,
    })
}

/// Sign a pool re-registration tx body with payment + cold + owner stake skeys.
pub(crate) fn sign_pool_update_core(
    req: &shared::pool_update::PoolUpdateRequest,
    payment_material: SigningKeyMaterial,
    cold_seed: Zeroizing<[u8; 32]>,
    owner_material: SigningKeyMaterial,
) -> Result<shared::pool_update::PoolUpdateResult, SignExecuteError> {
    let body_bytes = hex::decode(&req.tx_body_cbor_hex)
        .map_err(|e| SignExecuteError::BadCborHex(e.to_string()))?;
    shared::tx_validator::validate_pool_update_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;

    // Bind the actual signing key to the pool id the body re-registers,
    // the same defense-in-depth as the vote path: the cold key must hash
    // to the request's pool id before it signs anything.
    let cold_vkey = SigningKey::from_bytes(&cold_seed).verifying_key().to_bytes();
    shared::tx_validator::assert_cold_vkey_matches_pool(&req.pool_id_bech32, &cold_vkey)
        .map_err(|e| SignExecuteError::PoolMismatch(e.to_string()))?;

    let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
    hasher.update(&body_bytes);
    let mut body_hash = [0u8; 32];
    hasher
        .finalize_variable(&mut body_hash)
        .expect("blake2b 256 fin");

    let cold_material = SigningKeyMaterial::Plain(cold_seed);
    let witnesses = vec![
        build_vkey_witness(shared::witness::WitnessRole::Payment, &payment_material, &body_hash)?,
        build_vkey_witness(shared::witness::WitnessRole::Cold, &cold_material, &body_hash)?,
        build_vkey_witness(shared::witness::WitnessRole::OwnerStake, &owner_material, &body_hash)?,
    ];

    Ok(shared::pool_update::PoolUpdateResult {
        body_hash_hex: hex::encode(body_hash),
        witnesses,
    })
}

/// Sign an SPO governance-vote tx body with payment + cold skeys. The
/// cold key is the pool's voting authority, so this additionally checks
/// that the cold key hashes to the pool id the body votes as before it
/// signs anything.
pub(crate) fn sign_vote_core(
    req: &shared::vote::VoteRequest,
    payment_material: SigningKeyMaterial,
    cold_seed: Zeroizing<[u8; 32]>,
) -> Result<shared::vote::VoteResult, SignExecuteError> {
    let body_bytes = hex::decode(&req.tx_body_cbor_hex)
        .map_err(|e| SignExecuteError::BadCborHex(e.to_string()))?;
    shared::tx_validator::validate_vote_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;

    // Bind the actual signing key to the pool id the body votes as.
    let cold_vkey = SigningKey::from_bytes(&cold_seed).verifying_key().to_bytes();
    shared::tx_validator::assert_cold_vkey_matches_pool(&req.pool_id_bech32, &cold_vkey)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;

    let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
    hasher.update(&body_bytes);
    let mut body_hash = [0u8; 32];
    hasher
        .finalize_variable(&mut body_hash)
        .expect("blake2b 256 fin");

    let cold_material = SigningKeyMaterial::Plain(cold_seed);
    let witnesses = vec![
        build_vkey_witness(shared::witness::WitnessRole::Payment, &payment_material, &body_hash)?,
        build_vkey_witness(shared::witness::WitnessRole::Cold, &cold_material, &body_hash)?,
    ];

    Ok(shared::vote::VoteResult {
        body_hash_hex: hex::encode(body_hash),
        witnesses,
    })
}

/// Produce a CIP-100 author witness over a governance-metadata canonical
/// body, signed by the pool cold key. Refuses unless the payload is a
/// canonical N-Quads body (never a transaction body) and the cold key hashes
/// to the request's pool id, so the witness publicKey is verifiably the
/// operator's pool.
pub(crate) fn sign_witness_core(
    req: &shared::witness_doc::SpoWitnessRequest,
    cold_seed: Zeroizing<[u8; 32]>,
) -> Result<shared::witness_doc::SpoWitnessResult, SignExecuteError> {
    shared::validate::assert_canonical_body_nquads(req.canonical_body.as_bytes())
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let cold_vkey = SigningKey::from_bytes(&cold_seed).verifying_key().to_bytes();
    shared::tx_validator::assert_cold_vkey_matches_pool(&req.pool_id_bech32, &cold_vkey)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let body_hash = shared::validate::blake2b256(req.canonical_body.as_bytes());
    let sig = SigningKey::from_bytes(&cold_seed).sign(&body_hash);
    Ok(shared::witness_doc::SpoWitnessResult {
        body_hash_hex: hex::encode(body_hash),
        witness: shared::witness_doc::Cip100Witness {
            witness_algorithm: "ed25519".to_string(),
            public_key_hex: hex::encode(cold_vkey),
            signature_hex: hex::encode(sig.to_bytes()),
        },
    })
}

pub(crate) fn compute_leaderlog_core(
    req: &shared::leaderlog::LeaderlogRequest,
    vrf_skey: &SecretKey03,
) -> Result<shared::leaderlog::LeaderlogResult, SignExecuteError> {
    use shared::praos::{build_vrf_input, PraosError, PraosThreshold};

    let threshold = PraosThreshold::new(
        req.pool_stake,
        req.total_active_stake,
        req.active_slots_coeff_numer,
        req.active_slots_coeff_denom,
    )
    .map_err(|e| match e {
        PraosError::ZeroActiveStake => {
            SignExecuteError::BadParam("total_active_stake is zero".into())
        }
        PraosError::ZeroSlotCoeffDenom => {
            SignExecuteError::BadParam("active_slots_coeff_denom is zero".into())
        }
        PraosError::SlotCoeffNotBelowOne => {
            SignExecuteError::BadParam("active_slots_coeff must be below 1 (numer < denom)".into())
        }
    })?;

    let nonce_bytes =
        hex::decode(&req.epoch_nonce_hex).map_err(|e| SignExecuteError::BadNonce(e.to_string()))?;
    let nonce: [u8; 32] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SignExecuteError::BadNonce("epoch_nonce_hex must decode to 32 bytes".into()))?;

    let pk = PublicKey03::from(vrf_skey);
    let mut leader_slots: Vec<u64> = Vec::new();
    // Bound the iteration magnitude: epoch_length is untrusted request input
    // and each slot runs a full VRF evaluation. Mainnet epochs are 432_000
    // slots; cap at a generous multiple so a compromised online tool cannot
    // drive the signer into an effectively unbounded VRF loop.
    const MAX_EPOCH_LENGTH: u64 = 10 * 432_000;
    if req.epoch_length > MAX_EPOCH_LENGTH {
        return Err(SignExecuteError::BadParam(format!(
            "epoch_length {} exceeds maximum {}",
            req.epoch_length, MAX_EPOCH_LENGTH
        )));
    }
    // Reject ranges that would overflow u64. The online tool validates
    // this too; the signer cannot trust upstream input.
    let last = req
        .epoch_first_slot
        .checked_add(req.epoch_length)
        .ok_or_else(|| SignExecuteError::BadParam(
            "epoch_first_slot + epoch_length overflows u64".into(),
        ))?;
    for slot in req.epoch_first_slot..last {
        let input = build_vrf_input(slot, &nonce);
        let proof = VrfProof03::generate(&pk, vrf_skey, &input);
        let raw_vrf = proof.proof_to_hash();
        if threshold.is_leader(&raw_vrf) {
            leader_slots.push(slot);
        }
    }
    Ok(shared::leaderlog::LeaderlogResult {
        pool_id_bech32: req.pool_id_bech32.clone(),
        epoch: req.epoch,
        slots: leader_slots,
    })
}

/// Parse the issue counter and cold verification key out of an existing
/// `cold.counter` envelope in `output_dir`. The counter carries
/// cardano-cli's issue-counter semantics: it is the number the NEXT
/// opcert will use, i.e. last issued + 1. Returns `Ok(None)` when no
/// counter file is present (a first-ever rotation). A present-but-corrupt
/// file is an error, never silently treated as absent: the monotonicity
/// guard must not be bypassed by a malformed counter file.
fn read_existing_cold_counter(
    output_dir: &std::path::Path,
) -> Result<Option<(u64, [u8; 32])>, SignExecuteError> {
    let path = output_dir.join("cold.counter");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(SignExecuteError::Encode(format!("read cold.counter: {e}"))),
    };
    let v: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| SignExecuteError::OpcertCounter(format!("cold.counter is not valid JSON: {e}")))?;
    let cbor_hex = v["cborHex"]
        .as_str()
        .ok_or_else(|| SignExecuteError::OpcertCounter("cold.counter envelope has no cborHex".into()))?;
    let bytes = hex::decode(cbor_hex)
        .map_err(|e| SignExecuteError::OpcertCounter(format!("cold.counter cborHex is not hex: {e}")))?;
    let mut dec = minicbor::Decoder::new(&bytes);
    if dec
        .array()
        .map_err(|e| SignExecuteError::OpcertCounter(format!("cold.counter cbor: {e}")))?
        != Some(2)
    {
        return Err(SignExecuteError::OpcertCounter(
            "cold.counter cbor is not a definite 2-element array".into(),
        ));
    }
    let counter = dec
        .u64()
        .map_err(|e| SignExecuteError::OpcertCounter(format!("cold.counter cbor counter: {e}")))?;
    let vkey_bytes = dec
        .bytes()
        .map_err(|e| SignExecuteError::OpcertCounter(format!("cold.counter cbor vkey: {e}")))?;
    let vkey: [u8; 32] = vkey_bytes
        .try_into()
        .map_err(|_| SignExecuteError::OpcertCounter("cold.counter cold vkey is not 32 bytes".into()))?;
    Ok(Some((counter, vkey)))
}

/// Reject a KES rotation whose opcert issue counter regresses behind the
/// last counter issued from this directory. `cold.counter` carries
/// cardano-cli's issue-counter semantics — the number the NEXT opcert
/// will use (last issued + 1) — so `stored - 1` is the last counter that
/// actually went into a node.cert. The online tool computes `new_counter
/// = on-chain counter + 1` and never consults this file, so the signer is
/// the authority on what it last issued. Two values are accepted:
///
/// * `new_counter >= stored` — a normal advance past the last issue;
/// * `new_counter == stored - 1` — a reissue of the last-issued number.
///   Counter reuse is valid on-chain (the Praos OCERT rule accepts
///   `n == currentIssueNo`), and reissuing with a fresh KES key is the
///   recovery path when a rotation's outputs were lost before deployment:
///   the chain counter never advanced, the online tool suggests the same
///   number again, and refusing it would wedge rotation with no in-tool
///   recovery. The operator-PIN proof already binds the operator to the
///   exact `new_counter` being reissued, so the reissue is explicit.
///
/// Anything lower regresses behind an opcert the chain may already have
/// seen and is refused. With no prior `cold.counter` (first rotation)
/// there is nothing to compare against and the online-tool value is
/// accepted. A `cold.counter` written for a different cold key is
/// rejected outright rather than ignored: it means the rotation is
/// pointed at the wrong directory, and silently bypassing the check
/// would defeat its purpose.
fn assert_counter_monotonic(
    output_dir: &std::path::Path,
    new_counter: u64,
    cold_vkey: &[u8; 32],
) -> Result<(), SignExecuteError> {
    let Some((next_counter, stored_vkey)) = read_existing_cold_counter(output_dir)? else {
        return Ok(());
    };
    if &stored_vkey != cold_vkey {
        return Err(SignExecuteError::OpcertCounter(
            "cold.counter on disk was issued for a different cold key — refusing to rotate against an unrelated counter".into(),
        ));
    }
    if new_counter.saturating_add(1) < next_counter {
        return Err(SignExecuteError::OpcertCounter(format!(
            "new opcert counter {new_counter} regresses behind last issued counter {} — refusing to sign an opcert the chain may already have superseded",
            next_counter - 1
        )));
    }
    if new_counter.saturating_add(1) == next_counter {
        // Reissue of the last-issued number: legitimate recovery, but loud
        // in the logs because a healthy rotation always advances.
        tracing::warn!(
            counter = new_counter,
            "reissuing the last-issued opcert counter with a fresh KES key"
        );
    }
    Ok(())
}

/// Writes the three rotation outputs to `output_dir` as a staged bundle.
/// kes.skey is 0600, node.cert + cold.counter are 0644.
///
/// All three outputs are first written to `.tmp` siblings — named with a
/// per-invocation nonce so two concurrent rotations can never truncate or
/// rename each other's half-staged files — with the
/// final mode applied to the file descriptor (so kes.skey is 0600 from
/// its first byte, never momentarily group/world-readable) and fsync'd
/// individually — before any target path is touched. Only once every
/// output is durably staged are the three renames performed back-to-back,
/// with no compute or I/O between them. rename(2) is atomic per file, so
/// the sole window in which the bundle could be observed half-updated is
/// the few microseconds spanning three consecutive renames. This guards
/// against an orphaned hot key: the new kes.skey never lands without its
/// matching node.cert and cold.counter already staged and about to land.
/// A final directory fsync makes the renames durable so a crash cannot
/// resurrect the pre-rotation bundle.
pub(crate) fn write_kes_outputs(
    output_dir: &std::path::Path,
    kes_skey: &str,
    node_cert: &str,
    cold_counter: &str,
) -> Result<(), SignExecuteError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if !output_dir.is_dir() {
        return Err(SignExecuteError::Encode(format!(
            "output directory does not exist: {}",
            output_dir.display()
        )));
    }

    let writes: &[(&str, &str, u32)] = &[
        ("kes.skey", kes_skey, 0o600),
        ("node.cert", node_cert, 0o644),
        ("cold.counter", cold_counter, 0o644),
    ];

    // Staging names carry a per-invocation nonce (pid + process-wide
    // counter): a fixed `.{name}.tmp` would let two interleaved rotation
    // requests truncate each other's staged bytes between fsync and
    // rename, landing a mixed bundle.
    static STAGING_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        STAGING_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );

    let mut staged: Vec<(std::path::PathBuf, std::path::PathBuf)> =
        Vec::with_capacity(writes.len());
    let result = (|| -> Result<(), SignExecuteError> {
        // Phase 1: stage every output to a `.tmp` sibling with the final
        // mode and fsync it, so all bytes are durably on disk before any
        // target path changes.
        for (name, content, mode) in writes {
            let final_path = output_dir.join(name);
            let tmp_path = output_dir.join(format!(".{name}.{nonce}.tmp"));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(*mode)
                .open(&tmp_path)
                .map_err(|e| SignExecuteError::Encode(format!("open {name}.tmp: {e}")))?;
            // `mode` on OpenOptions only applies when the file is created, so
            // re-assert the permissions on the fd to cover a pre-existing tmp.
            f.set_permissions(std::fs::Permissions::from_mode(*mode))
                .map_err(|e| SignExecuteError::Encode(format!("chmod {name}.tmp: {e}")))?;
            f.write_all(content.as_bytes())
                .map_err(|e| SignExecuteError::Encode(format!("write {name}.tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| SignExecuteError::Encode(format!("fsync {name}.tmp: {e}")))?;
            staged.push((tmp_path, final_path));
        }

        // Phase 2: every output is durably staged — rename them into place
        // back-to-back with nothing in between.
        for (tmp_path, final_path) in &staged {
            std::fs::rename(tmp_path, final_path).map_err(|e| {
                let name = final_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?");
                SignExecuteError::Encode(format!("rename {name}: {e}"))
            })?;
        }
        Ok(())
    })();
    if result.is_err() {
        // Best-effort cleanup: with per-invocation staging names a failed
        // attempt would otherwise accumulate orphaned tmp files. Targets
        // already renamed keep their (complete, fsync'd) content.
        for (tmp_path, _) in &staged {
            let _ = std::fs::remove_file(tmp_path);
        }
        return result;
    }

    // Phase 3: persist the rename metadata so a crash after this point
    // cannot resurrect the pre-rotation bundle. Best-effort: a directory
    // that cannot be fsync'd does not undo the renames already applied.
    if let Ok(dir) = std::fs::File::open(output_dir) {
        let _ = dir.sync_all();
    }

    Ok(())
}

pub(crate) fn rotate_kes_core(
    req: &shared::kes::KesRotationRequest,
    cold_seed: Zeroizing<[u8; 32]>,
    output_dir: &std::path::Path,
) -> Result<shared::kes::KesRotationResult, SignExecuteError> {
    use zeroize::Zeroize;
    let cold_sk = SigningKey::from_bytes(&cold_seed);
    let cold_vkey: [u8; 32] = cold_sk.verifying_key().to_bytes();

    // Bind the configured cold key to the pool this rotation is for, the
    // same check the vote path performs before signing. A cold.skey
    // pointed at the wrong pool (multi-pool operator, mis-copied USB)
    // would otherwise produce a "successful" bundle whose opcert belongs
    // to a different pool — deploying it silently stops block production.
    shared::tx_validator::assert_cold_vkey_matches_pool(&req.pool_id_bech32, &cold_vkey)
        .map_err(|e| SignExecuteError::PoolMismatch(e.to_string()))?;

    // Refuse to issue an opcert whose counter regresses behind the last
    // one issued here (an exact reissue of the last number is allowed as
    // the lost-bundle recovery path). Checked before the KES keygen so a
    // bad counter never spends entropy or touches disk.
    assert_counter_monotonic(output_dir, req.new_counter, &cold_vkey)?;

    // cold.counter stores the counter the NEXT opcert will use, matching
    // cardano-cli's issue-counter file semantics. Guarded here so an
    // absurd counter also fails before the keygen spends entropy.
    let next_counter = req.new_counter.checked_add(1).ok_or_else(|| {
        SignExecuteError::OpcertCounter(format!(
            "new opcert counter {} has no successor — cannot store a next issue number",
            req.new_counter
        ))
    })?;

    // Both `seed` (Sum6Kes seed) and `kes_skey_disk` (the 608-byte
    // serialised KES signing key bytes) are sensitive — wrapped in
    // Zeroizing so the buffer is wiped on drop. The Sum6Kes-internal
    // expansion buffer (`kes_buffer`) is also a Vec<u8> owned here and
    // zeroed explicitly before drop.
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed).map_err(|e| SignExecuteError::Entropy(e.to_string()))?;
    let mut kes_buffer = vec![0u8; Sum6Kes::SIZE + 4];
    let mut kes_skey_disk: Zeroizing<[u8; KES_SKEY_DISK_SIZE]> =
        Zeroizing::new([0u8; KES_SKEY_DISK_SIZE]);
    let kes_vkey: [u8; 32];
    {
        let (sk, pk) = Sum6Kes::keygen(&mut kes_buffer, &mut *seed);
        kes_vkey = pk
            .as_bytes()
            .try_into()
            .map_err(|_| SignExecuteError::Encode("KES public key was not 32 bytes".into()))?;
        kes_skey_disk.copy_from_slice(&sk.as_bytes()[..KES_SKEY_DISK_SIZE]);
    }

    let mut msg = [0u8; 32 + 8 + 8];
    msg[..32].copy_from_slice(&kes_vkey);
    msg[32..40].copy_from_slice(&req.new_counter.to_be_bytes());
    msg[40..48].copy_from_slice(&req.kes_period.to_be_bytes());
    let cold_sig: [u8; 64] = cold_sk.sign(&msg).to_bytes();

    let kes_skey_json = build_kes_skey_envelope(&kes_skey_disk);
    let node_cert_json =
        build_node_cert_envelope(&kes_vkey, req.new_counter, req.kes_period, &cold_sig, &cold_vkey);
    let cold_counter_json = build_cold_counter_envelope(next_counter, &cold_vkey);

    write_kes_outputs(output_dir, &kes_skey_json, &node_cert_json, &cold_counter_json)?;

    // Wipe the Sum6Kes expansion buffer before drop; Vec<u8> does not
    // implement ZeroizeOnDrop, so this is the explicit hook.
    kes_buffer.zeroize();

    Ok(shared::kes::KesRotationResult {
        pool_id_bech32: req.pool_id_bech32.clone(),
        counter: req.new_counter,
        kes_period: req.kes_period,
        kes_vkey_hex: hex::encode(kes_vkey),
        output_dir: output_dir.to_string_lossy().into_owned(),
        kes_skey_filename: "kes.skey".into(),
        node_cert_filename: "node.cert".into(),
        cold_counter_filename: "cold.counter".into(),
    })
}


// ============================================================
// KES rotation (Sum6Kes keygen + opcert sign)
// ============================================================

/// Disk size of a Sum6 KES signing key (cardano-cli kes.skey is exactly
/// this many raw bytes; the in-memory amaru representation is the same
/// 608 bytes plus a 4-byte period suffix that lives in RAM only).
const KES_SKEY_DISK_SIZE: usize = 608;

/// Wrap a 608-byte Sum6 KES signing key in the cardano-cli envelope. The
/// inner cborHex is the 3-byte CBOR header `59 02 60` (byte string of 608)
/// followed by the raw key bytes. cardano-cli does NOT serialise the
/// 4-byte period suffix to disk; that lives in memory only.
///
/// The envelope and the intermediate hex both hold the complete hot
/// signing key, so both live in `Zeroizing` — assembled with `format!`
/// instead of `serde_json::json!` so no unwiped `Value` copy of the key
/// is left behind on the heap (same hygiene as the wallet keygen path).
fn build_kes_skey_envelope(skey: &[u8; KES_SKEY_DISK_SIZE]) -> Zeroizing<String> {
    let skey_hex = Zeroizing::new(hex::encode(skey));
    Zeroizing::new(format!(
        "{{\"type\":\"KesSigningKey_ed25519_kes_2^6\",\"description\":\"KES Signing Key\",\"cborHex\":\"590260{}\"}}",
        *skey_hex
    ))
}

/// Build the node.cert envelope. Outer CBOR is `82` array(2) wrapping
/// `[ OCert , coldVKey ]`. The OCert itself is `84` array(4) =
/// `[ bytes(32) hot_kes_vkey , uint counter , uint period , bytes(64) cold_sig ]`.
fn build_node_cert_envelope(
    kes_vkey: &[u8; 32],
    counter: u64,
    period: u64,
    cold_sig: &[u8; 64],
    cold_vkey: &[u8; 32],
) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut buf);
    enc.array(2).unwrap();
    enc.array(4).unwrap();
    enc.bytes(kes_vkey).unwrap();
    enc.u64(counter).unwrap();
    enc.u64(period).unwrap();
    enc.bytes(cold_sig).unwrap();
    enc.bytes(cold_vkey).unwrap();
    serde_json::json!({
        "type": "NodeOperationalCertificate",
        "description": "",
        "cborHex": hex::encode(&buf),
    })
    .to_string()
}

/// Build the cold.counter envelope. Inner CBOR is `82` array(2) =
/// `[ uint next_counter , bytes(32) cold_vkey ]`. Both the CBOR value and
/// the description carry cardano-cli's issue-counter semantics — the
/// counter the NEXT opcert will use, i.e. last issued + 1 — so
/// `cardano-cli node issue-op-cert` can consume the file directly without
/// reissuing a duplicate number, and a counter file written by cardano-cli
/// reads back into this tool without an off-by-one.
fn build_cold_counter_envelope(next_counter: u64, cold_vkey: &[u8; 32]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut buf);
    enc.array(2).unwrap();
    enc.u64(next_counter).unwrap();
    enc.bytes(cold_vkey).unwrap();
    serde_json::json!({
        "type": "NodeOperationalCertificateIssueCounter",
        "description": format!("Next certificate issue number: {next_counter}"),
        "cborHex": hex::encode(&buf),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_material_signs_and_verifies() {
        use pallas_crypto::key::ed25519::{PublicKey, SecretKeyExtended, Signature};
        // Build a structurally-valid extended secret (apply the BIP32 clamp).
        let mut esk = [7u8; 64];
        esk[0] &= 0b1111_1000;
        esk[31] &= 0b0011_1111;
        esk[31] |= 0b0100_0000;
        let sk = SecretKeyExtended::from_bytes(esk).expect("valid structure");
        let pk: PublicKey = sk.public_key();
        let mut pubkey_32 = [0u8; 32];
        pubkey_32.copy_from_slice(pk.as_ref());

        let material = extended_material(esk, pubkey_32).expect("integrity check passes");
        let body_hash = [0x42u8; 32];
        let w = build_vkey_witness(shared::witness::WitnessRole::Payment, &material, &body_hash)
            .expect("sign");

        // vkey is the derived public key, and the signature verifies under it.
        assert_eq!(w.vkey_hex, hex::encode(pk.as_ref()));
        let sig_bytes = hex::decode(&w.signature_hex).unwrap();
        let sig = Signature::try_from(sig_bytes.as_slice()).unwrap();
        assert!(pk.verify(body_hash, &sig));
    }

    #[test]
    fn extended_material_rejects_pubkey_mismatch() {
        let mut esk = [9u8; 64];
        esk[0] &= 0b1111_1000;
        esk[31] &= 0b0011_1111;
        esk[31] |= 0b0100_0000;
        // Embedded pubkey does not match the derived one -> rejected.
        // (SigningKeyMaterial intentionally has no Debug impl — it holds
        // secret key bytes — so match on the Result directly.)
        let result = extended_material(esk, [0u8; 32]);
        assert!(matches!(result, Err(SignExecuteError::WrongRole(_))));
    }

    #[test]
    fn kes_skey_envelope_has_correct_prefix_and_size() {
        let skey = [0xAAu8; KES_SKEY_DISK_SIZE];
        let env = build_kes_skey_envelope(&skey);
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert_eq!(v["type"], "KesSigningKey_ed25519_kes_2^6");
        assert_eq!(v["description"], "KES Signing Key");
        let cbor_hex = v["cborHex"].as_str().unwrap();
        assert!(cbor_hex.starts_with("590260"), "prefix wrong: {}", &cbor_hex[..10]);
        // 3 prefix bytes + 608 payload bytes = 611 bytes = 1222 hex chars.
        assert_eq!(cbor_hex.len(), 1222);
    }

    #[test]
    fn node_cert_envelope_layout_matches_spec() {
        let kes_vkey = [0x11u8; 32];
        let cold_sig = [0x22u8; 64];
        let cold_vkey = [0x33u8; 32];
        let env = build_node_cert_envelope(&kes_vkey, 7, 1180, &cold_sig, &cold_vkey);
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert_eq!(v["type"], "NodeOperationalCertificate");
        assert_eq!(v["description"], "");
        let cbor = hex::decode(v["cborHex"].as_str().unwrap()).unwrap();
        // Outer 82 = array(2), inner 84 = array(4), then 5820 (bytes 32) kes_vkey ...
        assert_eq!(cbor[0], 0x82);
        assert_eq!(cbor[1], 0x84);
        assert_eq!(&cbor[2..4], &[0x58, 0x20]);
        assert_eq!(&cbor[4..36], &kes_vkey);
        // Counter 7 fits in a single CBOR uint byte (major 0).
        assert_eq!(cbor[36], 0x07);
        // Period 1180 = 0x049C → encoded as 19 04 9C (uint, 16-bit length).
        assert_eq!(&cbor[37..40], &[0x19, 0x04, 0x9C]);
        // Cold sig bytes(64): 5840 ...
        assert_eq!(&cbor[40..42], &[0x58, 0x40]);
        assert_eq!(&cbor[42..106], &cold_sig);
        // Cold vkey bytes(32): 5820 ...
        assert_eq!(&cbor[106..108], &[0x58, 0x20]);
        assert_eq!(&cbor[108..140], &cold_vkey);
        assert_eq!(cbor.len(), 140);
    }

    #[test]
    fn cold_counter_envelope_layout_matches_spec() {
        let cold_vkey = [0x44u8; 32];
        let env = build_cold_counter_envelope(5, &cold_vkey);
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert_eq!(v["type"], "NodeOperationalCertificateIssueCounter");
        assert_eq!(v["description"], "Next certificate issue number: 5");
        let cbor = hex::decode(v["cborHex"].as_str().unwrap()).unwrap();
        // 82 = array(2), 05 = uint 5 (single byte), 5820 = bytes(32) ...
        assert_eq!(cbor[0], 0x82);
        assert_eq!(cbor[1], 0x05);
        assert_eq!(&cbor[2..4], &[0x58, 0x20]);
        assert_eq!(&cbor[4..36], &cold_vkey);
        assert_eq!(cbor.len(), 36);
    }

    #[test]
    fn read_existing_cold_counter_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let vkey = [0x55u8; 32];
        std::fs::write(
            dir.path().join("cold.counter"),
            build_cold_counter_envelope(42, &vkey),
        )
        .unwrap();
        assert_eq!(
            read_existing_cold_counter(dir.path()).unwrap(),
            Some((42, vkey))
        );
    }

    #[test]
    fn counter_monotonic_accepts_when_no_prior_counter() {
        let dir = tempfile::tempdir().unwrap();
        // First rotation: empty directory, nothing to compare against.
        assert!(assert_counter_monotonic(dir.path(), 1, &[0x01u8; 32]).is_ok());
    }

    #[test]
    fn counter_monotonic_accepts_advance() {
        let dir = tempfile::tempdir().unwrap();
        let vkey = [0x42u8; 32];
        // After issuing 7 the file holds next = 8 (cardano-cli semantics);
        // the normal next rotation issues 8, and skipping ahead is fine too.
        std::fs::write(
            dir.path().join("cold.counter"),
            build_cold_counter_envelope(8, &vkey),
        )
        .unwrap();
        assert!(assert_counter_monotonic(dir.path(), 8, &vkey).is_ok());
        assert!(assert_counter_monotonic(dir.path(), 9, &vkey).is_ok());
    }

    #[test]
    fn counter_monotonic_accepts_reissue_of_last_issued() {
        let dir = tempfile::tempdir().unwrap();
        let vkey = [0x42u8; 32];
        // File holds next = 8 (last issued 7). A rotation whose outputs
        // were lost before deployment reissues 7 with a fresh KES key —
        // the chain counter never advanced, so this must be allowed.
        std::fs::write(
            dir.path().join("cold.counter"),
            build_cold_counter_envelope(8, &vkey),
        )
        .unwrap();
        assert!(assert_counter_monotonic(dir.path(), 7, &vkey).is_ok());
    }

    #[test]
    fn counter_monotonic_rejects_regression() {
        let dir = tempfile::tempdir().unwrap();
        let vkey = [0x42u8; 32];
        // File holds next = 8 (last issued 7): 6 and below regress behind
        // an opcert the chain may already have seen.
        std::fs::write(
            dir.path().join("cold.counter"),
            build_cold_counter_envelope(8, &vkey),
        )
        .unwrap();
        assert!(matches!(
            assert_counter_monotonic(dir.path(), 6, &vkey),
            Err(SignExecuteError::OpcertCounter(_))
        ));
        assert!(matches!(
            assert_counter_monotonic(dir.path(), 0, &vkey),
            Err(SignExecuteError::OpcertCounter(_))
        ));
    }

    #[test]
    fn counter_monotonic_accepts_fresh_cli_counter_file() {
        let dir = tempfile::tempdir().unwrap();
        let vkey = [0x42u8; 32];
        // `cardano-cli node key-gen` writes next = 0 for a never-issued
        // cold key; the first opcert then issues 0.
        std::fs::write(
            dir.path().join("cold.counter"),
            build_cold_counter_envelope(0, &vkey),
        )
        .unwrap();
        assert!(assert_counter_monotonic(dir.path(), 0, &vkey).is_ok());
    }

    #[test]
    fn counter_monotonic_rejects_foreign_cold_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("cold.counter"),
            build_cold_counter_envelope(7, &[0x11u8; 32]),
        )
        .unwrap();
        // Counter would advance, but the stored counter belongs to a
        // different cold vkey -> rejected, not silently accepted.
        assert!(matches!(
            assert_counter_monotonic(dir.path(), 8, &[0x22u8; 32]),
            Err(SignExecuteError::OpcertCounter(_))
        ));
    }

    #[test]
    fn write_kes_outputs_stages_all_three_with_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        write_kes_outputs(dir.path(), "KES", "CERT", "COUNTER").unwrap();
        for (name, want_mode, want) in [
            ("kes.skey", 0o600u32, "KES"),
            ("node.cert", 0o644, "CERT"),
            ("cold.counter", 0o644, "COUNTER"),
        ] {
            let p = dir.path().join(name);
            assert_eq!(std::fs::read_to_string(&p).unwrap(), want, "{name} content");
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, want_mode, "{name} mode");
        }
        // No staging files survive a successful bundle write (staging
        // names carry a per-invocation nonce, so scan for any `.tmp`).
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy().into_owned();
            assert!(!name.ends_with(".tmp"), "staging file leaked: {name}");
        }
    }

    #[test]
    fn write_kes_outputs_replaces_stale_bundle_and_leftover_tmp() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // Stale bundle plus a crashed predecessor's staging leftover at the
        // default (looser) mode. Per-invocation staging names mean the new
        // write neither reuses nor disturbs the leftover, and the replaced
        // kes.skey must still land 0600.
        std::fs::write(dir.path().join("kes.skey"), "OLD").unwrap();
        std::fs::write(dir.path().join(".kes.skey.tmp"), "LEFTOVER").unwrap();
        write_kes_outputs(dir.path(), "NEW", "CERT", "COUNTER").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("kes.skey")).unwrap(),
            "NEW"
        );
        let mode = std::fs::metadata(dir.path().join("kes.skey"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "replaced kes.skey must be 0600");
        // The foreign leftover is not this invocation's staging file:
        // it must never be renamed over a bundle target.
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".kes.skey.tmp")).unwrap(),
            "LEFTOVER"
        );
    }

    /// Deterministic cold seed with its precomputed pool id: bech32
    /// ("pool") of blake2b-224 over the Ed25519 verification key derived
    /// from the seed — the same derivation `assert_cold_vkey_matches_pool`
    /// re-checks at rotation time.
    const TEST_COLD_SEED: [u8; 32] = [7u8; 32];
    const TEST_POOL_ID: &str = "pool13vscgf9dwn0jt56u965wp99ychz6avktk3pyrye326f3xctz4nm";

    fn kes_request(pool_id: &str, new_counter: u64) -> shared::kes::KesRotationRequest {
        shared::kes::KesRotationRequest {
            kind: shared::wire_kind::WireKind::KesRotation,
            pool_id_bech32: pool_id.into(),
            new_counter,
            kes_period: 1180,
            operator_pin_proof: String::new(),
            chain_context: shared::chain_context::ChainContext {
                current_epoch: 100,
                current_slot: 1_000_000,
                current_kes_period: 1180,
                epoch_ends_at_unix: 0,
                opcert_expires_at_unix: None,
                built_at_unix: 0,
            },
        }
    }

    #[test]
    fn rotate_writes_next_issue_counter_with_cli_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let result = rotate_kes_core(
            &kes_request(TEST_POOL_ID, 7),
            Zeroizing::new(TEST_COLD_SEED),
            dir.path(),
        )
        .expect("rotation succeeds");
        assert_eq!(result.counter, 7, "result echoes the issued counter");
        // cold.counter stores the NEXT issue number (cardano-cli
        // semantics), not the counter just embedded in node.cert.
        let cold_vkey = SigningKey::from_bytes(&TEST_COLD_SEED)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            read_existing_cold_counter(dir.path()).unwrap(),
            Some((8, cold_vkey))
        );
    }

    #[test]
    fn rotate_allows_reissue_after_lost_bundle() {
        // A rotation issuing 7 lands, but its outputs are lost before
        // deployment; the chain still shows 6, so the online tool suggests
        // 7 again. The reissue must succeed (fresh KES key, same issue
        // number — valid per the on-chain OCERT rule), while regressing
        // behind the last issue stays rejected.
        let dir = tempfile::tempdir().unwrap();
        rotate_kes_core(
            &kes_request(TEST_POOL_ID, 7),
            Zeroizing::new(TEST_COLD_SEED),
            dir.path(),
        )
        .expect("first rotation");
        rotate_kes_core(
            &kes_request(TEST_POOL_ID, 7),
            Zeroizing::new(TEST_COLD_SEED),
            dir.path(),
        )
        .expect("reissue of the last-issued counter");
        assert!(matches!(
            rotate_kes_core(
                &kes_request(TEST_POOL_ID, 6),
                Zeroizing::new(TEST_COLD_SEED),
                dir.path(),
            ),
            Err(SignExecuteError::OpcertCounter(_))
        ));
    }

    #[test]
    fn rotate_rejects_cold_key_for_wrong_pool() {
        let dir = tempfile::tempdir().unwrap();
        // The all-zeros pool id is not the hash of this cold key.
        let req = kes_request(
            "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d",
            1,
        );
        assert!(matches!(
            rotate_kes_core(&req, Zeroizing::new(TEST_COLD_SEED), dir.path()),
            Err(SignExecuteError::PoolMismatch(_))
        ));
        // The identity check fires before keygen or disk I/O, so no
        // partial bundle is left behind.
        for name in ["kes.skey", "node.cert", "cold.counter"] {
            assert!(!dir.path().join(name).exists(), "{name} must not exist");
        }
    }

    fn witness_ctx() -> shared::chain_context::ChainContext {
        shared::chain_context::ChainContext {
            current_epoch: 100,
            current_slot: 1_000_000,
            current_kes_period: 1180,
            epoch_ends_at_unix: 0,
            opcert_expires_at_unix: None,
            built_at_unix: 0,
        }
    }

    #[test]
    fn witness_over_canonical_body_verifies_and_binds_pool() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let body = "_:c14n0 <https://example.com/#body> _:c14n1 .\n_:c14n1 <https://example.com/#comment> \"hi\"@en-us .\n";
        let req = shared::witness_doc::SpoWitnessRequest {
            kind: shared::wire_kind::WireKind::WitnessDoc,
            canonical_body: body.to_string(),
            pool_id_bech32: TEST_POOL_ID.into(),
            operator_pin_proof: "0".repeat(16),
            chain_context: witness_ctx(),
        };
        let res = sign_witness_core(&req, Zeroizing::new(TEST_COLD_SEED)).expect("signs witness");
        assert_eq!(res.witness.witness_algorithm, "ed25519");
        let cold_vkey = SigningKey::from_bytes(&TEST_COLD_SEED).verifying_key().to_bytes();
        assert_eq!(res.witness.public_key_hex, hex::encode(cold_vkey));
        let hash = shared::validate::blake2b256(body.as_bytes());
        let vk = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(hex::decode(&res.witness.public_key_hex).unwrap()).unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&hex::decode(&res.witness.signature_hex).unwrap()).unwrap();
        vk.verify(&hash, &sig).expect("witness verifies over body hash");
    }

    #[test]
    fn witness_rejects_non_canonical_body() {
        let req = shared::witness_doc::SpoWitnessRequest {
            kind: shared::wire_kind::WireKind::WitnessDoc,
            canonical_body: "this is not n-quads .\n".to_string(),
            pool_id_bech32: TEST_POOL_ID.into(),
            operator_pin_proof: "0".repeat(16),
            chain_context: witness_ctx(),
        };
        assert!(sign_witness_core(&req, Zeroizing::new(TEST_COLD_SEED)).is_err());
    }

    #[test]
    fn witness_rejects_wrong_cold_key() {
        let body = "_:c14n0 <https://example.com/#body> _:c14n1 .\n";
        let req = shared::witness_doc::SpoWitnessRequest {
            kind: shared::wire_kind::WireKind::WitnessDoc,
            canonical_body: body.to_string(),
            pool_id_bech32: TEST_POOL_ID.into(),
            operator_pin_proof: "0".repeat(16),
            chain_context: witness_ctx(),
        };
        assert!(sign_witness_core(&req, Zeroizing::new([0xEEu8; 32])).is_err());
    }
}