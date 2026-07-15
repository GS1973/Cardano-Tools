//! Pure-compute signing helpers for the four DRep operations.
//!
//! Path-sourced signing keys (payment + DRep) are loaded once and consumed.
//! Each `sign_*_core` re-validates the body against its request, binds the
//! DRep verification key to the request's DRep id, hashes the body, and
//! returns Payment + DRep vkey witnesses. Nothing here writes config or
//! touches the network. Errors flow through `SignExecuteError` which has a
//! central `impl From<_> for ErrorEnvelope` for the HTTP layer.

use ed25519_dalek::{Signer, SigningKey};
use pallas_crypto::key::ed25519::SecretKeyExtended;
use shared::error::ErrorEnvelope;
use shared::witness::{DrepWitnessRole, VkeyWitness};
use tracing::debug;
use zeroize::Zeroizing;

/// Signing-key material the core signers consume. Plain keys are standard
/// 32-byte Ed25519 seeds; extended keys are BIP32-Ed25519 (kL‖kR) from a
/// converted mnemonic wallet, signed scalar-based.
pub(crate) enum SigningKeyMaterial {
    Plain(Zeroizing<[u8; 32]>),
    Extended {
        esk: Zeroizing<[u8; 64]>,
        /// Public key embedded in the skey envelope; the loader verified
        /// it equals the key derived from `esk`.
        expected_pubkey: [u8; 32],
    },
}

impl SigningKeyMaterial {
    /// The 32-byte Ed25519 verification key this material signs under.
    fn verifying_key(&self) -> Result<[u8; 32], SignExecuteError> {
        match self {
            SigningKeyMaterial::Plain(seed) => {
                Ok(SigningKey::from_bytes(seed).verifying_key().to_bytes())
            }
            SigningKeyMaterial::Extended { esk, expected_pubkey } => {
                let sk = SecretKeyExtended::from_bytes(**esk).map_err(|_| {
                    SignExecuteError::WrongRole(
                        "extended key failed Ed25519-BIP32 structure check".into(),
                    )
                })?;
                let derived = sk.public_key();
                if derived.as_ref() != expected_pubkey.as_slice() {
                    return Err(SignExecuteError::WrongRole("extended key public-key drift".into()));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(derived.as_ref());
                Ok(out)
            }
        }
    }
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
            SignExecuteError::DrepNotConfigured | SignExecuteError::PaymentNotConfigured => {
                ErrorEnvelope::not_configured(msg)
            }
            SignExecuteError::BodyValidation(_) | SignExecuteError::BadCborHex(_) => {
                tracing::warn!(detail = %msg, "rejecting request as invalid");
                ErrorEnvelope::invalid("invalid request payload")
            }
            SignExecuteError::WrongRole(_) => ErrorEnvelope::invalid("configured key has wrong role"),
            SignExecuteError::LoadDrep { source, .. }
            | SignExecuteError::LoadPayment { source, .. } => {
                tracing::error!(error = %source, "key load failed");
                ErrorEnvelope::internal("key load failed")
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SignExecuteError {
    #[error("DRep signing key path not configured — visit Setup")]
    DrepNotConfigured,
    #[error("payment signing key path not configured — visit Setup")]
    PaymentNotConfigured,
    #[error("could not load DRep key from {path}: {source}")]
    LoadDrep { path: String, source: Box<dyn std::error::Error + Send + Sync> },
    #[error("could not load payment key from {path}: {source}")]
    LoadPayment { path: String, source: Box<dyn std::error::Error + Send + Sync> },
    #[error("tx body does not match request: {0}")]
    BodyValidation(String),
    #[error("tx body cbor hex is invalid: {0}")]
    BadCborHex(String),
    #[error("key file is not the expected role: {0}")]
    WrongRole(String),
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
            "expected payment key, got {other:?}"
        ))),
    }
}

pub(crate) fn load_drep_material_from_path(
    path: &std::path::Path,
) -> Result<SigningKeyMaterial, SignExecuteError> {
    let key = shared::cardano_keys::load_skey(path).map_err(|e| SignExecuteError::LoadDrep {
        path: path.display().to_string(),
        source: Box::new(e),
    })?;
    match key {
        shared::cardano_keys::CardanoKey::DRep { seed_32 } => {
            let sk = SigningKey::from_bytes(&seed_32);
            use sha2::{Digest, Sha256};
            let fp = hex::encode(&Sha256::digest(sk.verifying_key().to_bytes())[..4]);
            debug!(fingerprint = %fp, "loaded DRep skey");
            Ok(SigningKeyMaterial::Plain(Zeroizing::new(seed_32)))
        }
        shared::cardano_keys::CardanoKey::DRepExtended { esk_64, pubkey_32 } => {
            extended_material(esk_64, pubkey_32)
        }
        other => Err(SignExecuteError::WrongRole(format!(
            "expected DRep key, got {other:?}"
        ))),
    }
}

/// Sign `body_hash` with `material` and wrap as a `VkeyWitness` tagged with
/// `role`.
fn build_vkey_witness(
    role: DrepWitnessRole,
    material: &SigningKeyMaterial,
    body_hash: &[u8; 32],
) -> Result<VkeyWitness, SignExecuteError> {
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
            let sk = SecretKeyExtended::from_bytes(**esk).map_err(|_| {
                SignExecuteError::WrongRole(
                    "extended key failed Ed25519-BIP32 structure check".into(),
                )
            })?;
            let derived = sk.public_key();
            if derived.as_ref() != expected_pubkey.as_slice() {
                return Err(SignExecuteError::WrongRole("extended key public-key drift".into()));
            }
            let sig = sk.sign(body_hash);
            (hex::encode(derived.as_ref()), hex::encode(sig.as_ref()))
        }
    };
    Ok(VkeyWitness { role, vkey_hex, signature_hex })
}

fn body_hash_of(cbor_hex: &str) -> Result<(Vec<u8>, [u8; 32]), SignExecuteError> {
    use blake2::digest::{Update, VariableOutput};
    let body_bytes = hex::decode(cbor_hex).map_err(|e| SignExecuteError::BadCborHex(e.to_string()))?;
    let mut hasher = blake2::Blake2bVar::new(32).expect("blake2b 256 init");
    hasher.update(&body_bytes);
    let mut body_hash = [0u8; 32];
    hasher.finalize_variable(&mut body_hash).expect("blake2b 256 fin");
    Ok((body_bytes, body_hash))
}

/// Common signing tail: bind the DRep key to the request's DRep id, hash
/// the (already-validated) body, and produce Payment + DRep witnesses.
fn sign_with_drep_binding(
    body_hash: &[u8; 32],
    drep_id_bech32: &str,
    payment_material: &SigningKeyMaterial,
    drep_material: &SigningKeyMaterial,
) -> Result<(String, Vec<VkeyWitness>), SignExecuteError> {
    let drep_vkey = drep_material.verifying_key()?;
    shared::tx_validator::assert_drep_vkey_matches_id(drep_id_bech32, &drep_vkey)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let witnesses = vec![
        build_vkey_witness(DrepWitnessRole::Payment, payment_material, body_hash)?,
        build_vkey_witness(DrepWitnessRole::Drep, drep_material, body_hash)?,
    ];
    Ok((hex::encode(body_hash), witnesses))
}

pub(crate) fn sign_register_core(
    req: &shared::register::DRepRegisterRequest,
    payment_material: SigningKeyMaterial,
    drep_material: SigningKeyMaterial,
) -> Result<shared::register::DRepRegisterResult, SignExecuteError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_register_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let (body_hash_hex, witnesses) = sign_with_drep_binding(
        &body_hash,
        &req.drep_id_bech32,
        &payment_material,
        &drep_material,
    )?;
    Ok(shared::register::DRepRegisterResult { body_hash_hex, witnesses })
}

pub(crate) fn sign_update_core(
    req: &shared::update::DRepUpdateRequest,
    payment_material: SigningKeyMaterial,
    drep_material: SigningKeyMaterial,
) -> Result<shared::update::DRepUpdateResult, SignExecuteError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_update_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let (body_hash_hex, witnesses) = sign_with_drep_binding(
        &body_hash,
        &req.drep_id_bech32,
        &payment_material,
        &drep_material,
    )?;
    Ok(shared::update::DRepUpdateResult { body_hash_hex, witnesses })
}

pub(crate) fn sign_retire_core(
    req: &shared::retire::DRepRetireRequest,
    payment_material: SigningKeyMaterial,
    drep_material: SigningKeyMaterial,
) -> Result<shared::retire::DRepRetireResult, SignExecuteError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_retire_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let (body_hash_hex, witnesses) = sign_with_drep_binding(
        &body_hash,
        &req.drep_id_bech32,
        &payment_material,
        &drep_material,
    )?;
    Ok(shared::retire::DRepRetireResult { body_hash_hex, witnesses })
}

pub(crate) fn sign_vote_core(
    req: &shared::vote::DRepVoteRequest,
    payment_material: SigningKeyMaterial,
    drep_material: SigningKeyMaterial,
) -> Result<shared::vote::DRepVoteResult, SignExecuteError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_vote_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let (body_hash_hex, witnesses) = sign_with_drep_binding(
        &body_hash,
        &req.drep_id_bech32,
        &payment_material,
        &drep_material,
    )?;
    Ok(shared::vote::DRepVoteResult { body_hash_hex, witnesses })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use pallas_codec::minicbor;
    use pallas_codec::utils::{Bytes, NonEmptySet, Set};
    use pallas_primitives::conway::{
        Certificate, PseudoTransactionOutput, TransactionBody, TransactionInput, Value,
    };
    use pallas_primitives::{Hash, NetworkId, StakeCredential};
    use shared::chain_context::ChainContext;
    use shared::register::DRepRegisterRequest;
    use shared::utxo::UtxoInput;
    use shared::wire_kind::DrepWireKind;

    const PAYMENT: &str = "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw";
    const DEPOSIT: u64 = 500_000_000;
    const FEE: u64 = 200_000;
    const TTL: u64 = 2_000_000;
    const CHANGE: u64 = 99_800_000;

    fn vkey_of(seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn drep_id_for(seed: &[u8; 32]) -> (String, [u8; 28]) {
        let keyhash = shared::validate::blake2b224(&vkey_of(seed));
        let mut data = vec![0x22u8];
        data.extend_from_slice(&keyhash);
        let hrp = bech32::Hrp::parse("drep").unwrap();
        (bech32::encode::<bech32::Bech32>(hrp, &data).unwrap(), keyhash)
    }

    fn register_body(keyhash: [u8; 28]) -> Vec<u8> {
        let addr = pallas_addresses::Address::from_bech32(PAYMENT).unwrap();
        let out = PseudoTransactionOutput::PostAlonzo(
            pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(addr.to_vec()),
                value: Value::Coin(CHANGE),
                datum_option: None,
                script_ref: None,
            },
        );
        let cert = Certificate::RegDRepCert(
            StakeCredential::AddrKeyhash(Hash::from(keyhash)),
            DEPOSIT,
            pallas_codec::utils::Nullable::Null,
        );
        let body = TransactionBody {
            inputs: Set::from(vec![TransactionInput {
                transaction_id: Hash::from([0u8; 32]),
                index: 0,
            }]),
            outputs: vec![out],
            fee: FEE,
            ttl: Some(TTL),
            certificates: Some(NonEmptySet::try_from(vec![cert]).unwrap()),
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
        let mut buf = Vec::new();
        minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    fn register_req(drep_id: String, body_cbor: &[u8]) -> DRepRegisterRequest {
        DRepRegisterRequest {
            kind: DrepWireKind::DrepRegister,
            tx_body_cbor_hex: hex::encode(body_cbor),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE,
            deposit_lovelace: DEPOSIT,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT.into(),
            drep_id_bech32: drep_id,
            anchor: None,
            inputs: vec![UtxoInput {
                tx_hash_hex: "00".repeat(32),
                tx_index: 0,
                amount_lovelace: CHANGE + FEE + DEPOSIT,
                address_bech32: PAYMENT.into(),
            }],
            operator_pin_proof: "0".repeat(16),
            chain_context: ChainContext {
                current_epoch: 1,
                current_slot: 100,
                current_kes_period: 0,
                epoch_ends_at_unix: 0,
                opcert_expires_at_unix: None,
                built_at_unix: 0,
            },
        }
    }

    fn plain(seed: [u8; 32]) -> SigningKeyMaterial {
        SigningKeyMaterial::Plain(Zeroizing::new(seed))
    }

    #[test]
    fn register_signs_and_witnesses_verify() {
        let drep_seed = [7u8; 32];
        let payment_seed = [9u8; 32];
        let (drep_id, keyhash) = drep_id_for(&drep_seed);
        let body = register_body(keyhash);
        let req = register_req(drep_id, &body);

        let res = sign_register_core(&req, plain(payment_seed), plain(drep_seed)).expect("signs");
        assert_eq!(res.witnesses.len(), 2);

        let body_hash = hex::decode(&res.body_hash_hex).unwrap();
        for w in &res.witnesses {
            let vk = VerifyingKey::from_bytes(
                &<[u8; 32]>::try_from(hex::decode(&w.vkey_hex).unwrap()).unwrap(),
            )
            .unwrap();
            let sig = Signature::from_slice(&hex::decode(&w.signature_hex).unwrap()).unwrap();
            vk.verify(&body_hash, &sig).expect("witness signature verifies over body hash");
        }
        // The DRep witness must be signed by the DRep key, the payment
        // witness by the payment key.
        let drep_w = res.witnesses.iter().find(|w| matches!(w.role, DrepWitnessRole::Drep)).unwrap();
        assert_eq!(drep_w.vkey_hex, hex::encode(vkey_of(&drep_seed)));
        let pay_w = res.witnesses.iter().find(|w| matches!(w.role, DrepWitnessRole::Payment)).unwrap();
        assert_eq!(pay_w.vkey_hex, hex::encode(vkey_of(&payment_seed)));
    }

    #[test]
    fn rejects_signing_with_mismatched_drep_key() {
        // Body + request agree on a DRep id derived from drep_seed, but the
        // loaded DRep material is a different key. validate_register_body
        // passes; assert_drep_vkey_matches_id must refuse before signing.
        let drep_seed = [7u8; 32];
        let (drep_id, keyhash) = drep_id_for(&drep_seed);
        let body = register_body(keyhash);
        let req = register_req(drep_id, &body);
        let wrong_drep = [0xAAu8; 32];
        let err = sign_register_core(&req, plain([9u8; 32]), plain(wrong_drep)).unwrap_err();
        assert!(matches!(err, SignExecuteError::BodyValidation(_)));
    }

    #[test]
    fn loads_drep_and_payment_keys_by_role() {
        use std::io::Write;
        fn write_skey(ty: &str, payload_hex: &str) -> tempfile::NamedTempFile {
            let json = format!(
                r#"{{"type":"{ty}","description":"x","cborHex":"5820{payload_hex}"}}"#
            );
            let mut f = tempfile::NamedTempFile::new().unwrap();
            f.write_all(json.as_bytes()).unwrap();
            // load_skey requires mode 0600.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
            f
        }
        let drep = write_skey("DRepSigningKey_ed25519", &"11".repeat(32));
        load_drep_material_from_path(drep.path()).expect("loads DRep key");
        let pay = write_skey("PaymentSigningKeyShelley_ed25519", &"22".repeat(32));
        load_payment_material_from_path(pay.path()).expect("loads payment key");
        // A payment key in the DRep slot is rejected.
        assert!(load_drep_material_from_path(pay.path()).is_err());
    }
}
