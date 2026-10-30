//! Pure-compute signing helpers for the four DRep operations.
//!
//! Path-sourced signing keys (payment + DRep) are loaded once and consumed.
//! Each `sign_*_core` re-validates the body against its request, binds the
//! DRep verification key to the request's DRep id, hashes the body, and
//! returns Payment + DRep vkey witnesses. Nothing here writes config or
//! touches the network. Errors flow through `SignExecuteError` which has a
//! central `impl From<_> for ErrorEnvelope` for the HTTP layer.

use ed25519_dalek::SigningKey;
use shared::error::ErrorEnvelope;
use shared::witness::{DrepWitnessRole, VkeyWitness};
use tracing::debug;
use zeroize::Zeroizing;

pub(crate) use shared::signing::SigningKeyMaterial;

impl From<shared::signing::MaterialError> for SignExecuteError {
    fn from(e: shared::signing::MaterialError) -> Self {
        SignExecuteError::WrongRole(e.to_string())
    }
}

/// Validate an extended (BIP32-Ed25519) key and wrap it as signing
/// material (`SigningKeyMaterial::extended` in airgap-core).
fn extended_material(
    esk_64: [u8; 64],
    pubkey_32: [u8; 32],
) -> Result<SigningKeyMaterial, SignExecuteError> {
    Ok(SigningKeyMaterial::extended(esk_64, pubkey_32)?)
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
            SignExecuteError::WrongRole(_) => {
                ErrorEnvelope::invalid("configured key has wrong role")
            }
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
    #[error("DRep signing key path not configured. Visit Setup")]
    DrepNotConfigured,
    #[error("payment signing key path not configured. Visit Setup")]
    PaymentNotConfigured,
    #[error("could not load DRep key from {path}: {source}")]
    LoadDrep {
        path: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("could not load payment key from {path}: {source}")]
    LoadPayment {
        path: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("tx body does not match request: {0}")]
    BodyValidation(String),
    #[error("tx body cbor hex is invalid: {0}")]
    BadCborHex(String),
    #[error("key file is not the expected role: {0}")]
    WrongRole(String),
}

/// A key-load failure as the signing path carries and logs it: the same
/// redacted description Setup shows, never the raw loader error (which can
/// quote file content).
fn redacted(e: &shared::cardano_keys::KeyLoadError) -> Box<dyn std::error::Error + Send + Sync> {
    crate::validate::friendly_error(e).into()
}

pub(crate) fn load_payment_material_from_path(
    path: &std::path::Path,
) -> Result<SigningKeyMaterial, SignExecuteError> {
    let key = shared::cardano_keys::load_skey(path).map_err(|e| SignExecuteError::LoadPayment {
        path: path.display().to_string(),
        source: redacted(&e),
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
        source: redacted(&e),
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
    let (vkey, sig) = material.sign(body_hash)?;
    let (vkey_hex, signature_hex) = (hex::encode(vkey), hex::encode(sig));
    Ok(VkeyWitness {
        role,
        vkey_hex,
        signature_hex,
    })
}

/// Sign a 32-byte payload hash with `material`, returning (vkey, signature).
/// Shared by the transaction witnesses and the CIP-100 rationale witness.
fn sign_hash(
    material: &SigningKeyMaterial,
    hash: &[u8; 32],
) -> Result<([u8; 32], [u8; 64]), SignExecuteError> {
    Ok(material.sign(hash)?)
}

/// Produce a CIP-100 author witness over a governance-metadata canonical
/// body. Refuses unless the payload is a canonical N-Quads body (never a
/// transaction body) and the DRep key hashes to the request's DRep id, so
/// the witness publicKey is verifiably the operator's DRep.
pub(crate) fn sign_witness_core(
    req: &shared::witness_doc::DRepWitnessRequest,
    drep_material: SigningKeyMaterial,
) -> Result<shared::witness_doc::DRepWitnessResult, SignExecuteError> {
    let body_hash = check_witness_body(req)?;
    let drep_vkey = drep_material.verifying_key()?;
    shared::tx_validator::assert_drep_vkey_matches_id(&req.drep_id_bech32, &drep_vkey)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let (vkey, sig) = sign_hash(&drep_material, &body_hash)?;
    Ok(shared::witness_doc::DRepWitnessResult {
        body_hash_hex: hex::encode(body_hash),
        witness: shared::witness_doc::Cip100Witness {
            witness_algorithm: "ed25519".to_string(),
            public_key_hex: hex::encode(vkey),
            signature_hex: hex::encode(sig),
        },
    })
}

fn body_hash_of(cbor_hex: &str) -> Result<(Vec<u8>, [u8; 32]), SignExecuteError> {
    let body_bytes =
        hex::decode(cbor_hex).map_err(|e| SignExecuteError::BadCborHex(e.to_string()))?;
    let body_hash = shared::validate::blake2b256(&body_bytes);
    Ok((body_bytes, body_hash))
}

/// Common signing tail: bind the DRep key to the request's DRep id and the
/// payment key to the request's payment address, then produce Payment +
/// DRep witnesses over the (already-validated) body hash. The validators
/// send the change to the request's payment address; the payment-key check
/// is what makes that address the operator's own, so a compromised online
/// tool cannot collect the change at an address it names.
fn sign_with_drep_binding(
    body_hash: &[u8; 32],
    drep_id_bech32: &str,
    payment_address_bech32: &str,
    payment_material: &SigningKeyMaterial,
    drep_material: &SigningKeyMaterial,
) -> Result<(String, Vec<VkeyWitness>), SignExecuteError> {
    let drep_vkey = drep_material.verifying_key()?;
    shared::tx_validator::assert_drep_vkey_matches_id(drep_id_bech32, &drep_vkey)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let payment_vkey = payment_material.verifying_key()?;
    shared::validate::assert_payment_key_controls_address(&payment_vkey, payment_address_bech32)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    let witnesses = vec![
        build_vkey_witness(DrepWitnessRole::Payment, payment_material, body_hash)?,
        build_vkey_witness(DrepWitnessRole::Drep, drep_material, body_hash)?,
    ];
    Ok((hex::encode(body_hash), witnesses))
}

// Body-to-request binding, per operation. These need no key: they decode
// the body, hold every field against the request and return the body hash.
// The preview runs them so that only a request whose body matches is ever
// shown to the operator; signing runs them again before a key is used.

pub(crate) fn check_register_body(
    req: &shared::register::DRepRegisterRequest,
) -> Result<[u8; 32], SignExecuteError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_register_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    Ok(body_hash)
}

pub(crate) fn check_update_body(
    req: &shared::update::DRepUpdateRequest,
) -> Result<[u8; 32], SignExecuteError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_update_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    Ok(body_hash)
}

pub(crate) fn check_retire_body(
    req: &shared::retire::DRepRetireRequest,
) -> Result<[u8; 32], SignExecuteError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_retire_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    Ok(body_hash)
}

pub(crate) fn check_vote_body(
    req: &shared::vote::DRepVoteRequest,
) -> Result<[u8; 32], SignExecuteError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_vote_body(&body_bytes, req)
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    Ok(body_hash)
}

/// The rationale-witness counterpart: the payload must be a CIP-100
/// canonical body (never a transaction body). Returns the hash the witness
/// signs.
pub(crate) fn check_witness_body(
    req: &shared::witness_doc::DRepWitnessRequest,
) -> Result<[u8; 32], SignExecuteError> {
    shared::validate::assert_canonical_body_nquads(req.canonical_body.as_bytes())
        .map_err(|e| SignExecuteError::BodyValidation(e.to_string()))?;
    Ok(shared::validate::blake2b256(req.canonical_body.as_bytes()))
}

pub(crate) fn sign_register_core(
    req: &shared::register::DRepRegisterRequest,
    payment_material: SigningKeyMaterial,
    drep_material: SigningKeyMaterial,
) -> Result<shared::register::DRepRegisterResult, SignExecuteError> {
    let body_hash = check_register_body(req)?;
    let (body_hash_hex, witnesses) = sign_with_drep_binding(
        &body_hash,
        &req.drep_id_bech32,
        &req.payment_address_bech32,
        &payment_material,
        &drep_material,
    )?;
    Ok(shared::register::DRepRegisterResult {
        body_hash_hex,
        witnesses,
    })
}

pub(crate) fn sign_update_core(
    req: &shared::update::DRepUpdateRequest,
    payment_material: SigningKeyMaterial,
    drep_material: SigningKeyMaterial,
) -> Result<shared::update::DRepUpdateResult, SignExecuteError> {
    let body_hash = check_update_body(req)?;
    let (body_hash_hex, witnesses) = sign_with_drep_binding(
        &body_hash,
        &req.drep_id_bech32,
        &req.payment_address_bech32,
        &payment_material,
        &drep_material,
    )?;
    Ok(shared::update::DRepUpdateResult {
        body_hash_hex,
        witnesses,
    })
}

pub(crate) fn sign_retire_core(
    req: &shared::retire::DRepRetireRequest,
    payment_material: SigningKeyMaterial,
    drep_material: SigningKeyMaterial,
) -> Result<shared::retire::DRepRetireResult, SignExecuteError> {
    let body_hash = check_retire_body(req)?;
    let (body_hash_hex, witnesses) = sign_with_drep_binding(
        &body_hash,
        &req.drep_id_bech32,
        &req.payment_address_bech32,
        &payment_material,
        &drep_material,
    )?;
    Ok(shared::retire::DRepRetireResult {
        body_hash_hex,
        witnesses,
    })
}

pub(crate) fn sign_vote_core(
    req: &shared::vote::DRepVoteRequest,
    payment_material: SigningKeyMaterial,
    drep_material: SigningKeyMaterial,
) -> Result<shared::vote::DRepVoteResult, SignExecuteError> {
    let body_hash = check_vote_body(req)?;
    let (body_hash_hex, witnesses) = sign_with_drep_binding(
        &body_hash,
        &req.drep_id_bech32,
        &req.payment_address_bech32,
        &payment_material,
        &drep_material,
    )?;
    Ok(shared::vote::DRepVoteResult {
        body_hash_hex,
        witnesses,
    })
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

    /// The payment key every signing test loads.
    const PAYMENT_SEED: [u8; 32] = [9u8; 32];
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
        (
            bech32::encode::<bech32::Bech32>(hrp, &data).unwrap(),
            keyhash,
        )
    }

    /// Mainnet address paying to the key of `payment_seed`: an enterprise
    /// address, or a base address when a stake key seed is given.
    fn address_of(payment_seed: &[u8; 32], stake_seed: Option<&[u8; 32]>) -> String {
        use pallas_addresses::{
            Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
        };
        let kh = |seed: &[u8; 32]| Hash::<28>::from(shared::validate::blake2b224(&vkey_of(seed)));
        let delegation = match stake_seed {
            Some(s) => ShelleyDelegationPart::key_hash(kh(s)),
            None => ShelleyDelegationPart::Null,
        };
        ShelleyAddress::new(
            Network::Mainnet,
            ShelleyPaymentPart::key_hash(kh(payment_seed)),
            delegation,
        )
        .to_bech32()
        .unwrap()
    }

    /// The operator's own payment address: the enterprise address of
    /// `PAYMENT_SEED`.
    fn payment() -> String {
        address_of(&PAYMENT_SEED, None)
    }

    fn register_body(keyhash: [u8; 28]) -> Vec<u8> {
        register_body_to(keyhash, &payment(), FEE)
    }

    fn register_body_to(keyhash: [u8; 28], change_address: &str, fee: u64) -> Vec<u8> {
        let addr = pallas_addresses::Address::from_bech32(change_address).unwrap();
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
            fee,
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
        register_req_at(drep_id, body_cbor, &payment())
    }

    fn register_req_at(
        drep_id: String,
        body_cbor: &[u8],
        payment_address: &str,
    ) -> DRepRegisterRequest {
        DRepRegisterRequest {
            kind: DrepWireKind::DrepRegister,
            tx_body_cbor_hex: hex::encode(body_cbor),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE,
            deposit_lovelace: DEPOSIT,
            ttl_slot: TTL,
            payment_address_bech32: payment_address.into(),
            drep_id_bech32: drep_id,
            anchor: None,
            inputs: vec![UtxoInput {
                tx_hash_hex: "00".repeat(32),
                tx_index: 0,
                amount_lovelace: CHANGE + FEE + DEPOSIT,
                address_bech32: payment_address.into(),
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
        let payment_seed = PAYMENT_SEED;
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
            vk.verify(&body_hash, &sig)
                .expect("witness signature verifies over body hash");
        }
        // The DRep witness must be signed by the DRep key, the payment
        // witness by the payment key.
        let drep_w = res
            .witnesses
            .iter()
            .find(|w| matches!(w.role, DrepWitnessRole::Drep))
            .unwrap();
        assert_eq!(drep_w.vkey_hex, hex::encode(vkey_of(&drep_seed)));
        let pay_w = res
            .witnesses
            .iter()
            .find(|w| matches!(w.role, DrepWitnessRole::Payment))
            .unwrap();
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
    fn refuses_change_to_an_address_the_payment_key_does_not_control() {
        // A compromised online tool names its own address as the payment
        // address: body and request agree, the change goes there, and the
        // inputs are labelled with it. Only the payment-key check refuses.
        let drep_seed = [7u8; 32];
        let (drep_id, keyhash) = drep_id_for(&drep_seed);
        let attacker = address_of(&[0x66u8; 32], None);
        let body = register_body_to(keyhash, &attacker, FEE);
        let req = register_req_at(drep_id, &body, &attacker);
        check_register_body(&req).expect("body and request agree");
        let err = sign_register_core(&req, plain(PAYMENT_SEED), plain(drep_seed)).unwrap_err();
        assert!(
            matches!(&err, SignExecuteError::BodyValidation(m) if m.contains("payment key")),
            "{err:?}"
        );
    }

    #[test]
    fn a_payment_address_with_any_stake_part_still_signs() {
        // The payment address may be a base address whose stake part belongs
        // to a key this signer does not hold (a pledge or owner key): only
        // the payment credential is bound.
        let drep_seed = [7u8; 32];
        let (drep_id, keyhash) = drep_id_for(&drep_seed);
        let base = address_of(&PAYMENT_SEED, Some(&[0x55u8; 32]));
        let body = register_body_to(keyhash, &base, FEE);
        let req = register_req_at(drep_id, &body, &base);
        sign_register_core(&req, plain(PAYMENT_SEED), plain(drep_seed)).expect("signs");
    }

    #[test]
    fn body_check_refuses_a_request_that_misdescribes_its_body() {
        // The preview would show the request's fee; the body pays another.
        let (drep_id, keyhash) = drep_id_for(&[7u8; 32]);
        let body = register_body(keyhash);
        let mut req = register_req(drep_id, &body);
        check_register_body(&req).expect("matches");
        req.fee_lovelace = FEE - 1;
        assert!(matches!(
            check_register_body(&req),
            Err(SignExecuteError::BodyValidation(_))
        ));
        req.tx_body_cbor_hex = "zz".into();
        assert!(matches!(
            check_register_body(&req),
            Err(SignExecuteError::BadCborHex(_))
        ));
    }

    #[test]
    fn preview_is_refused_for_a_request_that_misdescribes_its_body() {
        use crate::handlers::sign::{parse_and_check, ParsedRequest};
        let (drep_id, keyhash) = drep_id_for(&[7u8; 32]);
        let body = register_body(keyhash);
        let mut req = register_req(drep_id, &body);
        // A request whose body matches is previewed.
        let ok = parse_and_check(&serde_json::to_vec(&req).unwrap()).expect("preview");
        assert!(matches!(ok, ParsedRequest::DrepRegister { .. }));
        // The same request stating another change amount than the body pays
        // out: no preview at all.
        req.change_to_payment_address_lovelace += 1;
        let err = match parse_and_check(&serde_json::to_vec(&req).unwrap()) {
            Err(e) => e,
            Ok(_) => panic!("a request that misdescribes its body must not be previewed"),
        };
        assert!(err.message.contains("does not match"), "{}", err.message);

        // Every transaction kind is checked, not only registration: a body
        // that is no transaction at all is never previewed.
        let (drep_id, _) = drep_id_for(&[7u8; 32]);
        let base = register_req(drep_id, &[0xa0]);
        let update = shared::update::DRepUpdateRequest {
            kind: DrepWireKind::DrepUpdate,
            tx_body_cbor_hex: "a0".into(),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE,
            ttl_slot: TTL,
            payment_address_bech32: base.payment_address_bech32.clone(),
            drep_id_bech32: base.drep_id_bech32.clone(),
            anchor: None,
            inputs: base.inputs.clone(),
            operator_pin_proof: "0".repeat(16),
            chain_context: base.chain_context,
        };
        assert!(parse_and_check(&serde_json::to_vec(&update).unwrap()).is_err());
        let retire = shared::retire::DRepRetireRequest {
            kind: DrepWireKind::DrepRetire,
            tx_body_cbor_hex: "a0".into(),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE,
            deposit_refund_lovelace: DEPOSIT,
            ttl_slot: TTL,
            payment_address_bech32: base.payment_address_bech32.clone(),
            drep_id_bech32: base.drep_id_bech32.clone(),
            inputs: base.inputs.clone(),
            operator_pin_proof: "0".repeat(16),
            chain_context: base.chain_context,
        };
        assert!(parse_and_check(&serde_json::to_vec(&retire).unwrap()).is_err());
        let vote = shared::vote::DRepVoteRequest {
            kind: DrepWireKind::DrepVote,
            tx_body_cbor_hex: "a0".into(),
            fee_lovelace: FEE,
            change_to_payment_address_lovelace: CHANGE,
            ttl_slot: TTL,
            payment_address_bech32: base.payment_address_bech32.clone(),
            drep_id_bech32: base.drep_id_bech32.clone(),
            action_tx_hash_hex: "cd".repeat(32),
            action_index: 0,
            vote: shared::vote::VoteChoice::Yes,
            anchor: None,
            inputs: base.inputs.clone(),
            operator_pin_proof: "0".repeat(16),
            chain_context: base.chain_context,
        };
        assert!(parse_and_check(&serde_json::to_vec(&vote).unwrap()).is_err());
    }

    #[test]
    fn witness_preview_carries_the_rationale_read_from_the_signed_bytes() {
        use crate::handlers::sign::{parse_and_check, ParsedRequest};
        let (drep_id, _) = drep_id_for(&[5u8; 32]);
        let mut req = shared::witness_doc::DRepWitnessRequest {
            kind: shared::wire_kind::DrepWireKind::DrepWitnessDoc,
            canonical_body: "_:c14n0 <https://example.com/#body> _:c14n1 .\n\
                _:c14n1 <https://example.com/#comment> \"I vote yes.\"@en-us .\n"
                .to_string(),
            drep_id_bech32: drep_id,
            operator_pin_proof: "0".repeat(16),
            chain_context: witness_ctx(),
        };
        match parse_and_check(&serde_json::to_vec(&req).unwrap()).expect("preview") {
            ParsedRequest::DrepWitness { rationale, .. } => {
                assert_eq!(rationale.len(), 2);
                assert!(
                    matches!(&rationale[1], shared::nquads::BodyLine::Text { field, value, .. }
                    if field == "comment" && value == "I vote yes.")
                );
            }
            _ => panic!("expected a witness preview"),
        }
        // Something that is not a canonical body is refused, not previewed.
        req.canonical_body = "this is not n-quads .\n".to_string();
        assert!(parse_and_check(&serde_json::to_vec(&req).unwrap()).is_err());
    }

    #[test]
    fn body_check_refuses_a_fee_above_the_ceiling() {
        // Body and request agree on a fee the signer never signs.
        let (drep_id, keyhash) = drep_id_for(&[7u8; 32]);
        let fee = shared::validate::MAX_FEE_LOVELACE + 1;
        let body = register_body_to(keyhash, &payment(), fee);
        let mut req = register_req(drep_id.clone(), &body);
        req.fee_lovelace = fee;
        let err = check_register_body(&req).unwrap_err();
        assert!(
            matches!(&err, SignExecuteError::BodyValidation(m) if m.contains("ceiling")),
            "{err:?}"
        );
        // At the ceiling itself it passes.
        let fee = shared::validate::MAX_FEE_LOVELACE;
        let body = register_body_to(keyhash, &payment(), fee);
        let mut req = register_req(drep_id, &body);
        req.fee_lovelace = fee;
        check_register_body(&req).expect("a fee at the ceiling is accepted");
    }

    #[test]
    fn key_load_failure_in_the_signing_path_is_redacted() {
        use std::io::Write;
        // A raw key without its CBOR header: the loader's own error quotes
        // the first two bytes. Neither the error nor its source may.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            r#"{{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"c0ffee11{}"}}"#,
            "ab".repeat(28)
        )
        .unwrap();
        let err = match load_payment_material_from_path(f.path()) {
            Err(e) => e,
            Ok(_) => panic!("a headerless key must not load"),
        };
        let SignExecuteError::LoadPayment { source, .. } = &err else {
            panic!("expected LoadPayment, got {err:?}")
        };
        assert!(!source.to_string().contains("c0ff"), "{source}");
        assert!(!err.to_string().contains("c0ff"), "{err}");
    }

    #[test]
    fn loads_drep_and_payment_keys_by_role() {
        use std::io::Write;
        fn write_skey(ty: &str, payload_hex: &str) -> tempfile::NamedTempFile {
            let json =
                format!(r#"{{"type":"{ty}","description":"x","cborHex":"5820{payload_hex}"}}"#);
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

    fn witness_ctx() -> ChainContext {
        ChainContext {
            current_epoch: 1,
            current_slot: 100,
            current_kes_period: 0,
            epoch_ends_at_unix: 0,
            opcert_expires_at_unix: None,
            built_at_unix: 0,
        }
    }

    #[test]
    fn witness_over_canonical_body_verifies_and_binds_drep() {
        let seed = [5u8; 32];
        let (drep_id, _kh) = drep_id_for(&seed);
        let body = "_:c14n0 <https://example.com/#body> _:c14n1 .\n\
            _:c14n1 <https://example.com/#comment> \"hi\"@en-us .\n";
        let req = shared::witness_doc::DRepWitnessRequest {
            kind: shared::wire_kind::DrepWireKind::DrepWitnessDoc,
            canonical_body: body.to_string(),
            drep_id_bech32: drep_id,
            operator_pin_proof: "0".repeat(16),
            chain_context: witness_ctx(),
        };
        let res = sign_witness_core(&req, plain(seed)).expect("signs witness");
        assert_eq!(res.witness.witness_algorithm, "ed25519");
        // The witness publicKey is the DRep vkey, and the signature verifies
        // over the blake2b-256 of the exact canonical body.
        assert_eq!(res.witness.public_key_hex, hex::encode(vkey_of(&seed)));
        let hash = shared::validate::blake2b256(body.as_bytes());
        let vk = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(hex::decode(&res.witness.public_key_hex).unwrap()).unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&hex::decode(&res.witness.signature_hex).unwrap()).unwrap();
        vk.verify(&hash, &sig)
            .expect("witness verifies over body hash");
    }

    #[test]
    fn witness_rejects_non_canonical_body() {
        // A payload that is not a canonical N-Quads body must never be signed:
        // the guard is what stops the DRep key becoming a tx-signing oracle.
        let seed = [5u8; 32];
        let (drep_id, _kh) = drep_id_for(&seed);
        let req = shared::witness_doc::DRepWitnessRequest {
            kind: shared::wire_kind::DrepWireKind::DrepWitnessDoc,
            canonical_body: "this is not n-quads .\n".to_string(),
            drep_id_bech32: drep_id,
            operator_pin_proof: "0".repeat(16),
            chain_context: witness_ctx(),
        };
        assert!(sign_witness_core(&req, plain(seed)).is_err());
        // The preview check refuses it too, before any key is involved.
        assert!(check_witness_body(&req).is_err());
    }

    #[test]
    fn witness_rejects_wrong_drep_key() {
        // The loaded key must hash to the DRep id in the request, else the
        // witness publicKey would not be the operator's on-chain DRep.
        let seed = [5u8; 32];
        let (drep_id, _kh) = drep_id_for(&seed);
        let body = "_:c14n0 <https://example.com/#body> _:c14n1 .\n";
        let req = shared::witness_doc::DRepWitnessRequest {
            kind: shared::wire_kind::DrepWireKind::DrepWitnessDoc,
            canonical_body: body.to_string(),
            drep_id_bech32: drep_id,
            operator_pin_proof: "0".repeat(16),
            chain_context: witness_ctx(),
        };
        assert!(sign_witness_core(&req, plain([0xEEu8; 32])).is_err());
    }
}
