//! Pure-compute signing helpers for the wallet operations.
//!
//! Path-sourced payment + stake signing keys are loaded and consumed. Each
//! signing call hashes the (already-validated) body and returns vkey
//! witnesses tagged with their role. Plain keys are standard 32-byte
//! Ed25519 seeds; extended keys are BIP32-Ed25519 (kL‖kR) from a converted
//! mnemonic wallet, signed scalar-based. Nothing here writes config or
//! touches the network.

use shared::error::ErrorEnvelope;
use shared::witness::{VkeyWitness, WalletWitnessRole};
use zeroize::Zeroizing;

pub(crate) use shared::signing::SigningKeyMaterial;

impl From<shared::signing::MaterialError> for SignError {
    fn from(e: shared::signing::MaterialError) -> Self {
        SignError::WrongRole(e.to_string())
    }
}

/// Validate an extended (BIP32-Ed25519) key and wrap it as signing
/// material (`SigningKeyMaterial::extended` in airgap-core).
fn extended_material(
    esk_64: [u8; 64],
    pubkey_32: [u8; 32],
) -> Result<SigningKeyMaterial, SignError> {
    Ok(SigningKeyMaterial::extended(esk_64, pubkey_32)?)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SignError {
    #[error("no wallet keys configured. Visit Setup")]
    PaymentNotConfigured,
    #[error("could not load payment key from {path}: {source}")]
    LoadPayment {
        path: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("could not load stake key from {path}: {source}")]
    LoadStake {
        path: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("tx body does not match request: {0}")]
    BodyValidation(String),
    #[error("tx body cbor hex is invalid: {0}")]
    BadCborHex(String),
    #[error("key file is not the expected role: {0}")]
    WrongRole(String),
    #[error("no configured signing key controls the request's payment address")]
    NoMatchingKey,
    #[error("this wallet is an enterprise address (no stake key) and cannot delegate")]
    EnterpriseCannotDelegate,
    #[error("this wallet is an enterprise address (no stake key) and has no rewards to withdraw")]
    EnterpriseCannotWithdraw,
}

impl From<SignError> for ErrorEnvelope {
    fn from(e: SignError) -> ErrorEnvelope {
        let msg = e.to_string();
        match e {
            SignError::PaymentNotConfigured => ErrorEnvelope::not_configured(msg),
            SignError::BodyValidation(_) | SignError::BadCborHex(_) => {
                tracing::warn!(detail = %msg, "rejecting request as invalid");
                ErrorEnvelope::invalid("invalid request payload")
            }
            SignError::WrongRole(_) => ErrorEnvelope::invalid("configured key has wrong role"),
            SignError::NoMatchingKey => {
                ErrorEnvelope::invalid("no configured key controls this address")
            }
            SignError::EnterpriseCannotDelegate => {
                ErrorEnvelope::invalid("enterprise address (no stake key) cannot delegate")
            }
            SignError::EnterpriseCannotWithdraw => ErrorEnvelope::invalid(
                "enterprise address (no stake key) has no rewards to withdraw",
            ),
            SignError::LoadPayment { source, .. } | SignError::LoadStake { source, .. } => {
                tracing::error!(error = %source, "key load failed");
                ErrorEnvelope::internal("key load failed")
            }
        }
    }
}

/// A key-load failure as the signing path carries and logs it: the same
/// redacted description Setup shows, never the raw loader error (which can
/// quote file content).
fn redacted(e: &shared::cardano_keys::KeyLoadError) -> Box<dyn std::error::Error + Send + Sync> {
    crate::validate::friendly_error(e).into()
}

pub(crate) fn load_payment_material_from_path(
    path: &std::path::Path,
) -> Result<SigningKeyMaterial, SignError> {
    let key = shared::cardano_keys::load_skey(path).map_err(|e| SignError::LoadPayment {
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
        other => Err(SignError::WrongRole(format!(
            "expected payment key, got {other:?}"
        ))),
    }
}

pub(crate) fn load_stake_material_from_path(
    path: &std::path::Path,
) -> Result<SigningKeyMaterial, SignError> {
    let key = shared::cardano_keys::load_skey(path).map_err(|e| SignError::LoadStake {
        path: path.display().to_string(),
        source: redacted(&e),
    })?;
    match key {
        shared::cardano_keys::CardanoKey::Stake { seed_32 } => {
            Ok(SigningKeyMaterial::Plain(Zeroizing::new(seed_32)))
        }
        shared::cardano_keys::CardanoKey::StakeExtended { esk_64, pubkey_32 } => {
            extended_material(esk_64, pubkey_32)
        }
        other => Err(SignError::WrongRole(format!(
            "expected stake key, got {other:?}"
        ))),
    }
}

/// Sign `body_hash` with `material` and wrap it as a `VkeyWitness` tagged
/// with `role`.
pub(crate) fn build_vkey_witness(
    role: WalletWitnessRole,
    material: &SigningKeyMaterial,
    body_hash: &[u8; 32],
) -> Result<VkeyWitness, SignError> {
    let (vkey, sig) = material.sign(body_hash)?;
    let (vkey_hex, signature_hex) = (hex::encode(vkey), hex::encode(sig));
    Ok(VkeyWitness {
        role,
        vkey_hex,
        signature_hex,
    })
}

/// Decode the body CBOR hex and compute its blake2b-256 hash (what witnesses
/// sign over). Returns the raw bytes and the 32-byte hash.
pub(crate) fn body_hash_of(cbor_hex: &str) -> Result<(Vec<u8>, [u8; 32]), SignError> {
    let body_bytes = hex::decode(cbor_hex).map_err(|e| SignError::BadCborHex(e.to_string()))?;
    let body_hash = shared::validate::blake2b256(&body_bytes);
    Ok((body_bytes, body_hash))
}

// ---------------------------------------------------------------------------
// Per-operation signing (validate → change-guard → sign)
// ---------------------------------------------------------------------------

/// Key-based change-guard: confirm the request's payment address is exactly
/// this signer's own base address, derived from the loaded payment + stake
/// keys. Combined with the validator (which binds change to the payment
/// address), this guarantees change cannot be redirected away from the
/// wallet, even by a compromised online tool that lies consistently.
fn assert_payment_address_is_own(
    payment_material: &SigningKeyMaterial,
    stake_material: Option<&SigningKeyMaterial>,
    payment_address_bech32: &str,
) -> Result<(), SignError> {
    let pay_vkey = payment_material.verifying_key()?;
    let own = match stake_material {
        Some(stake) => {
            let stake_vkey = stake.verifying_key()?;
            shared::address::base_address_bech32(&pay_vkey, &stake_vkey)
        }
        None => shared::address::enterprise_address_bech32(&pay_vkey),
    }
    .map_err(|e| SignError::BodyValidation(format!("own-address derivation: {e}")))?;
    if own != payment_address_bech32 {
        return Err(SignError::BodyValidation(
            "payment address is not this signer's own address".into(),
        ));
    }
    Ok(())
}

/// Confirm the request's stake address is exactly this signer's own,
/// derived from the loaded stake key. The validator binds the body's
/// certificate credential or withdrawal account to the request's stake
/// address; this binds that address to the key that signs, so the stake
/// address the operator reads on the preview is the one the Stake witness
/// actually authorises.
fn assert_stake_address_is_own(
    stake_material: &SigningKeyMaterial,
    stake_address_bech32: &str,
) -> Result<(), SignError> {
    let stake_vkey = stake_material.verifying_key()?;
    let own = shared::address::stake_address_bech32(&stake_vkey)
        .map_err(|e| SignError::BodyValidation(format!("own-stake-address derivation: {e}")))?;
    if own != stake_address_bech32 {
        return Err(SignError::BodyValidation(
            "stake address is not this signer's own stake address".into(),
        ));
    }
    Ok(())
}

// Body-to-request binding, per operation. These need no key: they decode
// the body, hold every field against the request and return the body hash.
// The preview runs them so that only a request whose body matches is ever
// shown to the operator; signing runs them again before a key is used.

pub(crate) fn check_payment_body(
    req: &shared::payment::PaymentRequest,
) -> Result<[u8; 32], SignError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_payment_body(&body_bytes, req, req.chain_context.current_slot)
        .map_err(|e| SignError::BodyValidation(e.to_string()))?;
    Ok(body_hash)
}

pub(crate) fn check_pool_delegation_body(
    req: &shared::delegate::PoolDelegateRequest,
) -> Result<[u8; 32], SignError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_pool_delegation_body(
        &body_bytes,
        req,
        req.chain_context.current_slot,
    )
    .map_err(|e| SignError::BodyValidation(e.to_string()))?;
    Ok(body_hash)
}

pub(crate) fn check_drep_delegation_body(
    req: &shared::delegate::DrepDelegateRequest,
) -> Result<[u8; 32], SignError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_drep_delegation_body(
        &body_bytes,
        req,
        req.chain_context.current_slot,
    )
    .map_err(|e| SignError::BodyValidation(e.to_string()))?;
    Ok(body_hash)
}

pub(crate) fn check_withdraw_rewards_body(
    req: &shared::withdraw::WithdrawRewardsRequest,
) -> Result<[u8; 32], SignError> {
    let (body_bytes, body_hash) = body_hash_of(&req.tx_body_cbor_hex)?;
    shared::tx_validator::validate_withdraw_rewards_body(
        &body_bytes,
        req,
        req.chain_context.current_slot,
    )
    .map_err(|e| SignError::BodyValidation(e.to_string()))?;
    Ok(body_hash)
}

/// Validate the payment body against the request, confirm the change
/// returns to this signer's own address, and produce a single Payment
/// witness.
pub(crate) fn sign_payment_core(
    req: &shared::payment::PaymentRequest,
    payment_material: SigningKeyMaterial,
    stake_material: Option<SigningKeyMaterial>,
) -> Result<shared::payment::PaymentResult, SignError> {
    let body_hash = check_payment_body(req)?;
    assert_payment_address_is_own(
        &payment_material,
        stake_material.as_ref(),
        &req.payment_address_bech32,
    )?;
    let witnesses = vec![build_vkey_witness(
        WalletWitnessRole::Payment,
        &payment_material,
        &body_hash,
    )?];
    Ok(shared::payment::PaymentResult {
        body_hash_hex: hex::encode(body_hash),
        witnesses,
    })
}

/// Validate the pool-delegation body, confirm change returns to own and the
/// delegated stake address is this signer's own, and produce Payment +
/// Stake witnesses.
pub(crate) fn sign_pool_delegation_core(
    req: &shared::delegate::PoolDelegateRequest,
    payment_material: SigningKeyMaterial,
    stake_material: SigningKeyMaterial,
) -> Result<shared::delegate::DelegateResult, SignError> {
    let body_hash = check_pool_delegation_body(req)?;
    assert_payment_address_is_own(
        &payment_material,
        Some(&stake_material),
        &req.payment_address_bech32,
    )?;
    assert_stake_address_is_own(&stake_material, &req.stake_address_bech32)?;
    let witnesses = vec![
        build_vkey_witness(WalletWitnessRole::Payment, &payment_material, &body_hash)?,
        build_vkey_witness(WalletWitnessRole::Stake, &stake_material, &body_hash)?,
    ];
    Ok(shared::delegate::DelegateResult {
        body_hash_hex: hex::encode(body_hash),
        witnesses,
    })
}

/// Validate the DRep-delegation body, confirm change returns to own and the
/// delegated stake address is this signer's own, and produce Payment +
/// Stake witnesses.
pub(crate) fn sign_drep_delegation_core(
    req: &shared::delegate::DrepDelegateRequest,
    payment_material: SigningKeyMaterial,
    stake_material: SigningKeyMaterial,
) -> Result<shared::delegate::DelegateResult, SignError> {
    let body_hash = check_drep_delegation_body(req)?;
    assert_payment_address_is_own(
        &payment_material,
        Some(&stake_material),
        &req.payment_address_bech32,
    )?;
    assert_stake_address_is_own(&stake_material, &req.stake_address_bech32)?;
    let witnesses = vec![
        build_vkey_witness(WalletWitnessRole::Payment, &payment_material, &body_hash)?,
        build_vkey_witness(WalletWitnessRole::Stake, &stake_material, &body_hash)?,
    ];
    Ok(shared::delegate::DelegateResult {
        body_hash_hex: hex::encode(body_hash),
        witnesses,
    })
}

/// Validate the reward-withdrawal body, confirm the rewards and the change
/// return to this signer's own address and come from its own reward
/// account, and produce Payment + Stake witnesses.
pub(crate) fn sign_withdraw_rewards_core(
    req: &shared::withdraw::WithdrawRewardsRequest,
    payment_material: SigningKeyMaterial,
    stake_material: SigningKeyMaterial,
) -> Result<shared::withdraw::WithdrawRewardsResult, SignError> {
    let body_hash = check_withdraw_rewards_body(req)?;
    assert_payment_address_is_own(
        &payment_material,
        Some(&stake_material),
        &req.payment_address_bech32,
    )?;
    assert_stake_address_is_own(&stake_material, &req.stake_address_bech32)?;
    let witnesses = vec![
        build_vkey_witness(WalletWitnessRole::Payment, &payment_material, &body_hash)?,
        build_vkey_witness(WalletWitnessRole::Stake, &stake_material, &body_hash)?,
    ];
    Ok(shared::withdraw::WithdrawRewardsResult {
        body_hash_hex: hex::encode(body_hash),
        witnesses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};

    fn verify(w: &VkeyWitness, msg: &[u8; 32]) {
        let vkey: [u8; 32] = hex::decode(&w.vkey_hex).unwrap().try_into().unwrap();
        let sig: [u8; 64] = hex::decode(&w.signature_hex).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&vkey).unwrap();
        vk.verify(msg, &Signature::from_bytes(&sig))
            .expect("signature verifies under advertised vkey");
    }

    #[test]
    fn plain_witness_signs_and_verifies() {
        let seed = Zeroizing::new([7u8; 32]);
        let material = SigningKeyMaterial::Plain(seed);
        let hash = [0x11u8; 32];
        let w = build_vkey_witness(WalletWitnessRole::Payment, &material, &hash).unwrap();
        assert_eq!(w.role, WalletWitnessRole::Payment);
        verify(&w, &hash);
        // Vkey advertised in the witness equals the material's verifying key.
        assert_eq!(w.vkey_hex, hex::encode(material.verifying_key().unwrap()));
    }

    #[test]
    fn body_hash_is_32_bytes_and_deterministic() {
        let (_b, h1) = body_hash_of("a40081").unwrap();
        let (_b2, h2) = body_hash_of("a40081").unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn loads_generated_keys_and_signs_with_each_role() {
        let dir = tempfile::tempdir().unwrap();
        let g = keygen::generate_and_write(dir.path()).unwrap();
        let pay =
            load_payment_material_from_path(std::path::Path::new(&g.payment_skey_path)).unwrap();
        let stk = load_stake_material_from_path(std::path::Path::new(&g.stake_skey_path)).unwrap();
        let hash = [0x22u8; 32];
        verify(
            &build_vkey_witness(WalletWitnessRole::Payment, &pay, &hash).unwrap(),
            &hash,
        );
        verify(
            &build_vkey_witness(WalletWitnessRole::Stake, &stk, &hash).unwrap(),
            &hash,
        );
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
        let SignError::LoadPayment { source, .. } = &err else {
            panic!("expected LoadPayment, got {err:?}")
        };
        assert!(!source.to_string().contains("c0ff"), "{source}");
        assert!(!err.to_string().contains("c0ff"), "{err}");
        assert!(source.to_string().contains("CBOR header"), "{source}");
    }

    #[test]
    fn wrong_role_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let g = keygen::generate_and_write(dir.path()).unwrap();
        // Loading the payment skey as a stake key must fail.
        let err = load_stake_material_from_path(std::path::Path::new(&g.payment_skey_path));
        assert!(matches!(err, Err(SignError::WrongRole(_))));
    }

    // --- per-operation wrappers (validate → change-guard → sign) ---

    fn vk(seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    /// Build a minimal coin-only payment body inline (one input, dest +
    /// change outputs): the signer's dev-deps include Pallas so a valid
    /// body can be constructed without depending on the online tx builder.
    fn coin_body(
        dest_bytes: Vec<u8>,
        change_bytes: Vec<u8>,
        fee: u64,
        ttl: u64,
        amount: u64,
        change: u64,
    ) -> Vec<u8> {
        use pallas_codec::utils::{Bytes, Set};
        use pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput;
        use pallas_primitives::conway::{PseudoTransactionOutput, TransactionBody, Value};
        use pallas_primitives::{Hash, NetworkId, TransactionInput};
        let mk = |addr: Vec<u8>, c: u64| {
            PseudoTransactionOutput::PostAlonzo(PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(addr),
                value: Value::Coin(c),
                datum_option: None,
                script_ref: None,
            })
        };
        let input = TransactionInput {
            transaction_id: Hash::from([9u8; 32]),
            index: 0,
        };
        let body = TransactionBody {
            inputs: Set::from(vec![input]),
            outputs: vec![mk(dest_bytes, amount), mk(change_bytes, change)],
            fee,
            ttl: Some(ttl),
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
        let mut buf = Vec::new();
        pallas_codec::minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    fn payment_req(
        body: &[u8],
        payment: &str,
        dest: &str,
        amount: u64,
        change: u64,
        fee: u64,
        ttl: u64,
    ) -> shared::payment::PaymentRequest {
        shared::payment::PaymentRequest {
            kind: shared::wire_kind::WalletWireKind::Payment,
            tx_body_cbor_hex: hex::encode(body),
            destination_address_bech32: dest.into(),
            amount_lovelace: amount,
            assets_sent: vec![],
            fee_lovelace: fee,
            change_lovelace: change,
            change_assets: vec![],
            ttl_slot: ttl,
            payment_address_bech32: payment.into(),
            inputs: vec![shared::utxo::UtxoInput {
                tx_hash_hex: "09".repeat(32),
                tx_index: 0,
                amount_lovelace: amount + change + fee,
                address_bech32: payment.into(),
            }],
            operator_pin_proof: String::new(),
            chain_context: shared::chain_context::ChainContext {
                current_epoch: 0,
                current_slot: 0,
                current_kes_period: 0,
                epoch_ends_at_unix: 0,
                opcert_expires_at_unix: None,
                built_at_unix: 0,
            },
            metadata_msg: None,
        }
    }

    #[test]
    fn sign_payment_happy_path_change_to_own() {
        let own = shared::address::base_address_bech32(&vk(&[1; 32]), &vk(&[2; 32])).unwrap();
        let dest = shared::address::base_address_bech32(&vk(&[3; 32]), &vk(&[4; 32])).unwrap();
        let body = coin_body(
            shared::validate::addr_bytes(&dest).unwrap(),
            shared::validate::addr_bytes(&own).unwrap(),
            200_000,
            100,
            1_500_000,
            1_000_000,
        );
        let req = payment_req(&body, &own, &dest, 1_500_000, 1_000_000, 200_000, 100);
        let res = sign_payment_core(
            &req,
            SigningKeyMaterial::Plain(Zeroizing::new([1; 32])),
            Some(SigningKeyMaterial::Plain(Zeroizing::new([2; 32]))),
        )
        .expect("signs");
        assert_eq!(res.witnesses.len(), 1);
        assert_eq!(res.witnesses[0].role, WalletWitnessRole::Payment);
        let (_b, h) = body_hash_of(&req.tx_body_cbor_hex).unwrap();
        verify(&res.witnesses[0], &h);
    }

    #[test]
    fn sign_payment_change_guard_blocks_redirect() {
        // Change goes to an attacker address; the request claims that same
        // address as payment_address (so the body matches the request), but
        // the signer's own keys derive elsewhere, so the change-guard fires.
        let attacker = shared::address::base_address_bech32(&vk(&[5; 32]), &vk(&[6; 32])).unwrap();
        let dest = shared::address::base_address_bech32(&vk(&[3; 32]), &vk(&[4; 32])).unwrap();
        let body = coin_body(
            shared::validate::addr_bytes(&dest).unwrap(),
            shared::validate::addr_bytes(&attacker).unwrap(),
            200_000,
            100,
            1_500_000,
            1_000_000,
        );
        let req = payment_req(&body, &attacker, &dest, 1_500_000, 1_000_000, 200_000, 100);
        let err = sign_payment_core(
            &req,
            SigningKeyMaterial::Plain(Zeroizing::new([1; 32])),
            Some(SigningKeyMaterial::Plain(Zeroizing::new([2; 32]))),
        );
        assert!(matches!(err, Err(SignError::BodyValidation(_))));
    }

    #[test]
    fn sign_payment_enterprise_no_stake() {
        // An enterprise (payment-only) wallet signs a payment with no stake
        // material; the change-guard derives the addr1v from the payment key.
        let own = shared::address::enterprise_address_bech32(&vk(&[1; 32])).unwrap();
        let dest = shared::address::base_address_bech32(&vk(&[3; 32]), &vk(&[4; 32])).unwrap();
        let body = coin_body(
            shared::validate::addr_bytes(&dest).unwrap(),
            shared::validate::addr_bytes(&own).unwrap(),
            200_000,
            100,
            1_500_000,
            1_000_000,
        );
        let req = payment_req(&body, &own, &dest, 1_500_000, 1_000_000, 200_000, 100);
        let res = sign_payment_core(
            &req,
            SigningKeyMaterial::Plain(Zeroizing::new([1; 32])),
            None,
        )
        .expect("enterprise payment signs");
        assert_eq!(res.witnesses.len(), 1);
        assert_eq!(res.witnesses[0].role, WalletWitnessRole::Payment);
    }

    // --- reward withdrawal ---

    /// A withdrawal body: one input, one output to `change_bytes`, one
    /// withdrawal of `rewards` from `account_bytes`.
    fn withdraw_body(
        change_bytes: Vec<u8>,
        account_bytes: Vec<u8>,
        fee: u64,
        ttl: u64,
        rewards: u64,
        change: u64,
    ) -> Vec<u8> {
        use pallas_codec::utils::{Bytes, NonEmptyKeyValuePairs, Set};
        use pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput;
        use pallas_primitives::conway::{PseudoTransactionOutput, TransactionBody, Value};
        use pallas_primitives::{Hash, NetworkId, TransactionInput};
        let input = TransactionInput {
            transaction_id: Hash::from([9u8; 32]),
            index: 0,
        };
        let body = TransactionBody {
            inputs: Set::from(vec![input]),
            outputs: vec![PseudoTransactionOutput::PostAlonzo(
                PseudoPostAlonzoTransactionOutput {
                    address: Bytes::from(change_bytes),
                    value: Value::Coin(change),
                    datum_option: None,
                    script_ref: None,
                },
            )],
            fee,
            ttl: Some(ttl),
            certificates: None,
            withdrawals: Some(NonEmptyKeyValuePairs::Def(vec![(
                Bytes::from(account_bytes),
                rewards,
            )])),
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
        pallas_codec::minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    fn withdraw_req(
        body: &[u8],
        payment: &str,
        stake: &str,
        rewards: u64,
        change: u64,
        fee: u64,
        ttl: u64,
    ) -> shared::withdraw::WithdrawRewardsRequest {
        shared::withdraw::WithdrawRewardsRequest {
            kind: shared::wire_kind::WalletWireKind::WithdrawRewards,
            tx_body_cbor_hex: hex::encode(body),
            rewards_lovelace: rewards,
            fee_lovelace: fee,
            change_lovelace: change,
            change_assets: vec![],
            ttl_slot: ttl,
            payment_address_bech32: payment.into(),
            stake_address_bech32: stake.into(),
            inputs: vec![shared::utxo::UtxoInput {
                tx_hash_hex: "09".repeat(32),
                tx_index: 0,
                amount_lovelace: change + fee - rewards,
                address_bech32: payment.into(),
            }],
            operator_pin_proof: String::new(),
            chain_context: shared::chain_context::ChainContext {
                current_epoch: 0,
                current_slot: 0,
                current_kes_period: 0,
                epoch_ends_at_unix: 0,
                opcert_expires_at_unix: None,
                built_at_unix: 0,
            },
        }
    }

    fn own_keys() -> (SigningKeyMaterial, SigningKeyMaterial) {
        (
            SigningKeyMaterial::Plain(Zeroizing::new([1; 32])),
            SigningKeyMaterial::Plain(Zeroizing::new([2; 32])),
        )
    }

    #[test]
    fn sign_withdrawal_happy_path() {
        let own = shared::address::base_address_bech32(&vk(&[1; 32]), &vk(&[2; 32])).unwrap();
        let stake = shared::address::stake_address_bech32(&vk(&[2; 32])).unwrap();
        let body = withdraw_body(
            shared::validate::addr_bytes(&own).unwrap(),
            shared::validate::addr_bytes(&stake).unwrap(),
            180_000,
            100,
            50_000_000,
            52_820_000,
        );
        let req = withdraw_req(&body, &own, &stake, 50_000_000, 52_820_000, 180_000, 100);
        let (pay, stk) = own_keys();
        let res = sign_withdraw_rewards_core(&req, pay, stk).expect("signs");
        assert_eq!(res.witnesses.len(), 2);
        assert_eq!(res.witnesses[0].role, WalletWitnessRole::Payment);
        assert_eq!(res.witnesses[1].role, WalletWitnessRole::Stake);
        let (_b, h) = body_hash_of(&req.tx_body_cbor_hex).unwrap();
        verify(&res.witnesses[0], &h);
        verify(&res.witnesses[1], &h);
        assert_eq!(res.witnesses[1].vkey_hex, hex::encode(vk(&[2; 32])));
    }

    #[test]
    fn sign_withdrawal_blocks_rewards_sent_elsewhere() {
        // The rewards go to an attacker address which the request claims as
        // the payment address: body and request agree, the own-address guard
        // does not.
        let attacker = shared::address::base_address_bech32(&vk(&[5; 32]), &vk(&[6; 32])).unwrap();
        let stake = shared::address::stake_address_bech32(&vk(&[2; 32])).unwrap();
        let body = withdraw_body(
            shared::validate::addr_bytes(&attacker).unwrap(),
            shared::validate::addr_bytes(&stake).unwrap(),
            180_000,
            100,
            50_000_000,
            52_820_000,
        );
        let req = withdraw_req(
            &body, &attacker, &stake, 50_000_000, 52_820_000, 180_000, 100,
        );
        let (pay, stk) = own_keys();
        assert!(matches!(
            sign_withdraw_rewards_core(&req, pay, stk),
            Err(SignError::BodyValidation(_))
        ));
    }

    #[test]
    fn sign_withdrawal_blocks_a_foreign_reward_account() {
        // Body and request agree on a reward account this signer's stake key
        // does not control: the own-stake-address guard refuses.
        let own = shared::address::base_address_bech32(&vk(&[1; 32]), &vk(&[2; 32])).unwrap();
        let foreign = shared::address::stake_address_bech32(&vk(&[6; 32])).unwrap();
        let body = withdraw_body(
            shared::validate::addr_bytes(&own).unwrap(),
            shared::validate::addr_bytes(&foreign).unwrap(),
            180_000,
            100,
            50_000_000,
            52_820_000,
        );
        let req = withdraw_req(&body, &own, &foreign, 50_000_000, 52_820_000, 180_000, 100);
        let (pay, stk) = own_keys();
        let err = sign_withdraw_rewards_core(&req, pay, stk);
        assert!(
            matches!(err, Err(SignError::BodyValidation(m)) if m.contains("own stake address"))
        );
    }

    #[test]
    fn sign_withdrawal_blocks_a_body_that_differs_from_the_request() {
        let own = shared::address::base_address_bech32(&vk(&[1; 32]), &vk(&[2; 32])).unwrap();
        let stake = shared::address::stake_address_bech32(&vk(&[2; 32])).unwrap();
        // The body pays a larger fee than the request shows the operator.
        let body = withdraw_body(
            shared::validate::addr_bytes(&own).unwrap(),
            shared::validate::addr_bytes(&stake).unwrap(),
            40_000_000,
            100,
            50_000_000,
            13_000_000,
        );
        let req = withdraw_req(&body, &own, &stake, 50_000_000, 52_820_000, 180_000, 100);
        let (pay, stk) = own_keys();
        assert!(matches!(
            sign_withdraw_rewards_core(&req, pay, stk),
            Err(SignError::BodyValidation(_))
        ));
    }

    // --- delegation: the stake address must be this signer's own ---

    /// A delegation body: one input, one change output, one certificate.
    fn cert_body(
        change_bytes: Vec<u8>,
        cert: pallas_primitives::conway::Certificate,
        fee: u64,
        ttl: u64,
        change: u64,
    ) -> Vec<u8> {
        use pallas_codec::utils::{Bytes, NonEmptySet, Set};
        use pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput;
        use pallas_primitives::conway::{PseudoTransactionOutput, TransactionBody, Value};
        use pallas_primitives::{Hash, NetworkId, TransactionInput};
        let input = TransactionInput {
            transaction_id: Hash::from([9u8; 32]),
            index: 0,
        };
        let body = TransactionBody {
            inputs: Set::from(vec![input]),
            outputs: vec![PseudoTransactionOutput::PostAlonzo(
                PseudoPostAlonzoTransactionOutput {
                    address: Bytes::from(change_bytes),
                    value: Value::Coin(change),
                    datum_option: None,
                    script_ref: None,
                },
            )],
            fee,
            ttl: Some(ttl),
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
        pallas_codec::minicbor::encode(&body, &mut buf).unwrap();
        buf
    }

    fn stake_cred(seed: &[u8; 32]) -> pallas_primitives::StakeCredential {
        pallas_primitives::StakeCredential::AddrKeyhash(shared::address::key_hash(&vk(seed)))
    }

    fn ctx() -> shared::chain_context::ChainContext {
        shared::chain_context::ChainContext {
            current_epoch: 0,
            current_slot: 0,
            current_kes_period: 0,
            epoch_ends_at_unix: 0,
            opcert_expires_at_unix: None,
            built_at_unix: 0,
        }
    }

    fn one_input(payment: &str, amount: u64) -> Vec<shared::utxo::UtxoInput> {
        vec![shared::utxo::UtxoInput {
            tx_hash_hex: "09".repeat(32),
            tx_index: 0,
            amount_lovelace: amount,
            address_bech32: payment.into(),
        }]
    }

    /// A pool-delegation request + body delegating the stake key of
    /// `stake_seed`, with change to the base address of seeds 1 + 2.
    fn pool_req(stake_seed: &[u8; 32]) -> shared::delegate::PoolDelegateRequest {
        let own = shared::address::base_address_bech32(&vk(&[1; 32]), &vk(&[2; 32])).unwrap();
        let pool = [0xAB; 28];
        let body = cert_body(
            shared::validate::addr_bytes(&own).unwrap(),
            pallas_primitives::conway::Certificate::StakeDelegation(
                stake_cred(stake_seed),
                pallas_primitives::Hash::from(pool),
            ),
            180_000,
            100,
            2_820_000,
        );
        shared::delegate::PoolDelegateRequest {
            kind: shared::wire_kind::WalletWireKind::PoolDelegate,
            tx_body_cbor_hex: hex::encode(body),
            pool_id_bech32: bech32::encode::<bech32::Bech32>(
                bech32::Hrp::parse("pool").unwrap(),
                &pool,
            )
            .unwrap(),
            register_stake: false,
            deposit_lovelace: 0,
            fee_lovelace: 180_000,
            change_lovelace: 2_820_000,
            change_assets: vec![],
            ttl_slot: 100,
            payment_address_bech32: own.clone(),
            stake_address_bech32: shared::address::stake_address_bech32(&vk(stake_seed)).unwrap(),
            inputs: one_input(&own, 3_000_000),
            operator_pin_proof: String::new(),
            chain_context: ctx(),
        }
    }

    /// The same for a DRep delegation (to Always Abstain).
    fn drep_req(stake_seed: &[u8; 32]) -> shared::delegate::DrepDelegateRequest {
        let own = shared::address::base_address_bech32(&vk(&[1; 32]), &vk(&[2; 32])).unwrap();
        let body = cert_body(
            shared::validate::addr_bytes(&own).unwrap(),
            pallas_primitives::conway::Certificate::VoteDeleg(
                stake_cred(stake_seed),
                pallas_primitives::conway::DRep::Abstain,
            ),
            180_000,
            100,
            2_820_000,
        );
        shared::delegate::DrepDelegateRequest {
            kind: shared::wire_kind::WalletWireKind::DrepDelegate,
            tx_body_cbor_hex: hex::encode(body),
            target: shared::delegate::DrepTarget::Abstain,
            register_stake: false,
            deposit_lovelace: 0,
            fee_lovelace: 180_000,
            change_lovelace: 2_820_000,
            change_assets: vec![],
            ttl_slot: 100,
            payment_address_bech32: own.clone(),
            stake_address_bech32: shared::address::stake_address_bech32(&vk(stake_seed)).unwrap(),
            inputs: one_input(&own, 3_000_000),
            operator_pin_proof: String::new(),
            chain_context: ctx(),
        }
    }

    #[test]
    fn sign_pool_delegation_happy_path() {
        let req = pool_req(&[2; 32]);
        let (pay, stk) = own_keys();
        let res = sign_pool_delegation_core(&req, pay, stk).expect("signs");
        assert_eq!(res.witnesses.len(), 2);
        let (_b, h) = body_hash_of(&req.tx_body_cbor_hex).unwrap();
        verify(&res.witnesses[0], &h);
        verify(&res.witnesses[1], &h);
    }

    #[test]
    fn sign_pool_delegation_blocks_a_foreign_stake_address() {
        // Body and request agree on a stake credential that is not the one
        // this signer's stake key controls. Change still returns to own, so
        // only the stake-address guard stands in the way.
        let req = pool_req(&[6; 32]);
        check_pool_delegation_body(&req).expect("body and request agree");
        let (pay, stk) = own_keys();
        let err = sign_pool_delegation_core(&req, pay, stk);
        assert!(
            matches!(err, Err(SignError::BodyValidation(m)) if m.contains("own stake address"))
        );
    }

    #[test]
    fn sign_drep_delegation_happy_path() {
        let req = drep_req(&[2; 32]);
        let (pay, stk) = own_keys();
        let res = sign_drep_delegation_core(&req, pay, stk).expect("signs");
        assert_eq!(res.witnesses.len(), 2);
        let (_b, h) = body_hash_of(&req.tx_body_cbor_hex).unwrap();
        verify(&res.witnesses[0], &h);
        verify(&res.witnesses[1], &h);
    }

    #[test]
    fn sign_drep_delegation_blocks_a_foreign_stake_address() {
        let req = drep_req(&[6; 32]);
        check_drep_delegation_body(&req).expect("body and request agree");
        let (pay, stk) = own_keys();
        let err = sign_drep_delegation_core(&req, pay, stk);
        assert!(
            matches!(err, Err(SignError::BodyValidation(m)) if m.contains("own stake address"))
        );
    }

    // --- the body checks the preview runs (no key involved) ---

    #[test]
    fn body_check_refuses_a_request_that_misdescribes_its_body() {
        // The preview would show the request's fee; the body pays another.
        let mut req = pool_req(&[2; 32]);
        check_pool_delegation_body(&req).expect("matches");
        req.fee_lovelace = 170_000;
        assert!(matches!(
            check_pool_delegation_body(&req),
            Err(SignError::BodyValidation(_))
        ));
        // A body that is not CBOR hex at all.
        req.tx_body_cbor_hex = "zz".into();
        assert!(matches!(
            check_pool_delegation_body(&req),
            Err(SignError::BadCborHex(_))
        ));
    }

    #[test]
    fn body_check_refuses_a_fee_above_the_ceiling() {
        // Body and request agree on a fee the signer never signs.
        let own = shared::address::base_address_bech32(&vk(&[1; 32]), &vk(&[2; 32])).unwrap();
        let stake = shared::address::stake_address_bech32(&vk(&[2; 32])).unwrap();
        let fee = shared::tx_validator::MAX_FEE_LOVELACE + 1;
        let body = withdraw_body(
            shared::validate::addr_bytes(&own).unwrap(),
            shared::validate::addr_bytes(&stake).unwrap(),
            fee,
            100,
            50_000_000,
            50_000_000,
        );
        let req = withdraw_req(&body, &own, &stake, 50_000_000, 50_000_000, fee, 100);
        let err = check_withdraw_rewards_body(&req);
        assert!(
            matches!(&err, Err(SignError::BodyValidation(m)) if m.contains("ceiling")),
            "{err:?}"
        );
        // At the ceiling itself it passes.
        let fee = shared::tx_validator::MAX_FEE_LOVELACE;
        let body = withdraw_body(
            shared::validate::addr_bytes(&own).unwrap(),
            shared::validate::addr_bytes(&stake).unwrap(),
            fee,
            100,
            50_000_000,
            50_000_000,
        );
        let req = withdraw_req(&body, &own, &stake, 50_000_000, 50_000_000, fee, 100);
        check_withdraw_rewards_body(&req).expect("a fee at the ceiling is accepted");
    }
}
