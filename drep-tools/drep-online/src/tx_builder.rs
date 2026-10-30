//! Pallas-based Conway `TransactionBody` construction for the four DRep
//! operations.
//!
//! Each body is a tiny tx: one fee input from the payment address, one
//! change output back to it, and the DRep-specific cert or voting
//! procedure in the middle. The role-neutral pieces (address decode,
//! output build, input parse, length checks) come from
//! `airgap_core::tx`; only the cert/voter shape lives here. The fee is
//! computed from the encoded body size (mainnet linear fee, with headroom
//! for the two witnesses) and returned to the handler, which fixes it in
//! the request the signer pins. The body is unsigned: the signer returns
//! witnesses and `airgap_core::tx::assemble_signed_tx` re-assembles the
//! signed tx for submission.

use pallas_codec::minicbor;
use pallas_codec::utils::{NonEmptyKeyValuePairs, NonEmptySet, Nullable, Set};
use pallas_primitives::conway::{
    Anchor, Certificate, GovActionId, TransactionBody, TransactionOutput, Vote, Voter,
    VotingProcedure,
};
use pallas_primitives::{Hash, NetworkId, StakeCredential, TransactionInput};

use shared::tx::{check_tx_hash_hex_len, decode_address, parse_input};
// Re-exported so handlers/util can name `tx_builder::TxInput` / `TxBuildError`.
use airgap_core::asset::Asset;
use airgap_core::tx::{make_asset_output, min_ada_for_output};
pub use shared::tx::{TxBuildError, TxInput};
use shared::vote::VoteChoice;

/// Optional rationale/manifest anchor: a public document URL plus the
/// 32-byte blake2b-256 hash of its contents (hex).
#[derive(Debug, Clone)]
pub struct AnchorInput {
    pub url: String,
    pub hash_hex: String,
}

#[derive(Debug)]
pub struct DrepTxBody {
    pub body_cbor: Vec<u8>,
    /// Fee computed from the encoded body size; carried into the request,
    /// where the signer pins it before signing.
    pub fee_lovelace: u64,
    pub change_to_payment_address_lovelace: u64,
}

fn drep_credential(keyhash: [u8; 28]) -> StakeCredential {
    StakeCredential::AddrKeyhash(Hash::from(keyhash))
}

fn build_anchor(anchor: &Option<AnchorInput>) -> Result<Nullable<Anchor>, TxBuildError> {
    match anchor {
        Some(a) => {
            let h =
                hex::decode(&a.hash_hex).map_err(|_| TxBuildError::HashHex(a.hash_hex.clone()))?;
            if h.len() != 32 {
                return Err(TxBuildError::HashHex(format!(
                    "anchor hash not 32 bytes (got {})",
                    h.len()
                )));
            }
            let mut hb = [0u8; 32];
            hb.copy_from_slice(&h);
            Ok(Nullable::Some(Anchor {
                url: a.url.clone(),
                content_hash: Hash::from(hb),
            }))
        }
        None => Ok(Nullable::Null),
    }
}

fn parse_inputs(utxo_inputs: &[TxInput]) -> Result<Vec<TransactionInput>, TxBuildError> {
    utxo_inputs.iter().map(parse_input).collect()
}

/// Assemble a complete one-change-output body with the supplied middle
/// (certificate or voting procedures).
fn make_body(
    inputs: Vec<TransactionInput>,
    change_output: TransactionOutput,
    fee_lovelace: u64,
    ttl_slot: u64,
    certificates: Option<NonEmptySet<Certificate>>,
    voting_procedures: Option<
        NonEmptyKeyValuePairs<Voter, NonEmptyKeyValuePairs<GovActionId, VotingProcedure>>,
    >,
) -> TransactionBody {
    TransactionBody {
        inputs: Set::from(inputs),
        outputs: vec![change_output],
        fee: fee_lovelace,
        ttl: Some(ttl_slot),
        certificates,
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
        voting_procedures,
        proposal_procedures: None,
        treasury_value: None,
        donation: None,
    }
}

fn encode(body: &TransactionBody) -> Result<Vec<u8>, TxBuildError> {
    let mut buf = Vec::new();
    minicbor::encode(body, &mut buf).map_err(|e| TxBuildError::Cbor(e.to_string()))?;
    Ok(buf)
}

fn one_cert(cert: Certificate) -> Result<NonEmptySet<Certificate>, TxBuildError> {
    NonEmptySet::try_from(vec![cert])
        .map_err(|_| TxBuildError::Cbor("could not build NonEmptySet for certs".into()))
}

// ---------------------------------------------------------------------------
// Fee and change, from the encoded body size and the live parameters
// ---------------------------------------------------------------------------

/// The protocol parameters the fee and the min-ADA change are computed from,
/// read live from the chain-data provider and checked against the
/// constitution's guardrails before use (`koios::protocol_params`).
#[derive(Debug, Clone, Copy)]
pub struct FeeParams {
    /// `txFeePerByte`.
    pub min_fee_a: u64,
    /// `txFeeFixed`.
    pub min_fee_b: u64,
    /// `utxoCostPerByte`.
    pub utxo_cost_per_byte: u64,
}

/// Conservative per-witness wire size: array tag + (len+vkey 32) + (len+sig 64).
const WITNESS_BYTES: u64 = 100;
/// Witness-set map + outer tx array + a small safety margin (also covers the
/// fee field growing from the draft's 0 to its real value).
const TX_WRAP_OVERHEAD: u64 = 32;
/// Every DRep tx carries exactly two vkey witnesses: payment key + DRep key.
const N_WITNESSES: u64 = 2;

/// Linear Cardano fee over the estimated wire size of the fully signed tx.
fn fee_for_body(body_cbor_len: usize, p: &FeeParams) -> u64 {
    let size = body_cbor_len as u64 + N_WITNESSES * WITNESS_BYTES + TX_WRAP_OVERHEAD;
    p.min_fee_a.saturating_mul(size).saturating_add(p.min_fee_b)
}

/// Body bytes per spent input: 2-element array, 32-byte hash bytestring, index.
const PREVIEW_INPUT_BYTES: u64 = 40;
/// Change-output bytes per preserved native asset (policy + name + quantity
/// + map overhead), conservatively.
const PREVIEW_ASSET_BYTES: u64 = 80;
/// Draft-body bytes independent of the inputs: change output, fee / TTL /
/// network fields, and the largest cert or voting procedure with a full
/// 128-byte anchor.
const PREVIEW_BASE_BYTES: u64 = 360;

/// Preview-screen fee estimate. The preview cannot encode the real body (the
/// operator has not entered the anchor / action yet), so this sizes a
/// worst-case body from the input and asset counts: deliberately at or above
/// the fee `build_*_body` later computes from the encoded body.
pub fn preview_fee_lovelace(n_inputs: usize, n_change_assets: usize, p: &FeeParams) -> u64 {
    let body_bytes = PREVIEW_BASE_BYTES
        + n_inputs as u64 * PREVIEW_INPUT_BYTES
        + n_change_assets as u64 * PREVIEW_ASSET_BYTES;
    fee_for_body(body_bytes as usize, p)
}

/// Change output back to the payment address, preserving any native assets the
/// spent UTxOs carry (drep sends no assets, so all of them return as change).
/// Guards that the change ADA covers the output's min-ADA, coin-only change
/// included, so the node will not reject an under-funded output.
fn change_output(
    payment: Vec<u8>,
    change: u64,
    assets: &[Asset],
    utxo_cost_per_byte: u64,
) -> Result<TransactionOutput, TxBuildError> {
    let out = make_asset_output(payment, change, assets)?;
    let need = min_ada_for_output(&out, utxo_cost_per_byte)?;
    if change < need {
        return Err(TxBuildError::InsufficientInputs {
            fee: need,
            utxo_total: change,
        });
    }
    Ok(out)
}

/// Encode the final body for an already-built middle. The fee comes from the
/// encoded size, which the change amount in turn depends on, so a draft body
/// with fee 0 and change at its ceiling (an upper bound on the final
/// encoding) is sized first, then the real fee and change are encoded.
/// `spent` leaves the wallet on top of the fee (the register deposit);
/// `refunded` comes back through the cert (the retire refund).
#[allow(clippy::too_many_arguments)]
fn finish_body(
    utxo_inputs: &[TxInput],
    payment: Vec<u8>,
    utxo_total: u64,
    spent: u64,
    refunded: u64,
    change_assets: &[Asset],
    ttl_slot: u64,
    certificates: Option<NonEmptySet<Certificate>>,
    voting_procedures: Option<
        NonEmptyKeyValuePairs<Voter, NonEmptyKeyValuePairs<GovActionId, VotingProcedure>>,
    >,
    fee_params: &FeeParams,
) -> Result<DrepTxBody, TxBuildError> {
    let change_ceiling = utxo_total.saturating_add(refunded);
    let draft_change = make_asset_output(payment.clone(), change_ceiling, change_assets)?;
    let mut body = make_body(
        parse_inputs(utxo_inputs)?,
        draft_change,
        0,
        ttl_slot,
        certificates,
        voting_procedures,
    );
    let fee = fee_for_body(encode(&body)?.len(), fee_params);
    let change = utxo_total
        .checked_sub(fee)
        .and_then(|v| v.checked_sub(spent))
        .and_then(|v| v.checked_add(refunded))
        .ok_or(TxBuildError::InsufficientInputs {
            fee: fee.saturating_add(spent),
            utxo_total,
        })?;
    body.fee = fee;
    body.outputs = vec![change_output(
        payment,
        change,
        change_assets,
        fee_params.utxo_cost_per_byte,
    )?];
    let body_cbor = encode(&body)?;
    Ok(DrepTxBody {
        body_cbor,
        fee_lovelace: fee,
        change_to_payment_address_lovelace: change,
    })
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

pub struct RegisterInputs<'a> {
    pub utxo_inputs: &'a [TxInput],
    pub utxo_total_lovelace: u64,
    pub change_assets: &'a [Asset],
    pub payment_address_bech32: &'a str,
    pub drep_keyhash: [u8; 28],
    pub deposit_lovelace: u64,
    pub anchor: Option<AnchorInput>,
    pub ttl_slot: u64,
    /// Live fee parameters (`koios::protocol_params`).
    pub fee_params: FeeParams,
}

pub fn build_register_body(input: &RegisterInputs) -> Result<DrepTxBody, TxBuildError> {
    let payment = decode_address(input.payment_address_bech32, "addr")?;
    let cert = Certificate::RegDRepCert(
        drep_credential(input.drep_keyhash),
        input.deposit_lovelace,
        build_anchor(&input.anchor)?,
    );
    // Inputs must cover fee + deposit; change = total - fee - deposit.
    finish_body(
        input.utxo_inputs,
        payment,
        input.utxo_total_lovelace,
        input.deposit_lovelace,
        0,
        input.change_assets,
        input.ttl_slot,
        Some(one_cert(cert)?),
        None,
        &input.fee_params,
    )
}

// ---------------------------------------------------------------------------
// Update / refresh
// ---------------------------------------------------------------------------

pub struct UpdateInputs<'a> {
    pub utxo_inputs: &'a [TxInput],
    pub utxo_total_lovelace: u64,
    pub change_assets: &'a [Asset],
    pub payment_address_bech32: &'a str,
    pub drep_keyhash: [u8; 28],
    pub anchor: Option<AnchorInput>,
    pub ttl_slot: u64,
    /// Live fee parameters (`koios::protocol_params`).
    pub fee_params: FeeParams,
}

pub fn build_update_body(input: &UpdateInputs) -> Result<DrepTxBody, TxBuildError> {
    let payment = decode_address(input.payment_address_bech32, "addr")?;
    let cert = Certificate::UpdateDRepCert(
        drep_credential(input.drep_keyhash),
        build_anchor(&input.anchor)?,
    );
    finish_body(
        input.utxo_inputs,
        payment,
        input.utxo_total_lovelace,
        0,
        0,
        input.change_assets,
        input.ttl_slot,
        Some(one_cert(cert)?),
        None,
        &input.fee_params,
    )
}

// ---------------------------------------------------------------------------
// Retire
// ---------------------------------------------------------------------------

pub struct RetireInputs<'a> {
    pub utxo_inputs: &'a [TxInput],
    pub utxo_total_lovelace: u64,
    pub change_assets: &'a [Asset],
    pub payment_address_bech32: &'a str,
    pub drep_keyhash: [u8; 28],
    pub deposit_refund_lovelace: u64,
    pub ttl_slot: u64,
    /// Live fee parameters (`koios::protocol_params`).
    pub fee_params: FeeParams,
}

pub fn build_retire_body(input: &RetireInputs) -> Result<DrepTxBody, TxBuildError> {
    let payment = decode_address(input.payment_address_bech32, "addr")?;
    let cert = Certificate::UnRegDRepCert(
        drep_credential(input.drep_keyhash),
        input.deposit_refund_lovelace,
    );
    // Refund is returned by the cert; change = total - fee + refund.
    finish_body(
        input.utxo_inputs,
        payment,
        input.utxo_total_lovelace,
        0,
        input.deposit_refund_lovelace,
        input.change_assets,
        input.ttl_slot,
        Some(one_cert(cert)?),
        None,
        &input.fee_params,
    )
}

// ---------------------------------------------------------------------------
// Vote
// ---------------------------------------------------------------------------

pub struct VoteInputs<'a> {
    pub utxo_inputs: &'a [TxInput],
    pub utxo_total_lovelace: u64,
    pub change_assets: &'a [Asset],
    pub payment_address_bech32: &'a str,
    pub drep_keyhash: [u8; 28],
    pub action_tx_hash_hex: &'a str,
    pub action_index: u32,
    pub vote: VoteChoice,
    pub anchor: Option<AnchorInput>,
    pub ttl_slot: u64,
    /// Live fee parameters (`koios::protocol_params`).
    pub fee_params: FeeParams,
}

pub fn build_vote_body(input: &VoteInputs) -> Result<DrepTxBody, TxBuildError> {
    let payment = decode_address(input.payment_address_bech32, "addr")?;

    check_tx_hash_hex_len(input.action_tx_hash_hex)?;
    let action_bytes = hex::decode(input.action_tx_hash_hex)
        .map_err(|_| TxBuildError::HashHex(input.action_tx_hash_hex.to_string()))?;
    if action_bytes.len() != 32 {
        return Err(TxBuildError::HashHex(input.action_tx_hash_hex.to_string()));
    }
    let mut action_hash = [0u8; 32];
    action_hash.copy_from_slice(&action_bytes);

    let vote = match input.vote {
        VoteChoice::No => Vote::No,
        VoteChoice::Yes => Vote::Yes,
        VoteChoice::Abstain => Vote::Abstain,
    };
    let procedure = VotingProcedure {
        vote,
        anchor: build_anchor(&input.anchor)?,
    };
    let gov_action_id = GovActionId {
        transaction_id: Hash::from(action_hash),
        action_index: input.action_index,
    };
    let inner = NonEmptyKeyValuePairs::Def(vec![(gov_action_id, procedure)]);
    let voter = Voter::DRepKey(Hash::from(input.drep_keyhash));
    let voting_procedures = NonEmptyKeyValuePairs::Def(vec![(voter, inner)]);

    finish_body(
        input.utxo_inputs,
        payment,
        input.utxo_total_lovelace,
        0,
        0,
        input.change_assets,
        input.ttl_slot,
        None,
        Some(voting_procedures),
        &input.fee_params,
    )
}

// Round-trip tests: build each body, then validate it with the matching
// request through `shared::tx_validator`. A pass proves the builder and the
// security-gate validator agree byte-for-byte on every operation.
#[cfg(test)]
mod tests {
    use super::*;

    const PARAMS: FeeParams = FeeParams {
        min_fee_a: 44,
        min_fee_b: 155_381,
        utxo_cost_per_byte: 4_310,
    };
    use shared::anchor::GovAnchor;
    use shared::chain_context::ChainContext;
    use shared::register::DRepRegisterRequest;
    use shared::retire::DRepRetireRequest;
    use shared::tx_validator;
    use shared::update::DRepUpdateRequest;
    use shared::utxo::UtxoInput;
    use shared::vote::DRepVoteRequest;
    use shared::wire_kind::DrepWireKind;

    const PAYMENT: &str = "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw";
    const KEYHASH: [u8; 28] = [0x42u8; 28];
    const TOTAL: u64 = 600_000_000;
    const DEPOSIT: u64 = 500_000_000;
    const TTL: u64 = 2_000_000;
    const ACTION: &str = "fdd468da5cc4ac8431dcd7e2b3211666c73bc229f85879469f67f1d9d51d344d";
    const ANCHOR_URL: &str = "https://example.com/drep.jsonld";

    fn anchor_hash_hex() -> String {
        hex::encode([0x5Au8; 32])
    }
    fn anchor_input() -> AnchorInput {
        AnchorInput {
            url: ANCHOR_URL.into(),
            hash_hex: anchor_hash_hex(),
        }
    }
    fn gov_anchor() -> GovAnchor {
        GovAnchor {
            url: ANCHOR_URL.into(),
            hash_hex: anchor_hash_hex(),
        }
    }
    fn drep_id() -> String {
        let mut d = vec![0x22u8];
        d.extend_from_slice(&KEYHASH);
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("drep").unwrap(), &d).unwrap()
    }
    fn utxo() -> Vec<TxInput> {
        vec![TxInput {
            tx_hash_hex: "00".repeat(32),
            tx_index: 0,
        }]
    }
    fn req_inputs() -> Vec<UtxoInput> {
        vec![UtxoInput {
            tx_hash_hex: "00".repeat(32),
            tx_index: 0,
            amount_lovelace: TOTAL,
            address_bech32: PAYMENT.into(),
        }]
    }
    fn cc() -> ChainContext {
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
    fn register_preserves_change_assets() {
        let assets = [Asset {
            policy_hex: "00112233445566778899aabbccddeeff00112233445566778899aabb".into(),
            asset_name_hex: "4e49474854".into(),
            quantity: 42,
        }];
        let u = utxo();
        let with_assets = build_register_body(&RegisterInputs {
            fee_params: PARAMS,
            utxo_inputs: &u,
            change_assets: &assets,
            utxo_total_lovelace: TOTAL,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            deposit_lovelace: DEPOSIT,
            anchor: Some(anchor_input()),
            ttl_slot: TTL,
        })
        .unwrap();
        let without = build_register_body(&RegisterInputs {
            fee_params: PARAMS,
            utxo_inputs: &u,
            change_assets: &[],
            utxo_total_lovelace: TOTAL,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            deposit_lovelace: DEPOSIT,
            anchor: Some(anchor_input()),
            ttl_slot: TTL,
        })
        .unwrap();
        // the preserved asset rides in the change output, so the body grows
        // (and with it the size-derived fee).
        assert!(with_assets.body_cbor.len() > without.body_cbor.len());
        assert!(with_assets.fee_lovelace > without.fee_lovelace);
    }

    #[test]
    fn register_guards_min_ada_for_asset_change() {
        let assets = [Asset {
            policy_hex: "00112233445566778899aabbccddeeff00112233445566778899aabb".into(),
            asset_name_hex: String::new(),
            quantity: 1,
        }];
        // change after fee + deposit is a few thousand lovelace, far below
        // an asset output's min-ADA.
        let err = build_register_body(&RegisterInputs {
            fee_params: PARAMS,
            utxo_inputs: &utxo(),
            change_assets: &assets,
            utxo_total_lovelace: DEPOSIT + 200_000,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            deposit_lovelace: DEPOSIT,
            anchor: Some(anchor_input()),
            ttl_slot: TTL,
        });
        assert!(err.is_err());
    }

    #[test]
    fn register_round_trip() {
        let built = build_register_body(&RegisterInputs {
            fee_params: PARAMS,
            utxo_inputs: &utxo(),
            change_assets: &[],
            utxo_total_lovelace: TOTAL,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            deposit_lovelace: DEPOSIT,
            anchor: Some(anchor_input()),
            ttl_slot: TTL,
        })
        .unwrap();
        assert_eq!(
            built.change_to_payment_address_lovelace,
            TOTAL - built.fee_lovelace - DEPOSIT
        );
        let req = DRepRegisterRequest {
            kind: DrepWireKind::DrepRegister,
            tx_body_cbor_hex: hex::encode(&built.body_cbor),
            fee_lovelace: built.fee_lovelace,
            change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
            deposit_lovelace: DEPOSIT,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT.into(),
            drep_id_bech32: drep_id(),
            anchor: Some(gov_anchor()),
            inputs: req_inputs(),
            operator_pin_proof: "0".repeat(16),
            chain_context: cc(),
        };
        tx_validator::validate_register_body(&built.body_cbor, &req).expect("round-trips");
    }

    #[test]
    fn update_round_trip_keepalive() {
        let built = build_update_body(&UpdateInputs {
            fee_params: PARAMS,
            utxo_inputs: &utxo(),
            change_assets: &[],
            utxo_total_lovelace: TOTAL,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            anchor: None,
            ttl_slot: TTL,
        })
        .unwrap();
        let req = DRepUpdateRequest {
            kind: DrepWireKind::DrepUpdate,
            tx_body_cbor_hex: hex::encode(&built.body_cbor),
            fee_lovelace: built.fee_lovelace,
            change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT.into(),
            drep_id_bech32: drep_id(),
            anchor: None,
            inputs: req_inputs(),
            operator_pin_proof: "0".repeat(16),
            chain_context: cc(),
        };
        tx_validator::validate_update_body(&built.body_cbor, &req).expect("round-trips");
    }

    #[test]
    fn retire_round_trip() {
        let built = build_retire_body(&RetireInputs {
            fee_params: PARAMS,
            utxo_inputs: &utxo(),
            change_assets: &[],
            utxo_total_lovelace: TOTAL,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            deposit_refund_lovelace: DEPOSIT,
            ttl_slot: TTL,
        })
        .unwrap();
        assert_eq!(
            built.change_to_payment_address_lovelace,
            TOTAL - built.fee_lovelace + DEPOSIT
        );
        let req = DRepRetireRequest {
            kind: DrepWireKind::DrepRetire,
            tx_body_cbor_hex: hex::encode(&built.body_cbor),
            fee_lovelace: built.fee_lovelace,
            change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
            deposit_refund_lovelace: DEPOSIT,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT.into(),
            drep_id_bech32: drep_id(),
            inputs: req_inputs(),
            operator_pin_proof: "0".repeat(16),
            chain_context: cc(),
        };
        tx_validator::validate_retire_body(&built.body_cbor, &req).expect("round-trips");
    }

    #[test]
    fn vote_round_trip_with_anchor() {
        let built = build_vote_body(&VoteInputs {
            fee_params: PARAMS,
            utxo_inputs: &utxo(),
            change_assets: &[],
            utxo_total_lovelace: TOTAL,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            action_tx_hash_hex: ACTION,
            action_index: 0,
            vote: VoteChoice::Yes,
            anchor: Some(anchor_input()),
            ttl_slot: TTL,
        })
        .unwrap();
        let req = DRepVoteRequest {
            kind: DrepWireKind::DrepVote,
            tx_body_cbor_hex: hex::encode(&built.body_cbor),
            fee_lovelace: built.fee_lovelace,
            change_to_payment_address_lovelace: built.change_to_payment_address_lovelace,
            ttl_slot: TTL,
            payment_address_bech32: PAYMENT.into(),
            drep_id_bech32: drep_id(),
            action_tx_hash_hex: ACTION.into(),
            action_index: 0,
            vote: VoteChoice::Yes,
            anchor: Some(gov_anchor()),
            inputs: req_inputs(),
            operator_pin_proof: "0".repeat(16),
            chain_context: cc(),
        };
        tx_validator::validate_vote_body(&built.body_cbor, &req).expect("round-trips");
    }

    #[test]
    fn register_rejects_insufficient_inputs() {
        let err = build_register_body(&RegisterInputs {
            fee_params: PARAMS,
            utxo_inputs: &utxo(),
            change_assets: &[],
            utxo_total_lovelace: 200_000, // cannot cover deposit
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            deposit_lovelace: DEPOSIT,
            anchor: None,
            ttl_slot: TTL,
        })
        .unwrap_err();
        assert!(matches!(err, TxBuildError::InsufficientInputs { .. }));
    }

    #[test]
    fn fee_scales_with_input_count() {
        let update = |inputs: &[TxInput]| {
            build_update_body(&UpdateInputs {
                fee_params: PARAMS,
                utxo_inputs: inputs,
                change_assets: &[],
                utxo_total_lovelace: TOTAL,
                payment_address_bech32: PAYMENT,
                drep_keyhash: KEYHASH,
                anchor: None,
                ttl_slot: TTL,
            })
            .unwrap()
        };
        let one = update(&utxo());
        let many_inputs: Vec<TxInput> = (0..40u8)
            .map(|i| TxInput {
                tx_hash_hex: format!("{i:02x}").repeat(32),
                tx_index: 0,
            })
            .collect();
        let many = update(&many_inputs);
        // 39 extra inputs, ≥36 body bytes each: a flat fee would miss this.
        assert!(many.fee_lovelace >= one.fee_lovelace + 39 * 36 * 44);
        // and the fee covers the ledger minimum for the fully signed tx:
        // body + two ~101-byte vkey witnesses + the outer wrapper.
        let signed_size = many.body_cbor.len() as u64 + 2 * 101 + 10;
        assert!(many.fee_lovelace >= 44 * signed_size + 155_381);
    }

    #[test]
    fn coin_only_change_below_min_ada_is_rejected() {
        // 1.0 ADA at the address covers the fee, but the pure-ADA change left
        // over is below the ~0.86 ADA min-UTxO: must fail at build time, not
        // at the node after the signing ceremony.
        let err = build_update_body(&UpdateInputs {
            fee_params: PARAMS,
            utxo_inputs: &utxo(),
            change_assets: &[],
            utxo_total_lovelace: 1_000_000,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            anchor: None,
            ttl_slot: TTL,
        })
        .unwrap_err();
        assert!(matches!(err, TxBuildError::InsufficientInputs { .. }));
    }

    #[test]
    fn preview_fee_is_at_or_above_built_fee() {
        let built = build_register_body(&RegisterInputs {
            fee_params: PARAMS,
            utxo_inputs: &utxo(),
            change_assets: &[],
            utxo_total_lovelace: TOTAL,
            payment_address_bech32: PAYMENT,
            drep_keyhash: KEYHASH,
            deposit_lovelace: DEPOSIT,
            anchor: Some(anchor_input()),
            ttl_slot: TTL,
        })
        .unwrap();
        assert!(preview_fee_lovelace(1, 0, &PARAMS) >= built.fee_lovelace);
    }

    #[test]
    fn the_fee_follows_the_live_parameters() {
        let u = utxo();
        let build = |p: FeeParams| {
            build_update_body(&UpdateInputs {
                fee_params: p,
                utxo_inputs: &u,
                change_assets: &[],
                utxo_total_lovelace: TOTAL,
                payment_address_bech32: PAYMENT,
                drep_keyhash: KEYHASH,
                anchor: Some(anchor_input()),
                ttl_slot: TTL,
            })
            .unwrap()
        };
        let now = build(PARAMS);
        let dearer = build(FeeParams {
            min_fee_a: 50,
            min_fee_b: 200_000,
            ..PARAMS
        });
        assert!(dearer.fee_lovelace > now.fee_lovelace);
        assert_eq!(
            now.change_to_payment_address_lovelace,
            TOTAL - now.fee_lovelace
        );
    }
}
