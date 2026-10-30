//! Role-neutral pre-sign body-validation primitives.
//!
//! Before an air-gapped signer hashes a Conway `TransactionBody` and
//! signs it, it must verify the body actually does what the matching
//! request says. The pieces that are identical across every operation
//! (decoding the body, the central forbidden-field guard, binding the
//! inputs to the request, reading an output, comparing a rationale
//! anchor, and the blake2b-224 credential hash) live here so SPO Tools,
//! DREP Tools, and Wallet Tools share one implementation and cannot
//! drift apart on the checks that gate key use. Each tool layers its
//! operation-specific validator on top (asserting the exact cert /
//! voting procedure it expects).

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use pallas_addresses::{Address, StakePayload};
use pallas_codec::minicbor;
use pallas_codec::utils::Nullable;
use pallas_primitives::conway::{Anchor, PseudoTransactionOutput, TransactionBody, Value};
use pallas_primitives::StakeCredential;

use crate::utxo::UtxoInput;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("body CBOR decode failed: {0}")]
    Decode(String),
    #[error("invalid bech32 address `{0}`: {1}")]
    BadAddress(String, String),
    #[error("invalid hex `{0}`: {1}")]
    BadHex(String, String),
    #[error("body does not match request: {0}")]
    Mismatch(&'static str),
}

/// Decode raw CBOR bytes as a Conway [`TransactionBody`].
///
/// Decoding one item from the front is not enough: minicbor ignores
/// trailing bytes, but the signer hashes and signs the full byte string,
/// so the body item must consume the buffer exactly.
pub fn decode_body(body_bytes: &[u8]) -> Result<TransactionBody, ValidationError> {
    let mut dec = minicbor::Decoder::new(body_bytes);
    let body: TransactionBody = dec
        .decode()
        .map_err(|e| ValidationError::Decode(e.to_string()))?;
    if dec.position() != body_bytes.len() {
        return Err(ValidationError::Decode(format!(
            "body cbor has {} trailing bytes",
            body_bytes.len() - dec.position()
        )));
    }
    Ok(body)
}

/// Reject every Conway TransactionBody field that none of these tools'
/// operations use. An attacker controlling the online tool's body
/// construction must not be able to wedge in e.g. a treasury donation, a
/// mint, a proposal procedure, or collateral by leaving the field
/// unchecked. They are enumerated once here so each operation's validator
/// just calls into this list.
///
/// `allow_voting_procedures` lets the vote paths (SPO and DRep) carry a
/// `voting_procedures` field while every other dangerous field stays
/// forbidden, so a vote validator cannot drift from the other operations'
/// guard. `certificates` and `withdrawals` are intentionally NOT decided
/// here: each operation validator asserts their exact presence/absence
/// and contents itself.
pub fn assert_no_extra_fields_inner(
    body: &TransactionBody,
    allow_voting_procedures: bool,
    allow_aux_data: bool,
) -> Result<(), ValidationError> {
    if body.network_id != Some(pallas_primitives::NetworkId::Mainnet) {
        return Err(ValidationError::Mismatch("network_id must be mainnet"));
    }
    if body.donation.is_some() {
        return Err(ValidationError::Mismatch("unexpected donation"));
    }
    if body.treasury_value.is_some() {
        return Err(ValidationError::Mismatch("unexpected treasury_value"));
    }
    if !allow_voting_procedures && body.voting_procedures.is_some() {
        return Err(ValidationError::Mismatch("unexpected voting_procedures"));
    }
    if body.proposal_procedures.is_some() {
        return Err(ValidationError::Mismatch("unexpected proposal_procedures"));
    }
    if body.mint.is_some() {
        return Err(ValidationError::Mismatch("unexpected mint"));
    }
    if body.collateral.is_some() {
        return Err(ValidationError::Mismatch("unexpected collateral"));
    }
    if body.collateral_return.is_some() {
        return Err(ValidationError::Mismatch("unexpected collateral_return"));
    }
    if body.total_collateral.is_some() {
        return Err(ValidationError::Mismatch("unexpected total_collateral"));
    }
    if body.reference_inputs.is_some() {
        return Err(ValidationError::Mismatch("unexpected reference_inputs"));
    }
    if body.required_signers.is_some() {
        return Err(ValidationError::Mismatch("unexpected required_signers"));
    }
    if body.script_data_hash.is_some() {
        return Err(ValidationError::Mismatch("unexpected script_data_hash"));
    }
    if body.auxiliary_data_hash.is_some() && !allow_aux_data {
        return Err(ValidationError::Mismatch("unexpected auxiliary_data_hash"));
    }
    if body.validity_interval_start.is_some() {
        return Err(ValidationError::Mismatch(
            "unexpected validity_interval_start",
        ));
    }
    Ok(())
}

/// The highest fee any of these signers will put a signature under,
/// whatever the request says. The body validators bind the fee to the
/// request, but the request is written by the online tool, in some tools
/// from provider-supplied protocol parameters; without a ceiling a
/// compromised online tool or a lying provider could burn the funding
/// UTxOs into the fee with only the operator's reading of the preview in
/// the way.
///
/// 3 ADA leaves room over the largest fee these operations can honestly
/// produce at the current mainnet parameters: about 0.88 ADA for a
/// transaction of the maximum size (44 x 16384 + 155381 lovelace), plus,
/// where a tool folds a sub-min-ADA remainder into the fee, just under
/// 1 ADA more. Should a parameter change ever lift honest fees past it, the
/// signers refuse (fail closed) and this constant is raised in a new
/// release.
pub const MAX_FEE_LOVELACE: u64 = 3_000_000;

/// Refuse a fee above [`MAX_FEE_LOVELACE`].
pub fn assert_fee_within_ceiling(fee_lovelace: u64) -> Result<(), ValidationError> {
    if fee_lovelace > MAX_FEE_LOVELACE {
        return Err(ValidationError::Mismatch("fee above the signer's ceiling"));
    }
    Ok(())
}

/// Unix time of mainnet slot 0 on the one-slot-per-second clock that has
/// run since Shelley: slot 4 492 800 began at 1 596 059 091 (2020-07-29
/// 21:44:51 UTC), so `slot = unix - MAINNET_SLOT_ZERO_UNIX` for any time
/// after that.
pub const MAINNET_SLOT_ZERO_UNIX: u64 = 1_591_566_291;

/// The furthest a transaction's time-to-live may lie beyond the signer's
/// own clock: three hours of slots.
///
/// The body validators bind the TTL to the request and require it to be
/// after the request's `current_slot`, but both numbers are written by
/// the online tool. Without an upper bound a compromised online tool could
/// set a TTL years ahead, and the signed transaction would stay valid for
/// as long, to be held back and submitted later. The online tools set a
/// TTL two hours past the tip. Three hours leaves one hour for a signer
/// clock that runs behind, and the time spent between building and
/// signing only brings the TTL closer to the clock. Should the slot length ever change, the signers refuse
/// (fail closed) and the slot constant is updated in a new release.
pub const MAX_TTL_AHEAD_SLOTS: u64 = 10_800;

/// The mainnet slot at `unix` seconds (saturating at slot 0 for an
/// impossible earlier time).
pub fn mainnet_slot_at(unix: u64) -> u64 {
    unix.saturating_sub(MAINNET_SLOT_ZERO_UNIX)
}

/// Refuse a TTL more than [`MAX_TTL_AHEAD_SLOTS`] past the slot the
/// signer's own clock reads (`now_unix`).
pub fn assert_ttl_within_window(ttl_slot: u64, now_unix: u64) -> Result<(), ValidationError> {
    let limit = mainnet_slot_at(now_unix).saturating_add(MAX_TTL_AHEAD_SLOTS);
    if ttl_slot > limit {
        return Err(ValidationError::Mismatch(
            "ttl too far past the signer's clock",
        ));
    }
    Ok(())
}

/// Confirm that `address_bech32` is controlled by the payment key the
/// signer holds: its payment credential must be the blake2b-224 hash of
/// `payment_vkey`.
///
/// The body validators pin the change output to the request's payment
/// address, but the request is written by the online tool. Without this
/// check a compromised online tool could name an address of its own as the
/// payment address, spend the operator's real UTxOs (which the payment key
/// can sign for) and collect the change there; only the operator reading a
/// bech32 string would stand in the way. Only the payment part is bound:
/// the address may be an enterprise address or carry any stake part, so a
/// separate fee address with its own key works as before. A change address
/// with the right payment credential but a foreign stake part stays
/// spendable by this key alone.
pub fn assert_payment_key_controls_address(
    payment_vkey: &[u8; 32],
    address_bech32: &str,
) -> Result<(), ValidationError> {
    use pallas_addresses::ShelleyPaymentPart;
    let parsed = Address::from_bech32(address_bech32)
        .map_err(|e| ValidationError::BadAddress(address_bech32.to_string(), e.to_string()))?;
    let shelley = match &parsed {
        Address::Shelley(s) => s,
        _ => {
            return Err(ValidationError::Mismatch(
                "payment address is not a Shelley payment address",
            ))
        }
    };
    match shelley.payment() {
        ShelleyPaymentPart::Key(h) if h.as_ref() == blake2b224(payment_vkey) => Ok(()),
        ShelleyPaymentPart::Key(_) => Err(ValidationError::Mismatch(
            "payment address is not controlled by this signer's payment key",
        )),
        ShelleyPaymentPart::Script(_) => Err(ValidationError::Mismatch(
            "payment address is script-controlled",
        )),
    }
}

/// Decode a bech32 address to its raw on-chain bytes.
pub fn addr_bytes(bech32: &str) -> Result<Vec<u8>, ValidationError> {
    Address::from_bech32(bech32)
        .map(|a| a.to_vec())
        .map_err(|e| ValidationError::BadAddress(bech32.to_string(), e.to_string()))
}

/// Returns (address_bytes, lovelace) from an output, accepting both
/// coin-only and multi-asset outputs and rejecting the legacy output shape.
/// A change output legitimately carries the wallet's native assets, so the
/// multi-asset shape is read for its lovelace rather than refused. Token
/// preservation is enforced structurally, not here: `assert_no_extra_fields`
/// forbids minting and every validator pins the exact output count with all
/// outputs at operator addresses, so native assets are conserved by the
/// ledger and can only return to the operator's own outputs. Outputs
/// carrying a `datum_option` or `script_ref` are refused: no operation in
/// these tools produces either, and neither is ever shown to the operator,
/// so they must not ride along on a signed body.
pub fn output_pair(
    out: &pallas_primitives::conway::TransactionOutput,
) -> Result<(&[u8], u64), ValidationError> {
    match out {
        PseudoTransactionOutput::PostAlonzo(p) => {
            if p.datum_option.is_some() {
                return Err(ValidationError::Mismatch(
                    "unexpected datum_option in output",
                ));
            }
            if p.script_ref.is_some() {
                return Err(ValidationError::Mismatch("unexpected script_ref in output"));
            }
            let coin = match &p.value {
                Value::Coin(n) => *n,
                Value::Multiasset(n, _) => *n,
            };
            Ok((p.address.as_ref(), coin))
        }
        PseudoTransactionOutput::Legacy(_) => Err(ValidationError::Mismatch("legacy output shape")),
    }
}

/// Cross-check that the body's TransactionInputs match the request's
/// inputs and that every input claims to live at the payment address.
///
/// Two-part check, both directions:
///
/// 1. Each (tx_hash, tx_index) in `request_inputs` must appear in
///    `body_inputs`, and vice-versa. Catches a swapped body whose funding
///    tx differs from what the operator approved.
/// 2. Every `request_inputs[i].address_bech32` must equal the request's
///    payment_address. Catches the scenario where the same payment.skey
///    controls both an enterprise `addr1v(K)` and a base `addr1q(K,
///    stake_X)` form: a compromised online tool could otherwise fund the
///    transaction from a different form than the operator reviewed.
///
/// Architectural limit: the address field is *claimed* by the online tool;
/// the air-gapped signer cannot independently consult the chain.
/// Operator-visual review of the signer-side preview remains the trust
/// anchor.
pub fn assert_inputs_bind_to_request(
    body_inputs: &[pallas_primitives::TransactionInput],
    request_inputs: &[UtxoInput],
    payment_address_bech32: &str,
) -> Result<(), ValidationError> {
    // Empty-request guard: the length-equality check below would otherwise
    // accept a body with zero inputs because two empty vecs compare equal.
    // A zero-input transaction is structurally invalid on Cardano, but the
    // signer must reject it here rather than rely on the node to detect it
    // after broadcast.
    if request_inputs.is_empty() {
        return Err(ValidationError::Mismatch("request.inputs is empty"));
    }
    if body_inputs.len() != request_inputs.len() {
        return Err(ValidationError::Mismatch("input count"));
    }

    let mut req_pairs: Vec<([u8; 32], u32)> = Vec::with_capacity(request_inputs.len());
    for u in request_inputs {
        if u.address_bech32 != payment_address_bech32 {
            return Err(ValidationError::Mismatch(
                "input address does not match payment address",
            ));
        }
        let bytes = hex::decode(&u.tx_hash_hex)
            .map_err(|e| ValidationError::BadHex(u.tx_hash_hex.clone(), e.to_string()))?;
        if bytes.len() != 32 {
            return Err(ValidationError::Mismatch("input tx_hash length"));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        req_pairs.push((h, u.tx_index));
    }
    req_pairs.sort();

    // Reject duplicate (tx_hash, tx_index) pairs in the request: a sorted
    // Vec lets a same-pair duplicate slip past the body-equals-request
    // check if the body also duplicates. Conway nodes reject duplicate
    // inputs at submit, but the signer is the trust anchor and must not
    // depend on submission-time invariants. After the sort, any duplicate
    // sits next to its twin.
    if req_pairs.windows(2).any(|w| w[0] == w[1]) {
        return Err(ValidationError::Mismatch(
            "duplicate (tx_hash, tx_index) in request inputs",
        ));
    }

    let mut body_pairs: Vec<([u8; 32], u32)> = Vec::with_capacity(body_inputs.len());
    for i in body_inputs {
        let mut h = [0u8; 32];
        h.copy_from_slice(i.transaction_id.as_ref());
        // Pallas decodes the body index as u64; a lossy `as u32` cast would
        // let a body input with index k + 2^32 alias the request's index k
        // and slip past the equality check below.
        let index = u32::try_from(i.index)
            .map_err(|_| ValidationError::Mismatch("input index out of range"))?;
        body_pairs.push((h, index));
    }
    body_pairs.sort();

    if req_pairs != body_pairs {
        return Err(ValidationError::Mismatch(
            "body inputs do not match request inputs",
        ));
    }
    Ok(())
}

/// Parse a `stake1...` bech32 into a [`StakeCredential`] (key or script).
pub fn stake_credential_from_bech32(bech32: &str) -> Result<StakeCredential, ValidationError> {
    let parsed = Address::from_bech32(bech32)
        .map_err(|e| ValidationError::BadAddress(bech32.to_string(), e.to_string()))?;
    let stake = match parsed {
        Address::Stake(s) => s,
        _ => {
            return Err(ValidationError::Mismatch(
                "stake credential is not a stake address",
            ))
        }
    };
    Ok(match stake.payload() {
        StakePayload::Stake(h) => StakeCredential::AddrKeyhash(*h),
        StakePayload::Script(h) => StakeCredential::ScriptHash(*h),
    })
}

/// Compare an optional rationale anchor (as `(url, hash_hex)` parts) to an
/// on-chain `Nullable<Anchor>`. Absent request anchor matches a
/// null/undefined on-chain anchor and nothing else; a present request
/// anchor must equal the on-chain URL and 32-byte content hash. Tools wrap
/// this with their own typed anchor.
pub fn anchor_matches_parts(
    req: Option<(&str, &str)>,
    on_chain: &Nullable<Anchor>,
) -> Result<bool, ValidationError> {
    match (req, on_chain) {
        (Some((url, hash_hex)), Nullable::Some(anchor)) => {
            if url != anchor.url {
                return Ok(false);
            }
            let h = hex::decode(hash_hex)
                .map_err(|e| ValidationError::BadHex(hash_hex.to_string(), e.to_string()))?;
            Ok(h.len() == 32 && h.as_slice() == anchor.content_hash.as_ref())
        }
        (Some(_), _) => Ok(false),
        (None, Nullable::Some(_)) => Ok(false),
        (None, _) => Ok(true),
    }
}

/// blake2b-224 (28-byte) digest: the Cardano credential-hash function
/// used to derive a key hash (pool id, DRep id, key credential) from a
/// 32-byte Ed25519 verification key.
pub fn blake2b224(bytes: &[u8]) -> [u8; 28] {
    let mut hasher = Blake2bVar::new(28).expect("blake2b 224 init");
    hasher.update(bytes);
    let mut out = [0u8; 28];
    hasher.finalize_variable(&mut out).expect("blake2b 224 fin");
    out
}

/// blake2b-256 (32-byte) digest: the Cardano metadata content-hash and the
/// payload a CIP-100 author witness signs.
pub fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("blake2b 256 fin");
    out
}

/// Assert that `bytes` is a CIP-100 canonical body: the N-Quads
/// serialization an author witness signs, and never a transaction body.
///
/// A CIP-100 author witness and a Cardano transaction witness are both an
/// ed25519 signature over blake2b-256 of a byte string, produced by the same
/// key. Without this guard a compromised online tool could hand the signer
/// the CBOR of a malicious transaction body labelled as a canonical body and
/// obtain a valid transaction witness. The load-bearing guarantee is the
/// first-byte gate: an N-Quads document begins with a blank-node (`_`, 0x5F)
/// or IRI (`<`, 0x3C) subject, both < 0x80, whereas a Conway
/// `TransactionBody` is a CBOR map whose first byte is >= 0x80. That gate
/// alone makes the two preimage spaces disjoint, reinforced structurally
/// because `canonical_body` is a Rust `String` (valid UTF-8) whose leading
/// byte can never be a 0x80-0xBF CBOR map header. The `decode_body` check
/// below is defense-in-depth only and unreachable-by-design once the
/// first-byte gate has passed; it must not be relied on alone. Forging a
/// transaction witness this way therefore reduces to a blake2b-256 collision.
pub fn assert_canonical_body_nquads(bytes: &[u8]) -> Result<(), ValidationError> {
    if bytes.is_empty() {
        return Err(ValidationError::Mismatch("canonical body is empty"));
    }
    match bytes[0] {
        b'_' | b'<' => {}
        _ => {
            return Err(ValidationError::Mismatch(
                "canonical body must begin with an N-Quads subject",
            ))
        }
    }
    if !bytes.ends_with(b".\n") && !bytes.ends_with(b" .") {
        return Err(ValidationError::Mismatch(
            "canonical body must end with an N-Quad statement",
        ));
    }
    if decode_body(bytes).is_ok() {
        return Err(ValidationError::Mismatch(
            "canonical body decodes as a transaction body",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_codec::utils::{Bytes, Set};
    use pallas_primitives::conway::{TransactionBody, TransactionOutput};
    use pallas_primitives::{Hash, NetworkId, TransactionInput};

    const PAYMENT_ADDR: &str = "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw";

    fn coin_output(addr_bech: &str, lovelace: u64) -> TransactionOutput {
        let addr = Address::from_bech32(addr_bech).unwrap();
        PseudoTransactionOutput::PostAlonzo(
            pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(addr.to_vec()),
                value: Value::Coin(lovelace),
                datum_option: None,
                script_ref: None,
            },
        )
    }

    fn dummy_utxo_input() -> UtxoInput {
        UtxoInput {
            tx_hash_hex: "00".repeat(32),
            tx_index: 0,
            amount_lovelace: 0,
            address_bech32: PAYMENT_ADDR.into(),
        }
    }

    fn clean_body() -> TransactionBody {
        TransactionBody {
            inputs: Set::from(vec![TransactionInput {
                transaction_id: Hash::from([0u8; 32]),
                index: 0,
            }]),
            outputs: vec![coin_output(PAYMENT_ADDR, 1_000_000)],
            fee: 200_000,
            ttl: Some(2_000_000),
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
        }
    }

    #[test]
    fn clean_body_passes_guard() {
        assert_no_extra_fields_inner(&clean_body(), false, false).unwrap();
    }

    #[test]
    fn decode_body_round_trips_clean_body() {
        let mut buf = Vec::new();
        minicbor::encode(clean_body(), &mut buf).unwrap();
        decode_body(&buf).unwrap();
    }

    #[test]
    fn decode_body_rejects_trailing_bytes() {
        // A valid body item followed by garbage decodes fine as a prefix,
        // but the signer hashes and signs the full byte string, so the
        // prefix alone must not pass validation.
        let mut buf = Vec::new();
        minicbor::encode(clean_body(), &mut buf).unwrap();
        buf.push(0x00);
        let err = decode_body(&buf).unwrap_err();
        assert!(matches!(err, ValidationError::Decode(msg) if msg.contains("trailing")));
    }

    #[test]
    fn guard_rejects_donation() {
        let mut b = clean_body();
        b.donation = Some(pallas_primitives::PositiveCoin::try_from(1u64).unwrap());
        let err = assert_no_extra_fields_inner(&b, false, false).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("unexpected donation")
        ));
    }

    #[test]
    fn guard_rejects_voting_procedures_unless_allowed() {
        let mut b = clean_body();
        b.network_id = Some(NetworkId::Mainnet);
        // A bare voting_procedures presence is enough; build a trivial one.
        use pallas_codec::utils::NonEmptyKeyValuePairs;
        use pallas_primitives::conway::{GovActionId, Vote, Voter, VotingProcedure};
        let vp = VotingProcedure {
            vote: Vote::Yes,
            anchor: Nullable::Null,
        };
        let inner = NonEmptyKeyValuePairs::Def(vec![(
            GovActionId {
                transaction_id: Hash::from([1u8; 32]),
                action_index: 0,
            },
            vp,
        )]);
        let voter = Voter::DRepKey(Hash::from([2u8; 28]));
        b.voting_procedures = Some(NonEmptyKeyValuePairs::Def(vec![(voter, inner)]));
        assert!(assert_no_extra_fields_inner(&b, false, false).is_err());
        assert_no_extra_fields_inner(&b, true, false).unwrap();
    }

    #[test]
    fn guard_rejects_non_mainnet() {
        let mut b = clean_body();
        b.network_id = Some(NetworkId::Testnet);
        let err = assert_no_extra_fields_inner(&b, false, false).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("network_id must be mainnet")
        ));
    }

    #[test]
    fn inputs_bind_happy_path() {
        let b = clean_body();
        assert_inputs_bind_to_request(&b.inputs, &[dummy_utxo_input()], PAYMENT_ADDR).unwrap();
    }

    #[test]
    fn inputs_bind_rejects_empty_request() {
        let b = clean_body();
        let err = assert_inputs_bind_to_request(&b.inputs, &[], PAYMENT_ADDR).unwrap_err();
        assert!(matches!(err, ValidationError::Mismatch(s) if s.contains("empty")));
    }

    #[test]
    fn inputs_bind_rejects_index_above_u32_range() {
        // index 2^32 truncates to 0 under a lossy `as u32` cast, which would
        // alias the request's index 0 and pass the binding check; it must be
        // rejected outright instead.
        let body_inputs = vec![TransactionInput {
            transaction_id: Hash::from([0u8; 32]),
            index: 1u64 << 32,
        }];
        let err = assert_inputs_bind_to_request(&body_inputs, &[dummy_utxo_input()], PAYMENT_ADDR)
            .unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("input index out of range")
        ));
    }

    #[test]
    fn output_pair_reads_coin_output() {
        let out = coin_output(PAYMENT_ADDR, 5_000_000);
        let (addr, coin) = output_pair(&out).unwrap();
        assert_eq!(coin, 5_000_000);
        assert_eq!(addr, addr_bytes(PAYMENT_ADDR).unwrap().as_slice());
    }

    #[test]
    fn output_pair_rejects_datum_option() {
        use pallas_primitives::babbage::PseudoDatumOption;
        let addr = Address::from_bech32(PAYMENT_ADDR).unwrap();
        let out: TransactionOutput = PseudoTransactionOutput::PostAlonzo(
            pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(addr.to_vec()),
                value: Value::Coin(1_000_000),
                datum_option: Some(PseudoDatumOption::Hash(Hash::from([0u8; 32]))),
                script_ref: None,
            },
        );
        let err = output_pair(&out).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("unexpected datum_option in output")
        ));
    }

    #[test]
    fn output_pair_rejects_script_ref() {
        use pallas_codec::utils::CborWrap;
        use pallas_primitives::alonzo::NativeScript;
        use pallas_primitives::conway::PseudoScript;
        let addr = Address::from_bech32(PAYMENT_ADDR).unwrap();
        let out: TransactionOutput = PseudoTransactionOutput::PostAlonzo(
            pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
                address: Bytes::from(addr.to_vec()),
                value: Value::Coin(1_000_000),
                datum_option: None,
                script_ref: Some(CborWrap(PseudoScript::NativeScript(
                    NativeScript::InvalidBefore(0),
                ))),
            },
        );
        let err = output_pair(&out).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("unexpected script_ref in output")
        ));
    }

    #[test]
    fn mainnet_slot_follows_the_shelley_anchor() {
        // Slot 4 492 800 began at the Shelley hard fork, 1 596 059 091.
        assert_eq!(mainnet_slot_at(1_596_059_091), 4_492_800);
        assert_eq!(mainnet_slot_at(1_596_059_092), 4_492_801);
        assert_eq!(mainnet_slot_at(0), 0);
    }

    #[test]
    fn ttl_window_is_three_hours_past_the_signer_clock() {
        let now = 1_790_000_000;
        let now_slot = mainnet_slot_at(now);
        // Two hours ahead, what the online tools build: accepted.
        assert_ttl_within_window(now_slot + 7_200, now).unwrap();
        // Exactly at the limit: accepted.
        assert_ttl_within_window(now_slot + MAX_TTL_AHEAD_SLOTS, now).unwrap();
        // One slot past it, or years ahead: refused.
        assert!(matches!(
            assert_ttl_within_window(now_slot + MAX_TTL_AHEAD_SLOTS + 1, now).unwrap_err(),
            ValidationError::Mismatch("ttl too far past the signer's clock")
        ));
        assert!(assert_ttl_within_window(u64::MAX, now).is_err());
        // A TTL already behind the clock is not this check's business.
        assert_ttl_within_window(now_slot - 10, now).unwrap();
    }

    #[test]
    fn fee_ceiling_is_inclusive() {
        assert_fee_within_ceiling(0).unwrap();
        assert_fee_within_ceiling(170_000).unwrap();
        assert_fee_within_ceiling(MAX_FEE_LOVELACE).unwrap();
        let err = assert_fee_within_ceiling(MAX_FEE_LOVELACE + 1).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch("fee above the signer's ceiling")
        ));
    }

    #[test]
    fn payment_key_binding_checks_only_the_payment_credential() {
        use pallas_addresses::{
            Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
        };
        use pallas_crypto::hash::Hash as CHash;
        let own = [0x11u8; 32];
        let other = [0x33u8; 32];
        let kh = |v: &[u8; 32]| CHash::<28>::from(blake2b224(v));
        let addr = |pay: ShelleyPaymentPart, del: ShelleyDelegationPart| {
            ShelleyAddress::new(Network::Mainnet, pay, del)
                .to_bech32()
                .unwrap()
        };
        // Own key, enterprise form: a separate fee address with its own key.
        let enterprise = addr(
            ShelleyPaymentPart::key_hash(kh(&own)),
            ShelleyDelegationPart::Null,
        );
        assert_payment_key_controls_address(&own, &enterprise).unwrap();
        // Own key with any stake part, own or foreign.
        let base = addr(
            ShelleyPaymentPart::key_hash(kh(&own)),
            ShelleyDelegationPart::key_hash(kh(&[0x22; 32])),
        );
        assert_payment_key_controls_address(&own, &base).unwrap();
        // Another payment key: refused, whatever the stake part.
        let foreign = addr(
            ShelleyPaymentPart::key_hash(kh(&other)),
            ShelleyDelegationPart::key_hash(kh(&[0x22; 32])),
        );
        let err = assert_payment_key_controls_address(&own, &foreign).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Mismatch(
                "payment address is not controlled by this signer's payment key"
            )
        ));
        // A script address whose hash equals the key hash is still refused.
        let script = addr(
            ShelleyPaymentPart::script_hash(kh(&own)),
            ShelleyDelegationPart::Null,
        );
        assert!(matches!(
            assert_payment_key_controls_address(&own, &script).unwrap_err(),
            ValidationError::Mismatch("payment address is script-controlled")
        ));
        // A stake address or garbage is not a payment address.
        assert!(assert_payment_key_controls_address(
            &own,
            "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u"
        )
        .is_err());
        assert!(assert_payment_key_controls_address(&own, "not-an-address").is_err());
    }

    #[test]
    fn blake2b224_known_length() {
        let h = blake2b224(&[0u8; 32]);
        assert_eq!(h.len(), 28);
    }

    #[test]
    fn anchor_matches_none_with_null() {
        assert!(anchor_matches_parts(None, &Nullable::Null).unwrap());
    }
}
