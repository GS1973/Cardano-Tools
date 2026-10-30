//! Role-neutral Conway transaction primitives shared by SPO Tools,
//! DREP Tools, and Wallet Tools.
//!
//! Address decoding, output construction, input parsing, and final
//! signed-tx assembly are identical across every on-chain operation,
//! only the certificate / voting-procedure middle of the body differs per
//! tool. Those shared pieces live here so no tool re-implements (and
//! risks diverging on) the exact bytes that determine a transaction hash.

use crate::asset::Asset;
use pallas_addresses::{Address, Network};
use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptyKeyValuePairs, NonEmptySet, PositiveCoin};
use pallas_primitives::alonzo::VKeyWitness;
use pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput;
use pallas_primitives::conway::{
    PseudoTransactionOutput, TransactionBody, TransactionOutput, Value, WitnessSet,
};
use pallas_primitives::{AssetName, Hash, PolicyId, TransactionInput};
use std::collections::BTreeMap;
use thiserror::Error;

fn cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() + 2);
    match b.len() {
        n @ 0..=23 => out.push(0x60 | n as u8),
        n @ 24..=255 => {
            out.push(0x78);
            out.push(n as u8);
        }
        n @ 256..=0xffff => {
            out.push(0x79);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(0x7a);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(b);
    out
}

fn cbor_uint(n: u64) -> Vec<u8> {
    match n {
        0..=23 => vec![n as u8],
        24..=0xff => vec![0x18, n as u8],
        0x100..=0xffff => {
            let b = (n as u16).to_be_bytes();
            vec![0x19, b[0], b[1]]
        }
        0x10000..=0xffffffff => {
            let b = (n as u32).to_be_bytes();
            let mut v = vec![0x1a];
            v.extend_from_slice(&b);
            v
        }
        _ => {
            let b = n.to_be_bytes();
            let mut v = vec![0x1b];
            v.extend_from_slice(&b);
            v
        }
    }
}

/// Encode CIP-20 auxiliary data as Shelley metadata CBOR: `{674: {"msg": [...]}}`.
/// Each line must be <=64 bytes (UTF-8). The caller hashes the result with
/// blake2b-256 to get `auxiliary_data_hash`.
pub fn build_cip20_aux_data_cbor(lines: &[String]) -> Result<Vec<u8>, TxBuildError> {
    if lines.is_empty() {
        return Err(TxBuildError::Cbor("CIP-20 metadata has no lines".into()));
    }
    for line in lines {
        if line.len() > 64 {
            return Err(TxBuildError::Cbor(format!(
                "CIP-20 metadata line exceeds 64 bytes (got {})",
                line.len()
            )));
        }
    }
    let mut buf = Vec::new();
    buf.push(0xa1); // map(1)
    buf.extend(cbor_uint(674)); // key: 674
    buf.push(0xa1); // map(1) -- value
    buf.extend(cbor_text("msg")); // key: "msg"
                                  // array of msg lines
    let n = lines.len();
    match n {
        0..=23 => buf.push(0x80 | n as u8),
        24..=255 => {
            buf.push(0x98);
            buf.push(n as u8);
        }
        _ => return Err(TxBuildError::Cbor("too many CIP-20 metadata lines".into())),
    }
    for line in lines {
        buf.extend(cbor_text(line));
    }
    Ok(buf)
}

#[derive(Debug, Error)]
pub enum TxBuildError {
    #[error("invalid bech32 address `{0}`: {1}")]
    Bech32(String, String),
    #[error("expected bech32 prefix `{0}`, got `{1}`")]
    WrongHrp(&'static str, String),
    #[error("address `{0}` is not a mainnet address")]
    WrongNetwork(String),
    #[error(
        "address `{0}` header encodes a `{1}` payload, which does not match its bech32 prefix"
    )]
    WrongAddressKind(String, &'static str),
    #[error("invalid 32-byte hex hash: {0}")]
    HashHex(String),
    #[error("CBOR encode failed: {0}")]
    Cbor(String),
    #[error("{field} must be {expected} bytes, got {got}")]
    WitnessLen {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("fee {fee} exceeds combined input value {utxo_total}")]
    InsufficientInputs { fee: u64, utxo_total: u64 },
    #[error("invalid hex in {0}")]
    Hex(&'static str),
    #[error("policy id must be 28 bytes, got {0}")]
    PolicyLen(usize),
    #[error("asset quantity exceeds u64")]
    QuantityOverflow,
    #[error("asset quantity must be positive")]
    ZeroQuantity,
    #[error("could not build asset map: {0}")]
    AssetMap(&'static str),
    #[error("insufficient asset {asset}: need {need}, have {have}")]
    InsufficientAsset {
        asset: String,
        need: u128,
        have: u128,
    },
    #[error("{0} does not fit in a u64")]
    Overflow(&'static str),
}

/// One transaction input as the builders take it: a 64-char hex tx hash
/// plus the output index it spends.
#[derive(Clone)]
pub struct TxInput {
    pub tx_hash_hex: String,
    pub tx_index: u32,
}

/// Cardano tx_hash is exactly 32 bytes -> 64 hex chars. Reject anything of
/// the wrong length before allocating a decode buffer.
const TX_HASH_HEX_LEN: usize = 64;

pub fn check_tx_hash_hex_len(s: &str) -> Result<(), TxBuildError> {
    if s.len() != TX_HASH_HEX_LEN {
        return Err(TxBuildError::HashHex(s.to_string()));
    }
    Ok(())
}

/// Decode a bech32 Cardano address and confirm both its human-readable
/// prefix and its payload header match `expected_hrp` (`addr` or `stake`).
/// The HRP alone proves nothing, bech32 lets an encoder wrap any payload
/// under any prefix with a valid checksum, so after the HRP equality
/// check the parsed header is checked too: the network nibble must be
/// mainnet and the address kind must be what the prefix promises (a
/// payment-capable Shelley address for `addr`, a reward account for
/// `stake`). These tools are mainnet-only: a testnet HRP (`addr_test` /
/// `stake_test`) or a testnet network nibble is rejected, not silently
/// accepted, so a testnet address can never slip into a mainnet
/// transaction. Byron legacy addresses are rejected outright: no
/// operation built here uses them.
pub fn decode_address(bech32: &str, expected_hrp: &'static str) -> Result<Vec<u8>, TxBuildError> {
    let parsed = Address::from_bech32(bech32)
        .map_err(|e| TxBuildError::Bech32(bech32.to_string(), e.to_string()))?;
    let actual_hrp = bech32::decode(bech32)
        .ok()
        .map(|(hrp, _)| hrp.as_str().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    if actual_hrp != expected_hrp {
        return Err(TxBuildError::WrongHrp(expected_hrp, actual_hrp));
    }
    if let Address::Byron(_) = &parsed {
        return Err(TxBuildError::WrongHrp(expected_hrp, "addr_legacy".into()));
    }
    if !matches!(parsed.network(), Some(Network::Mainnet)) {
        return Err(TxBuildError::WrongNetwork(bech32.to_string()));
    }
    let kind = match &parsed {
        Address::Shelley(_) => "addr",
        Address::Stake(_) => "stake",
        Address::Byron(_) => "addr_legacy", // unreachable: rejected above
    };
    if kind != expected_hrp {
        return Err(TxBuildError::WrongAddressKind(bech32.to_string(), kind));
    }
    Ok(parsed.to_vec())
}

/// Build a coin-only PostAlonzo (Babbage) transaction output to `address`.
pub fn make_output(address: Vec<u8>, lovelace: u64) -> TransactionOutput {
    PseudoTransactionOutput::PostAlonzo(
        pallas_primitives::babbage::PseudoPostAlonzoTransactionOutput {
            address: Bytes::from(address),
            value: Value::Coin(lovelace),
            datum_option: None,
            script_ref: None,
        },
    )
}

/// Parse a [`TxInput`] into a Pallas [`TransactionInput`], validating the
/// tx-hash hex length and 32-byte decode.
pub fn parse_input(u: &TxInput) -> Result<TransactionInput, TxBuildError> {
    check_tx_hash_hex_len(&u.tx_hash_hex)?;
    let bytes =
        hex::decode(&u.tx_hash_hex).map_err(|_| TxBuildError::HashHex(u.tx_hash_hex.clone()))?;
    if bytes.len() != 32 {
        return Err(TxBuildError::HashHex(u.tx_hash_hex.clone()));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Ok(TransactionInput {
        transaction_id: Hash::from(h),
        index: u.tx_index as u64,
    })
}

/// Pair of vkey + signature, both as raw bytes: what comes out of the
/// signer's witness JSON after hex-decoding.
pub struct RawVkeyWitness {
    pub vkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Compose a Conway-era signed-tx CBOR, ready for submission.
///
/// The body bytes are spliced in verbatim so the resulting tx hash matches
/// exactly what the signer signed. Pass `None` for `aux_data` to emit a
/// null auxiliary-data slot; existing call sites are unaffected.
pub fn assemble_signed_tx(
    body_cbor: &[u8],
    witnesses: &[RawVkeyWitness],
) -> Result<Vec<u8>, TxBuildError> {
    assemble_signed_tx_with_aux(body_cbor, witnesses, None)
}

/// Like [`assemble_signed_tx`] but splices `aux_data` into the 4th slot
/// instead of hardcoding null. Pass `None` for no auxiliary data. Because
/// the aux bytes are spliced verbatim, they are bound to the body the
/// signer saw: blake2b-256(`aux_data`) must equal the body's
/// `auxiliary_data_hash` (and a body committing a hash must be given aux
/// data), or assembly fails instead of the node rejecting the tx after
/// the air-gap round trip.
pub fn assemble_signed_tx_with_aux(
    body_cbor: &[u8],
    witnesses: &[RawVkeyWitness],
    aux_data: Option<&[u8]>,
) -> Result<Vec<u8>, TxBuildError> {
    if witnesses.is_empty() {
        return Err(TxBuildError::Cbor("no witnesses".into()));
    }
    for w in witnesses {
        if w.vkey.len() != 32 {
            return Err(TxBuildError::WitnessLen {
                field: "vkey witness key",
                expected: 32,
                got: w.vkey.len(),
            });
        }
        if w.signature.len() != 64 {
            return Err(TxBuildError::WitnessLen {
                field: "vkey witness signature",
                expected: 64,
                got: w.signature.len(),
            });
        }
    }
    // Decoding one item from the front is not enough: minicbor ignores
    // trailing bytes, and the verbatim splice below would carry them into
    // the middle of the tx array. The body item must consume the buffer
    // exactly.
    let mut body_dec = minicbor::Decoder::new(body_cbor);
    let body: TransactionBody = body_dec
        .decode()
        .map_err(|e| TxBuildError::Cbor(format!("body decode: {e}")))?;
    if body_dec.position() != body_cbor.len() {
        return Err(TxBuildError::Cbor(format!(
            "body cbor has {} trailing bytes",
            body_cbor.len() - body_dec.position()
        )));
    }

    let vkey_witnesses: Vec<VKeyWitness> = witnesses
        .iter()
        .map(|w| VKeyWitness {
            vkey: Bytes::from(w.vkey.clone()),
            signature: Bytes::from(w.signature.clone()),
        })
        .collect();

    let witness_set = WitnessSet {
        vkeywitness: Some(NonEmptySet::try_from(vkey_witnesses).map_err(|_| {
            TxBuildError::Cbor("could not build NonEmptySet for vkey witnesses".into())
        })?),
        native_script: None,
        bootstrap_witness: None,
        plutus_v1_script: None,
        plutus_data: None,
        redeemer: None,
        plutus_v2_script: None,
        plutus_v3_script: None,
    };

    let mut ws_cbor = Vec::new();
    minicbor::encode(&witness_set, &mut ws_cbor)
        .map_err(|e| TxBuildError::Cbor(format!("witness set encode: {e}")))?;

    let mut buf = Vec::with_capacity(1 + body_cbor.len() + ws_cbor.len() + 2);
    buf.push(0x84);
    buf.extend_from_slice(body_cbor);
    buf.extend_from_slice(&ws_cbor);
    buf.push(0xf5);
    match aux_data {
        None => {
            // A body committing an auxiliary_data_hash with a null aux slot
            // can never be accepted by the node; fail at assembly instead.
            if body.auxiliary_data_hash.is_some() {
                return Err(TxBuildError::Cbor(
                    "body commits auxiliary_data_hash but no aux data supplied".into(),
                ));
            }
            buf.push(0xf6);
        }
        Some(aux) => {
            let h = pallas_crypto::hash::Hasher::<256>::hash(aux);
            match &body.auxiliary_data_hash {
                Some(bh) if &bh[..] == h.as_ref() => {}
                Some(_) => {
                    return Err(TxBuildError::Cbor("auxiliary_data_hash mismatch".into()));
                }
                None => {
                    return Err(TxBuildError::Cbor(
                        "aux data supplied but body commits no auxiliary_data_hash".into(),
                    ));
                }
            }
            buf.extend_from_slice(aux);
        }
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Native-asset arithmetic and multi-asset output construction
// ---------------------------------------------------------------------------

type AssetKey = (String, String); // (policy_hex, asset_name_hex)

fn aggregate(assets: &[Asset]) -> BTreeMap<AssetKey, u128> {
    let mut m: BTreeMap<AssetKey, u128> = BTreeMap::new();
    for a in assets {
        *m.entry((a.policy_hex.clone(), a.asset_name_hex.clone()))
            .or_insert(0) += a.quantity as u128;
    }
    m
}

/// Change = `available` - `sent`, per asset. Errors if any sent asset exceeds
/// what is available, or if an aggregated quantity does not fit in u64.
/// Assets reduced to zero drop out.
pub fn change_assets(available: &[Asset], sent: &[Asset]) -> Result<Vec<Asset>, TxBuildError> {
    let mut avail = aggregate(available);
    for ((pol, name), need) in aggregate(sent) {
        let have = avail
            .get(&(pol.clone(), name.clone()))
            .copied()
            .unwrap_or(0);
        if need > have {
            return Err(TxBuildError::InsufficientAsset {
                asset: format!("{pol}.{name}"),
                need,
                have,
            });
        }
        avail.insert((pol, name), have - need);
    }
    let mut change = Vec::new();
    for ((policy_hex, asset_name_hex), q) in avail {
        if q == 0 {
            continue;
        }
        let quantity = u64::try_from(q).map_err(|_| TxBuildError::QuantityOverflow)?;
        change.push(Asset {
            policy_hex,
            asset_name_hex,
            quantity,
        });
    }
    Ok(change)
}

fn parse_policy(hex_str: &str) -> Result<PolicyId, TxBuildError> {
    let b = hex::decode(hex_str).map_err(|_| TxBuildError::Hex("policy_id"))?;
    if b.len() != 28 {
        return Err(TxBuildError::PolicyLen(b.len()));
    }
    let mut h = [0u8; 28];
    h.copy_from_slice(&b);
    Ok(Hash::from(h))
}

/// Build an output to `address` carrying `lovelace` and, optionally, native
/// `assets`. No assets -> a coin-only output; otherwise a multi-asset
/// PostAlonzo output.
pub fn make_asset_output(
    address: Vec<u8>,
    lovelace: u64,
    assets: &[Asset],
) -> Result<TransactionOutput, TxBuildError> {
    if assets.is_empty() {
        return Ok(make_output(address, lovelace));
    }
    let mut by_policy: BTreeMap<String, Vec<(String, u128)>> = BTreeMap::new();
    for ((pol, name), qty) in aggregate(assets) {
        by_policy.entry(pol).or_default().push((name, qty));
    }
    let mut outer: Vec<(PolicyId, NonEmptyKeyValuePairs<AssetName, PositiveCoin>)> = Vec::new();
    for (pol_hex, names) in by_policy {
        let policy = parse_policy(&pol_hex)?;
        let mut inner: Vec<(AssetName, PositiveCoin)> = Vec::new();
        for (name_hex, qty) in names {
            let name_bytes = hex::decode(&name_hex).map_err(|_| TxBuildError::Hex("asset_name"))?;
            let q64: u64 = qty.try_into().map_err(|_| TxBuildError::QuantityOverflow)?;
            let pc = PositiveCoin::try_from(q64).map_err(|_| TxBuildError::ZeroQuantity)?;
            inner.push((Bytes::from(name_bytes), pc));
        }
        let inner_map = NonEmptyKeyValuePairs::try_from(inner)
            .map_err(|_| TxBuildError::AssetMap("empty asset name map"))?;
        outer.push((policy, inner_map));
    }
    let multiasset = NonEmptyKeyValuePairs::try_from(outer)
        .map_err(|_| TxBuildError::AssetMap("empty policy map"))?;
    Ok(PseudoTransactionOutput::PostAlonzo(
        PseudoPostAlonzoTransactionOutput {
            address: Bytes::from(address),
            value: Value::Multiasset(lovelace, multiasset),
            datum_option: None,
            script_ref: None,
        },
    ))
}

/// Min lovelace for a UTxO with this output: (serialized size + 160-byte
/// constant overhead) x coinsPerUtxoByte (Conway). `utxo_cost_per_byte` can
/// come from a chain-data provider, so the product is checked: a value that
/// does not fit is an error, never a panic or a wrapped amount.
pub fn min_ada_for_output(
    output: &TransactionOutput,
    utxo_cost_per_byte: u64,
) -> Result<u64, TxBuildError> {
    let mut buf = Vec::new();
    minicbor::encode(output, &mut buf).map_err(|e| TxBuildError::Cbor(e.to_string()))?;
    (buf.len() as u64)
        .checked_add(160)
        .and_then(|n| n.checked_mul(utxo_cost_per_byte))
        .ok_or(TxBuildError::Overflow("min-ADA"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_codec::utils::Set;
    use pallas_primitives::NetworkId;

    const POLICY_A: &str = "00112233445566778899aabbccddeeff00112233445566778899aabb";
    fn mk_asset(policy: &str, name: &str, q: u64) -> Asset {
        Asset {
            policy_hex: policy.into(),
            asset_name_hex: name.into(),
            quantity: q,
        }
    }

    #[test]
    fn change_assets_subtracts_and_drops_zero() {
        let change = change_assets(
            &[mk_asset(POLICY_A, "aa", 10)],
            &[mk_asset(POLICY_A, "aa", 10)],
        )
        .unwrap();
        assert!(change.is_empty());
    }

    #[test]
    fn change_assets_partial() {
        let change = change_assets(
            &[mk_asset(POLICY_A, "aa", 10)],
            &[mk_asset(POLICY_A, "aa", 3)],
        )
        .unwrap();
        assert_eq!(change, vec![mk_asset(POLICY_A, "aa", 7)]);
    }

    #[test]
    fn change_assets_insufficient_errors() {
        let err = change_assets(
            &[mk_asset(POLICY_A, "aa", 2)],
            &[mk_asset(POLICY_A, "aa", 5)],
        );
        assert!(matches!(err, Err(TxBuildError::InsufficientAsset { .. })));
    }

    #[test]
    fn change_assets_overflow_errors_instead_of_truncating() {
        // Two UTxOs of the same asset summing past u64::MAX must fail fast
        // with QuantityOverflow, not silently truncate the change quantity.
        let avail = [
            mk_asset(POLICY_A, "aa", u64::MAX),
            mk_asset(POLICY_A, "aa", 1),
        ];
        let err = change_assets(&avail, &[]);
        assert!(matches!(err, Err(TxBuildError::QuantityOverflow)));
    }

    #[test]
    fn min_ada_is_size_plus_overhead_times_cost() {
        let addr = decode_address(PAYMENT_ADDR, "addr").unwrap();
        let out = make_output(addr, 1_000_000);
        let mut buf = Vec::new();
        minicbor::encode(&out, &mut buf).unwrap();
        assert_eq!(
            min_ada_for_output(&out, 4310).unwrap(),
            (buf.len() as u64 + 160) * 4310
        );
    }

    #[test]
    fn min_ada_overflow_is_an_error_not_a_panic() {
        let addr = decode_address(PAYMENT_ADDR, "addr").unwrap();
        let out = make_output(addr, 1_000_000);
        assert!(matches!(
            min_ada_for_output(&out, u64::MAX),
            Err(TxBuildError::Overflow("min-ADA"))
        ));
    }

    #[test]
    fn make_asset_output_coin_only_when_empty() {
        let addr = decode_address(PAYMENT_ADDR, "addr").unwrap();
        let out = make_asset_output(addr, 1_000_000, &[]).unwrap();
        let mut buf = Vec::new();
        minicbor::encode(&out, &mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    #[test]
    fn make_asset_output_round_trips_byte_exact() {
        let addr = decode_address(PAYMENT_ADDR, "addr").unwrap();
        let out =
            make_asset_output(addr, 2_000_000, &[mk_asset(POLICY_A, "4e49474854", 42)]).unwrap();
        let mut buf = Vec::new();
        minicbor::encode(&out, &mut buf).unwrap();
        let back: TransactionOutput = minicbor::decode(&buf).unwrap();
        let mut buf2 = Vec::new();
        minicbor::encode(&back, &mut buf2).unwrap();
        assert_eq!(buf, buf2);
    }

    const PAYMENT_ADDR: &str = "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw";

    fn minimal_body_with_aux_hash(auxiliary_data_hash: Option<Bytes>) -> Vec<u8> {
        let payment = decode_address(PAYMENT_ADDR, "addr").unwrap();
        let input = parse_input(&TxInput {
            tx_hash_hex: "00".repeat(32),
            tx_index: 0,
        })
        .unwrap();
        let body = TransactionBody {
            inputs: Set::from(vec![input]),
            outputs: vec![make_output(payment, 1_000_000)],
            fee: 200_000,
            ttl: Some(2_000_000),
            certificates: None,
            withdrawals: None,
            auxiliary_data_hash,
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

    fn minimal_body() -> Vec<u8> {
        minimal_body_with_aux_hash(None)
    }

    #[test]
    fn decode_address_rejects_wrong_hrp() {
        let err = decode_address(
            "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            "addr",
        )
        .unwrap_err();
        assert!(matches!(err, TxBuildError::WrongHrp("addr", _)));
    }

    #[test]
    fn decode_address_rejects_testnet_hrp_on_mainnet() {
        // Build a valid testnet enterprise address (header 0x60 = type 6,
        // network id 0 = testnet) and confirm the mainnet-only decoder
        // rejects it rather than accepting the testnet HRP.
        let mut raw = vec![0x60u8];
        raw.extend_from_slice(&[0u8; 28]);
        let testnet = Address::from_bytes(&raw).unwrap().to_bech32().unwrap();
        let err = decode_address(&testnet, "addr").unwrap_err();
        assert!(matches!(err, TxBuildError::WrongHrp("addr", _)));
    }

    #[test]
    fn decode_address_rejects_testnet_payload_under_mainnet_hrp() {
        // bech32 lets an encoder wrap any payload under any HRP with a
        // valid checksum: a testnet enterprise payload (header 0x60 =
        // type 6, network 0) under the mainnet `addr` prefix passes the
        // HRP check, so the header network-nibble check must reject it.
        let mut raw = vec![0x60u8];
        raw.extend_from_slice(&[0u8; 28]);
        let crafted =
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("addr").unwrap(), &raw).unwrap();
        let err = decode_address(&crafted, "addr").unwrap_err();
        assert!(matches!(err, TxBuildError::WrongNetwork(_)));
    }

    #[test]
    fn decode_address_rejects_mismatched_payload_kind() {
        // A mainnet reward-account payload (header 0xe1) under the payment
        // `addr` prefix: HRP and network both pass, but the payload is not
        // a payment address.
        let mut stake_raw = vec![0xe1u8];
        stake_raw.extend_from_slice(&[0u8; 28]);
        let crafted =
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("addr").unwrap(), &stake_raw)
                .unwrap();
        let err = decode_address(&crafted, "addr").unwrap_err();
        assert!(matches!(err, TxBuildError::WrongAddressKind(..)));

        // And the mirror image: a payment payload under the `stake` prefix.
        let mut pay_raw = vec![0x61u8];
        pay_raw.extend_from_slice(&[0u8; 28]);
        let crafted =
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("stake").unwrap(), &pay_raw)
                .unwrap();
        let err = decode_address(&crafted, "stake").unwrap_err();
        assert!(matches!(err, TxBuildError::WrongAddressKind(..)));
    }

    #[test]
    fn decode_address_accepts_mainnet_stake_with_stake_hrp() {
        decode_address(
            "stake1uyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq28lj8u",
            "stake",
        )
        .unwrap();
    }

    #[test]
    fn parse_input_rejects_short_hash() {
        let err = parse_input(&TxInput {
            tx_hash_hex: "00".into(),
            tx_index: 0,
        })
        .unwrap_err();
        assert!(matches!(err, TxBuildError::HashHex(_)));
    }

    #[test]
    fn assemble_wraps_body_verbatim_with_two_witnesses() {
        let body = minimal_body();
        let witnesses = vec![
            RawVkeyWitness {
                vkey: vec![0u8; 32],
                signature: vec![0u8; 64],
            },
            RawVkeyWitness {
                vkey: vec![1u8; 32],
                signature: vec![1u8; 64],
            },
        ];
        let signed = assemble_signed_tx(&body, &witnesses).unwrap();
        assert_eq!(signed[0], 0x84);
        assert_eq!(signed[signed.len() - 2], 0xf5);
        assert_eq!(signed[signed.len() - 1], 0xf6);
        assert!(
            signed.windows(body.len()).any(|w| w == body.as_slice()),
            "body bytes should appear verbatim in signed tx"
        );
        let _: pallas_primitives::conway::Tx = minicbor::decode(&signed).unwrap();
    }

    #[test]
    fn assemble_rejects_empty_witnesses() {
        let body = minimal_body();
        let err = assemble_signed_tx(&body, &[]).unwrap_err();
        assert!(matches!(err, TxBuildError::Cbor(_)));
    }

    #[test]
    fn assemble_rejects_wrong_witness_lengths() {
        let body = minimal_body();
        let short_vkey = vec![RawVkeyWitness {
            vkey: vec![0u8; 31],
            signature: vec![0u8; 64],
        }];
        assert!(matches!(
            assemble_signed_tx(&body, &short_vkey).unwrap_err(),
            TxBuildError::WitnessLen {
                field: "vkey witness key",
                ..
            }
        ));
        let short_sig = vec![RawVkeyWitness {
            vkey: vec![0u8; 32],
            signature: vec![0u8; 63],
        }];
        assert!(matches!(
            assemble_signed_tx(&body, &short_sig).unwrap_err(),
            TxBuildError::WitnessLen {
                field: "vkey witness signature",
                ..
            }
        ));
    }

    #[test]
    fn assemble_rejects_trailing_bytes_after_body() {
        // A valid body item followed by garbage decodes fine as a prefix,
        // but the verbatim splice would carry the garbage into the middle
        // of the tx array. Assembly must require full consumption.
        let mut body = minimal_body();
        body.push(0x00);
        let witnesses = vec![RawVkeyWitness {
            vkey: vec![0u8; 32],
            signature: vec![0u8; 64],
        }];
        assert!(matches!(
            assemble_signed_tx(&body, &witnesses).unwrap_err(),
            TxBuildError::Cbor(_)
        ));
    }

    #[test]
    fn assemble_splices_aux_data_bound_to_body_hash() {
        let aux = build_cip20_aux_data_cbor(&["hello".to_string()]).unwrap();
        let h = pallas_crypto::hash::Hasher::<256>::hash(&aux);
        let body = minimal_body_with_aux_hash(Some(Bytes::from(h.as_ref().to_vec())));
        let witnesses = vec![RawVkeyWitness {
            vkey: vec![0u8; 32],
            signature: vec![0u8; 64],
        }];
        let signed = assemble_signed_tx_with_aux(&body, &witnesses, Some(&aux)).unwrap();
        assert!(
            signed.ends_with(&aux),
            "aux bytes should fill the 4th slot verbatim"
        );
        let _: pallas_primitives::conway::Tx = minicbor::decode(&signed).unwrap();
    }

    #[test]
    fn assemble_rejects_aux_data_not_matching_body_hash() {
        let aux = build_cip20_aux_data_cbor(&["hello".to_string()]).unwrap();
        let witnesses = vec![RawVkeyWitness {
            vkey: vec![0u8; 32],
            signature: vec![0u8; 64],
        }];
        // Body commits a different hash than blake2b-256(aux).
        let body = minimal_body_with_aux_hash(Some(Bytes::from(vec![0u8; 32])));
        assert!(matches!(
            assemble_signed_tx_with_aux(&body, &witnesses, Some(&aux)).unwrap_err(),
            TxBuildError::Cbor(_)
        ));
        // Body commits no hash at all, yet aux data is supplied.
        let body = minimal_body();
        assert!(matches!(
            assemble_signed_tx_with_aux(&body, &witnesses, Some(&aux)).unwrap_err(),
            TxBuildError::Cbor(_)
        ));
        // Body commits a hash but no aux data is supplied.
        let body = minimal_body_with_aux_hash(Some(Bytes::from(vec![0u8; 32])));
        assert!(matches!(
            assemble_signed_tx(&body, &witnesses).unwrap_err(),
            TxBuildError::Cbor(_)
        ));
    }

    #[test]
    fn text_lengths_get_their_own_cbor_header() {
        assert_eq!(&cbor_text(&"a".repeat(23))[..1], &[0x77]);
        assert_eq!(&cbor_text(&"a".repeat(24))[..2], &[0x78, 24]);
        assert_eq!(&cbor_text(&"a".repeat(256))[..3], &[0x79, 1, 0]);
        let long = cbor_text(&"a".repeat(70_000));
        assert_eq!(&long[..5], &[0x7a, 0, 1, 0x11, 0x70]);
        assert_eq!(long.len(), 5 + 70_000);
    }
}
