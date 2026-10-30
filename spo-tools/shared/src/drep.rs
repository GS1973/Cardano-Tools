//! DRep delegation request/result types: wire format between online
//! tool and signer.
//!
//! Same structure as withdrawal: request carries the unsigned tx body
//! CBOR, signer hashes + signs with payment_skey + owner_skey.

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

use crate::chain_context::ChainContext;
use crate::utxo::UtxoInput;
use crate::witness::VkeyWitness;

/// `deny_unknown_fields` rejects an unknown field inside the struct
/// variants (`key_hash` / `script_hash`); for the unit variants
/// (`abstain` / `no_confidence`) serde's internally-tagged deserializer
/// silently ignores extra fields: strictness there would need adjacent
/// tagging or a manual `Deserialize`, i.e. a wire-format break. Harmless
/// here: the body fingerprint is recomputed over the canonical
/// re-serialization on both sides, so a dropped field cannot
/// desynchronize the PIN proof, and the parent request struct already
/// denies unknown top-level fields. ts-rs cannot parse the attribute and
/// prints a harmless "attribute ignored" build warning: it has no
/// TypeScript representation, so the generated bindings are unaffected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DRepChoice {
    Abstain,
    NoConfidence,
    KeyHash { hash_hex: String },
    ScriptHash { hash_hex: String },
}

impl DRepChoice {
    /// The CIP-129 `drep1...` id of a specific DRep (header byte 0x22 for a
    /// key hash, 0x23 for a script hash, then the 28-byte hash), so the
    /// preview can show the whole id the operator knows from explorers.
    /// `None` for the two predefined choices and for a hash that is not 28
    /// bytes of hex.
    pub fn cip129_id(&self) -> Option<String> {
        let (header, hash_hex) = match self {
            DRepChoice::KeyHash { hash_hex } => (0x22u8, hash_hex),
            DRepChoice::ScriptHash { hash_hex } => (0x23u8, hash_hex),
            _ => return None,
        };
        let hash = hex::decode(hash_hex).ok().filter(|h| h.len() == 28)?;
        let mut bytes = vec![header];
        bytes.extend_from_slice(&hash);
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("drep").ok()?, &bytes).ok()
    }
}

/// Wire-level discriminator for DRepDelegationRequest. The signer rejects payloads
/// whose `kind` does not deserialize to exactly this variant, eliminating
/// the type-confusion risk from the previous untagged JSON layout.

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct DRepDelegationRequest {
    /// Wire-level discriminator. Always [`crate::wire_kind::WireKind::DrepDelegation`].
    pub kind: crate::wire_kind::WireKind,
    /// Hex-encoded CBOR of the Conway TransactionBody.
    pub tx_body_cbor_hex: String,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fee_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub change_to_payment_address_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub ttl_slot: u64,
    /// Bech32 strings for signer-side preview.
    pub payment_address_bech32: String,
    pub stake_credential_bech32: String,
    pub drep_choice: DRepChoice,
    /// UTxOs the online-tool selected to fund this transaction.
    /// Validator cross-checks each (tx_hash, tx_index) against
    /// body.inputs and verifies inputs[i].address ==
    /// payment_address_bech32 (operator-visible binding).
    pub inputs: Vec<UtxoInput>,
    /// Operator-PIN proof: 8 bytes (16 hex chars) of blake2b-256 over a
    /// domain-separated, length-prefixed preimage of the request kind,
    /// `chain_context.built_at_unix`, the request-body fingerprint
    /// (computed with this field blanked) and the operator's 4-digit PIN:
    /// see [`crate::pin`]. The operator types the PIN at QR-build time
    /// on the online tool; the signer prompts for the same PIN after
    /// decrypt and refuses to sign on mismatch. Operator-presence gate at
    /// the moment of signing.
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct DRepDelegationResult {
    pub body_hash_hex: String,
    pub witnesses: Vec<VkeyWitness>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drep_choice_accepts_known_variant() {
        let v: DRepChoice = serde_json::from_str(r#"{"kind":"key_hash","hash_hex":"ab"}"#).unwrap();
        assert!(matches!(v, DRepChoice::KeyHash { .. }));
    }

    #[test]
    fn drep_choice_rejects_unknown_field() {
        // An extra field inside the tagged variant must be rejected, not
        // silently dropped.
        let r: Result<DRepChoice, _> =
            serde_json::from_str(r#"{"kind":"key_hash","hash_hex":"ab","bogus":1}"#);
        assert!(r.is_err(), "unknown field in variant should be rejected");
    }

    /// Serde limitation, pinned: `deny_unknown_fields` has no effect on
    /// the *unit* variants of an internally tagged enum: extra fields are
    /// drained and ignored (see the comment on [`DRepChoice`]). If this
    /// test ever starts failing, serde has changed behavior and that
    /// comment should be revisited.
    #[test]
    fn drep_choice_unit_variant_ignores_unknown_fields() {
        let v: DRepChoice = serde_json::from_str(r#"{"kind":"abstain","hash_hex":"ab"}"#).unwrap();
        assert!(matches!(v, DRepChoice::Abstain));
    }

    #[test]
    fn a_specific_drep_gets_its_whole_cip129_id() {
        let key = DRepChoice::KeyHash {
            hash_hex: "00".repeat(28),
        };
        let id = key.cip129_id().unwrap();
        assert!(id.starts_with("drep1y"), "{id}");
        let (_, data) = bech32::decode(&id).unwrap();
        assert_eq!(data[0], 0x22);
        assert_eq!(&data[1..], &[0u8; 28]);
        let script = DRepChoice::ScriptHash {
            hash_hex: "00".repeat(28),
        };
        assert_eq!(
            bech32::decode(&script.cip129_id().unwrap()).unwrap().1[0],
            0x23
        );
        assert_eq!(DRepChoice::Abstain.cip129_id(), None);
        assert_eq!(
            DRepChoice::KeyHash {
                hash_hex: "00".repeat(27)
            }
            .cip129_id(),
            None
        );
    }
}
