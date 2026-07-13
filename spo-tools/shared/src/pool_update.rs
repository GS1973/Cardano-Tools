//! Pool parameter update request/result types — wire format between
//! online tool and signer.
//!
//! Single-owner v1.0. Three witness roles required: Payment (fee),
//! Cold (operator authority), OwnerStake (pledge).

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use serde_with::{serde_as, DisplayFromStr};

use crate::chain_context::ChainContext;
use crate::utxo::UtxoInput;
use crate::witness::VkeyWitness;

/// `deny_unknown_fields` rejects an unknown field inside every variant
/// here because all three `RelaySpec` variants are struct variants. That
/// is NOT a general property of internally-tagged enums: serde's
/// internally-tagged deserializer silently ignores extra fields on unit
/// variants (see `DRepChoice` in `drep.rs`). The parent request struct
/// already denies unknown top-level fields. ts-rs cannot parse the
/// attribute and prints a harmless "attribute ignored" build warning — it
/// has no TypeScript representation, so the generated bindings are
/// unaffected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelaySpec {
    /// IPv4 / IPv6 + optional port.
    SingleHostAddr {
        port: Option<u16>,
        ipv4: Option<String>,
        ipv6: Option<String>,
    },
    /// DNS A record + optional port.
    SingleHostName {
        port: Option<u16>,
        dns: String,
    },
    /// DNS SRV record (no port).
    MultiHostName { dns: String },
}

/// Wire-level discriminator for PoolUpdateRequest. The signer rejects payloads
/// whose `kind` does not deserialize to exactly this variant, eliminating
/// the type-confusion risk from the previous untagged JSON layout.

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct PoolUpdateRequest {
    /// Wire-level discriminator. Always [`crate::wire_kind::WireKind::PoolUpdate`].
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
    /// Bech32 strings for signer-side preview + diff.
    pub payment_address_bech32: String,
    pub pool_id_bech32: String,
    pub vrf_keyhash_hex: String,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub pledge_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub fixed_cost_lovelace: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub margin_numerator: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub margin_denominator: u64,
    pub reward_account_bech32: String,
    pub pool_owner_stake_addresses: Vec<String>,
    pub relays: Vec<RelaySpec>,
    pub metadata_url: Option<String>,
    pub metadata_hash_hex: Option<String>,
    /// UTxOs the online-tool selected to fund this transaction.
    /// Validator cross-checks each (tx_hash, tx_index) against
    /// body.inputs and verifies inputs[i].address ==
    /// payment_address_bech32 (operator-visible binding).
    pub inputs: Vec<UtxoInput>,
    /// Operator-PIN proof: 8 bytes (16 hex chars) of blake2b-256 over a
    /// domain-separated, length-prefixed preimage of the request kind,
    /// `chain_context.built_at_unix`, the request-body fingerprint
    /// (computed with this field blanked) and the operator's 4-digit PIN
    /// — see [`crate::pin`]. The operator types the PIN at QR-build time
    /// on the online tool; the signer prompts for the same PIN after
    /// decrypt and refuses to sign on mismatch. Operator-presence gate at
    /// the moment of signing.
    pub operator_pin_proof: String,
    pub chain_context: ChainContext,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct PoolUpdateResult {
    pub body_hash_hex: String,
    pub witnesses: Vec<VkeyWitness>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_spec_accepts_known_variant() {
        let v: RelaySpec =
            serde_json::from_str(r#"{"kind":"single_host_name","port":3001,"dns":"relay.example"}"#)
                .unwrap();
        assert!(matches!(v, RelaySpec::SingleHostName { .. }));
    }

    #[test]
    fn relay_spec_rejects_unknown_field() {
        // An extra field inside the tagged variant must be rejected, not
        // silently dropped.
        let r: Result<RelaySpec, _> = serde_json::from_str(
            r#"{"kind":"single_host_name","port":3001,"dns":"relay.example","bogus":1}"#,
        );
        assert!(r.is_err(), "unknown field in variant should be rejected");
    }
}

