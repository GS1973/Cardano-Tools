//! Wire types for the Leaderlog flow.
//!
//! The online tool fetches the epoch nonce, the pool's stake snapshot, and
//! the active slots coefficient from Koios, then sends the bundle to the
//! offline signer as a [`LeaderlogRequest`]. The signer runs the VRF
//! computation against its private VRF key and returns a [`LeaderlogResult`]
//! listing the absolute slots in which this pool is the block leader for
//! that epoch.
//!
//! Both structs are serialised as JSON inside the UR payload: human-readable,
//! easy to debug, and well under one QR frame (typically a few hundred bytes).

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use serde_with::{serde_as, DisplayFromStr};

/// Sent online → signer. Everything the signer needs to compute the
/// schedule, with one exception: the VRF private key, which never leaves
/// the signer's encrypted USB.
/// Wire-level discriminator for LeaderlogRequest. The signer rejects payloads
/// whose `kind` does not deserialize to exactly this variant, eliminating
/// the type-confusion risk from the previous untagged JSON layout.

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct LeaderlogRequest {
    /// Wire-level discriminator. Always [`crate::wire_kind::WireKind::Leaderlog`].
    pub kind: crate::wire_kind::WireKind,
    /// Bech32 pool id, used by the signer for display only.
    pub pool_id_bech32: String,
    /// Target epoch number (the requested epoch for the schedule).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub epoch: u64,
    /// Hex-encoded epoch nonce (32 bytes). Comes from Koios `/epoch_info`.
    pub epoch_nonce_hex: String,
    /// Pool's controlled stake in lovelace, as it appears in the Koios
    /// stake snapshot for the target epoch (`Set` for current, `Mark` for
    /// next). Sent as an integer so the signer can compute sigma at full
    /// FixedDecimal precision without an f64 round-trip.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub pool_stake: u64,
    /// Network-wide active stake in lovelace, same snapshot as `pool_stake`.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub total_active_stake: u64,
    /// Active slots coefficient `f` from protocol parameters, expressed as
    /// a rational `numer / denom`. Mainnet is 0.05 = 1/20 = 500/10000.
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub active_slots_coeff_numer: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub active_slots_coeff_denom: u64,
    /// Absolute first-slot of the target epoch (from genesis + epoch * length).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub epoch_first_slot: u64,
    /// Number of slots per epoch (mainnet: 432_000).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub epoch_length: u64,
    /// Operator-PIN proof: 8 bytes (16 hex chars) of blake2b-256 over a
    /// domain-separated, length-prefixed preimage of the request kind,
    /// `chain_context.built_at_unix`, the request-body fingerprint
    /// (computed with this field blanked) and the operator's 4-digit PIN
    /// — see [`crate::pin`]. The operator types the PIN at QR-build time
    /// on the online tool; the signer prompts for the same PIN after
    /// decrypt and refuses to sign on mismatch. Operator-presence gate at
    /// the moment of signing.
    pub operator_pin_proof: String,
    /// Snapshot of mainnet state at the moment the online tool built this
    /// request. The signer mirrors this for its top-bar display and persists
    /// the latest snapshot so values survive between sessions.
    pub chain_context: crate::chain_context::ChainContext,
}

/// Sent signer → online. The list of absolute slots in `epoch` where this
/// pool is the leader.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct LeaderlogResult {
    pub pool_id_bech32: String,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub epoch: u64,
    /// Absolute slots (within the entire chain timeline, not relative to
    /// epoch start).
    #[serde_as(as = "Vec<DisplayFromStr>")]
    #[ts(type = "Array<string>")]
    pub slots: Vec<u64>,
}


#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> LeaderlogRequest {
        LeaderlogRequest {
            kind: crate::wire_kind::WireKind::Leaderlog,
            pool_id_bech32:
                "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d".into(),
            epoch: 100,
            epoch_nonce_hex:
                "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef".into(),
            // pool_stake / total_active_stake = 1.0e-4 (matches the old f64 sample).
            pool_stake: 2_000_000_000,
            total_active_stake: 20_000_000_000_000,
            // 0.05 active slots coefficient (mainnet f).
            active_slots_coeff_numer: 1,
            active_slots_coeff_denom: 20,
            epoch_first_slot: 1_000_000,
            epoch_length: 432_000,
            operator_pin_proof: "0000000000000000".into(),
            chain_context: crate::chain_context::ChainContext {
                current_epoch: 100,
                current_slot: 1_000_000,
                current_kes_period: 1180,
                epoch_ends_at_unix: 0,
                opcert_expires_at_unix: None,
                built_at_unix: 0,
            },
        }
    }

    fn sample_result() -> LeaderlogResult {
        LeaderlogResult {
            pool_id_bech32:
                "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d".into(),
            epoch: 100,
            slots: vec![152_812_801, 152_900_000, 153_100_500],
        }
    }

    #[test]
    fn request_roundtrip_through_json() {
        let req = sample_request();
        let bytes = serde_json::to_vec(&req).expect("encode");
        let decoded: LeaderlogRequest = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(req, decoded);
    }

    #[test]
    fn result_roundtrip_through_json() {
        let res = sample_result();
        let bytes = serde_json::to_vec(&res).expect("encode");
        let decoded: LeaderlogResult = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(res, decoded);
    }

    /// Combined integration: encode request, push through UR (the QR
    /// transport), decode, recover the same request. Proves the two layers
    /// (leaderlog + qr) compose correctly.
    #[test]
    fn request_through_full_pipeline() {
        use crate::qr;

        let req = sample_request();
        let bytes = serde_json::to_vec(&req).expect("encode");
        let alice = crate::crypto::generate_keypair().unwrap();
        let bob = crate::crypto::generate_keypair().unwrap();
        let parts = qr::encode_encrypted_payload(&bytes, &bob.public, &alice.secret, qr::Direction::Request).expect("qr encode");

        let recovered = qr::decode_encrypted_parts(&parts, &alice.public, &bob.secret, qr::Direction::Request).expect("qr decode").expect("complete");
        let decoded: LeaderlogRequest = serde_json::from_slice(&recovered).expect("json decode");

        assert_eq!(req, decoded);
    }
}
