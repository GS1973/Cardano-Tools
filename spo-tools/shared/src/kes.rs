//! Wire types for the KES (Key Evolving Signatures) rotation flow.
//!
//! The online tool fetches the latest opcert counter and the current KES
//! period from Koios, then sends a [`KesRotationRequest`] to the offline
//! signer. The signer loads the cold signing key from its encrypted USB,
//! generates a fresh Sum6Kes keypair, builds an operational certificate
//! signed by the cold key, and returns three ready-to-write file contents
//! in [`KesRotationResult`]:
//!
//! - `kes.skey` envelope: the new KES signing key (deploys to the BP node)
//! - `node.cert` envelope: the operational certificate (deploys to the BP node)
//! - `cold.counter` envelope: the bumped counter (replaces the old counter on
//!   both the operator workstation and the BP node)
//!
//! The cold key never crosses the QR boundary, only counter, period, and
//! pool identity flow online → signer; only the three new files (and a few
//! echo-back fields) flow signer → online.
//!
//! Both structs are JSON-serialised inside the UR payload, same convention
//! as the leaderlog flow.

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ts_rs::TS;

/// Sent online → signer. Everything the signer needs to build a fresh
/// opcert; the cold signing key itself stays on the encrypted USB.
/// Wire-level discriminator for KesRotationRequest. The signer rejects payloads
/// whose `kind` does not deserialize to exactly this variant, eliminating
/// the type-confusion risk from the previous untagged JSON layout.

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
#[serde(deny_unknown_fields)]
pub struct KesRotationRequest {
    /// Wire-level discriminator. Always [`crate::wire_kind::WireKind::KesRotation`].
    pub kind: crate::wire_kind::WireKind,
    /// Bech32 pool id, used by the signer for display only.
    pub pool_id_bech32: String,
    /// New opcert issue counter (= on-chain counter + 1, computed online
    /// from the latest block this pool produced).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub new_counter: u64,
    /// KES period the new opcert becomes valid in (= floor(slot / slots_per_kes_period)).
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub kes_period: u64,
    /// Operator-PIN proof: 8 bytes (16 hex chars) of blake2b-256 over a
    /// domain-separated, length-prefixed preimage of the request kind,
    /// `chain_context.built_at_unix`, the request-body fingerprint
    /// (computed with this field blanked) and the operator's 4-digit PIN:
    /// see [`crate::pin`]. The operator types the PIN at QR-build time
    /// on the online tool; the signer prompts for the same PIN after
    /// decrypt and refuses to sign on mismatch. Operator-presence gate at
    /// the moment of signing.
    pub operator_pin_proof: String,
    /// Snapshot of mainnet state at the moment the online tool built this
    /// request. The signer mirrors this for its top-bar display.
    pub chain_context: crate::chain_context::ChainContext,
}

/// Sent signer → online. The signer writes three new files to its own
/// disk (typically the same LUKS USB that holds cold.skey) and returns
/// only paths and metadata so a compromised online tool never sees the
/// fresh kes.skey material.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export, export_to = "../../shared-frontend/src/types/wire.ts")]
pub struct KesRotationResult {
    pub pool_id_bech32: String,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub counter: u64,
    #[serde_as(as = "DisplayFromStr")]
    #[ts(type = "string")]
    pub kes_period: u64,
    /// Hex of the new KES verification key (32 bytes).
    pub kes_vkey_hex: String,
    /// Absolute path on the signer where the three new files were written.
    /// Defaults to the parent directory of the configured `cold.skey`,
    /// so the LUKS USB holding the cold key receives the rotation outputs.
    pub output_dir: String,
    /// Filename written under `output_dir` for the fresh KES signing key.
    pub kes_skey_filename: String,
    /// Filename written under `output_dir` for the new operational certificate.
    pub node_cert_filename: String,
    /// Filename written under `output_dir` for the bumped issue counter.
    pub cold_counter_filename: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> KesRotationRequest {
        KesRotationRequest {
            kind: crate::wire_kind::WireKind::KesRotation,
            pool_id_bech32: "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d".into(),
            new_counter: 7,
            kes_period: 1180,
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

    fn sample_result() -> KesRotationResult {
        KesRotationResult {
            pool_id_bech32: "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d".into(),
            counter: 7,
            kes_period: 1180,
            kes_vkey_hex: "ab".repeat(32),
            output_dir: "/mnt/luks/spo".into(),
            kes_skey_filename: "kes.skey".into(),
            node_cert_filename: "node.cert".into(),
            cold_counter_filename: "cold.counter".into(),
        }
    }

    #[test]
    fn request_roundtrip_through_json() {
        let req = sample_request();
        let bytes = serde_json::to_vec(&req).expect("encode");
        let decoded: KesRotationRequest = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(req, decoded);
    }

    #[test]
    fn result_roundtrip_through_json() {
        let res = sample_result();
        let bytes = serde_json::to_vec(&res).expect("encode");
        let decoded: KesRotationResult = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(res, decoded);
    }

    #[test]
    fn request_through_full_pipeline() {
        use crate::qr;
        let req = sample_request();
        let bytes = serde_json::to_vec(&req).expect("encode");
        let alice = crate::crypto::generate_keypair().unwrap();
        let bob = crate::crypto::generate_keypair().unwrap();
        let parts = qr::encode_encrypted_payload(
            &bytes,
            &bob.public,
            &alice.secret,
            qr::Direction::Request,
        )
        .expect("qr encode");
        let recovered =
            qr::decode_encrypted_parts(&parts, &alice.public, &bob.secret, qr::Direction::Request)
                .expect("qr decode")
                .expect("complete");
        let decoded: KesRotationRequest = serde_json::from_slice(&recovered).expect("json decode");
        assert_eq!(req, decoded);
    }

    #[test]
    fn result_through_full_pipeline() {
        use crate::qr;
        let res = sample_result();
        let bytes = serde_json::to_vec(&res).expect("encode");
        let alice = crate::crypto::generate_keypair().unwrap();
        let bob = crate::crypto::generate_keypair().unwrap();
        let parts = qr::encode_encrypted_payload(
            &bytes,
            &bob.public,
            &alice.secret,
            qr::Direction::Request,
        )
        .expect("qr encode");
        let recovered =
            qr::decode_encrypted_parts(&parts, &alice.public, &bob.secret, qr::Direction::Request)
                .expect("qr decode")
                .expect("complete");
        let decoded: KesRotationResult = serde_json::from_slice(&recovered).expect("json decode");
        assert_eq!(res, decoded);
    }
}
