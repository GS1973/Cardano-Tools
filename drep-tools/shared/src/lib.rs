//! Shared types and helpers for the DRep Tools workspace.
//!
//! Consumed by both `drep-online` (the web backend) and `drep-signer`
//! (the offline signing app). Anything that crosses the QR boundary lives
//! here: the four DRep operation request/result types, the DRep-id
//! decoder, the witness-role label, and the body validators.
//!
//! Role-neutral primitives — the encrypted QR/UR transport, X25519
//! pairing, operator PIN, cardano-cli key loading, chain-context
//! snapshot, the UTxO wire shape, and the Conway tx-assembly +
//! body-validation primitives — live in the `airgap-core` crate (shared
//! with SPO Tools) and are re-exported here so every `shared::` /
//! `crate::` path resolves uniformly.

#![allow(dead_code)]

// Role-neutral primitives, re-exported from airgap-core.
pub use airgap_core::{
    cardano_keys, chain_context, config_helpers, crypto, csrf, error, fingerprint, pairing, pin,
    qr, tx, utxo, validate, wire_io,
};

/// Fingerprint a request body for the operator-PIN proof, computed over the
/// request with its `operator_pin_proof` field blanked. Both sides call
/// this so the proof commits to the exact body the operator approved: the
/// online tool builds the request with an empty proof, fingerprints, then
/// fills the proof in; the signer blanks the received proof before
/// recomputing. Serialization of these plain serde structs is
/// deterministic, so both sides land on identical bytes.
pub fn request_body_fp<T: serde::Serialize>(req: &T) -> [u8; 8] {
    let bytes = serde_json::to_vec(req).expect("request body serializes");
    fingerprint::request_fingerprint(&bytes)
}

// DRep-specific modules.
pub mod anchor;
pub mod drep_id;
pub mod register;
pub mod retire;
pub mod tx_validator;
pub mod update;
pub mod vote;
pub mod wire_kind;
pub mod witness;
pub mod witness_doc;

#[cfg(test)]
mod request_body_fp_tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Stand-in with the same shape every real DRep request has: payload
    /// fields plus an `operator_pin_proof` String. Locks the body-fingerprint
    /// invariant the online tool and signer both depend on.
    #[derive(Serialize, Deserialize)]
    struct SampleReq {
        amount: u64,
        dest: String,
        operator_pin_proof: String,
    }

    #[test]
    fn body_fp_and_pin_proof_round_trip_across_the_wire() {
        // Online side: build with an empty proof, fingerprint the body, then
        // fill in the proof bound to that fingerprint.
        let mut req = SampleReq {
            amount: 42,
            dest: "addr1_test".into(),
            operator_pin_proof: String::new(),
        };
        let body_fp_online = request_body_fp(&req);
        req.operator_pin_proof = pin::pin_proof_hex("1234", "drep_vote", 1700, &body_fp_online);

        // Wire: serialize (real proof set), then the signer deserializes.
        let wire = serde_json::to_vec(&req).unwrap();
        let mut received: SampleReq = serde_json::from_slice(&wire).unwrap();
        let proof = std::mem::take(&mut received.operator_pin_proof);

        // Signer side: recompute the body fingerprint over the blanked request.
        let body_fp_signer = request_body_fp(&received);
        assert_eq!(body_fp_online, body_fp_signer, "body_fp must match across the wire");
        assert!(pin::verify_pin("1234", "drep_vote", 1700, &body_fp_signer, &proof));
    }

    #[test]
    fn swapping_the_body_breaks_the_proof() {
        let mut req = SampleReq {
            amount: 42,
            dest: "addr1_test".into(),
            operator_pin_proof: String::new(),
        };
        let body_fp = request_body_fp(&req);
        req.operator_pin_proof = pin::pin_proof_hex("1234", "drep_vote", 1700, &body_fp);
        let proof = req.operator_pin_proof.clone();

        // An attacker who cannot recompute the proof swaps the body. The
        // signer's recomputed body_fp no longer matches, so the proof fails.
        let swapped = SampleReq {
            amount: 999_999,
            dest: "addr1_attacker".into(),
            operator_pin_proof: String::new(),
        };
        let swapped_fp = request_body_fp(&swapped);
        assert!(!pin::verify_pin("1234", "drep_vote", 1700, &swapped_fp, &proof));
    }
}
