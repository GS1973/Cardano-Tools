//! Cardano Praos slot-leader test, extracted as pure functions.
//!
//! `build_vrf_input` produces the VRF challenge for a single slot:
//! the big-endian slot number concatenated with the epoch nonce, then
//! Blake2b-256 hashed.
//!
//! `PraosThreshold` precomputes the rationals derived from the pool's
//! sigma and the active-slots coefficient `f` that the leader-VRF
//! comparison needs. Construct it once per `(epoch, pool)` pair, then
//! call `is_leader` for each slot.
//!
//! The slot-leader test follows cncli's `is_slot_leader_praos` and the
//! cardano-node reference implementation:
//!
//!   leader_vrf  = blake2b_256(0x4C || raw_vrf_hash)
//!   recip_q     = 2^256 / (2^256 - leader_vrf)
//!   leader iff exp(-sigma * ln(1 - f)) > recip_q

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use pallas_math::math::{ExpOrdering, FixedDecimal, FixedPrecision, DEFAULT_PRECISION};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PraosError {
    #[error("total_active_stake is zero")]
    ZeroActiveStake,
    #[error("active_slots_coeff_denom is zero")]
    ZeroSlotCoeffDenom,
    #[error("active_slots_coeff must be below 1 (numer < denom)")]
    SlotCoeffNotBelowOne,
}

/// Returns blake2b_256(slot_be || epoch_nonce). Pure and deterministic.
pub fn build_vrf_input(slot: u64, epoch_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
    hasher.update(&slot.to_be_bytes());
    hasher.update(epoch_nonce);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("blake2b finalize");
    out
}

/// Precomputed Praos threshold parameters for one `(epoch, pool)` pair.
///
/// `cert_nat_max` is the constant 2^256 expressed in `DEFAULT_PRECISION`
/// FixedDecimal form. `neg_sigma_c` is `-sigma * ln(1 - f)` where
/// `sigma = pool_stake / total_active_stake` and `f` is the active-slots
/// coefficient.
pub struct PraosThreshold {
    cert_nat_max: FixedDecimal,
    neg_sigma_c: FixedDecimal,
}

impl PraosThreshold {
    /// Builds the threshold from u64 rationals, matching the Cardano
    /// protocol's exact-arithmetic discipline (no f64 round-trip).
    pub fn new(
        pool_stake: u64,
        total_active_stake: u64,
        active_slots_coeff_numer: u64,
        active_slots_coeff_denom: u64,
    ) -> Result<Self, PraosError> {
        if total_active_stake == 0 {
            return Err(PraosError::ZeroActiveStake);
        }
        if active_slots_coeff_denom == 0 {
            return Err(PraosError::ZeroSlotCoeffDenom);
        }
        // f >= 1 would make (1 - f) non-positive, and pallas-math's ln()
        // panics on inputs <= 0. Both coefficient fields arrive from the
        // untrusted QR channel, so reject rather than reach the panic.
        if active_slots_coeff_numer >= active_slots_coeff_denom {
            return Err(PraosError::SlotCoeffNotBelowOne);
        }

        let cert_nat_max = FixedDecimal::from_str(
            "1157920892373161954235709850086879078532699846656405640394575840079131296399360000000000000000000000000000000000",
            DEFAULT_PRECISION,
        )
        .expect("cert_nat_max constant 2^256 (static, infallible)");
        let one = FixedDecimal::from(1u64);
        let f_fd = FixedDecimal::from(active_slots_coeff_numer)
            / FixedDecimal::from(active_slots_coeff_denom);
        let c = (&one - &f_fd).ln();
        let sigma_fd =
            FixedDecimal::from(pool_stake) / FixedDecimal::from(total_active_stake);
        let neg_sigma_c = -(&sigma_fd * &c);

        Ok(Self { cert_nat_max, neg_sigma_c })
    }

    /// Returns true if `raw_vrf` (the 64-byte VRF proof-to-hash output)
    /// represents a leader-VRF below the threshold for this `(stake, f)`
    /// pair.
    pub fn is_leader(&self, raw_vrf: &[u8; 64]) -> bool {
        let mut hasher = Blake2bVar::new(32).expect("blake2b 256 init");
        // Domain-separation byte for the Praos leader-VRF input
        // (ASCII 'L', 0x4C). Hashing this prefix together with the raw
        // VRF output yields the leader-VRF the slot-leader test inspects.
        hasher.update(&[0x4Cu8]);
        hasher.update(raw_vrf);
        let mut leader_vrf = [0u8; 32];
        hasher
            .finalize_variable(&mut leader_vrf)
            .expect("blake2b finalize");

        let cert_leader_vrf = FixedDecimal::from(leader_vrf.as_slice());
        let denom = &self.cert_nat_max - &cert_leader_vrf;
        let recip_q = &self.cert_nat_max / &denom;
        // pallas-math compares exp(neg_sigma_c) against recip_q via a
        // Taylor-series expansion. 1000 max iterations, 3 chunked-precision
        // blocks; matches cncli's reference parameters.
        let ordering = self.neg_sigma_c.exp_cmp(1000, 3, &recip_q);
        ordering.estimation == ExpOrdering::LT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_vrf_input_known_vector_slot0_zero_nonce() {
        let nonce = [0u8; 32];
        let out = build_vrf_input(0, &nonce);
        assert_eq!(
            hex::encode(out),
            "4a1931803561f431decab002e7425f0a8531d5e456a1a47fd9998a2530c0f800"
        );
    }

    #[test]
    fn build_vrf_input_known_vector_slot1_zero_nonce() {
        let nonce = [0u8; 32];
        let out = build_vrf_input(1, &nonce);
        assert_eq!(
            hex::encode(out),
            "16ae1f981466eb1b9d792ba29837d73208451d3c15f9a6f9beeb6bfb603fb6d8"
        );
    }

    #[test]
    fn build_vrf_input_known_vector_slot42_nonce_first_byte_one() {
        let mut nonce = [0u8; 32];
        nonce[0] = 1;
        let out = build_vrf_input(42, &nonce);
        assert_eq!(
            hex::encode(out),
            "183ab44e3854452edd264f0949bd564c0e90d75a40d874da723f9b5ebfa7dc83"
        );
    }

    #[test]
    fn build_vrf_input_is_deterministic() {
        let nonce = [0xABu8; 32];
        assert_eq!(build_vrf_input(7, &nonce), build_vrf_input(7, &nonce));
    }

    #[test]
    fn build_vrf_input_changes_with_slot() {
        let nonce = [0u8; 32];
        assert_ne!(build_vrf_input(0, &nonce), build_vrf_input(1, &nonce));
    }

    #[test]
    fn build_vrf_input_changes_with_nonce() {
        let n0 = [0u8; 32];
        let mut n1 = [0u8; 32];
        n1[0] = 1;
        assert_ne!(build_vrf_input(42, &n0), build_vrf_input(42, &n1));
    }

    #[test]
    fn praos_threshold_zero_active_stake_errors() {
        assert!(matches!(
            PraosThreshold::new(0, 0, 1, 20),
            Err(PraosError::ZeroActiveStake)
        ));
    }

    #[test]
    fn praos_threshold_zero_slot_coeff_denom_errors() {
        assert!(matches!(
            PraosThreshold::new(1, 1, 1, 0),
            Err(PraosError::ZeroSlotCoeffDenom)
        ));
    }

    #[test]
    fn praos_threshold_slot_coeff_equal_to_one_errors() {
        assert!(matches!(
            PraosThreshold::new(1, 1, 20, 20),
            Err(PraosError::SlotCoeffNotBelowOne)
        ));
    }

    #[test]
    fn praos_threshold_slot_coeff_above_one_errors() {
        assert!(matches!(
            PraosThreshold::new(1, 1, 21, 20),
            Err(PraosError::SlotCoeffNotBelowOne)
        ));
    }

    #[test]
    fn praos_threshold_zero_pool_stake_never_leads() {
        let t = PraosThreshold::new(0, 100, 1, 20).expect("threshold builds");
        let raw = [0xFFu8; 64];
        assert!(!t.is_leader(&raw));
    }

    #[test]
    fn praos_threshold_is_deterministic() {
        let t = PraosThreshold::new(2_000_000_000, 20_000_000_000_000, 1, 20)
            .expect("threshold builds");
        let raw = [0xA5u8; 64];
        assert_eq!(t.is_leader(&raw), t.is_leader(&raw));
    }
}
