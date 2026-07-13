#![warn(missing_docs, rust_2018_idioms)]
#![allow(non_snake_case)]
//! VRF implementation
mod constants;
pub mod errors;
pub mod vrf03;

// VRF draft-10 (post-Babbage) modules. Gated behind the off-by-default
// `vrf10` feature: SPO Tools only signs the pre-Babbage draft-03 flavour
// (`vrf03`), which needs nothing but the vendored fork. The default build
// therefore excludes these modules and the crates.io `curve25519-dalek`
// 3.2.0 they depend on (RUSTSEC-2024-0344).
#[cfg(feature = "vrf10")]
pub mod vrf;
#[cfg(feature = "vrf10")]
pub mod vrf10;
#[cfg(feature = "vrf10")]
pub mod vrf10_batchcompat;
