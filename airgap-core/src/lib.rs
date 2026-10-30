//! airgap-core: role-neutral air-gapped transport + Cardano primitives,
//! shared by SPO Tools, DREP Tools, and Wallet Tools.
//!
//! Everything here is independent of any on-chain role: the encrypted
//! QR/UR channel, the X25519 pairing + fingerprint, the operator PIN
//! proof, the cardano-cli skey loader, the chain-context snapshot, the
//! UTxO + vkey-witness wire shapes, the role-neutral Conway
//! transaction-assembly + body-validation primitives, the reader that turns
//! a signed CIP-100 canonical body back into its text, and the address
//! classification behind the online tools' document fetch, the signers'
//! persistent state, their signing-key material, the writing of new key
//! files, the air-gap monitor and the directory browser of their Setup
//! screen. Nothing here knows
//! about SPO, DRep, or wallet operations: those live in each tool's own
//! crate.

pub mod airgap_monitor;
pub mod asset;
pub mod cardano_keys;
pub mod chain_context;
pub mod config_helpers;
pub mod crypto;
pub mod csrf;
pub mod error;
pub mod fingerprint;
pub mod key_files;
pub mod list_dir;
pub mod listen;
pub mod netguard;
pub mod nquads;
pub mod pairing;
pub mod pin;
pub mod qr;
pub mod signer_state;
pub mod signing;
pub mod tx;
pub mod utxo;
pub mod validate;
pub mod wire_io;
pub mod witness;
