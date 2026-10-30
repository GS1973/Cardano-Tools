//! Air-gapped wallet key generation.
//!
//! Generates fresh Ed25519 payment and stake key pairs on the offline
//! signer host and writes them in the cardano-cli envelope format the
//! loader already reads (`PaymentSigningKeyShelley_ed25519` /
//! `StakeSigningKeyShelley_ed25519`). Seeds come from the OS CSPRNG; the
//! secrets never leave this machine. Files are written atomically: a
//! hidden `.tmp` sibling is created at its final mode (each skey 0600
//! from its first byte, never momentarily wider), fsync'd, and renamed
//! into place, then the directory is fsync'd so the keys are durable
//! before the caller shows the address for funding. Existing keys are
//! never overwritten. The mainnet base (`addr1q…`) and stake (`stake1…`)
//! addresses are derived from the generated keys.

use ed25519_dalek::SigningKey;
use shared::address;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct GeneratedWalletKeys {
    pub base_address: String,
    pub stake_address: String,
    pub payment_keyhash_hex: String,
    pub stake_keyhash_hex: String,
    pub payment_skey_path: String,
    #[allow(dead_code)] // informational: the vkey path keygen also wrote
    pub payment_vkey_path: String,
    pub stake_skey_path: String,
    #[allow(dead_code)] // informational: the vkey path keygen also wrote
    pub stake_vkey_path: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum KeygenError {
    #[error("output directory does not exist: {0}")]
    NoDir(String),
    #[error("a key already exists at {0}: refusing to overwrite")]
    Exists(String),
    #[error("system entropy unavailable: {0}")]
    Entropy(String),
    #[error("address derivation failed: {0}")]
    Address(#[from] address::AddressError),
    #[error("write failed: {0}")]
    Write(String),
}

/// Generate a payment + stake key pair, write the four cardano-cli envelope
/// files into `output_dir`, and return the derived addresses, key-hashes,
/// and written paths. Refuses if either signing key already exists.
pub(crate) fn generate_and_write(
    output_dir: &std::path::Path,
) -> Result<GeneratedWalletKeys, KeygenError> {
    let _one_at_a_time = KEYGEN_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !output_dir.is_dir() {
        return Err(KeygenError::NoDir(output_dir.display().to_string()));
    }
    let payment_skey_path = output_dir.join("payment.skey");
    let payment_vkey_path = output_dir.join("payment.vkey");
    let stake_skey_path = output_dir.join("stake.skey");
    let stake_vkey_path = output_dir.join("stake.vkey");

    // Claim both signing-key names before anything secret is generated.
    claim(&payment_skey_path)?;
    if let Err(e) = claim(&stake_skey_path) {
        let _ = std::fs::remove_file(&payment_skey_path);
        return Err(e);
    }

    let written = (|| -> Result<([u8; 32], [u8; 32]), KeygenError> {
        let (payment_seed, payment_vkey) = fresh_keypair()?;
        let (stake_seed, stake_vkey) = fresh_keypair()?;
        write_secure(
            &payment_skey_path,
            &skey_json(
                "PaymentSigningKeyShelley_ed25519",
                "Payment Signing Key",
                &payment_seed,
            ),
            0o600,
        )?;
        write_secure(
            &payment_vkey_path,
            &vkey_json(
                "PaymentVerificationKeyShelley_ed25519",
                "Payment Verification Key",
                &payment_vkey,
            ),
            0o644,
        )?;
        write_secure(
            &stake_skey_path,
            &skey_json(
                "StakeSigningKeyShelley_ed25519",
                "Stake Signing Key",
                &stake_seed,
            ),
            0o600,
        )?;
        write_secure(
            &stake_vkey_path,
            &vkey_json(
                "StakeVerificationKeyShelley_ed25519",
                "Stake Verification Key",
                &stake_vkey,
            ),
            0o644,
        )?;
        Ok((payment_vkey, stake_vkey))
    })();
    let (payment_vkey, stake_vkey) = match written {
        Ok(v) => v,
        Err(e) => {
            // Nothing has been shown or funded yet: drop what this call
            // claimed or wrote, so a retry starts clean.
            for p in [
                &payment_skey_path,
                &stake_skey_path,
                &payment_vkey_path,
                &stake_vkey_path,
            ] {
                let _ = std::fs::remove_file(p);
            }
            return Err(e);
        }
    };

    // Make the four renames durable before the caller advertises the base
    // address for funding: a power cut or unclean drive unplug must not be
    // able to lose the only copy of the keys behind a funded address.
    // Best-effort: a directory that cannot be fsync'd does not undo the
    // writes already applied.
    if let Ok(dir) = std::fs::File::open(output_dir) {
        let _ = dir.sync_all();
    }

    Ok(GeneratedWalletKeys {
        base_address: address::base_address_bech32(&payment_vkey, &stake_vkey)?,
        stake_address: address::stake_address_bech32(&stake_vkey)?,
        payment_keyhash_hex: hex::encode(address::key_hash_bytes(&payment_vkey)),
        stake_keyhash_hex: hex::encode(address::key_hash_bytes(&stake_vkey)),
        payment_skey_path: payment_skey_path.display().to_string(),
        payment_vkey_path: payment_vkey_path.display().to_string(),
        stake_skey_path: stake_skey_path.display().to_string(),
        stake_vkey_path: stake_vkey_path.display().to_string(),
    })
}

/// A fresh Ed25519 key pair: (32-byte seed, 32-byte verification key).
fn fresh_keypair() -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), KeygenError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed).map_err(|e| KeygenError::Entropy(e.to_string()))?;
    let vkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    Ok((seed, vkey))
}

/// cardano-cli signing-key envelope: cborHex is `5820` (CBOR bytes(32)) + raw seed.
fn skey_json(ty: &str, desc: &str, seed: &[u8; 32]) -> Zeroizing<String> {
    let seed_hex = Zeroizing::new(hex::encode(seed));
    Zeroizing::new(format!(
        "{{\"type\":\"{ty}\",\"description\":\"{desc}\",\"cborHex\":\"5820{}\"}}",
        *seed_hex
    ))
}

/// cardano-cli verification-key envelope: cborHex is `5820` + raw public key.
fn vkey_json(ty: &str, desc: &str, vkey: &[u8; 32]) -> String {
    format!(
        "{{\"type\":\"{ty}\",\"description\":\"{desc}\",\"cborHex\":\"5820{}\"}}",
        hex::encode(vkey)
    )
}

/// One keygen at a time in this process. Together with the exclusive claim
/// on each signing-key name ([`claim`]), two requests can never write keys
/// into the same place: the second finds the name taken and is refused.
static KEYGEN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Claim `path` for a new signing key (`key_files::claim` in airgap-core):
/// an exclusive create at mode 0600 that refuses any name already taken.
fn claim(path: &std::path::Path) -> Result<(), KeygenError> {
    Ok(shared::key_files::claim(path)?)
}

/// Write `content` to `path` through a staged, fsync'd rename at `mode`
/// (`key_files::write_secure` in airgap-core).
fn write_secure(path: &std::path::Path, content: &str, mode: u32) -> Result<(), KeygenError> {
    Ok(shared::key_files::write_secure(path, content, mode)?)
}

impl From<shared::key_files::KeyFileError> for KeygenError {
    fn from(e: shared::key_files::KeyFileError) -> Self {
        match e {
            shared::key_files::KeyFileError::Exists(p) => KeygenError::Exists(p),
            shared::key_files::KeyFileError::Write(m) => KeygenError::Write(m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::cardano_keys::{load_skey, CardanoKey};

    #[test]
    fn generates_loadable_keys_with_matching_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let g = generate_and_write(dir.path()).expect("generates");

        // The written skeys load back as the expected key kinds.
        let payment_seed = match load_skey(std::path::Path::new(&g.payment_skey_path)).unwrap() {
            CardanoKey::Payment { seed_32 } => seed_32,
            other => panic!("expected Payment key, got {other:?}"),
        };
        let stake_seed = match load_skey(std::path::Path::new(&g.stake_skey_path)).unwrap() {
            CardanoKey::Stake { seed_32 } => seed_32,
            other => panic!("expected Stake key, got {other:?}"),
        };

        // Re-derive vkeys + addresses from the loaded seeds; they must equal
        // what generate_and_write advertised.
        let pay_vkey = SigningKey::from_bytes(&payment_seed)
            .verifying_key()
            .to_bytes();
        let stk_vkey = SigningKey::from_bytes(&stake_seed)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            g.base_address,
            address::base_address_bech32(&pay_vkey, &stk_vkey).unwrap()
        );
        assert_eq!(
            g.stake_address,
            address::stake_address_bech32(&stk_vkey).unwrap()
        );
        assert_eq!(
            g.payment_keyhash_hex,
            hex::encode(address::key_hash_bytes(&pay_vkey))
        );
        assert_eq!(
            g.stake_keyhash_hex,
            hex::encode(address::key_hash_bytes(&stk_vkey))
        );
        assert!(g.base_address.starts_with("addr1q"));
        assert!(g.stake_address.starts_with("stake1"));
    }

    #[test]
    fn refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        generate_and_write(dir.path()).expect("first");
        let err = generate_and_write(dir.path()).expect_err("second must refuse");
        assert!(matches!(err, KeygenError::Exists(_)));
    }

    #[test]
    fn writes_skeys_0600_vkeys_0644_and_no_tmp_leak() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        generate_and_write(dir.path()).expect("generates");
        for (name, want_mode) in [
            ("payment.skey", 0o600u32),
            ("stake.skey", 0o600),
            ("payment.vkey", 0o644),
            ("stake.vkey", 0o644),
        ] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, want_mode, "{name} mode");
            // No staging files survive a successful keygen.
            assert!(
                !dir.path().join(format!(".{name}.tmp")).exists(),
                "{name} tmp leaked"
            );
        }
    }

    #[test]
    fn replaces_leftover_tmp_from_crashed_run() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // A crashed previous run left a staging file at the default (looser)
        // mode: keygen must still succeed and the skey must land 0600 with
        // fresh content, not inherit the leftover's mode.
        std::fs::write(dir.path().join(".payment.skey.tmp"), "LEFTOVER").unwrap();
        let g = generate_and_write(dir.path()).expect("generates over leftover tmp");
        let p = std::path::PathBuf::from(&g.payment_skey_path);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "payment.skey must be 0600 over a leftover");
        assert!(
            !dir.path().join(".payment.skey.tmp").exists(),
            "leftover tmp survived"
        );
        // The written skey is a real key, not the leftover bytes.
        assert!(matches!(load_skey(&p), Ok(CardanoKey::Payment { .. })));
    }

    #[test]
    fn two_generations_at_once_never_overwrite_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || generate_and_write(&p))
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(ok.len(), 1, "exactly one generation may succeed");
        assert!(results
            .iter()
            .any(|r| matches!(r, Err(KeygenError::Exists(_)))));
        // The keys on disk are the ones the successful call advertised.
        let pay = match load_skey(std::path::Path::new(&ok[0].payment_skey_path)).unwrap() {
            CardanoKey::Payment { seed_32 } => {
                SigningKey::from_bytes(&seed_32).verifying_key().to_bytes()
            }
            other => panic!("expected Payment key, got {other:?}"),
        };
        let stk = match load_skey(std::path::Path::new(&ok[0].stake_skey_path)).unwrap() {
            CardanoKey::Stake { seed_32 } => {
                SigningKey::from_bytes(&seed_32).verifying_key().to_bytes()
            }
            other => panic!("expected Stake key, got {other:?}"),
        };
        assert_eq!(
            ok[0].base_address,
            address::base_address_bech32(&pay, &stk).unwrap()
        );
    }

    #[test]
    fn an_existing_stake_key_leaves_no_payment_key_behind() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stake.skey"), "someone else's").unwrap();
        let err = generate_and_write(dir.path()).expect_err("must refuse");
        assert!(matches!(err, KeygenError::Exists(_)));
        assert!(
            !dir.path().join("payment.skey").exists(),
            "the payment claim must be dropped"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("stake.skey")).unwrap(),
            "someone else's"
        );
    }

    #[test]
    fn a_claim_never_touches_an_existing_key() {
        // The step that makes a race harmless: whoever comes second finds the
        // name taken, and the key already there stays byte for byte as it was.
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("existing.skey");
        std::fs::write(&key, "the key that is already funded").unwrap();
        assert!(matches!(claim(&key), Err(KeygenError::Exists(_))));
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            "the key that is already funded"
        );
        // A free name is claimed empty, at mode 0600.
        use std::os::unix::fs::PermissionsExt;
        let fresh = dir.path().join("fresh.skey");
        claim(&fresh).unwrap();
        assert_eq!(std::fs::metadata(&fresh).unwrap().len(), 0);
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
