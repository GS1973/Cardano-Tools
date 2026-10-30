//! Air-gapped DRep key generation.
//!
//! Generates a fresh Ed25519 DRep key pair on the offline signer host and
//! writes it in the cardano-cli envelope format the loader already reads
//! (`DRepSigningKey_ed25519`). The seed comes from the OS CSPRNG, the same
//! entropy source the KES rotation uses; the secret never leaves this
//! machine. Files are written atomically (hidden `.tmp` + rename), created at
//! their final mode from the first byte (skey 0600) and fsynced, and an
//! existing key is never overwritten.

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct GeneratedDRepKey {
    /// CIP-129 `drep1...` (header byte + hash): what recent cardano-cli emits.
    pub drep_id_cip129: String,
    /// Legacy CIP-105 `drep1...` (bare hash).
    pub drep_id_cip105: String,
    pub keyhash_hex: String,
    pub skey_path: String,
    pub vkey_path: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum KeygenError {
    #[error("output directory does not exist: {0}")]
    NoDir(String),
    #[error("a DRep signing key already exists at {0}: refusing to overwrite")]
    Exists(String),
    #[error("system entropy unavailable: {0}")]
    Entropy(String),
    #[error("write failed: {0}")]
    Write(String),
}

/// Generate a DRep key pair and write `drep.skey` + `drep.vkey` into
/// `output_dir`. Returns the DRep id (both encodings) and the written paths.
pub(crate) fn generate_and_write(
    output_dir: &std::path::Path,
) -> Result<GeneratedDRepKey, KeygenError> {
    let _one_at_a_time = KEYGEN_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !output_dir.is_dir() {
        return Err(KeygenError::NoDir(output_dir.display().to_string()));
    }
    let skey_path = output_dir.join("drep.skey");
    let vkey_path = output_dir.join("drep.vkey");
    // Claim the signing-key name before anything secret is generated.
    claim(&skey_path)?;

    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed).map_err(|e| KeygenError::Entropy(e.to_string()))?;
    let sk = SigningKey::from_bytes(&seed);
    let vkey = sk.verifying_key().to_bytes();
    let keyhash = shared::validate::blake2b224(&vkey);

    // cardano-cli envelopes: cborHex is `5820` (CBOR bytes(32)) + raw key.
    let seed_hex = Zeroizing::new(hex::encode(*seed));
    let skey_json = Zeroizing::new(format!(
        "{{\"type\":\"DRepSigningKey_ed25519\",\"description\":\"Delegate Representative Signing Key\",\"cborHex\":\"5820{}\"}}",
        *seed_hex
    ));
    let vkey_json = format!(
        "{{\"type\":\"DRepVerificationKey_ed25519\",\"description\":\"Delegate Representative Verification Key\",\"cborHex\":\"5820{}\"}}",
        hex::encode(vkey)
    );

    let written = write_secure(&skey_path, &skey_json, 0o600)
        .and_then(|()| write_secure(&vkey_path, &vkey_json, 0o644));
    if let Err(e) = written {
        // Nothing has been shown yet: drop what this call claimed or wrote,
        // so a retry starts clean.
        let _ = std::fs::remove_file(&skey_path);
        let _ = std::fs::remove_file(&vkey_path);
        return Err(e);
    }
    // Persist the renames. Best-effort: a directory that cannot be fsync'd
    // does not undo the writes already applied.
    if let Ok(d) = std::fs::File::open(output_dir) {
        let _ = d.sync_all();
    }

    Ok(GeneratedDRepKey {
        drep_id_cip129: shared::drep_id::keyhash_to_cip129(&keyhash),
        drep_id_cip105: shared::drep_id::keyhash_to_cip105(&keyhash),
        keyhash_hex: hex::encode(keyhash),
        skey_path: skey_path.display().to_string(),
        vkey_path: vkey_path.display().to_string(),
    })
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

    #[test]
    fn generates_loadable_key_and_matching_id() {
        let dir = tempfile::tempdir().unwrap();
        let g = generate_and_write(dir.path()).expect("generates");

        // The written skey loads as a DRep key.
        let key =
            shared::cardano_keys::load_skey(std::path::Path::new(&g.skey_path)).expect("loads");
        let seed = match key {
            shared::cardano_keys::CardanoKey::DRep { seed_32 } => seed_32,
            other => panic!("expected DRep key, got {other:?}"),
        };
        // Its vkey hashes to the advertised DRep id.
        let vkey = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let keyhash = shared::validate::blake2b224(&vkey);
        assert_eq!(hex::encode(keyhash), g.keyhash_hex);
        assert_eq!(
            shared::drep_id::drep_id_to_keyhash(&g.drep_id_cip129).unwrap(),
            keyhash
        );
        assert_eq!(
            shared::drep_id::drep_id_to_keyhash(&g.drep_id_cip105).unwrap(),
            keyhash
        );
    }

    #[test]
    fn refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        generate_and_write(dir.path()).expect("first");
        let err = generate_and_write(dir.path()).expect_err("second must refuse");
        assert!(matches!(err, KeygenError::Exists(_)));
    }

    #[test]
    fn writes_skey_0600_and_vkey_0644() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let g = generate_and_write(dir.path()).expect("generates");
        let skey_mode = std::fs::metadata(&g.skey_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(skey_mode, 0o600, "skey must never be group/world-readable");
        let vkey_mode = std::fs::metadata(&g.vkey_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(vkey_mode, 0o644);
    }

    #[test]
    fn leftover_tmp_from_crashed_run_does_not_block_generation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // Simulate a crash between the tmp write and the rename, with the
        // stale tmp at a mode `create_new` alone could not fix.
        let stale = dir.path().join(".drep.skey.tmp");
        std::fs::write(&stale, "stale").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();
        let g = generate_and_write(dir.path()).expect("generates despite leftover tmp");
        let skey_mode = std::fs::metadata(&g.skey_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(skey_mode, 0o600);
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
        // The key on disk is the one the successful call advertised.
        let seed = match shared::cardano_keys::load_skey(std::path::Path::new(&ok[0].skey_path))
            .unwrap()
        {
            shared::cardano_keys::CardanoKey::DRep { seed_32 } => seed_32,
            other => panic!("expected DRep key, got {other:?}"),
        };
        let vkey = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            hex::encode(shared::validate::blake2b224(&vkey)),
            ok[0].keyhash_hex
        );
    }

    #[test]
    fn skey_and_vkey_stage_under_their_own_names() {
        let dir = tempfile::tempdir().unwrap();
        generate_and_write(dir.path()).expect("generates");
        for name in [".drep.skey.tmp", ".drep.vkey.tmp", "drep.tmp"] {
            assert!(!dir.path().join(name).exists(), "{name} left behind");
        }
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
