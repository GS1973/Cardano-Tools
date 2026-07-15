//! Air-gapped DRep key generation.
//!
//! Generates a fresh Ed25519 DRep key pair on the offline signer host and
//! writes it in the cardano-cli envelope format the loader already reads
//! (`DRepSigningKey_ed25519`). The seed comes from the OS CSPRNG, the same
//! entropy source the KES rotation uses; the secret never leaves this
//! machine. Files are written atomically (`.tmp` + rename), created at
//! their final mode from the first byte (skey 0600) and fsynced, and an
//! existing key is never overwritten.

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct GeneratedDRepKey {
    /// CIP-129 `drep1...` (header byte + hash) — what recent cardano-cli emits.
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
    #[error("a DRep signing key already exists at {0} — refusing to overwrite")]
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
    if !output_dir.is_dir() {
        return Err(KeygenError::NoDir(output_dir.display().to_string()));
    }
    let skey_path = output_dir.join("drep.skey");
    let vkey_path = output_dir.join("drep.vkey");
    if skey_path.exists() {
        return Err(KeygenError::Exists(skey_path.display().to_string()));
    }

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

    write_secure(&skey_path, &skey_json, 0o600)?;
    write_secure(&vkey_path, &vkey_json, 0o644)?;

    Ok(GeneratedDRepKey {
        drep_id_cip129: shared::drep_id::keyhash_to_cip129(&keyhash),
        drep_id_cip105: shared::drep_id::keyhash_to_cip105(&keyhash),
        keyhash_hex: hex::encode(keyhash),
        skey_path: skey_path.display().to_string(),
        vkey_path: vkey_path.display().to_string(),
    })
}

/// Write `content` to `path` via a `.tmp` sibling + rename, with `mode`.
///
/// The tmp file is created at `mode` from the first byte
/// (`OpenOptions::mode` + `create_new`), so the secret never sits on disk
/// with the process-default 0644; it is fsynced before the rename and the
/// parent directory is fsynced after, so a crash right after generating a
/// brand-new key cannot lose it or the rename.
fn write_secure(path: &std::path::Path, content: &str, mode: u32) -> Result<(), KeygenError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    // `create_new` would trip over a tmp left by a crashed earlier run;
    // nothing was committed to the final path, so the leftover is garbage.
    if tmp.exists() {
        std::fs::remove_file(&tmp).map_err(|e| KeygenError::Write(e.to_string()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| KeygenError::Write(e.to_string()))?;
    f.write_all(content.as_bytes())
        .map_err(|e| KeygenError::Write(e.to_string()))?;
    f.sync_all().map_err(|e| KeygenError::Write(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| KeygenError::Write(e.to_string()))?;
    // Persist the rename metadata. Best-effort: a directory that cannot
    // be fsync'd does not undo the write already applied.
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_loadable_key_and_matching_id() {
        let dir = tempfile::tempdir().unwrap();
        let g = generate_and_write(dir.path()).expect("generates");

        // The written skey loads as a DRep key.
        let key = shared::cardano_keys::load_skey(std::path::Path::new(&g.skey_path)).expect("loads");
        let seed = match key {
            shared::cardano_keys::CardanoKey::DRep { seed_32 } => seed_32,
            other => panic!("expected DRep key, got {other:?}"),
        };
        // Its vkey hashes to the advertised DRep id.
        let vkey = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let keyhash = shared::validate::blake2b224(&vkey);
        assert_eq!(hex::encode(keyhash), g.keyhash_hex);
        assert_eq!(shared::drep_id::drep_id_to_keyhash(&g.drep_id_cip129).unwrap(), keyhash);
        assert_eq!(shared::drep_id::drep_id_to_keyhash(&g.drep_id_cip105).unwrap(), keyhash);
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
        let skey_mode = std::fs::metadata(&g.skey_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(skey_mode, 0o600, "skey must never be group/world-readable");
        let vkey_mode = std::fs::metadata(&g.vkey_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(vkey_mode, 0o644);
    }

    #[test]
    fn leftover_tmp_from_crashed_run_does_not_block_generation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // Simulate a crash between the tmp write and the rename, with the
        // stale tmp at a mode `create_new` alone could not fix.
        let stale = dir.path().join("drep.tmp");
        std::fs::write(&stale, "stale").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();
        let g = generate_and_write(dir.path()).expect("generates despite leftover tmp");
        let skey_mode = std::fs::metadata(&g.skey_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(skey_mode, 0o600);
    }
}
