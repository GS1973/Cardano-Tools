//! Shared config-handling helpers used by both binaries.
//!
//! Each binary keeps its own typed config struct (`OnlineConfig` /
//! `SignerConfig`) but the X25519 keypair extraction logic is identical
//! — both store `own_crypto_skey_hex` and `peer_crypto_pubkey_hex` as
//! optional 64-char hex strings, and both want the same `(sk, pk)`
//! tuple back. This module factors out the parse-and-pair step.

use crate::crypto::key_from_hex;
use zeroize::Zeroizing;

/// Decode the persisted X25519 keypair (own secret + peer public) from
/// their hex-string representations. Returns `None` if either side is
/// missing or unparseable, signalling that the binary is not yet paired.
/// The secret half is returned in a `Zeroizing` wrapper so the in-RAM copy
/// is wiped when the caller drops it.
pub fn paired_keys_from_hex(
    own_skey_hex: Option<&str>,
    peer_pubkey_hex: Option<&str>,
) -> Option<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let sk_hex = own_skey_hex?;
    let pk_hex = peer_pubkey_hex?;
    let sk = Zeroizing::new(key_from_hex(sk_hex).ok()?);
    let pk = key_from_hex(pk_hex).ok()?;
    Some((sk, pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_some_when_both_present() {
        let sk_hex = "00".repeat(32);
        let pk_hex = "11".repeat(32);
        let pair = paired_keys_from_hex(Some(&sk_hex), Some(&pk_hex));
        assert!(pair.is_some());
        let (sk, pk) = pair.unwrap();
        assert_eq!(sk[0], 0x00);
        assert_eq!(pk[0], 0x11);
    }

    #[test]
    fn returns_none_when_skey_missing() {
        let pk_hex = "11".repeat(32);
        assert!(paired_keys_from_hex(None, Some(&pk_hex)).is_none());
    }

    #[test]
    fn returns_none_when_pkey_missing() {
        let sk_hex = "00".repeat(32);
        assert!(paired_keys_from_hex(Some(&sk_hex), None).is_none());
    }

    #[test]
    fn returns_none_when_both_missing() {
        assert!(paired_keys_from_hex(None, None).is_none());
    }

    #[test]
    fn returns_none_on_invalid_hex() {
        let pk_hex = "11".repeat(32);
        assert!(paired_keys_from_hex(Some("zzz"), Some(&pk_hex)).is_none());
    }
}

/// Persist a serializable value to disk with strict 0600 permissions on
/// the file and 0700 on its parent directory. Atomic: writes to a
/// per-invocation-unique `.tmp` sibling that is created with mode 0600
/// from the start (no chmod window), fsyncs, then renames over the
/// target so a reader sees either the old or the new content but never
/// a partial file, and two concurrent saves of the same file cannot
/// interleave writes on a shared staging name.
/// Idempotent: creates the parent dir on first call and tightens
/// permissions on every subsequent save. Use for state-files and
/// config-files that contain operator metadata (paths, hex secrets,
/// hashes) the attacker should not enumerate.
pub fn save_secure<T: serde::Serialize>(
    path: &std::path::Path,
    value: &T,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let mut parent_perms = std::fs::metadata(parent)?.permissions();
        parent_perms.set_mode(0o700);
        std::fs::set_permissions(parent, parent_perms)?;
    }

    let json = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    // Unique staging name per invocation: the pid disambiguates
    // processes, the counter disambiguates threads within one process.
    static SAVE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SAVE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".{}.{}.tmp", std::process::id(), seq));
    let tmp_path = path.with_file_name(tmp_name);

    // Mode 0600 is set at creation time; an explicit fchmod on the open
    // file handle then defends against a non-default umask (umask 077 +
    // mode 0o600 still yields 0o600, but a custom umask such as 002
    // would not). Both ensure the secret-bearing bytes are never
    // visible to non-owner processes for any window, even between
    // create and chmod.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    {
        let mut writer = &f;
        writer.write_all(json.as_bytes())?;
        writer.flush()?;
    }
    f.sync_all()?;
    drop(f);

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Custom deserializer for `Option<String>` that maps empty strings to
/// `None`. Hand-edited config files often have `"peer_crypto_pubkey_hex": ""`
/// after a clear-pairing flow that did not also remove the key; treating
/// that as `Some("")` makes downstream `paired` checks ambiguous.
pub fn deserialize_empty_string_as_none<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.filter(|s| !s.is_empty()))
}

#[cfg(test)]
mod save_secure_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_0600_file_and_leaves_no_staging_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg").join("state.json");
        save_secure(&path, &serde_json::json!({"k": "v"})).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let back: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back["k"], "v");

        // The unique staging file is renamed over the target; nothing else
        // may remain in the directory.
        let entries: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("state.json")]);
    }

    #[test]
    fn overwrites_existing_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        save_secure(&path, &serde_json::json!({"n": 1})).unwrap();
        save_secure(&path, &serde_json::json!({"n": 2})).unwrap();
        let back: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back["n"], 2);
    }
}
