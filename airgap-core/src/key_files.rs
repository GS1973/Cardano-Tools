//! Writing a new key file without ever overwriting one. A signer that
//! generates keys first claims each signing-key name with an exclusive
//! create ([`claim`]), then writes the key through a staged, fsync'd rename
//! at its final mode ([`write_secure`]). Two generations can then never write
//! into the same place, and a key that already exists is never touched.

/// Why a key file could not be claimed or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyFileError {
    #[error("a key already exists at {0}: refusing to overwrite")]
    Exists(String),
    #[error("write failed: {0}")]
    Write(String),
}

/// Claim `path` for a new signing key: create it empty, at mode 0600, with an
/// exclusive create. Fails with [`KeyFileError::Exists`] when anything is
/// already at that name, also when another process created it a moment ago.
/// The key itself then replaces this empty file (see [`write_secure`]), so a
/// name that was not claimed here is never written to. An exclusive create
/// works on every filesystem a key drive may use, FAT and exFAT included.
pub fn claim(path: &std::path::Path) -> Result<(), KeyFileError> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(KeyFileError::Exists(path.display().to_string()))
        }
        Err(e) => Err(KeyFileError::Write(e.to_string())),
    }
}

/// Write `content` to `path` via a hidden `.tmp` sibling + rename. `mode`
/// is applied at creation time (a seed-bearing skey is never readable at a
/// wider mode for any window, and a crash-orphaned tmp is never 0644) and
/// the file is fsync'd before the rename so the bytes are durably staged.
/// A signing key goes to a name this call claimed first ([`claim`]), and only
/// the claimer writes that name or its verification key, so the staging name
/// per file is never shared between two writers.
pub fn write_secure(path: &std::path::Path, content: &str, mode: u32) -> Result<(), KeyFileError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file_name = path
        .file_name()
        .ok_or_else(|| KeyFileError::Write(format!("path has no file name: {}", path.display())))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    // A crashed previous run may have left a stale staging file (possibly at
    // a looser mode); remove it so `create_new` lands `mode` on a fresh inode.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(KeyFileError::Write(e.to_string())),
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| KeyFileError::Write(e.to_string()))?;
    // `mode` on OpenOptions is masked by the process umask; re-assert it on
    // the open fd so the final mode is exactly `mode`.
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| KeyFileError::Write(e.to_string()))?;
    f.write_all(content.as_bytes())
        .map_err(|e| KeyFileError::Write(e.to_string()))?;
    f.sync_all()
        .map_err(|e| KeyFileError::Write(e.to_string()))?;
    drop(f);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(KeyFileError::Write(e.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_claimed_name_is_refused_the_second_time_and_never_touched() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("payment.skey");
        claim(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(&p, "KEEP").unwrap();
        assert!(matches!(claim(&p), Err(KeyFileError::Exists(_))));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "KEEP");
    }

    #[test]
    fn a_secure_write_lands_at_its_mode_and_leaves_no_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("payment.skey");
        claim(&p).unwrap();
        write_secure(&p, "SECRET", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "SECRET");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let v = dir.path().join("payment.vkey");
        write_secure(&v, "PUBLIC", 0o644).unwrap();
        assert_eq!(
            std::fs::metadata(&v).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }
}
