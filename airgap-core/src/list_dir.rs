//! `/api/list-dir` handler: operator-facing directory browser used by
//! the Setup view to pick LUKS-mounted skey paths.
//!
//! Only `/media`, `/mnt`, and `/run/media` are allowed roots. Path
//! traversal is foreclosed before `canonicalize` so a pre-existing
//! symlink chain cannot escape the allow-list. The same allow-list is
//! re-used by the setup-time `signer_test_load` handler.

use crate::error::ErrorEnvelope;

#[derive(serde::Deserialize)]
pub struct ListDirQuery {
    /// Absolute filesystem path to enumerate. Defaults to /media when empty.
    path: Option<String>,
}

#[derive(serde::Serialize)]
pub struct DirEntry {
    name: String,
    is_dir: bool,
    is_file: bool,
}

#[derive(serde::Serialize)]
pub struct ListDirResponse {
    /// Canonicalised absolute path that was actually enumerated.
    path: String,
    /// Parent path or null at filesystem root.
    parent: Option<String>,
    entries: Vec<DirEntry>,
}

/// Allow-list of root paths the signer is willing to list. Anything else
/// is rejected before `canonicalize` so an attacker cannot escape via
/// `..` sequences or pre-existing symlinks: the canonicalised result
/// must itself begin with one of these roots. v1.0 expects skeys on a
/// LUKS-encrypted removable drive (mounted under `/media`, `/mnt`, or
/// `/run/media`), so the operator's home directory is intentionally
/// not in the list.
pub fn list_dir_allowed_roots() -> Vec<std::path::PathBuf> {
    vec![
        std::path::PathBuf::from("/media"),
        std::path::PathBuf::from("/mnt"),
        std::path::PathBuf::from("/run/media"),
    ]
}

pub async fn list_dir(
    axum::extract::Query(q): axum::extract::Query<ListDirQuery>,
) -> Result<axum::Json<ListDirResponse>, ErrorEnvelope> {
    let raw = q.path.unwrap_or_default();
    let path = if raw.trim().is_empty() {
        "/media".to_string()
    } else {
        raw
    };
    let pb = std::path::PathBuf::from(&path);
    // `?` propagation on canonicalize-failure: do not silently fall back
    // to the raw input because a non-existent path could otherwise be
    // listed-of-its-parent (TOCTOU-style).
    let canonical = pb.canonicalize().map_err(|e| {
        tracing::error!(error = %e, "list-dir canonicalize failed");
        ErrorEnvelope::invalid("path does not exist")
    })?;

    let allowed = list_dir_allowed_roots();
    if !allowed.iter().any(|root| canonical.starts_with(root)) {
        tracing::error!(path = %canonical.display(), "list-dir path outside allow-list");
        return Err(ErrorEnvelope::invalid(
            "path is outside the allowed roots (/media, /mnt, /run/media)",
        ));
    }

    let read = std::fs::read_dir(&canonical).map_err(|e| {
        tracing::error!(error = %e, path = %canonical.display(), "list-dir read_dir failed");
        let kind = e.kind();
        let msg = match kind {
            std::io::ErrorKind::PermissionDenied => "permission denied reading directory",
            std::io::ErrorKind::NotFound => "directory does not exist",
            std::io::ErrorKind::NotADirectory => "path is not a directory",
            _ => "cannot list directory",
        };
        ErrorEnvelope::invalid(msg)
    })?;

    let mut entries: Vec<DirEntry> = read
        .flatten()
        .map(|e| {
            let ft = e.file_type().ok();
            DirEntry {
                name: e.file_name().to_string_lossy().to_string(),
                is_dir: ft.map(|t| t.is_dir()).unwrap_or(false),
                is_file: ft.map(|t| t.is_file()).unwrap_or(false),
            }
        })
        .filter(|e| e.is_dir || e.is_file)
        .collect();
    // Directories first, then files; alphabetical within each group.
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    let parent = canonical
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| p != &canonical.to_string_lossy().to_string());

    Ok(axum::Json(ListDirResponse {
        path: canonical.to_string_lossy().to_string(),
        parent,
        entries,
    }))
}

/// One allowed root and how populated it is. The browser uses this to render
/// quick-jump chips and to open on the first non-empty root: USB drives mount
/// under `/run/media/<user>` (or `/media/<user>`) on this host while a bare
/// `/media` is usually empty, so landing blindly on `/media` looked broken.
#[derive(serde::Serialize)]
pub struct RootInfo {
    path: String,
    /// Whether the root exists and is a directory on this host.
    exists: bool,
    /// Direct-entry count (0 when missing or unreadable).
    entry_count: usize,
}

/// Report each allowed root with its entry count. No path input, so there is
/// nothing to validate against the allow-list: the roots are the allow-list.
pub async fn list_dir_roots() -> axum::Json<Vec<RootInfo>> {
    let infos = list_dir_allowed_roots()
        .into_iter()
        .map(|root| RootInfo {
            exists: root.is_dir(),
            entry_count: std::fs::read_dir(&root)
                .map(|rd| rd.flatten().count())
                .unwrap_or(0),
            path: root.to_string_lossy().to_string(),
        })
        .collect();
    axum::Json(infos)
}
