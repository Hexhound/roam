use std::path::{Component, Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

use crate::error::FilesError;
use crate::fileset::FILESET_MAP_ID;

/// Compute the stable container id for `file` within `vault_root`.
///
/// The id is the file's path relative to the vault root, with separators
/// normalized to `/` and Unicode NFC normalization applied. Paths that
/// escape the vault (via `..`) or point outside it entirely are rejected
/// with [`FilesError::PathEscapesVault`].
pub fn container_id(vault_root: &Path, file: &Path) -> Result<String, FilesError> {
    // If `file` already carries the vault prefix (absolute or relative),
    // strip it so we don't double up when resolving; otherwise treat the
    // whole `file` as relative to the vault root.
    let remainder = file.strip_prefix(vault_root).unwrap_or(file);
    let combined = vault_root.join(remainder);

    let root_parts = lexical_normalize(vault_root);
    let file_parts = lexical_normalize(&combined);

    // A leading `..` survives normalization only when a relative path walked
    // above its own root — that is always an escape, regardless of whether
    // the vault root was absolute, relative, `.`, or empty.
    if file_parts.iter().any(|part| part == "..") {
        return Err(FilesError::PathEscapesVault(file.to_path_buf()));
    }

    // The normalized file path must begin with the normalized vault path;
    // otherwise the path resolves outside the vault.
    if file_parts.len() < root_parts.len() || file_parts[..root_parts.len()] != root_parts[..] {
        return Err(FilesError::PathEscapesVault(file.to_path_buf()));
    }

    let relative = &file_parts[root_parts.len()..];
    let joined = relative.join("/");

    // Apply Unicode NFC so decomposed and composed forms map to one id.
    let key: String = joined.nfc().collect();

    // Reserved-name guard (B3): a real vault file literally named
    // `__roam_fileset__` at the vault root resolves to exactly `FILESET_MAP_ID`,
    // which would collide the file's text container with the well-known file-set
    // map container. Reject it here — `container_id` is the single choke point
    // every flow (import/scan/project/rename) passes through, and it is only ever
    // called on real vault files (the map container is referenced by the constant
    // directly, never via `container_id`), so no legitimate caller trips this.
    // `path.rs` referencing `fileset::FILESET_MAP_ID` is a plain intra-crate
    // `use`; Rust module graphs may be cyclic, so there is no dependency cycle.
    if key == FILESET_MAP_ID {
        return Err(FilesError::ReservedName(key));
    }

    Ok(key)
}

/// Reconstruct the on-disk path for a container-id `key` under `vault_root`.
///
/// This is the platform-correct inverse of [`container_id`]: a key is a
/// `/`-separated vault-relative path, so we split on `/` and join each component
/// onto `vault_root` via [`Path::push`]. That produces native separators on
/// every platform (e.g. `vault\a\b.md` on Windows) instead of the literal
/// `vault/a/b.md` string a bare `vault_root.join(key)` would yield on Windows.
/// On unix the result is byte-identical to the old `join`.
pub fn key_to_path(vault_root: &Path, key: &str) -> PathBuf {
    let mut path = vault_root.to_path_buf();
    for component in key.split('/') {
        path.push(component);
    }
    path
}

/// Lexically normalize `path` into its `/`-oriented "normal" components,
/// resolving `.` and `..` without touching the filesystem.
///
/// A `..` pops the previous normal component. For an absolute path a `..`
/// at the root is a no-op (it cannot escape above the root). For a relative
/// path a `..` that cannot pop is preserved as a leading `".."` segment,
/// which signals that the path escaped its own root. The returned strings
/// are the plain path segments, with any leading root/prefix dropped.
fn lexical_normalize(path: &Path) -> Vec<String> {
    let absolute = path.is_absolute();
    let mut parts: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::ParentDir => match parts.last() {
                Some(last) if last != ".." => {
                    parts.pop();
                }
                _ if !absolute => parts.push("..".to_string()),
                _ => {}
            },
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn absolute_file_under_vault() {
        let vault = PathBuf::from("/vault/root");
        let file = vault.join("a/b.md");
        assert_eq!(container_id(&vault, &file).unwrap(), "a/b.md");
    }

    #[test]
    fn relative_dot_form_under_vault() {
        let vault = PathBuf::from("/vault/root");
        let file = PathBuf::from("./a/b.md");
        assert_eq!(container_id(&vault, &file).unwrap(), "a/b.md");
    }

    #[test]
    fn parent_escape_is_rejected() {
        let vault = PathBuf::from("/vault/root");
        let file = PathBuf::from("../escape.md");
        assert!(matches!(
            container_id(&vault, &file),
            Err(FilesError::PathEscapesVault(_))
        ));
    }

    #[test]
    fn absolute_outside_vault_is_rejected() {
        let vault = PathBuf::from("/vault/root");
        let file = PathBuf::from("/etc/passwd");
        assert!(matches!(
            container_id(&vault, &file),
            Err(FilesError::PathEscapesVault(_))
        ));
    }

    #[test]
    fn relative_vault_dot_escape_is_rejected() {
        let vault = PathBuf::from(".");
        let file = PathBuf::from("a/../../b");
        assert!(matches!(
            container_id(&vault, &file),
            Err(FilesError::PathEscapesVault(_))
        ));
    }

    #[test]
    fn relative_vault_escape_chain_is_rejected() {
        let vault = PathBuf::from("vault/sub");
        let file = PathBuf::from("vault/sub/../../x");
        assert!(matches!(
            container_id(&vault, &file),
            Err(FilesError::PathEscapesVault(_))
        ));
    }

    #[test]
    fn relative_vault_normal_file() {
        let vault = PathBuf::from("vault");
        let file = PathBuf::from("vault/a/b.md");
        assert_eq!(container_id(&vault, &file).unwrap(), "a/b.md");
    }

    #[test]
    fn key_to_path_round_trips_nested_key_by_components() {
        // B1: container_id(vault, vault/a/b.md) -> "a/b.md"; key_to_path must
        // reconstruct vault/a/b.md. Compare by COMPONENTS (not the raw string) so
        // the assertion holds regardless of the platform path separator.
        let vault = PathBuf::from("/vault/root");
        let original = vault.join("a").join("b.md");
        let key = container_id(&vault, &original).unwrap();
        assert_eq!(key, "a/b.md");

        let reconstructed = key_to_path(&vault, &key);
        let original_parts: Vec<_> = original.components().collect();
        let reconstructed_parts: Vec<_> = reconstructed.components().collect();
        assert_eq!(reconstructed_parts, original_parts);
    }

    #[test]
    fn key_to_path_deeply_nested_round_trip() {
        let vault = PathBuf::from("/vault/root");
        let original = vault.join("deep").join("nested").join("path").join("n.md");
        let key = container_id(&vault, &original).unwrap();
        assert_eq!(key, "deep/nested/path/n.md");
        let reconstructed = key_to_path(&vault, &key);
        assert_eq!(
            reconstructed.components().collect::<Vec<_>>(),
            original.components().collect::<Vec<_>>()
        );
    }

    #[test]
    fn reserved_fileset_name_is_rejected() {
        // B3: a vault-relative path that is exactly the file-set sentinel maps to
        // FILESET_MAP_ID and must be rejected.
        let vault = PathBuf::from("/vault/root");
        let file = vault.join(FILESET_MAP_ID);
        assert!(matches!(
            container_id(&vault, &file),
            Err(FilesError::ReservedName(name)) if name == FILESET_MAP_ID
        ));
    }

    #[test]
    fn sentinel_as_normal_filename_is_allowed() {
        // A file that merely CONTAINS the sentinel (different key) is fine.
        let vault = PathBuf::from("/vault/root");
        let file = vault.join("notes").join("__roam_fileset__.md");
        assert_eq!(
            container_id(&vault, &file).unwrap(),
            "notes/__roam_fileset__.md"
        );
    }

    #[test]
    fn nfc_decomposed_matches_composed() {
        let vault = PathBuf::from("/vault/root");
        let decomposed = container_id(&vault, &vault.join("cafe\u{0301}.md")).unwrap();
        let composed = container_id(&vault, &vault.join("caf\u{00e9}.md")).unwrap();
        assert_eq!(decomposed, composed);
        assert_eq!(composed, "caf\u{00e9}.md");
    }
}
