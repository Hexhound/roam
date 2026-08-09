use std::path::{Component, Path};

use unicode_normalization::UnicodeNormalization;

use crate::error::FilesError;

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
    Ok(joined.nfc().collect())
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
    fn nfc_decomposed_matches_composed() {
        let vault = PathBuf::from("/vault/root");
        let decomposed = container_id(&vault, &vault.join("cafe\u{0301}.md")).unwrap();
        let composed = container_id(&vault, &vault.join("caf\u{00e9}.md")).unwrap();
        assert_eq!(decomposed, composed);
        assert_eq!(composed, "caf\u{00e9}.md");
    }
}
