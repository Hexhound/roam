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
    // Resolve `file` against the vault root when it is relative, so a
    // `./a/b.md` form and an absolute `<vault>/a/b.md` form agree.
    let combined = if file.is_absolute() {
        file.to_path_buf()
    } else {
        vault_root.join(file)
    };

    let root_parts = lexical_normalize(vault_root);
    let file_parts = lexical_normalize(&combined);

    // The normalized file path must begin with the normalized vault path;
    // otherwise a `..` component walked above the vault, or the path was
    // absolute and outside the vault.
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
/// A `..` pops the previous component; at the root it is a no-op (a path
/// cannot escape above its own root). The returned strings are the plain
/// path segments, with any leading root/prefix dropped.
fn lexical_normalize(path: &Path) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::ParentDir => {
                parts.pop();
            }
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
    fn nfc_decomposed_matches_composed() {
        let vault = PathBuf::from("/vault/root");
        let decomposed = container_id(&vault, &vault.join("cafe\u{0301}.md")).unwrap();
        let composed = container_id(&vault, &vault.join("caf\u{00e9}.md")).unwrap();
        assert_eq!(decomposed, composed);
        assert_eq!(composed, "caf\u{00e9}.md");
    }
}
