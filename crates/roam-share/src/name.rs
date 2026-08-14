//! Names that are safe to write to disk after an untrusted peer chose them.
//!
//! A share receiver is in an unusual position: it accepts *filenames from a
//! stranger* and then creates files with them. That is the classic path to
//! writing outside the download directory, and it has to be refused by
//! construction rather than by remembering to check at each call site — hence
//! the newtypes. There is no way to build a [`SafeName`] or [`RelPath`] except
//! through validation.
//!
//! What is rejected, and why each one matters:
//!
//! * `..`, absolute paths, and drive prefixes — escape the download directory.
//! * Path separators inside a single name (both `/` and `\`) — `\` is a
//!   separator on Windows, so a name accepted as one component on Linux becomes
//!   two on Windows.
//! * NUL and other control characters — truncate the path in C APIs, so
//!   `"safe.txt\0.exe"` can land as something other than what was shown.
//! * Windows reserved device names (`CON`, `NUL`, `COM1`…) — opening them
//!   touches a device rather than a file.
//! * Trailing dots and spaces — Windows silently strips them, so `"a.txt "` and
//!   `"a.txt"` collide and one can overwrite the other.
//! * Unicode bidi overrides — `U+202E` renders `"…gnp.exe"` as `"…exe.png"` in
//!   the UI. The user approves one thing and receives another.
//!
//! Rejection is deliberate over sanitisation: silently rewriting a hostile name
//! into a different one invites a mismatch between what the user approved and
//! what got written.

use std::fmt;

/// Why a name was refused. Carries enough to tell the user *which* rule failed
/// without echoing the hostile name back into a shell or log verbatim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("name is empty")]
    Empty,
    #[error("name is longer than {max} bytes")]
    TooLong { max: usize },
    #[error("name contains a path separator")]
    Separator,
    #[error("name is `.` or `..`")]
    DotSegment,
    #[error("name contains a control character")]
    ControlCharacter,
    #[error("name contains a Unicode direction override, which can disguise the extension")]
    BidiOverride,
    #[error("name ends with a dot or space, which some systems silently strip")]
    TrailingDotOrSpace,
    #[error("`{0}` is a reserved device name")]
    ReservedDeviceName(String),
    #[error("path is absolute")]
    Absolute,
    #[error("path has no components")]
    NoComponents,
}

/// Filesystems generally cap a single component at 255 bytes.
const MAX_NAME_BYTES: usize = 255;

/// Windows device names. Reserved with or without an extension, so the check is
/// against the stem.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Characters that reorder rendered text and can therefore disguise an
/// extension: the bidi overrides and embeddings, plus the isolates.
fn is_bidi_override(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200F}' | '\u{200E}')
}

/// One validated path component — never a separator, never `..`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct SafeName(String);

impl SafeName {
    pub fn new(raw: &str) -> Result<Self, NameError> {
        if raw.is_empty() {
            return Err(NameError::Empty);
        }
        if raw.len() > MAX_NAME_BYTES {
            return Err(NameError::TooLong {
                max: MAX_NAME_BYTES,
            });
        }
        if raw.contains('/') || raw.contains('\\') {
            return Err(NameError::Separator);
        }
        if raw == "." || raw == ".." {
            return Err(NameError::DotSegment);
        }
        if raw.chars().any(|c| c.is_control()) {
            return Err(NameError::ControlCharacter);
        }
        if raw.chars().any(is_bidi_override) {
            return Err(NameError::BidiOverride);
        }
        if raw.ends_with('.') || raw.ends_with(' ') {
            return Err(NameError::TrailingDotOrSpace);
        }
        let stem = raw.split('.').next().unwrap_or(raw);
        if RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
            return Err(NameError::ReservedDeviceName(stem.to_string()));
        }
        Ok(SafeName(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Deserialization goes through the same validation as [`SafeName::new`].
///
/// This is the load-bearing part: names arrive over the wire, so a `Deserialize`
/// that just wrapped the string would let a hostile peer bypass every rule above
/// simply by sending an encoded frame.
impl<'de> serde::Deserialize<'de> for SafeName {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        SafeName::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// A validated *relative* path: one or more [`SafeName`] components.
///
/// Used for files inside an offered folder, where structure must survive but
/// must not be able to point anywhere outside the destination.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(Vec<SafeName>);

/// Serialized as the joined `/`-separated string, mirroring [`RelPath::new`].
/// Hand-written rather than derived: a derived impl would emit a sequence while
/// `Deserialize` expects a string, and the mismatch would only show up at
/// runtime.
impl serde::Serialize for RelPath {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl RelPath {
    /// Parse a `/`-separated relative path. Every component is validated, so
    /// `..`, absolute paths and backslash separators are all refused.
    pub fn new(raw: &str) -> Result<Self, NameError> {
        if raw.starts_with('/') || raw.starts_with('\\') {
            return Err(NameError::Absolute);
        }
        // A Windows drive prefix (`C:...`) is absolute there but not here, so
        // it is checked explicitly rather than left to `Path::is_absolute`.
        if raw.len() >= 2 && raw.as_bytes()[1] == b':' {
            return Err(NameError::Absolute);
        }
        let parts: Vec<SafeName> = raw
            .split('/')
            .map(SafeName::new)
            .collect::<Result<_, _>>()?;
        if parts.is_empty() {
            return Err(NameError::NoComponents);
        }
        Ok(RelPath(parts))
    }

    pub fn components(&self) -> &[SafeName] {
        &self.0
    }

    /// Join onto a destination directory. Safe by construction: every component
    /// is a validated [`SafeName`], so the result is always inside `base`.
    pub fn resolve_under(&self, base: &std::path::Path) -> std::path::PathBuf {
        let mut out = base.to_path_buf();
        for part in &self.0 {
            out.push(part.as_str());
        }
        out
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined: Vec<&str> = self.0.iter().map(SafeName::as_str).collect();
        f.write_str(&joined.join("/"))
    }
}

impl<'de> serde::Deserialize<'de> for RelPath {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        RelPath::new(&raw).map_err(serde::de::Error::custom)
    }
}
