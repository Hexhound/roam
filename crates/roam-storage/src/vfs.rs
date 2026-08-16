//! `VaultFs` — the filesystem seam under roam-storage.
//!
//! Everything the vault persists goes through this trait so the same storage
//! code can run on `std::fs` natively and on OPFS in a browser.
//!
//! # Why this trait is synchronous
//!
//! IndexedDB is async-only, so an IndexedDB backend would force `async fn`
//! through every persistence call — and from there through `Store` and most of
//! the crate. That is an enormous, invasive change for an IO detail.
//!
//! OPFS instead offers *synchronous* access handles
//! (`createSyncAccessHandle`), which are available **only inside a Web
//! Worker**. Keeping this trait sync and running roam in a worker is both far
//! cheaper and the proven path — it is exactly how SQLite's official wasm build
//! persists. The cost is a real constraint on M3: **the browser client cannot
//! run roam on the main thread.** That is a deliberate trade, recorded here so
//! it is not rediscovered later.
//!
//! # Why `io::Result`
//!
//! Callers already branch on `ErrorKind::NotFound` to mean "absent, not
//! broken". Keeping `io::Error` preserves that logic unchanged; non-native
//! backends synthesise the same kinds.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The persistence operations roam-storage actually performs.
///
/// Note there is no "open file handle" method: the one streaming use (chunked
/// blob transfer) is expressed as [`VaultFs::read_range`], which OPFS and
/// IndexedDB can both serve. Handing out `File` objects would not port.
pub trait VaultFs: Send + Sync {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Read `len` bytes starting at `offset`. Returns fewer only at EOF.
    /// Exists so large blobs are never loaded whole to serve one chunk.
    fn read_range(&self, path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>>;

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;

    /// Append to `path`, creating it if absent. The op-logs depend on this
    /// never rewriting existing bytes.
    ///
    /// Makes no durability promise — see [`VaultFs::append_sync`].
    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;

    /// Append and durably flush before returning.
    ///
    /// Separate from [`VaultFs::append`] because the difference is a real
    /// guarantee, not a performance hint: op-logs are the source of truth
    /// ("op-log-is-truth"), so an acknowledged append must survive power loss.
    /// A backend that quietly implements this as a plain append weakens
    /// durability in a way no test can observe, which is exactly why it is a
    /// distinct method rather than a flag.
    fn append_sync(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;

    /// Create `path` (truncating any existing file) and set its length to
    /// `len`, sparsely where the backend supports it. Pre-sizes an in-flight
    /// blob so its chunks can arrive in any order.
    fn create_sized(&self, path: &Path, len: u64) -> io::Result<()>;

    /// Overwrite `len` bytes at `offset` in an existing file, leaving the rest
    /// (and the file's length) alone. The random-access counterpart to
    /// [`VaultFs::read_range`]; `write` would truncate.
    fn write_range(&self, path: &Path, offset: u64, bytes: &[u8]) -> io::Result<()>;

    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// Full paths of the entries directly under `path`. `NotFound` if absent.
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;

    fn file_len(&self, path: &Path) -> io::Result<u64>;
    fn exists(&self, path: &Path) -> bool;

    /// Whether `path` is a directory. Needed to walk a tree via
    /// [`VaultFs::read_dir`], which yields paths without type information.
    fn is_dir(&self, path: &Path) -> bool;

    /// Restrict `path` to the owner (`0600`). A no-op where the concept does
    /// not exist — a browser origin is already the isolation boundary.
    fn set_owner_only(&self, path: &Path) -> io::Result<()>;

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        String::from_utf8(self.read(path)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no such file: {}", path.display()),
    )
}

/// The real filesystem. Must stay byte-identical to the pre-`VaultFs` code.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeFs;

impl VaultFs for NativeFs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn read_range(&self, path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};

        let mut file = std::fs::File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;

        let mut buf = vec![0u8; len];
        let mut filled = 0;
        while filled < len {
            let read = file.read(&mut buf[filled..])?;
            if read == 0 {
                break; // EOF
            }
            filled += read;
        }
        buf.truncate(filled);
        Ok(buf)
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        std::fs::write(path, bytes)
    }

    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(bytes)
    }

    fn append_sync(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;

        // Whether this append creates the file (vs. extends an existing one).
        let is_create = !path.exists();

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;

        // On file creation, the new directory entry itself must be flushed, or a
        // power failure can lose the whole file (and thus the first op) despite
        // the content sync above. Only needed on create; append-to-existing is fine.
        #[cfg(unix)]
        if is_create {
            if let Some(dir) = path.parent() {
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
        }
        #[cfg(not(unix))]
        let _ = is_create;
        Ok(())
    }

    fn create_sized(&self, path: &Path, len: u64) -> io::Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        file.set_len(len)
    }

    fn write_range(&self, path: &Path, offset: u64, bytes: &[u8]) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};

        // No `truncate`: this writes INTO an existing pre-sized file.
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path)? {
            out.push(entry?.path());
        }
        Ok(out)
    }

    fn file_len(&self, path: &Path) -> io::Result<u64> {
        Ok(std::fs::metadata(path)?.len())
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn set_owner_only(&self, path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }
}

/// In-memory `VaultFs`, for tests and as the reference the browser backend has
/// to match. Also proves the abstraction is real: anything that still reaches
/// for `std::fs` directly will fail against this.
#[derive(Debug, Default)]
pub struct MemFs {
    inner: Mutex<MemState>,
}

#[derive(Debug, Default)]
struct MemState {
    files: BTreeMap<PathBuf, Vec<u8>>,
    dirs: BTreeSet<PathBuf>,
    owner_only: BTreeSet<PathBuf>,
}

impl MemFs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether [`VaultFs::set_owner_only`] was applied to `path`. Lets tests
    /// assert the permission call survives a refactor even off-Unix.
    pub fn is_owner_only(&self, path: &Path) -> bool {
        self.inner.lock().unwrap().owner_only.contains(path)
    }

    /// Every file path currently stored, sorted.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.inner.lock().unwrap().files.keys().cloned().collect()
    }
}

impl VaultFs for MemFs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| not_found(path))
    }

    fn read_range(&self, path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let state = self.inner.lock().unwrap();
        let bytes = state.files.get(path).ok_or_else(|| not_found(path))?;
        let start = (offset as usize).min(bytes.len());
        let end = start.saturating_add(len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.inner
            .lock()
            .unwrap()
            .files
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }

    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.inner
            .lock()
            .unwrap()
            .files
            .entry(path.to_path_buf())
            .or_default()
            .extend_from_slice(bytes);
        Ok(())
    }

    /// Nothing to flush: memory has no durability to promise.
    fn append_sync(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.append(path, bytes)
    }

    fn create_sized(&self, path: &Path, len: u64) -> io::Result<()> {
        self.inner
            .lock()
            .unwrap()
            .files
            .insert(path.to_path_buf(), vec![0u8; len as usize]);
        Ok(())
    }

    fn write_range(&self, path: &Path, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap();
        let file = state.files.get_mut(path).ok_or_else(|| not_found(path))?;
        let start = offset as usize;
        // Writing past the end extends the file, matching a seek-past-EOF write.
        if start + bytes.len() > file.len() {
            file.resize(start + bytes.len(), 0);
        }
        file[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap();
        let mut current = PathBuf::new();
        for part in path.components() {
            current.push(part);
            state.dirs.insert(current.clone());
        }
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap();
        let bytes = state.files.remove(from).ok_or_else(|| not_found(from))?;
        state.files.insert(to.to_path_buf(), bytes);
        // Permissions live on the inode natively, so they follow the file across
        // a rename. Modelling that matters: the write-tmp, chmod, rename
        // sequence is exactly how the identity secret gets published.
        if state.owner_only.remove(from) {
            state.owner_only.insert(to.to_path_buf());
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inner
            .lock()
            .unwrap()
            .files
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| not_found(path))
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let state = self.inner.lock().unwrap();
        if !state.dirs.contains(path) {
            return Err(not_found(path));
        }
        // Direct children only, matching `std::fs::read_dir`.
        let mut out = BTreeSet::new();
        for existing in state.files.keys().chain(state.dirs.iter()) {
            if let Ok(rest) = existing.strip_prefix(path) {
                if let Some(first) = rest.components().next() {
                    let child = path.join(first);
                    if &child != path {
                        out.insert(child);
                    }
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    fn file_len(&self, path: &Path) -> io::Result<u64> {
        self.inner
            .lock()
            .unwrap()
            .files
            .get(path)
            .map(|b| b.len() as u64)
            .ok_or_else(|| not_found(path))
    }

    fn exists(&self, path: &Path) -> bool {
        let state = self.inner.lock().unwrap();
        state.files.contains_key(path) || state.dirs.contains(path)
    }

    fn is_dir(&self, path: &Path) -> bool {
        self.inner.lock().unwrap().dirs.contains(path)
    }

    fn set_owner_only(&self, path: &Path) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap();
        if !state.files.contains_key(path) {
            return Err(not_found(path));
        }
        state.owner_only.insert(path.to_path_buf());
        Ok(())
    }
}

/// One conformance suite, run against every backend. A browser `VaultFs` must
/// pass this same function — that is the point of it.
///
/// Reachable outside `cfg(test)` behind the `conformance` feature, because the
/// OPFS backend can only be exercised in a real browser: the harness in
/// `roam-wasm` calls this from a `#[wasm_bindgen]` export. The feature is off by
/// default so a shipped artifact cannot contain it.
#[cfg(any(test, feature = "conformance"))]
pub fn conformance(fs: &dyn VaultFs, root: &Path) {
    fs.create_dir_all(root).expect("create root");

    let file = root.join("a.bin");
    assert!(!fs.exists(&file), "must not exist before writing");
    assert_eq!(
        fs.read(&file).unwrap_err().kind(),
        io::ErrorKind::NotFound,
        "absent file must report NotFound, not a generic error"
    );

    fs.write(&file, b"hello").expect("write");
    assert!(fs.exists(&file));
    assert_eq!(fs.read(&file).unwrap(), b"hello");
    assert_eq!(fs.file_len(&file).unwrap(), 5);
    assert_eq!(fs.read_to_string(&file).unwrap(), "hello");

    // Append extends, never rewrites — the op-log invariant.
    fs.append(&file, b" world").expect("append");
    assert_eq!(fs.read(&file).unwrap(), b"hello world");

    // Append also creates.
    let fresh = root.join("fresh.bin");
    fs.append(&fresh, b"new").expect("append creates");
    assert_eq!(fs.read(&fresh).unwrap(), b"new");

    // append_sync must be semantically identical to append; only its
    // durability promise differs. Both create-then-extend paths matter,
    // since the native backend takes a different branch on create.
    let durable = root.join("durable.bin");
    fs.append_sync(&durable, b"first")
        .expect("append_sync creates");
    fs.append_sync(&durable, b"-second")
        .expect("append_sync extends");
    assert_eq!(fs.read(&durable).unwrap(), b"first-second");

    // Ranged reads, including a clamped tail.
    assert_eq!(fs.read_range(&file, 6, 5).unwrap(), b"world");
    assert_eq!(fs.read_range(&file, 6, 99).unwrap(), b"world");
    assert_eq!(fs.read_range(&file, 99, 4).unwrap(), b"");

    // write() replaces rather than appends.
    fs.write(&file, b"xyz").expect("overwrite");
    assert_eq!(fs.read(&file).unwrap(), b"xyz");

    // Pre-size + random-access write: the out-of-order blob chunk path.
    // Chunks are written back-to-front here precisely because arrival order
    // must not matter.
    let part = root.join("blob.part");
    fs.create_sized(&part, 8).expect("create_sized");
    assert_eq!(fs.file_len(&part).unwrap(), 8, "must be pre-sized");
    assert_eq!(fs.read(&part).unwrap(), vec![0u8; 8], "must be zero-filled");

    fs.write_range(&part, 4, b"cdef").expect("write tail first");
    fs.write_range(&part, 0, b"ab").expect("write head after");
    assert_eq!(fs.read(&part).unwrap(), b"ab\0\0cdef");
    assert_eq!(
        fs.file_len(&part).unwrap(),
        8,
        "an in-range write must not change the file length"
    );

    // create_sized replaces any existing file rather than merging into it.
    fs.create_sized(&part, 2).expect("resize");
    assert_eq!(fs.read(&part).unwrap(), vec![0u8; 2]);
    fs.remove_file(&part).expect("cleanup part");

    // rename is the atomic-publish primitive.
    let renamed = root.join("b.bin");
    fs.rename(&file, &renamed).expect("rename");
    assert!(!fs.exists(&file), "source must be gone after rename");
    assert_eq!(fs.read(&renamed).unwrap(), b"xyz");

    fs.set_owner_only(&renamed).expect("set_owner_only");

    let listed = fs.read_dir(root).expect("read_dir");
    assert!(listed.contains(&renamed), "read_dir must list {renamed:?}");
    assert!(
        !listed.contains(&file),
        "read_dir must not list a renamed-away path"
    );

    fs.remove_file(&renamed).expect("remove");
    assert!(!fs.exists(&renamed));
    assert_eq!(
        fs.remove_file(&renamed).unwrap_err().kind(),
        io::ErrorKind::NotFound,
        "removing twice must report NotFound"
    );

    assert_eq!(
        fs.read_dir(&root.join("nope")).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_fs_satisfies_the_contract() {
        let dir = tempfile::tempdir().expect("tempdir");
        conformance(&NativeFs, dir.path());
    }

    #[test]
    fn mem_fs_satisfies_the_contract() {
        conformance(&MemFs::new(), Path::new("/vault"));
    }

    #[test]
    fn mem_fs_records_owner_only() {
        let fs = MemFs::new();
        let path = Path::new("/vault/secret");
        fs.create_dir_all(Path::new("/vault")).unwrap();
        fs.write(path, b"k").unwrap();

        assert!(!fs.is_owner_only(path));
        fs.set_owner_only(path).unwrap();
        assert!(fs.is_owner_only(path));
    }

    /// The write-tmp → chmod → rename sequence that publishes the identity
    /// secret only works if permissions follow the file across the rename.
    /// Asserted per backend because the trait exposes no permission getter.
    #[test]
    fn mem_fs_carries_owner_only_across_a_rename() {
        let fs = MemFs::new();
        let tmp = Path::new("/vault/secret.tmp");
        let final_path = Path::new("/vault/secret");

        fs.write(tmp, b"k").unwrap();
        fs.set_owner_only(tmp).unwrap();
        fs.rename(tmp, final_path).unwrap();

        assert!(fs.is_owner_only(final_path), "permission lost on rename");
        assert!(!fs.is_owner_only(tmp), "stale permission left on old path");
    }

    #[cfg(unix)]
    #[test]
    fn native_fs_carries_owner_only_across_a_rename() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = dir.path().join("secret.tmp");
        let final_path = dir.path().join("secret");

        NativeFs.write(&tmp, b"k").unwrap();
        NativeFs.set_owner_only(&tmp).unwrap();
        NativeFs.rename(&tmp, &final_path).unwrap();

        let mode = std::fs::metadata(&final_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permission lost on rename");
    }

    #[cfg(unix)]
    #[test]
    fn native_set_owner_only_actually_chmods() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        NativeFs.write(&path, b"k").unwrap();
        NativeFs.set_owner_only(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
