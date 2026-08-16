//! A [`VaultFs`] built on a fixed pool of pre-opened, byte-addressable slots.
//!
//! This exists because of one mismatch: `VaultFs` is synchronous (M2 decided
//! that deliberately — see `docs/browser_storage_opfs.md`), while OPFS is
//! synchronous *only* on an already-open sync access handle. Navigating to a
//! file — `getFileHandle`, `createSyncAccessHandle`, `removeEntry` — is
//! asynchronous, and a synchronous trait method has nowhere to await.
//!
//! The fix is the shape `sqlite3.wasm`'s `opfs-sahpool` VFS uses: open a fixed
//! number of opaque backing files once, asynchronously, at mount; keep a handle
//! on each for the lifetime of the worker; and map vault paths onto slots. Every
//! `VaultFs` call afterwards is a synchronous operation on a handle that is
//! already open.
//!
//! Everything in this module is **plain Rust over a [`Slot`] trait**, so the
//! whole thing — allocation, the name map, rename, `read_dir`, the durable
//! header — is exercised by ordinary native tests. The browser backend supplies
//! `Slot` and nothing else, which keeps the part that can only be tested in a
//! real browser down to a handful of one-line delegations.
//!
//! # Why the name map is stored in the files
//!
//! A pool that kept the path→slot association only in memory would lose the
//! whole vault on tab close, which is the exact problem this module exists to
//! solve. So each slot carries a header naming the path it holds, and mounting
//! rebuilds the map by reading them. A slot with an empty name is free.

use crate::vfs::VaultFs;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One pre-opened, randomly-addressable backing file.
///
/// Deliberately smaller than `VaultFs`: no paths, no directories, no creation,
/// no deletion. Those are exactly the operations OPFS makes asynchronous, and
/// keeping them out of this trait is what lets [`SlotPool`] be synchronous.
pub trait Slot: Send + Sync {
    fn size(&self) -> io::Result<u64>;

    /// Set the length, zero-filling any growth.
    fn truncate(&self, len: u64) -> io::Result<()>;

    /// Read into `buf` starting at `at`, returning how many bytes were read.
    /// Fewer than `buf.len()` only at EOF.
    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Write at `at`, extending the file if the write runs past the end.
    fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()>;

    /// Durably commit everything written so far.
    fn flush(&self) -> io::Result<()>;
}

/// So a caller can keep its own handle on the backing store while the pool owns
/// one. That is what makes a remount testable: hold `Arc<S>` clones, drop the
/// pool, and mount a fresh one over the same bytes — which is exactly what a new
/// browser tab does to the same OPFS files.
impl<S: Slot + ?Sized> Slot for std::sync::Arc<S> {
    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }
    fn truncate(&self, len: u64) -> io::Result<()> {
        (**self).truncate(len)
    }
    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(at, buf)
    }
    fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()> {
        (**self).write_at(at, buf)
    }
    fn flush(&self) -> io::Result<()> {
        (**self).flush()
    }
}

/// Bytes reserved at the head of every slot for its header. Vault data starts
/// here, so a slot's logical length is always `size() - HEADER_LEN`.
///
/// 1 KiB is far more than the header needs; it is round, it leaves room for a
/// field to be added without a format break, and at pool sizes measured in
/// hundreds the total overhead is a rounding error next to one blob.
const HEADER_LEN: u64 = 1024;

const MAGIC: &[u8; 8] = b"ROAMSAH1";
const FLAG_OWNER_ONLY: u8 = 0b0000_0001;

/// Longest vault path a slot can name. Bounded by the header, and checked on
/// every write rather than truncated — a silently shortened path would map two
/// different files onto one name.
const MAX_NAME: usize = (HEADER_LEN as usize) - 11;

/// What a slot's header says about it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Header {
    /// Empty means the slot is free.
    name: String,
    owner_only: bool,
}

impl Header {
    fn encode(&self) -> Vec<u8> {
        let name = self.name.as_bytes();
        let mut out = vec![0u8; HEADER_LEN as usize];
        out[0..8].copy_from_slice(MAGIC);
        out[8] = if self.owner_only { FLAG_OWNER_ONLY } else { 0 };
        out[9..11].copy_from_slice(&(name.len() as u16).to_le_bytes());
        out[11..11 + name.len()].copy_from_slice(name);
        out
    }

    /// `None` for a slot that has never been initialised (a freshly created
    /// backing file is all zeroes, so it has no magic).
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 11 || &bytes[0..8] != MAGIC {
            return None;
        }
        let len = u16::from_le_bytes([bytes[9], bytes[10]]) as usize;
        let name = std::str::from_utf8(bytes.get(11..11 + len)?)
            .ok()?
            .to_string();
        Some(Self {
            name,
            owner_only: bytes[8] & FLAG_OWNER_ONLY != 0,
        })
    }
}

/// A `VaultFs` over a fixed pool of [`Slot`]s.
pub struct SlotPool<S> {
    inner: Mutex<State<S>>,
}

struct State<S> {
    slots: Vec<S>,
    /// Vault path → slot index. The durable copy lives in the slot headers;
    /// this is the index rebuilt from them at mount.
    names: BTreeMap<PathBuf, usize>,
    /// Directories created explicitly this session. Not persisted — see
    /// [`SlotPool::is_dir`], which also infers directories from the paths that
    /// exist, so a reopened vault does not depend on this.
    dirs: BTreeSet<PathBuf>,
    free: Vec<usize>,
}

impl<S: Slot> SlotPool<S> {
    /// Adopt a set of already-opened slots, rebuilding the path map from their
    /// headers.
    ///
    /// Opening the slots is the caller's job precisely because it is the
    /// asynchronous part; by the time a `SlotPool` exists, nothing it does needs
    /// to await.
    pub fn adopt(slots: Vec<S>) -> io::Result<Self> {
        let mut names = BTreeMap::new();
        let mut free = Vec::new();

        for (index, slot) in slots.iter().enumerate() {
            let mut header = vec![0u8; HEADER_LEN as usize];
            let read = slot.read_at(0, &mut header)?;
            match Header::decode(&header[..read]) {
                Some(h) if !h.name.is_empty() => {
                    if names.insert(PathBuf::from(&h.name), index).is_some() {
                        // Two slots claiming one path means the header write and
                        // the data write were interleaved by a crash. Refusing to
                        // mount is right: silently picking one would hand back a
                        // vault with a file's bytes half-replaced.
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("two pool slots both claim {:?}", h.name),
                        ));
                    }
                }
                _ => free.push(index),
            }
        }

        Ok(Self {
            inner: Mutex::new(State {
                slots,
                names,
                dirs: BTreeSet::new(),
                free,
            }),
        })
    }

    /// How many slots are unused. The worker's message loop watches this so it
    /// can grow the pool between commands — growth needs an `await` and so can
    /// never happen inside a `VaultFs` call.
    pub fn free_slots(&self) -> usize {
        self.inner.lock().unwrap().free.len()
    }

    pub fn capacity(&self) -> usize {
        self.inner.lock().unwrap().slots.len()
    }

    /// Add one more slot to the pool.
    ///
    /// Separate from [`SlotPool::adopt`] because opening a slot is the
    /// asynchronous part and this is not: the caller awaits, then hands the
    /// opened slot over. That is the whole reason growth lives outside the
    /// `VaultFs` surface — no trait method has an `await` to spend.
    ///
    /// A slot arriving with a non-empty header is adopted under that name, so
    /// growing a pool cannot silently orphan a file that was already there.
    pub fn add_slot(&self, slot: S) -> io::Result<()> {
        let header = read_header(&slot)?;
        let mut state = self.inner.lock().unwrap();
        let index = state.slots.len();
        state.slots.push(slot);

        if header.name.is_empty() {
            state.free.push(index);
        } else if state
            .names
            .insert(PathBuf::from(&header.name), index)
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "added slot claims {:?}, which is already mapped",
                    header.name
                ),
            ));
        }
        Ok(())
    }

    /// Whether `set_owner_only` was applied to `path`. Mirrors
    /// `MemFs::is_owner_only` so the identity-secret rename test can run against
    /// this backend too.
    pub fn is_owner_only(&self, path: &Path) -> bool {
        let state = self.inner.lock().unwrap();
        let Some(&index) = state.names.get(path) else {
            return false;
        };
        read_header(&state.slots[index]).is_ok_and(|h| h.owner_only)
    }
}

fn read_header<S: Slot>(slot: &S) -> io::Result<Header> {
    let mut bytes = vec![0u8; HEADER_LEN as usize];
    let read = slot.read_at(0, &mut bytes)?;
    Ok(Header::decode(&bytes[..read]).unwrap_or_default())
}

fn write_header<S: Slot>(slot: &S, header: &Header) -> io::Result<()> {
    if header.name.len() > MAX_NAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "vault path is {} bytes, over the {MAX_NAME}-byte pool limit: {}",
                header.name.len(),
                header.name
            ),
        ));
    }
    slot.write_at(0, &header.encode())
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no such file: {}", path.display()),
    )
}

fn exhausted() -> io::Error {
    io::Error::new(
        io::ErrorKind::StorageFull,
        "the storage slot pool is exhausted; grow it between commands",
    )
}

impl<S: Slot> State<S> {
    fn index_of(&self, path: &Path) -> io::Result<usize> {
        self.names.get(path).copied().ok_or_else(|| not_found(path))
    }

    /// Find `path`'s slot, claiming a free one if it does not exist yet.
    fn index_or_claim(&mut self, path: &Path) -> io::Result<usize> {
        if let Some(&index) = self.names.get(path) {
            return Ok(index);
        }
        let name = path
            .to_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("vault path is not UTF-8: {}", path.display()),
                )
            })?
            .to_string();

        let index = self.free.pop().ok_or_else(exhausted)?;
        let slot = &self.slots[index];

        // Header first, then length. A crash between the two leaves a slot that
        // claims the path but is empty, which reads as a zero-length file —
        // recoverable. The other order would leave data under no name at all.
        if let Err(e) = write_header(
            slot,
            &Header {
                name,
                owner_only: false,
            },
        ) {
            self.free.push(index);
            return Err(e);
        }
        slot.truncate(HEADER_LEN)?;
        self.names.insert(path.to_path_buf(), index);
        Ok(index)
    }

    /// Logical length: the backing file minus its header.
    fn len_of(&self, index: usize) -> io::Result<u64> {
        Ok(self.slots[index].size()?.saturating_sub(HEADER_LEN))
    }
}

impl<S: Slot> VaultFs for SlotPool<S> {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let state = self.inner.lock().unwrap();
        let index = state.index_of(path)?;
        let len = state.len_of(index)? as usize;
        let mut buf = vec![0u8; len];
        let read = state.slots[index].read_at(HEADER_LEN, &mut buf)?;
        buf.truncate(read);
        Ok(buf)
    }

    fn read_range(&self, path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let state = self.inner.lock().unwrap();
        let index = state.index_of(path)?;
        let size = state.len_of(index)?;
        // Clamp rather than error: the contract is "fewer only at EOF", and a
        // blob chunk request at the tail routinely overruns.
        let start = offset.min(size);
        let want = (len as u64).min(size - start) as usize;
        let mut buf = vec![0u8; want];
        let read = state.slots[index].read_at(HEADER_LEN + start, &mut buf)?;
        buf.truncate(read);
        Ok(buf)
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap();
        let index = state.index_or_claim(path)?;
        let slot = &state.slots[index];
        // Truncate first: `write` replaces, so a shorter payload must not leave
        // the previous file's tail behind.
        slot.truncate(HEADER_LEN)?;
        slot.write_at(HEADER_LEN, bytes)
    }

    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap();
        let index = state.index_or_claim(path)?;
        let end = state.slots[index].size()?.max(HEADER_LEN);
        state.slots[index].write_at(end, bytes)
    }

    fn append_sync(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.append(path, bytes)?;
        let state = self.inner.lock().unwrap();
        let index = state.index_of(path)?;
        // The whole reason `append_sync` is a separate method: the op-log is the
        // source of truth, so an acknowledged append has to survive a crash.
        state.slots[index].flush()
    }

    fn create_sized(&self, path: &Path, len: u64) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap();
        let index = state.index_or_claim(path)?;
        let slot = &state.slots[index];
        // Down to zero first so an existing longer file does not leave stale
        // bytes visible through the pre-sized region.
        slot.truncate(HEADER_LEN)?;
        slot.truncate(HEADER_LEN + len)
    }

    fn write_range(&self, path: &Path, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let state = self.inner.lock().unwrap();
        let index = state.index_of(path)?;
        state.slots[index].write_at(HEADER_LEN + offset, bytes)
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
        let index = state.index_of(from)?;
        let name = to
            .to_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("vault path is not UTF-8: {}", to.display()),
                )
            })?
            .to_string();

        // If the destination already exists its slot is orphaned by this rename,
        // so return it to the pool rather than leaking it.
        if let Some(displaced) = state.names.remove(to) {
            write_header(&state.slots[displaced], &Header::default())?;
            state.slots[displaced].truncate(HEADER_LEN)?;
            state.free.push(displaced);
        }

        // Only the name in the header changes. The bytes never move, and the
        // owner-only flag rides along in the same header — so the bug MemFs had
        // (permissions dropped on rename, which is how the identity secret gets
        // published world-readable) cannot happen here by construction.
        let mut header = read_header(&state.slots[index])?;
        header.name = name;
        write_header(&state.slots[index], &header)?;

        state.names.remove(from);
        state.names.insert(to.to_path_buf(), index);
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap();
        let index = state.index_of(path)?;
        // The backing file is recycled, never deleted: `removeEntry` is async in
        // OPFS, and this method is not. Clearing the name is what makes the slot
        // free, and truncating is what stops the next tenant reading the last
        // one's bytes.
        write_header(&state.slots[index], &Header::default())?;
        state.slots[index].truncate(HEADER_LEN)?;
        state.names.remove(path);
        state.free.push(index);
        Ok(())
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let state = self.inner.lock().unwrap();
        let mut out = BTreeSet::new();
        let mut found = state.dirs.contains(path);

        for existing in state.names.keys().chain(state.dirs.iter()) {
            let Ok(rest) = existing.strip_prefix(path) else {
                continue;
            };
            let Some(first) = rest.components().next() else {
                continue;
            };
            found = true;
            let child = path.join(first);
            if &child != path {
                out.insert(child);
            }
        }

        if !found {
            return Err(not_found(path));
        }
        Ok(out.into_iter().collect())
    }

    fn file_len(&self, path: &Path) -> io::Result<u64> {
        let state = self.inner.lock().unwrap();
        let index = state.index_of(path)?;
        state.len_of(index)
    }

    fn exists(&self, path: &Path) -> bool {
        let state = self.inner.lock().unwrap();
        state.names.contains_key(path) || state.dirs.contains(path)
    }

    fn is_dir(&self, path: &Path) -> bool {
        let state = self.inner.lock().unwrap();
        // Inferred from the paths under it as well as from an explicit
        // `create_dir_all`, because directories are not persisted: after a
        // reopen the only evidence `ops/` is a directory is that `ops/12.log`
        // exists.
        state.dirs.contains(path)
            || state.names.keys().any(|existing| {
                existing
                    .strip_prefix(path)
                    .is_ok_and(|r| r != Path::new(""))
            })
    }

    fn set_owner_only(&self, path: &Path) -> io::Result<()> {
        let state = self.inner.lock().unwrap();
        let index = state.index_of(path)?;
        let mut header = read_header(&state.slots[index])?;
        header.owner_only = true;
        write_header(&state.slots[index], &header)
        // A browser origin is already the isolation boundary, so this flag
        // grants nothing on its own. It is recorded anyway so the native and
        // browser backends agree about what a caller asked for, and so the
        // rename test means the same thing on both.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slot backed by a `Vec`. Stands in for a sync access handle so every
    /// rule in this module is testable without a browser.
    #[derive(Default)]
    struct VecSlot {
        bytes: Mutex<Vec<u8>>,
        flushes: Mutex<usize>,
    }

    impl Slot for VecSlot {
        fn size(&self) -> io::Result<u64> {
            Ok(self.bytes.lock().unwrap().len() as u64)
        }

        fn truncate(&self, len: u64) -> io::Result<()> {
            self.bytes.lock().unwrap().resize(len as usize, 0);
            Ok(())
        }

        fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
            let bytes = self.bytes.lock().unwrap();
            let start = (at as usize).min(bytes.len());
            let n = buf.len().min(bytes.len() - start);
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            Ok(n)
        }

        fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()> {
            let mut bytes = self.bytes.lock().unwrap();
            let start = at as usize;
            if start + buf.len() > bytes.len() {
                bytes.resize(start + buf.len(), 0);
            }
            bytes[start..start + buf.len()].copy_from_slice(buf);
            Ok(())
        }

        fn flush(&self) -> io::Result<()> {
            *self.flushes.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn pool(n: usize) -> SlotPool<VecSlot> {
        SlotPool::adopt((0..n).map(|_| VecSlot::default()).collect()).expect("adopt")
    }

    #[test]
    fn slot_pool_satisfies_the_contract() {
        crate::vfs::conformance(&pool(32), Path::new("/vault"));
    }

    #[test]
    fn a_freed_slot_is_reused_rather_than_leaked() {
        let fs = pool(2);
        fs.write(Path::new("/v/a"), b"one").unwrap();
        fs.write(Path::new("/v/b"), b"two").unwrap();
        assert_eq!(fs.free_slots(), 0);

        fs.remove_file(Path::new("/v/a")).unwrap();
        assert_eq!(fs.free_slots(), 1);

        // Without recycling this is where a browser vault would wedge after a
        // few hundred blob writes.
        fs.write(Path::new("/v/c"), b"three").unwrap();
        assert_eq!(fs.read(Path::new("/v/c")).unwrap(), b"three");
        assert_eq!(fs.read(Path::new("/v/b")).unwrap(), b"two");
    }

    #[test]
    fn a_recycled_slot_does_not_leak_the_previous_tenants_bytes() {
        let fs = pool(1);
        fs.write(Path::new("/v/secret"), b"the whole vault key")
            .unwrap();
        fs.remove_file(Path::new("/v/secret")).unwrap();

        fs.write(Path::new("/v/public"), b"hi").unwrap();
        assert_eq!(
            fs.read(Path::new("/v/public")).unwrap(),
            b"hi",
            "a shorter new tenant must not see the old file's tail"
        );
    }

    #[test]
    fn growing_the_pool_relieves_exhaustion() {
        let fs = pool(1);
        fs.write(Path::new("/v/a"), b"one").unwrap();
        assert_eq!(fs.free_slots(), 0);

        // What the worker does between commands, once awaiting is possible again.
        fs.add_slot(VecSlot::default()).unwrap();

        assert_eq!(fs.capacity(), 2);
        fs.write(Path::new("/v/b"), b"two").unwrap();
        assert_eq!(fs.read(Path::new("/v/a")).unwrap(), b"one");
        assert_eq!(fs.read(Path::new("/v/b")).unwrap(), b"two");
    }

    #[test]
    fn exhausting_the_pool_is_a_distinct_error() {
        let fs = pool(1);
        fs.write(Path::new("/v/a"), b"one").unwrap();
        let err = fs.write(Path::new("/v/b"), b"two").unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::StorageFull,
            "exhaustion must be distinguishable from a real IO failure, since \
             the worker recovers from it by growing the pool"
        );
    }

    #[test]
    fn append_sync_actually_flushes() {
        let fs = pool(1);
        fs.append(Path::new("/v/log"), b"a").unwrap();
        let before = *fs.inner.lock().unwrap().slots[0].flushes.lock().unwrap();

        fs.append_sync(Path::new("/v/log"), b"b").unwrap();
        let after = *fs.inner.lock().unwrap().slots[0].flushes.lock().unwrap();

        assert_eq!(
            after,
            before + 1,
            "append_sync exists to make a durability promise; a pool that \
             quietly forwards it to append breaks op-log-is-truth and no other \
             test can see it"
        );
    }

    #[test]
    fn owner_only_follows_a_file_across_a_rename() {
        let fs = pool(4);
        let tmp = Path::new("/vault/secret.tmp");
        let published = Path::new("/vault/secret");

        fs.write(tmp, b"k").unwrap();
        fs.set_owner_only(tmp).unwrap();
        fs.rename(tmp, published).unwrap();

        assert!(fs.is_owner_only(published), "permission lost on rename");
        assert!(!fs.is_owner_only(tmp), "stale permission left on old path");
    }

    #[test]
    fn renaming_onto_an_existing_file_returns_its_slot() {
        let fs = pool(2);
        fs.write(Path::new("/v/new"), b"fresh").unwrap();
        fs.write(Path::new("/v/live"), b"stale").unwrap();
        assert_eq!(fs.free_slots(), 0);

        fs.rename(Path::new("/v/new"), Path::new("/v/live"))
            .unwrap();

        assert_eq!(fs.read(Path::new("/v/live")).unwrap(), b"fresh");
        assert_eq!(
            fs.free_slots(),
            1,
            "the displaced file's slot must go back to the pool; leaking one \
             per atomic publish would exhaust the pool over a vault's lifetime"
        );
    }

    /// The whole reason the name map lives in the slot headers. Without this a
    /// browser vault is lost on tab close, which is the bug this module exists
    /// to fix.
    #[test]
    fn a_remounted_pool_recovers_every_file() {
        let slots: Vec<VecSlot> = (0..8).map(|_| VecSlot::default()).collect();
        let fs = SlotPool::adopt(slots).unwrap();

        fs.write(Path::new("/vault/ops/7.log"), b"opdata").unwrap();
        fs.write(Path::new("/vault/founder"), b"pin").unwrap();
        fs.set_owner_only(Path::new("/vault/founder")).unwrap();
        fs.write(Path::new("/vault/scratch"), b"gone").unwrap();
        fs.remove_file(Path::new("/vault/scratch")).unwrap();

        // Take the backing store back out and mount it afresh, exactly as a new
        // tab would after reopening the same OPFS files.
        let slots = fs.inner.into_inner().unwrap().slots;
        let reopened = SlotPool::adopt(slots).unwrap();

        assert_eq!(
            reopened.read(Path::new("/vault/ops/7.log")).unwrap(),
            b"opdata"
        );
        assert_eq!(reopened.read(Path::new("/vault/founder")).unwrap(), b"pin");
        assert!(reopened.is_owner_only(Path::new("/vault/founder")));
        assert!(!reopened.exists(Path::new("/vault/scratch")));
        assert_eq!(reopened.free_slots(), 6);

        // Directories are not persisted, so they have to be inferred from the
        // paths under them — otherwise the store cannot walk `ops/` after a
        // reopen until something happens to recreate it.
        assert!(reopened.is_dir(Path::new("/vault/ops")));
        assert_eq!(
            reopened.read_dir(Path::new("/vault/ops")).unwrap(),
            vec![PathBuf::from("/vault/ops/7.log")]
        );
    }

    #[test]
    fn a_path_too_long_for_the_header_is_refused_not_truncated() {
        let fs = pool(2);
        let long = PathBuf::from(format!("/vault/{}", "x".repeat(MAX_NAME)));

        let err = fs.write(&long, b"data").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            fs.free_slots(),
            2,
            "a refused write must not consume a slot"
        );
    }

    #[test]
    fn two_slots_claiming_one_path_refuses_to_mount() {
        let slots: Vec<VecSlot> = (0..2).map(|_| VecSlot::default()).collect();
        for slot in &slots {
            write_header(
                slot,
                &Header {
                    name: "/vault/ops/1.log".into(),
                    owner_only: false,
                },
            )
            .unwrap();
        }

        let err = match SlotPool::adopt(slots) {
            Err(e) => e,
            Ok(_) => panic!("mounting a pool with a duplicate claim must fail"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn header_roundtrips_and_rejects_an_uninitialised_slot() {
        let header = Header {
            name: "/vault/roster/roster.log".into(),
            owner_only: true,
        };
        assert_eq!(Header::decode(&header.encode()).unwrap(), header);

        // A freshly created backing file is all zeroes and must read as free,
        // not as a file named "".
        assert!(Header::decode(&vec![0u8; HEADER_LEN as usize]).is_none());
    }
}
