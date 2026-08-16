//! Reopening a vault whose storage outlived the process.
//!
//! `vault_sync.rs` runs on `MemFs`, and every `MemFs` open is a first open, so
//! it cannot see the two things `Vault::open` has to get right once storage is
//! durable: keeping the same identity, and not re-founding a vault that already
//! has a founder. Both were wrong before this file existed, and neither is
//! subtle in effect — a fresh identity per reload makes a device a stranger to
//! its own op log, and the second `declare_founder` fails outright, so the
//! second visit to the site could not open the vault at all.
//!
//! The storage here is a `SlotPool` over `Vec`-backed slots, which is the shape
//! OPFS forces (see `docs/browser_storage_opfs.md`). Between the two opens the
//! pool is thrown away and rebuilt from the slot bytes alone — exactly what a
//! reloaded tab does — so nothing is carried across in memory.

use roam_storage::vfs::VaultFs;
use roam_storage::vfs_pool::{Slot, SlotPool};
use roam_wasm::Vault;
use std::io;
use std::sync::{Arc, Mutex};

const VAULT_KEY: [u8; 32] = [7u8; 32];
const TEXT_ID: &str = "notes/hello.md";
const CAPACITY: usize = 64;

/// Stands in for an OPFS sync access handle: the same five operations, over a
/// `Vec` that survives the pool that was using it.
#[derive(Default)]
struct VecSlot {
    bytes: Mutex<Vec<u8>>,
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
        Ok(())
    }
}

/// The persistent bytes. Held by the test, not by any pool, so remounting is a
/// matter of handing the same slots to a new `SlotPool`.
type Disk = Vec<Arc<VecSlot>>;

fn format() -> Disk {
    (0..CAPACITY)
        .map(|_| Arc::new(VecSlot::default()))
        .collect()
}

fn mount(disk: &Disk) -> Arc<dyn VaultFs> {
    Arc::new(SlotPool::adopt(disk.clone()).expect("adopt the slots"))
}

/// The claim the whole browser client rests on: close the tab, come back, and
/// it is the same vault seen by the same device.
#[tokio::test]
async fn reopening_finds_the_same_vault_and_the_same_device() {
    let disk = format();

    let (peer_id, verifying_key) = {
        let vault = Vault::open(mount(&disk), VAULT_KEY).expect("first open");
        vault
            .edit_text(TEXT_ID, 0, "written before the tab closed")
            .await
            .unwrap();
        vault.set_entry("meta", "title", "Hello").await.unwrap();
        (vault.peer_id().await, vault.verifying_key().await)
    };

    let reopened = Vault::open(mount(&disk), VAULT_KEY).expect(
        "reopening a founded vault must not fail — declaring a founder twice \
         returns `vault founder already pinned`",
    );

    assert_eq!(
        reopened.peer_id().await,
        peer_id,
        "a new identity per reload makes the device a stranger to its own op log"
    );
    assert_eq!(
        reopened.verifying_key().await,
        verifying_key,
        "same peer id but a different key is worse than a new device: every \
         signature it already wrote stops verifying"
    );
    assert_eq!(
        reopened.text(TEXT_ID).await,
        "written before the tab closed"
    );
    assert_eq!(
        reopened.get_entry("meta", "title").await.as_deref(),
        Some("Hello")
    );
}

/// A reopened vault must still be able to *write*, and its edits must land on
/// top of what was already there rather than beside it.
///
/// Mutation-checked: making `declare_founder` unconditional fails this, because
/// the second open cannot get far enough to write at all. Regenerating the
/// identity does *not* fail it — local writes turn out not to be gated on this
/// device's own vouch, so a device that lost its identity would keep writing,
/// under a new peer id, and only the op log would notice. That is what
/// `reopening_finds_the_same_vault_and_the_same_device` is for.
#[tokio::test]
async fn a_reopened_vault_can_still_write() {
    let disk = format();
    {
        let vault = Vault::open(mount(&disk), VAULT_KEY).unwrap();
        vault.edit_text(TEXT_ID, 0, "first visit").await.unwrap();
    }

    let reopened = Vault::open(mount(&disk), VAULT_KEY).unwrap();
    reopened
        .edit_text(TEXT_ID, "first visit".len(), " and second")
        .await
        .expect("a reopened vault is not read-only");
    reopened.write_snapshot().await.expect("snapshot");

    let again = Vault::open(mount(&disk), VAULT_KEY).unwrap();
    assert_eq!(again.text(TEXT_ID).await, "first visit and second");
}

/// The identity secret is written through the same `VaultFs` as everything
/// else, which on OPFS keeps it inside the origin's private filesystem. Assert
/// it is actually there: if it were not, the previous tests would still pass by
/// regenerating a key, and only the op log would notice.
#[tokio::test]
async fn the_identity_is_persisted_in_the_vault_storage() {
    let disk = format();
    Vault::open(mount(&disk), VAULT_KEY).unwrap();

    let fs = mount(&disk);
    let identity = fs
        .read(std::path::Path::new("/vault/identity.key"))
        .expect("identity was not persisted into the vault storage");
    assert!(!identity.is_empty());
}
