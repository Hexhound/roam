use roam_crdt::TextSpan;
use roam_storage::{Identity, Role, Store, VersionKind};
use tempfile::tempdir;

fn open(dir: &std::path::Path) -> Store {
    let identity = Identity::generate();
    let mut store = Store::open(dir, identity).unwrap();
    store.declare_founder(Role::Admin).unwrap(); // self write access
    store
}

#[test]
fn history_lists_created_then_edited_with_author_and_diff() {
    let dir = tempdir().unwrap();
    let mut store = open(dir.path());
    let me = store.self_peer_id();

    // Stamp the two edits >10s apart via the test seam so the change-merge
    // window does not coalesce them into a single change.
    store.edit_text_at("doc", 0, "hello", 1000).unwrap();
    store.edit_text_at("doc", 5, " world", 2000).unwrap();

    let versions = store.text_history("doc").unwrap(); // newest-first
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].kind, VersionKind::Edited);
    assert_eq!(versions[1].kind, VersionKind::Created);
    assert_eq!(versions[1].author_key, Some(store.self_key()));
    assert_eq!(versions[0].author_peer, me);
    assert!(versions[0]
        .diff
        .spans
        .iter()
        .any(|s| matches!(s, TextSpan::Insert(t) if t == " world")));
}

#[test]
fn revert_text_restores_earlier_content() {
    let dir = tempdir().unwrap();
    let mut store = open(dir.path());
    store.edit_text_at("doc", 0, "keep me", 1000).unwrap();
    let versions = store.text_history("doc").unwrap();
    let created = versions.last().unwrap().frontier.clone();

    store.edit_text_at("doc", 7, " ...garbage", 2000).unwrap();
    assert_eq!(store.text("doc"), "keep me ...garbage");

    store.revert_text("doc", &created).unwrap();
    assert_eq!(store.text("doc"), "keep me");
}
