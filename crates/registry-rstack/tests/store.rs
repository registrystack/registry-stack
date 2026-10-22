// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use registry_rstack::{GenerationStore, PreserveReason, PublicLinkStatus};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn new_store(root: &Path) -> GenerationStore {
    GenerationStore::new(root.join("lib/registrystack"), root.join("bin"))
}

fn write_generation(stage: &Path, marker: &str) {
    let launcher = stage.join("rstack");
    fs::write(&launcher, format!("#!/bin/sh\nprintf '%s' '{marker}'\n")).unwrap();
    let mut permissions = fs::metadata(&launcher).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&launcher, permissions).unwrap();
    fs::write(
        stage.join("manifest.json"),
        format!(r#"{{"release":"{marker}"}}"#),
    )
    .unwrap();
    fs::create_dir(stage.join("components")).unwrap();
    fs::write(stage.join("components/tool"), marker).unwrap();
}

fn publish(
    mutation: &registry_rstack::MutationGuard<'_>,
    name: &str,
    marker: &str,
) -> registry_rstack::Generation {
    let stage = mutation.stage_generation(name).unwrap();
    write_generation(stage.path(), marker);
    stage.publish_preverified().unwrap()
}

#[test]
fn read_only_selection_does_not_create_an_absent_installation() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());
    let install_root = store.install_root().to_owned();

    assert!(!store.has_installation().unwrap());
    let error = store.acquire_current().unwrap_err();
    assert!(error.contains("no Registry Stack installation"));
    assert!(!install_root.exists());
}

#[test]
fn publishes_complete_generation_and_atomically_selects_it() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());

    let mutation = store.lock_mutation().unwrap();
    assert!(mutation.current().unwrap().is_none());
    let generation = publish(&mutation, "v1.2.3-0001", "old");
    assert!(store.current_link().symlink_metadata().is_err());
    mutation.activate(&generation).unwrap();
    assert_eq!(
        mutation.current().unwrap().unwrap().name(),
        generation.name()
    );
    drop(mutation);

    assert!(store.has_installation().unwrap());
    let lease = store.acquire_current().unwrap();
    assert_eq!(lease.generation().name(), "v1.2.3-0001");
    assert_eq!(lease.path(), generation.path());
    assert_eq!(
        fs::read_to_string(lease.path().join("components/tool")).unwrap(),
        "old"
    );
    assert!(lease.lease_fd() >= 0);
}

#[test]
fn incomplete_stage_never_changes_current_selection() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());
    let mutation = store.lock_mutation().unwrap();
    let old = publish(&mutation, "v1.2.3-0001", "old");
    mutation.activate(&old).unwrap();

    let incomplete_path = {
        let stage = mutation.stage_generation("v1.2.3-0002").unwrap();
        fs::write(stage.path().join("manifest.json"), "{}").unwrap();
        let path = stage.path().to_owned();
        let error = stage.publish_preverified().unwrap_err();
        assert!(error.contains("rstack"), "unexpected error: {error}");
        path
    };
    assert!(
        !incomplete_path.exists(),
        "failed staging directory remained"
    );
    drop(mutation);

    assert_eq!(
        store.acquire_current().unwrap().generation().name(),
        old.name()
    );
}

#[test]
fn serializes_mutations_across_store_instances() {
    let temporary = tempfile::tempdir().unwrap();
    let install_root = temporary.path().join("lib/registrystack");
    let bin_dir = temporary.path().join("bin");
    let first = GenerationStore::new(&install_root, &bin_dir);
    let guard = first.lock_mutation().unwrap();

    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let second = GenerationStore::new(install_root, bin_dir);
        let _guard = second.lock_mutation().unwrap();
        sender.send(()).unwrap();
    });
    assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
    drop(guard);
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.join().unwrap();
}

#[test]
fn public_link_is_idempotent_but_never_replaces_an_unrelated_entry() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());
    let mutation = store.lock_mutation().unwrap();
    assert_eq!(
        mutation.ensure_public_link().unwrap(),
        PublicLinkStatus::Created
    );
    assert_eq!(
        mutation.ensure_public_link().unwrap(),
        PublicLinkStatus::AlreadyOwned
    );
    let public_link = temporary.path().join("bin/rstack");
    assert_eq!(
        fs::read_link(&public_link).unwrap(),
        store.current_link().join("rstack")
    );
    drop(mutation);

    let unrelated_root = tempfile::tempdir().unwrap();
    let unrelated_store = new_store(unrelated_root.path());
    fs::create_dir_all(unrelated_root.path().join("bin")).unwrap();
    fs::write(unrelated_root.path().join("bin/rstack"), "mine").unwrap();
    let mutation = unrelated_store.lock_mutation().unwrap();
    let error = mutation.ensure_public_link().unwrap_err();
    assert!(error.contains("unrelated"), "unexpected error: {error}");
    assert_eq!(
        fs::read(unrelated_root.path().join("bin/rstack")).unwrap(),
        b"mine"
    );

    let symlink_root = tempfile::tempdir().unwrap();
    let symlink_store = new_store(symlink_root.path());
    fs::create_dir_all(symlink_root.path().join("bin")).unwrap();
    symlink("somewhere-else", symlink_root.path().join("bin/rstack")).unwrap();
    let mutation = symlink_store.lock_mutation().unwrap();
    assert!(mutation
        .ensure_public_link()
        .unwrap_err()
        .contains("unrelated"));
    assert_eq!(
        fs::read_link(symlink_root.path().join("bin/rstack")).unwrap(),
        Path::new("somewhere-else")
    );
}

#[test]
fn activation_refuses_an_unrelated_current_entry() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());
    let mutation = store.lock_mutation().unwrap();
    let generation = publish(&mutation, "v1.2.3-0001", "new");
    fs::write(store.current_link(), "mine").unwrap();

    let error = mutation.activate(&generation).unwrap_err();
    assert!(error.contains("unrelated"), "unexpected error: {error}");
    assert_eq!(fs::read(store.current_link()).unwrap(), b"mine");
}

#[test]
fn current_and_invocation_refuse_modified_active_generation() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());
    let mutation = store.lock_mutation().unwrap();
    let modified = publish(&mutation, "v1.2.3-0001", "old");
    mutation.activate(&modified).unwrap();
    fs::write(modified.path().join("components/tool"), "changed").unwrap();

    let error = mutation.current().unwrap_err();
    assert!(error.contains("changed"), "unexpected error: {error}");
    drop(mutation);
    let error = store.acquire_current().unwrap_err();
    assert!(error.contains("changed"), "unexpected error: {error}");

    let mutation = store.lock_mutation().unwrap();
    let replacement = publish(&mutation, "v1.2.3-0002", "new");
    mutation.activate(&replacement).unwrap();
    assert_eq!(
        mutation.current().unwrap().unwrap().name(),
        replacement.name()
    );
    assert_eq!(
        fs::read(modified.path().join("components/tool")).unwrap(),
        b"changed"
    );
}

#[test]
fn cleanup_waits_for_the_final_generation_lease() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());
    let mutation = store.lock_mutation().unwrap();
    let old = publish(&mutation, "v1.2.3-0001", "old");
    mutation.activate(&old).unwrap();
    drop(mutation);

    let old_lease = store.acquire_current().unwrap();
    let mutation = store.lock_mutation().unwrap();
    let new = publish(&mutation, "v1.2.3-0002", "new");
    mutation.activate(&new).unwrap();
    let report = mutation.cleanup().unwrap();
    assert!(report.removed.is_empty());
    assert_eq!(report.reason_for(old.name()), Some(PreserveReason::InUse));
    assert_eq!(report.reason_for(new.name()), Some(PreserveReason::Active));
    assert!(old.path().exists());
    drop(mutation);

    drop(old_lease);
    let mutation = store.lock_mutation().unwrap();
    let report = mutation.cleanup().unwrap();
    assert_eq!(report.removed, vec![old.name().to_owned()]);
    assert!(!old.path().exists());
    assert!(new.path().exists());
}

#[test]
fn stale_pid_text_cannot_keep_an_unlocked_generation_alive() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());
    let mutation = store.lock_mutation().unwrap();
    let old = publish(&mutation, "v1.2.3-0001", "old");
    let new = publish(&mutation, "v1.2.3-0002", "new");
    mutation.activate(&new).unwrap();
    let mut lease_record = OpenOptions::new()
        .write(true)
        .open(old.path().join(".rstack-lease"))
        .unwrap();
    lease_record.write_all(b"999999\n").unwrap();
    drop(lease_record);

    let report = mutation.cleanup().unwrap();
    assert_eq!(report.removed, vec![old.name().to_owned()]);
}

#[test]
fn cleanup_preserves_modified_and_unowned_generations() {
    let temporary = tempfile::tempdir().unwrap();
    let store = new_store(temporary.path());
    let mutation = store.lock_mutation().unwrap();
    let modified = publish(&mutation, "v1.2.3-0001", "old");
    let active = publish(&mutation, "v1.2.3-0002", "new");
    mutation.activate(&active).unwrap();
    fs::write(modified.path().join("components/tool"), "changed").unwrap();
    fs::write(modified.path().join("personal-notes.txt"), "keep this").unwrap();
    let unrelated = store.generations_dir().join("someone-elses-files");
    fs::create_dir(&unrelated).unwrap();
    fs::write(unrelated.join("keep"), "keep").unwrap();

    let report = mutation.cleanup().unwrap();
    assert!(report.removed.is_empty());
    assert_eq!(
        report.reason_for(modified.name()),
        Some(PreserveReason::Modified)
    );
    assert_eq!(
        report.reason_for("someone-elses-files"),
        Some(PreserveReason::Unowned)
    );
    assert_eq!(
        fs::read(modified.path().join("components/tool")).unwrap(),
        b"changed"
    );
    assert_eq!(
        fs::read(modified.path().join("personal-notes.txt")).unwrap(),
        b"keep this"
    );
    assert_eq!(fs::read(unrelated.join("keep")).unwrap(), b"keep");
}
