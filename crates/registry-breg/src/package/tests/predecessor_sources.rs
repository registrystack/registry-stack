// SPDX-License-Identifier: Apache-2.0

//! Predecessor packages whose stored sources this release cannot read.

#![cfg(feature = "tooling")]

use super::*;
use std::fs;
use std::path::Path;

/// An exact historical package built before access profiles were keyed by id,
/// so its stored sources list them.
fn list_form_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pre-record-timer-store-package/package")
}

/// A copy of the list-form package that declares this release's engine
/// features, as a package built by the release before this one does: only its
/// stored sources predate the id-keyed maps.
fn list_form_package_with_current_features(parent: &Path) -> PathBuf {
    fn copy(from: &Path, to: &Path) {
        fs::create_dir_all(to).expect("copy directory creates");
        for entry in fs::read_dir(from).expect("fixture directory reads") {
            let entry = entry.expect("fixture entry reads");
            let target = to.join(entry.file_name());
            if entry.file_type().expect("entry type reads").is_dir() {
                copy(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("fixture file copies");
            }
        }
    }
    let root = parent.join("package");
    copy(&list_form_package(), &root);
    let manifest_path = root.join(MANIFEST_PATH);
    let mut envelope: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
            .expect("manifest parses");
    envelope["manifest"]["engineFeatures"] = serde_json::json!([
        "statistical_release_store",
        "caller_scoped_idempotency",
        "record_timer_store"
    ]);
    fs::write(
        &manifest_path,
        canonicalize_json(&envelope).expect("manifest canonicalizes"),
    )
    .expect("manifest writes");
    fs::remove_file(root.join(SUM_FILE)).expect("sum file removes");
    write_sum_file(&root, None, &shared_package_limits(), "test package")
        .expect("the rewritten package closes");
    root
}

#[test]
fn predecessor_with_list_form_sources_is_refused_even_as_a_plain_predecessor() {
    let parent = tempfile::tempdir().expect("temporary directory creates");
    let root = list_form_package_with_current_features(parent.path());

    let Err(refusal) = load_predecessor_package(
        &root,
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    ) else {
        panic!("stored list-form sources are not read from a predecessor");
    };

    let PackageError::PreviousReleaseSources(detail) = &refusal else {
        panic!("expected the previous-release refusal, got {refusal:?}");
    };
    assert!(
        detail.contains("Write accessProfiles as a mapping"),
        "{detail}"
    );
    assert!(
        refusal.to_string().contains(FRESH_DATABASE_PATH),
        "{refusal}"
    );
}

/// A package with legacy engine features predates every release that reads
/// id-keyed maps, so it is refused as a predecessor and as a rehearsal
/// baseline alike, with the fresh-database path.
#[test]
fn predecessor_with_legacy_engine_features_is_refused() {
    let context = PackageLoadContext {
        database_initialization_environment: "local",
    };
    let root = list_form_package();
    assert_eq!(
        load_predecessor_package(&root, &context).err(),
        Some(PackageError::EngineFeatureUpgradeRequired)
    );
    assert_eq!(
        load_predecessor_rehearsal_baseline(&root, &context).err(),
        Some(PackageError::EngineFeatureUpgradeRequired)
    );
}

/// An engine feature this release has never heard of is not read as a
/// legacy set either.
#[test]
fn unknown_engine_features_are_not_read() {
    let manifest = fs::read(list_form_package().join(MANIFEST_PATH)).expect("manifest reads");
    let unknown = String::from_utf8(manifest)
        .expect("manifest is UTF-8")
        .replace("caller_scoped_idempotency", "future_engine_feature");
    assert_eq!(
        parse_package_envelope(unknown.as_bytes()).err(),
        Some(PackageError::CanonicalJson)
    );
}

/// A package written by v0.41.0 or earlier, whose generated files name the
/// Record type `entityId`.
fn entity_id_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/entity-id-package/package")
}

#[test]
fn predecessor_naming_entity_id_is_refused_with_the_fresh_database_path() {
    let Err(refusal) = load_predecessor_package(
        &entity_id_package(),
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    ) else {
        panic!("a package that names entityId is not read as a predecessor");
    };

    let message = refusal.to_string();
    assert!(message.contains(FRESH_DATABASE_PATH), "{message}");
}

/// A package built before this release, read as a current package, is refused
/// with the reader's diagnostics and the one path forward: a fresh database.
#[test]
fn list_form_sources_read_as_a_current_package_name_the_fresh_database_path() {
    let root = list_form_package();
    let shared = verify_shared_package(&root).expect("the historical envelope verifies");
    let (manifest, loaded) =
        load_verified_closure(&root, &shared, false).expect("the historical closure verifies");

    let Err(refusal) = compile_package_sources(&manifest, &loaded) else {
        panic!("list-form access profiles are not read from a current package");
    };

    let PackageError::PreviousReleaseSources(detail) = &refusal else {
        panic!("expected the previous-release refusal, got {refusal:?}");
    };
    assert!(
        detail.contains("Write accessProfiles as a mapping"),
        "{detail}"
    );
    let message = refusal.to_string();
    assert!(message.contains(FRESH_DATABASE_PATH), "{message}");
    assert!(!message.contains("--baseline-package"), "{message}");
}

/// A package that predates the Record timer store gets the same path forward.
#[test]
fn legacy_engine_feature_refusal_names_the_fresh_database_path() {
    let message = PackageError::EngineFeatureUpgradeRequired.to_string();
    assert!(message.contains(FRESH_DATABASE_PATH), "{message}");
    assert!(!message.contains("successor"), "{message}");
}

/// A package that names `entityId` gets the same path forward.
#[test]
fn entity_id_refusal_names_the_fresh_database_path() {
    let message = PackageError::EntityIdMember.to_string();
    assert!(message.ends_with(FRESH_DATABASE_PATH), "{message}");
}
