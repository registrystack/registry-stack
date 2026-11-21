// SPDX-License-Identifier: Apache-2.0

//! Predecessor packages whose stored sources this release cannot read.

#![cfg(feature = "tooling")]

use super::*;
use std::path::Path;

/// An exact historical package built before access profiles were keyed by id,
/// so its stored sources list them.
fn list_form_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pre-record-timer-store-package/package")
}

#[test]
fn predecessor_with_list_form_access_profiles_is_refused_for_rehearsal() {
    let root = list_form_package();
    load_predecessor_package(
        &root,
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    )
    .expect("the package is a verified predecessor, so only its sources are at issue");

    let Err(refusal) = load_predecessor_rehearsal_baseline(
        &root,
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    ) else {
        panic!("list-form access profiles are not read from a predecessor");
    };

    let message = refusal.to_string();
    assert!(
        message.contains("stored sources do not compile with this bregctl"),
        "{message}"
    );
    assert!(
        message.contains("Write accessProfiles as a mapping"),
        "{message}"
    );
}

/// A package written by v0.41.0 or earlier, whose generated files name the
/// Record type `entityId`.
fn entity_id_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/entity-id-package/package")
}

#[test]
fn predecessor_naming_entity_id_is_refused() {
    let Err(refusal) = load_predecessor_package(
        &entity_id_package(),
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    ) else {
        panic!("a package that names entityId is not read as a predecessor");
    };

    let message = refusal.to_string();
    assert!(message.contains("entityId"), "{message}");
    assert!(message.contains("recreate the database"), "{message}");
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
