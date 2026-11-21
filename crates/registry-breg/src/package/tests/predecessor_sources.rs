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
