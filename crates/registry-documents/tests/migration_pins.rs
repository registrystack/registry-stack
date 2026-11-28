// SPDX-License-Identifier: Apache-2.0
//! Every Document Store migration file is pinned by its sha256. The migration
//! ledger records versions only, so a database that applied a version never
//! reads its file again: an edit would change fresh installs and leave every
//! existing database behind. A change to the schema is the next version.

use std::path::Path;

use registry_platform_testing::assert_migration_pins;

const PINS: &[(&str, &str)] = &[
    (
        "0100_documents.sql",
        "d21dae145068a46052af7ec69076ad2bdf883a0e550325db66c811380fe91575",
    ),
    (
        "0101_activation_posture.sql",
        "b984c63d7402d024752955aed60dd3b9b5dd821a0210ca64a0e1bbc1a6ec1df9",
    ),
];

#[test]
fn every_migration_file_is_pinned_by_its_digest() {
    assert_migration_pins(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
        PINS,
    );
}
