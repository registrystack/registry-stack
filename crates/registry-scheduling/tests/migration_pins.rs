// SPDX-License-Identifier: Apache-2.0
//! Every Scheduling migration file is pinned by its sha256. The migration
//! ledger records versions only, so a database that applied a version never
//! reads its file again: an edit would change fresh installs and leave every
//! existing database behind. A change to the schema is the next version.

use std::path::Path;

use registry_platform_testing::assert_migration_pins;

const PINS: &[(&str, &str)] = &[(
    "0200_scheduling.sql",
    "7ed50e3d22059aa66d647ab81a089f82823cd534c2ca066b1bd99c4062a8a4f0",
)];

#[test]
fn every_migration_file_is_pinned_by_its_digest() {
    assert_migration_pins(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
        PINS,
    );
}
