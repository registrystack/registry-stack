// SPDX-License-Identifier: Apache-2.0
//! Every Casework migration file is pinned by its sha256. The migration
//! ledger records versions only, so a database that applied a version never
//! reads its file again: an edit would change fresh installs and leave every
//! existing database behind. A change to the schema is the next version.

use std::path::Path;

use registry_platform_testing::assert_migration_pins;

const PINS: &[(&str, &str)] = &[(
    "0200_reviews.sql",
    "72a4b39c7f2cc64e28c1241b76c7277ee4b2581832ca8a2168d84f46b94d6b98",
)];

#[test]
fn every_migration_file_is_pinned_by_its_digest() {
    assert_migration_pins(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
        PINS,
    );
}
