// SPDX-License-Identifier: Apache-2.0
//! Every Scheduling migration file is pinned by its sha256. The migration
//! ledger records versions only, so a database that applied a version never
//! reads its file again: an edit would change fresh installs and leave every
//! existing database behind. A change to the schema is the next version.

use std::path::Path;

use registry_platform_testing::assert_migration_pins;

const PINS: &[(&str, &str)] = &[(
    "0200_scheduling.sql",
    "0e488c27a47818f21455292f030940bccc6dd82878fd6fe5baeef7dddda84b6f",
)];

#[test]
fn every_migration_file_is_pinned_by_its_digest() {
    assert_migration_pins(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
        PINS,
    );
}
