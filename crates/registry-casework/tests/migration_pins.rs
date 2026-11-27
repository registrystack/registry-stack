// SPDX-License-Identifier: Apache-2.0
//! Every Casework migration file is pinned by its sha256. The migration
//! ledger records versions only, so a database that applied a version never
//! reads its file again: an edit would change fresh installs and leave every
//! existing database behind. A change to the schema is the next version.

use std::path::Path;

use registry_platform_testing::assert_migration_pins;

const PINS: &[(&str, &str)] = &[
    (
        "0200_reviews.sql",
        "72a4b39c7f2cc64e28c1241b76c7277ee4b2581832ca8a2168d84f46b94d6b98",
    ),
    (
        "0201_activation_posture.sql",
        "3eacf388a3ebcc488315291f17c466bcc877932fd2a3c83c2333b36d2d02f85f",
    ),
    (
        "0202_review_asks.sql",
        "a423a281c3c6da4a0213ac6fece8c8d7e93f30b7a0aa88098f3fbbdac851ffa9",
    ),
];

#[test]
fn every_migration_file_is_pinned_by_its_digest() {
    assert_migration_pins(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
        PINS,
    );
}
