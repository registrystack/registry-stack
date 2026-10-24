// SPDX-License-Identifier: Apache-2.0
//! Every Scheduling migration file is pinned by its sha256. The migration
//! ledger records versions only, so a database that applied a version never
//! reads its file again: an edit would change fresh installs and leave every
//! existing database behind. A change to the schema is the next version.

use std::path::Path;

use registry_platform_testing::assert_migration_pins;

const PINS: &[(&str, &str)] = &[
    (
        "0200_scheduling.sql",
        "fa913d96b69dd2636bd02d7048906e3c58ed59715331ea26caaf54ba08cbabfe",
    ),
    (
        "0201_operational_reads.sql",
        "cc2e38f3f31011b1df5810a96bc1ada09d21c7c5ad3ce2b5d26a04a0be688e5f",
    ),
    (
        "0202_resource_availability.sql",
        "4258132d569bb2f417116ceda636741b46e90c5584ecb89531abde040f5b733c",
    ),
    (
        "0203_booking_party.sql",
        "7c863920444b628a51beec00cbbb08c6db7d4d406e79b456ecaf52bef802ba57",
    ),
    (
        "0204_source_manager.sql",
        "60399a5869002f93e16d32d8fa9fd8ff7114cdb44096fccefa6c087f69c4cdb6",
    ),
    (
        "0205_atomic_allocations.sql",
        "abc64351c86c9618880fc1cef867ad46e6bbb73157639fec3727048358394942",
    ),
    (
        "0206_source_busy.sql",
        "bd7b8d2be298ccc23136797f155cf850c341f7685d08efbf3a3b9dc98750edda",
    ),
    (
        "0207_window_resources.sql",
        "3afbb69a259b57ff367965a191676165c9264461e98da9f18e204dc86a586552",
    ),
    (
        "0208_attendance.sql",
        "56bd99b6b814c8f9a5e265a60dbfe36f2a9a86f966341d07663a6598919659b8",
    ),
    (
        "0209_source_busy_outcome.sql",
        "5bba73f60c0f8d0b480fe5f98e6e9c0e7315f8e1b7dc24f74d5fa6bfedbc37ce",
    ),
];

#[test]
fn every_migration_file_is_pinned_by_its_digest() {
    assert_migration_pins(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
        PINS,
    );
}
