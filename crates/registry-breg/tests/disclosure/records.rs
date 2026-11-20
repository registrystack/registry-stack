// SPDX-License-Identifier: Apache-2.0

//! Record-level canaries: get, list, lookup, count, read paths, statistics.

use super::fixture::{Fixture, RESIDENCE_ID};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fixture_seeds_a_protected_residence_with_its_sentinel() {
    let fixture = Fixture::build(1).await;
    let entity = &fixture.registry.entities()["residence"];
    let table = super::fixture::quote_identifier(&entity.physical_table);
    let column = super::fixture::quote_identifier(&entity.fields["address"].physical_name);
    let row = fixture
        .database
        .admin
        .query_one(
            &format!("SELECT {column} FROM registry_data.{table} WHERE record_id = $1::text::uuid"),
            &[&RESIDENCE_ID],
        )
        .await
        .expect("the seeded residence is readable by the owner");
    let address: String = row.get(0);
    assert_eq!(address, super::fixture::CANARY_ADDRESS);
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_record_guard_hides_a_protected_row_from_every_profile_but_the_exempt_and_the_timer() {
    use registry_breg::disclosure::{record_guard_sql, TIMER_ACCESS_PROFILE};
    let fixture = Fixture::build(1).await;
    let entity = &fixture.registry.entities()["residence"];
    let guard = record_guard_sql(entity, &entity.disclosure_conditions[0]);
    let table = super::fixture::quote_identifier(&entity.physical_table);
    let sql =
        format!("SELECT ({guard}) FROM registry_data.{table} WHERE record_id = $1::text::uuid");
    for (profile, visible) in [
        (Some(super::fixture::REGISTRAR), false),
        (Some(super::fixture::PROTECTION_OFFICER), true),
        (Some(super::fixture::EMERGENCY_REGISTRAR), true),
        (Some(TIMER_ACCESS_PROFILE), true),
        // With no selected profile the guard answers null, which a row policy
        // treats as hidden.
        (None, false),
    ] {
        fixture
            .database
            .admin
            .execute(
                "SELECT set_config('registry.access_profile', $1, false)",
                &[&profile.unwrap_or("")],
            )
            .await
            .expect("the access profile is selected");
        let row = fixture
            .database
            .admin
            .query_one(&sql, &[&RESIDENCE_ID])
            .await
            .expect("the guard evaluates");
        assert_eq!(
            row.get::<_, Option<bool>>(0).unwrap_or(false),
            visible,
            "{profile:?}"
        );
    }
    fixture.database.cleanup().await;
}
