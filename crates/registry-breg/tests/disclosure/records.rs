// SPDX-License-Identifier: Apache-2.0

//! Record-level canaries: get, list, lookup, count, read paths, statistics.

use super::fixture::{
    Fixture, ABSENT_ID, EMERGENCY_REGISTRAR, NAME_USAGE_ID, PERSON_ID, PROTECTION_OFFICER,
    REGISTRAR, RESIDENCE_ID,
};

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

/// The record ids of one table a runtime-role transaction selected under
/// `profile`, with the context the generated row policies read.
async fn visible_ids(fixture: &Fixture, record_type: &str, profile: &str) -> Vec<String> {
    let entity = &fixture.registry.entities()[record_type];
    let table = super::fixture::quote_identifier(&entity.physical_table);
    let pool = fixture
        .database
        .runtime_config
        .build_pool()
        .expect("bounded pool");
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let transaction = client.transaction().await.expect("transaction begins");
    transaction
        .execute(
            "SELECT set_config('registry.principal', 'test-principal', true),
                    set_config('registry.access_profile', $1, true),
                    set_config('registry.row_boundaries', '[]', true)",
            &[&profile],
        )
        .await
        .expect("the runtime context installs");
    let rows = transaction
        .query(
            &format!("SELECT record_id::text FROM registry_data.{table} ORDER BY record_id"),
            &[],
        )
        .await
        .expect("the runtime role selects");
    transaction.rollback().await.expect("rolls back");
    rows.iter().map(|row| row.get(0)).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_condition_hides_the_row_from_every_select_under_a_profile_it_does_not_exempt() {
    let fixture = Fixture::build(2).await;
    // The residence is withheld from the registrar and shown to both exempt
    // profiles. The timer is exempt in the guard, proven above, and holds its
    // own permissive policies. The control row proves the profile can read.
    for (profile, sees_residence) in [
        (REGISTRAR, false),
        (PROTECTION_OFFICER, true),
        (EMERGENCY_REGISTRAR, true),
    ] {
        let ids = visible_ids(&fixture, "residence", profile).await;
        assert_eq!(
            ids.iter().any(|id| id == RESIDENCE_ID),
            sees_residence,
            "{profile}"
        );
    }
    let registrar_people = visible_ids(&fixture, "person", REGISTRAR).await;
    assert!(
        registrar_people.iter().any(|id| id == PERSON_ID),
        "a fields condition leaves the person row readable"
    );
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_literal_of_a_conjunctive_condition_must_match_for_the_row_to_be_withheld() {
    let fixture = Fixture::build(2).await;
    // N is closed and protected, so only its exempt profile and the timer see it.
    for (profile, sees) in [
        (REGISTRAR, false),
        (EMERGENCY_REGISTRAR, false),
        (PROTECTION_OFFICER, true),
    ] {
        let ids = visible_ids(&fixture, "name-usage", profile).await;
        assert_eq!(ids.iter().any(|id| id == NAME_USAGE_ID), sees, "{profile}");
    }
    // The same person's open name usage stays visible: one literal fails.
    let open = "00000000-0000-0000-0000-00000000d005";
    fixture
        .insert(
            "name-usage",
            open,
            &[
                ("person-id", serde_json::json!(PERSON_ID)),
                ("protection-level", serde_json::json!("protected")),
                ("old-name", serde_json::json!("still-open")),
            ],
        )
        .await;
    let ids = visible_ids(&fixture, "name-usage", REGISTRAR).await;
    assert_eq!(ids, [open]);
    assert!(!ids.iter().any(|id| id == ABSENT_ID));
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restrictive_policy_installs_and_verifies_with_the_catalog() {
    let fixture = Fixture::build(1).await;
    let rows = fixture
        .database
        .admin
        .query(
            "SELECT polpermissive, polroles = ARRAY[0::oid], polcmd::text FROM pg_catalog.pg_policy
             WHERE polrelid = ('registry_data.' || quote_ident($1))::regclass AND NOT polpermissive",
            &[&fixture.registry.entities()["residence"].physical_table],
        )
        .await
        .expect("policies are readable");
    assert_eq!(rows.len(), 1, "one restrictive policy per record condition");
    assert!(rows[0].get::<_, bool>(1), "no TO clause: PUBLIC");
    assert_eq!(rows[0].get::<_, String>(2), "*", "FOR ALL");
    fixture.database.cleanup().await;
}
