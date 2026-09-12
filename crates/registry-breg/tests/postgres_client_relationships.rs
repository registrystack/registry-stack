// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};

use registry_breg::api::VerifiedRequestClaims;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg_client::{
    BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey, BRegListRequest, BRegRecordFormat,
    BRegRecordOptions, BRegRelationshipListRequest,
};
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_relationship_continuation_keeps_source_path_authority_and_target_projection() {
    let fixture = client_http::ClientFixture::start(compiled_registry(), claims()).await;
    let client = &fixture.http.client;
    let contract = client.registry_contract(Some("operator")).await.unwrap();
    let household_create = create_binding(&contract.value, "records.household.create", "operator");
    let person_create = create_binding(&contract.value, "records.person.create", "operator");
    let membership_create =
        create_binding(&contract.value, "records.membership.create", "operator");

    let household = client
        .create_record(
            &household_create,
            &create(json!({"householdCode":"HH-1"})),
            &key("relationship-household"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let mut linked_ids = BTreeSet::new();
    for index in 1..=3 {
        let person = client
            .create_record(
                &person_create,
                &create(json!({
                    "personCode": format!("P-{index}"),
                    "sensitiveNote": format!("private-{index}")
                })),
                &key(&format!("relationship-person-{index}")),
                BRegRecordFormat::Json,
            )
            .await
            .unwrap();
        linked_ids.insert(person.value.data.record_identifier.clone());
        client
            .create_record(
                &membership_create,
                &create(json!({
                    "household": household.value.data.record_identifier,
                    "person": person.value.data.record_identifier
                })),
                &key(&format!("relationship-membership-{index}")),
                BRegRecordFormat::Json,
            )
            .await
            .unwrap();
    }
    let unlinked = client
        .create_record(
            &person_create,
            &create(json!({
                "personCode":"P-4",
                "sensitiveNote":"private-4"
            })),
            &key("relationship-unlinked-person"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();

    let direct = client
        .list_records(
            "people",
            &BRegListRequest::default().options(
                BRegRecordOptions::default()
                    .access_profile("operator")
                    .unwrap()
                    .select(["sensitiveNote"])
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(direct.value.value.items.len(), 4);
    assert!(direct.value.value.items.iter().any(|record| {
        record.record_identifier == unlinked.value.data.record_identifier
            && record.domain_data == BTreeMap::from([("sensitiveNote".into(), json!("private-4"))])
    }));
    assert!(direct
        .value
        .value
        .items
        .iter()
        .all(|record| !record.domain_data.contains_key("personCode")));

    let request = BRegRelationshipListRequest::default()
        .options(
            BRegRecordOptions::default()
                .access_profile("operator")
                .unwrap()
                .select(["personCode"])
                .unwrap(),
        )
        .orderby("personCode")
        .unwrap()
        .count(true)
        .top(1)
        .unwrap();
    let mut page = client
        .list_relationship_records(
            "households",
            &household.value.data.record_identifier,
            "people",
            &request,
        )
        .await
        .unwrap();
    let first_continuation = page
        .value
        .continuation
        .as_ref()
        .expect("one-row relationship page has a continuation")
        .projection();
    assert_eq!(first_continuation.collection.route, "households");
    assert_eq!(first_continuation.path_route, "people");
    assert_eq!(
        first_continuation.root_record_identifier,
        household.value.data.record_identifier
    );
    assert_eq!(
        first_continuation.collection.entity_type_identifier,
        "person"
    );
    assert_eq!(
        first_continuation.collection.access_profile.as_deref(),
        Some("operator")
    );
    assert_eq!(page.value.value.extensions.get("count"), Some(&json!(3)));

    let mut seen = BTreeSet::new();
    loop {
        assert_eq!(page.value.value.meta.entity_type_identifier, "person");
        assert_eq!(page.value.value.items.len(), 1);
        let record = &page.value.value.items[0];
        assert!(seen.insert(record.record_identifier.clone()));
        assert_eq!(record.domain_data.len(), 1);
        assert!(record.domain_data.contains_key("personCode"));
        assert!(!record.domain_data.contains_key("sensitiveNote"));
        let Some(continuation) = page.value.continuation.as_ref() else {
            break;
        };
        page = client
            .continue_relationship_list(continuation)
            .await
            .unwrap();
    }
    assert_eq!(seen, linked_ids);
    assert!(!seen.contains(&unlinked.value.data.record_identifier));
    fixture.finish().await;
}

fn create_binding(
    metadata: &registry_breg_client::BRegMetadata,
    operation_id: &str,
    access_profile: &str,
) -> registry_breg_client::BRegCreateBinding {
    let BRegDirectWrite::Create(binding) = metadata
        .select_direct_write(operation_id, access_profile)
        .unwrap()
    else {
        panic!("{operation_id} is a create binding")
    };
    binding
}

fn create(value: Value) -> BRegCreateRequest {
    let Value::Object(data) = value else {
        unreachable!("test create payload is an object")
    };
    BRegCreateRequest::new(data).unwrap()
}

fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "relationship-reader",
        BTreeSet::from(["registry.read".to_owned()]),
        Some("case-management".into()),
        BTreeMap::new(),
    )
    .unwrap()
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"client-relationships","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://fixture.example.test"},
          "entities":[
            {
              "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable","classification":"restricted",
              "fields":[{"id":"household-code","type":"string","required":true,"maxLength":64,"classification":"restricted"}],
              "readPaths":[{"id":"people","through":"membership","to":"person","route":"people"}]
            },
            {
              "id":"membership","primaryDataset":"test-dataset","route":"memberships","mutationMode":"mutable","classification":"restricted",
              "fields":[
                {"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"},
                {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}
              ]
            },
            {
              "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"restricted",
              "fields":[
                {"id":"person-code","type":"string","required":true,"maxLength":64,"classification":"restricted"},
                {"id":"sensitive-note","type":"string","required":true,"maxLength":64,"classification":"restricted"}
              ]
            }
          ],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"registry_principal",
            "requiredScopes":["registry.read"],"requiredPurposes":["case-management"],
            "permissions":[
              {
                "entity":"household","rowBoundaries":[],"operations":["create","get","list"],
                "readableFields":["household-code"],"writableFields":["household-code"],
                "readPaths":[{"path":"people","readableFields":["person-code"],"sortableFields":["person-code"],"allowCount":true}]
              },
              {"entity":"membership","rowBoundaries":[],"operations":["create"],"readableFields":["household","person"],"writableFields":["household","person"]},
              {
                "entity":"person","rowBoundaries":[],"operations":["create","get","list"],
                "readableFields":["sensitive-note"],"writableFields":["person-code","sensitive-note"]
              }
            ]
          }]
        }"#,
    )
    .expect("relationship SDK project parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("relationship SDK project compiles")
}
