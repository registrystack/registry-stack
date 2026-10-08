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
    BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey, BRegListRequest, BRegProblemCode,
    BRegRecordFormat, BRegRecordOptions, BRegRelationshipListRequest,
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

/// #1391: a read path answers on the source profile's path grant, so a
/// profile with no permission entry at all for the path's target entity
/// still reads what the generated target policy authorizes. A profile that
/// does not declare the path is concealed as an unknown path (BREG-SEC-21).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_path_answers_when_the_profile_has_no_entry_for_its_target_entity() {
    let fixture = client_http::ClientFixture::start(
        compile(UNGRANTED_TARGET_PROJECT, "ungranted-target project"),
        claims(),
    )
    .await;
    let client = &fixture.http.client;
    let operator = client.registry_contract(Some("operator")).await.unwrap();
    let writer = client.registry_contract(Some("writer")).await.unwrap();
    let household = client
        .create_record(
            &create_binding(&operator.value, "records.household.create", "operator"),
            &create(json!({"householdCode":"HH-1"})),
            &key("ungranted-household"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let person = client
        .create_record(
            &create_binding(&writer.value, "records.person.create", "writer"),
            &create(json!({"personCode":"P-1"})),
            &key("ungranted-person"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    client
        .create_record(
            &create_binding(&operator.value, "records.membership.create", "operator"),
            &create(json!({
                "household": household.value.data.record_identifier,
                "person": person.value.data.record_identifier
            })),
            &key("ungranted-membership"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let unlinked = client
        .create_record(
            &create_binding(&writer.value, "records.person.create", "writer"),
            &create(json!({"personCode":"P-2"})),
            &key("ungranted-unlinked-person"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();

    let page = client
        .list_relationship_records(
            "households",
            &household.value.data.record_identifier,
            "people",
            &relationship_request("operator", "personCode"),
        )
        .await
        .expect("the path grant alone authorizes the target read");
    assert_eq!(page.value.value.meta.entity_type_identifier, "person");
    assert_eq!(page.value.value.items.len(), 1);
    let record = &page.value.value.items[0];
    assert_eq!(
        record.record_identifier,
        person.value.data.record_identifier
    );
    assert_ne!(
        record.record_identifier,
        unlinked.value.data.record_identifier
    );
    assert_eq!(
        record.domain_data,
        BTreeMap::from([("personCode".into(), json!("P-1"))])
    );

    let undeclared = client
        .list_relationship_records(
            "households",
            &household.value.data.record_identifier,
            "people",
            &relationship_request("viewer", "personCode"),
        )
        .await
        .expect_err("a profile without the path grant is refused");
    assert_eq!(undeclared.status(), Some(404));
    assert_eq!(
        undeclared.problem_code(),
        Some(BRegProblemCode::ResourceNotFound)
    );
    let unknown = client
        .list_relationship_records(
            "households",
            &household.value.data.record_identifier,
            "no-such-path",
            &relationship_request("operator", "personCode"),
        )
        .await
        .expect_err("an unknown path is refused");
    assert_eq!(unknown.status(), undeclared.status());
    assert_eq!(unknown.problem_code(), undeclared.problem_code());
    fixture.finish().await;
}

/// #1391 for a change-request target: a profile with no entry for the target
/// installs no owner request visibility and reads exactly what the target
/// policy authorizes, while a profile declaring `requestVisibility: owner`
/// on the change-request entity still sees only its own requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_path_to_a_change_request_entity_leaves_owner_visibility_to_its_own_profile() {
    let fixture = client_http::ClientFixture::start(
        compile(
            CHANGE_REQUEST_TARGET_PROJECT,
            "change-request target project",
        ),
        principal_claims("request-operator"),
    )
    .await;
    let operator_client = &fixture.http.client;
    let first = fixture
        .client_for(principal_claims("first-submitter"))
        .await;
    let second = fixture
        .client_for(principal_claims("second-submitter"))
        .await;
    let operator = operator_client
        .registry_contract(Some("operator"))
        .await
        .unwrap();
    let household = operator_client
        .create_record(
            &create_binding(&operator.value, "records.household.create", "operator"),
            &create(json!({"householdCode":"HH-1"})),
            &key("request-household"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let mut requests = BTreeMap::new();
    for (name, http) in [("first", &first), ("second", &second)] {
        // A write binding is tied to the client origin it was read through.
        let submitter = http
            .client
            .registry_contract(Some("submitter"))
            .await
            .unwrap();
        let request = http
            .client
            .create_record(
                &create_binding(&submitter.value, "records.claim.create", "submitter"),
                &create(json!({
                    "household": household.value.data.record_identifier,
                    "proposedCode": format!("HH-{name}"),
                    "reason": format!("{name} reason")
                })),
                &key(&format!("request-{name}")),
                BRegRecordFormat::Json,
            )
            .await
            .unwrap();
        operator_client
            .create_record(
                &create_binding(&operator.value, "records.claim-link.create", "operator"),
                &create(json!({
                    "household": household.value.data.record_identifier,
                    "claim": request.value.data.record_identifier
                })),
                &key(&format!("request-link-{name}")),
                BRegRecordFormat::Json,
            )
            .await
            .unwrap();
        requests.insert(name, request.value.data.record_identifier.clone());
    }

    let page = operator_client
        .list_relationship_records(
            "households",
            &household.value.data.record_identifier,
            "claims",
            &relationship_request("operator", "reason"),
        )
        .await
        .expect("the path grant alone authorizes the change-request target read");
    let seen = page
        .value
        .value
        .items
        .iter()
        .map(|record| record.record_identifier.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(seen, requests.values().cloned().collect());

    for (name, http) in [("first", &first), ("second", &second)] {
        let own = http
            .client
            .list_records(
                "claims",
                &BRegListRequest::default().options(
                    BRegRecordOptions::default()
                        .access_profile("submitter")
                        .unwrap()
                        .select(["reason"])
                        .unwrap(),
                ),
            )
            .await
            .unwrap();
        let own = own
            .value
            .value
            .items
            .iter()
            .map(|record| record.record_identifier.clone())
            .collect::<Vec<_>>();
        assert_eq!(own, vec![requests[name].clone()]);
    }
    drop(first);
    drop(second);
    fixture.finish().await;
}

fn relationship_request(profile: &str, field: &str) -> BRegRelationshipListRequest {
    BRegRelationshipListRequest::default().options(
        BRegRecordOptions::default()
            .access_profile(profile)
            .unwrap()
            .select([field])
            .unwrap(),
    )
}

fn principal_claims(principal: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::from(["registry.read".to_owned()]),
        Some("case-management".into()),
        BTreeMap::new(),
    )
    .unwrap()
}

fn compile(source: &str, label: &str) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(source.as_bytes())
        .unwrap_or_else(|error| panic!("{label} parses: {error:?}"));
    compile_project(&project, &[], CompileProfile::Authoring)
        .unwrap_or_else(|error| panic!("{label} compiles: {error:?}"))
}

const UNGRANTED_TARGET_PROJECT: &str = r#"{
  "apiVersion":"registry.registrystack.org/v1alpha1",
  "kind":"RegistryProject",
  "registry":{"id":"ungranted-read-path-target","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://fixture.example.test"},
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
      "fields":[{"id":"person-code","type":"string","required":true,"maxLength":64,"classification":"restricted"}]
    }
  ],
  "accessProfiles":[
    {
      "id":"operator","default":true,"principalClaim":"registry_principal",
      "requiredScopes":["registry.read"],"requiredPurposes":["case-management"],
      "permissions":[
        {
          "entity":"household","rowBoundaries":"unrestricted","operations":["create","get","list"],
          "readableFields":["household-code"],"writableFields":["household-code"],
          "readPaths":[{"path":"people","readableFields":["person-code"]}]
        },
        {"entity":"membership","rowBoundaries":"unrestricted","operations":["create"],"readableFields":["household","person"],"writableFields":["household","person"]}
      ]
    },
    {
      "id":"writer","principalClaim":"registry_principal",
      "requiredScopes":["registry.read"],"requiredPurposes":["case-management"],
      "permissions":[
        {"entity":"person","rowBoundaries":"unrestricted","operations":["create","get","list"],"readableFields":["person-code"],"writableFields":["person-code"]}
      ]
    },
    {
      "id":"viewer","principalClaim":"registry_principal",
      "requiredScopes":["registry.read"],"requiredPurposes":["case-management"],
      "permissions":[
        {"entity":"household","rowBoundaries":"unrestricted","operations":["get","list"],"readableFields":["household-code"]}
      ]
    }
  ]
}"#;

const CHANGE_REQUEST_TARGET_PROJECT: &str = r#"{
  "apiVersion":"registry.registrystack.org/v1alpha1",
  "kind":"RegistryProject",
  "registry":{"id":"change-request-read-path-target","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://fixture.example.test"},
  "entities":[
    {
      "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable","classification":"restricted",
      "changeControl":{"requiredFor":["patch"]},
      "fields":[{"id":"household-code","type":"string","required":true,"maxLength":64,"classification":"restricted"}],
      "readPaths":[{"id":"claims","through":"claim-link","to":"claim","route":"claims"}]
    },
    {
      "id":"claim-link","primaryDataset":"test-dataset","route":"claim-links","mutationMode":"mutable","classification":"restricted",
      "fields":[
        {"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"},
        {"id":"claim","type":"reference","target":"claim","required":true,"classification":"restricted"}
      ]
    },
    {
      "id":"claim","primaryDataset":"test-dataset","route":"claims","mutationMode":"mutable","classification":"restricted",
      "fields":[
        {"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"},
        {"id":"proposed-code","type":"string","required":true,"maxLength":64,"classification":"restricted"},
        {"id":"reason","type":"string","required":true,"maxLength":64,"classification":"restricted"}
      ],
      "changeRequest":{
        "effects":[{"target":{"fromField":"household"},"operation":"patch","set":{"household-code":{"fromField":"proposed-code"}}}],
        "review":{"authority":"casework-main","policyId":"claim-review"},
        "onApproved":{"mode":"manual"}
      }
    }
  ],
  "accessProfiles":[
    {
      "id":"operator","default":true,"principalClaim":"registry_principal",
      "requiredScopes":["registry.read"],"requiredPurposes":["case-management"],
      "permissions":[
        {
          "entity":"household","rowBoundaries":"unrestricted","operations":["create","get","list"],
          "readableFields":["household-code"],"writableFields":["household-code"],
          "readPaths":[{"path":"claims","readableFields":["reason"]}]
        },
        {"entity":"claim-link","rowBoundaries":"unrestricted","operations":["create"],"readableFields":["household","claim"],"writableFields":["household","claim"]}
      ]
    },
    {
      "id":"submitter","principalClaim":"registry_principal",
      "requiredScopes":["registry.read"],"requiredPurposes":["case-management"],
      "permissions":[
        {
          "entity":"claim","rowBoundaries":"unrestricted","operations":["create","get","list","submit_request"],
          "readableFields":["household","proposed-code","reason"],"writableFields":["household","proposed-code","reason"],
          "requestVisibility":"owner"
        }
      ]
    },
    {
      "id":"applier","principalClaim":"registry_principal",
      "requiredScopes":["registry.read"],"requiredPurposes":["case-management"],
      "permissions":[
        {
          "entity":"claim","rowBoundaries":"unrestricted","operations":["get","apply_request"],
          "readableFields":["household","proposed-code","reason"],
          "applyTargets":[{"entity":"household","rowBoundaries":"unrestricted"}]
        }
      ]
    }
  ]
}"#;

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
                "entity":"household","rowBoundaries":"unrestricted","operations":["create","get","list"],
                "readableFields":["household-code"],"writableFields":["household-code"],
                "readPaths":[{"path":"people","readableFields":["person-code"],"sortableFields":["person-code"],"allowCount":true}]
              },
              {"entity":"membership","rowBoundaries":"unrestricted","operations":["create"],"readableFields":["household","person"],"writableFields":["household","person"]},
              {
                "entity":"person","rowBoundaries":"unrestricted","operations":["create","get","list"],
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
