// SPDX-License-Identifier: Apache-2.0
//! Canonical standalone journeys through the maintained client and real RLS.
#![cfg(feature = "postgres-test")]

#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_yaml, ModuleAssetSource};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegListRequest, BRegPatchRequest, BRegProblemCode, BRegRecordFormat, BRegRecordOptions,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const MINIMAL: &[u8] = include_bytes!("../../../products/breg/examples/minimal/registry.yaml");
const FACILITY: &[u8] = include_bytes!("../../../products/breg/examples/facility/registry.yaml");
const FUNCTION: &[u8] =
    include_bytes!("../../../products/breg/examples/facility/plans/correct-address.rhai");

fn compile(source: &[u8]) -> registry_breg::CompiledRegistry {
    let project = parse_project_yaml(source).expect("canonical project reads");
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: FUNCTION.to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("canonical project compiles")
}

fn facility_registry() -> registry_breg::CompiledRegistry {
    compile(FACILITY)
}

fn registrar_claims() -> VerifiedRequestClaims {
    claims(
        "registrar",
        "registry:facility:register",
        "facility-administration",
        "zone-a",
    )
}

async fn count(fixture: &client_http::ClientFixture, record_type: &str) -> i64 {
    let table = &fixture.registry.entities()[record_type].physical_table;
    fixture
        .database
        .admin
        .query_one(
            &format!("SELECT count(*)::bigint FROM registry_data.\"{table}\""),
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn facility_action_is_atomic_checks_references_and_recovers_exactly_once() {
    use registry_breg::mutation::MutationFaultPoint;
    let fixture = client_http::ClientFixture::start(
        facility_registry(),
        claims(
            "operator-editor",
            "registry:operator:write",
            "facility-administration",
            "zone-a",
        ),
    )
    .await;
    let metadata = fixture
        .http
        .client
        .registry_contract(Some("operator-editor"))
        .await
        .unwrap();
    let BRegDirectWrite::Create(operator_create) = metadata
        .value
        .select_direct_write("records.operator.create", "operator-editor")
        .unwrap()
    else {
        panic!("create")
    };
    let mut operators = Vec::new();
    for (code, status) in [("ACTIVE", "active"), ("INACTIVE", "inactive")] {
        let operator = fixture
            .http
            .client
            .create_record(
                &operator_create,
                &create(json!({"operatorCode":code,"status":status,"jurisdiction":"zone-a"})),
                &key(&format!("operator-{code}")),
                BRegRecordFormat::Json,
            )
            .await
            .unwrap();
        operators.push(operator.value.data.record_identifier);
    }
    let registrar = fixture.client_for(registrar_claims()).await;
    let metadata = registrar
        .client
        .registry_contract(Some("facility-registrar"))
        .await
        .unwrap();
    let binding = metadata
        .value
        .select_action("register-facility", "facility-registrar")
        .unwrap();
    let input = |code: &str, operator: &str| {
        json!({"facilityCode":code,"name":"Clinic Alpha",
        "addressLine":"1 Main Road","city":"Bangkok","postalCode":"10200",
        "operatorId":operator,"jurisdiction":"zone-a"})
        .as_object()
        .unwrap()
        .clone()
    };
    let request =
        BRegActionInvocationRequest::new(&binding, input("F-1", &operators[0]), None).unwrap();

    let fault = fixture
        .client_with_mutations(
            registrar_claims(),
            (*fixture.mutations)
                .clone()
                .with_fault_for_test(MutationFaultPoint::BeforeIdempotency),
        )
        .await;
    let fault_metadata = fault
        .client
        .registry_contract(Some("facility-registrar"))
        .await
        .unwrap();
    let fault_binding = fault_metadata
        .value
        .select_action("register-facility", "facility-registrar")
        .unwrap();
    let fault_request =
        BRegActionInvocationRequest::new(&fault_binding, input("F-1", &operators[0]), None)
            .unwrap();
    assert!(fault
        .client
        .invoke_action(&fault_binding, &fault_request, &key("facility-aborted"))
        .await
        .is_err());
    assert_eq!(count(&fixture, "facility").await, 0);
    assert_eq!(count(&fixture, "facility-assignment").await, 0);
    let first = registrar
        .client
        .invoke_action(&binding, &request, &key("facility-aborted"))
        .await
        .unwrap();
    let replay = registrar
        .client
        .invoke_action(&binding, &request, &key("facility-aborted"))
        .await
        .unwrap();
    assert_eq!(first.value, replay.value);
    assert_eq!(first.value.results().len(), 2);
    let facility_id = first.value.results()["facility"]
        .record_identifier()
        .to_string();
    let assignment_id = first.value.results()["assignment"]
        .record_identifier()
        .to_string();
    let reader = fixture
        .client_for(claims(
            "facility-reader",
            "registry:facility:read",
            "facility-administration",
            "zone-a",
        ))
        .await;
    let options = BRegRecordOptions::default()
        .access_profile("facility-reader")
        .unwrap();
    let assignment = reader
        .client
        .get_record("facility-assignments", &assignment_id, &options)
        .await
        .unwrap();
    assert_eq!(
        assignment.value.data.domain_data["facility"],
        json!(facility_id)
    );
    assert_eq!(
        assignment.value.data.domain_data["operator"],
        json!(operators[0])
    );
    assert_eq!(count(&fixture, "facility").await, 1);
    assert_eq!(count(&fixture, "facility-assignment").await, 1);

    let denied =
        BRegActionInvocationRequest::new(&binding, input("F-DENIED", &operators[1]), None).unwrap();
    let denied = registrar
        .client
        .invoke_action(&binding, &denied, &key("inactive-operator"))
        .await
        .unwrap_err();
    assert_eq!(
        denied.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let missing = BRegActionInvocationRequest::new(
        &binding,
        input("F-MISSING", &Uuid::new_v4().to_string()),
        None,
    )
    .unwrap();
    assert!(registrar
        .client
        .invoke_action(&binding, &missing, &key("missing-operator"))
        .await
        .is_err());
    assert_eq!(count(&fixture, "facility").await, 1);
    assert_eq!(count(&fixture, "facility-assignment").await, 1);

    let concurrent =
        BRegActionInvocationRequest::new(&binding, input("F-2", &operators[0]), None).unwrap();
    let concurrent_key = key("facility-concurrent");
    let (left, right) = tokio::join!(
        registrar
            .client
            .invoke_action(&binding, &concurrent, &concurrent_key),
        registrar
            .client
            .invoke_action(&binding, &concurrent, &concurrent_key)
    );
    assert_eq!(left.unwrap().value, right.unwrap().value);
    assert_eq!(count(&fixture, "facility").await, 2);
    assert_eq!(count(&fixture, "facility-assignment").await, 2);
    let receipts: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_immediate_action_applications",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(receipts, 2);
    let mut lost = fixture
        .client_with_mutations(
            registrar_claims(),
            (*fixture.mutations)
                .clone()
                .with_fault_for_test(MutationFaultPoint::AfterCommitBeforeResponseRelease),
        )
        .await;
    lost.client = registry_breg_client::BaseRegistryClient::new(
        registry_breg_client::BaseRegistryClientConfig::new(lost.base_url.parse().unwrap())
            .with_maximum_mutation_retries(0),
    )
    .unwrap();
    let lost_contract = lost
        .client
        .registry_contract(Some("facility-registrar"))
        .await
        .unwrap();
    let lost_binding = lost_contract
        .value
        .select_action("register-facility", "facility-registrar")
        .unwrap();
    let lost_request =
        BRegActionInvocationRequest::new(&lost_binding, input("F-3", &operators[0]), None).unwrap();
    assert!(lost
        .client
        .invoke_action(&lost_binding, &lost_request, &key("facility-lost-response"))
        .await
        .is_err());
    assert_eq!(count(&fixture, "facility").await, 3);
    let recovery =
        BRegActionInvocationRequest::new(&binding, input("F-3", &operators[0]), None).unwrap();
    let recovered = registrar
        .client
        .invoke_action(&binding, &recovery, &key("facility-lost-response"))
        .await
        .unwrap();
    assert_eq!(recovered.value.results().len(), 2);
    assert_eq!(count(&fixture, "facility").await, 3);
    assert_eq!(count(&fixture, "facility-assignment").await, 3);
    assert_pool_authority_cleared(&fixture).await;
    drop(lost);
    drop(fault);
    drop(registrar);
    drop(reader);
    fixture.finish().await;
}

fn claims(
    principal: &str,
    scope: &str,
    purpose: &str,
    jurisdiction: &str,
) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::from([scope.into()]),
        Some(purpose.into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
        )]),
    )
    .expect("synthetic verified caller")
}

fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}
fn create(value: Value) -> BRegCreateRequest {
    BRegCreateRequest::new(value.as_object().unwrap().clone()).unwrap()
}

fn alias_registry() -> registry_breg::CompiledRegistry {
    let mut project = parse_project_yaml(MINIMAL).unwrap();
    project.entities[0].fields.push(
        serde_json::from_value(json!({
            "id":"parent", "type":"reference", "target":"contact", "classification":"internal"
        }))
        .unwrap(),
    );
    project.entities[0].hooks.push(serde_json::from_value(json!({
        "id":"contact-patched", "phase":"after", "trigger":"patched", "projection":["name","parent"]
    })).unwrap());
    project.access_profiles[0].permissions.entities[0] = serde_json::from_value(json!({
        "recordType":"contact", "operations":["create","get","list","patch"],
        "readableFields":["name","email","jurisdiction","parent"],
        "writableFields":["name","email","jurisdiction","parent"],
        "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    }))
    .unwrap();
    let mut action = json!({
        "id":"interleaved-aliases", "execution":{"mode":"immediate"},
        "inputs":[
            {"id":"first", "type":"reference", "target":"contact", "required":true,"classification":"internal"},
            {"id":"second", "type":"reference", "target":"contact", "required":true,"classification":"internal"},
            {"id":"name", "type":"string", "minimumLength":1,"maximumLength":160,"required":true,"classification":"internal"},
            {"id":"jurisdiction", "type":"string", "minimumLength":1,"maximumLength":40,"required":true,"classification":"internal"}
        ],
        "plan":{"type":"fixed","effects":[
            {"id":"first-patch","target":{"fromInput":"first"},"operation":"patch","set":{"name":{"fromInput":"name"}}},
            {"id":"parent-create","target":{"recordType":"contact"},"operation":"create","set":{
                "name":{"value":"Parent"},"email":{"value":"parent@example.test"},"jurisdiction":{"fromInput":"jurisdiction"}}},
            {"id":"second-patch","target":{"fromInput":"second"},"operation":"patch","set":{"parent":{"fromEffect":"parent-create"}}}
        ]}
    });
    for id in ["interleaved-aliases", "conflicting-aliases"] {
        action["id"] = json!(id);
        if id == "conflicting-aliases" {
            action["plan"]["effects"][2]["set"]["name"] = json!({"value":"Conflict"});
        }
        project
            .actions
            .push(serde_json::from_value(action.clone()).unwrap());
        project.access_profiles[0].permissions.actions.push(serde_json::from_value(json!({
            "action":id,"operations":["invoke"],
            "targets":[{"recordType":"contact","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
            "results":["first-patch","parent-create","second-patch"]
        })).unwrap());
    }
    registry_breg::compiler::compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interleaved_input_aliases_wait_for_dependencies_and_commit_one_patch_or_nothing() {
    use registry_breg_client::BRegActionTargetConditionsRequest;
    let fixture = client_http::ClientFixture::start(
        alias_registry(),
        claims(
            "directory-clerk",
            "registry:directory:write",
            "directory-administration",
            "zone-a",
        ),
    )
    .await;
    let client = &fixture.http.client;
    let metadata = client
        .registry_contract(Some("directory-editor"))
        .await
        .unwrap();
    let BRegDirectWrite::Create(create_binding) = metadata
        .value
        .select_direct_write("records.contact.create", "directory-editor")
        .unwrap()
    else {
        panic!("create")
    };
    let original = client
        .create_record(
            &create_binding,
            &create(
                json!({"name":"Original","email":"original@example.test","jurisdiction":"zone-a"}),
            ),
            &key("alias-seed"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let record = &original.value.data.record_identifier;
    // Commit members have canonical UUID order, independent of SQL execution.
    // Observe actual writes to prove the folded patch waits for its later
    // member's create dependency, regardless of the two random UUIDs' order.
    let table = &fixture.registry.entities()["contact"].physical_table;
    fixture
        .database
        .admin
        .batch_execute(&format!(
            r#"
        CREATE TABLE registry_internal.fixture_write_order (
            observed_index bigserial PRIMARY KEY, record_id uuid NOT NULL
        );
        CREATE FUNCTION registry_internal.fixture_observe_write() RETURNS trigger
            LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        BEGIN
            INSERT INTO registry_internal.fixture_write_order(record_id) VALUES(NEW.record_id);
            RETURN NEW;
        END $$;
        CREATE TRIGGER fixture_observe_write AFTER INSERT OR UPDATE ON registry_data."{table}"
            FOR EACH ROW EXECUTE FUNCTION registry_internal.fixture_observe_write();
    "#
        ))
        .await
        .unwrap();
    let input = json!({"first":record,"second":record,"name":"Changed","jurisdiction":"zone-a"});
    let binding = metadata
        .value
        .select_action("interleaved-aliases", "directory-editor")
        .unwrap();
    let conditions = client
        .action_target_conditions(
            &binding,
            &BRegActionTargetConditionsRequest::new(
                &binding,
                json!({"first":record,"second":record})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let invocation = BRegActionInvocationRequest::new(
        &binding,
        input.as_object().unwrap().clone(),
        Some(&conditions.value),
    )
    .unwrap();
    let applied = client
        .invoke_action(&binding, &invocation, &key("interleaved-aliases"))
        .await
        .unwrap();
    let results = applied.value.results();
    assert_eq!(results["first-patch"], results["second-patch"]);
    assert_eq!(results["first-patch"].revision(), 2);
    let parent = results["parent-create"].record_identifier();
    let current = client
        .get_record(
            "contacts",
            record,
            &BRegRecordOptions::default()
                .access_profile("directory-editor")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(current.value.data.domain_data["name"], json!("Changed"));
    assert_eq!(
        current.value.data.domain_data["parent"],
        json!(parent.to_string())
    );
    let writes = fixture
        .database
        .admin
        .query(
            "SELECT record_id FROM registry_internal.fixture_write_order ORDER BY observed_index",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        writes
            .iter()
            .map(|row| row.get::<_, Uuid>(0))
            .collect::<Vec<_>>(),
        vec![parent, Uuid::parse_str(record).unwrap()],
        "the physical folded patch follows every member's dependency"
    );
    let members = fixture
        .database
        .admin
        .query(
            "SELECT m.record_id FROM registry_internal.registry_revision_commit_members m
         JOIN registry_internal.registry_commit_head h ON h.latest_position=m.commit_position
         ORDER BY m.member_index",
            &[],
        )
        .await
        .unwrap();
    let mut expected_members = vec![parent, Uuid::parse_str(record).unwrap()];
    expected_members.sort();
    assert_eq!(
        members
            .iter()
            .map(|row| row.get::<_, Uuid>(0))
            .collect::<Vec<_>>(),
        expected_members,
        "the commit contains each physical row once in canonical order"
    );
    let events: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_outbox WHERE entity_id='contact'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(events, 1, "two aliases produce one patch event");
    let conflict = metadata
        .value
        .select_action("conflicting-aliases", "directory-editor")
        .unwrap();
    let conditions = client
        .action_target_conditions(
            &conflict,
            &BRegActionTargetConditionsRequest::new(
                &conflict,
                json!({"first":record,"second":record})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let invocation = BRegActionInvocationRequest::new(
        &conflict,
        input.as_object().unwrap().clone(),
        Some(&conditions.value),
    )
    .unwrap();
    assert!(client
        .invoke_action(&conflict, &invocation, &key("conflicting-aliases"))
        .await
        .is_err());
    assert_eq!(
        count(&fixture, "contact").await,
        2,
        "the interleaved create is also rolled back on conflict"
    );
    let events_after: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_outbox WHERE entity_id='contact'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(events_after, events);
    let revisions: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_revisions WHERE entity_id='contact'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(revisions, 3, "one seed, one create and one folded patch");
    fixture.finish().await;
}

async fn assert_pool_authority_cleared(fixture: &client_http::ClientFixture) {
    let mut clients = Vec::new();
    for _ in 0..8 {
        clients.push(fixture.pool.get_for_test().await.unwrap());
    }
    for client in &clients {
        let clear: bool = client.query_one(
            "SELECT bool_and(NULLIF(current_setting(name, true), '') IS NULL)
               FROM unnest(ARRAY['registry.principal','registry.access_profile','registry.purpose',
                    'registry.row_boundaries','registry.active_package_revision','registry.recipients',
                    'registry.immediate_action_target_context','registry.immediate_action_link_context',
                    'registry.proposal_target_context']) AS setting(name)", &[]).await.unwrap().get(0);
        assert!(clear, "pooled connection retains transaction authority");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn minimal_standalone_crud_concealment_conditions_and_exact_receipts() {
    let fixture = client_http::ClientFixture::start(
        compile(MINIMAL),
        claims(
            "directory-clerk",
            "registry:directory:write",
            "directory-administration",
            "zone-a",
        ),
    )
    .await;
    let client = &fixture.http.client;
    let metadata = client
        .registry_contract(Some("directory-editor"))
        .await
        .unwrap();
    let BRegDirectWrite::Create(create_binding) = metadata
        .value
        .select_direct_write("records.contact.create", "directory-editor")
        .unwrap()
    else {
        panic!("create")
    };
    let input =
        create(json!({"name":"Clinic Alpha","email":"alpha@example.test","jurisdiction":"zone-a"}));
    let first = client
        .create_record(
            &create_binding,
            &input,
            &key("minimal-create"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let replay = client
        .create_record(
            &create_binding,
            &input,
            &key("minimal-create"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    assert_eq!(first.value, replay.value);
    let changed =
        create(json!({"name":"Different","email":"alpha@example.test","jurisdiction":"zone-a"}));
    let conflict = client
        .create_record(
            &create_binding,
            &changed,
            &key("minimal-create"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap_err();
    assert_eq!(
        conflict.problem_code(),
        Some(BRegProblemCode::IdempotencyConflict)
    );
    let id = first.value.data.record_identifier.clone();
    let options = BRegRecordOptions::default()
        .access_profile("directory-editor")
        .unwrap();
    let read = client.get_record("contacts", &id, &options).await.unwrap();
    assert_eq!(read.value.data.domain_data["name"], json!("Clinic Alpha"));
    let BRegDirectWrite::Patch(patch_binding) = metadata
        .value
        .select_direct_write("records.contact.patch", "directory-editor")
        .unwrap()
    else {
        panic!("patch")
    };
    let patch = BRegPatchRequest::builder()
        .replace("name", json!("Clinic Beta"))
        .unwrap()
        .build()
        .unwrap();
    let old_etag = read.metadata.etag().unwrap();
    let updated = client
        .patch_record(
            &patch_binding,
            Uuid::parse_str(&id).unwrap(),
            old_etag,
            &patch,
            &key("minimal-patch"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    assert_eq!(updated.value.data.domain_data["name"], json!("Clinic Beta"));
    let replay = client
        .patch_record(
            &patch_binding,
            Uuid::parse_str(&id).unwrap(),
            old_etag,
            &patch,
            &key("minimal-patch"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    assert_eq!(updated.value, replay.value);
    let stale = client
        .patch_record(
            &patch_binding,
            Uuid::parse_str(&id).unwrap(),
            old_etag,
            &patch,
            &key("minimal-stale"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap_err();
    assert_eq!(
        stale.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );

    let outsider = fixture
        .client_for(claims(
            "other-clerk",
            "registry:directory:write",
            "directory-administration",
            "zone-b",
        ))
        .await;
    let hidden = outsider
        .client
        .get_record("contacts", &id, &options)
        .await
        .unwrap_err();
    let absent = outsider
        .client
        .get_record("contacts", &Uuid::new_v4().to_string(), &options)
        .await
        .unwrap_err();
    assert_eq!(
        hidden.problem_code(),
        Some(BRegProblemCode::ResourceNotFound)
    );
    assert_eq!(hidden.problem_code(), absent.problem_code());
    let empty = outsider
        .client
        .list_records("contacts", &BRegListRequest::default().options(options))
        .await
        .unwrap();
    assert!(empty.value.value.items.is_empty());

    let outside =
        create(json!({"name":"Outside","email":"outside@example.test","jurisdiction":"zone-b"}));
    assert!(client
        .create_record(
            &create_binding,
            &outside,
            &key("minimal-outside"),
            BRegRecordFormat::Json
        )
        .await
        .is_err());
    let move_outside = BRegPatchRequest::builder()
        .replace("jurisdiction", json!("zone-b"))
        .unwrap()
        .build()
        .unwrap();
    assert!(client
        .patch_record(
            &patch_binding,
            Uuid::parse_str(&id).unwrap(),
            updated.metadata.etag().unwrap(),
            &move_outside,
            &key("minimal-patch-outside"),
            BRegRecordFormat::Json,
        )
        .await
        .is_err());
    let table = &fixture.registry.entities()["contact"].physical_table;
    let row = fixture
        .database
        .admin
        .query_one(
            &format!("SELECT count(*)::bigint,max(record_revision) FROM registry_data.\"{table}\""),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, Option<i64>>(1), Some(2));
    drop(outsider);
    fixture.finish().await;
}
