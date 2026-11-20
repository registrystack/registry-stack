// SPDX-License-Identifier: Apache-2.0

//! Field-level canaries: omitted members on reads and write responses.
//!
//! A `fields` condition must render a withheld member as null on get and list,
//! exactly as a member the record never set, and drop it from every write
//! response. An idempotent replay must not return a value captured earlier. A
//! JSON Patch `test` must not answer a guess about a withheld member.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::disclosure::plan;
use registry_breg::model::DisclosureWithhold;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

use super::fixture::{
    assert_has_sentinel, assert_no_sentinel, compile_fixture, project_source, Fixture,
    CANARY_EMAIL, CANARY_PHONE, DATABASE_ID, OPEN_PERSON_ID, PACKAGE_ID, PERSON_ID,
    PROTECTION_OFFICER, REGISTRAR,
};
use super::postgres_harness::TestDatabase;

const PERSON_FIELDS: [&str; 5] = [
    "family-name",
    "protection-level",
    "history-protected",
    "email-address",
    "phone-number",
];

#[test]
fn the_fixture_withholds_contacts_from_the_registrar_only() {
    let registry = compile_fixture();
    let person = &registry.entities()["person"];
    let registrar = plan(person, REGISTRAR);
    let officer = plan(person, PROTECTION_OFFICER);
    assert!(!registrar.is_empty());
    assert!(officer
        .conditions()
        .iter()
        .all(|condition| matches!(condition.withhold, DisclosureWithhold::History)));
    assert_eq!(
        registrar.named_fields().into_iter().collect::<Vec<_>>(),
        ["email-address", "phone-number"]
    );
}

/// The fixture project with create and patch granted on `person`.
fn writable_project() -> registry_breg::CompiledRegistry {
    let mut source = project_source();
    source["recordTypes"][0]["batch"] = json!({"maximumItems": 4, "maximumBytes": 8192});
    for profile in source["accessProfiles"].as_array_mut().unwrap() {
        let grant = &mut profile["permissions"]["records"][0];
        assert_eq!(grant["recordType"], "person");
        grant["operations"] = json!(["create", "get", "list", "patch", "batch"]);
        grant["writableFields"] = json!(PERSON_FIELDS);
        grant["sortableFields"] = json!(["family-name"]);
    }
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

/// The fixture rows installed under the writable project, with the router that
/// serves them.
async fn serve() -> (Fixture, axum::Router) {
    let registry = writable_project();
    let database = TestDatabase::create(4).await;
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("fixture DDL installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "disclosure-package-1",
        },
    )
    .await
    .expect("fixture registry state initializes");
    task.abort();
    let fixture = Fixture { database, registry };
    for (id, name, level, flag, email, phone) in [
        (
            PERSON_ID,
            "Protected",
            "protected",
            true,
            CANARY_EMAIL,
            CANARY_PHONE,
        ),
        (
            OPEN_PERSON_ID,
            "Open",
            "none",
            false,
            "open@example.invalid",
            "555-0100",
        ),
    ] {
        fixture
            .insert(
                "person",
                id,
                &[
                    ("family-name", json!(name)),
                    ("protection-level", json!(level)),
                    ("history-protected", json!(flag)),
                    ("email-address", json!(email)),
                    ("phone-number", json!(phone)),
                ],
            )
            .await;
    }
    let registry = Arc::new(fixture.registry.clone());
    let pool = fixture.database.runtime_config.build_pool().unwrap();
    let audit = fixture
        .database
        .audit(AuditProfile::production_from_secret_bytes(vec![0x45; 32].into()).unwrap());
    let lock_key = RegistryLockKey::derive("disclosure-fields-registry").unwrap();
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300)).unwrap(),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.activation_id.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        "disclosure-instance",
        lock_key,
        Duration::from_secs(2),
        audit,
    );
    let app = router(Arc::new(
        HttpService::new(registry, read_identity, records, Arc::new(Ready), cursors)
            .with_postgres_mutations(Arc::new(mutations)),
    ));
    (fixture, app)
}

struct Reply {
    status: StatusCode,
    etag: String,
    text: String,
    body: Value,
}

async fn send(
    app: &axum::Router,
    method: Method,
    path: &str,
    profile: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Reply {
    let claims = VerifiedRequestClaims::authenticated(
        "registry_principal",
        "canary-principal",
        BTreeSet::new(),
        None,
        std::collections::BTreeMap::new(),
    )
    .unwrap();
    let separator = if path.contains('?') { '&' } else { '?' };
    let mut request = Request::builder()
        .method(method)
        .uri(format!("{path}{separator}accessProfile={profile}"))
        .body(Body::from(
            body.map(|body| body.to_string()).unwrap_or_default(),
        ))
        .unwrap();
    for (name, value) in headers {
        request.headers_mut().append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
    }
    request.extensions_mut().insert(claims);
    let response = app.clone().call(request).await.unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Reply {
        status,
        etag,
        text,
        body,
    }
}

fn person_path(id: &str) -> String {
    format!("/v1/records/people/{id}")
}

/// The member names of the single record a reply carries, under `domainData`.
fn data_members(reply: &Reply) -> BTreeSet<String> {
    find_object(&reply.body, "domainData")
        .unwrap_or_else(|| panic!("a record body: {}", reply.text))
        .keys()
        .cloned()
        .collect()
}

fn find_object<'a>(value: &'a Value, key: &str) -> Option<&'a serde_json::Map<String, Value>> {
    match value {
        Value::Object(members) => members
            .get(key)
            .and_then(Value::as_object)
            .or_else(|| members.values().find_map(|member| find_object(member, key))),
        Value::Array(items) => items.iter().find_map(|item| find_object(item, key)),
        _ => None,
    }
}

fn api_names(fixture: &Fixture, fields: &[&str]) -> BTreeSet<String> {
    let person = &fixture.registry.entities()["person"];
    fields
        .iter()
        .map(|field| {
            person
                .stored_fields
                .iter()
                .find(|stored| stored.logical.id == *field)
                .expect("a stored field")
                .logical
                .api_name
                .clone()
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_get_nulls_withheld_members_only_while_the_condition_matches() {
    let (fixture, app) = serve().await;

    let marked = send(
        &app,
        Method::GET,
        &person_path(PERSON_ID),
        REGISTRAR,
        &[],
        None,
    )
    .await;
    assert_eq!(marked.status, StatusCode::OK, "{}", marked.text);
    assert_no_sentinel(&marked.text);
    assert_eq!(
        data_members(&marked),
        api_names(&fixture, &PERSON_FIELDS),
        "a withheld member is present: {}",
        marked.text
    );
    let data = find_object(&marked.body, "domainData").unwrap();
    assert_eq!(
        data.get("emailAddress"),
        Some(&Value::Null),
        "{}",
        marked.text
    );
    assert_eq!(
        data.get("phoneNumber"),
        Some(&Value::Null),
        "{}",
        marked.text
    );

    let open = send(
        &app,
        Method::GET,
        &person_path(OPEN_PERSON_ID),
        REGISTRAR,
        &[],
        None,
    )
    .await;
    assert_eq!(open.status, StatusCode::OK, "{}", open.text);
    assert_has_sentinel(&open.text, "open@example.invalid");
    assert_eq!(data_members(&open), api_names(&fixture, &PERSON_FIELDS));

    let officer = send(
        &app,
        Method::GET,
        &person_path(PERSON_ID),
        PROTECTION_OFFICER,
        &[],
        None,
    )
    .await;
    assert_eq!(officer.status, StatusCode::OK, "{}", officer.text);
    assert_has_sentinel(&officer.text, CANARY_EMAIL);
    assert_has_sentinel(&officer.text, CANARY_PHONE);
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_nulls_withheld_members_row_by_row() {
    let (fixture, app) = serve().await;

    let registrar = send(
        &app,
        Method::GET,
        "/v1/records/people",
        REGISTRAR,
        &[],
        None,
    )
    .await;
    assert_eq!(registrar.status, StatusCode::OK, "{}", registrar.text);
    assert_no_sentinel(&registrar.text);
    // The unmarked person keeps its contacts, so the omission is per row.
    assert_has_sentinel(&registrar.text, "open@example.invalid");
    let items = registrar.body["items"].as_array().expect("a page of items");
    assert_eq!(items.len(), 2, "{}", registrar.text);
    let marked = items
        .iter()
        .find(|item| item["recordIdentifier"] == PERSON_ID)
        .expect("the marked person is listed");
    assert_eq!(marked["domainData"].get("emailAddress"), Some(&Value::Null));
    assert_eq!(marked["domainData"].get("phoneNumber"), Some(&Value::Null));

    let officer = send(
        &app,
        Method::GET,
        "/v1/records/people",
        PROTECTION_OFFICER,
        &[],
        None,
    )
    .await;
    assert_eq!(officer.status, StatusCode::OK, "{}", officer.text);
    assert_has_sentinel(&officer.text, CANARY_EMAIL);
    assert_has_sentinel(&officer.text, CANARY_PHONE);
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_response_never_carries_a_withheld_member() {
    let (fixture, app) = serve().await;
    let current = send(
        &app,
        Method::GET,
        &person_path(PERSON_ID),
        REGISTRAR,
        &[],
        None,
    )
    .await;
    assert_eq!(current.status, StatusCode::OK, "{}", current.text);

    let patched = send(
        &app,
        Method::PATCH,
        &person_path(PERSON_ID),
        REGISTRAR,
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "patch-protected"),
            ("if-match", &current.etag),
        ],
        Some(json!([{"op": "replace", "path": "/data/familyName", "value": "Renamed"}])),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.text);
    assert_no_sentinel(&patched.text);
    assert_has_sentinel(&patched.text, "Renamed");
    assert_eq!(
        data_members(&patched),
        api_names(
            &fixture,
            &["family-name", "protection-level", "history-protected"]
        ),
        "{}",
        patched.text
    );

    // The exempt profile still receives every member it reads.
    let current = send(
        &app,
        Method::GET,
        &person_path(PERSON_ID),
        PROTECTION_OFFICER,
        &[],
        None,
    )
    .await;
    let patched = send(
        &app,
        Method::PATCH,
        &person_path(PERSON_ID),
        PROTECTION_OFFICER,
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "patch-protected-officer"),
            ("if-match", &current.etag),
        ],
        Some(json!([{"op": "replace", "path": "/data/familyName", "value": "Again"}])),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.text);
    assert_has_sentinel(&patched.text, CANARY_EMAIL);
    assert_eq!(data_members(&patched), api_names(&fixture, &PERSON_FIELDS));
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_write_never_returns_a_value_the_response_once_held() {
    let (fixture, app) = serve().await;
    let create = || {
        send(
            &app,
            Method::POST,
            "/v1/records/people",
            REGISTRAR,
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "create-then-mark"),
            ],
            Some(json!({"data": {
                "familyName": "Late",
                "protectionLevel": "none",
                "historyProtected": false,
                "emailAddress": "late@example.invalid",
                "phoneNumber": "late-phone"
            }})),
        )
    };
    let first = create().await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.text);
    assert!(
        !first.text.contains("late@example.invalid"),
        "{}",
        first.text
    );

    // The person is marked after the first answer.
    let person = &fixture.registry.entities()["person"];
    let level = &person.fields["protection-level"].physical_name;
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{level}\" = 'protected'
                  WHERE \"{}\" = 'late-phone'",
                person.physical_table, person.fields["phone-number"].physical_name
            ),
            &[],
        )
        .await
        .expect("the person is marked");

    let replay = create().await;
    assert_eq!(replay.status, first.status, "{}", replay.text);
    assert_eq!(replay.body, first.body);
    assert!(
        !replay.text.contains("late@example.invalid"),
        "{}",
        replay.text
    );
    assert!(!replay.text.contains("late-phone"), "{}", replay.text);

    // The write itself stored the contacts, and an exempt profile reads them.
    let id = first.body["data"]["recordIdentifier"]
        .as_str()
        .or_else(|| first.body["recordIdentifier"].as_str())
        .or_else(|| first.body["id"].as_str())
        .unwrap_or_else(|| panic!("a created id in {}", first.text))
        .to_owned();
    let officer = send(
        &app,
        Method::GET,
        &person_path(&id),
        PROTECTION_OFFICER,
        &[],
        None,
    )
    .await;
    assert_has_sentinel(&officer.text, "late@example.invalid");
    fixture.database.cleanup().await;
}

/// A record the condition withholds from and one with the field unset answer
/// with the same members, so the shape does not reveal the marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withheld_member_is_indistinguishable_from_an_unset_one() {
    let (fixture, app) = serve().await;
    let created = send(
        &app,
        Method::POST,
        "/v1/records/people",
        REGISTRAR,
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "create-unset"),
        ],
        Some(json!({"data": {
            "familyName": "Unset", "protectionLevel": "none", "historyProtected": false
        }})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let unset_id = created.body["data"]["recordIdentifier"]
        .as_str()
        .unwrap_or_else(|| panic!("a created id in {}", created.text))
        .to_owned();
    let unset = send(
        &app,
        Method::GET,
        &person_path(&unset_id),
        REGISTRAR,
        &[],
        None,
    )
    .await;
    let marked = send(
        &app,
        Method::GET,
        &person_path(PERSON_ID),
        REGISTRAR,
        &[],
        None,
    )
    .await;
    assert_eq!(unset.status, StatusCode::OK, "{}", unset.text);
    assert_eq!(data_members(&marked), data_members(&unset));
    assert_eq!(
        find_object(&marked.body, "domainData").unwrap()["emailAddress"],
        find_object(&unset.body, "domainData").unwrap()["emailAddress"]
    );
    fixture.database.cleanup().await;
}

/// `$orderby` adds a column before the condition flags. The flag of each row
/// must still be read from the right column.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ordered_list_withholds_by_the_condition_flag_of_each_row() {
    let (fixture, app) = serve().await;
    let ordered = send(
        &app,
        Method::GET,
        "/v1/records/people?$orderby=familyName",
        REGISTRAR,
        &[],
        None,
    )
    .await;
    assert_eq!(ordered.status, StatusCode::OK, "{}", ordered.text);
    assert_no_sentinel(&ordered.text);
    let items = ordered.body["items"].as_array().expect("a page of items");
    assert_eq!(items.len(), 2, "{}", ordered.text);
    // Open sorts before Protected.
    assert_eq!(items[0]["recordIdentifier"], OPEN_PERSON_ID);
    assert_eq!(
        items[0]["domainData"]["emailAddress"],
        "open@example.invalid"
    );
    assert_eq!(items[1]["recordIdentifier"], PERSON_ID);
    assert_eq!(
        items[1]["domainData"].get("emailAddress"),
        Some(&Value::Null)
    );
    fixture.database.cleanup().await;
}

/// The problem body without its per-request trace identifier.
fn without_trace(mut body: Value) -> Value {
    body.as_object_mut()
        .expect("a problem body")
        .remove("traceId");
    body
}

/// A JSON Patch `test` on a withheld member must not answer a guess. A wrong,
/// a right and a null guess give the same status, code and body, alone and
/// next to a harmless replace in a batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_test_on_a_withheld_member_answers_every_guess_alike() {
    let (fixture, app) = serve().await;
    let guesses = [json!("guess@example.org"), json!(CANARY_EMAIL), Value::Null];
    let mut answers = Vec::new();
    for (index, guess) in guesses.iter().enumerate() {
        let current = send(
            &app,
            Method::GET,
            &person_path(PERSON_ID),
            REGISTRAR,
            &[],
            None,
        )
        .await;
        let key = format!("test-oracle-{index}");
        let reply = send(
            &app,
            Method::PATCH,
            &person_path(PERSON_ID),
            REGISTRAR,
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", &key),
                ("if-match", &current.etag),
            ],
            Some(json!([
                {"op": "test", "path": "/data/emailAddress", "value": guess},
                {"op": "replace", "path": "/data/familyName", "value": "Harmless"}
            ])),
        )
        .await;
        assert_no_sentinel(&reply.text);
        answers.push((reply.status, without_trace(reply.body)));
    }
    assert!(answers[0].0.is_client_error(), "{:?}", answers[0]);
    assert!(
        answers.iter().all(|answer| *answer == answers[0]),
        "guesses are told apart: {answers:?}"
    );

    // The same guesses beside a harmless replace in a batch.
    let mut batched = Vec::new();
    for (index, guess) in guesses.iter().enumerate() {
        let current = send(
            &app,
            Method::GET,
            &person_path(PERSON_ID),
            REGISTRAR,
            &[],
            None,
        )
        .await;
        let key = format!("test-oracle-batch-{index}");
        let reply = send(
            &app,
            Method::POST,
            "/v1/records/people:batch",
            REGISTRAR,
            &[
                ("content-type", "application/json"),
                ("idempotency-key", &key),
            ],
            Some(json!({"items": [{
                "operation": "patch", "recordIdentifier": PERSON_ID, "ifMatch": current.etag,
                "patch": [
                    {"op": "test", "path": "/data/emailAddress", "value": guess},
                    {"op": "replace", "path": "/data/familyName", "value": "Harmless"}]}]})),
        )
        .await;
        assert_no_sentinel(&reply.text);
        batched.push((reply.status, without_trace(reply.body)));
    }
    assert!(batched[0].0.is_client_error(), "{:?}", batched[0]);
    assert!(
        batched.iter().all(|answer| *answer == batched[0]),
        "guesses are told apart in a batch: {batched:?}"
    );

    // A test on a member the condition does not name still works, so the
    // refusal is not a blanket one.
    let current = send(
        &app,
        Method::GET,
        &person_path(PERSON_ID),
        REGISTRAR,
        &[],
        None,
    )
    .await;
    let allowed = send(
        &app,
        Method::PATCH,
        &person_path(PERSON_ID),
        REGISTRAR,
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "test-allowed"),
            ("if-match", &current.etag),
        ],
        Some(json!([
            {"op": "test", "path": "/data/familyName", "value": "Protected"},
            {"op": "replace", "path": "/data/familyName", "value": "Allowed"}
        ])),
    )
    .await;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.text);
    fixture.database.cleanup().await;
}
