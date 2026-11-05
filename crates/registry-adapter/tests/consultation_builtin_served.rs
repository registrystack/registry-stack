// SPDX-License-Identifier: Apache-2.0

//! Black-box acceptance for the built-in GovStack Consultation host.
//! These tests use a project-owned output schema and transformation over the
//! maintained DHIS2 pack. They do not use the legacy configurable facade
//! profile. Needs `ADAPTER_TEST_DATABASE_URL`.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::Value;
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{digest_of, fixture, Served};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CONTRACT: &str = "https://registry.example/contracts/1.0.0-draft/openapi.yaml";

fn project() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/dhis2-consultation")
}

fn opencrvs_project() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/examples/opencrvs-consultation")
}

fn opencrvs_pack() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/packs/opencrvs-events/pack.yaml")
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn source_entity_with_private_canary() -> Value {
    let fixture = fixture("get-found");
    let mut entity = fixture["entries"][0]["upstream"][0]["response"]["body"].clone();
    entity["attributes"][0]["value"] = serde_json::json!("PRIVATE-CANARY");
    entity
}

fn source_page_with_private_canary() -> Value {
    let fixture = fixture("search-page");
    let mut page = fixture["entries"][0]["upstream"][0]["response"]["body"].clone();
    if let Some(first) = page["trackedEntities"]
        .as_array_mut()
        .and_then(|items| items.first_mut())
    {
        first["attributes"][0]["value"] = serde_json::json!("PRIVATE-CANARY");
    }
    page
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create the project copy");
    for entry in std::fs::read_dir(from).expect("read the project tree") {
        let entry = entry.expect("a project entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy a project file");
        }
    }
}

fn replace_public_projection(directory: &Path, script: &str) {
    let script_path = directory.join("scripts/person-public.rhai");
    let old = std::fs::read(&script_path).expect("read the pinned script");
    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("read the project");
    let old_digest = digest_of(&old);
    assert!(project.contains(&old_digest));
    std::fs::write(&script_path, script).expect("write the test projection");
    std::fs::write(
        &project_path,
        project.replace(&old_digest, &digest_of(script.as_bytes())),
    )
    .expect("repin the test projection");
}

fn operations(collection: &Value) -> BTreeMap<&str, &Value> {
    collection["operations"]
        .as_array()
        .expect("operations is an array")
        .iter()
        .map(|operation| {
            let capability = operation["capability"].as_str().expect("a capability name");
            assert_eq!(operation["contract"], CONTRACT);
            assert!(operation["operationId"].is_string(), "{operation}");
            (capability, operation)
        })
        .collect()
}

fn generated_operation_ids() -> BTreeSet<String> {
    let bytes = std::fs::read(project().join("generated/openapi.json"))
        .expect("the maintained generated OpenAPI is present");
    let document: Value = serde_json::from_slice(&bytes).expect("the generated OpenAPI is JSON");
    document["paths"]
        .as_object()
        .expect("OpenAPI paths")
        .values()
        .flat_map(|path| {
            path.as_object()
                .expect("a path item")
                .values()
                .filter_map(|operation| operation["operationId"].as_str().map(str::to_owned))
        })
        .collect()
}

#[tokio::test]
async fn capabilities_expose_only_the_three_schema_bound_views_the_caller_can_read() {
    let upstream = UpstreamDouble::start();
    let served = Served::start_with_project(&upstream.url(""), &project()).await;

    let (status, _, body) = served.get("/govstack/registries/v1/capabilities", None);
    assert_eq!(status, 401, "capability discovery is authenticated: {body}");
    assert_eq!(
        upstream.request_count(),
        0,
        "discovery performs no source I/O"
    );

    let token = served.token("records.read");
    let (status, head, body) = served.get("/govstack/registries/v1/capabilities", Some(&token));
    assert_eq!(status, 200, "{body}");
    assert_eq!(header(&head, "cache-control"), Some("no-store"));
    assert_eq!(
        header(&head, "x-registry-idempotency-replay-window-seconds"),
        None,
        "no replay-window header exists"
    );

    let collections = body["collections"]
        .as_array()
        .expect("capabilities carries collections");
    assert_eq!(collections.len(), 3, "{body}");
    for collection in collections {
        for operation in collection["operations"].as_array().expect("operations") {
            assert!(
                operation.get("write").is_none(),
                "a read-only deployment publishes no replay window: {operation}"
            );
        }
    }
    let generated = generated_operation_ids();
    for collection in collections {
        for operation in collection["operations"].as_array().expect("operations") {
            assert!(
                generated.contains(operation["operationId"].as_str().expect("operationId")),
                "capability operation is present in generated OpenAPI: {operation}"
            );
        }
    }

    let public = collections
        .iter()
        .find(|collection| collection["collectionId"] == "people")
        .expect("the public people view");
    assert_eq!(
        public["registry"],
        "https://registry.example/registries/people"
    );
    let public_operations = operations(public);
    assert_eq!(
        public_operations.keys().copied().collect::<Vec<_>>(),
        vec!["list", "lookup", "retrieve", "search"]
    );
    for operation in public_operations.values() {
        assert_eq!(operation["view"], "person-public");
    }
    assert_eq!(
        public_operations["lookup"]["selectors"],
        serde_json::json!(["by-record-id"])
    );
    assert_eq!(
        public_operations["search"]["searches"],
        serde_json::json!(["by-org-unit"])
    );

    let (status, _, runtime) = served.get(
        "/.well-known/registry-adapter/effective-contract",
        Some(&token),
    );
    assert_eq!(status, 200, "{runtime}");
    let runtime_operations = runtime["contract"]["operations"]
        .as_array()
        .expect("effective operations");
    let retrieve = runtime_operations
        .iter()
        .find(|operation| operation["bindingId"] == "people-retrieve")
        .expect("runtime Retrieve contract");
    assert_eq!(
        retrieve["output"]["$defs"]["projectData"]["properties"]["registration"]["type"],
        "object"
    );
    let lookup = runtime_operations
        .iter()
        .find(|operation| operation["bindingId"] == "people-lookup")
        .expect("runtime Lookup contract");
    assert_eq!(
        lookup["input"]["body"]["properties"]["selector"]["const"],
        "by-record-id"
    );
    assert_eq!(
        lookup["input"]["body"]["$defs"]["projectInput"]["properties"]["record-id"]["maxLength"],
        128
    );

    let summary = collections
        .iter()
        .find(|collection| collection["collectionId"] == "people-summary")
        .expect("the summary people view");
    let summary_operations = operations(summary);
    assert_eq!(
        summary_operations.keys().copied().collect::<Vec<_>>(),
        vec!["list", "lookup", "retrieve", "search"]
    );
    for operation in summary_operations.values() {
        assert_eq!(operation["view"], "person-summary");
    }

    let registration = collections
        .iter()
        .find(|collection| collection["collectionId"] == "people-registration")
        .expect("the generated registration people view");
    let registration_operations = operations(registration);
    assert_eq!(
        registration_operations.keys().copied().collect::<Vec<_>>(),
        vec!["list", "lookup", "retrieve", "search"]
    );
    for operation in registration_operations.values() {
        assert_eq!(operation["view"], "person-registration");
    }
    assert_eq!(
        upstream.request_count(),
        0,
        "discovery performs no source I/O"
    );
}

#[tokio::test]
async fn capabilities_are_not_released_when_the_audit_append_fails() {
    let upstream = UpstreamDouble::start();
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    served
        .execute_sql(
            "CREATE FUNCTION deny_capability_audit() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.operation = 'getCallerCapabilities' THEN \
             RAISE EXCEPTION 'synthetic capability audit refusal'; END IF; RETURN NEW; END $$; \
             CREATE TRIGGER deny_capability_audit BEFORE INSERT ON adapter_journal_events \
             FOR EACH ROW EXECUTE FUNCTION deny_capability_audit()",
        )
        .await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/govstack/registries/v1/capabilities", Some(&token));

    assert_eq!(status, 500, "capabilities fail closed: {body}");
    assert!(
        body.get("collections").is_none(),
        "the caller-visible capability document was not released: {body}"
    );
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn one_source_entity_is_projected_into_two_closed_views_without_private_attributes() {
    let upstream = UpstreamDouble::start();
    let source = source_entity_with_private_canary();
    upstream.respond_with(vec![
        Response::json(200, &source.to_string()),
        Response::json(200, &source.to_string()),
    ]);
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    let token = served.token("records.read");

    let (status, _, public) = served.get(
        "/govstack/registries/v1/collections/people/records/EeBJ3Sn9uLg",
        Some(&token),
    );
    assert_eq!(status, 200, "{public}\n{}", served.stderr_text());
    assert_eq!(
        public,
        serde_json::json!({
            "recordId": "EeBJ3Sn9uLg",
            "data": {
                "source": {"id": "EeBJ3Sn9uLg", "type": "cQWYtUfH6Vx"},
                "registration": {
                    "organisationUnit": "slSrf7H9lMf",
                    "createdAt": "2017-01-20T10:44:02.770",
                    "updatedAt": "2017-05-26T11:46:22.372"
                }
            }
        })
    );

    let (status, _, summary) = served.get(
        "/govstack/registries/v1/collections/people-summary/records/EeBJ3Sn9uLg",
        Some(&token),
    );
    assert_eq!(status, 200, "{summary}");
    assert_eq!(
        summary,
        serde_json::json!({
            "recordId": "EeBJ3Sn9uLg",
            "data": {
                "organisationUnit": "slSrf7H9lMf",
                "lastChangedAt": "2017-05-26T11:46:22.372"
            }
        })
    );

    assert!(!public.to_string().contains("PRIVATE-CANARY"));
    assert!(!summary.to_string().contains("PRIVATE-CANARY"));
    assert!(!served.journal_text().await.contains("PRIVATE-CANARY"));
    assert_eq!(upstream.request_count(), 2);
}

#[tokio::test]
async fn lookup_list_and_search_use_native_inputs_and_the_stable_source_order() {
    let upstream = UpstreamDouble::start();
    let entity = source_entity_with_private_canary();
    let page = source_page_with_private_canary();
    upstream.respond_with(vec![
        Response::json(200, &entity.to_string()),
        Response::json(200, &page.to_string()),
        Response::json(200, &page.to_string()),
    ]);
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    let token = served.token("records.read");

    let (status, _, lookup) = served.post(
        "/govstack/registries/v1/collections/people/lookup",
        Some(&token),
        &serde_json::json!({
            "selector": "by-record-id",
            "values": {"record-id": "EeBJ3Sn9uLg"}
        }),
    );
    assert_eq!(status, 200, "{lookup}\n{}", served.stderr_text());
    assert_eq!(lookup["recordId"], "EeBJ3Sn9uLg");

    let (status, _, list) = served.get(
        "/govstack/registries/v1/collections/people/records?pageSize=5",
        Some(&token),
    );
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["items"][0]["recordId"], "EeBJ3Sn9uLg");

    let (status, _, search) = served.post(
        "/govstack/registries/v1/collections/people/search",
        Some(&token),
        &serde_json::json!({
            "search": "by-org-unit",
            "criteria": {"org-unit": "slSrf7H9lMf"},
            "pageSize": 5
        }),
    );
    assert_eq!(status, 200, "{search}");
    assert_eq!(search["items"][0]["recordId"], "EeBJ3Sn9uLg");

    for response in [&lookup, &list, &search] {
        assert!(!response.to_string().contains("PRIVATE-CANARY"));
    }
    let requests = upstream.requests();
    assert_eq!(
        requests[0].target,
        "/api/tracker/trackedEntities/EeBJ3Sn9uLg"
    );
    assert!(
        requests[1]
            .target
            .contains("order=createdAt%3Adesc%2ClZGmxYbs97q%3Aasc"),
        "{}",
        requests[1].target
    );
    assert!(requests[2].target.contains("orgUnits=slSrf7H9lMf"));
    assert!(
        requests[2]
            .target
            .contains("order=createdAt%3Adesc%2ClZGmxYbs97q%3Aasc"),
        "{}",
        requests[2].target
    );
}

#[tokio::test]
async fn an_exact_read_refuses_a_source_entity_with_another_identity() {
    let upstream = UpstreamDouble::start();
    let mut source = source_entity_with_private_canary();
    source["trackedEntity"] = serde_json::json!("Different01");
    upstream.respond_with(vec![Response::json(200, &source.to_string())]);
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get(
        "/govstack/registries/v1/collections/people/records/EeBJ3Sn9uLg",
        Some(&token),
    );

    assert_eq!(
        status, 502,
        "a source identity mismatch is a bad gateway: {body}"
    );
    assert!(!body.to_string().contains("Different01"));
    assert!(!body.to_string().contains("PRIVATE-CANARY"));
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn authorization_and_collection_denials_happen_before_source_io() {
    let upstream = UpstreamDouble::start();
    let served = Served::start_with_project(&upstream.url(""), &project()).await;

    let unscoped = served.token("records.write");
    let (status, _, _) = served.get(
        "/govstack/registries/v1/collections/people/records/EeBJ3Sn9uLg",
        Some(&unscoped),
    );
    assert_eq!(status, 403);

    let reader = served.token("records.read");
    let (status, _, _) = served.get(
        "/govstack/registries/v1/collections/not-enabled/records/EeBJ3Sn9uLg",
        Some(&reader),
    );
    assert_eq!(status, 404);
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_projection_field_outside_the_pinned_schema_is_not_disclosed() {
    let directory = tempfile::tempdir().expect("a scratch project");
    copy_tree(&project(), directory.path());
    replace_public_projection(
        directory.path(),
        r#"fn project_person_public(source) {
    #{
        source: #{id: source.trackedEntity, type: source.trackedEntityType},
        registration: #{
            organisationUnit: source.orgUnit,
            createdAt: source.createdAt,
            updatedAt: source.updatedAt
        },
        privateCanary: "PRIVATE-CANARY"
    }
}
"#,
    );
    let upstream = UpstreamDouble::start();
    let source = source_entity_with_private_canary();
    upstream.respond_with(vec![Response::json(200, &source.to_string())]);
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get(
        "/govstack/registries/v1/collections/people/records/EeBJ3Sn9uLg",
        Some(&token),
    );

    assert_eq!(
        status, 500,
        "the closed output schema refuses the projection: {body}"
    );
    assert!(!body.to_string().contains("PRIVATE-CANARY"));
    assert!(!served.journal_text().await.contains("PRIVATE-CANARY"));
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn opencrvs_retrieve_and_lookup_use_the_same_exact_native_read_with_oauth() {
    let upstream = UpstreamDouble::start();
    let source = serde_json::json!({
        "total": 1,
        "results": [{
            "id": "00000000-0000-4000-8000-000000000001",
            "trackingId": "EVT-SYNTHETIC-001",
            "type": "birth",
            "status": "REGISTERED",
            "dateOfEvent": "2015-04-01",
            "declaration": {"unrelated.field": "SOURCE-UNRELATED-CANARY"}
        }]
    });
    upstream.respond_with(vec![
        Response::json(
            200,
            r#"{"access_token":"synthetic-opencrvs-token","token_type":"Bearer","expires_in":300}"#,
        ),
        Response::json(200, &source.to_string()),
        Response::json(200, &source.to_string()),
    ]);
    let oauth = format!(
        r#"      type: oauth2-client-credentials
      tokenEndpoint: {}
      clientIdRef: secret:env/TEST_UPSTREAM_USERNAME
      clientSecretRef: secret:env/TEST_UPSTREAM_PASSWORD
      scope: recordsearch
      credentialPlacement: form-body
      maximumCacheSeconds: 300
      assumedLifetimeSeconds: 600
"#,
        upstream.url("/oauth/token")
    );
    let served = Served::start_with_pack_endpoint_and_credential(
        &upstream.url(""),
        &opencrvs_project(),
        &opencrvs_pack(),
        "events",
        &oauth,
    )
    .await;
    let token = served.token("records.read");

    let (status, _, retrieved) = served.get(
        "/govstack/registries/v1/collections/birth-registrations/records/EVT-SYNTHETIC-001",
        Some(&token),
    );
    assert_eq!(status, 200, "{retrieved}\n{}", served.stderr_text());
    let (status, _, looked_up) = served.post(
        "/govstack/registries/v1/collections/birth-registrations/lookup",
        Some(&token),
        &serde_json::json!({
            "selector": "by-tracking-id",
            "values": {"recordId": "EVT-SYNTHETIC-001"}
        }),
    );
    assert_eq!(status, 200, "{looked_up}\n{}", served.stderr_text());

    let expected = serde_json::json!({
        "recordId": "EVT-SYNTHETIC-001",
        "data": {
            "registration": {"eventType": "birth", "status": "REGISTERED"},
            "dateOfEvent": "2015-04-01"
        }
    });
    assert_eq!(retrieved, expected);
    assert_eq!(looked_up, expected);
    assert!(!retrieved.to_string().contains("SOURCE-UNRELATED-CANARY"));
    assert!(!looked_up.to_string().contains("SOURCE-UNRELATED-CANARY"));

    let requests = upstream.requests();
    assert_eq!(requests.len(), 3, "one cached token and two source reads");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/oauth/token");
    assert_eq!(requests[1].target, "/events/search");
    assert_eq!(requests[2].target, "/events/search");
    assert_eq!(
        requests[1].header("authorization"),
        Some("Bearer synthetic-opencrvs-token")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[1].body).expect("source request body"),
        serde_json::json!({
            "query": {
                "type": "and",
                "clauses": [{
                    "eventType": "birth",
                    "status": {"type": "exact", "term": "REGISTERED"},
                    "trackingId": {"type": "exact", "term": "EVT-SYNTHETIC-001"}
                }]
            },
            "limit": 2,
            "offset": 0
        })
    );
}
