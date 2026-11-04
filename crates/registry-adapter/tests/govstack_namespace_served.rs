// SPDX-License-Identifier: Apache-2.0

//! Public namespace acceptance for the built-in GovStack Consultation host.
//! The protocol is mounted below `/govstack/registries`; its OpenAPI keeps
//! standard relative `/v1` paths and identifies that public base with
//! `servers.url`. Generic authored profiles keep their existing paths. Needs
//! `ADAPTER_TEST_DATABASE_URL`.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, fixture, Served};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MOUNT: &str = "/govstack/registries";
const CAPABILITIES: &str = "/govstack/registries/v1/capabilities";
const RETRIEVE: &str = "/govstack/registries/v1/collections/people/records/EeBJ3Sn9uLg";
const LOOKUP: &str = "/govstack/registries/v1/collections/people/lookup";
const LIST: &str = "/govstack/registries/v1/collections/people/records?pageSize=5";
const SEARCH: &str = "/govstack/registries/v1/collections/people/search";

fn project() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/dhis2-consultation")
}

fn found() -> Response {
    let (status, body) = capture("get-found");
    Response::json(status, &body)
}

fn page() -> Response {
    let document = fixture("search-page");
    Response::json(
        document["entries"][0]["upstream"][0]["response"]["status"]
            .as_u64()
            .expect("the fixture status") as u16,
        &document["entries"][0]["upstream"][0]["response"]["body"].to_string(),
    )
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn lookup_body() -> Value {
    json!({
        "selector": "by-record-id",
        "values": {"record-id": "EeBJ3Sn9uLg"}
    })
}

fn search_body() -> Value {
    json!({
        "search": "by-org-unit",
        "criteria": {"org-unit": "slSrf7H9lMf"},
        "pageSize": 5
    })
}

#[tokio::test]
async fn builtin_discovery_and_reads_live_only_under_the_public_mount() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![found(), found(), page(), page()]);
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    let reader = served.token("records.read");

    let bare_calls = [
        served.get("/v1/capabilities", Some(&reader)),
        served.get("/v1/collections/people/records/EeBJ3Sn9uLg", Some(&reader)),
        served.post(
            "/v1/collections/people/lookup",
            Some(&reader),
            &lookup_body(),
        ),
        served.get("/v1/collections/people/records?pageSize=5", Some(&reader)),
        served.post(
            "/v1/collections/people/search",
            Some(&reader),
            &search_body(),
        ),
    ];
    for (status, _, body) in bare_calls {
        assert_eq!(status, 404, "an old bare route is not served: {body}");
        assert!(body.get("recordId").is_none(), "{body}");
        assert!(body.get("collections").is_none(), "{body}");
    }
    assert_eq!(
        upstream.request_count(),
        0,
        "old bare routes cannot reach the source"
    );

    let (status, _, body) = served.get(RETRIEVE, None);
    assert_eq!(status, 401, "the public mount authenticates first: {body}");
    let unscoped = served.token("records.write");
    let (status, _, body) = served.get(RETRIEVE, Some(&unscoped));
    assert_eq!(status, 403, "the public mount authorizes first: {body}");
    assert_eq!(
        upstream.request_count(),
        0,
        "admission refusals precede source I/O"
    );

    let (status, head, capabilities) = served.get(CAPABILITIES, Some(&reader));
    assert_eq!(status, 200, "{capabilities}");
    assert_eq!(header(&head, "cache-control"), Some("no-store"));
    assert!(capabilities["collections"].is_array(), "{capabilities}");
    assert_eq!(
        upstream.request_count(),
        0,
        "discovery performs no source I/O"
    );

    let (status, _, retrieved) = served.get(RETRIEVE, Some(&reader));
    assert_eq!(status, 200, "{retrieved}\n{}", served.stderr_text());
    assert_eq!(retrieved["recordId"], "EeBJ3Sn9uLg");

    let (status, _, looked_up) = served.post(LOOKUP, Some(&reader), &lookup_body());
    assert_eq!(status, 200, "{looked_up}");
    assert_eq!(looked_up["recordId"], "EeBJ3Sn9uLg");

    let (status, _, listed) = served.get(LIST, Some(&reader));
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["items"][0]["recordId"], "EeBJ3Sn9uLg");

    let (status, _, searched) = served.post(SEARCH, Some(&reader), &search_body());
    assert_eq!(status, 200, "{searched}");
    assert_eq!(searched["items"][0]["recordId"], "EeBJ3Sn9uLg");
    assert_eq!(upstream.request_count(), 4);
}

#[tokio::test]
async fn openapi_capabilities_and_runtime_contract_resolve_the_same_public_operations() {
    let upstream = UpstreamDouble::start();
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    let reader = served.token("records.read");

    let (status, _, capabilities) = served.get(CAPABILITIES, Some(&reader));
    assert_eq!(status, 200, "{capabilities}");
    let (status, _, runtime) = served.get(
        "/.well-known/registry-adapter/effective-contract",
        Some(&reader),
    );
    assert_eq!(status, 200, "{runtime}");

    let generated: Value = serde_json::from_slice(
        &std::fs::read(project().join("generated/openapi.json"))
            .expect("the maintained generated OpenAPI"),
    )
    .expect("the generated OpenAPI is JSON");
    assert_eq!(generated["servers"], json!([{"url": MOUNT}]));

    let mut public_paths = BTreeMap::new();
    for (relative, item) in generated["paths"].as_object().expect("OpenAPI paths") {
        assert!(
            relative.starts_with("/v1/"),
            "relative standard path: {relative}"
        );
        for method in ["get", "post", "put", "patch", "delete"] {
            let Some(operation_id) = item[method]["operationId"].as_str() else {
                continue;
            };
            let previous =
                public_paths.insert(operation_id.to_owned(), format!("{MOUNT}{relative}"));
            assert!(previous.is_none(), "duplicate operationId {operation_id}");
        }
    }
    assert_eq!(
        public_paths
            .get("getCallerCapabilities")
            .map(String::as_str),
        Some(CAPABILITIES)
    );

    let runtime_operations = runtime["contract"]["operations"]
        .as_array()
        .expect("effective operations");
    let mut discovered = BTreeSet::new();
    for collection in capabilities["collections"]
        .as_array()
        .expect("capability collections")
    {
        let collection_id = collection["collectionId"].as_str().expect("collectionId");
        for operation in collection["operations"]
            .as_array()
            .expect("capability operations")
        {
            let capability = operation["capability"].as_str().expect("capability");
            let operation_id = operation["operationId"].as_str().expect("operationId");
            assert!(discovered.insert(operation_id.to_owned()), "{operation}");
            let public_path = public_paths
                .get(operation_id)
                .unwrap_or_else(|| panic!("OpenAPI has {operation_id}"));
            let binding_id = format!("{collection_id}-{capability}");
            let effective = runtime_operations
                .iter()
                .find(|candidate| candidate["bindingId"] == binding_id)
                .unwrap_or_else(|| panic!("effective contract has {binding_id}"));
            assert_eq!(effective["path"], public_path.as_str(), "{operation_id}");
        }
    }
    let openapi_reads = public_paths
        .keys()
        .filter(|operation_id| operation_id.as_str() != "getCallerCapabilities")
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(discovered, openapi_reads);
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn capability_release_at_the_public_mount_fails_closed_with_its_audit() {
    let upstream = UpstreamDouble::start();
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    served
        .execute_sql(
            "CREATE FUNCTION deny_namespaced_capability_audit() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.operation = 'getCallerCapabilities' THEN \
             RAISE EXCEPTION 'synthetic capability audit refusal'; END IF; RETURN NEW; END $$; \
             CREATE TRIGGER deny_namespaced_capability_audit BEFORE INSERT ON adapter_journal_events \
             FOR EACH ROW EXECUTE FUNCTION deny_namespaced_capability_audit()",
        )
        .await;

    let reader = served.token("records.read");
    let (status, _, body) = served.get(CAPABILITIES, Some(&reader));

    assert_eq!(status, 500, "capabilities fail closed: {body}");
    assert!(body.get("collections").is_none(), "{body}");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_generic_profile_keeps_its_authored_path_outside_the_govstack_mount() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![found()]);
    let served = Served::start(&upstream.url("")).await;
    let reader = served.token("records.read");

    let namespaced = served.get(
        "/govstack/registries/v1/records/person/EeBJ3Sn9uLg",
        Some(&reader),
    );
    assert_eq!(
        namespaced.0, 404,
        "generic profiles do not inherit the mount"
    );
    assert_eq!(upstream.request_count(), 0);

    let (status, _, record) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&reader));
    assert_eq!(status, 200, "{record}");
    assert_eq!(record["data"]["recordIdentifier"], "EeBJ3Sn9uLg");
    assert_eq!(upstream.request_count(), 1);
}
