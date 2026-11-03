//! Exact declared lookup Problems are classified before provider scripts.
use std::{fs, path::PathBuf, sync::Arc};

use registry_adapter_core::{AdapterPack, EvidenceConnectionPolicy};
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{
        compile_evidence_pack_with_protocols, EvidenceAcquisitionIntent, EvidenceHookFuture,
        EvidenceHostHooks, EvidenceLimits, EvidenceLookup, EvidenceRuntimeBindings,
    },
    host_protocol::HostAccessAttribution,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const TYPE_URI: &str = "https://id.example.invalid/problems/lookup/unresolved";
const EXACT: &str = r#"{"type":"https://id.example.invalid/problems/lookup/unresolved","title":"Unresolved","status":404,"detail":"synthetic-private-detail","code":"lookup.unresolved","traceId":"synthetic-private-trace"}"#;

struct Intent;
impl EvidenceHostHooks for Intent {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn fixture(logged: bool, post: bool) -> (AdapterPack, PackArtifactBytes) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples/standalone/adapter-packs/synthetic-register");
    let mut value: Value =
        serde_json::from_slice(&fs::read(root.join("pack.yaml")).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("apiVersion");
    value.as_object_mut().unwrap().remove("kind");
    let config = serde_json::to_vec(&json!({
        "unresolvedProblem":{"status":404,"type":TYPE_URI,"code":"lookup.unresolved"},
        "forwardAccessAttribution":logged
    }))
    .unwrap();
    value["endpoints"][0]["hostProtocol"] = json!({
        "id":"registry-lookup-v1", "config":{"path":"protocols/lookup.json",
            "digest":registry_platform_config::sha256_uri(&config)}
    });
    value["endpoints"][0]["authentication"] = json!({"type":"none"});
    value["endpoints"][0]["maximumResponseBytes"] = json!(65536);
    value["endpoints"][0]["responseHeaders"] = json!(["x-lookup-private"]);
    value["endpoints"][0]["operations"] = json!([{"id":"lookup","safeUpstream":true}]);
    let script = br#"fn person(exchange) {
        if exchange.headers["camelhttpresponsecode"] == 404 {
            if exchange.headers["x-lookup-private"] != () { throw "problem-header-escaped"; }
            return exchange.body;
        }
        if exchange.headers["x-lookup-private"] != "synthetic-private-header" {
            throw "ordinary-success-header-lost";
        }
        #{lookup: "matched", facts: #{"birth-date": "1980-01-01",
            "residence-region": "north", "address-canary": "synthetic"}}
    }"#
    .to_vec();
    value["scripts"][0]["digest"] = json!(registry_platform_config::sha256_uri(&script));
    let mut parameters = json!({"httpMethod":if post {"POST"} else {"GET"},
        "path":"/lookup", "operation":"lookup", "throwExceptionOnFailure":false});
    if post {
        parameters["body"] = json!({"jsonpath":"$"});
    }
    value["sourceRoutes"] = json!([{
        "id":"person", "evidence":value["sourceRoutes"][0]["evidence"].clone(),
        "steps":[{"to":{"uri":"http:register","parameters":parameters}},
            {"setBody":{"rhai":{"file":"scripts/lookup.rhai","entrypoint":"person"}}}]
    }]);
    let pack: AdapterPack = serde_json::from_value(value).unwrap();
    let mut files = vec![("protocols/lookup.json".to_owned(), config)];
    for pin in pack.pinned_files() {
        if pin.path == "protocols/lookup.json" {
            continue;
        }
        let bytes = if pin.path == "scripts/lookup.rhai" {
            script.clone()
        } else {
            fs::read(root.join(&pin.path)).unwrap()
        };
        files.push((pin.path.clone(), bytes));
    }
    (pack, PackArtifactBytes::new(files))
}

async fn execute_case(
    body: &str,
    media: &str,
    status: u16,
    logged: bool,
    post: bool,
) -> Result<EvidenceLookup, String> {
    let server = MockServer::start().await;
    Mock::given(method(if post { "POST" } else { "GET" }))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(status)
                .set_body_raw(body, media)
                .insert_header("x-lookup-private", "synthetic-private-header"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (pack, artifacts) = fixture(logged, post);
    let checked = compile_evidence_pack_with_protocols(
        &pack,
        "person",
        &artifacts,
        EvidenceLimits::default(),
        &registry_evidence::host_protocol::registry().unwrap(),
    )
    .expect("reviewed lookup protocol compiles");
    let runtime = EvidenceRuntimeBindings::new(
        serde_json::from_value(json!({
            "id":"local", "endpoints":[{"endpoint":"register","baseUrl":server.uri(),
                "credential":{"type":"none"}}], "allowedPrivateCidrs":[]
        }))
        .unwrap(),
        SecretResolver::new([SecretProvider::Environment], "").unwrap(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"register", "baseUrl":server.uri(), "clientIdentity":"forbidden",
        "authentication":{"type":"none"}
    }))
    .unwrap();
    let program = checked
        .bind_live(&runtime, Some("local"), &[policy])
        .unwrap();
    assert_eq!(program.requires_access_attribution(), logged);
    if logged {
        let missing = program.begin_acquisition(Arc::new(Intent)).await.unwrap();
        assert!(program
            .execute(&missing, json!({"recordId":"0007"}))
            .await
            .is_err());
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "missing trusted attribution refuses before a source effect"
        );
    }

    let acquisition = if logged {
        program
            .begin_acquisition_with_attribution(
                Arc::new(Intent),
                Arc::new(
                    HostAccessAttribution::try_new("verified-requester", "eligibility").unwrap(),
                ),
            )
            .await
            .unwrap()
    } else {
        program.begin_acquisition(Arc::new(Intent)).await.unwrap()
    };
    let result = program
        .execute(&acquisition, json!({"recordId":"0007"}))
        .await
        .map_err(|error| format!("{error:?}"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "one data operation per case");
    if post {
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            json!({"recordId":"0007"})
        );
    } else {
        assert!(requests[0].body.is_empty(), "GET keeps body absence");
    }
    assert_eq!(
        requests[0]
            .headers
            .contains_key("registry-access-requester"),
        logged
    );
    assert_eq!(
        requests[0].headers.contains_key("registry-access-purpose"),
        logged
    );
    assert!(requests[0].url.query().is_none());
    let rendered = format!("{result:?}");
    for canary in [
        "synthetic-private-detail",
        "synthetic-private-trace",
        "verified-requester",
    ] {
        assert!(!rendered.contains(canary));
    }
    server.verify().await;
    result
}

#[tokio::test]
async fn exact_problem_is_data_free_for_get_and_post_with_optional_host_attribution() {
    for logged in [false, true] {
        for post in [false, true] {
            assert_eq!(
                execute_case(EXACT, "application/problem+json", 404, logged, post).await,
                Ok(EvidenceLookup::Unresolved)
            );
        }
    }
}

#[tokio::test]
async fn additive_members_and_media_type_parameters_do_not_defeat_the_exact_tuple() {
    let extended = EXACT.replace(
        "synthetic-private-trace\"",
        "synthetic-private-trace\",\"instance\":\"/lookups/1\"",
    );
    assert_ne!(extended, EXACT);
    for (body, media) in [
        (extended.as_str(), "application/problem+json"),
        (EXACT, "application/problem+json; charset=utf-8"),
        (EXACT, "Application/Problem+JSON"),
    ] {
        assert_eq!(
            execute_case(body, media, 404, false, false).await,
            Ok(EvidenceLookup::Unresolved),
            "media: {media}"
        );
    }
}

#[tokio::test]
async fn malformed_or_mismatched_problems_cannot_become_unavailable_information() {
    let cases = [
        (EXACT.to_owned(), "application/json", 404),
        (
            EXACT.replace(TYPE_URI, "https://id.example.invalid/problems/other"),
            "application/problem+json",
            404,
        ),
        (
            EXACT.replace("lookup.unresolved", "lookup.denied"),
            "application/problem+json",
            404,
        ),
        (
            EXACT.replace("\"status\":404", "\"status\":400"),
            "application/problem+json",
            404,
        ),
        (
            EXACT.replace("\"status\":404", "\"status\":404,\"status\":404"),
            "application/problem+json",
            404,
        ),
        (
            EXACT.replace(",\"traceId\":\"synthetic-private-trace\"", ""),
            "application/problem+json",
            404,
        ),
        (
            EXACT.replace("\"traceId\":\"synthetic-private-trace\"", "\"traceId\":7"),
            "application/problem+json",
            404,
        ),
        (EXACT.to_owned(), "application/problem+json", 503),
        (
            EXACT.replace("synthetic-private-detail", &"x".repeat(65536)),
            "application/problem+json",
            404,
        ),
    ];
    for (body, media, status) in cases {
        assert!(
            execute_case(&body, media, status, false, false)
                .await
                .is_err(),
            "invalid Problem is a protocol/dependency failure"
        );
    }
}

#[tokio::test]
async fn ordinary_success_remains_json_and_malformed_success_cannot_run_provider_scripts() {
    assert!(matches!(
        execute_case("{}", "application/json", 200, false, false).await,
        Ok(EvidenceLookup::Matched { .. })
    ));
    for (body, media) in [
        ("{}", "text/plain"),
        ("not-json", "application/json"),
        (r#"{"a":1,"a":2}"#, "application/json"),
    ] {
        assert!(execute_case(body, media, 200, false, false).await.is_err());
    }
}
