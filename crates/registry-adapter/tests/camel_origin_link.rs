// SPDX-License-Identifier: Apache-2.0

//! The origin-pinned link conformance suite, the `httpUri` form of `to`
//! (`products/adapter/CONCEPT.md` sections 8.8 and 8.11.5, port-table
//! row 15): the one dynamic send, a link the source returned, parsed
//! once, pinned to the endpoint's origin and base path, and sent as
//! parsed, never reparsed.

use std::collections::BTreeMap;

use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{
    check_servable, run_route, EndpointRuntime, RouteContext, RouteOutcome, RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    AdapterRuntimeConfig, ComponentKind, Endpoint, EndpointAuthentication, EndpointBinding,
    RuntimeCredential, Step,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, SecretReference, UniqueIdList, UniqueList, Url,
};
use serde_json::{json, Value};

/// The empty code-map table: no test lane here converts.
fn empty_code_maps() -> registry_adapter::scripts::CodeMaps {
    std::sync::Arc::new(std::collections::BTreeMap::new())
}

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

/// One endpoint over the loopback double under the base path `/base`,
/// so a link's staying under the base path is observable.
fn link_endpoints(base_url: &str, resolver: &SecretResolver) -> BTreeMap<String, EndpointRuntime> {
    let binding = EndpointBinding {
        endpoint: ExternalId::new("tracker").expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::StaticApiKey {
            value_ref: SecretReference::new("secret:env/LINK_KEY").expect("secret reference"),
        }),
        tls_trust_profile: None,
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    };
    let endpoint = Endpoint {
        id: LocalId::new("tracker").expect("endpoint id"),
        component: ComponentKind::Http,
        authentication: EndpointAuthentication::StaticApiKey {
            header_name: "x-api-key".to_owned(),
        },
        attempt_timeout_milliseconds: BoundedU64::new(10_000).expect("attempt timeout"),
        maximum_response_bytes: BoundedU64::new(65_536).expect("response bound"),
        response_headers: UniqueList::new(Vec::new()).expect("response headers"),
        request_headers: UniqueList::new(Vec::new()).expect("request headers"),
        operations: Vec::new(),
        tested_versions: Vec::new(),
        query_file: None,
        operation_name: None,
        variables: None,
    };
    let config = AdapterRuntimeConfig {
        id: LocalId::new("links").expect("deployment id"),
        endpoints: UniqueIdList::new(vec![binding]).expect("bindings"),
        allowed_private_cidrs: UniqueList::new(vec![registry_adapter_core::Cidr::new(
            "192.168.0.0/16",
        )
        .expect("cidrs")])
        .expect("cidrs"),
        outbound_tls: None,
        listener: serde_json::from_str(r#"{ "bind": "127.0.0.1:8080" }"#).expect("listener"),
        database: serde_json::from_str(
            r#"{
                "runtimeUrlRef": "secret:env/LINK_DB",
                "migrationUrlRef": "secret:env/LINK_DB"
            }"#,
        )
        .expect("database"),
        oidc: serde_json::from_str(
            r#"{ "issuer": "https://issuer.example.invalid", "audience": "links" }"#,
        )
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![ExternalId::new("links-client").expect("client")])
            .expect("clients"),
        audit: registry_adapter_core::AuditRetention {
            retention_days: registry_platform_yaml::BoundedU32::<1, 3_650>::new(90)
                .expect("retention"),
        },
        cursor_key_ref: None,
        previous_cursor_key_ref: None,
        cursor_ttl_seconds: None,
        idempotency: None,
    };
    let binding = config.endpoints.iter().next().expect("the binding");
    let runtime = EndpointRuntime::compile(binding, &endpoint, &config, resolver)
        .expect("the endpoint compiles");
    let mut endpoints = BTreeMap::new();
    endpoints.insert("tracker".to_owned(), runtime);
    endpoints
}

/// One lane whose endpoint lives under `/base` on the double. The link
/// expression is built against the lane's own base URL, so a test names
/// the double's port without knowing it.
struct Lane {
    double: upstream::UpstreamDouble,
    endpoints: BTreeMap<String, EndpointRuntime>,
    scripts: ScriptSet,
    resolver: SecretResolver,
    resilience: ResilienceRuntime,
    routes: RouteTable,
    steps: Vec<Step>,
}

impl Lane {
    fn over(expression: impl FnOnce(&str) -> Value) -> Self {
        let double = upstream::UpstreamDouble::start();
        std::env::set_var("LINK_KEY", "link-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "")
            .expect("the environment resolver builds");
        let base = double.url("/base");
        let endpoints = link_endpoints(&base, &resolver);
        let steps = steps(json!([{"to": {
            "uri": "http:tracker",
            "parameters": {"httpMethod": "GET", "httpUri": expression(&base)}
        }}]));
        let resilience = ResilienceRuntime::compile(&steps);
        Self {
            double,
            endpoints,
            scripts: ScriptSet::default(),
            resolver,
            resilience,
            routes: RouteTable::new(),
            steps,
        }
    }

    fn replies(&self, statuses: &[u16]) {
        self.double.respond_with(
            statuses
                .iter()
                .map(|status| upstream::Response::json(*status, r#"{"page": 2}"#))
                .collect(),
        );
    }

    async fn run(&self) -> RouteOutcome {
        let context = RouteContext {
            endpoints: &self.endpoints,
            scripts: &self.scripts,
            resolver: &self.resolver,
            resilience: &self.resilience,
            routes: &self.routes,
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 12,
        };
        run_route(&context, &self.steps, Exchange::new("links".to_owned())).await
    }

    fn requests(&self) -> Vec<upstream::RecordedRequest> {
        self.double.requests()
    }
}

fn failed_class(outcome: &RouteOutcome) -> &'static str {
    outcome
        .result
        .as_ref()
        .expect_err("the exchange fails")
        .class
        .class()
}

fn ok(outcome: &RouteOutcome) -> &registry_adapter::exchange::Exchange {
    outcome.result.as_ref().expect("the exchange completes")
}

#[tokio::test]
async fn an_http_uri_send_follows_the_source_link_as_written() {
    let lane = Lane::over(|base| json!({"constant": format!("{base}/things?page=2&q=a%20b")}));
    lane.replies(&[200]);
    let outcome = lane.run().await;
    assert_eq!(ok(&outcome).message.body, json!({"page": 2}));
    let requests = lane.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].target, "/base/things?page=2&q=a%20b",
        "the link is sent as written, query included"
    );
    assert_eq!(requests[0].method, "GET");
}

#[tokio::test]
async fn a_link_off_the_endpoint_origin_is_refused_without_a_send() {
    // The link names another port: same scheme and host, different
    // origin.
    let lane = Lane::over(|_| json!({"constant": "http://127.0.0.1:1/base/things"}));
    lane.replies(&[200]);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "egress.refused");
    assert!(lane.requests().is_empty());
}

#[tokio::test]
async fn a_link_on_another_host_is_refused() {
    let lane = Lane::over(|_| json!({"constant": "http://other.example.invalid/base/things"}));
    lane.replies(&[200]);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "egress.refused");
    assert!(lane.requests().is_empty());
}

#[tokio::test]
async fn a_link_outside_the_base_path_is_refused() {
    // Same origin, but under `/others`, not the endpoint's `/base`.
    let lane = Lane::over(|base| {
        let origin = base.trim_end_matches("/base");
        json!({"constant": format!("{origin}/others/things")})
    });
    lane.replies(&[200]);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "egress.refused");
    assert!(lane.requests().is_empty());
}

#[tokio::test]
async fn a_link_with_a_fragment_or_userinfo_is_refused() {
    let base = "http://127.0.0.1:9/base/things";
    for link in [
        format!("{base}#section"),
        "http://reader@127.0.0.1:9/base/things".to_owned(),
    ] {
        let lane = Lane::over(move |_| json!({"constant": link.clone()}));
        lane.replies(&[200]);
        let outcome = lane.run().await;
        assert_eq!(failed_class(&outcome), "egress.refused");
        assert!(lane.requests().is_empty());
    }
}

#[tokio::test]
async fn a_link_the_parser_would_repair_is_refused() {
    // Whitespace the parser would trim, a scheme-relative form, and a
    // dot segment are all refused rather than rewritten.
    for link in [
        "http://127.0.0.1:9/base/things \t".to_owned(),
        "//127.0.0.1:9/base/things".to_owned(),
        "http://127.0.0.1:9/base/./things".to_owned(),
    ] {
        let lane = Lane::over(move |_| json!({"constant": link.clone()}));
        lane.replies(&[200]);
        let outcome = lane.run().await;
        assert_eq!(failed_class(&outcome), "egress.refused");
        assert!(lane.requests().is_empty());
    }
}

#[tokio::test]
async fn a_non_string_link_fails_the_exchange_as_validation() {
    // No `next` header is set, so the expression yields null.
    let lane = Lane::over(|_| json!({"header": "next"}));
    lane.replies(&[200]);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "validation");
    assert!(lane.requests().is_empty());
}

#[test]
fn a_query_beside_an_http_uri_is_not_served() {
    let refusal = check_servable(&steps(json!([{"to": {
        "uri": "http:tracker",
        "parameters": {
            "httpMethod": "GET",
            "httpUri": {"header": "next"},
            "query": {"page": {"constant": 2}}
        }
    }}])))
    .expect_err("a query beside an httpUri is refused");
    assert!(
        refusal.contains("httpUri"),
        "the refusal names the link form: {refusal}"
    );
}

#[test]
fn a_path_and_an_http_uri_together_are_not_served() {
    let refusal = check_servable(&steps(json!([{"to": {
        "uri": "http:tracker",
        "parameters": {
            "httpMethod": "GET",
            "path": "/things",
            "httpUri": {"header": "next"}
        }
    }}])))
    .expect_err("both forms together are refused");
    assert!(
        refusal.contains("httpUri"),
        "the refusal names the link form: {refusal}"
    );
}
