// SPDX-License-Identifier: Apache-2.0

//! GraphQL response-envelope and send-default regressions.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_adapter::component::graphql::GraphQlQuery;
use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{run_route, EndpointRuntime, RouteContext, RouteOutcome, RouteTable};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    AdapterRuntimeConfig, ComponentKind, Endpoint, EndpointAuthentication, EndpointBinding,
    GraphQlOperationKind, RuntimeCredential, Step,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, SecretReference, UniqueIdList, UniqueList, Url,
};
use serde_json::json;

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

fn endpoint_runtime(
    base_url: &str,
    resolver: &SecretResolver,
) -> BTreeMap<String, EndpointRuntime> {
    let binding = EndpointBinding {
        endpoint: ExternalId::new("cases").expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::StaticApiKey {
            value_ref: SecretReference::new("secret:env/GRAPHQL_REPLY_KEY")
                .expect("secret reference"),
        }),
        anonymous_https: None,
        tls_trust_profile: None,
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    };
    let endpoint = Endpoint {
        id: LocalId::new("cases").expect("endpoint id"),
        component: ComponentKind::GraphQl,
        authentication: EndpointAuthentication::StaticApiKey {
            header_name: "x-api-key".to_owned(),
        },
        attempt_timeout_milliseconds: BoundedU64::new(10_000).expect("attempt timeout"),
        maximum_response_bytes: BoundedU64::new(65_536).expect("response bound"),
        response_headers: UniqueList::new(Vec::new()).expect("response headers"),
        request_headers: UniqueList::new(Vec::new()).expect("request headers"),
        operations: Vec::new(),
        tested_versions: Vec::new(),
        query_file: Some("queries/find-cases.graphql".to_owned()),
        operation_name: Some("FindCases".to_owned()),
        variables: None,
    };
    let config = AdapterRuntimeConfig {
        id: LocalId::new("graphql-reply").expect("deployment id"),
        endpoints: UniqueIdList::new(vec![binding]).expect("bindings"),
        allowed_private_cidrs: UniqueList::new(vec![registry_adapter_core::Cidr::new(
            "192.168.0.0/16",
        )
        .expect("cidr")])
        .expect("cidrs"),
        outbound_tls: None,
        listener: serde_json::from_str(r#"{ "bind": "127.0.0.1:8080" }"#).expect("listener"),
        database: serde_json::from_str(
            r#"{
                "runtimeUrlRef": "secret:env/GRAPHQL_REPLY_DB",
                "migrationUrlRef": "secret:env/GRAPHQL_REPLY_DB"
            }"#,
        )
        .expect("database"),
        oidc: serde_json::from_str(
            r#"{ "issuer": "https://issuer.example.invalid", "audience": "graphql-reply" }"#,
        )
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![
            ExternalId::new("graphql-reply-client").expect("client")
        ])
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
    let binding = config.endpoints.iter().next().expect("binding");
    let mut runtime =
        EndpointRuntime::compile(binding, &endpoint, &config, resolver).expect("endpoint compiles");
    runtime.graphql = Some(GraphQlQuery {
        text: "query FindCases { cases { id } }".to_owned(),
        operation: Some("FindCases".to_owned()),
        kind: Some(GraphQlOperationKind::Query),
        operations: Default::default(),
        variables: None,
    });
    BTreeMap::from([("cases".to_owned(), runtime)])
}

async fn run_reply(status: u16, body: &str) -> RouteOutcome {
    let double = upstream::UpstreamDouble::start();
    double.respond_with(vec![upstream::Response::json(status, body)]);
    std::env::set_var("GRAPHQL_REPLY_KEY", "graphql-reply-key");
    let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver builds");
    let endpoints = endpoint_runtime(&double.url("/"), &resolver);
    let steps: Vec<Step> = serde_json::from_value(json!([
        {"to": {"uri": "graphql:cases"}}
    ]))
    .expect("steps parse");
    let resilience = ResilienceRuntime::compile(&steps);
    let scripts = ScriptSet::default();
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: Arc::new(BTreeMap::new()),
        maximum_upstream_calls: 2,
    };
    run_route(&context, &steps, Exchange::new("graphql-reply".to_owned())).await
}

/// A parameterless GraphQL send keeps Camel's `throwExceptionOnFailure: true`
/// default rather than silently accepting an HTTP failure.
#[tokio::test]
async fn a_parameterless_graphql_send_throws_on_http_failure_by_default() {
    let outcome = run_reply(500, r#"{"data":{"cases":[]}}"#).await;
    assert_eq!(
        outcome.result.expect_err("the status fails").class.class(),
        "upstream.http"
    );
}

/// The GraphQL response must carry `data`, `errors`, or both, and `errors`
/// must be an array. These are protocol failures, not successful null data.
#[tokio::test]
async fn malformed_graphql_envelopes_are_upstream_malformed() {
    for body in [r#"{}"#, r#"{"errors":{"message":"wrong shape"}}"#] {
        let outcome = run_reply(200, body).await;
        assert_eq!(
            outcome
                .result
                .expect_err("the envelope fails")
                .class
                .class(),
            "upstream.malformed"
        );
    }
}
