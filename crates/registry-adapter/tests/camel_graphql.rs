// SPDX-License-Identifier: Apache-2.0

//! The `graphql` conformance suite, port-table row 12
//! (`products/adapter/CONCEPT.md` section 8.8): one endpoint carries one
//! digest-pinned query file, one operation name, and one variables
//! expression; a send posts the query text with the operation name and
//! the evaluated variables over the same transport as `http`, the
//! reply's `data` member becomes the body, and a GraphQL `errors` array
//! fails the exchange with the declared detail only.

use std::collections::BTreeMap;

use registry_adapter::component::graphql::{GraphQlLoadError, GraphQlQuery};
use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{
    check_servable, run_route, EndpointRuntime, RouteContext, RouteFailure, RouteOutcome,
    RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    AdapterPack, AdapterRuntimeConfig, ComponentKind, Endpoint, EndpointAuthentication,
    EndpointBinding, EndpointOperation, Expression, GraphQlOperationKind, RuntimeCredential, Step,
};
use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use registry_platform_yaml::{
    BoundedU64, Digest, ExternalId, LocalId, SecretReference, UniqueIdList, UniqueList, Url,
};
use serde_json::{json, Value};

/// The empty code-map table: no test lane here converts.
fn empty_code_maps() -> registry_adapter::scripts::CodeMaps {
    std::sync::Arc::new(std::collections::BTreeMap::new())
}

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

const QUERY: &str = "query FindCases($limit: Int) { cases(first: $limit) { id } }";

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

/// One graphql endpoint over the loopback double, the static-api-key
/// shape over the pinned query the lane names.
fn graphql_endpoints(
    base_url: &str,
    resolver: &SecretResolver,
    query: Option<GraphQlQuery>,
) -> BTreeMap<String, EndpointRuntime> {
    let binding = EndpointBinding {
        endpoint: ExternalId::new("cases").expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::StaticApiKey {
            value_ref: SecretReference::new("secret:env/GRAPHQL_KEY").expect("secret reference"),
        }),
        tls_trust_profile: None,
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    };
    let endpoint = declared_endpoint();
    let config = AdapterRuntimeConfig {
        id: LocalId::new("graphql").expect("deployment id"),
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
                "runtimeUrlRef": "secret:env/GRAPHQL_DB",
                "migrationUrlRef": "secret:env/GRAPHQL_DB"
            }"#,
        )
        .expect("database"),
        oidc: serde_json::from_str(
            r#"{ "issuer": "https://issuer.example.invalid", "audience": "graphql" }"#,
        )
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![ExternalId::new("graphql-client").expect("client")])
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
    let mut runtime = EndpointRuntime::compile(binding, &endpoint, &config, resolver)
        .expect("the endpoint compiles");
    runtime.graphql = query;
    let mut endpoints = BTreeMap::new();
    endpoints.insert("cases".to_owned(), runtime);
    endpoints
}

/// The declared endpoint the pack shape names: the pinned query file,
/// the operation name, and the variables expression.
fn declared_endpoint() -> Endpoint {
    Endpoint {
        id: LocalId::new("cases").expect("endpoint id"),
        component: ComponentKind::GraphQl,
        authentication: EndpointAuthentication::StaticApiKey {
            header_name: "x-api-key".to_owned(),
        },
        attempt_timeout_milliseconds: BoundedU64::new(10_000).expect("attempt timeout"),
        maximum_response_bytes: BoundedU64::new(65_536).expect("response bound"),
        response_headers: UniqueList::new(Vec::new()).expect("response headers"),
        request_headers: UniqueList::new(Vec::new()).expect("request headers"),
        operations: vec![EndpointOperation {
            id: LocalId::new("cases-query").expect("operation id"),
            idempotent_upstream: false,
            safe_upstream: false,
            graphql: Some(GraphQlOperationKind::Query),
        }],
        tested_versions: Vec::new(),
        query_file: Some("queries/find-cases.graphql".to_owned()),
        operation_name: Some("FindCases".to_owned()),
        variables: None,
    }
}

/// One pinned query for the lane.
fn pinned_query(variables: Option<Expression>) -> GraphQlQuery {
    GraphQlQuery {
        text: QUERY.to_owned(),
        operation: Some("FindCases".to_owned()),
        kind: Some(GraphQlOperationKind::Query),
        operations: ["cases-query".to_owned()].into_iter().collect(),
        variables,
    }
}

/// One lane: the double, one graphql endpoint over it, and the route
/// steps under test.
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
    fn over(main: Value, query: Option<GraphQlQuery>) -> Self {
        let double = upstream::UpstreamDouble::start();
        std::env::set_var("GRAPHQL_KEY", "graphql-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "")
            .expect("the environment resolver builds");
        let endpoints = graphql_endpoints(&double.url("/"), &resolver, query);
        let steps = steps(main);
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

    fn reply(&self, body: &str) {
        self.double
            .respond_with(vec![upstream::Response::json(200, body)]);
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
        run_route(&context, &self.steps, Exchange::new("graphql".to_owned())).await
    }

    fn request(&self) -> (String, String, Value) {
        let requests = self.double.requests();
        assert_eq!(requests.len(), 1, "exactly one send reached the double");
        let request = &requests[0];
        let body = serde_json::from_slice(&request.body).expect("the request body is JSON");
        (request.method.clone(), request.target.clone(), body)
    }

    fn requests(&self) -> usize {
        self.double.request_count()
    }
}

fn failed(outcome: &RouteOutcome) -> &RouteFailure {
    outcome.result.as_ref().expect_err("the exchange fails")
}

fn failed_class(outcome: &RouteOutcome) -> &'static str {
    failed(outcome).class.class()
}

fn ok(outcome: &RouteOutcome) -> &registry_adapter::exchange::Exchange {
    outcome.result.as_ref().expect("the exchange completes")
}

fn sending_method(outcome: &RouteOutcome) -> &str {
    outcome
        .events
        .iter()
        .find(|event| event.kind == "exchangeSending")
        .and_then(|event| event.detail.get("method"))
        .and_then(Value::as_str)
        .expect("the sending event carries its method")
}

#[tokio::test]
async fn a_send_posts_the_pinned_query_with_its_operation_and_variables() {
    // The endpoint declares its own variables; the send's body member
    // overrides them for that send (section 8.8).
    let lane = Lane::over(
        json!([{"to": {
            "uri": "graphql:cases",
            "parameters": {"operation": "cases-query", "body": {"constant": {"limit": 5}}}
        }}]),
        Some(pinned_query(Some(Expression::Constant(
            json!({"limit": 2}),
        )))),
    );
    lane.reply(r#"{"data": {"cases": [{"id": "c1"}]}}"#);
    let outcome = lane.run().await;
    assert_eq!(ok(&outcome).message.body, json!({"cases": [{"id": "c1"}]}));
    let (method, target, body) = lane.request();
    assert_eq!(method, "POST");
    assert_eq!(
        target, "/",
        "the document posts over the endpoint's base link"
    );
    assert_eq!(body["query"], json!(QUERY));
    assert_eq!(body["operationName"], json!("FindCases"));
    assert_eq!(body["variables"], json!({"limit": 5}));
    assert_eq!(
        lane.double.requests()[0].header("x-api-key"),
        Some("graphql-key"),
        "the endpoint's credential rides the same transport"
    );
    assert_eq!(sending_method(&outcome), "POST");
}

#[tokio::test]
async fn the_endpoints_variables_expression_answers_when_the_send_carries_no_body() {
    let lane = Lane::over(
        json!([{"to": {
            "uri": "graphql:cases",
            "parameters": {"operation": "cases-query"}
        }}]),
        Some(pinned_query(Some(Expression::Constant(
            json!({"limit": 2}),
        )))),
    );
    lane.reply(r#"{"data": {"cases": []}}"#);
    let outcome = lane.run().await;
    assert!(outcome.result.is_ok(), "the send completes");
    let (_, _, body) = lane.request();
    assert_eq!(body["variables"], json!({"limit": 2}));

    // A send without parameters at all stands on the endpoint alone, and
    // an endpoint that declares no variables sends JSON null for them.
    let lane = Lane::over(
        json!([{"to": {"uri": "graphql:cases"}}]),
        Some(pinned_query(None)),
    );
    lane.reply(r#"{"data": {"cases": []}}"#);
    let outcome = lane.run().await;
    assert!(outcome.result.is_ok(), "the bare send completes");
    let (_, _, body) = lane.request();
    assert_eq!(body["variables"], json!(null));
    assert_eq!(body["operationName"], json!("FindCases"));
}

#[tokio::test]
async fn an_errors_array_fails_the_exchange_as_upstream_http() {
    // The failure carries the declared detail only, never the source's
    // error text; the raw reply keeps its body on the exchange for a
    // clause to read (section 8.8).
    let lane = Lane::over(
        json!([
            {"onException": {
                "exception": ["upstream.http"],
                "handled": true,
                "steps": [{"setProperty": {"name": "saw", "value": {"jsonpath": "$"}}}]
            }},
            {"to": {"uri": "graphql:cases", "parameters": {"operation": "cases-query"}}}
        ]),
        Some(pinned_query(None)),
    );
    lane.reply(r#"{"errors": [{"message": "the token is expired"}]}"#);
    let outcome = lane.run().await;
    let exchange = ok(&outcome);
    assert_eq!(
        exchange.property("saw"),
        Some(&json!({
            "errors": [{"message": "the token is expired"}]
        }))
    );
    // The handled clause answers, so the failure itself is only visible
    // through its clause: assert the failure shape on a bare lane.
    let bare = Lane::over(
        json!([{"to": {"uri": "graphql:cases", "parameters": {"operation": "cases-query"}}}]),
        Some(pinned_query(None)),
    );
    bare.reply(r#"{"errors": [{"message": "the token is expired"}]}"#);
    let outcome = bare.run().await;
    let failure = failed(&outcome);
    assert_eq!(failure.class.class(), "upstream.http");
    let message = failure
        .message
        .as_deref()
        .expect("the failure names its detail");
    assert_eq!(message, "the graphql reply carries an errors array");
    assert!(
        !message.contains("expired"),
        "the source's error text never reaches the failure detail"
    );
}

#[tokio::test]
async fn partial_data_with_errors_still_fails_the_exchange() {
    // Camel leaves the partial data in the body; here the exchange fails
    // and the reply stays whole on the exchange (section 8.8).
    let lane = Lane::over(
        json!([
            {"onException": {
                "exception": ["upstream.http"],
                "handled": true,
                "steps": [{"setProperty": {"name": "saw", "value": {"jsonpath": "$.data"}}}]
            }},
            {"to": {"uri": "graphql:cases", "parameters": {"operation": "cases-query"}}}
        ]),
        Some(pinned_query(None)),
    );
    lane.reply(r#"{"data": {"cases": []}, "errors": [{"message": "x"}]}"#);
    let outcome = lane.run().await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.property("saw"), Some(&json!({"cases": []})));
}

#[tokio::test]
async fn variables_that_yield_no_object_fail_as_validation() {
    let lane = Lane::over(
        json!([{"to": {
            "uri": "graphql:cases",
            "parameters": {"operation": "cases-query", "body": {"constant": [1, 2]}}
        }}]),
        Some(pinned_query(None)),
    );
    lane.reply(r#"{"data": null}"#);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "validation");
    assert!(
        failed(&outcome)
            .message
            .as_deref()
            .is_some_and(|message| message.contains("variables")),
        "the failure names the variables: {:?}",
        failed(&outcome).message
    );
    assert_eq!(lane.requests(), 0, "nothing was sent");
}

#[tokio::test]
async fn a_graphql_send_to_an_endpoint_without_a_query_is_refused() {
    // An endpoint a caller assembled without the loader holds no pinned
    // query; the engine refuses the send rather than posting without one.
    let lane = Lane::over(
        json!([{"to": {"uri": "graphql:cases", "parameters": {"operation": "cases-query"}}}]),
        None,
    );
    lane.reply(r#"{"data": null}"#);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "egress.refused");
    assert_eq!(lane.requests(), 0);
}

#[tokio::test]
async fn a_graphql_send_naming_an_operation_outside_the_pinned_endpoint_is_refused() {
    let lane = Lane::over(
        json!([{"to": {
            "uri": "graphql:cases",
            "parameters": {"operation": "different-query"}
        }}]),
        Some(pinned_query(None)),
    );
    lane.reply(r#"{"data": null}"#);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "egress.refused");
    assert_eq!(lane.requests(), 0, "the operation guard runs before egress");
}

/// The graphql shape carries `operation` and `body` only: no address
/// members, no method of its own, no status range of its own, and no
/// resume bindings this runtime serves (section 8.8).
#[test]
fn the_graphql_send_shape_carries_operation_and_body_only() {
    for member in [
        json!({"httpMethod": "GET", "path": "/cases"}),
        json!({"httpUri": {"constant": "http://source.example/cases"}}),
        json!({"query": {"limit": {"constant": 5}}}),
        json!({"pathParameters": {"id": {"constant": "c1"}}}),
        json!({"okStatusCodeRange": "200-299"}),
        json!({"resumeBindings": [{"name": "resume-at", "path": "$.id"}]}),
    ] {
        let refusal = check_servable(&steps(json!([{"to": {
            "uri": "graphql:cases",
            "parameters": member
        }}])))
        .expect_err("the member is not served on a graphql send");
        assert!(
            refusal.contains("graphql"),
            "the refusal names the graphql form: {refusal}"
        );
    }
    check_servable(&steps(json!([{"to": {"uri": "graphql:cases"}}])))
        .expect("a bare graphql send is served");
    check_servable(&steps(json!([{"to": {
        "uri": "graphql:cases",
        "parameters": {"operation": "cases-query", "body": {"constant": {"limit": 5}}}
    }}])))
    .expect("operation and body are served");
}

/// One pack whose inventory pins the lane's query file, over a scratch
/// directory that holds the file itself.
fn pack_pinning(directory: &std::path::Path, text: &str, path: &str) -> AdapterPack {
    std::fs::create_dir_all(directory.join("queries")).expect("the query directory");
    std::fs::write(directory.join(path), text).expect("write the query file");
    let bytes = std::fs::read(directory.join(path)).expect("read the query file back");
    AdapterPack {
        id: LocalId::new("case-api-pack").expect("pack id"),
        version: "1".to_owned(),
        tested_versions: Vec::new(),
        endpoints: UniqueIdList::new(Vec::new()).expect("empty"),
        route_templates: UniqueIdList::new(Vec::new()).expect("empty"),
        routes: UniqueIdList::new(Vec::new()).expect("empty"),
        code_maps: UniqueIdList::new(Vec::new()).expect("empty"),
        scripts: UniqueList::new(Vec::new()).expect("empty"),
        query_files: UniqueList::new(vec![registry_adapter_core::ScriptReference {
            path: path.to_owned(),
            digest: Digest::new(sha256_uri(&bytes)).expect("the digest parses"),
        }])
        .expect("unique"),
        capabilities: registry_adapter_core::Capabilities::default(),
    }
}

/// The loader's own line, beside `adapterctl verify`: the query file is
/// digest-pinned, inventoried, text, under the bound, and declares the
/// named operation.
#[test]
fn the_loader_holds_the_query_files_own_line() {
    let directory = tempfile::tempdir().expect("a scratch directory");
    let pack = pack_pinning(directory.path(), QUERY, "queries/find-cases.graphql");
    let endpoint = declared_endpoint();
    let query =
        GraphQlQuery::load(&pack, directory.path(), &endpoint).expect("the pinned query loads");
    assert_eq!(query.text, QUERY);
    assert_eq!(query.operation.as_deref(), Some("FindCases"));
    assert_eq!(query.kind, Some(GraphQlOperationKind::Query));
    assert!(query.accepts_operation(Some(&ExternalId::new("cases-query").expect("operation"))));
    assert!(!query.accepts_operation(Some(
        &ExternalId::new("different-query").expect("operation")
    )));

    let mutation_text = QUERY.replacen("query", "mutation", 1);
    let mutation_pack = pack_pinning(
        directory.path(),
        &mutation_text,
        "queries/find-cases-mutation.graphql",
    );
    let mut mismatched = endpoint.clone();
    mismatched.query_file = Some("queries/find-cases-mutation.graphql".to_owned());
    assert!(matches!(
        GraphQlQuery::load(&mutation_pack, directory.path(), &mismatched),
        Err(GraphQlLoadError::OperationKindMismatch)
    ));

    // A digest that pins different bytes than the file holds is refused.
    let stale = AdapterPack {
        query_files: UniqueList::new(vec![registry_adapter_core::ScriptReference {
            path: "queries/find-cases.graphql".to_owned(),
            digest: Digest::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .expect("the digest parses"),
        }])
        .expect("unique"),
        ..pack.clone()
    };
    match GraphQlQuery::load(&stale, directory.path(), &endpoint) {
        Err(GraphQlLoadError::DigestMismatch(path)) => {
            assert_eq!(path, "queries/find-cases.graphql");
        }
        other => panic!("a changed file is refused by its digest: {other:?}"),
    }
    // An operation the document does not declare is refused, with both
    // names in the refusal.
    let mut renamed = endpoint.clone();
    renamed.operation_name = Some("Missing".to_owned());
    match GraphQlQuery::load(&pack, directory.path(), &renamed) {
        Err(GraphQlLoadError::UnknownOperation(path, operation)) => {
            assert_eq!(path, "queries/find-cases.graphql");
            assert_eq!(operation, "Missing");
        }
        other => panic!("an undeclared operation is refused: {other:?}"),
    }
    // A file outside the inventory, and an endpoint naming none.
    let mut bare = endpoint.clone();
    bare.query_file = Some("queries/unlisted.graphql".to_owned());
    match GraphQlQuery::load(&pack, directory.path(), &bare) {
        Err(GraphQlLoadError::NotInventoried(path)) => {
            assert_eq!(path, "queries/unlisted.graphql");
        }
        other => panic!("an unlisted file is refused: {other:?}"),
    }
    let mut none = endpoint.clone();
    none.query_file = None;
    assert!(matches!(
        GraphQlQuery::load(&pack, directory.path(), &none),
        Err(GraphQlLoadError::NotInventoried(_))
    ));
    let mut unnamed = endpoint.clone();
    unnamed.operation_name = None;
    assert!(matches!(
        GraphQlQuery::load(&pack, directory.path(), &unnamed),
        Err(GraphQlLoadError::OperationRequired)
    ));
    // A sparse file over the engine's bound is refused from metadata,
    // without allocating or reading its declared length.
    let oversized_path = directory.path().join("queries/oversized.graphql");
    std::fs::File::create(&oversized_path)
        .expect("the sparse query file is created")
        .set_len(1024 * 1024 * 1024)
        .expect("the sparse query file length is set");
    let oversized = AdapterPack {
        query_files: UniqueList::new(vec![registry_adapter_core::ScriptReference {
            path: "queries/oversized.graphql".to_owned(),
            digest: Digest::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .expect("the digest parses"),
        }])
        .expect("unique"),
        ..pack.clone()
    };
    let mut big = endpoint.clone();
    big.query_file = Some("queries/oversized.graphql".to_owned());
    match GraphQlQuery::load(&oversized, directory.path(), &big) {
        Err(GraphQlLoadError::TooLarge(_)) => {}
        other => panic!("an oversized file is refused: {other:?}"),
    }
}
