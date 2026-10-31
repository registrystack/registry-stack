// SPDX-License-Identifier: Apache-2.0

//! Cross-layer read properties for `CONCEPT.md` section 13.5. The core
//! checker discovers the lowest admitted upstream-call budget for each
//! deterministic route shape, then the real interpreter executes that
//! same route over loopback HTTP under the admitted budget. A route only
//! passes when it completes and the independently observed request count
//! stays within the checker-accepted bound.

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{
    check_servable, run_route, EndpointRuntime, RouteContext, RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    check_project, check_routes, AccessProfile, AdapterPack, AdapterProfile, AdapterProject,
    AdapterRuntimeConfig, AuditRetention, Binding, Capabilities, Cidr, ComponentKind, Endpoint,
    EndpointAuthentication, EndpointBinding, EnvelopeTemplate, ErrorClass, HttpMethod, PinnedRef,
    Problem, ProfileOperation, ProjectIdentity, RecordField, RecordFieldType, RecordType,
    RouteDefinition, RouteFrom, Step, Workspace,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::{
    BoundedU32, BoundedU64, Digest, ExternalId, LocalId, UniqueIdList, UniqueList, Url,
};
use serde_json::{json, Value};

const BUDGET_CODE: &str = "adapter.project.upstream-budget-exceeded";

fn local(value: &str) -> LocalId {
    LocalId::new(value).expect("a local id")
}

fn external(value: &str) -> ExternalId {
    ExternalId::new(value).expect("an external id")
}

fn digest() -> Digest {
    Digest::new("sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9")
        .expect("a digest")
}

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the generated steps parse")
}

fn get() -> Value {
    json!({
        "to": {
            "uri": "http:source",
            "parameters": {"httpMethod": "GET", "path": "/records"}
        }
    })
}

#[derive(Clone)]
struct RouteCase {
    name: &'static str,
    root: Vec<Step>,
    direct: Vec<(&'static str, Vec<Step>)>,
    statuses: Vec<u16>,
}

/// A fixed generated corpus. It covers addition, widest-branch choice,
/// transparent nested filters, loop and split multiplication, direct-route
/// expansion, and redelivery multiplication without duplicating the core
/// walk in this test.
fn corpus() -> Vec<RouteCase> {
    vec![
        RouteCase {
            name: "simple",
            root: steps(json!([get()])),
            direct: Vec::new(),
            statuses: vec![200],
        },
        RouteCase {
            name: "choice",
            root: steps(json!([{
                "choice": {
                    "when": [{"constant": true, "steps": [get(), get()]}],
                    "otherwise": {"steps": [get()]}
                }
            }])),
            direct: Vec::new(),
            statuses: vec![200, 200],
        },
        RouteCase {
            name: "nested-filter",
            root: steps(json!([{
                "filter": {
                    "constant": true,
                    "steps": [{
                        "filter": {"constant": true, "steps": [get(), get()]}
                    }]
                }
            }])),
            direct: Vec::new(),
            statuses: vec![200, 200],
        },
        RouteCase {
            name: "loop",
            root: steps(json!([{
                "loop": {
                    "constant": 3,
                    "maximumIterations": 3,
                    "steps": [get()]
                }
            }])),
            direct: Vec::new(),
            statuses: vec![200, 200, 200],
        },
        RouteCase {
            name: "split",
            root: steps(json!([{
                "split": {
                    "expression": {"constant": [1, 2, 3]},
                    "maximumItems": 3,
                    "steps": [get()]
                }
            }])),
            direct: Vec::new(),
            statuses: vec![200, 200, 200],
        },
        RouteCase {
            name: "direct",
            root: steps(json!([{"to": {"uri": "direct:shared"}}])),
            direct: vec![("shared", steps(json!([get(), get()])))],
            statuses: vec![200, 200],
        },
        RouteCase {
            name: "redelivery",
            root: steps(json!([
                {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                    "maximumRedeliveries": 1,
                    "retryDelaySeconds": 1
                }}}},
                get()
            ])),
            direct: Vec::new(),
            statuses: vec![500, 200],
        },
    ]
}

fn endpoint() -> Endpoint {
    Endpoint {
        id: local("source"),
        component: ComponentKind::Http,
        authentication: EndpointAuthentication::None {},
        attempt_timeout_milliseconds: BoundedU64::new(10_000).expect("attempt bound"),
        maximum_response_bytes: BoundedU64::new(65_536).expect("response bound"),
        response_headers: UniqueList::new(Vec::new()).expect("empty headers"),
        request_headers: UniqueList::new(Vec::new()).expect("empty headers"),
        operations: Vec::new(),
        tested_versions: vec!["test".to_owned()],
        query_file: None,
        operation_name: None,
        variables: None,
    }
}

fn route(id: &str, body: Vec<Step>) -> RouteDefinition {
    RouteDefinition {
        id: local(id),
        from: RouteFrom {
            uri: serde_json::from_value(json!(format!("direct:{id}"))).expect("a direct route URI"),
        },
        steps: body,
    }
}

fn pack(case: &RouteCase) -> AdapterPack {
    let mut routes = vec![route("root", case.root.clone())];
    routes.extend(case.direct.iter().map(|(id, body)| route(id, body.clone())));
    AdapterPack {
        id: local("soundness-pack"),
        version: "1".to_owned(),
        tested_versions: vec!["test".to_owned()],
        endpoints: UniqueIdList::new(vec![endpoint()]).expect("unique endpoints"),
        route_templates: UniqueIdList::new(Vec::new()).expect("empty templates"),
        routes: UniqueIdList::new(routes).expect("unique routes"),
        code_maps: UniqueIdList::new(Vec::new()).expect("empty maps"),
        scripts: UniqueList::new(Vec::new()).expect("empty scripts"),
        query_files: UniqueList::new(Vec::new()).expect("empty queries"),
        capabilities: Capabilities::default(),
    }
}

fn problem(code: &str, class: ErrorClass) -> Problem {
    Problem {
        code: external(code),
        status: BoundedU32::new(500).expect("problem status"),
        title: "the read failed".to_owned(),
        classes: UniqueList::new(vec![class]).expect("one class"),
        data_fields: None,
    }
}

fn profile() -> AdapterProfile {
    AdapterProfile {
        id: local("soundness-profile"),
        version: "1".to_owned(),
        operations: UniqueIdList::new(vec![ProfileOperation {
            id: local("records-find"),
            method: HttpMethod::Get,
            path: "/records/{type}".to_owned(),
            path_parameters: UniqueList::new(vec![local("type")]).expect("one parameter"),
            record_type_parameter: local("type"),
            record_id_parameter: None,
            success_status: BoundedU32::new(200).expect("success status"),
            request_envelope: None,
            read_only: false,
            request_maximum_bytes: None,
            response_envelope: EnvelopeTemplate(r#"{"records": {{records}}}"#.to_owned()),
            item_envelope: None,
            pagination: None,
        }])
        .expect("one operation"),
        problems: UniqueIdList::new(vec![
            problem("soundness.upstream", ErrorClass::Upstream),
            problem("soundness.breaker", ErrorClass::BreakerOpen),
            problem("soundness.throttle", ErrorClass::ThrottleRejected),
            problem("soundness.loop", ErrorClass::LoopMaximumIterationsReached),
            problem("soundness.validation", ErrorClass::Validation),
            problem("soundness.conversion", ErrorClass::ConversionUnmapped),
            problem("soundness.aggregation", ErrorClass::AggregationDuplicate),
            problem("soundness.script", ErrorClass::Script),
            problem("soundness.budget", ErrorClass::BudgetExhausted),
            problem("soundness.credential", ErrorClass::CredentialRejected),
            problem("soundness.disclosure", ErrorClass::DisclosureViolation),
            problem("soundness.egress", ErrorClass::EgressRefused),
            problem("soundness.outcome", ErrorClass::Outcome),
            problem("soundness.facade", ErrorClass::Facade),
        ])
        .expect("unique problems"),
        problem_envelope: EnvelopeTemplate(r#"{"code":"{{problemCode}}"}"#.to_owned()),
        parameterized_parts: UniqueList::new(Vec::new()).expect("empty parts"),
    }
}

fn project(budget: u64) -> AdapterProject {
    AdapterProject {
        project: ProjectIdentity {
            id: local("soundness-project"),
            version: "1".to_owned(),
        },
        profile: PinnedRef {
            id: local("soundness-profile"),
            version: "1".to_owned(),
            digest: digest(),
        },
        pack: PinnedRef {
            id: local("soundness-pack"),
            version: "1".to_owned(),
            digest: digest(),
        },
        record_types: UniqueIdList::new(vec![RecordType {
            name: local("person"),
            fields: UniqueList::new(vec![RecordField {
                name: local("name"),
                r#type: RecordFieldType::String,
                required: true,
            }])
            .expect("one field"),
        }])
        .expect("one record type"),
        templated_routes: UniqueIdList::new(Vec::new()).expect("empty instantiations"),
        bindings: UniqueIdList::new(vec![Binding {
            id: local("find-people"),
            operation: external("records-find"),
            record_type: local("person"),
            route: external("root"),
            filters: UniqueList::new(Vec::new()).expect("empty filters"),
            maximum_upstream_calls: BoundedU64::new(budget).expect("bounded budget"),
        }])
        .expect("one binding"),
        access_profiles: UniqueIdList::new(vec![AccessProfile {
            id: local("reader"),
            scopes: UniqueList::new(vec![external("records:read")]).expect("one scope"),
            operations: UniqueList::new(vec![external("records-find")]).expect("one operation"),
            record_types: UniqueList::new(vec![local("person")]).expect("one type"),
        }])
        .expect("one access profile"),
        parameterized_parts: BTreeMap::new(),
    }
}

fn lowest_accepted_budget(profile: &AdapterProfile, pack: &AdapterPack, case: &RouteCase) -> u64 {
    for budget in 1..=64 {
        let project = project(budget);
        let route_findings = check_routes(pack, &project);
        assert!(
            route_findings.is_empty(),
            "{} route is invalid: {route_findings:?}",
            case.name
        );
        for route in &pack.routes {
            check_servable(&route.steps)
                .unwrap_or_else(|fault| panic!("{} is not servable: {fault}", case.name));
        }
        let findings = check_project(&Workspace {
            profile,
            pack,
            project: &project,
            runtime: None,
            fixtures: &[],
        });
        let budget_refused = findings
            .iter()
            .any(|finding| finding.code.as_str() == BUDGET_CODE);
        let unrelated: Vec<_> = findings
            .iter()
            .filter(|finding| finding.code.as_str() != BUDGET_CODE)
            .collect();
        assert!(
            unrelated.is_empty(),
            "{} has unrelated project findings: {unrelated:?}",
            case.name
        );
        if !budget_refused {
            return budget;
        }
    }
    panic!("{} has no admitted budget in the bounded probe", case.name)
}

fn runtime_config(base_url: &str) -> AdapterRuntimeConfig {
    AdapterRuntimeConfig {
        id: local("soundness-runtime"),
        endpoints: UniqueIdList::new(vec![EndpointBinding {
            endpoint: external("source"),
            base_url: Url::new(base_url).expect("loopback base URL"),
            credential: None,
            tls_trust_profile: None,
            mtls_identity: None,
            attempt_timeout_milliseconds: None,
            maximum_response_bytes: None,
        }])
        .expect("one endpoint"),
        allowed_private_cidrs: UniqueList::new(vec![Cidr::new("192.168.0.0/16").expect("cidr")])
            .expect("one cidr"),
        outbound_tls: None,
        listener: serde_json::from_value(json!({"bind": "127.0.0.1:8080"})).expect("listener"),
        database: serde_json::from_value(json!({
            "runtimeUrlRef": "secret:env/READ_PROPERTY_DB",
            "migrationUrlRef": "secret:env/READ_PROPERTY_DB"
        }))
        .expect("database"),
        oidc: serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "audience": "read-properties"
        }))
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![external("read-property-client")])
            .expect("one client"),
        audit: AuditRetention {
            retention_days: BoundedU32::new(90).expect("retention"),
        },
        cursor_key_ref: None,
        previous_cursor_key_ref: None,
        cursor_ttl_seconds: None,
        idempotency: None,
    }
}

fn empty_code_maps() -> registry_adapter::scripts::CodeMaps {
    Arc::new(BTreeMap::new())
}

#[tokio::test]
async fn checker_accepted_read_budgets_bound_actual_interpreter_sends() {
    let profile = profile();
    for case in corpus() {
        let pack = pack(&case);
        let accepted = lowest_accepted_budget(&profile, &pack, &case);
        let double = upstream::UpstreamDouble::start();
        double.respond_with(
            case.statuses
                .iter()
                .map(|status| upstream::Response::json(*status, r#"{"ok":true}"#))
                .collect(),
        );

        let resolver =
            SecretResolver::new([SecretProvider::Environment], "").expect("the resolver builds");
        let config = runtime_config(&double.url("/"));
        let binding = config.endpoints.iter().next().expect("the binding");
        let runtime = EndpointRuntime::compile(binding, &endpoint(), &config, &resolver)
            .expect("the endpoint compiles");
        let endpoints = BTreeMap::from([("source".to_owned(), runtime)]);
        let routes: RouteTable = pack
            .routes
            .iter()
            .map(|route| (route.id.to_string(), Arc::new(route.steps.clone())))
            .collect();
        let scripts = ScriptSet::default();
        let resilience = ResilienceRuntime::compile(&case.root);
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: empty_code_maps(),
            maximum_upstream_calls: accepted,
        };
        let outcome = run_route(
            &context,
            &case.root,
            Exchange::new(format!("soundness-{}", case.name)),
        )
        .await;
        outcome.result.unwrap_or_else(|failure| {
            panic!(
                "{} failed under checker-accepted budget {accepted}: {}",
                case.name,
                failure.class.class()
            )
        });
        let observed = double.request_count() as u64;
        assert!(
            observed <= accepted,
            "{} observed {observed} sends above accepted budget {accepted}",
            case.name
        );
        assert_eq!(
            observed,
            case.statuses.len() as u64,
            "{} did not execute its intended transcript",
            case.name
        );
    }
}

/// The existing egress suite covers an oversized response head. This
/// complementary actual-HTTP case holds the head small and exceeds the
/// endpoint's declared body bound, proving the body is refused before a
/// partial JSON value reaches the route.
#[tokio::test]
async fn an_oversized_http_body_is_a_too_large_failure_with_no_partial_result() {
    let double = upstream::UpstreamDouble::start();
    double.respond_with(vec![upstream::Response::json(
        200,
        &json!({"payload": "x".repeat(512)}).to_string(),
    )]);
    let resolver =
        SecretResolver::new([SecretProvider::Environment], "").expect("the resolver builds");
    let config = runtime_config(&double.url("/"));
    let binding = config.endpoints.iter().next().expect("the binding");
    let mut declared = endpoint();
    declared.maximum_response_bytes = BoundedU64::new(64).expect("small response bound");
    let runtime = EndpointRuntime::compile(binding, &declared, &config, &resolver)
        .expect("the endpoint compiles");
    let endpoints = BTreeMap::from([("source".to_owned(), runtime)]);
    let scripts = ScriptSet::default();
    let resilience = ResilienceRuntime::empty();
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: empty_code_maps(),
        maximum_upstream_calls: 1,
    };
    let route = steps(json!([get()]));
    let outcome = run_route(&context, &route, Exchange::new("oversized-body".to_owned())).await;
    assert_eq!(
        outcome
            .result
            .expect_err("the body exceeds the endpoint bound")
            .class,
        ErrorClass::UpstreamTooLarge
    );
    assert_eq!(double.request_count(), 1, "the real send reached loopback");
}
