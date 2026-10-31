// SPDX-License-Identifier: Apache-2.0

//! Generated checker/interpreter properties for `CONCEPT.md` section 13.5.
//! The test asks the core checker for the lowest accepted static call bound,
//! executes that same generated route over real loopback HTTP twice, and
//! compares the resulting route bytes and observed sends.

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

use std::collections::BTreeMap;
use std::sync::Arc;

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed, TestCaseError, TestRunner};
use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{
    check_servable, run_route, EndpointRuntime, RouteContext, RouteOutcome, RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    check_project, check_routes, AccessProfile, AdapterPack, AdapterProfile, AdapterProject,
    AdapterRuntimeConfig, AuditRetention, Binding, Capabilities, Cidr, ComponentKind, Endpoint,
    EndpointAuthentication, EndpointBinding, EnvelopeTemplate, ErrorClass, HttpMethod, PinnedRef,
    Problem, ProfileOperation, ProjectIdentity, RecordField, RecordFieldType, RecordType,
    RouteDefinition, RouteFrom, RuntimeCredential, Step, Workspace,
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
    serde_json::from_value(value).expect("generated steps parse")
}

fn get() -> Value {
    json!({
        "to": {
            "uri": "http:source",
            "parameters": {"httpMethod": "GET", "path": "/records"}
        }
    })
}

#[derive(Clone, Debug)]
struct GeneratedRoute {
    prefix_sends: usize,
    first_branch_sends: usize,
    second_branch_sends: usize,
    take_first_branch: bool,
    loop_iterations: usize,
    direct_sends: usize,
    redeliveries: usize,
}

impl GeneratedRoute {
    fn root_steps(&self) -> Vec<Step> {
        let mut generated = vec![json!({
            "errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": self.redeliveries,
                "retryDelaySeconds": 1
            }}}
        })];
        generated.extend(std::iter::repeat_with(get).take(self.prefix_sends));
        generated.push(json!({
            "choice": {
                "when": [{
                    "constant": self.take_first_branch,
                    "steps": std::iter::repeat_with(get)
                        .take(self.first_branch_sends)
                        .collect::<Vec<_>>()
                }],
                "otherwise": {
                    "steps": std::iter::repeat_with(get)
                        .take(self.second_branch_sends)
                        .collect::<Vec<_>>()
                }
            }
        }));
        generated.push(json!({
            "loop": {
                "constant": self.loop_iterations,
                "maximumIterations": self.loop_iterations,
                "steps": [get()]
            }
        }));
        generated.push(json!({"to": {"uri": "direct:shared"}}));
        generated.push(get());
        steps(Value::Array(generated))
    }

    fn direct_steps(&self) -> Vec<Step> {
        steps(Value::Array(
            std::iter::repeat_with(get)
                .take(self.direct_sends)
                .collect(),
        ))
    }

    fn observed_sends(&self) -> usize {
        self.prefix_sends
            + if self.take_first_branch {
                self.first_branch_sends
            } else {
                self.second_branch_sends
            }
            + self.loop_iterations
            + self.direct_sends
            + self.redeliveries
            + 1
    }

    fn transcript(&self) -> Vec<upstream::Response> {
        let ordinary = self.observed_sends() - self.redeliveries - 1;
        let mut responses: Vec<_> = (0..ordinary)
            .map(|index| upstream::Response::json(200, &json!({"send": index}).to_string()))
            .collect();
        responses.extend(
            (0..self.redeliveries).map(|_| upstream::Response::json(500, r#"{"retry":true}"#)),
        );
        responses.push(upstream::Response::json(
            200,
            &json!({"terminal": self.observed_sends()}).to_string(),
        ));
        responses
    }
}

fn generated_route() -> impl Strategy<Value = GeneratedRoute> {
    (
        0_usize..=3,
        0_usize..=3,
        0_usize..=3,
        any::<bool>(),
        1_usize..=4,
        1_usize..=3,
        0_usize..=0,
    )
        .prop_map(
            |(
                prefix_sends,
                first_branch_sends,
                second_branch_sends,
                take_first_branch,
                loop_iterations,
                direct_sends,
                redeliveries,
            )| GeneratedRoute {
                prefix_sends,
                first_branch_sends,
                second_branch_sends,
                take_first_branch,
                loop_iterations,
                direct_sends,
                redeliveries,
            },
        )
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

fn pack(case: &GeneratedRoute) -> AdapterPack {
    AdapterPack {
        id: local("generated-pack"),
        version: "1".to_owned(),
        tested_versions: vec!["test".to_owned()],
        endpoints: UniqueIdList::new(vec![endpoint()]).expect("one endpoint"),
        route_templates: UniqueIdList::new(Vec::new()).expect("empty templates"),
        routes: UniqueIdList::new(vec![
            route("root", case.root_steps()),
            route("shared", case.direct_steps()),
        ])
        .expect("unique routes"),
        source_routes: UniqueIdList::new(Vec::new()).expect("empty source routes"),
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
        title: "generated route failure".to_owned(),
        classes: UniqueList::new(vec![class]).expect("one class"),
        data_fields: None,
    }
}

fn profile() -> AdapterProfile {
    AdapterProfile {
        id: local("generated-profile"),
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
            problem("generated.upstream", ErrorClass::Upstream),
            problem("generated.breaker", ErrorClass::BreakerOpen),
            problem("generated.throttle", ErrorClass::ThrottleRejected),
            problem("generated.loop", ErrorClass::LoopMaximumIterationsReached),
            problem("generated.validation", ErrorClass::Validation),
            problem("generated.conversion", ErrorClass::ConversionUnmapped),
            problem("generated.aggregation", ErrorClass::AggregationDuplicate),
            problem("generated.script", ErrorClass::Script),
            problem("generated.budget", ErrorClass::BudgetExhausted),
            problem("generated.credential", ErrorClass::CredentialRejected),
            problem("generated.disclosure", ErrorClass::DisclosureViolation),
            problem("generated.egress", ErrorClass::EgressRefused),
            problem("generated.outcome", ErrorClass::Outcome),
            problem("generated.facade", ErrorClass::Facade),
        ])
        .expect("unique problems"),
        problem_envelope: EnvelopeTemplate(r#"{"code":"{{problemCode}}"}"#.to_owned()),
        parameterized_parts: UniqueList::new(Vec::new()).expect("empty parts"),
    }
}

fn project(budget: u64) -> AdapterProject {
    AdapterProject {
        project: ProjectIdentity {
            id: local("generated-project"),
            version: "1".to_owned(),
        },
        profile: PinnedRef {
            id: local("generated-profile"),
            version: "1".to_owned(),
            digest: digest(),
        },
        pack: PinnedRef {
            id: local("generated-pack"),
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

fn lowest_accepted_budget(profile: &AdapterProfile, pack: &AdapterPack) -> Result<u64, String> {
    for budget in 1..=128 {
        let project = project(budget);
        let route_findings = check_routes(pack, &project);
        if !route_findings.is_empty() {
            return Err(format!("generated route is invalid: {route_findings:?}"));
        }
        for route in &pack.routes {
            check_servable(&route.steps)
                .map_err(|fault| format!("generated route is not servable: {fault}"))?;
        }
        let findings = check_project(&Workspace {
            profile,
            pack,
            project: &project,
            runtime: None,
            fixtures: &[],
        });
        let unrelated: Vec<_> = findings
            .iter()
            .filter(|finding| finding.code.as_str() != BUDGET_CODE)
            .collect();
        if !unrelated.is_empty() {
            return Err(format!(
                "generated project has unrelated findings: {unrelated:?}"
            ));
        }
        if !findings
            .iter()
            .any(|finding| finding.code.as_str() == BUDGET_CODE)
        {
            return Ok(budget);
        }
    }
    Err("generated route has no admitted budget in the bounded probe".to_owned())
}

fn runtime_config(base_url: &str) -> AdapterRuntimeConfig {
    AdapterRuntimeConfig {
        id: local("generated-runtime"),
        endpoints: UniqueIdList::new(vec![EndpointBinding {
            endpoint: external("source"),
            base_url: Url::new(base_url).expect("loopback base URL"),
            credential: Some(RuntimeCredential::None {}),
            anonymous_https: None,
            tls_trust_profile: None,
            mtls_identity: None,
            attempt_timeout_milliseconds: None,
            maximum_response_bytes: None,
        }])
        .expect("one endpoint"),
        allowed_private_cidrs: UniqueList::new(vec![
            Cidr::new("192.168.0.0/16").expect("private CIDR")
        ])
        .expect("one CIDR"),
        outbound_tls: None,
        listener: serde_json::from_value(json!({"bind": "127.0.0.1:8080"})).expect("listener"),
        database: serde_json::from_value(json!({
            "runtimeUrlRef": "secret:env/GENERATED_PROPERTY_DB",
            "migrationUrlRef": "secret:env/GENERATED_PROPERTY_DB"
        }))
        .expect("database"),
        oidc: serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "audience": "generated-properties"
        }))
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![external("generated-property-client")])
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

async fn run_once(case: &GeneratedRoute, accepted: u64) -> Result<(usize, Vec<u8>), String> {
    let source = upstream::UpstreamDouble::start();
    source.respond_with(case.transcript());
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .map_err(|fault| fault.to_string())?;
    let config = runtime_config(&source.url("/"));
    let declared = endpoint();
    let binding = config.endpoints.iter().next().expect("the binding");
    let endpoint = EndpointRuntime::compile(binding, &declared, &config, &resolver)
        .map_err(|fault| fault.to_string())?;
    let endpoints = BTreeMap::from([("source".to_owned(), endpoint)]);
    let pack = pack(case);
    let routes: RouteTable = pack
        .routes
        .iter()
        .map(|route| (route.id.to_string(), Arc::new(route.steps.clone())))
        .collect();
    let root = pack.routes.get("root").expect("root route");
    let scripts = ScriptSet::default();
    let resilience = ResilienceRuntime::compile(&root.steps);
    let code_maps = Arc::new(BTreeMap::new());
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps,
        maximum_upstream_calls: accepted,
    };
    let outcome = run_route(&context, &root.steps, Exchange::new("generated".to_owned())).await;
    let exchange = outcome.result.map_err(|failure| {
        format!(
            "generated route failed under checker-accepted budget {accepted}: {}",
            failure.class.class()
        )
    })?;
    let body = serde_json::to_vec(&exchange.message.body).map_err(|fault| fault.to_string())?;
    Ok((source.request_count(), body))
}

fn pagination_steps(page_count: usize) -> Vec<Step> {
    let page_indexes: Vec<_> = (0..page_count).collect();
    steps(json!([{
        "split": {
            "expression": {"constant": page_indexes},
            "maximumItems": page_count,
            "aggregationStrategy": {
                "type": "json-array-append",
                "from": "page",
                "into": "records",
                "uniqueBy": "id"
            },
            "steps": [
                get(),
                {"setProperty": {"name": "page", "value": {"jsonpath": "$.entries"}}}
            ]
        }
    }]))
}

async fn run_pages(pages: &[Value]) -> Result<(usize, Result<Value, ErrorClass>), String> {
    let source = upstream::UpstreamDouble::start();
    source.respond_with(
        pages
            .iter()
            .map(|page| upstream::Response::json(200, &page.to_string()))
            .collect(),
    );
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .map_err(|fault| fault.to_string())?;
    let config = runtime_config(&source.url("/"));
    let declared = endpoint();
    let binding = config.endpoints.iter().next().expect("the binding");
    let endpoint = EndpointRuntime::compile(binding, &declared, &config, &resolver)
        .map_err(|fault| fault.to_string())?;
    let endpoints = BTreeMap::from([("source".to_owned(), endpoint)]);
    let route = pagination_steps(pages.len());
    check_servable(&route).map_err(|fault| format!("pagination route is not servable: {fault}"))?;
    let scripts = ScriptSet::default();
    let resilience = ResilienceRuntime::compile(&route);
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: Arc::new(BTreeMap::new()),
        maximum_upstream_calls: pages.len() as u64,
    };
    let mut exchange = Exchange::new("generated-pagination".to_owned());
    exchange.message.body = json!({"records": []});
    let outcome = run_route(&context, &route, exchange).await;
    Ok((
        source.request_count(),
        outcome
            .result
            .map(|exchange| exchange.message.body)
            .map_err(|failure| failure.class),
    ))
}

fn split_items(raw: &[u8]) -> Vec<Value> {
    raw.iter()
        .enumerate()
        .map(|(index, outcome)| {
            json!({
                "id": format!("item-{index}"),
                "private": format!("split-private-canary-{index}"),
                "validation": *outcome == 1,
                "script": *outcome == 2,
            })
        })
        .collect()
}

fn split_route(
    items: &[Value],
    stop_on_exception: bool,
    error_threshold: Option<f64>,
    maximum_failed_records: Option<usize>,
) -> Vec<Step> {
    let mut split = json!({
        "expression": {"constant": items},
        "maximumItems": items.len(),
        "aggregationStrategy": {"type": "grouped-body"},
        "stopOnException": stop_on_exception,
        "steps": [{
            "choice": {
                "when": [
                    {
                        "jsonpath": "$.validation",
                        "steps": [{"validate": {"expression": {"constant": false}}}]
                    },
                    {
                        "jsonpath": "$.script",
                        "steps": [{
                            "throwException": {
                                "exceptionType": "script",
                                "message": "generated split failure"
                            }
                        }]
                    }
                ],
                "otherwise": {"steps": [{"setBody": {"jsonpath": "$.id"}}]}
            }
        }]
    });
    if let Some(threshold) = error_threshold {
        split["errorThreshold"] = json!(threshold);
    }
    if let Some(maximum) = maximum_failed_records {
        split["maximumFailedRecords"] = json!(maximum);
    }
    steps(json!([{"split": split}]))
}

async fn run_local_route(route: &[Step]) -> RouteOutcome {
    let endpoints = BTreeMap::new();
    let resolver =
        SecretResolver::new([SecretProvider::Environment], "").expect("the resolver builds");
    let scripts = ScriptSet::default();
    let resilience = ResilienceRuntime::compile(route);
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: Arc::new(BTreeMap::new()),
        maximum_upstream_calls: 1,
    };
    run_route(&context, route, Exchange::new("generated-split".to_owned())).await
}

fn failure_class(outcome: u8) -> Option<ErrorClass> {
    match outcome {
        1 => Some(ErrorClass::Validation),
        2 => Some(ErrorClass::Script),
        _ => None,
    }
}

fn class_name(class: ErrorClass) -> Value {
    json!({"source": "split", "class": class.class()})
}

fn generated_split_outcomes() -> impl Strategy<Value = (Vec<u8>, u8)> {
    (prop::collection::vec(0_u8..3, 2..=8), any::<u8>()).prop_map(
        |(mut outcomes, abort_selector)| {
            outcomes[0] = 0;
            if outcomes[1..].iter().all(|outcome| *outcome == 0) {
                let last = outcomes.len() - 1;
                outcomes[last] = 1;
            }
            (outcomes, abort_selector)
        },
    )
}

#[test]
fn generated_checker_bounds_hold_and_transcripts_are_deterministic() {
    let config = ProptestConfig {
        cases: 64,
        rng_seed: RngSeed::Fixed(0x1305_b0ad_5eed),
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "crates/registry-adapter/proptest-regressions/generated_route_properties.txt",
        ))),
        source_file: Some(file!()),
        ..ProptestConfig::default()
    };
    let mut runner = TestRunner::new(config);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    runner
        .run(&generated_route(), |case| {
            let pack = pack(&case);
            let accepted =
                lowest_accepted_budget(&profile(), &pack).map_err(TestCaseError::fail)?;
            let expected = case.observed_sends();
            let first = runtime
                .block_on(run_once(&case, accepted))
                .map_err(TestCaseError::fail)?;
            let second = runtime
                .block_on(run_once(&case, accepted))
                .map_err(TestCaseError::fail)?;
            prop_assert!(first.0 as u64 <= accepted);
            prop_assert_eq!(first.0, expected);
            prop_assert_eq!(second.0, expected);
            prop_assert_eq!(first.1, second.1);
            Ok(())
        })
        .expect("generated route property");
}

#[test]
fn generated_pagination_converges_or_refuses_page_drift() {
    let config = ProptestConfig {
        cases: 64,
        rng_seed: RngSeed::Fixed(0x1305_9a9e_cafe),
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "crates/registry-adapter/proptest-regressions/generated_route_properties.txt",
        ))),
        source_file: Some(file!()),
        ..ProptestConfig::default()
    };
    let mut runner = TestRunner::new(config);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    runner
        .run(&prop::collection::vec(0_usize..=3, 1..=5), |sizes| {
            let mut next_id = 0_usize;
            let pages: Vec<_> = sizes
                .iter()
                .map(|size| {
                    let entries: Vec<_> = (0..*size)
                        .map(|_| {
                            let entry = json!({"id": format!("record-{next_id}")});
                            next_id += 1;
                            entry
                        })
                        .collect();
                    json!({"entries": entries})
                })
                .collect();
            let expected: Vec<_> = (0..next_id)
                .map(|index| json!({"id": format!("record-{index}")}))
                .collect();
            let (observed, result) = runtime
                .block_on(run_pages(&pages))
                .map_err(TestCaseError::fail)?;
            prop_assert_eq!(observed, pages.len());
            prop_assert_eq!(
                result.map_err(|class| class.class()),
                Ok(json!({"records": expected}))
            );

            // The same generated page count carries a concrete drift
            // counterexample: the first record appears again on the last
            // page. The real uniqueBy aggregation must fail before release.
            let mut drifted: Vec<_> = (0..pages.len())
                .map(|index| json!({"entries": [{"id": format!("unique-{index}")}]}))
                .collect();
            drifted[0] = json!({"entries": [{"id": "repeated"}]});
            drifted.push(json!({"entries": [{"id": "repeated"}]}));
            let (observed, result) = runtime
                .block_on(run_pages(&drifted))
                .map_err(TestCaseError::fail)?;
            prop_assert!(observed <= drifted.len());
            prop_assert_eq!(
                result.expect_err("page drift must fail"),
                ErrorClass::AggregationDuplicate
            );
            Ok(())
        })
        .expect("generated pagination property");
}

#[test]
fn generated_split_accounting_is_complete_or_stops_at_the_declared_failure() {
    let config = ProptestConfig {
        cases: 96,
        rng_seed: RngSeed::Fixed(0x1305_5a11_acc0),
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "crates/registry-adapter/proptest-regressions/generated_route_properties.txt",
        ))),
        source_file: Some(file!()),
        ..ProptestConfig::default()
    };
    let mut runner = TestRunner::new(config);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    runner
        .run(&generated_split_outcomes(), |(outcomes, abort_selector)| {
            let items = split_items(&outcomes);
            let failures: Vec<_> = outcomes
                .iter()
                .filter_map(|outcome| failure_class(*outcome))
                .collect();
            let maximum_prefix_ratio = outcomes
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let failed = outcomes[..=index]
                        .iter()
                        .filter(|outcome| failure_class(**outcome).is_some())
                        .count();
                    failed as f64 / (index + 1) as f64
                })
                .fold(0.0_f64, f64::max);
            let completing_threshold = maximum_prefix_ratio + (1.0 - maximum_prefix_ratio) / 2.0;
            let route = split_route(
                &items,
                false,
                Some(completing_threshold),
                Some(failures.len() + 1),
            );
            let completed = runtime.block_on(run_local_route(&route));
            let consumed: Vec<_> = completed
                .events
                .iter()
                .filter(|event| event.kind == "exchangeFailureHandled")
                .map(|event| event.detail.clone())
                .collect();
            let expected_consumed: Vec<_> = failures.iter().copied().map(class_name).collect();
            prop_assert_eq!(&consumed, &expected_consumed);
            prop_assert!(!Value::Array(consumed)
                .to_string()
                .contains("split-private-canary"));
            let exchange = completed
                .result
                .map_err(|failure| TestCaseError::fail(failure.class.class()))?;
            let successful_ids: Vec<_> = outcomes
                .iter()
                .enumerate()
                .filter(|(_, outcome)| failure_class(**outcome).is_none())
                .map(|(index, _)| Value::String(format!("item-{index}")))
                .collect();
            prop_assert_eq!(&exchange.message.body, &Value::Array(successful_ids));
            prop_assert_eq!(
                exchange.property("CamelSplitResult"),
                Some(&json!({
                    "totalItems": outcomes.len(),
                    "processedItems": outcomes.len(),
                    "failureCount": failures.len(),
                }))
            );

            let first_failure = outcomes
                .iter()
                .position(|outcome| failure_class(*outcome).is_some())
                .expect("the generator supplies a failure");
            let expected_terminal = failure_class(outcomes[first_failure]).expect("a class");
            let stopped = runtime.block_on(run_local_route(&split_route(&items, true, None, None)));
            let stopped_failure = stopped.result.expect_err("stopOnException fails");
            prop_assert_eq!(stopped_failure.class, expected_terminal);
            prop_assert!(!stopped_failure
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("split-private-canary"));
            prop_assert!(stopped.events.is_empty());

            let abort_after = usize::from(abort_selector) % failures.len() + 1;
            let aborted = runtime.block_on(run_local_route(&split_route(
                &items,
                false,
                None,
                Some(abort_after),
            )));
            let terminal_failure = aborted.result.expect_err("the threshold aborts");
            prop_assert_eq!(terminal_failure.class, failures[abort_after - 1]);
            let expected_prefix: Vec<_> = failures[..abort_after - 1]
                .iter()
                .copied()
                .map(class_name)
                .collect();
            let completed_prefix: Vec<_> = aborted
                .events
                .iter()
                .filter(|event| event.kind == "exchangeFailureHandled")
                .map(|event| event.detail.clone())
                .collect();
            prop_assert_eq!(completed_prefix, expected_prefix);
            prop_assert!(aborted
                .events
                .iter()
                .all(|event| !event.detail.to_string().contains("split-private-canary")));
            Ok(())
        })
        .expect("generated split-accounting property");
}
