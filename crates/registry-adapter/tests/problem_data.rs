// SPDX-License-Identifier: Apache-2.0

//! Problem data is evaluated by the route, but it crosses the facade only
//! through the selected profile problem's closed scalar declaration. Invalid
//! data fails closed as `disclosure.violation`, without retaining the value in
//! diagnostics or falling back to a partially rendered problem.

use std::collections::BTreeMap;

use axum::body::{to_bytes, Body};
use axum::http::{Response, StatusCode};
use registry_adapter::envelope::CompiledEnvelope;
use registry_adapter::exchange::Exchange;
use registry_adapter::facade::{route_problem, Problems};
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{
    run_route, run_route_with_profile, RouteContext, RouteFailure, RouteOutcome, RouteTable,
};
use registry_adapter::scripts::{CodeMaps, ScriptSet};
use registry_adapter_core::{
    AdapterProfile, EnvelopeTemplate, ErrorClass, Expression, Problem, RecordField,
    RecordFieldType, Step, ThrowExceptionStep, MAX_PROBLEM_DATA_BYTES,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::{BoundedU32, ExternalId, LocalId, UniqueIdList, UniqueList};
use serde_json::{json, Value};

fn local(value: &str) -> LocalId {
    LocalId::new(value).expect("local id")
}

fn problem(
    code: &str,
    class: ErrorClass,
    data_fields: Option<Vec<(&str, RecordFieldType)>>,
) -> Problem {
    Problem {
        code: ExternalId::new(code).expect("problem code"),
        status: BoundedU32::new(if class == ErrorClass::DisclosureViolation {
            500
        } else {
            409
        })
        .expect("problem status"),
        title: format!("{code} title"),
        classes: UniqueList::new(vec![class]).expect("one class"),
        data_fields: data_fields.map(|fields| {
            UniqueList::new(
                fields
                    .into_iter()
                    .map(|(name, r#type)| RecordField {
                        name: local(name),
                        r#type,
                        required: true,
                    })
                    .collect(),
            )
            .expect("unique fields")
        }),
    }
}

fn profile() -> AdapterProfile {
    AdapterProfile {
        id: local("problem-profile"),
        version: "1".to_owned(),
        operations: UniqueIdList::new(Vec::new()).expect("no operations"),
        problems: UniqueIdList::new(vec![
            problem(
                "cases.partial",
                ErrorClass::OutcomeRejected,
                Some(vec![
                    ("accepted", RecordFieldType::Integer),
                    ("rejected", RecordFieldType::Integer),
                ]),
            ),
            problem(
                "cases.secret",
                ErrorClass::OutcomeInvalidRequest,
                Some(vec![("secret", RecordFieldType::String)]),
            ),
            problem(
                "cases.plain",
                ErrorClass::OutcomeConflict,
                None,
            ),
            problem(
                "disclosure.violation",
                ErrorClass::DisclosureViolation,
                None,
            ),
        ])
        .expect("unique problems"),
        problem_envelope: EnvelopeTemplate(
            r#"{"code":"{{problemCode}}","title":"{{problemTitle}}","status":{{status}},"detail":"{{?problemDetail}}","data":{{?problemData}},"requestId":"{{requestId}}"}"#
                .to_owned(),
        ),
        parameterized_parts: UniqueList::new(Vec::new()).expect("no parameters"),
    }
}

fn problem_envelope(profile: &AdapterProfile) -> CompiledEnvelope {
    CompiledEnvelope::compile(profile.problem_envelope.text(), &BTreeMap::new())
        .expect("problem envelope compiles")
}

async fn body(response: Response<Body>) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("problem body fits");
    let value = serde_json::from_slice(&bytes).expect("problem body is JSON");
    (status, value)
}

async fn run(profile: Option<&AdapterProfile>, steps: &[Step]) -> RouteOutcome {
    let endpoints = BTreeMap::new();
    let scripts = ScriptSet::default();
    let resolver =
        SecretResolver::new([SecretProvider::Environment], "").expect("environment resolver");
    let resilience = ResilienceRuntime::compile(steps);
    let routes = RouteTable::new();
    let code_maps: CodeMaps = std::sync::Arc::new(BTreeMap::new());
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps,
        maximum_upstream_calls: 1,
        job: registry_adapter::job_sources::JobPageState::default(),
    };
    match profile {
        Some(profile) => {
            run_route_with_profile(
                &context,
                profile,
                steps,
                Exchange::new("problem-data".to_owned()),
            )
            .await
        }
        None => run_route(&context, steps, Exchange::new("problem-data".to_owned())).await,
    }
}

async fn raised(data: Option<Value>) -> RouteFailure {
    let steps = vec![Step::ThrowException(ThrowExceptionStep {
        exception_type: ErrorClass::OutcomeInvalidRequest,
        message: Some("bounded public detail".to_owned()),
        data: data.map(Expression::Constant),
    })];
    let profile = profile();
    run(Some(&profile), &steps)
        .await
        .result
        .expect_err("throwException fails the exchange")
}

#[tokio::test]
async fn throw_exception_evaluates_data_but_debug_never_prints_it() {
    let canary = "PROBLEM-DATA-MUST-NOT-ENTER-DEBUG";
    let failure = raised(Some(json!({"secret": canary}))).await;

    assert_eq!(failure.class, ErrorClass::OutcomeInvalidRequest);
    assert_eq!(failure.data, Some(json!({"secret": canary})));
    let debug = format!("{failure:?}");
    assert!(
        !debug.contains(canary),
        "route failure debug disclosed data"
    );
    assert!(debug.contains("<redacted>"), "debug names the redaction");
}

#[tokio::test]
async fn throw_exception_applies_the_serialized_byte_cap_before_the_facade() {
    let canary = "X".repeat(MAX_PROBLEM_DATA_BYTES);
    let failure = raised(Some(json!({"secret": canary}))).await;

    assert_eq!(failure.class, ErrorClass::DisclosureViolation);
    assert!(failure.data.is_none());
    assert!(failure.message.is_none());
    assert!(!format!("{failure:?}").contains("XXXXX"));
}

#[tokio::test]
async fn data_bearing_throw_without_a_trusted_profile_fails_closed() {
    let steps = vec![Step::ThrowException(ThrowExceptionStep {
        exception_type: ErrorClass::OutcomeRejected,
        message: Some("must not survive".to_owned()),
        data: Some(Expression::Constant(json!({"accepted": 3, "rejected": 1}))),
    })];
    let failure = run(None, &steps)
        .await
        .result
        .expect_err("a profile-neutral run cannot release problem data");

    assert_eq!(failure.class, ErrorClass::DisclosureViolation);
    assert!(failure.data.is_none());
    assert!(failure.message.is_none());
}

fn wrapped_throw(wrapper: &str, data: Value) -> Vec<Step> {
    let thrown = json!({
        "throwException": {
            "exceptionType": "outcome.rejected",
            "data": {"constant": data}
        }
    });
    let route = match wrapper {
        "onException" => json!([
            {"onException": {
                "exception": ["outcome"],
                "handled": true,
                "steps": [
                    {"setBody": {"constant": {"handledBy": "onException"}}}
                ]
            }},
            thrown
        ]),
        "doCatch" => json!([
            {"doTry": {
                "steps": [thrown],
                "doCatch": [{
                    "exception": ["outcome"],
                    "steps": [
                        {"setBody": {"constant": {"handledBy": "doCatch"}}}
                    ]
                }]
            }}
        ]),
        "circuitBreaker" => json!([
            {"circuitBreaker": {
                "failureRateThreshold": 50,
                "slidingWindowCalls": 2,
                "minimumNumberOfCalls": 2,
                "openStateWaitSeconds": 60,
                "maximumHalfOpenCalls": 10,
                "steps": [thrown],
                "onFallback": {"steps": [
                    {"setBody": {"constant": {"handledBy": "circuitBreaker"}}}
                ]}
            }}
        ]),
        other => panic!("unknown wrapper {other}"),
    };
    serde_json::from_value(route).expect("wrapped route parses")
}

#[tokio::test]
async fn invalid_data_is_uncatchable_before_route_handlers_can_run() {
    let invalid = [
        ("missing", json!({"accepted": 3})),
        (
            "extra",
            json!({"accepted": 3, "rejected": 1, "raw": "must-not-survive"}),
        ),
        ("mistyped", json!({"accepted": "three", "rejected": 1})),
    ];
    for (case, data) in invalid {
        for wrapper in ["onException", "doCatch", "circuitBreaker"] {
            let profile = profile();
            let outcome = run(Some(&profile), &wrapped_throw(wrapper, data.clone())).await;
            let failure = outcome.result.expect_err("invalid data fails the route");

            assert_eq!(
                failure.class,
                ErrorClass::DisclosureViolation,
                "{case} through {wrapper}"
            );
            assert!(failure.data.is_none(), "{case} through {wrapper}");
            assert!(
                outcome.events.iter().all(|event| {
                    event.kind != "exchangeFailureHandled"
                        && event.detail["class"] != json!("outcome.rejected")
                }),
                "{case} through {wrapper} was consumed or journaled under the pre-validation class: {:?}",
                outcome.events
            );
        }
    }
}

#[tokio::test]
async fn valid_typed_data_remains_catchable() {
    for wrapper in ["onException", "doCatch", "circuitBreaker"] {
        let profile = profile();
        let outcome = run(
            Some(&profile),
            &wrapped_throw(wrapper, json!({"accepted": 3, "rejected": 1})),
        )
        .await;
        let exchange = outcome.result.expect("valid data remains catchable");

        assert_eq!(exchange.message.body["handledBy"], wrapper);
        assert!(
            outcome.events.iter().any(|event| {
                event.kind == "exchangeFailureHandled" || event.kind == "breakerFallback"
            }),
            "{wrapper} records the handled failure"
        );
    }
}

#[tokio::test]
async fn declared_closed_typed_problem_data_is_rendered() {
    let profile = profile();
    let envelope = problem_envelope(&profile);
    let problems = Problems {
        profile: &profile,
        envelope: &envelope,
    };
    let failure = RouteFailure {
        class: ErrorClass::OutcomeRejected,
        message: Some("bounded public detail".to_owned()),
        data: Some(json!({"accepted": 3, "rejected": 1})),
        auth: None,
        code: None,
    };

    let (status, rendered) = body(route_problem(problems, &failure, "case", "request-1")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(rendered["code"], "cases.partial");
    assert_eq!(rendered["detail"], "bounded public detail");
    assert_eq!(rendered["data"], json!({"accepted": 3, "rejected": 1}));
}

#[tokio::test]
async fn invalid_problem_data_fails_closed_without_value_or_detail_fallback() {
    let canary = "PROBLEM-DATA-MUST-NOT-BE-RELEASED";
    let invalid = [
        json!({"accepted": 3}),
        json!({"accepted": 3, "rejected": 1, "raw": canary}),
        json!({"accepted": "three", "rejected": 1}),
        json!([3, 1]),
        json!({"accepted": 3, "rejected": 1, "padding": "X".repeat(MAX_PROBLEM_DATA_BYTES)}),
    ];

    for data in invalid {
        let profile = profile();
        let envelope = problem_envelope(&profile);
        let problems = Problems {
            profile: &profile,
            envelope: &envelope,
        };
        let failure = RouteFailure {
            class: ErrorClass::OutcomeRejected,
            message: Some(canary.to_owned()),
            data: Some(data),
            auth: None,
            code: None,
        };
        let (status, rendered) =
            body(route_problem(problems, &failure, "case", "request-invalid")).await;
        let text = rendered.to_string();

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(rendered["code"], "disclosure.violation");
        assert!(rendered.get("data").is_none());
        assert!(rendered.get("detail").is_none());
        assert!(!text.contains(canary));
        assert!(!text.contains("padding"));
    }
}

#[tokio::test]
async fn data_for_a_problem_without_a_declaration_is_a_disclosure_violation() {
    let profile = profile();
    let envelope = problem_envelope(&profile);
    let problems = Problems {
        profile: &profile,
        envelope: &envelope,
    };
    let failure = RouteFailure {
        class: ErrorClass::OutcomeConflict,
        message: Some("must not survive".to_owned()),
        data: Some(json!({"accepted": 3})),
        auth: None,
        code: None,
    };
    let (status, rendered) = body(route_problem(
        problems,
        &failure,
        "case",
        "request-undeclared",
    ))
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(rendered["code"], "disclosure.violation");
    assert!(rendered.get("data").is_none());
    assert!(rendered.get("detail").is_none());
}

#[tokio::test]
async fn whole_problem_data_remains_optional_and_plain_problems_are_unchanged() {
    for class in [ErrorClass::OutcomeRejected, ErrorClass::OutcomeConflict] {
        let profile = profile();
        let envelope = problem_envelope(&profile);
        let problems = Problems {
            profile: &profile,
            envelope: &envelope,
        };
        let failure = RouteFailure {
            class,
            message: Some("bounded public detail".to_owned()),
            data: None,
            auth: None,
            code: None,
        };
        let (status, rendered) =
            body(route_problem(problems, &failure, "case", "request-plain")).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(rendered.get("data").is_none());
        assert_eq!(rendered["detail"], "bounded public detail");
    }
}
