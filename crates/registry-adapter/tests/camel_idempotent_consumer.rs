// SPDX-License-Identifier: Apache-2.0

//! Direct engine conformance for the Idempotent Consumer port-table row
//! (`products/adapter/CONCEPT.md` sections 8.10 and 9).
//!
//! Camel checks or adds the key before the guarded block according to
//! `eager`, and runs its completion either when that block ends or when the
//! whole exchange ends according to `completionEager`
//! (`camel-4.23.0:core/camel-core-processor/src/main/java/org/apache/camel/processor/idempotent/IdempotentConsumer.java`).
//! Adapter's host keeps its stricter durable write reservation independent
//! of those EIP timings, so a non-safe effect is never reopened.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use registry_adapter::engine::exchange::{Exchange, WriteClaim, WriteCustody};
use registry_adapter::engine::route::{
    check_servable, run_route, RouteContext, RouteFailure, RouteTable,
};
use registry_adapter::engine::scripts::ScriptSet;
use registry_adapter_core::{ErrorClass, Step};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CustodyEvent {
    Claim {
        eager: bool,
    },
    Complete {
        succeeded: bool,
        remove_on_failure: bool,
    },
}

#[derive(Debug, Default)]
struct RecordingCustody {
    events: Mutex<Vec<CustodyEvent>>,
}

impl RecordingCustody {
    fn events(&self) -> Vec<CustodyEvent> {
        self.events.lock().expect("custody mutex").clone()
    }
}

impl WriteCustody for RecordingCustody {
    fn claim<'a>(
        &'a self,
        _key: &'a str,
        eager: bool,
    ) -> Pin<Box<dyn Future<Output = Result<WriteClaim, RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            self.events
                .lock()
                .expect("custody mutex")
                .push(CustodyEvent::Claim { eager });
            Ok(WriteClaim::Execute)
        })
    }

    fn before_effect<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn mark_unsupported_incomplete<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RouteFailure>> + Send + 'a>> {
        Box::pin(async { Ok(true) })
    }

    fn complete<'a>(
        &'a self,
        succeeded: bool,
        remove_on_failure: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            self.events
                .lock()
                .expect("custody mutex")
                .push(CustodyEvent::Complete {
                    succeeded,
                    remove_on_failure,
                });
            Ok(())
        })
    }
}

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

async fn run(
    step_list: Vec<Step>,
) -> (
    registry_adapter::engine::route::RouteOutcome,
    Arc<RecordingCustody>,
) {
    run_with_routes(step_list, RouteTable::new()).await
}

async fn run_with_routes(
    step_list: Vec<Step>,
    routes: RouteTable,
) -> (
    registry_adapter::engine::route::RouteOutcome,
    Arc<RecordingCustody>,
) {
    let endpoints = BTreeMap::new();
    let scripts = ScriptSet::default();
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment resolver builds");
    let resilience = registry_adapter::engine::resilience::ResilienceRuntime::empty();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: Arc::new(BTreeMap::new()),
        maximum_upstream_calls: 1,
        job: registry_adapter::engine::job_sources::JobPageState::default(),
    };
    let custody = Arc::new(RecordingCustody::default());
    let mut exchange = Exchange::new("idempotent-conformance".to_owned());
    exchange
        .message
        .set_header("Idempotency-Key", json!("conformance-key"));
    exchange.install_write(custody.clone());
    (run_route(&context, &step_list, exchange).await, custody)
}

/// Camel's `eager=false` checks before processing and adds only on successful
/// completion (`IdempotentConsumerEagerTest.testNotEager` at the pinned tag).
#[tokio::test]
async fn eager_false_defers_eip_membership_until_successful_completion() {
    let route = steps(json!([{
        "idempotentConsumer": {
            "expression": {"header": "Idempotency-Key"},
            "eager": false,
            "steps": [{"setBody": {"constant": "accepted"}}]
        }
    }]));
    check_servable(&route).expect("eager false is a supported Camel mode");

    let (outcome, custody) = run(route).await;
    assert_eq!(
        outcome
            .result
            .expect("the guarded work succeeds")
            .message
            .body,
        json!("accepted")
    );
    assert_eq!(
        custody.events(),
        [
            CustodyEvent::Claim { eager: false },
            CustodyEvent::Complete {
                succeeded: true,
                remove_on_failure: true,
            },
        ]
    );
}

/// Camel's `completionEager=true` completes when the guarded block ends, so
/// a later route failure does not roll its membership back. The default false
/// completes when the whole exchange ends and observes that later failure
/// (`IdempotentConsumerCompletionEagerTest.testCompletionEager` and
/// `testNotCompletionEager` at the pinned tag).
#[tokio::test]
async fn completion_eager_scopes_completion_to_the_guarded_block() {
    async fn completion(completion_eager: bool) -> Vec<CustodyEvent> {
        let route = steps(json!([
            {"idempotentConsumer": {
                "expression": {"header": "Idempotency-Key"},
                "completionEager": completion_eager,
                "steps": [{"setBody": {"constant": "guarded-success"}}]
            }},
            {"throwException": {
                "exceptionType": "validation",
                "message": "failure after the idempotent block"
            }}
        ]));
        check_servable(&route).expect("completionEager is a supported Camel mode");
        let (outcome, custody) = run(route).await;
        assert_eq!(
            outcome.result.expect_err("the downstream step fails").class,
            ErrorClass::Validation
        );
        custody.events()
    }

    assert_eq!(
        completion(true).await,
        [
            CustodyEvent::Claim { eager: true },
            CustodyEvent::Complete {
                succeeded: true,
                remove_on_failure: true,
            },
        ],
        "eager completion is insulated from a downstream failure"
    );
    assert_eq!(
        completion(false).await,
        [
            CustodyEvent::Claim { eager: true },
            CustodyEvent::Complete {
                succeeded: false,
                remove_on_failure: true,
            },
        ],
        "default completion observes the whole exchange failure"
    );
}

/// `removeOnFailure=false` is delivered to completion unchanged. The host
/// decides whether a safe reservation remains, while an attempted effect is
/// always kept spent by Adapter's section 9 divergence
/// (`IdempotentConsumerRemoveOnFailureTest.testFailedExchangesNotRemoved` at
/// the pinned tag).
#[tokio::test]
async fn remove_on_failure_false_is_applied_at_the_selected_completion_scope() {
    let route = steps(json!([{
        "idempotentConsumer": {
            "expression": {"header": "Idempotency-Key"},
            "removeOnFailure": false,
            "steps": [{"throwException": {
                "exceptionType": "validation",
                "message": "guarded failure"
            }}]
        }
    }]));

    let (outcome, custody) = run(route).await;
    assert_eq!(
        outcome.result.expect_err("the guarded step fails").class,
        ErrorClass::Validation
    );
    assert_eq!(
        custody.events(),
        [
            CustodyEvent::Claim { eager: true },
            CustodyEvent::Complete {
                succeeded: false,
                remove_on_failure: false,
            },
        ]
    );
}

/// Camel's completion callback treats an exchange whose error channel handled
/// a failure as failed. Eager block completion remains successful when the
/// handled failure occurs later; whole-exchange completion observes it
/// (`IdempotentOnCompletion.onComplete` at the pinned tag).
#[tokio::test]
async fn handled_downstream_failure_respects_completion_scope_and_removal_mode() {
    for (completion_eager, remove_on_failure, succeeded) in [
        (true, true, true),
        (true, false, true),
        (false, true, false),
        (false, false, false),
    ] {
        let route = steps(json!([
            {"onException": {
                "exception": ["validation"],
                "handled": true,
                "steps": [{"setBody": {"constant": "handled"}}]
            }},
            {"idempotentConsumer": {
                "expression": {"header": "Idempotency-Key"},
                "completionEager": completion_eager,
                "removeOnFailure": remove_on_failure,
                "steps": [{"setBody": {"constant": "guarded-success"}}]
            }},
            {"throwException": {
                "exceptionType": "validation",
                "message": "handled after the idempotent block"
            }}
        ]));

        let (outcome, custody) = run(route).await;
        assert_eq!(
            outcome
                .result
                .expect("the error channel handles the failure")
                .message
                .body,
            json!("handled")
        );
        assert_eq!(
            custody.events(),
            [
                CustodyEvent::Claim { eager: true },
                CustodyEvent::Complete {
                    succeeded,
                    remove_on_failure,
                },
            ],
            "completionEager={completion_eager}, removeOnFailure={remove_on_failure}"
        );
    }
}

/// A handled failure in a `direct:` callee stays recorded on Camel's shared
/// exchange even though the caller resumes after the endpoint. Both block and
/// exchange completion therefore see failure. In contrast, `continued=true`
/// invokes Camel's `prepareExchangeForContinue`, which clears that handled
/// failure before the caller resumes.
#[tokio::test]
async fn direct_callee_error_state_reaches_both_completion_scopes() {
    for (continued_clears, completion_eager, succeeded) in [
        (false, true, false),
        (false, false, false),
        (true, true, true),
        (true, false, true),
    ] {
        let mut routes = RouteTable::new();
        routes.insert(
            "handled".to_owned(),
            Arc::new(steps(json!([
                {"onException": {
                    "exception": ["validation"],
                    "handled": true,
                    "steps": [{"setBody": {"constant": "callee-recovered"}}]
                }},
                {"throwException": {
                    "exceptionType": "validation",
                    "message": "handled callee failure"
                }}
            ]))),
        );
        routes.insert(
            "continued".to_owned(),
            Arc::new(steps(json!([
                {"onException": {
                    "exception": ["validation"],
                    "continued": true,
                    "steps": [{"setBody": {"constant": "callee-recovered"}}]
                }},
                {"throwException": {
                    "exceptionType": "validation",
                    "message": "continued callee failure"
                }}
            ]))),
        );
        let guarded_steps = if continued_clears {
            json!([
                {"to": {"uri": "direct:handled"}},
                {"to": {"uri": "direct:continued"}}
            ])
        } else {
            json!([{"to": {"uri": "direct:handled"}}])
        };
        let route = steps(json!([{
            "idempotentConsumer": {
                "expression": {"header": "Idempotency-Key"},
                "completionEager": completion_eager,
                "steps": guarded_steps
            }
        }]));

        let (outcome, custody) = run_with_routes(route, routes).await;
        assert_eq!(
            outcome
                .result
                .expect("the direct error channel recovers the route")
                .message
                .body,
            json!("callee-recovered")
        );
        assert_eq!(
            custody.events(),
            [
                CustodyEvent::Claim { eager: true },
                CustodyEvent::Complete {
                    succeeded,
                    remove_on_failure: true,
                },
            ],
            "continuedClears={continued_clears}, completionEager={completion_eager}"
        );
    }
}
