// SPDX-License-Identifier: Apache-2.0
//! An Action plan runs on a deterministic surface: it cannot read the wall
//! clock, and no function it can call holds its thread past the planner
//! deadline.
//!
//! Each case compiles and calls a plan through the same functions the handler
//! path uses: `compile_entrypoint`, the planner `engine`, and the platform's
//! fresh-scope call. The deadline is checked only between operations, so a
//! native call that blocks or never returns is out of its reach; the cases
//! hold that no such call is reachable by name, by function pointer, or by
//! method syntax. Every call runs on its own thread under a watchdog, so a
//! call that never returns fails its case instead of hanging the suite, and a
//! plain plan runs normally after each refusal.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use registry_platform_script::rhai as platform;
use rhai::{Dynamic, EvalAltResult, ImmutableString, Map};

use super::{compile_entrypoint, engine};

/// The planner deadline the blocking cases run under. It starts before the
/// engine is built, so it leaves room for a slow build and stays well under
/// the watchdog.
const DEADLINE: Duration = Duration::from_millis(500);

/// How long a call may take before the case fails. Far longer than any
/// refusal takes, and shorter than the two-second pauses the cases request.
const WATCHDOG: Duration = Duration::from_secs(1);

/// A plan that uses the string, array, and padding functions a plan keeps.
const CONTROL: &str = r#"fn plan(ctx) {
    let text = "x";
    text.pad(4, "ab");
    let items = [3, 1, 2];
    items.sort();
    text + items[0].to_string()
}"#;

fn call_plan(source: &str, budget: Duration) -> Result<Dynamic, Box<EvalAltResult>> {
    let ast = compile_entrypoint(source, "plan").expect("plan compiles");
    let (sender, receiver) = mpsc::channel();
    let started = Instant::now();
    std::thread::spawn(move || {
        let engine = engine(Some(Instant::now() + budget));
        let result =
            platform::call_with_fresh_scope(&engine, &ast, "plan", (Dynamic::from(Map::new()),));
        sender
            .send(result)
            .expect("the watchdog is still waiting for this plan");
    });
    receiver.recv_timeout(WATCHDOG).unwrap_or_else(|_| {
        panic!(
            "the plan held its thread for {:?} under a {budget:?} deadline: {source}",
            started.elapsed()
        )
    })
}

fn assert_control_plan_runs() {
    let value = call_plan(CONTROL, Duration::from_secs(5)).expect("the control plan runs");
    assert_eq!(
        value.cast::<ImmutableString>().as_str(),
        "xaba1",
        "the control plan keeps its standard behaviour"
    );
}

/// The call must fail because `function` itself is missing from the engine,
/// not because the call form around it was refused.
fn assert_absent(function: &str, source: &str, budget: Duration) {
    match call_plan(source, budget) {
        Err(error)
            if matches!(
                &*error,
                EvalAltResult::ErrorFunctionNotFound(signature, _)
                    if signature.starts_with(&format!("{function} ("))
            ) => {}
        other => panic!("expected {function} to be absent, got {other:?}: {source}"),
    }
    assert_control_plan_runs();
}

#[test]
fn the_control_plan_runs_on_the_planner_engine() {
    assert_control_plan_runs();
}

#[test]
fn a_plan_cannot_read_the_clock() {
    for source in [
        "fn plan(ctx) { timestamp() }",
        "fn plan(ctx) { let started = timestamp(); started.elapsed }",
        r#"fn plan(ctx) { Fn("timestamp").call() }"#,
        r#"fn plan(ctx) { call(Fn("timestamp")) }"#,
        r#"fn plan(ctx) { let clock = Fn("timestamp"); clock.call() }"#,
    ] {
        assert_absent("timestamp", source, Duration::from_secs(5));
    }
}

#[test]
fn a_plan_cannot_hold_its_thread_past_the_deadline() {
    for source in [
        "fn plan(ctx) { sleep(2); 1 }",
        "fn plan(ctx) { sleep(2.0); 1 }",
        "fn plan(ctx) { let seconds = 2; seconds.sleep(); 1 }",
        "fn plan(ctx) { let seconds = 2.0; seconds.sleep(); 1 }",
        r#"fn plan(ctx) { Fn("sleep").call(2); 1 }"#,
        r#"fn plan(ctx) { call(Fn("sleep"), 2.0); 1 }"#,
        r#"fn plan(ctx) { let pause = Fn("sleep"); pause.call(2); 1 }"#,
        r#"fn plan(ctx) { let seconds = 2; seconds.call(Fn("sleep")); 1 }"#,
    ] {
        assert_absent("sleep", source, DEADLINE);
    }
}

#[test]
fn padding_with_an_empty_string_is_refused_instead_of_never_returning() {
    for source in [
        r#"fn plan(ctx) { let text = "a"; text.pad(5, ""); text }"#,
        r#"fn plan(ctx) { let text = "a"; pad(text, 5, ""); text }"#,
        r#"fn plan(ctx) { let text = "a"; Fn("pad").call(text, 5, ""); text }"#,
        r#"fn plan(ctx) { let text = "a"; text.call(Fn("pad"), 5, ""); text }"#,
    ] {
        let result = call_plan(source, Duration::from_secs(5));
        assert!(
            result.is_err(),
            "empty padding was accepted with {result:?}: {source}"
        );
        assert_control_plan_runs();
    }
}
