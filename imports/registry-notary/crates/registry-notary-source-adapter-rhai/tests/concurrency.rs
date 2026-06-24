// SPDX-License-Identifier: Apache-2.0
//! The bridge cancellation / admission behavior — the decisive concurrency
//! guarantees, exercised against the deterministic [`MockScriptHost`].
//!
//! Proves: (1) an infinite loop times out AND the blocking thread stops;
//! (2) a timeout releases the dedicated permit (no leak); (3) a slow host
//! respects the caller deadline and the in-flight call is abandoned;
//! (4) saturation yields a clean rejection, not a hang; (5) outcome counters
//! distinguish the terminal states.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use registry_notary_source_adapter_rhai::{
    BudgetKind, Lookup, MockScriptHost, RhaiPolicy, ScriptCtx, ScriptEngine, SourceScriptError,
};

const INFINITE: &str = r#"fn lookup(ctx) { let i = 0; while true { i += 1; } [#{ i: i }] }"#;
const SLOW_CALL: &str = r#"
fn lookup(ctx) {
    let rows = source.get("t", "/path", #{ value: ctx.lookup.value }).body;
    rows
}
"#;

fn ctx(value: &str) -> ScriptCtx {
    ScriptCtx::new(
        "src",
        "ds",
        "ent",
        Lookup {
            field: "f".into(),
            value: value.into(),
        },
        "verify",
    )
}

fn policy(timeout: Duration, permits: usize) -> RhaiPolicy {
    // Make the operation budget effectively unlimited so the *deadline* is the
    // deterministic trigger for these timing tests (otherwise a tight loop can
    // exhaust the default op budget before the deadline and classify as a
    // Budget outcome rather than a Deadline one).
    let mut p = RhaiPolicy {
        timeout,
        max_concurrent: permits,
        ..RhaiPolicy::default()
    };
    // A very large finite budget makes the *deadline* (not the op budget) the
    // deterministic trigger for these timing tests, without using `0` (which the
    // engine now rejects as "unlimited" — it disables the runaway-loop backstop).
    p.limits.max_operations = u64::MAX;
    p
}

// (1) Infinite-loop script times out AND the blocking thread actually stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn infinite_loop_times_out_and_thread_stops() {
    let engine =
        ScriptEngine::compile(INFINITE, "lookup", &policy(Duration::from_millis(150), 4)).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let finished = Arc::new(AtomicBool::new(false));

    let res = engine
        .execute_observing(host, ctx("1"), finished.clone())
        .await;
    assert!(res.is_err(), "infinite loop must not return Ok");
    assert!(matches!(res.unwrap_err(), SourceScriptError::Deadline));

    // The script thread must STOP shortly after the deadline; poll up to ~2s.
    let mut stopped = false;
    for _ in 0..200 {
        if finished.load(Ordering::SeqCst) {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(stopped, "blocking script thread did NOT stop after timeout");
}

// (2) Caller timeout releases the dedicated semaphore permit (no leak): with a
//     single permit, a fresh request after a timed-out runaway must succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timeout_releases_dedicated_permit() {
    let engine =
        ScriptEngine::compile(INFINITE, "lookup", &policy(Duration::from_millis(120), 1)).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));

    let finished = Arc::new(AtomicBool::new(false));
    let r1 = engine
        .execute_observing(host.clone(), ctx("1"), finished.clone())
        .await;
    assert!(matches!(r1.unwrap_err(), SourceScriptError::Deadline));

    // Wait for the aborted thread to unwind and drop its permit.
    for _ in 0..200 {
        if finished.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(finished.load(Ordering::SeqCst), "thread must have unwound");

    // A normal request must now succeed using the SAME single permit. Recompile
    // with a runnable script but reuse the constraint by giving generous time.
    let engine2 =
        ScriptEngine::compile(SLOW_CALL, "lookup", &policy(Duration::from_secs(2), 1)).unwrap();
    let out = engine2
        .execute(host, ctx("9"))
        .await
        .expect("permit must be free so this runs");
    assert_eq!(out[0]["v"], "9");
}

// (3) A slow host (sleeps far longer than the deadline) respects the caller
//     deadline, and the in-flight call is abandoned (not awaited to completion).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_host_respects_caller_deadline() {
    let engine =
        ScriptEngine::compile(SLOW_CALL, "lookup", &policy(Duration::from_millis(200), 4)).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_secs(2)));

    let start = Instant::now();
    let res = engine.execute(host.clone(), ctx("1")).await;
    let elapsed = start.elapsed();

    assert!(res.is_err(), "slow host call must not complete in time");
    assert!(matches!(res.unwrap_err(), SourceScriptError::Deadline));
    // Returns ~at the deadline, NOT after the full 2s host sleep.
    assert!(
        elapsed < Duration::from_millis(900),
        "caller deadline not respected; took {elapsed:?}"
    );
    // The host call was started but abandoned mid-flight.
    assert!(host.started() >= 1, "the host call should have started");
    assert_eq!(host.completed(), 0, "the slow call must be abandoned");
}

// (4) Under saturation (more concurrent runs than permits), the excess request
//     gets a clean `Budget { Saturated }` rejection rather than hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturation_yields_clean_rejection_not_hang() {
    let engine = Arc::new(
        ScriptEngine::compile(INFINITE, "lookup", &policy(Duration::from_millis(800), 2)).unwrap(),
    );
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));

    // Occupy both permits with runaways.
    let e1 = engine.clone();
    let h1host = host.clone();
    let h1 = tokio::spawn(async move { e1.execute(h1host, ctx("1")).await });
    let e2 = engine.clone();
    let h2host = host.clone();
    let h2 = tokio::spawn(async move { e2.execute(h2host, ctx("1")).await });

    // Let both acquire their permits.
    tokio::time::sleep(Duration::from_millis(80)).await;

    // The 3rd request must be rejected promptly.
    let start = Instant::now();
    let r3 = engine.execute(host.clone(), ctx("1")).await;
    assert!(matches!(
        r3.unwrap_err(),
        SourceScriptError::Budget {
            kind: BudgetKind::Saturated
        }
    ));
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "saturated reject must be prompt, took {:?}",
        start.elapsed()
    );

    let _ = h1.await;
    let _ = h2.await;
    let (.., saturated) = engine.counters().snapshot();
    assert!(saturated >= 1, "expected a saturated outcome");
}

// (6) If the orchestrating future is dropped/cancelled by its caller, the
//     blocking script thread must stop PROMPTLY (CancelOnDrop flips the cancel
//     flag) instead of running to the full wall-clock deadline. The deadline is
//     set long (10s) so that, were the guard missing, the thread would still be
//     spinning well past the test's ~2s observation window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_execute_future_stops_blocking_thread() {
    let engine = Arc::new(
        ScriptEngine::compile(INFINITE, "lookup", &policy(Duration::from_secs(10), 4)).unwrap(),
    );
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let finished = Arc::new(AtomicBool::new(false));

    let e = engine.clone();
    let h = host.clone();
    let f = finished.clone();
    let task = tokio::spawn(async move { e.execute_observing(h, ctx("1"), f).await });

    // Let the blocking thread spawn and start spinning, then drop the
    // orchestrating future by aborting the task that holds it.
    tokio::time::sleep(Duration::from_millis(100)).await;
    task.abort();
    let _ = task.await;

    // The blocking thread must stop well before the 10s deadline.
    let mut stopped = false;
    for _ in 0..200 {
        if finished.load(Ordering::SeqCst) {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        stopped,
        "dropping the execute future must stop the blocking thread promptly"
    );
}

// (5) Counters classify outcomes: completed, timed_out, transport_failed, and
//     saturated all increment distinctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn counters_distinguish_outcomes() {
    // completed + timed_out share one engine (same counters).
    let ok_engine =
        ScriptEngine::compile(SLOW_CALL, "lookup", &policy(Duration::from_secs(2), 4)).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    ok_engine
        .execute(host, ctx("5"))
        .await
        .expect("should complete");

    let to_engine =
        ScriptEngine::compile(INFINITE, "lookup", &policy(Duration::from_millis(120), 4)).unwrap();
    let host = Arc::new(MockScriptHost::echo(Duration::from_millis(1)));
    let _ = to_engine.execute(host, ctx("1")).await;

    let (completed, ..) = ok_engine.counters().snapshot();
    assert!(completed >= 1, "expected a completed outcome");
    let (_c, timed_out, ..) = to_engine.counters().snapshot();
    assert!(timed_out >= 1, "expected a timed_out outcome");

    // transport_failed via a failing host.
    let tf_engine =
        ScriptEngine::compile(SLOW_CALL, "lookup", &policy(Duration::from_secs(2), 4)).unwrap();
    let host = Arc::new(MockScriptHost::transport_failure(Duration::from_millis(1)));
    let r = tf_engine.execute(host, ctx("1")).await;
    assert!(matches!(r.unwrap_err(), SourceScriptError::HttpTransport));
    let (_c, _t, _ca, _b, transport_failed, _s) = tf_engine.counters().snapshot();
    assert!(transport_failed >= 1, "expected a transport_failed outcome");
}
