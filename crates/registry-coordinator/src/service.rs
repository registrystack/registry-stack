// SPDX-License-Identifier: Apache-2.0
use crate::{
    adapters::HttpAdapters,
    deployment,
    http::{self, HttpState},
    metrics,
    protocol::AdapterSet,
    runtime::RuntimeConfig,
    store::ATTEMPT_TIMEOUT,
    worker::Worker,
    CoordinatorError, Result,
};
use clap::{CommandFactory, Parser};
use registry_platform_dispatch::postgres::LEASE_FINALIZATION_ALLOWANCE;
use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::watch, time::Instant};

// Full schema/role inspection is an operator health check. Each worker
// transaction still verifies package activation and key custody before I/O.
const DEPLOYMENT_RECHECK_INTERVAL: Duration = Duration::from_secs(30);
/// How long a stop waits for the attempt in flight and the requests being
/// answered: one attempt plus the finalization allowance its lease carries,
/// so an attempt that began just before the stop can still record its outcome.
const SHUTDOWN_GRACE: Duration = ATTEMPT_TIMEOUT.saturating_add(LEASE_FINALIZATION_ALLOWANCE);
#[derive(Parser)]
#[command(
    name = "coordinator",
    about = "Authenticated Registry Coordinator workflow service",
    version
)]
struct Cli {
    /// Runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Milliseconds between worker polls.
    #[arg(long,default_value_t=100,value_parser=clap::value_parser!(u64).range(10..=10_000))]
    poll_ms: u64,
    /// Serve authenticated recovery operations with worker dispatch disabled.
    #[arg(long)]
    recovery_only: bool,
}
async fn execute(cli: Cli) -> Result<()> {
    let shutdown = shutdown_signal()?;
    let runtime = Arc::new(RuntimeConfig::load(&cli.runtime_config)?);
    let d = deployment::config(&runtime)?;
    let workflows = Arc::new(deployment::load_workflows(d)?);
    workflows.validate(&runtime)?;
    let authenticator = Arc::new(
        d.authentication
            .authenticator(&runtime.secret_providers, d.local())
            .await?,
    );
    let store = deployment::open(&runtime, false).await?;
    // One worker serves every workflow: start it with each pinned definition
    // compiled, so only earlier snapshots of in-flight runs compile later.
    for (_, package) in workflows.iter() {
        store.definitions().seed(package.definition.clone())?;
    }
    if cli.recovery_only {
        deployment::check(&store, &runtime, workflows.digest()).await?;
    } else {
        deployment::check_serving(&store, &runtime, workflows.digest()).await?;
    }
    let adapters: Arc<dyn AdapterSet> = Arc::new(HttpAdapters::new(&runtime)?);
    let worker = Worker::new(store.clone(), adapters.clone());
    let listener = tokio::net::TcpListener::bind(d.listener.bind.socket_addr())
        .await
        .map_err(|_| {
            CoordinatorError::new(
                "listener-unavailable",
                "cannot bind the configured private listener",
            )
        })?;
    let metrics_listener = match &d.metrics_listener {
        Some(metrics) => Some(
            tokio::net::TcpListener::bind(metrics.bind.socket_addr())
                .await
                .map_err(|_| {
                    CoordinatorError::new(
                        "listener-unavailable",
                        "cannot bind the configured metrics listener",
                    )
                    .suggest("free the metricsListener address or choose another private one")
                })?,
        ),
        None => None,
    };
    let state = HttpState {
        recovery_only: cli.recovery_only,
        store: store.clone(),
        runtime: runtime.clone(),
        workflows: workflows.clone(),
        authenticator,
        adapters,
    };
    let (stop, stopped) = watch::channel(false);
    let server = axum::serve(listener, http::router(state))
        .with_graceful_shutdown(stop_requested(stopped.clone()));
    let metrics_server = metrics_listener.map(|listener| {
        axum::serve(listener, metrics::metrics_router(store.clone()))
            .with_graceful_shutdown(stop_requested(stopped.clone()))
    });
    let server = async {
        let public = async {
            server.await.map_err(|_| {
                CoordinatorError::new("listener-unavailable", "the private listener stopped")
            })
        };
        let metrics = async {
            match metrics_server {
                Some(server) => server.await.map_err(|_| {
                    CoordinatorError::new("listener-unavailable", "the metrics listener stopped")
                }),
                None => Ok(()),
            }
        };
        tokio::try_join!(public, metrics).map(|_| ())
    };
    let worker = worker_loop(
        Duration::from_millis(cli.poll_ms),
        cli.recovery_only,
        stopped,
        || async {
            deployment::check(&store, &runtime, workflows.digest())
                .await
                .map(|_| ())
        },
        || worker.tick(),
    );
    tracing::info!(
        listener = %d.listener.bind.socket_addr(),
        metrics_listener = d.metrics_listener.is_some(),
        recovery_only = cli.recovery_only,
        "serving Registry Coordinator"
    );
    serve_until(server, worker, shutdown, stop).await
}

/// Resolve on the first SIGTERM or SIGINT. The SIGTERM handler is installed
/// before anything is served, so a service that SIGTERM could not stop
/// gracefully refuses to start.
fn shutdown_signal() -> Result<impl Future<Output = ()>> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| {
        CoordinatorError::new(
            "signal-unavailable",
            "the SIGTERM handler could not be installed",
        )
        .suggest("start the service again; it does not serve when it could not stop gracefully")
    })?;
    Ok(async move {
        let interrupt = tokio::signal::ctrl_c();
        #[cfg(unix)]
        tokio::select! {
            _ = interrupt => {}
            _ = terminate.recv() => {}
        }
        #[cfg(not(unix))]
        if interrupt.await.is_err() {
            tracing::error!("the interrupt handler failed; stopping");
        }
    })
}

/// Resolve once `stopped` turns true. The sender outlives the listener and
/// the worker, so the channel closing is not a stop request.
async fn stop_requested(mut stopped: watch::Receiver<bool>) {
    if stopped.wait_for(|stop| *stop).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Sleep for `delay`, ending early when a stop is requested; true when it was.
async fn pause(delay: Duration, stopped: &watch::Receiver<bool>) -> bool {
    tokio::select! {
        biased;
        () = stop_requested(stopped.clone()) => true,
        () = tokio::time::sleep(delay) => false,
    }
}

/// Run the listener and the worker until `shutdown` resolves, then stop both:
/// the listener accepts no new connection and answers the requests it holds,
/// and the worker leases nothing more and finishes the attempt in flight. Both
/// get [`SHUTDOWN_GRACE`]. An attempt still unfinished after it keeps its lease
/// until the lease expires, and Dispatch recovers it as it recovers the attempt
/// of a worker that crashed. Either one stopping before `shutdown` ends the
/// service with its result.
async fn serve_until(
    server: impl Future<Output = Result<()>>,
    worker: impl Future<Output = Result<()>>,
    shutdown: impl Future<Output = ()>,
    stop: watch::Sender<bool>,
) -> Result<()> {
    tokio::pin!(server, worker, shutdown);
    tokio::select! {
        result = &mut server => return result,
        result = &mut worker => return result,
        () = &mut shutdown => {}
    }
    tracing::info!(
        grace_seconds = SHUTDOWN_GRACE.as_secs(),
        "stopping: no new request or attempt is accepted, the work in flight finishes"
    );
    stop.send_replace(true);
    match tokio::time::timeout(SHUTDOWN_GRACE, async {
        tokio::join!(&mut server, &mut worker)
    })
    .await
    {
        Ok((served, worked)) => {
            served?;
            worked?;
            tracing::info!("stopped");
        }
        Err(_) => tracing::warn!(
            grace_seconds = SHUTDOWN_GRACE.as_secs(),
            "stopped with work still in flight; an unfinished attempt is recovered once its lease expires"
        ),
    }
    Ok(())
}
/// Longest pause between attempts while the worker cannot poll.
const RETRY_MAXIMUM_DELAY: Duration = DEPLOYMENT_RECHECK_INTERVAL;

/// Pause after the given number of consecutive failures: one second, doubling,
/// capped at the deployment refresh interval.
fn retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(5);
    Duration::from_secs(1u64 << doublings).min(RETRY_MAXIMUM_DELAY)
}

// The startup check has already succeeded before the listener is bound. Reuse
// it between bounded refreshes without caching protected transaction decisions.
//
// A failed poll does not stop the service. Each worker transaction verifies
// the activation fence and key custody itself, but its refusal cannot tell a
// moved fence from a lost connection, so the loop pauses and runs the full
// deployment check before it polls again. That check decides:
// - confirmed: poll again, and reset the pause once a poll succeeds;
// - `store-unavailable` (no connection could be opened): poll nothing, pause
//   longer and check again, so an outage is waited out rather than ending the
//   service;
// - any other refusal, a moved activation or changed key custody among them:
//   stop the service.
// A connection that opens but fails partway through the check is a refusal,
// and the service stops for its supervisor to restart it.
//
// A stop request ends the loop at its next pause, and no poll starts after it;
// a poll or check already running finishes first. The loop then returns
// `Ok(())`, the only way it returns without an error.
async fn worker_loop<C, CF, W, WF>(
    poll_interval: Duration,
    recovery_only: bool,
    stopped: watch::Receiver<bool>,
    mut check: C,
    mut tick: W,
) -> Result<()>
where
    C: FnMut() -> CF,
    CF: Future<Output = Result<()>>,
    W: FnMut() -> WF,
    WF: Future<Output = Result<bool>>,
{
    let mut next_check = Instant::now() + DEPLOYMENT_RECHECK_INTERVAL;
    let mut failures: u32 = 0;
    loop {
        if failures > 0 || Instant::now() >= next_check {
            match check().await {
                Ok(()) => next_check = Instant::now() + DEPLOYMENT_RECHECK_INTERVAL,
                Err(error) if error.code == "store-unavailable" => {
                    failures = failures.saturating_add(1);
                    let delay = retry_delay(failures);
                    tracing::warn!(
                        code = %error.code,
                        suggested_action = error.suggested_action.as_deref(),
                        retry_in_ms = delay.as_millis() as u64,
                        "deployment check could not reach the database; holding the worker"
                    );
                    if pause(delay, &stopped).await {
                        return Ok(());
                    }
                    continue;
                }
                // Failure ends the service before this poll can dispatch work.
                Err(error) => return Err(error),
            }
        }
        if !recovery_only {
            if *stopped.borrow() {
                return Ok(());
            }
            // Store activation, hold, custody and audit gates are never cached.
            if let Err(error) = tick().await {
                failures = failures.saturating_add(1);
                let delay = retry_delay(failures);
                tracing::warn!(
                    code = %error.code,
                    retry_in_ms = delay.as_millis() as u64,
                    "worker poll failed; confirming the deployment before the next poll"
                );
                if pause(delay, &stopped).await {
                    return Ok(());
                }
                continue;
            }
        }
        if failures > 0 {
            tracing::info!(failures, "worker loop resumed");
            failures = 0;
        }
        if pause(poll_interval, &stopped).await {
            return Ok(());
        }
    }
}

pub async fn run() -> std::process::ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Public service command tree.
pub fn command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn increment(counter: &AtomicUsize) {
        counter.fetch_add(1, Ordering::SeqCst);
    }

    /// A stop channel nobody will send on: the loop runs until it fails.
    fn running() -> watch::Receiver<bool> {
        watch::channel(false).1
    }

    #[tokio::test(start_paused = true)]
    async fn polls_reuse_startup_validation_until_the_fixed_refresh_deadline() {
        let checks = Arc::new(AtomicUsize::new(1));
        let ticks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            running(),
            {
                let checks = checks.clone();
                move || {
                    increment(&checks);
                    std::future::ready(Ok(()))
                }
            },
            {
                let ticks = ticks.clone();
                move || {
                    increment(&ticks);
                    std::future::ready(Ok(false))
                }
            },
        ));
        tokio::task::yield_now().await;
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
        for _ in 0..299 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(ticks.load(Ordering::SeqCst), 300);
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert_eq!(ticks.load(Ordering::SeqCst), 301);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_refresh_stops_before_the_next_worker_tick() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            running(),
            || {
                std::future::ready(Err(CoordinatorError::new(
                    "deployment-invalid",
                    "test refusal",
                )))
            },
            {
                let ticks = ticks.clone();
                move || {
                    increment(&ticks);
                    std::future::ready(Ok(false))
                }
            },
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(DEPLOYMENT_RECHECK_INTERVAL).await;
        assert_eq!(task.await.unwrap().unwrap_err().code, "deployment-invalid");
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_only_rechecks_without_ever_polling_the_worker() {
        let checks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            true,
            running(),
            {
                let checks = checks.clone();
                move || {
                    increment(&checks);
                    std::future::ready(Ok(()))
                }
            },
            || async { panic!("recovery-only mode must never dispatch") },
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(DEPLOYMENT_RECHECK_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    fn refusal(code: &'static str) -> CoordinatorError {
        CoordinatorError::new(code, "synthetic refusal")
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_only_waits_out_an_unreachable_database_without_polling() {
        let checks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            true,
            running(),
            {
                let checks = checks.clone();
                move || {
                    let check = checks.fetch_add(1, Ordering::SeqCst) + 1;
                    std::future::ready(if check == 1 {
                        Err(refusal("store-unavailable"))
                    } else {
                        Ok(())
                    })
                }
            },
            || async { panic!("recovery-only mode must never dispatch") },
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(DEPLOYMENT_RECHECK_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert!(!task.is_finished());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn failure_pauses_double_from_one_second_to_the_refresh_interval() {
        let seconds: Vec<u64> = [1, 2, 3, 4, 5, 6, 7, u32::MAX]
            .into_iter()
            .map(|failures| retry_delay(failures).as_secs())
            .collect();
        assert_eq!(seconds, [1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_tick_waits_and_confirms_the_deployment_before_the_next_tick() {
        let checks = Arc::new(AtomicUsize::new(0));
        let ticks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            running(),
            {
                let checks = checks.clone();
                move || {
                    increment(&checks);
                    std::future::ready(Ok(()))
                }
            },
            {
                let ticks = ticks.clone();
                move || {
                    let tick = ticks.fetch_add(1, Ordering::SeqCst) + 1;
                    std::future::ready(if tick <= 2 {
                        Err(refusal("worker-unavailable"))
                    } else {
                        Ok(false)
                    })
                }
            },
        ));
        let observe = || (checks.load(Ordering::SeqCst), ticks.load(Ordering::SeqCst));
        tokio::task::yield_now().await;
        assert_eq!(observe(), (0, 1), "the first tick failed");
        for (advance, seen) in [
            (999, (0, 1)),
            (1, (1, 2)),
            (1_999, (1, 2)),
            (1, (2, 3)),
            (100, (2, 4)),
        ] {
            tokio::time::advance(Duration::from_millis(advance)).await;
            tokio::task::yield_now().await;
            assert_eq!(observe(), seen, "{advance} ms later");
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_database_holds_every_tick_until_the_deployment_is_confirmed() {
        let checks = Arc::new(AtomicUsize::new(0));
        let ticks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            running(),
            {
                let checks = checks.clone();
                move || {
                    let check = checks.fetch_add(1, Ordering::SeqCst) + 1;
                    std::future::ready(if check <= 2 {
                        Err(refusal("store-unavailable"))
                    } else {
                        Ok(())
                    })
                }
            },
            {
                let ticks = ticks.clone();
                move || {
                    let tick = ticks.fetch_add(1, Ordering::SeqCst) + 1;
                    std::future::ready(if tick == 1 {
                        Err(refusal("worker-unavailable"))
                    } else {
                        Ok(false)
                    })
                }
            },
        ));
        let observe = || (checks.load(Ordering::SeqCst), ticks.load(Ordering::SeqCst));
        tokio::task::yield_now().await;
        assert_eq!(observe(), (0, 1));
        for (advance, seen) in [
            (1_000, (1, 1)),
            (2_000, (2, 1)),
            (3_999, (2, 1)),
            (1, (3, 2)),
            (100, (3, 3)),
        ] {
            tokio::time::advance(Duration::from_millis(advance)).await;
            tokio::task::yield_now().await;
            assert_eq!(observe(), seen, "{advance} ms later");
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn a_moved_fence_found_after_a_failed_tick_stops_the_service() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            running(),
            || std::future::ready(Err(refusal("deployment.refused"))),
            {
                let ticks = ticks.clone();
                move || {
                    increment(&ticks);
                    std::future::ready(Err(refusal("worker-unavailable")))
                }
            },
        ));
        assert_eq!(task.await.unwrap().unwrap_err().code, "deployment.refused");
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_finishes_the_poll_in_flight_and_polls_nothing_more() {
        let (stop, stopped) = watch::channel(false);
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            stopped,
            || std::future::ready(Ok(())),
            {
                let (started, finished) = (started.clone(), finished.clone());
                move || {
                    let (started, finished) = (started.clone(), finished.clone());
                    async move {
                        increment(&started);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        increment(&finished);
                        Ok(true)
                    }
                }
            },
        ));
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::SeqCst), 1);
        stop.send_replace(true);
        let begun = Instant::now();
        task.await.unwrap().unwrap();
        assert_eq!(begun.elapsed(), Duration::from_secs(5));
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(finished.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_during_a_failure_pause_ends_the_loop_without_another_check() {
        let (stop, stopped) = watch::channel(false);
        let checks = Arc::new(AtomicUsize::new(0));
        let ticks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            stopped,
            {
                let checks = checks.clone();
                move || {
                    increment(&checks);
                    std::future::ready(Ok(()))
                }
            },
            {
                let ticks = ticks.clone();
                move || {
                    increment(&ticks);
                    std::future::ready(Err(refusal("worker-unavailable")))
                }
            },
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(500)).await;
        stop.send_replace(true);
        let begun = Instant::now();
        task.await.unwrap().unwrap();
        assert_eq!(begun.elapsed(), Duration::ZERO);
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_requested_during_a_check_leases_nothing() {
        let (stop, stopped) = watch::channel(false);
        let stop = Arc::new(stop);
        let ticks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            stopped,
            {
                let stop = stop.clone();
                move || {
                    stop.send_replace(true);
                    std::future::ready(Ok(()))
                }
            },
            {
                let ticks = ticks.clone();
                move || {
                    let tick = ticks.fetch_add(1, Ordering::SeqCst) + 1;
                    std::future::ready(if tick == 1 {
                        Err(refusal("worker-unavailable"))
                    } else {
                        Ok(false)
                    })
                }
            },
        ));
        task.await.unwrap().unwrap();
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_ends_recovery_only_between_checks() {
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            true,
            stopped,
            || std::future::ready(Ok(())),
            || async { panic!("recovery-only mode must never dispatch") },
        ));
        tokio::task::yield_now().await;
        stop.send_replace(true);
        task.await.unwrap().unwrap();
    }

    #[test]
    fn the_shutdown_grace_covers_one_attempt_and_its_finalization() {
        assert_eq!(SHUTDOWN_GRACE, Duration::from_secs(15));
        assert_eq!(
            SHUTDOWN_GRACE,
            ATTEMPT_TIMEOUT + LEASE_FINALIZATION_ALLOWANCE
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops_the_listener_and_waits_for_the_attempt_in_flight() {
        let (stop, stopped) = watch::channel(false);
        let listener_stopped = Arc::new(AtomicBool::new(false));
        let attempt_finished = Arc::new(AtomicBool::new(false));
        let server = {
            let (stopped, listener_stopped) = (stopped.clone(), listener_stopped.clone());
            async move {
                stop_requested(stopped).await;
                listener_stopped.store(true, Ordering::SeqCst);
                Ok(())
            }
        };
        let worker = {
            let attempt_finished = attempt_finished.clone();
            async move {
                stop_requested(stopped).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                attempt_finished.store(true, Ordering::SeqCst);
                Ok(())
            }
        };
        let begun = Instant::now();
        serve_until(
            server,
            worker,
            tokio::time::sleep(Duration::from_secs(1)),
            stop,
        )
        .await
        .unwrap();
        assert_eq!(begun.elapsed(), Duration::from_secs(6));
        assert!(listener_stopped.load(Ordering::SeqCst));
        assert!(attempt_finished.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_leaves_an_unfinished_attempt_to_lease_expiry_after_the_grace() {
        let (stop, stopped) = watch::channel(false);
        let begun = Instant::now();
        serve_until(
            async {
                stop_requested(stopped).await;
                Ok(())
            },
            std::future::pending(),
            std::future::ready(()),
            stop,
        )
        .await
        .unwrap();
        assert_eq!(begun.elapsed(), SHUTDOWN_GRACE);
    }

    #[tokio::test(start_paused = true)]
    async fn a_worker_failure_before_shutdown_still_stops_the_service_with_its_error() {
        let (stop, stopped) = watch::channel(false);
        let error = serve_until(
            async {
                stop_requested(stopped).await;
                Ok(())
            },
            std::future::ready(Err(refusal("deployment.refused"))),
            std::future::pending(),
            stop,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "deployment.refused");
    }

    #[tokio::test(start_paused = true)]
    async fn a_listener_failure_during_shutdown_is_reported() {
        let (stop, stopped) = watch::channel(false);
        let error = serve_until(
            {
                let stopped = stopped.clone();
                async {
                    stop_requested(stopped).await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Err(refusal("listener-unavailable"))
                }
            },
            async {
                stop_requested(stopped).await;
                Ok(())
            },
            std::future::ready(()),
            stop,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "listener-unavailable");
    }

    #[cfg(feature = "postgres-test")]
    #[tokio::test]
    #[ignore = "requires dedicated disposable PostgreSQL 17+ via COORDINATOR_TEST_DATABASE_URL"]
    async fn activation_changes_fence_real_worker_transactions_before_the_cached_refresh() {
        use crate::{protocol::CallOutcome, protocol::CallRequest, store::Store};

        struct NoCalls;
        #[async_trait::async_trait]
        impl AdapterSet for NoCalls {
            fn binding_digest(&self) -> &str {
                "synthetic-binding"
            }
            async fn call(&self, _: &CallRequest) -> CallOutcome {
                panic!("this isolated idle-worker fixture must never call a product")
            }
        }

        let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("a dedicated disposable PostgreSQL database is required");
        let namespace = format!("coordinator_{}", uuid::Uuid::new_v4().simple());
        let store = Store::connect(&url, &namespace).await.unwrap();
        store.migrate().await.unwrap();
        let client = store.client().await.unwrap();
        client
            .execute(
                "UPDATE control SET active_flows_digest=$1 WHERE id",
                &[&"synthetic-current-workflows"],
            )
            .await
            .unwrap();
        let store = Arc::new(store.with_workflows_digest("synthetic-current-workflows".into()));
        let worker = Worker::new(store, Arc::new(NoCalls));
        assert!(!worker.tick().await.unwrap());
        client
            .execute(
                "UPDATE control SET active_flows_digest=$1 WHERE id",
                &[&"synthetic-replacement-workflows"],
            )
            .await
            .unwrap();
        // The worker transaction itself refuses the moved activation.
        assert_eq!(worker.tick().await.unwrap_err().code, "worker-unavailable");
        // The loop then confirms the deployment before any further tick, and
        // the moved activation it finds stops the service.
        let ticks = AtomicUsize::new(0);
        let error = worker_loop(
            Duration::from_millis(100),
            false,
            running(),
            || async {
                let row = client
                    .query_one("SELECT active_flows_digest FROM control WHERE id", &[])
                    .await
                    .unwrap();
                let active: String = row.get(0);
                if active == "synthetic-current-workflows" {
                    Ok(())
                } else {
                    Err(refusal("deployment.refused"))
                }
            },
            || {
                increment(&ticks);
                worker.tick()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "deployment.refused");
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }
}
