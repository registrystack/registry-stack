// SPDX-License-Identifier: Apache-2.0
use crate::{
    adapters::HttpAdapters,
    deployment,
    http::{self, HttpState},
    protocol::AdapterSet,
    runtime::RuntimeConfig,
    worker::Worker,
    PocError, Result,
};
use clap::{CommandFactory, Parser};
use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::Instant;

// Full schema/role inspection is an operator health check. Each worker
// transaction still verifies package activation and key custody before I/O.
const DEPLOYMENT_RECHECK_INTERVAL: Duration = Duration::from_secs(30);
#[derive(Parser)]
#[command(
    name = "coordinator",
    about = "Authenticated Registry Coordinator service for controlled institutional pilots",
    version
)]
struct Cli {
    /// Absolute runtime configuration file.
    #[arg(long, value_name = "FILE")]
    runtime_config: PathBuf,
    /// Milliseconds between worker polls.
    #[arg(long,default_value_t=100,value_parser=clap::value_parser!(u64).range(10..=10_000))]
    poll_ms: u64,
    /// Serve authenticated recovery operations with worker dispatch disabled.
    #[arg(long)]
    recovery_only: bool,
}
async fn execute(cli: Cli) -> Result<()> {
    let runtime = Arc::new(RuntimeConfig::load(&cli.runtime_config)?);
    let d = deployment::config(&runtime)?;
    let package = Arc::new(deployment::load_package(d)?);
    runtime.validate_workflow(&package.definition.workflow)?;
    let authenticator = Arc::new(
        d.authentication
            .authenticator(&runtime.secret_providers, d.local())
            .await?,
    );
    let store = deployment::open(&runtime, false).await?;
    if cli.recovery_only {
        deployment::check(&store, &runtime, &package.digest).await?;
    } else {
        deployment::check_serving(&store, &runtime, &package.digest).await?;
    }
    let adapters: Arc<dyn AdapterSet> = Arc::new(HttpAdapters::new(&runtime)?);
    let worker = Worker::new(store.clone(), adapters.clone());
    let listener = tokio::net::TcpListener::bind(d.listener.bind.socket_addr())
        .await
        .map_err(|_| {
            PocError::new(
                "coordinator.command.listener-unavailable",
                "cannot bind the configured private listener",
            )
        })?;
    let state = HttpState {
        recovery_only: cli.recovery_only,
        store: store.clone(),
        runtime: runtime.clone(),
        package: package.clone(),
        authenticator,
        adapters,
    };
    let server = axum::serve(listener, http::router(state)).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    tokio::select! {
     result=server=>result.map_err(|_|PocError::new("coordinator.command.listener-unavailable","the private listener stopped")),
     result=worker_loop(
         Duration::from_millis(cli.poll_ms),
         cli.recovery_only,
         || async { deployment::check(&store, &runtime, &package.digest).await.map(|_| ()) },
         || worker.tick(),
     )=>result
    }
}
// The startup check has already succeeded before the listener is bound. Reuse
// it between bounded refreshes without caching protected transaction decisions.
async fn worker_loop<C, CF, W, WF>(
    poll_interval: Duration,
    recovery_only: bool,
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
    loop {
        if Instant::now() >= next_check {
            // Failure ends the service before this poll can dispatch work.
            check().await?;
            next_check = Instant::now() + DEPLOYMENT_RECHECK_INTERVAL;
        }
        if !recovery_only {
            // Store activation, hold, custody and audit gates are never cached.
            tick().await?;
        }
        tokio::time::sleep(poll_interval).await;
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn increment(counter: &AtomicUsize) {
        counter.fetch_add(1, Ordering::SeqCst);
    }

    #[tokio::test(start_paused = true)]
    async fn polls_reuse_startup_validation_until_the_fixed_refresh_deadline() {
        let checks = Arc::new(AtomicUsize::new(1));
        let ticks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
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
            || {
                std::future::ready(Err(PocError::new(
                    "coordinator.command.deployment-invalid",
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
        assert_eq!(
            task.await.unwrap().unwrap_err().code,
            "coordinator.command.deployment-invalid"
        );
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_only_rechecks_without_ever_polling_the_worker() {
        let checks = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            true,
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

    #[tokio::test(start_paused = true)]
    async fn worker_transaction_refusals_still_end_the_loop_between_refreshes() {
        let task = tokio::spawn(worker_loop(
            Duration::from_millis(100),
            false,
            || async { panic!("the cached deployment check is not yet due") },
            || {
                std::future::ready(Err(PocError::new(
                    "coordinator.command.worker-unavailable",
                    "test fence refusal",
                )))
            },
        ));
        assert_eq!(
            task.await.unwrap().unwrap_err().code,
            "coordinator.command.worker-unavailable"
        );
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
                "UPDATE control SET active_package_digest=$1 WHERE id",
                &[&"synthetic-current-package"],
            )
            .await
            .unwrap();
        let store = Arc::new(store.with_package_digest("synthetic-current-package".into()));
        let worker = Worker::new(store, Arc::new(NoCalls));
        assert!(!worker.tick().await.unwrap());
        client
            .execute(
                "UPDATE control SET active_package_digest=$1 WHERE id",
                &[&"synthetic-replacement-package"],
            )
            .await
            .unwrap();
        let error = worker_loop(
            Duration::from_millis(100),
            false,
            || async { panic!("the deployment refresh is not due for another 30 seconds") },
            || worker.tick(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "coordinator.command.worker-unavailable");
    }
}
