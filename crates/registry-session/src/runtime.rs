// SPDX-License-Identifier: Apache-2.0

//! Assembling the service from a loaded runtime file, and serving its two
//! listeners.

use std::sync::Arc;

use axum::Router;
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_ratelimit::token_bucket::{TokenBucketConfig, TokenBucketLimiter};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::check::{check_router, Checker};
use crate::clock::SystemClock;
use crate::config::{describe_secret_failure, RateLimitConfig, RuntimeConfig};
use crate::issuer::HttpIssuer;
use crate::journal::Journal;
use crate::public::{self, App};
use crate::store::Store;

/// Why the service could not start. The text names the member at fault and
/// never a value.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("{0}")]
    Secret(String),
    #[error("a signIns.clientSecretRef does not hold UTF-8 text")]
    ClientSecret,
    #[error("the issuer client could not be configured: {0}")]
    Issuer(String),
    #[error("the audit journal could not be opened: {0}")]
    Audit(String),
    #[error("rateLimits could not be configured")]
    Limits,
}

/// The two routers of a running service: the public listener's and the
/// gateway check listener's.
pub struct Service {
    pub public: Router,
    pub check: Router,
}

fn limiter(rate: RateLimitConfig) -> Result<TokenBucketLimiter, RuntimeError> {
    TokenBucketLimiter::new(TokenBucketConfig {
        requests_per_minute: rate.requests_per_minute.get(),
        burst: rate.burst.get(),
    })
    .map_err(|_| RuntimeError::Limits)
}

impl Service {
    /// Resolve the secrets, open the audit journal and build both routers. A
    /// `writer` replaces the configured audit destination, for tests.
    pub async fn build(
        config: RuntimeConfig,
        writer: Option<AuditWriter>,
    ) -> Result<Self, RuntimeError> {
        let secrets = config.secret_providers.resolver().map_err(|error| {
            RuntimeError::Secret(describe_secret_failure(
                "secretProviders",
                "secret providers",
                &error,
            ))
        })?;
        let audit_reference = config.audit.key.hash_key_ref.as_str();
        let audit_key = secrets.resolve(audit_reference).map_err(|error| {
            RuntimeError::Secret(describe_secret_failure(
                "audit.hashKeyRef",
                audit_reference,
                &error,
            ))
        })?;
        let audit_profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(
            audit_key.expose_secret().to_vec(),
        ))
        .map_err(|error| RuntimeError::Audit(error.to_string()))?;
        drop(audit_key);
        let issuer = Arc::new(HttpIssuer::new(&config, &secrets)?);

        let writer = match writer {
            Some(writer) => writer,
            None => AuditWriter::open_without_posture(
                config
                    .audit
                    .destination()
                    .map_err(|error| RuntimeError::Audit(error.to_string()))?,
            )
            .await
            .map_err(|error| RuntimeError::Audit(error.operator_description()))?,
        };
        let journal = Arc::new(
            Journal::new(
                writer,
                audit_profile.key_hasher(),
                config.issuer.id.as_str(),
                config
                    .sign_ins
                    .iter()
                    .map(|sign_in| (sign_in.id.as_str(), sign_in.client_id.as_str())),
            )
            .map_err(|_| {
                RuntimeError::Audit("a client pseudonym could not be derived".to_owned())
            })?,
        );

        let config = Arc::new(config);
        let store = Arc::new(Store::new(
            Arc::new(SystemClock),
            config.session.sessions(),
            config.session.pending_sign_ins(),
        ));
        let checker = Checker::new(config.clone(), store.clone(), issuer.clone())
            .with_journal(journal.clone());
        let app = Arc::new(App {
            global_sign_in: limiter(config.rate_limits.global_sign_in)?,
            per_person: limiter(config.rate_limits.per_person)?,
            config,
            store,
            grants: issuer,
            journal,
        });
        Ok(Self {
            public: public::router(app),
            check: check_router(checker),
        })
    }
}

/// Serve `router` on `listener` until `shutdown` completes, letting requests
/// in flight finish.
pub async fn serve_until(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

/// Serve both listeners until the process is interrupted or terminated.
pub async fn serve(
    public: tokio::net::TcpListener,
    check: tokio::net::TcpListener,
    service: Service,
) -> std::io::Result<()> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let (fault_sender, mut fault) = tokio::sync::oneshot::channel::<std::io::Error>();
    tokio::spawn(async move {
        #[cfg(unix)]
        let terminated = terminate.recv();
        #[cfg(not(unix))]
        let terminated = std::future::pending::<Option<()>>();
        tokio::select! {
            interrupted = tokio::signal::ctrl_c() => {
                if let Err(error) = interrupted {
                    tracing::error!(%error, "the interrupt signal cannot be observed");
                    let _ = fault_sender.send(error);
                }
            }
            _ = terminated => {}
        }
        tracing::info!("the session service is shutting down");
        let _ = stop.send(true);
    });
    let until = |mut stopped: tokio::sync::watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let (public_result, check_result) = tokio::join!(
        serve_until(public, service.public, until(stopped.clone())),
        serve_until(check, service.check, until(stopped)),
    );
    public_result?;
    check_result?;
    match fault.try_recv() {
        Ok(error) => Err(error),
        Err(_) => Ok(()),
    }
}
