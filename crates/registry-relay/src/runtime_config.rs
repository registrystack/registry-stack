// SPDX-License-Identifier: Apache-2.0
//! Runtime configuration snapshot and swap handle.
//!
//! Request handlers read compiled runtime state through [`RuntimeSnapshot`],
//! which loads from [`RelayRuntimeHandle`] on the production path and keeps
//! compatibility fallbacks for older test builders.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::Extension;
use datafusion::execution::context::SessionContext;
use hmac::{KeyInit, Mac, SimpleHmac};
use registry_manifest_core::CompiledMetadata;
use registry_platform_ops::{ConfigProvenance, PendingBundleAcceptance};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::attribute_release::AttributeReleaseEvaluator;
use crate::audit::AuditPipeline;
use crate::auth::middleware::AuthProviderRef;
use crate::config::Config;
use crate::entity::EntityRegistry;
use crate::ingest::{IngestRegistry, ReadinessSnapshot};
use crate::observability::RequestMetrics;
use crate::query::{AggregateQueryEngine, EntityQueryEngine};
#[cfg(feature = "spdci-api-standards")]
use crate::spdci::SpdciResponseMapper;

/// Truncated HMAC tag length, in bytes. 16 bytes (128 bits) preserves
/// the standard collision-resistance bound for HMAC while keeping the
/// hex-encoded cursor short.
pub(crate) const CURSOR_MAC_LEN: usize = 16;

/// Server-side signer for opaque pagination cursors.
///
/// The key is generated at startup from the OS CSPRNG via
/// [`getrandom::fill`] and lives only in process memory; restarting the
/// gateway invalidates outstanding cursors, which is acceptable for
/// opaque pagination tokens (clients must always be prepared for
/// `pagination.cursor_invalidated`). Held in [`Zeroizing`] so the key
/// is wiped on drop.
pub struct CursorSigner {
    key: Zeroizing<[u8; 32]>,
}

impl CursorSigner {
    /// Generate a fresh signer with a random 32-byte key.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is unavailable. On supported targets
    /// (Linux, macOS, BSD, Windows) `getrandom` only fails in
    /// catastrophic conditions (e.g. early-boot before the kernel pool
    /// is seeded); failing fast at startup is preferred over running
    /// the gateway without cursor integrity.
    #[must_use]
    pub fn new_random() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut_slice()).expect("OS CSPRNG must be available at startup");
        Self { key }
    }

    fn tag(&self, message: &[u8]) -> [u8; CURSOR_MAC_LEN] {
        let mut mac = <SimpleHmac<Sha256> as KeyInit>::new_from_slice(self.key.as_ref())
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(message);
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; CURSOR_MAC_LEN];
        tag.copy_from_slice(&full[..CURSOR_MAC_LEN]);
        tag
    }

    #[must_use]
    pub fn sign_payload(&self, message: &[u8]) -> [u8; CURSOR_MAC_LEN] {
        self.tag(message)
    }

    /// Constant-time verify that `tag` is the MAC of `message`.
    #[must_use]
    pub fn verify_payload(&self, message: &[u8], tag: &[u8]) -> bool {
        if tag.len() != CURSOR_MAC_LEN {
            return false;
        }
        let expected = self.tag(message);
        expected.ct_eq(tag).into()
    }
}

impl std::fmt::Debug for CursorSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CursorSigner").finish_non_exhaustive()
    }
}

/// Fully compiled runtime objects derived from one validated config load.
#[non_exhaustive]
pub struct RelayRuntimeSnapshot {
    pub config: Arc<Config>,
    pub config_provenance: ConfigProvenance,
    pub compiled_metadata: Option<Arc<CompiledMetadata>>,
    pub metadata_source_digest: Option<String>,
    pub metadata_package_digest: Option<String>,
    pub pending_bundle_acceptance: Option<PendingBundleAcceptance>,
    pub auth: AuthProviderRef,
    pub audit_sink: Arc<AuditPipeline>,
    pub bind: SocketAddr,
    pub admin_bind: Option<SocketAddr>,
    pub audit_kind: &'static str,
    pub df_ctx: Arc<SessionContext>,
    pub ingest: Arc<IngestRegistry>,
    pub entity_registry: Arc<EntityRegistry>,
    pub query: Arc<EntityQueryEngine>,
    pub aggregate_query: Arc<AggregateQueryEngine>,
    pub readiness_tx: watch::Sender<ReadinessSnapshot>,
    pub readiness_rx: watch::Receiver<ReadinessSnapshot>,
    pub cursor_signer: Arc<CursorSigner>,
    pub attribute_release_evaluator: Arc<AttributeReleaseEvaluator>,
    #[cfg(feature = "spdci-api-standards")]
    pub spdci_response_mapper: Option<Arc<SpdciResponseMapper>>,
    pub metrics: Arc<RequestMetrics>,
}

impl RelayRuntimeSnapshot {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        config_provenance: ConfigProvenance,
        compiled_metadata: Option<Arc<CompiledMetadata>>,
        metadata_source_digest: Option<String>,
        metadata_package_digest: Option<String>,
        pending_bundle_acceptance: Option<PendingBundleAcceptance>,
        auth: AuthProviderRef,
        audit_sink: Arc<AuditPipeline>,
        bind: SocketAddr,
        admin_bind: Option<SocketAddr>,
        audit_kind: &'static str,
        df_ctx: Arc<SessionContext>,
        ingest: Arc<IngestRegistry>,
        entity_registry: Arc<EntityRegistry>,
        query: Arc<EntityQueryEngine>,
        aggregate_query: Arc<AggregateQueryEngine>,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
        readiness_rx: watch::Receiver<ReadinessSnapshot>,
        cursor_signer: Arc<CursorSigner>,
        #[cfg(feature = "spdci-api-standards")] spdci_response_mapper: Option<
            Arc<SpdciResponseMapper>,
        >,
        metrics: Arc<RequestMetrics>,
    ) -> Self {
        let attribute_release_evaluator =
            Arc::new(AttributeReleaseEvaluator::from_config(config.as_ref()));
        Self {
            config,
            config_provenance,
            compiled_metadata,
            metadata_source_digest,
            metadata_package_digest,
            pending_bundle_acceptance,
            auth,
            audit_sink,
            bind,
            admin_bind,
            audit_kind,
            df_ctx,
            ingest,
            entity_registry,
            query,
            aggregate_query,
            readiness_tx,
            readiness_rx,
            cursor_signer,
            attribute_release_evaluator,
            #[cfg(feature = "spdci-api-standards")]
            spdci_response_mapper,
            metrics,
        }
    }

    #[must_use]
    pub fn dataset_count(&self) -> usize {
        self.config.datasets.len()
    }

    #[must_use]
    pub fn auth_size_hint(&self) -> usize {
        match self.config.auth.mode {
            crate::config::AuthMode::ApiKey => self.config.auth.api_keys.len(),
            crate::config::AuthMode::Oidc => 0,
        }
    }
}

/// Atomically swappable pointer to the active runtime snapshot.
pub struct RelayRuntimeHandle {
    inner: ArcSwap<RelayRuntimeSnapshot>,
}

impl RelayRuntimeHandle {
    #[must_use]
    pub fn new(snapshot: RelayRuntimeSnapshot) -> Self {
        Self {
            inner: ArcSwap::from_pointee(snapshot),
        }
    }

    #[must_use]
    pub fn load_full(&self) -> Arc<RelayRuntimeSnapshot> {
        self.inner.load_full()
    }

    pub fn store(&self, snapshot: RelayRuntimeSnapshot) {
        self.inner.store(Arc::new(snapshot));
    }
}

/// Request extractor that reads the current runtime snapshot through the
/// swappable runtime handle.
///
/// Live-apply code may treat an accessor as hot-swappable only when it is
/// documented in the runtime component classification contract and the caller
/// does not hold cloned sub-component `Arc`s across await points as if they
/// would refresh independently. Components with captured state, such as query
/// engines and the DataFusion context, stay restart-required until a dedicated
/// stale-state regression test promotes them.
pub struct RuntimeSnapshot {
    handle: Option<Arc<RelayRuntimeHandle>>,
    snapshot: Option<Arc<RelayRuntimeSnapshot>>,
    config: Option<Arc<Config>>,
    config_provenance: Option<ConfigProvenance>,
    compiled_metadata: Option<Arc<CompiledMetadata>>,
    metadata_source_digest: Option<String>,
    metadata_package_digest: Option<String>,
    ingest: Option<Arc<IngestRegistry>>,
    entity_registry: Option<Arc<EntityRegistry>>,
    query: Option<Arc<EntityQueryEngine>>,
    aggregate_query: Option<Arc<AggregateQueryEngine>>,
    readiness_tx: Option<watch::Sender<ReadinessSnapshot>>,
    readiness_rx: Option<watch::Receiver<ReadinessSnapshot>>,
    cursor_signer: Option<Arc<CursorSigner>>,
    audit_sink: Option<Arc<AuditPipeline>>,
    attribute_release_evaluator: Option<Arc<AttributeReleaseEvaluator>>,
    #[cfg(feature = "spdci-api-standards")]
    spdci_response_mapper: Option<Arc<SpdciResponseMapper>>,
    metrics: Option<Arc<RequestMetrics>>,
}

impl RuntimeSnapshot {
    #[must_use]
    pub fn handle(&self) -> Option<Arc<RelayRuntimeHandle>> {
        self.handle.clone()
    }

    #[must_use]
    pub fn load(&self) -> Option<Arc<RelayRuntimeSnapshot>> {
        self.snapshot.clone()
    }

    #[must_use]
    pub fn config(&self) -> Option<Arc<Config>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.config))
            .or_else(|| self.config.clone())
    }

    #[must_use]
    pub fn config_provenance(&self) -> Option<ConfigProvenance> {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.config_provenance.clone())
            .or_else(|| self.config_provenance.clone())
    }

    #[must_use]
    pub fn compiled_metadata(&self) -> Option<Arc<CompiledMetadata>> {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.compiled_metadata.clone())
            .or_else(|| self.compiled_metadata.clone())
    }

    #[must_use]
    pub fn metadata_source_digest(&self) -> Option<String> {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.metadata_source_digest.clone())
            .or_else(|| self.metadata_source_digest.clone())
    }

    #[must_use]
    pub fn metadata_package_digest(&self) -> Option<String> {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.metadata_package_digest.clone())
            .or_else(|| self.metadata_package_digest.clone())
    }

    #[must_use]
    pub fn ingest(&self) -> Option<Arc<IngestRegistry>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.ingest))
            .or_else(|| self.ingest.clone())
    }

    #[must_use]
    pub fn entity_registry(&self) -> Option<Arc<EntityRegistry>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.entity_registry))
            .or_else(|| self.entity_registry.clone())
    }

    #[must_use]
    pub fn query(&self) -> Option<Arc<EntityQueryEngine>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.query))
            .or_else(|| self.query.clone())
    }

    #[must_use]
    pub fn aggregate_query(&self) -> Option<Arc<AggregateQueryEngine>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.aggregate_query))
            .or_else(|| self.aggregate_query.clone())
    }

    #[must_use]
    pub fn readiness_tx(&self) -> Option<watch::Sender<ReadinessSnapshot>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.readiness_tx.clone())
            .or_else(|| self.readiness_tx.clone())
    }

    #[must_use]
    pub fn readiness_rx(&self) -> Option<watch::Receiver<ReadinessSnapshot>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.readiness_rx.clone())
            .or_else(|| self.readiness_rx.clone())
    }

    #[must_use]
    pub fn cursor_signer(&self) -> Option<Arc<CursorSigner>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.cursor_signer))
            .or_else(|| self.cursor_signer.clone())
    }

    #[must_use]
    pub fn audit_sink(&self) -> Option<Arc<AuditPipeline>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.audit_sink))
            .or_else(|| self.audit_sink.clone())
    }

    #[must_use]
    pub fn attribute_release_evaluator(&self) -> Option<Arc<AttributeReleaseEvaluator>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.attribute_release_evaluator))
            .or_else(|| self.attribute_release_evaluator.clone())
    }

    #[cfg(feature = "spdci-api-standards")]
    #[must_use]
    pub fn spdci_response_mapper(&self) -> Option<Arc<SpdciResponseMapper>> {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.spdci_response_mapper.clone())
            .or_else(|| self.spdci_response_mapper.clone())
    }

    #[must_use]
    pub fn metrics(&self) -> Option<Arc<RequestMetrics>> {
        self.snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(&snapshot.metrics))
            .or_else(|| self.metrics.clone())
    }
}

impl<S> FromRequestParts<S> for RuntimeSnapshot
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let handle = Option::<Extension<Arc<RelayRuntimeHandle>>>::from_request_parts(parts, state)
            .await
            .unwrap_or(None)
            .map(|Extension(handle)| handle);
        let snapshot = handle.as_ref().map(|handle| handle.load_full());
        Ok(Self {
            handle,
            snapshot,
            config: Option::<Extension<Arc<Config>>>::from_request_parts(parts, state)
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
            config_provenance: Option::<Extension<ConfigProvenance>>::from_request_parts(
                parts, state,
            )
            .await
            .unwrap_or(None)
            .map(|Extension(value)| value),
            compiled_metadata: Option::<Extension<Arc<CompiledMetadata>>>::from_request_parts(
                parts, state,
            )
            .await
            .unwrap_or(None)
            .map(|Extension(value)| value),
            metadata_source_digest: None,
            metadata_package_digest: None,
            ingest: Option::<Extension<Arc<IngestRegistry>>>::from_request_parts(parts, state)
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
            entity_registry: Option::<Extension<Arc<EntityRegistry>>>::from_request_parts(
                parts, state,
            )
            .await
            .unwrap_or(None)
            .map(|Extension(value)| value),
            query: Option::<Extension<Arc<EntityQueryEngine>>>::from_request_parts(parts, state)
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
            aggregate_query: Option::<Extension<Arc<AggregateQueryEngine>>>::from_request_parts(
                parts, state,
            )
            .await
            .unwrap_or(None)
            .map(|Extension(value)| value),
            readiness_tx:
                Option::<Extension<watch::Sender<ReadinessSnapshot>>>::from_request_parts(
                    parts, state,
                )
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
            readiness_rx:
                Option::<Extension<watch::Receiver<ReadinessSnapshot>>>::from_request_parts(
                    parts, state,
                )
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
            cursor_signer: Option::<Extension<Arc<CursorSigner>>>::from_request_parts(parts, state)
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
            audit_sink: Option::<Extension<Arc<AuditPipeline>>>::from_request_parts(parts, state)
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
            attribute_release_evaluator:
                Option::<Extension<Arc<AttributeReleaseEvaluator>>>::from_request_parts(
                    parts, state,
                )
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
            #[cfg(feature = "spdci-api-standards")]
            spdci_response_mapper:
                Option::<Extension<Arc<SpdciResponseMapper>>>::from_request_parts(parts, state)
                    .await
                    .unwrap_or(None)
                    .map(|Extension(value)| value),
            metrics: Option::<Extension<Arc<RequestMetrics>>>::from_request_parts(parts, state)
                .await
                .unwrap_or(None)
                .map(|Extension(value)| value),
        })
    }
}
