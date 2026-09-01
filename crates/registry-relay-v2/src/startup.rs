// SPDX-License-Identifier: Apache-2.0
//! Atomic process startup for the Relay V2 `relay` binary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::future::IntoFuture;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use jsonwebtoken::Algorithm;
use registry_platform_audit::{
    AuditChainProfile, AuditSink, ChainState, DurableSegmentedJsonlSink,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    fetch_discovery_at_with_policy, fetch_discovery_with_policy, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, TokenVerifier, TokenVerifierConfig,
};
use thiserror::Error;
use tokio::net::TcpListener;
use url::Url;
use zeroize::Zeroizing;

use crate::audit::RelayAudit;
use crate::auth::RelayAuthenticator;
use crate::contract::{
    contract_has_protected_access, runtime_cursor_configuration_is_valid, IssuerAlgorithm,
    IssuerKeyTransport, IssuerProfile, IssuerRuntime, RegistryContract, RelayRuntime,
    MAXIMUM_RUNTIME_BYTES,
};
use crate::cursor::CursorKey;
use crate::package::{load_package, VerifiedPackage};
use crate::server::{
    router, AlignmentMetadata, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use crate::source_observation::observe_sources;
use crate::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};

const MAXIMUM_AUDIT_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_CURSOR_MAXIMUM_AGE: Duration = Duration::from_secs(300);
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
const ISSUER_NETWORK_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_TOKEN_LIFETIME: Duration = Duration::from_secs(15 * 60);
const TOKEN_CLOCK_LEEWAY: Duration = Duration::from_secs(30);
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_HEALTH_BODY_BYTES: usize = 128;
const HEALTH_BODY: &[u8] = br#"{"status":"ok"}"#;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StartupError {
    #[error("the runtime configuration could not be loaded")]
    RuntimeLoad,
    #[error("the runtime configuration is invalid")]
    RuntimeInvalid,
    #[error("the sealed package could not be verified")]
    PackageInvalid,
    #[error("a runtime source could not be verified")]
    SourceInvalid,
    #[error("the configured issuer is not ready")]
    IssuerUnavailable,
    #[error("the required audit sink is not ready")]
    AuditUnavailable,
    #[error("a required secret is unavailable")]
    SecretUnavailable,
    #[error("the cursor configuration is invalid")]
    CursorInvalid,
    #[error("the service did not become ready")]
    NotReady,
    #[error("the listener could not be started")]
    Listener,
    #[error("the graceful shutdown deadline elapsed")]
    ShutdownTimeout,
    #[error("the healthcheck failed")]
    Healthcheck,
}

/// Fully initialized immutable service state. Constructing this value performs
/// every fallible readiness step except taking the listener socket.
pub struct PreparedRelay {
    bind: SocketAddr,
    service: Arc<RelayService>,
    app: Router,
    shutdown_grace: Duration,
}

/// Verify one runtime and construct its immutable service without listening.
pub async fn prepare(runtime_path: &Path) -> Result<PreparedRelay, StartupError> {
    let (runtime_root, runtime) = load_runtime(runtime_path)?;
    let paths = RuntimePaths::resolve(&runtime_root, &runtime)?;

    // The package is the governed trust root. Verify it before opening issuer,
    // audit, source, or listener resources.
    let package = load_package(&paths.package).map_err(|_| StartupError::PackageInvalid)?;
    validate_runtime_contract(&runtime, &package.contract)?;

    let observed = observe_sources(&runtime_root, &package.contract, &runtime)
        .map_err(|_| StartupError::SourceInvalid)?;
    if observed.len() != package.contract.sources.len() {
        return Err(StartupError::SourceInvalid);
    }
    require_packaged_source_schemas(&package, &observed)?;

    let request_timeout = Duration::from_millis(runtime.limits.request_timeout_milliseconds);
    let sqlite = Arc::new(
        SqliteRuntime::open(
            &package.registry,
            &paths.sources,
            SqliteRuntimeLimits {
                request_timeout,
                concurrent_queries: usize::try_from(runtime.limits.concurrent_queries)
                    .map_err(|_| StartupError::RuntimeInvalid)?,
            },
        )
        .map_err(|_| StartupError::SourceInvalid)?,
    );

    let authenticator = build_authenticator(runtime.authentication.issuer.as_ref()).await?;
    let audit = build_audit(
        &runtime_root,
        &runtime.audit.integrity_key_ref,
        &paths.audit,
    )
    .await?;
    let (cursor_key, cursor_maximum_age) = build_cursor(&runtime_root, &runtime)?;
    let quota = runtime.quotas.as_ref().map(|quota| QuotaConfig {
        requests_per_minute: quota.requests_per_minute,
        burst: quota.burst,
    });
    let metadata = service_metadata(&package.contract);
    let service = Arc::new(RelayService::new(
        Arc::new(package.registry),
        Arc::new(package.artifacts),
        sqlite,
        authenticator,
        audit,
        cursor_key,
        cursor_maximum_age,
        request_timeout,
        quota,
        metadata,
    ));
    if !service.is_ready().await {
        return Err(StartupError::NotReady);
    }
    let bind = runtime
        .server
        .bind
        .parse()
        .map_err(|_| StartupError::RuntimeInvalid)?;
    let shutdown_grace = runtime
        .shutdown
        .as_ref()
        .map_or(DEFAULT_SHUTDOWN_GRACE, |item| {
            Duration::from_millis(item.grace_period_milliseconds)
        });
    Ok(PreparedRelay {
        bind,
        app: router(Arc::clone(&service)),
        service,
        shutdown_grace,
    })
}

/// Validate the complete deployment exactly as startup does without binding a
/// listener. This is the native container preflight used before traffic is
/// routed to a new Relay instance.
pub async fn check(runtime_path: &Path) -> Result<(), StartupError> {
    let prepared = prepare(runtime_path).await?;
    if !prepared.service.is_ready().await {
        return Err(StartupError::NotReady);
    }
    Ok(())
}

/// Prepare atomically, bind only after readiness, and serve until SIGINT or
/// SIGTERM. Configuration and package state never reload in place.
pub async fn serve(runtime_path: &Path) -> Result<(), StartupError> {
    tracing::info!(target: "registry_relay_v2::startup", "relay startup began");
    let prepared = prepare(runtime_path).await?;
    if !prepared.service.is_ready().await {
        return Err(StartupError::NotReady);
    }
    let listener = TcpListener::bind(prepared.bind)
        .await
        .map_err(|_| StartupError::Listener)?;
    let address = listener.local_addr().map_err(|_| StartupError::Listener)?;
    tracing::info!(
        target: "registry_relay_v2::startup",
        bind = %address,
        "relay service listening"
    );
    serve_listener(listener, prepared.app, prepared.shutdown_grace).await
}

async fn serve_listener(
    listener: TcpListener,
    app: Router,
    shutdown_grace: Duration,
) -> Result<(), StartupError> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            while !*shutdown_rx.borrow_and_update() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .into_future();
    tokio::pin!(server);
    let result = tokio::select! {
        result = &mut server => result.map_err(|_| StartupError::Listener),
        () = shutdown_signal() => {
            tracing::info!(target: "registry_relay_v2::startup", "relay shutdown began");
            let _ = shutdown_tx.send(true);
            tokio::time::timeout(shutdown_grace, &mut server)
                .await
                .map_err(|_| StartupError::ShutdownTimeout)?
                .map_err(|_| StartupError::Listener)
        }
    };
    if result.is_ok() {
        tracing::info!(target: "registry_relay_v2::startup", "relay shutdown complete");
    }
    result
}

/// Probe exactly the minimal unauthenticated liveness response.
pub async fn healthcheck(raw_url: &str) -> Result<(), StartupError> {
    let url = Url::parse(raw_url).map_err(|_| StartupError::Healthcheck)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(StartupError::Healthcheck);
    }
    let client = reqwest::Client::builder()
        .timeout(HEALTHCHECK_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // A process-local health probe must not leak its URL or response to an
        // ambient proxy configured for unrelated outbound traffic.
        .no_proxy()
        .build()
        .map_err(|_| StartupError::Healthcheck)?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| StartupError::Healthcheck)?;
    if response.status() != reqwest::StatusCode::OK
        || !response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    {
        return Err(StartupError::Healthcheck);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| StartupError::Healthcheck)?
    {
        if body.len().saturating_add(chunk.len()) > MAXIMUM_HEALTH_BODY_BYTES {
            return Err(StartupError::Healthcheck);
        }
        body.extend_from_slice(&chunk);
    }
    if body != HEALTH_BODY {
        return Err(StartupError::Healthcheck);
    }
    Ok(())
}

fn load_runtime(path: &Path) -> Result<(PathBuf, RelayRuntime), StartupError> {
    let path_metadata = validate_runtime_path(path)?;
    let mut file = fs::File::open(path).map_err(|_| StartupError::RuntimeLoad)?;
    let opened_metadata = file.metadata().map_err(|_| StartupError::RuntimeLoad)?;
    if !opened_metadata.is_file()
        || opened_metadata.len() == 0
        || opened_metadata.len() > MAXIMUM_RUNTIME_BYTES
        || !same_file(&path_metadata, &opened_metadata)
        || !safe_runtime_permissions(&opened_metadata)
    {
        return Err(StartupError::RuntimeInvalid);
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.by_ref()
        .take(MAXIMUM_RUNTIME_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| StartupError::RuntimeLoad)?;
    let final_metadata = validate_runtime_path(path)?;
    if bytes.len() as u64 > MAXIMUM_RUNTIME_BYTES || !same_file(&final_metadata, &opened_metadata) {
        return Err(StartupError::RuntimeInvalid);
    }
    let yaml = std::str::from_utf8(&bytes).map_err(|_| StartupError::RuntimeInvalid)?;
    let runtime = RelayRuntime::parse_yaml(yaml).map_err(|_| StartupError::RuntimeInvalid)?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let root = parent
        .canonicalize()
        .map_err(|_| StartupError::RuntimeLoad)?;
    Ok((root, runtime))
}

#[cfg(unix)]
fn validate_runtime_path(path: &Path) -> Result<fs::Metadata, StartupError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| StartupError::RuntimeLoad)?
            .join(path)
    };
    let effective_user = rustix::process::geteuid().as_raw();
    let component_count = absolute.components().count();
    let mut current = PathBuf::new();
    let mut final_metadata = None;
    for (index, component) in absolute.components().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|_| StartupError::RuntimeLoad)?;
        let final_component = index + 1 == component_count;
        if metadata.file_type().is_symlink()
            || if final_component {
                !metadata.is_file()
                    || !trusted_unix_owner_and_mode(
                        metadata.uid(),
                        metadata.permissions().mode(),
                        effective_user,
                        false,
                    )
            } else {
                !metadata.is_dir()
                    || !trusted_unix_owner_and_mode(
                        metadata.uid(),
                        metadata.permissions().mode(),
                        effective_user,
                        true,
                    )
            }
        {
            return Err(StartupError::RuntimeInvalid);
        }
        if final_component {
            final_metadata = Some(metadata);
        }
    }
    final_metadata.ok_or(StartupError::RuntimeInvalid)
}

#[cfg(unix)]
fn trusted_unix_owner_and_mode(
    owner: u32,
    mode: u32,
    effective_user: u32,
    allow_root_sticky: bool,
) -> bool {
    let trusted_owner = owner == 0 || owner == effective_user;
    let not_writable_by_others = mode & 0o022 == 0;
    let protected_shared_ancestor = allow_root_sticky && owner == 0 && mode & 0o1000 != 0;
    trusted_owner && (not_writable_by_others || protected_shared_ancestor)
}

#[cfg(not(unix))]
fn validate_runtime_path(_path: &Path) -> Result<fs::Metadata, StartupError> {
    // This trust contract depends on Unix ownership and sticky-directory
    // semantics. Platforms without an equivalent implementation fail closed.
    Err(StartupError::RuntimeInvalid)
}

#[cfg(unix)]
fn same_file(path_metadata: &fs::Metadata, opened_metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    path_metadata.dev() == opened_metadata.dev() && path_metadata.ino() == opened_metadata.ino()
}

#[cfg(unix)]
fn safe_runtime_permissions(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    trusted_unix_owner_and_mode(
        metadata.uid(),
        metadata.permissions().mode(),
        rustix::process::geteuid().as_raw(),
        false,
    )
}

#[cfg(not(unix))]
fn same_file(path_metadata: &fs::Metadata, opened_metadata: &fs::Metadata) -> bool {
    path_metadata.len() == opened_metadata.len()
        && path_metadata.modified().ok() == opened_metadata.modified().ok()
}

#[cfg(not(unix))]
fn safe_runtime_permissions(_metadata: &fs::Metadata) -> bool {
    false
}

struct RuntimePaths {
    package: PathBuf,
    sources: BTreeMap<String, RuntimeSourceBinding>,
    audit: PathBuf,
}

impl RuntimePaths {
    fn resolve(root: &Path, runtime: &RelayRuntime) -> Result<Self, StartupError> {
        let package = resolve_binding(root, &runtime.package_path)?;
        reject_existing_symlink_components(&package)?;
        let mut sources = BTreeMap::new();
        for (identifier, source) in runtime.sources.iter() {
            let path = resolve_binding(root, &source.path)?;
            reject_existing_symlink_components(&path)?;
            sources.insert(identifier.to_owned(), RuntimeSourceBinding { path });
        }
        let audit = resolve_binding(root, &runtime.audit.sink)?;
        reject_existing_symlink_components(&audit)?;
        Ok(Self {
            package,
            sources,
            audit,
        })
    }
}

fn resolve_binding(root: &Path, value: &str) -> Result<PathBuf, StartupError> {
    let path = Path::new(value);
    if path.as_os_str().is_empty() {
        return Err(StartupError::RuntimeInvalid);
    }
    if path.is_absolute() {
        if path.components().any(|component| {
            !matches!(
                component,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            )
        }) {
            return Err(StartupError::RuntimeInvalid);
        }
        Ok(path.to_owned())
    } else {
        if path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(StartupError::RuntimeInvalid);
        }
        Ok(root.join(path))
    }
}

fn reject_existing_symlink_components(target: &Path) -> Result<(), StartupError> {
    let mut current = PathBuf::new();
    for component in target.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StartupError::RuntimeInvalid);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(StartupError::RuntimeInvalid),
        }
    }
    Ok(())
}

fn validate_runtime_contract(
    runtime: &RelayRuntime,
    contract: &RegistryContract,
) -> Result<(), StartupError> {
    let governed = contract.sources.keys().collect::<BTreeSet<_>>();
    let bound = runtime.sources.keys().collect::<BTreeSet<_>>();
    if governed != bound {
        return Err(StartupError::RuntimeInvalid);
    }
    if !runtime_cursor_configuration_is_valid(contract, runtime) {
        return Err(StartupError::CursorInvalid);
    }
    if contract_has_protected_access(contract) && runtime.authentication.issuer.is_none() {
        return Err(StartupError::IssuerUnavailable);
    }
    let has_lookup = contract
        .resources
        .iter()
        .any(|resource| !resource.operations.lookups.is_empty());
    if has_lookup && runtime.quotas.is_none() {
        return Err(StartupError::RuntimeInvalid);
    }
    Ok(())
}

fn require_packaged_source_schemas(
    package: &VerifiedPackage,
    observed: &[crate::model::ObservedSourceSchema],
) -> Result<(), StartupError> {
    let observed = observed
        .iter()
        .map(|schema| (schema.source.clone(), schema.clone()))
        .collect::<BTreeMap<_, _>>();
    if observed != package.manifest.source_schemas {
        return Err(StartupError::SourceInvalid);
    }
    Ok(())
}

async fn build_authenticator(
    issuer: Option<&IssuerRuntime>,
) -> Result<Option<RelayAuthenticator>, StartupError> {
    let Some(issuer) = issuer else {
        return Ok(None);
    };
    let profile = verifier_issuer_profile(issuer)?;
    build_authenticator_with_profile(issuer, profile, &FetchUrlPolicy::strict())
        .await
        .map(Some)
}

async fn build_authenticator_with_profile(
    issuer: &IssuerRuntime,
    profile: IssuerProfile,
    fetch_url_policy: &FetchUrlPolicy,
) -> Result<RelayAuthenticator, StartupError> {
    let IssuerProfile {
        issuer_identifier,
        algorithm,
        key_transport,
    } = profile;
    let algorithm = match algorithm {
        IssuerAlgorithm::EdDsa => Algorithm::EdDSA,
        IssuerAlgorithm::Es256 => Algorithm::ES256,
        IssuerAlgorithm::Rs256 => Algorithm::RS256,
    };
    let mut discovery_config = OidcDiscoveryConfig {
        issuer: issuer_identifier.clone(),
        jwks_uri_override: None,
        discovery_timeout: ISSUER_NETWORK_TIMEOUT,
        max_doc_bytes: 1024 * 1024,
    };
    let discovery = match key_transport {
        IssuerKeyTransport::Discovery(discovery_url) => {
            fetch_discovery_at_with_policy(&discovery_config, &discovery_url, fetch_url_policy)
                .await
        }
        IssuerKeyTransport::Jwks(jwks_url) => {
            discovery_config.jwks_uri_override = Some(jwks_url);
            fetch_discovery_with_policy(&discovery_config, fetch_url_policy).await
        }
    }
    .map_err(|_| StartupError::IssuerUnavailable)?;
    if discovery.issuer != issuer_identifier {
        return Err(StartupError::IssuerUnavailable);
    }
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        discovery.jwks_uri,
        JwksFetcherConfig {
            request_timeout: ISSUER_NETWORK_TIMEOUT,
            ..JwksFetcherConfig::defaults()
        },
        fetch_url_policy.clone(),
    ));
    fetcher
        .ensure_key_set()
        .await
        .map_err(|_| StartupError::IssuerUnavailable)?;
    let verifier = TokenVerifier::new(
        TokenVerifierConfig::registry_relay_access_profile(
            issuer_identifier,
            vec![issuer.audience.clone()],
            vec![algorithm],
            issuer.token_types.clone(),
        )
        .with_max_token_lifetime(Some(MAXIMUM_TOKEN_LIFETIME))
        .with_leeway(TOKEN_CLOCK_LEEWAY),
        fetcher,
    );
    Ok(RelayAuthenticator::new(
        Arc::new(verifier),
        issuer.audience.clone(),
        TOKEN_CLOCK_LEEWAY,
    ))
}

/// Build the exact production authenticator over a supervised loopback issuer.
///
/// This exists only with the `tooling` feature so integration tests can prove
/// discovery, JWKS loading, and verifier construction against a real local
/// issuer without weakening the production HTTPS and SSRF policy.
#[cfg(feature = "tooling")]
pub async fn build_authenticator_for_supervised_local_development(
    issuer: &IssuerRuntime,
) -> Result<RelayAuthenticator, StartupError> {
    let profile = issuer
        .supervised_local_profile()
        .ok_or(StartupError::RuntimeInvalid)?;
    build_authenticator_with_profile(issuer, profile, &FetchUrlPolicy::dev()).await
}

fn verifier_issuer_profile(issuer: &IssuerRuntime) -> Result<IssuerProfile, StartupError> {
    issuer.profile().ok_or(StartupError::RuntimeInvalid)
}

async fn build_audit(
    runtime_root: &Path,
    reference: &str,
    path: &Path,
) -> Result<RelayAudit, StartupError> {
    let secret = resolve_secret(runtime_root, reference)?;
    let hasher = AuditChainProfile::production_from_secret_bytes(Zeroizing::new(
        secret.expose_secret().to_vec(),
    ))
    .map_err(|_| StartupError::SecretUnavailable)?;
    let hasher = hasher.hasher();
    let sink = Arc::new(
        DurableSegmentedJsonlSink::open(path, MAXIMUM_AUDIT_SEGMENT_BYTES)
            .map_err(|_| StartupError::AuditUnavailable)?,
    );
    let chain = Arc::new(
        ChainState::bootstrap_or_start_empty(sink.as_ref(), hasher.clone())
            .await
            .map_err(|_| StartupError::AuditUnavailable)?,
    );
    let probe_sink = Arc::clone(&sink);
    let probe_hasher = hasher.clone();
    let sink_for_events: Arc<dyn AuditSink> = sink;
    Ok(
        RelayAudit::new(chain, sink_for_events).with_readiness_check(move || {
            let sink = Arc::clone(&probe_sink);
            let hasher = probe_hasher.clone();
            async move { sink.tail_hash_with_hasher(&hasher).await.is_ok() && sink.ready().await }
        }),
    )
}

fn build_cursor(
    runtime_root: &Path,
    runtime: &RelayRuntime,
) -> Result<(Option<Arc<CursorKey>>, Duration), StartupError> {
    let Some(cursor) = &runtime.cursor else {
        return Ok((None, DEFAULT_CURSOR_MAXIMUM_AGE));
    };
    let secret = resolve_secret(runtime_root, &cursor.integrity_key_ref)?;
    let key =
        CursorKey::new(secret.expose_secret().to_vec()).map_err(|_| StartupError::CursorInvalid)?;
    Ok((
        Some(Arc::new(key)),
        Duration::from_secs(cursor.maximum_age_seconds),
    ))
}

fn resolve_secret(
    runtime_root: &Path,
    reference: &str,
) -> Result<registry_platform_config::ProtectedSecret, StartupError> {
    let resolver = SecretResolver::new(
        [SecretProvider::Environment, SecretProvider::File],
        runtime_root,
    )
    .map_err(|_| StartupError::RuntimeInvalid)?;
    resolver
        .resolve(reference)
        .map_err(|_| StartupError::SecretUnavailable)
}

fn service_metadata(contract: &RegistryContract) -> ServiceMetadata {
    ServiceMetadata {
        authority: InstitutionMetadata {
            identifier: contract.registry.authority.identifier.clone(),
            name: contract.registry.authority.name.clone(),
        },
        operator: contract
            .registry
            .operator
            .as_ref()
            .map(|operator| InstitutionMetadata {
                identifier: operator.identifier.clone(),
                name: operator.name.clone(),
            }),
        authoritative_scope: contract.registry.authoritative_scope.clone(),
        alignment_targets: contract
            .registry
            .alignment_targets
            .iter()
            .map(|target| AlignmentMetadata {
                name: target.name.clone(),
                version: target.version.clone(),
                status: target.status.clone(),
                cfr_target: target.cfr_target.clone(),
            })
            .collect(),
    }
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tokio::io::AsyncWriteExt as _;

    #[test]
    fn environment_and_owner_only_file_secrets_use_the_closed_resolver() {
        const VARIABLE: &str = "RELAY_V2_SECRET_RESOLVER_TEST";
        std::env::set_var(VARIABLE, "synthetic-test-key-material-32-bytes-long");
        let temporary = tempfile::tempdir().expect("temporary root");
        assert_eq!(
            resolve_secret(temporary.path(), &format!("secret:env/{VARIABLE}"))
                .expect("environment secret")
                .expose_secret(),
            b"synthetic-test-key-material-32-bytes-long"
        );

        let path = temporary.path().join("audit-integrity-key");
        fs::write(&path, b"synthetic-file-key-material-32-bytes-long").expect("secret writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secret becomes owner-only");
        }
        assert_eq!(
            resolve_secret(temporary.path(), "secret:file/audit-integrity-key")
                .expect("file secret")
                .expose_secret(),
            b"synthetic-file-key-material-32-bytes-long"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
                .expect("secret becomes unsafe");
            assert!(resolve_secret(temporary.path(), "secret:file/audit-integrity-key").is_err());
        }
    }

    #[test]
    fn configured_paths_may_be_secure_absolute_bindings_but_cannot_escape() {
        let root = Path::new("/srv/relay");
        assert_eq!(
            resolve_binding(root, "package").expect("relative path"),
            Path::new("/srv/relay/package")
        );
        assert_eq!(
            resolve_binding(root, "/var/lib/relay/audit/events.jsonl").expect("absolute path"),
            Path::new("/var/lib/relay/audit/events.jsonl")
        );
        assert!(resolve_binding(root, "../package").is_err());
        assert_eq!(
            resolve_binding(root, "var/./audit.jsonl").expect("normalized relative path"),
            Path::new("/srv/relay/var/audit.jsonl")
        );
        assert!(resolve_binding(root, "/var/lib/relay/../package").is_err());
    }

    #[test]
    fn issuer_discovery_is_one_exact_https_profile() {
        let issuer = |discovery_url: &str| {
            serde_norway::from_str::<IssuerRuntime>(&format!(
                "id: issuer\ndiscoveryUrl: {discovery_url}\naudience: registry\ntokenTypes: [at+jwt]\nalgorithms: [EdDSA]\n"
            ))
            .expect("issuer shape parses")
        };
        let valid = "https://identity.example.invalid/.well-known/openid-configuration";
        let profile = verifier_issuer_profile(&issuer(valid)).expect("issuer profile validates");
        assert_eq!(
            profile.issuer_identifier,
            "https://identity.example.invalid"
        );
        assert_eq!(profile.algorithm, IssuerAlgorithm::EdDsa);

        for invalid in [
            "https://operator:credential@identity.example.invalid/.well-known/openid-configuration",
            "https://identity.example.invalid/.well-known/openid-configuration?tenant=x",
            "https://identity.example.invalid/.well-known/openid-configuration#fragment",
            "https://identity.example.invalid/.well-known/oauth-authorization-server",
            "https:///.well-known/openid-configuration",
        ] {
            assert!(matches!(
                verifier_issuer_profile(&issuer(invalid)),
                Err(StartupError::RuntimeInvalid)
            ));
        }

        #[cfg(feature = "tooling")]
        {
            let loopback = issuer("http://127.0.0.1:18080/.well-known/openid-configuration");
            assert!(matches!(
                verifier_issuer_profile(&loopback),
                Err(StartupError::RuntimeInvalid)
            ));
            let profile = loopback
                .supervised_local_profile()
                .expect("tooling accepts one canonical loopback issuer");
            assert_eq!(profile.issuer_identifier, "http://127.0.0.1:18080");
            for invalid in [
                "http://localhost:18080/.well-known/openid-configuration",
                "http://127.0.0.1/.well-known/openid-configuration",
                "http://10.0.0.1:18080/.well-known/openid-configuration",
            ] {
                assert!(issuer(invalid).supervised_local_profile().is_none());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_runtime_binding_is_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary root");
        let real = temporary.path().join("real");
        fs::create_dir(&real).expect("real directory");
        let linked = temporary.path().join("linked");
        symlink(&real, &linked).expect("symlink");
        assert!(reject_existing_symlink_components(&linked.join("file")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_trust_rejects_foreign_owners_and_limits_the_sticky_exception() {
        let effective_user = 1000;
        assert!(trusted_unix_owner_and_mode(
            effective_user,
            0o100600,
            effective_user,
            false
        ));
        assert!(trusted_unix_owner_and_mode(
            0,
            0o100644,
            effective_user,
            false
        ));
        assert!(!trusted_unix_owner_and_mode(
            effective_user + 1,
            0o100600,
            effective_user,
            false
        ));
        assert!(trusted_unix_owner_and_mode(
            0,
            0o041777,
            effective_user,
            true
        ));
        assert!(!trusted_unix_owner_and_mode(
            0,
            0o041777,
            effective_user,
            false
        ));
        assert!(!trusted_unix_owner_and_mode(
            effective_user,
            0o041777,
            effective_user,
            true
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_below_a_writable_ancestor_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path().canonicalize().expect("canonical root");
        let writable = root.join("writable");
        fs::create_dir(&writable).expect("writable ancestor");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
            .expect("ancestor becomes unsafe");
        let runtime = writable.join("runtime.yaml");
        fs::write(&runtime, b"runtime").expect("runtime fixture");

        assert_eq!(
            validate_runtime_path(&runtime).err(),
            Some(StartupError::RuntimeInvalid)
        );
    }

    #[tokio::test]
    async fn healthcheck_requires_the_exact_minimal_response() {
        async fn probe(body: &'static [u8]) -> Result<(), StartupError> {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
            let address = listener.local_addr().expect("address");
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("connection");
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("headers");
                stream.write_all(body).await.expect("body");
                stream.shutdown().await.expect("finish response");
            });
            let result = healthcheck(&format!("http://{address}/health")).await;
            task.await.expect("server task");
            result
        }

        assert!(probe(HEALTH_BODY).await.is_ok());
        assert!(probe(br#"{"status":"ok","source":"hidden"}"#)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn audit_path_replacement_revokes_readiness() {
        const VARIABLE: &str = "RELAY_V2_STARTUP_TEST_AUDIT_KEY";
        std::env::set_var(VARIABLE, "synthetic-test-key-material-32-bytes-long");
        let temporary = tempfile::tempdir().expect("temporary root");
        let path = temporary.path().join("audit").join("events.jsonl");
        let audit = build_audit(temporary.path(), &format!("secret:env/{VARIABLE}"), &path)
            .await
            .expect("audit initializes");
        assert!(audit.ready().await);

        fs::remove_file(&path).expect("remove temporary active file");
        assert!(!audit.ready().await);
    }

    #[tokio::test]
    async fn failed_preparation_never_takes_the_listener() {
        let reservation = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve address");
        let address = reservation.local_addr().expect("reserved address");
        drop(reservation);

        let temporary = tempfile::tempdir().expect("temporary root");
        let path = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root")
            .join("runtime.yaml");
        fs::write(
            &path,
            format!(
                "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {{bind: '{address}'}}\npackagePath: missing-package\nsources: {{db: {{path: source.sqlite}}}}\nauthentication: {{issuer: null}}\naudit: {{sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}}\nlimits: {{requestTimeoutMilliseconds: 1000, concurrentQueries: 1}}\n"
            ),
        )
        .expect("write runtime");

        assert_eq!(
            prepare(&path).await.err(),
            Some(StartupError::PackageInvalid)
        );
        let listener = TcpListener::bind(address)
            .await
            .expect("startup did not bind before readiness");
        drop(listener);
    }

    #[test]
    fn protected_contracts_require_issuer_lists_require_cursor_and_lookups_require_quota() {
        fn contract(operations: &str) -> RegistryContract {
            let yaml = r#"
apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata: {id: records, version: v1, title: Records}
registry:
  registryIdentifier: urn:example:registry
  name: Example Registry
  authority: {identifier: urn:example:authority, name: Example Authority}
  authoritativeScope: Example records
  baseUri: https://registry.example.invalid/
  identifierLifecyclePolicyRef: governance/identifiers.yaml
  alignmentTargets: []
governance: {controller: urn:example:authority, publisher: urn:example:authority, auditOwner: urn:example:audit}
semantics: {localVocabulary: https://registry.example.invalid/vocabulary/}
classifications:
  privacy: {scheme: urn:example:privacy, version: "1"}
  institutional: {scheme: urn:example:institutional, version: "1"}
  handling: {scheme: urn:example:handling, version: "1"}
  provenanceRef: governance/review.yaml
sources:
  records: {kind: sqlite, profile: snapshot, expectedSchemaFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
resources:
  - id: record
    datasetIdentifier: records
    entityTypeIdentifier: record
    title: Record
    description: Reviewed record
    semanticClass: local:Record
    source: {source: records, view: records}
    classificationDefaults: {privacy: public, institutional: public, handling: public, status: reviewed}
    recordContext:
      recordIdentifier: {sourceColumn: id}
      revisionIdentifier: {sourceColumn: revision}
      lifecycleState: {sourceColumn: state, codelist: codelists/states.yaml}
      recordedAt: {sourceColumn: recorded_at}
    properties:
      label: {label: Label, description: Label, sourceColumn: label, type: string, sourceRequired: true, semanticTerm: local:label}
    disclosureProfiles: {default: {properties: [label]}}
    operations: OPERATIONS
metadataVisibility: {service: public, resources: public, semantics: public, classifications: operator-only, processing: operator-only}
"#
            .replace("OPERATIONS", operations);
            RegistryContract::parse_yaml(&yaml).expect("generic contract")
        }

        let protected = contract(
            "{read: {defaultAccessProfile: default, accessProfiles: {default: {access: {scope: registry:record:read}, disclosureProfile: default}}}}",
        );
        let protected_runtime = RelayRuntime::parse_yaml(
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {bind: '127.0.0.1:18081'}\npackagePath: package\nsources: {records: {path: fixture.sqlite}}\nauthentication: {issuer: null}\naudit: {sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}\nlimits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}\n",
        )
        .expect("closed runtime");
        assert_eq!(
            validate_runtime_contract(&protected_runtime, &protected),
            Err(StartupError::IssuerUnavailable)
        );

        let protected_search = contract(
            "{searches: [{id: within-area, query: {kind: point-bbox, maximumLongitudeSpanDegrees: 10, maximumLatitudeSpanDegrees: 10}, defaultAccessProfile: default, accessProfiles: {default: {access: {scope: registry:record:search}, disclosureProfile: default}}, orderBy: [id], pagination: {defaultPageSize: 10, maximumPageSize: 20}}]}",
        );
        let mut protected_search_runtime = protected_runtime.clone();
        protected_search_runtime.cursor = Some(crate::contract::CursorRuntime {
            integrity_key_ref: "secret:env/CURSOR_KEY".into(),
            maximum_age_seconds: 300,
        });
        assert_eq!(
            validate_runtime_contract(&protected_search_runtime, &protected_search),
            Err(StartupError::IssuerUnavailable)
        );

        let mut protected_statistics =
            RegistryContract::parse_yaml(crate::compiler::tests::statistical_contract())
                .expect("statistical contract");
        protected_statistics.statistical_datasets[0].access =
            serde_norway::from_str("{scope: registry:statistics:read}")
                .expect("protected statistical access");
        let protected_statistics_runtime = RelayRuntime::parse_yaml(
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {bind: '127.0.0.1:18084'}\npackagePath: package\nsources: {db: {path: fixture.sqlite}}\nauthentication: {issuer: null}\naudit: {sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}\nlimits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}\n",
        )
        .expect("closed runtime");
        assert_eq!(
            validate_runtime_contract(&protected_statistics_runtime, &protected_statistics),
            Err(StartupError::IssuerUnavailable)
        );

        let list = contract(
            "{list: {defaultAccessProfile: default, accessProfiles: {default: {access: public, disclosureProfile: default}}, filters: [], allowUnfiltered: true, orderBy: [id], pagination: {defaultPageSize: 10, maximumPageSize: 20}}}",
        );
        let list_runtime = RelayRuntime::parse_yaml(
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {bind: '127.0.0.1:18082'}\npackagePath: package\nsources: {records: {path: fixture.sqlite}}\nauthentication: {issuer: null}\naudit: {sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}\nlimits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}\n",
        )
        .expect("closed runtime");
        assert_eq!(
            validate_runtime_contract(&list_runtime, &list),
            Err(StartupError::CursorInvalid)
        );

        let lookup = contract(
            "{lookups: [{id: by-label, requestBody: {maximumBytes: 128, selectors: {label: {sourceColumn: label, type: string, minimumBytes: 1, maximumBytes: 32}}}, defaultAccessProfile: default, accessProfiles: {default: {access: public, disclosureProfile: default}}}]}",
        );
        let mut lookup_runtime = RelayRuntime::parse_yaml(
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {bind: '127.0.0.1:18083'}\npackagePath: package\nsources: {records: {path: fixture.sqlite}}\nauthentication: {issuer: null}\naudit: {sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}\nlimits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}\n",
        )
        .expect("closed runtime");
        assert_eq!(
            validate_runtime_contract(&lookup_runtime, &lookup),
            Err(StartupError::RuntimeInvalid)
        );
        lookup_runtime.quotas = Some(crate::contract::QuotaRuntime {
            requests_per_minute: 60,
            burst: 10,
        });
        assert_eq!(validate_runtime_contract(&lookup_runtime, &lookup), Ok(()));
    }

    #[test]
    fn metadata_cursor_requirement_counts_only_potentially_visible_resources() {
        let mut contract = RegistryContract::parse_yaml(crate::compiler::tests::valid_contract())
            .expect("base contract");
        let mut second_resource = contract.resources[0].clone();
        second_resource.id = "second-record".into();
        contract.resources.push(second_resource);
        let mut runtime = RelayRuntime::parse_yaml(
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {bind: '127.0.0.1:18084'}\npackagePath: package\nsources: {db: {path: fixture.sqlite}}\nauthentication: {issuer: null}\naudit: {sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}\nlimits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}\n",
        )
        .expect("closed runtime");

        assert_eq!(
            validate_runtime_contract(&runtime, &contract),
            Err(StartupError::CursorInvalid)
        );

        contract.metadata_visibility.resources = crate::contract::Visibility::OperatorOnly;
        assert_eq!(validate_runtime_contract(&runtime, &contract), Ok(()));

        contract.metadata_visibility.resources = crate::contract::Visibility::Public;
        contract.resources[1].operations.read = Some(
            serde_norway::from_str(
                "defaultAccessProfile: protected\naccessProfiles:\n  protected: {access: {scope: 'registry:record:read'}, disclosureProfile: public}\n",
            )
            .expect("protected read operation"),
        );
        runtime.authentication.issuer = Some(
            serde_norway::from_str(
                "id: issuer\ndiscoveryUrl: https://issuer.example.invalid/.well-known/openid-configuration\naudience: registry\ntokenTypes: [at+jwt]\nalgorithms: [EdDSA]\n",
            )
            .expect("issuer runtime"),
        );
        assert_eq!(validate_runtime_contract(&runtime, &contract), Ok(()));

        contract.metadata_visibility.resources = crate::contract::Visibility::OperationBound;
        assert_eq!(
            validate_runtime_contract(&runtime, &contract),
            Err(StartupError::CursorInvalid)
        );

        runtime.cursor = Some(crate::contract::CursorRuntime {
            integrity_key_ref: "secret:env/CURSOR_KEY".into(),
            maximum_age_seconds: 300,
        });
        assert_eq!(validate_runtime_contract(&runtime, &contract), Ok(()));
    }

    #[test]
    fn a_runtime_file_is_bounded_and_strict() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let path = temporary.path().join("runtime.yaml");
        let mut file = fs::File::create(&path).expect("runtime file");
        writeln!(
            file,
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {{bind: '127.0.0.1:0'}}\npackagePath: package\nsources: {{db: {{path: source.sqlite}}}}\nauthentication: {{issuer: null}}\naudit: {{sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}}\nlimits: {{requestTimeoutMilliseconds: 1000, concurrentQueries: 1}}\nunknown: true"
        )
        .expect("write runtime");
        assert_eq!(load_runtime(&path), Err(StartupError::RuntimeInvalid));
    }
}
