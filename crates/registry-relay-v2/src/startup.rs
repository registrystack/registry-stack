// SPDX-License-Identifier: Apache-2.0
//! Atomic process startup for the Relay V2 `relay` binary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use jsonwebtoken::Algorithm;
use registry_platform_audit::{
    require_audit_under, AuditDestination, AuditWriter, PersistentRootFault,
};
use registry_platform_config::SecretResolver;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    fetch_discovery_at_with_policy, fetch_discovery_with_policy, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, TokenVerifier, TokenVerifierConfig,
};
use thiserror::Error;
use tokio::net::TcpListener;
use url::Url;

use crate::audit::RelayAudit;
use crate::auth::RelayAuthenticator;
use crate::contract::{
    contract_has_protected_access, runtime_cursor_configuration_is_valid, IssuerAlgorithm,
    IssuerKeyTransport, IssuerProfile, OidcRuntime, RegistryContract, RelayRuntime, RuntimeRefusal,
};
use crate::cursor::CursorKey;
use crate::package::{load_package, VerifiedPackage};
use crate::server::{
    router, AlignmentMetadata, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use crate::source_observation::observe_sources;
use crate::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};

const DEFAULT_CURSOR_MAXIMUM_AGE: Duration = Duration::from_secs(300);
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
const ISSUER_NETWORK_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_TOKEN_LIFETIME: Duration = Duration::from_secs(15 * 60);
const TOKEN_CLOCK_LEEWAY: Duration = Duration::from_secs(30);
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_HEALTH_BODY_BYTES: usize = 128;
const HEALTH_BODY: &[u8] = br#"{"status":"ok"}"#;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StartupError {
    #[error("the runtime configuration could not be loaded")]
    RuntimeLoad,
    #[error("the runtime configuration is invalid")]
    RuntimeInvalid,
    /// The shared runtime-configuration loader or a shared block refused the
    /// file. The message names the field and never a configured value or the
    /// runtime file's path.
    #[error("the runtime configuration is refused: {0}")]
    RuntimeRefused(String),
    /// The package at `package.root` was refused. The message names the
    /// field, the package files involved, and `relayctl package`, never the
    /// configured directory.
    #[error("the package is refused: {0}")]
    PackageRefused(String),
    #[error("a runtime source could not be verified")]
    SourceInvalid,
    #[error("the configured issuer is not ready")]
    IssuerUnavailable,
    #[error("the required audit destination is not ready")]
    AuditUnavailable,
    /// The configured audit file was not proven to resolve inside the
    /// operator-declared persistent root. The fault names the side that
    /// failed and never the configured path or the declared root.
    #[error("the audit destination check failed: {0}")]
    AuditRoot(PersistentRootFault),
    /// A persistent audit root was declared for a runtime whose audit
    /// destination is `stdout`, which has no path to prove.
    #[error("the audit destination check applies only when audit.destination is file")]
    AuditRootRequiresFile,
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
    prepare_loaded(LoadedRuntime::load(runtime_path)?).await
}

/// One runtime file, read once: the directory its bindings resolve against,
/// the parsed document, and the paths it resolves to. Every proof startup
/// makes about a runtime reads this value rather than the pathname again, so
/// a check that passes and the preparation that follows describe the same
/// file even when the pathname is replaced in between.
struct LoadedRuntime {
    root: PathBuf,
    runtime: RelayRuntime,
    paths: RuntimePaths,
}

impl LoadedRuntime {
    fn load(runtime_path: &Path) -> Result<Self, StartupError> {
        let (root, runtime) = load_runtime(runtime_path)?;
        let paths = RuntimePaths::resolve(&root, &runtime)?;
        Ok(Self {
            root,
            runtime,
            paths,
        })
    }
}

async fn prepare_loaded(loaded: LoadedRuntime) -> Result<PreparedRelay, StartupError> {
    let LoadedRuntime {
        root: runtime_root,
        runtime,
        paths,
    } = loaded;

    // The package is the governed trust root. Verify it before opening issuer,
    // audit, source, or listener resources.
    let package = load_package(&paths.package)
        .map_err(|error| StartupError::PackageRefused(error.to_string()))?;
    runtime
        .package
        .verify_digest(&package.digest)
        .map_err(|error| StartupError::RuntimeRefused(error.to_string()))?;
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

    let authenticator = build_authenticator(runtime.authentication.oidc.as_ref()).await?;
    let secrets = runtime
        .secret_providers
        .resolver()
        .map_err(|_| StartupError::RuntimeInvalid)?;
    let audit = build_audit(paths.audit).await?;
    let (cursor_key, cursor_maximum_age) = build_cursor(&secrets, &runtime)?;
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
    let bind = runtime.listener.bind.socket_addr();
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
pub async fn check(
    runtime_path: &Path,
    require_audit_root: Option<&Path>,
) -> Result<(), StartupError> {
    // The deployment owns storage persistence and declares the root it mounts;
    // Relay owns where the audit file resolves. Proving containment first
    // keeps the two boundaries separate, and the readiness proof below still
    // has to pass. The runtime is read once, so the file proven here is the
    // file prepared below whatever the pathname names by then.
    let loaded = LoadedRuntime::load(runtime_path)?;
    if let Some(root) = require_audit_root {
        require_persistent_audit_file(&loaded, root)?;
    }
    let prepared = prepare_loaded(loaded).await?;
    if !prepared.service.is_ready().await {
        return Err(StartupError::NotReady);
    }
    Ok(())
}

/// Prove the audit file of a loaded runtime resolves inside `root`. The file
/// is the one `LoadedRuntime::load` resolved, the one preparation opens. A
/// `stdout` destination leaves persistence to whatever collects the stream,
/// so declaring a persistent root for it is refused rather than passed.
fn require_persistent_audit_file(loaded: &LoadedRuntime, root: &Path) -> Result<(), StartupError> {
    match &loaded.paths.audit {
        AuditDestination::File(file) => {
            require_audit_under(file.path(), root).map_err(StartupError::AuditRoot)
        }
        AuditDestination::Stdout | AuditDestination::Stderr => {
            Err(StartupError::AuditRootRequiresFile)
        }
    }
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

/// Read the runtime once through the shared loader: an absolute, lexically
/// normal path with no symbolic-link component, a trusted owner and mode on
/// the file and every ancestor, and a bounded size. The directory holding the
/// file is the root that relative source and audit bindings resolve against.
fn load_runtime(path: &Path) -> Result<(PathBuf, RelayRuntime), StartupError> {
    let runtime: RelayRuntime = RelayRuntime::loader()
        .load(path)
        .map_err(|error| StartupError::RuntimeRefused(RuntimeRefusal::from(error).to_string()))?
        .config;
    runtime
        .check()
        .map_err(|error| StartupError::RuntimeRefused(error.to_string()))?;
    let root = path
        .parent()
        .ok_or(StartupError::RuntimeLoad)?
        .to_path_buf();
    Ok((root, runtime))
}

struct RuntimePaths {
    package: PathBuf,
    sources: BTreeMap<String, RuntimeSourceBinding>,
    audit: AuditDestination,
}

impl RuntimePaths {
    fn resolve(root: &Path, runtime: &RelayRuntime) -> Result<Self, StartupError> {
        let package = runtime.package.root.clone();
        reject_existing_symlink_components(&package)?;
        let mut sources = BTreeMap::new();
        for (identifier, source) in runtime.sources.iter() {
            let path = resolve_binding(root, &source.path)?;
            reject_existing_symlink_components(&path)?;
            sources.insert(identifier.to_owned(), RuntimeSourceBinding { path });
        }
        // A relative audit path resolves against the runtime directory like
        // every other binding, so the writer only ever sees an absolute path.
        let audit_path = match runtime.audit.path.as_deref() {
            Some(path) => {
                let path = resolve_binding(root, path)?;
                reject_existing_symlink_components(&path)?;
                Some(path)
            }
            None => None,
        };
        let audit = AuditDestination::from_settings(
            runtime.audit.destination,
            audit_path,
            runtime.audit.rotate_bytes,
            runtime.audit.retain_days,
        )
        .map_err(|_| StartupError::RuntimeInvalid)?;
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
    if contract_has_protected_access(contract) && runtime.authentication.oidc.is_none() {
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
    if observed != package.source_schemas() {
        return Err(StartupError::SourceInvalid);
    }
    Ok(())
}

async fn build_authenticator(
    issuer: Option<&OidcRuntime>,
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
    issuer: &OidcRuntime,
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
    issuer: &OidcRuntime,
) -> Result<RelayAuthenticator, StartupError> {
    let profile = issuer
        .supervised_local_profile()
        .ok_or(StartupError::RuntimeInvalid)?;
    build_authenticator_with_profile(issuer, profile, &FetchUrlPolicy::dev()).await
}

fn verifier_issuer_profile(issuer: &OidcRuntime) -> Result<IssuerProfile, StartupError> {
    issuer.profile().ok_or(StartupError::RuntimeInvalid)
}

async fn build_audit(destination: AuditDestination) -> Result<RelayAudit, StartupError> {
    let writer = AuditWriter::open(destination).await.map_err(|error| {
        // The description names the rule the writer applied and how to
        // recover, and never the path or a secret.
        tracing::error!(
            target: "registry_relay_v2::startup",
            reason = %error.operator_description(),
            "the audit destination was refused"
        );
        StartupError::AuditUnavailable
    })?;
    Ok(RelayAudit::new(writer))
}

fn build_cursor(
    secrets: &SecretResolver,
    runtime: &RelayRuntime,
) -> Result<(Option<Arc<CursorKey>>, Duration), StartupError> {
    let Some(cursor) = &runtime.cursor else {
        return Ok((None, DEFAULT_CURSOR_MAXIMUM_AGE));
    };
    let secret = resolve_secret(secrets, &cursor.integrity_key_ref)?;
    let key =
        CursorKey::new(secret.expose_secret().to_vec()).map_err(|_| StartupError::CursorInvalid)?;
    Ok((
        Some(Arc::new(key)),
        Duration::from_secs(cursor.maximum_age_seconds),
    ))
}

/// Resolve one reference through exactly the providers `secretProviders`
/// declares; a `secret:file/` reference resolves under
/// `secretProviders.file.root`.
fn resolve_secret(
    secrets: &SecretResolver,
    reference: &str,
) -> Result<registry_platform_config::ProtectedSecret, StartupError> {
    secrets
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
    use registry_platform_config::DEFAULT_MAX_RUNTIME_CONFIG_BYTES;
    use std::io::Write as _;
    use tokio::io::AsyncWriteExt as _;

    fn runtime_text(bind: &str, package_root: &str, source: &str, audit: &str) -> String {
        format!(
            "apiVersion: registry.registrystack.org/relay-runtime/v1alpha1\nkind: RelayRuntimeConfig\nlistener: {{bind: '{bind}'}}\npackage: {{root: {package_root}}}\nsecretProviders: {{environment: {{}}}}\nsources: {{{source}: {{path: fixture.sqlite}}}}\naudit: {audit}\nlimits: {{requestTimeoutMilliseconds: 1000, concurrentQueries: 1}}\n"
        )
    }

    fn closed_runtime(source: &str) -> RelayRuntime {
        RelayRuntime::parse_yaml(&runtime_text(
            "127.0.0.1:18081",
            "/srv/relay/package",
            source,
            "{path: var/audit.jsonl}",
        ))
        .expect("closed runtime")
    }

    fn resolver(providers: &str) -> SecretResolver {
        serde_norway::from_str::<registry_platform_config::SecretProvidersConfig>(providers)
            .expect("secret providers parse")
            .resolver()
            .expect("secret resolver")
    }

    #[test]
    fn secrets_resolve_only_through_the_declared_providers() {
        const VARIABLE: &str = "RELAY_V2_SECRET_RESOLVER_TEST";
        std::env::set_var(VARIABLE, "synthetic-test-key-material-32-bytes-long");
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path().canonicalize().expect("canonical root");
        let secrets_root = root.join("secrets");
        fs::create_dir(&secrets_root).expect("secrets root");
        let both = resolver(&format!(
            "environment: {{}}\nfile: {{root: {}}}",
            secrets_root.display()
        ));
        assert_eq!(
            resolve_secret(&both, &format!("secret:env/{VARIABLE}"))
                .expect("environment secret")
                .expose_secret(),
            b"synthetic-test-key-material-32-bytes-long"
        );

        // A file reference resolves under secretProviders.file.root, never
        // beside the runtime configuration.
        let beside_runtime = root.join("cursor-integrity-key");
        fs::write(
            &beside_runtime,
            b"synthetic-other-key-material-32-bytes-long",
        )
        .expect("decoy writes");
        let path = secrets_root.join("cursor-integrity-key");
        fs::write(&path, b"synthetic-file-key-material-32-bytes-long").expect("secret writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for file in [&path, &beside_runtime] {
                fs::set_permissions(file, fs::Permissions::from_mode(0o600))
                    .expect("secret becomes owner-only");
            }
        }
        assert_eq!(
            resolve_secret(&both, "secret:file/cursor-integrity-key")
                .expect("file secret")
                .expose_secret(),
            b"synthetic-file-key-material-32-bytes-long"
        );

        let environment_only = resolver("environment: {}");
        assert_eq!(
            resolve_secret(&environment_only, "secret:file/cursor-integrity-key").err(),
            Some(StartupError::SecretUnavailable)
        );
        let file_only = resolver(&format!("file: {{root: {}}}", secrets_root.display()));
        assert_eq!(
            resolve_secret(&file_only, &format!("secret:env/{VARIABLE}")).err(),
            Some(StartupError::SecretUnavailable)
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
                .expect("secret becomes unsafe");
            assert!(resolve_secret(&both, "secret:file/cursor-integrity-key").is_err());
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
        let issuer = |issuer: &str| {
            serde_norway::from_str::<OidcRuntime>(&format!(
                "issuer: '{issuer}'\naudience: registry\ntokenTypes: [at+jwt]\nalgorithms: [EdDSA]\n"
            ))
            .expect("issuer shape parses")
        };
        let profile = verifier_issuer_profile(&issuer("https://identity.example.invalid"))
            .expect("issuer profile validates");
        assert_eq!(
            profile.issuer_identifier,
            "https://identity.example.invalid"
        );
        assert_eq!(profile.algorithm, IssuerAlgorithm::EdDsa);
        assert_eq!(
            profile.key_transport,
            IssuerKeyTransport::Discovery(
                "https://identity.example.invalid/.well-known/openid-configuration".to_owned()
            )
        );

        for invalid in [
            "https://operator:credential@identity.example.invalid",
            "https://identity.example.invalid/?tenant=x",
            "https://identity.example.invalid/#fragment",
            "http://identity.example.invalid",
        ] {
            assert!(matches!(
                verifier_issuer_profile(&issuer(invalid)),
                Err(StartupError::RuntimeInvalid)
            ));
        }

        #[cfg(feature = "tooling")]
        {
            let loopback = issuer("http://127.0.0.1:18080");
            assert!(matches!(
                verifier_issuer_profile(&loopback),
                Err(StartupError::RuntimeInvalid)
            ));
            let profile = loopback
                .supervised_local_profile()
                .expect("tooling accepts one canonical loopback issuer");
            assert_eq!(profile.issuer_identifier, "http://127.0.0.1:18080");
            for invalid in [
                "http://localhost:18080",
                "http://127.0.0.1",
                "http://10.0.0.1:18080",
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
    fn a_runtime_below_a_writable_ancestor_is_refused_without_naming_the_path() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path().canonicalize().expect("canonical root");
        let writable = root.join("writable");
        fs::create_dir(&writable).expect("writable ancestor");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
            .expect("ancestor becomes unsafe");
        let runtime = writable.join("runtime.yaml");
        fs::write(
            &runtime,
            runtime_text(
                "127.0.0.1:0",
                "/srv/relay/package",
                "db",
                "{path: var/audit.jsonl}",
            ),
        )
        .expect("runtime fixture");

        let Err(StartupError::RuntimeRefused(message)) = load_runtime(&runtime) else {
            panic!("a runtime below a writable ancestor must be refused");
        };
        assert!(!message.contains(&*root.to_string_lossy()), "{message}");
    }

    #[test]
    fn a_relative_runtime_path_is_refused() {
        assert!(matches!(
            load_runtime(Path::new("runtime.yaml")),
            Err(StartupError::RuntimeRefused(_))
        ));
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
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let path = root.join("audit").join("events.jsonl");
        let destination = AuditDestination::from_settings(
            registry_platform_audit::AuditDestinationKind::File,
            Some(path.clone()),
            None,
            None,
        )
        .expect("file destination");
        let audit = build_audit(destination).await.expect("audit initializes");
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
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let path = root.join("runtime.yaml");
        fs::write(
            &path,
            runtime_text(
                &address.to_string(),
                &root.join("missing-package").display().to_string(),
                "db",
                "{path: var/audit.jsonl}",
            ),
        )
        .expect("write runtime");

        let Some(StartupError::PackageRefused(message)) = prepare(&path).await.err() else {
            panic!("an absent package is refused");
        };
        assert!(message.contains("package.root"), "{message}");
        assert!(message.contains("relayctl package"), "{message}");
        assert!(!message.contains(&*root.to_string_lossy()), "{message}");
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
        let protected_runtime = closed_runtime("records");
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
        let protected_statistics_runtime = closed_runtime("db");
        assert_eq!(
            validate_runtime_contract(&protected_statistics_runtime, &protected_statistics),
            Err(StartupError::IssuerUnavailable)
        );

        let list = contract(
            "{list: {defaultAccessProfile: default, accessProfiles: {default: {access: public, disclosureProfile: default}}, filters: [], allowUnfiltered: true, orderBy: [id], pagination: {defaultPageSize: 10, maximumPageSize: 20}}}",
        );
        let list_runtime = closed_runtime("records");
        assert_eq!(
            validate_runtime_contract(&list_runtime, &list),
            Err(StartupError::CursorInvalid)
        );

        let lookup = contract(
            "{lookups: [{id: by-label, requestBody: {maximumBytes: 128, selectors: {label: {sourceColumn: label, type: string, minimumBytes: 1, maximumBytes: 32}}}, defaultAccessProfile: default, accessProfiles: {default: {access: public, disclosureProfile: default}}}]}",
        );
        let mut lookup_runtime = closed_runtime("records");
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
        let mut runtime = closed_runtime("db");

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
        runtime.authentication.oidc = Some(
            serde_norway::from_str(
                "issuer: https://issuer.example.invalid\naudience: registry\ntokenTypes: [at+jwt]\nalgorithms: [EdDSA]\n",
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

    /// Write one loadable runtime whose audit mapping is `audit`.
    fn runtime_with_audit(root: &Path, audit: &str) -> PathBuf {
        let path = root.join("runtime.yaml");
        fs::write(
            &path,
            runtime_text("127.0.0.1:0", "/srv/relay/package", "db", audit),
        )
        .expect("write runtime");
        path
    }

    /// Write one loadable runtime whose audit file is `path`.
    fn runtime_with_audit_path(root: &Path, path: &str) -> PathBuf {
        runtime_with_audit(root, &format!("{{path: '{path}'}}"))
    }

    fn audit_file_path(loaded: &LoadedRuntime) -> &Path {
        match &loaded.paths.audit {
            AuditDestination::File(file) => file.path(),
            AuditDestination::Stdout | AuditDestination::Stderr => {
                panic!("a file audit destination")
            }
        }
    }

    #[test]
    fn a_relative_audit_path_resolves_to_an_absolute_file_destination() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let path = runtime_with_audit(
            &root,
            "{path: var/audit.jsonl, rotateBytes: 1048576, retainDays: 7}",
        );
        let loaded = LoadedRuntime::load(&path).expect("loadable runtime");
        let AuditDestination::File(file) = &loaded.paths.audit else {
            panic!("a file audit destination");
        };
        assert_eq!(file.path(), root.join("var/audit.jsonl"));
        assert_eq!(file.rotate_bytes(), 1_048_576);
        assert_eq!(file.retain_days(), 7);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_audit_path_is_rejected() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let elsewhere = tempfile::tempdir().expect("temporary elsewhere");
        std::os::unix::fs::symlink(elsewhere.path(), root.join("var")).expect("symlink");
        let path = runtime_with_audit_path(&root, "var/audit.jsonl");
        assert_eq!(
            LoadedRuntime::load(&path).err(),
            Some(StartupError::RuntimeInvalid)
        );
    }

    #[test]
    fn a_stdout_audit_destination_cannot_be_proven_persistent() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let path = runtime_with_audit(&root, "{destination: stdout}");
        let loaded = LoadedRuntime::load(&path).expect("loadable runtime");
        assert_eq!(loaded.paths.audit, AuditDestination::Stdout);
        assert_eq!(
            Err(StartupError::AuditRootRequiresFile),
            require_persistent_audit_file(&loaded, &root)
        );
    }

    #[test]
    fn a_relative_audit_path_is_proven_against_the_resolved_runtime_binding() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let ephemeral = tempfile::tempdir().expect("temporary ephemeral root");
        let path = runtime_with_audit_path(&root, "var/audit.jsonl");
        let loaded = LoadedRuntime::load(&path).expect("loadable runtime");

        // The path is configured relative to the runtime file, so proving it
        // against the runtime directory is what shows Relay compared the
        // destination its own binding resolution produced.
        assert_eq!(Ok(()), require_persistent_audit_file(&loaded, &root));
        assert_eq!(
            Err(StartupError::AuditRoot(PersistentRootFault::Outside)),
            require_persistent_audit_file(&loaded, ephemeral.path())
        );
        assert_eq!(
            Err(StartupError::AuditRoot(PersistentRootFault::Root)),
            require_persistent_audit_file(&loaded, Path::new("var/lib/relay/audit"))
        );
    }

    #[test]
    fn an_absolute_audit_path_outside_the_declared_root_is_refused() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let ephemeral = tempfile::tempdir().expect("temporary ephemeral root");
        // The runtime binding refuses an absolute path whose components are
        // already symlinks, so the ephemeral location is named canonically.
        let ephemeral_root = ephemeral
            .path()
            .canonicalize()
            .expect("canonical ephemeral root");
        let declared = root.join("audit");
        fs::create_dir(&declared).expect("declared persistent root");
        let path = runtime_with_audit_path(
            &root,
            &ephemeral_root.join("events.jsonl").display().to_string(),
        );
        let loaded = LoadedRuntime::load(&path).expect("loadable runtime");

        assert_eq!(
            Err(StartupError::AuditRoot(PersistentRootFault::Outside)),
            require_persistent_audit_file(&loaded, &declared)
        );
    }

    #[test]
    fn the_containment_proof_reads_the_runtime_it_loaded_not_the_pathname() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let ephemeral = tempfile::tempdir().expect("temporary ephemeral root");
        let ephemeral_root = ephemeral
            .path()
            .canonicalize()
            .expect("canonical ephemeral root");
        let path = runtime_with_audit_path(&root, "var/audit.jsonl");
        let loaded = LoadedRuntime::load(&path).expect("loadable runtime");

        // The pathname now names a runtime whose audit file leaves the root.
        // The proof binds to what was loaded, which is also what `check` goes
        // on to prepare, so the replacement never becomes the file that
        // passed; a fresh load of the pathname sees the replacement and is
        // refused.
        runtime_with_audit_path(
            &root,
            &ephemeral_root.join("events.jsonl").display().to_string(),
        );
        assert_eq!(Ok(()), require_persistent_audit_file(&loaded, &root));
        assert_eq!(audit_file_path(&loaded), root.join("var/audit.jsonl"));
        let replaced = LoadedRuntime::load(&path).expect("loadable replacement");
        assert_eq!(
            Err(StartupError::AuditRoot(PersistentRootFault::Outside)),
            require_persistent_audit_file(&replaced, &root)
        );
    }

    #[test]
    fn a_runtime_file_is_bounded_and_strict() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path().canonicalize().expect("canonical root");
        let path = root.join("runtime.yaml");
        let mut file = fs::File::create(&path).expect("runtime file");
        writeln!(
            file,
            "{}unknown: true",
            runtime_text(
                "127.0.0.1:0",
                "/srv/relay/package",
                "db",
                "{path: var/audit.jsonl}"
            )
        )
        .expect("write runtime");
        assert!(matches!(
            load_runtime(&path),
            Err(StartupError::RuntimeRefused(_))
        ));

        fs::write(
            &path,
            vec![b' '; DEFAULT_MAX_RUNTIME_CONFIG_BYTES as usize + 1],
        )
        .expect("oversized");
        assert!(matches!(
            load_runtime(&path),
            Err(StartupError::RuntimeRefused(_))
        ));
    }
}
