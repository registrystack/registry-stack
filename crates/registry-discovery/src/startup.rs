// SPDX-License-Identifier: Apache-2.0
//! Strict startup-only runtime and immutable-index activation.

use std::fs;
#[cfg(unix)]
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use registry_platform_config::{ListenerConfig, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope};
use serde::Deserialize;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::model::{
    parse_index, DiscoveryIndex, MAXIMUM_HTTP_BODY_BYTES, MAXIMUM_IDENTIFIER_CHARACTERS,
    MAXIMUM_INDEX_BYTES, MAXIMUM_RESULT_ALTERNATIVES, MAXIMUM_RESULT_RECORDS,
    MINIMUM_HTTP_RESPONSE_BYTES,
};
use crate::query::Directory;
use crate::server::{router, DiscoveryService};

pub use registry_platform_config::MAX_LISTENER_BIND_CHARACTERS as MAXIMUM_LISTENER_BIND_CHARACTERS;

pub const RUNTIME_API_VERSION: &str = "registry.registrystack.org/discovery-runtime/v1alpha1";
pub const RUNTIME_KIND: &str = "DiscoveryRuntimeConfig";

const RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

const REMOVED_RUNTIME_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "schemaVersion",
        replacement: "declare apiVersion registry.registrystack.org/discovery-runtime/v1alpha1 \
                      and kind DiscoveryRuntimeConfig instead",
    },
    RemovedKey {
        path: "listener.address",
        replacement: "declare listener.bind instead",
    },
];

const MAXIMUM_REQUEST_TIMEOUT_SECONDS: u64 = 300;
const MAXIMUM_SHUTDOWN_TIMEOUT_SECONDS: u64 = 300;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeLimits {
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
    pub maximum_result_records: usize,
    pub maximum_result_alternatives: usize,
    pub request_timeout_seconds: u64,
    pub shutdown_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    pub listener: ListenerConfig,
    pub index_path: String,
    pub limits: RuntimeLimits,
    pub log_level: LogLevel,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupError {
    /// The shared loader refused the runtime file; the message names the
    /// file and the field and never carries a configured value.
    #[error("the Discovery runtime configuration was refused: {0}")]
    RuntimeRefused(String),
    #[error("the Discovery runtime configuration is invalid")]
    RuntimeInvalid,
    #[error("the Discovery index could not be loaded")]
    IndexLoad,
    #[error("the Discovery index is invalid")]
    IndexInvalid,
    #[error("the Discovery listener could not be started")]
    Listener,
    #[error("the Discovery shutdown signal failed")]
    Shutdown,
}

pub struct PreparedDiscovery {
    bind: SocketAddr,
    app: Router,
    shutdown_timeout: Duration,
}

impl PreparedDiscovery {
    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub fn app(&self) -> Router {
        self.app.clone()
    }
}

pub fn prepare(runtime_path: &Path) -> Result<PreparedDiscovery, StartupError> {
    let (root, runtime) = load_runtime(runtime_path)?;
    let index_path = safe_existing_file(&root, &runtime.index_path)?;
    let index = load_index(&index_path)?;
    let directory = Directory::new(
        index,
        runtime.limits.maximum_result_records,
        runtime.limits.maximum_result_alternatives,
    )
    .map_err(|_| StartupError::RuntimeInvalid)?;
    let service = Arc::new(
        DiscoveryService::new(directory, runtime.limits.maximum_response_bytes)
            .map_err(|_| StartupError::RuntimeInvalid)?,
    );
    let app = router(
        service,
        runtime.limits.maximum_request_bytes,
        Duration::from_secs(runtime.limits.request_timeout_seconds),
    )
    .map_err(|_| StartupError::RuntimeInvalid)?;
    Ok(PreparedDiscovery {
        bind: runtime.listener.bind.socket_addr(),
        app,
        shutdown_timeout: Duration::from_secs(runtime.limits.shutdown_timeout_seconds),
    })
}

pub async fn serve(runtime_path: &Path) -> Result<(), StartupError> {
    tracing::info!(target: "registry_discovery::startup", "Discovery startup began");
    let prepared = prepare(runtime_path)?;
    let listener = TcpListener::bind(prepared.bind)
        .await
        .map_err(|_| StartupError::Listener)?;
    tracing::info!(
        target: "registry_discovery::startup",
        "Discovery service is listening"
    );

    let shutdown_timeout = prepared.shutdown_timeout;
    let app = prepared.app;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    tokio::select! {
        result = &mut server => map_server_result(result),
        signal = shutdown_signal() => {
            signal?;
            let _ = shutdown_tx.send(());
            match tokio::time::timeout(shutdown_timeout, &mut server).await {
                Ok(result) => map_server_result(result),
                Err(_) => {
                    server.abort();
                    Err(StartupError::Shutdown)
                }
            }
        }
    }
}

async fn shutdown_signal() -> Result<(), StartupError> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| StartupError::Shutdown)?;
        first_shutdown_signal(tokio::signal::ctrl_c(), terminate.recv()).await
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|_| StartupError::Shutdown)
    }
}

#[cfg(unix)]
async fn first_shutdown_signal<C, T, E>(ctrl_c: C, terminate: T) -> Result<(), StartupError>
where
    C: Future<Output = Result<(), E>>,
    T: Future<Output = Option<()>>,
{
    tokio::select! {
        result = ctrl_c => result.map_err(|_| StartupError::Shutdown),
        result = terminate => result.ok_or(StartupError::Shutdown),
    }
}

fn map_server_result(
    result: Result<Result<(), std::io::Error>, tokio::task::JoinError>,
) -> Result<(), StartupError> {
    match result {
        Ok(Ok(())) => Ok(()),
        _ => Err(StartupError::Listener),
    }
}

/// Load the runtime file through the shared runtime configuration loader.
/// Returns the directory holding the file, which `indexPath` is resolved
/// against, and the validated configuration.
pub fn load_runtime(path: &Path) -> Result<(PathBuf, RuntimeConfig), StartupError> {
    let runtime = RuntimeConfigLoader::new(RUNTIME_ENVELOPE)
        .removed_keys(REMOVED_RUNTIME_KEYS)
        .load::<RuntimeConfig>(path)
        .map_err(|error| StartupError::RuntimeRefused(error.to_string()))?
        .config;
    validate_runtime(&runtime)?;
    let root = path
        .parent()
        .ok_or(StartupError::RuntimeInvalid)?
        .to_path_buf();
    Ok((root, runtime))
}

pub fn load_index(path: &Path) -> Result<DiscoveryIndex, StartupError> {
    let bytes = bounded_regular_file(path, MAXIMUM_INDEX_BYTES)?;
    parse_index(&bytes).map_err(|_| StartupError::IndexInvalid)
}

fn bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StartupError::IndexLoad)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(StartupError::IndexLoad);
    }
    fs::read(path).map_err(|_| StartupError::IndexLoad)
}

fn validate_runtime(runtime: &RuntimeConfig) -> Result<(), StartupError> {
    if runtime.index_path.is_empty()
        || runtime.index_path.chars().count() > MAXIMUM_IDENTIFIER_CHARACTERS
        || runtime.limits.maximum_request_bytes == 0
        || runtime.limits.maximum_request_bytes > MAXIMUM_HTTP_BODY_BYTES
        || runtime.limits.maximum_response_bytes < MINIMUM_HTTP_RESPONSE_BYTES
        || runtime.limits.maximum_response_bytes > MAXIMUM_HTTP_BODY_BYTES
        || runtime.limits.maximum_result_records == 0
        || runtime.limits.maximum_result_records > MAXIMUM_RESULT_RECORDS
        || runtime.limits.maximum_result_alternatives == 0
        || runtime.limits.maximum_result_alternatives > MAXIMUM_RESULT_ALTERNATIVES
        || runtime.limits.request_timeout_seconds == 0
        || runtime.limits.request_timeout_seconds > MAXIMUM_REQUEST_TIMEOUT_SECONDS
        || runtime.limits.shutdown_timeout_seconds == 0
        || runtime.limits.shutdown_timeout_seconds > MAXIMUM_SHUTDOWN_TIMEOUT_SECONDS
    {
        return Err(StartupError::RuntimeInvalid);
    }
    Ok(())
}

fn safe_existing_file(root: &Path, value: &str) -> Result<PathBuf, StartupError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StartupError::RuntimeInvalid);
    }
    let mut resolved = root.to_path_buf();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(StartupError::RuntimeInvalid);
        };
        resolved.push(component);
        let metadata = fs::symlink_metadata(&resolved).map_err(|_| StartupError::IndexLoad)?;
        if metadata.file_type().is_symlink() {
            return Err(StartupError::RuntimeInvalid);
        }
    }
    if !fs::symlink_metadata(&resolved)
        .map_err(|_| StartupError::IndexLoad)?
        .file_type()
        .is_file()
    {
        return Err(StartupError::IndexInvalid);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{canonical_index_bytes, tests::example_index};

    #[test]
    fn startup_loads_one_canonical_index_and_rejects_noncanonical_input() {
        let temporary = tempfile::tempdir().unwrap();
        let index_path = temporary.path().join("discovery-index.json");
        fs::write(
            &index_path,
            canonical_index_bytes(&example_index()).unwrap(),
        )
        .unwrap();
        assert_eq!(load_index(&index_path).unwrap(), example_index());

        fs::write(
            &index_path,
            serde_json::to_vec_pretty(&example_index()).unwrap(),
        )
        .unwrap();
        assert_eq!(load_index(&index_path), Err(StartupError::IndexInvalid));
    }

    const RUNTIME: &str = "\
apiVersion: registry.registrystack.org/discovery-runtime/v1alpha1
kind: DiscoveryRuntimeConfig
listener: { bind: 127.0.0.1:8080 }
indexPath: discovery-index.json
limits:
  maximumRequestBytes: 65536
  maximumResponseBytes: 1048576
  maximumResultRecords: 100
  maximumResultAlternatives: 100
  requestTimeoutSeconds: 10
  shutdownTimeoutSeconds: 10
logLevel: info
";

    fn canonical_tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }

    fn write_runtime(directory: &Path, text: &str) -> PathBuf {
        let path = directory.join("runtime.yaml");
        fs::write(&path, text).unwrap();
        path
    }

    fn refusal(text: &str) -> String {
        let temporary = canonical_tempdir();
        match load_runtime(&write_runtime(temporary.path(), text)) {
            Err(StartupError::RuntimeRefused(message)) => message,
            other => panic!("expected a loader refusal, got {other:?}"),
        }
    }

    #[test]
    fn runtime_is_closed_and_contains_no_origin_mapping_trust_or_fetch_configuration() {
        let message = refusal(&format!(
            "{RUNTIME}origins: [{{ catalogUrl: https://attacker.invalid/catalog.jsonld }}]\n"
        ));
        assert!(message.contains("origins"), "{message}");
    }

    #[test]
    fn the_runtime_file_is_read_through_the_shared_loader() {
        let temporary = canonical_tempdir();
        let path = write_runtime(temporary.path(), RUNTIME);
        let (root, runtime) = load_runtime(&path).expect("runtime loads");
        assert_eq!(root, temporary.path());
        assert_eq!(runtime.listener.bind.socket_addr().port(), 8080);

        let message = refusal(&RUNTIME.replace("kind: DiscoveryRuntimeConfig", "kind: Other"));
        assert!(
            message.contains("kind must be exactly DiscoveryRuntimeConfig"),
            "{message}"
        );

        let relative = Path::new("runtime.yaml");
        assert!(matches!(
            load_runtime(relative),
            Err(StartupError::RuntimeRefused(_))
        ));

        #[cfg(unix)]
        {
            let linked = temporary.path().join("linked.yaml");
            std::os::unix::fs::symlink(&path, &linked).unwrap();
            assert!(matches!(
                load_runtime(&linked),
                Err(StartupError::RuntimeRefused(_))
            ));
        }
    }

    #[test]
    fn removed_runtime_keys_name_their_replacements() {
        let message = refusal(&RUNTIME.replace(
            "apiVersion: registry.registrystack.org/discovery-runtime/v1alpha1\nkind: DiscoveryRuntimeConfig",
            "schemaVersion: registry-discovery/runtime/v1alpha1",
        ));
        assert!(
            message.contains("schemaVersion is no longer accepted; declare apiVersion"),
            "{message}"
        );
        let message = refusal(&RUNTIME.replace("bind:", "address:"));
        assert!(
            message
                .contains("listener.address is no longer accepted; declare listener.bind instead"),
            "{message}"
        );
    }

    #[test]
    fn the_listener_bind_is_required_and_substitutes_from_the_environment() {
        let message = refusal(&RUNTIME.replace("listener: { bind: 127.0.0.1:8080 }\n", ""));
        assert!(message.contains("listener"), "{message}");

        let temporary = canonical_tempdir();
        let path = write_runtime(
            temporary.path(),
            &RUNTIME.replace(
                "127.0.0.1:8080",
                "\"${DISCOVERY_TEST_BIND:-127.0.0.1:9090}\"",
            ),
        );
        let (_, runtime) = load_runtime(&path).expect("default substitutes");
        assert_eq!(runtime.listener.bind.socket_addr().port(), 9090);
    }

    #[test]
    fn shipped_runtime_fixture_matches_the_closed_runtime_contract() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/discovery/fixtures/project/runtime.yaml")
            .canonicalize()
            .unwrap();
        let (_, runtime) = load_runtime(&path).expect("shipped runtime fixture validates");
        assert_eq!(runtime.api_version, RUNTIME_API_VERSION);
        assert_eq!(runtime.kind, RUNTIME_KIND);
        assert_eq!(runtime.index_path, "discovery-index.json");
    }

    #[test]
    fn runtime_paths_cannot_escape_or_follow_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::write(root.join("index.json"), b"index").unwrap();
        for value in ["", "/etc/passwd", "../index.json", "nested/../index.json"] {
            assert!(safe_existing_file(root, value).is_err(), "{value}");
        }
        assert_eq!(
            safe_existing_file(root, "index.json").unwrap(),
            root.join("index.json")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(root.join("index.json"), root.join("linked.json")).unwrap();
            assert!(safe_existing_file(root, "linked.json").is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn injected_ctrl_c_enters_the_shared_graceful_shutdown_path() {
        let ctrl_c = async { Ok::<(), ()>(()) };
        let terminate = std::future::pending::<Option<()>>();
        assert_eq!(first_shutdown_signal(ctrl_c, terminate).await, Ok(()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn injected_sigterm_enters_the_shared_graceful_shutdown_path() {
        let ctrl_c = std::future::pending::<Result<(), ()>>();
        let terminate = async { Some(()) };
        assert_eq!(first_shutdown_signal(ctrl_c, terminate).await, Ok(()));
    }
}
