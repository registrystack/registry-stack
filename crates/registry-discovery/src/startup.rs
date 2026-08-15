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
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::model::{
    parse_index, DiscoveryIndex, RuntimeConfig, MAXIMUM_HTTP_BODY_BYTES,
    MAXIMUM_IDENTIFIER_CHARACTERS, MAXIMUM_INDEX_BYTES, MAXIMUM_LISTENER_ADDRESS_CHARACTERS,
    MAXIMUM_RESULT_ALTERNATIVES, MAXIMUM_RESULT_RECORDS, MINIMUM_HTTP_RESPONSE_BYTES,
    RUNTIME_SCHEMA,
};
use crate::query::Directory;
use crate::server::{router, DiscoveryService};

const MAXIMUM_RUNTIME_BYTES: u64 = 1024 * 1024;
const MAXIMUM_REQUEST_TIMEOUT_SECONDS: u64 = 300;
const MAXIMUM_SHUTDOWN_TIMEOUT_SECONDS: u64 = 300;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupError {
    #[error("the Discovery runtime configuration could not be loaded")]
    RuntimeLoad,
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
    let bind = runtime
        .listener
        .address
        .parse()
        .map_err(|_| StartupError::RuntimeInvalid)?;
    Ok(PreparedDiscovery {
        bind,
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

pub fn load_runtime(path: &Path) -> Result<(PathBuf, RuntimeConfig), StartupError> {
    let bytes = bounded_regular_file(path, MAXIMUM_RUNTIME_BYTES, StartupError::RuntimeLoad)?;
    let runtime: RuntimeConfig =
        serde_yaml_ng::from_slice(&bytes).map_err(|_| StartupError::RuntimeInvalid)?;
    validate_runtime(&runtime)?;
    let root = effective_parent(path)
        .canonicalize()
        .map_err(|_| StartupError::RuntimeLoad)?;
    Ok((root, runtime))
}

fn effective_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub fn load_index(path: &Path) -> Result<DiscoveryIndex, StartupError> {
    let bytes = bounded_regular_file(path, MAXIMUM_INDEX_BYTES, StartupError::IndexLoad)?;
    parse_index(&bytes).map_err(|_| StartupError::IndexInvalid)
}

fn bounded_regular_file(
    path: &Path,
    maximum: u64,
    load_error: StartupError,
) -> Result<Vec<u8>, StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| load_error)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(load_error);
    }
    fs::read(path).map_err(|_| load_error)
}

fn validate_runtime(runtime: &RuntimeConfig) -> Result<(), StartupError> {
    if runtime.schema_version != RUNTIME_SCHEMA
        || runtime.listener.address.chars().count() > MAXIMUM_LISTENER_ADDRESS_CHARACTERS
        || runtime.index_path.is_empty()
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
    runtime
        .listener
        .address
        .parse::<SocketAddr>()
        .map_err(|_| StartupError::RuntimeInvalid)?;
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

    #[test]
    fn runtime_is_closed_and_contains_no_origin_mapping_trust_or_fetch_configuration() {
        let raw = br#"
schemaVersion: registry-discovery/runtime/v1alpha1
listener: { address: 127.0.0.1:8080 }
indexPath: discovery-index.json
limits:
  maximumRequestBytes: 65536
  maximumResponseBytes: 1048576
  maximumResultRecords: 100
  maximumResultAlternatives: 100
  requestTimeoutSeconds: 10
  shutdownTimeoutSeconds: 10
logLevel: info
origins: [{ catalogUrl: https://attacker.invalid/catalog.jsonld }]
"#;
        assert!(serde_yaml_ng::from_slice::<RuntimeConfig>(raw).is_err());
    }

    #[test]
    fn shipped_runtime_fixture_matches_the_closed_runtime_contract() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/discovery/fixtures/project/runtime.yaml");
        let (_, runtime) = load_runtime(&path).expect("shipped runtime fixture validates");
        assert_eq!(runtime.schema_version, RUNTIME_SCHEMA);
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

    #[test]
    fn a_bare_runtime_filename_uses_the_current_directory() {
        assert_eq!(effective_parent(Path::new("runtime.yaml")), Path::new("."));
        assert_eq!(
            effective_parent(Path::new("config/runtime.yaml")),
            Path::new("config")
        );
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
