// SPDX-License-Identifier: Apache-2.0
//! Strict startup-only runtime and immutable-index activation.

use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::future::Future;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{sha256_uri, PackageError, PackageLimits, VerifiedPackage};
use registry_platform_yaml::Diagnostic;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::model::{parse_index, DiscoveryIndex, IndexError, MAXIMUM_INDEX_BYTES};
use crate::query::Directory;
use crate::runtime_config::{load_runtime_config, RuntimeConfig};
use crate::server::{router, DiscoveryService};
use crate::{
    INDEX_FILE, MAXIMUM_PACKAGE_BYTES, MAXIMUM_PACKAGE_DEPTH, MAXIMUM_PACKAGE_FILES,
    PACKAGE_COMMAND,
};

pub use registry_platform_config::MAX_LISTENER_BIND_CHARACTERS as MAXIMUM_LISTENER_BIND_CHARACTERS;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupError {
    /// The shared loader refused the runtime file; the message is the
    /// reader's human diagnostics, which name the file, the position, and
    /// the fix and never carry a configured value.
    #[error("the Discovery runtime configuration was refused:\n{0}")]
    RuntimeRefused(String),
    #[error("the Discovery runtime configuration is invalid")]
    RuntimeInvalid,
    #[error("{0}")]
    Package(#[from] PackageError),
    #[error(
        "the Discovery package at package.root has invalid contents{details}; rebuild it with \
         `discoveryctl package`"
    )]
    PackageContents { details: String },
    #[error(
        "the Discovery package file {path} changed after package verification; redeploy the whole \
         directory built by `discoveryctl package`"
    )]
    PackageFileChanged { path: String },
    #[error(
        "the Discovery package file discovery-index.json is invalid; rebuild the package with \
         `discoveryctl package`"
    )]
    PackageIndexInvalid,
    #[error(
        "the Discovery package contains a retired Relay service; remove Relay origins and rebuild \
         it with `discoveryctl package`"
    )]
    PackageIndexRetiredService,
    #[error(
        "the Discovery package file discovery-index.json was built before the index carried \
         apiVersion and kind; rebuild the package with `discoveryctl package`, then update \
         package.expectedDigest if you pin it"
    )]
    PackageIndexRetiredHeader,
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
    let (_, runtime) = load_runtime(runtime_path)?;
    let verified = runtime
        .package
        .verify_package(&package_limits(), PACKAGE_COMMAND)
        .map_err(|error| error.naming_root_as("package.root"))?;
    let index = load_verified_index(&runtime.package.root, &verified)?;
    tracing::info!(
        target: "registry_discovery::startup",
        package_digest = verified.digest(),
        "Discovery package accepted"
    );
    let directory = Directory::new(
        index,
        runtime.limits.result_records(),
        runtime.limits.result_alternatives(),
    )
    .map_err(|_| StartupError::RuntimeInvalid)?;
    let service = Arc::new(
        DiscoveryService::new(directory, runtime.limits.response_bytes())
            .map_err(|_| StartupError::RuntimeInvalid)?,
    );
    let app = router(
        service,
        runtime.limits.request_bytes(),
        Duration::from_secs(runtime.limits.request_timeout_seconds.get()),
    )
    .map_err(|_| StartupError::RuntimeInvalid)?;
    Ok(PreparedDiscovery {
        bind: runtime.listener.bind.socket_addr(),
        app,
        shutdown_timeout: Duration::from_secs(runtime.limits.shutdown_timeout_seconds.get()),
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
/// Returns the directory holding the file and the validated configuration.
pub fn load_runtime(path: &Path) -> Result<(PathBuf, RuntimeConfig), StartupError> {
    let runtime = load_runtime_config(path).map_err(|diagnostics| {
        let mut rendered: String = diagnostics.iter().map(Diagnostic::render_human).collect();
        rendered.truncate(rendered.trim_end().len());
        StartupError::RuntimeRefused(rendered)
    })?;
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

/// The bounds for the one-index Discovery package and optional revision.
#[must_use]
pub fn package_limits() -> PackageLimits {
    PackageLimits {
        max_files: MAXIMUM_PACKAGE_FILES,
        max_file_bytes: MAXIMUM_INDEX_BYTES,
        max_total_bytes: MAXIMUM_PACKAGE_BYTES,
        max_depth: MAXIMUM_PACKAGE_DEPTH,
        ..PackageLimits::default()
    }
}

/// Capture and parse the exact index bytes named by an already verified
/// package. The second digest check binds the bytes consumed by the directory
/// to the `SHA256SUMS` entry retained in `verified`.
pub fn load_verified_index(
    root: &Path,
    verified: &VerifiedPackage,
) -> Result<DiscoveryIndex, StartupError> {
    let expected = BTreeSet::from([INDEX_FILE.to_owned()]);
    let found = verified
        .files()
        .filter(|path| !is_envelope_file(path))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if found != expected {
        let mut details = String::new();
        let missing = expected.difference(&found).cloned().collect::<Vec<_>>();
        let extra = found.difference(&expected).cloned().collect::<Vec<_>>();
        if !missing.is_empty() {
            details.push_str(&format!("; missing: {}", missing.join(", ")));
        }
        if !extra.is_empty() {
            details.push_str(&format!("; extra: {}", extra.join(", ")));
        }
        return Err(StartupError::PackageContents { details });
    }
    let path = root.join(INDEX_FILE);
    let bytes = bounded_regular_file(&path, MAXIMUM_INDEX_BYTES).map_err(|_| {
        StartupError::PackageFileChanged {
            path: INDEX_FILE.to_owned(),
        }
    })?;
    if verified.file_digest(INDEX_FILE).as_deref() != Some(sha256_uri(&bytes).as_str()) {
        return Err(StartupError::PackageFileChanged {
            path: INDEX_FILE.to_owned(),
        });
    }
    parse_index(&bytes).map_err(|error| match error {
        IndexError::RetiredServiceKind => StartupError::PackageIndexRetiredService,
        IndexError::RetiredHeader => StartupError::PackageIndexRetiredHeader,
        _ => StartupError::PackageIndexInvalid,
    })
}

fn bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, StartupError> {
    let scanned = fs::symlink_metadata(path).map_err(|_| StartupError::IndexLoad)?;
    if scanned.file_type().is_symlink()
        || !scanned.is_file()
        || scanned.len() == 0
        || scanned.len() > maximum
    {
        return Err(StartupError::IndexLoad);
    }
    let file = fs::File::open(path).map_err(|_| StartupError::IndexLoad)?;
    let opened = file.metadata().map_err(|_| StartupError::IndexLoad)?;
    let current = fs::symlink_metadata(path).map_err(|_| StartupError::IndexLoad)?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || !same_file(&scanned, &opened)
        || !same_file(&opened, &current)
    {
        return Err(StartupError::IndexLoad);
    }
    read_opened_regular_file(file, &opened, maximum)
}

fn read_opened_regular_file(
    file: fs::File,
    opened: &fs::Metadata,
    maximum: u64,
) -> Result<Vec<u8>, StartupError> {
    let capacity = usize::try_from(opened.len()).map_err(|_| StartupError::IndexLoad)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(capacity)
        .map_err(|_| StartupError::IndexLoad)?;
    let mut reader = file.take(maximum.saturating_add(1));
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| StartupError::IndexLoad)?;
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| StartupError::IndexLoad)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_or(true, |length| length > maximum)
        || !same_file(opened, &after)
        || u64::try_from(bytes.len()).ok() != Some(after.len())
    {
        return Err(StartupError::IndexLoad);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::model::{canonical_index_bytes, tests::example_index};
    use crate::{RUNTIME_API_VERSION, RUNTIME_KIND};
    use registry_platform_config::write_package;

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
package:
  root: /tmp/registry-discovery-package
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

    fn prepare_error(path: &Path) -> StartupError {
        match prepare(path) {
            Ok(_) => panic!("expected Discovery startup to fail"),
            Err(error) => error,
        }
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
            message.contains("it reads `DiscoveryRuntimeConfig`"),
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
        // A file that replaced the envelope with schemaVersion is told which
        // envelope to write, and that schemaVersion is no longer read.
        let message = refusal(&RUNTIME.replace(
            "apiVersion: registry.registrystack.org/discovery-runtime/v1alpha1\nkind: DiscoveryRuntimeConfig",
            "schemaVersion: registry-discovery/runtime/v1alpha1",
        ));
        assert!(
            message.contains(
                "next: Start the file with `apiVersion: \
                 registry.registrystack.org/discovery-runtime/v1alpha1` and `kind: \
                 DiscoveryRuntimeConfig`."
            ),
            "{message}"
        );
        assert!(
            message.contains("`schemaVersion` is no longer accepted\n  next: Declare apiVersion"),
            "{message}"
        );
        let message = refusal(&RUNTIME.replace(
            "kind: DiscoveryRuntimeConfig",
            "kind: DiscoveryRuntimeConfig\nschemaVersion: registry-discovery/runtime/v1alpha1",
        ));
        assert!(
            message.contains("`schemaVersion` is no longer accepted\n  next: Declare apiVersion"),
            "{message}"
        );
        let message = refusal(&RUNTIME.replace("bind:", "address:"));
        assert!(
            message.contains(
                "/listener/address\n  `address` is no longer accepted\n  next: Declare \
                 listener.bind instead."
            ),
            "{message}"
        );
        let message = refusal(&RUNTIME.replace(
            "package:\n  root: /tmp/registry-discovery-package",
            "indexPath: discovery-index.json",
        ));
        assert!(
            message.contains(
                "`indexPath` is no longer accepted\n  next: Declare package.root instead"
            ),
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
        assert!(runtime.package.root.is_absolute());
    }

    #[test]
    fn package_root_must_be_absolute_and_normalized() {
        for value in ["package", "../package", "/tmp/../package"] {
            let message = refusal(&RUNTIME.replace("/tmp/registry-discovery-package", value));
            assert!(message.contains("package.root"), "{value}: {message}");
        }
    }

    fn package_files(index: &DiscoveryIndex) -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([(INDEX_FILE.to_owned(), canonical_index_bytes(index).unwrap())])
    }

    fn write_index_package(root: &Path) -> registry_platform_config::VerifiedPackage {
        write_package(
            root,
            &package_files(&example_index()),
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap()
    }

    fn runtime_for(package_root: &Path, expected_digest: Option<&str>) -> String {
        let pin = expected_digest
            .map(|digest| format!("\n  expectedDigest: {digest}"))
            .unwrap_or_default();
        RUNTIME.replace(
            "/tmp/registry-discovery-package",
            &format!("{}{pin}", package_root.display()),
        )
    }

    #[test]
    fn startup_verifies_package_and_refuses_expected_digest_mismatch_with_common_shape() {
        let temporary = canonical_tempdir();
        let package_root = temporary.path().join("package");
        let package = write_index_package(&package_root);
        let runtime_path = write_runtime(
            temporary.path(),
            &runtime_for(&package_root, Some(package.digest())),
        );
        prepare(&runtime_path).expect("matching pinned package starts");

        let expected = format!("sha256:{}", "0".repeat(64));
        let runtime_path = write_runtime(
            temporary.path(),
            &runtime_for(&package_root, Some(&expected)),
        );
        let message = prepare_error(&runtime_path).to_string();
        assert!(
            message.contains(&format!(
                "package.expectedDigest is {expected} but the package at package.root is {}",
                package.digest()
            )),
            "{message}"
        );
        assert!(
            message.contains("deploy the pinned package or update package.expectedDigest"),
            "{message}"
        );
    }

    #[test]
    fn startup_refuses_changed_missing_and_extra_package_files_by_name() {
        for (case, expected) in [
            ("changed", "changed: discovery-index.json"),
            ("extra", "extra: note.txt"),
        ] {
            let temporary = canonical_tempdir();
            let package_root = temporary.path().join("package");
            write_index_package(&package_root);
            let target = if case == "changed" {
                package_root.join(INDEX_FILE)
            } else {
                package_root.join("note.txt")
            };
            fs::write(&target, b"replacement").unwrap();
            let runtime_path = write_runtime(temporary.path(), &runtime_for(&package_root, None));
            let message = prepare_error(&runtime_path).to_string();
            assert!(message.contains(expected), "{case}: {message}");
        }

        let temporary = canonical_tempdir();
        let package_root = temporary.path().join("package");
        write_index_package(&package_root);
        fs::remove_file(package_root.join(INDEX_FILE)).unwrap();
        let runtime_path = write_runtime(temporary.path(), &runtime_for(&package_root, None));
        let message = prepare_error(&runtime_path).to_string();
        assert!(
            message.contains("missing: discovery-index.json"),
            "{message}"
        );
    }

    #[test]
    fn startup_refuses_a_hash_covered_non_index_file_by_name() {
        let temporary = canonical_tempdir();
        let package_root = temporary.path().join("package");
        let mut files = package_files(&example_index());
        files.insert("note.txt".to_owned(), b"not part of Discovery".to_vec());
        write_package(
            &package_root,
            &files,
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();
        let runtime_path = write_runtime(temporary.path(), &runtime_for(&package_root, None));
        let message = prepare_error(&runtime_path).to_string();
        assert!(message.contains("extra: note.txt"), "{message}");
    }

    #[test]
    fn startup_refuses_a_pre_retirement_mixed_package_with_rebuild_guidance() {
        let temporary = canonical_tempdir();
        let package_root = temporary.path().join("package");
        let fixture = include_bytes!(
            "../../../products/discovery/fixtures/compatibility/pre-retirement-mixed-index.json"
        );
        let index = fixture.strip_suffix(b"\n").unwrap_or(fixture).to_vec();
        write_package(
            &package_root,
            &BTreeMap::from([(INDEX_FILE.to_owned(), index)]),
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();
        let runtime_path = write_runtime(temporary.path(), &runtime_for(&package_root, None));

        let message = prepare_error(&runtime_path).to_string();
        assert!(message.contains("retired Relay service"), "{message}");
        assert!(message.contains("remove Relay origins"), "{message}");
        assert!(message.contains("discoveryctl package"), "{message}");
    }

    #[test]
    fn startup_refuses_an_index_with_the_retired_header_with_rebuild_guidance() {
        let temporary = canonical_tempdir();
        let package_root = temporary.path().join("package");
        let mut value = serde_json::to_value(example_index()).unwrap();
        let members = value.as_object_mut().unwrap();
        members.remove("apiVersion");
        members.remove("kind");
        members.insert(
            "schemaVersion".into(),
            "registry-discovery/index/v1alpha1".into(),
        );
        let index = registry_platform_canonical_json::canonicalize_json(&value).unwrap();
        write_package(
            &package_root,
            &BTreeMap::from([(INDEX_FILE.to_owned(), index)]),
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();
        let runtime_path = write_runtime(temporary.path(), &runtime_for(&package_root, None));

        assert_eq!(
            prepare_error(&runtime_path),
            StartupError::PackageIndexRetiredHeader
        );
        let message = prepare_error(&runtime_path).to_string();
        assert!(message.contains("discoveryctl package"), "{message}");
        assert!(message.contains("package.expectedDigest"), "{message}");
    }

    #[test]
    fn exact_consumed_index_bytes_remain_bound_to_the_verified_package() {
        let temporary = canonical_tempdir();
        let package_root = temporary.path().join("package");
        let package = write_index_package(&package_root);
        let mut replacement = example_index();
        replacement.built_at = "2026-09-26T00:00:00Z".to_owned();
        fs::write(
            package_root.join(INDEX_FILE),
            canonical_index_bytes(&replacement).unwrap(),
        )
        .unwrap();

        assert_eq!(
            load_verified_index(&package_root, &package),
            Err(StartupError::PackageFileChanged {
                path: INDEX_FILE.to_owned(),
            })
        );
    }

    #[test]
    fn index_capture_refuses_growth_beyond_the_read_limit() {
        use std::io::Write as _;

        let temporary = canonical_tempdir();
        let path = temporary.path().join(INDEX_FILE);
        fs::write(&path, b"12").unwrap();
        let file = fs::File::open(&path).unwrap();
        let opened = file.metadata().unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"3")
            .unwrap();

        assert_eq!(
            read_opened_regular_file(file, &opened, 2),
            Err(StartupError::IndexLoad)
        );
    }

    #[test]
    fn package_root_symlink_is_refused_before_index_consumption() {
        #[cfg(unix)]
        {
            let temporary = canonical_tempdir();
            let package_root = temporary.path().join("package");
            write_index_package(&package_root);
            let linked = temporary.path().join("linked-package");
            std::os::unix::fs::symlink(&package_root, &linked).unwrap();
            let runtime_path = write_runtime(temporary.path(), &runtime_for(&linked, None));
            let message = prepare_error(&runtime_path).to_string();
            assert!(message.contains("symbolic link"), "{message}");
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
