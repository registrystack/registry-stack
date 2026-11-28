// SPDX-License-Identifier: Apache-2.0
//! Strict startup-only runtime and immutable-index activation.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use registry_platform_config::{DeclaredPosture, LoadedRuntimeConfig};
use registry_platform_yaml::Diagnostic;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::model::record_index_posture;
pub use crate::package::{load_index, load_verified_index, package_limits, StartupError};
use crate::query::Directory;
use crate::runtime_config::{load_runtime_config, RuntimeConfig};
use crate::server::{router, DiscoveryService};
use crate::INDEX_FILE;

pub use registry_platform_config::MAX_LISTENER_BIND_CHARACTERS as MAXIMUM_LISTENER_BIND_CHARACTERS;

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

pub fn prepare(
    runtime_path: &Path,
    declared: DeclaredPosture,
) -> Result<PreparedDiscovery, StartupError> {
    let (_, mut loaded) = load_runtime(runtime_path, declared)?;
    crate::runtime_config::package_root_exists(&loaded.config.package.root)
        .map_err(StartupError::PackageRootLookup)?;
    let (index, verified) = crate::package::load_runtime_package(&loaded.config.package)?;
    record_index_posture(&index, &mut loaded.posture, |host| {
        registry_platform_httpsec::loopback::loopback_host(host).is_some()
    });
    let runtime = &loaded.config;
    let index_path = runtime.package.root.join(INDEX_FILE);
    loaded
        .posture
        .decide(&index_path)
        .map_err(|error| StartupError::RuntimeRefused(error.to_string()))?;
    loaded.posture.log_startup();
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
        DiscoveryService::new_with_posture(
            directory,
            runtime.limits.response_bytes(),
            loaded.posture,
        )
        .map_err(|_| StartupError::RuntimeInvalid)?,
    );
    let app = router(
        service,
        runtime.limits.request_bytes(),
        runtime.listener.request_timeout(),
    )
    .map_err(|_| StartupError::RuntimeInvalid)?;
    Ok(PreparedDiscovery {
        bind: runtime.listener.bind.socket_addr(),
        app,
        shutdown_timeout: runtime.limits.shutdown_grace(),
    })
}

pub async fn serve(runtime_path: &Path, declared: DeclaredPosture) -> Result<(), StartupError> {
    tracing::info!(target: "registry_discovery::startup", "Discovery startup began");
    let prepared = prepare(runtime_path, declared)?;
    let shutdown = shutdown_after(registry_platform_httpsec::shutdown_signal)?;
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
        () = shutdown => {
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

/// Install the stop-signal handlers with `install`. A failure refuses startup
/// with [`StartupError::Shutdown`], so the service never runs with no way to
/// be stopped by a signal.
fn shutdown_after<I, S>(install: I) -> Result<S, StartupError>
where
    I: FnOnce() -> std::io::Result<S>,
{
    install().map_err(|error| {
        tracing::error!(
            target: "registry_discovery::startup",
            %error,
            "the stop signals cannot be observed"
        );
        StartupError::Shutdown
    })
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
pub fn load_runtime(
    path: &Path,
    declared: DeclaredPosture,
) -> Result<(PathBuf, LoadedRuntimeConfig<RuntimeConfig>), StartupError> {
    let runtime = load_runtime_config(path, declared).map_err(|diagnostics| {
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

#[cfg(test)]
mod tests {
    use crate::DiscoveryIndex;
    use crate::PACKAGE_COMMAND;
    use std::collections::BTreeMap;
    use std::fs;

    use super::*;
    use registry_platform_config::{Posture, PostureSource};
    const PRODUCTION: DeclaredPosture = DeclaredPosture {
        posture: Posture::Production,
        source: PostureSource::Default,
    };
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
apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1
kind: DiscoveryRuntimeConfig
listener: { bind: 127.0.0.1:8080, requestTimeoutMilliseconds: 10000 }
package:
  root: /tmp/registry-discovery-package
limits:
  maximumRequestBytes: 65536
  maximumResponseBytes: 1048576
  maximumResultRecords: 100
  maximumResultAlternatives: 100
  shutdownGraceMilliseconds: 10000
logLevel: info
";

    fn canonical_tempdir() -> tempfile::TempDir {
        let base = std::env::temp_dir().canonicalize().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(base)
                .unwrap()
        }
        #[cfg(not(unix))]
        {
            tempfile::tempdir_in(base).unwrap()
        }
    }

    fn write_runtime(directory: &Path, text: &str) -> PathBuf {
        let path = directory.join("runtime.yaml");
        fs::write(&path, text).unwrap();
        path
    }

    fn prepare_error(path: &Path) -> StartupError {
        match prepare(path, PRODUCTION) {
            Ok(_) => panic!("expected Discovery startup to fail"),
            Err(error) => error,
        }
    }

    fn refusal(text: &str) -> String {
        let temporary = canonical_tempdir();
        match load_runtime(&write_runtime(temporary.path(), text), PRODUCTION) {
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
        let (root, runtime) = load_runtime(&path, PRODUCTION).expect("runtime loads");
        assert_eq!(root, temporary.path());
        assert_eq!(runtime.config.listener.bind.socket_addr().port(), 8080);

        let message = refusal(&RUNTIME.replace("kind: DiscoveryRuntimeConfig", "kind: Other"));
        assert!(
            message.contains("it reads `DiscoveryRuntimeConfig`"),
            "{message}"
        );

        let relative = Path::new("runtime.yaml");
        assert!(matches!(
            load_runtime(relative, PRODUCTION),
            Err(StartupError::RuntimeRefused(_))
        ));

        #[cfg(unix)]
        {
            let linked = temporary.path().join("linked.yaml");
            std::os::unix::fs::symlink(&path, &linked).unwrap();
            assert!(matches!(
                load_runtime(&linked, PRODUCTION),
                Err(StartupError::RuntimeRefused(_))
            ));
        }
    }

    #[test]
    fn removed_runtime_keys_name_their_replacements() {
        // A file that replaced the envelope with schemaVersion is told which
        // envelope to write, and that schemaVersion is no longer read.
        let message = refusal(&RUNTIME.replace(
            "apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1\nkind: DiscoveryRuntimeConfig",
            "schemaVersion: registry-discovery/runtime/v1alpha1",
        ));
        assert!(
            message.contains(
                "next: Start the file with `apiVersion: \
                 id.registrystack.org/formats/discovery/runtime/v1alpha1` and `kind: \
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
        let message = refusal(&RUNTIME.replace(
            "listener: { bind: 127.0.0.1:8080, requestTimeoutMilliseconds: 10000 }\n",
            "",
        ));
        assert!(message.contains("listener"), "{message}");

        let temporary = canonical_tempdir();
        let path = write_runtime(
            temporary.path(),
            &RUNTIME.replace(
                "127.0.0.1:8080",
                "\"${DISCOVERY_TEST_BIND:-127.0.0.1:9090}\"",
            ),
        );
        let (_, runtime) = load_runtime(&path, PRODUCTION).expect("default substitutes");
        assert_eq!(runtime.config.listener.bind.socket_addr().port(), 9090);
    }

    #[test]
    fn shipped_runtime_fixture_matches_the_closed_runtime_contract() {
        let temporary = canonical_tempdir();
        let path = write_runtime(
            temporary.path(),
            include_str!("../../../products/discovery/fixtures/project/runtime.yaml"),
        );
        let (_, runtime) =
            load_runtime(&path, PRODUCTION).expect("shipped runtime fixture validates");
        assert_eq!(runtime.config.api_version, RUNTIME_API_VERSION);
        assert_eq!(runtime.config.kind, RUNTIME_KIND);
        assert!(runtime.config.package.root.is_absolute());
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
        prepare(&runtime_path, PRODUCTION).expect("matching pinned package starts");

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

    #[test]
    fn a_stop_signal_install_failure_refuses_startup() {
        let error = shutdown_after(|| -> std::io::Result<std::future::Pending<()>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "install refused",
            ))
        })
        .expect_err("an install failure is an error, never a silent wait");
        assert_eq!(error, StartupError::Shutdown);
    }

    #[tokio::test]
    async fn an_installed_stop_signal_resolves_when_it_fires() {
        let signal = shutdown_after(|| Ok(std::future::ready(()))).expect("installs");
        tokio::time::timeout(Duration::from_secs(5), signal)
            .await
            .expect("a fired signal resolves");
    }
}
