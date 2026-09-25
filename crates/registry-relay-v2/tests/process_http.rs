// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::io::Read as _;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use registry_platform_sqlite::{
    inspect_schema, materialize_fixture, CapturedSnapshot, DatabaseProfile, InspectionLimits,
    SchemaObjectKind,
};
use registry_relay_v2::compiler::{classification_inventory_digest, compile_contract};
use registry_relay_v2::contract::{ClassificationReviewDocument, RegistryContract, RelayRuntime};
use registry_relay_v2::model::{
    CompileProfile, ObservedColumn, ObservedSourceSchema, ObservedView,
};
use registry_relay_v2::tooling::{package_project, PackageOptions};
use reqwest::{Client, StatusCode};
use serde_json::Value;

const BUSINESS_PROJECT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../products/relay-v2/acceptance/business-registry"
);

struct RelayProcess {
    child: Child,
}

impl RelayProcess {
    fn spawn(runtime: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_relay"))
            .arg("serve")
            .arg("--runtime-config")
            .arg(runtime)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("built relay process starts");
        Self { child }
    }

    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().expect("relay status reads") {
            panic!(
                "relay exited before accepting TCP requests with {status}: {}",
                self.stderr()
            );
        }
    }

    async fn terminate_cleanly(mut self) {
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .expect("SIGTERM command runs");
        assert!(status.success(), "SIGTERM reaches relay");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().expect("relay status reads") {
                assert!(
                    status.success(),
                    "relay did not shut down cleanly: {status}: {}",
                    self.stderr()
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "relay graceful shutdown exceeded its deadline"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn stderr(&mut self) -> String {
        let mut output = String::new();
        if let Some(stderr) = &mut self.child.stderr {
            let _ = stderr.read_to_string(&mut output);
        }
        output
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// One copied acceptance project laid out like the official image, with its
/// sealed package built and its runtime configuration written.
struct BusinessImage {
    _temporary: tempfile::TempDir,
    runtime_path: PathBuf,
    runtime: RelayRuntime,
    address: std::net::SocketAddr,
}

impl BusinessImage {
    fn prepare() -> Self {
        let temporary = tempfile::tempdir().expect("temporary image layout");
        let image_root = temporary
            .path()
            .canonicalize()
            .expect("temporary image root canonicalizes");
        let etc = image_root.join("etc/relay");
        let data = image_root.join("var/lib/relay/data");
        let audit = image_root.join("var/lib/relay/audit");
        let secrets = image_root.join("run/secrets/relay");
        fs::create_dir_all(&etc).expect("runtime directory creates");
        fs::create_dir_all(&data).expect("data directory creates");
        fs::create_dir_all(&audit).expect("audit directory creates");
        fs::create_dir_all(&secrets).expect("secrets directory creates");
        fs::set_permissions(&audit, fs::Permissions::from_mode(0o700))
            .expect("audit directory becomes owner-only");
        copy_tree(Path::new(BUSINESS_PROJECT), &etc);

        let source = data.join("business-registry.sqlite");
        materialize_fixture(
            &source,
            &fs::read_to_string(etc.join("fixture.sql")).expect("fixture SQL reads"),
        )
        .expect("fixture materializes");
        make_business_project_public_only(&etc, &source);

        let package = data.join("business-registry-package");
        let runtime_path = etc.join("runtime.yaml");
        let mut runtime = RelayRuntime::parse_yaml(
            &fs::read_to_string(&runtime_path).expect("acceptance runtime reads"),
        )
        .expect("acceptance runtime parses");
        let reservation = TcpListener::bind("127.0.0.1:0").expect("loopback port reserves");
        let address = reservation.local_addr().expect("reserved address");
        drop(reservation);
        let mut runtime_value = serde_json::to_value(&runtime).expect("runtime becomes a value");
        *runtime_value
            .pointer_mut("/listener/bind")
            .expect("listener binding") = Value::String(address.to_string());
        *runtime_value
            .pointer_mut("/package/root")
            .expect("package root") = Value::String(package.to_string_lossy().into_owned());
        *runtime_value
            .pointer_mut("/sources/companies/path")
            .expect("business source binding") =
            Value::String(source.to_string_lossy().into_owned());
        // File secrets resolve under secretProviders.file.root, a directory
        // apart from the runtime configuration.
        *runtime_value
            .pointer_mut("/secretProviders")
            .expect("secret providers") = serde_json::json!({
            "file": {"root": secrets.to_string_lossy()}
        });
        runtime_value
            .as_object_mut()
            .expect("runtime object")
            .remove("authentication");
        runtime = serde_json::from_value(runtime_value).expect("modified runtime remains valid");
        runtime.audit.sink = audit.join("events.jsonl").to_string_lossy().into_owned();
        runtime.audit.hash_key_ref = "secret:file/audit-integrity-key".into();
        runtime
            .cursor
            .as_mut()
            .expect("business cursor")
            .integrity_key_ref = "secret:file/cursor-integrity-key".into();
        runtime
            .check()
            .expect("modified runtime passes the shared blocks");
        write_runtime(&runtime_path, &runtime);
        write_secret(
            &secrets.join("audit-integrity-key"),
            b"a-32-byte-minimum-synthetic-audit-key",
        );
        write_secret(
            &secrets.join("cursor-integrity-key"),
            b"a-32-byte-minimum-synthetic-cursor-key",
        );

        let report = package_project(&PackageOptions {
            project_root: etc.clone(),
            output_dir: Some(package),
            revision: None,
        })
        .expect("package operation succeeds");
        assert!(
            report.is_success(),
            "acceptance project packages: {report:?}"
        );
        Self {
            _temporary: temporary,
            runtime_path,
            runtime,
            address,
        }
    }
}

fn write_runtime(path: &Path, runtime: &RelayRuntime) {
    fs::write(
        path,
        serde_norway::to_string(runtime).expect("runtime serializes"),
    )
    .expect("absolute runtime writes");
}

fn relay_check(runtime: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_relay"))
        .arg("check")
        .arg("--runtime-config")
        .arg(runtime)
        .stdin(Stdio::null())
        .output()
        .expect("built relay check runs")
}

#[tokio::test]
async fn built_relay_serves_a_sealed_package_over_real_tcp_and_shuts_down() {
    let image = BusinessImage::prepare();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("HTTP client builds");
    let base = format!("http://{}", image.address);
    let first = serve_one_lifecycle(&image.runtime_path, &client, &base).await;
    let second = serve_one_lifecycle(&image.runtime_path, &client, &base).await;
    assert_eq!(
        first, second,
        "the same sealed package and snapshot must serialize identically after restart"
    );
}

#[test]
fn built_relay_check_honors_a_package_digest_pin() {
    let image = BusinessImage::prepare();
    let digest = registry_platform_config::sha256_uri(
        &fs::read(image.runtime.package.root.join("SHA256SUMS")).expect("package sums read"),
    );

    let mut pinned = image.runtime.clone();
    pinned.package.expected_digest = Some(digest);
    write_runtime(&image.runtime_path, &pinned);
    let output = relay_check(&image.runtime_path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let wrong = format!("sha256:{}", "0".repeat(64));
    pinned.package.expected_digest = Some(wrong);
    write_runtime(&image.runtime_path, &pinned);
    let output = relay_check(&image.runtime_path);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("package.expectedDigest"), "{stderr}");
    assert!(
        stderr.contains("deploy the pinned package or update package.expectedDigest"),
        "{stderr}"
    );
}

#[test]
fn built_relay_check_refuses_a_changed_package_file_by_name_without_a_pin() {
    let image = BusinessImage::prepare();
    assert_eq!(image.runtime.package.expected_digest, None);
    let contract = image.runtime.package.root.join("registry.yaml");
    let mut bytes = fs::read(&contract).expect("packaged contract reads");
    bytes.extend_from_slice(b"\n");
    fs::write(&contract, bytes).expect("packaged contract changes");

    let output = relay_check(&image.runtime_path);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("changed: registry.yaml"), "{stderr}");
    assert!(stderr.contains("package.root"), "{stderr}");
    assert!(stderr.contains("relayctl package"), "{stderr}");
    assert!(
        !stderr.contains(&*image.runtime.package.root.to_string_lossy()),
        "{stderr}"
    );
}

#[test]
fn built_relay_refuses_removed_keys_and_relative_paths_by_field() {
    let image = BusinessImage::prepare();
    let text = fs::read_to_string(&image.runtime_path).expect("runtime reads");
    fs::write(&image.runtime_path, format!("{text}packagePath: package\n"))
        .expect("runtime with a removed key writes");
    let output = relay_check(&image.runtime_path);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("packagePath"), "{stderr}");
    assert!(stderr.contains("package.root"), "{stderr}");
    assert!(
        !stderr.contains(&*image.runtime_path.to_string_lossy()),
        "{stderr}"
    );

    let output = relay_check(Path::new("runtime.yaml"));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runtime configuration is refused"));
}

fn make_business_project_public_only(project: &Path, source: &Path) {
    let contract_path = project.join("registry.yaml");
    let mut value: Value = serde_norway::from_str(
        &fs::read_to_string(&contract_path).expect("business contract reads"),
    )
    .expect("business contract becomes a value");
    let resources = value
        .get_mut("resources")
        .and_then(Value::as_array_mut)
        .expect("business resources");
    let business = resources
        .iter_mut()
        .find(|resource| resource.get("id").and_then(Value::as_str) == Some("registered-business"))
        .expect("registered business resource exists");
    for pointer in [
        "/operations/list/accessProfiles",
        "/operations/read/accessProfiles",
    ] {
        business
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .expect("business access profile map")
            .remove("registrar")
            .expect("registrar access profile exists");
    }
    resources.retain(|resource| {
        resource.get("id").and_then(Value::as_str) == Some("registered-business")
    });
    fs::write(
        &contract_path,
        serde_norway::to_string(&value).expect("public-only contract serializes"),
    )
    .expect("public-only contract writes");
    let contract = RegistryContract::parse_yaml(
        &fs::read_to_string(&contract_path).expect("public-only contract reads"),
    )
    .expect("public-only contract parses");

    let captured = CapturedSnapshot::capture(source).expect("business snapshot captures");
    let catalog = inspect_schema(
        &DatabaseProfile::Snapshot(captured),
        &InspectionLimits {
            maximum_objects: 10_000,
            maximum_sql_bytes: 8 * 1024 * 1024,
            maximum_statement_steps: 1_000_000,
            timeout: Duration::from_secs(5),
        },
    )
    .expect("business schema inspects");
    let source_id = contract
        .sources
        .keys()
        .next()
        .expect("one source")
        .to_owned();
    let observed = vec![ObservedSourceSchema {
        source: source_id,
        fingerprint: catalog.fingerprint,
        views: catalog
            .objects
            .into_iter()
            .filter(|object| object.kind == SchemaObjectKind::View)
            .map(|object| ObservedView {
                name: object.name,
                columns: object
                    .columns
                    .into_iter()
                    .map(|column| ObservedColumn {
                        name: column.name,
                        declared_type: column.declared_type,
                        nullable: column.nullable,
                        primary_key: column.primary_key,
                    })
                    .collect(),
            })
            .collect(),
    }];
    let compiled = compile_contract(&contract, &observed, CompileProfile::Production)
        .expect("public-only inventory compiles");
    let inventory_digest =
        classification_inventory_digest(&compiled).expect("public-only inventory digests");
    let review_path = project.join(&contract.classifications.provenance_ref);
    let mut review: ClassificationReviewDocument = serde_norway::from_str(
        &fs::read_to_string(&review_path).expect("classification review reads"),
    )
    .expect("classification review parses");
    review.classification_inventory_digest = inventory_digest;
    fs::write(
        review_path,
        serde_norway::to_string(&review).expect("classification review serializes"),
    )
    .expect("classification review writes");
}

async fn serve_one_lifecycle(runtime: &Path, client: &Client, base: &str) -> Vec<u8> {
    let mut process = RelayProcess::spawn(runtime);
    wait_until_ready(client, base, &mut process).await;

    let health = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("health request completes");
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(
        health.bytes().await.expect("health body reads"),
        r#"{"status":"ok"}"#
    );

    let ready = client
        .get(format!("{base}/ready"))
        .send()
        .await
        .expect("readiness request completes");
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(
        ready.bytes().await.expect("readiness body reads"),
        r#"{"status":"ready"}"#
    );

    let response = client
        .get(format!(
            "{base}/v2/resources/registered-business/records/BIZ-SYNTH-0001"
        ))
        .send()
        .await
        .expect("business request completes");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.bytes().await.expect("business response reads");
    let document: Value = serde_json::from_slice(&bytes).expect("business response parses");
    assert_eq!(
        document
            .pointer("/data/recordIdentifier")
            .and_then(Value::as_str),
        Some("BIZ-SYNTH-0001")
    );

    process.terminate_cleanly().await;
    bytes.to_vec()
}

async fn wait_until_ready(client: &Client, base: &str, process: &mut RelayProcess) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        process.assert_running();
        if let Ok(response) = client.get(format!("{base}/ready")).send().await {
            if response.status() == StatusCode::OK {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "relay did not become reachable on loopback"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn write_secret(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("secret writes");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("secret becomes owner-only");
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).expect("acceptance project lists") {
        let entry = entry.expect("acceptance entry reads");
        let target = destination.join(entry.file_name());
        let kind = entry.file_type().expect("acceptance entry type reads");
        if kind.is_dir() {
            fs::create_dir(&target).expect("acceptance directory copies");
            copy_tree(&entry.path(), &target);
        } else {
            assert!(
                kind.is_file(),
                "acceptance closure contains only plain files"
            );
            fs::copy(entry.path(), target).expect("acceptance file copies");
        }
    }
}
