// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::io::Read as _;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
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
            .arg("--runtime")
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

#[tokio::test]
async fn built_relay_serves_a_sealed_package_over_real_tcp_and_shuts_down() {
    let temporary = tempfile::tempdir().expect("temporary image layout");
    let image_root = temporary
        .path()
        .canonicalize()
        .expect("temporary image root canonicalizes");
    let etc = image_root.join("etc/relay");
    let data = image_root.join("var/lib/relay/data");
    let audit = image_root.join("var/lib/relay/audit");
    fs::create_dir_all(&etc).expect("runtime directory creates");
    fs::create_dir_all(&data).expect("data directory creates");
    fs::create_dir_all(&audit).expect("audit directory creates");
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
    runtime.server.bind = address.to_string();
    runtime.package_path = package.to_string_lossy().into_owned();
    runtime.authentication.issuer = None;
    let mut runtime_value = serde_json::to_value(&runtime).expect("runtime becomes a value");
    *runtime_value
        .pointer_mut("/sources/companies/path")
        .expect("business source binding") = Value::String(source.to_string_lossy().into_owned());
    runtime = serde_json::from_value(runtime_value).expect("modified runtime remains valid");
    runtime.audit.sink = audit.join("events.jsonl").to_string_lossy().into_owned();
    runtime.audit.integrity_key_ref = "secret:file/audit-integrity-key".into();
    runtime
        .cursor
        .as_mut()
        .expect("business cursor")
        .integrity_key_ref = "secret:file/cursor-integrity-key".into();
    fs::write(
        &runtime_path,
        serde_norway::to_string(&runtime).expect("runtime serializes"),
    )
    .expect("absolute runtime writes");
    write_secret(
        &etc.join("audit-integrity-key"),
        b"a-32-byte-minimum-synthetic-audit-key",
    );
    write_secret(
        &etc.join("cursor-integrity-key"),
        b"a-32-byte-minimum-synthetic-cursor-key",
    );

    let report = package_project(&PackageOptions {
        project_root: etc.clone(),
        output_dir: package,
    })
    .expect("sealed package operation succeeds");
    assert!(
        report.is_success(),
        "acceptance project packages: {report:?}"
    );

    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("HTTP client builds");
    let base = format!("http://{address}");
    let first = serve_one_lifecycle(&runtime_path, &client, &base).await;
    let second = serve_one_lifecycle(&runtime_path, &client, &base).await;
    assert_eq!(
        first, second,
        "the same sealed package and snapshot must serialize identically after restart"
    );
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
