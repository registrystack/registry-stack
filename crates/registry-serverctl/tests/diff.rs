// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_server::compiler::module_digest;
use registry_server::contract::parse_module_json;
use registry_server::fixtures::validate_fixture_journeys;
use registry_server::package::{
    prepare_package, PackageBuildRequest, PackageMigrationPlanInput, PackageModuleSource,
    PackageSignature, PackageSourceFile, PackageTrustAnchor, SignaturePolicy, TrustAnchorKey,
    TRUST_ANCHOR_API_VERSION,
};
use serde::Serialize;
use serde_json::Value;

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const VALUE_CANARY: &str = "diff-source-path-record-sql-canary";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: diff-record-list
    steps:
      - id: list-records
        entity: record
        accessProfile: reader
        claims: {principal: diff-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Self {
        let path = std::env::current_dir()
            .expect("current directory is available")
            .join(format!(
                "registry-serverctl-diff-test-{}-{}",
                std::process::id(),
                TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&path).expect("test directory is created");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("registry-serverctl-diff-test-"))
            && self.path.exists()
        {
            fs::remove_dir_all(&self.path).expect("test directory is removed");
        }
    }
}

#[test]
fn diff_inventory_is_deterministic_and_classification_direction_is_exact() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "local", "internal", None);
    let widening = write_project(&directory.path, "widening", "local", "public");

    let first = run(&[
        "--format",
        "json",
        "diff",
        path(&widening),
        "--package",
        path(&baseline.package),
    ]);
    let second = run(&[
        "--format",
        "json",
        "diff",
        path(&widening),
        "--package",
        path(&baseline.package),
    ]);
    assert!(first.status.success(), "{first:?}");
    assert_eq!(
        first.stdout, second.stdout,
        "JSON diff is byte deterministic"
    );
    assert!(first.stderr.is_empty());
    let report = json_stdout(&first);
    assert_eq!(report["profile"], "authoring");
    assert_eq!(report["baselineAssurance"], "integrity_only");
    assert!(report["changes"]
        .as_array()
        .expect("changes array")
        .iter()
        .any(|change| change["classification"] == "disclosure_widening"
            && change["change"]["code"] == "field_classification_changed"));

    let public_baseline =
        publish_package(&directory.path, "public-baseline", "local", "public", None);
    let narrowing = write_project(&directory.path, "narrowing", "local", "internal");
    let reverse = run(&[
        "--format",
        "json",
        "diff",
        path(&narrowing),
        "--package",
        path(&public_baseline.package),
    ]);
    assert!(reverse.status.success(), "{reverse:?}");
    assert!(json_stdout(&reverse)["changes"]
        .as_array()
        .expect("changes array")
        .iter()
        .any(|change| change["classification"] == "disclosure_narrowing"));

    let human = run(&[
        "diff",
        path(&widening),
        "--package",
        path(&baseline.package),
    ]);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty());
    assert!(String::from_utf8_lossy(&human.stdout).contains("diff succeeded"));

    let unsupported = write_project(&directory.path, "unsupported", "local", "internal");
    let project_path = unsupported.join("registry.yaml");
    let source = fs::read_to_string(&project_path)
        .expect("unsupported candidate reads")
        .replacen(r#""version":"1""#, r#""version":"2""#, 1);
    fs::write(project_path, source).expect("unsupported candidate writes");
    let unsupported_output = run(&[
        "--format",
        "json",
        "diff",
        path(&unsupported),
        "--package",
        path(&baseline.package),
    ]);
    assert!(
        unsupported_output.status.success(),
        "{unsupported_output:?}"
    );
    let report = json_stdout(&unsupported_output);
    assert!(report["changes"]
        .as_array()
        .expect("changes array")
        .iter()
        .any(|change| change["classification"] == "unsupported"));
    assert!(report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .any(|finding| finding["code"] == "diff.classification.unsupported"));
}

#[test]
fn package_closure_and_path_disclosure_threats_are_enforced_by_value_free_negatives() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "local", "internal", None);
    let candidate = write_project(&directory.path, "candidate", "local", "public");
    let module_path = baseline.package.join("source/modules/core/module.yaml");
    fs::write(&module_path, VALUE_CANARY).expect("package closure is tampered");

    let tampered = run(&[
        "--format",
        "json",
        "diff",
        path(&candidate),
        "--package",
        path(&baseline.package),
    ]);
    assert_eq!(tampered.status.code(), Some(1));
    assert!(tampered.stderr.is_empty());
    let rendered = String::from_utf8_lossy(&tampered.stdout);
    assert!(!rendered.contains(VALUE_CANARY));
    assert!(!rendered.contains(path(&baseline.package)));
    assert_eq!(
        json_stdout(&tampered)["diagnostics"][0]["code"],
        "diff.baseline.integrity_refused"
    );
    assert_tool_diagnostic(
        &json_stdout(&tampered)["diagnostics"][0],
        "baseline_package",
        "verify_package_integrity",
    );
    let human_refusal = run(&[
        "diff",
        path(&candidate),
        "--package",
        path(&baseline.package),
    ]);
    assert_eq!(human_refusal.status.code(), Some(1));
    assert!(human_refusal.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&human_refusal.stderr).contains("diff.baseline.integrity_refused")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let safe = publish_package(&directory.path, "safe", "local", "internal", None);
        fs::set_permissions(&safe.package, fs::Permissions::from_mode(0o777))
            .expect("unsafe permissions are installed");
        let unsafe_permissions = run(&[
            "--format",
            "json",
            "diff",
            path(&candidate),
            "--package",
            path(&safe.package),
        ]);
        assert_eq!(unsafe_permissions.status.code(), Some(1));
        assert_eq!(
            json_stdout(&unsafe_permissions)["diagnostics"][0]["code"],
            "diff.baseline.permissions_refused"
        );
        assert_tool_diagnostic(
            &json_stdout(&unsafe_permissions)["diagnostics"][0],
            "baseline_package",
            "verify_package_permissions",
        );

        let linked = directory.path.join(VALUE_CANARY);
        symlink(&safe.package, &linked).expect("package symlink is created");
        let symlinked = run(&[
            "--format",
            "json",
            "diff",
            path(&candidate),
            "--package",
            path(&linked),
        ]);
        assert_eq!(symlinked.status.code(), Some(1));
        assert!(!String::from_utf8_lossy(&symlinked.stdout).contains(VALUE_CANARY));
        assert_eq!(
            json_stdout(&symlinked)["diagnostics"][0]["code"],
            "diff.baseline.path_refused"
        );
        assert_tool_diagnostic(
            &json_stdout(&symlinked)["diagnostics"][0],
            "baseline_package",
            "verify_package_path",
        );
    }
}

#[test]
fn production_trust_is_verified_without_opening_runtime_dependencies() {
    let directory = TestDirectory::create();
    let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
        .expect("production package signing key generates");
    let baseline = publish_package(
        &directory.path,
        "production-baseline",
        "production",
        "internal",
        Some(&signing),
    );
    let candidate = write_project(
        &directory.path,
        "production-candidate",
        "production",
        "public",
    );
    let runtime = write_runtime_config(
        &directory.path,
        &baseline,
        baseline.anchor.as_ref().expect("anchor exists"),
    );

    let accepted = run(&[
        "--format",
        "json",
        "diff",
        path(&candidate),
        "--runtime-config",
        path(&runtime),
    ]);
    assert!(accepted.status.success(), "{accepted:?}");
    assert!(accepted.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&accepted.stdout).contains(VALUE_CANARY));
    assert_eq!(json_stdout(&accepted)["baselineAssurance"], "runtime_bound");

    let wrong =
        generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("wrong trust key generates");
    let wrong_anchor = directory.path.join(format!("{VALUE_CANARY}.json"));
    write_anchor(&wrong_anchor, &wrong);
    let wrong_runtime = write_runtime_config(&directory.path, &baseline, &wrong_anchor);
    let refused = run(&[
        "--format",
        "json",
        "diff",
        path(&candidate),
        "--runtime-config",
        path(&wrong_runtime),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&refused.stdout).contains(VALUE_CANARY));
    assert_eq!(
        json_stdout(&refused)["diagnostics"][0]["code"],
        "diff.baseline.signature_refused"
    );
    assert_tool_diagnostic(
        &json_stdout(&refused)["diagnostics"][0],
        "baseline_package",
        "verify_package_trust",
    );

    let wrong_revision_runtime = rewrite_runtime_config(
        &directory.path,
        &runtime,
        "wrong-active-revision",
        &format!("activeRevision: {}", baseline.revision),
        &format!("activeRevision: {VALUE_CANARY}"),
    );
    assert_runtime_package_binding_refusal(&candidate, &wrong_revision_runtime);

    let wrong_sequence_runtime = rewrite_runtime_config(
        &directory.path,
        &runtime,
        &format!("wrong-active-sequence-{VALUE_CANARY}"),
        "activeSequence: 1",
        "activeSequence: 2",
    );
    assert_runtime_package_binding_refusal(&candidate, &wrong_sequence_runtime);
}

#[test]
fn diff_help_and_selector_usage_preserve_the_closed_command_inventory_and_exit_codes() {
    let directory = TestDirectory::create();
    let candidate = write_project(&directory.path, "candidate", "local", "internal");
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    let rendered = String::from_utf8_lossy(&help.stdout);
    assert!(rendered.contains("diff"));
    assert!(rendered
        .lines()
        .any(|line| line.trim_start().starts_with("data")));
    assert!(rendered
        .lines()
        .any(|line| line.trim_start().starts_with("verify")));
    assert!(rendered
        .lines()
        .any(|line| line.trim_start().starts_with("migration")));

    let diff_help = run(&["diff", "--help"]);
    let rendered = String::from_utf8_lossy(&diff_help.stdout);
    assert!(rendered.contains("--runtime-config <ABSOLUTE_FILE>"));
    assert!(rendered.contains("--package <DIRECTORY>"));

    let neither = run(&["--format", "json", "diff", VALUE_CANARY]);
    assert_eq!(neither.status.code(), Some(2));
    assert!(neither.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&neither.stdout).contains(VALUE_CANARY));
    assert_eq!(
        json_stdout(&neither)["diagnostics"][0]["code"],
        "usage.invalid"
    );
    assert_tool_diagnostic(
        &json_stdout(&neither)["diagnostics"][0],
        "command_arguments",
        "correct_command_usage",
    );

    let both = run(&[
        "--format",
        "json",
        "diff",
        VALUE_CANARY,
        "--runtime-config",
        VALUE_CANARY,
        "--package",
        VALUE_CANARY,
    ]);
    assert_eq!(both.status.code(), Some(2));
    assert!(both.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&both.stdout).contains(VALUE_CANARY));

    let relative_runtime = run(&[
        "--format",
        "json",
        "diff",
        path(&candidate),
        "--runtime-config",
        VALUE_CANARY,
    ]);
    assert_eq!(relative_runtime.status.code(), Some(1));
    assert!(relative_runtime.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&relative_runtime.stdout).contains(VALUE_CANARY));
    assert_eq!(
        json_stdout(&relative_runtime)["diagnostics"][0]["code"],
        "diff.runtime_config.path_invalid"
    );
    assert_tool_diagnostic(
        &json_stdout(&relative_runtime)["diagnostics"][0],
        "runtime_configuration",
        "correct_runtime_configuration",
    );

    let malformed_runtime = directory.path.join(format!("{VALUE_CANARY}.yaml"));
    fs::write(
        &malformed_runtime,
        format!("unexpectedSetting: {VALUE_CANARY}\n"),
    )
    .expect("malformed runtime configuration is written");
    let refused_runtime = run(&[
        "--format",
        "json",
        "diff",
        path(&candidate),
        "--runtime-config",
        path(&malformed_runtime),
    ]);
    assert_eq!(refused_runtime.status.code(), Some(1));
    assert!(refused_runtime.stderr.is_empty());
    let rendered = String::from_utf8_lossy(&refused_runtime.stdout);
    assert!(!rendered.contains(VALUE_CANARY));
    assert!(!rendered.contains(path(&malformed_runtime)));
    let report = json_stdout(&refused_runtime);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "diff.runtime_config.refused"
    );
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "runtime_configuration",
        "correct_runtime_configuration",
    );
}

struct PublishedPackage {
    package: PathBuf,
    anchor: Option<PathBuf>,
    revision: String,
}

fn publish_package(
    parent: &Path,
    name: &str,
    environment: &str,
    classification: &str,
    signing: Option<&PrivateJwk>,
) -> PublishedPackage {
    let module_bytes = module_bytes(classification);
    let module = parse_module_json(&module_bytes).expect("package module parses");
    let project_bytes = project_bytes(environment, &module_digest(&module));
    let signature_policy = signing
        .map(|key| SignaturePolicy {
            threshold: 1,
            key_ids: vec![key.public().kid.expect("generated key has an id")],
        })
        .unwrap_or(SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        });
    let prepared = prepare_package(PackageBuildRequest {
        environment: environment.to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        signature_policy,
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("package prepares");
    validate_fixture_journeys(FIXTURE_JOURNEYS, prepared.registry())
        .expect("diff fixture journeys resolve against the packaged registry");
    let signatures = signing
        .map(|key| {
            vec![PackageSignature {
                key_id: key.public().kid.expect("generated key has an id"),
                signature_hex: hex(
                    &sign(prepared.canonical_signed_bytes(), key).expect("package signs")
                ),
            }]
        })
        .unwrap_or_default();
    let package = parent.join(name);
    let revision = prepared.package_revision().to_owned();
    prepared
        .publish_to_directory(&package, signatures)
        .expect("package publishes");
    let anchor = signing.map(|key| {
        let path = parent.join(format!("{name}-trust.json"));
        write_anchor(&path, key);
        path
    });
    PublishedPackage {
        package,
        anchor,
        revision,
    }
}

fn write_project(parent: &Path, name: &str, environment: &str, classification: &str) -> PathBuf {
    let root = parent.join(name);
    let module = module_bytes(classification);
    let parsed = parse_module_json(&module).expect("candidate module parses");
    fs::create_dir_all(root.join("modules/core")).expect("candidate directories create");
    fs::write(
        root.join("registry.yaml"),
        project_bytes(environment, &module_digest(&parsed)),
    )
    .expect("candidate project writes");
    fs::write(root.join("modules/core/module.yaml"), module).expect("candidate module writes");
    root
}

fn project_bytes(environment: &str, module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en"}},"package":{{"environment":"{environment}","instanceId":"{INSTANCE}","sequence":1,"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"name":"Package Test Publisher"}}}},"dataset":{{"title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes(classification: &str) -> Vec<u8> {
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"record","route":"records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":16,"classification":"{classification}"}}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]}}]}}"#
    )
    .into_bytes()
}

fn write_anchor(path: &Path, key: &PrivateJwk) {
    let public = key.public();
    write_canonical(
        path,
        &PackageTrustAnchor {
            api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
            environment: "production".to_owned(),
            instance_id: INSTANCE.to_owned(),
            database_id: DATABASE.to_owned(),
            threshold: 1,
            keys: vec![TrustAnchorKey {
                key_id: public.kid.clone().expect("generated key has an id"),
                jwk: serde_json::to_value(public).expect("public key serializes"),
            }],
        },
    );
}

fn write_canonical(path: &Path, value: &impl Serialize) {
    let value = serde_json::to_value(value).expect("value serializes");
    let bytes = canonicalize_json(&value).expect("value canonicalizes");
    fs::write(path, bytes).expect("canonical file writes");
}

fn write_runtime_config(parent: &Path, package: &PublishedPackage, trust_anchor: &Path) -> PathBuf {
    let secret_root = parent.join("secrets");
    fs::create_dir_all(&secret_root).expect("secret root creates");
    let path = parent.join(format!(
        "runtime-{}.yaml",
        TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(
        &path,
        format!(
            r#"listener:
  bind: 127.0.0.1:1
  trustedProxy: direct
identity:
  environment: production
  instanceId: {INSTANCE}
  databaseId: {DATABASE}
  databaseInitializationEnvironment: production
secretProviders:
  environment: {{}}
  file:
    root: {secret_root}
database:
  runtimeUrlRef: secret:env/DIFF_RUNTIME_DATABASE_SECRET_IS_NOT_OPENED
  migrationUrlRef: secret:env/DIFF_MIGRATION_DATABASE_SECRET_IS_NOT_OPENED
  pool:
    maxSize: 1
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {package_root}
  trustAnchorPath: {trust_anchor}
  compilerSourceRevision: {SOURCE_REVISION}
  activeRevision: {revision}
  activeSequence: 1
authentication:
  oidc:
    issuer: https://oidc-is-not-opened.invalid
    audience: urn:registry-server:diff
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [diff-client]
    deniedKids: []
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 1
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
    rowBoundaryClaims: []
audit:
  hashKeyRef: secret:file/{VALUE_CANARY}
cursor:
  secretRef: secret:file/{VALUE_CANARY}
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
            secret_root = secret_root.display(),
            package_root = package.package.display(),
            trust_anchor = trust_anchor.display(),
            revision = package.revision,
        ),
    )
    .expect("runtime config writes");
    path
}

fn rewrite_runtime_config(
    parent: &Path,
    source: &Path,
    name: &str,
    from: &str,
    to: &str,
) -> PathBuf {
    let target = parent.join(format!("{name}.yaml"));
    let original = fs::read_to_string(source).expect("runtime config reads");
    assert!(
        original.contains(from),
        "runtime fixture replacement is exact"
    );
    fs::write(&target, original.replacen(from, to, 1)).expect("runtime config variant writes");
    target
}

fn assert_runtime_package_binding_refusal(candidate: &Path, runtime_config: &Path) {
    let refused = run(&[
        "--format",
        "json",
        "diff",
        path(candidate),
        "--runtime-config",
        path(runtime_config),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stderr.is_empty());
    let rendered = String::from_utf8_lossy(&refused.stdout);
    assert!(!rendered.contains(VALUE_CANARY));
    assert!(!rendered.contains(path(runtime_config)));
    assert_eq!(
        json_stdout(&refused)["diagnostics"][0]["code"],
        "diff.baseline.binding_refused"
    );
    assert_tool_diagnostic(
        &json_stdout(&refused)["diagnostics"][0],
        "baseline_package",
        "verify_package_binding",
    );
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_registry-serverctl"))
        .args(arguments)
        .output()
        .expect("registry-serverctl starts")
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout is JSON")
}

fn assert_tool_diagnostic(diagnostic: &Value, artifact: &str, suggested_action: &str) {
    let keys = diagnostic
        .as_object()
        .expect("diagnostic is an object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "artifact",
            "code",
            "message",
            "path",
            "severity",
            "suggestedAction",
        ])
    );
    assert_eq!(diagnostic["artifact"], artifact);
    assert_eq!(diagnostic["suggestedAction"], suggested_action);
}

fn path(path: &Path) -> &str {
    path.to_str().expect("test path is UTF-8")
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    result
}
