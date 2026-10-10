// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use registry_breg::compiler::module_digest;
use registry_breg::contract::parse_module_json;
use registry_breg::fixtures::validate_fixture_journeys;
use registry_breg::package::{
    prepare_package, PackageBuildRequest, PackageMigrationPlanInput, PackageModuleSource,
    PackageSourceFile, RETIRED_PACKAGE_API_VERSION,
};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::package::{write_sum_file, PackageLimits, SUM_FILE};
use serde_json::Value;

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const VALUE_CANARY: &str = "diff-source-path-record-sql-canary";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: diff-record-list
    steps:
      - id: list-records
        entity: record
        accessProfile: reader
        claims: {principal: diff-reader}
        request: {type: list}
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
                "bregctl-diff-test-{}-{}",
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
            .is_some_and(|name| name.starts_with("bregctl-diff-test-"))
            && self.path.exists()
        {
            fs::remove_dir_all(&self.path).expect("test directory is removed");
        }
    }
}

#[test]
fn diff_inventory_is_deterministic_and_classification_direction_is_exact() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "internal");
    let widening = write_project(&directory.path, "widening", "public");

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
    assert_eq!(
        report["baselinePackageRevision"], baseline.digest,
        "the baseline is named by its package digest"
    );
    assert!(report["changes"]
        .as_array()
        .expect("changes array")
        .iter()
        .any(|change| change["classification"] == "disclosure_widening"
            && change["change"]["code"] == "field_classification_changed"));

    let public_baseline = publish_package(&directory.path, "public-baseline", "public");
    let narrowing = write_project(&directory.path, "narrowing", "internal");
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
    assert!(String::from_utf8_lossy(&human.stdout)
        .contains("Classified the candidate against the baseline."));

    let unsupported = write_project(&directory.path, "unsupported", "internal");
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
fn a_removed_field_is_reported_as_retained_in_history_not_erased() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "internal");
    let module = String::from_utf8(module_bytes("internal"))
        .expect("module is UTF-8")
        .replacen(r#""id":"code""#, r#""id":"label""#, 1)
        .replacen(
            r#""readableFields":["code"]"#,
            r#""readableFields":["label"]"#,
            1,
        );
    let removal = write_project_with_module(&directory.path, "removal", module.into_bytes());

    let output = run(&[
        "--format",
        "json",
        "diff",
        path(&removal),
        "--package",
        path(&baseline.package),
    ]);
    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    assert!(report["changes"]
        .as_array()
        .expect("changes array")
        .iter()
        .any(|change| change["change"]["code"] == "field_removed"));
    let retained: Vec<&Value> = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter(|finding| finding["code"] == "diff.history.removed_values_retained")
        .collect();
    assert_eq!(retained.len(), 1, "{report}");
    assert_eq!(retained[0]["path"], "changes.record.code");
    assert_eq!(retained[0]["artifact"], "compiled_diff");
    assert_eq!(retained[0]["suggestedAction"], "review_compiled_diff");
    let message = retained[0]["message"].as_str().expect("message is text");
    assert!(message.contains("not erasure"), "{message}");
    assert!(message.contains("bregctl history erase"), "{message}");

    let unchanged = write_project(&directory.path, "unchanged", "internal");
    let quiet = run(&[
        "--format",
        "json",
        "diff",
        path(&unchanged),
        "--package",
        path(&baseline.package),
    ]);
    assert!(quiet.status.success(), "{quiet:?}");
    assert!(!json_stdout(&quiet)["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .any(|finding| finding["code"] == "diff.history.removed_values_retained"));
}

#[test]
fn package_closure_and_path_disclosure_threats_are_enforced_by_value_free_negatives() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "internal");
    let candidate = write_project(&directory.path, "candidate", "public");
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

        let safe = publish_package(&directory.path, "safe", "internal");
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
fn a_package_under_the_retired_api_version_is_read_only_as_the_deployed_predecessor() {
    let directory = TestDirectory::create();
    let deployed = publish_package(&directory.path, "deployed", "internal");
    let deployed = retire_package_api_version(deployed);
    let candidate = write_project(&directory.path, "candidate", "public");

    let checked = run(&[
        "--format",
        "json",
        "check",
        "--package",
        path(&deployed.package),
    ]);
    assert_eq!(checked.status.code(), Some(1), "{checked:?}");
    let diagnostic = &json_stdout(&checked)["diagnostics"][0];
    assert_eq!(diagnostic["code"], "config.retired-api-version");
    assert!(diagnostic["suggestedAction"]
        .as_str()
        .is_some_and(|action| action.contains("--baseline-package DEPLOYED")));

    let integrity_only = run(&[
        "--format",
        "json",
        "diff",
        path(&candidate),
        "--package",
        path(&deployed.package),
    ]);
    assert_eq!(integrity_only.status.code(), Some(1), "{integrity_only:?}");
    assert_tool_diagnostic(
        &json_stdout(&integrity_only)["diagnostics"][0],
        "baseline_package",
        "correct_package_build",
    );
    assert_eq!(
        json_stdout(&integrity_only)["diagnostics"][0]["code"],
        "diff.baseline.retired_api_version"
    );

    // The runtime file names the deployed package, which this release reads
    // as the predecessor of an upgrade.
    let runtime = write_runtime_config(&directory.path, &deployed);
    let runtime_bound = run(&[
        "--format",
        "json",
        "diff",
        path(&candidate),
        "--runtime-config",
        path(&runtime),
    ]);
    assert!(runtime_bound.status.success(), "{runtime_bound:?}");
    let report = json_stdout(&runtime_bound);
    assert_eq!(report["baselineAssurance"], "runtime_bound");
    assert_eq!(report["baselinePackageRevision"], deployed.digest);
}

#[test]
fn a_runtime_bound_baseline_is_verified_without_opening_runtime_dependencies() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "production-baseline", "internal");
    let candidate = write_project(&directory.path, "production-candidate", "public");
    let runtime = write_runtime_config(&directory.path, &baseline);

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

    // The runtime file's digest pin binds the baseline to the exact package
    // the runtime serves; another package at package.root is refused.
    let pinned_elsewhere = rewrite_runtime_config(
        &directory.path,
        &runtime,
        "pinned-elsewhere",
        &format!("  root: {}\n", baseline.package.display()),
        &format!(
            "  root: {}\n  expectedDigest: sha256:{}\n",
            baseline.package.display(),
            "0".repeat(64)
        ),
    );
    let refused = run(&[
        "--format",
        "json",
        "diff",
        path(&candidate),
        "--runtime-config",
        path(&pinned_elsewhere),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&refused.stdout).contains(VALUE_CANARY));
    assert_eq!(
        json_stdout(&refused)["diagnostics"][0]["code"],
        "diff.package.integrity_refused"
    );
}

#[test]
fn diff_help_and_selector_usage_preserve_the_closed_command_inventory_and_exit_codes() {
    let directory = TestDirectory::create();
    let candidate = write_project(&directory.path, "candidate", "internal");
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
        format!(
            "apiVersion: registry.registrystack.org/breg-runtime/v1alpha1\nkind: BRegRuntimeConfig\nunexpectedSetting: {VALUE_CANARY}\n"
        ),
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
    let diagnostics = report["diagnostics"]
        .as_array()
        .expect("diagnostics are a list");
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic["code"] == "config.unknown-key" && diagnostic["path"] == "/unexpectedSetting"
    }));
    for diagnostic in diagnostics {
        assert_tool_diagnostic(
            diagnostic,
            "runtime_configuration",
            "correct_runtime_configuration",
        );
    }
}

struct PublishedPackage {
    package: PathBuf,
    digest: String,
}

#[test]
fn check_reports_the_registry_revision_of_a_project_and_of_a_verified_package() {
    let directory = TestDirectory::create();
    let package = publish_package(&directory.path, "package", "internal");
    let project = write_project(&directory.path, "project", "internal");

    let checked = run(&["--format", "json", "check", path(&project)]);
    assert!(checked.status.success(), "{checked:?}");
    let checked = json_stdout(&checked);
    let registry_revision = checked["registryRevision"]
        .as_str()
        .expect("check names the registry revision");
    assert!(registry_revision.starts_with("sha256:"), "{checked}");
    assert_eq!(checked["revision"], registry_revision);

    // The package the same sources built rederives the same revision, with
    // no database, runtime configuration, or receipt.
    let verified = run(&[
        "--format",
        "json",
        "check",
        "--package",
        path(&package.package),
    ]);
    assert!(verified.status.success(), "{verified:?}");
    assert!(verified.stderr.is_empty());
    let verified = json_stdout(&verified);
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["command"], "check");
    assert_eq!(
        verified["registryRevision"], registry_revision,
        "{verified}"
    );

    let human = run(&["check", "--package", path(&package.package)]);
    assert!(human.status.success(), "{human:?}");
    assert!(String::from_utf8_lossy(&human.stdout).contains(registry_revision));

    let changed = publish_package(&directory.path, "changed", "public");
    let other = json_stdout(&run(&[
        "--format",
        "json",
        "check",
        "--package",
        path(&changed.package),
    ]));
    assert_ne!(other["registryRevision"], registry_revision, "{other}");

    // A package whose bytes no longer match its sums is refused, naming no
    // packaged value; the source is the package path as it was given.
    fs::write(
        package.package.join("source/modules/core/module.yaml"),
        VALUE_CANARY,
    )
    .expect("package closure is tampered");
    let tampered = run(&[
        "--format",
        "json",
        "check",
        "--package",
        path(&package.package),
    ]);
    assert_eq!(tampered.status.code(), Some(1));
    assert!(tampered.stderr.is_empty());
    let rendered = String::from_utf8_lossy(&tampered.stdout);
    assert!(!rendered.contains(VALUE_CANARY));
    assert!(!rendered.contains("source/modules/core/module.yaml"));
    let refused = json_stdout(&tampered);
    assert_eq!(refused["command"], "check");
    let diagnostic = &refused["diagnostics"][0];
    assert_eq!(diagnostic["code"], "breg.package.integrity-refused");
    assert_eq!(diagnostic["severity"], "error");
    assert_eq!(diagnostic["path"], "");
    assert!(diagnostic.get("artifact").is_none(), "{diagnostic}");
    assert_eq!(diagnostic["source"]["file"], path(&package.package));
    assert!(diagnostic["suggestedAction"]
        .as_str()
        .is_some_and(|action| action.starts_with("Rebuild the package with bregctl package")));

    // A project and a package together, or neither, is a usage error.
    let both = run(&["check", path(&project), "--package", path(&changed.package)]);
    assert_eq!(both.status.code(), Some(2), "{both:?}");
    let neither = run(&["check"]);
    assert_eq!(neither.status.code(), Some(2), "{neither:?}");
}

fn publish_package(parent: &Path, name: &str, classification: &str) -> PublishedPackage {
    let module_bytes = module_bytes(classification);
    let module = parse_module_json(&module_bytes).expect("package module parses");
    let project_bytes = project_bytes(&module_digest(&module));
    let prepared = prepare_package(PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
            assets: Vec::new(),
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
    let digest = prepared
        .package_digest()
        .expect("prepared package digest computes");
    let package = parent.join(name);
    prepared
        .publish_to_directory(&package)
        .expect("package publishes");
    PublishedPackage { package, digest }
}

/// Rewrite a published package's header to the retired package apiVersion an
/// earlier `bregctl package` wrote, and close it again under new sums.
fn retire_package_api_version(package: PublishedPackage) -> PublishedPackage {
    let manifest_path = package.package.join("package.json");
    let mut envelope: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("the package manifest reads"))
            .expect("the package manifest parses");
    let header = envelope.as_object_mut().expect("the envelope is an object");
    header.insert(
        "apiVersion".to_owned(),
        Value::from(RETIRED_PACKAGE_API_VERSION),
    );
    header.remove("kind");
    fs::write(
        &manifest_path,
        canonicalize_json(&envelope).expect("the retired envelope canonicalizes"),
    )
    .expect("the retired manifest is written");
    fs::remove_file(package.package.join(SUM_FILE)).expect("the stale sum file is removed");
    let closed = write_sum_file(
        &package.package,
        None,
        &PackageLimits {
            max_files: 1_026,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_depth: 16,
            max_path_bytes: 512,
        },
        "test package",
    )
    .expect("the retired package closes");
    PublishedPackage {
        digest: closed.digest().to_owned(),
        package: package.package,
    }
}

fn write_project(parent: &Path, name: &str, classification: &str) -> PathBuf {
    write_project_with_module(parent, name, module_bytes(classification))
}

fn write_project_with_module(parent: &Path, name: &str, module: Vec<u8>) -> PathBuf {
    let root = parent.join(name);
    let parsed = parse_module_json(&module).expect("candidate module parses");
    fs::create_dir_all(root.join("modules/core")).expect("candidate directories create");
    fs::write(
        root.join("registry.yaml"),
        project_bytes(&module_digest(&parsed)),
    )
    .expect("candidate project writes");
    fs::write(root.join("modules/core/module.yaml"), module).expect("candidate module writes");
    root
}

fn project_bytes(module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes(classification: &str) -> Vec<u8> {
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"record","primaryDataset":"neutral-registry","route":"records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":16,"classification":"{classification}"}}],"accessProfiles":[{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted", "id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]}}]}}"#
    )
    .into_bytes()
}

fn write_runtime_config(parent: &Path, package: &PublishedPackage) -> PathBuf {
    let secret_root = parent.join("secrets");
    fs::create_dir_all(&secret_root).expect("secret root creates");
    let path = parent.join(format!(
        "runtime-{}.yaml",
        TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let audit_path = secret_root
        .with_file_name("audit")
        .join("audit.jsonl")
        .display()
        .to_string();
    fs::write(
        &path,
        format!(
            r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:1
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
authentication:
  oidc:
    issuer: https://oidc-is-not-opened.invalid
    audience: urn:breg:diff
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
audit:
  hashKeyRef: secret:file/{VALUE_CANARY}
  path: {audit_path}
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

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(arguments)
        .output()
        .expect("bregctl starts")
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
