//! Executable proof for the complete Evidence Version 1 reference deployments.
//!
//! Every declared case runs through the production command, including exact
//! replay matching, SQL execution, fact/output checks, signing, verification
//! and privacy canaries. Injected sourceFailure cases model an outage; they do
//! not establish a live transport failure.
#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "tests read reviewed package fixtures and drive the actual offline Evidence command; they read no operator configuration"
)]

use base64::Engine as _;
use registry_evidence::bundle::{evidence_package_limits, Bundle, DeploymentInputs};
use registry_platform_config::verify_package;
use registry_platform_sqlite::materialize_fixture;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
};
use tempfile::TempDir;

struct LoadedProject {
    _temporary: TempDir,
    runtime_path: PathBuf,
    bundle: Arc<Bundle>,
}

impl Drop for LoadedProject {
    fn drop(&mut self) {
        set_tree_mode(self._temporary.path(), 0o755, 0o644);
    }
}

fn evaluate(project: &LoadedProject, fixture: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidence"))
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .arg("evaluate")
        .arg("--runtime-config")
        .arg(&project.runtime_path)
        .arg("--fixture")
        .arg(fixture)
        .arg("--explain")
        .arg("--explain-format")
        .arg("json")
        .output()
        .expect("the actual Evidence fixture command starts")
}

// The production fixture command remains the owner of these assertions:
//
// A case states its world in the form its transport has. HTTP has exact
// recorded exchanges; statement cases select a registrant from the fixture's
// own extract and execute reviewed SQL. Injected failures remain modeled.
//
// The statement is named rather than restated: its text is a bundle artifact
// hashed with the rest, so a second copy would be something else to drift.
// Its host evaluation instant is bound where the statement executes, so the
// fixture cannot replace it with a prepared parameter.
//
// A requirement disclosing more than one concept states every concept it
// discloses, so a new or leaked concept cannot pass unnoticed. A uniquely
// found record with inconsistent derivation inputs shares the unavailable
// public class with unresolved lookup outcomes. Expected failures must match
// their closed outcome rather than merely produce an error.
#[test]
fn reference_deployment_projects_execute_the_closed_fixture_contract() {
    let mut evaluated = 0;
    for name in discovered_projects() {
        let project = load_project_with(&name, |_| {});
        let mut covered = BTreeSet::new();
        for requirement in &project.bundle.config.requirements {
            let path = requirement
                .fixtures
                .as_ref()
                .expect("reference requirement declares fixtures")
                .as_str();
            assert!(
                covered.insert(path),
                "{name}: fixture assigned more than once"
            );
            let fixture = project
                .bundle
                .fixtures
                .get(path)
                .expect("declared reference fixture");
            assert_eq!(fixture["syntheticOnly"], true, "{name}/{path}");
            let expected = fixture["cases"].as_array().expect("reference cases");
            assert!(!expected.is_empty(), "{name}/{path}: no cases");
            let output = evaluate(&project, path);
            assert!(
                output.status.success(),
                "{name}/{path}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                output.stderr.is_empty(),
                "{name}/{path}: unexpected stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: Value =
                serde_json::from_slice(&output.stdout).expect("single JSON fixture report");
            assert_eq!(report["passed"], true, "{name}/{path}");
            assert_eq!(report["evaluatedCases"], expected.len(), "{name}/{path}");
            let observed = report["cases"]
                .as_array()
                .expect("actual executed case traces");
            assert_eq!(
                observed.len(),
                expected.len(),
                "{name}/{path}: every case executes"
            );
            for (declared, actual) in expected.iter().zip(observed) {
                assert_eq!(
                    actual["id"], declared["id"],
                    "{name}/{path}: exact case order"
                );
                assert!(
                    actual.get("failure").is_none(),
                    "{name}/{path}: case failed"
                );
                assert!(
                    actual.get("findingCodes").is_none(),
                    "{name}/{path} case {}: comparison findings {}",
                    actual["id"],
                    actual["findingCodes"]
                );
                assert!(actual.get("expectedResult").is_some());
                assert!(actual.get("observedResult").is_some());
                assert!(actual.get("reasonCode").is_some());
                // An injected outage or an early bundle rejection does not
                // execute acquisition stages. Real pack acquisitions do.
                if declared.get("acquisition").is_some() {
                    assert!(
                        !actual["stages"]
                            .as_array()
                            .expect("executed stages")
                            .is_empty(),
                        "{name}/{path} case {}: no acquisition stages observed",
                        actual["id"]
                    );
                }
            }
            for canary in fixture
                .pointer("/privacyExpectation/diagnosticsExclude")
                .and_then(Value::as_array)
                .expect("reference diagnostic canaries")
            {
                let canary = canary.as_str().expect("diagnostic canary string");
                assert!(
                    !String::from_utf8_lossy(&output.stdout).contains(canary),
                    "{name}/{path}: diagnostic contains a prohibited value"
                );
            }
            evaluated += expected.len();
        }
        assert_eq!(
            covered.len(),
            project.bundle.fixtures.len(),
            "{name}: orphaned reference fixture"
        );
    }
    assert!(evaluated > 0, "no reference case executed");
}

#[test]
fn reference_fixture_refuses_wrong_expected_facts_in_the_real_command() {
    let mut changed_fixture = None;
    let project = load_project_with("protected-read-evidence", |files| {
        if let Some((path, bytes)) = files
            .iter_mut()
            .find(|(path, _)| path.starts_with("fixtures/"))
        {
            let mut fixture: Value = serde_norway::from_slice(bytes).expect("reference fixture");
            let case = &mut fixture["cases"][0];
            let mut facts = case["expected"]["facts"].clone();
            facts["record_reference"] = Value::String("REC-NOT-THE-REPLAYED-RECORD".to_owned());
            case["expected"]["facts"] = facts;
            *bytes = serde_json::to_vec_pretty(&fixture).expect("negative fixture serializes");
            changed_fixture = Some(path.clone());
        }
    });
    let fixture = changed_fixture.expect("a reviewed reference fixture was mutated");
    let output = evaluate(&project, &fixture);
    assert!(!output.status.success(), "mismatched exact facts must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("reference exact facts did not match"),
        "{stderr}"
    );
    assert!(!stderr.contains("REC-NOT-THE-REPLAYED-RECORD"));
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("failure has a structured trace");
    assert_eq!(report["passed"], false);
}

/// Every reference deployment project on disk, in a stable order.
///
/// The list is read rather than written out. A project that exists and runs in
/// no test is the failure this file is here to prevent, and a literal list is
/// exactly what lets a new project arrive unnoticed.
fn discovered_projects() -> Vec<String> {
    let mut names = fs::read_dir(projects_root())
        .expect("reference deployment projects are readable")
        .map(|entry| entry.expect("reference project entry is readable"))
        .filter(|entry| {
            entry
                .file_type()
                .expect("reference project entry type is readable")
                .is_dir()
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    assert!(
        !names.is_empty(),
        "no reference deployment project was discovered"
    );
    names
}

fn load_project_with(
    project_name: &str,
    mutate: impl FnOnce(&mut BTreeMap<String, Vec<u8>>),
) -> LoadedProject {
    let project_root = projects_root().join(project_name);
    let original_runtime = fs::read_to_string(project_root.join("runtime.yaml"))
        .unwrap_or_else(|_| panic!("{project_name}: runtime is unreadable"));
    let runtime_config =
        registry_evidence::config::RuntimeConfig::parse_yaml(original_runtime.as_bytes())
            .unwrap_or_else(|_| panic!("{project_name}: checked-in runtime is invalid"));

    let temporary = tempfile::tempdir().expect("temporary project deployment");
    let bundle_root = temporary.path().join("bundle");
    let source_root = project_root.join("bundle");
    let limits = evidence_package_limits();
    let verified = verify_package(&source_root, &limits, "evidencectl package")
        .expect("the maintained reference package verifies");
    let mut files = verified
        .files()
        .filter(|path| !registry_platform_config::package::is_envelope_file(path))
        .map(|path| {
            (
                path.to_owned(),
                fs::read(source_root.join(path)).expect("verified reference artifact reads"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    mutate(&mut files);
    registry_platform_config::package::write_package(
        &bundle_root,
        &files,
        verified.revision(),
        &limits,
        "evidencectl package",
    )
    .expect("the isolated reference package writes with its exact checksum closure");

    let secret_root = temporary.path().join("secrets");
    fs::create_dir(&secret_root).expect("temporary secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("temporary secret root is private");
    let audit_path = temporary.path().join("audit.jsonl");
    let ca_path = temporary.path().join("reference-ca.pem");
    let certificate =
        rcgen::generate_simple_self_signed(vec!["registry.example.invalid".to_owned()])
            .expect("synthetic reference TLS certificate");
    let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.cert.der());
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        &ca_path,
        format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"),
    )
    .expect("temporary CA writes");

    let mut local_runtime = original_runtime;
    replace_once(
        &mut local_runtime,
        "/etc/registry-evidence/bundle",
        &bundle_root.display().to_string(),
    );
    replace_once(
        &mut local_runtime,
        "/run/secrets/registry-evidence",
        &secret_root.display().to_string(),
    );
    replace_once(
        &mut local_runtime,
        "/var/lib/registry-evidence/audit/evidence.jsonl",
        &audit_path.display().to_string(),
    );
    if local_runtime.contains("/etc/registry-evidence/ca/government-internal.pem") {
        replace_once(
            &mut local_runtime,
            "/etc/registry-evidence/ca/government-internal.pem",
            &ca_path.display().to_string(),
        );
    }
    // The bundle does not load until the extract its runtime document binds
    // exists, and the seed that builds that extract is itself a bundle artifact,
    // so the fixture is read from the project directory here rather than through
    // the bundle that is not loaded yet.
    if let Some(seed) = project_extract_seed(project_name, temporary.path()) {
        let extract_root = temporary.path().join("extracts");
        fs::create_dir(&extract_root).expect("temporary extract root");
        let extract_path = extract_root.join("fixture.sqlite");
        materialize_fixture(&extract_path, &seed).unwrap_or_else(|_| {
            panic!("{project_name}: the fixture extract seed did not materialize")
        });
        // Not hygiene. The loader refuses a writable extract because the
        // executor opens it immutable, so the mode is part of what makes the
        // file loadable at all.
        fs::set_permissions(&extract_path, fs::Permissions::from_mode(0o444))
            .expect("temporary extract is immutable");
        replace_once(
            &mut local_runtime,
            bound_extract_path(project_name, &runtime_config),
            &extract_path.display().to_string(),
        );
    }
    // A project with an activated target authority commits the compiled
    // document beside its runtime; it is activated into a private root the
    // way an operator does before the first start.
    let activated_authority = local_runtime.contains(AUTHORITY_ROOT);
    if activated_authority {
        let authority_root = temporary.path().join("authority");
        fs::create_dir(&authority_root).expect("temporary authority root");
        fs::set_permissions(&authority_root, fs::Permissions::from_mode(0o700))
            .expect("temporary authority root is private");
        replace_once(
            &mut local_runtime,
            AUTHORITY_ROOT,
            &authority_root.display().to_string(),
        );
    }
    let runtime_path = temporary.path().join("runtime.yaml");
    fs::write(&runtime_path, local_runtime).expect("temporary runtime writes");
    set_tree_mode(&bundle_root, 0o555, 0o444);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("temporary runtime is immutable");
    fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o444))
        .expect("temporary CA is immutable");

    if activated_authority {
        // Activation is audited, so it resolves the project's audit key.
        let audit_key = secret_root.join("audit-hmac-key");
        fs::write(&audit_key, [0x5a_u8; 32]).expect("synthetic audit key writes");
        fs::set_permissions(&audit_key, fs::Permissions::from_mode(0o400))
            .expect("synthetic audit key is private");
        let activated = Command::new(env!("CARGO_BIN_EXE_evidence"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME")
            .args(["authority", "activate", "--runtime-config"])
            .arg(&runtime_path)
            .arg("--document")
            .arg(project_root.join("compiled-authority.yaml"))
            .output()
            .expect("the actual Evidence authority command starts");
        assert!(
            activated.status.success(),
            "{project_name}: authority activation failed: {}",
            String::from_utf8_lossy(&activated.stderr)
        );
    }
    let deployment = DeploymentInputs::load(&runtime_path).unwrap_or_else(|error| {
        panic!("{project_name}: production deployment loading failed: {error:?}")
    });
    let (loaded_bundle, _loaded_runtime) = deployment.into_parts();
    let bundle = Arc::new(loaded_bundle);
    LoadedProject {
        _temporary: temporary,
        runtime_path,
        bundle,
    }
}

/// The extract seed a project's fixtures state, if any of them state one.
/// A local extract executes real SQL; HTTP fixtures replay exact transport
/// transcripts without contacting a live source or resolving its credentials.
fn project_extract_seed(project_name: &str, project_root: &Path) -> Option<String> {
    let fixtures_root = project_root.join("bundle/fixtures");
    let mut seeds = fs::read_dir(fixtures_root)
        .expect("reference fixture directory")
        .map(|entry| entry.expect("reference fixture entry").path())
        .filter_map(|path| {
            let bytes = fs::read(path).expect("reference fixture bytes");
            let fixture: Value = serde_norway::from_slice(&bytes).expect("reference fixture YAML");
            fixture
                .pointer("/common/extract")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    assert!(
        seeds.len() <= 1,
        "{project_name}: more than one fixture states an extract"
    );
    seeds.pop()
}
/// The host path a project's runtime document binds its one extract profile to.
fn bound_extract_path<'a>(
    project_name: &str,
    runtime: &'a registry_evidence::config::RuntimeConfig,
) -> &'a str {
    let mut bindings = runtime.source_extracts.iter();
    let binding = bindings
        .next()
        .unwrap_or_else(|| panic!("{project_name}: the runtime binds no extract"));
    assert!(
        bindings.next().is_none(),
        "{project_name}: the runtime binds more than one extract"
    );
    binding.1.path.as_str()
}

/// The runtime path of an activated target authority, replaced by a private
/// root for each loaded project.
const AUTHORITY_ROOT: &str = "/var/lib/registry-evidence/authority";

fn projects_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/reference/request-adapter/deployment-projects")
        .canonicalize()
        .expect("reference deployment projects exist")
}

fn replace_once(text: &mut String, from: &str, to: &str) {
    assert_eq!(
        text.matches(from).count(),
        1,
        "runtime fixture binding drifted"
    );
    *text = text.replacen(from, to, 1);
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("directory mode updates");
        for entry in fs::read_dir(path).expect("mode target is readable") {
            set_tree_mode(
                &entry.expect("mode target entry is readable").path(),
                directory_mode,
                file_mode,
            );
        }
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .expect("file mode updates");
    }
}
