// SPDX-License-Identifier: Apache-2.0

//! The BReg tooling a development run relies on: a project `rstack dev` runs
//! stays a local placeholder that the public package command refuses as a
//! deployment, and `bregctl test` refuses a runtime path with its closed
//! report.

use std::{fs, os::unix::fs::OpenOptionsExt, process::Command};

fn project(root: &std::path::Path, extra: &str) {
    fs::write(
        root.join("registry.yaml"),
        include_str!(
            "../../../products/platform/conformance/projects/breg-project-dev/registry/registry.yaml"
        ),
    )
    .unwrap();
    fs::write(
        root.join("dev.yaml"),
        format!(
            "# yaml-language-server: $schema=https://id.registrystack.org/schemas/breg/project-dev/project-dev.v1alpha1.schema.json\n\
apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\n\
kind: BRegProjectDev\n\
issuer: https://issuer.example.invalid\n\
products:\n  - {{product: breg, project: ., audience: registry}}\n\
people:\n  operator:\n    subject: operator\n    client: operator-client\n    grants:\n      breg: {{profile: operator, scopes: []}}\n\
scenarioFile: tests/scenarios.yaml\n\
{extra}"
        ),
    )
    .unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/scenarios.yaml"),
        "apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1\nkind: RStackScenarios\nscenarios:\n  - id: smoke\n    steps:\n      - {id: read, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
    )
    .unwrap();
}

fn fixture_project(root: &std::path::Path, extra: &str) {
    project(root, extra);
    fs::write(
        root.join("tests/journeys.yaml"),
        concat!(
            "apiVersion: id.registrystack.org/formats/breg/journeys/v1\n",
            "kind: BRegJourneys\n",
            "journeys:\n",
            "  - id: real-journey\n",
            "    steps:\n",
            "      - id: real-step\n",
            "        recordType: record\n",
            "        accessProfile: operator\n",
            "        claims: {principal: fixture-operator}\n",
            "        request: {type: list}\n",
            "        expect: {outcome: success, status: 200, count: 0}\n",
        ),
    )
    .unwrap();
}

/// The run directories `state` still holds; kept logs of failed runs are not
/// runs.
fn live_runs(state: &std::path::Path) -> Vec<String> {
    match fs::read_dir(state) {
        Ok(entries) => entries
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "failed")
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("cannot read the run state: {error}"),
    }
}

/// Match the existing BReg dev-client normalizer, not a new issuer default.
fn public_parity_client_claims(
    client: &serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let mut claims = client["claims"].as_object().unwrap().clone();
    claims
        .entry("registry_actor_kind".to_owned())
        .or_insert_with(|| serde_json::json!("service"));
    assert!(
        client["allowHumanFixture"].as_bool().unwrap_or(false)
            == (claims["registry_actor_kind"] == "human"),
        "human fixtures require the existing authored opt-in"
    );
    claims
}

#[test]
fn public_parity_clients_preserve_existing_machine_contract() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/minimal/dev-clients.yaml");
    let clients = registry_platform_yaml::Reader::new(path.display().to_string())
        .scan(&fs::read(&path).unwrap())
        .unwrap()
        .unwrap()
        .to_json_value();
    for client in clients["clients"].as_array().unwrap() {
        let raw = client["claims"].as_object().unwrap();
        assert!(!raw.contains_key("registry_actor_kind"));
        let normalized = public_parity_client_claims(client);
        assert!(normalized.len() == raw.len() + 1);
        assert!(raw
            .iter()
            .all(|(key, value)| normalized.get(key) == Some(value)));
        assert!(normalized["registry_actor_kind"] == "service");
        for kind in ["agent", "service", "human"] {
            let mut explicit = client.clone();
            explicit["claims"]["registry_actor_kind"] = serde_json::json!(kind);
            explicit["allowHumanFixture"] = serde_json::json!(kind == "human");
            assert!(public_parity_client_claims(&explicit)["registry_actor_kind"] == kind);
        }
    }
}

/// A closed receipt, not a redacted copy of arbitrary native error text.
fn public_parity_start_result(
    started: &serde_json::Value,
    exit: Option<i32>,
    source_unchanged: bool,
) -> serde_json::Value {
    let (schema, status) = match (
        started["schema_version"].as_str(),
        started["status"].as_str(),
    ) {
        (Some("registry.rstack.dev.v1"), Some("ready")) => {
            (Some("registry.rstack.dev.v1"), Some("ready"))
        }
        (Some("registry.rstack.error.v1"), Some("refused")) => {
            (Some("registry.rstack.error.v1"), Some("refused"))
        }
        _ => (None, None),
    };
    let class = if status == Some("refused") {
        match started["error"]["class"].as_str() {
            Some("domain") => Some("domain"),
            Some("usage") => Some("usage"),
            Some("operational") => Some("operational"),
            _ => None,
        }
    } else {
        None
    };
    let exit = exit.filter(|code| (0..=3).contains(code));
    let valid = matches!(
        (status, class, exit),
        (Some("ready"), None, Some(0 | 1))
            | (Some("refused"), Some("domain"), Some(1))
            | (Some("refused"), Some("usage"), Some(2))
            | (Some("refused"), Some("operational"), Some(3))
    );
    // Preserve only membership of this one existing contract diagnostic.
    // Neither its surrounding text nor any prefix-derived code is copied.
    let reserved = status == Some("refused")
        && started["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("breg.registry.canonical-base-iri-reserved"));
    serde_json::json!({"phase":"native-start","startExit":exit,"schema":schema,"status":status,
        "class":class,"protocolEnvelopeValid":valid,"reservedIdentityDiagnostic":reserved,
        "sourceBytesUnchanged":source_unchanged})
}

#[test]
fn public_parity_retention_excludes_short_claim_message_and_forged_codes() {
    for canary in [
        "unallowlisted-claim-canary auth.unallowlisted-canary",
        "tiny-token-abc",
        "config.short-canary source.short-canary test.forged-canary",
    ] {
        let report = serde_json::json!({"schema_version":"registry.rstack.error.v1","status":"refused",
            "error":{"class":"domain","message":canary,"code":canary},
            "claims":{"short":canary},"boundedRedactedSummary":canary,"diagnosticCodes":[canary]});
        let result = public_parity_start_result(&report, Some(1), true);
        let encoded = result.to_string();
        for word in canary.split_whitespace() {
            assert!(!encoded.contains(word));
        }
        assert!(result.get("boundedRedactedSummary").is_none());
        assert!(result.get("diagnosticCodes").is_none());
        assert!(result.as_object().unwrap().len() == 8);
        assert!(result["protocolEnvelopeValid"] == true);
        assert!(result["reservedIdentityDiagnostic"] == false);
    }
    let report = serde_json::json!({"schema_version":"registry.rstack.error.v1","status":"refused",
        "error":{"class":"domain","message":"breg.registry.canonical-base-iri-reserved short-claim-canary auth.forged-canary"}});
    let result = public_parity_start_result(&report, Some(1), false);
    assert!(result["reservedIdentityDiagnostic"] == true);
    assert!(result["sourceBytesUnchanged"] == false);
    assert!(!result.to_string().contains("canary"));
}

#[test]
fn public_parity_retention_accepts_only_fixed_protocol_enums() {
    for (class, exit) in [("domain", 1), ("usage", 2), ("operational", 3)] {
        let report = serde_json::json!({"schema_version":"registry.rstack.error.v1","status":"refused","error":{"class":class}});
        let result = public_parity_start_result(&report, Some(exit), true);
        assert!(result["protocolEnvelopeValid"] == true);
        assert!(result["class"] == class);
        for field in ["schema_version", "status", "class"] {
            let mut forged = report.clone();
            if field == "class" {
                forged["error"][field] = serde_json::json!("short-enum-canary");
            } else {
                forged[field] = serde_json::json!("short-enum-canary");
            }
            let result = public_parity_start_result(&forged, Some(exit), true);
            assert!(!result.to_string().contains("canary"));
            assert!(result["class"].is_null());
            assert!(result["protocolEnvelopeValid"] == false);
        }
    }
    let ready = serde_json::json!({"schema_version":"registry.rstack.dev.v1","status":"ready","error":{"class":"short-enum-canary"}});
    for exit in [0, 1] {
        let result = public_parity_start_result(&ready, Some(exit), true);
        assert!(result["protocolEnvelopeValid"] == true && result["class"].is_null());
        assert!(!result.to_string().contains("canary"));
    }
    for exit in [None, Some(-1), Some(4), Some(101), Some(i32::MAX)] {
        let result = public_parity_start_result(&ready, exit, true);
        assert!(result["startExit"].is_null() && result["protocolEnvelopeValid"] == false);
    }
}

/// Public native lifecycle regression. The caller supplies a fresh owner-only
/// directory and a disposable TLS PostgreSQL, never a retained developer DB.
#[test]
#[ignore = "requires RSTACK_PARITY_ROOT, RSTACK_PARITY_DATABASE_URL_FILE, RSTACK_PARITY_DATABASE_CA, RSTACK_PARITY_RSTACK_BIN and RSTACK_PARITY_BREG_BIN"]
fn a_local_placeholder_project_runs_without_becoming_a_deployment_package() {
    use registry_breg::package::{
        load_package, load_predecessor_package, PackageError, PackageLoadContext,
    };
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    fn required(name: &str) -> PathBuf {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("set {name}"))
    }
    fn copy(source: &Path, target: &Path) {
        fs::create_dir(target).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let destination = target.join(entry.file_name());
            assert!(!entry.file_type().unwrap().is_symlink());
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &destination);
            } else {
                fs::copy(entry.path(), destination).unwrap();
            }
        }
    }
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    visit(root, &entry.path(), files);
                } else {
                    files.insert(
                        entry.path().strip_prefix(root).unwrap().to_owned(),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }
    struct OwnedRun {
        rstack: PathBuf,
        install: PathBuf,
        state: PathBuf,
        run: Option<String>,
    }
    impl OwnedRun {
        fn command(&self, operation: &str, subject: &Path) -> Command {
            let mut command = Command::new(&self.rstack);
            command
                .args(["--install-root"])
                .arg(&self.install)
                .args(["dev", operation])
                .arg(subject)
                .arg("--json")
                .env("RSTACK_DEV_STATE_DIR", &self.state)
                .env("RSTACK_BREGCTL_BIN", env!("CARGO_BIN_EXE_bregctl"))
                .env("RSTACK_BREG_BIN", required("RSTACK_PARITY_BREG_BIN"));
            command
        }
        fn stop(&mut self) {
            if let Some(id) = self.run.clone() {
                let stopped = self.command("stop", Path::new(&id)).output().unwrap();
                assert!(stopped.status.success(), "owned normal stop failed");
                let report: serde_json::Value = serde_json::from_slice(&stopped.stdout).unwrap();
                assert!(
                    report["status"] == "stopped",
                    "owned status must be stopped"
                );
                self.run = None;
                let later = self.command("status", Path::new(&id)).output().unwrap();
                assert!(later.status.success());
                let report: serde_json::Value = serde_json::from_slice(&later.stdout).unwrap();
                assert!(
                    report["status"] == "stopped",
                    "owned status must be stopped"
                );
            }
        }
    }
    impl Drop for OwnedRun {
        fn drop(&mut self) {
            if self.run.is_some() {
                self.stop();
            }
        }
    }

    let parent = required("RSTACK_PARITY_ROOT").canonicalize().unwrap();
    let scratch = tempfile::Builder::new()
        .prefix("public-local-package-")
        .tempdir_in(&parent)
        .unwrap();
    let root = scratch.path();
    let project = root.join("project");
    copy(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/minimal"),
        &project,
    );
    let source = fs::read_to_string(project.join("registry.yaml")).unwrap();
    assert_eq!(source.matches("https://directory.example.gov").count(), 1);
    fs::write(
        project.join("registry.yaml"),
        source.replace(
            "https://directory.example.gov",
            "https://directory.example.invalid",
        ),
    )
    .unwrap();

    // Derive identities and exact fixture-step assignments from the public
    // project's existing authored clients and journeys, without widening them.
    let yaml = |name: &str| -> serde_json::Value {
        let path = project.join(name);
        registry_platform_yaml::Reader::new(path.display().to_string())
            .scan(&fs::read(&path).unwrap())
            .unwrap()
            .unwrap()
            .to_json_value()
    };
    let clients = yaml("dev-clients.yaml");
    let journeys = yaml("tests/journeys.yaml");
    let mut people = serde_json::Map::new();
    for client in clients["clients"].as_array().unwrap() {
        let alias = client["id"].as_str().unwrap();
        assert_eq!(client["accessProfiles"].as_array().unwrap().len(), 1);
        let mut claims = public_parity_client_claims(client);
        let subject = claims.remove("registry_principal").unwrap();
        people.insert(alias.to_owned(), serde_json::json!({"subject":subject,"client":alias,
            "grants":{"breg":{"profile":client["accessProfiles"][0],"scopes":client["scopes"],"claims":claims}}}));
    }
    let mut assignments = serde_json::Map::new();
    for journey in journeys["journeys"].as_array().unwrap() {
        let mut steps = serde_json::Map::new();
        for step in journey["steps"].as_array().unwrap() {
            let selected: Vec<_> = clients["clients"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|client| {
                    client["claims"]["registry_principal"] == step["claims"]["principal"]
                        && client["accessProfiles"][0] == step["accessProfile"]
                        && client["scopes"] == step["claims"]["scopes"]
                        && client["claims"]["registry_purpose"] == step["claims"]["purpose"]
                })
                .collect();
            assert_eq!(
                selected.len(),
                1,
                "one existing authored client must bind each fixture step"
            );
            steps.insert(
                step["id"].as_str().unwrap().to_owned(),
                selected[0]["id"].clone(),
            );
        }
        assignments.insert(journey["id"].as_str().unwrap().to_owned(), steps.into());
    }
    fs::write(project.join("dev.yaml"), serde_json::to_vec_pretty(&serde_json::json!({
        "apiVersion":"id.registrystack.org/formats/breg/project-dev/v1alpha1","kind":"BRegProjectDev",
        "issuer":"https://issuer.example.invalid",
        "products":[{"product":"breg","project":".","audience":"registry"}],
        "people":people,"schemaTestPeople":assignments,
        "scenarioFile":"scenarios.yaml"
    })).unwrap()).unwrap();
    // The BReg project is the development project root here, and `bregctl
    // check` reads every YAML file under its tests/, so the scenario file
    // stays outside tests/.
    fs::write(project.join("scenarios.yaml"), serde_json::to_vec_pretty(&serde_json::json!({
        "apiVersion":"id.registrystack.org/formats/rstack/scenarios/v1alpha1","kind":"RStackScenarios",
        "scenarios":[{"id":"public-directory","steps":[{"id":"read-registry","product":"breg","as":"editor","method":"GET","path":"/v1/registry","expect":{"status":200}}]}]
    })).unwrap()).unwrap();
    let original = snapshot(&project);
    let mut owned = OwnedRun {
        rstack: required("RSTACK_PARITY_RSTACK_BIN"),
        install: root.join("install"),
        state: root.join("state"),
        run: None,
    };
    let checked = owned.command("check", &project).output().unwrap();
    assert!(
        checked.status.success(),
        "public authored project-dev check failed"
    );
    let database = fs::read_to_string(required("RSTACK_PARITY_DATABASE_URL_FILE")).unwrap();
    let output = owned
        .command("start", &project)
        .args(["--ttl", "5m"])
        .env("RSTACK_DEV_DATABASE_URL", database.trim())
        .env(
            "RSTACK_DEV_DATABASE_CA",
            required("RSTACK_PARITY_DATABASE_CA"),
        )
        .output()
        .unwrap();
    let started: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    if let Some(id) = started["run_id"].as_str() {
        owned.run = Some(id.to_owned());
    }
    fn retain_failure(root: &Path, parent: &Path) {
        if !root.is_dir() {
            return;
        }
        for entry in fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                retain_failure(&entry.path(), parent);
            } else if entry.file_name() == "breg-test-report.json" {
                let bytes = fs::read(entry.path()).unwrap();
                let _: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                use std::io::Write as _;
                fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(parent.join("first-failure.json"))
                    .unwrap()
                    .write_all(&bytes)
                    .unwrap();
            }
        }
    }
    retain_failure(&owned.state, &parent);
    let safe = public_parity_start_result(
        &started,
        output.status.code(),
        snapshot(&project) == original,
    );
    fs::write(
        parent.join("result.json"),
        serde_json::to_vec_pretty(&safe).unwrap(),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "public placeholder start refused; see bounded result.json"
    );
    assert!(started["status"] == "ready", "native start must be ready");
    assert!(
        started["scenarios"][0]["result"] == "passed",
        "native journey must pass"
    );
    let id = owned.run.as_deref().unwrap();
    let run_root = owned.state.join(id);
    let receipt = run_root.join("schema-test-receipt.json");
    let receipt_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    assert!(
        receipt_value["successfulJourneyIds"] == serde_json::json!(["directory-contact"]),
        "receipt must bind the authored journey"
    );
    fs::copy(&receipt, parent.join("schema-test-receipt.json")).unwrap();
    let package = run_root.join("breg-build/package");
    load_package(
        &package,
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    )
    .unwrap();
    assert!(matches!(
        load_package(
            &package,
            &PackageLoadContext {
                database_initialization_environment: "production"
            }
        ),
        Err(PackageError::DeploymentIdentity)
    ));
    load_predecessor_package(
        &package,
        &PackageLoadContext {
            database_initialization_environment: "production",
        },
    )
    .unwrap();
    let deployment = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("package")
        .arg(&project)
        .arg("--test-receipt")
        .arg(&receipt)
        .arg("--output")
        .arg(root.join("deployment-build"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(!deployment.status.success());
    let refused: serde_json::Value = serde_json::from_slice(&deployment.stdout).unwrap();
    assert!(refused["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["code"] == "breg.registry.canonical-base-iri-reserved"));
    assert!(!root.join("deployment-build").exists());
    let status = owned.command("status", Path::new(id)).output().unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(status["status"] == "ready", "native status must be ready");
    assert!(
        status["scenarios"] == started["scenarios"],
        "native status must match the start journey"
    );
    owned.stop();
    assert!(live_runs(&owned.state).is_empty());
    assert!(
        snapshot(&project) == original,
        "authored source must remain byte-identical"
    );
    fs::write(parent.join("result.json"), serde_json::to_vec_pretty(&serde_json::json!({"checkPassed":true,"startReady":true,"authoredNativeJourneyReceiptPassed":true,"journeyPassed":true,"localPackageAdmitted":true,"productionPackageRefused":true,"productionTargetLoadRefused":true,"predecessorRecoveryReadable":true,"statusReady":true,"stopStopped":true,"postStopStatusStopped":true,"stateEmpty":true,"sourceBytesUnchanged":true})).unwrap()).unwrap();
}

#[test]
fn local_package_public_command_keeps_reserved_identity_refusal() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let initialized = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("init")
        .arg(&project)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "normal public initialization must succeed"
    );
    let path = project.join("registry.yaml");
    let original = fs::read_to_string(&path).unwrap();
    assert!(original.matches("https://directory.example.gov").count() == 1);
    let source = original.replace(
        "https://directory.example.gov",
        "https://directory.example.invalid",
    );
    fs::write(&path, &source).unwrap();
    let output = root.path().join("deployment-build");
    let refused = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("package")
        .arg(&project)
        .arg("--schema-fingerprint")
        .arg(format!("sha256:{}", "0".repeat(64)))
        .arg("--test-receipt")
        .arg(root.path().join("missing-receipt.json"))
        .arg("--output")
        .arg(&output)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "ordinary package must refuse reserved identity"
    );
    let report: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["code"] == "breg.registry.canonical-base-iri-reserved"));
    assert!(!output.exists());
    assert!(fs::read_to_string(&path).unwrap() == source);
}

#[test]
fn native_schema_test_runtime_path_refusal_has_closed_report_envelope() {
    let scratch = tempfile::tempdir().unwrap();
    fixture_project(scratch.path(), "");
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("test")
        .arg(scratch.path())
        .args([
            "--runtime-config",
            "relative-private-canary",
            "--credentials",
            "relative-private-canary",
            "--output",
        ])
        .arg(scratch.path().join("receipt.json"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "test");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "test.runtime-config.path-invalid"
    );
    assert_eq!(report["diagnostics"][0]["path"], "runtimeConfig");
    assert!(!scratch.path().join("receipt.json").exists());
}
