#![cfg(unix)]

//! Exact production-candidate handoff through the real adopter and runtime
//! binaries. The gate is ignored in the ordinary package suite because it
//! starts services and requires `python3` and `openssl` on the host. The pinned
//! stock-issuer journey lives in the Evidence client acceptance suite; this
//! suite keeps the strict production HTTPS, signing, and audit handoff proof.
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::{
        fs::{OpenOptionsExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::Utc;
use p256::ecdsa::{
    signature::{hazmat::PrehashSigner as _, Signer as _},
    Signature, SigningKey,
};
use serde_json::{json, Value};

const TOKEN_AUDIENCE: &str = "registry-evidence-production-test";
const EVIDENCE_AUDIENCE: &str = "https://relying.invalid/production-acceptance";
const REQUIREMENT: &str = "urn:example:requirements:adult-status:v1";
const EVIDENCE_TYPE: &str = "urn:example:evidence-types:adult-status:v1";
const CONCEPT: &str = "urn:example:concepts:is-adult";
const PURPOSE: &str = "fixture-eligibility";
const SELECTOR_CANARY: &str = "synthetic-person-001";
const AGE_REQUIREMENT: &str = "urn:example:requirements:age-bracket:v1";
const AGE_CONCEPT: &str = "urn:example:concepts:age-bracket";
const IMMUNIZATION_REQUIREMENT: &str = "urn:example:requirements:immunization-summary:v1";
const SCHEDULE_CONCEPT: &str = "urn:example:concepts:schedule-complete";
const DOSE_COUNT_CONCEPT: &str = "urn:example:concepts:dose-count";
const RELATIONSHIP_REQUIREMENT: &str = "urn:example:requirements:parent-relationship:v1";
const RELATIONSHIP_CONCEPT: &str = "urn:example:concepts:relationship-confirmed";

#[test]
#[ignore = "opt-in starts real Evidence with a local HTTPS issuer, source, and Transit signer"]
fn production_candidate_handoff_reaches_verified_assertion_and_audit() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_https_identity();
    fixture.stage_target();
    let _transit = fixture.start_transit();

    assert_success(
        evidencectl()
            .arg("check")
            .arg(&fixture.project)
            .arg("--target")
            .arg(fixture.target.join("target.yaml"))
            .arg("--production")
            .env("EVIDENCE_BIN", evidence)
            .output()
            .expect("offline production check starts"),
        "offline production check",
    );
    let first = fixture.package(evidence);
    let first_revision = package_digest(&first);
    let first_bytes = snapshot_files(&fixture.candidate);
    fs::rename(&fixture.candidate, &fixture.first_candidate)
        .expect("archive the first create-only candidate");

    let second = fixture.package(evidence);
    let revision = package_digest(&second);
    assert_eq!(
        revision, first_revision,
        "package digest must be repeatable"
    );
    assert_eq!(
        snapshot_files(&fixture.candidate),
        first_bytes,
        "identical inputs and output binding must reproduce every candidate file byte"
    );
    assert!(fixture.candidate.join("runtime.yaml").is_file());
    assert!(fixture.candidate.join("compiled-authority.yaml").is_file());
    fixture.activate_candidate_bundle();
    fixture.provision_target_secrets();
    fixture.activate_target_authority(evidence);

    let mut https = fixture.start_https();
    fixture.wait_for_https(&mut https);
    let audit_secret = fixture.secrets.join("audit-hmac-key");
    let audit_secret_bytes = fs::read(&audit_secret).expect("audit secret");
    fs::remove_file(&audit_secret).expect("temporarily remove audit secret");
    let unavailable = evidencectl()
        .arg("doctor")
        .arg("--runtime-config")
        .arg(fixture.target_runtime.clone())
        .env("EVIDENCE_BIN", evidence)
        .env("SSL_CERT_FILE", &fixture.ca)
        .output()
        .expect("runtime doctor with unavailable secret starts");
    assert_eq!(
        unavailable.status.code(),
        Some(3),
        "an unavailable mounted runtime secret is an operational failure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&unavailable.stdout),
        String::from_utf8_lossy(&unavailable.stderr)
    );
    fs::write(&audit_secret, audit_secret_bytes).expect("restore audit secret");
    fs::set_permissions(&audit_secret, fs::Permissions::from_mode(0o600))
        .expect("restore audit secret mode");
    assert_success(
        evidencectl()
            .arg("doctor")
            .arg("--runtime-config")
            .arg(&fixture.target_runtime)
            .env("EVIDENCE_BIN", evidence)
            .env("SSL_CERT_FILE", &fixture.ca)
            .output()
            .expect("doctor starts"),
        "target-host doctor",
    );
    assert_success(
        evidencectl()
            .arg("test")
            .arg(&fixture.project)
            .arg("--target")
            .arg(fixture.target.join("target.yaml"))
            .env("EVIDENCE_BIN", evidence)
            .output()
            .expect("fixture driver starts"),
        "target-host fixtures",
    );
    fixture.assert_compose_package_identity(evidence, &revision);

    assert_success(
        evidencectl()
            .arg("doctor")
            .arg("--runtime-config")
            .arg(fixture.target_runtime.clone())
            .env("EVIDENCE_BIN", evidence)
            .env("SSL_CERT_FILE", &fixture.ca)
            .output()
            .expect("runtime doctor starts"),
        "runtime doctor",
    );
    let mut service = fixture.start_evidence(evidence);
    fixture.wait_for_evidence(&mut service);

    // A candidate staged beside the serving instance shares its audit path.
    // The plain form meets that instance's writer lock and says how to check
    // beside it; the lock-free form proves the candidate without taking it.
    let beside = evidencectl()
        .arg("doctor")
        .arg("--runtime-config")
        .arg(fixture.target_runtime.clone())
        .env("EVIDENCE_BIN", evidence)
        .env("SSL_CERT_FILE", &fixture.ca)
        .output()
        .expect("runtime doctor beside the serving instance starts");
    assert_eq!(
        beside.status.code(),
        Some(3),
        "the serving instance's writer lock must refuse the locking form"
    );
    assert!(
        String::from_utf8_lossy(&beside.stderr).contains("--without-audit-lock"),
        "a held writer lock must name the lock-free form"
    );
    assert_success(
        evidencectl()
            .arg("doctor")
            .arg("--runtime-config")
            .arg(fixture.target_runtime.clone())
            .arg("--without-audit-lock")
            .env("EVIDENCE_BIN", evidence)
            .env("SSL_CERT_FILE", &fixture.ca)
            .output()
            .expect("lock-free runtime doctor starts"),
        "lock-free runtime doctor beside the serving instance",
    );

    let token = fixture.access_token();
    let published_revision = published_configuration_revision(fixture.evidence_port, &token);
    assert_ne!(
        published_revision, revision,
        "an assertion carries its requirement's own revision, not the bundle's"
    );
    let nonce = URL_SAFE_NO_PAD.encode([0x42_u8; 32]);
    let (status, response) = post_evidence(fixture.evidence_port, &token, &nonce);
    if status != 200 {
        let log = fs::read(fixture.root.join("evidence.log")).expect("Evidence diagnostic log");
        let source_token = fs::read(&fixture.source_token).expect("source token");
        for prohibited in [
            token.as_bytes(),
            source_token.as_slice(),
            SELECTOR_CANARY.as_bytes(),
        ] {
            assert!(
                !log.windows(prohibited.len()).any(|part| part == prohibited),
                "Evidence diagnostic leaked protected request or credential data"
            );
        }
        panic!(
            "Evidence request returned HTTP {status}, not HTTP 200; value-free log:\n{}",
            String::from_utf8_lossy(&log)
        );
    }
    fs::write(&fixture.response, &response).expect("retain signed response");
    fs::set_permissions(&fixture.response, fs::Permissions::from_mode(0o600))
        .expect("protect retained response");
    assert!(
        fixture.source_marker.is_file(),
        "the real request must reach the authenticated HTTPS source"
    );

    let payload = signed_payload(&response);
    assert_eq!(payload["assuranceProfile"], "production");
    assert_eq!(payload["configurationRevision"], published_revision);
    assert_eq!(payload["supportedValues"][0]["providesValueFor"], CONCEPT);
    assert_eq!(payload["supportedValues"][0]["value"], true);
    let payload_bytes = serde_json::to_vec(&payload).expect("payload serializes");
    for prohibited in [
        b"date_of_birth".as_slice(),
        SELECTOR_CANARY.as_bytes(),
        token.as_bytes(),
    ] {
        assert!(
            !payload_bytes
                .windows(prohibited.len())
                .any(|part| part == prohibited),
            "signed payload retained protected source or selector data"
        );
    }
    let source_token = fs::read(&fixture.source_token).expect("source token");
    assert!(
        !payload_bytes
            .windows(source_token.len())
            .any(|part| part == source_token),
        "signed payload retained a source credential"
    );

    fixture.write_verification_policy(&payload, &nonce, &published_revision);
    assert_success(
        Command::new(evidence)
            .arg("verify")
            .arg("--jws")
            .arg(&fixture.response)
            .arg("--jwks")
            .arg(&fixture.evidence_jwks)
            .arg("--policy")
            .arg(&fixture.policy)
            .output()
            .expect("offline verifier starts"),
        "independent production verification policy",
    );

    let audit = wait_for_audit(&fixture.audit_path);
    assert_audit_contract(
        &audit,
        &revision,
        &fixture.evidence_signing_kid(),
        &[source_token.as_slice(), token.as_bytes()],
    );
    stop_gracefully(&mut service, "Evidence");
    stop_forcefully(&mut https);
}

#[test]
#[ignore = "opt-in builds exact-source Evidence for an independent package check"]
fn production_package_accepts_the_real_package_check_digest() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_four_shape_project();
    fixture.stage_target();
    fixture.authorize_four_shapes();

    let output = fixture.package(evidence);
    let revision = package_digest(&output);
    assert!(revision.starts_with("sha256:"));
    assert!(fixture.candidate.join("bundle/evidence.yaml").is_file());
}

#[test]
#[ignore = "opt-in builds exact-source Evidence for an independent target closure check"]
fn offline_production_check_closes_without_target_host_mounts() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_target();

    assert!(!fixture.candidate.exists());
    assert!(!fixture.secrets.exists());
    assert!(!fixture.project.join(".generated/secrets").exists());
    assert!(!fixture.audit_path.exists());
    let output = assert_success(
        evidencectl()
            .args(["--format", "json", "check"])
            .arg(&fixture.project)
            .arg("--target")
            .arg(fixture.target.join("target.yaml"))
            .arg("--production")
            .env("EVIDENCE_BIN", evidence)
            .output()
            .expect("offline production check starts"),
        "offline production check",
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("check JSON report");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["proof"], "compiled-target");
    assert_eq!(report["offline"], true);
    assert_eq!(report["networkAccess"], false);
    assert_eq!(report["secretResolution"], false);
    assert_eq!(report["fixtureExecution"], false);
    assert!(report["packageDigest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
    assert_eq!(
        report["definitionRevisions"]
            .as_array()
            .expect("definition revisions")
            .len(),
        1
    );
    assert!(!fixture.candidate.exists());
    assert!(!fixture.secrets.exists());
    assert!(!fixture.project.join(".generated/secrets").exists());
    assert!(!fixture.audit_path.exists());
}

#[test]
#[ignore = "opt-in builds exact-source Evidence for an independent authoring check"]
fn offline_project_check_needs_no_disposable_signing_state() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    assert!(!fixture.project.join(".generated/secrets").exists());

    let output = assert_success(
        evidencectl()
            .args(["--format", "json", "check"])
            .arg(&fixture.project)
            .env("EVIDENCE_BIN", evidence)
            .output()
            .expect("offline project check starts"),
        "offline project check",
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("check JSON report");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["proof"], "authoring");
    assert!(report.get("fixtureProof").is_none());
    assert!(!fixture.project.join(".generated/secrets").exists());

    fixture.stage_target();
    edit_json_document(&fixture.target.join("authority.yaml"), |authority| {
        authority["accessProfiles"]["statutory-caseworker-v1"]["grants"][0]["purpose"] =
            json!("outside-definition-ceiling");
    });
    let target_check = evidencectl()
        .args(["--format", "json", "check"])
        .arg(&fixture.project)
        .arg("--target")
        .arg(fixture.target.join("target.yaml"))
        .env("EVIDENCE_BIN", evidence)
        .output()
        .expect("target-bound offline check starts");
    assert_eq!(
        target_check.status.code(),
        Some(1),
        "the selected target must enforce the AssertionDefinition grant ceiling: {}",
        String::from_utf8_lossy(&target_check.stdout)
    );
}

#[test]
#[ignore = "opt-in builds exact-source Evidence to inspect compiler diagnostics"]
fn explain_refuses_unknown_source_members_without_disclosing_values() {
    const CANARY: &str = "SOURCE_SECRET_CANARY";
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    edit_json_document(&fixture.project.join("evidence.yaml"), |project| {
        project["sources"]["people"]["unknownSourceMember"] = json!(CANARY);
    });

    let output = evidencectl()
        .args(["--format", "json", "explain"])
        .arg(&fixture.project)
        .env("EVIDENCE_BIN", evidence)
        .output()
        .expect("explain starts");
    assert_eq!(output.status.code(), Some(1));
    assert!(!output
        .stdout
        .windows(CANARY.len())
        .any(|part| part == CANARY.as_bytes()));
    assert!(!output
        .stderr
        .windows(CANARY.len())
        .any(|part| part == CANARY.as_bytes()));
    let report: Value = serde_json::from_slice(&output.stdout).expect("refusal JSON report");
    assert_eq!(report["status"], "refused");
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .any(|diagnostic| {
            diagnostic["path"]
                .as_str()
                .is_some_and(|path| path.contains("/sources/people/unknownSourceMember"))
        }));
}

#[test]
#[ignore = "opt-in uses the macOS loader to verify private staging under a permissive umask"]
fn offline_check_makes_private_staging_under_umask_022() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_target();

    let runtime_library_path = std::env::var("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH")
        .or_else(|_| std::env::var("DYLD_FALLBACK_LIBRARY_PATH"))
        .unwrap_or_default();
    let output = assert_success(
        Command::new("/bin/sh")
            .args([
                "-c",
                "umask 022\nexport DYLD_FALLBACK_LIBRARY_PATH=\"${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}\"\nexec \"$@\"",
                "evidencectl-check",
            ])
            .env("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH", runtime_library_path)
            .arg(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["--format", "json", "check"])
            .arg(&fixture.project)
            .arg("--target")
            .arg(fixture.target.join("target.yaml"))
            .arg("--production")
            .env("EVIDENCE_BIN", evidence)
            .output()
            .expect("offline check starts under umask 022"),
        "offline check under umask 022",
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("check JSON report");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["proof"], "compiled-target");
}

#[test]
#[ignore = "opt-in builds exact-source Evidence to verify evidence-grade target rules"]
fn explicit_evidence_grade_target_applies_its_own_strict_source_rules() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_target();
    edit_json_document(&fixture.target.join("target.yaml"), |target| {
        target["assuranceProfile"] = json!("evidence-grade");
        target["connections"]["people"]["origin"] = json!("http://registry.invalid");
    });

    let output = evidencectl()
        .args(["--format", "json", "check"])
        .arg(&fixture.project)
        .arg("--target")
        .arg(fixture.target.join("target.yaml"))
        .env("EVIDENCE_BIN", evidence)
        .output()
        .expect("evidence-grade check starts");
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).expect("refusal JSON report");
    assert_eq!(report["status"], "domain-refusal");
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .any(|diagnostic| {
            diagnostic["severity"] == "error"
                && diagnostic["path"]
                    .as_str()
                    .is_some_and(|path| path.contains("/connections/people/origin"))
        }));
}

#[test]
#[ignore = "opt-in builds exact-source Evidence and evaluates all four assertion shapes"]
fn production_build_checks_and_evaluates_every_neutral_authoring_shape() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_four_shape_project();
    fixture.stage_target();
    let _transit = fixture.start_transit();
    fixture.authorize_four_shapes();

    let output = fixture.package(evidence);
    let revision = package_digest(&output);
    fixture.activate_candidate_bundle();
    fixture.provision_target_secrets();
    fixture.activate_target_authority(evidence);
    let checked_revision = check_package(
        evidence,
        &fixture.target_runtime,
        "published four-shape production check",
    );
    assert_eq!(checked_revision, revision);

    let bundle: Value = serde_norway::from_slice(
        &fs::read(fixture.candidate.join("bundle/evidence.yaml")).expect("four-shape bundle"),
    )
    .expect("four-shape bundle parses");
    assert_eq!(bundle["assuranceProfile"], "production");
    let requirements = bundle["requirements"]
        .as_array()
        .expect("compiled requirements");
    assert_eq!(requirements.len(), 4);
    let requirements = requirements
        .iter()
        .map(|requirement| {
            (
                requirement["uri"]
                    .as_str()
                    .expect("stable requirement identifier"),
                requirement,
            )
        })
        .collect::<BTreeMap<_, _>>();

    assert_requirement_forms(&requirements, REQUIREMENT, &["boolean"], 1);
    assert_requirement_forms(&requirements, AGE_REQUIREMENT, &["controlled-category"], 1);
    assert_requirement_forms(
        &requirements,
        IMMUNIZATION_REQUIREMENT,
        &["bounded-integer", "boolean"],
        1,
    );
    assert_requirement_forms(&requirements, RELATIONSHIP_REQUIREMENT, &["boolean"], 2);
    assert_eq!(requirements[REQUIREMENT]["handle"], "adult-status");
    assert_eq!(requirements[REQUIREMENT]["concepts"][0]["handle"], "adult");
    for fixture_path in [
        "adult-status.yaml",
        "age-bracket.yaml",
        "immunization-summary.yaml",
        "parent-relationship.yaml",
    ] {
        assert!(
            fixture
                .candidate
                .join("bundle/fixtures")
                .join(fixture_path)
                .is_file(),
            "the production candidate must capture fixture {fixture_path}"
        );
    }
    let age_codelist = requirements[AGE_REQUIREMENT]["concepts"][0]["constraints"]["codelist"]
        .as_str()
        .expect("compiled controlled-category codelist path");
    assert!(
        fixture
            .candidate
            .join("bundle")
            .join(age_codelist)
            .is_file(),
        "the governed controlled-category codelist must be captured"
    );
}

#[test]
#[ignore = "opt-in starts the local issuer and Evidence services through Docker"]
fn public_lifecycle_keeps_local_dev_state_out_of_the_production_candidate() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    let docker = installed_binary("DOCKER_BIN", "docker");
    let retained_openapi = fixture.root.join("lifecycle.openapi.yaml");
    fs::write(
        &retained_openapi,
        "openapi: 3.1.0\ninfo: {title: Lifecycle source, version: 1.0.0}\npaths: {}\n",
    )
    .expect("lifecycle OpenAPI");

    assert_success(
        evidencectl()
            .arg("init")
            .arg(&fixture.project)
            .arg("--openapi")
            .arg(&retained_openapi)
            .args(["--profile", "local"])
            .output()
            .expect("public new starts"),
        "public new",
    );
    assert!(!fixture.project.join(".evidence").exists());
    fixture.stage_local_project();
    assert_success(
        evidencectl()
            .args(["keygen", "token", "--output"])
            .arg(fixture.project.join(".generated/secrets/source-token"))
            .output()
            .expect("local source token keygen starts"),
        "local source token keygen",
    );

    let started = assert_success(
        evidencectl()
            .args(["dev", "start"])
            .arg(&fixture.project)
            .arg("--evidence-bin")
            .arg(evidence)
            .arg("--docker-bin")
            .arg(docker)
            .args(["--evidence-port", &fixture.evidence_port.to_string()])
            .args(["--issuer-port", &fixture.issuer_port.to_string()])
            .args(["--ready-timeout-seconds", "20"])
            .output()
            .expect("public dev starts"),
        "public dev with complete local authority",
    );
    let mut stop_guard = DevStopGuard::new(&fixture.project);
    let started_stdout = String::from_utf8(started.stdout).expect("dev stdout");
    assert!(started_stdout.contains(&format!(
        "Evidence ready at http://127.0.0.1:{}",
        fixture.evidence_port
    )));
    assert!(started_stdout.contains(&format!(
        "Issuer ready at http://127.0.0.1:{}",
        fixture.issuer_port
    )));
    let dev_root = fixture.project.join(".evidence/dev");
    let local_bundle = fs::read(dev_root.join("bundle/evidence.yaml")).expect("local dev bundle");
    assert!(local_bundle
        .windows(REQUIREMENT.len())
        .any(|part| part == REQUIREMENT.as_bytes()));
    assert_success(
        evidencectl()
            .args(["dev", "stop"])
            .arg(&fixture.project)
            .output()
            .expect("public dev stop starts"),
        "public dev stop",
    );
    stop_guard.disarm();
    assert!(dev_root.join("state.json").is_file());
    let stopped_dev = snapshot_files(&dev_root);

    fixture.stage_authoring_project();
    fixture.stage_target();
    let governed_project = fs::read_to_string(fixture.project.join("evidence.yaml"))
        .expect("governed EvidenceProject");
    assert!(governed_project.contains(REQUIREMENT));
    assert!(governed_project.contains(CONCEPT));
    assert!(fixture.project.join("fixtures/adult-status.yaml").is_file());

    let local_source_token = fs::read(fixture.project.join(".generated/secrets/source-token"))
        .expect("local source token");
    let build = fixture.package(evidence);
    package_digest(&build);
    assert_eq!(
        snapshot_files(&dev_root),
        stopped_dev,
        "production build must neither consume nor mutate stopped local state"
    );
    let candidate = snapshot_files(&fixture.candidate);
    for (path, bytes) in &candidate {
        assert!(
            !path.to_string_lossy().contains(".evidence"),
            "production candidate captured local state at {}",
            path.display()
        );
        assert!(
            !bytes
                .windows(local_source_token.len())
                .any(|part| part == local_source_token),
            "production candidate copied local secret material into {}",
            path.display()
        );
    }
    let production_bundle =
        fs::read(fixture.candidate.join("bundle/evidence.yaml")).expect("production bundle");
    assert!(
        production_bundle
            .windows(REQUIREMENT.len())
            .any(|part| part == REQUIREMENT.as_bytes()),
        "production candidate must use the normalized stable definition"
    );

    assert_success(
        evidencectl()
            .args(["dev", "clean"])
            .arg(&fixture.project)
            .output()
            .expect("public dev clean starts"),
        "public dev clean",
    );
}

struct DevStopGuard {
    project: PathBuf,
    active: bool,
}

impl DevStopGuard {
    fn new(project: &Path) -> Self {
        Self {
            project: project.to_owned(),
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for DevStopGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = evidencectl()
                .args(["dev", "stop"])
                .arg(&self.project)
                .output();
        }
    }
}

struct TransitServer {
    stop: Arc<AtomicBool>,
    socket: PathBuf,
    worker: Option<thread::JoinHandle<()>>,
}

impl Drop for TransitServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.socket);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("synthetic Transit server");
        }
        let _ = fs::remove_file(&self.socket);
    }
}

struct Fixture {
    temporary: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
    target: PathBuf,
    target_runtime: PathBuf,
    candidate: PathBuf,
    first_candidate: PathBuf,
    secrets: PathBuf,
    audit_path: PathBuf,
    ca: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    oidc_private: PathBuf,
    oidc_jwks: PathBuf,
    source_token: PathBuf,
    source_marker: PathBuf,
    https_ready: PathBuf,
    response: PathBuf,
    evidence_jwks: PathBuf,
    policy: PathBuf,
    https_port: u16,
    evidence_port: u16,
    issuer_port: u16,
}

impl Fixture {
    fn new() -> Self {
        // Keep the Transit socket below the Unix path limit. Resolve only the
        // newly owned root because macOS may expose its temp directory via
        // a symlinked /var prefix that the publisher correctly refuses.
        let temporary = tempfile::tempdir().expect("acceptance tempdir");
        let root = fs::canonicalize(temporary.path()).expect("canonical acceptance tempdir");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("acceptance tempdir mode");
        let project = root.join("authoring");
        let target = project.join("deployment-targets/production");
        let candidate = root.join("candidate");
        let secrets = root.join("production-secrets");
        let ports = free_ports(3);
        Self {
            target_runtime: candidate.join("runtime.yaml"),
            first_candidate: root.join("first-candidate"),
            audit_path: root.join("audit/evidence.jsonl"),
            ca: root.join("tls/ca.pem"),
            tls_cert: root.join("tls/server.pem"),
            tls_key: root.join("tls/server.key"),
            oidc_private: root.join("oidc-private/signing-p256-private-jwk"),
            oidc_jwks: root.join("oidc.jwks.json"),
            source_token: secrets.join("source-token"),
            source_marker: root.join("source-requested"),
            https_ready: root.join("https-ready"),
            response: root.join("response.jws.json"),
            evidence_jwks: root.join("evidence.jwks.json"),
            policy: root.join("verification.policy.yaml"),
            https_port: ports[0],
            evidence_port: ports[1],
            issuer_port: ports[2],
            temporary,
            root,
            project,
            target,
            candidate,
            secrets,
        }
    }

    fn start_transit(&self) -> TransitServer {
        let socket = self.root.join("transit-proxy.sock");
        let listener = UnixListener::bind(&socket).expect("bind synthetic Transit socket");
        listener
            .set_nonblocking(true)
            .expect("synthetic Transit nonblocking listener");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let root = self.root.clone();
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if worker_stop.load(Ordering::Acquire) {
                            break;
                        }
                        // Darwin inherits O_NONBLOCK from the listener; wait for
                        // each complete request within the bounded read timeout.
                        stream
                            .set_nonblocking(false)
                            .expect("synthetic Transit blocking accepted stream");
                        serve_transit_request(&root, &mut stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("synthetic Transit accept failed: {error}"),
                }
            }
        });
        TransitServer {
            stop,
            socket,
            worker: Some(worker),
        }
    }

    fn stage_authoring_project(&self) {
        fs::create_dir_all(self.project.join("functions")).expect("Function directory");
        fs::create_dir_all(self.project.join("fixtures")).expect("fixture directory");
        let project = json!({
            "apiVersion":"id.registrystack.org/formats/evidence/project/v1alpha1",
            "kind":"EvidenceProject",
            "id":"production-handoff",
            "selectorProfiles":{"person-reference-v1":{"maximumAggregateBytes":200,"fields":{"person-id":{"type":"string","minimumBytes":1,"maximumBytes":200}}}},
            "functions":[
                {"id":"people-prepare","interface":"source-prepare/v1","source":"functions/people-prepare.rhai"},
                {"id":"people-extract","interface":"source-extract/v1","source":"functions/people-extract.rhai"},
                {"id":"adult-status-derive","interface":"assertion-derive/v1","source":"functions/adult-status-derive.rhai"}
            ],
            "sources":{"people":{
                "type":"http-json","connection":"people","acquisitionPosture":"field-projected",
                "selectors":[{"role":"subject","profiles":["person-reference-v1"]}],
                "request":{"method":"POST","path":"/v1/facts","fixedHeaders":[{"name":"Accept","value":"application/json"}]},
                "prepare":{"function":"people-prepare"},
                "adapterParameters":{"requestedFields":["date_of_birth"],"resultLimit":2},
                "adapterParametersSchema":{"type":"object","additionalProperties":false,"required":["requestedFields","resultLimit"],"properties":{"requestedFields":{"const":["date_of_birth"]},"resultLimit":{"const":2}}},
                "preparationLimits":{"query":"forbidden","jsonBody":"required","maximumJsonDepth":8,"maximumCollectionItems":16,"maximumStringBytes":256,"maximumNormalizedBytes":4096},
                "response":{"projection":["/total","/date_of_birth"],"shape":{"type":"object","additionalProperties":false,"required":["total"],"properties":{"total":{"type":"bounded-integer","minimum":0,"maximum":1000000},"date_of_birth":{"type":"date"}}},"maximumBytes":65536},
                "extract":{"function":"people-extract"},
                "facts":{"date-of-birth":{"type":"date"}},
                "limits":{"attemptTimeoutMilliseconds":3000,"maximumConcurrency":8}
            }},
            "assertionDefinitions":{"adult-status": assertion_definition(AssertionDefinitionInput {
                question: "Is the person at least 18 years old?",
                requirement: REQUIREMENT,
                kind: "criterion",
                evidence_type: EVIDENCE_TYPE,
                purpose: PURPOSE,
                source: "people",
                derive: "adult-status-derive",
                output: "adult",
                concept: CONCEPT,
                output_constraints: json!({"type":"boolean"}),
                subjects: vec![("subject", "person-reference-v1")],
                fixture: "fixtures/adult-status.yaml",
            })}
        });
        write_json_document(&self.project.join("evidence.yaml"), &project);
        fs::write(self.project.join("functions/people-prepare.rhai"), r#"fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let lookup = #{"person_id": selectors["subject"]["values"]["person-id"]};
    #{"query": [], "body": #{"lookup": lookup, "fields": parameters["requestedFields"], "limit": parameters["resultLimit"]}}
}
"#).expect("people prepare Function");
        fs::write(
            self.project.join("functions/people-extract.rhai"),
            r#"fn extract(source_response, context) {
    let total = source_response["total"];
    if total == 0 { return #{outcome: "no_match"}; }
    if total > 1 { return #{outcome: "ambiguous"}; }
    let value = get_path(source_response, "/date_of_birth");
    if is_missing(value) { return #{outcome: "match", facts: #{}}; }
    #{outcome: "match", facts: #{"date-of-birth": value}}
}
"#,
        )
        .expect("people extract Function");
        fs::write(self.project.join("functions/adult-status-derive.rhai"), r#"fn derive(facts, selectors, context) {
    let born = parse_date(required(facts["date-of-birth"], "date_of_birth_missing"));
    [#{output: "adult", value: compare_dates(context.legal_local_date, add_calendar_years(born, 18)) >= 0}]
}
"#).expect("adult derivation Function");
        fs::write(self.project.join("fixtures/adult-status.yaml"), format!(r#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
coequalAcceptanceDefinition: true
syntheticOnly: true
common:
  observedAt: '2026-08-02T00:00:00Z'
  legalLocalDate: '2026-08-02'
  selectors:
    subject: {{profile: person-reference-v1, values: {{person-id: {SELECTOR_CANARY}}}}}
cases:
  - {{id: positive, source: {{total: 1, date_of_birth: '2000-01-01'}}, expectedValue: true, expectedLookup: match, derivationRuns: true, signedSuccess: true}}
  - {{id: negative-false-is-success, source: {{total: 1, date_of_birth: '2010-01-01'}}, expectedValue: false, expectedLookup: match, derivationRuns: true, signedSuccess: true}}
  - {{id: boundary-on, legalLocalDate: '2026-08-02', source: {{total: 1, date_of_birth: '2008-08-02'}}, expectedValue: true, expectedLookup: match, derivationRuns: true, signedSuccess: true}}
  - {{id: missing-fact, source: {{total: 1}}, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: no-match, source: {{total: 0}}, expectedLookup: no_match, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: ambiguous, source: {{total: 2}}, expectedLookup: ambiguous, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: source-failure, sourceFailure: timeout, expectedPublicProblem: source.unavailable, signedSuccess: false}}
  - {{id: negative-wrong-derived-type, injectedDerivation: [{{concept_id: {CONCEPT}, value: 'true'}}], expected: output-gate-rejection}}
  - {{id: anti-reconstruction, companionBundle: threshold-ladder, expected: bundle-rejection}}
privacyExpectation:
  evidenceContains: [{CONCEPT}]
  evidenceExcludes: [date_of_birth, person-id]
  diagnosticsExclude: [{SELECTOR_CANARY}, fixture-source-canary]
"#)).expect("adult fixture");
    }

    fn stage_local_project(&self) {
        self.stage_authoring_project();
        edit_json_document(&self.project.join("local-target.yaml"), |target| {
            target["project"] = json!("production-handoff");
            target["connections"]["people"] = json!({
                "origin": format!("https://127.0.0.1:{}", self.https_port),
                "authentication": {"type":"bearer", "tokenRef":"secret:file/source-token"}
            });
        });
        write_json_document(
            &self.project.join("dev-authority.yaml"),
            &json!({
                "apiVersion":"id.registrystack.org/formats/evidence/target-authority/v1alpha1",
                "kind":"EvidenceTargetAuthority",
                "target":"local",
                "project":"production-handoff",
                "accessProfiles":{
                    "statutory-caseworker-v1":{
                        "authority":"statutory",
                        "actorKind":"service",
                        "requesterTags":["local-evidence-client"],
                        "grants":[authority_grant(
                            "adult-status",
                            PURPOSE,
                            vec![("subject", "person-reference-v1")],
                        )]
                    }
                }
            }),
        );
    }

    fn stage_four_shape_project(&self) {
        edit_json_document(&self.project.join("evidence.yaml"), |project| {
            project["selectorProfiles"]["child-reference-v1"] = json!({"maximumAggregateBytes":200,"fields":{"child-id":{"type":"string","minimumBytes":1,"maximumBytes":200}}});
            project["selectorProfiles"]["candidate-reference-v1"] = json!({"maximumAggregateBytes":200,"fields":{"candidate-id":{"type":"string","minimumBytes":1,"maximumBytes":200}}});
            for function in [
                json!({"id":"immunizations-prepare","interface":"source-prepare/v1","source":"functions/immunizations-prepare.rhai"}),
                json!({"id":"immunizations-extract","interface":"source-extract/v1","source":"functions/immunizations-extract.rhai"}),
                json!({"id":"relationships-prepare","interface":"source-prepare/v1","source":"functions/relationships-prepare.rhai"}),
                json!({"id":"relationships-extract","interface":"source-extract/v1","source":"functions/relationships-extract.rhai"}),
                json!({"id":"age-bracket-derive","interface":"assertion-derive/v1","source":"functions/age-bracket-derive.rhai"}),
                json!({"id":"immunization-summary-derive","interface":"assertion-derive/v1","source":"functions/immunization-summary-derive.rhai"}),
                json!({"id":"parent-relationship-derive","interface":"assertion-derive/v1","source":"functions/parent-relationship-derive.rhai"}),
            ] {
                project["functions"].as_array_mut().unwrap().push(function);
            }
            project["sources"]["immunizations"] = http_source(
                "/v1/immunizations",
                "immunizations-prepare",
                "immunizations-extract",
                "dose_count",
                json!({"type":"bounded-integer","minimum":0,"maximum":20}),
                vec![("subject", "person-reference-v1")],
            );
            project["sources"]["relationships"] = http_source(
                "/v1/relationships",
                "relationships-prepare",
                "relationships-extract",
                "relationship_confirmed",
                json!({"type":"boolean"}),
                vec![
                    ("child", "child-reference-v1"),
                    ("candidate-parent", "candidate-reference-v1"),
                ],
            );
            project["assertionDefinitions"]["age-bracket"] = assertion_definition(
                AssertionDefinitionInput {
                    question: "Which governed age bracket contains this person?",
                    requirement: AGE_REQUIREMENT,
                    kind: "information-requirement",
                    evidence_type: "urn:example:evidence-types:age-bracket:v1",
                    purpose: "service-path-selection",
                    source: "people",
                    derive: "age-bracket-derive",
                    output: "age-bracket",
                    concept: AGE_CONCEPT,
                    output_constraints: json!({"type":"controlled-category","values":["under-18","18-to-24","25-to-64","65-or-older"]}),
                    subjects: vec![("subject", "person-reference-v1")],
                    fixture: "fixtures/age-bracket.yaml",
                },
            );
            project["assertionDefinitions"]["immunization-summary"] =
                assertion_definition(AssertionDefinitionInput {
                    question: "Is the schedule complete, and how many doses are recorded?",
                    requirement: IMMUNIZATION_REQUIREMENT,
                    kind: "information-requirement",
                    evidence_type: "urn:example:evidence-types:immunization-summary:v1",
                    purpose: "care-coordination",
                    source: "immunizations",
                    derive: "immunization-summary-derive",
                    output: "schedule-complete",
                    concept: SCHEDULE_CONCEPT,
                    output_constraints: json!({"type":"boolean"}),
                    subjects: vec![("subject", "person-reference-v1")],
                    fixture: "fixtures/immunization-summary.yaml",
                });
            project["assertionDefinitions"]["immunization-summary"]["outputs"]["dose-count"] = json!({"concept":DOSE_COUNT_CONCEPT,"type":"bounded-integer","minimum":0,"maximum":20});
            project["assertionDefinitions"]["parent-relationship"] =
                assertion_definition(AssertionDefinitionInput {
                    question: "Is the candidate registered as a parent of the child?",
                    requirement: RELATIONSHIP_REQUIREMENT,
                    kind: "criterion",
                    evidence_type: "urn:example:evidence-types:parent-relationship:v1",
                    purpose: "relationship-check",
                    source: "relationships",
                    derive: "parent-relationship-derive",
                    output: "relationship-confirmed",
                    concept: RELATIONSHIP_CONCEPT,
                    output_constraints: json!({"type":"boolean"}),
                    subjects: vec![
                        ("child", "child-reference-v1"),
                        ("candidate-parent", "candidate-reference-v1"),
                    ],
                    fixture: "fixtures/parent-relationship.yaml",
                });
        });
        for (name, script) in [
            (
                "immunizations-prepare",
                r#"fn prepare(selectors, context) {
    let lookup = #{"person_id": selectors["subject"]["values"]["person-id"]};
    #{"query": [], "body": #{"lookup": lookup, "fields": ["dose_count"], "limit": 2}}
}"#,
            ),
            (
                "immunizations-extract",
                r#"fn extract(source_response, context) { let total = source_response["total"]; if total == 0 { return #{outcome:"no_match"}; } if total > 1 { return #{outcome:"ambiguous"}; } #{outcome:"match", facts: #{dose_count: source_response["dose_count"]}} }"#,
            ),
            (
                "relationships-prepare",
                r#"fn prepare(selectors, context) {
    let lookup = #{"child_id": selectors["child"]["values"]["child-id"], "candidate_id": selectors["candidate-parent"]["values"]["candidate-id"]};
    #{"query": [], "body": #{"lookup": lookup, "fields": ["relationship_confirmed"], "limit": 2}}
}"#,
            ),
            (
                "relationships-extract",
                r#"fn extract(source_response, context) { let total = source_response["total"]; if total == 0 { return #{outcome:"no_match"}; } if total > 1 { return #{outcome:"ambiguous"}; } #{outcome:"match", facts: #{relationship_confirmed: source_response["relationship_confirmed"]}} }"#,
            ),
            (
                "age-bracket-derive",
                r#"fn derive(facts, selectors, context) {
    let born = parse_date(required(facts["date-of-birth"], "date_of_birth_missing"));
    let value = "under-18";
    if compare_dates(context.legal_local_date, add_calendar_years(born, 18)) >= 0 { value = "18-to-24"; }
    if compare_dates(context.legal_local_date, add_calendar_years(born, 25)) >= 0 { value = "25-to-64"; }
    if compare_dates(context.legal_local_date, add_calendar_years(born, 65)) >= 0 { value = "65-or-older"; }
    [#{output:"age-bracket", value:value}]
}"#,
            ),
            (
                "immunization-summary-derive",
                r#"fn derive(facts, selectors, context) { let count = required(facts["dose_count"], "dose_count_missing"); [#{output:"schedule-complete", value:count >= 3}, #{output:"dose-count", value:count}] }"#,
            ),
            (
                "parent-relationship-derive",
                r#"fn derive(facts, selectors, context) { [#{output:"relationship-confirmed", value:required(facts["relationship_confirmed"], "relationship_missing")}] }"#,
            ),
        ] {
            fs::write(
                self.project.join(format!("functions/{name}.rhai")),
                format!("{script}\n"),
            )
            .expect("four-shape Function");
        }
        self.stage_four_shape_fixtures();
    }

    fn stage_four_shape_fixtures(&self) {
        fs::write(
            self.project.join("fixtures/age-bracket.yaml"),
            format!(
                r#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
coequalAcceptanceDefinition: true
syntheticOnly: true
common:
  observedAt: '2026-08-02T00:00:00Z'
  legalLocalDate: '2026-08-02'
  selectors:
    subject: {{profile: person-reference-v1, values: {{person-id: {SELECTOR_CANARY}}}}}
  expectedRequestParts:
    query: []
    body: {{lookup: {{person_id: {SELECTOR_CANARY}}}, fields: [date_of_birth], limit: 2}}
  expectedTransport:
    path: /v1/facts
    fixedHeaders: [{{name: Accept, value: application/json}}]
cases:
  - {{id: positive, source: {{total: 1, date_of_birth: '2000-01-01'}}, expectedValue: 25-to-64, expectedLookup: match, derivationRuns: true, signedSuccess: true}}
  - {{id: negative-under-18-is-success, source: {{total: 1, date_of_birth: '2010-01-01'}}, expectedValue: under-18, expectedLookup: match, derivationRuns: true, signedSuccess: true}}
  - {{id: boundary-on-18, source: {{total: 1, date_of_birth: '2008-08-02'}}, expectedValue: 18-to-24, expectedLookup: match, derivationRuns: true, signedSuccess: true}}
  - {{id: missing-fact, source: {{total: 1}}, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: no-match, source: {{total: 0}}, expectedLookup: no_match, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: ambiguous, source: {{total: 2}}, expectedLookup: ambiguous, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: source-failure, sourceFailure: timeout, expectedPublicProblem: source.unavailable, signedSuccess: false}}
  - {{id: negative-wrong-derived-type, injectedDerivation: [{{concept_id: {AGE_CONCEPT}, value: true}}], expected: output-gate-rejection}}
  - {{id: anti-reconstruction, companionBundle: threshold-ladder, expected: bundle-rejection}}
privacyExpectation:
  evidenceContains: [{AGE_CONCEPT}]
  evidenceExcludes: [date_of_birth, person_id]
  diagnosticsExclude: [{SELECTOR_CANARY}, fixture-source-canary]
"#
            ),
        )
        .expect("age-bracket fixture");

        fs::write(
            self.project.join("fixtures/immunization-summary.yaml"),
            format!(
                r#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
coequalAcceptanceDefinition: true
syntheticOnly: true
common:
  observedAt: '2026-08-02T00:00:00Z'
  selectors:
    subject: {{profile: person-reference-v1, values: {{person-id: {SELECTOR_CANARY}}}}}
  expectedRequestParts:
    query: []
    body: {{lookup: {{person_id: {SELECTOR_CANARY}}}, fields: [dose_count], limit: 2}}
  expectedTransport:
    path: /v1/immunizations
    fixedHeaders: [{{name: Accept, value: application/json}}]
cases:
  - id: positive
    source: {{total: 1, dose_count: 4}}
    expectedValues: {{schedule-complete: true, dose-count: 4}}
    expectedLookup: match
    derivationRuns: true
    signedSuccess: true
  - id: negative-false-is-success
    source: {{total: 1, dose_count: 2}}
    expectedValues: {{schedule-complete: false, dose-count: 2}}
    expectedLookup: match
    derivationRuns: true
    signedSuccess: true
  - id: boundary-maximum
    source: {{total: 1, dose_count: 20}}
    expectedValues: {{schedule-complete: true, dose-count: 20}}
    expectedLookup: match
    derivationRuns: true
    signedSuccess: true
  - {{id: missing-fact, source: {{total: 1}}, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: no-match, source: {{total: 0}}, expectedLookup: no_match, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: ambiguous, source: {{total: 2}}, expectedLookup: ambiguous, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: source-failure, sourceFailure: timeout, expectedPublicProblem: source.unavailable, signedSuccess: false}}
  - id: negative-wrong-derived-type
    injectedDerivation:
      - {{concept_id: {SCHEDULE_CONCEPT}, value: true}}
      - {{concept_id: {DOSE_COUNT_CONCEPT}, value: '4'}}
    expected: output-gate-rejection
  - {{id: anti-reconstruction, companionBundle: threshold-ladder, expected: bundle-rejection}}
privacyExpectation:
  evidenceContains: [{SCHEDULE_CONCEPT}, {DOSE_COUNT_CONCEPT}]
  evidenceExcludes: [dose_count, person_id]
  diagnosticsExclude: [{SELECTOR_CANARY}, fixture-source-canary]
"#
            ),
        )
        .expect("immunization fixture");

        fs::write(
            self.project.join("fixtures/parent-relationship.yaml"),
            format!(
                r#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
coequalAcceptanceDefinition: true
syntheticOnly: true
common:
  observedAt: '2026-08-02T00:00:00Z'
  selectors:
    child: {{profile: child-reference-v1, values: {{child-id: synthetic-child-001}}}}
    candidate-parent: {{profile: candidate-reference-v1, values: {{candidate-id: synthetic-parent-001}}}}
  expectedRequestParts:
    query: []
    body:
      lookup: {{child_id: synthetic-child-001, candidate_id: synthetic-parent-001}}
      fields: [relationship_confirmed]
      limit: 2
  expectedTransport:
    path: /v1/relationships
    fixedHeaders: [{{name: Accept, value: application/json}}]
cases:
  - {{id: positive, source: {{total: 1, relationship_confirmed: true}}, expectedValue: true, expectedLookup: match, derivationRuns: true, signedSuccess: true}}
  - {{id: negative-false-is-success, source: {{total: 1, relationship_confirmed: false}}, expectedValue: false, expectedLookup: match, derivationRuns: true, signedSuccess: true}}
  - id: boundary-role-order
    source: {{total: 1, relationship_confirmed: true}}
    expectedValue: true
    expectedLookup: match
    derivationRuns: true
    signedSuccess: true
    expectedSubjectRoles: [child, candidate-parent]
  - {{id: missing-fact, source: {{total: 1}}, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: no-match, source: {{total: 0}}, expectedLookup: no_match, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: ambiguous, source: {{total: 2}}, expectedLookup: ambiguous, expectedPublicProblem: evidence.unavailable, derivationRuns: false, signedSuccess: false}}
  - {{id: source-failure, sourceFailure: timeout, expectedPublicProblem: source.unavailable, signedSuccess: false}}
  - {{id: negative-wrong-derived-type, injectedDerivation: [{{concept_id: {RELATIONSHIP_CONCEPT}, value: 'true'}}], expected: output-gate-rejection}}
  - {{id: anti-reconstruction, companionBundle: relationship-graph, expected: bundle-rejection}}
privacyExpectation:
  evidenceContains: [child, candidate-parent, {RELATIONSHIP_CONCEPT}]
  evidenceExcludes: [child_id, candidate_id, relationship_confirmed]
  diagnosticsExclude: [synthetic-child-001, synthetic-parent-001, fixture-source-canary]
"#
            ),
        )
        .expect("parent relationship fixture");
    }

    fn stage_https_identity(&self) {
        let tls = self.ca.parent().expect("TLS directory");
        fs::create_dir(tls).expect("TLS directory");
        fs::write(
            tls.join("server.cnf"),
            "[server]\nsubjectAltName = IP:127.0.0.1\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\n",
        )
        .expect("OpenSSL config");
        let ca_key = tls.join("ca.key");
        assert_success(
            Command::new("openssl")
                .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256"])
                .args(["-days", "1", "-keyout"])
                .arg(&ca_key)
                .arg("-out")
                .arg(&self.ca)
                .args(["-subj", "/CN=Evidence acceptance CA"])
                .output()
                .expect("openssl starts"),
            "test HTTPS CA generation",
        );
        let csr = tls.join("server.csr");
        assert_success(
            Command::new("openssl")
                .args(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256"])
                .arg("-keyout")
                .arg(&self.tls_key)
                .arg("-out")
                .arg(&csr)
                .args(["-subj", "/CN=127.0.0.1"])
                .output()
                .expect("openssl starts"),
            "test HTTPS leaf-key generation",
        );
        assert_success(
            Command::new("openssl")
                .args(["x509", "-req", "-sha256", "-days", "1", "-in"])
                .arg(&csr)
                .arg("-CA")
                .arg(&self.ca)
                .arg("-CAkey")
                .arg(&ca_key)
                .arg("-CAcreateserial")
                .arg("-out")
                .arg(&self.tls_cert)
                .arg("-extfile")
                .arg(tls.join("server.cnf"))
                .args(["-extensions", "server"])
                .output()
                .expect("openssl starts"),
            "test HTTPS leaf certificate generation",
        );
        fs::set_permissions(&self.tls_key, fs::Permissions::from_mode(0o600))
            .expect("TLS key mode");
        fs::set_permissions(&self.ca, fs::Permissions::from_mode(0o444)).expect("CA mode");

        let public = self.root.join("oidc-public.jwk.json");
        assert_success(
            evidencectl()
                .args(["keygen", "signing", "--output-dir"])
                .arg(self.oidc_private.parent().expect("OIDC private directory"))
                .arg("--public-output")
                .arg(&public)
                .output()
                .expect("OIDC keygen starts"),
            "external OIDC signing key generation",
        );
        assert_success(
            evidencectl()
                .args(["jwks", "--output"])
                .arg(&self.oidc_jwks)
                .arg(&public)
                .output()
                .expect("OIDC JWKS assembly starts"),
            "external OIDC JWKS assembly",
        );
    }

    fn stage_target(&self) {
        let target_public_keys = self.target.join("public-keys");
        fs::create_dir_all(&target_public_keys).expect("deployment target public keys");
        let generated_public = self.root.join("evidence-transit-public.jwk.json");
        assert_success(
            evidencectl()
                .args(["keygen", "signing", "--output-dir"])
                .arg(self.root.join("transit-evidence-key"))
                .arg("--public-output")
                .arg(&generated_public)
                .output()
                .expect("Evidence Transit fixture keygen starts"),
            "Evidence Transit fixture key generation",
        );
        let governed_public: Value = serde_json::from_slice(
            &fs::read(&generated_public).expect("Evidence Transit fixture public JWK"),
        )
        .expect("Evidence Transit fixture public JWK parses");
        let signing_kid = governed_public["kid"]
            .as_str()
            .expect("Evidence Transit fixture kid");
        let governed_public_name = format!("{signing_kid}.jwk.json");
        fs::rename(
            &generated_public,
            target_public_keys.join(&governed_public_name),
        )
        .expect("publish governed Evidence public JWK to deployment target");
        let identity = format!("https://127.0.0.1:{}", self.https_port);
        let target = json!({
            "apiVersion":"id.registrystack.org/formats/evidence/target/v1alpha1", "kind":"EvidenceTarget",
            "id":"production", "project":"production-handoff", "authority":"authority.yaml", "assuranceProfile":"production",
            "package":{"root":self.root.join("activated/bundle")},
            "service":{"providerId":"urn:example:providers:evidence","issuer":"urn:example:issuers:evidence","publicOrigin":"https://evidence.example.test","trustDomain":"urn:example:trust-domains:acceptance"},
            "authentication":{"oidc":{"issuer":identity,"audience":TOKEN_AUDIENCE,"jwksSource":{"type":"uri","uri":format!("{identity}/.well-known/jwks.json")},"tokenTypes":["at+jwt"],"algorithms":["ES256"],"principalClaim":"sub","requesterTagsClaim":"evidence_tags","evidenceAudienceClaim":"evidence_audience","allowedClients":"unrestricted","requiredScopes":"unrestricted","maximumTokenLifetimeSeconds":300,"revokedKeyIds":[]}},
            "connections":{"people":{"origin":format!("https://127.0.0.1:{}",self.https_port),"authentication":{"type":"bearer","tokenRef":"secret:file/source-token"}}},
            "secretProviders":{"file":{"root":self.secrets}},
            "signer":{"type":"transit","algorithm":"ES256","publicJwkFile":format!("public-keys/{governed_public_name}"),"unixSocketPath":self.root.join("transit-proxy.sock"),"mount":"transit","keyName":"evidence-signing","keyVersion":1,"attemptTimeoutMilliseconds":2000},
            "listener":{"bind":format!("127.0.0.1:{}",self.evidence_port),"tlsTermination":"operator-controlled-upstream","trustProxyIdentityHeaders":false,"maximumRequestBytes":65536,"maximumConcurrentRequests":64,"requestTimeoutMilliseconds":10000,"shutdownGraceMilliseconds":5000},
            "audit":{"path":self.audit_path,"hashKeyRef":"secret:file/audit-hmac-key","hashKeyVersion":1},
            "subjectBinding":{"secretRef":"secret:file/subject-binding-hmac-key","keyVersion":1},
            "rateLimits":{"requestsPerPrincipalPerMinute":60,"burstPerPrincipal":16,"failedSelectorAttemptsPerPrincipalAuthorityPerMinute":10},
            "responseFormats":["signed-jws"], "outboundTls":{"systemRoots":true,"trustProfiles":{}}
        });
        write_json_document(&self.target.join("target.yaml"), &target);
        let authority = json!({
            "apiVersion":"id.registrystack.org/formats/evidence/target-authority/v1alpha1", "kind":"EvidenceTargetAuthority",
            "target":"production", "project":"production-handoff",
            "accessProfiles":{"statutory-caseworker-v1":{"authority":"statutory","actorKind":"service","requesterTags":["fixture-agency"],"grants":[authority_grant("adult-status", PURPOSE, vec![("subject","person-reference-v1")])]}}
        });
        write_json_document(&self.target.join("authority.yaml"), &authority);
    }

    fn authorize_four_shapes(&self) {
        edit_json_document(&self.target.join("authority.yaml"), |authority| {
            let grants = authority["accessProfiles"]["statutory-caseworker-v1"]["grants"]
                .as_array_mut()
                .unwrap();
            grants.push(authority_grant(
                "age-bracket",
                "service-path-selection",
                vec![("subject", "person-reference-v1")],
            ));
            grants.push(authority_grant(
                "immunization-summary",
                "care-coordination",
                vec![("subject", "person-reference-v1")],
            ));
            grants.push(authority_grant(
                "parent-relationship",
                "relationship-check",
                vec![
                    ("child", "child-reference-v1"),
                    ("candidate-parent", "candidate-reference-v1"),
                ],
            ));
        });
    }

    fn package(&self, evidence: &Path) -> Output {
        let output = evidencectl()
            .arg("package")
            .arg(&self.project)
            .arg("--target")
            .arg(self.target.join("target.yaml"))
            .arg("--output")
            .arg(&self.candidate)
            .env("EVIDENCE_BIN", evidence)
            .output()
            .expect("package starts");
        assert_success(output, "production package")
    }

    fn activate_candidate_bundle(&self) {
        let deployed = self.root.join("activated/bundle");
        copy_tree(&self.candidate.join("bundle"), &deployed);
    }

    fn activate_target_authority(&self, evidence: &Path) {
        assert_success(
            Command::new(evidence)
                .args(["authority", "activate", "--runtime-config"])
                .arg(&self.target_runtime)
                .arg("--document")
                .arg(self.candidate.join("compiled-authority.yaml"))
                .output()
                .expect("target authority activation starts"),
            "target authority activation",
        );
    }

    fn provision_target_secrets(&self) {
        fs::create_dir(self.audit_path.parent().expect("audit directory"))
            .expect("audit directory");
        fs::set_permissions(
            self.audit_path.parent().expect("audit directory"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("audit directory mode");
        for name in ["audit-hmac-key", "subject-binding-hmac-key"] {
            assert_success(
                evidencectl()
                    .args(["keygen", "secret", "--output"])
                    .arg(self.secrets.join(name))
                    .output()
                    .expect("HMAC keygen starts"),
                "independent HMAC generation",
            );
        }
        assert_success(
            evidencectl()
                .args(["keygen", "token", "--output"])
                .arg(&self.source_token)
                .output()
                .expect("source token keygen starts"),
            "independent source credential generation",
        );
        assert_success(
            evidencectl()
                .args(["jwks", "--output"])
                .arg(&self.evidence_jwks)
                .arg(self.active_evidence_public_jwk())
                .output()
                .expect("Evidence JWKS assembly starts"),
            "trusted Evidence JWKS assembly",
        );
    }

    fn active_evidence_public_jwk(&self) -> PathBuf {
        let bundle: Value = serde_norway::from_slice(
            &fs::read(self.candidate.join("bundle/evidence.yaml")).expect("candidate bundle"),
        )
        .expect("candidate bundle parses");
        self.candidate.join("bundle").join(
            bundle["signing"]["activePublicJwkFile"]
                .as_str()
                .expect("active public JWK file"),
        )
    }

    fn evidence_signing_kid(&self) -> String {
        let public: Value = serde_json::from_slice(
            &fs::read(self.active_evidence_public_jwk()).expect("active Evidence public JWK"),
        )
        .expect("active Evidence public JWK parses");
        public["kid"]
            .as_str()
            .expect("active Evidence signing kid")
            .to_owned()
    }

    fn assert_compose_package_identity(&self, evidence: &Path, digest: &str) {
        assert_eq!(
            check_package(evidence, &self.target_runtime, "host runtime check"),
            digest
        );

        let compose = self.root.join("compose-adapter");
        fs::create_dir(&compose).expect("Compose adapter directory");
        let runtime = compose.join("runtime.yaml");
        fs::write(
            &runtime,
            format!(
                "apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1\nkind: EvidenceRuntimeConfig\npackage:\n  root: {bundle}\nlistener:\n  bind: 127.0.0.1:{port}\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 131072\n  maximumConcurrentRequests: 32\n  requestTimeoutMilliseconds: 15000\n  shutdownGraceMilliseconds: 10000\nsecretProviders:\n  file:\n    root: {secrets}\nsigner:\n  type: transit\n  unixSocketPath: {transit_socket}\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 1\n  attemptTimeoutMilliseconds: 2000\naudit:\n  path: {audit}\nauthority:\n  root: {authority_root}\n  target: production\noutboundTls:\n  systemRoots: true\n  trustProfiles: {{}}\n",
                // This absolute host path stands for the unchanged read-only
                // candidate package mount in the container execution context.
                bundle = self.candidate.join("bundle").display(),
                port = free_port(),
                secrets = self.secrets.display(),
                transit_socket = self.root.join("transit-proxy.sock").display(),
                audit = compose.join("persistent-audit/evidence.jsonl").display(),
                authority_root = self.target.join(".generated/authority").display(),
            ),
        )
        .expect("Compose runtime");
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o400))
            .expect("seal Compose runtime");

        let unchanged_package = snapshot_files(&self.candidate);
        let compose_digest = check_package(evidence, &runtime, "Compose-context runtime check");
        assert_eq!(
            snapshot_files(&self.candidate),
            unchanged_package,
            "the Compose adapter must not edit the governed package"
        );
        assert_eq!(compose_digest, digest);
    }

    fn start_https(&self) -> Child {
        Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/production_handoff_https.py"),
            )
            .env("ACCEPTANCE_HTTPS_PORT", self.https_port.to_string())
            .env("ACCEPTANCE_TLS_CERT", &self.tls_cert)
            .env("ACCEPTANCE_TLS_KEY", &self.tls_key)
            .env("ACCEPTANCE_JWKS", &self.oidc_jwks)
            .env("ACCEPTANCE_SOURCE_TOKEN", &self.source_token)
            .env("ACCEPTANCE_SOURCE_MARKER", &self.source_marker)
            .env("ACCEPTANCE_READY", &self.https_ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("local HTTPS process starts")
    }

    fn wait_for_https(&self, child: &mut Child) {
        wait_for(Duration::from_secs(10), || {
            assert_running(child, "local HTTPS");
            self.https_ready.is_file()
        });
    }

    fn start_evidence(&self, evidence: &Path) -> Child {
        let log = owner_only_log(&self.root.join("evidence.log"));
        Command::new(evidence)
            .arg("serve")
            .arg("--runtime-config")
            .arg(self.target_runtime.clone())
            .env("SSL_CERT_FILE", &self.ca)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone Evidence log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("Evidence service starts")
    }

    fn wait_for_evidence(&self, child: &mut Child) {
        wait_for(Duration::from_secs(20), || {
            assert_running(child, "Evidence");
            http_status(self.evidence_port, "/ready") == Some(200)
        });
    }

    fn access_token(&self) -> String {
        let private: Value = serde_json::from_slice(
            &fs::read(&self.oidc_private).expect("read external OIDC private JWK"),
        )
        .expect("external OIDC private JWK parses");
        let secret = URL_SAFE_NO_PAD
            .decode(private["d"].as_str().expect("private JWK d"))
            .expect("private JWK d decodes");
        let key = SigningKey::from_slice(&secret).expect("P-256 signing scalar");
        let kid = private["kid"].as_str().expect("private JWK kid");
        let identity = format!("https://127.0.0.1:{}", self.https_port);
        let now = Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"alg":"ES256","kid":kid,"typ":"at+jwt"}))
                .expect("JWT header"),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": identity,
                "aud": TOKEN_AUDIENCE,
                "sub": "synthetic-caller",
                "iat": now - 1,
                "exp": now + 299,
                "registry_actor_kind": "service",
                "evidence_tags": ["fixture-agency"],
                "evidence_audience": EVIDENCE_AUDIENCE,
            }))
            .expect("JWT claims"),
        );
        let input = format!("{header}.{claims}");
        let signature: Signature = key.sign(input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{input}.{signature}")
    }

    fn write_verification_policy(&self, payload: &Value, nonce: &str, revision: &str) {
        let binding = payload["subjects"][0]["binding"]
            .as_str()
            .expect("accepted transaction subject binding");
        let policy = json!({
            "apiVersion": "id.registrystack.org/formats/evidence/verification-policy/v1",
            "kind": "EvidenceVerificationPolicy",
            "expectedAssuranceProfile": "production",
            "issuedBy": "urn:example:issuers:evidence",
            "providedBy": "urn:example:providers:evidence",
            "requirement": REQUIREMENT,
            "evidenceType": EVIDENCE_TYPE,
            "purpose": PURPOSE,
            "audience": EVIDENCE_AUDIENCE,
            "configurationRevision": revision,
            "requestNonce": nonce,
            // A relying party retains this opaque binding from the accepted
            // first transaction. Every other expectation is independently
            // controlled by the target and retained request in this fixture.
            "expectedSubjects": [{"role":"subject","binding":binding}],
            "expectedOutputs": [{"handle":"adult","concept":CONCEPT,"required":true,"form":{"type":"boolean"}}],
            "revokedKeyIds": [],
            "maximumAssertionLifetimeSeconds": 86400,
            "clockSkewSeconds": 30,
        });
        fs::write(
            &self.policy,
            serde_norway::to_string(&policy).expect("policy YAML"),
        )
        .expect("verification policy");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for path in [&self.candidate, &self.first_candidate] {
            let _ = make_tree_writable(path);
        }
        let _ = &self.temporary;
    }
}

fn serve_transit_request(root: &Path, stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("synthetic Transit read timeout");
    let response = read_transit_request(stream).and_then(|(method, path, body)| {
        if method == "GET" {
            let key_name = path
                .strip_prefix("/v1/transit/keys/")
                .ok_or("unsupported Transit metadata path")?;
            transit_metadata(root, key_name)
        } else if method == "POST" {
            let key_name = path
                .strip_prefix("/v1/transit/sign/")
                .and_then(|path| path.strip_suffix("/sha2-256"))
                .ok_or("unsupported Transit signing path")?;
            transit_signature(root, key_name, &body)
        } else {
            Err("unsupported Transit method")
        }
    });
    let (status, document) = match response {
        Ok(document) => (200, document),
        Err(message) => (400, json!({"errors": [message]})),
    };
    let bytes = serde_json::to_vec(&document).expect("synthetic Transit response JSON");
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )
    .expect("synthetic Transit response headers");
    stream
        .write_all(&bytes)
        .expect("synthetic Transit response body");
}

fn read_transit_request(
    stream: &mut UnixStream,
) -> Result<(String, String, Vec<u8>), &'static str> {
    let mut request = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "Transit request could not be read")?;
        if read == 0 {
            return Err("Transit request ended before its headers");
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > 128 * 1024 {
            return Err("Transit request exceeded the fixture bound");
        }
        if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&request[..header_end])
        .map_err(|_| "Transit request headers were not UTF-8")?;
    let mut lines = headers.lines();
    let mut request_line = lines
        .next()
        .ok_or("Transit request line was missing")?
        .split_whitespace();
    let method = request_line
        .next()
        .ok_or("Transit request method was missing")?
        .to_owned();
    let path = request_line
        .next()
        .ok_or("Transit request path was missing")?
        .to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|_| "Transit content length was invalid")?
        .unwrap_or(0);
    if content_length > 64 * 1024 {
        return Err("Transit request body exceeded the fixture bound");
    }
    while request.len() < header_end + content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "Transit request body could not be read")?;
        if read == 0 {
            return Err("Transit request ended before its body");
        }
        request.extend_from_slice(&chunk[..read]);
    }
    Ok((
        method,
        path,
        request[header_end..header_end + content_length].to_vec(),
    ))
}

fn transit_metadata(root: &Path, key_name: &str) -> Result<Value, &'static str> {
    let private = transit_private_jwk(root, key_name)?;
    let public_key = transit_public_pem(&private)?;
    Ok(json!({
        "data": {
            "type": "ecdsa-p256",
            "derived": false,
            "exportable": false,
            "allow_plaintext_backup": false,
            "supports_signing": true,
            "latest_version": 1,
            "min_encryption_version": 1,
            "keys": {"1": {"public_key": public_key}}
        }
    }))
}

fn transit_signature(root: &Path, key_name: &str, body: &[u8]) -> Result<Value, &'static str> {
    let private = transit_private_jwk(root, key_name)?;
    let request: Value =
        serde_json::from_slice(body).map_err(|_| "Transit signing JSON invalid")?;
    if request["key_version"] != 1
        || request["marshaling_algorithm"] != "jws"
        || request["prehashed"] != true
    {
        return Err("Transit signing contract invalid");
    }
    let digest = request["input"]
        .as_str()
        .ok_or("Transit signing input missing")
        .and_then(|input| {
            STANDARD
                .decode(input)
                .map_err(|_| "Transit signing input invalid")
        })?;
    if digest.len() != 32 {
        return Err("Transit signing digest invalid");
    }
    let secret = private["d"]
        .as_str()
        .ok_or("Transit private JWK scalar missing")
        .and_then(|value| {
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| "Transit private JWK scalar invalid")
        })?;
    let key = SigningKey::from_slice(&secret).map_err(|_| "Transit private JWK invalid")?;
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|_| "Transit signing failed")?;
    Ok(json!({
        "data": {
            "signature": format!("vault:v1:{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
        }
    }))
}

fn transit_private_jwk(root: &Path, key_name: &str) -> Result<Value, &'static str> {
    let path = match key_name {
        "evidence-signing" => root.join("transit-evidence-key/signing-p256-private-jwk"),
        _ => return Err("unknown Transit key"),
    };
    let bytes = fs::read(path).map_err(|_| "Transit fixture key unavailable")?;
    serde_json::from_slice(&bytes).map_err(|_| "Transit fixture key invalid")
}

fn transit_public_pem(private: &Value) -> Result<String, &'static str> {
    let x = private["x"]
        .as_str()
        .ok_or("Transit public JWK x missing")
        .and_then(|value| {
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| "Transit public JWK x invalid")
        })?;
    let y = private["y"]
        .as_str()
        .ok_or("Transit public JWK y missing")
        .and_then(|value| {
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| "Transit public JWK y invalid")
        })?;
    if x.len() != 32 || y.len() != 32 {
        return Err("Transit public JWK coordinate invalid");
    }
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    spki.extend_from_slice(&x);
    spki.extend_from_slice(&y);
    let encoded = STANDARD.encode(spki);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"
    ))
}

fn read_json_document(path: &Path) -> Value {
    serde_norway::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn write_json_document(path: &Path, document: &Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("create {}: {error}", parent.display()));
    }
    let mut bytes = serde_json::to_vec_pretty(document).expect("serialize synthetic document");
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}

fn edit_json_document(path: &Path, edit: impl FnOnce(&mut Value)) {
    let mut document = read_json_document(path);
    edit(&mut document);
    write_json_document(path, &document);
}

struct AssertionDefinitionInput<'a> {
    question: &'a str,
    requirement: &'a str,
    kind: &'a str,
    evidence_type: &'a str,
    purpose: &'a str,
    source: &'a str,
    derive: &'a str,
    output: &'a str,
    concept: &'a str,
    output_constraints: Value,
    subjects: Vec<(&'a str, &'a str)>,
    fixture: &'a str,
}

fn assertion_definition(input: AssertionDefinitionInput<'_>) -> Value {
    let AssertionDefinitionInput {
        question,
        requirement,
        kind,
        evidence_type,
        purpose,
        source,
        derive,
        output,
        concept,
        output_constraints,
        subjects,
        fixture,
    } = input;
    let mut governed_output = json!({"concept": concept});
    governed_output
        .as_object_mut()
        .expect("output object")
        .extend(
            output_constraints
                .as_object()
                .expect("output constraints")
                .clone(),
        );
    json!({
        "question":question,
        "semantics":{
            "requirement":requirement,
            "kind":kind,
            "evidenceType":evidence_type,
            "referenceFrameworks":["urn:example:frameworks:production-handoff:v1"]
        },
        "purpose":purpose,
        "grantCeiling":{
            "authorities":["statutory"],
            "actorKinds":["service"],
            "valueOrigins":["request"],
            "audiences":[EVIDENCE_AUDIENCE]
        },
        "subjects":subjects.iter().map(|(role, profile)| {
            json!({"role":role, "selectors":[profile]})
        }).collect::<Vec<_>>(),
        "acquisition":{"type":"single", "source":source},
        "derive":{"function":derive},
        "outputs":{output:governed_output},
        "validitySeconds":300,
        "subjectBinding":"audience-scoped",
        "representations":["signed-jws"],
        "observationTimezone":"Asia/Bangkok",
        "fixtures":fixture,
        "disclosureGuard":{"families":[format!("{requirement}:release")]},
        "existenceDisclosure":"collapse-unresolved"
    })
}

fn http_source(
    path: &str,
    prepare: &str,
    extract: &str,
    fact_name: &str,
    fact_shape: Value,
    subjects: Vec<(&str, &str)>,
) -> Value {
    let requested_fields = vec![fact_name];
    let mut response_properties = serde_json::Map::new();
    response_properties.insert(
        "total".to_owned(),
        json!({"type":"bounded-integer", "minimum":0, "maximum":1_000_000}),
    );
    response_properties.insert(fact_name.to_owned(), fact_shape.clone());
    let mut facts = serde_json::Map::new();
    facts.insert(fact_name.to_owned(), fact_shape);
    json!({
        "type":"http-json",
        "connection":"people",
        "acquisitionPosture":"field-projected",
        "selectors":subjects.iter().map(|(role, profile)| {
            json!({"role":role, "profiles":[profile]})
        }).collect::<Vec<_>>(),
        "request":{
            "method":"POST",
            "path":path,
            "fixedHeaders":[{"name":"Accept", "value":"application/json"}]
        },
        "prepare":{"function":prepare},
        "adapterParameters":{"requestedFields":requested_fields, "resultLimit":2},
        "adapterParametersSchema":{
            "type":"object",
            "additionalProperties":false,
            "required":["requestedFields", "resultLimit"],
            "properties":{
                "requestedFields":{"const":requested_fields},
                "resultLimit":{"const":2}
            }
        },
        "preparationLimits":{
            "query":"forbidden",
            "jsonBody":"required",
            "maximumJsonDepth":8,
            "maximumCollectionItems":16,
            "maximumStringBytes":256,
            "maximumNormalizedBytes":4096
        },
        "response":{
            "projection":["/total", format!("/{fact_name}")],
            "shape":{
                "type":"object",
                "additionalProperties":false,
                "required":["total"],
                "properties":response_properties
            },
            "maximumBytes":65536
        },
        "extract":{"function":extract},
        "facts":facts,
        "limits":{"attemptTimeoutMilliseconds":3000, "maximumConcurrency":8}
    })
}

fn authority_grant(definition: &str, purpose: &str, subjects: Vec<(&str, &str)>) -> Value {
    json!({
        "definition":definition,
        "purpose":purpose,
        "audienceFrom":"authenticated-requester",
        "representations":["signed-jws"],
        "subjectBinding":"audience-scoped",
        "subjects":subjects.iter().map(|(role, profile)| {
            json!({"role":role, "selectorProfile":profile, "valueOrigin":"request"})
        }).collect::<Vec<_>>()
    })
}

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn assert_success(output: Output, label: &str) -> Output {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn package_digest(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Package digest: "))
        .filter(|revision| {
            revision.len() == 71
                && revision.starts_with("sha256:")
                && revision[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .expect("build reports one package digest")
        .to_owned()
}

fn assert_requirement_forms(
    requirements: &BTreeMap<&str, &Value>,
    requirement_id: &str,
    expected_forms: &[&str],
    expected_subject_roles: usize,
) {
    let requirement = requirements
        .get(requirement_id)
        .unwrap_or_else(|| panic!("missing compiled requirement {requirement_id}"));
    let forms = requirement["concepts"]
        .as_array()
        .expect("compiled concepts")
        .iter()
        .map(|concept| concept["type"].as_str().expect("compiled concept form"))
        .collect::<Vec<_>>();
    assert_eq!(forms, expected_forms);
    assert_eq!(
        requirement["subjectRoles"]
            .as_array()
            .expect("compiled subject roles")
            .len(),
        expected_subject_roles
    );
}

fn check_package(evidence: &Path, runtime: &Path, label: &str) -> String {
    let output = assert_success(
        Command::new(evidence)
            .arg("check")
            .arg("--runtime-config")
            .arg(runtime)
            .output()
            .expect("Evidence check starts"),
        label,
    );
    let stdout = String::from_utf8(output.stdout).expect("Evidence check stdout");
    let fields = stdout
        .lines()
        .find(|line| line.starts_with("Evidence package "))
        .expect("Evidence check report")
        .split_whitespace()
        .collect::<Vec<_>>();
    fields.get(2).expect("package digest").to_string()
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("create {}: {error}", destination.display()));
    let mut entries = fs::read_dir(source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()))
        .map(|entry| entry.expect("bundle entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for source_path in entries {
        let destination_path = destination.join(source_path.file_name().expect("bundle file name"));
        if source_path.is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        }
    }
    fs::set_permissions(
        destination,
        fs::metadata(source).expect("bundle metadata").permissions(),
    )
    .expect("copy bundle directory mode");
}

fn snapshot_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(path)
            .expect("candidate directory")
            .map(|entry| entry.expect("candidate entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        for entry in entries {
            let metadata = fs::symlink_metadata(&entry).expect("candidate metadata");
            assert!(
                !metadata.file_type().is_symlink(),
                "candidate contains symlink"
            );
            if metadata.is_dir() {
                visit(root, &entry, snapshot);
            } else {
                snapshot.insert(
                    entry
                        .strip_prefix(root)
                        .expect("candidate-relative path")
                        .to_owned(),
                    fs::read(entry).expect("candidate file"),
                );
            }
        }
    }
    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("reserved address")
        .port()
}

fn free_ports(count: usize) -> Vec<u16> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("reserve distinct port"))
        .collect::<Vec<_>>();
    listeners
        .iter()
        .map(|listener| listener.local_addr().expect("reserved address").port())
        .collect()
}

fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("condition did not become true before the acceptance timeout");
}

fn assert_running(child: &mut Child, label: &str) {
    if let Some(status) = child.try_wait().expect("child status") {
        panic!("{label} exited before readiness with {status}");
    }
}

fn http_status(port: u16, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn post_evidence(port: u16, token: &str, nonce: &str) -> (u16, Vec<u8>) {
    let body = serde_json::to_vec(&json!({
        "requestNonce": nonce,
        "requirement": REQUIREMENT,
        "purpose": PURPOSE,
        "subjects": [{
            "role": "subject",
            "selector": {
                "profile": "person-reference-v1",
                "values": {"person-id": SELECTOR_CANARY},
            },
        }],
    }))
    .expect("request JSON");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("Evidence connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("request timeout");
    write!(
        stream,
        "POST /v1/evidence HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/jose+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("request headers");
    stream.write_all(&body).expect("request body");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("response bytes");
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response separator");
    let headers = std::str::from_utf8(&response[..separator]).expect("HTTP response headers");
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .expect("HTTP response status");
    (status, response[separator + 4..].to_vec())
}

/// The configuration revision discovery publishes for the fixture requirement.
///
/// It is requirement scoped, so it is not the deployment's package digest.
/// Reading it from discovery keeps the assertion check independent of the
/// signed payload it is compared against.
fn published_configuration_revision(port: u16, token: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("Evidence connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("request timeout");
    write!(
        stream,
        "GET /v1/evidence-definitions HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .expect("discovery request headers");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("response bytes");
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response separator");
    let document: Value =
        serde_json::from_slice(&response[separator + 4..]).expect("discovery document JSON");
    let definitions = document["definitions"]
        .as_array()
        .expect("discovery publishes definitions");
    let revision = definitions
        .iter()
        .find(|definition| definition["requirement"] == REQUIREMENT)
        .and_then(|definition| definition["configurationRevision"].as_str())
        .expect("the fixture requirement publishes its own configuration revision")
        .to_owned();
    assert!(revision.starts_with("sha256:") && revision.len() == 71);
    revision
}

fn signed_payload(response: &[u8]) -> Value {
    let jws: Value = serde_json::from_slice(response).expect("flattened JWS response");
    let encoded = jws["payload"].as_str().expect("flattened JWS payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).expect("payload decodes"))
        .expect("Evidence payload JSON")
}

fn wait_for_audit(path: &Path) -> String {
    let mut result = None;
    wait_for(Duration::from_secs(10), || {
        let Ok(contents) = fs::read_to_string(path) else {
            return false;
        };
        if contents.matches("\"phase\":\"access-attempt\"").count() == 1
            && contents.matches("\"phase\":\"disclosure-release\"").count() == 1
        {
            result = Some(contents);
            true
        } else {
            false
        }
    });
    result.expect("the complete operation audit")
}

fn assert_audit_contract(audit: &str, revision: &str, signing_key_id: &str, credentials: &[&[u8]]) {
    let records = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit JSONL"))
        .collect::<Vec<_>>();
    assert_eq!(
        records.len(),
        2,
        "one request must write exactly two events"
    );
    assert_eq!(records[0]["schema"], "registry.evidence.audit/v2");
    assert_eq!(records[0]["phase"], "request");
    assert_eq!(records[1]["schema"], "registry.evidence.audit/v2");
    assert_eq!(records[1]["phase"], "response");
    assert_eq!(records[0]["correlation"], records[0]["record"]["operation"]);
    assert_eq!(records[1]["correlation"], records[1]["record"]["operation"]);
    assert_eq!(records[0]["record"]["phase"], "access-attempt");
    assert_eq!(records[0]["record"]["decision"], "authorized");
    assert_eq!(records[1]["record"]["phase"], "disclosure-release");
    assert_eq!(records[1]["record"]["decision"], "released");
    assert_eq!(records[1]["record"]["signingKeyId"], signing_key_id);
    for record in &records {
        assert_eq!(record["record"]["bundleRevision"], revision);
        assert_eq!(record["record"]["assuranceProfile"], "production");
    }
    let bytes = audit.as_bytes();
    for prohibited in [
        SELECTOR_CANARY.as_bytes(),
        b"date_of_birth".as_slice(),
        b"synthetic-caller".as_slice(),
    ] {
        assert!(
            !bytes
                .windows(prohibited.len())
                .any(|part| part == prohibited),
            "audit retained protected request, source, principal, or credential data"
        );
    }
    for credential in credentials {
        assert!(
            !bytes
                .windows(credential.len())
                .any(|part| part == *credential),
            "audit retained an access token or source credential"
        );
    }
}

fn stop_gracefully(child: &mut Child, label: &str) {
    let pid =
        rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("child PID fits i32"))
            .expect("child PID is positive");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("send SIGTERM");
    let status = child.wait().expect("child exits");
    assert!(status.success(), "{label} did not stop cleanly: {status}");
}

fn stop_forcefully(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn owner_only_log(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create owner-only log")
}

fn make_tree_writable(path: &Path) -> std::io::Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            make_tree_writable(&entry?.path())?;
        }
    } else if metadata.is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn evidence_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        if let Some(path) = std::env::var_os("EVIDENCE_BIN") {
            return PathBuf::from(path);
        }
        let build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(workspace_root())
            .args([
                "build",
                "--locked",
                "-p",
                "registry-evidence",
                "--bin",
                "evidence",
                "--profile",
                &current_test_profile(),
                "--message-format",
                "json-render-diagnostics",
            ])
            .output()
            .expect("building the Evidence binary");
        assert!(
            build.status.success(),
            "building the Evidence binary failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        String::from_utf8_lossy(&build.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .filter_map(|message| message["executable"].as_str().map(PathBuf::from))
            .find(|path| path.file_name().is_some_and(|name| name == "evidence"))
            .expect("Evidence executable path")
    })
}

fn installed_binary(variable: &str, name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(variable) {
        return PathBuf::from(path);
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("set {variable} for this exact lifecycle gate"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn current_test_profile() -> String {
    let executable = std::env::current_exe().expect("test executable");
    let profile = executable
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .expect("test profile");
    if profile == "debug" {
        "dev".to_owned()
    } else {
        profile.to_owned()
    }
}
