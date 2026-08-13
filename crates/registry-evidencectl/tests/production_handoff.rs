#![cfg(unix)]

//! Exact production-candidate handoff through the real adopter and runtime
//! binaries. The gate is ignored in the ordinary package suite because it
//! starts two services and requires `python3` and `openssl` on the host.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
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
#[ignore = "exact gate: starts real binaries plus local HTTPS issuer and source"]
fn production_candidate_handoff_reaches_verified_assertion_and_audit() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_https_identity();
    fixture.stage_target();

    let first = fixture.build(evidence);
    let first_revision = bundle_revision(&first);
    let first_bytes = snapshot_files(&fixture.candidate);
    fs::rename(&fixture.candidate, &fixture.first_candidate)
        .expect("archive the first create-only candidate");

    let second = fixture.build(evidence);
    let revision = bundle_revision(&second);
    assert_eq!(
        revision, first_revision,
        "bundle revision must be repeatable"
    );
    assert_eq!(
        snapshot_files(&fixture.candidate),
        first_bytes,
        "identical inputs and output binding must reproduce every candidate file byte"
    );
    assert_eq!(
        fs::read(&fixture.target_runtime).expect("target runtime"),
        fs::read(fixture.candidate.join("runtime.yaml")).expect("copied runtime"),
        "the target runtime must be copied byte-for-byte"
    );

    fixture.provision_target_secrets();
    assert_success(
        evidencectl()
            .args(["doctor", "--project"])
            .arg(&fixture.candidate)
            .output()
            .expect("doctor starts"),
        "target-host doctor",
    );
    assert_success(
        evidencectl()
            .args(["fixtures", "run", "--project"])
            .arg(&fixture.candidate)
            .arg("--evidence-bin")
            .arg(evidence)
            .output()
            .expect("fixture driver starts"),
        "target-host fixtures",
    );
    fixture.assert_compose_revision_distinction(evidence, &revision);

    let mut https = fixture.start_https();
    fixture.wait_for_https(&mut https);
    let mut service = fixture.start_evidence(evidence);
    fixture.wait_for_evidence(&mut service);

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
    assert_success(
        Command::new(evidence)
            .arg("--runtime")
            .arg(fixture.candidate.join("runtime.yaml"))
            .arg("verify-audit")
            .output()
            .expect("audit verifier starts"),
        "complete audit-chain verification",
    );
}

#[test]
#[ignore = "exact gate: starts real Mint and Evidence plus local HTTPS routing"]
fn production_candidate_accepts_a_token_from_an_independent_real_mint() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    let mint = mint_binary();
    fixture.stage_authoring_project();
    fixture.stage_https_identity();
    fixture.stage_target();
    let build = fixture.build(evidence);
    let revision = bundle_revision(&build);
    fixture.provision_target_secrets();
    let mint_deployment = fixture.stage_mint();

    assert_success(
        Command::new(mint)
            .args(["check", "--config"])
            .arg(&mint_deployment.config)
            .output()
            .expect("Mint check starts"),
        "real Mint deployment check",
    );
    assert_success(
        evidencectl()
            .args(["doctor", "--project"])
            .arg(&fixture.candidate)
            .arg("--mint-config")
            .arg(&mint_deployment.config)
            .output()
            .expect("paired doctor starts"),
        "paired Evidence and Mint doctor",
    );

    let mut https = fixture.start_https();
    fixture.wait_for_https(&mut https);
    let mut mint_service = fixture.start_mint(mint, &mint_deployment.config);
    wait_for_listener(&mut mint_service, fixture.mint_port, "Mint");
    let mut evidence_service = fixture.start_evidence(evidence);
    fixture.wait_for_evidence(&mut evidence_service);

    let public_token_endpoint = format!("https://127.0.0.1:{}/token", fixture.https_port);
    let token_output = Command::new(mint)
        .arg("token")
        .arg("--url")
        .arg(&public_token_endpoint)
        .arg("--audience")
        .arg(public_token_endpoint)
        .args(["--client-id", "acceptance-client", "--key"])
        .arg(&mint_deployment.caller_private)
        .arg("--ca-certificate")
        .arg(&fixture.ca)
        .output()
        .expect("Mint token starts");
    assert!(
        token_output.status.success(),
        "Mint token failed without printing a token: {}",
        String::from_utf8_lossy(&token_output.stderr)
    );
    let token = String::from_utf8(token_output.stdout).expect("Mint token stdout");
    assert_eq!(
        token.lines().count(),
        1,
        "Mint prints exactly one token line"
    );
    let token = token.trim();

    let published_revision = published_configuration_revision(fixture.evidence_port, token);
    let nonce = URL_SAFE_NO_PAD.encode([0x24_u8; 32]);
    let (status, response) = post_evidence(fixture.evidence_port, token, &nonce);
    assert_eq!(status, 200, "a real Mint token must authorize Evidence");
    fs::write(&fixture.response, &response).expect("retain Mint-backed response");
    fs::set_permissions(&fixture.response, fs::Permissions::from_mode(0o600))
        .expect("protect Mint-backed response");
    let payload = signed_payload(&response);
    assert_eq!(payload["assuranceProfile"], "production");
    assert_eq!(payload["configurationRevision"], published_revision);
    assert_eq!(payload["supportedValues"][0]["providesValueFor"], CONCEPT);
    assert_eq!(payload["supportedValues"][0]["value"], true);
    assert!(
        !serde_json::to_vec(&payload)
            .expect("Mint-backed payload serializes")
            .windows(token.len())
            .any(|part| part == token.as_bytes()),
        "signed payload retained the Mint access token"
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
            .expect("Mint-backed response verifier starts"),
        "Mint-backed independent response verification",
    );
    let source_token = fs::read(&fixture.source_token).expect("source token");
    assert_audit_contract(
        &wait_for_audit(&fixture.audit_path),
        &revision,
        &fixture.evidence_signing_kid(),
        &[source_token.as_slice(), token.as_bytes()],
    );

    stop_gracefully(&mut evidence_service, "Evidence");
    stop_gracefully(&mut mint_service, "Mint");
    stop_forcefully(&mut https);
    assert_success(
        Command::new(evidence)
            .arg("--runtime")
            .arg(fixture.candidate.join("runtime.yaml"))
            .arg("verify-audit")
            .output()
            .expect("Mint-backed audit verifier starts"),
        "Mint-backed complete audit-chain verification",
    );
}

#[test]
#[ignore = "exact gate: runs the real production builder and sibling Evidence bundle check"]
fn production_build_accepts_the_real_bundle_check_revision() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_four_shape_project();
    fixture.stage_target();
    fixture.authorize_four_shapes();

    let output = fixture.build(evidence);
    let revision = bundle_revision(&output);
    assert!(revision.starts_with("sha256:"));
    assert!(fixture.candidate.join("bundle/evidence.yaml").is_file());
}

#[test]
#[ignore = "exact gate: runs the real production builder across all four authoring shapes"]
fn production_build_checks_and_evaluates_every_neutral_authoring_shape() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    fixture.stage_authoring_project();
    fixture.stage_four_shape_project();
    fixture.stage_target();
    fixture.authorize_four_shapes();

    let output = fixture.build(evidence);
    let revision = bundle_revision(&output);
    fixture.provision_target_secrets();
    let (checked_revision, _) = check_revisions(
        evidence,
        &fixture.candidate.join("runtime.yaml"),
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
                requirement["id"]
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
        &["boolean", "bounded-integer"],
        1,
    );
    assert_requirement_forms(&requirements, RELATIONSHIP_REQUIREMENT, &["boolean"], 2);
    assert_eq!(requirements[REQUIREMENT]["handle"], "adult-status");
    assert_eq!(
        requirements[REQUIREMENT]["concepts"][0]["handle"],
        "is_adult"
    );
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
#[ignore = "exact gate: starts and stops real local Evidence and Mint before production build"]
fn public_lifecycle_keeps_local_dev_state_out_of_the_production_candidate() {
    let fixture = Fixture::new();
    let evidence = evidence_binary();
    let mint = mint_binary();
    let retained_openapi = fixture.root.join("lifecycle.openapi.yaml");
    fs::write(
        &retained_openapi,
        "openapi: 3.1.0\ninfo: {title: Lifecycle source, version: 1.0.0}\npaths: {}\n",
    )
    .expect("lifecycle OpenAPI");

    assert_success(
        evidencectl()
            .arg("new")
            .arg(&fixture.project)
            .arg("--openapi")
            .arg(&retained_openapi)
            .args(["--profile", "local", "--generate-keys"])
            .output()
            .expect("public new starts"),
        "public new",
    );
    assert!(!fixture.project.join(".evidence").exists());
    fixture.stage_local_project_without_governance();
    assert_success(
        evidencectl()
            .args(["keygen", "token", "--out"])
            .arg(fixture.project.join("secrets/source-token"))
            .output()
            .expect("local source token keygen starts"),
        "local source token keygen",
    );

    let started = assert_success(
        evidencectl()
            .args(["dev", "--detach", "--project"])
            .arg(&fixture.project)
            .arg("--evidence-bin")
            .arg(evidence)
            .arg("--mint-bin")
            .arg(mint)
            .args(["--evidence-port", &fixture.evidence_port.to_string()])
            .args(["--mint-port", &fixture.mint_port.to_string()])
            .args(["--ready-timeout-seconds", "20"])
            .output()
            .expect("public dev starts"),
        "public dev with omitted governance",
    );
    let mut stop_guard = DevStopGuard::new(&fixture.project);
    let started_stdout = String::from_utf8(started.stdout).expect("dev stdout");
    assert!(started_stdout.contains(&format!(
        "Evidence ready at http://127.0.0.1:{}",
        fixture.evidence_port
    )));
    assert!(started_stdout.contains(&format!(
        "Mint ready at http://127.0.0.1:{}",
        fixture.mint_port
    )));
    let dev_root = fixture.project.join(".evidence/dev");
    let local_bundle = fs::read(dev_root.join("bundle/evidence.yaml")).expect("local dev bundle");
    assert!(
        local_bundle
            .windows(b"urn:registrystack:evidence:local:".len())
            .any(|part| part == b"urn:registrystack:evidence:local:"),
        "the governance-free dev generation must use disposable local identifiers"
    );
    assert_success(
        evidencectl()
            .args(["dev", "stop", "--project"])
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
    let governed_question = fs::read_to_string(fixture.project.join("questions/adult-status.yaml"))
        .expect("governed question");
    assert!(governed_question.contains(&format!("  requirement: {REQUIREMENT}")));
    assert!(governed_question.contains(&format!("    id: {CONCEPT}")));
    assert!(fixture.project.join("fixtures/adult-status.yaml").is_file());

    let local_source_token =
        fs::read(fixture.project.join("secrets/source-token")).expect("local source token");
    let build = fixture.build(evidence);
    bundle_revision(&build);
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
                .windows(b"urn:registrystack:evidence:local:".len())
                .any(|part| part == b"urn:registrystack:evidence:local:"),
            "production candidate retained a disposable local identifier in {}",
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
        "production candidate must use the newly added stable governance"
    );

    assert_success(
        evidencectl()
            .args(["dev", "clean", "--project"])
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
                .args(["dev", "stop", "--project"])
                .arg(&self.project)
                .output();
        }
    }
}

struct MintDeployment {
    config: PathBuf,
    caller_private: PathBuf,
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
    mint_port: u16,
}

impl Fixture {
    fn new() -> Self {
        // macOS exposes its default temporary root through `/var`, which is a
        // symlink. Production build correctly refuses that ancestry, so keep
        // the exact gate under the workspace's already-created target tree.
        let temporary = tempfile::Builder::new()
            .prefix("production-handoff-")
            .tempdir_in(workspace_root().join("target"))
            .expect("acceptance tempdir");
        let root = temporary.path().to_path_buf();
        let project = root.join("authoring");
        let target = project.join("deployment-targets/production");
        let candidate = root.join("candidate");
        let secrets = root.join("production-secrets");
        let ports = free_ports(3);
        Self {
            target_runtime: target.join("runtime.yaml"),
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
            policy: root.join("verification-policy.yaml"),
            https_port: ports[0],
            evidence_port: ports[1],
            mint_port: ports[2],
            temporary,
            root,
            project,
            target,
            candidate,
            secrets,
        }
    }

    fn stage_authoring_project(&self) {
        let source_origin = format!("https://127.0.0.1:{}", self.https_port);
        let source_files = [
            (
                "selectors/person-reference-v1.yaml",
                "maximumAggregateBytes: 200\nfields:\n  person_id: {type: string, minimumBytes: 1, maximumBytes: 200}\n".to_owned(),
            ),
            (
                "sources/people.yaml",
                format!(
                    r#"transport: http-json
baseUrl: {source_origin}
posture: field-projected
authentication: {{kind: static-authorization, tokenRef: 'secret:file/source-token'}}
request:
  method: POST
  path: /v1/facts
  fixedHeaders: [{{name: Accept, value: application/json}}]
  selectorInputs:
    - role: subject
      alternatives:
        - {{profile: person-reference-v1, fields: [person_id]}}
  prepareScript: adapters/people-prepare.rhai
  adapterParameters: {{requestedFields: [date_of_birth], resultLimit: 2}}
  adapterParametersSchema: schemas/people-parameters.schema.yaml
  preparationLimits: {{query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}}
  projection: [/total, /date_of_birth]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: schemas/people-response.schema.yaml
extractScript: adapters/people-extract.rhai
factSchema: schemas/people-facts.schema.yaml
"#
                ),
            ),
            (
                "adapters/people-prepare.rhai",
                r#"fn prepare(selectors, context) {
    let parameters = context["parameters"];
    #{
        query: [],
        body: #{
            lookup: #{person_id: selectors["subject"]["values"]["person_id"]},
            fields: parameters["requestedFields"],
            limit: parameters["resultLimit"]
        }
    }
}
"#
                .to_owned(),
            ),
            (
                "adapters/people-extract.rhai",
                r#"fn extract(source_response, context) {
    let total = source_response["total"];
    if total == 0 { return #{outcome: "no_match"}; }
    if total > 1 { return #{outcome: "ambiguous"}; }
    let value = get_path(source_response, "/date_of_birth");
    if is_missing(value) { return #{outcome: "match", facts: #{}}; }
    #{outcome: "match", facts: #{date_of_birth: value}}
}
"#
                .to_owned(),
            ),
            (
                "schemas/people-parameters.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [requestedFields, resultLimit]\nproperties:\n  requestedFields: {const: [date_of_birth]}\n  resultLimit: {const: 2}\n".to_owned(),
            ),
            (
                "schemas/people-response.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [total]\nproperties:\n  total: {type: integer, minimum: 0, maximum: 1000000}\n  date_of_birth: {type: string, format: date}\n".to_owned(),
            ),
            (
                "schemas/people-facts.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [date_of_birth]\nproperties:\n  date_of_birth: {type: string, format: date}\n".to_owned(),
            ),
        ]
        .into_iter()
        .map(
            |(path, contents)| registry_evidence_authoring::testing::ProjectFile {
                path: path.to_owned(),
                contents,
            },
        )
        .collect::<Vec<_>>();

        let question = format!(
            r#"id: adult-status
question: Is the person at least 18 years old?
purpose: {PURPOSE}
subject:
  role: subject
  selector: person_id
  profile: person-reference-v1
source:
  ref: people
answers:
  - concept: is_adult
    id: {CONCEPT}
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
governance:
  requirement: {REQUIREMENT}
  kind: criterion
  referenceFrameworks: [urn:example:frameworks:adult-status:v1]
  evidenceType: {EVIDENCE_TYPE}
  validitySeconds: 86400
  observationTimezone: Asia/Bangkok
  fixtures: fixtures/adult-status.yaml
  disclosureFamilies: [urn:example:disclosure-families:adult-status]
"#
        );
        let derivation = r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    #{is_adult: compare_dates(context.legal_local_date, add_calendar_years(born, 18)) >= 0}
}
"#;
        let fixture = format!(
            r#"fixture: registry.evidence.acceptance.production-handoff/v1
coequal_acceptance_definition: true
synthetic_only: true
common:
  observed_at: '2026-08-02T00:00:00Z'
  legal_local_date: '2026-08-02'
  selector: {{person_id: {SELECTOR_CANARY}}}
  selectors:
    subject: {{profile: person-reference-v1, values: {{person_id: {SELECTOR_CANARY}}}}}
  expectedRequestParts:
    query: []
    body: {{lookup: {{person_id: {SELECTOR_CANARY}}}, fields: [date_of_birth], limit: 2}}
  expectedTransport:
    path: /v1/facts
    fixedHeaders: [{{name: Accept, value: application/json}}]
cases:
  - {{id: positive, source: {{total: 1, date_of_birth: '2000-01-01'}}, expected_value: true, expected_lookup: match, derivation_runs: true, signed_success: true}}
  - {{id: negative-false-is-success, source: {{total: 1, date_of_birth: '2010-01-01'}}, expected_value: false, expected_lookup: match, derivation_runs: true, signed_success: true}}
  - {{id: boundary-on, legal_local_date: '2026-08-02', source: {{total: 1, date_of_birth: '2008-08-02'}}, expected_value: true, expected_lookup: match, derivation_runs: true, signed_success: true}}
  - {{id: missing-fact, source: {{total: 1}}, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: no-match, source: {{total: 0}}, expected_lookup: no_match, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: ambiguous, source: {{total: 2}}, expected_lookup: ambiguous, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: source-failure, source_failure: timeout, expected_public_problem: source.unavailable, signed_success: false}}
  - {{id: negative-wrong-derived-type, injected_derivation: [{{concept_id: {CONCEPT}, value: 'true'}}], expected: output-gate-rejection}}
  - {{id: anti-reconstruction, companion_bundle: threshold-ladder, expected: bundle-rejection}}
privacy_expectation:
  evidence_contains: [{CONCEPT}]
  evidence_excludes: [date_of_birth, person_id]
  diagnostics_exclude: [{SELECTOR_CANARY}, fixture-source-canary]
"#
        );

        for file in registry_evidence_authoring::testing::referenced_form_project(
            "openapi: 3.1.0\ninfo: {title: Acceptance source, version: 1.0.0}\npaths: {}\n",
            "adult-status",
            &question,
            derivation,
            Some(&fixture),
            &source_files,
        ) {
            let path = self.project.join(&file.path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("authoring directory");
            }
            fs::write(&path, file.contents).expect("authoring project file");
        }
    }

    fn stage_local_project_without_governance(&self) {
        self.stage_authoring_project();
        let question_path = self.project.join("questions/adult-status.yaml");
        let question = fs::read_to_string(&question_path).expect("governed adult question");
        let governance = question
            .find("governance:\n")
            .expect("adult question governance block");
        let question = question[..governance].replace(&format!("    id: {CONCEPT}\n"), "");
        fs::write(&question_path, question).expect("governance-free local question");
        fs::remove_file(self.project.join("fixtures/adult-status.yaml"))
            .expect("withhold production fixture during local dev");
        assert!(
            !fs::read_to_string(question_path)
                .expect("local question")
                .contains("governance:"),
            "local dev must begin before stable governance exists"
        );
    }

    fn stage_four_shape_project(&self) {
        for (profile, field) in [
            ("child-reference-v1", "child_id"),
            ("candidate-reference-v1", "candidate_id"),
        ] {
            fs::write(
                self.project.join(format!("selectors/{profile}.yaml")),
                format!(
                    "maximumAggregateBytes: 200\nfields:\n  {field}: {{type: string, minimumBytes: 1, maximumBytes: 200}}\n"
                ),
            )
            .expect("role-bound selector");
        }

        let source_origin = format!("https://127.0.0.1:{}", self.https_port);
        fs::write(
            self.project.join("sources/immunizations.yaml"),
            format!(
                r#"transport: http-json
baseUrl: {source_origin}
posture: field-projected
authentication: {{kind: static-authorization, tokenRef: 'secret:file/source-token'}}
request:
  method: POST
  path: /v1/immunizations
  fixedHeaders: [{{name: Accept, value: application/json}}]
  selectorInputs:
    - role: subject
      alternatives:
        - {{profile: person-reference-v1, fields: [person_id]}}
  prepareScript: adapters/immunizations-prepare.rhai
  adapterParameters: {{requestedFields: [dose_count], resultLimit: 2}}
  adapterParametersSchema: schemas/immunizations-parameters.schema.yaml
  preparationLimits: {{query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}}
  projection: [/total, /dose_count]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: schemas/immunizations-response.schema.yaml
extractScript: adapters/immunizations-extract.rhai
factSchema: schemas/immunizations-facts.schema.yaml
"#
            ),
        )
        .expect("immunization source");
        fs::write(
            self.project.join("sources/relationships.yaml"),
            format!(
                r#"transport: http-json
baseUrl: {source_origin}
posture: field-projected
authentication: {{kind: static-authorization, tokenRef: 'secret:file/source-token'}}
request:
  method: POST
  path: /v1/relationships
  fixedHeaders: [{{name: Accept, value: application/json}}]
  selectorInputs:
    - role: child
      alternatives:
        - {{profile: child-reference-v1, fields: [child_id]}}
    - role: candidate-parent
      alternatives:
        - {{profile: candidate-reference-v1, fields: [candidate_id]}}
  prepareScript: adapters/relationships-prepare.rhai
  adapterParameters: {{requestedFields: [relationship_confirmed], resultLimit: 2}}
  adapterParametersSchema: schemas/relationships-parameters.schema.yaml
  preparationLimits: {{query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}}
  projection: [/total, /relationship_confirmed]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: schemas/relationships-response.schema.yaml
extractScript: adapters/relationships-extract.rhai
factSchema: schemas/relationships-facts.schema.yaml
"#
            ),
        )
        .expect("relationship source");

        for (path, contents) in [
            (
                "adapters/immunizations-prepare.rhai",
                r#"fn prepare(selectors, context) {
    let parameters = context["parameters"];
    #{
        query: [],
        body: #{
            lookup: #{person_id: selectors["subject"]["values"]["person_id"]},
            fields: parameters["requestedFields"],
            limit: parameters["resultLimit"]
        }
    }
}
"#,
            ),
            (
                "adapters/immunizations-extract.rhai",
                r#"fn extract(source_response, context) {
    let total = source_response["total"];
    if total == 0 { return #{outcome: "no_match"}; }
    if total > 1 { return #{outcome: "ambiguous"}; }
    let value = get_path(source_response, "/dose_count");
    if is_missing(value) { return #{outcome: "match", facts: #{}}; }
    #{outcome: "match", facts: #{dose_count: value}}
}
"#,
            ),
            (
                "adapters/relationships-prepare.rhai",
                r#"fn prepare(selectors, context) {
    let parameters = context["parameters"];
    #{
        query: [],
        body: #{
            lookup: #{
                child_id: selectors["child"]["values"]["child_id"],
                candidate_id: selectors["candidate-parent"]["values"]["candidate_id"]
            },
            fields: parameters["requestedFields"],
            limit: parameters["resultLimit"]
        }
    }
}
"#,
            ),
            (
                "adapters/relationships-extract.rhai",
                r#"fn extract(source_response, context) {
    let total = source_response["total"];
    if total == 0 { return #{outcome: "no_match"}; }
    if total > 1 { return #{outcome: "ambiguous"}; }
    let value = get_path(source_response, "/relationship_confirmed");
    if is_missing(value) { return #{outcome: "match", facts: #{}}; }
    #{outcome: "match", facts: #{relationship_confirmed: value}}
}
"#,
            ),
            (
                "schemas/immunizations-parameters.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [requestedFields, resultLimit]\nproperties:\n  requestedFields: {const: [dose_count]}\n  resultLimit: {const: 2}\n",
            ),
            (
                "schemas/immunizations-response.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [total]\nproperties:\n  total: {type: integer, minimum: 0, maximum: 1000000}\n  dose_count: {type: integer, minimum: 0, maximum: 20}\n",
            ),
            (
                "schemas/immunizations-facts.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [dose_count]\nproperties:\n  dose_count: {type: integer, minimum: 0, maximum: 20}\n",
            ),
            (
                "schemas/relationships-parameters.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [requestedFields, resultLimit]\nproperties:\n  requestedFields: {const: [relationship_confirmed]}\n  resultLimit: {const: 2}\n",
            ),
            (
                "schemas/relationships-response.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [total]\nproperties:\n  total: {type: integer, minimum: 0, maximum: 1000000}\n  relationship_confirmed: {type: boolean}\n",
            ),
            (
                "schemas/relationships-facts.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [relationship_confirmed]\nproperties:\n  relationship_confirmed: {type: boolean}\n",
            ),
        ] {
            fs::write(self.project.join(path), contents).expect("four-shape source artifact");
        }

        self.stage_four_shape_questions();
        self.stage_four_shape_fixtures();
    }

    fn stage_four_shape_questions(&self) {
        for (path, contents) in [
            (
                "questions/age-bracket.yaml",
                format!(
                    r#"id: age-bracket
question: Which governed age bracket contains this person?
purpose: service-path-selection
subject:
  role: subject
  selector: person_id
  profile: person-reference-v1
source:
  ref: people
answers:
  - concept: age_bracket
    id: {AGE_CONCEPT}
    type: controlled-category
    values: [under-18, 18-to-24, 25-to-64, 65-or-older]
derivation: derivations/age-bracket.rhai
disclosure:
  allow: [age_bracket]
governance:
  requirement: {AGE_REQUIREMENT}
  kind: information-requirement
  referenceFrameworks: [urn:example:frameworks:age-bracket:v1]
  evidenceType: urn:example:evidence-types:age-bracket:v1
  validitySeconds: 86400
  observationTimezone: Asia/Bangkok
  fixtures: fixtures/age-bracket.yaml
  disclosureFamilies: [urn:example:disclosure-families:age-bracket]
"#
                ),
            ),
            (
                "questions/immunization-summary.yaml",
                format!(
                    r#"id: immunization-summary
question: Is the schedule complete, and how many doses are recorded?
purpose: care-coordination
subject:
  role: subject
  selector: person_id
  profile: person-reference-v1
source:
  ref: immunizations
answers:
  - concept: schedule_complete
    id: {SCHEDULE_CONCEPT}
    type: boolean
  - concept: dose_count
    id: {DOSE_COUNT_CONCEPT}
    type: bounded-integer
    minimum: 0
    maximum: 20
derivation: derivations/immunization-summary.rhai
disclosure:
  allow: [schedule_complete, dose_count]
governance:
  requirement: {IMMUNIZATION_REQUIREMENT}
  kind: information-requirement
  referenceFrameworks: [urn:example:frameworks:immunization-summary:v1]
  evidenceType: urn:example:evidence-types:immunization-summary:v1
  validitySeconds: 86400
  observationTimezone: Asia/Bangkok
  fixtures: fixtures/immunization-summary.yaml
  disclosureFamilies: [urn:example:disclosure-families:immunization-summary]
"#
                ),
            ),
            (
                "questions/parent-relationship.yaml",
                format!(
                    r#"id: parent-relationship
question: Is the candidate registered as a parent of the child?
purpose: relationship-check
subjects:
  - role: child
    selector: child_id
    profile: child-reference-v1
  - role: candidate-parent
    selector: candidate_id
    profile: candidate-reference-v1
source:
  ref: relationships
answers:
  - concept: relationship_confirmed
    id: {RELATIONSHIP_CONCEPT}
    type: boolean
derivation: derivations/parent-relationship.rhai
disclosure:
  allow: [relationship_confirmed]
governance:
  requirement: {RELATIONSHIP_REQUIREMENT}
  kind: criterion
  referenceFrameworks: [urn:example:frameworks:parent-relationship:v1]
  evidenceType: urn:example:evidence-types:parent-relationship:v1
  validitySeconds: 86400
  observationTimezone: Asia/Bangkok
  fixtures: fixtures/parent-relationship.yaml
  disclosureFamilies: [urn:example:disclosure-families:parent-relationship]
"#
                ),
            ),
        ] {
            fs::write(self.project.join(path), contents).expect("four-shape question");
        }
        for (path, contents) in [
            (
                "derivations/age-bracket.rhai",
                r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    if compare_dates(context.legal_local_date, add_calendar_years(born, 18)) < 0 {
        #{age_bracket: "under-18"}
    } else if compare_dates(context.legal_local_date, add_calendar_years(born, 25)) < 0 {
        #{age_bracket: "18-to-24"}
    } else if compare_dates(context.legal_local_date, add_calendar_years(born, 65)) < 0 {
        #{age_bracket: "25-to-64"}
    } else {
        #{age_bracket: "65-or-older"}
    }
}
"#,
            ),
            (
                "derivations/immunization-summary.rhai",
                r#"fn answer(facts, selectors, context) {
    let dose_count = required(facts.dose_count, "dose_count_missing");
    #{schedule_complete: dose_count >= 3, dose_count: dose_count}
}
"#,
            ),
            (
                "derivations/parent-relationship.rhai",
                r#"fn answer(facts, selectors, context) {
    #{relationship_confirmed: required(facts.relationship_confirmed, "relationship_missing")}
}
"#,
            ),
        ] {
            fs::write(self.project.join(path), contents).expect("four-shape derivation");
        }
    }

    fn stage_four_shape_fixtures(&self) {
        fs::write(
            self.project.join("fixtures/age-bracket.yaml"),
            format!(
                r#"fixture: registry.evidence.acceptance.production-age-bracket/v1
coequal_acceptance_definition: true
synthetic_only: true
common:
  observed_at: '2026-08-02T00:00:00Z'
  legal_local_date: '2026-08-02'
  selector: {{person_id: {SELECTOR_CANARY}}}
  selectors:
    subject: {{profile: person-reference-v1, values: {{person_id: {SELECTOR_CANARY}}}}}
  expectedRequestParts:
    query: []
    body: {{lookup: {{person_id: {SELECTOR_CANARY}}}, fields: [date_of_birth], limit: 2}}
  expectedTransport:
    path: /v1/facts
    fixedHeaders: [{{name: Accept, value: application/json}}]
cases:
  - {{id: positive, source: {{total: 1, date_of_birth: '2000-01-01'}}, expected_value: 25-to-64, expected_lookup: match, derivation_runs: true, signed_success: true}}
  - {{id: negative-under-18-is-success, source: {{total: 1, date_of_birth: '2010-01-01'}}, expected_value: under-18, expected_lookup: match, derivation_runs: true, signed_success: true}}
  - {{id: boundary-on-18, source: {{total: 1, date_of_birth: '2008-08-02'}}, expected_value: 18-to-24, expected_lookup: match, derivation_runs: true, signed_success: true}}
  - {{id: missing-fact, source: {{total: 1}}, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: no-match, source: {{total: 0}}, expected_lookup: no_match, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: ambiguous, source: {{total: 2}}, expected_lookup: ambiguous, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: source-failure, source_failure: timeout, expected_public_problem: source.unavailable, signed_success: false}}
  - {{id: negative-wrong-derived-type, injected_derivation: [{{concept_id: {AGE_CONCEPT}, value: true}}], expected: output-gate-rejection}}
  - {{id: anti-reconstruction, companion_bundle: threshold-ladder, expected: bundle-rejection}}
privacy_expectation:
  evidence_contains: [{AGE_CONCEPT}]
  evidence_excludes: [date_of_birth, person_id]
  diagnostics_exclude: [{SELECTOR_CANARY}, fixture-source-canary]
"#
            ),
        )
        .expect("age-bracket fixture");

        fs::write(
            self.project.join("fixtures/immunization-summary.yaml"),
            format!(
                r#"fixture: registry.evidence.acceptance.production-immunization-summary/v1
coequal_acceptance_definition: true
synthetic_only: true
common:
  observed_at: '2026-08-02T00:00:00Z'
  selector: {{person_id: {SELECTOR_CANARY}}}
  selectors:
    subject: {{profile: person-reference-v1, values: {{person_id: {SELECTOR_CANARY}}}}}
  expectedRequestParts:
    query: []
    body: {{lookup: {{person_id: {SELECTOR_CANARY}}}, fields: [dose_count], limit: 2}}
  expectedTransport:
    path: /v1/immunizations
    fixedHeaders: [{{name: Accept, value: application/json}}]
cases:
  - id: positive
    source: {{total: 1, dose_count: 4}}
    expected_values: {{schedule-complete: true, dose-count: 4}}
    expected_lookup: match
    derivation_runs: true
    signed_success: true
  - id: negative-false-is-success
    source: {{total: 1, dose_count: 2}}
    expected_values: {{schedule-complete: false, dose-count: 2}}
    expected_lookup: match
    derivation_runs: true
    signed_success: true
  - id: boundary-maximum
    source: {{total: 1, dose_count: 20}}
    expected_values: {{schedule-complete: true, dose-count: 20}}
    expected_lookup: match
    derivation_runs: true
    signed_success: true
  - {{id: missing-fact, source: {{total: 1}}, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: no-match, source: {{total: 0}}, expected_lookup: no_match, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: ambiguous, source: {{total: 2}}, expected_lookup: ambiguous, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: source-failure, source_failure: timeout, expected_public_problem: source.unavailable, signed_success: false}}
  - id: negative-wrong-derived-type
    injected_derivation:
      - {{concept_id: {SCHEDULE_CONCEPT}, value: true}}
      - {{concept_id: {DOSE_COUNT_CONCEPT}, value: '4'}}
    expected: output-gate-rejection
  - {{id: anti-reconstruction, companion_bundle: threshold-ladder, expected: bundle-rejection}}
privacy_expectation:
  evidence_contains: [{SCHEDULE_CONCEPT}, {DOSE_COUNT_CONCEPT}]
  evidence_excludes: [dose_count, person_id]
  diagnostics_exclude: [{SELECTOR_CANARY}, fixture-source-canary]
"#
            ),
        )
        .expect("immunization fixture");

        fs::write(
            self.project.join("fixtures/parent-relationship.yaml"),
            format!(
                r#"fixture: registry.evidence.acceptance.production-parent-relationship/v1
coequal_acceptance_definition: true
synthetic_only: true
common:
  observed_at: '2026-08-02T00:00:00Z'
  selectors:
    child: {{profile: child-reference-v1, values: {{child_id: synthetic-child-001}}}}
    candidate-parent: {{profile: candidate-reference-v1, values: {{candidate_id: synthetic-parent-001}}}}
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
  - {{id: positive, source: {{total: 1, relationship_confirmed: true}}, expected_value: true, expected_lookup: match, derivation_runs: true, signed_success: true}}
  - {{id: negative-false-is-success, source: {{total: 1, relationship_confirmed: false}}, expected_value: false, expected_lookup: match, derivation_runs: true, signed_success: true}}
  - id: boundary-role-order
    source: {{total: 1, relationship_confirmed: true}}
    expected_value: true
    expected_lookup: match
    derivation_runs: true
    signed_success: true
    expected_subject_roles: [child, candidate-parent]
  - {{id: missing-fact, source: {{total: 1}}, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: no-match, source: {{total: 0}}, expected_lookup: no_match, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: ambiguous, source: {{total: 2}}, expected_lookup: ambiguous, expected_public_problem: evidence.unavailable, derivation_runs: false, signed_success: false}}
  - {{id: source-failure, source_failure: timeout, expected_public_problem: source.unavailable, signed_success: false}}
  - {{id: negative-wrong-derived-type, injected_derivation: [{{concept_id: {RELATIONSHIP_CONCEPT}, value: 'true'}}], expected: output-gate-rejection}}
  - {{id: anti-reconstruction, companion_bundle: relationship-graph, expected: bundle-rejection}}
privacy_expectation:
  evidence_contains: [child, candidate-parent, {RELATIONSHIP_CONCEPT}]
  evidence_excludes: [child_id, candidate_id, relationship_confirmed]
  diagnostics_exclude: [synthetic-child-001, synthetic-parent-001, fixture-source-canary]
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
                .args(["keygen", "signing", "--out-dir"])
                .arg(self.oidc_private.parent().expect("OIDC private directory"))
                .arg("--public-out")
                .arg(&public)
                .output()
                .expect("OIDC keygen starts"),
            "external OIDC signing key generation",
        );
        assert_success(
            evidencectl()
                .args(["jwks", "--out"])
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
                .args(["keygen", "signing", "--out-dir"])
                .arg(self.root.join("transit-evidence-key"))
                .arg("--public-out")
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
        fs::write(
            self.target.join("governance.yaml"),
            format!(
                r#"version: 1
assuranceProfile: production
service: {{providerId: urn:example:providers:evidence, trustDomain: urn:example:trust-domains:acceptance, publicOrigin: https://evidence.example.test}}
issuer: {{id: urn:example:issuers:evidence}}
authentication:
  kind: oidc-access-token
  issuer: {identity}
  audiences: [{TOKEN_AUDIENCE}]
  tokenTypes: [at+jwt]
  algorithms: [ES256]
  jwksUri: {identity}/.well-known/jwks.json
  principalClaim: sub
  requesterTagsClaim: evidence_tags
  evidenceAudienceClaim: evidence_audience
  grantIdClaim: evidence_grant_id
  grantAuthorityClaim: evidence_authority
  maximumTokenLifetimeSeconds: 300
  revokedKeyIds: []
audit: {{format: keyed-jsonl, hashSecretRef: 'secret:file/audit-hmac-key', hashKeyVersion: 1, failClosed: true}}
subjectBinding: {{secretRef: 'secret:file/subject-binding-hmac-key', keyVersion: 1}}
rateLimits: {{requestsPerPrincipalPerMinute: 60, burstPerPrincipal: 10, failedSelectorAttemptsPerPrincipalAuthorityPerMinute: 10}}
signing:
  format: flattened-jws-json
  algorithm: ES256
  activePublicJwkFile: public-keys/{governed_public_name}
  publishedPublicJwkFiles: []
  revokedKeyIds: []
  jwksPath: /.well-known/evidence/jwks.json
  maximumAssertionValiditySeconds: 86400
  verifierClockSkewSeconds: 30
responseFormats: [signed-jws]
authorityProfiles:
  statutory-caseworker-v1:
    kind: statutory
    requesterTags: [fixture-agency]
    grants:
      - requirement: {REQUIREMENT}
        purpose: {PURPOSE}
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws]
        subjects: [{{role: subject, selectorProfile: person-reference-v1, valueOrigin: request}}]
"#
            ),
        )
        .expect("governance");
        fs::write(
            &self.target_runtime,
            format!(
                "version: 1\nbundleDirectory: {bundle}\nlistener:\n  bindHost: 127.0.0.1\n  port: {port}\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 65536\n  maximumConcurrentRequests: 64\n  requestTimeoutMilliseconds: 10000\n  shutdownGraceMilliseconds: 5000\nsecretProviders:\n  file:\n    root: {secrets}\nsigner:\n  kind: transit\n  unixSocketPath: {transit_socket}\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 1\n  timeoutMilliseconds: 2000\nauditStorage:\n  path: {audit}\n  maximumFileBytes: 1048576\noutboundTls:\n  systemRoots: true\n  trustProfiles: {{}}\n",
                bundle = self.candidate.join("bundle").display(),
                port = self.evidence_port,
                secrets = self.secrets.display(),
                transit_socket = self.root.join("transit-proxy.sock").display(),
                audit = self.audit_path.display(),
            ),
        )
        .expect("runtime");
    }

    fn authorize_four_shapes(&self) {
        let path = self.target.join("governance.yaml");
        let mut governance = fs::read_to_string(&path).expect("deployment governance");
        governance.push_str(&format!(
            r#"      - requirement: {AGE_REQUIREMENT}
        purpose: service-path-selection
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws]
        subjects: [{{role: subject, selectorProfile: person-reference-v1, valueOrigin: request}}]
      - requirement: {IMMUNIZATION_REQUIREMENT}
        purpose: care-coordination
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws]
        subjects: [{{role: subject, selectorProfile: person-reference-v1, valueOrigin: request}}]
      - requirement: {RELATIONSHIP_REQUIREMENT}
        purpose: relationship-check
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws]
        subjects:
          - {{role: child, selectorProfile: child-reference-v1, valueOrigin: request}}
          - {{role: candidate-parent, selectorProfile: candidate-reference-v1, valueOrigin: request}}
"#
        ));
        fs::write(path, governance).expect("four-shape deployment governance");
    }

    fn build(&self, evidence: &Path) -> Output {
        let output = evidencectl()
            .arg("build")
            .arg("--project")
            .arg(&self.project)
            .arg("--target")
            .arg(&self.target)
            .arg("--output")
            .arg(&self.candidate)
            .env("EVIDENCE_BIN", evidence)
            .output()
            .expect("build starts");
        assert_success(output, "production build")
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
                    .args(["keygen", "secret", "--out"])
                    .arg(self.secrets.join(name))
                    .output()
                    .expect("HMAC keygen starts"),
                "independent HMAC generation",
            );
        }
        assert_success(
            evidencectl()
                .args(["keygen", "token", "--out"])
                .arg(&self.source_token)
                .output()
                .expect("source token keygen starts"),
            "independent source credential generation",
        );
        assert_success(
            evidencectl()
                .args(["jwks", "--out"])
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

    fn assert_compose_revision_distinction(&self, evidence: &Path, revision: &str) {
        let (host_bundle, host_runtime) = check_revisions(
            evidence,
            &self.candidate.join("runtime.yaml"),
            "host runtime check",
        );
        assert_eq!(host_bundle, revision);

        let compose = self.root.join("compose-adapter");
        fs::create_dir(&compose).expect("Compose adapter directory");
        let runtime = compose.join("runtime.yaml");
        fs::write(
            &runtime,
            format!(
                "version: 1\nbundleDirectory: {bundle}\nlistener:\n  bindHost: 127.0.0.1\n  port: {port}\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 131072\n  maximumConcurrentRequests: 32\n  requestTimeoutMilliseconds: 15000\n  shutdownGraceMilliseconds: 10000\nsecretProviders:\n  file:\n    root: {secrets}\nsigner:\n  kind: transit\n  unixSocketPath: {transit_socket}\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 1\n  timeoutMilliseconds: 2000\nauditStorage:\n  path: {audit}\n  maximumFileBytes: 2097152\noutboundTls:\n  systemRoots: true\n  trustProfiles: {{}}\n",
                // This absolute host path stands for the unchanged read-only
                // candidate/bundle mount in the container execution context.
                bundle = self.candidate.join("bundle").display(),
                port = free_port(),
                secrets = self.secrets.display(),
                transit_socket = self.root.join("transit-proxy.sock").display(),
                audit = compose.join("persistent-audit/evidence.jsonl").display(),
            ),
        )
        .expect("Compose runtime");
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o400))
            .expect("seal Compose runtime");

        let unchanged_bundle = snapshot_files(&self.candidate.join("bundle"));
        let (compose_bundle, compose_runtime) =
            check_revisions(evidence, &runtime, "Compose-context runtime check");
        assert_eq!(
            snapshot_files(&self.candidate.join("bundle")),
            unchanged_bundle,
            "the Compose adapter must not edit the governed bundle"
        );
        assert_eq!(compose_bundle, revision);
        assert_ne!(
            compose_runtime, host_runtime,
            "environment-specific runtime bindings require an independent runtime revision"
        );
    }

    fn stage_mint(&self) -> MintDeployment {
        let mint = self.root.join("mint");
        let clients = mint.join("clients");
        fs::create_dir_all(&clients).expect("Mint client registry");

        let mint_public_keys = mint.join("public-keys");
        fs::create_dir(&mint_public_keys).expect("Mint public key directory");
        let generated_mint_public = mint.join("mint-public.jwk.json");
        assert_success(
            evidencectl()
                .args(["keygen", "signing", "--out-dir"])
                .arg(mint.join("transit-key"))
                .arg("--public-out")
                .arg(&generated_mint_public)
                .output()
                .expect("Mint signing keygen starts"),
            "independent Mint signing key generation",
        );
        let mint_public_jwk: Value =
            serde_json::from_slice(&fs::read(&generated_mint_public).expect("Mint public JWK"))
                .expect("Mint public JWK parses");
        let mint_kid = mint_public_jwk["kid"].as_str().expect("Mint signing kid");
        let mint_public = mint_public_keys.join(format!("{mint_kid}.jwk.json"));
        fs::rename(&generated_mint_public, &mint_public).expect("publish Mint public JWK");
        let audit = mint.join("audit");
        fs::create_dir(&audit).expect("Mint audit directory");
        fs::create_dir(mint.join("secrets")).expect("Mint secret directory");
        fs::set_permissions(mint.join("secrets"), fs::Permissions::from_mode(0o700))
            .expect("Mint secret directory mode");
        fs::set_permissions(&audit, fs::Permissions::from_mode(0o700))
            .expect("Mint audit directory mode");
        let audit_key = mint.join("secrets/mint-audit-hmac-key");
        let mut audit_key_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&audit_key)
            .expect("Mint audit key");
        audit_key_file
            .write_all(b"production-handoff-mint-audit-key")
            .expect("Mint audit key contents");
        audit_key_file.sync_all().expect("sync Mint audit key");
        assert_eq!(
            fs::metadata(&audit)
                .expect("Mint audit metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700,
        );
        assert_eq!(
            fs::metadata(&audit_key)
                .expect("Mint audit key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
        );
        let caller_public = mint.join("caller-public.jwk.json");
        let caller_directory = mint.join("caller");
        assert_success(
            evidencectl()
                .args(["keygen", "signing", "--out-dir"])
                .arg(&caller_directory)
                .arg("--public-out")
                .arg(&caller_public)
                .output()
                .expect("Mint caller keygen starts"),
            "independent Mint caller key generation",
        );
        let caller_jwk: Value =
            serde_json::from_slice(&fs::read(&caller_public).expect("Mint caller public JWK"))
                .expect("Mint caller public JWK parses");
        fs::write(
            clients.join("acceptance-client.yaml"),
            format!(
                "clientId: acceptance-client\nprincipal: urn:example:principals:acceptance-client\nevidenceAudience: {EVIDENCE_AUDIENCE}\nrequesterTags: [fixture-agency]\nkeys: [{}]\n",
                serde_json::to_string(&caller_jwk).expect("caller JWK serializes")
            ),
        )
        .expect("Mint client registration");

        // The HTTPS process now publishes Mint's public signing key at the
        // configured public identity. Mint itself remains on a private plain
        // HTTP listener behind that operator-owned route.
        fs::remove_file(&self.oidc_jwks).expect("replace external IdP JWKS for Mint path");
        assert_success(
            evidencectl()
                .args(["jwks", "--out"])
                .arg(&self.oidc_jwks)
                .arg(&mint_public)
                .output()
                .expect("Mint JWKS assembly starts"),
            "Mint public JWKS assembly",
        );

        let identity = format!("https://127.0.0.1:{}", self.https_port);
        let config = mint.join("mint.yaml");
        fs::write(
            &config,
            format!(
                "version: 1\nissuer: {identity}\nlistener: {{address: 127.0.0.1, port: {port}}}\nsigning:\n  algorithm: ES256\n  activePublicJwkFile: public-keys/{mint_kid}.jwk.json\n  publishedPublicJwkFiles: []\n  revokedKeyIds: []\nsigner:\n  kind: transit\n  unixSocketPath: {transit_socket}\n  mount: transit\n  keyName: mint-signing\n  keyVersion: 1\n  timeoutMilliseconds: 2000\nsecretProviders:\n  file:\n    root: {secrets}\naudit:\n  path: audit/mint.jsonl\n  maximumFileBytes: 1073741824\n  hashKeyRef: secret:file/mint-audit-hmac-key\n  hashKeyVersion: 1\naccessTokens:\n  audiences: [{TOKEN_AUDIENCE}]\n  lifetimeSeconds: 300\n  claims:\n    principal: sub\n    requesterTags: evidence_tags\n    evidenceAudience: evidence_audience\n    grantId: evidence_grant_id\n    grantAuthority: evidence_authority\nclientAssertion:\n  audience: {identity}/token\n  algorithms: [ES256]\nclients:\n  directory: clients\n",
                port = self.mint_port,
                transit_socket = self.root.join("transit-proxy.sock").display(),
                secrets = mint.join("secrets").display(),
            ),
        )
        .expect("Mint config");
        MintDeployment {
            config,
            caller_private: caller_directory.join("signing-p256-private-jwk"),
        }
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
            .env("ACCEPTANCE_MINT_PORT", self.mint_port.to_string())
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
            .arg("--runtime")
            .arg(self.candidate.join("runtime.yaml"))
            .arg("serve")
            .env("SSL_CERT_FILE", &self.ca)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone Evidence log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("Evidence service starts")
    }

    fn start_mint(&self, mint: &Path, config: &Path) -> Child {
        let log = owner_only_log(&self.root.join("mint.log"));
        Command::new(mint)
            .args(["serve", "--config"])
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone Mint log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("Mint service starts")
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
            "expectedOutputs": [{"concept":CONCEPT,"form":"boolean"}],
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

fn bundle_revision(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Bundle revision: "))
        .filter(|revision| {
            revision.len() == 71
                && revision.starts_with("sha256:")
                && revision[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .expect("build reports one bundle revision")
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
        .map(|concept| concept["form"].as_str().expect("compiled concept form"))
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

fn check_revisions(evidence: &Path, runtime: &Path, label: &str) -> (String, String) {
    let output = assert_success(
        Command::new(evidence)
            .arg("--runtime")
            .arg(runtime)
            .arg("check")
            .output()
            .expect("Evidence check starts"),
        label,
    );
    let stdout = String::from_utf8(output.stdout).expect("Evidence check stdout");
    let fields = stdout
        .lines()
        .find(|line| line.starts_with("Evidence deployment "))
        .expect("Evidence check report")
        .split_whitespace()
        .collect::<Vec<_>>();
    assert_eq!(fields.get(3), Some(&"/"), "Evidence revision separator");
    (
        fields.get(2).expect("bundle revision").to_string(),
        fields.get(4).expect("runtime revision").to_string(),
    )
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

fn wait_for_listener(child: &mut Child, port: u16, label: &str) {
    wait_for(Duration::from_secs(20), || {
        assert_running(child, label);
        TcpStream::connect(("127.0.0.1", port)).is_ok()
    });
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
                "values": {"person_id": SELECTOR_CANARY},
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
/// It is requirement scoped, so it is not the deployment's bundle revision.
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

fn mint_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        if let Some(path) = std::env::var_os("MINT_BIN") {
            return PathBuf::from(path);
        }
        let build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(workspace_root())
            .args([
                "build",
                "--locked",
                "-p",
                "registry-mint",
                "--bin",
                "mint",
                "--profile",
                &current_test_profile(),
                "--message-format",
                "json-render-diagnostics",
            ])
            .output()
            .expect("building the Mint binary");
        assert!(
            build.status.success(),
            "building the Mint binary failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        String::from_utf8_lossy(&build.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .filter_map(|message| message["executable"].as_str().map(PathBuf::from))
            .find(|path| path.file_name().is_some_and(|name| name == "mint"))
            .expect("Mint executable path")
    })
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
