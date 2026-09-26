use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{json, Value};

const PSEUDONYM: &str =
    "hmac-sha256:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FAILURE: &str = "error[evidence.audit.inspection-failed] local audit history $: \
    Evidence could not verify the stopped local audit history.\n  \
    next: Stop the local session with evidencectl dev stop and rerun audit show; \
    if it is already stopped, its retained audit history did not verify.\n";

#[test]
fn audit_help_is_nested_required_and_hides_test_seams() {
    let audit = command()
        .args(["audit", "--help"])
        .output()
        .expect("audit help");
    assert_success(&audit);
    let audit = String::from_utf8_lossy(&audit.stdout);
    assert!(
        audit.contains("show"),
        "nested show command is absent: {audit}"
    );

    let show = command()
        .args(["audit", "show", "--help"])
        .output()
        .expect("show help");
    assert_success(&show);
    let show = String::from_utf8_lossy(&show.stdout);
    assert!(
        show.contains("--last-operation"),
        "selector is absent: {show}"
    );
    for hidden in ["--project", "--evidence-bin"] {
        assert!(!show.contains(hidden), "test seam leaked: {show}");
    }

    for arguments in [
        vec!["audit", "show"],
        vec!["audit", "show", "--all"],
        vec!["audit", "show", "--last-operation", "--last-operation"],
    ] {
        let output = command().args(arguments).output().expect("invalid CLI");
        assert!(
            !output.status.success(),
            "selector must be required/exclusive"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn successful_view_delegates_to_stopped_core_and_prints_only_aliases() {
    let fixture = Fixture::new();
    fixture.write_core_json(&successful_view());
    let output = fixture.show();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "ACCESS AUTHORIZED adult-status age-check requester={PSEUDONYM}\n\
             DISCLOSURE RELEASED is_adult\n"
        )
    );
    assert!(output.stderr.is_empty());

    let arguments =
        fs::read_to_string(fixture.evidence.with_extension("args")).expect("Evidence argv");
    assert_eq!(
        arguments.lines().collect::<Vec<_>>(),
        [
            "--runtime",
            fs::canonicalize(&fixture.root)
                .expect("canonical project")
                .join(".evidence/dev/runtime.yaml")
                .to_str()
                .expect("runtime path"),
            "local-audit-last-operation",
        ]
    );
    let rendered = String::from_utf8_lossy(&output.stdout);
    for forbidden in [
        "person-123",
        "token-canary",
        "operation",
        "evidenceId",
        "source",
        "adapter",
        "actor",
        "grant",
        "subject",
        "citizen",
        "accountability",
    ] {
        assert!(!rendered.contains(forbidden), "rendered {forbidden}");
    }
}

#[test]
fn access_only_view_prints_authorized_without_claiming_release() {
    let fixture = Fixture::new();
    let mut view = successful_view();
    view["events"].as_array_mut().expect("events").truncate(1);
    fixture.write_core_json(&view);
    let output = fixture.show();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("ACCESS AUTHORIZED adult-status age-check requester={PSEUDONYM}\n")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("RELEASE"));
}

#[test]
fn standalone_authorization_refusal_prints_only_the_safe_reason() {
    let fixture = Fixture::new();
    fixture.write_core_json(&refusal_view());
    let output = fixture.show();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("ACCESS REFUSED requester={PSEUDONYM} reason=not_authorized\n")
    );
    assert!(output.stderr.is_empty());

    let rendered = String::from_utf8_lossy(&output.stdout);
    for forbidden in [
        "adult-status",
        "age-check",
        "is_adult",
        "requirement",
        "purpose",
        "selector",
        "authority",
        "responseProtection",
        "signed",
        "operation",
    ] {
        assert!(!rendered.contains(forbidden), "rendered {forbidden}");
    }
}

#[test]
fn structured_sd_jwt_release_uses_the_same_minimized_audit_view() {
    let fixture = Fixture::new();
    let state_path = fixture.root.join(".evidence/dev/state.json");
    let mut state: Value =
        serde_json::from_slice(&fs::read(&state_path).expect("state")).expect("state JSON");
    state["questions"][1]["concepts"][0]["form"] = json!("reviewed-structured-value");
    fs::write(
        &state_path,
        serde_json::to_vec(&state).expect("state renders"),
    )
    .expect("state writes");
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).expect("state mode");

    let bundle_path = fixture.root.join(".evidence/dev/bundle/evidence.yaml");
    let mut bundle: Value =
        serde_norway::from_slice(&fs::read(&bundle_path).expect("bundle")).expect("bundle YAML");
    bundle["requirements"][1]["concepts"][0]["form"] = json!("reviewed-structured-value");
    fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o600))
        .expect("unseal bundle for fixture update");
    fs::write(
        &bundle_path,
        serde_norway::to_string(&bundle).expect("bundle renders"),
    )
    .expect("bundle writes");
    fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o400)).expect("bundle mode");

    let mut view = successful_view();
    view["events"][0]["responseProtection"] = json!("sd-jwt-vc");
    view["events"][1]["responseProtection"] = json!("sd-jwt-vc");
    fixture.write_core_json(&view);

    let output = fixture.show();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "ACCESS AUTHORIZED adult-status age-check requester={PSEUDONYM}\n\
             DISCLOSURE RELEASED is_adult\n"
        )
    );
}

#[test]
fn multi_concept_release_requires_and_prints_the_exact_declared_list() {
    let fixture = Fixture::new();
    let state_path = fixture.root.join(".evidence/dev/state.json");
    let mut state: Value =
        serde_json::from_slice(&fs::read(&state_path).expect("state")).expect("state JSON");
    state["questions"][1]["concepts"] = json!([
        {
            "alias": "is_adult",
            "uri": "urn:registrystack:evidence:local:concept:adult-status:is_adult",
            "form": "boolean"
        },
        {
            "alias": "age_years",
            "uri": "urn:registrystack:evidence:local:concept:adult-status:age_years",
            "form": "bounded-integer"
        }
    ]);
    fs::write(
        &state_path,
        serde_json::to_vec(&state).expect("state renders"),
    )
    .expect("state writes");
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).expect("state mode");

    let bundle_path = fixture.root.join(".evidence/dev/bundle/evidence.yaml");
    let mut bundle: Value =
        serde_norway::from_slice(&fs::read(&bundle_path).expect("bundle")).expect("bundle YAML");
    bundle["requirements"][1]["concepts"] = json!([
        {
            "id": "urn:registrystack:evidence:local:concept:adult-status:is_adult",
            "form": "boolean"
        },
        {
            "id": "urn:registrystack:evidence:local:concept:adult-status:age_years",
            "form": "bounded-integer"
        }
    ]);
    fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o600))
        .expect("open bundle for fixture update");
    fs::write(
        &bundle_path,
        serde_norway::to_string(&bundle).expect("bundle renders"),
    )
    .expect("bundle writes");
    fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o400))
        .expect("seal updated bundle");

    let mut view = successful_view();
    view["events"][1]["disclosedConcepts"] = json!([
        "urn:registrystack:evidence:local:concept:adult-status:is_adult",
        "urn:registrystack:evidence:local:concept:adult-status:age_years"
    ]);
    fixture.write_core_json(&view);
    let output = fixture.show();
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("DISCLOSURE RELEASED is_adult, age_years\n"));

    view["events"][1]["disclosedConcepts"] =
        json!(["urn:registrystack:evidence:local:concept:adult-status:is_adult"]);
    fixture.write_core_json(&view);
    assert_closed_failure(&fixture.show(), "incomplete multi-concept release");
}

#[test]
fn closed_parser_alias_mapping_and_metadata_fail_without_partial_output() {
    let fixture = Fixture::new();
    let base = successful_view();
    let mut cases = Vec::new();

    let mut unknown_top = base.clone();
    unknown_top["rawSelector"] = json!("person-123");
    cases.push(("unknown top field", unknown_top));

    let mut unknown_event = base.clone();
    unknown_event["events"][0]["sourceId"] = json!("source-canary");
    cases.push(("unknown event field", unknown_event));

    let mut schema = base.clone();
    schema["schema"] = json!("registry.evidence.local-audit-operation/v2");
    cases.push(("schema", schema));

    let mut requirement = base.clone();
    requirement["events"][0]["requirement"] = json!("urn:other:requirement");
    cases.push(("requirement alias", requirement));

    let mut concept = base.clone();
    concept["events"][1]["disclosedConcepts"] = json!(["urn:other:concept"]);
    cases.push(("concept alias", concept));

    let mut requester = base.clone();
    requester["events"][1]["requesterPseudonym"] =
        json!(format!("hmac-sha256:v1:{}", "b".repeat(64)));
    cases.push(("requester coherence", requester));

    let mut unsafe_requester = base.clone();
    unsafe_requester["events"][0]["requesterPseudonym"] = json!("person-123");
    cases.push(("unsafe pseudonym", unsafe_requester));

    let mut protection = base.clone();
    protection["events"][0]["responseProtection"] = json!("unsigned");
    cases.push(("response protection", protection));

    let mut phase = base.clone();
    phase["events"][1]["phase"] = json!("access-attempt");
    cases.push(("phase", phase));

    let mut decision = base.clone();
    decision["events"][1]["decision"] = json!("authorized");
    cases.push(("decision", decision));

    let mut explicit_null = base.clone();
    explicit_null["events"][0]["disclosedConcepts"] = Value::Null;
    cases.push(("explicit null is not omission", explicit_null));

    let mut reversed_time = base.clone();
    reversed_time["events"][1]["occurredAt"] = json!("2026-08-04T00:00:00.000Z");
    cases.push(("event time order", reversed_time));

    let mut too_many = base.clone();
    let third = too_many["events"][1].clone();
    too_many["events"]
        .as_array_mut()
        .expect("events")
        .push(third);
    cases.push(("event bound", too_many));

    for (label, value) in cases {
        fixture.write_core_json(&value);
        assert_closed_failure(&fixture.show(), label);
    }

    fixture.write_core_bytes(b"{malformed person-123 token-canary");
    assert_closed_failure(&fixture.show(), "malformed JSON");
}

#[test]
fn malformed_or_mixed_refusal_views_fail_without_partial_output() {
    let fixture = Fixture::new();
    let base = refusal_view();
    let mut cases = Vec::new();

    let mut mixed = base.clone();
    mixed["events"]
        .as_array_mut()
        .expect("events")
        .push(successful_view()["events"][0].clone());
    cases.push(("refusal followed by authorization", mixed));

    let mut two_refusals = base.clone();
    let second = two_refusals["events"][0].clone();
    two_refusals["events"]
        .as_array_mut()
        .expect("events")
        .push(second);
    cases.push(("two refusals", two_refusals));

    let mut request_metadata = base.clone();
    request_metadata["events"][0]["requirement"] =
        json!("urn:registrystack:evidence:local:requirement:adult-status");
    cases.push(("refusal request metadata", request_metadata));

    let mut response_metadata = base.clone();
    response_metadata["events"][0]["responseProtection"] = json!("signed");
    cases.push(("refusal response metadata", response_metadata));

    let mut category = base.clone();
    category["events"][0]["safeErrorCategory"] = json!("selector");
    cases.push(("unsafe category", category));

    let mut phase = base.clone();
    phase["events"][0]["phase"] = json!("access-attempt");
    cases.push(("refusal phase", phase));

    let mut decision = base.clone();
    decision["events"][0]["decision"] = json!("authorized");
    cases.push(("refusal decision", decision));

    let mut requester = base.clone();
    requester["events"][0]["requesterPseudonym"] = json!("person-123");
    cases.push(("unsafe refusal requester", requester));

    let mut occurred_at = base.clone();
    occurred_at["events"][0]["occurredAt"] = json!("not-a-time");
    cases.push(("invalid refusal time", occurred_at));

    let mut missing_category = base.clone();
    missing_category["events"][0]
        .as_object_mut()
        .expect("event")
        .remove("safeErrorCategory");
    cases.push(("missing refusal category", missing_category));

    for (label, value) in cases {
        fixture.write_core_json(&value);
        assert_closed_failure(&fixture.show(), label);
    }
}

#[test]
fn core_failure_oversized_output_and_non_stopped_state_are_value_free() {
    let fixture = Fixture::new();
    fixture.write_core_json(&successful_view());
    fs::write(fixture.evidence.with_extension("fail"), b"").expect("failure marker");
    assert_closed_failure(&fixture.show(), "core failure");
    fs::remove_file(fixture.evidence.with_extension("fail")).expect("remove marker");

    fixture.write_core_bytes(&vec![b'x'; 256 * 1024 + 1]);
    assert_closed_failure(&fixture.show(), "output bound");

    fixture.write_core_json(&successful_view());
    let state_path = fixture.root.join(".evidence/dev/state.json");
    let mut state: Value =
        serde_json::from_slice(&fs::read(&state_path).expect("state")).expect("state JSON");
    state["status"] = json!("ready");
    fs::write(
        &state_path,
        serde_json::to_vec(&state).expect("state renders"),
    )
    .expect("state writes");
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).expect("state mode");
    assert_closed_failure(&fixture.show(), "running state");
}

fn successful_view() -> Value {
    json!({
        "schema": "registry.evidence.local-audit-operation/v1",
        "operation": "person-123-token-canary",
        "events": [
            {
                "occurredAt": "2026-08-04T00:00:01.000Z",
                "phase": "access-attempt",
                "decision": "authorized",
                "requirement": "urn:registrystack:evidence:local:requirement:adult-status",
                "purpose": "age-check",
                "requesterPseudonym": PSEUDONYM,
                "responseProtection": "signed"
            },
            {
                "occurredAt": "2026-08-04T00:00:02.000Z",
                "phase": "disclosure-release",
                "decision": "released",
                "requirement": "urn:registrystack:evidence:local:requirement:adult-status",
                "purpose": "age-check",
                "requesterPseudonym": PSEUDONYM,
                "responseProtection": "signed",
                "disclosedConcepts": [
                    "urn:registrystack:evidence:local:concept:adult-status:is_adult"
                ],
                "evidenceId": "urn:token-canary:evidence:person-123"
            }
        ]
    })
}

fn refusal_view() -> Value {
    json!({
        "schema": "registry.evidence.local-audit-operation/v1",
        "operation": "refused-operation-1234",
        "events": [
            {
                "occurredAt": "2026-08-04T00:00:01.000Z",
                "phase": "denial",
                "decision": "not-authorized",
                "requesterPseudonym": PSEUDONYM,
                "safeErrorCategory": "not-authorized"
            }
        ]
    })
}

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    evidence: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("project");
        private_directory(&root);
        private_directory(&root.join(".evidence"));
        private_directory(&root.join(".evidence/dev"));
        private_directory(&root.join(".evidence/dev/bundle"));
        private_file(&root.join(".evidence/dev/runtime.yaml"), b"runtime", 0o400);
        let canonical = fs::canonicalize(&root).expect("canonical project");
        let state = json!({
            "schema": "registry.evidencectl.dev-state/v6",
            "status": "stopped",
            "project": canonical,
            "runtimePath": canonical.join(".evidence/dev/runtime.yaml"),
            "evidenceOrigin": "http://127.0.0.1:8080",
            "issuerOrigin": "http://127.0.0.1:8081",
            "issuerSessionId": "0123456789abcdef0123456789abcdef0123456789abcdef",
            "tokenUrl": "http://127.0.0.1:8081/oauth2/token",
            "accessTokenAudience": "urn:registrystack:evidence:local:gateway",
            "caller": null,
            "accessPolicies": [],
            "questions": [
                {
                    "alias": "age-bracket",
                    "requirementUri": "urn:registrystack:evidence:local:requirement:age-bracket",
                    "purpose": "service-path-selection",
                    "subjects": [{
                        "role": "person",
                        "selectorProfile": "local-subject-age-bracket-v1",
                        "selectorField": "person_id"
                    }],
                    "concepts": [{
                        "alias": "age_bracket",
                        "uri": "urn:registrystack:evidence:local:concept:age-bracket:age_bracket",
                        "form": "controlled-category"
                    }]
                },
                {
                    "alias": "adult-status",
                    "requirementUri": "urn:registrystack:evidence:local:requirement:adult-status",
                    "purpose": "age-check",
                    "subjects": [{
                        "role": "person",
                        "selectorProfile": "local-subject-adult-status-v1",
                        "selectorField": "person_id"
                    }],
                    "concepts": [{
                        "alias": "is_adult",
                        "uri": "urn:registrystack:evidence:local:concept:adult-status:is_adult",
                        "form": "boolean"
                    }]
                }
            ],
            "failure": null
        });
        private_file(
            &root.join(".evidence/dev/state.json"),
            &serde_json::to_vec(&state).expect("state renders"),
            0o600,
        );
        let bundle = json!({
            "selectorProfiles": {
                "local-subject-age-bracket-v1": {
                    "fields": {"person_id": {"type": "string"}}
                },
                "local-subject-adult-status-v1": {
                    "fields": {"person_id": {"type": "string"}}
                }
            },
            "authorityProfiles": {
                "local-caller": {
                    "kind": "explicit-request",
                    "requesterTags": ["local-caller"],
                    "grants": [
                        {
                            "requirement": "urn:registrystack:evidence:local:requirement:age-bracket",
                            "purpose": "service-path-selection",
                            "audienceFrom": "authenticated-requester",
                            "responseFormats": ["signed-jws"],
                            "subjects": [{
                                "role": "person",
                                "selectorProfile": "local-subject-age-bracket-v1",
                                "valueOrigin": "request"
                            }]
                        },
                        {
                            "requirement": "urn:registrystack:evidence:local:requirement:adult-status",
                            "purpose": "age-check",
                            "audienceFrom": "authenticated-requester",
                            "responseFormats": ["signed-jws"],
                            "subjects": [{
                                "role": "person",
                                "selectorProfile": "local-subject-adult-status-v1",
                                "valueOrigin": "request"
                            }]
                        }
                    ]
                }
            },
            "requirements": [
                {
                    "id": "urn:registrystack:evidence:local:requirement:age-bracket",
                    "purposes": ["service-path-selection"],
                    "subjectRoles": [{
                        "role": "person",
                        "selectorProfiles": ["local-subject-age-bracket-v1"]
                    }],
                    "concepts": [{
                        "id": "urn:registrystack:evidence:local:concept:age-bracket:age_bracket",
                        "form": "controlled-category"
                    }]
                },
                {
                    "id": "urn:registrystack:evidence:local:requirement:adult-status",
                    "purposes": ["age-check"],
                    "subjectRoles": [{
                        "role": "person",
                        "selectorProfiles": ["local-subject-adult-status-v1"]
                    }],
                    "concepts": [{
                        "id": "urn:registrystack:evidence:local:concept:adult-status:is_adult",
                        "form": "boolean"
                    }]
                }
            ]
        });
        private_file(
            &root.join(".evidence/dev/bundle/evidence.yaml"),
            serde_norway::to_string(&bundle)
                .expect("bundle renders")
                .as_bytes(),
            0o400,
        );

        let evidence = temporary.path().join("evidence-stub");
        executable(
            &evidence,
            b"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\nif [ -f \"$0.empty\" ]; then\n  exit 3\nfi\nif [ -f \"$0.fail\" ]; then\n  printf 'person-123 token-canary source-canary\\n' >&2\n  exit 41\nfi\ncat \"$0.output\"\n",
        );
        Self {
            _temporary: temporary,
            root,
            evidence,
        }
    }

    fn write_core_json(&self, value: &Value) {
        self.write_core_bytes(&serde_json::to_vec(value).expect("core output renders"));
    }

    fn write_core_bytes(&self, bytes: &[u8]) {
        fs::write(self.evidence.with_extension("output"), bytes).expect("core output writes");
    }

    fn show(&self) -> Output {
        self.show_in_format(None)
    }

    fn show_json(&self) -> Output {
        self.show_in_format(Some("json"))
    }

    fn show_in_format(&self, format: Option<&str>) -> Output {
        let mut command = command();
        if let Some(format) = format {
            command.args(["--format", format]);
        }
        command
            .current_dir(&self.root)
            .args([
                "audit",
                "show",
                "--last-operation",
                "--project",
                ".",
                "--evidence-bin",
            ])
            .arg(&self.evidence)
            .output()
            .expect("audit show")
    }
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn private_directory(path: &Path) {
    fs::create_dir(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
}

fn private_file(path: &Path, contents: &[u8], mode: u32) {
    fs::write(path, contents).expect("private file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("private file mode");
}

fn executable(path: &Path, contents: &[u8]) {
    private_file(path, contents, 0o700);
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_closed_failure(output: &Output, label: &str) {
    assert!(!output.status.success(), "{label} unexpectedly succeeded");
    assert!(output.stdout.is_empty(), "{label} printed partial output");
    assert_eq!(String::from_utf8_lossy(&output.stderr), FAILURE, "{label}");
    for protected in ["person-123", "token-canary", "source-canary"] {
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(protected),
            "{label} leaked {protected}"
        );
    }
}

/// JSON mode keeps the two disciplines the human view carries: the core
/// document is embedded whole only after it validates, and a failure says
/// nothing beyond the value-free refusal.
#[test]
fn json_mode_embeds_the_validated_core_view_and_keeps_failures_value_free() {
    let fixture = Fixture::new();
    fixture.write_core_json(&successful_view());
    let output = fixture.show_json();
    assert_success(&output);
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON report");
    assert_eq!(report["command"], "audit show");
    assert_eq!(report["ok"], Value::Bool(true));
    assert_eq!(report["status"], "complete");
    assert_eq!(
        report["operation"]["schema"],
        "registry.evidence.local-audit-operation/v1"
    );
    assert_eq!(
        report["operation"]["events"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        report["rendered"],
        json!([
            format!("ACCESS AUTHORIZED adult-status age-check requester={PSEUDONYM}"),
            "DISCLOSURE RELEASED is_adult",
        ])
    );
    assert_eq!(
        String::from_utf8_lossy(&fixture.show().stdout),
        format!(
            "ACCESS AUTHORIZED adult-status age-check requester={PSEUDONYM}\n\
             DISCLOSURE RELEASED is_adult\n"
        ),
        "the human renderer is unchanged"
    );

    fixture.write_core_bytes(b"{malformed person-123 token-canary");
    let output = fixture.show_json();
    assert!(!output.status.success());
    assert!(
        output.stderr.is_empty(),
        "a JSON failure wrote human diagnostics: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON failure document");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "evidence.audit.inspection-failed"
    );
    assert!(
        report["diagnostics"][0].get("cause").is_none(),
        "a closed refusal carries no cause: {report}"
    );
    let rendered = report.to_string();
    for protected in ["person-123", "token-canary"] {
        assert!(!rendered.contains(protected), "leaked {protected}");
    }
}

/// A project that never ran a local session has no audit history. The
/// refusal says so by name instead of the closed inspection failure, and
/// never delegates to the core.
#[test]
fn a_project_without_a_local_session_names_the_missing_session() {
    let fixture = Fixture::new();
    fs::remove_dir_all(fixture.root.join(".evidence/dev")).expect("remove session");
    fixture.write_core_json(&successful_view());

    let output = fixture.show();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.starts_with("error[evidence.audit.no-stopped-session]"),
        "{message}"
    );

    let output = fixture.show_json();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON refusal");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "evidence.audit.no-stopped-session"
    );
    assert!(report["diagnostics"][0].get("cause").is_none());
    assert!(
        !fixture.evidence.with_extension("args").exists(),
        "the core was consulted without a stopped session"
    );
}

/// Retained session state that lost its state file, or a stopped session
/// set aside by an interrupted restart, is damaged history rather than a
/// project that never ran, so it takes the closed inspection failure.
#[test]
fn damaged_retained_session_state_is_not_reported_as_no_session() {
    let fixture = Fixture::new();
    fixture.write_core_json(&successful_view());
    fs::remove_file(fixture.root.join(".evidence/dev/state.json")).expect("remove state");
    assert_closed_failure(&fixture.show(), "session without state");

    fs::rename(
        fixture.root.join(".evidence/dev"),
        fixture.root.join(".evidence/dev-stopped-before-restart"),
    )
    .expect("set the session aside");
    assert_closed_failure(&fixture.show(), "session set aside by a restart");
    assert!(
        !fixture.evidence.with_extension("args").exists(),
        "the core was consulted without a stopped session"
    );
}

/// A stopped session that answered no request leaves a verified chain with
/// no operation. The core reports that with its own exit status, and the
/// refusal names it instead of the closed inspection failure.
#[test]
fn a_verified_history_without_an_operation_is_named() {
    let fixture = Fixture::new();
    fs::write(fixture.evidence.with_extension("empty"), b"").expect("empty marker");

    let output = fixture.show();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.starts_with("error[evidence.audit.no-operation]"),
        "{message}"
    );

    let output = fixture.show_json();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON refusal");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "evidence.audit.no-operation"
    );
    assert!(report["diagnostics"][0].get("cause").is_none());
}
