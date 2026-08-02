#![cfg(unix)]

use std::{
    fs,
    net::TcpStream,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

/// A value planted in every mutated artifact so a diagnostic that leaks a
/// document value fails loudly instead of quietly.
const CANARY: &str = "s3cr3t-canary-value";

#[test]
fn actual_binary_checks_and_evaluates_an_immutable_project() {
    let staged = tempfile::tempdir().expect("temporary deployment");
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence",
    );
    copy_tree(&project.join("bundle"), &staged.path().join("bundle"));
    let secret_root = staged.path().join("secrets");
    fs::create_dir(&secret_root).expect("create private secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("set private secret-root mode");

    let runtime = fs::read_to_string(project.join("runtime.yaml")).expect("read runtime template");
    let bundle_path = staged.path().join("bundle");
    let bundle_directory = bundle_path.to_str().expect("temporary path is UTF-8");
    let audit_path = staged.path().join("audit.jsonl");
    let runtime = runtime
        .replacen("/etc/registry-evidence/bundle", bundle_directory, 1)
        .replacen(
            "/run/secrets/registry-evidence",
            secret_root.to_str().expect("temporary path is UTF-8"),
            1,
        )
        .replacen(
            "/var/lib/registry-evidence/audit/evidence.jsonl",
            audit_path.to_str().expect("temporary path is UTF-8"),
            1,
        );
    let runtime_path = staged.path().join("runtime.yaml");
    fs::write(&runtime_path, runtime).expect("stage runtime");
    set_tree_mode(&bundle_path, 0o555, 0o444);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("set immutable runtime mode");

    let check = invoke(&runtime_path, &["check"]);
    let evaluate = invoke(
        &runtime_path,
        &["evaluate", "--fixture", "fixtures/adult-status-cases.yaml"],
    );

    set_tree_mode(&bundle_path, 0o755, 0o644);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o644))
        .expect("restore runtime mode");
    assert_success(
        &check,
        "Evidence deployment ",
        " passed check (3 requirements)\n",
    );
    assert_success(
        &evaluate,
        "Evidence fixture passed (",
        " evaluated cases)\n",
    );
}

/// One deployment failure class, with the exact operator text it must produce.
///
/// The expected text is split into a prefix and a suffix so a case that
/// reports a text location can pin the cause and the location shape without
/// pinning a line number that ordinary fixture edits would move.
struct FailureCase {
    label: &'static str,
    break_deployment: fn(&Deployment),
    prefix: &'static str,
    suffix: &'static str,
}

#[test]
fn check_names_a_safe_artifact_and_a_value_free_cause_for_every_failure_class() {
    let cases = [
        FailureCase {
            label: "malformed bundle YAML",
            break_deployment: |deployment| {
                deployment.append("bundle/evidence.yaml", &format!("trailing: [{CANARY}\n"));
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: document is not well-formed YAML (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "unknown bundle field",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "  principalClaim: sub\n",
                    &format!("  principalClaim: sub\n  unknownField: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: unknown field at authentication (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "wrong bundle field type",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "version: 1\n",
                    &format!("version: \"{CANARY}\"\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: field has the wrong type at version (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "unaccepted bundle field variant",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "  kind: oidc-access-token\n",
                    &format!("  kind: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: field value is not one of the accepted variants at authentication.kind (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "configuration cross-reference",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "    source: source-a\n",
                    &format!("    source: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: requirement references an unknown source\n",
            suffix: "",
        },
        FailureCase {
            label: "artifact closure references a missing file",
            break_deployment: |deployment| {
                deployment.remove("bundle/derivations/adult-status.rhai");
            },
            prefix: "evidence: deployment artifact closure is invalid: artifact derivations/adult-status.rhai: the configuration references an artifact the bundle does not contain\n",
            suffix: "",
        },
        FailureCase {
            label: "artifact closure carries an unreferenced file",
            break_deployment: |deployment| {
                deployment.write("bundle/schemas/orphan.schema.yaml", &format!("x: {CANARY}\n"));
            },
            prefix: "evidence: deployment artifact closure is invalid: artifact schemas/orphan.schema.yaml: the bundle contains an artifact the configuration does not reference\n",
            suffix: "",
        },
        FailureCase {
            label: "unsafe artifact name is never echoed",
            break_deployment: |deployment| {
                deployment.write(
                    &format!("bundle/fixtures/orphan {CANARY}.yaml"),
                    "synthetic_only: true\n",
                );
            },
            prefix: "evidence: deployment artifact closure is invalid: the bundle contains an artifact the configuration does not reference\n",
            suffix: "",
        },
        FailureCase {
            label: "script",
            break_deployment: |deployment| {
                deployment.append(
                    "bundle/derivations/adult-status.rhai",
                    &format!("\nthis is not rhai {CANARY}(((\n"),
                );
            },
            prefix: "evidence: deployment script is invalid: artifact derivations/adult-status.rhai: script does not compile\n",
            suffix: "",
        },
        FailureCase {
            label: "fact schema",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/schemas/adult-status-facts.schema.yaml",
                    &format!("type: [{CANARY}]\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact schemas/adult-status-facts.schema.yaml: fact schema must close the root object\n",
            suffix: "",
        },
        FailureCase {
            label: "codelist",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/codelists/residence-region-map.yaml",
                    &format!("id: broken\nversion: \"1\"\nentries: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact codelists/residence-region-map.yaml: codelist YAML is invalid\n",
            suffix: "",
        },
        FailureCase {
            label: "fixture",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/fixtures/adult-status-cases.yaml",
                    &format!("synthetic_only: true\ncases: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact fixtures/adult-status-cases.yaml: fixture cases are missing\n",
            suffix: "",
        },
        FailureCase {
            label: "unknown runtime field",
            break_deployment: |deployment| {
                deployment.append("runtime.yaml", &format!("unknownField: {CANARY}\n"));
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: unknown field (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "wrong runtime field type",
            break_deployment: |deployment| {
                deployment.replace(
                    "runtime.yaml",
                    "  port: 8080\n",
                    &format!("  port: \"{CANARY}\"\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: field has the wrong type at listener.port (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "runtime operator path",
            break_deployment: |deployment| {
                deployment.replace_line(
                    "runtime.yaml",
                    "bundleDirectory: ",
                    &format!("bundleDirectory: relative/{CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: absolute operator path is invalid\n",
            suffix: "",
        },
    ];

    for case in cases {
        let deployment = Deployment::stage("all-definitions");
        (case.break_deployment)(&deployment);
        let output = deployment.check();

        assert!(
            !output.status.success(),
            "{}: check accepted a broken deployment",
            case.label
        );
        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert!(stdout.is_empty(), "{}: check wrote output", case.label);
        assert!(
            stderr.starts_with(case.prefix) && stderr.ends_with(case.suffix),
            "{}: unexpected diagnostic {stderr:?}",
            case.label
        );
        assert!(
            !stdout.contains(CANARY) && !stderr.contains(CANARY),
            "{}: diagnostic disclosed a document value",
            case.label
        );
    }
}

/// The documented audit rotation procedure, executed against the real binary.
///
/// The procedure is: stop the service with SIGTERM, archive the audit file by
/// rename, start the service again on the same path, and confirm readiness on
/// the new chain. This proves the stop and start-new-chain steps of the
/// operator procedure and the SIGTERM handling that makes the stop step
/// possible at all.
#[test]
fn serve_stops_on_sigterm_and_restarts_on_an_archived_audit_chain() {
    let port = free_port();
    let deployment = Deployment::stage_on_port("all-definitions", port);
    deployment.stage_acceptance_secrets();
    deployment.seal();

    let mut service = deployment.serve();
    wait_until_ready(port);
    let first = deployment.path("audit.jsonl");
    assert!(first.is_file(), "the service did not open an audit chain");
    stop(&mut service);

    // Archive by rename: the audit file must stay a singly linked owner-only
    // regular file, so a copy-and-truncate rotation is not the procedure.
    let archive = deployment.path("audit-archived.jsonl");
    fs::rename(&first, &archive).expect("archive the audit chain");
    assert!(!first.exists(), "the archived chain was left in place");

    let mut restarted = deployment.serve();
    wait_until_ready(port);
    assert!(first.is_file(), "the restart did not start a new chain");
    stop(&mut restarted);

    assert!(archive.is_file(), "the archived chain was disturbed");

    // Rollback is the same stop, rename, start sequence in reverse: the new
    // chain is set aside and the archived chain resumes at the original path.
    let superseded = deployment.path("audit-superseded.jsonl");
    fs::rename(&first, &superseded).expect("set the new chain aside");
    fs::rename(&archive, &first).expect("restore the archived chain");
    let mut rolled_back = deployment.serve();
    wait_until_ready(port);
    stop(&mut rolled_back);
    assert!(
        superseded.is_file(),
        "the superseded chain was disturbed during rollback"
    );
    deployment.unseal();
}

/// The staged verification key identifier, echoed by the protected header.
const VERIFY_KEY_ID: &str = "verify-fixture-key";

/// A staged Ed25519 test key. It signs fixture assertions in this test binary
/// only and is not a deployment key.
const VERIFY_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"verify-fixture-key"}"#;

/// A staged request nonce, of the exact 43-character request-nonce shape.
const FIXTURE_NONCE: &str = "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I";

/// A different nonce of the same shape, carrying the canary so a policy
/// diagnostic that echoed the expected value would fail loudly.
const CANARY_NONCE: &str = "s3cr3t-canary-value000000000000000000000000";

#[test]
fn verify_accepts_an_authentic_and_current_stored_response() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(0),
        "verify rejected a good response"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with(
            "verified-at: 2026-08-02T12:00:00Z\nauthentic: yes\ncurrently-valid: yes\n"
        ),
        "unexpected verification output {stdout:?}"
    );
    assert!(
        stdout.contains(&format!("\"requestNonce\": \"{FIXTURE_NONCE}\"")),
        "verify did not print the verified Evidence for inspection"
    );
}

#[test]
fn verify_separates_authenticity_from_current_validity() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());
    let output = stored.verify(Some("2026-08-05T00:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(3),
        "an expired response did not report its own exit status"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    assert_eq!(
        std::str::from_utf8(&output.stdout).expect("stdout is UTF-8"),
        "verified-at: 2026-08-05T00:00:00Z\nauthentic: yes\ncurrently-valid: no\n",
        "an expired response must stay authentic without being current"
    );
}

#[test]
fn verify_rejects_a_tampered_payload_without_naming_a_value() {
    let mut tampered = fixture_evidence();
    tampered["supportedValues"][0]["value"] = serde_json::Value::String(CANARY.to_owned());
    let stored = StoredResponse::stage(&fixture_evidence(), &tampered, &fixture_policy());
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (signature)\n",
    );
}

#[test]
fn verify_reports_only_the_generic_policy_class_for_a_wrong_expected_nonce() {
    let policy = fixture_policy().replacen(FIXTURE_NONCE, CANARY_NONCE, 1);
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (policy)\n",
    );
}

#[test]
fn verify_rejects_a_policy_document_with_an_unknown_field() {
    let policy = format!("{}unknownField: {CANARY}\n", fixture_policy());
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "",
        "evidence: stored response verification failed (malformed)\n",
    );
}

#[test]
fn verify_rejects_a_verification_instant_that_is_not_strict_utc() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());

    for at in ["2026-08-02T12:00:00+02:00", "2026-08-02", CANARY] {
        let output = stored.verify(Some(at));
        assert_eq!(output.status.code(), Some(1), "verify accepted {at:?}");
        assert!(
            output.stdout.is_empty(),
            "verify printed an unusable instant"
        );
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            stderr, "evidence: verification instant is not strict RFC 3339 UTC\n",
            "unexpected verification diagnostic"
        );
    }
}

#[test]
fn verify_accepts_an_authentic_and_current_stored_sd_jwt_vc() {
    let stored = StoredCredential::stage(&fixture_policy(), |credential| credential);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(0),
        "verify rejected a good credential"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.contains("authentic: yes\n") && stdout.contains("currently-valid: yes\n"),
        "verify did not report the credential as authentic and current"
    );
    assert!(
        stdout.contains("urn:example:concept"),
        "verify did not print the rebuilt Evidence for inspection"
    );
}

#[test]
fn verify_rejects_a_stored_sd_jwt_vc_whose_disclosure_was_replaced() {
    // Substitute a well-formed disclosure of the same claim with the opposite
    // value. Its digest is absent from the signed `_sd`, so the credential
    // fails without the signature itself being touched.
    let stored = StoredCredential::stage(&fixture_policy(), |credential| {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let body = credential
            .strip_suffix('~')
            .expect("the credential ends with the key-binding terminator");
        let (jwt, disclosure) = body.split_once('~').expect("the credential discloses");
        let decoded: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(disclosure)
                .expect("disclosure decodes"),
        )
        .expect("disclosure parses");
        let replaced = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!([decoded[0], decoded[1], true]))
                .expect("disclosure serializes"),
        );
        format!("{jwt}~{replaced}~")
    });
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (disclosure)\n",
    );
}

#[test]
fn verify_requires_exactly_one_stored_response_format() {
    let stored = StoredCredential::stage(&fixture_policy(), |credential| credential);
    for arguments in [
        vec![],
        vec![
            "--jws".to_owned(),
            stored.path("response.sd-jwt").display().to_string(),
            "--sd-jwt-vc".to_owned(),
            stored.path("response.sd-jwt").display().to_string(),
        ],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .args(&arguments)
            .arg("--jwks")
            .arg(stored.path("trusted.jwks.json"))
            .arg("--policy")
            .arg(stored.path("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        let output = command.output().expect("evidence binary starts");
        assert_eq!(
            output.status.code(),
            Some(2),
            "verify accepted an ambiguous stored-response selection"
        );
        assert!(
            output.stdout.is_empty(),
            "verify began before selecting a stored response"
        );
    }
}

/// Assert one closed verification failure: exit 1, the chosen instant, the
/// expected remaining stdout, only the closed class on stderr, and no leaked
/// document value on either stream.
fn assert_verification_failure(
    output: &Output,
    instant: &str,
    remaining_stdout: &str,
    stderr: &str,
) {
    assert_eq!(output.status.code(), Some(1), "verify accepted a bad input");
    let printed_out = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let printed_err = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert_eq!(
        printed_out,
        format!("verified-at: {instant}\n{remaining_stdout}"),
        "unexpected verification output"
    );
    assert_eq!(printed_err, stderr, "unexpected verification diagnostic");
    assert!(
        !printed_out.contains(CANARY) && !printed_err.contains(CANARY),
        "verification disclosed a document value"
    );
}

/// The stored Evidence payload the verify tests sign and re-verify.
fn fixture_evidence() -> serde_json::Value {
    serde_json::json!({
        "schema": "registry.assertion-evidence/v1",
        "requestNonce": FIXTURE_NONCE,
        "id": "urn:ulid:01K1EXAMPLE0000000000000000",
        "type": "Evidence",
        "supportsRequirement": "urn:example:requirement:v1",
        "isConformantTo": "urn:example:type:v1",
        "issuedBy": "urn:example:issuer",
        "providedBy": "urn:example:provider",
        "issuedAt": "2026-08-02T00:00:00Z",
        "observedAt": "2026-08-02T00:00:00Z",
        "validUntil": "2026-08-03T00:00:00Z",
        "purpose": "casework",
        "audience": "urn:example:audience",
        "configurationRevision": format!("sha256:{}", "0".repeat(64)),
        "subjects": [{"role": "subject", "binding": format!("urn:evidence:subject:v1_{}", "A".repeat(43))}],
        "supportedValues": [{"providesValueFor": "urn:example:concept", "value": false}],
    })
}

/// The relying-procedure policy matching that payload.
///
/// A real relying party builds this from independently retained trusted state.
/// The test simulates that state from the fixture it controls.
fn fixture_policy() -> String {
    format!(
        "issuedBy: urn:example:issuer
providedBy: urn:example:provider
requirement: urn:example:requirement:v1
evidenceType: urn:example:type:v1
purpose: casework
audience: urn:example:audience
configurationRevision: sha256:{revision}
requestNonce: {FIXTURE_NONCE}
expectedSubjects:
  - role: subject
    binding: urn:evidence:subject:v1_{binding}
expectedOutputs:
  - concept: urn:example:concept
    form: boolean
maximumAssertionLifetimeSeconds: 172800
clockSkewSeconds: 30
",
        revision = "0".repeat(64),
        binding = "A".repeat(43),
    )
}

/// The three files an operator holds for offline re-verification: one stored
/// signed response, one pinned trusted key set, and one policy document.
struct StoredResponse {
    root: tempfile::TempDir,
}

impl StoredResponse {
    /// Sign `signed`, store `stored` as the response payload, and stage
    /// `policy`. Passing different payloads produces a tampered response whose
    /// signature no longer covers the stored bytes.
    fn stage(signed: &serde_json::Value, stored: &serde_json::Value, policy: &str) -> Self {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use ed25519_dalek::Signer as _;

        let root = tempfile::tempdir().expect("temporary verification inputs");
        let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let protected = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"alg":"EdDSA","kid":"{VERIFY_KEY_ID}","typ":"evidence+jws","cty":"application/evidence+json"}}"#
        ));
        let signed_payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(signed).expect("Evidence payload serializes"));
        let signature = URL_SAFE_NO_PAD.encode(
            key.sign(format!("{protected}.{signed_payload}").as_bytes())
                .to_bytes(),
        );
        let stored_payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(stored).expect("Evidence payload serializes"));

        fs::write(
            root.path().join("response.jws.json"),
            format!(
                r#"{{"protected":"{protected}","payload":"{stored_payload}","signature":"{signature}"}}"#
            ),
        )
        .expect("stage the stored response");
        fs::write(
            root.path().join("trusted.jwks.json"),
            format!(
                r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"{VERIFY_KEY_ID}","x":"{}"}}]}}"#,
                URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
            ),
        )
        .expect("stage the pinned key set");
        fs::write(root.path().join("policy.yaml"), policy).expect("stage the policy");
        Self { root }
    }

    /// Run `verify` with no runtime file staged, so the command proves it needs
    /// no deployment and opens no socket.
    fn verify(&self, at: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .arg("--jws")
            .arg(self.root.path().join("response.jws.json"))
            .arg("--jwks")
            .arg(self.root.path().join("trusted.jwks.json"))
            .arg("--policy")
            .arg(self.root.path().join("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        if let Some(at) = at {
            command.arg("--at").arg(at);
        }
        command.output().expect("evidence binary starts")
    }
}

/// The SD-JWT VC counterpart of `StoredResponse`. The same assertion is
/// serialized through the production issuance path, so the command is proven
/// against the bytes an adopter actually receives rather than a hand-built
/// approximation.
struct StoredCredential {
    root: tempfile::TempDir,
}

impl StoredCredential {
    /// Issue the fixture assertion, apply `mutate` to the serialization, and
    /// stage it beside the pinned key set and the policy.
    fn stage(policy: &str, mutate: impl FnOnce(String) -> String) -> Self {
        use registry_evidence::{
            model::Evidence,
            sdjwt_vc::issuance_input,
            signing::{jwks_document, EvidenceSigner},
        };
        use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
        use std::sync::Arc;

        let root = tempfile::tempdir().expect("temporary verification inputs");
        let evidence: Evidence =
            serde_json::from_value(fixture_evidence()).expect("the fixture is an Evidence payload");
        let private = PrivateJwk::parse(VERIFY_PRIVATE_JWK).expect("fixture key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("fixture signer builds"));

        let (credential, trusted) = tokio::runtime::Runtime::new()
            .expect("issuance runtime starts")
            .block_on(async {
                let signer = EvidenceSigner::initialize(provider, VERIFY_KEY_ID)
                    .await
                    .expect("signer initializes");
                let input = issuance_input(&evidence, None).expect("the fixture maps");
                let credential = signer
                    .sign_sd_jwt_vc(input)
                    .await
                    .expect("credential serializes");
                let trusted = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
                (credential, trusted)
            });

        fs::write(root.path().join("response.sd-jwt"), mutate(credential))
            .expect("stage the stored credential");
        fs::write(
            root.path().join("trusted.jwks.json"),
            serde_json::to_vec(&trusted).expect("JWKS serializes"),
        )
        .expect("stage the pinned key set");
        fs::write(root.path().join("policy.yaml"), policy).expect("stage the policy");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn verify(&self, at: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .arg("--sd-jwt-vc")
            .arg(self.path("response.sd-jwt"))
            .arg("--jwks")
            .arg(self.path("trusted.jwks.json"))
            .arg("--policy")
            .arg(self.path("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        if let Some(at) = at {
            command.arg("--at").arg(at);
        }
        command.output().expect("evidence binary starts")
    }
}

fn stop(service: &mut Child) {
    let pid = rustix::process::Pid::from_raw(
        i32::try_from(service.id()).expect("child identifier is a pid"),
    )
    .expect("child identifier is a pid");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("send SIGTERM");
    let status = service.wait().expect("service exits");
    assert!(
        status.success(),
        "SIGTERM did not stop the service cleanly: {status}"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a local port")
        .local_addr()
        .expect("reserved port")
        .port()
}

/// Poll `/ready` until the service reports a healthy audit chain.
///
/// Readiness covers the subject-binding key, the signer, the audit chain head,
/// and every source credential, so a ready service proves the whole startup
/// path completed rather than only that a socket is open.
fn wait_until_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = String::new();
    while Instant::now() < deadline {
        if let Some(status) = probe(port, "/ready") {
            if status == "HTTP/1.1 200 OK" {
                return;
            }
            last = status;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the service never became ready (last status {last:?})");
}

fn probe(port: u16, path: &str) -> Option<String> {
    use std::io::{BufRead as _, BufReader, Write as _};

    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut status = String::new();
    BufReader::new(stream).read_line(&mut status).ok()?;
    Some(status.trim_end().to_owned())
}

/// A staged deployment: one acceptance bundle, one operator runtime file, and
/// one private secret root under a single temporary directory.
struct Deployment {
    root: tempfile::TempDir,
    port: u16,
}

impl Deployment {
    fn stage(case: &str) -> Self {
        Self::stage_on_port(case, 8080)
    }

    fn stage_on_port(case: &str, port: u16) -> Self {
        let deployment = Self {
            root: tempfile::tempdir().expect("temporary deployment"),
            port,
        };
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance")
            .join(case);
        copy_tree(&source, &deployment.path("bundle"));
        let secrets = deployment.path("secrets");
        fs::create_dir(&secrets).expect("create private secret root");
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
            .expect("set private secret-root mode");
        fs::write(
            deployment.path("runtime.yaml"),
            deployment.runtime_document(),
        )
        .expect("stage runtime");
        deployment
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn runtime_document(&self) -> String {
        format!(
            "version: 1
bundleDirectory: {bundle}
listener:
  bindHost: 127.0.0.1
  port: {port}
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 5000
secretProviders:
  file:
    root: {secrets}
auditStorage:
  path: {audit}
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
",
            bundle = self.path("bundle").display(),
            port = self.port,
            secrets = self.path("secrets").display(),
            audit = self.path("audit.jsonl").display(),
        )
    }

    fn write(&self, relative: &str, contents: &str) {
        fs::write(self.path(relative), contents).expect("write staged artifact");
    }

    fn append(&self, relative: &str, contents: &str) {
        let path = self.path(relative);
        let mut text = fs::read_to_string(&path).expect("read staged artifact");
        text.push_str(contents);
        fs::write(path, text).expect("write staged artifact");
    }

    fn remove(&self, relative: &str) {
        fs::remove_file(self.path(relative)).expect("remove staged artifact");
    }

    fn replace(&self, relative: &str, from: &str, to: &str) {
        let path = self.path(relative);
        let text = fs::read_to_string(&path).expect("read staged artifact");
        assert!(text.contains(from), "staged artifact has no {from:?}");
        fs::write(path, text.replacen(from, to, 1)).expect("write staged artifact");
    }

    fn replace_line(&self, relative: &str, prefix: &str, line: &str) {
        let path = self.path(relative);
        let text = fs::read_to_string(&path).expect("read staged artifact");
        let replaced = text
            .lines()
            .map(|current| {
                if current.starts_with(prefix) {
                    line.to_owned()
                } else {
                    format!("{current}\n")
                }
            })
            .collect::<String>();
        assert_ne!(replaced, text, "staged artifact has no {prefix:?} line");
        fs::write(path, replaced).expect("write staged artifact");
    }

    fn write_secret(&self, name: &str, value: &str) {
        let path = self.path("secrets").join(name);
        fs::write(&path, value).expect("write staged secret");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set owner-only secret mode");
    }

    /// Stage every logical secret the acceptance bundle references.
    ///
    /// The signing key is generated for this run so no private key material is
    /// tracked, and the source credentials are synthetic constants that never
    /// reach a network because the test performs no evidence request.
    fn stage_acceptance_secrets(&self) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let private_jwk = format!(
            r#"{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"fixture-key-2026-01","d":"{}","x":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
            URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes())
        );
        self.write_secret("audit-hash-key", "audit-hash-secret-32-bytes-minimum-value");
        self.write_secret(
            "subject-binding-key",
            "subject-binding-secret-32-bytes-minimum-value",
        );
        self.write_secret("signing-key", &private_jwk);
        self.write_secret("source-a-token", "synthetic-source-token");
        self.write_secret("source-b-token", "synthetic-source-token");
        self.write_secret("source-c-username", "synthetic-source-user");
        self.write_secret("source-c-password", "synthetic-source-password");
        self.write_secret("source-d-token", "synthetic-source-token");
    }

    /// Start `serve` against the sealed deployment.
    fn serve(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_evidence"))
            .arg("--runtime")
            .arg(self.path("runtime.yaml"))
            .arg("serve")
            .env_remove("REGISTRY_EVIDENCE_RUNTIME")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("evidence service starts")
    }

    /// Run `check` against the sealed deployment, then restore write access so
    /// the temporary directory can be cleaned up.
    fn check(&self) -> Output {
        self.seal();
        let output = invoke(&self.path("runtime.yaml"), &["check"]);
        self.unseal();
        output
    }

    fn seal(&self) {
        set_tree_mode(&self.path("bundle"), 0o555, 0o444);
        fs::set_permissions(self.path("runtime.yaml"), fs::Permissions::from_mode(0o444))
            .expect("seal runtime");
    }

    fn unseal(&self) {
        set_tree_mode(&self.path("bundle"), 0o755, 0o644);
        fs::set_permissions(self.path("runtime.yaml"), fs::Permissions::from_mode(0o644))
            .expect("unseal runtime");
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if self.path("bundle").is_dir() {
            set_tree_mode(&self.path("bundle"), 0o755, 0o644);
        }
    }
}

fn invoke(runtime: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidence"))
        .arg("--runtime")
        .arg(runtime)
        .args(arguments)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .expect("evidence binary starts")
}

fn assert_success(output: &Output, prefix: &str, suffix: &str) {
    assert!(output.status.success(), "evidence command failed");
    assert!(
        output.stderr.is_empty(),
        "evidence command wrote diagnostics"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with(prefix) && stdout.ends_with(suffix),
        "evidence command output shape changed"
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create staged directory");
    for entry in fs::read_dir(source).expect("read source tree") {
        let entry = entry.expect("source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("source entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy staged artifact");
        }
    }
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    let metadata = fs::symlink_metadata(path).expect("staged path metadata");
    if metadata.is_dir() {
        for entry in fs::read_dir(path).expect("read staged tree") {
            set_tree_mode(
                &entry.expect("staged entry").path(),
                directory_mode,
                file_mode,
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("set staged directory mode");
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .expect("set staged file mode");
    }
}
