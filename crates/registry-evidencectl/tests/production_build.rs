#![cfg(unix)]

//! Production-build filesystem and delegation invariants.
//!
//! These tests deliberately replace the sibling `evidence` binary with a
//! value-free recorder. They pin the adopter tool's responsibilities without
//! copying bundle or fixture semantics out of the runtime.

use serde_json::{json, Value};

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{symlink, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LOCAL_URI: &str = "urn:registrystack:evidence:local:forbidden";
const SECRET_CANARY: &str = "production-build-secret-canary";
const CHECK_DIAGNOSTIC: &str =
    "evidence bundle-check diagnostic: derivations/answer.rhai failed static compilation";

/// `build` is not a command: it is refused as any unknown command is, before
/// a project is read or an output is created.
#[test]
fn build_is_an_unknown_command_and_creates_no_output() {
    let fixture = Fixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .arg("build")
        .arg("--project")
        .arg(&fixture.project)
        .arg("--target")
        .arg(&fixture.target)
        .arg("--output")
        .arg(&fixture.output)
        .output()
        .expect("build command line starts");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let message = stderr(&output);
    assert!(message.starts_with("error[evidencectl.usage]"), "{message}");
    assert!(!message.contains("evidence.build.retired"), "{message}");
    assert!(!fixture.output.exists());
    assert!(fixture.invocations().is_empty());
}

#[test]
fn build_is_create_only_and_never_changes_an_existing_output() {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.output).expect("existing output");
    fs::write(fixture.output.join("owned.txt"), "preserve me\n").expect("existing file");

    let output = fixture.build();

    assert_failed(&output, "existing output must be refused");
    assert_eq!(
        fs::read_to_string(fixture.output.join("owned.txt")).unwrap(),
        "preserve me\n"
    );
    assert!(fixture.invocations().is_empty());
    fixture.assert_no_staging_residue();
}

#[test]
fn build_rejects_output_inside_the_editable_project_without_modifying_it() {
    let fixture = Fixture::new();
    let candidate = fixture.project.join("candidate");
    let before = snapshot(&fixture.project);

    let output = fixture.build_with(&fixture.project, &fixture.target, &candidate);

    assert_failed(&output, "project-contained output must be refused");
    assert!(!candidate.exists());
    assert_eq!(snapshot(&fixture.project), before);
    assert!(fixture.invocations().is_empty());
    fixture.assert_no_staging_residue();
}

#[test]
fn build_rejects_symlinked_project_target_output_parent_and_artifact() {
    for boundary in ["project", "target", "output-parent", "artifact"] {
        let fixture = Fixture::new();
        let mut project = fixture.project.clone();
        let mut target = fixture.target.clone();
        let mut output = fixture.output.clone();
        match boundary {
            "project" => {
                project = fixture.root.join("project-link");
                symlink(&fixture.project, &project).expect("project symlink");
            }
            "target" => {
                target = fixture.root.join("target-link");
                symlink(&fixture.target, &target).expect("target symlink");
            }
            "output-parent" => {
                let actual = fixture.root.join("actual-output-parent");
                fs::create_dir(&actual).expect("actual output parent");
                let linked = fixture.root.join("linked-output-parent");
                symlink(&actual, &linked).expect("output parent symlink");
                output = linked.join("candidate");
            }
            "artifact" => {
                let derivation = fixture.project.join("functions/answer.rhai");
                fs::remove_file(&derivation).expect("remove regular derivation");
                let outside = fixture.root.join("outside.rhai");
                fs::write(&outside, "fn derive(facts, selectors, context) { [#{output: \"allowed\", value: true}] }\n")
                    .expect("outside derivation");
                symlink(outside, derivation).expect("artifact symlink");
            }
            _ => unreachable!(),
        }

        let result = fixture.build_with(&project, &target, &output);
        assert_failed(&result, boundary);
        assert!(!output.exists(), "{boundary} published an output");
        assert!(
            fixture.invocations().is_empty(),
            "{boundary} reached Evidence"
        );
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn failed_runtime_check_leaves_no_output_or_private_staging() {
    let fixture = Fixture::new();

    let output = fixture.build_failing("check");

    assert_failed(&output, "runtime rejection must fail the build");
    assert!(!fixture.output.exists());
    fixture.assert_no_staging_residue();
    assert_eq!(fixture.steps(), ["check"]);
    assert_value_free(&output);
}

#[test]
fn a_rejected_bundle_and_fixture_name_the_command_that_shows_the_diagnosis() {
    let rejected_bundle = Fixture::new();

    let output = rejected_bundle.build_failing("check");

    assert_failed(&output, "a rejected bundle must fail the build");
    let message = stderr(&output);
    assert!(
        message.contains("evidence.package.failed"),
        "the package refusal keeps its stable safe diagnostic: {message}"
    );
    assert!(
        !message.contains(CHECK_DIAGNOSTIC),
        "the package refusal does not relay delegated stderr: {message}"
    );
    assert_value_free(&output);

    let rejected_fixture = Fixture::new();

    let output = rejected_fixture.build_failing("fixture:fixtures/answer.yaml");

    assert_failed(&output, "a rejected fixture must fail the build");
    let message = stderr(&output);
    assert!(
        message.contains("evidence.package.failed"),
        "the package refusal keeps its stable safe diagnostic: {message}"
    );
    assert!(
        !message.contains("Evidence reported:"),
        "a rejected fixture's own diagnosis is not relayed here: {message}"
    );
    assert_value_free(&output);
}

#[test]
fn a_long_bundle_check_diagnostic_is_bounded_and_says_so() {
    let fixture = Fixture::new();

    let output = fixture.build_failing("check-overflow");

    assert_failed(&output, "a long rejected bundle must still fail the build");
    let message = stderr(&output);
    assert!(
        message.contains("evidence.package.failed"),
        "a long delegated diagnostic maps to the stable safe refusal: {message}"
    );
    assert!(
        !message.contains("evidence bundle-check diagnostic line"),
        "delegated stderr is not relayed by package: {message}"
    );
}

#[test]
fn a_mismatched_evidence_binary_is_refused_before_any_step() {
    let fixture = Fixture::new();

    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env("FAKE_EVIDENCE_VERSION", "0.0.0-other")
        .output()
        .expect("evidencectl build starts");

    assert_failed(&output, "a mismatched evidence binary must fail the build");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0.0.0-other"),
        "the refusal names the reported version: {stderr}"
    );
    assert!(
        stderr.contains(registry_platform_buildinfo::DISPLAY_VERSION),
        "the refusal names this build: {stderr}"
    );
    assert!(!fixture.output.exists());
    assert!(
        fixture.invocations().is_empty(),
        "a mismatched binary was handed work"
    );
    fixture.assert_no_staging_residue();
}

#[test]
fn an_evidence_binary_that_does_not_identify_itself_is_refused_before_any_step() {
    let fixture = Fixture::new();

    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env("FAKE_EVIDENCE_VERSION", "")
        .output()
        .expect("evidencectl build starts");

    assert_failed(
        &output,
        "an unidentified evidence binary must fail the build",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did not report an Evidence runtime version"),
        "the refusal names what was missing: {stderr}"
    );
    assert!(!fixture.output.exists());
    assert!(
        fixture.invocations().is_empty(),
        "an unidentified binary was handed work"
    );
    fixture.assert_no_staging_residue();
}

#[test]
fn successful_package_excludes_runtime_local_state_and_validation_secrets() {
    let fixture = Fixture::new();
    let local = fixture.project.join(".evidence/dev");
    fs::create_dir_all(&local).expect("local state");
    fs::write(local.join("disposable-private-key"), SECRET_CANARY).expect("local secret");
    let output = fixture.build();

    assert_success(&output, "production package");
    let snapshot = snapshot(&fixture.output);
    assert_eq!(
        snapshot.keys().cloned().collect::<Vec<_>>(),
        vec![
            PathBuf::from("bundle/SHA256SUMS"),
            PathBuf::from("bundle/adapters/functions/source-extract.rhai"),
            PathBuf::from("bundle/adapters/functions/source-prepare.rhai"),
            PathBuf::from("bundle/catalog.jsonld"),
            PathBuf::from("bundle/derivations/answer.rhai"),
            PathBuf::from("bundle/evidence.yaml"),
            PathBuf::from("bundle/fixtures/answer.yaml"),
            PathBuf::from(
                "bundle/public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json"
            ),
            PathBuf::from("bundle/schemas/source-facts/registry.schema.json"),
            PathBuf::from("bundle/schemas/source-parameters/registry.schema.json"),
            PathBuf::from("bundle/schemas/source-response/registry.schema.json"),
            PathBuf::from("compiled-authority.yaml"),
            PathBuf::from("runtime.yaml"),
        ]
    );
    for (path, bytes) in snapshot {
        assert!(
            !bytes
                .windows(SECRET_CANARY.len())
                .any(|part| part == SECRET_CANARY.as_bytes()),
            "{} contains local secret material",
            path.display()
        );
        assert!(!path.to_string_lossy().contains("validation"));
    }
    fixture.assert_no_staging_residue();
}

#[test]
fn an_empty_publication_description_leaves_no_candidate() {
    let fixture = Fixture::new();
    fixture.declare_publication();

    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env("FAKE_EVIDENCE_EMPTY_DESCRIPTION", "1")
        .output()
        .expect("evidencectl build starts");

    assert_failed(
        &output,
        "an empty publication description must fail the build",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("evidence.package.failed"),
        "the refusal uses the stable package diagnostic: {stderr}"
    );
    assert!(!fixture.output.exists());
    fixture.assert_no_staging_residue();
}

#[test]
fn a_bundle_without_publication_carries_no_catalog_description() {
    let fixture = Fixture::new();

    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env("FAKE_EVIDENCE_EMPTY_DESCRIPTION", "1")
        .output()
        .expect("evidencectl build starts");

    assert_success(&output, "build of a bundle that declares no publication");
    assert!(!fixture.output.join("bundle/catalog.jsonld").exists());
    fixture.assert_no_staging_residue();
}

#[test]
fn package_accepts_local_targets_with_the_same_complete_grant_model() {
    for format in ["human", "json"] {
        let fixture = Fixture::new();
        edit_json(&fixture.target, |target| {
            target["assuranceProfile"] = json!("local");
            target["connections"]["registry-http"]["origin"] = json!("http://127.0.0.1:8088");
            target["connections"]["registry-http"]["authentication"] = json!({"type":"none"});
        });
        let output = fixture.package(format);
        assert_success(&output, "local candidate with explicit grants");
        assert!(fixture.output.join("bundle/evidence.yaml").is_file());
        assert!(fixture.output.join("compiled-authority.yaml").is_file());
        assert!(fixture.output.join("runtime.yaml").is_file());
        assert_eq!(fixture.steps(), ["check", "evaluate:fixtures/answer.yaml"]);
        assert_value_free(&output);
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn provisioning_reports_the_bundle_and_runtime_secret_union_once() {
    let expected = [
        "audit-hmac-key",
        "signing-p256-private-jwk",
        "source-token",
        "subject-binding-hmac-key",
    ];
    for format in ["human", "json"] {
        let fixture = Fixture::new();
        fixture.use_default_local_signer();
        edit_json(&fixture.target, |target| {
            target["connections"]["registry-http"]["authentication"] =
                json!({"type":"bearer","tokenRef":"secret:file/source-token"});
        });

        let output = fixture.package(format);

        assert_success(&output, "local package provisioning report");
        assert_value_free(&output);
        if format == "json" {
            let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
            assert_eq!(
                report["requiredSecrets"],
                json!(expected),
                "the JSON report must include the exact sorted union"
            );
        } else {
            let stdout = String::from_utf8(output.stdout).expect("human report");
            let reported = stdout
                .lines()
                .filter_map(|line| line.strip_prefix("Provision secret:file/"))
                .collect::<Vec<_>>();
            assert_eq!(reported, expected);
        }
    }
}

#[test]
fn target_check_and_package_refuse_runtime_mismatches_at_the_authored_location() {
    for command in ["check", "package"] {
        let fixture = Fixture::new();
        edit_json(&fixture.target, |target| {
            target["listener"]["trustProxyIdentityHeaders"] = json!(true);
        });

        let output = if command == "check" {
            fixture.check_production("json")
        } else {
            fixture.package("json")
        };

        assert_failed(&output, "invalid target listener");
        assert_value_free(&output);
        assert!(!fixture.output.exists());
        let report: Value = serde_json::from_slice(&output.stdout).expect("JSON refusal report");
        let diagnostic = report["diagnostics"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item["code"] == "evidence.runtime.invalid-listener")
            })
            .unwrap_or_else(|| panic!("{command}: missing listener diagnostic: {report}"));
        assert_eq!(diagnostic["path"], "/listener/trustProxyIdentityHeaders");
        assert!(diagnostic["source"]["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("production-target/target.yaml")));
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn runtime_refusal_at_the_authored_location_precedes_secret_reference_syntax() {
    for command in ["check", "package"] {
        let fixture = Fixture::new();
        edit_json(&fixture.target, |target| {
            target["listener"]["trustProxyIdentityHeaders"] = json!(true);
            target["signer"]["keyName"] = json!("secret:file/Bad");
        });

        let output = if command == "check" {
            fixture.check_production("json")
        } else {
            fixture.package("json")
        };

        assert_failed(
            &output,
            "invalid listener with a malformed secret reference",
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!(
                "{command}: expected a JSON refusal report: {}",
                stderr(&output)
            )
        });
        assert!(
            report["diagnostics"].as_array().is_some_and(|items| items
                .iter()
                .any(|item| item["code"] == "evidence.runtime.invalid-listener")),
            "{command}: the authored runtime diagnostic must win: {report}"
        );
    }
}

#[test]
fn local_target_bootstrap_generates_matching_keys_and_repairs_only_the_public_half() {
    let fixture = Fixture::new();
    fixture.use_default_local_signer();
    let secrets = fixture.target.parent().unwrap().join(".generated/secrets");
    let private_path = secrets.join("signing-p256-private-jwk");
    let public_path = secrets.join("signing-p256-public.jwk.json");

    assert_success(&fixture.package("json"), "default local signing bootstrap");
    let private_bytes = fs::read(&private_path).expect("generated private key");
    let public_bytes = fs::read(&public_path).expect("generated public key");
    let private =
        registry_platform_crypto::PrivateJwk::parse(std::str::from_utf8(&private_bytes).unwrap())
            .expect("generated local private key parses");
    let public =
        registry_platform_crypto::PublicJwk::parse(std::str::from_utf8(&public_bytes).unwrap())
            .expect("generated local public key parses");
    assert!(
        private.public() == public,
        "generated signing halves must match"
    );
    assert_eq!(
        fs::metadata(&secrets).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&private_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    fs::remove_file(&public_path).expect("remove recoverable public half");
    assert_success(
        &fixture.package_to("json", &fixture.root.join("repaired-candidate")),
        "repair public half from the existing private key",
    );
    assert!(
        fs::read(&private_path).unwrap() == private_bytes,
        "private key was replaced"
    );
    assert!(
        registry_platform_crypto::PublicJwk::parse(&fs::read_to_string(&public_path).unwrap())
            .unwrap()
            == public,
        "public half was not recovered"
    );
}

#[test]
fn local_target_bootstrap_refuses_symlinked_ancestors_before_writes_or_chmod() {
    for boundary in [".generated", ".generated/secrets"] {
        for repair in [false, true] {
            let fixture = Fixture::new();
            fixture.use_default_local_signer();
            let target_root = fixture.target.parent().unwrap();
            let outside = fixture.root.join("outside");
            let outside_secrets = if boundary == ".generated" {
                outside.join("secrets")
            } else {
                outside.clone()
            };
            fs::create_dir_all(&outside_secrets).expect("outside secret directory");
            if repair {
                let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
                    .args(["keygen", "signing", "--output-dir"])
                    .arg(&outside_secrets)
                    .output()
                    .expect("seed existing local key");
                assert_success(&output, "seed local signing key");
                fs::remove_file(outside_secrets.join("signing-p256-public.jwk.json"))
                    .expect("remove public half");
            }
            fs::write(outside_secrets.join("sentinel"), b"preserve outside data")
                .expect("outside sentinel");
            fs::set_permissions(&outside_secrets, fs::Permissions::from_mode(0o750))
                .expect("outside directory mode");
            let before = snapshot(&outside);
            if boundary == ".generated/secrets" {
                fs::create_dir(target_root.join(".generated")).expect("generated parent");
            }
            symlink(&outside, target_root.join(boundary)).expect("generated ancestor link");

            let output = fixture.package("json");

            assert_failed(&output, "linked local signing ancestor");
            assert!(snapshot(&outside) == before, "outside files changed");
            assert_eq!(
                fs::metadata(&outside_secrets).unwrap().permissions().mode() & 0o777,
                0o750
            );
            assert!(target_root.join(boundary).is_symlink());
            assert!(fixture.invocations().is_empty());
            assert!(!fixture.output.exists());
            fixture.assert_no_staging_residue();
        }
    }
}

#[test]
fn local_target_bootstrap_refuses_bindings_that_cannot_use_the_generated_key() {
    for mismatch in [
        "private-file",
        "private-environment",
        "file-root",
        "missing-file-provider",
        "transit",
    ] {
        let fixture = Fixture::new();
        fixture.use_default_local_signer();
        edit_json(&fixture.target, |target| match mismatch {
            "private-file" => {
                target["signer"]["privateKeyRef"] = json!("secret:file/custom-signing")
            }
            "private-environment" => {
                target["signer"]["privateKeyRef"] = json!("secret:env/SIGNING_KEY")
            }
            "file-root" => target["secretProviders"]["file"]["root"] = json!("custom-secrets"),
            "missing-file-provider" => target["secretProviders"] = json!({}),
            "transit" => {
                target["signer"] = target_document()["signer"].clone();
                target["signer"]["publicJwkFile"] =
                    json!(".generated/secrets/signing-p256-public.jwk.json");
            }
            _ => unreachable!(),
        });

        let output = fixture.package("json");

        assert_failed(&output, mismatch);
        let report: Value = serde_json::from_slice(&output.stdout).expect("JSON refusal report");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "evidence.target.signing-key-missing"
        );
        assert!(report["diagnostics"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("target.yaml:/signer/publicJwkFile"));
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("provide the matching public JWK"));
        assert!(
            !fixture.target.parent().unwrap().join(".generated").exists(),
            "{mismatch} generated unused keys"
        );
        assert!(fixture.invocations().is_empty());
        assert!(!fixture.output.exists());
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn local_target_creation_refuses_a_symlinked_generated_parent_before_key_generation() {
    let fixture = Fixture::new();
    let outside = fixture.root.join("outside");
    fs::create_dir(&outside).expect("outside directory");
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o750)).expect("outside mode");
    symlink(&outside, fixture.project.join(".generated")).expect("generated parent link");
    let destination = fixture.root.join("local-target");

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["target", "new"])
        .arg(&destination)
        .arg("--local")
        .arg("--project")
        .arg(&fixture.project)
        .output()
        .expect("create local target");

    assert_failed(&output, "linked generated parent during target creation");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert!(!destination.exists());
}

#[test]
fn local_target_preserves_explicit_matching_custom_signing_material() {
    let fixture = Fixture::new();
    fixture.use_default_local_signer();
    let target_root = fixture.target.parent().unwrap();
    let secrets = target_root.join("custom-secrets");
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["keygen", "signing", "--output-dir"])
        .arg(&secrets)
        .arg("--public-output")
        .arg(target_root.join("public-keys/custom.jwk.json"))
        .output()
        .expect("custom signing key");
    assert_success(&output, "explicit custom signing key");
    fs::rename(
        secrets.join("signing-p256-private-jwk"),
        secrets.join("custom-signing"),
    )
    .expect("custom private key name");
    edit_json(&fixture.target, |target| {
        target["signer"]["privateKeyRef"] = json!("secret:file/custom-signing");
        target["signer"]["publicJwkFile"] = json!("public-keys/custom.jwk.json");
        target["secretProviders"]["file"]["root"] = json!("custom-secrets");
    });

    assert_success(&fixture.package("json"), "explicit custom signing binding");

    let runtime = registry_platform_yaml::Reader::new("runtime.yaml")
        .scan(&fs::read(fixture.output.join("runtime.yaml")).unwrap())
        .unwrap()
        .unwrap()
        .to_json_value();
    assert_eq!(
        runtime["signer"]["privateKeyRef"],
        "secret:file/custom-signing"
    );
    assert_eq!(runtime["secretProviders"]["file"]["root"], json!(secrets));
    assert!(!target_root.join(".generated").exists());
}

#[test]
fn local_targets_obey_the_same_create_only_output_boundaries() {
    let fixture = Fixture::new();
    edit_json(&fixture.target, |target| {
        target["assuranceProfile"] = json!("local")
    });
    let existing = fixture.output.with_file_name("existing-candidate");
    fs::create_dir(&existing).expect("existing output");
    fs::write(existing.join("owned.txt"), "preserve me").expect("existing sentinel");
    let outputs = [
        fixture.project.join("dist"),
        existing.clone(),
        fixture.output.with_file_name("missing").join("candidate"),
    ];
    for output in &outputs {
        let result = fixture.package_to("json", output);
        assert_failed(&result, "unsafe local output location");
        assert!(fixture.invocations().is_empty());
    }
    assert!(!fixture.project.join("dist").exists());
    assert_eq!(
        fs::read_to_string(existing.join("owned.txt")).unwrap(),
        "preserve me"
    );
}

#[test]
fn package_accepts_a_stable_package_root_outside_the_output() {
    for format in ["human", "json"] {
        let fixture = Fixture::new();

        let output = fixture.package(format);

        assert_success(&output, "stable package root");
        assert!(fixture.output.join("bundle/evidence.yaml").is_file());
        match format {
            "human" => {
                assert!(stderr(&output).is_empty());
                assert!(String::from_utf8_lossy(&output.stdout).contains("Package digest: sha256:"));
            }
            "json" => {
                assert!(output.stderr.is_empty());
                let report: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("JSON package report");
                assert_eq!(report["status"], "packaged");
                assert!(report["packageDigest"]
                    .as_str()
                    .unwrap()
                    .starts_with("sha256:"));
            }
            _ => unreachable!(),
        }
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn package_refuses_a_package_root_inside_the_output() {
    let fixture = Fixture::new();
    let unstable_package_directory = fixture.output.join("nested").display().to_string();
    edit_json(&fixture.target, |target| {
        target["package"]["root"] = json!(unstable_package_directory)
    });
    let output = fixture.package("human");
    assert_failed(&output, "unstable package root");
    assert!(!fixture.output.exists());
    let message = stderr(&output);
    assert!(
        message.contains("evidence.package.root-unstable"),
        "{message}"
    );
    assert!(message.contains("runtime.yaml:/package/root"), "{message}");
    assert!(!message.contains(&unstable_package_directory), "{message}");
    fixture.assert_no_staging_residue();
}

#[test]
fn sqlite_extract_build_copies_the_statement_without_http_only_artifacts() {
    let fixture = Fixture::new();
    fixture.use_sqlite_source();

    let output = fixture.build();

    assert_success(&output, "SQLite extract production build");
    assert_eq!(
        fs::read_to_string(fixture.output.join("bundle/queries/source.sql")).unwrap(),
        "SELECT :reference <> '' AS allowed;\n"
    );
    assert!(fixture
        .output
        .join("bundle/adapters/functions/source-extract.rhai")
        .is_file());
    assert!(!fixture
        .output
        .join("bundle/adapters/functions/source-prepare.rhai")
        .exists());
    let bundle = registry_platform_yaml::Reader::new("bundle/evidence.yaml")
        .scan(&fs::read(fixture.output.join("bundle/evidence.yaml")).unwrap())
        .expect("compiled bundle")
        .expect("nonempty compiled bundle")
        .to_json_value();
    assert!(bundle["sources"]["registry"]["request"]
        .get("prepareScript")
        .is_none());
    assert!(bundle["sources"]["registry"]["request"]
        .get("adapterParametersSchema")
        .is_none());
    assert_eq!(fixture.steps(), ["check", "evaluate:fixtures/answer.yaml"]);
    fixture.assert_no_staging_residue();
}

#[test]
fn governed_public_keys_are_owned_by_the_complete_deployment_target() {
    let fixture = Fixture::new();
    let relative = Path::new("public-keys/active.jwk.json");
    let target_key = fixture.target.parent().unwrap().join(relative);
    let bytes = fs::read(&target_key).expect("target public key");
    fs::remove_file(&target_key).expect("remove target public key");
    fs::create_dir(fixture.project.join("public-keys")).expect("project public key directory");
    fs::write(fixture.project.join(relative), bytes).expect("misplaced project public key");

    let output = fixture.build();

    assert_failed(&output, "a public key outside the deployment target");
    assert!(!fixture.output.exists());
    assert!(
        fixture.invocations().is_empty(),
        "missing target-owned key must fail before Evidence delegation"
    );
    fixture.assert_no_staging_residue();
}

#[test]
fn a_missing_target_public_key_refuses_packaging_before_delegation() {
    let fixture = Fixture::new();
    fs::remove_file(
        fixture
            .target
            .parent()
            .unwrap()
            .join("public-keys/active.jwk.json"),
    )
    .expect("remove target key");
    let output = fixture.package("json");
    assert_failed(&output, "missing target public key");
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON refusal report");
    assert_eq!(report["ok"], false, "{report}");
    assert!(
        report["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| !diagnostics.is_empty()),
        "{report}"
    );
    assert!(fixture.invocations().is_empty());
    assert!(!fixture.output.exists());
    assert_value_free(&output);
    fixture.assert_no_staging_residue();
}

#[test]
fn a_missing_target_public_key_refuses_production_check_before_delegation() {
    let fixture = Fixture::new();
    fs::remove_file(
        fixture
            .target
            .parent()
            .unwrap()
            .join("public-keys/active.jwk.json"),
    )
    .expect("remove target key");

    let output = fixture.check_production("json");

    assert_failed(&output, "production check with missing target public key");
    assert!(fixture.invocations().is_empty());
    assert_value_free(&output);
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON refusal report");
    assert_eq!(report["status"], "domain-refusal", "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"], "evidence.target.signing-key-missing",
        "{report}"
    );
    assert!(report["diagnostics"][0]["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("target.yaml:/signer/publicJwkFile")));
}

#[test]
fn invalid_target_scalars_refuse_check_and_package_without_effects() {
    for (pointer, invalid) in [
        ("/package/expectedDigest", json!(SECRET_CANARY)),
        ("/service/issuer", json!("relative-issuer")),
        ("/subjectBinding/secretRef", json!(SECRET_CANARY)),
        ("/audit/hashKeyRef", json!("secret:file/../escape")),
        (
            "/connections/registry-http/authentication/tokenRef",
            json!(SECRET_CANARY),
        ),
        ("/assuranceProfile", json!([SECRET_CANARY])),
        ("/service/issuer", json!({"private": SECRET_CANARY})),
    ] {
        let fixture = Fixture::new();
        edit_json(&fixture.target, |target| {
            if pointer == "/package/expectedDigest" {
                target["package"]["expectedDigest"] = json!(invalid);
            } else {
                *target.pointer_mut(pointer).unwrap() = json!(invalid);
            }
        });
        let target_before = fs::read(&fixture.target).unwrap();
        let project_before = snapshot(&fixture.project);
        for format in ["human", "json"] {
            for output in [
                fixture.check_production(format),
                fixture.explain_project(format, &fixture.target),
                fixture.package(format),
            ] {
                assert_failed(&output, "invalid typed target scalar");
                assert_value_free(&output);
                if format == "json" {
                    let report: Value =
                        serde_json::from_slice(&output.stdout).expect("JSON refusal report");
                    let diagnostics = report["diagnostics"].as_array().unwrap();
                    assert!(
                        diagnostics.iter().any(|diagnostic| {
                            let Some(path) = diagnostic["path"].as_str() else {
                                return false;
                            };
                            path == pointer || path.ends_with(&format!("target.yaml:{pointer}"))
                        }),
                        "{report}"
                    );
                }
            }
        }
        assert!(
            fixture.invocations().is_empty(),
            "target syntax must fail before runtime delegation"
        );
        assert!(!fixture.output.exists());
        assert_eq!(fs::read(&fixture.target).unwrap(), target_before);
        assert_eq!(snapshot(&fixture.project), project_before);
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn production_check_refuses_local_assurance_without_creating_local_secrets() {
    let fixture = Fixture::new();
    fixture.use_default_local_signer();
    let target_before = snapshot(fixture.target.parent().unwrap());
    let project_before = snapshot(&fixture.project);

    for format in ["human", "json"] {
        let output = fixture.check_production(format);
        assert_failed(&output, "production check of a local target");
        assert_eq!(output.status.code(), Some(1));
        assert_value_free(&output);
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            diagnostic.contains("--production requires production or evidence-grade"),
            "{diagnostic}"
        );
        if format == "json" {
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                report["diagnostics"][0]["code"],
                "evidence.target.production-assurance-required"
            );
            assert!(report["diagnostics"][0]["path"]
                .as_str()
                .unwrap()
                .ends_with("target.yaml:/assuranceProfile"));
        }
    }

    assert!(fixture.invocations().is_empty());
    assert!(!fixture.output.exists());
    assert_eq!(snapshot(fixture.target.parent().unwrap()), target_before);
    assert_eq!(snapshot(&fixture.project), project_before);
    fixture.assert_no_staging_residue();
}

#[test]
fn unsafe_function_sources_refuse_inspection_before_missing_dependencies() {
    for (source, expected_code) in [
        (
            "missing/../outside.rhai",
            "evidence.project.function-source",
        ),
        ("functions/linked.rhai", "evidence.project.asset-path"),
    ] {
        let fixture = Fixture::new();
        let outside = fixture.root.join("outside.rhai");
        fs::write(&outside, SECRET_CANARY).expect("private asset outside the project");
        if source == "functions/linked.rhai" {
            symlink(&outside, fixture.project.join(source)).expect("linked Function asset");
        }
        edit_json(&fixture.project.join("evidence.yaml"), |project| {
            project["functions"][0]["source"] = json!(source);
            project["functions"][1]["source"] = json!("functions/missing.rhai");
        });
        let project_before = fs::read(fixture.project.join("evidence.yaml")).unwrap();
        for format in ["human", "json"] {
            for output in [
                fixture.check_production(format),
                fixture.explain_project(format, &fixture.target),
            ] {
                assert_failed(
                    &output,
                    "unsafe Function asset with another missing dependency",
                );
                assert_value_free(&output);
                if format == "json" {
                    let report: Value =
                        serde_json::from_slice(&output.stdout).expect("JSON refusal report");
                    assert!(
                        report["diagnostics"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|diagnostic| {
                                diagnostic["code"] == expected_code
                                    && diagnostic["path"] == "/functions/0/source"
                                    && diagnostic["source"]["file"]
                                        .as_str()
                                        .is_some_and(|file| file.ends_with("evidence.yaml"))
                            }),
                        "{report}"
                    );
                }
            }
        }
        assert!(fixture.invocations().is_empty());
        assert!(!fixture.output.exists());
        assert_eq!(fs::read(&outside).unwrap(), SECRET_CANARY.as_bytes());
        assert_eq!(
            fs::read(fixture.project.join("evidence.yaml")).unwrap(),
            project_before
        );
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn target_explain_reports_complete_grants_without_runtime_secret_resolution() {
    let fixture = Fixture::new();
    let output = fixture.explain();
    assert_success(&output, "target grant inspection");
    let report: Value = serde_json::from_slice(&output.stdout).expect("explain JSON report");
    assert_eq!(report["offline"], true, "{report}");
    assert_eq!(report["secretResolution"], false, "{report}");
    assert_eq!(report["target"], "production", "{report}");
    assert_eq!(report["project"], "production-fixture", "{report}");
    assert!(
        report["accessProfiles"]["requester"]["grants"]
            .as_array()
            .is_some_and(|grants| grants.len() == 1),
        "{report}"
    );
    assert!(fixture.invocations().is_empty());
}

#[test]
fn check_and_explain_accept_a_directory_containing_target_yaml() {
    let fixture = Fixture::new();
    let target_directory = fixture.target.parent().expect("target directory");

    let checked = fixture.check_production_with("json", target_directory);
    assert_success(&checked, "production check with target directory");
    assert_value_free(&checked);
    assert_eq!(fixture.steps(), ["check"]);

    let explained = fixture.explain_project_with_target(target_directory);
    assert_success(&explained, "project explain with target directory");
    let report: Value = serde_json::from_slice(&explained.stdout).expect("explain JSON report");
    assert_eq!(report["command"], "explain", "{report}");
    assert!(report["target"]
        .as_str()
        .is_some_and(|target| target.ends_with("target.yaml")));
}

#[test]
fn definition_metadata_and_referenced_fixtures_fail_before_runtime_delegation() {
    for label in [
        "missing-grant-ceiling",
        "missing-stable-concept",
        "missing-fixture",
    ] {
        let fixture = Fixture::new();
        match label {
            "missing-grant-ceiling" => {
                edit_json(&fixture.project.join("evidence.yaml"), |project| {
                    project["assertionDefinitions"]["answer"]
                        .as_object_mut()
                        .unwrap()
                        .remove("grantCeiling");
                })
            }
            "missing-stable-concept" => {
                edit_json(&fixture.project.join("evidence.yaml"), |project| {
                    project["assertionDefinitions"]["answer"]["outputs"]["allowed"]
                        .as_object_mut()
                        .unwrap()
                        .remove("concept");
                })
            }
            "missing-fixture" => fs::remove_file(fixture.project.join("fixtures/answer.yaml"))
                .expect("remove fixture"),
            _ => unreachable!(),
        }
        let output = fixture.build();
        assert_failed(&output, label);
        assert!(!fixture.output.exists());
        assert!(fixture.invocations().is_empty(), "{label} reached Evidence");
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn disposable_local_identifiers_fail_before_runtime_delegation() {
    for field in [
        "/semantics/requirement",
        "/semantics/referenceFrameworks/0",
        "/semantics/evidenceType",
        "/disclosureGuard/families/0",
        "/outputs/allowed/concept",
    ] {
        let fixture = Fixture::new();
        edit_json(&fixture.project.join("evidence.yaml"), |project| {
            *project["assertionDefinitions"]["answer"]
                .pointer_mut(field)
                .expect("semantic field") = json!(LOCAL_URI);
        });
        let output = fixture.build();
        assert_failed(&output, "local identifier");
        assert!(!fixture.output.exists());
        assert!(fixture.invocations().is_empty());
        assert!(!stderr(&output).contains(LOCAL_URI));
    }
}

#[test]
fn plain_http_and_unauthenticated_production_connections_fail_before_runtime_delegation() {
    for field in ["origin", "authentication"] {
        let fixture = Fixture::new();
        edit_json(&fixture.target, |target| {
            target["connections"]["registry-http"][field] = if field == "origin" {
                json!("http://127.0.0.1:8088")
            } else {
                json!({"type":"none"})
            };
        });
        let output = fixture.build();
        assert_failed(&output, "insecure source");
        assert!(!fixture.output.exists());
        assert!(fixture.invocations().is_empty());
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn unresolved_review_markers_and_unknown_target_fields_fail_closed() {
    let marker = Fixture::new();
    fs::write(
        marker.project.join("fixtures/answer.yaml"),
        "fixture: TODO(evidencectl)\n",
    )
    .expect("review marker");
    let marker_output = marker.build();
    assert_failed(&marker_output, "review marker");
    assert!(marker.invocations().is_empty());
    assert!(!marker.output.exists());
    assert_value_free(&marker_output);

    let unknown = Fixture::new();
    edit_json(&unknown.target, |target| {
        target["deploymentGenerator"] = json!("forbidden")
    });
    let unknown_output = unknown.build();
    assert_failed(&unknown_output, "unknown target field");
    assert!(unknown.invocations().is_empty());
    assert!(!unknown.output.exists());
    unknown.assert_no_staging_residue();
}

#[test]
fn package_names_the_file_and_rule_of_an_unresolved_review_marker() {
    for format in ["human", "json"] {
        let fixture = Fixture::new();
        fs::write(
            fixture.project.join("fixtures/answer.yaml"),
            "fixture: TODO(evidencectl)\n",
        )
        .expect("review marker");

        let output = fixture.package(format);

        assert_failed(&output, "review marker");
        assert!(!fixture.output.exists());
        assert!(fixture.invocations().is_empty());
        assert_value_free(&output);
        match format {
            "human" => {
                assert!(output.stdout.is_empty());
                let message = stderr(&output);
                assert!(message.contains("evidence.package.review-marker"));
                assert!(message.contains("bundle/fixtures/answer.yaml"));
                assert!(message.contains("TODO(evidencectl)"));
            }
            "json" => {
                assert!(output.stderr.is_empty());
                let report: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("JSON refusal report");
                assert_eq!(report["status"], "domain-refusal");
                assert_eq!(
                    report["diagnostics"][0]["code"],
                    "evidence.package.review-marker"
                );
                assert_eq!(
                    report["diagnostics"][0]["path"],
                    "bundle/fixtures/answer.yaml"
                );
                let message = report["diagnostics"][0]["message"]
                    .as_str()
                    .expect("diagnostic message");
                assert!(message.contains("TODO(evidencectl)"));
            }
            _ => unreachable!(),
        }
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn check_production_reports_the_same_review_marker_package_would_refuse() {
    let fixture = Fixture::new();
    fs::write(
        fixture.project.join("fixtures/answer.yaml"),
        "fixture: TODO(evidencectl)\n",
    )
    .expect("review marker");

    let output = fixture.check_production("json");

    assert_failed(&output, "check --production review marker");
    assert!(fixture.invocations().is_empty());
    assert_value_free(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON check report");
    assert!(report.get("findings").is_none(), "{report}");
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics list");
    assert!(
        diagnostics.iter().any(
            |diagnostic| diagnostic["code"] == "evidence.package.review-marker"
                && diagnostic["path"] == "bundle/fixtures/answer.yaml"
        ),
        "{report}"
    );
}

#[test]
fn target_naming_another_project_is_refused_before_runtime_delegation() {
    let fixture = Fixture::new();
    edit_json(&fixture.target, |target| {
        target["project"] = json!("another-project")
    });

    let output = fixture.build();

    assert_failed(&output, "the target must bind this project");
    let diagnostic = stderr(&output);
    assert!(
        diagnostic.contains("evidence.target.project"),
        "{diagnostic}"
    );
    assert!(diagnostic.contains("/project"), "{diagnostic}");
    assert!(!fixture.output.exists());
    assert!(fixture.invocations().is_empty());
    fixture.assert_no_staging_residue();
}

#[test]
fn project_replacement_during_description_keeps_one_coherent_candidate() {
    let fixture = Fixture::new();
    edit_json(&fixture.project.join("evidence.yaml"), |project| {
        project["assertionDefinitions"]["answer"]
            .as_object_mut()
            .unwrap()
            .remove("fixtures");
    });
    let replacement = fixture.root.join("replacement-project.json");
    let mut replaced: Value =
        serde_json::from_slice(&fs::read(fixture.project.join("evidence.yaml")).unwrap()).unwrap();
    replaced["assertionDefinitions"]["answer"]["semantics"]["requirement"] =
        json!("urn:example:requirements:replacement:v2");
    write_json(&replacement, &replaced);
    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env(
            "FAKE_EVIDENCE_MUTATE_PROJECT",
            fixture.project.join("evidence.yaml"),
        )
        .env("FAKE_EVIDENCE_REPLACEMENT_PROJECT", replacement)
        .output()
        .expect("package starts");
    assert_success(
        &output,
        "the captured project stays coherent through delegation",
    );
    let read_generated = |relative: &str| {
        registry_platform_yaml::Reader::new(relative)
            .scan(&fs::read(fixture.output.join(relative)).unwrap())
            .expect("generated document parses")
            .expect("generated document is nonempty")
            .to_json_value()
    };
    let bundle = read_generated("bundle/evidence.yaml");
    let authority = read_generated("compiled-authority.yaml");
    assert_eq!(
        bundle["requirements"][0]["uri"],
        "urn:example:requirements:answer:v1"
    );
    assert_eq!(
        authority["accessProfiles"]["requester"]["grants"][0]["requirement"],
        bundle["requirements"][0]["uri"]
    );
    let original: Value =
        serde_json::from_slice(&fs::read(fixture.project.join("evidence.yaml")).unwrap()).unwrap();
    assert_eq!(
        original["assertionDefinitions"]["answer"]["semantics"]["requirement"],
        "urn:example:requirements:replacement:v2"
    );
    fixture.assert_no_staging_residue();
}

#[test]
fn target_authority_is_captured_before_delegated_tool_execution() {
    for target_in_project in [false, true] {
        let mut fixture = Fixture::new();
        if target_in_project {
            let target_root = fixture.project.join("targets/production");
            fs::create_dir_all(target_root.parent().unwrap()).unwrap();
            fs::rename(fixture.target.parent().unwrap(), &target_root).unwrap();
            fixture.target = target_root.join("target.yaml");
            fixture.authority = target_root.join("authority.yaml");
        }
        let baseline = fixture.root.join("baseline");
        assert_success(
            &fixture.build_with(&fixture.project, &fixture.target, &baseline),
            "baseline captured authority",
        );
        let expected = fs::read(baseline.join("compiled-authority.yaml")).unwrap();
        let replacement = fixture.root.join("replacement-authority.json");
        let mut changed = authority_document();
        changed["accessProfiles"]["requester"]["requesterTags"] = json!(["changed-requester"]);
        write_json(&replacement, &changed);

        let output = fixture
            .command(&fixture.project, &fixture.target, &fixture.output)
            .env("FAKE_EVIDENCE_MUTATE_AUTHORITY", &fixture.authority)
            .env("FAKE_EVIDENCE_REPLACEMENT_AUTHORITY", &replacement)
            .output()
            .expect("package with authority replaced during version check starts");

        assert_success(&output, "package retains the captured target authority");
        assert_eq!(
            fs::read(&fixture.authority).unwrap(),
            fs::read(&replacement).unwrap()
        );
        assert!(
            fs::read(fixture.output.join("compiled-authority.yaml")).unwrap() == expected,
            "target_in_project={target_in_project}: package reread live authority after target capture"
        );
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn package_without_fixtures_still_delegates_compiled_authority_validation() {
    let fixture = Fixture::new();
    edit_json(&fixture.project.join("evidence.yaml"), |project| {
        project["assertionDefinitions"]["answer"]
            .as_object_mut()
            .unwrap()
            .remove("fixtures");
    });

    let output = fixture.build();

    assert_success(&output, "fixture-free package");
    assert_eq!(fixture.steps(), ["check"]);
    let invocations = fixture.invocations();
    let checked = &invocations[0];
    let position = checked
        .iter()
        .position(|argument| argument == "--authority-document")
        .expect("offline authority validation is mandatory for a target candidate");
    assert!(Path::new(&checked[position + 1]).ends_with("compiled-authority.yaml"));
    fixture.assert_no_staging_residue();
}

#[test]
fn incomplete_target_authority_is_refused_before_runtime_delegation() {
    let fixture = Fixture::new();
    edit_json(&fixture.authority, |authority| {
        authority["accessProfiles"] = json!({"incomplete":{}})
    });
    let output = fixture.build();
    assert_failed(&output, "complete authored authority is required");
    assert!(fixture.steps().is_empty());
    assert!(!fixture.output.exists());
    assert_value_free(&output);
    fixture.assert_no_staging_residue();
}

#[test]
fn every_referenced_fixture_is_delegated_and_one_failure_prevents_publication() {
    let fixture = Fixture::new();
    fixture.add_second_definition();

    let passed = fixture.build();
    assert_success(&passed, "two-fixture build");
    assert_eq!(
        fixture.steps(),
        [
            "check",
            "evaluate:fixtures/answer.yaml",
            "evaluate:fixtures/second.yaml"
        ]
    );

    let failed = Fixture::new();
    failed.add_second_definition();
    let output = failed.build_failing("fixture:fixtures/second.yaml");
    assert_failed(&output, "one rejected fixture");
    assert_eq!(
        failed.steps(),
        [
            "check",
            "evaluate:fixtures/answer.yaml",
            "evaluate:fixtures/second.yaml"
        ]
    );
    assert!(!failed.output.exists());
    assert_value_free(&output);
    failed.assert_no_staging_residue();
}

#[test]
fn identical_inputs_produce_identical_package_bytes_digest_and_stable_report_shape() {
    let fixture = Fixture::new();
    let first_output = fixture.root.join("candidate-one");
    let second_output = fixture.root.join("candidate-two");

    let first = fixture.build_with(&fixture.project, &fixture.target, &first_output);
    let second = fixture.build_with(&fixture.project, &fixture.target, &second_output);

    assert_success(&first, "first deterministic build");
    assert_success(&second, "second deterministic build");
    assert_eq!(snapshot(&first_output), snapshot(&second_output));
    assert_report(&first, &first_output);
    assert_report(&second, &second_output);
    assert_eq!(reported_revision(&first), reported_revision(&second));
}

#[test]
fn termination_cancels_evidence_and_removes_only_current_build_staging() {
    // Only a hung build reaches this; a runner starved by parallel builds just
    // makes each wait below longer.
    const BUILD_EVENT_DEADLINE: Duration = Duration::from_secs(120);

    for signal in [rustix::process::Signal::INT, rustix::process::Signal::TERM] {
        let fixture = Fixture::new();
        let ready = fixture.root.join("blocked-evidence-ready");
        let unrelated = fixture.root.join(".evidencectl-build-unrelated");
        fs::create_dir(&unrelated).expect("unrelated staging");
        fs::write(unrelated.join("owned.txt"), "preserve me\n").expect("unrelated sentinel");

        let mut child = fixture
            .command(&fixture.project, &fixture.target, &fixture.output)
            .env("FAKE_EVIDENCE_BLOCK", "1")
            .env("FAKE_EVIDENCE_BLOCK_READY", &ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("blocking evidencectl build starts");

        let ready_deadline = Instant::now() + BUILD_EVENT_DEADLINE;
        while !ready.exists() {
            assert!(
                child.try_wait().expect("poll blocking build").is_none(),
                "build exited before the fake Evidence process blocked"
            );
            assert!(
                Instant::now() < ready_deadline,
                "fake Evidence did not reach its blocking point"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let pid = rustix::process::Pid::from_raw(
            i32::try_from(child.id()).expect("evidencectl PID fits i32"),
        )
        .expect("evidencectl PID is positive");
        rustix::process::kill_process(pid, signal).expect("send signal to evidencectl build");

        let exit_deadline = Instant::now() + BUILD_EVENT_DEADLINE;
        loop {
            if child.try_wait().expect("poll interrupted build").is_some() {
                break;
            }
            if Instant::now() >= exit_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("interrupted evidencectl build did not exit");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().expect("collect interrupted build");

        assert_failed(&output, "signal-interrupted build");
        assert_value_free(&output);
        assert!(!fixture.output.exists());
        assert_eq!(
            fs::read_to_string(unrelated.join("owned.txt")).unwrap(),
            "preserve me\n",
            "build cleaned unrelated staging"
        );
        fs::remove_dir_all(&unrelated).expect("remove test-owned unrelated staging");
        fixture.assert_no_staging_residue();
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
    target: PathBuf,
    authority: PathBuf,
    output: PathBuf,
    evidence: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn use_default_local_signer(&self) {
        edit_json(&self.target, |target| {
            target["assuranceProfile"] = json!("local");
            target["connections"]["registry-http"]["origin"] = json!("http://127.0.0.1:8088");
            target["connections"]["registry-http"]["authentication"] = json!({"type":"none"});
            target["secretProviders"]["file"]["root"] = json!(".generated/secrets");
            target["signer"] = json!({"type":"local-jwk", "algorithm":"ES256", "privateKeyRef":"secret:file/signing-p256-private-jwk", "publicJwkFile":".generated/secrets/signing-p256-public.jwk.json"});
        });
    }

    fn new() -> Self {
        let temporary_root = workspace_root().join("target");
        fs::create_dir_all(&temporary_root).expect("workspace target");
        let temporary = tempfile::Builder::new()
            .prefix("production-build-")
            .tempdir_in(temporary_root)
            .expect("test tempdir");
        let root = temporary.path().to_path_buf();
        let project = root.join("project");
        let target_directory = root.join("production-target");
        let target = target_directory.join("target.yaml");
        for directory in ["functions", "fixtures"] {
            fs::create_dir_all(project.join(directory)).expect("project directory");
        }
        fs::create_dir_all(target_directory.join("public-keys")).expect("target directory");
        write_json(&project.join("evidence.yaml"), &project_document());
        fs::write(
            target_directory.join("public-keys/active.jwk.json"),
            r#"{"kty":"EC","crv":"P-256","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#,
        )
        .expect("governed public key");
        for (name, script) in [
            ("source-prepare", "fn prepare(selectors, context) { #{query: [], body: #{reference: selectors[\"subject\"][\"values\"][\"reference\"]}} }\n"),
            ("source-extract", "fn extract(source_response, context) { #{outcome: \"match\", facts: #{allowed: source_response[\"allowed\"]}} }\n"),
            ("answer", "fn derive(facts, selectors, context) { [#{output: \"allowed\", value: facts[\"allowed\"]}] }\n"),
        ] {
            fs::write(project.join(format!("functions/{name}.rhai")), script).expect("named Function");
        }
        fs::write(
            project.join("fixtures/answer.yaml"),
            "fixture: neutral.answer/v1\n",
        )
        .expect("fixture");
        let authority = target_directory.join("authority.yaml");
        write_json(&authority, &authority_document());
        write_json(&target, &target_document());

        let evidence = root.join("evidence");
        fs::write(&evidence, FAKE_EVIDENCE).expect("fake Evidence");
        let mut permissions = fs::metadata(&evidence).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&evidence, permissions).unwrap();

        Self {
            output: root.join("candidate"),
            log: root.join("evidence-invocations"),
            _temporary: temporary,
            root,
            project,
            target,
            authority,
            evidence,
        }
    }

    fn build(&self) -> Output {
        self.build_with(&self.project, &self.target, &self.output)
    }

    fn build_failing(&self, failure: &str) -> Output {
        self.command(&self.project, &self.target, &self.output)
            .env("FAKE_EVIDENCE_FAIL", failure)
            .output()
            .expect("evidencectl build starts")
    }

    fn package(&self, format: &str) -> Output {
        self.package_to(format, &self.output)
    }

    fn package_to(&self, format: &str, output: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["--format", format, "package"])
            .arg(&self.project)
            .arg("--target")
            .arg(&self.target)
            .arg("--output")
            .arg(output)
            .env("EVIDENCE_BIN", &self.evidence)
            .env("FAKE_EVIDENCE_LOG", &self.log)
            .env(
                "FAKE_EVIDENCE_VERSION",
                registry_platform_buildinfo::DISPLAY_VERSION,
            )
            .output()
            .expect("evidencectl package starts")
    }

    fn check_production(&self, format: &str) -> Output {
        self.check_production_with(format, &self.target)
    }

    fn check_production_with(&self, format: &str, target: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["--format", format, "check"])
            .arg(&self.project)
            .arg("--target")
            .arg(target)
            .arg("--production")
            .env("EVIDENCE_BIN", &self.evidence)
            .env("FAKE_EVIDENCE_LOG", &self.log)
            .env(
                "FAKE_EVIDENCE_VERSION",
                registry_platform_buildinfo::DISPLAY_VERSION,
            )
            .output()
            .expect("evidencectl check starts")
    }

    fn build_with(&self, project: &Path, target: &Path, output: &Path) -> Output {
        self.command(project, target, output)
            .output()
            .expect("evidencectl build starts")
    }

    fn explain(&self) -> Output {
        self.explain_target(&self.target)
    }

    fn explain_target(&self, target: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["--format", "json"])
            .arg("target")
            .arg("explain")
            .arg(target)
            .arg(&self.project)
            .env("EVIDENCE_BIN", &self.evidence)
            .env("FAKE_EVIDENCE_LOG", &self.log)
            .env(
                "FAKE_EVIDENCE_VERSION",
                registry_platform_buildinfo::DISPLAY_VERSION,
            )
            .output()
            .expect("evidencectl target explain starts")
    }

    fn explain_project_with_target(&self, target: &Path) -> Output {
        self.explain_project("json", target)
    }

    fn explain_project(&self, format: &str, target: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["--format", format, "explain"])
            .arg(&self.project)
            .arg("--target")
            .arg(target)
            .env("EVIDENCE_BIN", &self.evidence)
            .env("FAKE_EVIDENCE_LOG", &self.log)
            .env(
                "FAKE_EVIDENCE_VERSION",
                registry_platform_buildinfo::DISPLAY_VERSION,
            )
            .output()
            .expect("evidencectl explain starts")
    }

    fn command(&self, project: &Path, target: &Path, output: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
        command
            .arg("package")
            .arg(project)
            .arg("--target")
            .arg(target)
            .arg("--output")
            .arg(output)
            .env("EVIDENCE_BIN", &self.evidence)
            .env("FAKE_EVIDENCE_LOG", &self.log)
            .env(
                "FAKE_EVIDENCE_VERSION",
                registry_platform_buildinfo::DISPLAY_VERSION,
            )
            .env_remove("FAKE_EVIDENCE_FAIL")
            .env_remove("FAKE_EVIDENCE_EMPTY_DESCRIPTION");
        command
    }

    fn invocations(&self) -> Vec<Vec<String>> {
        let Ok(contents) = fs::read_to_string(&self.log) else {
            return Vec::new();
        };
        contents
            .split("===\n")
            .filter(|part| !part.is_empty())
            .map(|part| part.lines().map(str::to_owned).collect())
            .collect()
    }

    fn steps(&self) -> Vec<String> {
        self.invocations()
            .into_iter()
            .map(|args| {
                if let Some(index) = args.iter().position(|arg| arg == "--fixture") {
                    format!("evaluate:{}", args[index + 1])
                } else {
                    "check".to_owned()
                }
            })
            .collect()
    }

    fn use_sqlite_source(&self) {
        fs::create_dir(self.project.join("queries")).expect("query directory");
        fs::write(
            self.project.join("queries/source.sql"),
            "SELECT :reference <> '' AS allowed;\n",
        )
        .expect("statement");
        edit_json(&self.project.join("evidence.yaml"), |project| {
            project["functions"]
                .as_array_mut()
                .unwrap()
                .retain(|function| function["id"] != "source-prepare");
            let source = &mut project["sources"]["registry"];
            source["type"] = json!("sqlite-extract");
            source["acquisitionPosture"] = json!("source-derived");
            source["extractProfile"] = json!("registry-snapshot");
            source["maximumExtractAgeSeconds"] = json!(86400);
            for key in [
                "connection",
                "prepare",
                "adapterParameters",
                "adapterParametersSchema",
                "preparationLimits",
            ] {
                source.as_object_mut().unwrap().remove(key);
            }
            source["request"] = json!({"statement":"queries/source.sql","columns":[{"name":"allowed","type":"boolean"}],"parameterBindings":{"reference":{"selector":{"role":"subject","profile":"subject-reference-v1","field":"reference"}}},"maximumRows":1,"maximumCellBytes":8,"maximumStatementSteps":10000});
            source["response"] = json!({"projection":["/rows/*/allowed"],"shape":{"type":"object","required":["rows"],"properties":{"rows":{"type":"array","minimumItems":1,"maximumItems":1,"items":{"type":"object","required":["allowed"],"properties":{"allowed":{"type":"boolean"}}}}}},"maximumBytes":4096});
        });
        fs::write(self.project.join("functions/source-extract.rhai"), "fn extract(source_response, context) { #{outcome: \"match\", facts: #{allowed: source_response[\"rows\"][0][\"allowed\"]}} }\n").expect("SQLite extract Function");
        edit_json(
            &self.target,
            |target| {
                target["extracts"] =
                    json!({"registry-snapshot":{"path":"/var/lib/evidence/registry.sqlite"}})
            },
        );
    }

    /// Publication remains an optional deployment contract.
    fn declare_publication(&self) {
        edit_json(
            &self.target,
            |target| target["publication"] = json!({"serviceId":"urn:example:services:evidence","title":"Governed Evidence service","description":"Governed minimum-disclosure Evidence service","endpointUrl":"https://evidence.invalid","jurisdictions":["urn:example:jurisdictions:governed"]}),
        );
    }

    fn add_second_definition(&self) {
        edit_json(&self.project.join("evidence.yaml"), |project| {
            project["assertionDefinitions"]["second"] = definition_document("second")
        });
        edit_json(&self.authority, |authority| {
            let mut grant = authority["accessProfiles"]["requester"]["grants"][0].clone();
            grant["definition"] = json!("second");
            authority["accessProfiles"]["requester"]["grants"]
                .as_array_mut()
                .unwrap()
                .push(grant);
        });
        fs::write(
            self.project.join("fixtures/second.yaml"),
            "fixture: neutral.second/v1\n",
        )
        .expect("second fixture");
    }

    fn assert_no_staging_residue(&self) {
        fn collect(path: &Path, names: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(path).expect("staging scan directory") {
                let entry = entry.expect("staging scan entry");
                let entry_path = entry.path();
                let metadata = fs::symlink_metadata(&entry_path).expect("staging scan metadata");
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(".evidencectl-build-")
                    || name.starts_with(".evidencectl-build-validation-")
                {
                    names.push(entry_path.clone());
                }
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    collect(&entry_path, names);
                }
            }
        }
        let mut names = Vec::new();
        collect(&self.root, &mut names);
        assert!(
            names.is_empty(),
            "private staging residue remained: {names:?}"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // A successful build seals its published candidate: the bundle directory tree loses
        // its write bit (0o500 dirs, 0o400 files) as its production immutability guarantee.
        // The tempdir cleanup below cannot remove entries from a directory it cannot write
        // to, so every path a test may have published a candidate under is restored to
        // owner-writable first.
        if let Err(error) = make_tree_writable(&self.root) {
            // Swallowing the error would leave a read-only tree behind with no trace.
            // A test that is already unwinding keeps its own failure as the report.
            if !std::thread::panicking() {
                panic!("restore fixture permissions before cleanup: {error}");
            }
        }
    }
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

fn project_document() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/evidence/project/v1alpha1",
        "kind":"EvidenceProject", "id":"production-fixture",
        "selectorProfiles":{"subject-reference-v1":{"maximumAggregateBytes":128,"fields":{"reference":{"type":"string","minimumBytes":1,"maximumBytes":128}}}},
        "functions":[
            {"id":"source-prepare","interface":"source-prepare/v1","source":"functions/source-prepare.rhai"},
            {"id":"source-extract","interface":"source-extract/v1","source":"functions/source-extract.rhai"},
            {"id":"answer","interface":"assertion-derive/v1","source":"functions/answer.rhai"}
        ],
        "sources":{"registry":{
            "type":"http-json", "connection":"registry-http", "acquisitionPosture":"field-projected",
            "selectors":[{"role":"subject","profiles":["subject-reference-v1"]}],
            "request":{"method":"POST","path":"/v1/facts","fixedHeaders":[{"name":"Accept","value":"application/json"}]},
            "prepare":{"function":"source-prepare"}, "extract":{"function":"source-extract"},
            "response":{"projection":["/allowed"],"shape":{"type":"object","required":["allowed"],"properties":{"allowed":{"type":"boolean"}}},"maximumBytes":4096},
            "facts":{"allowed":{"type":"boolean"}},
            "limits":{"attemptTimeoutMilliseconds":1000,"maximumConcurrency":1},
            "adapterParameters":{},"adapterParametersSchema":{"type":"object","additionalProperties":false,"required":[],"properties":{}},
            "preparationLimits":{"query":"forbidden","jsonBody":"required","maximumJsonDepth":4,"maximumCollectionItems":8,"maximumStringBytes":128,"maximumNormalizedBytes":1024}
        }},
        "assertionDefinitions":{"answer":definition_document("answer")}
    })
}

fn definition_document(id: &str) -> Value {
    json!({
        "question":"Is the governed condition satisfied?",
        "semantics":{"requirement":format!("urn:example:requirements:{id}:v1"),"kind":"criterion","referenceFrameworks":["urn:example:frameworks:allowed:v1"],"evidenceType":"urn:example:evidence-types:allowed:v1"},
        "purpose":"eligibility",
        "grantCeiling":{"authorities":["statutory"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":["urn:example:audience:relying"]},
        "subjects":[{"role":"subject","selectors":["subject-reference-v1"]}],
        "acquisition":{"type":"single","source":"registry"},"derive":{"function":"answer"},
        "outputs":{"allowed":{"concept":"urn:example:concepts:allowed","type":"boolean"}},
        "validitySeconds":300,"observationTimezone":"UTC","subjectBinding":"audience-scoped","representations":["signed-jws"],
        "disclosureGuard":{"families":["urn:example:disclosure-families:allowed"]},
        "fixtures":format!("fixtures/{id}.yaml")
    })
}

fn authority_document() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/evidence/target-authority/v1alpha1",
        "kind":"EvidenceTargetAuthority", "target":"production", "project":"production-fixture",
        "accessProfiles":{"requester":{"authority":"statutory","actorKind":"service","requesterTags":["requester"],"grants":[{
            "definition":"answer","purpose":"eligibility","audienceFrom":"authenticated-requester","representations":["signed-jws"],"subjectBinding":"audience-scoped",
            "subjects":[{"role":"subject","selectorProfile":"subject-reference-v1","valueOrigin":"request"}]
        }]}}
    })
}

fn target_document() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/evidence/target/v1alpha1", "kind":"EvidenceTarget",
        "id":"production","project":"production-fixture","authority":"authority.yaml","assuranceProfile":"production",
        "package":{"root":"/srv/evidence/candidate/bundle"},
        "service":{"providerId":"urn:example:providers:evidence","issuer":"urn:example:issuers:evidence","publicOrigin":"https://evidence.invalid","trustDomain":"urn:example:trust-domains:evidence"},
        "authentication":{"oidc":{"issuer":"https://issuer.invalid","audience":"evidence","jwksSource":{"type":"uri","uri":"https://issuer.invalid/.well-known/jwks.json"},"tokenTypes":["at+jwt"],"algorithms":["ES256"],"principalClaim":"sub","requesterTagsClaim":"evidence_tags","evidenceAudienceClaim":"evidence_audience","allowedClients":"unrestricted","requiredScopes":"unrestricted","maximumTokenLifetimeSeconds":300,"revokedKeyIds":[]}},
        "connections":{"registry-http":{"origin":"https://registry.invalid","authentication":{"type":"bearer","tokenRef":"secret:file/source-token"}}},
        "secretProviders":{"file":{"root":"/run/secrets/evidence"}},
        "signer":{"type":"transit","algorithm":"ES256","publicJwkFile":"public-keys/active.jwk.json","unixSocketPath":"/run/registry-evidence/transit-proxy.sock","mount":"transit","keyName":"evidence-signing","keyVersion":7,"attemptTimeoutMilliseconds":2000},
        "listener":{"bind":"127.0.0.1:8080","tlsTermination":"operator-controlled-upstream","trustProxyIdentityHeaders":false,"maximumRequestBytes":65536,"maximumConcurrentRequests":8,"requestTimeoutMilliseconds":10000,"shutdownGraceMilliseconds":10000},
        "audit":{"path":"/var/lib/evidence/audit.jsonl","hashKeyRef":"secret:file/audit-hmac-key","hashKeyVersion":1},
        "subjectBinding":{"secretRef":"secret:file/subject-binding-hmac-key","keyVersion":1},
        "rateLimits":{"requestsPerPrincipalPerMinute":60,"burstPerPrincipal":10,"failedSelectorAttemptsPerPrincipalAuthorityPerMinute":10},
        "responseFormats":["signed-jws"],"outboundTls":{"systemRoots":true,"trustProfiles":{}}
    })
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("fixture JSON"),
    )
    .expect("write fixture");
}

fn edit_json(path: &Path, edit: impl FnOnce(&mut Value)) {
    let mut value =
        serde_json::from_slice(&fs::read(path).expect("fixture reads")).expect("fixture JSON");
    edit(&mut value);
    write_json(path, &value);
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failed(output: &Output, label: &str) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn assert_value_free(output: &Output) {
    let mut diagnostic = output.stdout.clone();
    diagnostic.extend_from_slice(&output.stderr);
    for prohibited in [
        SECRET_CANARY,
        "synthetic-selector-canary",
        "source-value-canary",
    ] {
        assert!(
            !diagnostic
                .windows(prohibited.len())
                .any(|part| part == prohibited.as_bytes()),
            "build diagnostic exposed protected test material"
        );
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_report(output: &Output, candidate: &Path) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout,
        format!(
            "Package digest: {REVISION}\nPackage: {}\nRuntime: {}\nAuthority: {}\nProvision secret:file/audit-hmac-key\nProvision secret:file/source-token\nProvision secret:file/subject-binding-hmac-key\nTarget runtime paths and deployment secret material remain unverified until `evidencectl doctor --runtime-config {}`.\n",
            candidate.join("bundle").display(),
            candidate.join("runtime.yaml").display(),
            candidate.join("compiled-authority.yaml").display(),
            candidate.join("runtime.yaml").display(),
        )
    );
}

fn reported_revision(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Package digest: "))
        .expect("package digest report")
        .to_owned()
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(path)
            .expect("snapshot directory")
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for entry in entries {
            let metadata = fs::symlink_metadata(&entry).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                visit(root, &entry, files);
            } else {
                files.insert(
                    entry.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

const FAKE_EVIDENCE: &str = r#"#!/bin/sh
set -eu

if [ "${1:-}" = '--version' ]; then
  if [ -n "${FAKE_EVIDENCE_MUTATE_AUTHORITY:-}" ]; then
    cp "$FAKE_EVIDENCE_REPLACEMENT_AUTHORITY" "$FAKE_EVIDENCE_MUTATE_AUTHORITY"
  fi
  printf 'evidence %s\n' "$FAKE_EVIDENCE_VERSION"
  exit 0
fi

if [ "${1:-}" = 'render-discovery-description' ]; then
  if [ -n "${FAKE_EVIDENCE_MUTATE_PROJECT:-}" ]; then
    cp "$FAKE_EVIDENCE_REPLACEMENT_PROJECT" "$FAKE_EVIDENCE_MUTATE_PROJECT"
  fi
  if [ "${FAKE_EVIDENCE_EMPTY_DESCRIPTION:-}" != '1' ]; then
    printf '{}\n'
  fi
  exit 0
fi

for arg in "$@"; do
  printf '%s\n' "$arg" >> "$FAKE_EVIDENCE_LOG"
done
printf '%s\n' '===' >> "$FAKE_EVIDENCE_LOG"

if [ "${FAKE_EVIDENCE_BLOCK:-}" = '1' ]; then
  printf '%s\n' ready > "$FAKE_EVIDENCE_BLOCK_READY"
  exec sleep 300
fi

fixture=''
json=0
runtime=''
previous=''
for arg in "$@"; do
  if [ "$previous" = '--fixture' ]; then fixture=$arg; fi
  if [ "$previous" = '--runtime-config' ]; then runtime=$arg; fi
  if [ "$arg" = '--json' ]; then json=1; fi
  previous=$arg
done

if [ -n "$runtime" ] && grep -q 'trustProxyIdentityHeaders: true' "$runtime"; then
  printf '{"ok":false,"command":"bundle-check","status":"domain-refusal","apiVersion":"id.registrystack.org/formats/evidence/ctl-report/v1alpha1","kind":"EvidenceCtlReport","filesChecked":1,"diagnostics":[{"severity":"error","code":"evidence.runtime.invalid-listener","path":"/listener/trustProxyIdentityHeaders","message":"proxy identity headers must not be trusted","suggestedAction":"Write false; Evidence authenticates every request itself.","source":{"file":"%s","line":9,"column":31}}]}\n' "$runtime"
  exit 1
fi

failure=${FAKE_EVIDENCE_FAIL:-}
if [ "$failure" = 'check' ] && [ -z "$fixture" ]; then
  printf '%s\n' 'evidence bundle-check diagnostic: derivations/answer.rhai failed static compilation' >&2
  exit 1
fi
if [ "$failure" = 'check-overflow' ] && [ -z "$fixture" ]; then
  i=1
  while [ "$i" -le 200 ]; do
    printf 'evidence bundle-check diagnostic line %s\n' "$i" >&2
    i=$((i + 1))
  done
  exit 1
fi
if [ "$failure" = "fixture:$fixture" ]; then
  printf '%s\n' 'production-build-secret-canary synthetic-selector-canary source-value-canary' >&2
  exit 1
fi

if [ -z "$fixture" ]; then
  if [ "$json" = '1' ]; then
    printf '%s\n' '{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","requirements":[{"id":"urn:example:requirements:allowed:v1","configurationRevision":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}'
  else
    printf '%s\n' 'Evidence bundle sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa passed check (2 requirements)'
  fi
else
  printf '%s\n' 'Evidence fixture passed (1 evaluated cases)'
fi
"#;
