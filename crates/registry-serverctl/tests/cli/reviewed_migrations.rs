// SPDX-License-Identifier: Apache-2.0
//! Offline contract tests. Synthetic receipts here prove validation, not execution.

use super::*;
use registry_server::migration_plan::{
    MigrationRehearsalReceipt, RehearsalProofs, ReviewedChangeCover, ReviewedMigrationDescriptor,
    ReviewedMigrationFile, ReviewedMigrationRecovery, ReviewedMigrationSource,
};
use registry_server::package::{compiled_registry_change_set, CompiledRegistryChangeClass};

const BASE: &str = "modules/core/migrations/read-label";
const FINGERPRINT: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

struct ReviewFixture {
    baseline: RuntimePackageFixture,
    project: TestProject,
    review: PathBuf,
    key_id: String,
    prepared: PreparedPackage,
}

impl ReviewFixture {
    fn create() -> Self {
        let baseline = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
        let inspected =
            registry_server::package::inspect_package_integrity(&baseline.package).unwrap();
        let envelope: registry_server::package::PackageEnvelope =
            serde_json::from_slice(&fs::read(baseline.package.join("package.json")).unwrap())
                .unwrap();
        let key_id = envelope.signed.signature_policy.key_ids[0].clone();
        let mut module: Value = serde_json::from_slice(&package_module_bytes()).unwrap();
        module["entities"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"label", "type":"string", "maxLength":32, "classification":"internal"
            }));
        module["entities"][0]["accessProfiles"][0]["readableFields"] = json!(["code", "label"]);
        module["entities"][0]["accessProfiles"][0]["filterableFields"] = json!(["label"]);
        let module_bytes = canonicalize_json(&module).unwrap();
        let module = parse_module_json(&module_bytes).unwrap();
        let mut source: Value =
            serde_json::from_slice(&package_project_bytes(&module_digest(&module))).unwrap();
        source["package"]["sequence"] = json!(2);
        let project_bytes = canonicalize_json(&source).unwrap();
        let project = TestProject::from_registry_source(&project_bytes);
        fs::create_dir_all(project.path().join("modules/core")).unwrap();
        fs::write(
            project.path().join("modules/core/module.yaml"),
            &module_bytes,
        )
        .unwrap();
        fs::create_dir(project.path().join("tests")).unwrap();
        fs::write(
            project.path().join(FIXTURE_JOURNEYS_PATH),
            PACKAGE_FIXTURE_JOURNEYS,
        )
        .unwrap();
        let candidate = compile_project(
            &parse_project_yaml(&project_bytes).unwrap(),
            &[module],
            CompileProfile::Production,
        )
        .unwrap();
        let changes = compiled_registry_change_set(
            inspected.registry(),
            &candidate,
            inspected.package_revision(),
        );
        let mut covers = changes
            .changes
            .iter()
            .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
            .map(ReviewedChangeCover::from)
            .collect::<Vec<_>>();
        covers.sort();
        let descriptor = ReviewedMigrationDescriptor {
            id: "read-label".into(),
            change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
            covers,
            recovery: ReviewedMigrationRecovery::ExactTargetResume,
            lock_timeout_ms: 1000,
            statement_timeout_ms: 5000,
            steps: vec![],
            pre_assertions: vec![],
            post_assertions: vec![],
            rehearsal_receipt_path: format!("{BASE}/rehearsal.json"),
            backup_binding_path: None,
        };
        let descriptor_bytes =
            canonicalize_json(&serde_json::to_value(descriptor).unwrap()).unwrap();
        let receipt = MigrationRehearsalReceipt {
            prior_revision: inspected.package_revision().into(),
            prior_schema_fingerprint: inspected.schema_fingerprint().into(),
            plan_sha256: sha256_prefixed(&descriptor_bytes),
            sql_sha256: vec![],
            assertion_sha256: vec![],
            fixture_inventory: vec![],
            postgres_major: 16,
            row_assertions: vec![],
            final_schema_fingerprint: FINGERPRINT.into(),
            proofs: RehearsalProofs {
                lock_timeout: true,
                chunk_resume: false,
                destructive_resume: false,
            },
        };
        let receipt_bytes = canonicalize_json(&serde_json::to_value(receipt).unwrap()).unwrap();
        let review = project.path().join("review");
        fs::create_dir_all(review.join(BASE)).unwrap();
        fs::write(review.join(BASE).join("descriptor.json"), &descriptor_bytes).unwrap();
        fs::write(review.join(BASE).join("rehearsal.json"), &receipt_bytes).unwrap();
        let predecessor = load_predecessor_package(
            &baseline.package,
            &PredecessorPackageContext {
                environment: "production",
                instance_id: PACKAGE_INSTANCE,
                database_id: PACKAGE_DATABASE,
                database_initialization_environment: "production",
                trust_anchor: Some(&baseline.anchor),
                expected_package_revision: inspected.package_revision(),
                expected_sequence: 1,
            },
        )
        .unwrap();
        let prepared = prepare_package(PackageBuildRequest {
            environment: "production".into(),
            instance_id: PACKAGE_INSTANCE.into(),
            database_id: PACKAGE_DATABASE.into(),
            sequence: 2,
            prior_revision: Some(inspected.package_revision().into()),
            compiler_source_revision: PACKAGE_SOURCE_REVISION.into(),
            schema_fingerprint: FINGERPRINT.into(),
            signature_policy: SignaturePolicy {
                threshold: 1,
                key_ids: vec![key_id.clone()],
            },
            project: PackageSourceFile {
                path: "source/registry.yaml".into(),
                bytes: project_bytes,
            },
            modules: vec![PackageModuleSource {
                id: "core".into(),
                path: "source/modules/core/module.yaml".into(),
                bytes: module_bytes,
                assets: vec![],
            }],
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.into(),
                bytes: PACKAGE_FIXTURE_JOURNEYS.to_vec(),
            },
            migration_plan: PackageMigrationPlanInput::ReviewedSuccessorFromBaseline {
                prior_baseline: Box::new(predecessor.migration_baseline().clone()),
                prior_schema_fingerprint: inspected.schema_fingerprint().into(),
                migrations: vec![ReviewedMigrationSource {
                    module_id: "core".into(),
                    descriptor: ReviewedMigrationFile {
                        path: format!("{BASE}/descriptor.json"),
                        bytes: descriptor_bytes,
                    },
                    files: vec![ReviewedMigrationFile {
                        path: format!("{BASE}/rehearsal.json"),
                        bytes: receipt_bytes,
                    }],
                }],
            },
        })
        .unwrap();
        Self {
            baseline,
            project,
            review,
            key_id,
            prepared,
        }
    }

    fn run(&self, command: &str, with_review: bool) -> Output {
        let receipt = self.project.path().join("test-receipt.json");
        fs::write(
            &receipt,
            schema_test_receipt_bytes(&self.prepared, &["package-record-list"]),
        )
        .unwrap();
        let output = self.project.path().join(if command == "test" {
            "result.json"
        } else {
            "build"
        });
        let credentials = self.project.path().join("missing-credentials.yaml");
        let mut args = vec![
            "--format",
            "json",
            command,
            path(self.project.path()),
            "--database-id",
            PACKAGE_DATABASE,
            "--baseline-runtime-config",
            path(&self.baseline.runtime_config),
            "--signature-threshold",
            "1",
            "--signature-key-id",
            &self.key_id,
            "--output",
            path(&output),
        ];
        if with_review {
            args.extend(["--reviewed-migrations", path(&self.review)]);
        }
        if command == "test" {
            args.extend([
                "--runtime-config",
                path(&self.baseline.runtime_config),
                "--credentials",
                path(&credentials),
            ]);
        } else {
            args.extend([
                "--schema-fingerprint",
                FINGERPRINT,
                "--test-receipt",
                path(&receipt),
            ]);
        }
        registry_serverctl(&args)
    }

    fn mutate_json(&self, file: &str, mutate: impl FnOnce(&mut Value)) {
        let path = self.review.join(BASE).join(file);
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut value);
        fs::write(path, canonicalize_json(&value).unwrap()).unwrap();
    }
}

#[test]
fn reviewed_successor_is_shared_by_test_and_package_without_placeholder_fingerprint() {
    let fixture = ReviewFixture::create();
    let diff = registry_serverctl(&[
        "--format",
        "json",
        "diff",
        path(fixture.project.path()),
        "--runtime-config",
        path(&fixture.baseline.runtime_config),
    ]);
    assert!(diff.status.success(), "{diff:?}");
    let report = json_stdout(&diff);
    let query_change = report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["change"]["code"] == "query_inventory_changed")
        .unwrap();
    assert_eq!(query_change["classification"], "access_change");
    let profile_change = report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["change"]["code"] == "access_profile_changed")
        .unwrap();
    assert_eq!(profile_change["classification"], "access_change");
    for command in ["test", "package"] {
        let refused = fixture.run(command, false);
        assert!(!refused.status.success());
        assert_eq!(
            json_stdout(&refused)["diagnostics"][0]["code"],
            "migration.review.required"
        );
        assert!(json_stdout(&refused)["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("--reviewed-migrations"));
    }
    let test = fixture.run("test", true);
    assert_eq!(
        json_stdout(&test)["diagnostics"][0]["code"],
        "test.credentials.refused",
        "{test:?}"
    );
    let package = fixture.run("package", true);
    assert!(package.status.success(), "{package:?}");
    assert_eq!(json_stdout(&package)["state"], "awaiting_signatures");
    assert_eq!(
        json_stdout(&package)["packageRevision"],
        fixture.prepared.package_revision()
    );
    assert_eq!(
        fs::read(fixture.project.path().join("build/signing-input.json")).unwrap(),
        fixture.prepared.canonical_signed_bytes()
    );
}

#[test]
fn reviewed_successor_changed_review_invalidates_the_schema_test_receipt() {
    let fixture = ReviewFixture::create();
    // This remains a valid review, but it is no longer the tested candidate.
    fixture.mutate_json("descriptor.json", |value| {
        value["lockTimeoutMs"] = json!(2000)
    });
    let descriptor = fs::read(fixture.review.join(BASE).join("descriptor.json")).unwrap();
    fixture.mutate_json("rehearsal.json", |value| {
        value["planSha256"] = json!(sha256_prefixed(&descriptor))
    });
    let output = fixture.run("package", true);
    assert!(!output.status.success());
    assert_eq!(
        json_stdout(&output)["diagnostics"][0]["code"],
        "package.test_receipt.refused"
    );
    assert!(!fixture.project.path().join("build").exists());
}

#[test]
fn reviewed_successor_cli_requires_a_verified_baseline_argument() {
    let error = registry_serverctl::command()
        .try_get_matches_from([
            "registry-serverctl",
            "test",
            ".",
            "--reviewed-migrations",
            "review",
            "--database-id",
            PACKAGE_DATABASE,
            "--runtime-config",
            "/unused.yaml",
            "--credentials",
            "/unused-credentials.yaml",
            "--output",
            "/unused-receipt.json",
        ])
        .unwrap_err();
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    assert!(error.to_string().contains("--baseline-runtime-config"));
}

#[test]
fn reviewed_successor_refuses_mismatched_baseline_database_before_receipt_validation() {
    let fixture = ReviewFixture::create();
    let receipt = fixture.project.path().join("test-receipt.json");
    fs::write(
        &receipt,
        schema_test_receipt_bytes(&fixture.prepared, &["package-record-list"]),
    )
    .unwrap();
    let output = fixture.project.path().join("wrong-database-build");
    let result = registry_serverctl(&[
        "--format",
        "json",
        "package",
        path(fixture.project.path()),
        "--database-id",
        "other-database",
        "--baseline-runtime-config",
        path(&fixture.baseline.runtime_config),
        "--signature-threshold",
        "1",
        "--signature-key-id",
        &fixture.key_id,
        "--reviewed-migrations",
        path(&fixture.review),
        "--schema-fingerprint",
        FINGERPRINT,
        "--test-receipt",
        path(&receipt),
        "--output",
        path(&output),
    ]);

    assert!(!result.status.success());
    assert_eq!(
        json_stdout(&result)["diagnostics"][0]["code"],
        "package.baseline.identity"
    );
    assert!(!output.exists());
}

#[test]
fn reviewed_successor_refuses_unbound_evidence_and_uncovered_changes_before_io() {
    for field in [
        "priorRevision",
        "priorSchemaFingerprint",
        "planSha256",
        "finalSchemaFingerprint",
    ] {
        let fixture = ReviewFixture::create();
        fixture.mutate_json("rehearsal.json", |value| {
            value[field] = json!("private-review-value-canary")
        });
        for command in ["test", "package"] {
            let output = fixture.run(command, true);
            assert!(!output.status.success());
            assert_eq!(
                json_stdout(&output)["diagnostics"][0]["code"],
                "migration.review.refused",
                "{field}: {output:?}"
            );
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains("private-review-value-canary")
            );
            assert!(!fixture.project.path().join("build").exists());
            assert!(!fixture.project.path().join("result.json").exists());
        }
    }
    let fixture = ReviewFixture::create();
    fixture.mutate_json("descriptor.json", |value| value["covers"] = json!([]));
    let output = fixture.run("test", true);
    assert_eq!(
        json_stdout(&output)["diagnostics"][0]["code"],
        "migration.review.refused"
    );
}

#[test]
fn reviewed_successor_refuses_duplicate_keys_noncanonical_bytes_and_extra_artifacts() {
    for malformed in [
        b"{\"id\":\"read-label\",\"id\":\"private-review-value-canary\"}".as_slice(),
        b"{}\n".as_slice(),
    ] {
        let fixture = ReviewFixture::create();
        fs::write(fixture.review.join(BASE).join("descriptor.json"), malformed).unwrap();
        let output = fixture.run("test", true);
        assert_eq!(
            json_stdout(&output)["diagnostics"][0]["code"],
            "migration.review.refused"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-review-value-canary"));
    }
    let fixture = ReviewFixture::create();
    fs::create_dir(fixture.review.join(BASE).join("steps")).unwrap();
    fs::write(
        fixture.review.join(BASE).join("steps/unused.sql"),
        b"SELECT 'private-review-value-canary'",
    )
    .unwrap();
    let output = fixture.run("test", true);
    assert_eq!(
        json_stdout(&output)["diagnostics"][0]["code"],
        "migration.review.refused"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-review-value-canary"));
}

#[cfg(unix)]
#[test]
fn reviewed_successor_refuses_symlinks_and_oversized_artifacts() {
    use std::os::unix::fs::symlink;
    let fixture = ReviewFixture::create();
    symlink(
        fixture.review.join(BASE).join("descriptor.json"),
        fixture.review.join(BASE).join("backup.json"),
    )
    .unwrap();
    let output = fixture.run("test", true);
    assert_eq!(
        json_stdout(&output)["diagnostics"][0]["code"],
        "migration.review.path"
    );
    fs::remove_file(fixture.review.join(BASE).join("backup.json")).unwrap();
    fs::write(
        fixture.review.join(BASE).join("descriptor.json"),
        vec![b' '; 1024 * 1024 + 1],
    )
    .unwrap();
    let output = fixture.run("test", true);
    assert_eq!(
        json_stdout(&output)["diagnostics"][0]["code"],
        "migration.review.file"
    );
}
