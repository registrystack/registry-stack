// SPDX-License-Identifier: Apache-2.0
//! Offline contract tests. Synthetic receipts here prove validation, not execution.

use super::*;
use registry_breg::migration_plan::{
    MigrationRehearsalReceipt, ReviewedChangeCover, ReviewedMigrationDescriptor,
    ReviewedMigrationFile, ReviewedMigrationRecovery, ReviewedMigrationSource,
};
use registry_breg::package::{compiled_registry_change_set, CompiledRegistryChangeClass};

const BASE: &str = "modules/core/migrations/read-label";
const FINGERPRINT: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

struct ReviewFixture {
    baseline: RuntimePackageFixture,
    project: TestProject,
    review: PathBuf,
    prepared: PreparedPackage,
}

impl ReviewFixture {
    fn create() -> Self {
        let baseline = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
        let inspected =
            registry_breg::package::inspect_package_integrity(&baseline.package).unwrap();
        let mut module: Value = serde_json::from_slice(&package_module_bytes()).unwrap();
        module["entities"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"label", "type":"string", "maximumLength":32, "classification":"internal"
            }));
        module["entities"][0]["accessProfiles"][0]["readableFields"] = json!(["code", "label"]);
        module["entities"][0]["accessProfiles"][0]["filterableFields"] = json!(["label"]);
        let module_bytes = canonicalize_json(&module).unwrap();
        let module = parse_module_json(&module_bytes).unwrap();
        let project_bytes = package_project_bytes(&module_digest(&module));
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
            inspected.package_digest(),
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
            history: None,
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
            prior_package_digest: inspected.package_digest().into(),
            prior_schema_fingerprint: inspected.schema_fingerprint().into(),
            plan_sha256: sha256_prefixed(&descriptor_bytes),
            sql_sha256: vec![],
            assertion_sha256: vec![],
            fixture_inventory: vec![],
            postgres_major: 16,
            row_assertions: vec![],
            final_schema_fingerprint: FINGERPRINT.into(),
        };
        let receipt_bytes = canonicalize_json(&serde_json::to_value(receipt).unwrap()).unwrap();
        let review = project.path().join("review");
        fs::create_dir_all(review.join(BASE)).unwrap();
        fs::write(review.join(BASE).join("descriptor.json"), &descriptor_bytes).unwrap();
        fs::write(review.join(BASE).join("rehearsal.json"), &receipt_bytes).unwrap();
        let predecessor = load_predecessor_package(
            &baseline.package,
            &PackageLoadContext {
                database_initialization_environment: "production",
            },
        )
        .unwrap();
        let prepared = prepare_package(PackageBuildRequest {
            from_package_digest: Some(inspected.package_digest().into()),
            compiler_source_revision: PACKAGE_SOURCE_REVISION.into(),
            schema_fingerprint: FINGERPRINT.into(),
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
            prepared,
        }
    }

    fn run(&self, command: &str, with_review: bool) -> Output {
        self.run_as(command, with_review, true)
    }

    fn run_as(&self, command: &str, with_review: bool, json: bool) -> Output {
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
        let mut args = if json {
            vec!["--format", "json"]
        } else {
            vec![]
        };
        args.extend([
            command,
            path(self.project.path()),
            "--baseline-package",
            path(&self.baseline.package),
            "--output",
            path(&output),
        ]);
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
        bregctl(&args)
    }

    /// Run `command` with the review, printing human output.
    fn run_human(&self, command: &str) -> Output {
        self.run_as(command, true, false)
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
    let diff = bregctl(&[
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
        .find(|change| change["change"]["code"] == "query-inventory-changed")
        .unwrap();
    assert_eq!(query_change["classification"], "access-change");
    let profile_change = report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["change"]["code"] == "access-profile-changed")
        .unwrap();
    assert_eq!(profile_change["classification"], "access-change");
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
    assert_eq!(
        json_stdout(&package)["packageDigest"],
        fixture.prepared.package_digest().unwrap()
    );
    assert!(fixture
        .project
        .path()
        .join("build/package/package.json")
        .is_file());
}

impl ReviewFixture {
    /// Publish the successor, and return a runtime file that names it as the
    /// active package.
    fn publish_successor_as_active(&self) -> PathBuf {
        let package = self.project.path().join("successor-package");
        self.prepared
            .publish_to_directory(&package)
            .expect("the successor package publishes");
        let runtime_parent = self.project.path().join("successor-runtime");
        fs::create_dir_all(&runtime_parent).expect("the successor runtime directory creates");
        write_runtime_config(&runtime_parent, &package, "127.0.0.1:1".parse().unwrap())
    }
}

#[test]
fn apply_reports_an_unchanged_successor_as_nothing_to_apply() {
    let baseline = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let inspected = registry_breg::package::inspect_package_integrity(&baseline.package).unwrap();
    let module_bytes = package_module_bytes();
    let module = parse_module_json(&module_bytes).unwrap();
    let project_bytes = package_project_bytes(&module_digest(&module));
    let project = TestProject::from_registry_source(&project_bytes);
    let predecessor = load_predecessor_package(
        &baseline.package,
        &PackageLoadContext {
            database_initialization_environment: "production",
        },
    )
    .unwrap();
    let prepared = prepare_package(PackageBuildRequest {
        from_package_digest: Some(inspected.package_digest().into()),
        compiler_source_revision: PACKAGE_SOURCE_REVISION.into(),
        schema_fingerprint: inspected.schema_fingerprint().into(),
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
        migration_plan: PackageMigrationPlanInput::SuccessorFromBaseline {
            prior_baseline: Box::new(predecessor.migration_baseline().clone()),
        },
    })
    .unwrap();
    let package = project.path().join("successor-package");
    prepared.publish_to_directory(&package).unwrap();
    let package_digest = prepared.package_digest().unwrap();

    // The refusal precedes any connection, so the migration URL names a
    // closed port.
    let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args([
            "--format",
            "json",
            "apply",
            "--runtime-config",
            path(&baseline.runtime_config),
            "--package",
            path(&package),
        ])
        .env(
            "VERIFY_MIGRATION_DATABASE_SECRET_IS_NOT_OPENED",
            "postgresql://registry_migration@127.0.0.1:1/breg",
        )
        .output()
        .expect("bregctl starts");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "apply.package.empty_plan");
    assert_eq!(diagnostic["path"], "package");
    let message = diagnostic["message"].as_str().expect("message is text");
    assert!(message.contains("nothing to apply"), "{message}");
    assert!(message.contains("Nothing was changed"), "{message}");
    assert_tool_diagnostic(diagnostic, "verified_package", "correct_package_build");
    let rendered = String::from_utf8(output.stdout).expect("apply refusal is UTF-8");
    for forbidden in [
        path(&baseline.runtime_config),
        path(&package),
        package_digest.as_str(),
        "VERIFY_MIGRATION_DATABASE_SECRET_IS_NOT_OPENED",
    ] {
        assert!(!rendered.contains(forbidden), "{rendered}");
    }
}

#[test]
fn migration_explain_names_every_bound_a_reviewed_migration_carries() {
    let fixture = ReviewFixture::create();
    let runtime_config = fixture.publish_successor_as_active();

    let explained = bregctl(&[
        "migration",
        "explain",
        "--runtime-config",
        path(&runtime_config),
    ]);

    assert!(explained.status.success(), "{explained:?}");
    assert!(explained.stderr.is_empty());
    let rendered = String::from_utf8(explained.stdout).expect("the migration report is UTF-8");
    assert!(
        rendered.contains("\n  reviewed migration 1\n"),
        "{rendered}"
    );
    let detail = |label: &str| {
        rendered
            .lines()
            .find_map(|line| line.trim_start().strip_prefix(label))
            .map(|value| value.trim().to_owned())
    };
    for (label, value) in [
        ("change class", "access-or-disclosure-change"),
        ("recovery", "exact-target-resume"),
        ("lock timeout ms", "1000"),
        ("statement timeout ms", "5000"),
        ("transactional step count", "0"),
        ("chunked step count", "0"),
        ("pre-assertion count", "0"),
        ("post-assertion count", "0"),
        ("backup required", "false"),
    ] {
        assert_eq!(
            detail(label).as_deref(),
            Some(value),
            "the reviewed migration reports {label}: {rendered}"
        );
    }
}

#[test]
fn reviewed_successor_changed_review_invalidates_the_schema_test_receipt() {
    let fixture = ReviewFixture::create();
    // This remains a valid review, but it is no longer the tested candidate.
    fixture.mutate_json("descriptor.json", |value| {
        value["lockTimeoutMilliseconds"] = json!(2000)
    });
    let descriptor = fs::read(fixture.review.join(BASE).join("descriptor.json")).unwrap();
    fixture.mutate_json("rehearsal.json", |value| {
        value["planDigest"] = json!(sha256_prefixed(&descriptor))
    });
    let output = fixture.run("package", true);
    assert!(!output.status.success());
    let diagnostic = json_stdout(&output)["diagnostics"][0].clone();
    assert_eq!(
        diagnostic["code"],
        "package.test_receipt.candidate_mismatch"
    );
    assert_eq!(diagnostic["path"], "testReceipt.sourceClosureSha256");
    assert!(
        diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("sourceClosureSha256"),
        "{diagnostic}"
    );
    assert!(!fixture.project.path().join("build").exists());
}

#[test]
fn reviewed_successor_cli_requires_a_verified_baseline_argument() {
    let error = registry_bregctl::command()
        .try_get_matches_from([
            "bregctl",
            "test",
            ".",
            "--reviewed-migrations",
            "review",
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
    assert!(error.to_string().contains("--baseline-package"));
}

#[test]
fn reviewed_successor_refuses_a_baseline_from_another_registry_before_receipt_validation() {
    let fixture = ReviewFixture::create();
    let receipt = fixture.project.path().join("test-receipt.json");
    fs::write(
        &receipt,
        schema_test_receipt_bytes(&fixture.prepared, &["package-record-list"]),
    )
    .unwrap();
    let registry_file = fixture.project.path().join("registry.yaml");
    let mut source: Value = serde_json::from_slice(&fs::read(&registry_file).unwrap()).unwrap();
    source["project"]["id"] = json!("another-registry");
    fs::write(&registry_file, canonicalize_json(&source).unwrap()).unwrap();
    let output = fixture.project.path().join("other-registry-build");
    let result = bregctl(&[
        "--format",
        "json",
        "package",
        path(fixture.project.path()),
        "--baseline-package",
        path(&fixture.baseline.package),
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
    let diagnostic = json_stdout(&result)["diagnostics"][0].clone();
    assert_eq!(
        diagnostic["code"], "package.baseline.identity",
        "{diagnostic}"
    );
    assert!(!output.exists());
}

#[test]
fn reviewed_successor_refuses_unbound_evidence_and_uncovered_changes_before_io() {
    // A well-formed digest that binds nothing this review holds, so each
    // refusal comes from the binding check rather than from the reader.
    let unbound = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for (field, code) in [
        ("priorPackageDigest", "migration.review.evidence_refused"),
        (
            "priorSchemaFingerprint",
            "migration.review.evidence_refused",
        ),
        ("planDigest", "migration.review.evidence_refused"),
    ] {
        let fixture = ReviewFixture::create();
        fixture.mutate_json("rehearsal.json", |value| value[field] = json!(unbound));
        for command in ["test", "package"] {
            let output = fixture.run(command, true);
            assert!(!output.status.success());
            assert_eq!(
                json_stdout(&output)["diagnostics"][0]["code"],
                code,
                "{field}: {output:?}"
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
        "migration.review.descriptor_refused"
    );
}

#[test]
fn reviewed_successor_refuses_a_malformed_receipt_digest_at_its_key_without_repeating_it() {
    for field in [
        "priorPackageDigest",
        "priorSchemaFingerprint",
        "planDigest",
        "finalSchemaFingerprint",
    ] {
        let fixture = ReviewFixture::create();
        fixture.mutate_json("rehearsal.json", |value| {
            value[field] = json!("private-review-value-canary")
        });
        for command in ["test", "package"] {
            let output = fixture.run(command, true);
            assert_eq!(output.status.code(), Some(1), "{field}: {output:?}");
            let report = json_stdout(&output);
            let diagnostic = &report["diagnostics"][0];
            assert_eq!(diagnostic["code"], "config.invalid-value", "{field}");
            assert_eq!(diagnostic["path"], format!("/{field}"));
            assert_eq!(
                diagnostic["source"]["file"],
                path(&fixture.review.join(BASE).join("rehearsal.json"))
            );
            assert!(diagnostic["source"]["line"].is_u64(), "{diagnostic}");
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains("private-review-value-canary")
            );
            assert!(!fixture.project.path().join("build").exists());
            assert!(!fixture.project.path().join("result.json").exists());
        }
    }
}

#[test]
fn reviewed_successor_refuses_a_receipt_that_carries_retired_proofs() {
    let fixture = ReviewFixture::create();
    fixture.mutate_json("rehearsal.json", |value| {
        value["proofs"] = json!({
            "chunkResume": false,
            "destructiveResume": false,
            "lockTimeout": true,
        })
    });
    for command in ["test", "package"] {
        let output = fixture.run(command, true);
        assert!(!output.status.success());
        let diagnostic = &json_stdout(&output)["diagnostics"][0];
        assert_eq!(
            diagnostic["code"], "config.removed-key",
            "{command}: {output:?}"
        );
        assert_eq!(diagnostic["path"], "/proofs");
        assert_eq!(
            diagnostic["source"]["file"],
            path(&fixture.review.join(BASE).join("rehearsal.json"))
        );
        let action = diagnostic["suggestedAction"].as_str().unwrap();
        assert!(action.contains("Delete `proofs`"), "{action}");
        assert!(!fixture.project.path().join("build").exists());
        assert!(!fixture.project.path().join("result.json").exists());
    }
    let output = fixture.run_human("test");
    let rendered = String::from_utf8(output.stderr).unwrap();
    assert!(
        rendered.starts_with("bregctl test refused the migration rehearsal receipt.\n"),
        "{rendered}"
    );
    assert!(rendered.contains("config.removed-key"), "{rendered}");
}

#[test]
fn reviewed_successor_accepts_a_reformatted_descriptor_and_refuses_previous_spellings() {
    let fixture = ReviewFixture::create();
    let descriptor_path = fixture.review.join(BASE).join("descriptor.json");
    let value: Value = serde_json::from_slice(&fs::read(&descriptor_path).unwrap()).unwrap();
    fs::write(&descriptor_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    // The review validates, so the run reaches the credentials it was not
    // given.
    let test = fixture.run("test", true);
    assert_eq!(
        json_stdout(&test)["diagnostics"][0]["code"],
        "test.credentials.refused",
        "{test:?}"
    );

    let fixture = ReviewFixture::create();
    fixture.mutate_json("descriptor.json", |value| {
        let object = value.as_object_mut().unwrap();
        let timeout = object.remove("statementTimeoutMilliseconds").unwrap();
        object.insert("statementTimeoutMs".into(), timeout);
    });
    let output = fixture.run("package", true);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = json_stdout(&output);
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "config.removed-key")
        .unwrap_or_else(|| panic!("the previous spelling is named: {report}"));
    assert_eq!(diagnostic["path"], "/statementTimeoutMs");
    assert!(diagnostic["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("`statementTimeoutMilliseconds`"));
}

#[test]
fn reviewed_successor_refuses_duplicate_keys_headerless_documents_and_extra_artifacts() {
    for (malformed, code) in [
        (
            format!(
                "{{\"apiVersion\":\"{}\",\"kind\":\"{}\",\"id\":\"read-label\",\"id\":\"private-review-value-canary\"}}",
                registry_breg::migration_plan::MIGRATION_DESCRIPTOR_API_VERSION,
                registry_breg::migration_plan::MIGRATION_DESCRIPTOR_KIND,
            )
            .into_bytes(),
            "yaml.duplicate-key",
        ),
        (b"{}\n".to_vec(), "config.missing-envelope"),
    ] {
        let fixture = ReviewFixture::create();
        fs::write(fixture.review.join(BASE).join("descriptor.json"), &malformed).unwrap();
        let output = fixture.run("test", true);
        assert_eq!(json_stdout(&output)["diagnostics"][0]["code"], code);
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
        "migration.review.coverage_refused"
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

/// A successor project whose project and module sources are mutated before
/// compilation, for the refusals an adopter meets before authoring a review.
fn successor_project(
    mutate_module: impl FnOnce(&mut Value),
    mutate_project: impl FnOnce(&mut Value),
) -> (RuntimePackageFixture, TestProject) {
    let baseline = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let mut module: Value = serde_json::from_slice(&package_module_bytes()).unwrap();
    mutate_module(&mut module);
    let module_bytes = canonicalize_json(&module).unwrap();
    let parsed = parse_module_json(&module_bytes).unwrap();
    let mut source: Value =
        serde_json::from_slice(&package_project_bytes(&module_digest(&parsed))).unwrap();
    mutate_project(&mut source);
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
    (baseline, project)
}

fn package_successor(baseline: &RuntimePackageFixture, project: &TestProject) -> Output {
    bregctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
        "--baseline-package",
        path(&baseline.package),
        "--schema-fingerprint",
        FINGERPRINT,
        "--test-receipt",
        path(&project.path().join("absent-receipt.json")),
        "--output",
        path(&project.path().join("build")),
    ])
}

#[test]
fn a_successor_needing_review_names_every_change_and_its_target() {
    let (baseline, project) = successor_project(
        |module| {
            module["entities"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id": "label",
                    "type": "string",
                    "maximumLength": 32,
                    "required": true,
                    "classification": "internal"
                }));
        },
        |_| {},
    );
    let output = package_successor(&baseline, &project);
    assert!(!output.status.success(), "{output:?}");
    let diagnostic = json_stdout(&output)["diagnostics"][0].clone();
    assert_eq!(diagnostic["code"], "migration.review.required");
    let message = diagnostic["message"].as_str().unwrap().to_owned();
    assert!(message.contains("field-added-required"), "{message}");
    assert!(message.contains("record.label"), "{message}");
    assert!(message.contains("--reviewed-migrations"), "{message}");
    assert!(!project.path().join("build").exists());
}

#[test]
fn an_unsupported_successor_names_every_change_and_why_it_cannot_be_planned() {
    let (baseline, project) =
        successor_project(|_| {}, |source| source["project"]["version"] = json!("2"));
    let output = package_successor(&baseline, &project);
    assert!(!output.status.success(), "{output:?}");
    let diagnostic = json_stdout(&output)["diagnostics"][0].clone();
    assert_eq!(diagnostic["code"], "migration.change.unsupported");
    let message = diagnostic["message"].as_str().unwrap().to_owned();
    assert!(message.contains("registry-version-changed"), "{message}");
    assert!(message.contains("registry-identity-changed"), "{message}");
    assert!(message.contains("at registry"), "{message}");
    assert!(
        message.contains("bound to the database for its lifetime"),
        "{message}"
    );
    assert!(!project.path().join("build").exists());
}

#[test]
fn a_refused_review_names_the_changes_it_has_to_cover() {
    let fixture = ReviewFixture::create();
    fixture.mutate_json("descriptor.json", |value| value["covers"] = json!([]));
    let output = fixture.run("package", true);
    let diagnostic = json_stdout(&output)["diagnostics"][0].clone();
    assert_eq!(diagnostic["code"], "migration.review.descriptor_refused");
    let message = diagnostic["message"].as_str().unwrap().to_owned();
    assert!(message.contains("access-profile-changed"), "{message}");
    assert!(message.contains("at record.reader"), "{message}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-review-value-canary"));
}
