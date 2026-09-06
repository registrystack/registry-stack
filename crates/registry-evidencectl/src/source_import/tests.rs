use super::*;
use std::os::unix::fs::{symlink, PermissionsExt as _};

struct Fixture {
    root: tempfile::TempDir,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        put(&project, "evidence-project.yaml", "version: 1\n");
        Self { root, project }
    }

    fn export(
        &self,
        directory: &str,
        id: &str,
        revision: &str,
        artifacts: &[(&str, &str)],
    ) -> PathBuf {
        let root = self.root.path().join(directory);
        fs::create_dir_all(&root).unwrap();
        let mut entries = Vec::new();
        for (path, text) in artifacts {
            put(&root, path, text);
            entries.push(ExportArtifact {
                path: (*path).to_owned(),
                sha256: digest(text.as_bytes()),
            });
        }
        let manifest = ExportManifest {
            format_version: 1,
            source_id: id.to_owned(),
            provenance: BTreeMap::from([
                ("producer".to_owned(), "source-contract-test".to_owned()),
                ("revision".to_owned(), revision.to_owned()),
            ]),
            artifacts: entries,
        };
        put(
            &root,
            MANIFEST_FILE,
            &serde_json::to_string(&manifest).unwrap(),
        );
        root
    }
}

fn put(root: &Path, path: &str, text: &str) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), text).unwrap();
}

fn accepted(
    lock: &ProjectLock,
    exports: &[PathBuf],
    resolutions: BTreeMap<String, Resolution>,
) -> bool {
    let mut candidate = prepare(lock, exports, &resolutions).unwrap();
    // Unit tests exercise update mechanics. CLI integration supplies the real
    // authoring/compiler validation callback rather than this narrow fixture.
    candidate.validate(|_| Ok(())).unwrap();
    let no_op = candidate.report().no_op;
    candidate.apply(lock).unwrap();
    no_op
}

#[test]
fn moved_exports_and_reordered_inventory_are_true_no_ops() {
    let fixture = Fixture::new();
    let export = fixture.export(
        "first-location",
        "lookup",
        "v1",
        &[
            (
                "sources/lookup.yaml",
                "extractScript: adapters/lookup.rhai\n",
            ),
            (
                "adapters/lookup.rhai",
                "fn extract(response, context) { response }\n",
            ),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    assert!(!accepted(
        &lock,
        std::slice::from_ref(&export),
        BTreeMap::new()
    ));
    let state = fs::read(fixture.project.join(STATE_PATH)).unwrap();
    let moved = fixture.root.path().join("moved-export");
    fs::rename(export, &moved).unwrap();
    let mut manifest: ExportManifest =
        serde_json::from_slice(&fs::read(moved.join(MANIFEST_FILE)).unwrap()).unwrap();
    manifest.artifacts.reverse();
    fs::write(
        moved.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    assert!(accepted(&lock, &[moved], BTreeMap::new()));
    assert_eq!(fs::read(fixture.project.join(STATE_PATH)).unwrap(), state);
}

#[test]
fn customization_conflicts_finish_with_keep_adopt_and_resolved_file() {
    for choice in ["keep", "adopt", "file"] {
        let fixture = Fixture::new();
        let original = fixture.export(
            "original",
            "lookup",
            "v1",
            &[
                (
                    "sources/lookup.yaml",
                    "extractScript: adapters/lookup.rhai\n",
                ),
                ("adapters/lookup.rhai", "upstream-one\n"),
            ],
        );
        let lock = ProjectLock::acquire(&fixture.project).unwrap();
        accepted(&lock, &[original], BTreeMap::new());
        put(
            &fixture.project,
            "adapters/lookup.rhai",
            "authored-customization\n",
        );
        put(
            &fixture.project,
            "adapters/unrelated.rhai",
            "independent-authoring\n",
        );
        let next = fixture.export(
            "next",
            "lookup",
            "v2",
            &[
                (
                    "sources/lookup.yaml",
                    "extractScript: adapters/lookup.rhai\n",
                ),
                ("adapters/lookup.rhai", "upstream-two\n"),
            ],
        );
        let mut conflict = prepare(&lock, std::slice::from_ref(&next), &BTreeMap::new()).unwrap();
        assert_eq!(conflict.report().conflicts, ["adapters/lookup.rhai"]);
        assert!(conflict.validate(|_| Ok(())).is_err());
        let resolved = fixture.root.path().join("resolved.rhai");
        fs::write(&resolved, "reviewed-resolution\n").unwrap();
        let (resolution, expected) = match choice {
            "keep" => (Resolution::Keep, "authored-customization\n"),
            "adopt" => (Resolution::Adopt, "upstream-two\n"),
            _ => (Resolution::File { path: resolved }, "reviewed-resolution\n"),
        };
        accepted(
            &lock,
            std::slice::from_ref(&next),
            BTreeMap::from([("adapters/lookup.rhai".to_owned(), resolution)]),
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join("adapters/lookup.rhai")).unwrap(),
            expected
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join("adapters/unrelated.rhai")).unwrap(),
            "independent-authoring\n"
        );
        let state = parse_state(
            read(&fixture.project, STATE_PATH, MAX_STATE_BYTES)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        assert_eq!(
            state.imports["lookup"].upstream["adapters/lookup.rhai"],
            "upstream-two\n"
        );
        assert_eq!(
            state.accepted["adapters/lookup.rhai"].as_deref(),
            Some(expected)
        );
        assert!(accepted(&lock, &[next], BTreeMap::new()));
    }
}

#[test]
fn shared_changes_require_one_consistent_multi_export_candidate() {
    let fixture = Fixture::new();
    let first = fixture.export(
        "a-one",
        "first",
        "v1",
        &[
            ("sources/first.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 1\n"),
        ],
    );
    let second = fixture.export(
        "b-one",
        "second",
        "v1",
        &[
            ("sources/second.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 1\n"),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[first, second], BTreeMap::new());
    let first_next = fixture.export(
        "a-two",
        "first",
        "v2",
        &[
            ("sources/first.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 2\n"),
        ],
    );
    let second_next = fixture.export(
        "b-two",
        "second",
        "v2",
        &[
            ("sources/second.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 2\n"),
        ],
    );
    let conflict = prepare(&lock, std::slice::from_ref(&first_next), &BTreeMap::new()).unwrap();
    let shared = conflict
        .report()
        .changes
        .iter()
        .find(|change| change.path == "selectors/shared.yaml")
        .unwrap();
    assert_eq!(shared.next_owners, ["first", "second"]);
    assert_eq!(conflict.report().conflicts, ["selectors/shared.yaml"]);
    assert_eq!(
        fs::read_to_string(fixture.project.join("selectors/shared.yaml")).unwrap(),
        "version: 1\n"
    );
    accepted(&lock, &[first_next, second_next], BTreeMap::new());
    assert_eq!(
        fs::read_to_string(fixture.project.join("selectors/shared.yaml")).unwrap(),
        "version: 2\n"
    );
}

#[test]
fn deleting_obsolete_artifacts_preserves_customization_and_authored_references() {
    let fixture = Fixture::new();
    let initial = fixture.export(
        "initial",
        "lookup",
        "v1",
        &[
            ("sources/lookup.yaml", "kind: initial\n"),
            ("adapters/unused.rhai", "generated\n"),
            ("adapters/referenced.rhai", "generated\n"),
            ("adapters/custom.rhai", "generated\n"),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[initial], BTreeMap::new());
    put(
        &fixture.project,
        "sources/authored.yaml",
        "extractScript: adapters/referenced.rhai\n",
    );
    put(&fixture.project, "adapters/custom.rhai", "customized\n");
    let next = fixture.export(
        "next",
        "lookup",
        "v2",
        &[("sources/lookup.yaml", "kind: next\n")],
    );
    let mut candidate = prepare(
        &lock,
        &[next],
        &BTreeMap::from([("adapters/custom.rhai".to_owned(), Resolution::Keep)]),
    )
    .unwrap();
    assert_eq!(
        candidate
            .report()
            .changes
            .iter()
            .find(|change| change.path == "adapters/unused.rhai")
            .unwrap()
            .action,
        "delete"
    );
    assert_eq!(
        candidate
            .report()
            .changes
            .iter()
            .find(|change| change.path == "adapters/referenced.rhai")
            .unwrap()
            .action,
        "retained"
    );
    candidate.validate(|_| Ok(())).unwrap();
    candidate.apply(&lock).unwrap();
    assert!(!fixture.project.join("adapters/unused.rhai").exists());
    assert_eq!(
        fs::read_to_string(fixture.project.join("adapters/referenced.rhai")).unwrap(),
        "generated\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.project.join("adapters/custom.rhai")).unwrap(),
        "customized\n"
    );
}

#[test]
fn stale_candidate_and_unvalidated_candidate_cannot_change_the_project() {
    let fixture = Fixture::new();
    let export = fixture.export(
        "export",
        "lookup",
        "v1",
        &[("sources/lookup.yaml", "version: 1\n")],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    assert!(
        prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new())
            .unwrap()
            .apply(&lock)
            .is_err()
    );
    let mut candidate = prepare(&lock, &[export], &BTreeMap::new()).unwrap();
    candidate.validate(|_| Ok(())).unwrap();
    put(
        &fixture.project,
        "questions/independent.yaml",
        "id: independent\n",
    );
    assert!(candidate.apply(&lock).is_err());
    assert!(!fixture.project.join(STATE_PATH).exists());
    assert!(!fixture.project.join("sources/lookup.yaml").exists());
    assert_eq!(
        fs::read_to_string(fixture.project.join("questions/independent.yaml")).unwrap(),
        "id: independent\n"
    );
}

#[test]
fn candidate_contains_no_secret_target_or_local_service_state() {
    let fixture = Fixture::new();
    put(
        &fixture.project,
        "secrets/credential",
        "sensitive-test-canary",
    );
    put(
        &fixture.project,
        ".evidence/dev/request.json",
        "private-request-canary",
    );
    put(
        &fixture.project,
        "targets/production/governance.yaml",
        "institution-target-canary",
    );
    put(
        &fixture.project,
        "access/clients/client.yaml",
        "caller-state-canary",
    );
    let export = fixture.export(
        "export",
        "lookup",
        "v1",
        &[("sources/lookup.yaml", "version: 1\n")],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let candidate = prepare(&lock, &[export], &BTreeMap::new()).unwrap();
    for path in ["secrets", ".evidence", "targets", "access"] {
        assert!(!candidate.project().join(path).exists());
    }
    assert!(candidate.project().join("sources/lookup.yaml").exists());
}

#[test]
fn build_lock_serializes_updates_without_requiring_writable_project_state() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.project, fs::Permissions::from_mode(0o500)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    assert!(ProjectLock::acquire(&fixture.project).is_err());
    assert!(!fixture.project.join(".evidence").exists());
    drop(lock);
    assert!(ProjectLock::acquire(&fixture.project).is_ok());
    fs::set_permissions(&fixture.project, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn interrupted_replacement_and_baseline_advance_restore_the_complete_prior_state() {
    for applied_count in 0..=3 {
        let fixture = Fixture::new();
        let export = fixture.export(
            "initial",
            "lookup",
            "v1",
            &[
                ("sources/lookup.yaml", "version: 1\n"),
                ("adapters/lookup.rhai", "original\n"),
            ],
        );
        let lock = ProjectLock::acquire(&fixture.project).unwrap();
        accepted(&lock, &[export], BTreeMap::new());
        let baseline = read(&fixture.project, STATE_PATH, MAX_STATE_BYTES).unwrap();
        let operations = vec![
            Operation {
                path: "sources/lookup.yaml".to_owned(),
                before: read(&fixture.project, "sources/lookup.yaml", MAX_FILE_BYTES).unwrap(),
                after: Some(Contents {
                    text: "version: 2\n".to_owned(),
                    mode: 0o600,
                }),
            },
            Operation {
                path: "adapters/lookup.rhai".to_owned(),
                before: read(&fixture.project, "adapters/lookup.rhai", MAX_FILE_BYTES).unwrap(),
                after: None,
            },
            Operation {
                path: STATE_PATH.to_owned(),
                before: baseline.clone(),
                after: Some(Contents {
                    text: "candidate-baseline\n".to_owned(),
                    mode: 0o600,
                }),
            },
        ];
        let journal = Journal {
            format_version: 1,
            operations,
        };
        write(
            &fixture.project,
            JOURNAL_PATH,
            Some(&Contents {
                text: serde_json::to_string(&journal).unwrap(),
                mode: 0o600,
            }),
        )
        .unwrap();
        for operation in journal.operations.iter().take(applied_count) {
            write(&fixture.project, &operation.path, operation.after.as_ref()).unwrap();
        }
        drop(lock);
        // The same entry point used by builds recovers before granting a reader.
        let recovered = ProjectLock::acquire(&fixture.project).unwrap();
        assert_eq!(
            fs::read_to_string(fixture.project.join("sources/lookup.yaml")).unwrap(),
            "version: 1\n"
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join("adapters/lookup.rhai")).unwrap(),
            "original\n"
        );
        assert_eq!(
            read(&fixture.project, STATE_PATH, MAX_STATE_BYTES).unwrap(),
            baseline
        );
        assert!(!fixture.project.join(JOURNAL_PATH).exists());
        drop(recovered);
        assert!(ProjectLock::acquire(&fixture.project).is_ok());
    }
}

#[test]
fn recovery_checks_every_precondition_before_touching_independent_edits() {
    let fixture = Fixture::new();
    put(&fixture.project, "adapters/first.rhai", "after\n");
    put(
        &fixture.project,
        "adapters/second.rhai",
        "independent-edit\n",
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    files::ensure_state_directory(&fixture.project).unwrap();
    let operations = ["adapters/first.rhai", "adapters/second.rhai"]
        .into_iter()
        .map(|path| Operation {
            path: path.to_owned(),
            before: Some(Contents {
                text: "before\n".to_owned(),
                mode: 0o644,
            }),
            after: Some(Contents {
                text: "after\n".to_owned(),
                mode: 0o644,
            }),
        })
        .collect();
    write(
        &fixture.project,
        JOURNAL_PATH,
        Some(&Contents {
            text: serde_json::to_string(&Journal {
                format_version: 1,
                operations,
            })
            .unwrap(),
            mode: 0o600,
        }),
    )
    .unwrap();
    drop(lock);
    assert!(ProjectLock::acquire(&fixture.project).is_err());
    assert_eq!(
        fs::read_to_string(fixture.project.join("adapters/first.rhai")).unwrap(),
        "after\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.project.join("adapters/second.rhai")).unwrap(),
        "independent-edit\n"
    );
    assert!(fixture.project.join(JOURNAL_PATH).exists());
}

#[test]
fn build_refuses_recovery_capability_planted_in_writable_shared_state() {
    for writable in [
        ".",
        ".evidence",
        ".evidence/source-imports",
        JOURNAL_PATH,
        STATE_PATH,
    ] {
        let fixture = Fixture::new();
        put(
            &fixture.project,
            "sources/protected.yaml",
            "reviewed: current\n",
        );
        let current = read(&fixture.project, "sources/protected.yaml", MAX_FILE_BYTES).unwrap();
        files::ensure_state_directory(&fixture.project).unwrap();
        let journal = Journal {
            format_version: 1,
            operations: vec![Operation {
                path: "sources/protected.yaml".to_owned(),
                before: Some(Contents {
                    text: "unreviewed: replacement\n".to_owned(),
                    mode: 0o644,
                }),
                after: current,
            }],
        };
        write(
            &fixture.project,
            JOURNAL_PATH,
            Some(&Contents {
                text: serde_json::to_string(&journal).unwrap(),
                mode: 0o600,
            }),
        )
        .unwrap();
        write(
            &fixture.project,
            STATE_PATH,
            Some(&Contents {
                text: "{}\n".to_owned(),
                mode: 0o600,
            }),
        )
        .unwrap();
        let path = fixture.project.join(writable);
        let mode = if path.is_dir() { 0o777 } else { 0o666 };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();

        assert!(ProjectLock::acquire(&fixture.project).is_err());
        assert_eq!(
            fs::read_to_string(fixture.project.join("sources/protected.yaml")).unwrap(),
            "reviewed: current\n"
        );
        assert!(fixture.project.join(JOURNAL_PATH).exists());
    }
}

#[test]
fn detach_keeps_provenance_and_prevents_implicit_shared_artifact_changes() {
    let fixture = Fixture::new();
    let first = fixture.export(
        "a",
        "first",
        "v1",
        &[
            ("sources/first.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 1\n"),
        ],
    );
    let second = fixture.export(
        "b",
        "second",
        "v1",
        &[
            ("sources/second.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 1\n"),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[first.clone(), second], BTreeMap::new());
    let authored = snapshot(&fixture.project).unwrap();
    detach(&lock, "first").unwrap();
    detach(&lock, "first").unwrap();
    assert_eq!(snapshot(&fixture.project).unwrap(), authored);
    let state = parse_state(
        read(&fixture.project, STATE_PATH, MAX_STATE_BYTES)
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    assert!(state.imports["first"].detached);
    assert_eq!(state.imports["first"].manifest.provenance["revision"], "v1");
    assert!(prepare(&lock, &[first], &BTreeMap::new()).is_err());
    let next = fixture.export(
        "b-next",
        "second",
        "v2",
        &[
            ("sources/second.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 2\n"),
        ],
    );
    let candidate = prepare(&lock, &[next], &BTreeMap::new()).unwrap();
    assert_eq!(candidate.report().conflicts, ["selectors/shared.yaml"]);
}

#[test]
fn import_refuses_checksum_path_symlink_and_duplicate_identity_failures() {
    let fixture = Fixture::new();
    let export = fixture.export(
        "export",
        "lookup",
        "v1",
        &[("sources/lookup.yaml", "version: 1\n")],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    assert!(prepare(&lock, &[export.clone(), export.clone()], &BTreeMap::new()).is_err());
    let manifest_bytes = fs::read(export.join(MANIFEST_FILE)).unwrap();
    let mut duplicate: ExportManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    duplicate.artifacts.push(duplicate.artifacts[0].clone());
    fs::write(
        export.join(MANIFEST_FILE),
        serde_json::to_vec(&duplicate).unwrap(),
    )
    .unwrap();
    assert!(prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new()).is_err());
    let mut hook: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    hook["install"] = Value::String("unexpected-hook".to_owned());
    fs::write(
        export.join(MANIFEST_FILE),
        serde_json::to_vec(&hook).unwrap(),
    )
    .unwrap();
    assert!(prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new()).is_err());
    fs::write(export.join(MANIFEST_FILE), manifest_bytes).unwrap();
    put(&export, "sources/lookup.yaml", "version: 2\n");
    assert!(prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new()).is_err());
    for path in [
        "../sources/lookup.yaml",
        "/sources/lookup.yaml",
        "sources/../lookup.yaml",
        "targets/authority.yaml",
        "adapters/nested/lookup.rhai",
        "sources\\lookup.yaml",
    ] {
        assert!(artifact_path(path).is_err());
    }
    fs::remove_file(export.join("sources/lookup.yaml")).unwrap();
    let outside = fixture.root.path().join("outside.yaml");
    fs::write(&outside, "version: 1\n").unwrap();
    symlink(&outside, export.join("sources/lookup.yaml")).unwrap();
    assert!(prepare(&lock, &[export], &BTreeMap::new()).is_err());
    assert!(!fixture.project.join(STATE_PATH).exists());
}

#[test]
fn exact_authored_destination_collision_requires_an_explicit_ownership_choice() {
    let fixture = Fixture::new();
    put(&fixture.project, "sources/lookup.yaml", "version: 1\n");
    let export = fixture.export(
        "export",
        "lookup",
        "v1",
        &[("sources/lookup.yaml", "version: 1\n")],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let candidate = prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new()).unwrap();
    assert_eq!(candidate.report().conflicts, ["sources/lookup.yaml"]);
    accepted(
        &lock,
        &[export],
        BTreeMap::from([("sources/lookup.yaml".to_owned(), Resolution::Keep)]),
    );
    let next = fixture.export(
        "next",
        "lookup",
        "v2",
        &[("sources/lookup.yaml", "version: 2\n")],
    );
    assert_eq!(
        prepare(&lock, &[next], &BTreeMap::new())
            .unwrap()
            .report()
            .conflicts,
        ["sources/lookup.yaml"]
    );
}

#[test]
fn structural_impact_follows_source_dependencies_without_inventing_revisions() {
    let fixture = Fixture::new();
    put(
        &fixture.project,
        "questions/first.yaml",
        "source: {ref: lookup}\n",
    );
    put(
        &fixture.project,
        "questions/other.yaml",
        "source: {ref: other}\n",
    );
    let first = fixture.export(
        "first",
        "lookup",
        "v1",
        &[
            (
                "sources/lookup.yaml",
                "extractScript: adapters/lookup.rhai\n",
            ),
            ("adapters/lookup.rhai", "one\n"),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[first], BTreeMap::new());
    let next = fixture.export(
        "next",
        "lookup",
        "v2",
        &[
            (
                "sources/lookup.yaml",
                "extractScript: adapters/lookup.rhai\n",
            ),
            ("adapters/lookup.rhai", "two\n"),
        ],
    );
    let candidate = prepare(&lock, &[next], &BTreeMap::new()).unwrap();
    assert_eq!(candidate.report().affected_questions, ["first"]);
    assert!(serde_json::to_value(candidate.report())
        .unwrap()
        .get("configurationRevision")
        .is_none());
}
