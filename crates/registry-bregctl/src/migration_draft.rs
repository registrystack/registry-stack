// SPDX-License-Identifier: Apache-2.0
//! `bregctl migration draft`: write the reviewed migration directory for a
//! successor whose changes need no SQL.
//!
//! The descriptor covers exactly the changes that are not compatible-additive,
//! and the rehearsal receipt binds the predecessor package, the descriptor's
//! digest, and the fingerprint and PostgreSQL major the candidate measures on
//! the disposable database. The package validator still decides coverage and
//! evidence when the directory is passed as `--reviewed-migrations`.
//!
//! Every refusal that depends only on the arguments, the project, and the
//! baseline package happens before the runtime configuration is read or any
//! database is opened.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use registry_breg::migration_plan::{
    covers_are_metadata_only, read_migration_descriptor, read_rehearsal_receipt,
    MigrationRehearsalReceipt, ReviewedChangeCover, ReviewedMigrationDescriptor,
    ReviewedMigrationRecovery,
};
use registry_breg::package::{CompiledRegistryChange, CompiledRegistryChangeClass};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_yaml::LocalId;
use sha2::{Digest, Sha256};

use crate::safe_path::{SafeDir, SafeEntry, SafePathError};
use crate::{
    baseline_package_failure, candidate_failure, canonicalize_project_path,
    capture_resolved_project_source, compile_captured_project, has_parent_component,
    inspect_baseline_package, rendered_changes, test_lifecycle, DiagnosticArtifact, FailureReport,
    PackageCandidateArgs, ProfileArg, Refusal, SuggestedAction,
};

pub(crate) const COMMAND: &str = "migration draft";

const DESCRIPTOR_FILE: &str = "descriptor.json";
const RECEIPT_FILE: &str = "rehearsal.json";
const LOCK_TIMEOUT_MILLISECONDS: u64 = 1_000;
const STATEMENT_TIMEOUT_MILLISECONDS: u64 = 60_000;

pub(crate) struct DraftRequest<'a> {
    pub project: &'a Path,
    pub baseline_package: &'a Path,
    pub runtime_config: &'a Path,
    pub output: &'a Path,
    pub module: &'a str,
    pub id: &'a str,
}

/// What was written, for the success report.
#[derive(Debug)]
pub(crate) struct Drafted {
    pub directory: String,
    pub covers: Vec<ReviewedChangeCover>,
    pub plan_digest: String,
    pub prior_package_digest: String,
    pub final_schema_fingerprint: String,
    pub postgres_major: u16,
}

/// Why the changes cannot be drafted.
#[derive(Debug, Eq, PartialEq)]
enum CoverRefusal {
    NothingToReview,
    Unsupported(String),
    SqlRequired(String),
}

/// The two documents of one drafted migration, as canonical JSON.
#[derive(Debug)]
struct Documents {
    descriptor: Vec<u8>,
    receipt: Vec<u8>,
    plan_digest: String,
}

struct Measured<'a> {
    prior_package_digest: &'a str,
    prior_schema_fingerprint: &'a str,
    final_schema_fingerprint: &'a str,
    postgres_major: u16,
}

pub(crate) fn run(request: &DraftRequest<'_>) -> Result<Drafted, Refusal> {
    let (module, id) = checked_identifiers(request)?;
    let output = preflight_output(request.output, &module, &id)?;
    let selected_project = canonicalize_project_path(request.project).map_err(|diagnostic| {
        crate::source_failure(
            COMMAND,
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    let source = capture_resolved_project_source(&selected_project).map_err(|diagnostic| {
        crate::source_failure(
            COMMAND,
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    let compiled = compile_captured_project(&source, ProfileArg::Production, COMMAND)?;
    if !source
        .modules
        .iter()
        .any(|captured| captured.id.as_str() == module)
    {
        return Err(candidate_failure(
            COMMAND,
            "migration.draft.module-unknown",
            "module",
            &format!("the project has no module `{module}`; name one of its modules with --module"),
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::CorrectCommandUsage,
        )
        .into());
    }
    let baseline = inspect_baseline_package(request.baseline_package)
        .map_err(|error| baseline_package_failure(COMMAND, error))?;
    if baseline.package_id() != compiled.registry_id() {
        return Err(candidate_failure(
            COMMAND,
            "package.baseline.identity",
            "baselinePackage",
            "the baseline package belongs to another registry; name this registry's chain tip package directory with --baseline-package",
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::CorrectPackageBuild,
        )
        .into());
    }
    let changes = registry_breg::package::compiled_registry_change_set_from_baseline(
        baseline.migration_baseline(),
        &compiled,
        baseline.package_digest(),
    );
    let covers = plan_covers(&changes.changes).map_err(|refusal| cover_failure(&refusal))?;

    // A fresh install of the same project measures the fingerprint and
    // PostgreSQL major the receipt records, the way `test --fingerprint-only`
    // does.
    let candidate = crate::capture_candidate(
        &PackageCandidateArgs {
            project: request.project.to_path_buf(),
            baseline_package: None,
            reviewed_migrations: None,
        },
        COMMAND,
        false,
        false,
    )?;
    if candidate.registry().revision() != compiled.revision() {
        return Err(candidate_failure(
            COMMAND,
            "migration.draft.project-changed",
            "project",
            "the project changed while the draft was being prepared; run the command again",
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
        .into());
    }
    let measurement =
        test_lifecycle::measure(candidate, request.runtime_config).map_err(|error| {
            let mut failure = crate::test_lifecycle_failure(error);
            failure.command = COMMAND;
            failure
        })?;

    let documents = build_documents(
        &module,
        &id,
        &covers,
        &Measured {
            prior_package_digest: baseline.package_digest(),
            prior_schema_fingerprint: baseline.schema_fingerprint(),
            final_schema_fingerprint: &measurement.schema_fingerprint,
            postgres_major: measurement.postgres_major,
        },
    )
    .map_err(|message| {
        candidate_failure(
            COMMAND,
            "migration.draft.document-refused",
            "output",
            &message,
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::CorrectPackageBuild,
        )
    })?;
    publish(&output, &module, &id, &documents)?;
    Ok(Drafted {
        directory: relative_directory(&module, &id),
        covers,
        plan_digest: documents.plan_digest,
        prior_package_digest: baseline.package_digest().to_owned(),
        final_schema_fingerprint: measurement.schema_fingerprint,
        postgres_major: measurement.postgres_major,
    })
}

fn relative_directory(module: &str, id: &str) -> String {
    format!("modules/{module}/migrations/{id}")
}

fn checked_identifiers(request: &DraftRequest<'_>) -> Result<(String, String), FailureReport> {
    let local_id = |value: &str, path: &str, flag: &str| {
        LocalId::new(value).map(LocalId::into_string).map_err(|_| {
            candidate_failure(
                COMMAND,
                "migration.draft.id-invalid",
                path,
                &format!(
                    "{flag} must be a local identifier: lowercase letters, digits, `-` and `_`, starting with a letter, at most 64 characters"
                ),
                DiagnosticArtifact::CommandArguments,
                SuggestedAction::CorrectCommandUsage,
            )
        })
    };
    Ok((
        local_id(request.module, "module", "--module")?,
        local_id(request.id, "id", "--id")?,
    ))
}

/// The changes the descriptor covers, or the reason they cannot be drafted.
/// A draft has no steps, no assertions, and no backup binding, so it can only
/// review access and disclosure changes that alter no table, column, or
/// index.
fn plan_covers(
    changes: &[CompiledRegistryChange],
) -> Result<Vec<ReviewedChangeCover>, CoverRefusal> {
    let describe =
        |change: &CompiledRegistryChange| rendered_changes(std::slice::from_ref(change), |_| true);
    if let Some(change) = changes
        .iter()
        .find(|change| change.class == CompiledRegistryChangeClass::Unsupported)
    {
        return Err(CoverRefusal::Unsupported(describe(change)));
    }
    let reviewable = changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .collect::<Vec<_>>();
    if reviewable.is_empty() {
        return Err(CoverRefusal::NothingToReview);
    }
    for change in &reviewable {
        let needs_more = change.class != CompiledRegistryChangeClass::AccessOrDisclosureChange
            || !covers_are_metadata_only(&[ReviewedChangeCover::from(*change)]);
        if needs_more {
            return Err(CoverRefusal::SqlRequired(describe(change)));
        }
    }
    Ok(reviewable
        .into_iter()
        .map(ReviewedChangeCover::from)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn cover_failure(refusal: &CoverRefusal) -> FailureReport {
    match refusal {
        CoverRefusal::NothingToReview => candidate_failure(
            COMMAND,
            "migration.draft.nothing-to-review",
            "candidate",
            "every change against the baseline is compatible-additive, so no reviewed migration is needed; run test and package without --reviewed-migrations",
            DiagnosticArtifact::CompiledDiff,
            SuggestedAction::ReviewCompiledDiff,
        ),
        CoverRefusal::Unsupported(change) => candidate_failure(
            COMMAND,
            "migration.change.unsupported",
            "candidate",
            &format!(
                "the migration planner does not support this successor change: {change}. Inspect diff and revise the candidate. Reviewed artifacts cannot authorize unsupported changes"
            ),
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::CorrectPackageBuild,
        ),
        CoverRefusal::SqlRequired(change) => candidate_failure(
            COMMAND,
            "migration.draft.sql-required",
            "candidate",
            &format!(
                "this change needs a migration written by hand, with authored SQL, a backup binding, or a descriptor of its own class: {change}. A draft only covers access and disclosure changes that alter no table, column, or index"
            ),
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::ReviewCompiledDiff,
        ),
    }
}

fn build_documents(
    module: &str,
    id: &str,
    covers: &[ReviewedChangeCover],
    measured: &Measured<'_>,
) -> Result<Documents, String> {
    let directory = relative_directory(module, id);
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers: covers.to_vec(),
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: LOCK_TIMEOUT_MILLISECONDS,
        statement_timeout_ms: STATEMENT_TIMEOUT_MILLISECONDS,
        steps: Vec::new(),
        pre_assertions: Vec::new(),
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{directory}/{RECEIPT_FILE}"),
        backup_binding_path: None,
        history: None,
    };
    let descriptor_bytes = canonical_bytes(&descriptor)?;
    let plan_digest = sha256_digest(&descriptor_bytes);
    let receipt = MigrationRehearsalReceipt {
        prior_package_digest: measured.prior_package_digest.to_owned(),
        prior_schema_fingerprint: measured.prior_schema_fingerprint.to_owned(),
        plan_sha256: plan_digest.clone(),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: Vec::new(),
        postgres_major: measured.postgres_major,
        row_assertions: Vec::new(),
        final_schema_fingerprint: measured.final_schema_fingerprint.to_owned(),
    };
    let receipt_bytes = canonical_bytes(&receipt)?;
    // The drafted files are read back through the readers the package
    // validator uses, so a draft that would be refused is never written.
    read_migration_descriptor(&format!("{directory}/{DESCRIPTOR_FILE}"), &descriptor_bytes)
        .map_err(|_| "the drafted descriptor was refused by the descriptor reader".to_owned())?;
    read_rehearsal_receipt(&format!("{directory}/{RECEIPT_FILE}"), &receipt_bytes)
        .map_err(|_| "the drafted receipt was refused by the receipt reader".to_owned())?;
    Ok(Documents {
        descriptor: descriptor_bytes,
        receipt: receipt_bytes,
        plan_digest,
    })
}

fn canonical_bytes(document: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(document)
        .map_err(|_| "the drafted document does not serialize".to_owned())?;
    canonicalize_json(&value).map_err(|_| "the drafted document does not canonicalize".to_owned())
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// The migration directory's path under `output`, checked before anything is
/// measured: an unsafe or relative output, or an existing migration of the
/// same id, is refused with nothing written.
fn preflight_output(output: &Path, module: &str, id: &str) -> Result<PathBuf, FailureReport> {
    let invalid = |detail: &str| {
        candidate_failure(
            COMMAND,
            "migration.draft.output-invalid",
            "output",
            &format!(
                "--output must be an absolute directory path without parent traversal or symbolic links: {detail}"
            ),
            DiagnosticArtifact::SchemaTestOutput,
            SuggestedAction::ChooseSafeOutputDirectory,
        )
    };
    if !output.is_absolute() || has_parent_component(output) {
        return Err(invalid("the path is relative or traverses a parent"));
    }
    let exists = candidate_failure(
        COMMAND,
        "migration.draft.output-exists",
        "output",
        &format!(
            "{} already exists under --output; a draft never overwrites a reviewed migration. Choose another --id or review the existing directory",
            relative_directory(module, id)
        ),
        DiagnosticArtifact::SchemaTestOutput,
        SuggestedAction::ChooseSafeOutputDirectory,
    );
    let mut directory = match SafeDir::resolve(output) {
        Ok(directory) => directory,
        // Nothing exists yet, so nothing can collide. Publication creates the
        // missing directories.
        Err(SafePathError::NotFound) => return Ok(output.to_path_buf()),
        Err(_) => return Err(invalid("the path cannot be resolved safely")),
    };
    for name in ["modules", module, "migrations"] {
        match directory.open_directory(name.as_ref()) {
            Ok(next) => directory = next,
            Err(SafePathError::NotFound) => return Ok(output.to_path_buf()),
            Err(_) => return Err(invalid("a component is not a plain directory")),
        }
    }
    match directory.entry_exists(id.as_ref()) {
        Ok(true) => Err(exists),
        Ok(false) => Ok(output.to_path_buf()),
        Err(_) => Err(invalid("the migration directory cannot be inspected")),
    }
}

/// Create `modules/<module>/migrations/<id>` under `output` and write both
/// documents into it. The final directory is created exclusively, so a
/// concurrent draft of the same id is refused rather than overwritten.
fn publish(
    output: &Path,
    module: &str,
    id: &str,
    documents: &Documents,
) -> Result<(), FailureReport> {
    let unwritable = |detail: &str| {
        candidate_failure(
            COMMAND,
            "migration.draft.output-unavailable",
            "output",
            &format!(
                "the drafted migration could not be written ({detail}). Remove {} if it was partly written, then run the command again",
                relative_directory(module, id)
            ),
            DiagnosticArtifact::SchemaTestOutput,
            SuggestedAction::ChooseSafeOutputDirectory,
        )
    };
    let entry = SafeEntry::resolve(output).map_err(|_| unwritable("the output path"))?;
    let mut directory = entry
        .parent()
        .open_or_create_directory(entry.name(), 0o777)
        .map_err(|_| unwritable("the output directory"))?;
    for name in ["modules", module, "migrations"] {
        directory = directory
            .open_or_create_directory(name.as_ref(), 0o777)
            .map_err(|_| unwritable("a parent directory"))?;
    }
    match directory.create_directory(id.as_ref(), 0o777) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(candidate_failure(
                COMMAND,
                "migration.draft.output-exists",
                "output",
                &format!(
                    "{} already exists under --output; a draft never overwrites a reviewed migration",
                    relative_directory(module, id)
                ),
                DiagnosticArtifact::SchemaTestOutput,
                SuggestedAction::ChooseSafeOutputDirectory,
            ));
        }
        Err(_) => return Err(unwritable("the migration directory")),
    }
    let migration = directory
        .open_directory(id.as_ref())
        .map_err(|_| unwritable("the migration directory"))?;
    for (name, bytes) in [
        (DESCRIPTOR_FILE, &documents.descriptor),
        (RECEIPT_FILE, &documents.receipt),
    ] {
        let mut file = migration
            .create_new(name.as_ref(), 0o666)
            .map_err(|_| unwritable(name))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| unwritable(name))?;
    }
    migration.sync().map_err(|_| unwritable("the directory"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_breg::package::{
        CompiledRegistryChangeCode, CompiledRegistryChangeTarget, CompiledRegistryChangeTargetKind,
    };

    const PRIOR_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const PRIOR_FINGERPRINT: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const FINAL_FINGERPRINT: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    fn change(
        class: CompiledRegistryChangeClass,
        code: CompiledRegistryChangeCode,
        member: &str,
    ) -> CompiledRegistryChange {
        CompiledRegistryChange {
            class,
            code,
            target: CompiledRegistryChangeTarget {
                kind: CompiledRegistryChangeTargetKind::RecordType,
                record_type_id: Some("record".to_owned()),
                member_id: Some(member.to_owned()),
            },
        }
    }

    fn access_change(member: &str) -> CompiledRegistryChange {
        change(
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeCode::AccessProfileChanged,
            member,
        )
    }

    fn measured() -> Measured<'static> {
        Measured {
            prior_package_digest: PRIOR_DIGEST,
            prior_schema_fingerprint: PRIOR_FINGERPRINT,
            final_schema_fingerprint: FINAL_FINGERPRINT,
            postgres_major: 17,
        }
    }

    #[test]
    fn covers_are_the_sorted_changes_that_are_not_compatible_additive() {
        let additive = change(
            CompiledRegistryChangeClass::CompatibleAdditive,
            CompiledRegistryChangeCode::FieldAddedOptional,
            "extra",
        );
        let covers = plan_covers(&[access_change("zeta"), additive, access_change("alpha")])
            .expect("access changes are draftable");
        let members = covers
            .iter()
            .map(|cover| cover.target.member_id.as_deref().expect("member"))
            .collect::<Vec<_>>();
        assert_eq!(members, ["alpha", "zeta"]);
    }

    #[test]
    fn a_change_set_without_reviewable_changes_has_nothing_to_review() {
        let additive = change(
            CompiledRegistryChangeClass::CompatibleAdditive,
            CompiledRegistryChangeCode::FieldAddedOptional,
            "extra",
        );
        assert_eq!(plan_covers(&[additive]), Err(CoverRefusal::NothingToReview));
        assert_eq!(plan_covers(&[]), Err(CoverRefusal::NothingToReview));
    }

    #[test]
    fn a_change_outside_the_access_class_needs_a_handwritten_migration() {
        let removed = change(
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeCode::FieldRemoved,
            "code",
        );
        let Err(CoverRefusal::SqlRequired(named)) = plan_covers(&[access_change("alpha"), removed])
        else {
            panic!("a removed field needs a hand-written migration");
        };
        assert!(named.contains("field-removed"), "{named}");
    }

    #[test]
    fn descriptor_bytes_are_canonical_and_the_receipt_binds_their_digest() {
        let covers = plan_covers(&[access_change("alpha")]).expect("draftable");
        let documents =
            build_documents("core", "widen", &covers, &measured()).expect("documents build");

        let descriptor: serde_json::Value =
            serde_json::from_slice(&documents.descriptor).expect("descriptor is JSON");
        assert_eq!(
            canonicalize_json(&descriptor).expect("canonicalizes"),
            documents.descriptor,
            "the descriptor file is its own canonical form"
        );
        assert_eq!(documents.plan_digest, sha256_digest(&documents.descriptor));
        assert_eq!(descriptor["changeClass"], "access-or-disclosure-change");
        assert_eq!(descriptor["steps"], serde_json::json!([]));
        assert_eq!(descriptor["preAssertions"], serde_json::json!([]));
        assert_eq!(descriptor["postAssertions"], serde_json::json!([]));
        assert_eq!(
            descriptor["rehearsalReceiptPath"],
            "modules/core/migrations/widen/rehearsal.json"
        );

        let receipt: serde_json::Value =
            serde_json::from_slice(&documents.receipt).expect("receipt is JSON");
        assert_eq!(receipt["planDigest"], documents.plan_digest.as_str());
        assert_eq!(receipt["priorPackageDigest"], PRIOR_DIGEST);
        assert_eq!(receipt["priorSchemaFingerprint"], PRIOR_FINGERPRINT);
        assert_eq!(receipt["finalSchemaFingerprint"], FINAL_FINGERPRINT);
        assert_eq!(receipt["postgresMajor"], 17);
        assert_eq!(
            canonicalize_json(&receipt).expect("canonicalizes"),
            documents.receipt
        );
    }

    #[test]
    fn a_draft_is_deterministic() {
        let covers = plan_covers(&[access_change("alpha")]).expect("draftable");
        let first = build_documents("core", "widen", &covers, &measured()).expect("first builds");
        let second = build_documents("core", "widen", &covers, &measured()).expect("second builds");
        assert_eq!(first.descriptor, second.descriptor);
        assert_eq!(first.receipt, second.receipt);
    }
}
