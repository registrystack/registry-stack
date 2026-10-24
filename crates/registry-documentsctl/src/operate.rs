// SPDX-License-Identifier: Apache-2.0

//! The commands that reach a deployment's database through the runtime
//! configuration: `plan`, `apply`, and `status` over the package activation
//! ledger, `verification list` and `verification replay` over the
//! dead-lettered content verification jobs, and `erasure status`,
//! `erasure list`, and `erasure replay` over erasure and its dead-lettered
//! jobs.
//!
//! Each reads the runtime configuration and the package it names exactly as
//! `documents serve` does, pinned digest included, and each refusal names
//! its own code at the member it concerns.

use std::path::{Path, PathBuf};

use registry_documents::activation::{ActivationError, ActivationRefusal, ApplyRequest};
use registry_documents::config::Erasure;
use registry_documents::config::{startup_report, RuntimeConfig, RuntimeConfigError};
use registry_documents::package::PackageLoadError;
use registry_documents::replay::{ReplayFailure, ReplayRefusal};
use registry_documents::runtime::{
    activation_plan, activation_status, apply_activation, dead_lettered_erasures,
    dead_lettered_verifications, erasure_report, replay_erasure, replay_verification, RuntimeError,
};
use registry_documents::store::StoreError;
use registry_platform_config::PackageErrorKind;
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::report::{DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT};
use crate::{guidance, Job, Outcome, View};

/// The runtime configuration a database command reads, resolved against the
/// working directory, as an operator means a relative path.
struct Runtime {
    given: PathBuf,
    absolute: PathBuf,
    config: RuntimeConfig,
}

fn load(path: &Path) -> Result<Runtime, Outcome> {
    let Ok(absolute) = std::path::absolute(path) else {
        return Err(Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "config.unresolvable",
            "arguments",
            "the --runtime-config path could not be resolved against the working directory"
                .to_owned(),
        ));
    };
    let config =
        RuntimeConfig::load(&absolute).map_err(|error| config_refusal(&absolute, &error))?;
    Ok(Runtime {
        given: path.to_owned(),
        absolute,
        config,
    })
}

/// A single-threaded async runtime for one database command.
fn block_on<F: std::future::Future>(future: F) -> Result<F::Output, Outcome> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map(|runtime| runtime.block_on(future))
        .map_err(|error| {
            Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "runtime.unavailable",
                "/",
                format!("the async runtime could not start: {error}"),
            )
        })
}

pub(crate) fn plan(path: &Path) -> Outcome {
    let runtime = match load(path) {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    match block_on(activation_plan(&runtime.config)) {
        Err(refused) => refused,
        Ok(Err(error)) => failure(&runtime.given, error),
        Ok(Ok(plan)) => {
            let exit = if plan.refusals.is_empty() {
                0
            } else {
                DOMAIN_REFUSAL_EXIT
            };
            Outcome {
                report: json!({
                    "runtimeConfig": runtime.given,
                    "packageDigest": plan.package_digest,
                    "activeDigest": plan.active_digest,
                    "change": plan.change,
                    "databaseId": plan.database_id,
                    "planKind": plan.plan_kind,
                    "pendingSchemaVersions": plan.pending_schema_versions,
                    "runtimeRoleMode": plan.runtime_role_mode,
                    "grantsCurrent": plan.grants_current,
                    "refusals": plan.refusals,
                    "diagnostics": activation_diagnostics(&plan.refusals),
                }),
                exit,
                view: View::Activation,
            }
        }
    }
}

pub(crate) fn apply(path: &Path, operator_reference: Option<&str>, backups: &[String]) -> Outcome {
    let runtime = match load(path) {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    let request = ApplyRequest {
        operator_reference: operator_reference.map(str::to_owned),
        backup_references: backups.to_vec(),
    };
    match block_on(apply_activation(&runtime.config, &request)) {
        Err(refused) => refused,
        Ok(Err(error)) => failure(&runtime.given, error),
        Ok(Ok(applied)) => {
            let active_digest = if applied.recorded {
                applied.activation.predecessor_package_digest.clone()
            } else {
                Some(applied.activation.package_digest.clone())
            };
            Outcome::new(
                json!({
                    "runtimeConfig": runtime.given,
                    "packageDigest": applied.activation.package_digest,
                    "activeDigest": active_digest,
                    "change": if applied.recorded { "activate" } else { "none" },
                    "applied": applied.recorded,
                    "restartRequired": applied.recorded,
                    "activation": applied.activation,
                    "schemaVersionsApplied": applied.schema_versions_applied,
                }),
                View::Activation,
            )
        }
    }
}

pub(crate) fn status(path: &Path) -> Outcome {
    let runtime = match load(path) {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    match block_on(activation_status(&runtime.config)) {
        Err(refused) => refused,
        Ok(Err(error)) => failure(&runtime.given, error),
        Ok(Ok(status)) => Outcome::new(
            json!({
                "runtimeConfig": runtime.given,
                "active": status.active,
                "history": status.history,
                "schemaVersion": status.schema_version,
                "runtimeRoleMode": status.runtime_role_mode,
                "grantsCurrent": status.grants_current,
            }),
            View::Activation,
        ),
    }
}

pub(crate) fn erasure_status(path: &Path) -> Outcome {
    let runtime = match load(path) {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    match block_on(erasure_report(&runtime.config)) {
        Err(refused) => refused,
        Ok(Err(error)) => failure(&runtime.given, error),
        Ok(Ok(status)) => Outcome::new(
            json!({
                "runtimeConfig": runtime.given,
                "erasure": match status.erasure {
                    Erasure::Active => "active",
                    Erasure::Paused => "paused",
                },
                "awaitingGrace": status.awaiting_grace,
                "due": status.due,
                "deadLettered": status.dead_lettered,
            }),
            View::Erasure,
        ),
    }
}

pub(crate) fn dead_letters(job: Job, path: &Path, limit: u16) -> Outcome {
    let runtime = match load(path) {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    let listed = match job {
        Job::Verification => block_on(dead_lettered_verifications(&runtime.config, limit)),
        Job::Erasure => block_on(dead_lettered_erasures(&runtime.config, limit)),
    };
    match listed {
        Err(refused) => refused,
        Ok(Err(error)) => failure(&runtime.given, error),
        Ok(Ok(dead_letters)) => Outcome::new(
            json!({
                "runtimeConfig": runtime.given,
                "limit": limit,
                "deadLetters": dead_letters,
            }),
            View::DeadLetters(job),
        ),
    }
}

pub(crate) fn replay(job: Job, path: &Path, version: Uuid, expected_generation: i64) -> Outcome {
    let runtime = match load(path) {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    let replayed = match job {
        Job::Verification => block_on(replay_verification(
            &runtime.absolute,
            &runtime.config,
            version,
            expected_generation,
        )),
        Job::Erasure => block_on(replay_erasure(
            &runtime.config,
            version,
            expected_generation,
        )),
    };
    match replayed {
        Err(refused) => refused,
        Ok(Err(error)) => failure(&runtime.given, error),
        Ok(Ok(replayed)) => Outcome::new(
            json!({
                "runtimeConfig": runtime.given,
                "versionId": replayed.version_id,
                "expectedGeneration": expected_generation,
                "generation": replayed.generation,
                "state": "pending",
            }),
            View::Replayed,
        ),
    }
}

/// The report of a database command that did not finish.
fn failure(path: &Path, error: RuntimeError) -> Outcome {
    let refused = |exit, code, member| Outcome::refused(exit, code, member, error.to_string());
    let activation_refused = |activation: &ActivationError, member| {
        refused(
            DOMAIN_REFUSAL_EXIT,
            activation.code().expect("a named activation refusal"),
            member,
        )
    };
    match &error {
        RuntimeError::Config(config) => config_refusal(path, config),
        RuntimeError::ConfigurationRefused(report) => {
            Outcome::diagnosed(DOMAIN_REFUSAL_EXIT, report)
        }
        RuntimeError::Package(PackageLoadError::Project(report)) => {
            Outcome::diagnosed(DOMAIN_REFUSAL_EXIT, report)
        }
        RuntimeError::Package(package) => {
            let unreadable = matches!(
                package,
                PackageLoadError::Package(shared)
                    if matches!(
                        shared.kind(),
                        PackageErrorKind::RootInvalid { .. } | PackageErrorKind::Io { .. }
                    )
            );
            let exit = if unreadable {
                OPERATIONAL_FAILURE_EXIT
            } else {
                DOMAIN_REFUSAL_EXIT
            };
            refused(exit, package.code(), package.pointer())
        }
        RuntimeError::Activation(ActivationError::Refused(refusals)) => Outcome {
            report: json!({
                "refusals": refusals,
                "diagnostics": activation_diagnostics(refusals),
            }),
            exit: DOMAIN_REFUSAL_EXIT,
            view: View::Activation,
        },
        RuntimeError::Activation(activation @ ActivationError::NotActivated) => {
            activation_refused(activation, "database")
        }
        RuntimeError::Activation(activation @ ActivationError::DatabaseIdMismatch) => {
            activation_refused(activation, "identity.databaseId")
        }
        RuntimeError::Activation(activation @ ActivationError::PackageNotActive) => {
            activation_refused(activation, "package")
        }
        RuntimeError::Activation(
            activation @ (ActivationError::RoleModeWeakened
            | ActivationError::GrantsStale
            | ActivationError::LedgerUnreadable),
        ) => activation_refused(activation, "database.runtimeUrlRef"),
        RuntimeError::Activation(ActivationError::AppliedUnaudited { .. }) => {
            refused(OPERATIONAL_FAILURE_EXIT, "audit.unconfirmed", "audit")
        }
        RuntimeError::Activation(ActivationError::OutcomeUnknown { .. }) => refused(
            OPERATIONAL_FAILURE_EXIT,
            "package.outcome-unknown",
            "database",
        ),
        RuntimeError::Activation(ActivationError::Audit(_))
        | RuntimeError::AuditSecret(_)
        | RuntimeError::AuditJournal(_) => {
            refused(OPERATIONAL_FAILURE_EXIT, "audit.unavailable", "audit")
        }
        RuntimeError::Replay(refusal) => replay_refusal(Job::Verification, refusal, refused),
        RuntimeError::ErasureReplay(refusal) => replay_refusal(Job::Erasure, refusal, refused),
        RuntimeError::ReplayFailed(failure) => replay_failure(Job::Verification, failure, refused),
        RuntimeError::ErasureReplayFailed(failure) => {
            replay_failure(Job::Erasure, failure, refused)
        }
        RuntimeError::Activation(ActivationError::Store(StoreError::SchemaUnresolved))
        | RuntimeError::Database {
            source: StoreError::SchemaUnresolved,
            ..
        } => refused(
            DOMAIN_REFUSAL_EXIT,
            "documentsctl.activation.schema-unresolved",
            "database",
        ),
        RuntimeError::Activation(ActivationError::Store(_)) | RuntimeError::Database { .. } => {
            refused(OPERATIONAL_FAILURE_EXIT, "database.unavailable", "database")
        }
        _ => refused(OPERATIONAL_FAILURE_EXIT, "runtime.unavailable", "/"),
    }
}

/// The report of a replay of `job` that was refused.
fn replay_refusal(
    job: Job,
    refusal: &ReplayRefusal,
    refused: impl Fn(u8, &'static str, &'static str) -> Outcome,
) -> Outcome {
    let code = match (job, refusal) {
        (Job::Verification, ReplayRefusal::NotFound) => "documents.verification.not-found",
        (Job::Verification, ReplayRefusal::NotDeadLettered { .. }) => {
            "documents.verification.not-dead-lettered"
        }
        (Job::Verification, ReplayRefusal::StaleGeneration { .. }) => {
            "documents.verification.stale-generation"
        }
        (Job::Verification, ReplayRefusal::Changed) => "documents.verification.changed",
        (Job::Verification, ReplayRefusal::RemovalRequested { .. }) => {
            "documents.verification.removal-requested"
        }
        (Job::Erasure, ReplayRefusal::NotFound) => "documents.erasure.not-found",
        (Job::Erasure, ReplayRefusal::NotDeadLettered { .. }) => {
            "documents.erasure.not-dead-lettered"
        }
        (Job::Erasure, ReplayRefusal::StaleGeneration { .. }) => {
            "documents.erasure.stale-generation"
        }
        // An erasure replay never refuses a removal; it carries one out.
        (Job::Erasure, ReplayRefusal::Changed | ReplayRefusal::RemovalRequested { .. }) => {
            "documents.erasure.changed"
        }
    };
    refused(DOMAIN_REFUSAL_EXIT, code, job.path())
}

/// The report of a replay of `job` that did not finish.
fn replay_failure(
    job: Job,
    failure: &ReplayFailure,
    refused: impl Fn(u8, &'static str, &'static str) -> Outcome,
) -> Outcome {
    match failure {
        ReplayFailure::AuditUnavailable => {
            refused(OPERATIONAL_FAILURE_EXIT, "audit.unavailable", "audit")
        }
        ReplayFailure::Unaudited { .. } => {
            refused(OPERATIONAL_FAILURE_EXIT, "audit.unconfirmed", "audit")
        }
        ReplayFailure::OutcomeUnknown { .. } => {
            let code = match job {
                Job::Verification => "documents.verification.outcome-unknown",
                Job::Erasure => "documents.erasure.outcome-unknown",
            };
            refused(OPERATIONAL_FAILURE_EXIT, code, job.path())
        }
        ReplayFailure::DatabaseUnavailable => {
            refused(OPERATIONAL_FAILURE_EXIT, "database.unavailable", "database")
        }
    }
}

/// The refusal of the runtime configuration at `path`: every rule it
/// breaks, each at its position, or the one dependency it names that could
/// not be prepared.
fn config_refusal(path: &Path, error: &RuntimeConfigError) -> Outcome {
    if let Some(report) = startup_report(path, error) {
        let unavailable = report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == registry_platform_config::UNAVAILABLE_CODE);
        let exit = if unavailable {
            OPERATIONAL_FAILURE_EXIT
        } else {
            DOMAIN_REFUSAL_EXIT
        };
        return Outcome::diagnosed(exit, &report);
    }
    let (_, action) = guidance("config.refused", OPERATIONAL_FAILURE_EXIT);
    let mut diagnostic = Diagnostic::error("config.refused", "", error.to_string(), action);
    diagnostic.artifact = Some(registry_documents_core::DOCUMENTS_RUNTIME_KIND.to_owned());
    Outcome::diagnosed(OPERATIONAL_FAILURE_EXIT, &Report::new(vec![diagnostic]))
}

fn activation_diagnostics(refusals: &[ActivationRefusal]) -> Vec<Value> {
    refusals
        .iter()
        .map(|refusal| {
            let (artifact, action) = guidance(refusal.code, DOMAIN_REFUSAL_EXIT);
            json!({
                "severity": "error",
                "code": refusal.code,
                "artifact": artifact,
                "path": refusal.path,
                "message": refusal.message,
                "suggestedAction": action,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// The code, exit, and path each replay outcome of `job` reports.
    fn reported(job: Job) -> Vec<(u8, &'static str, &'static str)> {
        let seen = RefCell::new(Vec::new());
        let refused = |exit, code, member| {
            seen.borrow_mut().push((exit, code, member));
            Outcome::refused(exit, code, member, String::new())
        };
        let version_id = Uuid::nil();
        for refusal in [
            ReplayRefusal::NotFound,
            ReplayRefusal::NotDeadLettered {
                state: "pending".to_owned(),
            },
            ReplayRefusal::StaleGeneration { current: 1 },
            ReplayRefusal::Changed,
            ReplayRefusal::RemovalRequested {
                reason: "the version is erased",
            },
        ] {
            replay_refusal(job, &refusal, refused);
        }
        for failure in [
            ReplayFailure::AuditUnavailable,
            ReplayFailure::Unaudited {
                version_id,
                generation: 2,
            },
            ReplayFailure::OutcomeUnknown { version_id },
            ReplayFailure::DatabaseUnavailable,
        ] {
            replay_failure(job, &failure, refused);
        }
        seen.into_inner()
    }

    #[test]
    fn each_replay_outcome_reports_its_own_job_code() {
        assert_eq!(
            reported(Job::Verification),
            [
                (
                    DOMAIN_REFUSAL_EXIT,
                    "documents.verification.not-found",
                    "verification"
                ),
                (
                    DOMAIN_REFUSAL_EXIT,
                    "documents.verification.not-dead-lettered",
                    "verification"
                ),
                (
                    DOMAIN_REFUSAL_EXIT,
                    "documents.verification.stale-generation",
                    "verification"
                ),
                (
                    DOMAIN_REFUSAL_EXIT,
                    "documents.verification.changed",
                    "verification"
                ),
                (
                    DOMAIN_REFUSAL_EXIT,
                    "documents.verification.removal-requested",
                    "verification"
                ),
                (OPERATIONAL_FAILURE_EXIT, "audit.unavailable", "audit"),
                (OPERATIONAL_FAILURE_EXIT, "audit.unconfirmed", "audit"),
                (
                    OPERATIONAL_FAILURE_EXIT,
                    "documents.verification.outcome-unknown",
                    "verification"
                ),
                (OPERATIONAL_FAILURE_EXIT, "database.unavailable", "database"),
            ]
        );
        assert_eq!(
            reported(Job::Erasure),
            [
                (
                    DOMAIN_REFUSAL_EXIT,
                    "documents.erasure.not-found",
                    "erasure"
                ),
                (
                    DOMAIN_REFUSAL_EXIT,
                    "documents.erasure.not-dead-lettered",
                    "erasure"
                ),
                (
                    DOMAIN_REFUSAL_EXIT,
                    "documents.erasure.stale-generation",
                    "erasure"
                ),
                (DOMAIN_REFUSAL_EXIT, "documents.erasure.changed", "erasure"),
                (DOMAIN_REFUSAL_EXIT, "documents.erasure.changed", "erasure"),
                (OPERATIONAL_FAILURE_EXIT, "audit.unavailable", "audit"),
                (OPERATIONAL_FAILURE_EXIT, "audit.unconfirmed", "audit"),
                (
                    OPERATIONAL_FAILURE_EXIT,
                    "documents.erasure.outcome-unknown",
                    "erasure"
                ),
                (OPERATIONAL_FAILURE_EXIT, "database.unavailable", "database"),
            ]
        );
    }
}
