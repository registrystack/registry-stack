// SPDX-License-Identifier: Apache-2.0

//! The package activation commands.
//!
//! `apply` is the only way a Scheduling database accepts a verified package:
//! with the migration credential it migrates the schema, adopts the
//! deployment identity, publishes the policy, and records one activation
//! ledger row, in one transaction under the migration lock. It writes its
//! `request` audit entry before that transaction opens and its `response`
//! entry after the transaction commits or rolls back, to the `schedulingctl`
//! sibling of the runtime's audit destination. `plan` reports what `apply`
//! would do and every refusal it would raise that is known without writing,
//! and `status` reports the ledger; both use the runtime credential and
//! write nothing.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use registry_platform_audit::AuditWriter;
use registry_platform_config::SecretResolver;
use registry_scheduling::audit::{with_event_id, SchedulingAudit};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::hooks::{ActivatedHooks, HookRuntimeIdentity};
use registry_scheduling::runtime::open_audit;
use registry_scheduling::store::{
    Activation, ActivationRequest, DeployedPolicy, PostgresStore, RoleMode, StoreError,
    SINGLE_ROLE_STATEMENT,
};
use registry_scheduling_core::SchedulingPolicy;
use serde_json::{json, Value};
use uuid::Uuid;

/// The keyed-hash class of an operator reference.
const OPERATOR_REFERENCE_CLASS: &str = "scheduling-operator-reference-v1";
/// The bounds of the operator text apply records.
pub(crate) const MAX_OPERATOR_TEXT_BYTES: usize = 256;
pub(crate) const MAX_BACKUP_REFERENCES: usize = 16;

/// Parse one `--operator-reference` value: non-empty, bounded, and free of
/// control characters.
pub(crate) fn parse_operator_reference(value: &str) -> Result<String, String> {
    bounded_operator_text("--operator-reference", value)
}

/// Parse one `--backup` value under the same bounds as
/// `--operator-reference`.
pub(crate) fn parse_backup_reference(value: &str) -> Result<String, String> {
    bounded_operator_text("--backup", value)
}

/// The reasons name the flag and never the value, since a usage error
/// repeats them.
fn bounded_operator_text(flag: &str, value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > MAX_OPERATOR_TEXT_BYTES {
        return Err(format!(
            "{flag} must be between 1 and {MAX_OPERATOR_TEXT_BYTES} bytes"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{flag} must not contain control characters"));
    }
    Ok(value.to_owned())
}

struct Loaded {
    config_path: PathBuf,
    config: RuntimeConfig,
    package_digest: String,
    policy: SchedulingPolicy,
    resolver: SecretResolver,
}

fn load(config_path: &Path) -> Result<Loaded> {
    let config_path =
        fs::canonicalize(config_path).context("resolving the Scheduling runtime configuration")?;
    let config = crate::project::load_runtime_config(&config_path)?;
    let loaded = config
        .load_policy()
        .map_err(|error| crate::project::runtime_refusal(&config_path, error))?;
    let resolver = crate::records::secret_resolver(&config)?;
    Ok(Loaded {
        config_path,
        config,
        package_digest: loaded.package_digest,
        policy: loaded.policy,
        resolver,
    })
}

fn operator_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Scheduling operator runtime")
}

fn connect_runtime(loaded: &Loaded) -> Result<PostgresStore> {
    PostgresStore::connect_runtime(&loaded.config.database, &loaded.resolver)
        .context("the Scheduling runtime database configuration is invalid")
}

fn hook_payload_retention(config: &RuntimeConfig) -> Duration {
    Duration::from_secs(u64::from(config.retention.hook_payload_retention_days) * 24 * 60 * 60)
}

/// The closed code of a candidate whose hook destinations cannot run, which
/// apply refuses before it writes anything.
pub(crate) const HOOK_DESTINATIONS_CODE: &str = "schedulingctl.activation.hook-destinations";

/// Activate the candidate policy's hooks under one identity. Every
/// destination and its signing material is resolved here, so a candidate
/// whose hooks cannot run is refused before anything is written.
fn candidate_hooks(
    loaded: &Loaded,
    identity: HookRuntimeIdentity,
    schema: String,
) -> Result<ActivatedHooks> {
    ActivatedHooks::activate(
        &loaded.policy.hook_declarations(),
        &loaded.config.destinations.hooks,
        &loaded.resolver,
        identity,
        schema,
        hook_payload_retention(&loaded.config),
    )
    .context("activating the candidate policy's hook destinations")
}

/// Prove every retained hook event stays deliverable when the candidate's
/// hooks run under the identity the database serves now.
async fn verify_retained(
    loaded: &Loaded,
    store: &PostgresStore,
    audit: &SchedulingAudit,
    schema: &str,
    deployed: DeployedPolicy,
) -> Result<(), StoreError> {
    let hooks = ActivatedHooks::activate(
        &loaded.policy.hook_declarations(),
        &loaded.config.destinations.hooks,
        &loaded.resolver,
        HookRuntimeIdentity {
            scheduling_id: deployed.scheduling_id,
            policy_revision: deployed.policy_revision,
            policy_digest: deployed.policy_digest,
        },
        schema.to_owned(),
        hook_payload_retention(&loaded.config),
    )
    .map_err(|_| StoreError::RetainedHookBindings)?;
    hooks
        .delivery_service(store.clone(), audit.clone())
        .verify_retained_bindings()
        .await
        .map_err(|_| StoreError::RetainedHookBindings)
}

/// A store refusal an activation command reports as a domain refusal, exit 1,
/// rather than as an unavailable store. Its text is the store's own
/// sentence, which names the next command.
#[derive(Debug)]
pub struct Refusal(pub StoreError);

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for Refusal {}

/// Wrap a store error as a [`Refusal`] when it is one an activation raises,
/// and as an ordinary store failure otherwise.
pub(crate) fn refusal_or_failure(error: StoreError) -> anyhow::Error {
    if error.is_activation_refusal() {
        anyhow::Error::new(Refusal(error))
    } else {
        anyhow::Error::new(error)
    }
}

/// The audit outcome and reason of an apply that did not answer. An
/// activation whose commit was not acknowledged and could not be read back
/// may have taken effect, so it is `unfinished`, never `failed`.
fn unanswered_activation(error: &StoreError) -> (&'static str, &'static str) {
    if error.is_activation_refusal() {
        ("refused", refusal_code(error))
    } else if matches!(error, StoreError::Unacknowledged) {
        ("unfinished", "schedulingctl.activation.unacknowledged")
    } else {
        ("failed", "schedulingctl.activation.failed")
    }
}

/// The closed code of a refusal apply would raise.
pub(crate) fn refusal_code(error: &StoreError) -> &'static str {
    match error {
        StoreError::DatabaseIdMismatch => "schedulingctl.activation.database-id-mismatch",
        StoreError::PackageAlreadyActive { .. } => {
            "schedulingctl.activation.package-already-active"
        }
        StoreError::PackageNotActive { .. } => "schedulingctl.activation.package-not-active",
        StoreError::RoleModeDrift => "schedulingctl.activation.role-mode-drift",
        StoreError::SplitRoleWeakened(_) => "schedulingctl.activation.split-role-weakened",
        StoreError::NotActivated => "schedulingctl.activation.not-activated",
        StoreError::LedgerUnreadable { .. } => "schedulingctl.activation.ledger-unreadable",
        StoreError::SchemaPending { .. } => "schedulingctl.activation.schema-pending",
        StoreError::SchemaNewer { .. } => "schedulingctl.activation.schema-newer",
        StoreError::DeploymentIdentity => "schedulingctl.activation.deployment-identity",
        StoreError::EarlierRelease => "schedulingctl.activation.earlier-release",
        StoreError::PolicyInUse(_) => "schedulingctl.activation.policy-in-use",
        StoreError::CombinedInvariant(_) => "schedulingctl.activation.combined-invariant",
        StoreError::SupplyIdentifierCollision(_) => {
            "schedulingctl.activation.supply-identifier-collision"
        }
        StoreError::RetainedHookBindings => "schedulingctl.activation.retained-hook-bindings",
        StoreError::UnpublishedAuditWouldBeDropped { .. } => {
            "schedulingctl.activation.unpublished-audit"
        }
        _ => "schedulingctl.activation.refused",
    }
}

fn activation_json(activation: &Activation) -> Value {
    json!({
        "activationId": activation.activation_id.to_string(),
        "applyOrder": activation.apply_order,
        "packageDigest": activation.package_digest,
        "predecessorPackageDigest": activation.predecessor_package_digest,
        "databaseId": activation.database_id,
        "planKind": activation.plan_kind,
        "appliedAt": activation.applied_at.to_rfc3339(),
        "operatorReferenceHash": activation.operator_reference_hash,
        "backupReferences": activation.backup_references,
        "roleMode": activation.role_mode.as_str(),
        "runtimeRole": activation.runtime_role,
    })
}

/// An audit handle for the read-only commands. The retained-binding check
/// takes a delivery service, which only appends when it delivers; the check
/// never delivers, so any append reaching this sink is a defect and fails
/// loudly instead of being discarded.
fn refusing_audit() -> SchedulingAudit {
    struct RefusingSink;
    impl io::Write for RefusingSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other(
                "a read-only schedulingctl command attempted an audit append",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    SchedulingAudit::new(AuditWriter::from_line_sink(Box::new(RefusingSink)))
}

pub fn plan(config_path: &Path) -> Result<Value> {
    let loaded = load(config_path)?;
    let store = connect_runtime(&loaded)?;
    let runtime = operator_runtime()?;
    let audit = refusing_audit();
    // The schema is read only once a deployment exists: before the first
    // split apply the runtime credential holds no USAGE on it yet.
    let plan = runtime
        .block_on(store.plan_activation(
            loaded.config.database_id(),
            &loaded.package_digest,
            &loaded.policy,
            |deployed| async {
                let schema = store.schema_name().await?;
                verify_retained(&loaded, &store, &audit, &schema, deployed).await
            },
        ))
        .map_err(refusal_or_failure)
        .context("planning the Scheduling activation")?;
    let database_id_check = match &plan.active {
        None => "initial",
        Some(active) if active.database_id == loaded.config.database_id() => "match",
        Some(_) => "mismatch",
    };
    let retained_hook_bindings = match plan.retained_hook_bindings_verified {
        None => "none-retained",
        Some(true) => "verified",
        Some(false) => "refused",
    };
    let mut refusals = plan
        .refusals
        .iter()
        .map(|refusal| json!({"code": refusal_code(refusal), "message": refusal.to_string()}))
        .collect::<Vec<_>>();
    // Apply resolves the candidate's hook destinations and signing material
    // before it writes anything, so plan reports the same refusal. A key is
    // resolved only to learn that it exists at a usable size, then dropped.
    let hook_refusal = ActivatedHooks::check_destinations(
        &loaded.policy.hook_declarations(),
        &loaded.config.destinations.hooks,
        &loaded.resolver,
    )
    .err();
    if let Some(error) = &hook_refusal {
        refusals.push(json!({
            "code": HOOK_DESTINATIONS_CODE,
            "message": format!(
                "{error}; bind every destination the policy hooks name under destinations.hooks, \
                 with an hmacSha256KeyRef that resolves to a key of at least 32 bytes, then plan again"
            ),
        }));
    }
    Ok(json!({
        "ok": true,
        "command": "plan",
        "config": loaded.config_path,
        "activePackage": plan.active.as_ref().map(|active| json!({
            "packageDigest": active.package_digest,
            "activationId": active.activation_id.to_string(),
            "roleMode": active.role_mode.as_str(),
            "runtimeRole": active.runtime_role,
        })),
        "candidatePackageDigest": loaded.package_digest,
        "databaseId": loaded.config.database_id(),
        "databaseIdCheck": database_id_check,
        "schemaVersion": plan.schema.current(),
        "pendingSchemaVersions": plan.schema.pending,
        "policy": {
            "activeDigest": plan.deployed.as_ref()
                .map(|deployed| deployed.policy_digest.clone())
                .filter(|digest| !digest.is_empty()),
            "candidateDigest": loaded.policy.policy_digest(),
            "revisionAdvances": plan.publication.as_ref().map(|publication| publication.advances),
            "revision": plan.publication.as_ref().map(|publication| publication.revision()),
        },
        "retainedHookBindings": retained_hook_bindings,
        "runtimeRole": plan.runtime_role,
        "effectiveRoleMode": plan.effective_role_mode.map(RoleMode::as_str),
        "changesPending": plan.changes_pending && hook_refusal.is_none(),
        "refusals": refusals,
    }))
}

/// The root error of an apply that committed but whose response audit entry
/// could not be written: the activation stands, unaudited.
#[derive(Debug)]
pub struct AppliedUnaudited {
    pub(crate) package_digest: String,
    pub(crate) activation_id: Uuid,
    pub(crate) cause: String,
}

impl std::fmt::Display for AppliedUnaudited {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "package {} was applied as activation {}, but its activation.apply response audit entry could not be written ({}); the activation stands. Restore the schedulingctl audit destination beside audit.path, then run `schedulingctl status --runtime-config FILE` to confirm the active package",
            self.package_digest, self.activation_id, self.cause
        )
    }
}

impl std::error::Error for AppliedUnaudited {}

pub fn apply(
    config_path: &Path,
    operator_reference: Option<&str>,
    backups: &[String],
) -> Result<Value> {
    apply_audited(config_path, operator_reference, backups, None)
}

/// Apply with the schedulingctl audit written to `sink` instead of the
/// configured destination, so a test can refuse a chosen append.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub fn apply_with_audit_sink(
    config_path: &Path,
    operator_reference: Option<&str>,
    backups: &[String],
    sink: Box<dyn io::Write + Send>,
) -> Result<Value> {
    apply_audited(config_path, operator_reference, backups, Some(sink))
}

fn apply_audited(
    config_path: &Path,
    operator_reference: Option<&str>,
    backups: &[String],
    sink: Option<Box<dyn io::Write + Send>>,
) -> Result<Value> {
    let loaded = load(config_path)?;
    let runtime_store = connect_runtime(&loaded)?;
    let store = PostgresStore::connect_migration(&loaded.config.database, &loaded.resolver)
        .context("the Scheduling migration database configuration is invalid")?;
    let runtime = operator_runtime()?;
    let runtime_role = runtime
        .block_on(runtime_store.current_user())
        .context("connecting with the Scheduling runtime credential")?;
    let migration_role = runtime
        .block_on(store.current_user())
        .context("connecting with the Scheduling migration credential")?;
    let role_mode = if runtime_role == migration_role {
        RoleMode::Single
    } else {
        RoleMode::Split
    };
    let schema = runtime
        .block_on(store.schema_name())
        .context("reading the Scheduling database schema")?;
    // The identity only shapes the delivery rows a capture writes, and this
    // activation captures nothing: it resolves every destination the
    // candidate declares so a hook that cannot run is refused up front.
    candidate_hooks(
        &loaded,
        HookRuntimeIdentity {
            scheduling_id: loaded.policy.project.id.to_string(),
            policy_revision: 1,
            policy_digest: loaded.policy.policy_digest(),
        },
        schema.clone(),
    )?;
    let (hasher, audit) = runtime
        .block_on(open_audit(
            &loaded.config,
            &loaded.resolver,
            Some("schedulingctl"),
        ))
        .context("opening the schedulingctl audit destination")?;
    let audit = match sink {
        Some(sink) => SchedulingAudit::new(AuditWriter::from_line_sink(sink)),
        None => audit,
    };
    let activation_id = Uuid::new_v4();
    let operator_reference_hash = operator_reference
        .map(|reference| {
            hasher.audit_reference_hash(
                OPERATOR_REFERENCE_CLASS,
                &activation_id.to_string(),
                reference,
            )
        })
        .transpose()
        .context("hashing the operator reference")?;
    let request_record = json!({
        "actorKind": "operator",
        "operation": "activation.apply",
        "activationId": activation_id.to_string(),
        "packageDigest": loaded.package_digest,
        "roleMode": role_mode.as_str(),
        "operatorReferenceHash": operator_reference_hash,
        "backupReferenceCount": backups.len(),
    });
    runtime
        .block_on(audit.activation_request(activation_id, request_record.clone()))
        .context("writing the activation.apply request audit entry; nothing was applied")?;

    let request = ActivationRequest {
        activation_id,
        package_digest: &loaded.package_digest,
        database_id: loaded.config.database_id(),
        policy: &loaded.policy,
        operator_reference_hash: operator_reference_hash.as_deref(),
        backup_references: backups,
        role_mode,
        runtime_role: &runtime_role,
    };
    let outcome = match runtime.block_on(store.activate(&request, |deployed| {
        verify_retained(&loaded, &store, &audit, &schema, deployed)
    })) {
        Ok(outcome) => outcome,
        Err(store_error) => {
            let (outcome, reason) = unanswered_activation(&store_error);
            let context = if outcome == "unfinished" {
                "applying the Scheduling package; run `schedulingctl status --runtime-config FILE` to learn whether it is active"
            } else {
                "applying the Scheduling package"
            };
            let error = refusal_or_failure(store_error).context(context);
            return Err(
                match record_response(
                    &runtime,
                    &audit,
                    activation_id,
                    &request_record,
                    json!({"outcome": outcome, "reason": reason}),
                ) {
                    Ok(()) => error,
                    Err(audit_error) => error.context(format!(
                        "the activation.apply response audit entry could not be written either: {audit_error:#}"
                    )),
                },
            );
        }
    };
    let effects = json!({
        "schedulingIdAdopted": outcome.scheduling_id_adopted,
        "policyDigest": outcome.publication.policy_digest,
        "policyRevision": outcome.publication.revision(),
        "policyRevisionAdvanced": outcome.publication.advances,
    });
    record_response(
        &runtime,
        &audit,
        activation_id,
        &request_record,
        json!({
            "outcome": "allowed",
            "reason": "authorization.allowed",
            "roleMode": outcome.activation.role_mode.as_str(),
            "predecessorPackageDigest": outcome.activation.predecessor_package_digest,
            "schemaVersionsApplied": outcome.schema_versions_applied,
            "effects": effects,
        }),
    )
    .map_err(|cause| AppliedUnaudited {
        package_digest: outcome.activation.package_digest.clone(),
        activation_id,
        cause: format!("{cause:#}"),
    })?;
    let mut report = json!({
        "ok": true,
        "command": "apply",
        "config": loaded.config_path,
        "activationId": activation_id.to_string(),
        "applyOrder": outcome.activation.apply_order,
        "packageDigest": outcome.activation.package_digest,
        "predecessorPackageDigest": outcome.activation.predecessor_package_digest,
        "roleMode": outcome.activation.role_mode.as_str(),
        "schemaVersionsApplied": outcome.schema_versions_applied,
        "effects": effects,
    });
    if outcome.activation.role_mode == RoleMode::Single {
        report["roleModeStatement"] = json!(SINGLE_ROLE_STATEMENT);
    }
    Ok(report)
}

/// Write the `response` entry of one activation: the request's fields with
/// the outcome fields merged in.
fn record_response(
    runtime: &tokio::runtime::Runtime,
    audit: &SchedulingAudit,
    activation_id: Uuid,
    request_record: &Value,
    outcome: Value,
) -> Result<()> {
    let mut record = request_record.clone();
    if let (Some(fields), Some(outcome)) = (record.as_object_mut(), outcome.as_object()) {
        for (key, value) in outcome {
            fields.insert(key.clone(), value.clone());
        }
    }
    let record = with_event_id(activation_id, record)
        .ok_or_else(|| anyhow!("the activation.apply audit record carries no identity"))?;
    runtime
        .block_on(audit.activation_response(activation_id, record))
        .map_err(anyhow::Error::new)
}

pub fn status(config_path: &Path) -> Result<Value> {
    let loaded = load(config_path)?;
    let store = connect_runtime(&loaded)?;
    let runtime = operator_runtime()?;
    let history = runtime
        .block_on(store.activation_history())
        .context("reading the Scheduling activation ledger")?;
    let schema = runtime
        .block_on(store.schema_state())
        .context("reading the Scheduling schema versions")?;
    let role_mode = runtime
        .block_on(store.effective_role_mode())
        .context("reading the Scheduling runtime credential's ledger privileges")?;
    let active = history.last().map(|active| {
        json!({
            "packageDigest": active.package_digest,
            "activationId": active.activation_id.to_string(),
            "appliedAt": active.applied_at.to_rfc3339(),
            "databaseId": active.database_id,
        })
    });
    let mut report = json!({
        "ok": true,
        "command": "status",
        "config": loaded.config_path,
        "activePackage": active,
        "verifiedPackageDigest": loaded.package_digest,
        "history": history.iter().map(activation_json).collect::<Vec<_>>(),
        "schemaVersion": schema.current(),
        "pendingSchemaVersions": schema.pending,
        "roleMode": role_mode.map(RoleMode::as_str),
    });
    if role_mode == Some(RoleMode::Single) {
        report["roleModeStatement"] = json!(SINGLE_ROLE_STATEMENT);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_text_is_bounded_and_printable() {
        assert_eq!(parse_operator_reference("change 42").unwrap(), "change 42");
        assert!(parse_operator_reference("").is_err());
        assert!(parse_backup_reference(&"x".repeat(MAX_OPERATOR_TEXT_BYTES + 1)).is_err());
        assert!(parse_backup_reference("line\nbreak").is_err());
    }

    #[test]
    fn an_activation_of_unknown_outcome_is_answered_as_unfinished() {
        assert_eq!(
            unanswered_activation(&StoreError::Unacknowledged),
            ("unfinished", "schedulingctl.activation.unacknowledged")
        );
        assert_eq!(
            unanswered_activation(&StoreError::DatabaseIdMismatch),
            ("refused", "schedulingctl.activation.database-id-mismatch")
        );
        assert_eq!(
            unanswered_activation(&StoreError::Corrupt),
            ("failed", "schedulingctl.activation.failed")
        );
    }
}
