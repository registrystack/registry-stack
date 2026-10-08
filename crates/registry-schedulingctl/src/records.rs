// SPDX-License-Identifier: Apache-2.0

//! The live environment-records command.
//!
//! `records apply` is the one attributable operator write that swaps a
//! deployment's locations, pools, members, published windows, and exceptions
//! wholesale. The
//! records document is read and checked against the active policy offline
//! first, nothing reaches the database until the whole document holds
//! together, and the swap itself lands through the store's single replace
//! transaction. The command writes its `request` audit entry before that
//! transaction opens and a paired `response` entry after it either commits,
//! the store refuses it, or its commit's outcome cannot be read back, to the
//! `schedulingctl` sibling of the runtime's audit destination.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_scheduling::audit::{with_event_id, SchedulingAudit};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::runtime::open_audit;
use registry_scheduling::store::{ActivePackage, PostgresStore, StoreError};
use registry_scheduling_core::{SchedulingFacts, SchedulingRecords};
use serde_json::{json, Value};
use uuid::Uuid;

pub fn apply(config_path: &Path, records_path: &Path) -> Result<Value> {
    let config_path =
        fs::canonicalize(config_path).context("resolving the Scheduling runtime configuration")?;
    let records_path =
        fs::canonicalize(records_path).context("resolving the Scheduling environment records")?;
    let config = crate::project::load_runtime_config(&config_path)?;
    let policy = config
        .load_policy()
        .map_err(|error| crate::project::runtime_refusal(&config_path, error))?;
    let bytes = crate::project::read_input(&records_path)?;
    // The records are checked against the policy the configuration binds,
    // and every refusal is reported at its position before anything opens.
    let facts =
        SchedulingRecords::read(&records_path.display().to_string(), &bytes, &policy.policy)?
            .value
            .into_facts();
    let counts = counts(&facts);
    let resolver = secret_resolver(&config)?;
    let store = PostgresStore::connect_migration(&config.database, &resolver)
        .context("the Scheduling migration database configuration is invalid")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Scheduling operator runtime")?;
    // Records land only on a database `schedulingctl apply` has activated,
    // only on the database this configuration's ledger names, and only while
    // this configuration's package is the active one. The swap checks the
    // ledger again under its locks, so an apply that lands after this check
    // refuses the swap rather than slipping under it.
    runtime
        .block_on(store.ready())
        .map_err(crate::activation::refusal_or_failure)
        .context("checking the Scheduling schema")?;
    let active = runtime
        .block_on(store.active_activation())
        .map_err(crate::activation::refusal_or_failure)
        .context("reading the Scheduling activation ledger")?
        .ok_or_else(|| crate::activation::refusal_or_failure(StoreError::NotActivated))?;
    if active.database_id != config.database_id() {
        return Err(crate::activation::refusal_or_failure(
            StoreError::DatabaseIdMismatch,
        ));
    }
    if active.package_digest != policy.package_digest {
        return Err(crate::activation::refusal_or_failure(
            StoreError::PackageNotActive {
                active: active.package_digest,
                candidate: policy.package_digest,
            },
        ));
    }
    let (_, audit) = runtime
        .block_on(open_audit(&config, &resolver, Some("schedulingctl")))
        .context("opening the schedulingctl audit destination")?;
    let correlation = Uuid::new_v4();
    runtime
        .block_on(audit.request(
            correlation,
            json!({
                "actorKind": "operator",
                "operation": "records.apply",
                "counts": counts,
            }),
        ))
        .context("writing the records.apply request audit entry; nothing was replaced")?;
    let expected = ActivePackage {
        database_id: config.database_id(),
        package_digest: &policy.package_digest,
    };
    match runtime.block_on(store.replace_active_facts(
        policy.policy.project.id.as_str(),
        &facts,
        &expected,
    )) {
        Ok(()) => {}
        Err(store_error) => {
            let answer = unanswered_swap(&store_error);
            let error =
                anyhow::Error::new(store_error).context("replacing the environment records");
            return Err(record_unanswered(
                &runtime,
                &audit,
                correlation,
                &counts,
                answer,
                error,
            ));
        }
    }
    record_applied(&runtime, &audit, correlation, &counts)?;
    Ok(json!({
        "ok": true,
        "command": "records apply",
        "config": config_path,
        "records": records_path,
        "applied": counts,
    }))
}

/// Write the `response` entry of a committed swap. The records are already
/// replaced, so a refusal here reports that the change stands unaudited.
fn record_applied(
    runtime: &tokio::runtime::Runtime,
    audit: &SchedulingAudit,
    correlation: Uuid,
    counts: &Value,
) -> Result<()> {
    let record = with_event_id(
        correlation,
        json!({
            "actorKind": "operator",
            "operation": "records.apply",
            "outcome": "allowed",
            "reason": "authorization.allowed",
            "counts": counts,
        }),
    )
    .ok_or_else(|| anyhow!("the records.apply audit record carries no identity"))?;
    runtime
        .block_on(audit.response(correlation, record))
        .context(
            "the environment records were replaced, but the records.apply response audit \
             entry could not be written",
        )
}

/// The outcome and reason of the `response` entry of a swap the store did
/// not confirm. A swap whose commit was not acknowledged and could not be
/// read back may have taken effect, so it is `unfinished`, never `refused`.
fn unanswered_swap(error: &StoreError) -> (&'static str, &'static str) {
    match error {
        StoreError::Unacknowledged => ("unfinished", "records.replace-unacknowledged"),
        _ => ("refused", "records.replace-failed"),
    }
}

/// Write the `response` entry of a swap the store did not confirm. The
/// `request` entry was already written, so a failure here would otherwise
/// leave it orphaned. The store's own error is always what `apply` returns;
/// a response entry that also fails to write says so too, rather than hiding
/// behind the store's message.
fn record_unanswered(
    runtime: &tokio::runtime::Runtime,
    audit: &SchedulingAudit,
    correlation: Uuid,
    counts: &Value,
    (outcome, reason): (&str, &str),
    error: anyhow::Error,
) -> anyhow::Error {
    let record = with_event_id(
        correlation,
        json!({
            "actorKind": "operator",
            "operation": "records.apply",
            "outcome": outcome,
            "reason": reason,
            "counts": counts,
        }),
    );
    let Some(record) = record else {
        return error.context("the records.apply audit record carries no identity");
    };
    match runtime.block_on(audit.response(correlation, record)) {
        Ok(()) => error,
        Err(audit_error) => error.context(format!(
            "the records.apply response audit entry could not be written either: {audit_error}"
        )),
    }
}

fn counts(facts: &SchedulingFacts) -> Value {
    json!({
        "locations": facts.locations.len(),
        "pools": facts.pools.len(),
        "members": facts.pools.iter().map(|pool| pool.members.len()).sum::<usize>(),
        "windows": facts.windows.len(),
        "exceptions": facts.exceptions.len(),
    })
}

pub(crate) fn secret_resolver(config: &RuntimeConfig) -> Result<SecretResolver> {
    let mut providers = Vec::new();
    if config.secret_providers.file.is_some() {
        providers.push(SecretProvider::File);
    }
    if config.secret_providers.environment.is_some() {
        providers.push(SecretProvider::Environment);
    }
    SecretResolver::new(
        providers,
        config
            .secret_providers
            .file
            .as_ref()
            .map_or_else(|| Path::new(""), |file| file.root.as_path()),
    )
    .context("configuring the Scheduling secret providers")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_swap_of_unknown_outcome_is_answered_as_unfinished() {
        assert_eq!(
            unanswered_swap(&StoreError::Unacknowledged),
            ("unfinished", "records.replace-unacknowledged")
        );
        assert_eq!(
            unanswered_swap(&StoreError::DeploymentIdentity),
            ("refused", "records.replace-failed")
        );
    }

    #[test]
    fn the_applied_counts_name_every_record_kind() {
        let facts = SchedulingRecords::decode(
            "records.yaml",
            b"apiVersion: id.registrystack.org/formats/scheduling/records/v1alpha1\n\
              kind: SchedulingRecords\n\
              locations:\n  - id: north-counter\n    timezone: Asia/Bangkok\n\
              pools:\n  - id: stations\n    members:\n      - resourceId: station-1\n\
              \x20       capabilities: []\n        available: true\n\
              exceptions:\n  - id: training\n    location: north-counter\n    kind: closure\n\
              \x20   date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '12:30'\n",
        )
        .unwrap()
        .value
        .into_facts();
        assert_eq!(
            counts(&facts),
            json!({"locations": 1, "pools": 1, "members": 1, "windows": 0, "exceptions": 1})
        );
    }
}
