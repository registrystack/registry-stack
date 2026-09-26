// SPDX-License-Identifier: Apache-2.0

//! The live environment-records command.
//!
//! `records apply` is the one attributable operator write that swaps a
//! deployment's locations, pools, members, published windows, and exceptions
//! wholesale. The
//! records document is parsed and validated offline first, nothing reaches
//! the database until the whole document holds together, and the swap itself
//! lands through the store's single replace transaction. The command writes
//! its `request` audit entry before that transaction opens and a paired
//! `response` entry after it either commits or the store refuses it, to the
//! `schedulingctl` sibling of the runtime's audit destination.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_scheduling::audit::{with_event_id, SchedulingAudit};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::runtime::open_audit;
use registry_scheduling::store::PostgresStore;
use registry_scheduling_core::{location_open_intervals, SchedulingFacts};
use serde_json::{json, Value};
use uuid::Uuid;

pub fn apply(config_path: &Path, records_path: &Path) -> Result<Value> {
    let config_path =
        fs::canonicalize(config_path).context("resolving the Scheduling runtime configuration")?;
    let records_path =
        fs::canonicalize(records_path).context("resolving the Scheduling environment records")?;
    let config = RuntimeConfig::load(&config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;
    let policy = config
        .load_policy()
        .with_context(|| format!("loading {}", config.policy_path().display()))?;
    let text = crate::project::read_authoring_input(&records_path)?;
    let facts = parse_records(&text)?;
    validate(&facts, &policy)?;
    let counts = counts(&facts);
    let resolver = secret_resolver(&config)?;
    let store = PostgresStore::connect_migration(&config.database, &resolver)
        .context("the Scheduling migration database configuration is invalid")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Scheduling operator runtime")?;
    runtime
        .block_on(store.ready())
        .context(
            "checking the Scheduling schema; run `scheduling --runtime-config <runtime.yaml> migrate` first",
        )?;
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
    match runtime.block_on(store.replace_facts(&policy.scheduling.id, &facts)) {
        Ok(()) => {}
        Err(store_error) => {
            let error =
                anyhow::Error::new(store_error).context("replacing the environment records");
            return Err(record_refused(
                &runtime,
                &audit,
                correlation,
                &counts,
                error,
            ));
        }
    }
    record_applied(&runtime, &audit, correlation, &counts)?;
    Ok(json!({
        "ok": true,
        "command": "records-apply",
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

/// Write the `response` entry of a swap the store refused. The `request`
/// entry was already written, so a refusal here would otherwise leave it
/// orphaned. The store's own refusal is always what `apply` returns; a
/// response entry that also fails to write says so too, rather than hiding
/// behind the store's message.
fn record_refused(
    runtime: &tokio::runtime::Runtime,
    audit: &SchedulingAudit,
    correlation: Uuid,
    counts: &Value,
    error: anyhow::Error,
) -> anyhow::Error {
    let record = with_event_id(
        correlation,
        json!({
            "actorKind": "operator",
            "operation": "records.apply",
            "outcome": "refused",
            "reason": "records.replace-failed",
            "detail": format!("{error:#}"),
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

/// Read the environment records, refusing a document the model does not
/// carry and naming the path of the first offending field.
pub(crate) fn parse_records(text: &str) -> Result<SchedulingFacts> {
    let deserializer = serde_norway::Deserializer::from_str(text);
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let path = error.path().to_string();
        anyhow!(
            "parsing the environment records failed at {}: {error}",
            if path.is_empty() {
                "/".to_owned()
            } else {
                path
            }
        )
    })
}

/// The checks the store cannot make: the tables it writes have primary keys
/// and typed columns, so an inconsistent document would fail mid-swap with a
/// database error naming none of the author's vocabulary. Every rule here
/// refuses before the transaction opens, in the records document's own terms.
pub(crate) fn validate(
    facts: &SchedulingFacts,
    policy: &registry_scheduling_core::SchedulingPolicy,
) -> Result<()> {
    let mut locations = BTreeSet::new();
    for location in &facts.locations {
        if location.id.is_empty() {
            bail!("a location record carries an empty id");
        }
        if !locations.insert(&location.id) {
            bail!("location {} is declared more than once", location.id);
        }
        if location.timezone.parse::<chrono_tz::Tz>().is_err() {
            bail!(
                "location {} names an unknown timezone {}",
                location.id,
                location.timezone
            );
        }
    }
    let mut pools = BTreeSet::new();
    let mut resources = BTreeSet::new();
    for pool in &facts.pools {
        if pool.id.is_empty() {
            bail!("a resource pool carries an empty id");
        }
        if !pools.insert(&pool.id) {
            bail!("resource pool {} is declared more than once", pool.id);
        }
        for member in &pool.members {
            if member.resource_id.is_empty() {
                bail!(
                    "pool {} carries a member with an empty resource id",
                    pool.id
                );
            }
            if !resources.insert(&member.resource_id) {
                bail!(
                    "resource {} is declared in more than one pool",
                    member.resource_id
                );
            }
        }
    }
    if let Some(finding) = policy
        .check_window_records(&facts.windows)
        .into_iter()
        .next()
    {
        bail!("invalid window record at {finding}");
    }
    for window in &facts.windows {
        if !locations.contains(&window.location) {
            bail!(
                "window {} names location {} the records do not declare",
                window.id,
                window.location
            );
        }
        if pools.contains(&window.id) {
            bail!(
                "window {} collides with a resource-pool supply identifier",
                window.id
            );
        }
        if let Some(staffing) = &window.staffing {
            if !pools.contains(&staffing.pool) {
                bail!(
                    "window {} names staffing pool {} the records do not declare",
                    window.id,
                    staffing.pool
                );
            }
        }
    }
    let mut exception_ids = BTreeSet::new();
    for exception in &facts.exceptions {
        if exception.id.is_empty() {
            bail!("an exception record carries an empty id");
        }
        if !exception_ids.insert(&exception.id) {
            bail!("exception {} is declared more than once", exception.id);
        }
        if !locations.contains(&exception.location) {
            bail!(
                "exception {} names location {} the records do not declare",
                exception.id,
                exception.location
            );
        }
        if !is_iso_date(&exception.date) {
            bail!(
                "exception {} carries a date that is not YYYY-MM-DD: {}",
                exception.id,
                exception.date
            );
        }
        for time in [&exception.start_time, &exception.end_time] {
            if !is_hh_mm(time) {
                bail!(
                    "exception {} carries a time that is not HH:MM: {}",
                    exception.id,
                    time
                );
            }
        }
    }
    for location in &facts.locations {
        let exceptions: Vec<_> = facts
            .exceptions
            .iter()
            .filter(|exception| exception.location == location.id)
            .map(|exception| exception.borrowed())
            .collect();
        location_open_intervals(policy, &location.id, &location.timezone, &exceptions)
            .with_context(|| format!("validating calendar records for location {}", location.id))?;
    }
    Ok(())
}

/// The strict shapes the database columns accept: exactly `YYYY-MM-DD` and
/// exactly `HH:MM`, so a loose value is refused here rather than rejected by
/// the column mid-swap.
fn is_iso_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
        && chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok()
}

fn is_hh_mm(value: &str) -> bool {
    value.len() == 5
        && value.as_bytes()[2] == b':'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 2 || byte.is_ascii_digit())
        && chrono::NaiveTime::parse_from_str(value, "%H:%M").is_ok()
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

    fn policy() -> registry_scheduling_core::SchedulingPolicy {
        let files = crate::templates::template_files("standalone-exact-time").unwrap();
        let text = files
            .iter()
            .find(|(path, _)| *path == "scheduling.yaml")
            .unwrap()
            .1;
        registry_scheduling_core::parse_policy_yaml(text).unwrap()
    }

    fn facts_from(text: &str) -> SchedulingFacts {
        serde_norway::from_str(text).unwrap()
    }

    #[test]
    fn a_consistent_document_validates() {
        let facts = facts_from(
            "locations:\n  - id: north-counter\n    timezone: Asia/Bangkok\n\
             pools:\n  - id: stations\n    members:\n      - resourceId: station-1\n\
             \x20       capabilities: []\n        available: true\n\
             exceptions:\n  - id: training\n    location: north-counter\n    kind: closure\n\
             \x20   date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '12:30'\n",
        );
        assert!(validate(&facts, &policy()).is_ok());
        assert_eq!(
            counts(&facts),
            json!({"locations": 1, "pools": 1, "members": 1, "windows": 0, "exceptions": 1})
        );
    }

    #[test]
    fn inconsistent_documents_are_refused_in_their_own_terms() {
        let cases = [
            (
                "locations:\n  - id: a\n    timezone: Asia/Bangkok\n  - id: a\n    timezone: Asia/Bangkok\n",
                "location a is declared more than once",
            ),
            (
                "locations:\n  - id: a\n    timezone: Mars/Olympus\n",
                "names an unknown timezone Mars/Olympus",
            ),
            (
                "locations:\n  - id: a\n    timezone: Asia/Bangkok\npools:\n  \
                 - id: p\n    members:\n      - resourceId: r1\n        capabilities: []\n\
                 \x20       available: true\n      - resourceId: r1\n        capabilities: []\n\
                 \x20       available: true\n",
                "resource r1 is declared in more than one pool",
            ),
            (
                "locations:\n  - id: a\n    timezone: Asia/Bangkok\nexceptions:\n  \
                 - id: x\n    location: elsewhere\n    kind: closure\n    date: '2026-10-07'\n\
                 \x20   startTime: '09:00'\n    endTime: '12:30'\n",
                "names location elsewhere the records do not declare",
            ),
            (
                "locations:\n  - id: a\n    timezone: Asia/Bangkok\nexceptions:\n  \
                 - id: x\n    location: a\n    kind: closure\n    date: '2026-10-7'\n\
                 \x20   startTime: '09:00'\n    endTime: '12:30'\n",
                "not YYYY-MM-DD",
            ),
            (
                "locations:\n  - id: a\n    timezone: Asia/Bangkok\nexceptions:\n  \
                 - id: x\n    location: a\n    kind: closure\n    date: '2026-10-07'\n\
                 \x20   startTime: '9:00'\n    endTime: '12:30'\n",
                "not HH:MM",
            ),
        ];
        for (document, expected) in cases {
            let facts = facts_from(document);
            let refusal = validate(&facts, &policy()).expect_err("the document is refused");
            assert!(
                refusal.to_string().contains(expected),
                "{refusal} does not name {expected}"
            );
        }
    }

    #[test]
    fn exception_layer_semantics_are_refused_before_apply() {
        let cases = [
            (
                "duplicate id",
                "  - id: repeated\n    location: bangkok-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '10:00'\n\
                 \x20 - id: repeated\n    location: bangkok-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '10:00'\n    endTime: '11:00'\n",
                "exception repeated is declared more than once",
            ),
            (
                "opening without a named closure",
                "  - id: reopening\n    location: bangkok-counter\n    kind: opening\n    date: '2026-10-07'\n    startTime: '09:30'\n    endTime: '10:00'\n",
                "exceptional reopening reopening does not name an existing closure",
            ),
            (
                "opening without authority",
                "  - id: closure\n    location: bangkok-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '11:00'\n\
                 \x20 - id: reopening\n    location: bangkok-counter\n    kind: opening\n    date: '2026-10-07'\n    startTime: '09:30'\n    endTime: '10:00'\n    reopens: closure\n",
                "exceptional reopening reopening has no explicit authority",
            ),
            (
                "opening names an unknown closure",
                "  - id: reopening\n    location: bangkok-counter\n    kind: opening\n    date: '2026-10-07'\n    startTime: '09:30'\n    endTime: '10:00'\n    reopens: absent\n    authority: office-manager\n",
                "exceptional reopening reopening does not name an existing closure",
            ),
            (
                "closure carries reopening fields",
                "  - id: closure\n    location: bangkok-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '10:00'\n    reopens: another\n    authority: office-manager\n",
                "blocking closure closure carries reopening fields",
            ),
            (
                "invalid interval",
                "  - id: backwards\n    location: bangkok-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '11:00'\n    endTime: '10:00'\n",
                "exception times must be valid HH:MM local values with start before end",
            ),
            (
                "reopening outside the pattern",
                "  - id: early-closure\n    location: bangkok-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '08:00'\n    endTime: '10:00'\n\
                 \x20 - id: early-reopening\n    location: bangkok-counter\n    kind: opening\n    date: '2026-10-07'\n    startTime: '08:00'\n    endTime: '08:30'\n    reopens: early-closure\n    authority: office-manager\n",
                "reopening early-reopening is not inside the opening pattern's time",
            ),
        ];

        for (name, exceptions, expected) in cases {
            let facts = facts_from(&format!(
                "locations:\n  - id: bangkok-counter\n    timezone: Asia/Bangkok\nexceptions:\n{exceptions}"
            ));
            let refusal = validate(&facts, &policy()).expect_err(name);
            let message = format!("{refusal:#}");
            assert!(
                message.contains("validating calendar records for location bangkok-counter")
                    || expected.contains("declared more than once"),
                "{name}: {message} does not name the affected location"
            );
            assert!(
                message.contains(expected),
                "{name}: {message} does not name {expected}"
            );
        }
    }

    #[test]
    fn a_document_the_model_does_not_carry_is_refused_with_its_path() {
        let refusal = parse_records(
            "locations:\n  - id: a\n    timezone: Asia/Bangkok\n\
             schedule: daily\n",
        )
        .expect_err("the stray field is refused");
        let message = refusal.to_string();
        assert!(
            message.contains("locations") || message.contains("schedule"),
            "{message} names neither the container nor the field"
        );
    }
}
