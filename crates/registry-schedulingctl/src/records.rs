// SPDX-License-Identifier: Apache-2.0

//! The live environment-records command.
//!
//! `records apply` is the one attributable operator write that swaps a
//! deployment's locations, pools, members, and exceptions wholesale. The
//! records document is parsed and validated offline first — nothing reaches
//! the database until the whole document holds together — and the swap itself
//! lands through the store's single replace transaction, which writes its own
//! audit row beside the new facts.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::store::PostgresStore;
use registry_scheduling_core::SchedulingFacts;
use serde_json::{json, Value};
use uuid::Uuid;

pub fn apply(config_path: &Path, records_path: &Path) -> Result<Value> {
    let config_path =
        fs::canonicalize(config_path).context("resolving the Scheduling runtime configuration")?;
    let records_path =
        fs::canonicalize(records_path).context("resolving the Scheduling environment records")?;
    let config = RuntimeConfig::load(&config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;
    let text = crate::project::read_authoring_input(&records_path)?;
    let facts = parse_records(&text)?;
    validate(&facts)?;
    let counts = counts(&facts);
    let resolver = secret_resolver(&config)?;
    let store = PostgresStore::connect_migration(&config.database, &resolver)
        .context("the Scheduling migration database configuration is invalid")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Scheduling operator runtime")?;
    runtime
        .block_on(store.migrate())
        .context("applying the Scheduling schema")?;
    let audit_event = Uuid::new_v4();
    let audit_record = json!({
        "actorKind": "operator",
        "operation": "records.apply",
        "outcome": "allowed",
        "reason": "authorization.allowed",
        "counts": counts,
    });
    runtime
        .block_on(store.replace_facts(&facts, audit_event, audit_record))
        .context("replacing the environment records")?;
    Ok(json!({
        "ok": true,
        "command": "records-apply",
        "config": config_path,
        "records": records_path,
        "applied": counts,
    }))
}

/// Read the environment records, refusing a document the model does not
/// carry and naming the path of the first offending field.
fn parse_records(text: &str) -> Result<SchedulingFacts> {
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
fn validate(facts: &SchedulingFacts) -> Result<()> {
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
    for exception in &facts.exceptions {
        if exception.id.is_empty() {
            bail!("an exception record carries an empty id");
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
        assert!(validate(&facts).is_ok());
        assert_eq!(
            counts(&facts),
            json!({"locations": 1, "pools": 1, "members": 1, "exceptions": 1})
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
            let refusal = validate(&facts).expect_err("the document is refused");
            assert!(
                refusal.to_string().contains(expected),
                "{refusal} does not name {expected}"
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
