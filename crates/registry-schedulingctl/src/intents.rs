// SPDX-License-Identifier: Apache-2.0

//! The undelivered delivery-intents read command.
//!
//! A deployment that declares no reminders destination holds every delivery
//! intent locally, and a destination that refused every attempt leaves the
//! intent failed. Both are recorded in the outbox and then waited on by
//! nobody, so this is the read path an operator has without one: it lists
//! what the sweep has stopped carrying, oldest due first, in the store's own
//! terms.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::store::PostgresStore;
use serde_json::{json, Value};

pub fn undelivered(config_path: &Path, limit: i64) -> Result<Value> {
    let config_path =
        fs::canonicalize(config_path).context("resolving the Scheduling runtime configuration")?;
    let config = RuntimeConfig::load(&config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;
    let resolver = crate::records::secret_resolver(&config)?;
    let store = PostgresStore::connect_runtime(&config.database, &resolver)
        .context("the Scheduling runtime database configuration is invalid")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Scheduling operator runtime")?;
    let intents = runtime
        .block_on(store.undelivered_intents(limit))
        .context("reading undelivered delivery intents")?
        .into_iter()
        .map(|intent| {
            json!({
                "outboxId": intent.outbox_id.to_string(),
                "purpose": intent.purpose,
                "claimId": intent.claim_id.to_string(),
                "appointmentRevision": intent.appointment_revision,
                "dueAt": intent.due_at.to_rfc3339(),
                "deliveryState": intent.delivery_state,
                "attempts": intent.attempts,
                "payload": intent.payload,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "ok": true,
        "command": "intents",
        "config": config_path,
        "intents": intents,
    }))
}
