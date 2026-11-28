// SPDX-License-Identifier: Apache-2.0

//! The undelivered delivery-intents read command.
//!
//! A deployment that declares no reminders destination sets every delivery
//! intent aside locally, and a destination that refused every attempt leaves
//! the intent failed. Both are recorded in the outbox and then waited on by
//! nobody, so this is the read path an operator has without one: it lists
//! what the dispatcher has stopped carrying, oldest due first, in the store's
//! own terms. A reminder superseded by a cancellation or a reschedule is not
//! listed: nobody was ever meant to deliver it, and the row is retained as
//! accounting rather than as work.

use registry_platform_config::DeclaredPosture;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use registry_scheduling::store::PostgresStore;
use serde_json::{json, Value};

pub fn undelivered(config_path: &Path, limit: i64, declared: DeclaredPosture) -> Result<Value> {
    let config_path =
        fs::canonicalize(config_path).context("resolving the Scheduling runtime configuration")?;
    let config = crate::project::load_runtime_config(&config_path, declared)?;
    let resolver = crate::records::secret_resolver(&config)?;
    let store =
        PostgresStore::connect_runtime(&config.database, &resolver, config.development_witness())
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
