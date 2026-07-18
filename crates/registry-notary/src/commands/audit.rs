// SPDX-License-Identifier: Apache-2.0
//! Offline audit-chain recovery.

use crate::*;

pub(crate) fn audit_quarantine(
    config_path: &Path,
    args: AuditQuarantineArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    // Recovery must also work after the first governed boot verified a signed
    // bundle but could not persist acceptance because its audit write failed.
    // Preparing initialization here is read-only: bundle acceptance state is
    // still persisted only by the governed boot path after its audit succeeds.
    let loaded = load_server_config(config_path, true)?;
    let config = &loaded.config.audit;
    if !matches!(config.sink.as_str(), "file" | "jsonl") {
        return Err("audit quarantine requires audit.sink = file or jsonl".into());
    }
    let path = PathBuf::from(
        config
            .path
            .as_deref()
            .ok_or("audit quarantine requires audit.path")?,
    );
    let hash_secret_env = config
        .hash_secret_env
        .as_deref()
        .ok_or("audit quarantine requires audit.hash_secret_env")?;
    let profile = registry_platform_audit::AuditProfile::registry_notary_from_env(hash_secret_env)?;
    let now_unix_ms = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(i64::MAX);
    let outcome = registry_platform_audit::quarantine_and_recover_chain(
        &path,
        config.max_files(),
        &profile.chain_hasher(),
        &args.reason,
        args.operator.as_deref(),
        now_unix_ms,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": "registry.audit.recovery.v1",
            "product": "registry-notary",
            "audit_path": path_for_json(&path),
            "already_consistent": outcome.already_consistent,
            "first_bad_line": outcome.first_bad_line,
            "last_good_hash": outcome.last_good_hash.map(|hash| {
                registry_platform_audit::OptionalHashHex(Some(hash)).to_string()
            }),
            "break_event_hash": outcome.break_event_hash.map(|hash| {
                registry_platform_audit::OptionalHashHex(Some(hash)).to_string()
            }),
            "records_before_break": outcome.records_before_break,
            "quarantine_suffix": outcome.quarantine_suffix,
        }))?
    );
    Ok(())
}

#[cfg(test)]
#[path = "audit/tests.rs"]
mod tests;
