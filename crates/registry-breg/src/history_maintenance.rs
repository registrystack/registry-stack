// SPDX-License-Identifier: Apache-2.0

//! Shared plumbing for the bounded, audited history maintenance paths.
//!
//! Every maintenance path runs under the same interlock: the configured
//! migration authority, bounded lock and statement timeouts, the exclusive
//! Registry advisory lock, a ready registry identity, and one chained audit
//! record whose payload carries references and counts instead of values. The
//! erasure and rebaseline paths differ only in what they change inside that
//! transaction, so the interlock lives here once.

use std::time::Duration;

use registry_platform_audit::{AuditChainHasher, AuditEnvelope, AuditKeyHasher, AuditProfile};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::Value;

use crate::postgres::{ExpectedRegistryIdentity, PostgresKernelError};

const MAX_LOCK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Bounded lock and statement timeouts for one maintenance transaction.
#[derive(Clone, Copy)]
pub struct HistoryMaintenanceTimeouts {
    lock: Duration,
    statement: Duration,
}

impl HistoryMaintenanceTimeouts {
    pub fn new(lock: Duration, statement: Duration) -> Result<Self, HistoryMaintenanceError> {
        if lock.is_zero()
            || lock > MAX_LOCK_TIMEOUT
            || statement.is_zero()
            || statement > MAX_STATEMENT_TIMEOUT
        {
            return Err(HistoryMaintenanceError::InvalidInput);
        }
        Ok(Self { lock, statement })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoryMaintenanceError {
    #[error("history maintenance input is invalid")]
    InvalidInput,
    #[error("history maintenance requires the configured migration authority")]
    MigrationAuthority,
    #[error("history maintenance storage is unavailable")]
    Unavailable,
}

impl From<PostgresKernelError> for HistoryMaintenanceError {
    fn from(error: PostgresKernelError) -> Self {
        match error {
            PostgresKernelError::RoleInvariant(_) => Self::MigrationAuthority,
            PostgresKernelError::Configuration(_) => Self::InvalidInput,
            PostgresKernelError::Connection
            | PostgresKernelError::Pool
            | PostgresKernelError::PoolBuild
            | PostgresKernelError::CatalogInvariant(_)
            | PostgresKernelError::RegistryUnavailable => Self::Unavailable,
        }
    }
}

pub(crate) async fn set_local_timeouts(
    transaction: &tokio_postgres::Transaction<'_>,
    timeouts: HistoryMaintenanceTimeouts,
) -> Result<(), HistoryMaintenanceError> {
    let lock_millis = u64::try_from(timeouts.lock.as_millis())
        .map_err(|_| HistoryMaintenanceError::InvalidInput)?;
    let statement_millis = u64::try_from(timeouts.statement.as_millis())
        .map_err(|_| HistoryMaintenanceError::InvalidInput)?;
    transaction
        .execute(
            "SELECT set_config('lock_timeout', $1::text, true),
                    set_config('statement_timeout', $2::text, true)",
            &[
                &format!("{lock_millis}ms"),
                &format!("{statement_millis}ms"),
            ],
        )
        .await
        .map_err(|_| HistoryMaintenanceError::Unavailable)?;
    Ok(())
}

/// Lock the registry state row and require it to be ready for the expected
/// package binding. A mismatch and a non-ready state answer alike, so the
/// refusal never discloses which invariant failed.
pub(crate) async fn verify_ready_identity(
    transaction: &tokio_postgres::Transaction<'_>,
    expected: &ExpectedRegistryIdentity,
) -> Result<(), HistoryMaintenanceError> {
    expected.validate()?;
    let row = transaction
        .query_opt(
            "SELECT package_id, environment, instance_id, database_id,
                    active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status
               FROM registry_internal.registry_state
              WHERE singleton
              FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| HistoryMaintenanceError::Unavailable)?
        .ok_or(HistoryMaintenanceError::Unavailable)?;
    let ready = row.get::<_, String>(7) == "ready"
        && row.get::<_, String>(0) == expected.package_id
        && row.get::<_, String>(1) == expected.environment
        && row.get::<_, String>(2) == expected.instance_id
        && row.get::<_, String>(3) == expected.database_id
        && row.get::<_, String>(4) == expected.package_revision
        && row.get::<_, String>(5) == expected.schema_fingerprint
        && row.get::<_, i64>(6) == expected.package_sequence;
    if !ready {
        return Err(HistoryMaintenanceError::Unavailable);
    }
    Ok(())
}

/// Append one maintenance record to the keyed audit chain inside the caller's
/// transaction, advancing the single audit head under a row lock.
///
/// The envelope is stored as canonical JSON, and the operator chain traversal
/// in `audit_tooling` recovers each link from those bytes by taking the first
/// `"prev_hash":"<64 hex>"` they hold. Canonicalization sorts object keys, so
/// `prev_hash` is written before `record` and an envelope that names a link
/// names it ahead of anything its record body carries: a record body holding a
/// `prev_hash` of its own can never be read as the link of the envelope
/// carrying it. A genesis envelope writes `"prev_hash":null` and names no
/// link, so a record body key is the only match its bytes can offer, and only
/// a record hash that did not exist when the genesis record was written could
/// be one. `stored_envelope_bytes_name_the_link_before_the_record_body` pins
/// that order so a change of serializer cannot make the shadowing reachable
/// without failing a test.
pub(crate) async fn append_audit_envelope(
    transaction: &tokio_postgres::Transaction<'_>,
    profile: &AuditProfile,
    record: Value,
) -> Result<(), HistoryMaintenanceError> {
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_audit_head (singleton, last_hash)
             VALUES (true, NULL)
             ON CONFLICT (singleton) DO NOTHING",
            &[],
        )
        .await
        .map_err(|_| HistoryMaintenanceError::Unavailable)?;
    let row = transaction
        .query_one(
            "SELECT last_hash
               FROM registry_internal.registry_audit_head
              WHERE singleton
              FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| HistoryMaintenanceError::Unavailable)?;
    let previous = row
        .get::<_, Option<Vec<u8>>>(0)
        .map(|bytes| <[u8; 32]>::try_from(bytes).map_err(|_| HistoryMaintenanceError::Unavailable))
        .transpose()?;
    let envelope = AuditEnvelope::new_with_hasher(record, previous, &profile.chain_hasher())
        .map_err(|_| HistoryMaintenanceError::Unavailable)?;
    let envelope_value =
        serde_json::to_value(&envelope).map_err(|_| HistoryMaintenanceError::Unavailable)?;
    let envelope_bytes =
        canonicalize_json(&envelope_value).map_err(|_| HistoryMaintenanceError::Unavailable)?;
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_audit
                 (envelope_id, record_hash, envelope)
             VALUES ($1, $2, $3)",
            &[
                &envelope.envelope_id,
                &envelope.record_hash.as_slice(),
                &envelope_bytes,
            ],
        )
        .await
        .map_err(|_| HistoryMaintenanceError::Unavailable)?;
    if changed != 1 {
        return Err(HistoryMaintenanceError::Unavailable);
    }
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_audit_head
                SET last_hash = $1
              WHERE singleton",
            &[&envelope.record_hash.as_slice()],
        )
        .await
        .map_err(|_| HistoryMaintenanceError::Unavailable)?;
    if changed != 1 {
        return Err(HistoryMaintenanceError::Unavailable);
    }
    Ok(())
}

pub(crate) fn profile_is_keyed(profile: &AuditProfile) -> bool {
    matches!(profile.chain_hasher(), AuditChainHasher::Keyed(_))
        && matches!(profile.key_hasher(), AuditKeyHasher::Keyed(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    /// The canonical key order of a stored envelope, which the chain traversal
    /// depends on to read an envelope's own link ahead of its record body.
    const CANONICAL_KEYS: [&str; 5] = [
        "\"envelope_id\":",
        "\"prev_hash\":",
        "\"record\":",
        "\"record_hash\":",
        "\"timestamp_unix_ms\":",
    ];

    /// The link the chain traversal recovers from stored bytes: the first
    /// `"prev_hash":"<64 hex>"` they hold, read the way `CHAIN_CTE` reads it.
    fn stored_link(bytes: &[u8]) -> Option<String> {
        const KEY: &[u8] = b"\"prev_hash\":\"";
        bytes
            .windows(KEY.len())
            .enumerate()
            .filter(|(_, window)| *window == KEY)
            .find_map(|(index, _)| {
                let start = index + KEY.len();
                let digits = bytes.get(start..start.checked_add(64)?)?;
                (digits.iter().all(u8::is_ascii_hexdigit) && bytes.get(start + 64) == Some(&b'"'))
                    .then(|| String::from_utf8(digits.to_vec()).expect("hex digits are ASCII"))
            })
    }

    fn stored_bytes(record: Value, previous: Option<[u8; 32]>, profile: &AuditProfile) -> Vec<u8> {
        let envelope = AuditEnvelope::new_with_hasher(record, previous, &profile.chain_hasher())
            .expect("the envelope is built");
        let value = serde_json::to_value(&envelope).expect("the envelope serializes");
        canonicalize_json(&value).expect("the envelope canonicalizes")
    }

    /// Pins the canonical key order the audit chain traversal reads links with.
    /// A record body may hold a `prev_hash` of its own, so an envelope that
    /// names a link has to name it first, and a genesis envelope has to write
    /// its absent link where a later key cannot be mistaken for it.
    #[test]
    fn stored_envelope_bytes_name_the_link_before_the_record_body() {
        let profile = AuditProfile::production_from_secret_bytes(vec![0x8b; 32].into())
            .expect("the test audit profile is keyed");
        let decoy = "a".repeat(64);
        let record = json!({
            "schema": "breg-audit/v1",
            "phase": "attempt",
            "prev_hash": decoy,
        });

        let genesis = stored_bytes(record.clone(), None, &profile);
        let previous = [0x5c; 32];
        let linked = stored_bytes(record, Some(previous), &profile);

        for bytes in [&genesis, &linked] {
            let text = String::from_utf8(bytes.clone()).expect("canonical JSON is UTF-8");
            let positions: Vec<usize> = CANONICAL_KEYS
                .iter()
                .map(|key| {
                    text.find(key)
                        .unwrap_or_else(|| panic!("the stored envelope holds {key}"))
                })
                .collect();
            let mut ordered = positions.clone();
            ordered.sort_unstable();
            assert_eq!(
                positions, ordered,
                "the stored envelope keeps the canonical key order {CANONICAL_KEYS:?}"
            );
        }

        assert_eq!(
            stored_link(&linked),
            Some(hex::encode(previous)),
            "an envelope that names a link names it before its record body"
        );
        assert!(
            String::from_utf8(genesis.clone())
                .expect("canonical JSON is UTF-8")
                .contains("\"prev_hash\":null"),
            "a genesis envelope names no link of its own"
        );
        assert_eq!(
            stored_link(&genesis),
            Some(decoy),
            "a genesis envelope offers only its record body, which no record \
             hash of an earlier record can appear in"
        );
    }
}
