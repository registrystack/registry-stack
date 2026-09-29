// SPDX-License-Identifier: Apache-2.0

//! Registry-local, expiring access history, separate from the operational audit.

use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_audit::AuditEntry;
use serde_json::json;
use tokio_postgres::{types::Type, GenericClient};

use crate::api::{AuthorizedRequestContext, ReadServiceError};
use crate::audit::RegistryAudit;
use crate::correlation::RequestCorrelation;
use crate::model::CompiledEntity;
use crate::postgres::{ExpectedRegistryIdentity, RuntimePool, RuntimeRevoke, SqlIdentifier};

pub(crate) const REQUESTER_HEADER: &str = "registry-access-requester";
pub(crate) const PURPOSE_HEADER: &str = "registry-access-purpose";
const MAX_VALUE_BYTES: usize = 512;
/// Rows one `expire_subject_access_log()` call erases at most.
const EXPIRY_BATCH_ROWS: i64 = 1_000;
/// Batches one retention tick erases before it yields to the next tick, so a
/// backlog drains without one tick running unbounded.
const MAX_EXPIRY_BATCHES_PER_TICK: u32 = 100;

/// Provenance only. It never enters a claim context, row policy, or purpose grant.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ForwardedAccessAttribution {
    pub requester: String,
    pub purpose: String,
}

impl std::fmt::Debug for ForwardedAccessAttribution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<access attribution redacted>")
    }
}

/// Both headers are host-authored, canonical base64url UTF-8. Only an explicitly
/// named, verified OAuth client may attest another requester's access purpose.
pub(crate) fn forwarded_attribution(
    entity: &CompiledEntity,
    context: &AuthorizedRequestContext,
    headers: &HeaderMap,
) -> Result<Option<ForwardedAccessAttribution>, ()> {
    if !headers.contains_key(REQUESTER_HEADER) && !headers.contains_key(PURPOSE_HEADER) {
        return Ok(None);
    }
    let policy = entity.access_log.as_ref().ok_or(())?;
    let client = context.requester_client().ok_or(())?;
    if !policy.trusted_intermediaries.contains(client) {
        return Err(());
    }
    Ok(Some(ForwardedAccessAttribution {
        requester: decode_header(headers, REQUESTER_HEADER)?,
        purpose: decode_header(headers, PURPOSE_HEADER)?,
    }))
}

fn decode_header(headers: &HeaderMap, name: &str) -> Result<String, ()> {
    let mut values = headers.get_all(name).iter();
    let encoded = values.next().ok_or(())?.to_str().map_err(|_| ())?;
    if values.next().is_some() || encoded.len() > 684 {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(());
    }
    let value = String::from_utf8(bytes).map_err(|_| ())?;
    if !valid_value(&value) {
        return Err(());
    }
    Ok(value)
}

fn valid_value(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_VALUE_BYTES
        && !value.chars().any(char::is_control)
}

pub(crate) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), tokio_postgres::Error> {
    let revoke = RuntimeRevoke::detect(migration, runtime_role)
        .await?
        .with_public();
    migration
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_subject_access_log (
                event_id uuid PRIMARY KEY,
                entity_id text NOT NULL,
                record_id uuid NOT NULL,
                requester text NOT NULL CHECK (octet_length(requester) BETWEEN 1 AND 512),
                service_client text CHECK (octet_length(service_client) BETWEEN 1 AND 512),
                purpose text CHECK (octet_length(purpose) BETWEEN 1 AND 512),
                operation_id text NOT NULL,
                authority_entity text NOT NULL,
                access_profile text NOT NULL,
                package_revision text NOT NULL,
                request_id uuid NOT NULL,
                accessed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                visible_after timestamptz NOT NULL,
                expires_at timestamptz NOT NULL,
                exemption_reason text CHECK (octet_length(exemption_reason) BETWEEN 1 AND 256),
                CHECK (accessed_at <= visible_after AND visible_after < expires_at)
             );
             CREATE INDEX IF NOT EXISTS registry_subject_access_log_record
                ON registry_internal.registry_subject_access_log (entity_id, record_id, accessed_at DESC, event_id DESC);
             CREATE INDEX IF NOT EXISTS registry_subject_access_log_expiry
                ON registry_internal.registry_subject_access_log (expires_at);
             REVOKE ALL ON registry_internal.registry_subject_access_log FROM {revoke};
             GRANT SELECT, INSERT ON registry_internal.registry_subject_access_log TO {role};
             CREATE OR REPLACE FUNCTION registry_internal.expire_subject_access_log()
                RETURNS bigint LANGUAGE sql SECURITY DEFINER
                SET search_path = pg_catalog, registry_internal AS $body$
                WITH expired AS (
                    SELECT event_id FROM registry_internal.registry_subject_access_log
                    WHERE expires_at <= transaction_timestamp()
                    ORDER BY expires_at LIMIT {EXPIRY_BATCH_ROWS} FOR UPDATE SKIP LOCKED
                ), removed AS (
                    DELETE FROM registry_internal.registry_subject_access_log AS entry
                    USING expired WHERE entry.event_id = expired.event_id RETURNING 1
                ) SELECT count(*) FROM removed;
                $body$;
             REVOKE ALL ON FUNCTION registry_internal.expire_subject_access_log() FROM {revoke};
             GRANT EXECUTE ON FUNCTION registry_internal.expire_subject_access_log() TO {role};",
            role = runtime_role.quoted(),
        ))
        .await
}

/// Called inside the authorized source transaction, after paging has discarded
/// its lookahead row. Failure refuses the complete read, never just the entry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_reads(
    transaction: &impl GenericClient,
    entity: &CompiledEntity,
    authority_entity: &str,
    context: &AuthorizedRequestContext,
    record_ids: &[String],
    operation_id: &str,
    identity: &ExpectedRegistryIdentity,
    correlation: &RequestCorrelation,
    audit: &RegistryAudit,
) -> Result<(), ReadServiceError> {
    let Some(policy) = &entity.access_log else {
        return Ok(());
    };
    if record_ids.is_empty() {
        return Ok(());
    }
    let forwarded = context.forwarded_access_attribution();
    let requester = forwarded
        .map(|value| value.requester.as_str())
        .or(context.requester_client())
        .or(context.principal())
        .filter(|value| valid_value(value))
        .ok_or(ReadServiceError::Unavailable)?;
    let purpose = forwarded
        .map(|value| value.purpose.as_str())
        .or(context.purpose());
    let service_client = forwarded.and(context.requester_client());
    let exemption = policy
        .exemptions
        .get(context.selected_profile())
        .filter(|exemption| {
            exemption.source_entity.as_deref().unwrap_or(&entity.id) == authority_entity
        });
    let delay = i32::from(exemption.map_or(0, |value| value.delay_days));
    let retention = i32::from(policy.retention_days);
    let reason = exemption.map(|value| value.reason.as_str());
    // The separate exemption audit identifies the governed policy by a keyed
    // reference. Neither its text, the subject, nor the purpose enters audit.
    if let Some(reason) = reason {
        let reference = audit
            .profile()
            .key_hasher()
            .audit_reference_hash(
                "breg-access-log-exemption-v1",
                &identity.activation_id,
                reason,
            )
            .map_err(|_| ReadServiceError::Unavailable)?;
        let correlation_id = format!("{}:access-log", correlation.request_id());
        let _attempt = audit
            .begin(
                AuditEntry::request(
                    "breg-access-log/v1",
                    &correlation_id,
                    json!({"operation":"visibility-delay", "entityId":entity.id,
                        "authorityEntity":authority_entity,
                        "packageRevision":identity.activation_id,
                        "selectedAccessProfile":context.selected_profile(),
                        "exemptionReference":reference,"delayDays":delay}),
                ),
                json!({"outcome":"unfinished"}),
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        audit
            .append(AuditEntry::response(
                "breg-access-log/v1",
                correlation_id,
                json!({"outcome":"authorized"}),
            ))
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
    }
    let event_ids = record_ids
        .iter()
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect::<Vec<_>>();
    let request_id = correlation.request_id().to_string();
    // A page has one bounded insert, rather than one database round trip per
    // subject. The parallel arrays retain a distinct event for every read hit.
    transaction
        .execute_typed(
            "INSERT INTO registry_internal.registry_subject_access_log
                    (event_id, entity_id, record_id, requester, service_client, purpose,
                     operation_id, access_profile, package_revision, request_id,
                     authority_entity,
                     visible_after, expires_at, exemption_reason)
                 SELECT hit.event_id::uuid, $2, hit.record_id::uuid, $4, $5, $6, $7, $8, $9,
                         $10::text::uuid, $14, transaction_timestamp() + make_interval(days => $11),
                         transaction_timestamp() + make_interval(days => $12), $13
                 FROM unnest($1::text[], $3::text[]) AS hit(event_id, record_id)",
            &[
                (&event_ids, Type::TEXT_ARRAY),
                (&entity.id, Type::TEXT),
                (&record_ids, Type::TEXT_ARRAY),
                (&requester, Type::TEXT),
                (&service_client, Type::TEXT),
                (&purpose, Type::TEXT),
                (&operation_id, Type::TEXT),
                (&context.selected_profile(), Type::TEXT),
                (&identity.activation_id, Type::TEXT),
                (&request_id, Type::TEXT),
                (&delay, Type::INT4),
                (&retention, Type::INT4),
                (&reason, Type::TEXT),
                (&authority_entity, Type::TEXT),
            ],
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    Ok(())
}

/// Runs even when the active package stops collecting entries. Expired entries
/// are hidden immediately; bounded erasure keeps old purpose values out of the
/// live database without granting the runtime arbitrary DELETE authority.
pub(crate) async fn run_retention(
    pool: RuntimePool,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() { break; }
            }
            _ = interval.tick() => {
                if let Ok(client) = pool.get().await {
                    match expire_tick(&**client, MAX_EXPIRY_BATCHES_PER_TICK).await {
                        Ok(tick) => tracing::debug!(
                            erased = tick.erased,
                            bound_reached = tick.bound_reached,
                            "subject access log expiry tick finished"
                        ),
                        Err(_) => tracing::error!("subject access log expiry failed"),
                    }
                } else {
                    tracing::error!("subject access log expiry could not acquire a connection");
                }
            }
        }
    }
}

struct ExpiryTick {
    erased: i64,
    bound_reached: bool,
}

/// Erases expired entries batch by batch until a batch comes back short, or
/// until `max_batches` batches ran. Each batch commits on its own, so a long
/// drain never holds one large transaction. Reaching the bound logs the
/// remaining backlog, counted up to one further tick's worth of rows.
async fn expire_tick(
    client: &impl GenericClient,
    max_batches: u32,
) -> Result<ExpiryTick, tokio_postgres::Error> {
    let mut erased = 0;
    for _ in 0..max_batches {
        let removed: i64 = client
            .query_one("SELECT registry_internal.expire_subject_access_log()", &[])
            .await?
            .get(0);
        erased += removed;
        if removed < EXPIRY_BATCH_ROWS {
            return Ok(ExpiryTick {
                erased,
                bound_reached: false,
            });
        }
    }
    let cap = i64::from(MAX_EXPIRY_BATCHES_PER_TICK) * EXPIRY_BATCH_ROWS;
    let remaining: i64 = client
        .query_one(
            "SELECT count(*) FROM (
                SELECT 1 FROM registry_internal.registry_subject_access_log
                 WHERE expires_at <= transaction_timestamp() LIMIT $1
             ) AS backlog",
            &[&cap],
        )
        .await?
        .get(0);
    tracing::warn!(
        erased,
        remaining_expired = remaining,
        remaining_count_capped = remaining >= cap,
        "subject access log expiry reached its per-tick bound; expired entries remain"
    );
    Ok(ExpiryTick {
        erased,
        bound_reached: true,
    })
}

/// Runs one retention tick, bounded by `max_batches` when given.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn expire_subject_access_log_for_test(
    pool: &RuntimePool,
    max_batches: Option<u32>,
) -> Result<(i64, bool), tokio_postgres::Error> {
    let client = pool.get_for_test().await.expect("test pool connection");
    let tick = expire_tick(
        &**client,
        max_batches.unwrap_or(MAX_EXPIRY_BATCHES_PER_TICK),
    )
    .await?;
    Ok((tick.erased, tick.bound_reached))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn attribution_headers_refuse_duplicates_controls_oversize_and_noncanonical_encoding() {
        let mut headers = HeaderMap::new();
        for bad in ["", "a=", "!", "YQ=="] {
            headers.insert(REQUESTER_HEADER, HeaderValue::from_str(bad).unwrap());
            assert!(decode_header(&headers, REQUESTER_HEADER).is_err());
        }
        for bad in ["bad\nvalue".to_owned(), " ".to_owned(), "x".repeat(513)] {
            headers.insert(
                REQUESTER_HEADER,
                HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(bad)).unwrap(),
            );
            assert!(decode_header(&headers, REQUESTER_HEADER).is_err());
        }
        let good = HeaderValue::from_str(&URL_SAFE_NO_PAD.encode("agence-éducation")).unwrap();
        headers.insert(REQUESTER_HEADER, good.clone());
        assert_eq!(
            decode_header(&headers, REQUESTER_HEADER).unwrap(),
            "agence-éducation"
        );
        headers.append(REQUESTER_HEADER, good);
        assert!(decode_header(&headers, REQUESTER_HEADER).is_err());
    }
}
