// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed mutation idempotency binding and exact held responses.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde_json::{json, Value};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::history_reference::SnapshotReference;
use crate::model::HttpMethod;
use crate::postgres::{ActionClaimContext, ClaimContext, RowBoundaryContext};

// Every compiled effect mutates at least one field, so this also bounds the
// number of separately named references in an immediate-action receipt.
pub(crate) const MAX_IMMEDIATE_ACTION_RESULTS: u16 =
    crate::change_request::MAX_CHANGE_REQUEST_FIELD_MUTATIONS;

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_HELD_BODY_BYTES: usize = 2 * 1024 * 1024;
// Overwrites the held bytes of a key whose record history was erased. The table
// requires a nonempty body and a 2xx status on every row, so an erased key keeps
// a minimal placeholder instead of the response it cached. Replay refuses on the
// `erased` result kind, so this placeholder never reaches a caller.
const ERASED_TOMBSTONE_BODY: &[u8] = br#"{"kind":"erased"}"#;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PermittedResponseHeader {
    ContentType,
    Etag,
    Link,
    Location,
}

impl PermittedResponseHeader {
    fn as_str(self) -> &'static str {
        match self {
            Self::ContentType => "content-type",
            Self::Etag => "etag",
            Self::Link => "link",
            Self::Location => "location",
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ContentType),
            2 => Some(Self::Etag),
            3 => Some(Self::Location),
            4 => Some(Self::Link),
            _ => None,
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::ContentType => 1,
            Self::Etag => 2,
            Self::Location => 3,
            Self::Link => 4,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HeldResponse {
    status: u16,
    body: Vec<u8>,
    headers: BTreeMap<PermittedResponseHeader, Vec<u8>>,
}

impl HeldResponse {
    pub(crate) fn from_json(
        status: u16,
        body: &serde_json::Value,
        headers: BTreeMap<PermittedResponseHeader, Vec<u8>>,
    ) -> Result<Self, IdempotencyError> {
        if !(200..=299).contains(&status)
            || headers.values().any(|value| !valid_header_value(value))
        {
            return Err(IdempotencyError::InvalidInput);
        }
        let body = canonicalize_json(body).map_err(|_| IdempotencyError::InvalidInput)?;
        if body.is_empty() || body.len() > MAX_HELD_BODY_BYTES {
            return Err(IdempotencyError::InvalidInput);
        }
        Ok(Self {
            status,
            body,
            headers,
        })
    }

    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn headers(&self) -> &BTreeMap<PermittedResponseHeader, Vec<u8>> {
        &self.headers
    }
}

pub(crate) struct IdempotencyBinding<'a> {
    pub key: &'a str,
    pub context: &'a ClaimContext,
    pub method: HttpMethod,
    pub route: &'a str,
    pub target_record: Option<&'a str>,
    pub package_revision: &'a str,
    pub response_fields: &'a BTreeSet<String>,
    pub canonical_request_digest: [u8; 32],
}

pub(crate) struct ActionIdempotencyBinding<'a> {
    pub key: &'a str,
    pub context: &'a ActionClaimContext,
    pub method: HttpMethod,
    pub route: &'a str,
    pub package_revision: &'a str,
    pub action_contract_fingerprint: &'a str,
    pub target_authority: &'a BTreeMap<String, Vec<RowBoundaryContext>>,
    pub result_effects: &'a BTreeSet<String>,
    pub canonical_request_digest: [u8; 32],
}

pub(crate) struct ResolvedIdempotencyBinding {
    pub key_reference: String,
    pub binding_reference: String,
    pub principal_reference: String,
    pub record_reference: String,
}

pub(crate) struct StoredMutationResult {
    pub response: HeldResponse,
    pub metadata: StoredResultMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StoredResultMetadata {
    Record {
        record_reference: String,
        record_revision: i64,
    },
    Batch {
        result_count: u16,
    },
    Application {
        record_reference: String,
        record_revision: i64,
        proposal_version: i64,
        result_count: u16,
    },
    ImmediateAction {
        result_count: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdempotencyError {
    #[error("mutation request is invalid")]
    InvalidInput,
    #[error("idempotency key is already bound to another request")]
    Conflict,
    #[error("mutation state is unavailable")]
    Unavailable,
}

pub(crate) fn resolve_binding(
    profile: &AuditProfile,
    binding: &IdempotencyBinding<'_>,
) -> Result<ResolvedIdempotencyBinding, IdempotencyError> {
    if binding.key.is_empty()
        || binding.key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || binding.route.is_empty()
        || binding.package_revision.is_empty()
        || binding.response_fields.iter().any(|field| field.is_empty())
    {
        return Err(IdempotencyError::InvalidInput);
    }

    let key_hasher = profile.key_hasher();
    let key_reference = key_hasher
        .audit_reference_hash("registry-server-idempotency-key-v1", "", binding.key)
        .map_err(|_| IdempotencyError::InvalidInput)?;
    let canonical_context =
        canonical_claim_context(profile, binding.context, binding.package_revision)?;
    let principal_reference = key_hasher
        .audit_reference_hash(
            "registry-server-principal-v1",
            binding.package_revision,
            binding
                .context
                .principal()
                .ok_or(IdempotencyError::InvalidInput)?,
        )
        .map_err(|_| IdempotencyError::InvalidInput)?;
    let record_reference = binding
        .target_record
        .map(|target_record| {
            if target_record.is_empty() {
                return Err(IdempotencyError::InvalidInput);
            }
            key_hasher
                .audit_reference_hash(
                    "registry-server-record-v1",
                    binding.package_revision,
                    target_record,
                )
                .map_err(|_| IdempotencyError::InvalidInput)
        })
        .transpose()?;
    let canonical = canonicalize_json(&json!({
        "context": canonical_context,
        "method": method_name(binding.method),
        "route": binding.route,
        "targetRecordReference": record_reference,
        "packageRevision": binding.package_revision,
        "responseFields": binding.response_fields,
        "canonicalRequestDigest": hex(&binding.canonical_request_digest),
    }))
    .map_err(|_| IdempotencyError::InvalidInput)?;
    let canonical = std::str::from_utf8(&canonical).map_err(|_| IdempotencyError::InvalidInput)?;
    let binding_reference = key_hasher
        .audit_reference_hash(
            "registry-server-idempotency-binding-v1",
            binding.package_revision,
            canonical,
        )
        .map_err(|_| IdempotencyError::InvalidInput)?;

    Ok(ResolvedIdempotencyBinding {
        key_reference,
        binding_reference,
        principal_reference,
        record_reference: record_reference.unwrap_or_default(),
    })
}

pub(crate) fn resolve_action_binding(
    profile: &AuditProfile,
    binding: &ActionIdempotencyBinding<'_>,
) -> Result<ResolvedIdempotencyBinding, IdempotencyError> {
    if binding.key.is_empty()
        || binding.key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || binding.route.is_empty()
        || binding.package_revision.is_empty()
        || binding.action_contract_fingerprint.is_empty()
        || binding
            .result_effects
            .iter()
            .any(|effect| effect.is_empty())
    {
        return Err(IdempotencyError::InvalidInput);
    }
    let key_hasher = profile.key_hasher();
    let key_reference = key_hasher
        .audit_reference_hash("registry-server-idempotency-key-v1", "", binding.key)
        .map_err(|_| IdempotencyError::InvalidInput)?;
    let principal_reference = key_hasher
        .audit_reference_hash(
            "registry-server-principal-v1",
            binding.package_revision,
            binding.context.principal(),
        )
        .map_err(|_| IdempotencyError::InvalidInput)?;
    let canonical_context =
        canonical_action_context(profile, binding.context, binding.package_revision)?;
    let target_authority = binding
        .target_authority
        .iter()
        .map(|(entity_id, boundaries)| {
            if entity_id.is_empty() {
                return Err(IdempotencyError::InvalidInput);
            }
            Ok(json!({
                "entityId": entity_id,
                "rowBoundaries": canonical_boundary_references(
                    profile,
                    binding.package_revision,
                    boundaries,
                )?,
            }))
        })
        .collect::<Result<Vec<_>, IdempotencyError>>()?;
    let canonical = canonicalize_json(&json!({
        "context": canonical_context,
        "method": method_name(binding.method),
        "route": binding.route,
        "packageRevision": binding.package_revision,
        "actionContractFingerprint": binding.action_contract_fingerprint,
        "targetAuthority": target_authority,
        "resultEffects": binding.result_effects,
        "canonicalRequestDigest": hex(&binding.canonical_request_digest),
    }))
    .map_err(|_| IdempotencyError::InvalidInput)?;
    let canonical = std::str::from_utf8(&canonical).map_err(|_| IdempotencyError::InvalidInput)?;
    let binding_reference = key_hasher
        .audit_reference_hash(
            "registry-server-action-idempotency-binding-v1",
            binding.package_revision,
            canonical,
        )
        .map_err(|_| IdempotencyError::InvalidInput)?;
    Ok(ResolvedIdempotencyBinding {
        key_reference,
        binding_reference,
        principal_reference,
        record_reference: String::new(),
    })
}

/// Canonical, value-safe identity of every verified authorization input that
/// PostgreSQL receives for one protected operation.
pub(crate) fn canonical_claim_context(
    profile: &AuditProfile,
    context: &ClaimContext,
    package_revision: &str,
) -> Result<Value, IdempotencyError> {
    let principal = context.principal().ok_or(IdempotencyError::InvalidInput)?;
    let key_hasher = profile.key_hasher();
    let principal_reference = key_hasher
        .audit_reference_hash("registry-server-principal-v1", package_revision, principal)
        .map_err(|_| IdempotencyError::InvalidInput)?;
    let row_boundaries = context
        .row_boundaries()
        .iter()
        .map(|boundary| {
            let reference_context = format!(
                "{package_revision}:{}:{}",
                boundary.field(),
                boundary.operator().as_str()
            );
            let value_references = boundary
                .values()
                .into_iter()
                .map(|value| {
                    key_hasher.audit_reference_hash(
                        "registry-server-row-boundary-value-v1",
                        &reference_context,
                        value,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| IdempotencyError::InvalidInput)?;
            Ok(json!({
                "field": boundary.field(),
                "operator": boundary.operator().as_str(),
                "valueReferences": value_references,
            }))
        })
        .collect::<Result<Vec<_>, IdempotencyError>>()?;
    Ok(json!({
        "entityId": context.entity_id(),
        "principalReference": principal_reference,
        "selectedAccessProfile": context.access_profile(),
        "verifiedPurpose": context.purpose(),
        "rowBoundaries": row_boundaries,
    }))
}

pub(crate) fn canonical_action_context(
    profile: &AuditProfile,
    context: &ActionClaimContext,
    package_revision: &str,
) -> Result<Value, IdempotencyError> {
    let key_hasher = profile.key_hasher();
    let principal_reference = key_hasher
        .audit_reference_hash(
            "registry-server-principal-v1",
            package_revision,
            context.principal(),
        )
        .map_err(|_| IdempotencyError::InvalidInput)?;
    Ok(json!({
        "actionId": context.action_id(),
        "principalReference": principal_reference,
        "selectedAccessProfile": context.access_profile(),
        "verifiedPurpose": context.purpose(),
    }))
}

fn canonical_boundary_references(
    profile: &AuditProfile,
    package_revision: &str,
    boundaries: &[RowBoundaryContext],
) -> Result<Vec<Value>, IdempotencyError> {
    let key_hasher = profile.key_hasher();
    boundaries
        .iter()
        .map(|boundary| {
            let reference_context = format!(
                "{package_revision}:{}:{}",
                boundary.field(),
                boundary.operator().as_str()
            );
            let value_references = boundary
                .values()
                .into_iter()
                .map(|value| {
                    key_hasher.audit_reference_hash(
                        "registry-server-row-boundary-value-v1",
                        &reference_context,
                        value,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| IdempotencyError::InvalidInput)?;
            Ok(json!({
                "field": boundary.field(),
                "operator": boundary.operator().as_str(),
                "valueReferences": value_references,
            }))
        })
        .collect()
}

pub(crate) async fn lock_and_load(
    transaction: &Transaction<'_>,
    binding: &ResolvedIdempotencyBinding,
) -> Result<Option<StoredMutationResult>, IdempotencyError> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))",
            &[&binding.key_reference],
        )
        .await
        .map_err(|_| IdempotencyError::Unavailable)?;
    let Some(row) = transaction
        .query_opt(
            "SELECT binding_reference, result_kind, record_revision, response_status,
                    response_body, response_headers, record_reference, result_count,
                    proposal_version, erased_at
             FROM registry_internal.registry_idempotency
             WHERE key_reference = $1",
            &[&binding.key_reference],
        )
        .await
        .map_err(|_| IdempotencyError::Unavailable)?
    else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != binding.binding_reference {
        return Err(IdempotencyError::Conflict);
    }
    if row.get::<_, Option<std::time::SystemTime>>(9).is_some() {
        // Erasure is permanent. Keep the consumed key reserved and refuse
        // replay without presenting a transient outage to retrying clients.
        return Err(IdempotencyError::Conflict);
    }
    let metadata = match row.get::<_, String>(1).as_str() {
        // Erasure is irreversible, so the consumed key answers with the same
        // terminal conflict the erased-at path answers with. A transient outage
        // would invite a client to retry a key that can never succeed.
        "erased" => return Err(IdempotencyError::Conflict),
        "record" => {
            let record_revision = row
                .get::<_, Option<i64>>(2)
                .filter(|revision| *revision > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            let record_reference = row
                .get::<_, Option<String>>(6)
                .filter(|reference| !reference.is_empty())
                .ok_or(IdempotencyError::Unavailable)?;
            if row.get::<_, Option<i16>>(7).is_some() || row.get::<_, Option<i64>>(8).is_some() {
                return Err(IdempotencyError::Unavailable);
            }
            StoredResultMetadata::Record {
                record_reference,
                record_revision,
            }
        }
        "batch" => {
            if row.get::<_, Option<i64>>(2).is_some()
                || row.get::<_, Option<String>>(6).is_some()
                || row.get::<_, Option<i64>>(8).is_some()
            {
                return Err(IdempotencyError::Unavailable);
            }
            let result_count = row
                .get::<_, Option<i16>>(7)
                .and_then(|count| u16::try_from(count).ok())
                .filter(|count| *count > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            StoredResultMetadata::Batch { result_count }
        }
        "application" => {
            let record_revision = row
                .get::<_, Option<i64>>(2)
                .filter(|revision| *revision > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            let record_reference = row
                .get::<_, Option<String>>(6)
                .filter(|reference| !reference.is_empty())
                .ok_or(IdempotencyError::Unavailable)?;
            let result_count = row
                .get::<_, Option<i16>>(7)
                .and_then(|count| u16::try_from(count).ok())
                .filter(|count| (1..=16).contains(count))
                .ok_or(IdempotencyError::Unavailable)?;
            let proposal_version = row
                .get::<_, Option<i64>>(8)
                .filter(|version| *version > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            StoredResultMetadata::Application {
                record_reference,
                record_revision,
                proposal_version,
                result_count,
            }
        }
        "immediate_action" => {
            if row.get::<_, Option<i64>>(2).is_some()
                || row.get::<_, Option<String>>(6).is_some()
                || row.get::<_, Option<i64>>(8).is_some()
            {
                return Err(IdempotencyError::Unavailable);
            }
            let result_count = row
                .get::<_, Option<i16>>(7)
                .and_then(|count| u16::try_from(count).ok())
                .filter(|count| *count <= MAX_IMMEDIATE_ACTION_RESULTS)
                .ok_or(IdempotencyError::Unavailable)?;
            StoredResultMetadata::ImmediateAction { result_count }
        }
        _ => return Err(IdempotencyError::Unavailable),
    };
    let status = u16::try_from(row.get::<_, i16>(3)).map_err(|_| IdempotencyError::Unavailable)?;
    let body = row
        .get::<_, Option<Vec<u8>>>(4)
        .ok_or(IdempotencyError::Unavailable)?;
    if body.is_empty() || body.len() > MAX_HELD_BODY_BYTES {
        return Err(IdempotencyError::Unavailable);
    }
    let parsed = parse_json_strict(&body).map_err(|_| IdempotencyError::Unavailable)?;
    if canonicalize_json(&parsed).map_err(|_| IdempotencyError::Unavailable)? != body {
        return Err(IdempotencyError::Unavailable);
    }
    let headers = decode_headers(&row.get::<_, Vec<u8>>(5))?;
    Ok(Some(StoredMutationResult {
        response: HeldResponse {
            status,
            body,
            headers,
        },
        metadata,
    }))
}

pub(crate) async fn insert_result(
    transaction: &Transaction<'_>,
    binding: &ResolvedIdempotencyBinding,
    metadata: &StoredResultMetadata,
    response: &HeldResponse,
) -> Result<(), IdempotencyError> {
    let status = i16::try_from(response.status).map_err(|_| IdempotencyError::InvalidInput)?;
    let headers = encode_headers(&response.headers)?;
    let (result_kind, record_revision, record_reference, result_count, proposal_version) =
        match metadata {
            StoredResultMetadata::Record {
                record_reference,
                record_revision,
            } if !record_reference.is_empty() && *record_revision > 0 => (
                "record",
                Some(*record_revision),
                Some(record_reference.as_str()),
                None,
                None,
            ),
            StoredResultMetadata::Batch { result_count } if *result_count > 0 => (
                "batch",
                None,
                None,
                Some(i16::try_from(*result_count).map_err(|_| IdempotencyError::InvalidInput)?),
                None,
            ),
            StoredResultMetadata::Application {
                record_reference,
                record_revision,
                proposal_version,
                result_count,
            } if !record_reference.is_empty()
                && *record_revision > 0
                && *proposal_version > 0
                && (1..=16).contains(result_count) =>
            {
                (
                    "application",
                    Some(*record_revision),
                    Some(record_reference.as_str()),
                    Some(i16::try_from(*result_count).map_err(|_| IdempotencyError::InvalidInput)?),
                    Some(*proposal_version),
                )
            }
            StoredResultMetadata::ImmediateAction { result_count }
                if *result_count <= MAX_IMMEDIATE_ACTION_RESULTS =>
            {
                (
                    "immediate_action",
                    None,
                    None,
                    Some(i16::try_from(*result_count).map_err(|_| IdempotencyError::InvalidInput)?),
                    None,
                )
            }
            _ => return Err(IdempotencyError::InvalidInput),
        };
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_revision,
                  response_status, response_body, response_headers, record_reference, result_count,
                  proposal_version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &binding.key_reference,
                &binding.binding_reference,
                &result_kind,
                &record_revision,
                &status,
                &response.body,
                &headers,
                &record_reference,
                &result_count,
                &proposal_version,
            ],
        )
        .await
        .map_err(|_| IdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(IdempotencyError::Unavailable);
    }
    Ok(())
}

/// Replace exact cached mutation responses that could replay erased historical
/// bytes with a minimal tombstone row. The idempotency key and binding remain
/// durable so an old retry cannot re-execute the mutation.
pub(crate) async fn tombstone_erased_cached_responses(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    erase_through_revision: i64,
    affected_positions: &[i64],
) -> Result<u64, IdempotencyError> {
    if entity_id.is_empty() || erase_through_revision <= 0 {
        return Err(IdempotencyError::InvalidInput);
    }
    let snapshot_references = affected_snapshot_references(transaction, affected_positions).await?;
    let record_id_text = record_id.hyphenated().to_string();
    let headers = encode_headers(&BTreeMap::new())?;
    transaction
        .execute(
            "WITH target_revision_refs AS (
                 SELECT record_reference, record_revision
                   FROM registry_internal.registry_revisions
                  WHERE entity_id = $1
                    AND record_id = $2
                    AND record_revision <= $3
             ),
             batch_candidates AS (
                 SELECT idempotency.key_reference
                   FROM registry_internal.registry_idempotency AS idempotency
                   CROSS JOIN LATERAL (
                       SELECT pg_catalog.convert_from(idempotency.response_body, 'UTF8')::jsonb
                           AS body
                   ) AS decoded
                  WHERE idempotency.result_kind = 'batch'
                    AND (
                        decoded.body->>'snapshot' = ANY($4::text[])
                        OR EXISTS (
                            SELECT 1
                              FROM jsonb_array_elements(
                                       CASE
                                           WHEN jsonb_typeof(decoded.body->'results') = 'array'
                                           THEN decoded.body->'results'
                                           ELSE '[]'::jsonb
                                       END
                                   ) AS item
                             WHERE item->>'id' = $5
                               AND item->>'revision' ~ '^[1-9][0-9]*$'
                               AND (item->>'revision')::bigint <= $3
                        )
                    )
             ),
             record_candidates AS (
                 SELECT idempotency.key_reference
                   FROM registry_internal.registry_idempotency AS idempotency
                  WHERE idempotency.result_kind = 'record'
                    AND EXISTS (
                        SELECT 1
                          FROM target_revision_refs AS target
                         WHERE target.record_reference = idempotency.record_reference
                           AND target.record_revision = idempotency.record_revision
                    )
             )
             UPDATE registry_internal.registry_idempotency AS idempotency
                SET result_kind = 'erased',
                    record_reference = NULL,
                    record_revision = NULL,
                    result_count = NULL,
                    response_status = 200,
                    response_body = $6,
                    response_headers = $7
              WHERE idempotency.result_kind IN ('record', 'batch')
                AND idempotency.key_reference IN (
                    SELECT key_reference FROM record_candidates
                    UNION
                    SELECT key_reference FROM batch_candidates
                )",
            &[
                &entity_id,
                &record_id,
                &erase_through_revision,
                &snapshot_references,
                &record_id_text,
                &ERASED_TOMBSTONE_BODY,
                &headers,
            ],
        )
        .await
        .map_err(|_| IdempotencyError::Unavailable)
}

async fn affected_snapshot_references(
    transaction: &Transaction<'_>,
    affected_positions: &[i64],
) -> Result<Vec<String>, IdempotencyError> {
    let rows = transaction
        .query(
            "SELECT snapshot_reference
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = ANY($1::bigint[])
              ORDER BY commit_position",
            &[&affected_positions],
        )
        .await
        .map_err(|_| IdempotencyError::Unavailable)?;
    Ok(rows
        .into_iter()
        .map(|row| SnapshotReference::for_uuid(row.get::<_, Uuid>(0)).to_string())
        .collect())
}

fn encode_headers(
    headers: &BTreeMap<PermittedResponseHeader, Vec<u8>>,
) -> Result<Vec<u8>, IdempotencyError> {
    let count = u16::try_from(headers.len()).map_err(|_| IdempotencyError::InvalidInput)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&count.to_be_bytes());
    for (name, value) in headers {
        let length = u32::try_from(value.len()).map_err(|_| IdempotencyError::InvalidInput)?;
        encoded.push(name.to_u8());
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(value);
    }
    Ok(encoded)
}

fn decode_headers(
    encoded: &[u8],
) -> Result<BTreeMap<PermittedResponseHeader, Vec<u8>>, IdempotencyError> {
    let Some(count) = encoded.get(..2) else {
        return Err(IdempotencyError::Unavailable);
    };
    let count = usize::from(u16::from_be_bytes([count[0], count[1]]));
    let mut offset = 2;
    let mut headers = BTreeMap::new();
    for _ in 0..count {
        let name = encoded
            .get(offset)
            .copied()
            .and_then(PermittedResponseHeader::from_u8)
            .ok_or(IdempotencyError::Unavailable)?;
        offset += 1;
        let length = encoded
            .get(offset..offset + 4)
            .ok_or(IdempotencyError::Unavailable)?;
        let length = u32::from_be_bytes([length[0], length[1], length[2], length[3]]) as usize;
        offset += 4;
        let value = encoded
            .get(offset..offset + length)
            .ok_or(IdempotencyError::Unavailable)?
            .to_vec();
        offset += length;
        if !valid_header_value(&value) || headers.insert(name, value).is_some() {
            return Err(IdempotencyError::Unavailable);
        }
    }
    if offset != encoded.len() {
        return Err(IdempotencyError::Unavailable);
    }
    Ok(headers)
}

fn valid_header_value(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HEADER_VALUE_BYTES
        && value.iter().all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Delete => "DELETE",
        HttpMethod::Get => "GET",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Post => "POST",
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

impl std::fmt::Display for PermittedResponseHeader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::fmt::Debug for HeldResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeldResponse")
            .field("status", &self.status)
            .field(
                "body",
                &format_args!("<redacted:{} bytes>", self.body.len()),
            )
            .field("headers", &self.headers.keys())
            .finish()
    }
}
