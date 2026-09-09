// SPDX-License-Identifier: Apache-2.0

//! Request/version references are distinct from registry-scoped deduplicated bytes.
//! Callers admit the typed request row before invoking this internal store. The
//! request state lock orders draft mutations against submission and erasure; a
//! transaction advisory lock orders every blob reference against physical deletion.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;

use crate::mutation::MutationError;
use crate::postgres::SqlIdentifier;
use crate::request_workflow::AttachmentManifestEntry;

pub(crate) const ATTACHMENT_TABLES: &[(&str, &[&str])] = &[
    ("registry_attachment_storage_binding", &["INSERT", "SELECT"]),
    (
        "registry_attachment_verification",
        &["INSERT", "SELECT", "UPDATE", "DELETE"],
    ),
    (
        "registry_attachment_blobs",
        &["INSERT", "SELECT", "UPDATE", "DELETE"],
    ),
    (
        "registry_request_attachments",
        &["INSERT", "SELECT", "UPDATE", "DELETE"],
    ),
];

pub(crate) async fn install(
    client: &impl GenericClient,
    role: &SqlIdentifier,
) -> Result<(), MutationError> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS registry_internal.registry_attachment_storage_binding (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            backend_id text NOT NULL CHECK (backend_id <> ''),
            verification_policy text NOT NULL DEFAULT 'disabled' CHECK (verification_policy <> ''),
            pinned_at timestamptz NOT NULL DEFAULT transaction_timestamp()
        );
        ALTER TABLE registry_internal.registry_attachment_storage_binding
            ADD COLUMN IF NOT EXISTS verification_policy text NOT NULL DEFAULT 'disabled';
        CREATE TABLE IF NOT EXISTS registry_internal.registry_attachment_blobs (
            sha256 text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
            byte_size bigint NOT NULL CHECK (byte_size BETWEEN 0 AND 16777216),
            backend_id text NOT NULL,
            content bytea,
            state text NOT NULL CHECK (state IN ('staged','live','delete_pending','delete_confirmed')),
            deletion_checked_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            CHECK ((backend_id = 'database' AND content IS NOT NULL AND octet_length(content) = byte_size)
                OR (backend_id <> 'database' AND content IS NULL))
        );
        ALTER TABLE registry_internal.registry_attachment_blobs
            ADD COLUMN IF NOT EXISTS deletion_checked_at timestamptz;
        ALTER TABLE registry_internal.registry_attachment_blobs
            DROP CONSTRAINT IF EXISTS registry_attachment_blobs_state_check;
        ALTER TABLE registry_internal.registry_attachment_blobs
            ADD CONSTRAINT registry_attachment_blobs_state_check
            CHECK (state IN ('staged','live','delete_pending','delete_confirmed'));
        CREATE TABLE IF NOT EXISTS registry_internal.registry_attachment_verification (
            sha256 text NOT NULL REFERENCES registry_internal.registry_attachment_blobs ON DELETE CASCADE,
            policy_digest text NOT NULL CHECK (policy_digest <> 'disabled' AND policy_digest <> ''),
            content_type text NOT NULL,
            verdict text NOT NULL DEFAULT 'pending' CHECK (verdict IN ('pending','approved','rejected')),
            next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            lease_id uuid,
            lease_expires_at timestamptz,
            attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            PRIMARY KEY (sha256,policy_digest,content_type),
            CHECK ((lease_id IS NULL) = (lease_expires_at IS NULL))
        );
        CREATE INDEX IF NOT EXISTS registry_attachment_verification_pending
            ON registry_internal.registry_attachment_verification
                (policy_digest,next_attempt_at,sha256,content_type) WHERE verdict='pending';
        CREATE TABLE IF NOT EXISTS registry_internal.registry_request_attachments (
            request_entity_id text NOT NULL,
            request_id uuid NOT NULL,
            proposal_version bigint NOT NULL CHECK (proposal_version BETWEEN 1 AND 4294967295),
            slot_id text NOT NULL,
            sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
            content_type text NOT NULL,
            byte_size bigint NOT NULL CHECK (byte_size BETWEEN 0 AND 16777216),
            uploaded_at timestamptz,
            uploaded_by text,
            erased_at timestamptz,
            PRIMARY KEY (request_entity_id, request_id, proposal_version, slot_id),
            FOREIGN KEY (request_entity_id,request_id) REFERENCES registry_internal.registry_request_state,
            CHECK ((erased_at IS NULL AND uploaded_at IS NOT NULL AND uploaded_by IS NOT NULL)
                OR (erased_at IS NOT NULL AND uploaded_at IS NULL AND uploaded_by IS NULL))
        );
        CREATE INDEX IF NOT EXISTS registry_attachment_live_references
            ON registry_internal.registry_request_attachments (sha256) WHERE erased_at IS NULL;"
    ).await.map_err(unavailable)?;
    for (table, grants) in ATTACHMENT_TABLES {
        // The SQL role is trusted engine code. RLS requires an admitted runtime
        // transaction, while current request-row authority is checked by callers.
        // The owning migration role retains its explicit maintenance boundary.
        client.batch_execute(&format!(
            "REVOKE ALL ON registry_internal.{table} FROM PUBLIC, {role};
             GRANT {} ON registry_internal.{table} TO {role};
             ALTER TABLE registry_internal.{table} ENABLE ROW LEVEL SECURITY;
             ALTER TABLE registry_internal.{table} FORCE ROW LEVEL SECURITY;
             DROP POLICY IF EXISTS attachment_runtime ON registry_internal.{table};
             CREATE POLICY attachment_runtime ON registry_internal.{table} TO {role}
             USING (NULLIF(current_setting('registry.active_package_revision',true),'') IS NOT NULL
                    AND NULLIF(current_setting('registry.principal',true),'') IS NOT NULL)
             WITH CHECK (NULLIF(current_setting('registry.active_package_revision',true),'') IS NOT NULL
                    AND NULLIF(current_setting('registry.principal',true),'') IS NOT NULL);
             DROP POLICY IF EXISTS attachment_operator ON registry_internal.{table};
             CREATE POLICY attachment_operator ON registry_internal.{table}
             USING (current_user = (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'registry_internal.{table}'::regclass))
             WITH CHECK (current_user = (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'registry_internal.{table}'::regclass));",
            grants.join(", "), role=role.quoted()
        )).await.map_err(unavailable)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttachmentMetadata {
    pub slot_id: String,
    pub content_type: String,
    pub byte_size: u64,
    pub sha256: String,
    pub uploaded_at: String,
    pub uploaded_by: String,
    pub verification_status: AttachmentVerificationStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AttachmentVerificationStatus {
    NotRequired,
    Pending,
    Approved,
    Rejected,
}
impl AttachmentVerificationStatus {
    pub(crate) fn permits_content(self) -> bool {
        matches!(self, Self::NotRequired | Self::Approved)
    }
    fn from_storage(value: &str) -> Result<Self, MutationError> {
        match value {
            "notRequired" => Ok(Self::NotRequired),
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            _ => Err(MutationError::Unavailable),
        }
    }
}
const METADATA_SELECT:&str = "SELECT a.slot_id,a.content_type,a.byte_size,a.sha256,
    to_char(a.uploaded_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),a.uploaded_by,
    CASE WHEN COALESCE(p.verification_policy,'disabled')='disabled' THEN 'notRequired'
         ELSE COALESCE(v.verdict,'pending') END
    FROM registry_internal.registry_request_attachments a
    LEFT JOIN registry_internal.registry_attachment_storage_binding p ON p.singleton
    LEFT JOIN registry_internal.registry_attachment_verification v
      ON v.sha256=a.sha256 AND v.policy_digest=p.verification_policy AND v.content_type=a.content_type";
fn metadata_row(row: tokio_postgres::Row) -> Result<AttachmentMetadata, MutationError> {
    Ok(AttachmentMetadata {
        slot_id: row.get(0),
        content_type: row.get(1),
        byte_size: u64::try_from(row.get::<_, i64>(2)).map_err(|_| MutationError::Unavailable)?,
        sha256: row.get(3),
        uploaded_at: row.get(4),
        uploaded_by: row.get(5),
        verification_status: AttachmentVerificationStatus::from_storage(&row.get::<_, String>(6))?,
    })
}

#[derive(Clone)]
pub(crate) struct StoredAttachment {
    pub metadata: AttachmentMetadata,
    pub backend_id: String,
    pub content: Option<Vec<u8>>,
}

pub(crate) fn content_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Acquire before any external PUT/GET/DELETE. The lock lasts until transaction
/// completion and must also cover creation/removal of every live reference.
pub(crate) async fn lock_hash(
    client: &impl GenericClient,
    hash: &str,
) -> Result<(), MutationError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(MutationError::InvalidRequest);
    }
    client
        .execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 960))",
            &[&hash],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn require_draft(
    client: &impl GenericClient,
    entity: &str,
    id: Uuid,
    version: i64,
) -> Result<(), MutationError> {
    let row=client.query_opt("SELECT state,proposal_version,detail_erased_at IS NULL FROM
             registry_internal.registry_request_state WHERE request_entity_id=$1 AND request_id=$2 FOR
             UPDATE", &[&entity,&id]).await.map_err(unavailable)?.ok_or(MutationError::PreconditionFailed)?;
    if row.get::<_, String>(0) != "draft"
        || row.get::<_, i64>(1) != version
        || !row.get::<_, bool>(2)
    {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

/// Call in a separately committed admitted transaction before an external PUT.
/// An interrupted upload leaves a durable staged row for operator cleanup.
pub(crate) async fn stage_external(
    client: &impl GenericClient,
    hash: &str,
    byte_size: u64,
    backend_id: &str,
    verification_policy: &str,
) -> Result<(), MutationError> {
    if backend_id == "database" || byte_size > 16777216 {
        return Err(MutationError::InvalidRequest);
    }
    pin_backend(client, backend_id, verification_policy).await?;
    lock_hash(client, hash).await?;
    let size = i64::try_from(byte_size).map_err(|_| MutationError::InvalidRequest)?;
    client
        .execute(
            "INSERT INTO registry_internal.registry_attachment_blobs
             (sha256,byte_size,backend_id,state) VALUES ($1,$2,$3,'staged') ON CONFLICT DO NOTHING",
            &[&hash, &size, &backend_id],
        )
        .await
        .map_err(unavailable)?;
    require_backend(client, hash, backend_id, byte_size).await?;
    // A durable staging commit precedes every external write, including reuse
    // after a previously confirmed deletion. Keep live shared blobs live.
    client
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET state='staged',
             created_at=transaction_timestamp(), deletion_checked_at=NULL
         WHERE sha256=$1 AND state <> 'live'",
            &[&hash],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

pub(crate) async fn require_backend(
    client: &impl GenericClient,
    hash: &str,
    backend: &str,
    size: u64,
) -> Result<(), MutationError> {
    let row=client.query_one("SELECT backend_id,byte_size FROM registry_internal.registry_attachment_blobs WHERE sha256=$1", &[&hash]).await.map_err(unavailable)?;
    if row.get::<_, String>(0) != backend || row.get::<_, i64>(1) != size as i64 {
        return Err(MutationError::Conflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn put(
    client: &Transaction<'_>,
    entity: &str,
    id: Uuid,
    version: i64,
    slot: &str,
    content_type: &str,
    bytes: &[u8],
    actor: &str,
    backend: &str,
    verification_policy: &str,
) -> Result<AttachmentMetadata, MutationError> {
    require_draft(client, entity, id, version).await?;
    if bytes.len() > 16777216 {
        return Err(MutationError::InvalidRequest);
    }
    pin_backend(client, backend, verification_policy).await?;
    let hash = content_hash(bytes);
    // Sorted locks avoid deadlocks when two requests swap their prior hashes.
    let old = client
        .query_opt(
            "SELECT sha256 FROM registry_internal.registry_request_attachments WHERE
             request_entity_id=$1 AND request_id=$2 AND proposal_version=$3 AND slot_id=$4 AND
             erased_at IS NULL",
            &[&entity, &id, &version, &slot],
        )
        .await
        .map_err(unavailable)?
        .map(|r| r.get::<_, String>(0));
    let mut hashes = vec![hash.clone()];
    if let Some(old) = &old {
        hashes.push(old.clone());
    }
    hashes.sort();
    hashes.dedup();
    for h in hashes {
        lock_hash(client, &h).await?;
    }
    let size = bytes.len() as i64;
    if backend == "database" {
        client
            .execute(
                "INSERT INTO registry_internal.registry_attachment_blobs
             (sha256,byte_size,backend_id,content,state) VALUES ($1,$2,'database',$3,'live') ON
             CONFLICT DO NOTHING",
                &[&hash, &size, &bytes],
            )
            .await
            .map_err(unavailable)?;
    }
    require_backend(client, &hash, backend, bytes.len() as u64).await?;
    if backend == "database" {
        let intact: bool = client.query_one(
            "SELECT content=$2 FROM registry_internal.registry_attachment_blobs WHERE sha256=$1",
            &[&hash,&bytes],
        ).await.map_err(unavailable)?.get(0);
        if !intact {
            return Err(MutationError::Unavailable);
        }
    }

    client
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET state='live', deletion_checked_at=NULL WHERE sha256=$1",
            &[&hash],
        )
        .await
        .map_err(unavailable)?;
    if verification_policy != "disabled" {
        client
            .execute(
                "INSERT INTO registry_internal.registry_attachment_verification
             (sha256,policy_digest,content_type) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&hash, &verification_policy, &content_type],
            )
            .await
            .map_err(unavailable)?;
    }
    let row=client.query_one("INSERT INTO registry_internal.registry_request_attachments
             (request_entity_id,request_id,proposal_version,slot_id,sha256,content_type,byte_size,uploaded_at,uploaded_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,transaction_timestamp(),$8) ON CONFLICT
             (request_entity_id,request_id,proposal_version,slot_id) DO UPDATE SET
             sha256=EXCLUDED.sha256,content_type=EXCLUDED.content_type,byte_size=EXCLUDED.byte_size,uploaded_at=EXCLUDED.uploaded_at,uploaded_by=EXCLUDED.uploaded_by
             WHERE registry_request_attachments.erased_at IS NULL RETURNING to_char(uploaded_at AT TIME
             ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')", &[&entity,&id,&version,&slot,&hash,&content_type,&size,&actor]).await.map_err(unavailable)?;
    if let Some(old) = old {
        retire_unreferenced(client, &old).await?;
    }
    let verification_status = verification_status(client, &hash, content_type).await?;
    Ok(AttachmentMetadata {
        verification_status,
        slot_id: slot.to_owned(),
        content_type: content_type.to_owned(),
        byte_size: bytes.len() as u64,
        sha256: hash,
        uploaded_at: row.get(0),
        uploaded_by: actor.to_owned(),
    })
}

pub(crate) async fn remove(
    client: &Transaction<'_>,
    entity: &str,
    id: Uuid,
    version: i64,
    slot: &str,
) -> Result<(), MutationError> {
    require_draft(client, entity, id, version).await?;
    let row = client
        .query_opt(
            "SELECT sha256 FROM registry_internal.registry_request_attachments WHERE
             request_entity_id=$1 AND request_id=$2 AND proposal_version=$3 AND slot_id=$4 AND
             erased_at IS NULL",
            &[&entity, &id, &version, &slot],
        )
        .await
        .map_err(unavailable)?;
    if let Some(row) = row {
        let hash: String = row.get(0);
        lock_hash(client, &hash).await?;
        client.execute("DELETE FROM registry_internal.registry_request_attachments WHERE request_entity_id=$1 AND
             request_id=$2 AND proposal_version=$3 AND slot_id=$4", &[&entity,&id,&version,&slot]).await.map_err(unavailable)?;
        retire_unreferenced(client, &hash).await?;
    }
    Ok(())
}

async fn retire_unreferenced(client: &impl GenericClient, hash: &str) -> Result<(), MutationError> {
    client
        .execute(
            "DELETE FROM registry_internal.registry_attachment_verification v WHERE sha256=$1
         AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_request_attachments a
             WHERE a.sha256=v.sha256 AND a.content_type=v.content_type AND a.erased_at IS NULL)",
            &[&hash],
        )
        .await
        .map_err(unavailable)?;
    client.execute("UPDATE registry_internal.registry_attachment_blobs b SET state='delete_pending', deletion_checked_at=NULL WHERE
             sha256=$1 AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_request_attachments a
             WHERE a.sha256=b.sha256 AND a.erased_at IS NULL)", &[&hash]).await.map_err(unavailable)?;
    client
        .execute(
            "DELETE FROM registry_internal.registry_attachment_blobs WHERE sha256=$1 AND
             backend_id='database' AND state='delete_pending'",
            &[&hash],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

pub(crate) async fn metadata(
    client: &impl GenericClient,
    entity: &str,
    id: Uuid,
    version: i64,
) -> Result<BTreeMap<String, AttachmentMetadata>, MutationError> {
    let sql = format!(
        "{METADATA_SELECT} WHERE a.request_entity_id=$1 AND a.request_id=$2
        AND a.proposal_version=$3 AND a.erased_at IS NULL ORDER BY a.slot_id LIMIT 9"
    );
    let rows = client
        .query(&sql, &[&entity, &id, &version])
        .await
        .map_err(unavailable)?;
    if rows.len() > crate::contract::MAX_ATTACHMENT_SLOTS {
        return Err(MutationError::Unavailable);
    }
    rows.into_iter()
        .map(|row| {
            let metadata = metadata_row(row)?;
            Ok((metadata.slot_id.clone(), metadata))
        })
        .collect()
}

pub(crate) async fn load(
    client: &impl GenericClient,
    entity: &str,
    id: Uuid,
    version: i64,
    slot: &str,
) -> Result<Option<StoredAttachment>, MutationError> {
    let sql = format!(
        "{METADATA_SELECT} WHERE a.request_entity_id=$1 AND a.request_id=$2
        AND a.proposal_version=$3 AND a.slot_id=$4 AND a.erased_at IS NULL"
    );
    let Some(row) = client
        .query_opt(&sql, &[&entity, &id, &version, &slot])
        .await
        .map_err(unavailable)?
    else {
        return Ok(None);
    };
    let metadata = metadata_row(row)?;
    if !metadata.verification_status.permits_content() {
        return Ok(None);
    }
    lock_hash(client, &metadata.sha256).await?;
    if !verification_status(client, &metadata.sha256, &metadata.content_type)
        .await?
        .permits_content()
    {
        return Ok(None);
    }
    // Recheck reference after acquiring the deletion lock.
    let row=client.query_opt("SELECT b.backend_id,b.content FROM registry_internal.registry_attachment_blobs b JOIN
             registry_internal.registry_request_attachments a ON a.sha256=b.sha256 WHERE
             a.request_entity_id=$1 AND a.request_id=$2 AND a.proposal_version=$3 AND a.slot_id=$4 AND
             a.erased_at IS NULL AND a.sha256=$5 AND b.state='live'", &[&entity,&id,&version,&slot,&metadata.sha256]).await.map_err(unavailable)?;
    Ok(row.map(|r| StoredAttachment {
        metadata,
        backend_id: r.get(0),
        content: r.get(1),
    }))
}

pub(crate) async fn manifest(
    client: &impl GenericClient,
    entity: &str,
    id: Uuid,
    version: i64,
) -> Result<BTreeMap<String, AttachmentManifestEntry>, MutationError> {
    let policy = persisted_verification_policy(client).await?;
    metadata(client, entity, id, version)
        .await?
        .into_iter()
        .map(|(slot, metadata)| {
            if !metadata.verification_status.permits_content() {
                return Err(MutationError::PreconditionFailed);
            }
            Ok((
                slot,
                AttachmentManifestEntry {
                    sha256: metadata.sha256,
                    content_type: metadata.content_type,
                    byte_size: metadata.byte_size,
                    verification_policy: (policy != "disabled").then(|| policy.clone()),
                },
            ))
        })
        .collect()
}

pub(crate) async fn carry_forward(
    client: &impl GenericClient,
    entity: &str,
    id: Uuid,
    from: i64,
    to: i64,
) -> Result<(), MutationError> {
    // The request state is held FOR UPDATE throughout lifecycle transition.
    let hashes=client.query("SELECT DISTINCT sha256 FROM registry_internal.registry_request_attachments WHERE
             request_entity_id=$1 AND request_id=$2 AND proposal_version=$3 AND erased_at IS NULL ORDER
             BY sha256", &[&entity,&id,&from]).await.map_err(unavailable)?;
    for row in hashes {
        lock_hash(client, &row.get::<_, String>(0)).await?;
    }
    client.execute("INSERT INTO registry_internal.registry_request_attachments
             (request_entity_id,request_id,proposal_version,slot_id,sha256,content_type,byte_size,uploaded_at,uploaded_by)
             SELECT
             request_entity_id,request_id,$4,slot_id,sha256,content_type,byte_size,uploaded_at,uploaded_by
             FROM registry_internal.registry_request_attachments WHERE request_entity_id=$1 AND
             request_id=$2 AND proposal_version=$3 AND erased_at IS NULL", &[&entity,&id,&from,&to]).await.map_err(unavailable)?;
    Ok(())
}

pub(crate) async fn erase(
    client: &impl GenericClient,
    entity: &str,
    id: Uuid,
    version: i64,
) -> Result<u64, MutationError> {
    let hashes=client.query("SELECT DISTINCT sha256 FROM registry_internal.registry_request_attachments WHERE
             request_entity_id=$1 AND request_id=$2 AND proposal_version=$3 AND erased_at IS NULL ORDER
             BY sha256", &[&entity,&id,&version]).await.map_err(unavailable)?;
    for row in &hashes {
        lock_hash(client, &row.get::<_, String>(0)).await?;
    }
    let count = client
        .execute(
            "UPDATE registry_internal.registry_request_attachments SET
             uploaded_by=NULL,uploaded_at=NULL,erased_at=transaction_timestamp() WHERE
             request_entity_id=$1 AND request_id=$2 AND proposal_version=$3 AND erased_at IS NULL",
            &[&entity, &id, &version],
        )
        .await
        .map_err(unavailable)?;
    for row in hashes {
        retire_unreferenced(client, &row.get::<_, String>(0)).await?;
    }
    Ok(count)
}

fn unavailable(_: tokio_postgres::Error) -> MutationError {
    MutationError::Unavailable
}

/// Only selected fields are queried, including after operator erasure. Erased
/// values carry no uploader identity or timestamp and never confer byte access.
pub(crate) async fn metadata_for_read(
    client: &impl GenericClient,
    entity: &str,
    id: Uuid,
    version: i64,
    selected_slots: &std::collections::BTreeSet<String>,
) -> Result<BTreeMap<String, serde_json::Value>, MutationError> {
    let slots: Vec<&str> = selected_slots.iter().map(String::as_str).collect();
    let rows=client.query(
        "SELECT a.slot_id,a.sha256,a.byte_size,a.erased_at IS NOT NULL,a.content_type,
         to_char(a.uploaded_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),a.uploaded_by,
         CASE WHEN COALESCE(p.verification_policy,'disabled')='disabled' THEN 'notRequired'
              ELSE COALESCE(v.verdict,'pending') END
         FROM registry_internal.registry_request_attachments a
         LEFT JOIN registry_internal.registry_attachment_storage_binding p ON p.singleton
         LEFT JOIN registry_internal.registry_attachment_verification v
           ON v.sha256=a.sha256 AND v.policy_digest=p.verification_policy AND v.content_type=a.content_type
         WHERE a.request_entity_id=$1 AND a.request_id=$2 AND a.proposal_version=$3
           AND a.slot_id=ANY($4) ORDER BY a.slot_id LIMIT 9", &[&entity,&id,&version,&slots]
    ).await.map_err(unavailable)?;
    if rows.len() > crate::contract::MAX_ATTACHMENT_SLOTS {
        return Err(MutationError::Unavailable);
    }
    Ok(rows.into_iter().map(|row| {
        let slot:String=row.get(0);let erased:bool=row.get(3);
        let mut value=serde_json::json!({"slotId":slot,"proposalVersion":version,"sha256":row.get::<_,String>(1),"byteSize":row.get::<_,i64>(2),"filled":true,"erased":erased});
        if !erased {
            value["contentType"]=serde_json::json!(row.get::<_,String>(4));
            value["uploadedAt"]=serde_json::json!(row.get::<_,Option<String>>(5));
            value["uploadedBy"]=serde_json::json!(row.get::<_,Option<String>>(6));
            value["verificationStatus"]=serde_json::json!(row.get::<_,String>(7));
        }
        (slot,value)
    }).collect())
}

/// Locks replacement hashes in canonical order before an external storage call.
pub(crate) async fn lock_for_put(
    client: &impl GenericClient,
    entity: &str,
    id: Uuid,
    version: i64,
    slot: &str,
    hash: &str,
) -> Result<(), MutationError> {
    let old = client
        .query_opt(
            "SELECT sha256 FROM registry_internal.registry_request_attachments WHERE
             request_entity_id=$1 AND request_id=$2 AND proposal_version=$3 AND slot_id=$4 AND
             erased_at IS NULL",
            &[&entity, &id, &version, &slot],
        )
        .await
        .map_err(unavailable)?
        .map(|r| r.get::<_, String>(0));
    let mut hashes = vec![hash.to_owned()];
    if let Some(old) = old {
        hashes.push(old);
    }
    hashes.sort();
    hashes.dedup();
    for hash in hashes {
        lock_hash(client, &hash).await?;
    }
    Ok(())
}

/// Remember confirmed absence indefinitely. A canceled remote PUT can finish
/// after its client transaction disappears, so DELETE/GET404 does not justify
/// forgetting this key. Operator cleanup rechecks tombstones until safe reuse.
pub(crate) async fn finish_external_delete(
    client: &impl GenericClient,
    hash: &str,
    backend: &str,
) -> Result<(), MutationError> {
    client
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs b
         SET state='delete_confirmed', deletion_checked_at=transaction_timestamp()
         WHERE sha256=$1 AND backend_id=$2
           AND state IN ('staged','delete_pending','delete_confirmed')
           AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_request_attachments a
               WHERE a.sha256=b.sha256 AND a.erased_at IS NULL)",
            &[&hash, &backend],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

/// Failed rechecks revoke the previous absence observation and remain retryable.
pub(crate) async fn fail_external_delete(
    client: &impl GenericClient,
    hash: &str,
    backend: &str,
) -> Result<(), MutationError> {
    client
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs b
         SET state='delete_pending', deletion_checked_at=transaction_timestamp()
         WHERE sha256=$1 AND backend_id=$2
           AND state IN ('staged','delete_pending','delete_confirmed')
           AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_request_attachments a
               WHERE a.sha256=b.sha256 AND a.erased_at IS NULL)",
            &[&hash, &backend],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

/// An insert on the singleton serializes first writes from runtimes that both
/// started against an empty database with different operator configurations.
/// Acquire this before hash locks. The pin is deliberately never erased with
/// request content: future writes must retain the same registry storage scope.
async fn pin_backend(
    client: &impl GenericClient,
    backend: &str,
    verification_policy: &str,
) -> Result<(), MutationError> {
    if backend.is_empty()
        || backend.len() > 1024
        || verification_policy.is_empty()
        || verification_policy.len() > 1024
    {
        return Err(MutationError::InvalidRequest);
    }
    client.execute(
        "INSERT INTO registry_internal.registry_attachment_storage_binding (singleton,backend_id,verification_policy)
         VALUES (true,$1,$2) ON CONFLICT (singleton) DO NOTHING", &[&backend,&verification_policy]
    ).await.map_err(unavailable)?;
    verify_backend_binding(client, backend, verification_policy).await
}

/// Changing a pinned backend, or one with bytes or cleanup knowledge, would
/// strand retained content or permit active runtimes to mix storage scopes.
/// This metadata-only check follows verified startup admission
/// or the existing migration-role operator boundary.
pub(crate) async fn verify_backend_binding(
    client: &impl GenericClient,
    backend: &str,
    verification_policy: &str,
) -> Result<(), MutationError> {
    let mismatch = client
        .query_opt(
            "SELECT 1 FROM registry_internal.registry_attachment_storage_binding WHERE backend_id <> $1 OR verification_policy <> $2
         UNION ALL SELECT 1 FROM registry_internal.registry_attachment_blobs
         WHERE backend_id <> $1 LIMIT 1",
            &[&backend,&verification_policy],
        )
        .await
        .map_err(unavailable)?
        .is_some();
    if mismatch {
        return Err(MutationError::Conflict);
    }
    Ok(())
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub mod test_support {
    use crate::mutation::MutationError;
    use tokio_postgres::GenericClient;
    pub async fn stage(
        client: &impl GenericClient,
        hash: &str,
        size: u64,
        backend: &str,
    ) -> Result<(), MutationError> {
        super::stage_external(client, hash, size, backend, "disabled").await
    }
    pub async fn confirm_delete(
        client: &impl GenericClient,
        hash: &str,
        backend: &str,
    ) -> Result<(), MutationError> {
        super::finish_external_delete(client, hash, backend).await
    }
    pub async fn fail_delete(
        client: &impl GenericClient,
        hash: &str,
        backend: &str,
    ) -> Result<(), MutationError> {
        super::fail_external_delete(client, hash, backend).await
    }
    pub async fn verify_binding(
        client: &impl GenericClient,
        backend: &str,
    ) -> Result<(), MutationError> {
        super::verify_backend_binding(client, backend, "disabled").await
    }
    pub async fn put_external(
        client: &tokio_postgres::Transaction<'_>,
        entity: &str,
        id: uuid::Uuid,
        backend: &str,
    ) -> Result<(), MutationError> {
        super::put(
            client,
            entity,
            id,
            1,
            "evidence",
            "application/pdf",
            b"abc",
            "uploader",
            backend,
            "disabled",
        )
        .await
        .map(|_| ())
    }
    #[derive(Clone)]
    pub struct VerificationLease(super::VerificationJob);
    impl VerificationLease {
        pub fn content_type(&self) -> &str {
            &self.0.content_type
        }
        pub fn lease_id(&self) -> uuid::Uuid {
            self.0.lease_id
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn put_verified(
        client: &tokio_postgres::Transaction<'_>,
        entity: &str,
        id: uuid::Uuid,
        slot: &str,
        mime: &str,
        bytes: &[u8],
        policy: &str,
    ) -> Result<(), MutationError> {
        super::put(
            client, entity, id, 1, slot, mime, bytes, "uploader", "database", policy,
        )
        .await
        .map(|_| ())
    }
    pub async fn claim(
        client: &tokio_postgres::Transaction<'_>,
        policy: &str,
    ) -> Result<Option<VerificationLease>, MutationError> {
        super::claim_verification(client, policy)
            .await
            .map(|job| job.map(VerificationLease))
    }
    pub async fn finish(
        client: &tokio_postgres::Transaction<'_>,
        job: &VerificationLease,
        approved: bool,
    ) -> Result<bool, MutationError> {
        super::finish_verification(client, &job.0, approved).await
    }
    pub async fn retry(
        client: &tokio_postgres::Transaction<'_>,
        job: &VerificationLease,
    ) -> Result<bool, MutationError> {
        super::retry_verification(client, &job.0).await
    }
    pub async fn verification_content(
        client: &tokio_postgres::Transaction<'_>,
        job: &VerificationLease,
    ) -> Result<Option<Vec<u8>>, MutationError> {
        super::load_verification_content(client, &job.0).await
    }
    pub async fn content_available(
        client: &tokio_postgres::Transaction<'_>,
        entity: &str,
        id: uuid::Uuid,
        slot: &str,
    ) -> Result<bool, MutationError> {
        super::load(client, entity, id, 1, slot)
            .await
            .map(|content| content.is_some())
    }
    pub async fn manifest(
        client: &tokio_postgres::Transaction<'_>,
        entity: &str,
        id: uuid::Uuid,
    ) -> Result<serde_json::Value, MutationError> {
        serde_json::to_value(super::manifest(client, entity, id, 1).await?)
            .map_err(|_| MutationError::Unavailable)
    }
    pub async fn metadata(
        client: &impl GenericClient,
        entity: &str,
        id: uuid::Uuid,
    ) -> Result<std::collections::BTreeMap<String, serde_json::Value>, MutationError> {
        super::metadata_for_read(
            client,
            entity,
            id,
            1,
            &std::collections::BTreeSet::from(["evidence".to_owned(), "alternate".to_owned()]),
        )
        .await
    }
    pub async fn verify_policy_binding(
        client: &impl GenericClient,
        backend: &str,
        policy: &str,
    ) -> Result<(), MutationError> {
        super::verify_backend_binding(client, backend, policy).await
    }
}

pub(crate) async fn persisted_verification_policy(
    client: &impl GenericClient,
) -> Result<String, MutationError> {
    Ok(client.query_opt("SELECT verification_policy FROM registry_internal.registry_attachment_storage_binding WHERE singleton", &[])
        .await.map_err(unavailable)?.map_or_else(||"disabled".to_owned(),|row|row.get(0)))
}

async fn verification_status(
    client: &impl GenericClient,
    hash: &str,
    content_type: &str,
) -> Result<AttachmentVerificationStatus, MutationError> {
    let policy = persisted_verification_policy(client).await?;
    if policy == "disabled" {
        return Ok(AttachmentVerificationStatus::NotRequired);
    }
    let verdict = client
        .query_opt(
            "SELECT verdict FROM registry_internal.registry_attachment_verification
         WHERE sha256=$1 AND policy_digest=$2 AND content_type=$3",
            &[&hash, &policy, &content_type],
        )
        .await
        .map_err(unavailable)?
        .map_or_else(|| "pending".to_owned(), |row| row.get::<_, String>(0));
    AttachmentVerificationStatus::from_storage(&verdict)
}

/// Metadata-only lease. Workers audit the attempt before loading any bytes.
#[derive(Clone, Debug)]
pub(crate) struct VerificationJob {
    pub sha256: String,
    pub content_type: String,
    pub byte_size: u64,
    pub backend_id: String,
    pub lease_id: Uuid,
    policy_digest: String,
}

pub(crate) async fn claim_verification(
    transaction: &Transaction<'_>,
    policy: &str,
) -> Result<Option<VerificationJob>, MutationError> {
    if policy == "disabled" || persisted_verification_policy(transaction).await? != policy {
        return Ok(None);
    }
    let candidate = transaction
        .query_opt(
            "SELECT v.sha256,v.content_type,b.byte_size,b.backend_id
         FROM registry_internal.registry_attachment_verification v
         JOIN registry_internal.registry_attachment_blobs b ON b.sha256=v.sha256
         WHERE v.policy_digest=$1 AND v.verdict='pending' AND b.state='live'
           AND v.next_attempt_at<=transaction_timestamp()
           AND (v.lease_expires_at IS NULL OR v.lease_expires_at<=transaction_timestamp())
           AND EXISTS (SELECT 1 FROM registry_internal.registry_request_attachments a
               WHERE a.sha256=v.sha256 AND a.content_type=v.content_type AND a.erased_at IS NULL)
         ORDER BY v.next_attempt_at,v.sha256,v.content_type LIMIT 1 FOR UPDATE OF v SKIP LOCKED",
            &[&policy],
        )
        .await
        .map_err(unavailable)?;
    let Some(row) = candidate else {
        return Ok(None);
    };
    let sha256: String = row.get(0);
    let content_type: String = row.get(1);
    let lease_id = Uuid::new_v4();
    transaction.execute(
        "UPDATE registry_internal.registry_attachment_verification
         SET lease_id=$4,lease_expires_at=transaction_timestamp()+interval '240 seconds',attempts=attempts+1
         WHERE sha256=$1 AND policy_digest=$2 AND content_type=$3",
        &[&sha256,&policy,&content_type,&lease_id],
    ).await.map_err(unavailable)?;
    Ok(Some(VerificationJob {
        sha256,
        content_type,
        byte_size: u64::try_from(row.get::<_, i64>(2)).map_err(|_| MutationError::Unavailable)?,
        backend_id: row.get(3),
        lease_id,
        policy_digest: policy.to_owned(),
    }))
}

/// A missing or retired lease refuses byte loading. External storage returns
/// None only for a still-live lease whose bytes reside in the pinned backend.
pub(crate) async fn load_verification_content(
    transaction: &Transaction<'_>,
    job: &VerificationJob,
) -> Result<Option<Vec<u8>>, MutationError> {
    lock_hash(transaction, &job.sha256).await?;
    let row = transaction
        .query_opt(
            "SELECT b.content FROM registry_internal.registry_attachment_verification v
         JOIN registry_internal.registry_attachment_blobs b ON b.sha256=v.sha256
         WHERE v.sha256=$1 AND v.policy_digest=$2 AND v.content_type=$3
           AND v.lease_id=$4 AND v.verdict='pending' AND v.lease_expires_at>transaction_timestamp()
           AND b.state='live' AND b.backend_id=$5 AND b.byte_size=$6
           AND EXISTS (SELECT 1 FROM registry_internal.registry_request_attachments a
               WHERE a.sha256=v.sha256 AND a.content_type=v.content_type AND a.erased_at IS NULL)",
            &[
                &job.sha256,
                &job.policy_digest,
                &job.content_type,
                &job.lease_id,
                &job.backend_id,
                &(job.byte_size as i64),
            ],
        )
        .await
        .map_err(unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    Ok(row.get(0))
}

/// Lease comparison makes delayed completion after erasure or reclaim inert.
pub(crate) async fn finish_verification(
    transaction: &Transaction<'_>,
    job: &VerificationJob,
    approved: bool,
) -> Result<bool, MutationError> {
    let verdict = if approved { "approved" } else { "rejected" };
    let count = transaction
        .execute(
            "UPDATE registry_internal.registry_attachment_verification
         SET verdict=$5,lease_id=NULL,lease_expires_at=NULL
         WHERE sha256=$1 AND policy_digest=$2 AND content_type=$3 AND lease_id=$4
           AND verdict='pending' AND lease_expires_at>transaction_timestamp()",
            &[
                &job.sha256,
                &job.policy_digest,
                &job.content_type,
                &job.lease_id,
                &verdict,
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(count == 1)
}

pub(crate) async fn retry_verification(
    transaction: &Transaction<'_>,
    job: &VerificationJob,
) -> Result<bool, MutationError> {
    let count=transaction.execute(
        "UPDATE registry_internal.registry_attachment_verification
         SET next_attempt_at=transaction_timestamp()+interval '30 seconds',lease_id=NULL,lease_expires_at=NULL
         WHERE sha256=$1 AND policy_digest=$2 AND content_type=$3 AND lease_id=$4 AND verdict='pending'",
        &[&job.sha256,&job.policy_digest,&job.content_type,&job.lease_id]
    ).await.map_err(unavailable)?;
    Ok(count == 1)
}
