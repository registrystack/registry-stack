// SPDX-License-Identifier: Apache-2.0
//! Live supporting files are separate from the frozen attachment manifest.
use super::*;

pub(crate) struct AdditionMetadata {
    pub id: Uuid,
    pub submission_version: i64,
    pub file: AttachmentMetadata,
}

pub(crate) async fn count(
    client: &impl GenericClient,
    action: &str,
    proposal: Uuid,
    version: i64,
    slot: &str,
) -> Result<u64, MutationError> {
    let count: i64 = client.query_one(
        "SELECT count(*) FROM registry_internal.registry_proposal_additions
         WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND slot_id=$4 AND erased_at IS NULL",
        &[&action, &proposal, &version, &slot],
    ).await.map_err(unavailable)?.get(0);
    u64::try_from(count).map_err(|_| MutationError::Unavailable)
}

pub(crate) async fn prepare_put(
    client: &impl GenericClient,
    hash: &str,
    backend: &str,
    verification_policy: &str,
) -> Result<(), MutationError> {
    pin_backend(client, backend, verification_policy).await?;
    lock_hash(client, hash).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn put(
    client: &Transaction<'_>,
    action: &str,
    proposal: Uuid,
    version: i64,
    slot: &str,
    content_type: &str,
    bytes: &[u8],
    actor: &str,
    backend: &str,
    verification_policy: &str,
    maximum_count: u32,
) -> Result<Uuid, MutationError> {
    let admitted = client
        .query_opt(
            "SELECT 1 FROM registry_internal.registry_proposal_state
         WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND state='submitted'
           AND blocked_reason IS NULL AND detail_erased_at IS NULL FOR UPDATE",
            &[&action, &proposal, &version],
        )
        .await
        .map_err(unavailable)?
        .is_some();
    if !admitted {
        return Err(MutationError::PreconditionFailed);
    }
    if bytes.is_empty() || bytes.len() > crate::contract::MAX_ATTACHMENT_BYTES as usize {
        return Err(MutationError::InvalidRequest);
    }
    if count(client, action, proposal, version, slot).await? >= u64::from(maximum_count) {
        return Err(MutationError::AttachmentLimitReached);
    }
    let hash = content_hash(bytes);
    prepare_put(client, &hash, backend, verification_policy).await?;
    put_blob(
        client,
        &hash,
        content_type,
        bytes,
        backend,
        verification_policy,
    )
    .await?;
    let addition = Uuid::new_v4();
    let size = bytes.len() as i64;
    client.execute(
        "INSERT INTO registry_internal.registry_proposal_additions
         (action_id,proposal_id,submission_version,addition_id,slot_id,sha256,content_type,byte_size,added_at,added_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,transaction_timestamp(),$9)",
        &[&action, &proposal, &version, &addition, &slot, &hash, &content_type, &size, &actor],
    ).await.map_err(unavailable)?;
    Ok(addition)
}

const ADDITION_METADATA_SELECT: &str = "SELECT a.addition_id,a.submission_version,a.slot_id,
    a.content_type,a.byte_size,a.sha256,
    to_char(a.added_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),a.added_by,
    CASE WHEN COALESCE(p.verification_policy,'disabled')='disabled' THEN 'notRequired'
         ELSE COALESCE(v.verdict,'pending') END
    FROM registry_internal.registry_proposal_additions a
    LEFT JOIN registry_internal.registry_attachment_storage_binding p ON p.singleton
    LEFT JOIN registry_internal.registry_attachment_verification v
      ON v.sha256=a.sha256 AND v.policy_digest=p.verification_policy AND v.content_type=a.content_type";

pub(crate) async fn metadata(
    client: &impl GenericClient,
    action: &str,
    proposal: Uuid,
    version: i64,
    slot: &str,
) -> Result<Vec<AdditionMetadata>, MutationError> {
    let rows = client
        .query(
            &format!(
                "{ADDITION_METADATA_SELECT} WHERE a.action_id=$1 AND a.proposal_id=$2 AND a.submission_version=$3
        AND a.slot_id=$4 AND a.erased_at IS NULL ORDER BY a.added_at,a.addition_id LIMIT 33"
            ),
            &[&action, &proposal, &version, &slot],
        )
        .await
        .map_err(unavailable)?;
    if rows.len() > 32 {
        return Err(MutationError::Unavailable);
    }
    rows.into_iter()
        .map(|row| {
            Ok(AdditionMetadata {
                id: row.get(0),
                submission_version: row.get(1),
                file: AttachmentMetadata {
                    slot_id: row.get(2),
                    content_type: row.get(3),
                    byte_size: u64::try_from(row.get::<_, i64>(4))
                        .map_err(|_| MutationError::Unavailable)?,
                    sha256: row.get(5),
                    uploaded_at: row.get(6),
                    uploaded_by: row.get(7),
                    verification_status: AttachmentVerificationStatus::from_storage(
                        &row.get::<_, String>(8),
                    )?,
                },
            })
        })
        .collect()
}

pub(crate) async fn load(
    client: &impl GenericClient,
    action: &str,
    proposal: Uuid,
    version: i64,
    addition: Uuid,
    slot: &str,
) -> Result<Option<StoredAttachment>, MutationError> {
    let Some(metadata) = metadata(client, action, proposal, version, slot)
        .await?
        .into_iter()
        .find(|file| file.id == addition)
    else {
        return Ok(None);
    };
    if !metadata.file.verification_status.permits_content() {
        return Ok(None);
    }
    lock_hash(client, &metadata.file.sha256).await?;
    if !verification_status(client, &metadata.file.sha256, &metadata.file.content_type)
        .await?
        .permits_content()
    {
        return Ok(None);
    }
    let row = client
        .query_opt(
            "SELECT b.backend_id,b.content FROM registry_internal.registry_attachment_blobs b JOIN
         registry_internal.registry_proposal_additions a ON a.sha256=b.sha256
         WHERE a.action_id=$1 AND a.proposal_id=$2 AND a.submission_version=$3 AND a.addition_id=$4
           AND a.erased_at IS NULL AND a.sha256=$5 AND b.state='live'",
            &[
                &action,
                &proposal,
                &version,
                &addition,
                &metadata.file.sha256,
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(row.map(|row| StoredAttachment {
        metadata: metadata.file,
        backend_id: row.get(0),
        content: row.get(1),
    }))
}
