// SPDX-License-Identifier: Apache-2.0

//! Document content: the bounded, hashing read of an upload body, and the
//! storage the finalized bytes are held in.
//!
//! An upload body is read only up to the reserved length plus one byte and
//! hashed while it arrives, so an over-long body is cut off without being
//! read further and nothing of a refused body is kept.
//!
//! Content lives in PostgreSQL or in one S3 bucket. The storage binding a
//! deployment writes under is pinned at its first finalized version; a
//! later start under another backend, bucket, or database identity refuses
//! rather than writing content somewhere it will not be read from.

use std::sync::Arc;

use bytes::Bytes;
use futures::{Stream, StreamExt as _};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::SecretResolver;
use registry_platform_objectstore::{ObjectNamespace, ObjectStoreError, S3ObjectStore, S3Settings};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::config::StorageConfig;

/// The binding domain of content held in PostgreSQL.
const DATABASE_BINDING_DOMAIN: &str = "documents-content-database-v1";
/// The binding domain of content held in S3.
const S3_BINDING_DOMAIN: &str = "documents-content-s3-v1";
/// Every Document Store object sits under this key prefix in the bucket.
const S3_KEY_PREFIX: &str = "documents";

/// Why an upload body was not accepted as the reserved content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyRefusal {
    /// More bytes arrived than were reserved. The read stopped at the
    /// reserved length plus one byte.
    Longer,
    /// The body ended before the reserved length.
    Shorter,
    /// The body could not be read.
    Unreadable,
}

/// An upload body read in full, with its digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashedBody {
    pub bytes: Vec<u8>,
    /// The lowercase hex SHA-256 of `bytes`.
    pub sha256_hex: String,
}

impl HashedBody {
    /// The digest in the `sha256:<hex>` form a version records.
    #[must_use]
    pub fn digest(&self) -> String {
        format!("sha256:{}", self.sha256_hex)
    }
}

/// Read `stream` while hashing it, accepting exactly `declared` bytes. The
/// stream is not polled again once more than `declared` bytes have
/// arrived, so an over-long body is cut off at its reserved length plus one
/// byte, and a refused body is dropped whole.
pub async fn read_hashing<S, E>(mut stream: S, declared: u64) -> Result<HashedBody, BodyRefusal>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    let capacity = usize::try_from(declared).map_err(|_| BodyRefusal::Longer)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut hasher = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| BodyRefusal::Unreadable)?;
        if (bytes.len() as u64).saturating_add(chunk.len() as u64) > declared {
            return Err(BodyRefusal::Longer);
        }
        hasher.update(&chunk);
        bytes.extend_from_slice(&chunk);
    }
    if (bytes.len() as u64) < declared {
        return Err(BodyRefusal::Shorter);
    }
    Ok(HashedBody {
        bytes,
        sha256_hex: hex::encode(hasher.finalize()),
    })
}

/// Whether `bytes` are exactly `length` bytes whose digest is `digest`, in
/// the `sha256:<hex>` form.
#[must_use]
pub fn content_matches(bytes: &[u8], digest: &str, length: u64) -> bool {
    bytes.len() as u64 == length && registry_documents_core::sha256_digest(bytes) == digest
}

/// The hex form of a `sha256:<hex>` digest.
#[must_use]
pub fn digest_hex(digest: &str) -> Option<&str> {
    digest
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Content storage failed. No variant carries a URL, an object key, a
/// credential, or a backend response.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("the content storage binding could not be computed")]
    Binding,
    #[error("object storage refused: {0}")]
    Object(#[from] ObjectStoreError),
    #[error("the stored content does not carry this deployment's storage binding")]
    BindingMismatch,
    #[error("the content storage query failed: {0}")]
    Query(#[from] tokio_postgres::Error),
    #[error("the stored content is missing")]
    Missing,
}

/// Where this deployment holds content.
pub enum ContentStorage {
    Database {
        binding: String,
    },
    S3 {
        settings: Box<S3Settings>,
        resolver: Arc<SecretResolver>,
        database_id: String,
        ceiling: u64,
        binding: String,
    },
}

impl std::fmt::Debug for ContentStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Database { .. } => "ContentStorage::Database",
            Self::S3 { .. } => "ContentStorage::S3(<redacted>)",
        })
    }
}

impl ContentStorage {
    /// Bind the storage `config` names to the deployment `database_id`. For
    /// S3 this resolves the credentials and refuses a bucket that has ever
    /// enabled versioning, before anything is served.
    pub async fn activate(
        config: &StorageConfig,
        database_id: &str,
        resolver: Arc<SecretResolver>,
    ) -> Result<Self, StorageError> {
        match config {
            StorageConfig::Database { .. } => Ok(Self::Database {
                binding: database_binding(database_id)?,
            }),
            StorageConfig::S3 { settings, .. } => {
                let ceiling = config.maximum_document_bytes();
                let settings = S3Settings::from_config(settings)?;
                let deployment = settings
                    .activate(s3_namespace(ceiling), database_id, &resolver)
                    .await?;
                Ok(Self::S3 {
                    binding: deployment.binding_digest().to_owned(),
                    settings: Box::new(settings),
                    resolver,
                    database_id: database_id.to_owned(),
                    ceiling,
                })
            }
        }
    }

    /// The backend name a version and the storage pin record.
    #[must_use]
    pub const fn backend(&self) -> &'static str {
        match self {
            Self::Database { .. } => "database",
            Self::S3 { .. } => "s3",
        }
    }

    /// The deployment binding the storage pin holds.
    #[must_use]
    pub fn binding(&self) -> &str {
        match self {
            Self::Database { binding } | Self::S3 { binding, .. } => binding,
        }
    }

    /// The store of one object. Every object is its own scope, so its key
    /// is server-chosen and opaque, and two versions never share an object
    /// even when their content is identical.
    pub async fn object(&self, object_id: Uuid) -> Result<S3ObjectStore, StorageError> {
        match self {
            Self::Database { .. } => Err(StorageError::Binding),
            Self::S3 {
                settings,
                resolver,
                database_id,
                ceiling,
                ..
            } => Ok(settings
                .activate(
                    s3_namespace(*ceiling),
                    &format!("{database_id}/{object_id}"),
                    resolver,
                )
                .await?),
        }
    }

    /// Read the content of a finalized version and check it against its
    /// recorded digest and length before handing any of it back.
    pub async fn read<C: GenericClient>(
        &self,
        client: &C,
        version_id: Uuid,
        object_id: Option<Uuid>,
        digest: &str,
        length: u64,
    ) -> Result<Vec<u8>, StorageError> {
        let bytes = match (self, object_id) {
            (Self::Database { .. }, None) => {
                let row = client
                    .query_opt(
                        "SELECT content FROM documents_contents WHERE version_id = $1",
                        &[&version_id],
                    )
                    .await?
                    .ok_or(StorageError::Missing)?;
                row.try_get::<_, Vec<u8>>(0)?
            }
            (Self::S3 { .. }, Some(object_id)) => {
                let row = client
                    .query_opt(
                        "SELECT binding_digest FROM documents_staged_objects
                         WHERE object_id = $1 AND version_id = $2 AND committed",
                        &[&object_id, &version_id],
                    )
                    .await?
                    .ok_or(StorageError::Missing)?;
                let recorded: String = row.try_get(0)?;
                let store = self.object(object_id).await?;
                if store.binding_digest() != recorded {
                    return Err(StorageError::BindingMismatch);
                }
                let sha = digest_hex(digest).ok_or(StorageError::Binding)?;
                store.get(sha, length).await?
            }
            _ => return Err(StorageError::BindingMismatch),
        };
        if !content_matches(&bytes, digest, length) {
            return Err(StorageError::Object(ObjectStoreError::Integrity));
        }
        Ok(bytes)
    }
}

fn s3_namespace(ceiling: u64) -> ObjectNamespace {
    ObjectNamespace {
        key_prefix: S3_KEY_PREFIX,
        binding_domain: S3_BINDING_DOMAIN,
        max_object_bytes: ceiling,
    }
}

/// The binding of content held in PostgreSQL: the hex SHA-256 of the
/// canonical JSON array `[domain, databaseId]`.
fn database_binding(database_id: &str) -> Result<String, StorageError> {
    let canonical = canonicalize_json(&serde_json::json!([DATABASE_BINDING_DOMAIN, database_id]))
        .map_err(|_| StorageError::Binding)?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

/// The storage binding pinned in the database, if any.
pub async fn pinned_storage<C: GenericClient>(
    client: &C,
) -> Result<Option<(String, String)>, tokio_postgres::Error> {
    client
        .query_opt(
            "SELECT backend, binding_digest FROM documents_storage_binding",
            &[],
        )
        .await?
        .map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
        .transpose()
}

/// Pin `storage` as this deployment's binding when none is pinned, and
/// report whether the pinned binding is `storage`'s.
pub async fn pin_storage<C: GenericClient>(
    client: &C,
    storage: &ContentStorage,
) -> Result<bool, tokio_postgres::Error> {
    client
        .execute(
            "INSERT INTO documents_storage_binding (singleton, backend, binding_digest, pinned_at)
             VALUES (true, $1, $2, transaction_timestamp())
             ON CONFLICT (singleton) DO NOTHING",
            &[&storage.backend(), &storage.binding()],
        )
        .await?;
    Ok(pinned_storage(client)
        .await?
        .is_some_and(|(backend, binding)| {
            backend == storage.backend() && binding == storage.binding()
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    /// A body of one-byte chunks that counts how often it is polled.
    struct Counted {
        remaining: usize,
        polls: Arc<AtomicUsize>,
    }

    impl Stream for Counted {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            self.remaining -= 1;
            Poll::Ready(Some(Ok(Bytes::from_static(b"x"))))
        }
    }

    fn counted(length: usize) -> (Counted, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        (
            Counted {
                remaining: length,
                polls: Arc::clone(&polls),
            },
            polls,
        )
    }

    #[tokio::test]
    async fn an_exact_body_is_read_and_hashed() {
        let (stream, _) = counted(5);
        let body = read_hashing(stream, 5).await.unwrap();
        assert_eq!(body.bytes, b"xxxxx");
        assert_eq!(
            body.digest(),
            registry_documents_core::sha256_digest(b"xxxxx")
        );
    }

    /// SEC-15: an over-long body is cut off at the reserved length plus one
    /// byte; the stream is never polled past it.
    #[tokio::test]
    async fn a_body_over_the_reserved_length_is_cut_off_at_one_byte_more() {
        let (stream, polls) = counted(1_000);
        assert_eq!(read_hashing(stream, 10).await, Err(BodyRefusal::Longer));
        assert_eq!(polls.load(Ordering::SeqCst), 11);
    }

    #[tokio::test]
    async fn a_short_body_is_refused() {
        let (stream, _) = counted(3);
        assert_eq!(read_hashing(stream, 4).await, Err(BodyRefusal::Shorter));
    }

    #[tokio::test]
    async fn an_unreadable_body_is_refused() {
        let stream = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"ab")),
            Err(std::io::Error::other("reset")),
        ]);
        assert_eq!(read_hashing(stream, 4).await, Err(BodyRefusal::Unreadable));
    }

    #[test]
    fn content_is_checked_by_digest_and_length() {
        let digest = registry_documents_core::sha256_digest(b"abc");
        assert!(content_matches(b"abc", &digest, 3));
        assert!(!content_matches(b"abd", &digest, 3));
        assert!(!content_matches(b"abc", &digest, 4));
        assert_eq!(digest_hex(&digest).map(str::len), Some(64));
        assert_eq!(digest_hex("sha256:xyz"), None);
    }

    #[test]
    fn the_database_binding_follows_the_database_identity() {
        let first = database_binding("registry-documents-a").unwrap();
        assert_eq!(first, database_binding("registry-documents-a").unwrap());
        assert_ne!(first, database_binding("registry-documents-b").unwrap());
        assert_eq!(first.len(), 64);
    }
}
