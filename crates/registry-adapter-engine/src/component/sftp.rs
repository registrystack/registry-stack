// SPDX-License-Identifier: Apache-2.0

//! The engine side of the read-only `sftp` governed-ingestion source.
//!
//! The engine owns the immutable candidate and completion plan, cursor and
//! content-digest identity, shared file decoders, and the closed host seam.
//! The job host owns SSH, credentials, host-key verification, the fixed remote
//! base directory, and bounded SFTP requests. No SSH client type crosses this
//! module. The host receives no origin or path from a route, so an exchange
//! cannot redirect the connection or escape the configured directory.

use registry_adapter_core::ReadBounds;
use serde_json::{json, Value};

use crate::component::file::{cursor_parts, decode_page};
use crate::decoder::Decoder;
use crate::job_sources::{DoneFileName, FlatGlob, SourceReadPage};

/// The immutable source rules held independently by the engine and the host.
#[derive(Clone, Debug)]
pub struct SftpPlan {
    /// The namespace every decoded item key carries.
    pub namespace: String,
    /// The flat candidate-name glob, when declared.
    pub include: Option<FlatGlob>,
    /// The required completed-file convention.
    pub completion: SftpCompletion,
    /// The maximum directory entries one operation may inspect.
    pub maximum_listing_entries: u32,
}

/// Exactly one explicit completed-file convention.
#[derive(Clone, Debug)]
pub enum SftpCompletion {
    /// A candidate is ready only while its sibling done file exists. The
    /// producer protocol is cooperative: before replacing a same-name file it
    /// removes the old marker, writes under a different name, atomically
    /// renames the completed bytes into place, then publishes the marker last.
    /// This read-only consumer never removes markers. A stale marker left while
    /// a producer overwrites in place cannot be distinguished from readiness;
    /// size/mtime and marker rechecks only detect changes during this read.
    DoneFile { pattern: DoneFileName },
    /// The producer has explicitly promised an atomic rename into the final
    /// candidate name. No suffix is interpreted as readiness.
    CompletedName,
}

/// The cursor portion the host needs to skip an already consumed file without
/// returning another whole bounded allocation to the engine.
#[derive(Clone, Debug)]
pub struct SftpCursor {
    pub resume_after: String,
    pub digest: String,
    pub position: u64,
}

/// One host read. The source instance already captures the origin, base,
/// credentials, selection plan, and listing bound.
#[derive(Clone, Debug)]
pub struct SftpRead {
    pub cursor: Option<SftpCursor>,
    pub maximum_file_bytes: u64,
    /// One absolute deadline owns connect, pin verification, credential use,
    /// authentication, listing, read, and every explicit close.
    pub deadline: tokio::time::Instant,
}

/// One completed remote file streamed under the byte bound.
#[derive(Debug)]
pub struct SftpFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// The bounded result of one host operation.
#[derive(Debug)]
pub struct SftpReadResult {
    /// The first ready candidate at or after the cursor, after skipping an
    /// unchanged file the cursor already consumed.
    pub file: Option<SftpFile>,
    /// Whether another ready candidate stands after `file`.
    pub more_candidates: bool,
    /// How many listing entries the host inspected, repeated so the engine can
    /// enforce the plan across a hand-built seam.
    pub listing_entries: u32,
}

/// Why a transport read failed. Client-library errors and source values never
/// cross this boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SftpReadFault {
    Timeout,
    Connection,
    HostKey,
    Credential,
    Authentication,
    Listing,
    Traversal,
    Escape,
    NotRegular,
    Incomplete,
    TooLarge,
    Malformed,
    Close,
    Row(u64),
    KeyMissing(u64),
    KeyInvalid(u64),
    KeyDuplicate(u64),
    RowBound,
    DecoderSyntax,
}

/// The SSH/SFTP client seam the job host supplies. The engine compiles and
/// decodes; the host connects and performs read-only transport operations.
pub trait SftpSource: std::fmt::Debug + Send + Sync {
    fn read<'a>(
        &'a self,
        read: SftpRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SftpReadResult, SftpReadFault>> + Send + 'a>,
    >;
}

/// Read and decode one bounded SFTP page through the host seam.
pub(crate) async fn read_page(
    plan: &SftpPlan,
    source: &dyn SftpSource,
    bounds: &ReadBounds,
    cursor: Option<&Value>,
    decoder: &Decoder,
    deadline: tokio::time::Instant,
) -> Result<SourceReadPage, SftpReadFault> {
    let (resume_name, resume_digest, resume_position) = cursor_parts(cursor);
    let host_cursor = match (resume_name.clone(), resume_digest.clone(), resume_position) {
        (Some(resume_after), Some(digest), Some(position)) => Some(SftpCursor {
            resume_after,
            digest,
            position,
        }),
        _ => None,
    };
    let result = source
        .read(SftpRead {
            cursor: host_cursor,
            maximum_file_bytes: bounds.maximum_file_bytes,
            deadline,
        })
        .await?;
    if result.listing_entries > plan.maximum_listing_entries {
        return Err(SftpReadFault::TooLarge);
    }
    let Some(file) = result.file else {
        if result.more_candidates {
            return Err(SftpReadFault::Malformed);
        }
        return Ok(SourceReadPage {
            body: json!({ "items": [] }),
            malformed_lines: 0,
        });
    };
    validate_flat_name(&file.name)?;
    if file.bytes.len() as u64 > bounds.maximum_file_bytes {
        return Err(SftpReadFault::TooLarge);
    }
    if resume_name
        .as_deref()
        .is_some_and(|resume| file.name.as_str() < resume)
    {
        return Err(SftpReadFault::Malformed);
    }
    let digest = registry_platform_config::sha256_uri(&file.bytes);
    let length = file.bytes.len() as u64;
    let named_by_cursor = resume_name.as_deref() == Some(file.name.as_str())
        && resume_digest.as_deref() == Some(digest.as_str());
    if named_by_cursor && resume_position.is_some_and(|position| position >= length) {
        // The host was given enough cursor state to skip this completed file.
        return Err(SftpReadFault::Malformed);
    }
    let resume = if named_by_cursor {
        resume_position
            .filter(|position| *position < length)
            .unwrap_or(0)
    } else {
        0
    };
    let page = decode_page(
        decoder.clone(),
        plan.namespace.clone(),
        digest.clone(),
        file.name.clone(),
        file.bytes,
        resume,
        bounds.clone(),
    )
    .await
    .map_err(|fault| match fault {
        crate::component::file::FileReadFault::Row(index) => SftpReadFault::Row(index),
        crate::component::file::FileReadFault::KeyMissing(index) => {
            SftpReadFault::KeyMissing(index)
        }
        crate::component::file::FileReadFault::KeyInvalid(index) => {
            SftpReadFault::KeyInvalid(index)
        }
        crate::component::file::FileReadFault::KeyDuplicate(index) => {
            SftpReadFault::KeyDuplicate(index)
        }
        crate::component::file::FileReadFault::RowBound => SftpReadFault::RowBound,
        crate::component::file::FileReadFault::DecoderSyntax => SftpReadFault::DecoderSyntax,
        _ => SftpReadFault::Malformed,
    })?;
    let body = if page.complete && !result.more_candidates {
        json!({ "items": page.items })
    } else {
        json!({
            "items": page.items,
            "next": {
                "digest": digest,
                "position": if page.complete { length } else { page.position },
                "resumeAfter": file.name,
            }
        })
    };
    Ok(SourceReadPage {
        body,
        malformed_lines: page.malformed_lines,
    })
}

/// A remote filename and every cursor-carried filename are one flat UTF-8
/// component. The host applies the same check before constructing a path.
pub fn validate_flat_name(name: &str) -> Result<(), SftpReadFault> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || name.len() > 1024
    {
        return Err(SftpReadFault::Traversal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::file::decode_page;
    use crate::decoder::Decoder;
    use registry_adapter_core::CsvDecoder;

    #[derive(Debug)]
    struct OneFile {
        bytes: Vec<u8>,
    }

    impl SftpSource for OneFile {
        fn read<'a>(
            &'a self,
            _read: SftpRead,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<SftpReadResult, SftpReadFault>> + Send + 'a,
            >,
        > {
            Box::pin(async {
                Ok(SftpReadResult {
                    file: Some(SftpFile {
                        name: "people.csv".to_owned(),
                        bytes: self.bytes.clone(),
                    }),
                    more_candidates: false,
                    listing_entries: 1,
                })
            })
        }
    }

    fn bounds() -> ReadBounds {
        ReadBounds {
            maximum_file_bytes: 1024,
            maximum_row_bytes: 256,
            maximum_field_bytes: 128,
            maximum_rows_per_page: 10,
        }
    }

    #[tokio::test]
    async fn local_and_sftp_decoding_share_business_key_identity() {
        let bytes = b"id,name\n001,Alice\n".to_vec();
        let decoder = Decoder::Csv {
            options: CsvDecoder::default(),
            key_pointer: "/id".to_owned(),
        };
        let digest = registry_platform_config::sha256_uri(&bytes);
        let local = decode_page(
            decoder.clone(),
            "people".to_owned(),
            digest,
            "people.csv".to_owned(),
            bytes.clone(),
            0,
            bounds(),
        )
        .await
        .expect("the local file decoder accepts the row");
        let remote = read_page(
            &SftpPlan {
                namespace: "people".to_owned(),
                include: None,
                completion: SftpCompletion::CompletedName,
                maximum_listing_entries: 10,
            },
            &OneFile { bytes },
            &bounds(),
            None,
            &decoder,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await
        .expect("the SFTP decoder accepts the row");

        assert_eq!(
            remote.body["items"][0]["key"],
            serde_json::Value::String(local.items[0].key.clone())
        );
        assert_eq!(local.items[0].key, "file-row-v1:6:people:001");
    }
}
