// SPDX-License-Identifier: Apache-2.0
//! Tamper-evident audit chain primitives.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{AuditEnvelope, AuditError, AuditFuture, AuditRecord, AuditSink};

/// Flat JSONL envelope with tamper-evident links.
#[derive(Debug, Clone, Serialize)]
pub struct ChainedAuditEnvelope {
    pub prev_hash: Option<String>,
    pub record_hash: String,
    #[serde(flatten)]
    pub record: AuditRecord,
}

impl ChainedAuditEnvelope {
    #[must_use]
    pub fn new(record: AuditRecord, prev_hash: Option<String>) -> Self {
        let record_hash = record_hash(prev_hash.as_deref(), &record);
        Self {
            prev_hash,
            record_hash,
            record,
        }
    }

    #[must_use]
    pub fn from_envelope(envelope: AuditEnvelope, prev_hash: Option<String>) -> Self {
        Self::new(envelope.record, prev_hash)
    }

    pub fn to_jsonl(&self) -> Result<String, AuditError> {
        let mut s = serde_json::to_string(self).map_err(AuditError::Serialize)?;
        s.push('\n');
        Ok(s)
    }
}

/// Mutable per-sink chain state. Callers persist `last_hash` across
/// writes and may seed it after opening a rotated file.
#[derive(Debug, Clone, Default)]
pub struct ChainState {
    last_hash: Option<String>,
}

impl ChainState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_prev_hash(prev_hash: Option<String>) -> Self {
        Self {
            last_hash: prev_hash,
        }
    }

    #[must_use]
    pub fn last_hash(&self) -> Option<&str> {
        self.last_hash.as_deref()
    }

    #[must_use]
    pub fn wrap(&mut self, envelope: AuditEnvelope) -> ChainedAuditEnvelope {
        let chained = ChainedAuditEnvelope::from_envelope(envelope, self.last_hash.clone());
        self.last_hash = Some(chained.record_hash.clone());
        chained
    }

    #[must_use]
    pub fn wrap_envelope(&mut self, mut envelope: AuditEnvelope) -> AuditEnvelope {
        let prev_hash = self.last_hash.clone();
        let record_hash = record_hash(prev_hash.as_deref(), &envelope.record);
        envelope.prev_hash = prev_hash;
        envelope.record_hash = Some(record_hash.clone());
        self.last_hash = Some(record_hash);
        envelope
    }
}

/// Audit sink wrapper that adds `prev_hash` and `record_hash` fields
/// before delegating to the configured sink.
pub struct ChainingSink {
    inner: std::sync::Arc<dyn AuditSink>,
    state: std::sync::Mutex<ChainState>,
}

impl ChainingSink {
    #[must_use]
    pub fn new(inner: std::sync::Arc<dyn AuditSink>) -> Self {
        Self {
            inner,
            state: std::sync::Mutex::new(ChainState::new()),
        }
    }
}

impl std::fmt::Debug for ChainingSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainingSink").finish_non_exhaustive()
    }
}

impl AuditSink for ChainingSink {
    fn write<'a>(&'a self, envelope: AuditEnvelope) -> AuditFuture<'a> {
        Box::pin(async move {
            let envelope = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.wrap_envelope(envelope)
            };
            self.inner.write(envelope).await
        })
    }

    fn flush<'a>(&'a self) -> AuditFuture<'a> {
        self.inner.flush()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerification {
    pub records: usize,
    pub start_prev_hash: Option<String>,
    pub last_hash: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainVerificationError {
    #[error("audit chain line {line} is not valid JSON: {source}")]
    InvalidJson {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("audit chain line {line} must be a JSON object")]
    NotObject { line: usize },
    #[error("audit chain line {line} is missing record_hash")]
    MissingRecordHash { line: usize },
    #[error("audit chain line {line} has non-string record_hash")]
    InvalidRecordHash { line: usize },
    #[error("audit chain line {line} has non-string prev_hash")]
    InvalidPrevHash { line: usize },
    #[error("audit chain line {line} expected prev_hash {expected:?}, got {actual:?}")]
    PrevHashMismatch {
        line: usize,
        expected: Option<String>,
        actual: Option<String>,
    },
    #[error("audit chain line {line} expected record_hash {expected}, got {actual}")]
    RecordHashMismatch {
        line: usize,
        expected: String,
        actual: String,
    },
}

pub fn verify_chain_lines<I, S>(lines: I) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    verify_chain_lines_from_prev_hash(lines, None)
}

pub fn verify_chain_lines_from_prev_hash<I, S>(
    lines: I,
    expected_start_prev_hash: Option<&str>,
) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut records = 0usize;
    let mut previous_hash = expected_start_prev_hash.map(ToOwned::to_owned);
    let mut start_prev_hash = None;

    for (idx, line) in lines.into_iter().enumerate() {
        let line_no = idx + 1;
        let line = line.as_ref().trim_end();
        if line.is_empty() {
            continue;
        }
        let mut value: Value =
            serde_json::from_str(line).map_err(|source| ChainVerificationError::InvalidJson {
                line: line_no,
                source,
            })?;
        let object = value
            .as_object_mut()
            .ok_or(ChainVerificationError::NotObject { line: line_no })?;

        let actual_hash = object
            .remove("record_hash")
            .ok_or(ChainVerificationError::MissingRecordHash { line: line_no })?
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or(ChainVerificationError::InvalidRecordHash { line: line_no })?;
        let actual_prev_hash = match object.remove("prev_hash") {
            Some(Value::Null) | None => None,
            Some(Value::String(hash)) => Some(hash),
            Some(_) => return Err(ChainVerificationError::InvalidPrevHash { line: line_no }),
        };

        if records == 0 {
            start_prev_hash = actual_prev_hash.clone();
        }

        if (previous_hash.is_some() || records > 0) && actual_prev_hash != previous_hash {
            return Err(ChainVerificationError::PrevHashMismatch {
                line: line_no,
                expected: previous_hash,
                actual: actual_prev_hash,
            });
        }

        let expected_hash =
            record_hash_value(actual_prev_hash.as_deref(), &value).map_err(|source| {
                ChainVerificationError::InvalidJson {
                    line: line_no,
                    source,
                }
            })?;
        if actual_hash != expected_hash {
            return Err(ChainVerificationError::RecordHashMismatch {
                line: line_no,
                expected: expected_hash,
                actual: actual_hash,
            });
        }

        previous_hash = Some(actual_hash);
        records += 1;
    }

    Ok(ChainVerification {
        records,
        start_prev_hash,
        last_hash: previous_hash,
    })
}

#[must_use]
pub fn record_hash(prev_hash: Option<&str>, record: &AuditRecord) -> String {
    let value = serde_json::to_value(record).expect("AuditRecord serialization should not fail");
    record_hash_value(prev_hash, &value).expect("hash input serialization should not fail")
}

fn record_hash_value(prev_hash: Option<&str>, record: &Value) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct HashInput<'a> {
        prev_hash: Option<&'a str>,
        record: &'a Value,
    }

    let input = serde_json::to_vec(&HashInput { prev_hash, record })?;
    let mut hasher = Sha256::new();
    hasher.update(input);
    Ok(format!("sha256:{}", hex_lower(&hasher.finalize())))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
