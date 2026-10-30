//! Client-owned response wire models.
//!
//! Evidence runtime and verifier models remain closed because they validate
//! governed input and signed payloads. These models sit only at the HTTP client
//! boundary, where response contracts permit additive members. Callers parse
//! duplicate-safe JSON before deserializing through these tolerant shapes.

use registry_evidence_verifier::model::{
    EvidenceRequestBatchResponseType, FlattenedJws, JwksDocument,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Deserialize)]
pub(crate) struct JwksDocumentWire {
    keys: Vec<Value>,
}

impl From<JwksDocumentWire> for JwksDocument {
    fn from(document: JwksDocumentWire) -> Self {
        Self {
            keys: document.keys,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct EvidenceRequestBatchResponseWire {
    pub(crate) schema: String,
    #[serde(rename = "type")]
    pub(crate) response_type: EvidenceRequestBatchResponseType,
    pub(crate) items: Vec<EvidenceRequestBatchResponseItemWire>,
}

#[derive(Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub(crate) enum EvidenceRequestBatchResponseItemWire {
    Evidence { evidence: FlattenedJws },
    EvidenceNotAvailable {},
}
