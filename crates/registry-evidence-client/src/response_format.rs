//! Explicit response-format selection for one prepared exchange.

use registry_evidence_verifier::{EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_MEDIA_TYPE};
use serde::{Deserialize, Serialize};

/// The signed Evidence response encoding one prepared request expects.
///
/// The format is closed before the request is sent and retained beside the
/// verification policy. Verification never guesses it from response bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceResponseFormat {
    /// Flattened JWS JSON carrying the Evidence payload.
    SignedJws,
    /// Compact SD-JWT VC serialization of the same Evidence payload.
    SdJwtVc,
}

impl EvidenceResponseFormat {
    pub(crate) fn media_type(self) -> &'static str {
        match self {
            Self::SignedJws => EVIDENCE_JWS_MEDIA_TYPE,
            Self::SdJwtVc => EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
        }
    }
}
