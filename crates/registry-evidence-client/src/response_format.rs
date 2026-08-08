//! Explicit response-format selection for one prepared exchange.

use registry_evidence_verifier::{EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_MEDIA_TYPE};
use serde::{Deserialize, Serialize};

use crate::batch::EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE;

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
    /// One issuance envelope carrying a credential per holder key the request
    /// presented, read by [`SdJwtVcBatchResponse`](crate::SdJwtVcBatchResponse).
    ///
    /// This is a request the caller states, exactly as the two singular formats
    /// are. Nothing infers it: a request gets a batch because its author asked
    /// for one, never because it happened to carry several holder keys.
    ///
    /// It is also the one format that is not a single verifiable response. The
    /// envelope is issuance packaging, so [`Self::is_verifiable_alone`] is false
    /// for it and every path that verifies one retained response refuses it.
    /// Each member is verified individually, after the caller splits the
    /// envelope, under whichever singular format that member is.
    SdJwtVcBatch,
}

impl EvidenceResponseFormat {
    pub(crate) fn media_type(self) -> &'static str {
        match self {
            Self::SignedJws => EVIDENCE_JWS_MEDIA_TYPE,
            Self::SdJwtVc => EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
            Self::SdJwtVcBatch => EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE,
        }
    }

    /// Whether one response in this format is a single thing verification can
    /// judge.
    ///
    /// True for the two singular formats. False for the batch envelope, which
    /// is a container: it carries no signature of its own, and asking whether
    /// it verifies is a question with no answer.
    #[must_use]
    pub fn is_verifiable_alone(self) -> bool {
        match self {
            Self::SignedJws | Self::SdJwtVc => true,
            Self::SdJwtVcBatch => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The media type is the whole of the format's effect on an exchange: it is
    /// the `Accept` the request carries and the content type the answer must
    /// come back under. Two formats sharing one would be one format, and a
    /// deployment could not tell which was asked for.
    #[test]
    fn each_format_selects_its_own_media_type() {
        let formats = [
            EvidenceResponseFormat::SignedJws,
            EvidenceResponseFormat::SdJwtVc,
            EvidenceResponseFormat::SdJwtVcBatch,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for format in formats {
            assert!(
                seen.insert(format.media_type()),
                "{format:?} repeats a media type"
            );
        }
        assert_eq!(
            EvidenceResponseFormat::SdJwtVcBatch.media_type(),
            EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE
        );
    }

    /// The format is retained beside the policy, so its serialization is part of
    /// what a retained context means. A batch context read back as a singular
    /// one would verify an envelope as an assertion.
    #[test]
    fn the_batch_format_round_trips_under_its_own_name() {
        let serialized = serde_json::to_string(&EvidenceResponseFormat::SdJwtVcBatch)
            .expect("the format serializes");
        assert_eq!(serialized, r#""sd-jwt-vc-batch""#);
        assert_eq!(
            serde_json::from_str::<EvidenceResponseFormat>(&serialized).expect("the format parses"),
            EvidenceResponseFormat::SdJwtVcBatch
        );
    }
}
