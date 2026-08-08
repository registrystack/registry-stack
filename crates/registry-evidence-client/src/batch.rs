//! The batch issuance envelope, as a relying party reads it.
//!
//! A request presenting N holder keys is answered with N credentials in one
//! envelope, selected by its own exact media type. The envelope is issuance
//! packaging and nothing else:
//!
//! - `credentials[i]` is the credential issued for the request's
//!   `holderKeys[i]`. Position is the only thing that says which key a member
//!   belongs to, so nothing here reorders, sorts, or deduplicates the list.
//! - Nothing verifies the envelope. Each member is an ordinary credential and
//!   is verified individually, by the portable verifier, against the policy the
//!   request closed. Parsing this container is not a verification step and
//!   establishes nothing about any member.
//! - There is no partial batch. The deployment releases every member or none,
//!   so a caller that holds a parsed envelope holds the whole answer.
//!
//! The wire shape is the runtime's, mirrored rather than re-decided: the
//! constants below are the runtime's own values, and a test asserts they still
//! agree.

use registry_evidence_verifier::redacted_debug;
use serde::Deserialize;

use crate::{error::EvidenceClientError, prepare::MAXIMUM_HOLDER_KEYS};

/// The exact media type that selects a batch issuance envelope. No other
/// negotiation reaches this format, and no other format reaches this type.
pub const EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE: &str =
    "application/vnd.registrystack.evidence.batch+json";

/// The only envelope version this client reads. A document announcing another
/// one is refused rather than read as if it meant the same thing.
pub const SD_JWT_VC_BATCH_SCHEMA_V1: &str = "registry.sd-jwt-vc-batch-envelope/v1";

/// Ceiling on the serialized envelope, in bytes.
///
/// The singular response formats never needed a bound of their own, because one
/// assertion is small. A batch multiplies that by its member count, so the
/// bound becomes load-bearing: a deployment refuses a release it cannot answer
/// within it, and a caller refuses a body past it before parsing anything.
///
/// This is the contract's bound, and a relying party's own configured response
/// bound applies as well. Whichever is smaller decides.
pub const MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES: usize = 1_048_576;

/// The single value the envelope's `type` member may carry.
const SD_JWT_VC_BATCH_ENVELOPE_TYPE: &str = "SdJwtVcBatchEnvelope";

/// One batch issuance envelope, read but not verified.
///
/// Holding this proves only that the deployment answered with a well-formed
/// container. Every member is still unverified material: verify each one
/// individually before acting on anything it says.
///
/// `Debug` is redacted. A credential carries disclosed values and must not
/// reach a log line, a panic message, or a snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct SdJwtVcBatchResponse {
    credentials: Vec<String>,
}

impl SdJwtVcBatchResponse {
    /// Read an envelope from the exact bytes the deployment answered with.
    ///
    /// This is a wire-shape check and nothing more. It refuses a body past the
    /// contract's byte ceiling, a document that is not this envelope version,
    /// one carrying a member this version does not declare, and a member list
    /// that is empty, past the contract's ceiling, or carrying an empty
    /// credential. It makes no judgement whatsoever about the credentials
    /// themselves.
    ///
    /// Every refusal is the same
    /// [`EvidenceClientError::Protocol`](crate::EvidenceClientError::Protocol),
    /// with the status of the answer that carried it: the deployment answered,
    /// and the answer was not the document it promised. The variant carries no
    /// detail about the body, for the reason every failure in this crate
    /// carries none.
    pub fn parse(body: &[u8]) -> Result<Self, EvidenceClientError> {
        if body.len() > MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES {
            return Err(refusal());
        }
        let document: SdJwtVcBatchEnvelopeDocument =
            serde_json::from_slice(body).map_err(|_| refusal())?;
        if document.schema != SD_JWT_VC_BATCH_SCHEMA_V1
            || document.envelope_type != SD_JWT_VC_BATCH_ENVELOPE_TYPE
        {
            return Err(refusal());
        }
        if document.credentials.is_empty()
            || document.credentials.len() > MAXIMUM_HOLDER_KEYS
            || document
                .credentials
                .iter()
                .any(|credential| credential.is_empty())
        {
            return Err(refusal());
        }
        Ok(Self {
            credentials: document.credentials,
        })
    }

    /// Every credential the envelope carries, in the order the request's holder
    /// keys were presented.
    #[must_use]
    pub fn credentials(&self) -> &[String] {
        &self.credentials
    }

    /// The credential issued for the holder key at `index` in the request.
    ///
    /// `None` means the envelope carries no member at that position, which for
    /// an answer to a request the caller made is a mismatch between the keys it
    /// presented and the credentials it received.
    #[must_use]
    pub fn credential_for_holder_key(&self, index: usize) -> Option<&str> {
        self.credentials.get(index).map(String::as_str)
    }

    /// How many credentials the envelope carries. Never zero: an envelope with
    /// no member does not parse.
    #[must_use]
    pub fn count(&self) -> usize {
        self.credentials.len()
    }

    /// Take the credentials, in the same order.
    #[must_use]
    pub fn into_credentials(self) -> Vec<String> {
        self.credentials
    }
}

redacted_debug!(SdJwtVcBatchResponse);

/// A body that does not satisfy the envelope contract.
///
/// The status is the one a released batch arrives with, because that is the
/// only status this document is ever read under: the deployment answered
/// successfully, and the body was not the document that answer promised.
fn refusal() -> EvidenceClientError {
    EvidenceClientError::Protocol {
        status: 200,
        code: None,
        operation: None,
        retry_after_seconds: None,
    }
}

/// The envelope exactly as the runtime declares it. `deny_unknown_fields` keeps
/// a document carrying anything this version does not declare from being read
/// as though it were this version.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SdJwtVcBatchEnvelopeDocument {
    schema: String,
    #[serde(rename = "type")]
    envelope_type: String,
    credentials: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(credentials: &[&str]) -> String {
        serde_json::json!({
            "schema": SD_JWT_VC_BATCH_SCHEMA_V1,
            "type": SD_JWT_VC_BATCH_ENVELOPE_TYPE,
            "credentials": credentials,
        })
        .to_string()
    }

    /// The wire shape is the runtime's, and this client re-declares it rather
    /// than depending on the runtime. A test is therefore the only thing
    /// holding the two together: if the runtime moves a constant, this fails
    /// instead of the client silently reading, or refusing, the wrong thing.
    #[test]
    fn the_declared_wire_shape_is_the_runtimes_own() {
        assert_eq!(
            EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE,
            registry_evidence::EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE
        );
        assert_eq!(
            SD_JWT_VC_BATCH_SCHEMA_V1,
            registry_evidence::SD_JWT_VC_BATCH_SCHEMA_V1
        );
        assert_eq!(
            MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES,
            registry_evidence::MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES
        );
        assert_eq!(
            MAXIMUM_HOLDER_KEYS,
            usize::from(registry_evidence::config::MAXIMUM_HOLDER_BOUND_BATCH_SIZE)
        );
        assert_eq!(
            serde_json::to_value(
                registry_evidence::model::SdJwtVcBatchEnvelopeType::SdJwtVcBatchEnvelope
            )
            .expect("the envelope type serializes"),
            serde_json::json!(SD_JWT_VC_BATCH_ENVELOPE_TYPE)
        );
    }

    /// The strongest available statement that the two shapes agree: what the
    /// runtime's own type serializes is what this type reads, member for member
    /// and in order.
    #[test]
    fn what_the_runtime_serializes_is_what_this_type_reads() {
        let issued = registry_evidence::model::SdJwtVcBatchEnvelope {
            schema: registry_evidence::SD_JWT_VC_BATCH_SCHEMA_V1.to_owned(),
            envelope_type: registry_evidence::model::SdJwtVcBatchEnvelopeType::SdJwtVcBatchEnvelope,
            credentials: vec![
                "first-credential~".to_owned(),
                "second-credential~".to_owned(),
            ],
        };
        let body = serde_json::to_vec(&issued).expect("the runtime envelope serializes");

        let parsed = SdJwtVcBatchResponse::parse(&body).expect("the envelope is read");
        assert_eq!(parsed.credentials(), issued.credentials);
        assert_eq!(parsed.count(), 2);
    }

    /// Position is the whole contract: member `i` belongs to the key presented
    /// at `i`, and reading it back by that index is the guarantee made
    /// executable.
    #[test]
    fn each_credential_belongs_to_the_holder_key_at_its_own_position() {
        let parsed = SdJwtVcBatchResponse::parse(
            envelope(&["credential-for-key-0", "credential-for-key-1"]).as_bytes(),
        )
        .expect("the envelope is read");

        assert_eq!(
            parsed.credential_for_holder_key(0),
            Some("credential-for-key-0")
        );
        assert_eq!(
            parsed.credential_for_holder_key(1),
            Some("credential-for-key-1")
        );
        assert_eq!(parsed.credential_for_holder_key(2), None);
        assert_eq!(
            parsed.clone().into_credentials(),
            parsed.credentials().to_vec(),
            "taking the credentials preserves the order"
        );
    }

    /// A batch of one is an ordinary answer, not a degenerate case: a request
    /// presenting one key gets an array of one.
    #[test]
    fn an_envelope_of_one_credential_is_read() {
        let parsed = SdJwtVcBatchResponse::parse(envelope(&["only-credential"]).as_bytes())
            .expect("the envelope is read");
        assert_eq!(parsed.count(), 1);
    }

    #[test]
    fn a_body_that_is_not_this_envelope_is_refused() {
        let ceiling = MAXIMUM_HOLDER_KEYS + 1;
        let too_many: Vec<String> = (0..ceiling)
            .map(|index| format!("credential-{index}"))
            .collect();
        let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("not JSON at all", b"not json".to_vec()),
            ("an empty body", Vec::new()),
            (
                "another schema version",
                serde_json::json!({
                    "schema": "registry.sd-jwt-vc-batch-envelope/v2",
                    "type": SD_JWT_VC_BATCH_ENVELOPE_TYPE,
                    "credentials": ["a-credential"],
                })
                .to_string()
                .into_bytes(),
            ),
            (
                "another envelope type",
                serde_json::json!({
                    "schema": SD_JWT_VC_BATCH_SCHEMA_V1,
                    "type": "SomeOtherEnvelope",
                    "credentials": ["a-credential"],
                })
                .to_string()
                .into_bytes(),
            ),
            (
                "a member this version does not declare",
                serde_json::json!({
                    "schema": SD_JWT_VC_BATCH_SCHEMA_V1,
                    "type": SD_JWT_VC_BATCH_ENVELOPE_TYPE,
                    "credentials": ["a-credential"],
                    "holderKeys": [],
                })
                .to_string()
                .into_bytes(),
            ),
            (
                "a missing credential list",
                serde_json::json!({
                    "schema": SD_JWT_VC_BATCH_SCHEMA_V1,
                    "type": SD_JWT_VC_BATCH_ENVELOPE_TYPE,
                })
                .to_string()
                .into_bytes(),
            ),
            ("no credential at all", envelope(&[]).into_bytes()),
            ("an empty credential", envelope(&["", "a"]).into_bytes()),
            (
                "more credentials than the contract allows",
                envelope(&too_many).into_bytes(),
            ),
            (
                "a body past the contract's byte ceiling",
                vec![b'a'; MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES + 1],
            ),
        ];

        for (description, body) in cases {
            assert_eq!(
                SdJwtVcBatchResponse::parse(&body)
                    .map(|_| ())
                    .expect_err(description),
                refusal(),
                "{description} was accepted"
            );
        }
    }

    /// The ceiling itself is still a legal answer: a refusal one step past an
    /// edge does not mean the edge is refused.
    #[test]
    fn an_envelope_at_the_contracts_ceiling_is_read() {
        let credentials: Vec<String> = (0..MAXIMUM_HOLDER_KEYS)
            .map(|index| format!("credential-{index}"))
            .collect();
        let credentials: Vec<&str> = credentials.iter().map(String::as_str).collect();
        let parsed = SdJwtVcBatchResponse::parse(envelope(&credentials).as_bytes())
            .expect("the envelope is read");
        assert_eq!(parsed.count(), MAXIMUM_HOLDER_KEYS);
    }

    #[test]
    fn debug_output_never_carries_a_credential() {
        let parsed = SdJwtVcBatchResponse::parse(envelope(&["a-credential-canary"]).as_bytes())
            .expect("the envelope is read");
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("canary"), "{rendered}");
    }
}
