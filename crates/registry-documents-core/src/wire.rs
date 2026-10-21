// SPDX-License-Identifier: Apache-2.0

//! HTTP wire documents the runtime writes and every client reads.

use registry_platform_yaml::{Digest, ExternalId};
use serde::{Deserialize, Serialize};

use crate::custody::{DocumentStatus, PolicyBinding};
use crate::problem::{type_uri, ProblemCode};

/// The body of `POST /documents`: reserve one document and the upload of
/// its single version. Size and media type are refused here, before any
/// byte moves.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReserveDocumentRequest {
    /// The document policy the document is held under.
    pub policy_id: String,
    /// Who holds the document in custody.
    pub custodian: CustodianRef,
    /// The digest the content must have, `sha256:` and 64 lowercase hex.
    pub expected_digest: Digest,
    /// The exact content length in bytes.
    pub length: u64,
    /// The media type the content is declared as; the content PUT must send
    /// exactly this `Content-Type`.
    pub media_type: String,
}

/// The custodian a reservation names: a subject at the configured token
/// issuer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodianRef {
    pub subject: ExternalId,
}

/// The answer to a reservation: the document, its version, and where to
/// send the content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReservationView {
    pub document: DocumentView,
    /// The route the content is sent to with `PUT`.
    pub upload_path: String,
    /// When the reservation lapses if no matching content arrived, RFC 3339.
    pub upload_expires_at: String,
}

/// One document as its custodian reads it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentView {
    pub id: String,
    pub policy: PolicyBinding,
    pub custodian: CustodianRef,
    pub version: DocumentVersionView,
}

/// One document version: its declared and verified content, and the one
/// status a client acts on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentVersionView {
    pub id: String,
    pub status: DocumentStatus,
    pub media_type: String,
    pub expected_digest: Digest,
    pub length: u64,
    pub reserved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized_at: Option<String>,
}

/// The problem document every refusal answers with, as a client reads it.
/// Field names match the Registry Stack problem envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProblemDocument {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    pub trace_id: String,
}

impl ProblemDocument {
    /// The closed-vocabulary code this document carries, when the document
    /// is exactly the one the runtime renders for that code: the type URI,
    /// title, detail, and status all match what the vocabulary pins.
    #[must_use]
    pub fn problem(&self) -> Option<ProblemCode> {
        let code = ProblemCode::from_code(&self.code)?;
        (self.type_uri == type_uri(code.code())
            && self.status == code.http_status()
            && self.title == code.title()
            && self.detail == code.detail())
        .then_some(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rendered(code: ProblemCode) -> serde_json::Value {
        json!({
            "type": type_uri(code.code()),
            "title": code.title(),
            "status": code.http_status(),
            "detail": code.detail(),
            "code": code.code(),
            "traceId": "0af7651916cd43dd8448eb211c80319c",
        })
    }

    #[test]
    fn a_rendered_problem_reads_back_as_its_code() {
        for code in ProblemCode::ALL {
            let document: ProblemDocument = serde_json::from_value(rendered(*code)).unwrap();
            assert_eq!(document.problem(), Some(*code));
        }
    }

    #[test]
    fn a_reservation_request_refuses_unknown_members_and_malformed_digests() {
        let valid = json!({
            "policyId": "citizen-delivery",
            "custodian": {"subject": "citizen-1"},
            "expectedDigest": format!("sha256:{}", "a".repeat(64)),
            "length": 10,
            "mediaType": "application/pdf",
        });
        let request: ReserveDocumentRequest = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(request.length, 10);
        let mut extra = valid.clone();
        extra["issuingInstitution"] = json!("someone-else");
        assert!(serde_json::from_value::<ReserveDocumentRequest>(extra).is_err());
        let mut upper = valid;
        upper["expectedDigest"] = json!(format!("sha256:{}", "A".repeat(64)));
        assert!(serde_json::from_value::<ReserveDocumentRequest>(upper).is_err());
    }

    #[test]
    fn a_problem_that_differs_from_the_vocabulary_is_not_recognized() {
        let mut value = rendered(ProblemCode::RequestNotFound);
        value["status"] = json!(400);
        let document: ProblemDocument = serde_json::from_value(value).unwrap();
        assert_eq!(document.problem(), None);
        let mut value = rendered(ProblemCode::RequestNotFound);
        value["extra"] = json!(true);
        assert!(serde_json::from_value::<ProblemDocument>(value).is_err());
    }
}
