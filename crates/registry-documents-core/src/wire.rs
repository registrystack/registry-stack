// SPDX-License-Identifier: Apache-2.0

//! HTTP wire documents the runtime writes and every client reads.

use std::fmt;

use registry_platform_yaml::{Digest, ExternalId, Invalid, LocalId};
use serde::{Deserialize, Serialize};

use crate::access::DocumentAction;
use crate::custody::{ContentType, DocumentStatus, PolicyBinding};
use crate::problem::{type_uri, ProblemCode};
use crate::project::ActorKind;

/// The most bytes a document label may hold.
pub const MAXIMUM_LABEL_BYTES: usize = 256;

/// The page size a list answers with when the caller names none.
pub const DEFAULT_PAGE_SIZE: u32 = 50;

/// The most items one list page may carry, whatever the caller asks.
pub const MAXIMUM_PAGE_SIZE: u32 = 100;

/// The body of `POST /v1/documents`: reserve one document and the upload of
/// its single version. Size and media type are refused here, before any
/// byte moves.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// The issuing institution, when the caller repeats it. The institution
    /// recorded is always the caller's access profile's; a different value
    /// is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuing_institution: Option<ExternalId>,
    /// A display label the caller chooses. It is stored and returned as
    /// written and never used for an authorization decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<DocumentLabel>,
}

/// A caller-chosen display label: one to 256 bytes of text without control
/// characters. It is untrusted: the runtime stores and returns it, and
/// decides nothing by it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DocumentLabel(String);

impl DocumentLabel {
    pub fn new(text: impl Into<String>) -> Result<Self, Invalid> {
        let text = text.into();
        if text.is_empty() || text.len() > MAXIMUM_LABEL_BYTES || text.chars().any(char::is_control)
        {
            return Err(Invalid::expected(
                "one to 256 bytes of text without control characters",
                "Shorten the label and remove line breaks, tabs, and other control characters.",
            ));
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DocumentLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DocumentLabel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(Invalid::into_error)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for DocumentLabel {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DocumentLabel".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAXIMUM_LABEL_BYTES,
            "pattern": "^[^\\p{Cc}]+$",
            "description": "One to 256 bytes of text without control characters. Untrusted: stored and returned, never used for authorization.",
        })
    }
}

/// The custodian a reservation names: a subject at the configured token
/// issuer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodianRef {
    pub subject: ExternalId,
}

/// The answer to a reservation: the document, its version, and where to
/// send the content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentView {
    pub id: String,
    pub policy: PolicyBinding,
    pub custodian: CustodianRef,
    pub version: DocumentVersionView,
    /// The label the reserving caller chose, as written. Untrusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What the reading caller may do to this document now, in vocabulary
    /// order.
    pub actions: Vec<DocumentAction>,
}

/// One document version: its declared and verified content, and the one
/// status a client acts on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// One page of the documents a caller holds in custody or reserved, oldest
/// first.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentPage {
    pub items: Vec<DocumentView>,
    /// The cursor of the next page; absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The body of `POST /v1/documents/{documentId}/grants`: name one recipient
/// for one exact version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueGrantRequest {
    /// The exact document version the grant releases.
    pub version_id: String,
    /// The one named person the grant releases it to.
    pub grantee: GranteeRef,
    /// Hours until the grant expires; the policy default when absent, and at
    /// most the policy maximum. The expiry is fixed at issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_hours: Option<u32>,
}

/// The recipient a grant names: a subject at the configured token issuer,
/// and the actor kind a caller must resolve to for the grant to release
/// anything to it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GranteeRef {
    pub subject: ExternalId,
    pub kind: ActorKind,
}

/// Where a grant stands.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum GrantState {
    Active,
    Expired,
    Revoked,
}

/// One document grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentGrantView {
    pub id: String,
    pub document_id: String,
    pub version_id: String,
    pub grantee: GranteeRef,
    pub state: GrantState,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

/// One page of document grants, oldest first.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentGrantPage {
    pub items: Vec<DocumentGrantView>,
    /// The cursor of the next page; absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// One policy the caller may place documents under, with the restrictions a
/// client checks before it uploads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentPolicyView {
    pub id: LocalId,
    pub version: String,
    pub label: String,
    pub maximum_document_bytes: u64,
    pub allowed_content_types: Vec<ContentType>,
    pub grant_expiry_hours: u32,
    pub maximum_grant_expiry_hours: u32,
}

/// The policies the caller may place documents under, by id.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentPolicyList {
    pub items: Vec<DocumentPolicyView>,
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
        extra["custodianInstitution"] = json!("someone-else");
        assert!(serde_json::from_value::<ReserveDocumentRequest>(extra).is_err());
        let mut upper = valid;
        upper["expectedDigest"] = json!(format!("sha256:{}", "A".repeat(64)));
        assert!(serde_json::from_value::<ReserveDocumentRequest>(upper).is_err());
    }

    #[test]
    fn a_label_is_bounded_text_without_control_characters() {
        assert_eq!(
            DocumentLabel::new("Birth certificate, 2024")
                .unwrap()
                .as_str(),
            "Birth certificate, 2024"
        );
        assert!(DocumentLabel::new("é".repeat(MAXIMUM_LABEL_BYTES / 2)).is_ok());
        for refused in [
            String::new(),
            "a".repeat(MAXIMUM_LABEL_BYTES + 1),
            "line\nbreak".to_owned(),
            "tab\there".to_owned(),
            "escape\u{1b}[31m".to_owned(),
            "next\u{85}line".to_owned(),
        ] {
            assert!(DocumentLabel::new(refused.clone()).is_err(), "{refused:?}");
            let body = json!({
                "policyId": "citizen-delivery",
                "custodian": {"subject": "citizen-1"},
                "expectedDigest": format!("sha256:{}", "a".repeat(64)),
                "length": 10,
                "mediaType": "application/pdf",
                "label": refused,
            });
            assert!(serde_json::from_value::<ReserveDocumentRequest>(body).is_err());
        }
    }

    #[test]
    fn a_grant_request_names_one_version_and_one_subject_of_one_kind() {
        let request: IssueGrantRequest = serde_json::from_value(json!({
            "versionId": "v",
            "grantee": {"subject": "reader-1", "kind": "human"},
        }))
        .unwrap();
        assert_eq!(request.expiry_hours, None);
        assert_eq!(request.grantee.kind, ActorKind::Human);
        for refused in [
            json!({"versionId": "v", "grantee": {"subject": "r"}}),
            json!({"versionId": "v", "grantee": {"subject": "r", "kind": "organization"}}),
            json!({"versionId": "v", "grantee": {"subject": "r", "kind": "human", "issuer": "x"}}),
            json!({"versionId": "v", "grantee": {"organization": "x"}}),
            json!({"versionId": "v", "grantee": {"subject": "r", "kind": "human"}, "renewable": true}),
        ] {
            assert!(serde_json::from_value::<IssueGrantRequest>(refused).is_err());
        }
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
