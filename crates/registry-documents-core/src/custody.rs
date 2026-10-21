// SPDX-License-Identifier: Apache-2.0

//! The custody model: the media types a policy admits, the frozen policy
//! binding a document version records, the three state dimensions of a
//! version and the one status a client reads, and the pure reservation
//! decision.
//!
//! Every decision here is I/O-free. The runtime reads what it needs from
//! PostgreSQL (the bytes a custodian already holds, the current state of a
//! version) and asks this module for the answer, so the rule a reservation
//! or a release follows is written once.

use std::fmt;

use registry_platform_yaml::{Digest, Invalid, LocalId, UniqueList};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::problem::ProblemCode;
use crate::project::{DocumentPolicy, DocumentsProject};

/// The most media types one policy may list.
pub const MAXIMUM_ALLOWED_CONTENT_TYPES: usize = 16;

/// The longest type or subtype component of a media type.
const MAXIMUM_CONTENT_TYPE_COMPONENT: usize = 127;

/// The schema string bound into every policy digest.
pub const DOCUMENT_POLICY_DIGEST_SCHEMA: &str = "registry-documents-document-policy/v1";

const CONTENT_TYPE_EXPECTED: &str =
    "a lowercase concrete media type `type/subtype` without parameters or wildcards";
const CONTENT_TYPE_ACTION: &str =
    "Write the exact media type, for example `application/pdf`, with no parameters.";

/// One media type a policy admits, in the exact-match grammar Base Registry
/// Engine attachment slots use: a lowercase concrete `type/subtype`, each
/// component starting with a letter or digit, with no parameters, wildcards,
/// or whitespace. A request matches only by byte equality; nothing is
/// normalized and no content is sniffed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentType(String);

impl ContentType {
    pub fn new(text: impl Into<String>) -> Result<Self, Invalid> {
        let text = text.into();
        if valid_content_type(&text) {
            Ok(Self(text))
        } else {
            Err(Invalid::expected(
                CONTENT_TYPE_EXPECTED,
                CONTENT_TYPE_ACTION,
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_content_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    [kind, subtype].into_iter().all(|component| {
        !component.is_empty()
            && component.len() <= MAXIMUM_CONTENT_TYPE_COMPONENT
            && (component.as_bytes()[0].is_ascii_lowercase()
                || component.as_bytes()[0].is_ascii_digit())
            && component.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(
                        byte,
                        b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                    )
            })
    })
}

impl fmt::Display for ContentType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for ContentType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(Invalid::into_error)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ContentType {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ContentType".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$",
            "description": "A lowercase concrete media type `type/subtype` without parameters or wildcards, matched exactly.",
        })
    }
}

/// The media types one policy admits: one to sixteen distinct entries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AllowedContentTypes(Vec<ContentType>);

impl AllowedContentTypes {
    pub fn as_slice(&self) -> &[ContentType] {
        &self.0
    }

    /// Whether `media_type` is listed, by exact byte equality.
    pub fn admits(&self, media_type: &str) -> bool {
        self.0.iter().any(|listed| listed.as_str() == media_type)
    }
}

impl<'de> Deserialize<'de> for AllowedContentTypes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = UniqueList::<ContentType>::deserialize(deserializer)?.into_vec();
        if items.is_empty() || items.len() > MAXIMUM_ALLOWED_CONTENT_TYPES {
            return Err(Invalid::expected(
                "a list of one to sixteen media types",
                "List between one and sixteen media types the policy admits.",
            )
            .into_error());
        }
        Ok(Self(items))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for AllowedContentTypes {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AllowedContentTypes".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<UniqueList<ContentType>>();
        schema.insert("minItems".to_owned(), 1.into());
        schema.insert(
            "maxItems".to_owned(),
            (MAXIMUM_ALLOWED_CONTENT_TYPES as u64).into(),
        );
        schema
    }
}

/// The policy a document version was reserved under, frozen at reservation:
/// its id, its authored version, and the digest of its whole authored body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBinding {
    pub id: LocalId,
    pub version: String,
    pub digest: Digest,
}

/// The policy body could not be serialized into its canonical form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDigestError;

impl fmt::Display for PolicyDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the document policy has no canonical JSON form")
    }
}

impl std::error::Error for PolicyDigestError {}

impl DocumentPolicy {
    /// The binding of this policy under `id`. The digest covers the schema
    /// string, the id, and every authored member in RFC 8785 canonical form,
    /// so any change to the policy body changes the digest.
    pub fn binding(&self, id: &LocalId) -> Result<PolicyBinding, PolicyDigestError> {
        let value = serde_json::json!({
            "schema": DOCUMENT_POLICY_DIGEST_SCHEMA,
            "id": id,
            "policy": self,
        });
        let bytes = registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| PolicyDigestError)?;
        let digest = Digest::new(sha256_digest(&bytes)).map_err(|_| PolicyDigestError)?;
        Ok(PolicyBinding {
            id: id.clone(),
            version: self.version.clone(),
            digest,
        })
    }
}

/// `sha256:` followed by the lowercase hex SHA-256 of `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Where the upload of a version stands.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UploadState {
    /// Reserved; no content has been accepted.
    Reserved,
    /// The content matched the reservation and is stored.
    Finalized,
    /// The reservation lapsed before content was accepted.
    Expired,
}

/// The content verifier's standing verdict on a version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationState {
    Pending,
    Approved,
    Rejected,
}

/// Whether a version may be released at all.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Eligibility {
    Suspended,
    Releasable,
}

/// The one status a client reads, derived from the three state dimensions.
/// There is no `verifying` value: a verification attempt in flight changes
/// nothing a client can act on.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DocumentStatus {
    /// Reserved, or the reservation lapsed: no content is stored.
    AwaitingContent,
    /// Content stored; no standing approval.
    Pending,
    /// Approved under the current verifier binding and releasable.
    Ready,
    /// Approved once, but not releasable now.
    Suspended,
    /// The verifier rejected the content.
    Rejected,
}

impl DocumentStatus {
    /// Derive the status from the stored dimensions. Only `ready` releases
    /// content.
    #[must_use]
    pub const fn derive(
        upload: UploadState,
        verification: VerificationState,
        eligibility: Eligibility,
    ) -> Self {
        match (upload, verification, eligibility) {
            (UploadState::Reserved | UploadState::Expired, _, _) => Self::AwaitingContent,
            (UploadState::Finalized, VerificationState::Rejected, _) => Self::Rejected,
            (UploadState::Finalized, VerificationState::Pending, _) => Self::Pending,
            (UploadState::Finalized, VerificationState::Approved, Eligibility::Releasable) => {
                Self::Ready
            }
            (UploadState::Finalized, VerificationState::Approved, Eligibility::Suspended) => {
                Self::Suspended
            }
        }
    }

    #[must_use]
    pub const fn is_releasable(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// What a reservation asks for, before the bytes the custodian already
/// holds are known.
#[derive(Clone, Copy, Debug)]
pub struct ReservationAsk<'a> {
    pub policy_id: &'a str,
    pub declared_length: u64,
    pub media_type: &'a str,
}

/// The policy a reservation was admitted under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReservation<'a> {
    pub policy_id: &'a LocalId,
    pub policy: &'a DocumentPolicy,
    pub media_type: ContentType,
}

/// Admit a reservation against the loaded project: the policy must exist,
/// the declared length must be at least one byte and at most the policy
/// maximum, and the media type must be listed exactly. Nothing about the
/// custodian is read here; [`check_custodian_quota`] runs once the held
/// bytes are counted.
pub fn admit_reservation<'p>(
    project: &'p DocumentsProject,
    ask: ReservationAsk<'_>,
) -> Result<AdmittedReservation<'p>, ProblemCode> {
    let (policy_id, policy) = project
        .document_policies
        .iter()
        .find(|(id, _)| id.as_str() == ask.policy_id)
        .ok_or(ProblemCode::DocumentPolicyUnknown)?;
    let restrictions = &policy.mandatory_restrictions;
    if ask.declared_length == 0 || ask.declared_length > restrictions.maximum_document_bytes.get() {
        return Err(ProblemCode::DocumentTooLarge);
    }
    if !restrictions.allowed_content_types.admits(ask.media_type) {
        return Err(ProblemCode::DocumentContentTypeNotAllowed);
    }
    let media_type =
        ContentType::new(ask.media_type).map_err(|_| ProblemCode::DocumentContentTypeNotAllowed)?;
    Ok(AdmittedReservation {
        policy_id,
        policy,
        media_type,
    })
}

/// Refuse a reservation that would take the custodian past the policy's
/// byte quota. `held_bytes` counts every reserved or finalized version the
/// custodian holds under the policy that is not yet erased.
pub fn check_custodian_quota(
    policy: &DocumentPolicy,
    held_bytes: u64,
    declared_length: u64,
) -> Result<(), ProblemCode> {
    let quota = policy.mandatory_restrictions.maximum_custodian_bytes.get();
    match held_bytes.checked_add(declared_length) {
        Some(total) if total <= quota => Ok(()),
        _ => Err(ProblemCode::CustodyQuotaExceeded),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STARTER: &str =
        include_str!("../../../products/documents/examples/starter/documents.yaml");

    fn starter() -> DocumentsProject {
        DocumentsProject::decode("documents.yaml", STARTER.as_bytes())
            .unwrap_or_else(|report| panic!("the starter project is refused: {report:?}"))
            .value
    }

    fn ask<'a>(
        policy_id: &'a str,
        declared_length: u64,
        media_type: &'a str,
    ) -> ReservationAsk<'a> {
        ReservationAsk {
            policy_id,
            declared_length,
            media_type,
        }
    }

    #[test]
    fn content_types_follow_the_exact_match_grammar() {
        for valid in [
            "application/pdf",
            "image/png",
            "application/vnd.oasis.opendocument.text",
            "application/ld+json",
            "3gpp/x-test",
        ] {
            assert!(ContentType::new(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "application",
            "Application/pdf",
            "application/PDF",
            "application/*",
            "*/*",
            "application/pdf; charset=utf-8",
            "application/pdf ",
            "/pdf",
            "application/",
            "application/pdf/extra",
            "-application/pdf",
        ] {
            assert!(ContentType::new(invalid).is_err(), "{invalid:?}");
        }
        assert!(ContentType::new(format!("a/{}", "b".repeat(127))).is_ok());
        assert!(ContentType::new(format!("a/{}", "b".repeat(128))).is_err());
    }

    #[test]
    fn a_reservation_inside_the_policy_is_admitted() {
        let project = starter();
        let admitted = admit_reservation(&project, ask("citizen-delivery", 1, "application/pdf"))
            .expect("admitted");
        assert_eq!(admitted.policy_id.as_str(), "citizen-delivery");
        assert_eq!(admitted.media_type.as_str(), "application/pdf");
        assert!(admit_reservation(
            &project,
            ask("citizen-delivery", 16_777_216, "application/pdf")
        )
        .is_ok());
    }

    #[test]
    fn an_unknown_policy_is_refused() {
        assert_eq!(
            admit_reservation(&starter(), ask("no-such-policy", 1, "application/pdf")),
            Err(ProblemCode::DocumentPolicyUnknown)
        );
    }

    #[test]
    fn a_zero_or_oversized_length_is_refused_before_any_bytes() {
        let project = starter();
        for length in [0, 16_777_217, u64::MAX] {
            assert_eq!(
                admit_reservation(&project, ask("citizen-delivery", length, "application/pdf")),
                Err(ProblemCode::DocumentTooLarge),
                "{length}"
            );
        }
    }

    /// DOCUMENTS-SEC-16: a media type outside the policy list is refused at
    /// reservation, by exact match, with no normalization.
    #[test]
    fn a_media_type_outside_the_policy_list_is_refused_at_reservation() {
        let project = starter();
        for media_type in [
            "image/png",
            "APPLICATION/PDF",
            "application/pdf; charset=binary",
            "application/*",
            "",
        ] {
            assert_eq!(
                admit_reservation(&project, ask("citizen-delivery", 1, media_type)),
                Err(ProblemCode::DocumentContentTypeNotAllowed),
                "{media_type:?}"
            );
        }
        assert!(admit_reservation(&project, ask("institutional-custody", 1, "image/png")).is_ok());
    }

    #[test]
    fn the_quota_counts_held_and_declared_bytes() {
        let project = starter();
        let policy = &project.document_policies[&LocalId::new("citizen-delivery").unwrap()];
        let quota = policy.mandatory_restrictions.maximum_custodian_bytes.get();
        assert_eq!(check_custodian_quota(policy, 0, quota), Ok(()));
        assert_eq!(check_custodian_quota(policy, quota - 1, 1), Ok(()));
        assert_eq!(
            check_custodian_quota(policy, quota, 1),
            Err(ProblemCode::CustodyQuotaExceeded)
        );
        assert_eq!(
            check_custodian_quota(policy, u64::MAX, 1),
            Err(ProblemCode::CustodyQuotaExceeded)
        );
    }

    #[test]
    fn only_an_approved_releasable_finalized_version_is_ready() {
        use Eligibility::*;
        use UploadState::*;
        use VerificationState::*;
        let cases = [
            (
                Reserved,
                Pending,
                Suspended,
                DocumentStatus::AwaitingContent,
            ),
            (Expired, Pending, Suspended, DocumentStatus::AwaitingContent),
            (
                Reserved,
                Approved,
                Releasable,
                DocumentStatus::AwaitingContent,
            ),
            (Finalized, Pending, Suspended, DocumentStatus::Pending),
            (Finalized, Pending, Releasable, DocumentStatus::Pending),
            (Finalized, Approved, Releasable, DocumentStatus::Ready),
            (Finalized, Approved, Suspended, DocumentStatus::Suspended),
            (Finalized, Rejected, Suspended, DocumentStatus::Rejected),
            (Finalized, Rejected, Releasable, DocumentStatus::Rejected),
        ];
        for (upload, verification, eligibility, expected) in cases {
            let status = DocumentStatus::derive(upload, verification, eligibility);
            assert_eq!(
                status, expected,
                "{upload:?} {verification:?} {eligibility:?}"
            );
            assert_eq!(status.is_releasable(), expected == DocumentStatus::Ready);
        }
    }

    #[test]
    fn statuses_serialize_in_kebab_case() {
        assert_eq!(
            serde_json::to_value(DocumentStatus::AwaitingContent).unwrap(),
            "awaiting-content"
        );
        assert_eq!(
            serde_json::to_value(DocumentStatus::Ready).unwrap(),
            "ready"
        );
    }

    #[test]
    fn a_policy_binding_changes_with_any_authored_member() {
        let project = starter();
        let id = LocalId::new("citizen-delivery").unwrap();
        let policy = project.document_policies[&id].clone();
        let binding = policy.binding(&id).unwrap();
        assert_eq!(binding.id, id);
        assert_eq!(binding.version, policy.version);
        assert_eq!(binding, policy.binding(&id).unwrap());

        let mut changed = policy.clone();
        changed.mandatory_restrictions.maximum_custodian_bytes =
            registry_platform_yaml::BoundedU64::new(1).unwrap();
        assert_ne!(changed.binding(&id).unwrap().digest, binding.digest);

        let other = LocalId::new("other-policy").unwrap();
        assert_ne!(policy.binding(&other).unwrap().digest, binding.digest);
    }

    #[test]
    fn sha256_digests_are_prefixed_lowercase_hex() {
        assert_eq!(
            sha256_digest(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
