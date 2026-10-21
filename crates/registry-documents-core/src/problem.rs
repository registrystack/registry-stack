// SPDX-License-Identifier: Apache-2.0

//! The closed problem vocabulary of the Document Store.
//!
//! The vocabulary is closed on purpose: a caller can enumerate every problem
//! this product can ever return, and a problem code outside this list is a
//! defect, not a compatibility event. A code joins the list in the same change
//! that first returns it, so the list holds only what the runtime answers
//! today: the request-edge rejections, the authentication and access
//! refusals, the upload, grant, and release refusals, the idempotency
//! refusals, and an unavailable service.
//!
//! `resource.not-found` is the one answer for a document, upload, or grant
//! the caller may not see, whether or not it exists, so a refusal never
//! discloses existence. `request.not-found` stays the answer for a route
//! that does not exist.
//!
//! The `request.*` family carries the request-edge rejections (a route that
//! does not exist, a method the route refuses, a body too large or not JSON)
//! under this product's own prefix, exactly as Casework, Scheduling, and
//! Messaging do: no shared platform problem prefix exists in the Registry
//! Stack catalog.

use crate::naming::DOCUMENTS_PROBLEM_TYPE_BASE;

pub const AUTHENTICATION_REFUSED_PROBLEM: &str = "authentication.refused";
pub const CUSTODY_NOT_PERMITTED_PROBLEM: &str = "custody.not-permitted";
pub const CUSTODY_QUOTA_EXCEEDED_PROBLEM: &str = "custody.quota-exceeded";
pub const DOCUMENT_POLICY_UNKNOWN_PROBLEM: &str = "document-policy.unknown";
pub const DOCUMENT_VERSION_NOT_RELEASABLE_PROBLEM: &str = "document-version.not-releasable";
pub const DOCUMENT_CONTENT_TYPE_NOT_ALLOWED_PROBLEM: &str = "document.content-type-not-allowed";
pub const DOCUMENT_TOO_LARGE_PROBLEM: &str = "document.too-large";
pub const IDEMPOTENCY_EXPIRED_PROBLEM: &str = "idempotency.expired";
pub const IDEMPOTENCY_KEY_REUSED_PROBLEM: &str = "idempotency.key-reused";
pub const PROFILE_NOT_AUTHORIZED_PROBLEM: &str = "profile.not-authorized";
pub const REQUEST_BODY_TOO_LARGE_PROBLEM: &str = "request.body-too-large";
pub const REQUEST_INVALID_PROBLEM: &str = "request.invalid";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const RESOURCE_NOT_FOUND_PROBLEM: &str = "resource.not-found";
pub const SERVICE_UNAVAILABLE_PROBLEM: &str = "service.unavailable";
pub const UPLOAD_CONTENT_TYPE_MISMATCH_PROBLEM: &str = "upload.content-type-mismatch";
pub const UPLOAD_DIGEST_MISMATCH_PROBLEM: &str = "upload.digest-mismatch";
pub const UPLOAD_EXPIRED_PROBLEM: &str = "upload.expired";
pub const UPLOAD_FINALIZED_PROBLEM: &str = "upload.finalized";
pub const UPLOAD_LENGTH_MISMATCH_PROBLEM: &str = "upload.length-mismatch";

/// Every problem code the Document Store can return, in code-string order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProblemCode {
    AuthenticationRefused,
    CustodyNotPermitted,
    CustodyQuotaExceeded,
    DocumentPolicyUnknown,
    DocumentVersionNotReleasable,
    DocumentContentTypeNotAllowed,
    DocumentTooLarge,
    IdempotencyExpired,
    IdempotencyKeyReused,
    ProfileNotAuthorized,
    RequestBodyTooLarge,
    RequestInvalid,
    RequestMethodNotAllowed,
    RequestNotFound,
    RequestUnprocessable,
    RequestUnsupportedMediaType,
    ResourceNotFound,
    ServiceUnavailable,
    UploadContentTypeMismatch,
    UploadDigestMismatch,
    UploadExpired,
    UploadFinalized,
    UploadLengthMismatch,
}

impl ProblemCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AuthenticationRefused,
        Self::CustodyNotPermitted,
        Self::CustodyQuotaExceeded,
        Self::DocumentPolicyUnknown,
        Self::DocumentVersionNotReleasable,
        Self::DocumentContentTypeNotAllowed,
        Self::DocumentTooLarge,
        Self::IdempotencyExpired,
        Self::IdempotencyKeyReused,
        Self::ProfileNotAuthorized,
        Self::RequestBodyTooLarge,
        Self::RequestInvalid,
        Self::RequestMethodNotAllowed,
        Self::RequestNotFound,
        Self::RequestUnprocessable,
        Self::RequestUnsupportedMediaType,
        Self::ResourceNotFound,
        Self::ServiceUnavailable,
        Self::UploadContentTypeMismatch,
        Self::UploadDigestMismatch,
        Self::UploadExpired,
        Self::UploadFinalized,
        Self::UploadLengthMismatch,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => AUTHENTICATION_REFUSED_PROBLEM,
            Self::CustodyNotPermitted => CUSTODY_NOT_PERMITTED_PROBLEM,
            Self::CustodyQuotaExceeded => CUSTODY_QUOTA_EXCEEDED_PROBLEM,
            Self::DocumentPolicyUnknown => DOCUMENT_POLICY_UNKNOWN_PROBLEM,
            Self::DocumentVersionNotReleasable => DOCUMENT_VERSION_NOT_RELEASABLE_PROBLEM,
            Self::DocumentContentTypeNotAllowed => DOCUMENT_CONTENT_TYPE_NOT_ALLOWED_PROBLEM,
            Self::DocumentTooLarge => DOCUMENT_TOO_LARGE_PROBLEM,
            Self::IdempotencyExpired => IDEMPOTENCY_EXPIRED_PROBLEM,
            Self::IdempotencyKeyReused => IDEMPOTENCY_KEY_REUSED_PROBLEM,
            Self::ProfileNotAuthorized => PROFILE_NOT_AUTHORIZED_PROBLEM,
            Self::RequestBodyTooLarge => REQUEST_BODY_TOO_LARGE_PROBLEM,
            Self::RequestInvalid => REQUEST_INVALID_PROBLEM,
            Self::RequestMethodNotAllowed => REQUEST_METHOD_NOT_ALLOWED_PROBLEM,
            Self::RequestNotFound => REQUEST_NOT_FOUND_PROBLEM,
            Self::RequestUnprocessable => REQUEST_UNPROCESSABLE_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::ResourceNotFound => RESOURCE_NOT_FOUND_PROBLEM,
            Self::ServiceUnavailable => SERVICE_UNAVAILABLE_PROBLEM,
            Self::UploadContentTypeMismatch => UPLOAD_CONTENT_TYPE_MISMATCH_PROBLEM,
            Self::UploadDigestMismatch => UPLOAD_DIGEST_MISMATCH_PROBLEM,
            Self::UploadExpired => UPLOAD_EXPIRED_PROBLEM,
            Self::UploadFinalized => UPLOAD_FINALIZED_PROBLEM,
            Self::UploadLengthMismatch => UPLOAD_LENGTH_MISMATCH_PROBLEM,
        }
    }

    /// The code for `code`, or `None` for anything outside the vocabulary.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|problem| problem.code() == code)
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::AuthenticationRefused => 401,
            Self::CustodyNotPermitted => 403,
            Self::CustodyQuotaExceeded => 422,
            Self::DocumentPolicyUnknown => 422,
            Self::DocumentVersionNotReleasable => 409,
            Self::DocumentContentTypeNotAllowed => 422,
            Self::DocumentTooLarge => 422,
            Self::IdempotencyExpired => 410,
            Self::IdempotencyKeyReused => 409,
            Self::ProfileNotAuthorized => 403,
            Self::RequestBodyTooLarge => 413,
            Self::RequestInvalid => 400,
            Self::RequestMethodNotAllowed => 405,
            Self::RequestNotFound => 404,
            Self::RequestUnprocessable => 422,
            Self::RequestUnsupportedMediaType => 415,
            Self::ResourceNotFound => 404,
            Self::ServiceUnavailable => 503,
            Self::UploadContentTypeMismatch => 422,
            Self::UploadDigestMismatch => 422,
            Self::UploadExpired => 410,
            Self::UploadFinalized => 409,
            Self::UploadLengthMismatch => 422,
        }
    }

    /// The fixed title. It names the problem and never a value.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => "Authentication refused",
            Self::CustodyNotPermitted => "Custody not permitted",
            Self::CustodyQuotaExceeded => "Custody quota exceeded",
            Self::DocumentPolicyUnknown => "Document policy unknown",
            Self::DocumentVersionNotReleasable => "Document version not releasable",
            Self::DocumentContentTypeNotAllowed => "Content type not allowed",
            Self::DocumentTooLarge => "Document too large",
            Self::IdempotencyExpired => "Idempotency window expired",
            Self::IdempotencyKeyReused => "Idempotency key reused",
            Self::ProfileNotAuthorized => "Profile not authorized",
            Self::RequestBodyTooLarge => "Payload too large",
            Self::RequestInvalid => "Request invalid",
            Self::RequestMethodNotAllowed => "Method not allowed",
            Self::RequestNotFound => "Not found",
            Self::RequestUnprocessable => "Request unprocessable",
            Self::RequestUnsupportedMediaType => "Unsupported media type",
            Self::ResourceNotFound => "Not found",
            Self::ServiceUnavailable => "Document Store unavailable",
            Self::UploadContentTypeMismatch => "Content type mismatch",
            Self::UploadDigestMismatch => "Digest mismatch",
            Self::UploadExpired => "Upload expired",
            Self::UploadFinalized => "Upload finalized",
            Self::UploadLengthMismatch => "Length mismatch",
        }
    }

    /// The fixed remediation sentence, value-free like the title.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => {
                "The bearer credential is missing, invalid, or expired. Sign in again."
            }
            Self::CustodyNotPermitted => "The caller's access profile may not place a document in this custody, or the request names an issuing institution other than the profile's.",
            Self::CustodyQuotaExceeded => "The upload would exceed the bytes this custodian may hold under the policy.",
            Self::DocumentPolicyUnknown => "The request names a document policy this deployment does not hold.",
            Self::DocumentVersionNotReleasable => "The document version is not ready for release. Read its status and try again once it is ready.",
            Self::DocumentContentTypeNotAllowed => "The declared media type is not one the document policy allows.",
            Self::DocumentTooLarge => "The declared length exceeds the document policy maximum.",
            Self::IdempotencyExpired => {
                "The stored response for this idempotency key has expired. Reconcile the original submission before choosing a new key."
            }
            Self::IdempotencyKeyReused => {
                "This idempotency key was used for a different request."
            }
            Self::ProfileNotAuthorized => "The caller's access profile does not permit this operation.",
            Self::RequestBodyTooLarge => "The request body exceeds the accepted size.",
            Self::RequestInvalid => "The request could not be read as a Document Store request.",
            Self::RequestMethodNotAllowed => "The route exists but not for this method.",
            Self::RequestNotFound => "The requested route does not exist.",
            Self::RequestUnprocessable => "The request body could not be processed.",
            Self::RequestUnsupportedMediaType => "The request body is not JSON.",
            Self::ResourceNotFound => "The requested resource does not exist or is not available to the caller.",
            Self::ServiceUnavailable => {
                "The Document Store is unavailable. Try again after the service recovers."
            }
            Self::UploadContentTypeMismatch => "The content type differs from the media type the upload reserved.",
            Self::UploadDigestMismatch => "The content does not match the expected digest. Nothing was kept; send the reserved content again.",
            Self::UploadExpired => "The upload reservation has expired. Reserve a new upload.",
            Self::UploadFinalized => "The upload already holds other content and cannot be replaced.",
            Self::UploadLengthMismatch => "The content length differs from the reserved length. Nothing was kept; send the reserved content again.",
        }
    }
}

/// Expand a dotted problem code into its full problem type URI.
#[must_use]
pub fn type_uri(code: &str) -> String {
    format!("{}{}", DOCUMENTS_PROBLEM_TYPE_BASE, code.replace('.', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vocabulary_is_complete_and_closed() {
        assert_eq!(ProblemCode::ALL.len(), 23);
        for code in ProblemCode::ALL {
            assert_eq!(ProblemCode::from_code(code.code()), Some(*code));
        }
        assert_eq!(ProblemCode::from_code("authorization.refused"), None);
        assert_eq!(ProblemCode::from_code("request.unknown"), None);
        assert_eq!(ProblemCode::from_code(""), None);
    }

    #[test]
    fn codes_are_listed_in_code_string_order() {
        let codes: Vec<&str> = ProblemCode::ALL.iter().map(|code| code.code()).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        assert_eq!(codes, sorted);
    }

    #[test]
    fn codes_are_family_dot_kebab_case() {
        for code in ProblemCode::ALL {
            let (family, name) = code.code().split_once('.').expect("a family and a name");
            for part in [family, name] {
                assert!(!part.is_empty(), "{}", code.code());
                assert!(
                    part.bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
                    "{}",
                    code.code()
                );
            }
        }
    }

    #[test]
    fn type_uris_expand_dots_into_path_segments() {
        assert_eq!(
            type_uri(REQUEST_NOT_FOUND_PROBLEM),
            format!("{DOCUMENTS_PROBLEM_TYPE_BASE}request/not-found")
        );
        assert_eq!(
            type_uri(SERVICE_UNAVAILABLE_PROBLEM),
            format!("{DOCUMENTS_PROBLEM_TYPE_BASE}service/unavailable")
        );
    }

    #[test]
    fn every_code_pins_a_title_and_detail() {
        for code in ProblemCode::ALL {
            assert!(!code.title().is_empty(), "{}", code.code());
            assert!(!code.detail().is_empty(), "{}", code.code());
        }
    }

    /// The request-edge family pins Casework's, Scheduling's, and
    /// Messaging's statuses, so the runtime's edge and every client agree on
    /// what a rejected request looks like.
    #[test]
    fn the_request_edge_family_pins_the_sibling_statuses() {
        assert_eq!(ProblemCode::RequestInvalid.http_status(), 400);
        assert_eq!(ProblemCode::RequestNotFound.http_status(), 404);
        assert_eq!(ProblemCode::RequestMethodNotAllowed.http_status(), 405);
        assert_eq!(ProblemCode::RequestBodyTooLarge.http_status(), 413);
        assert_eq!(ProblemCode::RequestUnsupportedMediaType.http_status(), 415);
        assert_eq!(ProblemCode::RequestUnprocessable.http_status(), 422);
        assert_eq!(ProblemCode::ServiceUnavailable.http_status(), 503);
    }

    /// The upload and release refusals pin the statuses the deposit design
    /// settled, so a client can branch on the status alone.
    #[test]
    fn the_upload_and_release_refusals_pin_their_statuses() {
        for (code, status) in [
            (ProblemCode::CustodyQuotaExceeded, 422),
            (ProblemCode::DocumentPolicyUnknown, 422),
            (ProblemCode::DocumentVersionNotReleasable, 409),
            (ProblemCode::DocumentContentTypeNotAllowed, 422),
            (ProblemCode::DocumentTooLarge, 422),
            (ProblemCode::UploadContentTypeMismatch, 422),
            (ProblemCode::UploadDigestMismatch, 422),
            (ProblemCode::UploadExpired, 410),
            (ProblemCode::UploadFinalized, 409),
            (ProblemCode::UploadLengthMismatch, 422),
        ] {
            assert_eq!(code.http_status(), status, "{}", code.code());
        }
    }

    /// The access refusals pin the statuses the sibling products answer
    /// with, and the idempotency family pins Messaging's.
    #[test]
    fn the_access_and_idempotency_refusals_pin_their_statuses() {
        for (code, status) in [
            (ProblemCode::AuthenticationRefused, 401),
            (ProblemCode::CustodyNotPermitted, 403),
            (ProblemCode::IdempotencyExpired, 410),
            (ProblemCode::IdempotencyKeyReused, 409),
            (ProblemCode::ProfileNotAuthorized, 403),
            (ProblemCode::ResourceNotFound, 404),
        ] {
            assert_eq!(code.http_status(), status, "{}", code.code());
        }
    }
}
