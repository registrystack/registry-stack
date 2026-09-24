// SPDX-License-Identifier: Apache-2.0

//! The closed problem vocabulary of Registry Messaging.
//!
//! The vocabulary is closed on purpose: a caller can enumerate every problem
//! this product can ever return, and a problem code outside this list is a
//! defect, not a compatibility event. A code joins the list in the same change
//! that first returns it. `authorization.refused` is deliberately absent: it
//! is an audit reason family used by other Registry Stack products, and audit
//! reasons and problem codes must not be conflated. The authorization
//! refusals callers see here are `authentication.refused`,
//! `operation.not-authorized`, and `profile.not-authorized`.
//!
//! `message.not-visible` answers every read of a message the caller may not
//! see, whether or not the message exists, so the status route is never an
//! existence oracle.
//!
//! The `request.*` family carries the request-edge rejections (a route that
//! does not exist, a method the route refuses, a body too large or not JSON)
//! under this product's own prefix, exactly as Casework and Scheduling do: no
//! shared platform problem prefix exists in the Registry Stack catalog.

use crate::naming::MESSAGING_PROBLEM_TYPE_BASE;

pub const AUTHENTICATION_REFUSED_PROBLEM: &str = "authentication.refused";
pub const IDEMPOTENCY_EXPIRED_PROBLEM: &str = "idempotency.expired";
pub const IDEMPOTENCY_KEY_REUSED_PROBLEM: &str = "idempotency.key-reused";
pub const MESSAGE_NOT_VISIBLE_PROBLEM: &str = "message.not-visible";
pub const OPERATION_NOT_AUTHORIZED_PROBLEM: &str = "operation.not-authorized";
pub const PROFILE_NOT_AUTHORIZED_PROBLEM: &str = "profile.not-authorized";
pub const REQUEST_BODY_TOO_LARGE_PROBLEM: &str = "request.body-too-large";
pub const REQUEST_INVALID_PROBLEM: &str = "request.invalid";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const SERVICE_UNAVAILABLE_PROBLEM: &str = "service.unavailable";

/// Every problem code Registry Messaging can return, in code-string order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProblemCode {
    AuthenticationRefused,
    IdempotencyExpired,
    IdempotencyKeyReused,
    MessageNotVisible,
    OperationNotAuthorized,
    ProfileNotAuthorized,
    RequestBodyTooLarge,
    RequestInvalid,
    RequestMethodNotAllowed,
    RequestNotFound,
    RequestUnprocessable,
    RequestUnsupportedMediaType,
    ServiceUnavailable,
}

impl ProblemCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AuthenticationRefused,
        Self::IdempotencyExpired,
        Self::IdempotencyKeyReused,
        Self::MessageNotVisible,
        Self::OperationNotAuthorized,
        Self::ProfileNotAuthorized,
        Self::RequestBodyTooLarge,
        Self::RequestInvalid,
        Self::RequestMethodNotAllowed,
        Self::RequestNotFound,
        Self::RequestUnprocessable,
        Self::RequestUnsupportedMediaType,
        Self::ServiceUnavailable,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => AUTHENTICATION_REFUSED_PROBLEM,
            Self::IdempotencyExpired => IDEMPOTENCY_EXPIRED_PROBLEM,
            Self::IdempotencyKeyReused => IDEMPOTENCY_KEY_REUSED_PROBLEM,
            Self::MessageNotVisible => MESSAGE_NOT_VISIBLE_PROBLEM,
            Self::OperationNotAuthorized => OPERATION_NOT_AUTHORIZED_PROBLEM,
            Self::ProfileNotAuthorized => PROFILE_NOT_AUTHORIZED_PROBLEM,
            Self::RequestBodyTooLarge => REQUEST_BODY_TOO_LARGE_PROBLEM,
            Self::RequestInvalid => REQUEST_INVALID_PROBLEM,
            Self::RequestMethodNotAllowed => REQUEST_METHOD_NOT_ALLOWED_PROBLEM,
            Self::RequestNotFound => REQUEST_NOT_FOUND_PROBLEM,
            Self::RequestUnprocessable => REQUEST_UNPROCESSABLE_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::ServiceUnavailable => SERVICE_UNAVAILABLE_PROBLEM,
        }
    }

    /// Resolve a code string back to its variant, or `None` for any string
    /// outside the closed vocabulary.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code() == code)
    }

    /// The HTTP status this problem answers with. The map lives here, beside
    /// the vocabulary it belongs to, so the runtime emits and every client
    /// validates one pinned status per code.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::RequestInvalid => 400,
            Self::AuthenticationRefused => 401,
            Self::OperationNotAuthorized | Self::ProfileNotAuthorized => 403,
            Self::MessageNotVisible | Self::RequestNotFound => 404,
            Self::RequestMethodNotAllowed => 405,
            Self::IdempotencyKeyReused => 409,
            Self::IdempotencyExpired => 410,
            Self::RequestBodyTooLarge => 413,
            Self::RequestUnsupportedMediaType => 415,
            Self::RequestUnprocessable => 422,
            Self::ServiceUnavailable => 503,
        }
    }

    /// The fixed, value-free problem title. Titles and details carry no
    /// identifiers, recipients, or message content.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => "Authentication refused",
            Self::IdempotencyExpired => "Idempotency window expired",
            Self::IdempotencyKeyReused => "Idempotency key reused",
            Self::MessageNotVisible => "Message not visible",
            Self::OperationNotAuthorized => "Operation not authorized",
            Self::ProfileNotAuthorized => "Profile not authorized",
            Self::RequestBodyTooLarge => "Payload too large",
            Self::RequestInvalid => "Request invalid",
            Self::RequestMethodNotAllowed => "Method not allowed",
            Self::RequestNotFound => "Route not found",
            Self::RequestUnprocessable => "Request unprocessable",
            Self::RequestUnsupportedMediaType => "Unsupported media type",
            Self::ServiceUnavailable => "Messaging service unavailable",
        }
    }

    /// The fixed remediation sentence, value-free like the title.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => {
                "The bearer credential is missing, invalid, or expired. Sign in again."
            }
            Self::IdempotencyExpired => {
                "The stored response for this idempotency key has expired. Reconcile the original submission before choosing a new key."
            }
            Self::IdempotencyKeyReused => {
                "This idempotency key was used for a different request."
            }
            Self::MessageNotVisible => {
                "No message with this identifier is visible to the caller."
            }
            Self::OperationNotAuthorized => {
                "Your Messaging access profile does not allow this operation."
            }
            Self::ProfileNotAuthorized => {
                "No Messaging access profile authorizes this caller for this request."
            }
            Self::RequestBodyTooLarge => "The request body exceeds the accepted size.",
            Self::RequestInvalid => "The request could not be read as a Messaging request.",
            Self::RequestMethodNotAllowed => "The route exists but not for this method.",
            Self::RequestNotFound => "The requested route does not exist.",
            Self::RequestUnprocessable => "The request body could not be processed.",
            Self::RequestUnsupportedMediaType => "The request body is not JSON.",
            Self::ServiceUnavailable => {
                "Messaging is unavailable. Try again after the service recovers."
            }
        }
    }
}

/// Expand a dotted problem code into its full problem type URI.
#[must_use]
pub fn type_uri(code: &str) -> String {
    format!("{}{}", MESSAGING_PROBLEM_TYPE_BASE, code.replace('.', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vocabulary_is_complete_and_closed() {
        assert_eq!(ProblemCode::ALL.len(), 13);
        for code in ProblemCode::ALL {
            assert_eq!(ProblemCode::from_code(code.code()), Some(*code));
        }
        assert_eq!(ProblemCode::from_code("authorization.refused"), None);
        assert_eq!(ProblemCode::from_code("message.visible"), None);
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
            type_uri(MESSAGE_NOT_VISIBLE_PROBLEM),
            format!("{MESSAGING_PROBLEM_TYPE_BASE}message/not-visible")
        );
        assert_eq!(
            type_uri(IDEMPOTENCY_KEY_REUSED_PROBLEM),
            format!("{MESSAGING_PROBLEM_TYPE_BASE}idempotency/key-reused")
        );
    }

    #[test]
    fn every_code_pins_a_status_title_and_detail() {
        let statuses = [400, 401, 403, 404, 405, 409, 410, 413, 415, 422, 503];
        for code in ProblemCode::ALL {
            assert!(
                statuses.contains(&code.http_status()),
                "{}: {}",
                code.code(),
                code.http_status()
            );
            assert!(!code.title().is_empty(), "{}", code.code());
            assert!(!code.detail().is_empty(), "{}", code.code());
        }
    }

    /// The request-edge family pins Casework's and Scheduling's statuses, so
    /// the runtime's edge and every client agree on what a rejected request
    /// looks like.
    #[test]
    fn the_request_edge_family_pins_the_sibling_statuses() {
        assert_eq!(ProblemCode::RequestInvalid.http_status(), 400);
        assert_eq!(ProblemCode::RequestNotFound.http_status(), 404);
        assert_eq!(ProblemCode::RequestMethodNotAllowed.http_status(), 405);
        assert_eq!(ProblemCode::RequestBodyTooLarge.http_status(), 413);
        assert_eq!(ProblemCode::RequestUnsupportedMediaType.http_status(), 415);
        assert_eq!(ProblemCode::RequestUnprocessable.http_status(), 422);
    }

    /// A message the caller may not see answers 404, not 403, so the status
    /// route never confirms that another caller's message exists.
    #[test]
    fn an_invisible_message_answers_not_found() {
        assert_eq!(ProblemCode::MessageNotVisible.http_status(), 404);
        assert_eq!(ProblemCode::AuthenticationRefused.http_status(), 401);
        assert_eq!(ProblemCode::IdempotencyKeyReused.http_status(), 409);
        assert_eq!(ProblemCode::IdempotencyExpired.http_status(), 410);
        assert_eq!(ProblemCode::ServiceUnavailable.http_status(), 503);
    }
}
