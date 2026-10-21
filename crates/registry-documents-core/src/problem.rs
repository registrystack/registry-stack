// SPDX-License-Identifier: Apache-2.0

//! The closed problem vocabulary of the Document Store.
//!
//! The vocabulary is closed on purpose: a caller can enumerate every problem
//! this product can ever return, and a problem code outside this list is a
//! defect, not a compatibility event. A code joins the list in the same change
//! that first returns it, so the list holds only what the runtime answers
//! today: the request-edge rejections and an unavailable service.
//!
//! The `request.*` family carries the request-edge rejections (a route that
//! does not exist, a method the route refuses, a body too large or not JSON)
//! under this product's own prefix, exactly as Casework, Scheduling, and
//! Messaging do: no shared platform problem prefix exists in the Registry
//! Stack catalog.

use crate::naming::DOCUMENTS_PROBLEM_TYPE_BASE;

pub const REQUEST_BODY_TOO_LARGE_PROBLEM: &str = "request.body-too-large";
pub const REQUEST_INVALID_PROBLEM: &str = "request.invalid";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const SERVICE_UNAVAILABLE_PROBLEM: &str = "service.unavailable";

/// Every problem code the Document Store can return, in code-string order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProblemCode {
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
            Self::RequestBodyTooLarge => REQUEST_BODY_TOO_LARGE_PROBLEM,
            Self::RequestInvalid => REQUEST_INVALID_PROBLEM,
            Self::RequestMethodNotAllowed => REQUEST_METHOD_NOT_ALLOWED_PROBLEM,
            Self::RequestNotFound => REQUEST_NOT_FOUND_PROBLEM,
            Self::RequestUnprocessable => REQUEST_UNPROCESSABLE_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::ServiceUnavailable => SERVICE_UNAVAILABLE_PROBLEM,
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
            Self::RequestInvalid => 400,
            Self::RequestNotFound => 404,
            Self::RequestMethodNotAllowed => 405,
            Self::RequestBodyTooLarge => 413,
            Self::RequestUnsupportedMediaType => 415,
            Self::RequestUnprocessable => 422,
            Self::ServiceUnavailable => 503,
        }
    }

    /// The fixed title. It names the problem and never a value.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::RequestBodyTooLarge => "Payload too large",
            Self::RequestInvalid => "Request invalid",
            Self::RequestMethodNotAllowed => "Method not allowed",
            Self::RequestNotFound => "Not found",
            Self::RequestUnprocessable => "Request unprocessable",
            Self::RequestUnsupportedMediaType => "Unsupported media type",
            Self::ServiceUnavailable => "Document Store unavailable",
        }
    }

    /// The fixed remediation sentence, value-free like the title.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::RequestBodyTooLarge => "The request body exceeds the accepted size.",
            Self::RequestInvalid => "The request could not be read as a Document Store request.",
            Self::RequestMethodNotAllowed => "The route exists but not for this method.",
            Self::RequestNotFound => "The requested route does not exist.",
            Self::RequestUnprocessable => "The request body could not be processed.",
            Self::RequestUnsupportedMediaType => "The request body is not JSON.",
            Self::ServiceUnavailable => {
                "The Document Store is unavailable. Try again after the service recovers."
            }
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
        assert_eq!(ProblemCode::ALL.len(), 7);
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
}
