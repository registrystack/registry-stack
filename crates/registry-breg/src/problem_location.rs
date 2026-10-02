// SPDX-License-Identifier: Apache-2.0

//! The closed locations a record or query refusal may name in `fieldPath`.
//!
//! A location is a fixed envelope member (`/data`, `/items/3`,
//! `/items/3/patch/0/path`, `/0/path` in a JSON Patch document), a compiled
//! API name the caller's grant already admits (`/data/householdCode`), or a
//! fixed query parameter or header name. A caller-supplied name that is
//! unknown or withheld is never echoed: the location stops at its container,
//! so an unknown and a withheld name produce the same problem. Every pointer
//! is built here, escaped as one RFC 6901 segment, and bounded by the problem
//! schema's 256-character limit.

use std::fmt::Write as _;

/// The problem schema's bound on `fieldPath`.
pub const MAX_FIELD_PATH_CHARS: usize = 256;

/// The fixed query parameter names a `query.invalid` refusal may name.
pub use crate::query::QUERY_PARAMETERS;

/// Fixed query locations on the separate statistical dataset surface.
pub const STATISTICS_QUERY_PARAMETERS: &[&str] = &["from", "to", "status"];

/// The header a `request.invalid` refusal names when it is missing or
/// malformed.
pub const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// The header a batch `request.invalid` refusal names when a caller sends it:
/// each batch item carries its own `ifMatch` instead.
pub const IF_MATCH_HEADER: &str = "If-Match";

/// One member of a JSON Patch operation object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchMember {
    Op,
    Path,
    Value,
}

impl PatchMember {
    const fn name(self) -> &'static str {
        match self {
            Self::Op => "op",
            Self::Path => "path",
            Self::Value => "value",
        }
    }
}

/// One fixed member of a batch item object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchItemMember {
    Operation,
    RecordId,
    IfMatch,
    Data,
    Patch,
}

impl BatchItemMember {
    const fn name(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::RecordId => "recordId",
            Self::IfMatch => "ifMatch",
            Self::Data => "data",
            Self::Patch => "patch",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    /// Relative to a create body or a batch create item: `/data...`.
    Record,
    /// Relative to a JSON Patch document: `/<index>...`.
    Patch,
    /// Relative to a batch body: `/items...` or `/changeContext`.
    Batch,
}

/// A validated location inside a record write body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestLocation {
    pointer: String,
    scope: Scope,
}

impl RequestLocation {
    /// The `data` member of a create body.
    #[must_use]
    pub fn data() -> Self {
        Self {
            pointer: "/data".to_owned(),
            scope: Scope::Record,
        }
    }

    /// One admitted field of a create body. The caller passes only an API
    /// name the grant admits; an over-long name falls back to `/data`.
    #[must_use]
    pub fn data_field(api_name: &str) -> Self {
        let pointer = format!("/data/{}", escape_segment(api_name));
        if pointer.chars().count() > MAX_FIELD_PATH_CHARS {
            return Self::data();
        }
        Self {
            pointer,
            scope: Scope::Record,
        }
    }

    /// One operation of a JSON Patch document, optionally one of its members.
    #[must_use]
    pub fn patch_operation(index: usize, member: Option<PatchMember>) -> Self {
        let mut pointer = format!("/{index}");
        if let Some(member) = member {
            let _ = write!(pointer, "/{}", member.name());
        }
        Self {
            pointer,
            scope: Scope::Patch,
        }
    }

    /// The `items` member of a batch body.
    #[must_use]
    pub fn batch_items() -> Self {
        Self {
            pointer: "/items".to_owned(),
            scope: Scope::Batch,
        }
    }

    /// The `changeContext` member of a batch body.
    #[must_use]
    pub fn batch_change_context() -> Self {
        Self {
            pointer: "/changeContext".to_owned(),
            scope: Scope::Batch,
        }
    }

    /// One batch item, optionally one of its fixed members.
    #[must_use]
    pub fn batch_item(index: usize, member: Option<BatchItemMember>) -> Self {
        let mut pointer = format!("/items/{index}");
        if let Some(member) = member {
            let _ = write!(pointer, "/{}", member.name());
        }
        Self {
            pointer,
            scope: Scope::Batch,
        }
    }

    /// Place a create-body or patch-document location inside batch item
    /// `index`. A batch-level location is already absolute and is kept.
    #[must_use]
    pub fn in_batch_item(self, index: usize) -> Self {
        let pointer = match self.scope {
            Scope::Record => format!("/items/{index}{}", self.pointer),
            Scope::Patch => format!("/items/{index}/patch{}", self.pointer),
            Scope::Batch => return self,
        };
        if pointer.chars().count() > MAX_FIELD_PATH_CHARS {
            return Self::batch_item(index, None);
        }
        Self {
            pointer,
            scope: Scope::Batch,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pointer
    }
}

fn escape_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

/// Whether `path` is one of the closed record write locations above.
#[must_use]
pub fn is_record_request_location(path: &str) -> bool {
    if path.chars().count() > MAX_FIELD_PATH_CHARS {
        return false;
    }
    if matches!(path, "/items" | "/changeContext") {
        return true;
    }
    let segments = match path.strip_prefix('/') {
        Some(rest) => rest.split('/').collect::<Vec<_>>(),
        None => return false,
    };
    match segments.as_slice() {
        ["items", index, rest @ ..] if valid_index(index) => match rest {
            [] => true,
            ["operation" | "recordId" | "ifMatch" | "patch"] => true,
            ["patch", operation, member @ ..] => valid_patch_operation(operation, member),
            data => valid_record_data(data),
        },
        [operation, member @ ..] if valid_index(operation) => {
            valid_patch_operation(operation, member)
        }
        data => valid_record_data(data),
    }
}

/// Whether `path` names a fixed query parameter.
#[must_use]
pub fn is_query_parameter_location(path: &str) -> bool {
    QUERY_PARAMETERS.contains(&path) || STATISTICS_QUERY_PARAMETERS.contains(&path)
}

fn valid_record_data(segments: &[&str]) -> bool {
    match segments {
        ["data"] => true,
        ["data", name] => valid_api_name_segment(name),
        _ => false,
    }
}

fn valid_patch_operation(index: &str, member: &[&str]) -> bool {
    valid_index(index) && matches!(member, [] | ["op" | "path" | "value"])
}

fn valid_index(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 5
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn valid_api_name_segment(value: &str) -> bool {
    crate::logical_names::valid_api_name(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_render_bounded_escaped_pointers() {
        assert_eq!(RequestLocation::data().as_str(), "/data");
        assert_eq!(
            RequestLocation::data_field("householdCode").as_str(),
            "/data/householdCode"
        );
        assert_eq!(
            RequestLocation::data_field("a/b~c").as_str(),
            "/data/a~1b~0c"
        );
        assert_eq!(
            RequestLocation::data_field(&"x".repeat(300)).as_str(),
            "/data"
        );
        assert_eq!(
            RequestLocation::patch_operation(0, Some(PatchMember::Path)).as_str(),
            "/0/path"
        );
        assert_eq!(
            RequestLocation::patch_operation(2, Some(PatchMember::Value))
                .in_batch_item(3)
                .as_str(),
            "/items/3/patch/2/value"
        );
        assert_eq!(
            RequestLocation::data_field("householdCode")
                .in_batch_item(1)
                .as_str(),
            "/items/1/data/householdCode"
        );
        assert_eq!(
            RequestLocation::batch_item(4, Some(BatchItemMember::IfMatch))
                .in_batch_item(9)
                .as_str(),
            "/items/4/ifMatch"
        );
    }

    #[test]
    fn the_closed_grammar_admits_only_the_rendered_forms() {
        for path in [
            "/data",
            "/data/householdCode",
            "/0",
            "/12/op",
            "/0/path",
            "/0/value",
            "/items",
            "/changeContext",
            "/items/3",
            "/items/3/operation",
            "/items/3/recordId",
            "/items/3/ifMatch",
            "/items/3/patch",
            "/items/3/data",
            "/items/3/data/householdCode",
            "/items/3/patch/0",
            "/items/3/patch/0/path",
        ] {
            assert!(is_record_request_location(path), "{path}");
        }
        for path in [
            "",
            "data",
            "/data/household-code",
            "/data/a/b",
            "/01/path",
            "/0/from",
            "/items/x",
            "/items/3/other",
            "/items/3/data/a/b",
            "/items/3/patch/0/from",
            "/input/name",
        ] {
            assert!(!is_record_request_location(path), "{path}");
        }
        assert!(is_query_parameter_location("$select"));
        assert!(!is_query_parameter_location("$expand"));
        assert!(!is_query_parameter_location("select"));
    }
}
