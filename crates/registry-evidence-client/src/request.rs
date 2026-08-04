//! The Evidence request body, exactly as the frozen Version 1 wire contract
//! states it.
//!
//! These types are owned here rather than imported from the runtime: a relying
//! party links this crate and the portable verifier, never the service runtime.
//! The integration suite proves the two agree by driving a real deployment.
//!
//! `holderKey` is deliberately absent. It is meaningful only for the SD-JWT VC
//! response format, which this client does not request.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

/// One complete request body.
///
/// `Debug` is redacted: the selector values are the caller's own identifying
/// input and must not reach a log line, a panic message, or a snapshot.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRequestBody {
    pub request_nonce: String,
    pub requirement: String,
    pub purpose: String,
    /// Unordered role set encoded as an array. Each configured role appears
    /// exactly once; array position carries no meaning.
    pub subjects: Vec<RequestedSubject>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RequestedSubject {
    pub role: String,
    pub selector: RequestedSelector,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RequestedSelector {
    pub profile: String,
    /// Values are present only for a selector profile whose values originate
    /// in the request. A profile that reads the authenticated context or an
    /// authenticated grant must carry none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<BTreeMap<String, SelectorValue>>,
}

/// The three scalar shapes a selector value may take.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SelectorValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl From<&str> for SelectorValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for SelectorValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<i64> for SelectorValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<bool> for SelectorValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

macro_rules! redacted_debug {
    ($($type_name:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $type_name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter
                        .debug_struct(stringify!($type_name))
                        .finish_non_exhaustive()
                }
            }
        )+
    };
}

redacted_debug!(
    EvidenceRequestBody,
    RequestedSubject,
    RequestedSelector,
    SelectorValue,
);

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> EvidenceRequestBody {
        EvidenceRequestBody {
            request_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            requirement: "urn:example:client:requirement:status:v1".to_owned(),
            purpose: "example-decision".to_owned(),
            subjects: vec![RequestedSubject {
                role: "subject".to_owned(),
                selector: RequestedSelector {
                    profile: "record-lookup-v1".to_owned(),
                    values: Some(BTreeMap::from([
                        (
                            "record_reference".to_owned(),
                            SelectorValue::from("synthetic-record-001"),
                        ),
                        ("sequence".to_owned(), SelectorValue::from(7_i64)),
                        ("confirmed".to_owned(), SelectorValue::from(true)),
                    ])),
                },
            }],
        }
    }

    /// The wire form is a frozen contract, so this is a golden serialization,
    /// including member names, member order, and the omission of `holderKey`.
    #[test]
    fn the_request_body_serializes_to_the_frozen_wire_form() {
        assert_eq!(
            serde_json::to_string(&body()).expect("the request body serializes"),
            concat!(
                r#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","#,
                r#""requirement":"urn:example:client:requirement:status:v1","#,
                r#""purpose":"example-decision","#,
                r#""subjects":[{"role":"subject","selector":{"profile":"record-lookup-v1","#,
                r#""values":{"confirmed":true,"record_reference":"synthetic-record-001","sequence":7}}}]}"#,
            )
        );
    }

    #[test]
    fn a_selector_without_request_values_omits_the_member() {
        let mut body = body();
        body.subjects[0].selector.values = None;
        let rendered = serde_json::to_string(&body).expect("the request body serializes");
        assert!(!rendered.contains("values"), "{rendered}");
    }

    #[test]
    fn debug_output_never_carries_selector_values() {
        let rendered = format!("{:?}", body());
        assert!(!rendered.contains("synthetic-record-001"), "{rendered}");
        assert!(!rendered.contains("record-lookup-v1"), "{rendered}");
    }
}
