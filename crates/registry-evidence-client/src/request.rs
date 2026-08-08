//! The Evidence request body, exactly as the frozen Version 1 wire contract
//! states it.
//!
//! These types are owned here rather than imported from the runtime: a relying
//! party links this crate and the portable verifier, never the service runtime.
//! The integration suite proves the two agree by driving a real deployment.
//!
//! A request may carry holder public keys the caller supplies, and the client
//! forwards them unchanged. They are public JWK material the caller already
//! holds: this crate never holds, generates, derives, or transmits a holder
//! private key, and [`HolderPublicKey`] has no member one could be written
//! into. What a key means to an assertion is the deployment's decision and the
//! portable verifier's to check; nothing about it is decided here.

use std::{collections::BTreeMap, fmt};

use registry_evidence_verifier::model::HolderPublicKey;
use serde::Serialize;

/// One complete request body.
///
/// The wire types are crate-internal: a caller states what it wants in
/// [`crate::EvidenceRequestSpec`], and this is the serialization
/// [`crate::EvidenceClient::prepare`] derives from it. Only
/// [`SelectorValue`] is part of the public surface, because a caller supplies
/// the selector values themselves.
///
/// `Debug` is redacted: the selector values are the caller's own identifying
/// input and must not reach a log line, a panic message, or a snapshot.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvidenceRequestBody {
    pub(crate) request_nonce: String,
    pub(crate) requirement: String,
    pub(crate) purpose: String,
    /// Unordered role set encoded as an array. Each configured role appears
    /// exactly once; array position carries no meaning.
    pub(crate) subjects: Vec<RequestedSubject>,
    /// Ordered holder public keys, present only when the caller supplied at
    /// least one. Unlike `subjects`, array position is meaningful: a batch
    /// answer carries one credential per key, in this order.
    ///
    /// A caller that supplied none leaves the member off the wire entirely
    /// rather than sending an empty array, so the request a caller who has
    /// never heard of holder keys sends is byte-identical to the one this
    /// client sent before the member existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) holder_keys: Option<Vec<HolderPublicKey>>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RequestedSubject {
    pub(crate) role: String,
    pub(crate) selector: RequestedSelector,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RequestedSelector {
    pub(crate) profile: String,
    /// Values are present only for a selector profile whose values originate
    /// in the request. A profile that reads the authenticated context or an
    /// authenticated grant must carry none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) values: Option<BTreeMap<String, SelectorValue>>,
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
            holder_keys: None,
        }
    }

    /// The two coordinates of the P-256 generator point, which is a real point
    /// on the curve and therefore a key the verifier's own acceptance rule
    /// admits. A serialization golden needs fixed bytes, so they are written
    /// out rather than drawn.
    const HOLDER_KEY_X: &str = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
    const HOLDER_KEY_Y: &str = "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU";

    fn holder_key() -> HolderPublicKey {
        HolderPublicKey {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: HOLDER_KEY_X.to_owned(),
            y: HOLDER_KEY_Y.to_owned(),
            alg: Some("ES256".to_owned()),
            kid: Some("holder-key-1".to_owned()),
        }
    }

    /// The wire form is a frozen contract, so this is a golden serialization,
    /// including member names, member order, and the omission of `holderKeys`
    /// by a caller that supplied none. The assertion below is the one that
    /// stood before holder keys existed, unchanged: adding an optional member
    /// must not move a byte of the request every existing caller sends.
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

    /// The second golden: the same body with holder keys present. `holderKeys`
    /// is last, each key keeps the member names and member order the verifier's
    /// own type declares, and an absent optional key member is omitted rather
    /// than sent as null.
    #[test]
    fn the_request_body_serializes_holder_keys_to_the_frozen_wire_form() {
        let mut body = body();
        body.holder_keys = Some(vec![
            holder_key(),
            HolderPublicKey {
                kid: None,
                alg: None,
                ..holder_key()
            },
        ]);

        assert_eq!(
            serde_json::to_string(&body).expect("the request body serializes"),
            concat!(
                r#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","#,
                r#""requirement":"urn:example:client:requirement:status:v1","#,
                r#""purpose":"example-decision","#,
                r#""subjects":[{"role":"subject","selector":{"profile":"record-lookup-v1","#,
                r#""values":{"confirmed":true,"record_reference":"synthetic-record-001","sequence":7}}}],"#,
                r#""holderKeys":[{"kty":"EC","crv":"P-256","#,
                r#""x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","#,
                r#""y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","#,
                r#""alg":"ES256","kid":"holder-key-1"},"#,
                r#"{"kty":"EC","crv":"P-256","#,
                r#""x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","#,
                r#""y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}]}"#,
            )
        );
    }

    /// The wire member is absent, not empty, when the caller supplied no key.
    /// The distinction is the runtime's: it reads an empty array as no keys at
    /// all, so sending one would be a request that says something it does not
    /// mean.
    #[test]
    fn a_request_without_holder_keys_carries_no_holder_key_member() {
        let rendered = serde_json::to_string(&body()).expect("the request body serializes");
        assert!(!rendered.contains("holderKeys"), "{rendered}");
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

    /// A holder key is caller input too. It is public material, but the key
    /// identifier a caller chooses need not be, and a coordinate pair
    /// correlates one request with every other request carrying that key.
    #[test]
    fn debug_output_never_carries_a_holder_key() {
        let mut body = body();
        body.holder_keys = Some(vec![holder_key()]);
        let rendered = format!("{body:?}");
        assert!(!rendered.contains(HOLDER_KEY_X), "{rendered}");
        assert!(!rendered.contains(HOLDER_KEY_Y), "{rendered}");
        assert!(!rendered.contains("holder-key-1"), "{rendered}");
    }

    /// The client accepts a key the deployment would accept, and the rule it
    /// applies is the verifier's own rather than a second opinion written here.
    #[test]
    fn the_golden_holder_key_is_one_the_verifier_accepts() {
        assert!(holder_key().is_acceptable());
    }
}
