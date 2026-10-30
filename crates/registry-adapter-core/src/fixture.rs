// SPDX-License-Identifier: Apache-2.0

//! The fixture suite: the facade request, the ordered upstream exchanges
//! it drives, and the facade response or problem it must produce, with
//! provenance (`products/adapter/CONCEPT.md` sections 6 and 13.3,
//! G-FIXTURES).
//!
//! The fixture declares which sends it intercepts, by endpoint id and by
//! token endpoint (CONCEPT 10.2: fixture replay intercepts the token
//! endpoint like any other send), so packs are replayable without a
//! credential. A route never declares its own test intercepts. Replayed
//! sends are answered in the order the entry recorded them; the matcher
//! here is the pure half the runtime engine drives
//! (`camel-4.23.0:core/camel-core-engine/src/main/docs/modules/eips/pages/intercept.adoc`:
//! `interceptSendToEndpoint` intercepts an exchange about to be sent to
//! the endpoint, and `skipSendToOriginalEndpoint` skips the real send).

use std::collections::BTreeMap;

use registry_platform_yaml::{BoundedU32, ExternalId, ForeignValue, LocalId};
use serde::{Deserialize, Deserializer, Serialize};

/// An HTTP status code, 100 through 599 (CFG-QTY-4).
pub(crate) type HttpStatus = BoundedU32<100, 599>;

/// The headers one recorded message carried, by name. A sorted map, so a
/// recorded message renders one way.
pub type RecordedHeaders = BTreeMap<String, String>;

/// A recorded body: a foreign JSON tree under the platform's own value
/// rules (CFG-EMBED-2), so JSON `null` is a body and nested nulls are
/// values, distinct from an absent body (G-FIXTURES). Deserialization
/// goes through [`ForeignValue`]: that is the one typed subtree the
/// reader opens its foreign region for.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecordedBody(pub serde_json::Value);

impl RecordedBody {
    /// The recorded tree.
    #[must_use]
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RecordedBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ForeignValue::deserialize(deserializer).map(|foreign| RecordedBody(foreign.into_value()))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for RecordedBody {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("RecordedBody")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <serde_json::Value>::json_schema(generator)
    }
}

/// Deserialize one recorded body member so a present `null` stays a body
/// under any reader: serde's own `Option` mapping folds a JSON `null`
/// into an absent body before the recorded rules run, and the fixture
/// keeps the three states apart (G-FIXTURES). An absent member never
/// reaches here; `#[serde(default)]` supplies it.
fn deserialize_recorded_body<'de, D>(deserializer: D) -> Result<Option<RecordedBody>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RecordedBodyVisitor;
    impl<'de> serde::de::Visitor<'de> for RecordedBodyVisitor {
        type Value = Option<RecordedBody>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a recorded body: null or a JSON value")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Some(RecordedBody(serde_json::Value::Null)))
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Some(RecordedBody(serde_json::Value::Null)))
        }
        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            RecordedBody::deserialize(deserializer).map(Some)
        }
    }
    deserializer.deserialize_option(RecordedBodyVisitor)
}

/// Where a fixture's recording came from
/// (`products/adapter/CONCEPT.md` section 13.3): captured from a live
/// system, or documented as an authored reconstruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FixtureProvenance {
    /// Recorded from the named live system.
    Captured {
        /// Where the recording came from, for review.
        reference: String,
    },
    /// Authored from the source system's documented behavior.
    Documented {
        /// The documentation the reconstruction follows, for review.
        reference: String,
    },
}

/// One declared intercept. Fixture replay intercepts `http` and `graphql`
/// sends and the token endpoint of an OAuth2 kind; nothing else is
/// interceptable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Intercept {
    /// Intercept every send to the named endpoint.
    Endpoint {
        /// The pack endpoint id whose sends replay from the fixtures.
        endpoint: ExternalId,
    },
    /// Intercept the token requests of the named endpoint's OAuth2 kind
    /// (`products/adapter/CONCEPT.md` section 10.2).
    TokenEndpoint {
        /// The pack endpoint whose token requests replay from the
        /// fixtures.
        endpoint: ExternalId,
    },
}

registry_platform_yaml::tagged_union!(FixtureProvenance, tag = "type");
crate::model::serialize_tagged_union!(FixtureProvenance, tag = "type");
registry_platform_yaml::tagged_union!(Intercept, tag = "type");
crate::model::serialize_tagged_union!(Intercept, tag = "type");

/// What the facade must answer one entry with: a recorded response, or a
/// problem named by class and code (G-FIXTURES). A problem expectation
/// carries no body: the profile's problem envelope owns that shape, and
/// the declared problem owns the status.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ExpectedFacade {
    /// The facade answers with this recorded response.
    Response {
        /// The status the facade answers with.
        status: HttpStatus,
        /// The response headers the facade answers with.
        #[serde(default, skip_serializing_if = "RecordedHeaders::is_empty")]
        headers: RecordedHeaders,
        /// The response body the facade answers with.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_recorded_body"
        )]
        body: Option<RecordedBody>,
    },
    /// The facade answers with the named problem.
    Problem {
        /// The error class the facade answers with; a declared class or a
        /// class a declared root covers resolves it.
        class: crate::model::ErrorClass,
        /// The declared problem code the facade fills its envelope with.
        code: ExternalId,
    },
}

registry_platform_yaml::tagged_union!(ExpectedFacade, tag = "type");
crate::model::serialize_tagged_union!(ExpectedFacade, tag = "type");

/// One recorded upstream request the fixture replay matches against.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    /// The endpoint the request goes to.
    pub endpoint: ExternalId,
    /// Whether this request is the endpoint's token request (CONCEPT
    /// 10.2); only a token intercept answers it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub token_request: bool,
    /// The request method.
    pub method: crate::model::HttpMethod,
    /// The request path, with any template segments already filled.
    pub path: String,
    /// The encoded query string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// The request headers.
    #[serde(default, skip_serializing_if = "RecordedHeaders::is_empty")]
    pub headers: RecordedHeaders,
    /// The request body: absent, JSON `null`, or a value (G-FIXTURES).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_recorded_body"
    )]
    pub body: Option<RecordedBody>,
}

/// The facade request one entry replays: the operation it exercises, plus
/// the request the deployment receives. The operation is the facade-side
/// primary key of the entry; the profile owns its method.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedFacadeRequest {
    /// The profile operation this entry exercises.
    pub operation: ExternalId,
    /// The request path, with any template segments already filled.
    pub path: String,
    /// The encoded query string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// The request headers.
    #[serde(default, skip_serializing_if = "RecordedHeaders::is_empty")]
    pub headers: RecordedHeaders,
    /// The request body: absent, JSON `null`, or a value (G-FIXTURES).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_recorded_body"
    )]
    pub body: Option<RecordedBody>,
}

/// One recorded upstream reply.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedResponse {
    /// The status the upstream answered with.
    pub status: HttpStatus,
    /// The response headers.
    #[serde(default, skip_serializing_if = "RecordedHeaders::is_empty")]
    pub headers: RecordedHeaders,
    /// The reply body: absent, JSON `null`, or a value (G-FIXTURES).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_recorded_body"
    )]
    pub body: Option<RecordedBody>,
}

/// One recorded upstream exchange: the send the route made and the reply
/// the source gave it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedExchange {
    /// The send the route made.
    pub request: RecordedRequest,
    /// The reply the source gave it.
    pub response: RecordedResponse,
}

/// One fixture entry: the facade request, the upstream exchanges it
/// drives in the order the route makes them, and what the facade must
/// answer (G-FIXTURES, CONCEPT 13.3). At least one exchange is an
/// authoring invariant the checks refuse a suite without.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureEntry {
    /// The facade request this entry replays.
    pub facade_request: RecordedFacadeRequest,
    /// The upstream exchanges, in the order the route makes them.
    pub upstream: Vec<RecordedExchange>,
    /// What the facade must answer.
    pub expected: ExpectedFacade,
}

/// The fixture suite artifact (`AdapterFixture`), authored per pack.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterFixture {
    /// The suite identifier.
    pub id: LocalId,
    /// The pack this suite replays.
    pub pack: ExternalId,
    /// The upstream version the recording reflects.
    pub upstream_version: String,
    /// Where the recording came from.
    pub provenance: FixtureProvenance,
    /// The sends this suite intercepts, by endpoint id and token endpoint.
    /// A route never declares its own test intercepts.
    pub intercepts: Vec<Intercept>,
    /// The recorded exchanges and expectations.
    #[serde(default)]
    pub entries: Vec<FixtureEntry>,
}

/// One send the replaying engine is about to make, in the matcher's own
/// terms: the runtime fills it from the exchange it holds. The body is
/// the same three states a recorded body is, so an explicit `null` send
/// matches an explicit `null` recording and neither matches an absent
/// one.
#[derive(Clone, Debug, PartialEq)]
pub struct Send<'a> {
    /// The endpoint the send goes to.
    pub endpoint: &'a str,
    /// Whether the send is the endpoint's token request (CONCEPT 10.2).
    pub token_request: bool,
    /// The send's method.
    pub method: crate::model::HttpMethod,
    /// The send's path, template segments filled.
    pub path: &'a str,
    /// The send's encoded query string.
    pub query: Option<&'a str>,
    /// The send's body: absent, or the JSON tree (where `null` is the
    /// null body).
    pub body: Option<&'a serde_json::Value>,
}

/// Why a send was not answered from the recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayMismatch {
    /// No declared intercept answers sends of this kind to the endpoint.
    NotIntercepted,
    /// Every recorded exchange of the entry is spent.
    Exhausted,
    /// The next recorded exchange carries another method.
    Method,
    /// The next recorded exchange carries another path.
    Path,
    /// The next recorded exchange carries another query string.
    Query,
    /// The next recorded exchange carries another body.
    BodyDigest,
}

/// Whether the suite's intercepts answer a send of this kind to the
/// endpoint: an endpoint intercept answers ordinary sends, a token
/// intercept answers token requests (`products/adapter/CONCEPT.md`
/// section 10.2). Interception is by send, not by route: the endpoint a
/// send names decides, however the route built it
/// (`camel-4.23.0:core/camel-core-engine/src/main/docs/modules/eips/pages/intercept.adoc`).
#[must_use]
pub fn intercepts_send(intercepts: &[Intercept], send: &Send<'_>) -> bool {
    intercepts.iter().any(|intercept| match intercept {
        Intercept::Endpoint { endpoint } => {
            !send.token_request && endpoint.as_str() == send.endpoint
        }
        Intercept::TokenEndpoint { endpoint } => {
            send.token_request && endpoint.as_str() == send.endpoint
        }
    })
}

/// The canonical bytes a body digest is taken over: the value's own JSON
/// serialization, whose object keys sort (serde_json's map order), so two
/// bodies equal as JSON canonicalize equal whatever order they were built
/// in. An absent body canonicalizes to its own stand-in, so it never
/// equals the null body.
fn canonical_body(body: Option<&serde_json::Value>) -> String {
    match body {
        None => "<absent>".to_owned(),
        Some(value) => value.to_string(),
    }
}

/// Answer one send from the entry's recorded exchanges, in order: the
/// exchange at the cursor must match the send's method, path, query, and
/// body digest, and answering consumes it, so the next send matches the
/// next recording (CONCEPT 13.3). The runtime engine calls this for every
/// `http` and `graphql` send it is about to make; nothing here does I/O.
pub fn answer_send<'a>(
    intercepts: &[Intercept],
    exchanges: &'a [RecordedExchange],
    cursor: &mut usize,
    send: &Send<'a>,
) -> Result<&'a RecordedResponse, ReplayMismatch> {
    if !intercepts_send(intercepts, send) {
        return Err(ReplayMismatch::NotIntercepted);
    }
    let recorded = exchanges.get(*cursor).ok_or(ReplayMismatch::Exhausted)?;
    let request = &recorded.request;
    let request_query = request.query.as_deref();
    if request.method != send.method {
        return Err(ReplayMismatch::Method);
    }
    if request.path != send.path {
        return Err(ReplayMismatch::Path);
    }
    if request_query != send.query {
        return Err(ReplayMismatch::Query);
    }
    if canonical_body(request.body.as_ref().map(RecordedBody::as_value))
        != canonical_body(send.body)
    {
        return Err(ReplayMismatch::BodyDigest);
    }
    *cursor += 1;
    Ok(&recorded.response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(value: serde_json::Value) -> Option<RecordedBody> {
        Some(RecordedBody(value))
    }

    fn exchange(method: crate::model::HttpMethod, path: &str) -> RecordedExchange {
        RecordedExchange {
            request: RecordedRequest {
                endpoint: ExternalId::new("case-api").expect("id"),
                token_request: false,
                method,
                path: path.to_owned(),
                query: None,
                headers: RecordedHeaders::new(),
                body: None,
            },
            response: RecordedResponse {
                status: HttpStatus::new(200).expect("a status"),
                headers: RecordedHeaders::new(),
                body: body(serde_json::json!({"page": path})),
            },
        }
    }

    fn send<'a>(method: crate::model::HttpMethod, path: &'a str) -> Send<'a> {
        Send {
            endpoint: "case-api",
            token_request: false,
            method,
            path,
            query: None,
            body: None,
        }
    }

    /// Every entry carries its facade request; the operation inside it is
    /// the facade-side primary key, and the reader refuses an entry
    /// without one.
    #[test]
    fn fixture_entry_requires_its_facade_request() {
        let mut fixture = serde_json::json!({
            "id": "fx",
            "pack": "case-api-pack",
            "upstreamVersion": "2.7",
            "provenance": {"type": "captured", "reference": "staging"},
            "intercepts": [],
            "entries": [{
                "facadeRequest": {"path": "/cases"},
                "upstream": [{
                    "request": {"endpoint": "case-api", "method": "GET", "path": "/v2/cases"},
                    "response": {"status": 200}
                }],
                "expected": {"type": "response", "status": 200}
            }],
        });
        assert!(
            serde_json::from_str::<AdapterFixture>(&fixture.to_string()).is_err(),
            "a facade request without an operation is refused"
        );
        fixture["entries"][0]["facadeRequest"]["operation"] = serde_json::json!("cases-find");
        let parsed = serde_json::from_str::<AdapterFixture>(&fixture.to_string()).expect("parse");
        assert_eq!(
            parsed.entries[0].facade_request.operation.as_str(),
            "cases-find"
        );
    }

    /// The fixture artifact round-trips with provenance, intercept
    /// declarations, an ordered multi-exchange entry carrying request and
    /// response headers, and a problem expectation by class and code
    /// (`products/adapter/CONCEPT.md` sections 6, 10.2, and 13.3,
    /// G-FIXTURES).
    #[test]
    fn fixture_round_trips() {
        let mut facade_headers = RecordedHeaders::new();
        facade_headers.insert("accept".to_owned(), "application/json".to_owned());
        let mut upstream_request_headers = RecordedHeaders::new();
        upstream_request_headers.insert("authorization".to_owned(), "Bearer x".to_owned());
        let mut upstream_response_headers = RecordedHeaders::new();
        upstream_response_headers.insert("etag".to_owned(), "\"v6\"".to_owned());
        let fixture = AdapterFixture {
            id: LocalId::new("case-api-fixtures").expect("id"),
            pack: ExternalId::new("case-api-pack").expect("id"),
            upstream_version: "2.7".to_string(),
            provenance: FixtureProvenance::Captured {
                reference: "staging 2026-10".to_string(),
            },
            intercepts: vec![
                Intercept::Endpoint {
                    endpoint: ExternalId::new("case-api").expect("id"),
                },
                Intercept::TokenEndpoint {
                    endpoint: ExternalId::new("case-api").expect("id"),
                },
            ],
            entries: vec![FixtureEntry {
                facade_request: RecordedFacadeRequest {
                    operation: ExternalId::new("cases-find").expect("id"),
                    path: "/cases/person/123".to_owned(),
                    query: Some("nationalId=123".to_owned()),
                    headers: facade_headers,
                    body: None,
                },
                upstream: vec![
                    RecordedExchange {
                        request: RecordedRequest {
                            endpoint: ExternalId::new("case-api").expect("id"),
                            token_request: true,
                            method: crate::model::HttpMethod::Post,
                            path: "/oauth/token".to_owned(),
                            query: None,
                            headers: upstream_request_headers,
                            body: body(serde_json::json!({
                                "grant_type": "client_credentials"
                            })),
                        },
                        response: RecordedResponse {
                            status: HttpStatus::new(200).expect("a status"),
                            headers: RecordedHeaders::new(),
                            body: body(serde_json::json!({"access_token": "t"})),
                        },
                    },
                    RecordedExchange {
                        request: RecordedRequest {
                            endpoint: ExternalId::new("case-api").expect("id"),
                            token_request: false,
                            method: crate::model::HttpMethod::Get,
                            path: "/v2/cases/person/123".to_owned(),
                            query: Some("fields=id".to_owned()),
                            headers: RecordedHeaders::new(),
                            body: None,
                        },
                        response: RecordedResponse {
                            status: HttpStatus::new(200).expect("a status"),
                            headers: upstream_response_headers,
                            body: body(serde_json::json!({"id": "123"})),
                        },
                    },
                ],
                expected: ExpectedFacade::Response {
                    status: HttpStatus::new(200).expect("a status"),
                    headers: RecordedHeaders::new(),
                    body: body(serde_json::json!({"record": {"id": "123"}})),
                },
            }],
        };
        let json = serde_json::to_string(&fixture).expect("serialize");
        assert!(json.contains(r#""type":"captured""#));
        assert!(json.contains(r#""type":"token-endpoint""#));
        assert_eq!(
            serde_json::from_str::<AdapterFixture>(&json).ok(),
            Some(fixture)
        );
    }

    /// A problem expectation travels by class and code, the expectation
    /// kinds are closed, and an entry whose upstream list is empty still
    /// decodes: emptiness is an authoring finding, not a reader one.
    #[test]
    fn expected_problems_carry_class_and_code() {
        let mut fixture = serde_json::json!({
            "id": "fx",
            "pack": "case-api-pack",
            "upstreamVersion": "2.7",
            "provenance": {"type": "documented", "reference": "handbook"},
            "intercepts": [],
            "entries": [{
                "facadeRequest": {"operation": "cases-find", "path": "/cases"},
                "upstream": [{
                    "request": {"endpoint": "case-api", "method": "GET", "path": "/v2/cases"},
                    "response": {"status": 503}
                }],
                "expected": {
                    "type": "problem",
                    "class": "upstream.connection",
                    "code": "cases.upstream"
                }
            }],
        });
        let parsed = serde_json::from_str::<AdapterFixture>(&fixture.to_string()).expect("parse");
        match &parsed.entries[0].expected {
            ExpectedFacade::Problem { class, code } => {
                assert_eq!(class, &crate::model::ErrorClass::UpstreamConnection);
                assert_eq!(code.as_str(), "cases.upstream");
            }
            other => panic!("the entry expects a problem, not {other:?}"),
        }
        // The expectation kinds are closed.
        fixture["entries"][0]["expected"]["type"] = serde_json::json!("catastrophe");
        assert!(
            serde_json::from_str::<AdapterFixture>(&fixture.to_string()).is_err(),
            "an unknown expectation kind is refused"
        );
        // An empty upstream list decodes; the checks refuse it.
        fixture["entries"][0]["expected"]["type"] = serde_json::json!("problem");
        fixture["entries"][0]["upstream"] = serde_json::json!([]);
        let parsed = serde_json::from_str::<AdapterFixture>(&fixture.to_string()).expect("parse");
        assert!(parsed.entries[0].upstream.is_empty());
    }

    /// JSON `null` is a body, not a missing one: absent, `null`, and a
    /// value are three recorded states, on requests and responses both,
    /// and a body with a null member keeps it (G-FIXTURES, CFG-EMBED-2).
    #[test]
    fn json_null_is_a_body_not_an_absent_one() {
        let request = |body: Option<RecordedBody>| {
            serde_json::to_string(&RecordedRequest {
                endpoint: ExternalId::new("case-api").expect("id"),
                token_request: false,
                method: crate::model::HttpMethod::Post,
                path: "/v2/cases".to_owned(),
                query: None,
                headers: RecordedHeaders::new(),
                body,
            })
            .expect("serialize")
        };
        let absent = request(None);
        assert!(!absent.contains("body"), "absent is not written");
        let parsed = serde_json::from_str::<RecordedRequest>(&absent).expect("parse");
        assert_eq!(parsed.body, None);
        let null = request(body(serde_json::Value::Null));
        assert!(null.contains(r#""body":null"#), "null is written");
        let parsed = serde_json::from_str::<RecordedRequest>(&null).expect("parse");
        assert_eq!(
            parsed.body.map(|body| body.0),
            Some(serde_json::Value::Null)
        );
        let value = request(body(serde_json::json!({"a": 1})));
        let parsed = serde_json::from_str::<RecordedRequest>(&value).expect("parse");
        assert_eq!(
            parsed.body.map(|body| body.0),
            Some(serde_json::json!({"a": 1}))
        );

        let response: RecordedResponse =
            serde_json::from_str(r#"{ "status": 204, "body": null }"#).expect("parse");
        assert_eq!(
            response.body.map(|body| body.0),
            Some(serde_json::Value::Null)
        );
        let nested: RecordedResponse =
            serde_json::from_str(r#"{ "status": 200, "body": { "deletedAt": null, "id": "7" } }"#)
                .expect("parse");
        assert_eq!(
            nested.body.map(|body| body.0),
            Some(serde_json::json!({"deletedAt": null, "id": "7"}))
        );
    }

    /// Documented provenance round-trips, and an unknown provenance kind
    /// or intercept kind is refused.
    #[test]
    fn provenance_kinds_are_closed() {
        let documented: FixtureProvenance = serde_json::from_str(
            r#"{ "type": "documented", "reference": "API handbook section 4" }"#,
        )
        .expect("parse");
        assert!(matches!(documented, FixtureProvenance::Documented { .. }));
        assert!(serde_json::from_str::<FixtureProvenance>(
            r#"{ "type": "imagined", "reference": "x" }"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Intercept>(r#"{ "type": "route", "endpoint": "case-api" }"#)
                .is_err(),
            "a route-level intercept is not a fixture concept"
        );
        // The discriminator is `type`; the earlier `kind` spelling is not
        // read back (addendum update a).
        assert!(serde_json::from_str::<FixtureProvenance>(
            r#"{ "kind": "documented", "reference": "x" }"#,
        )
        .is_err());
    }

    /// A fixture naming a pack unknown to it is data; the checks refuse the
    /// mismatch. The reader accepts both shapes.
    #[test]
    fn pack_reference_travels_with_the_suite() {
        let fixture: AdapterFixture = serde_json::from_str(
            r#"{
                "id": "case-api-fixtures",
                "pack": "other-pack",
                "upstreamVersion": "2.7",
                "provenance": { "type": "documented", "reference": "handbook" },
                "intercepts": []
            }"#,
        )
        .expect("parse");
        assert_eq!(fixture.pack.as_str(), "other-pack");
    }

    /// A recorded status is an HTTP status; the reader refuses anything
    /// outside the 100 to 599 range (CFG-QTY-4).
    #[test]
    fn recorded_statuses_carry_the_http_range() {
        let status = |value: u32| {
            serde_json::from_str::<RecordedResponse>(&format!(r#"{{ "status": {value} }}"#))
        };
        assert!(status(99).is_err());
        assert!(status(600).is_err());
        assert!(status(200).is_ok());
        assert!(status(404).is_ok());
    }

    /// Replay answers sends from the recording in order and refuses every
    /// other send: interception is by endpoint, the exchange at the cursor
    /// must match method, path, query, and body, and a spent recording
    /// answers nothing (CONCEPT 13.3;
    /// `camel-4.23.0:core/camel-core-engine/src/main/docs/modules/eips/pages/intercept.adoc`:
    /// the intercepted send never reaches the original endpoint).
    #[test]
    fn replay_answers_intercepted_sends_in_order() {
        let intercepts = [Intercept::Endpoint {
            endpoint: ExternalId::new("case-api").expect("id"),
        }];
        let exchanges = vec![
            exchange(crate::model::HttpMethod::Get, "/v2/cases?page=1"),
            exchange(crate::model::HttpMethod::Get, "/v2/cases?page=2"),
        ];
        let mut cursor = 0usize;
        let first = answer_send(
            &intercepts,
            &exchanges,
            &mut cursor,
            &send(crate::model::HttpMethod::Get, "/v2/cases?page=1"),
        )
        .expect("the first recorded exchange answers");
        assert_eq!(
            first.body.as_ref().map(RecordedBody::as_value),
            Some(&serde_json::json!({"page": "/v2/cases?page=1"}))
        );
        // The second send answers from the second recording, in order.
        answer_send(
            &intercepts,
            &exchanges,
            &mut cursor,
            &send(crate::model::HttpMethod::Get, "/v2/cases?page=2"),
        )
        .expect("the second recorded exchange answers");
        // A third send has no recording left.
        assert_eq!(
            answer_send(
                &intercepts,
                &exchanges,
                &mut cursor,
                &send(crate::model::HttpMethod::Get, "/v2/cases?page=1"),
            ),
            Err(ReplayMismatch::Exhausted)
        );
    }

    /// A send the recording does not match is refused with the member that
    /// differed: method, path, query, or body. An explicit null send
    /// matches an explicit null recording, and neither matches an absent
    /// body.
    #[test]
    fn replay_names_the_member_that_differed() {
        let intercepts = [Intercept::Endpoint {
            endpoint: ExternalId::new("case-api").expect("id"),
        }];
        let mut exchanges = vec![exchange(crate::model::HttpMethod::Get, "/v2/cases")];
        exchanges[0].request.query = Some("page=1".to_owned());
        exchanges[0].request.body = body(serde_json::json!({"q": "x"}));
        let mut cursor = 0usize;
        assert_eq!(
            answer_send(
                &intercepts,
                &exchanges,
                &mut cursor,
                &send(crate::model::HttpMethod::Post, "/v2/cases"),
            ),
            Err(ReplayMismatch::Method)
        );
        assert_eq!(
            answer_send(
                &intercepts,
                &exchanges,
                &mut cursor,
                &send(crate::model::HttpMethod::Get, "/v2/other"),
            ),
            Err(ReplayMismatch::Path)
        );
        let mut wrong_query = send(crate::model::HttpMethod::Get, "/v2/cases");
        wrong_query.query = Some("page=9");
        assert_eq!(
            answer_send(&intercepts, &exchanges, &mut cursor, &wrong_query),
            Err(ReplayMismatch::Query)
        );
        let value = serde_json::json!({"q": "y"});
        let mut wrong_body = send(crate::model::HttpMethod::Get, "/v2/cases");
        wrong_body.query = Some("page=1");
        wrong_body.body = Some(&value);
        assert_eq!(
            answer_send(&intercepts, &exchanges, &mut cursor, &wrong_body),
            Err(ReplayMismatch::BodyDigest)
        );
        // A null send matches a null recording; an absent send does not.
        let null = serde_json::Value::Null;
        let mut null_body = send(crate::model::HttpMethod::Get, "/v2/cases");
        null_body.query = Some("page=1");
        null_body.body = Some(&null);
        assert_eq!(
            answer_send(&intercepts, &exchanges, &mut cursor, &null_body),
            Err(ReplayMismatch::BodyDigest)
        );
        exchanges[0].request.body = body(serde_json::Value::Null);
        let mut cursor = 0usize;
        answer_send(&intercepts, &exchanges, &mut cursor, &null_body)
            .expect("an explicit null send matches an explicit null recording");
    }

    /// A token request answers only under a token intercept, and an
    /// ordinary send only under an endpoint intercept (CONCEPT 10.2: the
    /// token endpoint is a fixed destination, intercepted like any other
    /// send).
    #[test]
    fn token_requests_answer_under_the_token_intercept() {
        let endpoint_intercept = [Intercept::Endpoint {
            endpoint: ExternalId::new("case-api").expect("id"),
        }];
        let token_intercept = [Intercept::TokenEndpoint {
            endpoint: ExternalId::new("case-api").expect("id"),
        }];
        let mut token_exchange = exchange(crate::model::HttpMethod::Post, "/oauth/token");
        token_exchange.request.token_request = true;
        let mut token_send = send(crate::model::HttpMethod::Post, "/oauth/token");
        token_send.token_request = true;
        let mut cursor = 0usize;
        assert_eq!(
            answer_send(
                &endpoint_intercept,
                &[token_exchange.clone()],
                &mut cursor,
                &token_send
            ),
            Err(ReplayMismatch::NotIntercepted)
        );
        answer_send(
            &token_intercept,
            &[token_exchange],
            &mut cursor,
            &token_send,
        )
        .expect("the token intercept answers the token request");
        let mut cursor = 0usize;
        assert_eq!(
            answer_send(
                &token_intercept,
                &[exchange(crate::model::HttpMethod::Get, "/v2/cases")],
                &mut cursor,
                &send(crate::model::HttpMethod::Get, "/v2/cases"),
            ),
            Err(ReplayMismatch::NotIntercepted)
        );
    }
}
