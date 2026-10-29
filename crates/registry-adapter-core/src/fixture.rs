// SPDX-License-Identifier: Apache-2.0

//! The fixture suite: recorded upstream exchanges with expected facade
//! responses, with provenance (`products/adapter/CONCEPT.md` sections 6
//! and 13.3).
//!
//! The fixture declares which sends it intercepts, by endpoint id and by
//! token endpoint (CONCEPT 10.2: fixture replay intercepts the token
//! endpoint like any other send), so packs are replayable without a
//! credential. A route never declares its own test intercepts.

use registry_platform_yaml::{BoundedU32, ExternalId};
use serde::{Deserialize, Serialize};

/// An HTTP status code, 100 through 599 (CFG-QTY-4).
pub(crate) type HttpStatus = BoundedU32<100, 599>;

/// Where a fixture's recording came from
/// (`products/adapter/CONCEPT.md` section 13.3): captured from a live
/// system, or documented as an authored reconstruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "kind",
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
    tag = "kind",
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

/// One recorded upstream request the fixture replay matches against.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    /// The endpoint the request goes to.
    pub endpoint: ExternalId,
    /// The request method.
    pub method: crate::model::HttpMethod,
    /// The request path, with any template segments already filled.
    pub path: String,
    /// The encoded query string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// The request body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

/// One recorded upstream reply.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedResponse {
    /// The status the upstream answered with.
    pub status: HttpStatus,
    /// The reply body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

/// One fixture entry: a recorded upstream exchange and the facade response
/// the pack must produce for it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureEntry {
    /// The profile operation this entry exercises; the facade-side
    /// primary key of the entry.
    pub operation: ExternalId,
    /// The recorded upstream exchange.
    pub given: RecordedRequest,
    /// The upstream reply the route works from.
    pub upstream_response: RecordedResponse,
    /// The facade response the replay expects.
    pub expected_facade_response: RecordedResponse,
}

/// The fixture suite artifact (`AdapterFixture`), authored per pack.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterFixture {
    /// The suite identifier.
    pub id: ExternalId,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every entry names the profile operation it exercises (the
    /// facade-side primary key); the reader refuses an entry without one.
    #[test]
    fn fixture_entry_requires_its_operation() {
        let mut fixture = serde_json::json!({
            "id": "fx",
            "pack": "case-api-pack",
            "upstreamVersion": "2.7",
            "provenance": {"kind": "captured", "reference": "staging"},
            "intercepts": [],
            "entries": [{
                "given": {"endpoint": "case-api", "method": "GET", "path": "/v2/cases"},
                "upstreamResponse": {"status": 200},
                "expectedFacadeResponse": {"status": 200},
            }],
        });
        assert!(
            serde_json::from_str::<AdapterFixture>(&fixture.to_string()).is_err(),
            "an entry without an operation is refused"
        );
        fixture["entries"][0]["operation"] = serde_json::json!("cases.find");
        let parsed = serde_json::from_str::<AdapterFixture>(&fixture.to_string()).expect("parse");
        assert_eq!(parsed.entries[0].operation.as_str(), "cases.find");
    }

    /// The fixture artifact round-trips with provenance, intercept
    /// declarations, and entries (`products/adapter/CONCEPT.md` sections
    /// 6, 10.2, and 13.3).
    #[test]
    fn fixture_round_trips() {
        let fixture = AdapterFixture {
            id: ExternalId::new("case-api-fixtures").expect("id"),
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
                operation: ExternalId::new("cases.find").expect("id"),
                given: RecordedRequest {
                    endpoint: ExternalId::new("case-api").expect("id"),
                    method: crate::model::HttpMethod::Get,
                    path: "/v2/cases/person/123".to_string(),
                    query: Some("fields=id".to_string()),
                    body: None,
                },
                upstream_response: RecordedResponse {
                    status: HttpStatus::new(200).expect("a status"),
                    body: Some(serde_json::json!({"id": "123"})),
                },
                expected_facade_response: RecordedResponse {
                    status: HttpStatus::new(200).expect("a status"),
                    body: Some(serde_json::json!({"record": {"id": "123"}})),
                },
            }],
        };
        let json = serde_json::to_string(&fixture).expect("serialize");
        assert!(json.contains(r#""kind":"captured""#));
        assert!(json.contains(r#""kind":"token-endpoint""#));
        assert_eq!(
            serde_json::from_str::<AdapterFixture>(&json).ok(),
            Some(fixture)
        );
    }

    /// Documented provenance round-trips, and an unknown provenance kind
    /// or intercept kind is refused.
    #[test]
    fn provenance_kinds_are_closed() {
        let documented: FixtureProvenance = serde_json::from_str(
            r#"{ "kind": "documented", "reference": "API handbook section 4" }"#,
        )
        .expect("parse");
        assert!(matches!(documented, FixtureProvenance::Documented { .. }));
        assert!(serde_json::from_str::<FixtureProvenance>(
            r#"{ "kind": "imagined", "reference": "x" }"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Intercept>(r#"{ "kind": "route", "endpoint": "case-api" }"#)
                .is_err(),
            "a route-level intercept is not a fixture concept"
        );
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
                "provenance": { "kind": "documented", "reference": "handbook" },
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
}
