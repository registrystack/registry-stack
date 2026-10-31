// SPDX-License-Identifier: Apache-2.0

//! The adapter pack: a reviewed catalog of route templates, the role
//! Kamelets play for Camel (`products/adapter/CONCEPT.md` sections 6, 8.4,
//! and 8.8). A pack knows one source system and produces records in the
//! project's declared model.

use crate::auth::EndpointAuthentication;
use crate::job::MAXIMUM_JOB_RESPONSE_BYTES;
use crate::model::{ComponentKind, Eip, Language};
use crate::route::{RouteDefinition, RouteTemplate, Step};
use registry_platform_yaml::{BoundedU64, Digest, ExternalId, LocalId, UniqueIdList, UniqueList};
use serde::{Deserialize, Serialize};

/// One endpoint a route may send to: the component, the authentication
/// kind, the declared response headers, the endpoint operations with their
/// `idempotentUpstream` claims, and the tested upstream versions
/// (`products/adapter/CONCEPT.md` sections 6, 8.8, and 10.2).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    /// The endpoint identifier `http:`, `graphql:`, `postgres:`, and the
    /// `pollEnrich` URIs name.
    pub id: LocalId,
    /// The producer component: `http`, `graphql`, or the read-only
    /// `postgres` source; or the job-only `file` and `sftp` sources a
    /// `pollEnrich` step reads (section 17.1).
    pub component: ComponentKind,
    /// The upstream authentication kind, with its non-secret parameters.
    pub authentication: EndpointAuthentication,
    /// The longest one attempt to this endpoint may take, in
    /// milliseconds. Required, no default; a value above the platform
    /// ceiling is refused, never shortened. The runtime binding may lower
    /// it, never raise it.
    pub attempt_timeout_milliseconds: BoundedU64<1, 10_000>,
    /// The largest response body one send to this endpoint may take in, in
    /// bytes. Required, no default; a value above the platform cap is
    /// refused, never shortened. The runtime binding may lower it, never
    /// raise it. A facade-reachable endpoint stays within the facade
    /// ceiling and a source-route-only endpoint may declare up to the
    /// platform cap (D39); the checks refuse the facade-reachable excess
    /// under `adapter.job.endpoint-response-bound`.
    pub maximum_response_bytes: BoundedU64<1, MAXIMUM_JOB_RESPONSE_BYTES>,
    /// The response headers the engine copies onto the exchange, Camel's
    /// `HeaderFilterStrategy` as an allowlist, unique (CFG-ID-6).
    #[serde(default, skip_serializing_if = "headers_empty")]
    pub response_headers: UniqueList<ExternalId>,
    /// The request headers the engine sends upstream on every send to
    /// this endpoint, Camel's `HeaderFilterStrategy` as an allowlist,
    /// unique (CFG-ID-6). Never allowlistable: the reserved header names
    /// of `products/adapter/CONCEPT.md` section 8.11.4 and this
    /// endpoint's own api-key header name.
    #[serde(default, skip_serializing_if = "headers_empty")]
    pub request_headers: UniqueList<ExternalId>,
    /// The operations this endpoint serves, each with its
    /// `idempotentUpstream` claim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<EndpointOperation>,
    /// The upstream versions this pack was tested against.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tested_versions: Vec<String>,
    /// The GraphQL query file, from the pack's query-file inventory.
    /// Required for a `graphql` endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_file: Option<String>,
    /// The GraphQL operation name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
    /// The GraphQL variables expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<crate::model::Expression>,
}

/// An endpoint header allowlist is omitted from the wire when empty, the
/// shape `Vec`'s `skip_serializing_if = "Vec::is_empty"` gave.
fn headers_empty(headers: &UniqueList<ExternalId>) -> bool {
    headers.is_empty()
}

impl registry_platform_yaml::Identified for Endpoint {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// One operation of an endpoint, with the reviewed write claim
/// (`products/adapter/CONCEPT.md` sections 8.7 and 9): redelivery over a
/// non-safe send is admitted only when the endpoint operation declares
/// `idempotentUpstream: true`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointOperation {
    /// The operation identifier a `to` step's `operation` member names.
    pub id: LocalId,
    /// The reviewed claim that repeating this operation's send is safe,
    /// for example an upstream create with client-supplied UIDs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub idempotent_upstream: bool,
    /// The reviewed claim that the upstream serves this operation's POST
    /// as its safe search form, as FHIR servers serve `POST _search`
    /// (`products/adapter/CONCEPT.md` section 8.8): a route of a read
    /// operation may then reach the send. The claim names POST only; a
    /// PUT, PATCH, or graphql mutation send never reads it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub safe_upstream: bool,
    /// The GraphQL operation kind the pinned query file declares, on a
    /// `graphql` endpoint; a send naming this operation is safe only for
    /// a query (`products/adapter/CONCEPT.md` section 8.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphQlOperationKind>,
}

/// The GraphQL operation kind an endpoint operation declares, as the
/// pinned query file writes it (`products/adapter/CONCEPT.md` section
/// 8.8).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphQlOperationKind {
    /// A read; the only kind that keeps a graphql send safe.
    Query,
    /// A write; non-safe under every write-safety rule.
    Mutation,
}

/// One code map: an explicit conversion table, the port of Camel's type
/// converter (`products/adapter/CONCEPT.md` sections 8.6 and 8.10). No
/// converter chains; a key with no entry raises `conversion.unmapped`.
/// The member stays small enough for CFG-YAML-6 so its content can move to
/// a digest-pinned data file without a format change.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeMap {
    /// The map identifier.
    pub id: LocalId,
    /// The conversion entries; each key is the upstream's own code value,
    /// the wire name the source system documents (CFG-ID-2).
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::model::external_id_map_schema::<serde_json::Value>")
    )]
    pub entries: std::collections::BTreeMap<ExternalId, serde_json::Value>,
}

/// Whether a source route's scan ends: the closed set CONCEPT 17.2 pins
/// for the item contract.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceScan {
    /// The scan ends: `next` is absent at the end.
    Finite,
    /// The scan continues: the job re-runs the route until stopped.
    Ongoing,
}

/// The recovery semantics of a source route's `next` cursor, the closed
/// set CONCEPT 17.2 pins.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceRecovery {
    /// A replayed cursor re-reads the same bytes, such as a file digest
    /// and position.
    ExactReplay,
    /// Upstream pages may shift between reads; the consumer deduplicates
    /// by key.
    KeyDeduplicated,
}

/// The closed edit-finding declarations a source route carries in its
/// `edits` property (the governed-ingestion concept section 3, "Finding
/// edits"): the position only moves forward, so each source declares how
/// an edit to an already-read item becomes visible again. The values are
/// validated by the checks rather than the reader, so a value outside the
/// closed set refuses under `adapter.job.source-edits-unknown` and the
/// corpus can hold the fault like every other declared-code refusal.
pub const SOURCE_EDIT_VALUES: &[&str] = &["ordered", "rescan"];

/// The shortest rescan delay, in seconds: one minute, so a misconfigured
/// delay cannot drive an ordinary pass from the first page against the
/// source every few seconds.
pub const MINIMUM_SOURCE_RESCAN_DELAY_SECONDS: u64 = 60;

/// The longest rescan delay, in seconds: one day, so a rescan stays an
/// operator-visible cadence a deployment can reason about, never a
/// background sweep no one named.
pub const MAXIMUM_SOURCE_RESCAN_DELAY_SECONDS: u64 = 86_400;

/// One source route of the governed-ingestion mode
/// (`products/adapter/CONCEPT.md` sections 17.1 and 17.2): a route
/// definition's steps plus the item-contract declaration. A source route
/// is an entry point of the job mode, never a subroutine: a facade
/// binding naming it, or a `direct:` send targeting it, refuses
/// (`adapter.job.source-bound-refused`,
/// `adapter.job.source-called-refused`). There is no `from`: the
/// `from: file:` consumer form was rejected with the job's read step
/// (section 17.2).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceRouteDecl {
    /// The source route identifier the job definition names.
    pub id: LocalId,
    /// Whether the scan ends. Mandatory; the checks refuse its absence
    /// under `adapter.job.source-scan-required`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<SourceScan>,
    /// The recovery semantics of `next`. Mandatory; the checks refuse its
    /// absence under `adapter.job.source-recovery-required`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_recovery: Option<SourceRecovery>,
    /// How the source reports edits to items the scan has already read,
    /// one of [`SOURCE_EDIT_VALUES`]: `ordered`, where an edit moves the
    /// item past the read position or items never change so an ordinary
    /// pass suffices, or `rescan`, where an edit can stay behind the
    /// position and the declared `rescanDelaySeconds` starts an ordinary
    /// pass from the first page. Mandatory; the checks refuse its absence
    /// under `adapter.job.source-edits-required` and a value outside the
    /// closed set under `adapter.job.source-edits-unknown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edits: Option<String>,
    /// The seconds between a `rescan` source route's ordinary passes from
    /// the first page, from
    /// [`MINIMUM_SOURCE_RESCAN_DELAY_SECONDS`] to
    /// [`MAXIMUM_SOURCE_RESCAN_DELAY_SECONDS`] (one minute to one day).
    /// Mandatory beside `edits: rescan`, refused beside `edits: ordered`,
    /// and range-checked; the checks police all three under
    /// `adapter.job.source-rescan-delay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rescan_delay_seconds: Option<registry_platform_yaml::BoundedU64<60, 86_400>>,
    /// The ordered steps, as an internal route's body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

impl registry_platform_yaml::Identified for SourceRouteDecl {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

impl registry_platform_yaml::Identified for CodeMap {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

impl CodeMap {
    /// The entry one conversion looks up: exact and case-sensitive over
    /// a string key (`products/adapter/CONCEPT.md` section 8.6). A key
    /// that is not a valid external id matches no entry.
    #[must_use]
    pub fn lookup(&self, key: &str) -> Option<&serde_json::Value> {
        let key = ExternalId::new(key).ok()?;
        self.entries.get(&key)
    }
}

/// The engine capabilities a pack requires: the components, languages, and
/// EIPs its routes use. The ctl refuses a pack the binary cannot run
/// (`products/adapter/CONCEPT.md` section 6).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capabilities {
    /// The components the pack's routes reach.
    #[serde(default)]
    pub components: UniqueList<ComponentKind>,
    /// The expression languages the pack's routes use.
    #[serde(default)]
    pub languages: UniqueList<Language>,
    /// The EIPs the pack's routes use.
    #[serde(default)]
    pub eips: UniqueList<Eip>,
}

/// The adapter pack artifact (`AdapterPack`), a per-source-system catalog:
/// endpoint declarations, route templates with typed parameters, internal
/// `direct:` routes, code maps, script references with digest pins, and
/// the required engine capabilities.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterPack {
    /// The pack identifier a project pins.
    pub id: LocalId,
    /// The pack's own version; a project pin names it next to the digest
    /// (CFG-ID-4).
    pub version: String,
    /// The upstream versions this pack was tested against, pack-wide.
    pub tested_versions: Vec<String>,
    /// The endpoints routes send to.
    #[serde(default)]
    pub endpoints: UniqueIdList<Endpoint>,
    /// The route templates projects instantiate.
    #[serde(default)]
    pub route_templates: UniqueIdList<RouteTemplate>,
    /// The internal `direct:` routes shared sub-flows call.
    #[serde(default)]
    pub routes: UniqueIdList<RouteDefinition>,
    /// The governed-ingestion source routes the job mode runs
    /// (`products/adapter/CONCEPT.md` sections 17.1 and 17.2). Entry
    /// points of the job mode; a facade route never reaches one.
    #[serde(default)]
    pub source_routes: UniqueIdList<SourceRouteDecl>,
    /// The code maps routes convert values through.
    #[serde(default)]
    pub code_maps: UniqueIdList<CodeMap>,
    /// The Rhai script inventory, each file digest-pinned (CFG-EMBED-1).
    #[serde(default)]
    pub scripts: UniqueList<crate::model::ScriptReference>,
    /// The GraphQL query-file inventory, each file digest-pinned.
    #[serde(default)]
    pub query_files: UniqueList<crate::model::ScriptReference>,
    /// The engine capabilities the pack requires.
    #[serde(default)]
    pub capabilities: Capabilities,
}

impl AdapterPack {
    /// The pinned script or query file for a path, or `None`.
    #[must_use]
    pub fn pinned_file(&self, path: &str) -> Option<&Digest> {
        self.scripts
            .iter()
            .chain(self.query_files.iter())
            .find(|script| script.path == path)
            .map(|script| &script.digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SendUri;

    fn endpoint() -> Endpoint {
        Endpoint {
            id: LocalId::new("case-api").expect("id"),
            component: ComponentKind::Http,
            authentication: EndpointAuthentication::Oauth2ClientCredentials {},
            attempt_timeout_milliseconds: registry_platform_yaml::BoundedU64::new(10_000)
                .expect("attempt timeout"),
            maximum_response_bytes: registry_platform_yaml::BoundedU64::new(1_048_576)
                .expect("response bound"),
            response_headers: UniqueList::new(vec![ExternalId::new("etag").expect("header")])
                .expect("unique"),
            request_headers: UniqueList::new(Vec::new()).expect("unique"),
            operations: vec![EndpointOperation {
                id: LocalId::new("cases-upsert").expect("op"),
                idempotent_upstream: true,
                safe_upstream: false,
                graphql: None,
            }],
            tested_versions: vec!["2.7".to_string()],
            query_file: None,
            operation_name: None,
            variables: None,
        }
    }

    /// An endpoint declares both limits; neither has a default, and a value
    /// outside its range is refused, never shortened. The response bound's
    /// reader ceiling is the platform cap a source-route-only endpoint may
    /// declare (D39); a facade-reachable endpoint stays at the facade
    /// ceiling, which the checks refuse past.
    #[test]
    fn endpoint_requires_both_limits_within_their_ceilings() {
        let read = |attempt: &str, bytes: &str| {
            let document = format!(
                r#"{{"id":"case-api","component":"http","authentication":{{"type":"none"}}{attempt}{bytes}}}"#
            );
            serde_json::from_str::<Endpoint>(&document)
        };
        let attempt = r#","attemptTimeoutMilliseconds":10000"#;
        let bytes = r#","maximumResponseBytes":1048576"#;
        read(attempt, bytes).expect("both limits at their ceilings parse");
        read(attempt, r#","maximumResponseBytes":16777216"#).expect("the platform cap parses");
        assert!(read("", bytes).is_err(), "the attempt timeout is required");
        assert!(read(attempt, "").is_err(), "the response bound is required");
        assert!(
            read(r#","attemptTimeoutMilliseconds":10001"#, bytes).is_err(),
            "an attempt timeout above the ceiling is refused"
        );
        assert!(
            read(r#","attemptTimeoutMilliseconds":0"#, bytes).is_err(),
            "a zero attempt timeout is refused"
        );
        assert!(
            read(attempt, r#","maximumResponseBytes":16777217"#).is_err(),
            "a response bound above the platform cap is refused"
        );
        assert!(
            read(attempt, r#","maximumResponseBytes":0"#).is_err(),
            "a zero response bound is refused"
        );
    }

    /// The pack declares its own version (the artifact table: authored,
    /// versioned); the reader refuses a pack without one, since a project
    /// pin compares against it (CFG-ID-4).
    /// The version is text, compared exactly, never a number: an
    /// unquoted numeric version is refused with the reader's usual type
    /// diagnostic, never coerced.
    #[test]
    fn pack_refuses_a_numeric_version() {
        for json in [
            r#"{"id":"case-api-pack","version":1,"testedVersions":["2.7"]}"#,
            r#"{"id":"case-api-pack","version":1.0,"testedVersions":["2.7"]}"#,
        ] {
            assert!(
                serde_json::from_str::<AdapterPack>(json).is_err(),
                "a numeric version is refused, never coerced"
            );
        }
    }

    #[test]
    fn pack_reader_requires_a_version() {
        let json = r#"{"id":"case-api-pack","testedVersions":["2.7"]}"#;
        assert!(
            serde_json::from_str::<AdapterPack>(json).is_err(),
            "a pack without a version is refused"
        );
        let declared = r#"{"id":"case-api-pack","version":"1.0.0","testedVersions":["2.7"]}"#;
        let pack = serde_json::from_str::<AdapterPack>(declared).expect("parse");
        assert_eq!(pack.version, "1.0.0");
    }

    /// A code-map entry key is the upstream's own code value, the wire
    /// name the source system documents (CFG-ID-2): keys a local
    /// identifier would refuse, including numerics and upper case, parse
    /// and keep the value each converts to.
    #[test]
    fn code_map_entries_accept_external_id_keys() {
        let json = r#"{"id":"case-api-pack","version":"1.0.0","testedVersions":["2.7"],"codeMaps":[{"id":"tracker-status","entries":{"female":"F","M":"male","01":"zero"}}]}"#;
        let pack = serde_json::from_str::<AdapterPack>(json).expect("parse");
        let entries = &pack.code_maps[0].entries;
        let keys: Vec<&str> = entries.keys().map(|key| key.as_str()).collect();
        assert_eq!(keys, vec!["01", "M", "female"], "keys stay as written");
        assert_eq!(
            entries[&ExternalId::new("M").expect("key")],
            serde_json::json!("male")
        );
    }

    /// A code-map entry key outside `ExternalId` (empty, carrying a
    /// control character, or over 512 characters) refuses at the reader,
    /// worded as the shared text type (CFG-ID-2).
    #[test]
    fn code_map_entries_refuse_a_bad_key() {
        let read = |key: &str| {
            let document = format!(
                r#"{{"id":"case-api-pack","version":"1.0.0","testedVersions":["2.7"],"codeMaps":[{{"id":"tracker-status","entries":{{"{key}":"F"}}}}]}}"#
            );
            serde_json::from_str::<AdapterPack>(&document)
        };
        for key in ["", "no\\u0000pe", &"x".repeat(513)] {
            let error = read(key).expect_err("a key outside ExternalId is refused");
            assert!(
                error
                    .to_string()
                    .contains("a non-empty identifier of at most 512 characters"),
                "a bad entry key {key:?} is refused as the shared text type: {error}"
            );
        }
    }

    /// The pack artifact round-trips: endpoints with component kind and
    /// authentication, templates, internal routes, code maps, inventories,
    /// and capabilities.
    #[test]
    fn pack_round_trips() {
        let pack = AdapterPack {
            id: LocalId::new("case-api-pack").expect("id"),
            version: "1.0.0".to_string(),
            tested_versions: vec!["2.7".to_string()],
            endpoints: UniqueIdList::new(vec![endpoint()]).expect("unique"),
            route_templates: UniqueIdList::new(vec![RouteTemplate {
                id: LocalId::new("paged-fetch").expect("id"),
                parameters: Vec::new(),
                steps: Vec::new(),
            }])
            .expect("unique"),
            routes: UniqueIdList::new(vec![RouteDefinition {
                id: LocalId::new("shared-lookup").expect("id"),
                from: crate::route::RouteFrom {
                    uri: SendUri::parse("direct:sharedLookup").expect("uri"),
                },
                steps: Vec::new(),
            }])
            .expect("unique"),
            code_maps: UniqueIdList::new(vec![CodeMap {
                id: LocalId::new("gender-codes").expect("id"),
                entries: std::collections::BTreeMap::from([(
                    ExternalId::new("female").expect("key"),
                    serde_json::json!("F"),
                )]),
            }])
            .expect("unique"),
            scripts: UniqueList::new(vec![crate::model::ScriptReference {
                path: "scripts/map.rhai".to_string(),
                digest: Digest::new(
                    "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9",
                )
                .expect("digest"),
            }])
            .expect("unique"),
            query_files: UniqueList::new(vec![crate::model::ScriptReference {
                path: "queries/cases.graphql".to_string(),
                digest: Digest::new(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .expect("digest"),
            }])
            .expect("unique"),
            source_routes: UniqueIdList::new(vec![SourceRouteDecl {
                id: LocalId::new("kobo-submissions").expect("id"),
                scan: Some(SourceScan::Ongoing),
                next_recovery: Some(SourceRecovery::KeyDeduplicated),
                edits: Some("ordered".to_string()),
                rescan_delay_seconds: None,
                steps: Vec::new(),
            }])
            .expect("unique"),
            capabilities: Capabilities {
                components: UniqueList::new(vec![ComponentKind::Http]).expect("unique"),
                languages: UniqueList::new(vec![Language::JsonPath]).expect("unique"),
                eips: UniqueList::new(vec![Eip::Split, Eip::Enrich]).expect("unique"),
            },
        };
        let json = serde_json::to_string(&pack).expect("serialize");
        assert!(json.contains("idempotentUpstream"));
        assert!(json.contains("sourceRoutes"));
        assert!(json.contains("nextRecovery"));
        assert_eq!(serde_json::from_str::<AdapterPack>(&json).ok(), Some(pack));
    }

    /// A source route declares its scan and recovery semantics, spells
    /// them in the closed kebab/lowercase sets, declares its edit-finding
    /// mode beside them, and refuses an unknown member. Repeated source
    /// route ids refuse at the reader (CFG-ID-5).
    #[test]
    fn source_routes_round_trip_and_declare_their_contract() {
        let pack: AdapterPack = serde_json::from_str(
            r#"{
                "id": "kobo-pack",
                "version": "1",
                "testedVersions": [],
                "sourceRoutes": [
                    { "id": "kobo-submissions", "scan": "ongoing", "nextRecovery": "key-deduplicated", "edits": "ordered" },
                    { "id": "exports", "scan": "finite", "nextRecovery": "exact-replay", "edits": "rescan", "rescanDelaySeconds": 3600 }
                ]
            }"#,
        )
        .expect("parse");
        let source = pack.source_routes.get("kobo-submissions").expect("route");
        assert_eq!(source.scan, Some(SourceScan::Ongoing));
        assert_eq!(source.next_recovery, Some(SourceRecovery::KeyDeduplicated));
        assert_eq!(source.edits.as_deref(), Some("ordered"));
        assert_eq!(source.rescan_delay_seconds, None);
        let finite = pack.source_routes.get("exports").expect("route");
        assert_eq!(finite.scan, Some(SourceScan::Finite));
        assert_eq!(finite.next_recovery, Some(SourceRecovery::ExactReplay));
        assert_eq!(finite.edits.as_deref(), Some("rescan"));
        assert_eq!(
            finite
                .rescan_delay_seconds
                .map(registry_platform_yaml::BoundedU64::get),
            Some(3600)
        );
        let wire = serde_json::to_value(&pack).expect("serialize");
        assert_eq!(wire["sourceRoutes"][0]["scan"], "ongoing");
        assert_eq!(wire["sourceRoutes"][0]["nextRecovery"], "key-deduplicated");
        assert_eq!(wire["sourceRoutes"][0]["edits"], "ordered");
        assert_eq!(wire["sourceRoutes"][1]["rescanDelaySeconds"], 3600);
        assert!(wire["sourceRoutes"][0].get("steps").is_none());
        assert!(
            serde_json::from_str::<AdapterPack>(
                r#"{
                    "id": "kobo-pack",
                    "version": "1",
                    "testedVersions": [],
                    "sourceRoutes": [
                        { "id": "a", "scan": "ongoing", "nextRecovery": "exact-replay", "bogus": 1 }
                    ]
                }"#,
            )
            .is_err(),
            "an unknown member is refused"
        );
        assert!(
            serde_json::from_str::<SourceScan>("\"sweeping\"").is_err(),
            "scan is a closed set"
        );
        assert!(
            serde_json::from_str::<SourceRecovery>("\"replay\"").is_err(),
            "recovery is a closed set"
        );
        assert!(
            UniqueIdList::new(vec![
                SourceRouteDecl {
                    id: LocalId::new("same").expect("id"),
                    scan: None,
                    next_recovery: None,
                    edits: None,
                    rescan_delay_seconds: None,
                    steps: Vec::new(),
                },
                SourceRouteDecl {
                    id: LocalId::new("same").expect("id"),
                    scan: None,
                    next_recovery: None,
                    edits: None,
                    rescan_delay_seconds: None,
                    steps: Vec::new(),
                },
            ])
            .is_err(),
            "a repeated source route id is refused"
        );
    }

    /// The safe-upstream claim round trips under its camelCase name and
    /// stays default-off: an operation that does not claim it decodes
    /// without the member, and an unknown member beside the claim still
    /// refuses (CFG-VAL-2).
    #[test]
    fn safe_upstream_claim_round_trips_and_defaults_off() {
        let claimed: EndpointOperation =
            serde_json::from_str(r#"{"id": "cases-find", "safeUpstream": true}"#).expect("decode");
        assert!(claimed.safe_upstream);
        let json = serde_json::to_string(&claimed).expect("serialize");
        assert!(json.contains("safeUpstream"));
        assert_eq!(
            serde_json::from_str::<EndpointOperation>(&json).ok(),
            Some(claimed)
        );
        let unclaimed: EndpointOperation =
            serde_json::from_str(r#"{"id": "cases-find"}"#).expect("decode");
        assert!(!unclaimed.safe_upstream);
        assert!(
            serde_json::from_str::<EndpointOperation>(
                r#"{"id": "cases-find", "safeUpstreamTypo": true}"#
            )
            .is_err(),
            "an unknown member beside the claim refuses"
        );
    }

    /// GraphQL operation kinds spell lowercase on the wire: the
    /// CONFIG-CONVENTIONS enum-value rule, and the GraphQL keywords
    /// themselves.
    #[test]
    fn graphql_operation_kinds_spell_lowercase() {
        assert_eq!(
            serde_json::to_string(&GraphQlOperationKind::Query).expect("serialize"),
            r#""query""#
        );
        assert_eq!(
            serde_json::to_string(&GraphQlOperationKind::Mutation).expect("serialize"),
            r#""mutation""#
        );
        assert_eq!(
            serde_json::from_str::<GraphQlOperationKind>(r#""query""#).ok(),
            Some(GraphQlOperationKind::Query)
        );
        assert_eq!(
            serde_json::from_str::<GraphQlOperationKind>(r#""mutation""#).ok(),
            Some(GraphQlOperationKind::Mutation)
        );
        assert!(
            serde_json::from_str::<GraphQlOperationKind>(r#""Query""#).is_err(),
            "PascalCase spellings refuse at the reader"
        );
    }

    /// An endpoint's response-header allowlist is unique at the reader
    /// (CFG-ID-6): a repeated header name is refused.
    #[test]
    fn response_header_allowlist_is_unique() {
        let read = |headers: serde_json::Value| {
            let mut endpoint = serde_json::to_value(endpoint()).expect("endpoint");
            endpoint["responseHeaders"] = headers;
            serde_json::from_value::<AdapterPack>(serde_json::json!({
                "id": "case-api-pack",
                "version": "1.0.0",
                "testedVersions": ["2.7"],
                "endpoints": [endpoint],
            }))
        };
        assert!(read(serde_json::json!(["etag", "location"])).is_ok());
        assert!(
            read(serde_json::json!(["etag", "etag"])).is_err(),
            "a repeated response header is refused"
        );
    }

    /// Duplicate endpoint ids are refused at the reader (CFG-ID-5).
    #[test]
    fn duplicate_endpoint_ids_are_refused() {
        assert!(
            UniqueIdList::new(vec![endpoint(), endpoint()]).is_err(),
            "duplicate endpoint id refused"
        );
    }

    /// The inventory lookup resolves both script and query files.
    #[test]
    fn pinned_file_lookup() {
        let pack = AdapterPack {
            id: LocalId::new("case-api-pack").expect("id"),
            version: "1.0.0".to_string(),
            tested_versions: Vec::new(),
            endpoints: UniqueIdList::new(Vec::new()).expect("empty"),
            route_templates: UniqueIdList::new(Vec::new()).expect("empty"),
            routes: UniqueIdList::new(Vec::new()).expect("empty"),
            code_maps: UniqueIdList::new(Vec::new()).expect("empty"),
            scripts: UniqueList::new(vec![crate::model::ScriptReference {
                path: "scripts/map.rhai".to_string(),
                digest: Digest::new(
                    "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9",
                )
                .expect("digest"),
            }])
            .expect("unique"),
            query_files: UniqueList::new(Vec::new()).expect("empty"),
            source_routes: UniqueIdList::new(Vec::new()).expect("empty"),
            capabilities: Capabilities::default(),
        };
        assert!(pack.pinned_file("scripts/map.rhai").is_some());
        assert!(pack.pinned_file("scripts/other.rhai").is_none());
    }
}
