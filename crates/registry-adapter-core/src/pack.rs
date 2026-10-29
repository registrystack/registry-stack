// SPDX-License-Identifier: Apache-2.0

//! The adapter pack: a reviewed catalog of route templates, the role
//! Kamelets play for Camel (`products/adapter/CONCEPT.md` sections 6, 8.4,
//! and 8.8). A pack knows one source system and produces records in the
//! project's declared model.

use crate::auth::EndpointAuthentication;
use crate::model::{ComponentKind, Eip, Language};
use crate::route::{RouteDefinition, RouteTemplate};
use registry_platform_yaml::{Digest, ExternalId, UniqueIdList, UniqueList};
use serde::{Deserialize, Serialize};

/// One endpoint a route may send to: the component, the authentication
/// kind, the declared response headers, the endpoint operations with their
/// `idempotentUpstream` claims, and the tested upstream versions
/// (`products/adapter/CONCEPT.md` sections 6, 8.8, and 10.2).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    /// The endpoint identifier `http:` and `graphql:` URIs name.
    pub id: ExternalId,
    /// The producer component: `http` or `graphql`.
    pub component: ComponentKind,
    /// The upstream authentication kind, with its non-secret parameters.
    pub authentication: EndpointAuthentication,
    /// The response headers the engine copies onto the exchange, Camel's
    /// `HeaderFilterStrategy` as an allowlist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_headers: Vec<ExternalId>,
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
    pub id: ExternalId,
    /// The reviewed claim that repeating this operation's send is safe,
    /// for example an upstream create with client-supplied UIDs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub idempotent_upstream: bool,
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
    pub id: ExternalId,
    /// The conversion entries.
    pub entries: std::collections::BTreeMap<String, serde_json::Value>,
}

impl registry_platform_yaml::Identified for CodeMap {
    fn id(&self) -> &str {
        self.id.as_str()
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
    pub id: ExternalId,
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
            id: ExternalId::new("case-api").expect("id"),
            component: ComponentKind::Http,
            authentication: EndpointAuthentication::Oauth2ClientCredentials {},
            response_headers: vec![ExternalId::new("etag").expect("header")],
            operations: vec![EndpointOperation {
                id: ExternalId::new("cases.upsert").expect("op"),
                idempotent_upstream: true,
            }],
            tested_versions: vec!["2.7".to_string()],
            query_file: None,
            operation_name: None,
            variables: None,
        }
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

    /// The pack artifact round-trips: endpoints with component kind and
    /// authentication, templates, internal routes, code maps, inventories,
    /// and capabilities.
    #[test]
    fn pack_round_trips() {
        let pack = AdapterPack {
            id: ExternalId::new("case-api-pack").expect("id"),
            version: "1.0.0".to_string(),
            tested_versions: vec!["2.7".to_string()],
            endpoints: UniqueIdList::new(vec![endpoint()]).expect("unique"),
            route_templates: UniqueIdList::new(vec![RouteTemplate {
                id: ExternalId::new("pagedFetch").expect("id"),
                parameters: Vec::new(),
                steps: Vec::new(),
            }])
            .expect("unique"),
            routes: UniqueIdList::new(vec![RouteDefinition {
                id: ExternalId::new("sharedLookup").expect("id"),
                from: crate::route::RouteFrom {
                    uri: SendUri::parse("direct:sharedLookup").expect("uri"),
                },
                steps: Vec::new(),
            }])
            .expect("unique"),
            code_maps: UniqueIdList::new(vec![CodeMap {
                id: ExternalId::new("genderCodes").expect("id"),
                entries: std::collections::BTreeMap::from([(
                    "female".to_string(),
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
            capabilities: Capabilities {
                components: UniqueList::new(vec![ComponentKind::Http]).expect("unique"),
                languages: UniqueList::new(vec![Language::JsonPath]).expect("unique"),
                eips: UniqueList::new(vec![Eip::Split, Eip::Enrich]).expect("unique"),
            },
        };
        let json = serde_json::to_string(&pack).expect("serialize");
        assert!(json.contains("idempotentUpstream"));
        assert_eq!(serde_json::from_str::<AdapterPack>(&json).ok(), Some(pack));
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
            id: ExternalId::new("case-api-pack").expect("id"),
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
            capabilities: Capabilities::default(),
        };
        assert!(pack.pinned_file("scripts/map.rhai").is_some());
        assert!(pack.pinned_file("scripts/other.rhai").is_none());
    }
}
