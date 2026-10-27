// SPDX-License-Identifier: Apache-2.0
//! Conservative offline ODRL projection for operator review.
//!
//! This export is descriptive and partial. It neither grants authority nor
//! changes the runtime, package, or public Registry Manifest projection.

use std::collections::BTreeMap;

use registry_manifest_core::odrl::{
    render_policy_collection, Constraint, Operand, Permission, Policy, PolicyAsset,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::contract::{AccessProfileSource, ActorKindSource, Operation};
use crate::diagnostics::Diagnostic;
use crate::model::{CompiledEntity, CompiledRegistry};
use crate::GeneratedArtifact;

pub const COVERAGE_API_VERSION: &str = "id.registrystack.org/formats/breg/odrl-coverage/v1alpha1";
pub const PROFILE_IRI: &str = "https://id.registrystack.org/profiles/breg-odrl/v1";
pub const VOCAB: &str = "https://id.registrystack.org/vocab/breg-odrl#";

const ODRL_EQ: &str = "http://www.w3.org/ns/odrl/2/eq";
const ODRL_HAS_PART: &str = "http://www.w3.org/ns/odrl/2/hasPart";
const ODRL_IS_PART_OF: &str = "http://www.w3.org/ns/odrl/2/isPartOf";
const ODRL_READ: &str = "http://www.w3.org/ns/odrl/2/read";
const DCTERMS_DESCRIPTION: &str = "http://purl.org/dc/terms/description";
const PROFILE_BYTES: &[u8] = include_bytes!("../../../products/breg/contracts/odrl-profile.jsonld");

const EXCLUDED_SURFACES: &[&str] = &[
    "actions",
    "proposals",
    "statistics",
    "lookups",
    "read-paths",
    "revisions",
    "snapshots",
    "mutations",
    "counts",
    "filters",
    "sorting",
    "spatial-queries",
    "data-export",
    "provenance",
];

#[derive(Debug)]
pub struct OdrlExport {
    pub artifacts: Vec<GeneratedArtifact>,
    pub coverage: Value,
}

pub fn export_odrl(
    registry: &CompiledRegistry,
    selected_profile: Option<&str>,
) -> Result<OdrlExport, Diagnostic> {
    if let Some(selected) = selected_profile {
        if !registry
            .access_profile_displays()
            .iter()
            .any(|profile| profile.id == selected)
        {
            return Err(refusal(
                "breg.odrl.unknown-access-profile",
                "accessProfile",
                "select an access profile declared by the compiled registry",
            ));
        }
    }

    let ids = ExportIds::new(registry);
    let mut policies = BTreeMap::<String, Policy>::new();
    let mut grants = Vec::new();
    let mut exported = 0_u64;

    for entity in registry.entities().values() {
        for (profile_id, access) in &entity.access_profiles {
            audit_access_profile(access);
            if selected_profile.is_some_and(|selected| selected != profile_id) {
                continue;
            }
            for operation in &access.operations {
                let operation_name = operation_name(*operation);
                let reasons = omission_reasons(access, *operation);
                let status = if reasons.is_empty() {
                    let policy = policies
                        .entry(profile_id.clone())
                        .or_insert_with(|| Policy {
                            uid: ids.policy(profile_id),
                            profile: vec![PROFILE_IRI.to_owned()],
                            permissions: Vec::new(),
                        });
                    policy.permissions.push(permission(
                        &ids,
                        entity,
                        access,
                        profile_id,
                        operation_name,
                    ));
                    exported += 1;
                    "exported"
                } else {
                    "omitted"
                };
                grants.push(json!({
                    "recordType": entity.id,
                    "accessProfile": profile_id,
                    "operation": operation_name,
                    "status": status,
                    "reasons": reasons,
                }));
            }
        }
    }

    let considered = grants.len() as u64;
    let coverage = json!({
        "apiVersion": COVERAGE_API_VERSION,
        "kind": "BRegOdrlCoverage",
        "registryId": registry.registry_id(),
        "revision": registry.revision(),
        "partial": true,
        "audience": "operator-review",
        "scope": "record-operation-grants",
        "selectedAccessProfile": selected_profile,
        "totals": {
            "considered": considered,
            "exported": exported,
            "omitted": considered - exported,
        },
        "grants": grants,
        "excludedSurfaces": EXCLUDED_SURFACES,
    });

    let policies = policies.into_values().collect::<Vec<_>>();
    let mut rendered = render_policy_collection(&ids.collection(), &policies).map_err(|_| {
        refusal(
            "breg.odrl.render-failed",
            "odrl",
            "the selected access rules could not be rendered as the supported ODRL profile",
        )
    })?;
    let collection = rendered.as_object_mut().ok_or_else(|| {
        refusal(
            "breg.odrl.render-failed",
            "odrl",
            "the ODRL renderer returned an invalid collection",
        )
    })?;
    collection.insert(format!("{VOCAB}partial"), Value::Bool(true));
    collection.insert(
        DCTERMS_DESCRIPTION.to_owned(),
        Value::String(
            "Partial, non-enforcing projection of supported BReg record-operation grants; review coverage.json before use."
                .to_owned(),
        ),
    );

    let mut artifacts = vec![
        json_artifact(
            "generated/odrl/coverage.json",
            "application/json",
            &coverage,
        )?,
        json_artifact(
            "generated/odrl/policies.jsonld",
            "application/ld+json",
            &rendered,
        )?,
        artifact(
            "generated/odrl/profile.jsonld",
            "application/ld+json",
            PROFILE_BYTES.to_vec(),
        ),
    ];
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(OdrlExport {
        artifacts,
        coverage,
    })
}

fn permission(
    ids: &ExportIds,
    entity: &CompiledEntity,
    access: &AccessProfileSource,
    profile_id: &str,
    operation: &str,
) -> Permission {
    let readable_fields = access
        .readable_fields
        .iter()
        .map(|field| json!({"@value": field}))
        .collect::<Vec<_>>();
    let properties = BTreeMap::from([
        (format!("{VOCAB}recordType"), json!(entity.id)),
        (
            format!("{VOCAB}readableFields"),
            json!({"@list": readable_fields}),
        ),
    ]);

    Permission {
        target: PolicyAsset {
            uid: ids.projection(&entity.id, profile_id, operation),
            part_of: Some(ids.record_type(&entity.id)),
            properties,
        },
        action: ODRL_READ.to_owned(),
        constraints: constraints(access, profile_id, operation),
    }
}

fn constraints(access: &AccessProfileSource, profile_id: &str, operation: &str) -> Vec<Constraint> {
    let mut constraints = vec![
        literal_constraint("authenticated", ODRL_EQ, json!(true)),
        set_constraint(
            "verifiedNonemptyClaims",
            ODRL_HAS_PART,
            std::iter::once(access.principal_claim.as_str()),
        ),
        literal_constraint("accessProfile", ODRL_EQ, json!(profile_id)),
        literal_constraint("operation", ODRL_EQ, json!(operation)),
        literal_constraint(
            "delegatedActor",
            ODRL_EQ,
            json!(access.actor_kind == Some(ActorKindSource::Agent)),
        ),
        literal_constraint("taskGrantPresent", ODRL_EQ, json!(false)),
    ];
    if !access.required_scopes.is_empty() {
        constraints.push(set_constraint(
            "tokenScopes",
            ODRL_HAS_PART,
            access.required_scopes.iter().map(String::as_str),
        ));
    }
    if !access.required_purposes.is_empty() {
        constraints.push(set_constraint(
            "tokenPurpose",
            ODRL_IS_PART_OF,
            access.required_purposes.iter().map(String::as_str),
        ));
    }
    if !access.requester_clients.is_empty() {
        constraints.push(set_constraint(
            "requesterClient",
            ODRL_IS_PART_OF,
            access.requester_clients.iter().map(String::as_str),
        ));
    }
    if let Some(actor_kind) = access.actor_kind {
        constraints.push(literal_constraint(
            "actorKind",
            ODRL_EQ,
            json!(actor_kind_name(actor_kind)),
        ));
    }
    constraints
}

fn literal_constraint(term: &str, operator: &str, value: Value) -> Constraint {
    Constraint {
        left_operand: format!("{VOCAB}{term}"),
        operator: operator.to_owned(),
        right_operand: Operand::Literal(value),
    }
}

fn set_constraint<'a>(
    term: &str,
    operator: &str,
    values: impl Iterator<Item = &'a str>,
) -> Constraint {
    Constraint {
        left_operand: format!("{VOCAB}{term}"),
        operator: operator.to_owned(),
        right_operand: Operand::Set(values.map(|value| json!(value)).collect()),
    }
}

fn omission_reasons(access: &AccessProfileSource, operation: Operation) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if !matches!(operation, Operation::Get | Operation::List) {
        reasons.push("unsupported-operation");
    }
    if !access.row_boundaries.is_empty() {
        reasons.push("row-boundaries");
    }
    if !access.membership_boundaries.is_empty() {
        reasons.push("membership-boundaries");
    }
    if !access.require_consent.is_empty() {
        reasons.push("consent");
    }
    if access.task_grant.is_some() {
        reasons.push("task-grant");
    }
    reasons
}

/// Force every compiled access-profile member through an explicit review when
/// a new member is added. Export logic may ignore only the fields named here.
fn audit_access_profile(access: &AccessProfileSource) {
    let AccessProfileSource {
        id: _,
        display: _,
        default: _,
        actor_kind: _,
        requester_clients: _,
        task_grant: _,
        principal_claim: _,
        required_scopes: _,
        required_purposes: _,
        operations: _,
        readable_fields: _,
        writable_fields: _,
        filterable_fields: _,
        sortable_fields: _,
        spatial_queries: _,
        row_boundaries: _,
        membership_boundaries: _,
        require_consent: _,
        lookups: _,
        read_paths: _,
        allow_count: _,
        revision_access: _,
        provenance_fields: _,
        allow_data_export: _,
    } = access;
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Get => "get",
        Operation::Lookup => "lookup",
        Operation::List => "list",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        Operation::Batch => "batch",
        Operation::Revisions => "revisions",
        Operation::Snapshot => "snapshot",
        Operation::Invoke => "invoke",
        Operation::Start => "start",
        Operation::Import => "import",
    }
}

fn actor_kind_name(actor_kind: ActorKindSource) -> &'static str {
    match actor_kind {
        ActorKindSource::Human => "human",
        ActorKindSource::Agent => "agent",
        ActorKindSource::Service => "service",
    }
}

struct ExportIds {
    root: String,
    separator: char,
}

impl ExportIds {
    fn new(registry: &CompiledRegistry) -> Self {
        let revision = segment(registry.revision());
        registry.manifest_projection().map_or_else(
            || Self {
                root: format!(
                    "urn:registrystack:breg:{}:revision:{}:odrl",
                    segment(registry.registry_id()),
                    revision
                ),
                separator: ':',
            },
            |projection| Self {
                root: format!(
                    "{}/.well-known/registrystack/odrl/revisions/{}",
                    projection.canonical_base_iri.trim_end_matches('/'),
                    revision
                ),
                separator: '/',
            },
        )
    }

    fn child(&self, segments: &[&str]) -> String {
        let separator = self.separator.to_string();
        format!(
            "{}{}{}",
            self.root,
            self.separator,
            segments
                .iter()
                .map(|value| segment(value))
                .collect::<Vec<_>>()
                .join(&separator)
        )
    }

    fn collection(&self) -> String {
        self.child(&["policies"])
    }

    fn policy(&self, profile: &str) -> String {
        self.child(&["profiles", profile, "policy"])
    }

    fn record_type(&self, entity: &str) -> String {
        self.child(&["record-types", entity])
    }

    fn projection(&self, entity: &str, profile: &str, operation: &str) -> String {
        self.child(&[
            "record-types",
            entity,
            "profiles",
            profile,
            "operations",
            operation,
            "projection",
        ])
    }
}

fn segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn json_artifact(
    path: &str,
    media_type: &str,
    value: &Value,
) -> Result<GeneratedArtifact, Diagnostic> {
    let bytes = canonicalize_json(value).map_err(|_| {
        refusal(
            "breg.odrl.canonicalization-failed",
            path,
            "the ODRL export could not be canonicalized",
        )
    })?;
    Ok(artifact(path, media_type, bytes))
}

fn artifact(path: &str, media_type: &str, bytes: Vec<u8>) -> GeneratedArtifact {
    GeneratedArtifact {
        path: path.to_owned(),
        media_type: media_type.to_owned(),
        sha256: format!("sha256:{}", digest(&bytes)),
        bytes,
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn refusal(code: &str, path: &str, message: &str) -> Diagnostic {
    Diagnostic::error(code, path, message)
}

#[cfg(all(test, feature = "runtime"))]
mod tests;
