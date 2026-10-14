//! Complete target grants, shared by local and production authoring.
use crate::{
    finding::{FieldPath, Finding},
    formats::{decode_authored, findings_report},
    project::{BindingMode, EvidenceProject, Representation},
};
use registry_platform_yaml::{
    ApiVersion, Decoded, EnvelopeRule, FormatSpec, LocalId, Report, UniqueList,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const TARGET_API_VERSION: &str = "id.registrystack.org/formats/evidence/target/v1alpha1";
pub const TARGET_KIND: &str = "EvidenceTarget";
pub const AUTHORITY_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/target-authority/v1alpha1";
pub const AUTHORITY_KIND: &str = "EvidenceTargetAuthority";
pub const TARGET: FormatSpec<'static> = FormatSpec {
    kind: TARGET_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(TARGET_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
pub const AUTHORITY: FormatSpec<'static> = FormatSpec {
    kind: AUTHORITY_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(AUTHORITY_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceTargetAuthority {
    pub target: LocalId,
    pub project: LocalId,
    pub access_profiles: BTreeMap<LocalId, AccessProfile>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessProfile {
    pub authority: String,
    pub actor_kind: String,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub requester_tags: UniqueList<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_clients: Option<UniqueList<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_source_issuer: Option<registry_platform_yaml::Url>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub grants: Vec<AccessGrant>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessGrant {
    pub definition: LocalId,
    pub purpose: String,
    pub audience_from: String,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub representations: UniqueList<Representation>,
    pub subject_binding: BindingMode,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub subjects: Vec<GrantedSubject>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedSubject {
    pub role: LocalId,
    pub selector_profile: LocalId,
    #[cfg_attr(feature = "schema", schemars(extend("enum" = ["request", "authenticated-context", "authenticated-grant"])))]
    pub value_origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_claims: Option<BTreeMap<LocalId, String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceTarget {
    pub id: LocalId,
    pub project: LocalId,
    pub package: Value,
    pub authority: String,
    pub service: Value,
    pub listener: Value,
    pub authentication: Value,
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-passthrough" = "Named target connection bindings, compiled into the retained Evidence runtime connection contract.")))]
    pub connections: BTreeMap<LocalId, Value>,
    pub secret_providers: Value,
    pub signer: Value,
    pub subject_binding: Value,
    pub audit: Value,
    pub rate_limits: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_formats: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_tls: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracts: Option<Value>,
    /// Operator opt-ins, intersected with the package's acquisition capabilities.
    #[serde(default, skip_serializing_if = "crate::project::empty_capabilities")]
    pub acquisition_capabilities: UniqueList<crate::project::AcquisitionCapability>,
}

pub fn read_target(file: &str, bytes: &[u8]) -> Result<Decoded<EvidenceTarget>, Report> {
    let decoded = decode_authored::<EvidenceTarget>(file, bytes, &TARGET)?;
    let mut findings = Vec::new();
    if decoded
        .value
        .authentication
        .pointer("/oidc/jwksFile")
        .is_some()
    {
        findings.push(Finding::new(FieldPath::root().key("authentication").key("oidc").key("jwksFile"), "target-jwks-source", "declare jwksSource with type uri and the issuer JWKS URI; jwksFile is not an Evidence authentication binding"));
    }
    if decoded
        .value
        .authentication
        .pointer("/oidc/jwksSource/uri")
        .and_then(Value::as_str)
        .is_none()
    {
        findings.push(Finding::new(
            FieldPath::root()
                .key("authentication")
                .key("oidc")
                .key("jwksSource"),
            "target-jwks-source",
            "declare an explicit URI source for verified issuer keys",
        ));
    }
    let report = findings_report(&decoded.document, "target", findings);
    if report.has_errors() {
        return Err(report);
    }
    Ok(decoded)
}
pub fn read_authority(
    file: &str,
    bytes: &[u8],
    project: &EvidenceProject,
) -> Result<Decoded<EvidenceTargetAuthority>, Report> {
    let decoded = decode_authored::<EvidenceTargetAuthority>(file, bytes, &AUTHORITY)?;
    let report = findings_report(
        &decoded.document,
        "authority",
        validate_authority(&decoded.value, project),
    );
    if report.has_errors() {
        return Err(report);
    }
    Ok(decoded)
}

pub fn validate_authority(
    authority: &EvidenceTargetAuthority,
    project: &EvidenceProject,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if authority.project != project.id {
        findings.push(Finding::new(
            FieldPath::root().key("project"),
            "authority-project",
            "target authority must name this EvidenceProject",
        ));
    }
    for (id, profile) in &authority.access_profiles {
        let at = FieldPath::root()
            .key("accessProfiles")
            .map_key(id.to_string());
        if profile.requester_tags.is_empty() || profile.grants.is_empty() {
            findings.push(Finding::new(
                at.clone(),
                "authority-profile-empty",
                "a profile requires identity tags and complete grants",
            ));
        }
        for (index, grant) in profile.grants.iter().enumerate() {
            let at = at.clone().key("grants").index(index);
            let Some(definition) = project.assertion_definitions.get(&grant.definition) else {
                findings.push(Finding::new(
                    at.key("definition"),
                    "authority-definition",
                    "grant must name an existing AssertionDefinition",
                ));
                continue;
            };
            let matches = definition
                .grant_ceiling
                .authorities
                .iter()
                .any(|kind| kind == &profile.authority)
                && definition
                    .grant_ceiling
                    .actor_kinds
                    .iter()
                    .any(|kind| kind == &profile.actor_kind)
                && grant.purpose == definition.purpose
                && grant.subject_binding == definition.subject_binding
                && grant.audience_from == "authenticated-requester"
                && !grant.representations.is_empty()
                && grant
                    .representations
                    .iter()
                    .all(|format| definition.representations.contains(format))
                && grant.subjects.len() == definition.subjects.len()
                && grant.subjects.iter().all(|subject| {
                    definition.subjects.iter().any(|role| {
                        role.role == subject.role
                            && role.selectors.contains(&subject.selector_profile)
                    }) && definition
                        .grant_ceiling
                        .value_origins
                        .contains(&subject.value_origin)
                });
            let roles = grant
                .subjects
                .iter()
                .map(|subject| &subject.role)
                .collect::<std::collections::BTreeSet<_>>();
            if !matches || roles.len() != grant.subjects.len() {
                findings.push(Finding::new(
                    at,
                    "authority-ceiling",
                    "each complete grant must stay inside every definition ceiling",
                ));
            }
        }
    }
    findings
}

/// Resolve local authoring names exactly once, without adding or unioning any
/// permission. Activation and runtime matching validate the compiled tuple too.
pub fn compile_authority(
    authority: &EvidenceTargetAuthority,
    project: &EvidenceProject,
) -> Result<Value, Vec<Finding>> {
    let findings = validate_authority(authority, project);
    if !findings.is_empty() {
        return Err(findings);
    }
    let profiles = authority.access_profiles.iter().map(|(id, profile)| {
        let mut compiled = json!({"kind":profile.authority,"actorKind":profile.actor_kind,"requesterTags":profile.requester_tags,"grants":profile.grants.iter().map(|grant| json!({"requirement":project.assertion_definitions[&grant.definition].semantics.requirement,"purpose":grant.purpose,"audienceFrom":grant.audience_from,"responseFormats":grant.representations,"subjectBindingModes":[grant.subject_binding],"subjects":grant.subjects})).collect::<Vec<_>>()});
        if let Some(clients) = &profile.requester_clients { if !clients.is_empty() { compiled["requesterClients"] = json!(clients); } }
        if let Some(issuer) = &profile.grant_source_issuer { compiled["grantSourceIssuer"] = json!(issuer); }
        (id.as_str(), compiled)
    }).collect::<BTreeMap<_, _>>();
    Ok(
        json!({"apiVersion":"id.registrystack.org/formats/evidence/compiled-target-authority/v1alpha1","kind":"EvidenceCompiledTargetAuthority","target":authority.target,"project":authority.project,"accessProfiles":profiles}),
    )
}
