//! Complete target grants, shared by local and production authoring.
use crate::{
    finding::{FieldPath, Finding},
    formats::{decode_authored, findings_report},
    project::{
        ActorKind, AuthorityKind, BindingMode, EvidenceProject, Representation, ValueOrigin,
    },
};
use registry_platform_yaml::{
    ApiVersion, Decoded, Diagnostic, EnvelopeRule, FormatSpec, LocalId, RemovedKey, Report,
    Severity, UniqueList,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub use crate::target_binding::*;

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
    removed_keys: TARGET_REMOVED_KEYS,
};

/// The flat 0.44 connection form, whose endpoint members now sit under one
/// pack endpoint. Each member says where it moved, so an operator moves the
/// origin, credential and trust profile instead of deleting them.
const TARGET_REMOVED_KEYS: &[RemovedKey<'static>] = &[
    RemovedKey {
        pointer: "/connections/*/origin",
        replacement: MOVED_ORIGIN,
    },
    RemovedKey {
        pointer: "/connections/*/authentication",
        replacement: MOVED_AUTHENTICATION,
    },
    RemovedKey {
        pointer: "/connections/*/tlsTrustProfile",
        replacement: MOVED_TLS_TRUST_PROFILE,
    },
    RemovedKey {
        pointer: "/connections/*/maximumConcurrency",
        replacement: RETIRED_CONNECTION_CONCURRENCY,
    },
    RemovedKey {
        pointer: "/connections/*/admissionTimeoutMilliseconds",
        replacement: RETIRED_CONNECTION_BUDGET,
    },
    RemovedKey {
        pointer: "/connections/*/tokenTimeoutMilliseconds",
        replacement: RETIRED_CONNECTION_BUDGET,
    },
];
const MOVED_ORIGIN: &str = "Move it to connections.<id>.endpoints.<pack endpoint id>.origin, one entry per endpoint the pack declares; see products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project.";
const MOVED_AUTHENTICATION: &str = "Move it unchanged to connections.<id>.endpoints.<pack endpoint id>.authentication; see products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project.";
const MOVED_TLS_TRUST_PROFILE: &str = "Move it to connections.<id>.endpoints.<pack endpoint id>.tlsTrustProfile; see products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project.";
const RETIRED_CONNECTION_CONCURRENCY: &str = "Delete it from the authored target; the operator sets concurrency in the runtime file, at sourceConnections.<id>.endpoints.<id>.maximumConcurrency (1 to 256, default 8). Bound each attempt with connections.<id>.endpoints.<pack endpoint id>.attemptTimeoutMilliseconds and the whole acquisition with sourceAcquisition; see products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project.";
const RETIRED_CONNECTION_BUDGET: &str = "Delete it; a connection no longer sets this budget. Bound each attempt with connections.<id>.endpoints.<pack endpoint id>.attemptTimeoutMilliseconds and the whole acquisition with sourceAcquisition; see products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project.";
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
    /// Experimental (`v1alpha1`). Activates the unauthenticated public
    /// certificate check for one definition that declares `publicCheck`. A
    /// check-only instance leaves `accessProfiles` empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_check: Option<PublicCheckActivation>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicCheckActivation {
    /// The definition whose `publicCheck` declaration this target serves.
    pub definition: LocalId,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessProfile {
    /// A name for the profile, accepted for authoring and tooling; never matched against a caller.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub label: Option<String>,
    /// What the profile is for, accepted for authoring and tooling; never matched against a caller.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub description: Option<String>,
    pub authority: AuthorityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<ActorKind>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 32)))]
    pub requester_tags: UniqueList<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 32)))]
    pub requester_clients: Option<UniqueList<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_source_issuer: Option<registry_platform_yaml::Url>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
    pub grants: Vec<AccessGrant>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessGrant {
    pub definition: LocalId,
    pub purpose: String,
    pub audience_from: AudienceFrom,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 4)))]
    pub representations: UniqueList<Representation>,
    pub subject_binding: BindingMode,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 8)))]
    pub subjects: Vec<GrantedSubject>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AudienceFrom {
    AuthenticatedRequester,
}
impl AudienceFrom {
    pub const fn as_str(self) -> &'static str {
        "authenticated-requester"
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedSubject {
    pub role: LocalId,
    pub selector_profile: LocalId,
    pub value_origin: ValueOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_claims: Option<BTreeMap<LocalId, String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceTarget {
    pub id: LocalId,
    pub project: LocalId,
    pub package: TargetPackage,
    pub authority: String,
    pub service: TargetService,
    pub listener: TargetListener,
    pub authentication: TargetAuthentication,
    /// Explicit endpoint bindings and their reviewed connection policies. An
    /// empty mapping grants no outbound endpoint authority.
    pub connections: BTreeMap<LocalId, TargetConnection>,
    /// Optional operational acquisition budget projected only into runtime
    /// configuration. Omission uses the Evidence engine defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_acquisition: Option<TargetSourceAcquisition>,
    pub secret_providers: TargetSecretProviders,
    pub signer: TargetSigner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<TargetSigning>,
    pub subject_binding: TargetSubjectBinding,
    pub audit: TargetAudit,
    pub rate_limits: TargetRateLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_profile: Option<TargetAssuranceProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication: Option<TargetPublication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_formats: Option<UniqueList<TargetResponseFormat>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_tls: Option<TargetOutboundTls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracts: Option<BTreeMap<LocalId, TargetExtractBinding>>,
}

pub fn read_target(file: &str, bytes: &[u8]) -> Result<Decoded<EvidenceTarget>, Report> {
    let decoded = decode_authored::<EvidenceTarget>(file, bytes, &TARGET)?;
    let report = decoded
        .document
        .report_with(target_id_collision_diagnostics(&decoded));
    if report.has_errors() {
        Err(report)
    } else {
        Ok(decoded)
    }
}
pub fn read_authority(
    file: &str,
    bytes: &[u8],
    project: &EvidenceProject,
) -> Result<Decoded<EvidenceTargetAuthority>, Report> {
    let decoded = decode_authored::<EvidenceTargetAuthority>(file, bytes, &AUTHORITY)?;
    let mut diagnostics = findings_report(
        &decoded.document,
        "authority",
        validate_authority(&decoded.value, project),
    )
    .into_diagnostics();
    diagnostics.extend(map_id_collision_diagnostics(
        &decoded.document,
        "evidence.authority.access-profile-id-collision",
        "/accessProfiles",
        &decoded.value.access_profiles,
    ));
    let report = decoded.document.report_with(diagnostics);
    if report.has_errors() {
        return Err(report);
    }
    Ok(decoded)
}

fn map_id_collision_diagnostics<T>(
    document: &registry_platform_yaml::Document,
    code: &str,
    base: &str,
    values: &BTreeMap<LocalId, T>,
) -> Vec<Diagnostic> {
    let owned = values
        .keys()
        .map(|id| {
            let id = id.as_str().to_owned();
            let pointer = format!(
                "{base}/{}",
                registry_platform_yaml::escape_pointer_segment(&id)
            );
            (id, pointer)
        })
        .collect::<Vec<_>>();
    let entries = owned
        .iter()
        .map(|(id, pointer)| registry_platform_yaml::AuthoredId::at_key(id, pointer))
        .collect::<Vec<_>>();
    registry_platform_yaml::local_id_collision_diagnostics(document, code, &entries)
}

fn target_id_collision_diagnostics(decoded: &Decoded<EvidenceTarget>) -> Vec<Diagnostic> {
    let mut diagnostics = map_id_collision_diagnostics(
        &decoded.document,
        "evidence.target.connection-id-collision",
        "/connections",
        &decoded.value.connections,
    );
    if let Some(extracts) = &decoded.value.extracts {
        diagnostics.extend(map_id_collision_diagnostics(
            &decoded.document,
            "evidence.target.extract-id-collision",
            "/extracts",
            extracts,
        ));
    }
    if let Some(outbound_tls) = &decoded.value.outbound_tls {
        diagnostics.extend(map_id_collision_diagnostics(
            &decoded.document,
            "evidence.target.trust-profile-id-collision",
            "/outboundTls/trustProfiles",
            &outbound_tls.trust_profiles,
        ));
    }
    diagnostics.extend(unused_trust_profile_diagnostics(decoded));
    diagnostics
}

/// Refuse a trust profile that no endpoint and no issuer names, at its key.
///
/// The runtime refuses an unused profile too, but only after projection and
/// without a place in `target.yaml`; this names the profile where it is
/// written and the two ways to resolve it.
fn unused_trust_profile_diagnostics(decoded: &Decoded<EvidenceTarget>) -> Vec<Diagnostic> {
    let target = &decoded.value;
    let Some(outbound_tls) = &target.outbound_tls else {
        return Vec::new();
    };
    let referenced = target
        .authentication
        .oidc
        .tls_trust_profile
        .as_deref()
        .into_iter()
        .chain(
            target
                .connections
                .values()
                .flat_map(|connection| connection.endpoints.values())
                .filter_map(|endpoint| endpoint.tls_trust_profile.as_deref()),
        )
        .collect::<std::collections::BTreeSet<_>>();
    outbound_tls
        .trust_profiles
        .keys()
        .filter(|id| !referenced.contains(id.as_str()))
        .map(|id| {
            decoded.document.diagnostic_at_key(
                Severity::Error,
                "evidence.target.trust-profile-unused",
                &format!(
                    "/outboundTls/trustProfiles/{}",
                    registry_platform_yaml::escape_pointer_segment(id.as_str())
                ),
                &format!("trust profile `{id}` is not named by any endpoint or by the token issuer, so the runtime would refuse this target"),
                "Name it from a connection endpoint `tlsTrustProfile` or from `authentication.oidc.tlsTrustProfile`, or delete it.",
            )
        })
        .collect()
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
    if let Some(activation) = &authority.public_check {
        if !project
            .assertion_definitions
            .get(&activation.definition)
            .is_some_and(|definition| definition.public_check.is_some())
        {
            findings.push(Finding::new(
                FieldPath::root().key("publicCheck").key("definition"),
                "authority-public-check",
                "publicCheck must name an existing AssertionDefinition that declares publicCheck",
            ));
        }
    }
    for (id, profile) in &authority.access_profiles {
        let at = FieldPath::root()
            .key("accessProfiles")
            .map_key(id.to_string());
        if profile.requester_tags.len() > 32
            || profile
                .requester_tags
                .iter()
                .any(|tag| tag.len() > 128 || !crate::validate::valid_local_identifier(tag))
        {
            findings.push(Finding::new(
                at.clone().key("requesterTags"),
                "authority-requester-tags",
                "declare between one and 32 distinct local identity tags",
            ));
        }
        if profile.grants.len() > 128 {
            findings.push(Finding::new(
                at.clone().key("grants"),
                "authority-grants",
                "declare between one and 128 complete grants",
            ));
        }
        let task = profile
            .grants
            .iter()
            .flat_map(|grant| &grant.subjects)
            .any(|subject| subject.value_origin == ValueOrigin::AuthenticatedGrant);
        if task {
            if profile.requester_clients.as_ref().is_none_or(|clients| {
                clients.is_empty()
                    || clients.len() > 32
                    || clients.iter().any(|client| {
                        client.is_empty()
                            || client.len() > 128
                            || client.chars().any(char::is_control)
                    })
            }) {
                findings.push(Finding::new(
                    at.clone().key("requesterClients"),
                    "authority-task-clients",
                    "authenticated-grant subjects require one to 32 distinct requester clients",
                ));
            }
            if profile.grant_source_issuer.is_none() {
                findings.push(Finding::new(
                    at.clone().key("grantSourceIssuer"),
                    "authority-task-issuer",
                    "authenticated-grant subjects require their trusted source issuer",
                ));
            }
        } else {
            if profile.requester_clients.is_some() {
                findings.push(Finding::new(
                    at.clone().key("requesterClients"),
                    "authority-task-only",
                    "requesterClients requires an authenticated-grant subject",
                ));
            }
            if profile.grant_source_issuer.is_some() {
                findings.push(Finding::new(
                    at.clone().key("grantSourceIssuer"),
                    "authority-task-only",
                    "grantSourceIssuer requires an authenticated-grant subject",
                ));
            }
        }
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
            for (subject_index, subject) in grant.subjects.iter().enumerate() {
                let subject_at = at.clone().key("subjects").index(subject_index);
                if subject.value_origin == ValueOrigin::Request {
                    if subject.value_claims.is_some() {
                        findings.push(Finding::new(
                            subject_at.key("valueClaims"),
                            "authority-request-claims",
                            "request-derived subjects must omit valueClaims",
                        ));
                    }
                } else if let Some(selector) =
                    project.selector_profiles.get(&subject.selector_profile)
                {
                    let exact = subject.value_claims.as_ref().is_some_and(|claims| {
                        claims.len() == selector.fields.len()
                            && selector
                                .fields
                                .keys()
                                .all(|field| claims.contains_key(field))
                    });
                    if !exact {
                        findings.push(Finding::new(
                            subject_at.clone().key("valueClaims"),
                            "authority-value-claims",
                            "valueClaims must name exactly every field in the selected profile",
                        ));
                    }
                    if let Some(claims) = &subject.value_claims {
                        let mut targets = std::collections::BTreeSet::new();
                        for (field, claim) in claims {
                            if !claim_path(claim) || !targets.insert(claim) {
                                findings.push(Finding::new(subject_at.clone().key("valueClaims").map_key(field.to_string()),"authority-claim-path","each claim target must be a distinct bounded dotted claim path"));
                            }
                        }
                    }
                }
            }
            let matches = definition
                .grant_ceiling
                .authorities
                .iter()
                .any(|kind| kind == &profile.authority)
                && profile
                    .actor_kind
                    .is_none_or(|kind| definition.grant_ceiling.actor_kinds.contains(&kind))
                && grant.purpose == definition.purpose
                && grant.subject_binding == definition.subject_binding
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

fn claim_path(value: &str) -> bool {
    value.len() <= 512
        && value.split('.').all(|part| {
            part.as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                && part
                    .bytes()
                    .skip(1)
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
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
        if profile.actor_kind.is_none() { compiled.as_object_mut().expect("compiled profile").remove("actorKind"); }
        if let Some(clients) = &profile.requester_clients { if !clients.is_empty() { compiled["requesterClients"] = json!(clients); } }
        if let Some(issuer) = &profile.grant_source_issuer { compiled["grantSourceIssuer"] = json!(issuer); }
        (id.as_str(), compiled)
    }).collect::<BTreeMap<_, _>>();
    let mut compiled = json!({"apiVersion":"id.registrystack.org/formats/evidence/compiled-target-authority/v1alpha1","kind":"EvidenceCompiledTargetAuthority","target":authority.target,"project":authority.project,"accessProfiles":profiles});
    if let Some(activation) = &authority.public_check {
        compiled["publicCheck"] = json!({"requirement": project.assertion_definitions[&activation.definition].semantics.requirement});
    }
    Ok(compiled)
}
