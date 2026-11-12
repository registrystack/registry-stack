// SPDX-License-Identifier: Apache-2.0
//! Read-only, advisory reporting over configured Python service bindings.

use registry_platform_yaml::{
    ApiVersion, EnvelopeRule, Expect, ExternalId, ForeignValue, FormatSpec, Reader,
};
use registry_thunderid_tooling::identity_facts::{self, IdentityFacts};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const CONNECTION_API_VERSION: &str =
    "id.registrystack.org/formats/platform/python-connection/v1alpha1";
const CONNECTION_KIND: &str = "PlatformPythonConnection";
const CONNECTION_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CONNECTION_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CONNECTION_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionView {
    service: String,
    audience: String,
    secret_providers: ForeignValue,
    bindings: Vec<BindingView>,
    #[serde(default)]
    admission: Option<ForeignValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingView {
    name: ExternalId,
    product: ExternalId,
    url: ForeignValue,
    default: bool,
    credential: CredentialView,
}

#[derive(Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum CredentialView {
    PrivateKeyJwt {
        token_endpoint: ForeignValue,
        client_id: ExternalId,
        client_key_ref: ForeignValue,
        resource: ExternalId,
        scopes: Vec<ExternalId>,
    },
    RunnerToken {
        token_ref: ForeignValue,
        run_id: ExternalId,
        binding: ExternalId,
        issuer: ForeignValue,
        subject: ExternalId,
        client_id: ExternalId,
        profile: ExternalId,
        resource: ExternalId,
        scopes: Vec<ExternalId>,
        run_expires_at: u64,
    },
}

registry_platform_yaml::tagged_union!(CredentialView, tag = "type");

#[derive(Serialize)]
pub(crate) struct GrantsReport {
    schema_version: &'static str,
    status: &'static str,
    connection: ConnectionFact,
    bindings: Vec<BindingFact>,
    facts: Vec<ProductFacts>,
    omissions: Vec<Omission>,
}

#[derive(Serialize)]
struct ConnectionFact {
    source: String,
    service: String,
    audience: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BindingFact {
    source: String,
    path: String,
    name: String,
    product: String,
    default: bool,
    credential_type: &'static str,
    resource: String,
    configured_scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    configured_profile: Option<String>,
    profile_knowledge: &'static str,
    known_profiles: Vec<KnownProfile>,
    omissions: Vec<Omission>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct KnownProfile {
    source: String,
    path: String,
    id: String,
    scopes: Vec<String>,
    purposes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_kind: Option<String>,
    required_claims: Vec<String>,
    match_basis: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProductFacts {
    source: String,
    product: String,
    resource: String,
    profiles: Vec<ProfileFact>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileFact {
    source: String,
    path: String,
    id: String,
    scopes: Vec<String>,
    purposes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_kind: Option<String>,
    required_claims: Vec<String>,
}

#[derive(Serialize)]
struct Omission {
    code: &'static str,
    message: &'static str,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

struct FactsSource {
    source: String,
    value: IdentityFacts,
}

pub(crate) fn build(connection: &Path, facts: &[PathBuf]) -> Result<GrantsReport, String> {
    let connection_source = source_name(connection, "connection")?;
    let bytes =
        fs::read(connection).map_err(|_| "cannot read the Python connection file".to_owned())?;
    let decoded = Reader::new(&connection_source)
        .decode::<ConnectionView>(&bytes, &Expect::one(&CONNECTION_FORMAT))
        .map_err(|report| report.render_human())?;
    let connection_value = decoded.value;
    let _ = (
        &connection_value.secret_providers,
        &connection_value.admission,
    );

    let mut fact_sources = Vec::with_capacity(facts.len());
    for file in facts {
        let source = source_name(file, "facts")?;
        let bytes = fs::read(file).map_err(|_| "cannot read an identity facts file".to_owned())?;
        let value = identity_facts::read(&source, &bytes).map_err(|error| error.to_string())?;
        fact_sources.push(FactsSource { source, value });
    }

    let bindings = connection_value
        .bindings
        .into_iter()
        .enumerate()
        .map(|(index, binding)| binding_fact(index, binding, &connection_source, &fact_sources))
        .collect();
    let facts = fact_sources.iter().map(product_facts).collect();
    Ok(GrantsReport {
        schema_version: "registry.rstack.grants.v1",
        status: "advisory",
        connection: ConnectionFact {
            source: connection_source,
            service: connection_value.service,
            audience: connection_value.audience,
        },
        bindings,
        facts,
        omissions: vec![
            Omission {
                code: "live-grants-not-inspected",
                message: "This report reads configuration and supplied identity facts; it does not query an issuer or product and cannot certify live grants.",
                source: "report-method".to_owned(),
                path: None,
            },
            Omission {
                code: "record-sensitivity-not-classified",
                message: "This report does not inspect registry records and cannot classify their personal-data sensitivity.",
                source: "report-method".to_owned(),
                path: None,
            },
            Omission {
                code: "product-enforcement-not-exercised",
                message: "Row, field, purpose, disclosure and effect boundaries remain enforced by the owning product and are not exercised by this report.",
                source: "report-method".to_owned(),
                path: None,
            },
        ],
    })
}

fn source_name(path: &Path, label: &str) -> Result<String, String> {
    let Some(source) = path.to_str() else {
        return Err(format!("the {label} path must be UTF-8"));
    };
    if source.len() > 4096 || source.chars().any(char::is_control) {
        return Err(format!(
            "the {label} path is too long or contains a control character"
        ));
    }
    Ok(source.to_owned())
}

fn binding_fact(
    index: usize,
    binding: BindingView,
    source: &str,
    facts: &[FactsSource],
) -> BindingFact {
    let BindingView {
        name,
        product,
        url,
        default,
        credential,
    } = binding;
    let _ = url;
    let (credential_type, resource, scopes, configured_profile) = credential.facts();
    let product = product.into_string();
    let path = format!("/bindings/{index}");
    let known_profiles = matching_profiles(
        &product,
        resource.as_str(),
        &scopes,
        configured_profile.as_deref(),
        facts,
    );
    let profile_knowledge = if known_profiles.is_empty() {
        "unknown"
    } else if configured_profile.is_some() {
        "declared"
    } else {
        "candidate"
    };
    let omissions = if known_profiles.is_empty() {
        vec![Omission {
            code: "binding-profile-not-confirmed",
            message: "No supplied product facts confirm a profile for this configured binding; an external or otherwise unknown grant remains possible and is not a startup refusal.",
            source: source.to_owned(),
            path: Some(path.clone()),
        }]
    } else if configured_profile.is_none() {
        vec![Omission {
            code: "binding-profile-derived-from-scopes",
            message: "The listed profiles are candidates derived from configured scopes, not declared or live profile grants.",
            source: source.to_owned(),
            path: Some(path.clone()),
        }]
    } else {
        Vec::new()
    };

    BindingFact {
        source: source.to_owned(),
        path,
        name: name.into_string(),
        product,
        default,
        credential_type,
        resource: resource.into_string(),
        configured_scopes: scopes,
        configured_profile,
        profile_knowledge,
        known_profiles,
        omissions,
    }
}

impl CredentialView {
    fn facts(self) -> (&'static str, ExternalId, Vec<String>, Option<String>) {
        match self {
            CredentialView::PrivateKeyJwt {
                token_endpoint,
                client_id,
                client_key_ref,
                resource,
                scopes,
            } => {
                let _ = (token_endpoint, client_id, client_key_ref);
                ("private-key-jwt", resource, strings(scopes), None)
            }
            CredentialView::RunnerToken {
                token_ref,
                run_id,
                binding,
                issuer,
                subject,
                client_id,
                profile,
                resource,
                scopes,
                run_expires_at,
            } => {
                let _ = (
                    token_ref,
                    run_id,
                    binding,
                    issuer,
                    subject,
                    client_id,
                    run_expires_at,
                );
                (
                    "runner-token",
                    resource,
                    strings(scopes),
                    Some(profile.into_string()),
                )
            }
        }
    }
}

fn strings(values: Vec<ExternalId>) -> Vec<String> {
    values.into_iter().map(ExternalId::into_string).collect()
}

fn matching_profiles(
    product: &str,
    resource: &str,
    configured_scopes: &[String],
    configured_profile: Option<&str>,
    facts: &[FactsSource],
) -> Vec<KnownProfile> {
    let mut profiles = Vec::new();
    for fact in facts {
        if fact.value.product != product || fact.value.audience != resource {
            continue;
        }
        for (index, profile) in fact.value.access_profiles.iter().enumerate() {
            let name_matches = configured_profile.is_none_or(|name| profile.id == name);
            let scopes_fit = profile
                .scopes
                .iter()
                .all(|scope| configured_scopes.contains(scope));
            if name_matches && scopes_fit {
                profiles.push(KnownProfile {
                    source: fact.source.clone(),
                    path: format!("/accessProfiles/{index}"),
                    id: profile.id.clone(),
                    scopes: profile.scopes.clone(),
                    purposes: profile.purposes.clone(),
                    actor_kind: actor_kind(profile),
                    required_claims: profile.required_claims.clone(),
                    match_basis: if configured_profile.is_some() {
                        "declared-profile"
                    } else {
                        "scope-subset"
                    },
                });
            }
        }
    }
    profiles
}

fn product_facts(facts: &FactsSource) -> ProductFacts {
    ProductFacts {
        source: facts.source.clone(),
        product: facts.value.product.clone(),
        resource: facts.value.audience.clone(),
        profiles: facts
            .value
            .access_profiles
            .iter()
            .enumerate()
            .map(|(index, profile)| ProfileFact {
                source: facts.source.clone(),
                path: format!("/accessProfiles/{index}"),
                id: profile.id.clone(),
                scopes: profile.scopes.clone(),
                purposes: profile.purposes.clone(),
                actor_kind: actor_kind(profile),
                required_claims: profile.required_claims.clone(),
            })
            .collect(),
    }
}

fn actor_kind(profile: &identity_facts::AccessProfile) -> Option<String> {
    profile.actor_kind.map(|kind| kind.as_str().to_owned())
}

pub(crate) fn human(report: &GrantsReport) -> String {
    let mut output = format!(
        "Advisory grants report for {:?} ({})\nSource: {}\n",
        report.connection.service, report.connection.audience, report.connection.source
    );
    for binding in &report.bindings {
        output.push_str(&format!(
            "\n{}: {} binding, resource {:?}, scopes [{}]\n  Source: {}{}\n",
            binding.name,
            binding.product,
            binding.resource,
            binding.configured_scopes.join(", "),
            binding.source,
            binding.path
        ));
        if binding.known_profiles.is_empty() {
            output.push_str("  Known profiles: none confirmed by the supplied facts\n");
        } else {
            output.push_str("  Known profiles:\n");
            for profile in &binding.known_profiles {
                output.push_str(&format!(
                    "    {} ({}, source: {}{})\n",
                    profile.id, profile.match_basis, profile.source, profile.path
                ));
            }
        }
    }
    output.push_str("\nOmissions:\n");
    for omission in &report.omissions {
        output.push_str(&format!("  {}: {}\n", omission.code, omission.message));
    }
    for binding in &report.bindings {
        for omission in &binding.omissions {
            output.push_str(&format!(
                "  {} ({}): {}\n",
                omission.code, binding.name, omission.message
            ));
        }
    }
    output.trim_end().to_owned()
}
