// SPDX-License-Identifier: Apache-2.0

//! The identity facts the Document Store states about one issuer: the issuer
//! and audience it trusts, the clients that entry admits, and each access
//! profile with the scopes and requester clients it names among them.
//! `generate identity-facts` writes them from the deployment's own
//! configuration and project.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::Path;

use registry_documents::config::{IssuerConfig, RuntimeConfig};
use registry_documents_core::{ActorKind, DocumentsProject};
use registry_platform_config::CallerIssuerEntry;
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile as FactsProfile, ActorKind as FactsActorKind, Admission, ClaimType,
    IdentityFacts,
};

/// The product name the facts carry.
const PRODUCT: &str = "documents";
/// The claim the runtime reads an actor kind from.
const ACTOR_KIND_CLAIM: &str = "registry_actor_kind";
/// The claim the runtime reads scopes from when the configuration names none.
const DEFAULT_SCOPE_CLAIM: &str = "scope";
/// Claims the token verifier reads for other purposes. A scope claim named
/// one of these grants no scope without a mapping the Document Store does not
/// offer.
const RESERVED_SCOPE_CLAIMS: [&str; 4] = ["sub", "client_id", "azp", "aud"];
/// The code of the refusal for two or more issuer entries and no `--issuer`.
pub(crate) const ISSUER_REQUIRED_CODE: &str = "identity.facts.issuer-required";
/// The code of the refusal for an `--issuer` that names no entry.
pub(crate) const UNKNOWN_ISSUER_CODE: &str = "identity.facts.unknown-issuer";

#[derive(Debug)]
pub(crate) enum FactsError {
    /// A profile cannot be stated as facts. The message names no value.
    Unstatable(String),
    /// The assembled document failed the facts reader.
    Invalid(String),
    /// The runtime declares several issuer entries and none was named.
    IssuerRequired(String),
    /// The named issuer is not an entry of the runtime.
    UnknownIssuer(String),
    Encode,
    Write(io::Error),
}

impl FactsError {
    /// The diagnostic code of a refusal about which entry to describe.
    pub(crate) fn issuer_code(&self) -> Option<&'static str> {
        match self {
            Self::IssuerRequired(_) => Some(ISSUER_REQUIRED_CODE),
            Self::UnknownIssuer(_) => Some(UNKNOWN_ISSUER_CODE),
            _ => None,
        }
    }
}

impl fmt::Display for FactsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unstatable(message)
            | Self::Invalid(message)
            | Self::IssuerRequired(message)
            | Self::UnknownIssuer(message) => formatter.write_str(message),
            Self::Encode => formatter.write_str("the identity facts could not be encoded"),
            Self::Write(error) => write!(
                formatter,
                "the output file could not be created or written: {error}"
            ),
        }
    }
}

/// The issuer entry the facts describe: the one `issuer` names, or the only
/// entry when the runtime has one.
fn selected<'a>(
    config: &'a RuntimeConfig,
    issuer: Option<&str>,
) -> Result<(&'a str, &'a IssuerConfig), FactsError> {
    let listed: Vec<_> = config
        .authentication
        .oidc
        .issuers
        .iter()
        .map(|(id, entry)| (id.as_str(), entry))
        .collect();
    match (issuer, listed.as_slice()) {
        (Some(wanted), _) => listed
            .iter()
            .find(|(id, _)| *id == wanted)
            .copied()
            .ok_or_else(|| {
                FactsError::UnknownIssuer(
                    "authentication.oidc.issuers declares no issuer with the id given to --issuer. Name one of the issuer ids under authentication.oidc.issuers".to_owned(),
                )
            }),
        (None, [only]) => Ok(*only),
        (None, _) => Err(FactsError::IssuerRequired(format!(
            "authentication.oidc.issuers declares {} issuers, and the facts describe one. Pass --issuer with the id of the issuer to describe",
            listed.len()
        ))),
    }
}

/// The facts a runtime configuration and the project it serves state for one
/// issuer entry. The profiles are those that name a client the entry admits,
/// each with the requester clients it admits.
pub(crate) fn facts(
    config: &RuntimeConfig,
    project: &DocumentsProject,
    issuer: Option<&str>,
) -> Result<IdentityFacts, FactsError> {
    let (id, entry) = selected(config, issuer)?;
    let core = entry.core();
    let admitted = config
        .admitted_clients(project)
        .map_err(|finding| FactsError::Unstatable(finding.message))?
        .remove(id)
        .ok_or_else(|| {
            FactsError::Unstatable(format!(
                "the issuer `{id}` admits no clients against this project"
            ))
        })?
        .into_vec();
    let mut facts = IdentityFacts::new(
        PRODUCT,
        core.provider.issuer.as_str(),
        &core.provider.audience,
        Admission::Clients(admitted.clone()),
    );
    // The verifier accepts the scope claim as a space-separated string or an
    // array of strings. The facts state the array, which needs no separator.
    let scope_claim = core.scope_claim.get().as_str();
    if scope_claim != DEFAULT_SCOPE_CLAIM {
        if RESERVED_SCOPE_CLAIMS.contains(&scope_claim) {
            return Err(FactsError::Unstatable(format!(
                "authentication.oidc.issuers.{id}.scopeClaim names a reserved token claim that grants no scope. Name a dedicated scope claim"
            )));
        }
        facts
            .claims
            .insert(scope_claim.to_owned(), ClaimType::StringArray);
    }
    for (profile_id, profile) in &project.access_profiles {
        let requesters: Vec<String> = profile
            .requester_clients
            .as_slice()
            .iter()
            .map(|client| client.as_str().to_owned())
            .filter(|client| admitted.contains(client))
            .collect();
        if requesters.is_empty() {
            continue;
        }
        let scopes: Vec<String> = profile
            .required_scopes
            .as_slice()
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect();
        let principal_claim = profile.principal_claim.as_str();
        if principal_claim != "sub" {
            facts
                .claims
                .insert(principal_claim.to_owned(), ClaimType::String);
        }
        // Every profile pins a kind, so the issuer must state it on the token
        // or the operator must declare it in the runtime settings.
        facts
            .claims
            .insert(ACTOR_KIND_CLAIM.to_owned(), ClaimType::String);
        // A renamed scope claim is how the issuer selects this profile: the
        // principal must carry exactly the scopes the profile requires there.
        let selected_by = if scope_claim == DEFAULT_SCOPE_CLAIM {
            BTreeMap::new()
        } else {
            BTreeMap::from([(scope_claim.to_owned(), scopes.clone())])
        };
        facts.access_profiles.push(FactsProfile {
            id: profile_id.as_str().to_owned(),
            scopes,
            purposes: Vec::new(),
            requester_clients: Some(requesters),
            exchange: None,
            selected_by,
            // The Document Store resolves the profile by client id and then
            // requires this kind, so it is a requirement, not a selector.
            actor_kind: Some(facts_actor_kind(profile.actor_kind)),
            // A token whose principal claim is missing or empty is refused,
            // so a named principal claim is required. The subject is always
            // there.
            required_claims: (principal_claim != "sub")
                .then(|| principal_claim.to_owned())
                .into_iter()
                .collect(),
            admitted_actor_kinds: Vec::new(),
            refused_claims: Vec::new(),
        });
    }
    facts.access_profiles.sort_by(|a, b| a.id.cmp(&b.id));
    // Read the document back through the facts reader so an invalid
    // document is refused here, not by the generator that consumes it.
    let yaml = facts.to_yaml().map_err(|_| FactsError::Encode)?;
    identity_facts::read("identity-facts", yaml.as_bytes()).map_err(|error| {
        FactsError::Invalid(format!(
            "the facts derived from the configuration are not valid: {error}"
        ))
    })
}

/// The facts spelling of the actor kind a Document Store profile requires.
fn facts_actor_kind(kind: ActorKind) -> FactsActorKind {
    match kind {
        ActorKind::Human => FactsActorKind::Human,
        ActorKind::Service => FactsActorKind::Service,
    }
}

/// Write `facts` to a new file. An existing file is never replaced.
pub(crate) fn write(facts: &IdentityFacts, output: &Path) -> Result<(), FactsError> {
    let yaml = facts.to_yaml().map_err(|_| FactsError::Encode)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(FactsError::Write)?;
    file.write_all(yaml.as_bytes()).map_err(FactsError::Write)
}
