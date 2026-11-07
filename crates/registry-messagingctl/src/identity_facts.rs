// SPDX-License-Identifier: Apache-2.0

//! The identity facts Messaging states about its issuer: the issuer and
//! audience it trusts, the clients its runtime admits, and each access
//! profile with the scopes and requester clients it names. `generate
//! identity-facts` writes them from the deployment's own configuration, and
//! `messagingctl dev` derives the clients its session admits through the same
//! function, so a session and a deployment agree.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::Path;

use registry_messaging::config::RuntimeConfig;
use registry_messaging::package::LoadedPackage;
use registry_messaging_core::{AccessProfiles, ActorKind};
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile as FactsProfile, ActorKind as FactsActorKind, Admission, ClaimType,
    IdentityFacts,
};

/// The product name the facts carry.
const PRODUCT: &str = "messaging";
/// The claim the runtime reads an actor kind from.
pub(crate) const ACTOR_KIND_CLAIM: &str = "registry_actor_kind";
/// The claim the runtime reads scopes from when the configuration names none.
const DEFAULT_SCOPE_CLAIM: &str = "scope";
/// Claims the token verifier reads for other purposes; a scope claim named
/// one of these grants no scope without a mapping Messaging does not offer.
const RESERVED_SCOPE_CLAIMS: [&str; 4] = ["sub", "client_id", "azp", "aud"];

/// The clients the package's access profiles name, sorted and distinct.
pub(crate) fn requester_clients(profiles: &AccessProfiles) -> Vec<String> {
    let mut clients: Vec<String> = profiles
        .iter()
        .flat_map(|profile| profile.requester_clients.iter().cloned())
        .collect();
    clients.sort();
    clients.dedup();
    clients
}

#[derive(Debug)]
pub(crate) enum FactsError {
    /// A profile cannot be stated as facts; the message names no value.
    Unstatable(String),
    /// The assembled document failed the facts reader.
    Invalid(String),
    Encode,
    Write(io::Error),
}

impl fmt::Display for FactsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unstatable(message) | Self::Invalid(message) => formatter.write_str(message),
            Self::Encode => formatter.write_str("the identity facts could not be encoded"),
            Self::Write(error) => write!(
                formatter,
                "the output file could not be created or written: {error}"
            ),
        }
    }
}

/// The facts a runtime configuration and the package it serves state.
pub(crate) fn facts(
    config: &RuntimeConfig,
    loaded: &LoadedPackage,
) -> Result<IdentityFacts, FactsError> {
    let oidc = &config.authentication.oidc;
    let admitted = &oidc.clients.allowed_clients;
    let allowed = if admitted.is_empty() {
        Admission::Unrestricted
    } else {
        Admission::Clients(admitted.clone())
    };
    let mut facts = IdentityFacts::new(
        PRODUCT,
        oidc.provider.issuer.as_str(),
        &oidc.provider.audience,
        allowed.clone(),
    );
    // The verifier accepts the scope claim as a space-separated string or an
    // array of strings. The facts state the array, which needs no separator.
    let scope_claim = oidc.scope_claim.as_str();
    if scope_claim != DEFAULT_SCOPE_CLAIM {
        if RESERVED_SCOPE_CLAIMS.contains(&scope_claim) {
            return Err(FactsError::Unstatable(
                "authentication.oidc.scopeClaim names a reserved token claim that grants no scope; name a dedicated scope claim".to_owned(),
            ));
        }
        facts
            .claims
            .insert(scope_claim.to_owned(), ClaimType::StringArray);
    }
    for profile in loaded.package.access_profiles().iter() {
        if profile.required_scopes.is_empty() {
            return Err(FactsError::Unstatable(format!(
                "the access profile `{}` requires no scope, so it names no scope to grant; list its scopes in requiredScopes",
                profile.id
            )));
        }
        if let Some(client) = profile
            .requester_clients
            .iter()
            .find(|client| !allowed.admits(client))
        {
            return Err(FactsError::Unstatable(format!(
                "the access profile `{}` names the client `{client}`, which authentication.oidc.allowedClients does not admit",
                profile.id
            )));
        }
        if profile.principal_claim != "sub" {
            facts
                .claims
                .insert(profile.principal_claim.clone(), ClaimType::String);
        }
        if profile.actor_kind.is_some() {
            facts
                .claims
                .insert(ACTOR_KIND_CLAIM.to_owned(), ClaimType::String);
        }
        // A renamed scope claim is how the issuer selects this profile: the
        // principal must carry exactly the scopes the profile requires there.
        let selected_by = if scope_claim == DEFAULT_SCOPE_CLAIM {
            BTreeMap::new()
        } else {
            BTreeMap::from([(scope_claim.to_owned(), profile.required_scopes.clone())])
        };
        facts.access_profiles.push(FactsProfile {
            id: profile.id.clone(),
            scopes: profile.required_scopes.clone(),
            purposes: Vec::new(),
            requester_clients: Some(profile.requester_clients.clone()),
            exchange: None,
            selected_by,
            // Messaging resolves the profile by client id and then requires
            // this kind, so it is a requirement, not a selector.
            actor_kind: profile.actor_kind.map(facts_actor_kind),
            // Messaging refuses a token whose principal claim is missing or
            // empty (`AccessProfiles::resolve` in `registry-messaging-core`
            // `access.rs`), so a named principal claim is required. The
            // subject is always there.
            required_claims: (profile.principal_claim != "sub")
                .then(|| profile.principal_claim.clone())
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

/// The facts spelling of the actor kind a Messaging profile requires.
fn facts_actor_kind(kind: ActorKind) -> FactsActorKind {
    match kind {
        ActorKind::Human => FactsActorKind::Human,
        ActorKind::Agent => FactsActorKind::Agent,
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
