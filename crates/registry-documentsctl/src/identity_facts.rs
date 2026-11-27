// SPDX-License-Identifier: Apache-2.0

//! The identity facts the Document Store states about its issuer: the issuer
//! and audience it trusts, the clients its runtime admits, and each access
//! profile with the scopes and requester clients it names. `generate
//! identity-facts` writes them from the deployment's own runtime
//! configuration and the package it names.
//!
//! The identity generator checks that profiles sharing the person audience
//! each carry a scope of their own. The project reader refuses a profile
//! without one before a package exists, so a package that loads states
//! profiles the generator accepts on that rule.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::Path;

use registry_documents::config::RuntimeConfig;
use registry_documents::package::{load_package, LoadedPackage};
use registry_documents::runtime::RuntimeError;
use registry_documents_core::ActorKind;
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile as FactsProfile, ActorKind as FactsActorKind, Admission, ClaimType,
    IdentityFacts,
};
use serde_json::json;

use crate::operate;
use crate::report::{DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT};
use crate::{GenerateIdentityFactsArgs, Outcome, View};

/// The product name the facts carry.
const PRODUCT: &str = "documents";
/// The claim the runtime reads an actor kind from.
const ACTOR_KIND_CLAIM: &str = "registry_actor_kind";
/// The claim the runtime reads scopes from unless the configuration names
/// another.
const DEFAULT_SCOPE_CLAIM: &str = "scope";

#[derive(Debug)]
pub(crate) enum FactsError {
    /// The configuration or project cannot be stated as facts; the message
    /// names no value.
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
    if oidc.scope_claim.as_str() != DEFAULT_SCOPE_CLAIM {
        return Err(FactsError::Unstatable(format!(
            "authentication.oidc.scopeClaim is not the default `{DEFAULT_SCOPE_CLAIM}`, which hosted generation does not support yet; set it to `{DEFAULT_SCOPE_CLAIM}`"
        )));
    }
    if config.binds_assertion_issuers() {
        return Err(FactsError::Unstatable(
            "authentication.oidc names assertion issuers, which hosted generation does not state yet; remove them to write facts".to_owned(),
        ));
    }
    let admitted = config
        .admitted_clients(&loaded.project)
        .map_err(|finding| FactsError::Unstatable(finding.message))?;
    let allowed = Admission::Clients(admitted.as_slice().to_vec());
    let mut facts = IdentityFacts::new(
        PRODUCT,
        oidc.provider.issuer.as_str(),
        &oidc.provider.audience,
        allowed,
    );
    // Every profile requires an actor kind, so the claim is always declared
    // and every generated client carries one.
    facts
        .claims
        .insert(ACTOR_KIND_CLAIM.to_owned(), ClaimType::String);
    for (id, profile) in &loaded.project.access_profiles {
        let principal = profile.principal_claim.as_str();
        if principal != "sub" {
            facts.claims.insert(principal.to_owned(), ClaimType::String);
        }
        facts.access_profiles.push(FactsProfile {
            id: id.to_string(),
            scopes: listed(profile.required_scopes.as_slice()),
            purposes: Vec::new(),
            requester_clients: Some(listed(profile.requester_clients.as_slice())),
            exchange: None,
            selected_by: BTreeMap::new(),
            // The Document Store resolves the profile by client id and then
            // requires this kind, so it is a requirement, not a selector.
            actor_kind: Some(facts_actor_kind(profile.actor_kind)),
            // A token whose principal claim is missing is refused, so a
            // named principal claim is required. The subject is always there.
            required_claims: (principal != "sub")
                .then(|| principal.to_owned())
                .into_iter()
                .collect(),
            admitted_actor_kinds: Vec::new(),
            refused_claims: Vec::new(),
        });
    }
    facts.access_profiles.sort_by(|a, b| a.id.cmp(&b.id));
    // Read the document back through the facts reader so an invalid document
    // is refused here, not by the generator that consumes it.
    let yaml = facts.to_yaml().map_err(|_| FactsError::Encode)?;
    identity_facts::read("identity-facts", yaml.as_bytes()).map_err(|error| {
        FactsError::Invalid(format!(
            "the facts derived from the configuration are not valid: {error}"
        ))
    })
}

fn listed(ids: &[registry_platform_yaml::ExternalId]) -> Vec<String> {
    ids.iter().map(|id| id.as_str().to_owned()).collect()
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

/// `generate identity-facts`: read the runtime configuration and the package
/// it names exactly as `documents serve` does, and write the facts to a new
/// file.
pub(crate) fn generate(args: &GenerateIdentityFactsArgs) -> Outcome {
    // Refuse before reading anything when the output cannot be created.
    if args.output.exists() {
        return output_exists();
    }
    let runtime = match operate::load(&args.runtime_config) {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    let loaded = match load_package(&runtime.config) {
        Ok(loaded) => loaded,
        Err(error) => return operate::failure(&runtime.given, RuntimeError::Package(error)),
    };
    let facts = match facts(&runtime.config, &loaded) {
        Ok(facts) => facts,
        Err(error) => {
            return Outcome::refused(
                DOMAIN_REFUSAL_EXIT,
                "identity.facts.unstatable",
                "/",
                error.to_string(),
            )
        }
    };
    match write(&facts, &args.output) {
        Ok(()) => Outcome::new(
            json!({
                "ok": true,
                "output": args.output,
                "accessProfiles": facts.access_profiles.len(),
                "claims": facts.claims.len(),
            }),
            View::GenerateIdentityFacts,
        ),
        Err(FactsError::Write(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            output_exists()
        }
        Err(error) => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "output.failed",
            "--output",
            error.to_string(),
        ),
    }
}

fn output_exists() -> Outcome {
    Outcome::refused(
        DOMAIN_REFUSAL_EXIT,
        "output.exists",
        "--output",
        "the output file already exists; generate never overwrites".to_owned(),
    )
}
