//! The identity facts Render states about its issuer: the issuer and audience
//! it trusts, the clients its runtime admits, and the access profile of each
//! of its two routes, with the scope each requires and, for the seal route,
//! the requester clients its seals name. `generate identity-facts` writes them
//! from the deployment's own runtime file and package.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use registry_platform_config::{Admitted, CallerIssuerEntry, ClientRule};
use registry_platform_yaml::Diagnostic;
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile, Admission, ClaimType, IdentityFacts,
};

use crate::bundle::Bundle;
use crate::problem::{ProblemKind, RenderProblem};
use crate::runtime::{IssuerRuntime, OidcRuntime, RenderRuntime};

/// The product name the facts carry.
const PRODUCT: &str = "render";
/// The claim the runtime reads scopes from when an issuer names none.
const DEFAULT_SCOPE_CLAIM: &str = "scope";
/// The access profile of the render and document routes.
const RENDER_PROFILE: &str = "render";
/// The access profile of the seal route.
const SEAL_PROFILE: &str = "seal";

fn refusal(code: &'static str, message: String, action: &'static str) -> RenderProblem {
    RenderProblem::new(ProblemKind::InvalidArgument, message.clone())
        .with_diagnostics(vec![Diagnostic::error(code, "", message, action)])
}

fn invalid(message: String) -> RenderProblem {
    RenderProblem::new(ProblemKind::RuntimeInvalid, message)
}

/// The issuer entry the facts describe: the one `issuer` names, or the only
/// entry when the runtime has one.
fn selected<'a>(
    runtime: &'a RenderRuntime,
    issuer: Option<&str>,
) -> Result<(&'a OidcRuntime, &'a str, &'a IssuerRuntime), RenderProblem> {
    let Some(oidc) = &runtime.authentication.oidc else {
        return Err(invalid(
            "the runtime configures no authentication.oidc, so there are no issuer facts to state"
                .to_owned(),
        ));
    };
    let listed: Vec<_> = oidc
        .issuers
        .iter()
        .map(|(id, entry)| (id.as_str(), entry))
        .collect();
    match (issuer, listed.as_slice()) {
        (Some(wanted), _) => listed
            .iter()
            .find(|(id, _)| *id == wanted)
            .map(|(id, entry)| (oidc, *id, *entry))
            .ok_or_else(|| {
                refusal(
                    "identity.facts.unknown-issuer",
                    format!("authentication.oidc.issuers declares no issuer `{wanted}`"),
                    "Name one of the issuer ids under authentication.oidc.issuers.",
                )
            }),
        (None, [only]) => Ok((oidc, only.0, only.1)),
        (None, _) => Err(refusal(
            "identity.facts.issuer-required",
            format!(
                "authentication.oidc.issuers declares {} issuers, and the facts describe one",
                listed.len()
            ),
            "Pass --issuer with the id of the issuer to describe.",
        )),
    }
}

/// The facts the runtime and the package it serves state for one issuer.
pub(crate) fn facts(
    runtime: &RenderRuntime,
    bundle: &Bundle,
    issuer: Option<&str>,
) -> Result<IdentityFacts, RenderProblem> {
    let (oidc, id, entry) = selected(runtime, issuer)?;
    let core = entry.core();
    let admission = match core.allowed_clients.admitted() {
        Admitted::Listed(clients) => Admission::Clients(clients.to_vec()),
        _ => Admission::Unrestricted,
    };
    let mut facts = IdentityFacts::new(
        PRODUCT,
        core.provider.issuer.as_str(),
        &core.provider.audience,
        admission.clone(),
    );
    let scope_claim = core.scope_claim.get().as_str();
    if scope_claim != DEFAULT_SCOPE_CLAIM {
        facts
            .claims
            .insert(scope_claim.to_owned(), ClaimType::StringArray);
    }
    facts
        .access_profiles
        .push(profile(RENDER_PROFILE, oidc.render_scope().as_str(), None));
    if let Some(requesters) = seal_requesters(runtime, oidc, bundle, id, &admission)? {
        facts.access_profiles.push(profile(
            SEAL_PROFILE,
            oidc.seal_scope().as_str(),
            Some(requesters),
        ));
    }
    facts.access_profiles.sort_by(|a, b| a.id.cmp(&b.id));
    // Read the document back through the facts reader so an invalid document
    // is refused here, not by the generator that consumes it.
    let yaml = facts
        .to_yaml()
        .map_err(|_| invalid("the identity facts could not be encoded".to_owned()))?;
    identity_facts::read("identity-facts", yaml.as_bytes()).map_err(|error| {
        invalid(format!(
            "the facts derived from the configuration are not valid: {error}"
        ))
    })
}

fn profile(id: &str, scope: &str, requester_clients: Option<Vec<String>>) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        scopes: vec![scope.to_owned()],
        purposes: Vec::new(),
        requester_clients,
        exchange: None,
        selected_by: Default::default(),
        actor_kind: None,
        required_claims: Vec::new(),
        admitted_actor_kinds: Vec::new(),
        refused_claims: Vec::new(),
    }
}

/// The clients the seals of the package's documents allow, as this issuer
/// carries them: `None` when no document names a seal. A client another issuer
/// lists is that issuer's, and a listed issuer carries only the clients it
/// lists.
fn seal_requesters(
    runtime: &RenderRuntime,
    oidc: &OidcRuntime,
    bundle: &Bundle,
    issuer_id: &str,
    admission: &Admission,
) -> Result<Option<Vec<String>>, RenderProblem> {
    let named: BTreeSet<&str> = bundle
        .documents
        .values()
        .filter_map(|document| document.spec.seal.as_deref())
        .collect();
    if named.is_empty() {
        return Ok(None);
    }
    let seals = runtime.signing.as_ref().map(|signing| &signing.seals);
    let mut clients = BTreeSet::new();
    for seal in &named {
        let bound = seals
            .and_then(|seals| seals.iter().find(|(id, _)| id.as_str() == *seal))
            .ok_or_else(|| {
                invalid(format!(
                    "a document of the package names the seal `{seal}`, and signing.seals does not bind it"
                ))
            })?;
        clients.extend(bound.1.allowed_clients.as_slice().iter().cloned());
    }
    let listed_elsewhere: BTreeSet<&str> = oidc
        .issuers
        .iter()
        .filter(|(id, _)| id.as_str() != issuer_id)
        .filter_map(|(_, entry)| match entry.core().allowed_clients.admitted() {
            Admitted::Listed(listed) => Some(listed),
            _ => None,
        })
        .flatten()
        .map(String::as_str)
        .collect();
    let requesters: Vec<String> = clients
        .into_iter()
        .filter(|client| admission.admits(client) && !listed_elsewhere.contains(client.as_str()))
        .collect();
    if requesters.is_empty() {
        // An issuer used only to render carries no seal client, and has no
        // seal profile. A single issuer that carries none is refused by the
        // runtime check, so it is not reachable here.
        if oidc.issuers.len() > 1 {
            return Ok(None);
        }
        return Err(invalid(format!(
            "no client of the package's seals is carried by the issuer `{issuer_id}`, so its seal profile has no requester"
        )));
    }
    Ok(Some(requesters))
}

/// Write `facts` to a new file. An existing file is never replaced.
pub(crate) fn write(facts: &IdentityFacts, output: &Path) -> Result<(), RenderProblem> {
    let yaml = facts
        .to_yaml()
        .map_err(|_| invalid("the identity facts could not be encoded".to_owned()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| {
            RenderProblem::new(
                ProblemKind::InvalidArgument,
                format!(
                    "the output file {} could not be created: {error}",
                    output.display()
                ),
            )
        })?;
    file.write_all(yaml.as_bytes()).map_err(|error| {
        RenderProblem::new(
            ProblemKind::InvalidArgument,
            format!("the output file could not be written: {error}"),
        )
    })
}
