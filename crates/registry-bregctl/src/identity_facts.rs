// SPDX-License-Identifier: Apache-2.0
//! The identity facts BReg states about one issuer, from the deployment's
//! runtime `authentication.oidc.issuers` entry and the project's access
//! profiles.
//!
//! `generate identity-facts` writes them for the hosted identity generator.
//! `bregctl dev` derives its local authority claim names through
//! [`authority_claims`], the function the facts use, so a session and a
//! deployment name the same claims.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::Path;

use registry_breg::authority::{authority_inventory, DirectClaimExpectation};
use registry_breg::consent::is_reserved_claim;
use registry_breg::contract::{
    AccessProfileSource, ActorKindSource, FieldTypeSource, LookupValueOrigin, RowBoundarySource,
};
use registry_breg::model::{
    CompiledActionExecution, CompiledActionPermission, CompiledProposalPermission,
};
use registry_breg::runtime_config::{OidcVerifierConfig, RuntimeConfig};
use registry_breg::CompiledRegistry;
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile as FactsProfile, ActorKind as FactsActorKind, Admission, ClaimType,
    IdentityFacts,
};

/// The product name the facts carry.
const PRODUCT: &str = "breg";
/// The claim BReg reads scopes from unless the runtime names another.
const DEFAULT_SCOPE_CLAIM: &str = "scope";
/// The claim the hosted generator derives an actor kind under.
const ACTOR_KIND_CLAIM: &str = identity_facts::ACTOR_KIND_CLAIM;
/// The code of the refusal for two or more issuer entries and no `--issuer`.
pub(crate) const ISSUER_REQUIRED_CODE: &str = "identity.facts.issuer-required";
/// The code of the refusal for an `--issuer` that names no entry.
pub(crate) const UNKNOWN_ISSUER_CODE: &str = "identity.facts.unknown-issuer";
/// The one purpose claim hosted generation derives and checks.
const PURPOSE_CLAIM: &str = "registry_purpose";

/// The claim names the compiled access profiles read.
pub(crate) struct AuthorityClaims {
    /// The one claim every profile reads the principal from.
    pub principal: String,
    /// Whether any profile requires a purpose.
    pub purpose_required: bool,
}

/// The principal claim the compiled profiles share, and whether a purpose is
/// required. Refuses when profiles disagree on the principal claim, because
/// one runtime names one.
pub(crate) fn authority_claims(compiled: &CompiledRegistry) -> Result<AuthorityClaims, String> {
    let inventory = authority_inventory(compiled)
        .map_err(|_| "the compiled registry's authority claims cannot be inspected".to_owned())?;
    let principal = match inventory
        .principal_claims
        .into_iter()
        .collect::<Vec<_>>()
        .as_slice()
    {
        [claim] => claim.clone(),
        [] => "registry_principal".to_owned(),
        claims => {
            return Err(format!(
                "the compiled registry declares multiple: {}",
                claims.join(", ")
            ))
        }
    };
    Ok(AuthorityClaims {
        principal,
        purpose_required: inventory.purpose_required,
    })
}

#[derive(Debug)]
pub(crate) enum FactsError {
    /// The configuration or project cannot be stated as facts.
    Unstatable(String),
    /// The runtime declares several issuer entries and none was named.
    IssuerRequired(String),
    /// The named issuer is not an entry of the runtime.
    UnknownIssuer(String),
    Encode,
    Write(io::Error),
}

impl FactsError {
    /// The diagnostic code of the refusal.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::IssuerRequired(_) => ISSUER_REQUIRED_CODE,
            Self::UnknownIssuer(_) => UNKNOWN_ISSUER_CODE,
            Self::Unstatable(_) | Self::Encode => "identity-facts.unstatable",
            Self::Write(_) => "identity-facts.output-failed",
        }
    }
}

impl fmt::Display for FactsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unstatable(message)
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

fn unstatable(message: impl Into<String>) -> FactsError {
    FactsError::Unstatable(message.into())
}

/// One compiled grant of an access profile: a record type's or a statistical
/// dataset's profile, or an Action's or a Proposal's permission. A profile
/// that grants only an Action or a Proposal appears on no record type, so
/// each surface the compiler carries is visited; they are the surfaces
/// `authority_inventory` in `registry-breg` walks.
struct Grant<'a> {
    id: &'a str,
    actor_kind: Option<ActorKindSource>,
    requester_clients: Vec<String>,
    principal_claim: Option<&'a str>,
    scopes: Vec<String>,
    purposes: Vec<String>,
    /// The row-boundary and verified-claim lookup claims this grant reads.
    claims: BTreeSet<&'a str>,
}

fn boundary_claims(boundaries: &[RowBoundarySource]) -> impl Iterator<Item = &str> {
    boundaries.iter().map(|boundary| boundary.claim.as_str())
}

impl<'a> Grant<'a> {
    fn profile(profile: &'a AccessProfileSource) -> Self {
        let lookups = profile
            .lookups
            .iter()
            .filter(|lookup| lookup.value_origin == LookupValueOrigin::VerifiedClaim)
            .flat_map(|lookup| lookup.claim_mapping.values().map(String::as_str));
        Self {
            id: &profile.id,
            actor_kind: profile.actor_kind,
            requester_clients: profile.requester_clients.iter().cloned().collect(),
            principal_claim: Some(&profile.principal_claim),
            scopes: profile.required_scopes.iter().cloned().collect(),
            purposes: profile.required_purposes.iter().cloned().collect(),
            claims: boundary_claims(&profile.row_boundaries)
                .chain(lookups)
                .collect(),
        }
    }

    fn action(permission: &'a CompiledActionPermission) -> Self {
        Self {
            id: &permission.profile_id,
            actor_kind: permission.actor_kind,
            requester_clients: permission.requester_clients.iter().cloned().collect(),
            principal_claim: permission.principal_claim.as_deref(),
            scopes: permission.required_scopes.iter().cloned().collect(),
            purposes: permission.required_purposes.iter().cloned().collect(),
            claims: permission
                .targets
                .iter()
                .flat_map(|target| boundary_claims(&target.row_boundaries))
                .collect(),
        }
    }

    fn proposal(permission: &'a CompiledProposalPermission) -> Self {
        Self {
            id: &permission.profile_id,
            actor_kind: permission.actor_kind,
            requester_clients: permission.requester_clients.iter().cloned().collect(),
            principal_claim: permission.principal_claim.as_deref(),
            scopes: permission.required_scopes.iter().cloned().collect(),
            purposes: permission.required_purposes.iter().cloned().collect(),
            claims: permission
                .targets
                .iter()
                .flat_map(|target| boundary_claims(&target.row_boundaries))
                .collect(),
        }
    }

    /// The grant's facts, with the scopes, purposes and clients it states.
    fn facts(&self) -> Result<FactsProfile, FactsError> {
        let principal = self.principal_claim.ok_or_else(|| {
            unstatable(format!(
                "the access profile `{}` names no principal claim on an Action or Proposal",
                self.id
            ))
        })?;
        Ok(FactsProfile {
            id: self.id.to_owned(),
            scopes: self.scopes.clone(),
            purposes: self.purposes.clone(),
            requester_clients: (!self.requester_clients.is_empty())
                .then(|| self.requester_clients.clone()),
            exchange: None,
            selected_by: BTreeMap::new(),
            // A human or service profile admits a caller of this kind only,
            // so the facts state a requirement and not a selector.
            actor_kind: self.actor_kind.map(facts_actor_kind),
            required_claims: required_claims(principal, &self.claims)
                .into_iter()
                .collect(),
            admitted_actor_kinds: Vec::new(),
            refused_claims: Vec::new(),
        })
    }
}

fn compiled_grants(compiled: &CompiledRegistry) -> impl Iterator<Item = Grant<'_>> {
    let entity_grants = compiled
        .entities()
        .values()
        .flat_map(|entity| entity.access_profiles.values().map(Grant::profile));
    let dataset_grants = compiled
        .statistical_datasets()
        .values()
        .flat_map(|dataset| dataset.access_profiles.values().map(Grant::profile));
    let action_grants = compiled.actions().actions.iter().flat_map(|action| {
        let proposal = match &action.execution {
            CompiledActionExecution::Proposal { proposal } => proposal.permissions.as_slice(),
            CompiledActionExecution::Immediate => &[],
        };
        action
            .permissions
            .iter()
            .map(Grant::action)
            .chain(proposal.iter().map(Grant::proposal))
    });
    entity_grants.chain(dataset_grants).chain(action_grants)
}

/// The claims BReg refuses a token for a grant without, apart from the
/// subject every token carries and the reserved consent claims the engine
/// fills from the verified client.
///
/// The principal claim: authentication requires it on every token
/// (`required_direct_string` in `registry-breg` `auth.rs`), and
/// `authorize_profile_claims` in `api/mod.rs` refuses a token whose principal
/// is missing. Each row-boundary claim: `verified_row_boundaries_from_sources`
/// returns nothing without it, which `authorize_profile_claims` refuses as
/// `row-claim-missing-or-wrong-cardinality`. Each verified-claim lookup
/// claim: `lookup_verified_claim_values` refuses the lookup without it. A
/// profile bound by a claim on only some record types, Actions or Proposals
/// still states it, since the profile's grant is refused there without it.
fn required_claims(principal: &str, claims: &BTreeSet<&str>) -> BTreeSet<String> {
    std::iter::once(principal)
        .chain(claims.iter().copied())
        .filter(|claim| *claim != "sub" && !is_reserved_claim(claim))
        .map(str::to_owned)
        .collect()
}

/// The facts spelling of the actor kind a BReg profile requires.
fn facts_actor_kind(kind: ActorKindSource) -> FactsActorKind {
    match kind {
        ActorKindSource::Human => FactsActorKind::Human,
        ActorKindSource::Agent => FactsActorKind::Agent,
        ActorKindSource::Service => FactsActorKind::Service,
    }
}

/// The issuer entry the facts describe: the one `issuer` names, or the only
/// entry when the runtime has one.
fn selected<'a>(
    config: &'a RuntimeConfig,
    issuer: Option<&str>,
) -> Result<&'a OidcVerifierConfig, FactsError> {
    let oidc = config.authentication().oidc();
    match issuer {
        Some(wanted) => oidc.issuer(wanted).ok_or_else(|| {
            FactsError::UnknownIssuer(
                "authentication.oidc.issuers declares no issuer with the id given to --issuer. Name one of the issuer ids under authentication.oidc.issuers".to_owned(),
            )
        }),
        None if oidc.issuers().count() == 1 => Ok(oidc.first()),
        None => Err(FactsError::IssuerRequired(format!(
            "authentication.oidc.issuers declares {} issuers, and the facts describe one. Pass --issuer with the id of the issuer to describe",
            oidc.issuers().count()
        ))),
    }
}

/// The facts for one issuer entry, and the ids of the access profiles left
/// out of them.
///
/// A profile that requires an agent is left out: BReg refuses every direct
/// token on it and reaches it only through a delegated or task-grant token,
/// which hosted generation does not issue. A grant naming it is then refused
/// by the generator as an unknown profile.
pub(crate) struct Stated {
    pub facts: IdentityFacts,
    pub omitted_agent_profiles: BTreeSet<String>,
}

/// The facts a runtime configuration and the project it serves state for one
/// issuer entry. When the runtime declares several entries, a profile that
/// names requester clients is stated with those the entry lists, and left out
/// when it lists none of them. A client is listed by an entry only when the
/// entry names it: `unrestricted` lists none, as at startup.
pub(crate) fn facts(
    config: &RuntimeConfig,
    compiled: &CompiledRegistry,
    issuer: Option<&str>,
) -> Result<Stated, FactsError> {
    let entry = selected(config, issuer)?;
    let several_issuers = config.authentication().oidc().issuers().count() > 1;
    let verifier = entry.token_verifier_config();
    let [audience] = verifier.audiences.as_slice() else {
        return Err(unstatable(format!(
            "authentication.oidc.issuers.{}.audience names more than one audience",
            entry.id()
        )));
    };
    let authentication = config.authentication();
    let scope_claim = verifier.scope_claim.as_str();
    let claim_names = authentication.authority_claim_config();
    if claim_names.actor_kind_claim() != ACTOR_KIND_CLAIM {
        return Err(unstatable(format!(
            "authentication.authorityClaims.contextual.actorKind is not the default `{ACTOR_KIND_CLAIM}`, which hosted generation does not support yet. Set it to `{ACTOR_KIND_CLAIM}`"
        )));
    }
    if claim_names
        .purpose_claim()
        .is_some_and(|claim| claim != PURPOSE_CLAIM)
    {
        return Err(unstatable(format!(
            "authentication.authorityClaims.purpose is not `{PURPOSE_CLAIM}`, which hosted generation does not support yet. Set it to `{PURPOSE_CLAIM}`"
        )));
    }
    let allowed = if verifier.allowed_clients.is_empty() {
        Admission::Unrestricted
    } else {
        Admission::Clients(verifier.allowed_clients.clone())
    };
    let mut facts = IdentityFacts::new(PRODUCT, &verifier.issuer, audience, allowed.clone());

    // The verifier accepts the scope claim as a space-separated string or an
    // array of strings. The facts state the array, which needs no separator.
    if scope_claim != DEFAULT_SCOPE_CLAIM {
        refuse_reserved_scope_claim(&facts, scope_claim, entry.id())?;
        facts
            .claims
            .insert(scope_claim.to_owned(), ClaimType::StringArray);
    }
    // The generator derives a kind for every principal. A token that carries
    // none authenticates with no kind, so every generated client states one.
    facts
        .claims
        .insert(ACTOR_KIND_CLAIM.to_owned(), ClaimType::String);

    let mut profiles: BTreeMap<String, FactsProfile> = BTreeMap::new();
    let mut omitted_agent_profiles = BTreeSet::new();
    for grant in compiled_grants(compiled) {
        if grant.actor_kind == Some(ActorKindSource::Agent) {
            omitted_agent_profiles.insert(grant.id.to_owned());
            continue;
        }
        let mut stated = grant.facts()?;
        // A renamed scope claim is how the issuer selects this profile: the
        // principal must carry every scope the profile requires there.
        if scope_claim != DEFAULT_SCOPE_CLAIM {
            stated.selected_by = BTreeMap::from([(scope_claim.to_owned(), stated.scopes.clone())]);
        }
        if several_issuers && !stated.requester_clients.as_ref().is_none_or(Vec::is_empty) {
            refuse_clients_no_entry_lists(config, &stated)?;
            let requesters: Vec<String> = stated
                .requester_clients
                .iter()
                .flatten()
                .filter(|client| verifier.allowed_clients.contains(client))
                .cloned()
                .collect();
            if requesters.is_empty() {
                continue;
            }
            stated.requester_clients = Some(requesters);
        }
        match profiles.get_mut(grant.id) {
            Some(existing) => {
                // Row boundaries are set per record type, Action and
                // Proposal, so the required claims are the union over them;
                // everything else must agree.
                let required: BTreeSet<String> = existing
                    .required_claims
                    .iter()
                    .chain(&stated.required_claims)
                    .cloned()
                    .collect();
                stated.required_claims.clone_from(&existing.required_claims);
                if *existing != stated {
                    return Err(unstatable(format!(
                        "the access profile `{}` is declared with different scopes, purposes, clients or actor kinds on different record types, datasets, Actions or Proposals",
                        grant.id
                    )));
                }
                existing.required_claims = required.into_iter().collect();
            }
            None => {
                profiles.insert(grant.id.to_owned(), stated);
            }
        }
    }
    for stated in profiles.values() {
        if stated.scopes.is_empty() {
            return Err(unstatable(format!(
                "the access profile `{}` requires no scope, so it names no scope to grant. List its scopes in requiredScopes",
                stated.id
            )));
        }
        if stated
            .requester_clients
            .iter()
            .flatten()
            .any(|client| !verifier.allowed_clients.contains(client))
        {
            return Err(unstatable(format!(
                "the access profile `{}` names a requester client that authentication.oidc.issuers.{}.allowedClients does not admit",
                stated.id,
                entry.id()
            )));
        }
    }
    facts.access_profiles = profiles.into_values().collect();

    let authority = authority_claims(compiled).map_err(unstatable)?;
    if authority.principal != "sub" {
        facts.claims.insert(authority.principal, ClaimType::String);
    }
    if let Some(purpose) = config
        .authentication()
        .authority_claim_config()
        .purpose_claim()
    {
        facts.claims.insert(purpose.to_owned(), ClaimType::String);
    }
    let inventory = authority_inventory(compiled)
        .map_err(|_| unstatable("the compiled registry's authority claims cannot be inspected"))?;
    for (name, expectation) in inventory.direct_claims {
        refuse_unissuable_claim(&name, &expectation)?;
        let kind = if expectation.multi_value {
            ClaimType::StringArray
        } else {
            ClaimType::String
        };
        facts.claims.insert(name, kind);
    }

    // Read the document back through the facts reader so an invalid document
    // is refused here, not by the generator that consumes it.
    let yaml = facts.to_yaml().map_err(|_| FactsError::Encode)?;
    let facts = identity_facts::read("identity-facts", yaml.as_bytes()).map_err(|error| {
        unstatable(format!(
            "the facts derived from the configuration are not valid: {error}"
        ))
    })?;
    Ok(Stated {
        facts,
        omitted_agent_profiles,
    })
}

/// Refuse a scope claim name the facts reader reserves. The reader exposes no
/// check of its own, so the name is declared in an otherwise valid document and
/// the reader decides.
fn refuse_reserved_scope_claim(
    base: &IdentityFacts,
    scope_claim: &str,
    entry: &str,
) -> Result<(), FactsError> {
    let reads = |facts: &IdentityFacts| {
        facts
            .to_yaml()
            .map_err(|_| FactsError::Encode)
            .map(|yaml| identity_facts::read("identity-facts", yaml.as_bytes()).is_ok())
    };
    let mut probe = base.clone();
    if !reads(&probe)? {
        // The base itself is refused: the final read-back reports it.
        return Ok(());
    }
    probe
        .claims
        .insert(scope_claim.to_owned(), ClaimType::StringArray);
    if reads(&probe)? {
        return Ok(());
    }
    Err(unstatable(format!(
        "authentication.oidc.issuers.{entry}.scopeClaim names a claim hosted generation cannot issue: a JWT or OpenID Connect claim such as scp or roles, a registry_grant_ claim, or a name with characters other than letters, digits and `_`. Set it to scope, or to a name of letters, digits and `_`"
    )))
}

/// Refuse a profile that names a requester client no issuer entry of the
/// runtime lists, as the runtime does at startup.
fn refuse_clients_no_entry_lists(
    config: &RuntimeConfig,
    stated: &FactsProfile,
) -> Result<(), FactsError> {
    let oidc = config.authentication().oidc();
    let listed_somewhere = |client: &String| {
        oidc.issuers().any(|entry| {
            entry
                .token_verifier_config()
                .allowed_clients
                .contains(client)
        })
    };
    if stated
        .requester_clients
        .iter()
        .flatten()
        .all(listed_somewhere)
    {
        return Ok(());
    }
    Err(unstatable(format!(
        "the access profile `{}` names a requester client that no authentication.oidc.issuers entry's allowedClients admits",
        stated.id
    )))
}

/// Refuse a claim BReg reads as a JSON value other than a string.
///
/// `mapped_scalar_claim` in `registry-breg` `auth.rs` reads a claim compared
/// with a boolean field as a JSON boolean and one compared with an int64 field
/// as a JSON integer, and refuses every token whose value is not; the hosted
/// generator issues every claim value as a string. Coordinates and structured
/// values are refused whatever their shape.
fn refuse_unissuable_claim(
    name: &str,
    expectation: &DirectClaimExpectation,
) -> Result<(), FactsError> {
    let field_type = match expectation.field_type {
        FieldTypeSource::Boolean => "boolean",
        FieldTypeSource::Int64 => "int64",
        FieldTypeSource::Crs84Point { .. } => "crs84-point",
        FieldTypeSource::Crs84Polygon { .. } => "crs84-polygon",
        FieldTypeSource::Structured { .. } => "structured",
        _ => return Ok(()),
    };
    let field = expectation
        .uses
        .first()
        .map(|usage| format!(" `{}` of `{}`", usage.field_id, usage.entity_id))
        .unwrap_or_default();
    Err(unstatable(format!(
        "the claim `{name}` is compared with the {field_type} field{field}, which BReg reads from a token as a non-string JSON value. Hosted generation issues every claim value as a string, so bind the claim to a string field"
    )))
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
