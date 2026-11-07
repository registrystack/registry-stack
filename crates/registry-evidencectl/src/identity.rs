// SPDX-License-Identifier: Apache-2.0
//! Evidence's identity facts: what this product expects of its token issuer,
//! stated once from its own configuration.
//!
//! `evidencectl generate identity-facts` derives them from the project, its
//! deployment target and the public client registrations. `evidencectl dev`
//! writes its local clients' claims through the same [`ClaimNames`], so a
//! deployment and a development session declare the same claims.
//!
//! The facts name no path and no secret. The target is read for its
//! `authentication.oidc` and `authority` members only; no secret reference in
//! it is resolved.
use crate::{access, authored, normalized};
use anyhow::{Context, Result};
use registry_evidence_authoring::project::AuthorityKind;
use registry_evidence_authoring::target::TargetAdmissionGate;
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile, ActorKind, Admission, AssertionIssuer, AssertionMapping, ClaimType,
    ExchangeBinding, IdentityFacts,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

/// The product name in the facts document.
pub(crate) const PRODUCT: &str = "evidence";

/// The names of the claims Evidence reads from a token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimNames {
    /// Marks the kind of actor behind the token.
    pub actor_kind: String,
    /// Lists the requester tags the client holds.
    pub requester_tags: String,
    /// Names the relying-party audience the client may request for.
    pub evidence_audience: String,
    /// Identifies the acting person or agent, when the target configures it.
    pub actor: Option<String>,
    /// Names the requester, when the target reads it from a claim other than
    /// the subject.
    pub principal: Option<String>,
}

impl Default for ClaimNames {
    /// The names the local development issuer uses.
    fn default() -> Self {
        Self {
            actor_kind: "registry_actor_kind".to_owned(),
            requester_tags: "evidence_tags".to_owned(),
            evidence_audience: "evidence_audience".to_owned(),
            actor: None,
            principal: None,
        }
    }
}

impl ClaimNames {
    /// The claims of a client that requests assertions for itself.
    pub(crate) fn requester_claims(
        &self,
        actor_kind: &str,
        requester_tags: &[String],
        evidence_audience: &str,
    ) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (self.actor_kind.clone(), json!(actor_kind)),
            (self.requester_tags.clone(), json!(requester_tags)),
            (self.evidence_audience.clone(), json!(evidence_audience)),
        ])
    }

    /// The claims of a client that presents a task authority assertion; the
    /// issuer derives the rest from the exchange.
    pub(crate) fn exchange_claims(&self, actor_kind: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([(self.actor_kind.clone(), json!(actor_kind))])
    }

    fn declared(&self) -> BTreeMap<String, ClaimType> {
        let mut claims = BTreeMap::from([
            (self.actor_kind.clone(), ClaimType::String),
            (self.requester_tags.clone(), ClaimType::StringArray),
            (self.evidence_audience.clone(), ClaimType::String),
        ]);
        if let Some(actor) = &self.actor {
            claims.insert(actor.clone(), ClaimType::String);
        }
        if let Some(principal) = &self.principal {
            claims.insert(principal.clone(), ClaimType::String);
        }
        claims
    }

    /// The claims Evidence refuses any token without, apart from the subject.
    /// `extract_context` in `registry-evidence` `auth.rs` requires the actor
    /// kind, the principal, the Evidence audience and a non-empty list of
    /// requester tags on every token, whatever profile it reaches.
    fn required(&self) -> Vec<String> {
        let mut required = BTreeSet::from([
            self.actor_kind.clone(),
            self.evidence_audience.clone(),
            self.requester_tags.clone(),
        ]);
        required.extend(self.principal.clone());
        required.into_iter().collect()
    }
}

/// An access profile reached by presenting a task authority's assertion.
pub(crate) struct Exchange {
    /// The authority whose assertion the profile accepts.
    pub issuer: String,
    /// The audience of the resource that accepts the assertion.
    pub bootstrap_audience: String,
    pub bootstrap_scope: String,
}

pub(crate) struct Profile {
    pub id: String,
    pub purposes: BTreeSet<String>,
    pub requester_clients: Option<Vec<String>>,
    pub exchange: Option<Exchange>,
    /// The actor kind the profile is for, when it states one.
    pub actor_kind: Option<String>,
    /// The tags a requester must hold. Empty for an exchange profile: the
    /// authority's grant supplies those, not the client.
    pub requester_tags: Vec<String>,
    /// Whether the profile's authority is delegated, the only kind Evidence
    /// serves a token that names an acting person or agent from.
    pub delegated: bool,
}

/// Everything the facts are derived from.
pub(crate) struct Inputs<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub allowed_clients: Admission,
    /// The scopes every token must carry.
    pub required_scopes: &'a [String],
    pub claims: &'a ClaimNames,
    pub profiles: Vec<Profile>,
}

/// The assertion issuer id for `issuer`: its host and path as a local
/// identifier. Every product that names this authority derives the same id,
/// so the products' facts state it identically when they are merged.
pub(crate) fn assertion_issuer_id(issuer: &str) -> String {
    let rest = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
        .unwrap_or(issuer);
    let mut id = String::new();
    for character in rest.chars().flat_map(char::to_lowercase) {
        let kept = if character.is_ascii_alphanumeric() {
            character
        } else {
            '-'
        };
        if kept != '-' || !id.is_empty() && !id.ends_with('-') {
            id.push(kept);
        }
    }
    id.truncate(64);
    id.trim_end_matches('-').to_owned()
}

/// The claim values by which Evidence selects `profile` at runtime: the
/// actor kind and the requester tags.
fn selected_by(claims: &ClaimNames, profile: &Profile) -> BTreeMap<String, Vec<String>> {
    let mut selected = BTreeMap::new();
    if let Some(actor_kind) = &profile.actor_kind {
        selected.insert(claims.actor_kind.clone(), vec![actor_kind.clone()]);
    }
    if !profile.requester_tags.is_empty() {
        selected.insert(
            claims.requester_tags.clone(),
            profile.requester_tags.clone(),
        );
    }
    selected
}

/// The actor kinds Evidence admits for a client's own token on `profile`,
/// when it admits only some: an agent without a task grant reaches only the
/// profiles that name agents (`authority_selected_by_principal` in
/// `registry-evidence` `selector.rs`), so a standing profile that names no
/// kind admits humans and services. A profile that names a kind states it in
/// `selectedBy`, and an exchange profile's token carries a task grant.
fn admitted_actor_kinds(profile: &Profile) -> Vec<ActorKind> {
    if profile.exchange.is_none() && profile.actor_kind.is_none() {
        vec![ActorKind::Human, ActorKind::Service]
    } else {
        Vec::new()
    }
}

/// The claims that keep Evidence from serving `profile`: a token that names
/// an acting person or agent reaches only delegated authorities
/// (`match_entitlement` in `registry-evidence` `selector.rs`).
fn refused_claims(claims: &ClaimNames, profile: &Profile) -> Vec<String> {
    match &claims.actor {
        Some(actor) if !profile.delegated => vec![actor.clone()],
        _ => Vec::new(),
    }
}

/// Where an assertion authority publishes its public keys.
fn authority_jwks_url(issuer: &str) -> String {
    format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'))
}

/// The facts document for `inputs`. Two authorities whose issuers derive one
/// assertion issuer id are refused: one entry would bind both profiles to the
/// first authority.
pub(crate) fn facts(inputs: &Inputs<'_>) -> Result<IdentityFacts> {
    let mut facts = IdentityFacts::new(
        PRODUCT,
        inputs.issuer,
        inputs.audience,
        inputs.allowed_clients.clone(),
    );
    facts.claims = inputs.claims.declared();
    for profile in &inputs.profiles {
        let exchange = match &profile.exchange {
            None => None,
            Some(exchange) => {
                let id = assertion_issuer_id(&exchange.issuer);
                match facts
                    .assertion_issuers
                    .iter()
                    .find(|issuer| issuer.id == id)
                {
                    Some(existing) if existing.issuer != exchange.issuer => {
                        return Err(refuse(
                            "evidence.generate-identity-facts.assertion-issuer-collision",
                            format!("accessProfiles/{}: its grantSourceIssuer and another profile's differ but derive the same assertion issuer id; name each task authority by an issuer that differs in more than punctuation or past the first 64 characters.", profile.id),
                        ));
                    }
                    Some(_) => {}
                    None => facts.assertion_issuers.push(AssertionIssuer {
                        id: id.clone(),
                        issuer: exchange.issuer.clone(),
                        jwks_url: authority_jwks_url(&exchange.issuer),
                        mapping: AssertionMapping::InstitutionalGrant,
                        projected_claims: BTreeMap::new(),
                    }),
                }
                Some(ExchangeBinding {
                    assertion_issuer_id: id,
                    bootstrap_audience: exchange.bootstrap_audience.clone(),
                    bootstrap_scope: exchange.bootstrap_scope.clone(),
                })
            }
        };
        facts.access_profiles.push(AccessProfile {
            id: profile.id.clone(),
            scopes: inputs.required_scopes.to_vec(),
            purposes: profile.purposes.iter().cloned().collect(),
            requester_clients: profile.requester_clients.clone(),
            exchange,
            selected_by: selected_by(inputs.claims, profile),
            actor_kind: None,
            required_claims: inputs.claims.required(),
            admitted_actor_kinds: admitted_actor_kinds(profile),
            refused_claims: refused_claims(inputs.claims, profile),
        });
    }
    Ok(facts)
}

/// The facts of a deployment: its target, the authority the target names, and
/// the project's public client registrations.
fn deployed(project: &Path, target_path: &Path) -> Result<IdentityFacts> {
    let (project_doc, _) = normalized::read(project)?;
    let target_path = crate::target::target_path(target_path);
    let target_bytes = authored::read_authored_file(&target_path, "Evidence target")?;
    let target = registry_evidence_authoring::target::read_target(
        &target_path.to_string_lossy(),
        &target_bytes,
    )?
    .value;
    let target_root = normalized::target_directory(&target_path)
        .canonicalize()
        .context("resolving the Evidence target directory")?;
    let authority_path = normalized::safe_asset(&target_root, &target.authority)?;
    let authority_bytes = authored::read_authored_file(&authority_path, "target authority")?;
    let authority = registry_evidence_authoring::target::read_authority(
        &authority_path.to_string_lossy(),
        &authority_bytes,
        &project_doc,
    )?
    .value;

    let oidc = &target.authentication.oidc;
    // The gates serialize as the keyword `unrestricted` or a list.
    let allowed_clients = match oidc.allowed_clients.as_ref().map(listed).transpose()? {
        Some(Some(clients)) => Admission::Clients(clients),
        Some(None) | None => Admission::Unrestricted,
    };
    let Some(required_scopes) = listed(&oidc.required_scopes)? else {
        return Err(refuse(
            "evidence.generate-identity-facts.scopes-unrestricted",
            "authentication.oidc.requiredScopes is unrestricted; list the scopes the issuer grants Evidence.".to_owned(),
        ));
    };
    if let Some(names) = &oidc.claims {
        default_contextual_claims(&serde_json::to_value(names)?)?;
    }
    let claims = ClaimNames {
        requester_tags: oidc.requester_tags_claim.clone(),
        evidence_audience: oidc.evidence_audience_claim.clone(),
        actor: oidc.actor_claim.clone(),
        principal: (oidc.principal_claim != "sub").then(|| oidc.principal_claim.clone()),
        ..ClaimNames::default()
    };

    let exchange_clients = access::active_exchange_clients(project)?;
    let mut profiles = Vec::new();
    for (id, profile) in &authority.access_profiles {
        let id = id.to_string();
        let exchange = match &profile.grant_source_issuer {
            None => None,
            Some(issuer) => Some(exchange_binding(&id, issuer.as_ref(), &exchange_clients)?),
        };
        profiles.push(Profile {
            purposes: profile
                .grants
                .iter()
                .map(|grant| grant.purpose.clone())
                .collect(),
            requester_clients: profile
                .requester_clients
                .as_ref()
                .map(|clients| clients.iter().cloned().collect()),
            actor_kind: profile
                .actor_kind
                .as_ref()
                .map(|kind| {
                    serde_json::to_value(kind)?
                        .as_str()
                        .map(str::to_owned)
                        .context("an access profile actorKind is not text")
                })
                .transpose()?,
            requester_tags: if exchange.is_some() {
                Vec::new()
            } else {
                profile.requester_tags.iter().cloned().collect()
            },
            delegated: profile.authority == AuthorityKind::Delegated,
            exchange,
            id,
        });
    }
    facts(&Inputs {
        issuer: oidc.issuer.as_str(),
        audience: &oidc.audience,
        allowed_clients,
        required_scopes: &required_scopes,
        claims: &claims,
        profiles,
    })
}

/// Each member of `authentication.oidc.claims` and the platform name the
/// issuer writes that claim under: the actor kind on every token it issues,
/// the task grant and its purpose on every exchanged token.
const CONTEXTUAL_CLAIMS: [(&str, &str); 9] = [
    ("actorKind", "registry_actor_kind"),
    ("purpose", "registry_purpose"),
    ("grantId", "registry_grant_id"),
    ("grantSourceIssuer", "registry_grant_source_issuer"),
    ("grantClient", "registry_grant_client"),
    ("grantResource", "registry_grant_resource"),
    ("grantExp", "registry_grant_exp"),
    ("grantBounds", "registry_grant_bounds"),
    ("approver", "registry_approver"),
];

/// Refuse a target that renames a contextual claim. Evidence reads it under
/// the configured name, but the generated issuer writes it under the
/// platform name only, so every token would lack the claim Evidence reads.
fn default_contextual_claims(names: &Value) -> Result<()> {
    let names = names
        .as_object()
        .context("authentication.oidc.claims did not serialize as a map")?;
    for (member, name) in names {
        let Some((_, platform)) = CONTEXTUAL_CLAIMS.iter().find(|(known, _)| known == member)
        else {
            return Err(refuse(
                "evidence.generate-identity-facts.claim-name-unsupported",
                format!("authentication.oidc.claims.{member} names a claim hosted generation does not know; remove it."),
            ));
        };
        if name.as_str() != Some(*platform) {
            return Err(refuse(
                "evidence.generate-identity-facts.claim-name-unsupported",
                format!("authentication.oidc.claims.{member} is not the default `{platform}`, which hosted generation does not support yet; set it to `{platform}` or remove it."),
            ));
        }
    }
    Ok(())
}

/// The values a gate lists, or `None` when it admits everything. Each gate
/// variant is named, so a new one is a compile error and never read as
/// "unrestricted".
fn listed(gate: &TargetAdmissionGate) -> Result<Option<Vec<String>>> {
    match gate {
        TargetAdmissionGate::Unrestricted(_) => Ok(None),
        TargetAdmissionGate::Listed(values) => match serde_json::to_value(values)? {
            Value::Array(values) => strings(&values).map(Some),
            _ => Err(anyhow::anyhow!(
                "an admission list did not serialize as a list"
            )),
        },
    }
}

fn strings(values: &[Value]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("a configured list holds a value that is not text")
        })
        .collect()
}

/// The exchange a task-grant profile is reached by: the bootstrap the active
/// clients holding it are registered with. They must agree, and name the
/// resource that accepts the assertion, which the target cannot supply.
fn exchange_binding(
    profile: &str,
    issuer: &str,
    clients: &[access::ExchangeClient],
) -> Result<Exchange> {
    let mut registered = BTreeSet::new();
    for client in clients
        .iter()
        .filter(|client| client.access_profiles.iter().any(|held| held == profile))
    {
        if client.exchange.kind != access::ActiveClientExchangeKind::InstitutionalGrant {
            return Err(refuse(
                "evidence.generate-identity-facts.first-party-exchange",
                format!("accessProfiles/{profile}: a signed first-party exchange has no identity facts; register an institutional task exchange client."),
            ));
        }
        let Some(resource) = &client.exchange.bootstrap_resource else {
            return Err(refuse(
                "evidence.generate-identity-facts.bootstrap-resource",
                format!("accessProfiles/{profile}: a registered exchange client names no bootstrap resource; register it with --grant-bootstrap-resource."),
            ));
        };
        registered.insert((resource.clone(), client.exchange.bootstrap_scope.clone()));
    }
    let mut registered = registered.into_iter();
    match (registered.next(), registered.next()) {
        (Some((bootstrap_audience, bootstrap_scope)), None) => Ok(Exchange {
            issuer: issuer.to_owned(),
            bootstrap_audience,
            bootstrap_scope,
        }),
        (None, _) => Err(refuse(
            "evidence.generate-identity-facts.exchange-client",
            format!("accessProfiles/{profile}: a task-grant profile needs an active client registered for its exchange."),
        )),
        _ => Err(refuse(
            "evidence.generate-identity-facts.exchange-conflict",
            format!("accessProfiles/{profile}: its exchange clients name different bootstrap resources or scopes."),
        )),
    }
}

/// What `generate identity-facts` reports: the output and counts, nothing the
/// facts say.
pub(crate) struct Generated {
    pub output: PathBuf,
    pub claims: usize,
    pub access_profiles: usize,
    pub assertion_issuers: usize,
}

/// A deployment or output `generate identity-facts` refuses, with a message
/// that names no authored value.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

fn refuse(code: &'static str, message: String) -> anyhow::Error {
    Refusal { code, message }.into()
}

pub(crate) fn generate(project: &Path, target: &Path, output: &Path) -> Result<Generated> {
    let facts = deployed(project, target)?;
    let yaml = facts.to_yaml()?;
    // The facts must read back, so a document the generator would refuse is
    // never written.
    identity_facts::read("identity-facts", yaml.as_bytes())?;
    let mut file =
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Err(refuse(
                "evidence.generate-identity-facts.output-exists",
                "The --output file already exists; generate identity-facts never overwrites it."
                    .to_owned(),
            )),
            Err(error) => return Err(error).context("creating the identity facts file"),
        };
    file.write_all(yaml.as_bytes())
        .context("writing the identity facts file")?;
    file.sync_all().context("writing the identity facts file")?;
    Ok(Generated {
        output: output.to_path_buf(),
        claims: facts.claims.len(),
        access_profiles: facts.access_profiles.len(),
        assertion_issuers: facts.assertion_issuers.len(),
    })
}

/// `evidencectl generate identity-facts`: writes the facts and reports only
/// the output path and counts.
pub(crate) fn run(
    project: PathBuf,
    target: PathBuf,
    output: PathBuf,
    format: crate::OutputFormat,
) -> Result<std::process::ExitCode> {
    let generated = generate(&project, &target, &output)?;
    match format {
        crate::OutputFormat::Human => println!(
            "wrote {} ({} claims, {} access profiles, {} assertion issuers)",
            generated.output.display(),
            generated.claims,
            generated.access_profiles,
            generated.assertion_issuers
        ),
        crate::OutputFormat::Json => crate::print_report(&crate::command_report(
            "generate identity-facts",
            json!({
                "output": generated.output.display().to_string(),
                "product": PRODUCT,
                "claims": generated.claims,
                "accessProfiles": generated.access_profiles,
                "assertionIssuers": generated.assertion_issuers,
            }),
        )),
    }
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `evidencectl dev` issues its local clients' claims through
    /// [`ClaimNames`]; these are the maps it has always issued.
    #[test]
    fn the_development_claims_keep_their_names_and_shapes() {
        let names = ClaimNames::default();
        assert_eq!(
            names.requester_claims(
                "service",
                &["profile-one".to_owned()],
                "urn:evidence:caller"
            ),
            BTreeMap::from([
                ("registry_actor_kind".to_owned(), json!("service")),
                ("evidence_tags".to_owned(), json!(["profile-one"])),
                ("evidence_audience".to_owned(), json!("urn:evidence:caller")),
            ])
        );
        assert_eq!(
            names.exchange_claims("agent"),
            BTreeMap::from([("registry_actor_kind".to_owned(), json!("agent"))])
        );
    }

    fn gate(value: Value) -> registry_evidence_authoring::target::TargetAdmissionGate {
        serde_json::from_value(value).expect("admission gate")
    }

    #[test]
    fn an_admission_gate_is_unrestricted_or_a_list_never_a_guess() {
        assert_eq!(listed(&gate(json!("unrestricted"))).unwrap(), None);
        assert_eq!(
            listed(&gate(json!(["a", "b"]))).unwrap(),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
    }

    /// Casework derives the same id for the same authority, so merged facts
    /// state it once.
    #[test]
    fn the_assertion_issuer_id_matches_the_one_casework_derives() {
        assert_eq!(
            assertion_issuer_id("https://casework.example.test"),
            "casework-example-test"
        );
        assert_eq!(
            assertion_issuer_id("https://Casework.Example.test/tasks/"),
            "casework-example-test-tasks"
        );
    }

    fn task_profile(id: &str, issuer: &str) -> Profile {
        Profile {
            id: id.to_owned(),
            purposes: BTreeSet::from(["eligibility".to_owned()]),
            requester_clients: None,
            exchange: Some(Exchange {
                issuer: issuer.to_owned(),
                bootstrap_audience: "urn:casework:example".to_owned(),
                bootstrap_scope: "casework:grants:assert".to_owned(),
            }),
            actor_kind: Some("agent".to_owned()),
            requester_tags: Vec::new(),
            delegated: false,
        }
    }

    /// Only a delegated authority serves a token that names an acting person
    /// or agent, so every other profile refuses the target's actor claim.
    #[test]
    fn only_a_delegated_profile_admits_the_actor_claim() {
        let claims = ClaimNames {
            actor: Some("evidence_actor".to_owned()),
            ..ClaimNames::default()
        };
        let standing = |id: &str, delegated: bool| Profile {
            id: id.to_owned(),
            purposes: BTreeSet::from(["eligibility".to_owned()]),
            requester_clients: None,
            exchange: None,
            actor_kind: Some("service".to_owned()),
            requester_tags: vec!["tag".to_owned()],
            delegated,
        };
        let facts = facts(&Inputs {
            issuer: "https://id.example",
            audience: "urn:evidence:example",
            allowed_clients: Admission::Unrestricted,
            required_scopes: &["evidence:request".to_owned()],
            claims: &claims,
            profiles: vec![
                standing("organizational", false),
                standing("delegated", true),
            ],
        })
        .expect("facts");
        assert_eq!(facts.access_profiles[0].refused_claims, ["evidence_actor"]);
        assert!(facts.access_profiles[1].refused_claims.is_empty());
        let without_actor = facts_of(vec![standing("organizational", false)]).expect("facts");
        assert!(without_actor.access_profiles[0].refused_claims.is_empty());
    }

    fn facts_of(profiles: Vec<Profile>) -> Result<IdentityFacts> {
        facts(&Inputs {
            issuer: "https://id.example",
            audience: "urn:evidence:example",
            allowed_clients: Admission::Unrestricted,
            required_scopes: &["evidence:request".to_owned()],
            claims: &ClaimNames::default(),
            profiles,
        })
    }

    /// Two profiles of one authority share its assertion issuer entry.
    #[test]
    fn profiles_of_one_authority_share_its_assertion_issuer() {
        let facts = facts_of(vec![
            task_profile("one", "https://authority.example/a-b"),
            task_profile("two", "https://authority.example/a-b"),
        ])
        .expect("facts");
        assert_eq!(facts.assertion_issuers.len(), 1);
    }

    /// Two authorities whose URLs normalise to one id are refused, never
    /// merged: merging would bind the second profile to the first authority.
    #[test]
    fn two_authorities_with_one_assertion_issuer_id_are_refused() {
        let long = "a".repeat(70);
        for (first, second) in [
            (
                "https://authority.example/a-b".to_owned(),
                "https://authority.example/a/b".to_owned(),
            ),
            (
                format!("https://authority.example/{long}/one"),
                format!("https://authority.example/{long}/two"),
            ),
        ] {
            assert_eq!(assertion_issuer_id(&first), assertion_issuer_id(&second));
            let error = facts_of(vec![
                task_profile("one", &first),
                task_profile("two", &second),
            ])
            .expect_err("a collision is refused");
            let refusal = error.downcast_ref::<Refusal>().expect("a refusal");
            assert_eq!(
                refusal.code,
                "evidence.generate-identity-facts.assertion-issuer-collision"
            );
            assert!(!refusal.message.contains("authority.example"), "{refusal}");
        }
    }
}
