// SPDX-License-Identifier: Apache-2.0
//! Casework's identity facts: what this product expects of its token issuer,
//! stated once from its own configuration.
//!
//! `caseworkctl generate identity-facts` derives them from the authored
//! project and the runtime configuration. `caseworkctl dev` derives the same
//! facts from the session it builds, then renders its local issuer from them,
//! so a deployment and a development session agree on the clients admitted,
//! the task authority and the clients that exchange its assertions.
//!
//! The facts name no path and no secret. The runtime file is read for its
//! `authentication.oidc` and `taskAuthority` members only; no secret
//! reference in it is resolved.
use crate::project::ProjectRefusal;
use anyhow::{bail, Context, Result};
use registry_casework::RuntimeConfig;
use registry_casework_core::{AccessProfile as ProjectProfile, CaseworkActsAs, CaseworkProject};
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile, ActorKind, Admission, AssertionIssuer, AssertionMapping, ClaimType,
    ExchangeBinding, IdentityFacts,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    path::Path,
};

/// The product name in the facts document.
pub(crate) const PRODUCT: &str = "casework";
/// The claim hosted tokens carry their scopes in.
const HOSTED_SCOPE_CLAIM: &str = "scope";
/// The claim and value a hosted issuer gives every person's token.
const HOSTED_HUMAN_CLAIM: &str = "registry_actor_kind";
const HOSTED_HUMAN_VALUE: &str = "human";
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
/// The one scope a client holds to present a task authority assertion.
pub(crate) const ASSERT_SCOPE: &str = "casework:grants:assert";
/// The one scope a client holds to read the status of a task grant.
pub(crate) const STATUS_SCOPE: &str = "casework:grants:status";
const ASSERT_PROFILE: &str = "task-assert";
const STATUS_PROFILE: &str = "task-status";
/// The token subject; every token carries it, so it is not a declared claim.
const SUBJECT_CLAIM: &str = "sub";

/// The task authority as the facts see it.
pub(crate) struct Authority {
    /// The logical issuer assertions carry.
    pub issuer: String,
    /// Where the authority's public keys are published.
    pub jwks_url: String,
    /// Clients that may read task grant status.
    pub status_clients: BTreeSet<String>,
    /// Clients that present the authority's assertion to exchange it.
    pub exchange_clients: BTreeSet<String>,
}

/// Everything the facts are derived from.
pub(crate) struct Inputs<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub allowed_clients: Admission,
    /// The claim that marks a human actor.
    pub human_claim: &'a str,
    pub profiles: &'a [ProjectProfile],
    /// Requester profiles a trusted producer names as its initiator.
    pub initiator_profiles: BTreeSet<String>,
    pub authority: Option<Authority>,
}

/// The profiles trusted producers name as their initiator. The runtime admits
/// a token for one of them, like a staff profile, only from a person.
pub(crate) fn initiator_profiles(project: &CaseworkProject) -> BTreeSet<String> {
    project
        .trusted_producers
        .iter()
        .filter_map(|producer| producer.initiator_profile.clone())
        .collect()
}

/// The facts document for `inputs`.
pub(crate) fn facts(inputs: &Inputs<'_>) -> IdentityFacts {
    let mut facts = IdentityFacts::new(
        PRODUCT,
        inputs.issuer,
        inputs.audience,
        unique(inputs.allowed_clients.clone()),
    );
    facts
        .claims
        .insert(inputs.human_claim.to_owned(), ClaimType::String);
    for profile in inputs.profiles {
        if profile.principal_claim != SUBJECT_CLAIM {
            facts
                .claims
                .insert(profile.principal_claim.clone(), ClaimType::String);
        }
        // The runtime refuses a token for these profiles unless its human
        // identity claim marks a person, so only a person may be granted them.
        let requires_person = profile.acts_as != CaseworkActsAs::Requester
            || inputs.initiator_profiles.contains(&profile.id);
        facts.access_profiles.push(AccessProfile {
            id: profile.id.clone(),
            scopes: profile.required_scopes.clone(),
            purposes: Vec::new(),
            requester_clients: None,
            exchange: None,
            selected_by: BTreeMap::new(),
            actor_kind: requires_person.then_some(ActorKind::Human),
            // The runtime refuses a token whose principal claim is missing or
            // empty (`authenticate` in `registry-casework` `auth.rs`), so a
            // named principal claim is required. The subject is always there.
            required_claims: (profile.principal_claim != SUBJECT_CLAIM)
                .then(|| profile.principal_claim.clone())
                .into_iter()
                .collect(),
            admitted_actor_kinds: Vec::new(),
            refused_claims: Vec::new(),
        });
    }
    if let Some(authority) = &inputs.authority {
        let authority_id = assertion_issuer_id(&authority.issuer);
        facts.assertion_issuers.push(AssertionIssuer {
            id: authority_id.clone(),
            issuer: authority.issuer.clone(),
            jwks_url: authority.jwks_url.clone(),
            mapping: AssertionMapping::InstitutionalGrant,
            projected_claims: BTreeMap::new(),
        });
        let narrowed = |clients: &BTreeSet<String>| {
            (!clients.is_empty()).then(|| clients.iter().cloned().collect::<Vec<_>>())
        };
        facts.access_profiles.push(AccessProfile {
            id: STATUS_PROFILE.to_owned(),
            scopes: vec![STATUS_SCOPE.to_owned()],
            purposes: Vec::new(),
            requester_clients: narrowed(&authority.status_clients),
            exchange: None,
            selected_by: BTreeMap::new(),
            // `task_status` in `registry-casework` `http.rs` admits only a
            // service's token (`authenticate_task_client`).
            actor_kind: Some(ActorKind::Service),
            required_claims: Vec::new(),
            admitted_actor_kinds: Vec::new(),
            refused_claims: Vec::new(),
        });
        facts.access_profiles.push(AccessProfile {
            id: ASSERT_PROFILE.to_owned(),
            scopes: vec![ASSERT_SCOPE.to_owned()],
            purposes: Vec::new(),
            requester_clients: narrowed(&authority.exchange_clients),
            exchange: Some(ExchangeBinding {
                assertion_issuer_id: authority_id,
                bootstrap_audience: inputs.audience.to_owned(),
                bootstrap_scope: ASSERT_SCOPE.to_owned(),
            }),
            selected_by: BTreeMap::new(),
            // `task_assertion` admits only an agent's own token, the one the
            // client bootstraps with before it exchanges the assertion.
            actor_kind: Some(ActorKind::Agent),
            required_claims: Vec::new(),
            admitted_actor_kinds: Vec::new(),
            refused_claims: Vec::new(),
        });
    }
    facts
}

/// The task authority's assertion issuer and the one exchange binding that
/// presents its assertions, when the facts declare them.
pub(crate) fn task_exchange(facts: &IdentityFacts) -> Option<(&AssertionIssuer, &AccessProfile)> {
    let profile = facts
        .access_profiles
        .iter()
        .find(|profile| profile.exchange.is_some())?;
    let binding = profile.exchange.as_ref()?;
    let issuer = facts
        .assertion_issuers
        .iter()
        .find(|issuer| issuer.id == binding.assertion_issuer_id)?;
    Some((issuer, profile))
}

/// For each client that exchanges an assertion, the assertion issuers it may
/// present, as the runtime's `authentication.oidc.assertionIssuers` writes
/// them.
pub(crate) fn assertion_issuers(facts: &IdentityFacts) -> BTreeMap<String, Vec<String>> {
    let mut paired: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for profile in &facts.access_profiles {
        let Some(binding) = &profile.exchange else {
            continue;
        };
        let Some(issuer) = facts
            .assertion_issuers
            .iter()
            .find(|issuer| issuer.id == binding.assertion_issuer_id)
        else {
            continue;
        };
        for client in profile.requester_clients.iter().flatten() {
            paired
                .entry(client.clone())
                .or_default()
                .push(issuer.issuer.clone());
        }
    }
    paired
}

/// The admission with each client listed once, in first-seen order; the facts
/// refuse a client listed twice.
fn unique(admission: Admission) -> Admission {
    match admission {
        Admission::Clients(clients) => {
            let mut seen = std::collections::BTreeSet::new();
            Admission::Clients(
                clients
                    .into_iter()
                    .filter(|client| seen.insert(client.clone()))
                    .collect(),
            )
        }
        other => other,
    }
}

/// The inputs a deployment's runtime file and project state. Reads
/// `authentication.oidc` and `taskAuthority`; opens no secret.
fn deployed(runtime: &RuntimeConfig, project: &CaseworkProject) -> IdentityFacts {
    let oidc = &runtime.authentication.oidc;
    let allowed = &oidc.clients.allowed_clients;
    let allowed_clients = if allowed.is_empty() {
        Admission::Unrestricted
    } else {
        Admission::Clients(allowed.clone())
    };
    let authority = runtime.task_authority.as_ref().map(|authority| {
        let issuer = authority.issuer.clone();
        let mut exchange_clients: BTreeSet<String> = project
            .task_templates
            .iter()
            .map(|template| template.client.clone())
            .collect();
        exchange_clients.extend(
            oidc.clients
                .assertion_issuers
                .iter()
                .filter(|(_, issuers)| issuers.contains(&issuer))
                .map(|(client, _)| client.clone()),
        );
        Authority {
            jwks_url: format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')),
            issuer,
            status_clients: authority.status_clients.keys().cloned().collect(),
            exchange_clients,
        }
    });
    let inputs = Inputs {
        issuer: oidc.provider.issuer.as_str(),
        audience: &oidc.provider.audience,
        allowed_clients,
        human_claim: &oidc.human_identity.claim,
        profiles: &project.access_profiles,
        initiator_profiles: initiator_profiles(project),
        authority,
    };
    facts(&inputs)
}

/// What `generate identity-facts` reports: the output and counts, nothing
/// the facts say.
pub(crate) fn generate(project: &Path, runtime_config: &Path, output: &Path) -> Result<Value> {
    let policy = crate::project::load_and_check_policy(project)?;
    let absolute = std::path::absolute(runtime_config).context("resolving the runtime file")?;
    let loaded = RuntimeConfig::loader().load::<RuntimeConfig>(&absolute)?;
    let runtime = loaded.config;
    if let Some(finding) = runtime.findings(Some(&policy)).into_iter().next() {
        return Err(finding.into());
    }
    if runtime.authentication.oidc.scope_claim != HOSTED_SCOPE_CLAIM {
        bail!(ProjectRefusal::ScopeClaimUnsupported);
    }
    let human = &runtime.authentication.oidc.human_identity;
    if human.claim != HOSTED_HUMAN_CLAIM || human.value != HOSTED_HUMAN_VALUE {
        bail!(ProjectRefusal::HumanIdentityUnsupported);
    }
    let facts = deployed(&runtime, &policy);
    let yaml = facts.to_yaml()?;
    // The facts must read back, so a document the generator would refuse is
    // never written.
    identity_facts::read("identity-facts", yaml.as_bytes())?;
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(ProjectRefusal::OutputExists)
        }
        Err(error) => return Err(error).context("creating the identity facts file"),
    };
    file.write_all(yaml.as_bytes())
        .context("writing the identity facts file")?;
    file.sync_all().context("writing the identity facts file")?;
    Ok(json!({
        "ok": true,
        "command": "generate-identity-facts",
        "output": output,
        "product": PRODUCT,
        "claims": facts.claims.len(),
        "accessProfiles": facts.access_profiles.len(),
        "assertionIssuers": facts.assertion_issuers.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "../../products/casework/examples/canonical-review";

    fn manifest(path: &str) -> std::path::PathBuf {
        fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
    }

    fn run(runtime: &str) -> (String, Value) {
        let directory = crate::canonical_tempdir();
        let output = directory.path().join("facts.yaml");
        let report = generate(&manifest(EXAMPLE), &manifest(runtime), &output).unwrap();
        (fs::read_to_string(output).unwrap(), report)
    }

    fn golden(name: &str, actual: &str) {
        let path = manifest("tests/fixtures/identity").join(name);
        if std::env::var_os("REGISTRY_UPDATE_GOLDEN").is_some() {
            fs::write(&path, actual).unwrap();
        }
        assert_eq!(fs::read_to_string(path).unwrap(), actual);
    }

    #[test]
    fn the_canonical_review_example_states_its_oidc_settings_and_profiles() {
        let (facts, report) =
            run("../../products/casework/examples/canonical-review/runtime.example.yaml");
        golden("facts-canonical-review.yaml", &facts);
        assert_eq!(
            report,
            json!({
                "ok": true,
                "command": "generate-identity-facts",
                "output": report["output"],
                "product": "casework",
                "claims": 1,
                "accessProfiles": 4,
                "assertionIssuers": 0,
            })
        );
    }

    #[test]
    fn the_task_authority_and_its_exchange_clients_are_stated() {
        let (facts, _) = run("tests/fixtures/identity/runtime-task-authority.yaml");
        golden("facts-task-authority.yaml", &facts);
        let read = identity_facts::read("facts", facts.as_bytes()).unwrap();
        let (issuer, profile) = task_exchange(&read).unwrap();
        // The values the local development issuer registers for its task
        // authority and the clients that exchange its assertions.
        assert_eq!(issuer.id, "casework-example-test");
        assert_eq!(
            assertion_issuer_id("https://Casework.example.test/a/b/"),
            "casework-example-test-a-b"
        );
        assert_eq!(issuer.mapping, AssertionMapping::InstitutionalGrant);
        let binding = profile.exchange.as_ref().unwrap();
        assert_eq!(binding.bootstrap_scope, "casework:grants:assert");
        assert_eq!(
            assertion_issuers(&read),
            BTreeMap::from([(
                "task-agent".to_owned(),
                vec!["https://casework.example.test".to_owned()]
            )])
        );
    }

    #[test]
    fn the_facts_name_no_path_and_no_secret() {
        let (facts, report) = run("tests/fixtures/identity/runtime-task-authority.yaml");
        for forbidden in ["secret:", "/srv/", "/run/", "/var/", "signing", "Ref"] {
            assert!(!facts.contains(forbidden), "{forbidden}");
        }
        let report = report.to_string();
        assert!(!report.contains("task-agent"));
        assert!(!report.contains("casework.example.test"));
    }

    #[test]
    fn an_existing_output_is_refused_and_left_alone() {
        let directory = crate::canonical_tempdir();
        let output = directory.path().join("facts.yaml");
        fs::write(&output, "kept").unwrap();
        let error = generate(
            &manifest(EXAMPLE),
            &manifest("tests/fixtures/identity/runtime-task-authority.yaml"),
            &output,
        )
        .unwrap_err();
        assert!(error.chain().any(|cause| cause.is::<ProjectRefusal>()));
        assert_eq!(fs::read_to_string(output).unwrap(), "kept");
    }

    #[test]
    fn profiles_the_runtime_admits_only_for_a_person_require_a_human_actor() {
        let (facts, _) =
            run("../../products/casework/examples/canonical-review/runtime.example.yaml");
        let read = identity_facts::read("facts", facts.as_bytes()).unwrap();
        let kinds: BTreeMap<_, _> = read
            .access_profiles
            .iter()
            .map(|profile| (profile.id.as_str(), profile.actor_kind))
            .collect();
        assert_eq!(
            kinds,
            BTreeMap::from([
                ("administrator", Some(ActorKind::Human)),
                ("requester", None),
                ("staff", Some(ActorKind::Human)),
                ("supervisor", Some(ActorKind::Human)),
            ])
        );
    }

    /// `task_status` and `task_assertion` in `registry-casework` `http.rs`
    /// admit a token through `authenticate_task_client`, which refuses any
    /// actor kind but the one each pins.
    #[test]
    fn the_task_profiles_require_the_actor_kind_their_endpoints_pin() {
        let (facts, _) = run("tests/fixtures/identity/runtime-task-authority.yaml");
        let read = identity_facts::read("facts", facts.as_bytes()).unwrap();
        let kinds: BTreeMap<_, _> = read
            .access_profiles
            .iter()
            .map(|profile| (profile.id.as_str(), profile.actor_kind))
            .collect();
        assert_eq!(kinds["task-status"], Some(ActorKind::Service));
        assert_eq!(kinds["task-assert"], Some(ActorKind::Agent));
    }

    #[test]
    fn a_requester_profile_that_initiates_reviews_requires_a_human_actor() {
        let mut project = crate::project::load_and_check_policy(&manifest(EXAMPLE)).unwrap();
        project.trusted_producers[1].initiator_profile = Some("requester".to_owned());
        let facts = facts(&Inputs {
            issuer: "https://identity.example.test",
            audience: "urn:example:casework",
            allowed_clients: Admission::Unrestricted,
            human_claim: "registry_actor_kind",
            profiles: &project.access_profiles,
            initiator_profiles: initiator_profiles(&project),
            authority: None,
        });
        let requester = facts
            .access_profiles
            .iter()
            .find(|profile| profile.id == "requester")
            .unwrap();
        assert_eq!(requester.actor_kind, Some(ActorKind::Human));
    }

    #[test]
    fn a_profile_whose_principal_is_a_named_claim_requires_it_on_every_token() {
        let mut project = crate::project::load_and_check_policy(&manifest(EXAMPLE)).unwrap();
        let staff = project
            .access_profiles
            .iter_mut()
            .find(|profile| profile.id == "staff")
            .unwrap();
        staff.principal_claim = "casework_officer".to_owned();
        let facts = facts(&Inputs {
            issuer: "https://identity.example.test",
            audience: "urn:example:casework",
            allowed_clients: Admission::Unrestricted,
            human_claim: "registry_actor_kind",
            profiles: &project.access_profiles,
            initiator_profiles: initiator_profiles(&project),
            authority: None,
        });
        let required: BTreeMap<_, _> = facts
            .access_profiles
            .iter()
            .map(|profile| (profile.id.as_str(), profile.required_claims.clone()))
            .collect();
        assert_eq!(required["staff"], ["casework_officer"]);
        // A profile read by subject requires nothing beyond the subject.
        assert!(required["supervisor"].is_empty());
        let yaml = facts.to_yaml().unwrap();
        identity_facts::read("facts", yaml.as_bytes()).unwrap();
    }

    #[test]
    fn a_customized_human_identity_is_refused_because_hosted_users_carry_the_actor_kind() {
        let directory = crate::canonical_tempdir();
        let runtime = directory.path().join("runtime.yaml");
        let source = fs::read_to_string(manifest(
            "tests/fixtures/identity/runtime-task-authority.yaml",
        ))
        .unwrap();
        let original = "      claim: registry_actor_kind\n      value: human\n";
        assert!(source.contains(original));
        for (index, replacement) in [
            "      claim: person_kind\n      value: human\n",
            "      claim: registry_actor_kind\n      value: person\n",
        ]
        .into_iter()
        .enumerate()
        {
            fs::write(&runtime, source.replace(original, replacement)).unwrap();
            let output = directory.path().join(format!("{index}.yaml"));
            let error = generate(&manifest(EXAMPLE), &runtime, &output).unwrap_err();
            assert!(
                error.to_string().contains("humanIdentity")
                    && error
                        .to_string()
                        .contains("hosted generation does not support"),
                "{error}"
            );
            assert!(!output.exists());
        }
    }

    #[test]
    fn a_customized_scope_claim_is_refused_because_hosted_tokens_carry_scope() {
        let directory = crate::canonical_tempdir();
        let runtime = directory.path().join("runtime.yaml");
        let source = fs::read_to_string(manifest(
            "tests/fixtures/identity/runtime-task-authority.yaml",
        ))
        .unwrap();
        assert!(source.contains("scopeClaim: scope\n"));
        for claim in ["custom_scopes", "registry_scopes"] {
            fs::write(
                &runtime,
                source.replace("scopeClaim: scope\n", &format!("scopeClaim: {claim}\n")),
            )
            .unwrap();
            let output = directory.path().join(format!("{claim}.yaml"));
            let error = generate(&manifest(EXAMPLE), &runtime, &output).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("hosted generation does not support"),
                "{error}"
            );
            assert!(!output.exists());
        }
    }
}
