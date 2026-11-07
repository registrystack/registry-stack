#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]

//! `evidencectl generate identity-facts` writes the identity facts of a
//! deployment from its target, authority and client registrations.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/examples/standalone")
}

fn evidencectl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("run evidencectl")
}

fn generate(project: &Path, output: &Path) -> Output {
    evidencectl(&[
        "--format",
        "json",
        "generate",
        "identity-facts",
        &project.to_string_lossy(),
        "--target",
        &project.join("local-target.yaml").to_string_lossy(),
        "--output",
        &output.to_string_lossy(),
    ])
}

fn report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).expect("json report")
}

fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/identity")
        .join(name);
    if std::env::var_os("REGISTRY_UPDATE_GOLDEN").is_some() {
        fs::write(&path, actual).unwrap();
    }
    assert_eq!(fs::read_to_string(path).unwrap(), actual);
}

/// Copies the example's authored files, assets included.
fn copy_project(into: &Path) {
    fn copy(from: &Path, to: &Path) {
        for entry in fs::read_dir(from).expect("example directory") {
            let entry = entry.unwrap();
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            let target = to.join(&name);
            if entry.file_type().unwrap().is_dir() {
                fs::create_dir_all(&target).unwrap();
                copy(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("example file");
            }
        }
    }
    copy(&example(), into);
}

#[test]
fn the_standalone_example_states_its_oidc_settings_and_profile() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("facts.yaml");
    let reported = report(&generate(&example(), &output));
    assert_eq!(reported["command"], "generate identity-facts");
    assert_eq!(reported["output"], output.to_string_lossy().as_ref());
    assert_eq!(reported["product"], "evidence");
    assert_eq!(reported["claims"], 3);
    assert_eq!(reported["accessProfiles"], 1);
    assert_eq!(reported["assertionIssuers"], 0);
    let facts = fs::read_to_string(&output).unwrap();
    golden("facts-standalone.yaml", &facts);
    assert!(!facts.contains(&directory.path().to_string_lossy().to_string()));
    assert!(!facts.contains("secret:"));
}

#[test]
fn a_named_principal_claim_is_declared_and_required_on_every_token() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    fs::create_dir(&project).unwrap();
    copy_project(&project);
    let target = project.join("local-target.yaml");
    let text = fs::read_to_string(&target).unwrap();
    assert!(text.contains("    principalClaim: sub\n"));
    fs::write(
        &target,
        text.replace(
            "    principalClaim: sub\n",
            "    principalClaim: requester_id\n",
        ),
    )
    .unwrap();
    let output = directory.path().join("facts.yaml");
    let reported = report(&generate(&project, &output));
    assert_eq!(reported["claims"], 4);
    let facts = fs::read_to_string(&output).unwrap();
    assert!(facts.contains("  requester_id: string\n"), "{facts}");
    assert!(
        facts.ends_with(
            "  requiredClaims:\n  - evidence_audience\n  - evidence_tags\n  - registry_actor_kind\n  - requester_id\n"
        ),
        "{facts}"
    );
}

/// Evidence reads the actor kind and the task grant from the claims its
/// target names, but the issuer writes them under the platform names only:
/// a renamed claim would leave every token without the claim Evidence reads.
#[test]
fn a_renamed_contextual_claim_is_refused() {
    for (member, renamed) in [
        ("actorKind", "actor_type"),
        ("purpose", "use_purpose"),
        ("grantId", "task_grant_id"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        fs::create_dir(&project).unwrap();
        copy_project(&project);
        let target = project.join("local-target.yaml");
        let text = fs::read_to_string(&target).unwrap();
        assert!(text.contains("    principalClaim: sub\n"));
        fs::write(
            &target,
            text.replace(
                "    principalClaim: sub\n",
                &format!("    principalClaim: sub\n    claims:\n      {member}: {renamed}\n"),
            ),
        )
        .unwrap();
        let output = directory.path().join("facts.yaml");
        let refused = generate(&project, &output);
        let stdout = String::from_utf8_lossy(&refused.stdout);
        assert!(!refused.status.success(), "{member}: {stdout}");
        assert!(
            stdout.contains("evidence.generate-identity-facts.claim-name-unsupported"),
            "{member}: {stdout}"
        );
        assert!(
            stdout.contains(&format!("authentication.oidc.claims.{member}")),
            "{stdout}"
        );
        assert!(
            !stdout.contains(renamed),
            "names no authored value: {stdout}"
        );
        assert!(!output.exists(), "a refused generate writes nothing");
    }
}

/// A claims block that names the platform defaults changes nothing.
#[test]
fn a_contextual_claim_named_as_the_default_is_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    fs::create_dir(&project).unwrap();
    copy_project(&project);
    let target = project.join("local-target.yaml");
    let text = fs::read_to_string(&target).unwrap();
    fs::write(
        &target,
        text.replace(
            "    principalClaim: sub\n",
            "    principalClaim: sub\n    claims:\n      actorKind: registry_actor_kind\n      grantId: registry_grant_id\n",
        ),
    )
    .unwrap();
    let output = directory.path().join("facts.yaml");
    report(&generate(&project, &output));
    let unchanged = directory.path().join("unchanged.yaml");
    report(&generate(&example(), &unchanged));
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        fs::read_to_string(&unchanged).unwrap()
    );
}

#[test]
fn an_existing_output_is_refused_and_left_alone() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("facts.yaml");
    fs::write(&output, "keep").unwrap();
    let refused = generate(&example(), &output);
    assert!(!refused.status.success());
    assert_eq!(fs::read_to_string(&output).unwrap(), "keep");
}

/// A project whose only profile is reached by presenting a task authority's
/// assertion, with one client registered for the exchange.
fn task_grant_project(project: &Path, bootstrap_resource: Option<&str>) {
    copy_project(project);
    // The example's own caller registers the profile this replaces.
    fs::remove_file(project.join("access/clients/example-caller.yaml")).unwrap();
    let config_path = project.join("evidence.yaml");
    let mut config: Value = serde_norway::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    config["assertionDefinitions"]["adult-status"]["grantCeiling"]["actorKinds"] =
        serde_json::json!(["agent"]);
    config["assertionDefinitions"]["adult-status"]["grantCeiling"]["valueOrigins"] =
        serde_json::json!(["authenticated-grant"]);
    fs::write(config_path, serde_norway::to_string(&config).unwrap()).unwrap();

    let authority_path = project.join("dev-authority.yaml");
    let mut authority: Value =
        serde_norway::from_slice(&fs::read(&authority_path).unwrap()).unwrap();
    let mut profile = authority["accessProfiles"]["standalone-service"].clone();
    profile["actorKind"] = serde_json::json!("agent");
    profile["requesterTags"] = serde_json::json!(["age-checks"]);
    profile["requesterClients"] = serde_json::json!(["task-checker"]);
    profile["grantSourceIssuer"] = serde_json::json!("https://casework.example.test");
    profile["grants"] = Value::Array(vec![profile["grants"][0].clone()]);
    profile["grants"][0]["subjects"][0]["valueOrigin"] = serde_json::json!("authenticated-grant");
    profile["grants"][0]["subjects"][0]["valueClaims"] =
        serde_json::json!({"record-id":"grant.record_id"});
    authority["accessProfiles"] = serde_json::json!({"age-checks": profile});
    fs::write(authority_path, serde_norway::to_string(&authority).unwrap()).unwrap();

    let mut arguments = vec![
        "access",
        "client",
        "add",
        "task-checker",
        "--access-profile",
        "age-checks",
        "--generate-local-key",
        "--grant-bootstrap-scope",
        "casework:grants:assert",
    ];
    if let Some(resource) = &bootstrap_resource {
        arguments.extend(["--grant-bootstrap-resource", resource]);
    }
    let project_argument = project.to_string_lossy();
    arguments.extend(["--project", &project_argument]);
    let added = evidencectl(&arguments);
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
}

#[test]
fn a_task_grant_profile_states_its_exchange_and_assertion_issuer() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    fs::create_dir(&project).unwrap();
    task_grant_project(&project, Some("urn:example:resource:casework"));
    let output = directory.path().join("facts.yaml");
    let reported = report(&generate(&project, &output));
    assert_eq!(reported["accessProfiles"], 1);
    assert_eq!(reported["assertionIssuers"], 1);
    let facts = fs::read_to_string(&output).unwrap();
    golden("facts-task-grant.yaml", &facts);
    // The id is the one Casework derives for the same authority.
    assert!(facts.contains("casework-example-test"));
    assert!(!facts.contains(&directory.path().to_string_lossy().to_string()));
}

#[test]
fn an_exchange_client_without_a_bootstrap_resource_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    fs::create_dir(&project).unwrap();
    task_grant_project(&project, None);
    let output = directory.path().join("facts.yaml");
    let refused = generate(&project, &output);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("--grant-bootstrap-resource"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(!output.exists(), "a refused generate writes nothing");
}

#[test]
fn each_profile_states_the_actor_kind_and_tags_that_select_it() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    fs::create_dir(&project).unwrap();
    copy_project(&project);
    fs::remove_file(project.join("access/clients/example-caller.yaml")).unwrap();
    let authority_path = project.join("dev-authority.yaml");
    let mut authority: Value =
        serde_norway::from_slice(&fs::read(&authority_path).unwrap()).unwrap();
    let mut second = authority["accessProfiles"]["standalone-service"].clone();
    second["requesterTags"] = serde_json::json!(["second-tag", "extra-tag"]);
    second["grants"] = Value::Array(vec![second["grants"][0].clone()]);
    authority["accessProfiles"]["second-service"] = second;
    fs::write(authority_path, serde_norway::to_string(&authority).unwrap()).unwrap();
    let output = directory.path().join("facts.yaml");
    report(&generate(&project, &output));
    let facts: Value = serde_norway::from_slice(&fs::read(&output).unwrap()).unwrap();
    let profiles: std::collections::BTreeMap<_, _> = facts["accessProfiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|profile| {
            (
                profile["id"].as_str().unwrap().to_owned(),
                profile["selectedBy"].clone(),
            )
        })
        .collect();
    assert_eq!(
        profiles["standalone-service"],
        serde_json::json!({"registry_actor_kind":["service"],"evidence_tags":["standalone-service"]})
    );
    assert_eq!(
        profiles["second-service"],
        serde_json::json!({"registry_actor_kind":["service"],"evidence_tags":["second-tag","extra-tag"]})
    );
}

/// The identity generator decides which profiles a client's claims select with
/// `selects`, over the `selectedBy` these facts state, and refuses a grant
/// whose `admittedActorKinds` leaves out the client's kind. Evidence decides
/// at runtime with its own profile filter. For the client's own token the two
/// decisions agree exactly, so a granted profile is never reported as
/// unreachable when Evidence would serve it, and never passed when Evidence
/// would refuse it. An exchanged token carries a task grant the facts cannot
/// state: there the generator's selection only has to cover the runtime's.
#[test]
fn the_generators_selection_covers_every_profile_the_runtime_selects() {
    use registry_thunderid_tooling::identity_generate::selects;
    use std::collections::BTreeMap;

    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    fs::create_dir(&project).unwrap();
    copy_project(&project);
    fs::remove_file(project.join("access/clients/example-caller.yaml")).unwrap();
    let authority_path = project.join("dev-authority.yaml");
    let mut authority: Value =
        serde_norway::from_slice(&fs::read(&authority_path).unwrap()).unwrap();
    let template = authority["accessProfiles"]["standalone-service"].clone();
    let mut profiles = serde_json::Map::new();
    for (id, tags, kind) in [
        ("one-tag", vec!["a"], Some("service")),
        ("two-tags", vec!["a", "b"], Some("service")),
        ("any-actor", vec!["a"], None),
    ] {
        let mut profile = template.clone();
        profile["requesterTags"] = serde_json::json!(tags);
        match kind {
            Some(kind) => profile["actorKind"] = serde_json::json!(kind),
            None => {
                profile.as_object_mut().unwrap().remove("actorKind");
            }
        }
        profiles.insert(id.to_owned(), profile);
    }
    authority["accessProfiles"] = Value::Object(profiles);
    fs::write(authority_path, serde_norway::to_string(&authority).unwrap()).unwrap();
    let output = directory.path().join("facts.yaml");
    report(&generate(&project, &output));
    let facts: Value = serde_norway::from_slice(&fs::read(&output).unwrap()).unwrap();

    let mut selected_runtime = 0;
    let mut refused_by_kind = 0;
    for profile in facts["accessProfiles"].as_array().unwrap() {
        let id = profile["id"].as_str().unwrap();
        let selected_by: BTreeMap<String, Vec<String>> =
            serde_json::from_value(profile["selectedBy"].clone()).unwrap_or_default();
        let admitted: Vec<String> =
            serde_json::from_value(profile["admittedActorKinds"].clone()).unwrap_or_default();
        // The runtime reads the same profile from the authority document.
        let authored = &authority["accessProfiles"][id];
        let runtime_profile: registry_evidence::config::AuthorityProfile =
            serde_json::from_value(serde_json::json!({
                "kind": authored["authority"],
                "actorKind": authored.get("actorKind").cloned().unwrap_or(Value::Null),
                "requesterTags": authored["requesterTags"],
                "grants": [],
            }))
            .unwrap();
        for actor in ["human", "agent", "service"] {
            for tags in [
                vec![],
                vec!["a"],
                vec!["b"],
                vec!["a", "b"],
                vec!["a", "b", "c"],
            ] {
                for has_task_grant in [false, true] {
                    let claims = BTreeMap::from([
                        ("registry_actor_kind".to_owned(), serde_json::json!(actor)),
                        ("evidence_tags".to_owned(), serde_json::json!(tags)),
                    ]);
                    let runtime = registry_evidence::selector::authority_selected_by_principal(
                        &runtime_profile,
                        serde_json::from_value(serde_json::json!(actor)).unwrap(),
                        has_task_grant,
                        &tags.iter().map(|tag| (*tag).to_owned()).collect::<Vec<_>>(),
                    );
                    let selected = selects(&selected_by, &claims);
                    if has_task_grant {
                        assert!(
                            !runtime || selected,
                            "{id}: the runtime selects {actor} with {tags:?} and a task grant but the generator does not"
                        );
                    } else {
                        let admits =
                            admitted.is_empty() || admitted.iter().any(|kind| kind == actor);
                        assert_eq!(
                            selected && admits,
                            runtime,
                            "{id}: {actor} with {tags:?}: the generator and the runtime disagree"
                        );
                        refused_by_kind += usize::from(selected && !admits);
                    }
                    selected_runtime += usize::from(runtime);
                }
            }
        }
    }
    assert!(selected_runtime > 0, "the property is not vacuous");
    // An agent's own token reaches only the profiles that name agents, which
    // the facts state as the kinds the other profiles admit.
    assert!(refused_by_kind > 0, "the admitted kinds are exercised");
}

/// Evidence serves a token that names an acting person or agent only from a
/// delegated authority: every other profile refuses a token carrying the
/// target's actor claim, so the facts state that claim as refused there. The
/// unit tests cover a delegated profile, which the example's definitions do
/// not admit.
#[test]
fn a_profile_that_is_not_delegated_refuses_the_actor_claim() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    fs::create_dir(&project).unwrap();
    copy_project(&project);
    let target = project.join("local-target.yaml");
    let text = fs::read_to_string(&target).unwrap();
    assert!(text.contains("    principalClaim: sub\n"));
    fs::write(
        &target,
        text.replace(
            "    principalClaim: sub\n",
            "    principalClaim: sub\n    actorClaim: evidence_actor\n",
        ),
    )
    .unwrap();
    let output = directory.path().join("facts.yaml");
    report(&generate(&project, &output));
    let facts: Value = serde_norway::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(facts["claims"]["evidence_actor"], "string");
    assert_eq!(
        facts["accessProfiles"][0]["refusedClaims"],
        serde_json::json!(["evidence_actor"])
    );
}

/// An agent's own token reaches only the profiles that name agents: a
/// profile that names no kind admits humans and services, and the facts say
/// so, so the generator refuses to grant it to an agent.
#[test]
fn a_profile_that_names_no_kind_admits_humans_and_services() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    fs::create_dir(&project).unwrap();
    copy_project(&project);
    let authority_path = project.join("dev-authority.yaml");
    let mut authority: Value =
        serde_norway::from_slice(&fs::read(&authority_path).unwrap()).unwrap();
    authority["accessProfiles"]["standalone-service"]
        .as_object_mut()
        .unwrap()
        .remove("actorKind");
    fs::write(
        &authority_path,
        serde_norway::to_string(&authority).unwrap(),
    )
    .unwrap();
    let output = directory.path().join("facts.yaml");
    report(&generate(&project, &output));
    let facts: Value = serde_norway::from_slice(&fs::read(&output).unwrap()).unwrap();
    let profile = &facts["accessProfiles"][0];
    assert_eq!(
        profile["admittedActorKinds"],
        serde_json::json!(["human", "service"])
    );
    assert!(profile["selectedBy"].get("registry_actor_kind").is_none());
}
