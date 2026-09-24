// SPDX-License-Identifier: Apache-2.0
//! `bregctl module add consent`: the generated consent module is written into
//! the project, pinned, and compiles once a profile requires consent, and every
//! refusal leaves the project exactly as it was.

use super::*;

/// A project with recipients, a purpose vocabulary, and a subject entity, but
/// no consent module yet. `food-targeting` is the profile an adopter gates.
const BASE_PROJECT: &str = r#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: consent-generator
  version: 0.1.0
  defaultLanguage: en
  canonicalBaseIri: https://consent-generator.example.test
recipients:
  organizations:
  - id: food-agency
    name: Food Agency
    contact: dpo@food-agency.example.test
    clients: [food-agency-portal]
  - id: health-ngo
    name: Health NGO
    contact: privacy@health-ngo.example.test
    clients: [health-ngo-portal]
  groups:
  - id: referral-network
    name: Referral network
    members: [food-agency, health-ngo]
vocabularies:
# Purposes the registry discloses data for.
- id: data-use-purpose
  values: [food-assistance, health-referral]

entities:
- id: person
  primaryDataset: people
  route: persons
  mutationMode: mutable
  classification: restricted
  fields:
  - {id: given-name, type: string, maxLength: 80, required: true, classification: restricted}
  - {id: district, type: string, maxLength: 80, required: true, classification: internal}
- id: household
  primaryDataset: people
  route: households
  mutationMode: mutable
  classification: internal
  fields:
  - {id: head, type: reference, target: person, required: true, classification: restricted}
  - {id: label, type: string, maxLength: 80, required: true, classification: internal}
accessProfiles:
- id: food-targeting
  default: true
  principalClaim: principal
  actorKind: service
  requesterClients: [food-agency-portal, health-ngo-portal]
  requiredScopes: [records:read]
  requiredPurposes: [food-assistance]
  permissions:
  - entity: person
    rowBoundaries: []
    operations: [get, list]
    readableFields: [given-name, district]
  - entity: household
    rowBoundaries: []
    operations: [get, list]
    readableFields: [head, label]
- id: registrar
  principalClaim: principal
  actorKind: human
  requesterClients: [registrar-console]
  requiredScopes: [records:manage]
  permissions:
  - entity: person
    rowBoundaries: []
    operations: [create, get, patch]
    readableFields: [given-name, district]
    writableFields: [given-name, district]
  - entity: household
    rowBoundaries: []
    operations: [create, get, patch]
    readableFields: [head, label]
    writableFields: [head, label]
"#;

/// The permission line the report tells the adopter to add, inserted after the
/// named `readableFields` line of the gated profile.
fn require_consent(source: &str, readable_fields: &str, requirement: &str) -> String {
    let anchor = format!("    readableFields: [{readable_fields}]\n");
    let (before, after) = source
        .split_once(&anchor)
        .expect("the gated permission is present");
    format!("{before}{anchor}    requireConsent:\n    - {requirement}\n{after}")
}

fn module_add(project: &Path, subject: &str) -> Output {
    bregctl(&[
        "--format",
        "json",
        "module",
        "add",
        "consent",
        "--subject",
        subject,
        path(project),
    ])
}

fn registry_source(project: &Path) -> String {
    fs::read_to_string(project.join("registry.yaml")).expect("registry.yaml reads")
}

fn finding_codes(report: &Value) -> Vec<(String, String)> {
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|finding| {
            (
                finding["code"].as_str().expect("code").to_owned(),
                finding["path"].as_str().expect("path").to_owned(),
            )
        })
        .collect()
}

/// The registry-wide findings a steward-issued consent action and the steward
/// profile carry by design: staff act for any subject, and the audit plus the
/// revision history are the control.
fn expected_steward_findings(subject: &str) -> Vec<(String, String)> {
    let mut expected = Vec::new();
    for (profile, action, targets) in [
        (
            format!("{subject}-consent-assisted-capture"),
            format!("record-{subject}-consent-assisted"),
            vec![subject.to_owned(), format!("{subject}-consent-decision")],
        ),
        (
            format!("{subject}-consent-steward"),
            format!("invalidate-{subject}-consent"),
            vec![subject.to_owned(), format!("{subject}-consent-decision")],
        ),
        (
            format!("{subject}-consent-steward"),
            format!("import-{subject}-consent"),
            vec![subject.to_owned(), format!("{subject}-consent-decision")],
        ),
    ] {
        for target in targets {
            expected.push((
                "access.target.unrestricted_rows".to_owned(),
                format!(
                    "actions[id={action}].permissions[profile={profile}].targets[entity={target}].rowBoundaries"
                ),
            ));
        }
    }
    expected
}

fn module_findings(report: &Value, subject: &str) -> Vec<(String, String)> {
    let mut findings = finding_codes(report)
        .into_iter()
        .filter(|(_, path)| path.contains(&format!("{subject}-consent")))
        .filter(|(code, _)| code == "access.target.unrestricted_rows")
        .collect::<Vec<_>>();
    findings.sort();
    findings
}

#[test]
fn module_add_consent_writes_pins_and_compiles_once_a_profile_requires_consent() {
    let project = TestProject::from_registry_source(BASE_PROJECT.as_bytes());

    let added = module_add(project.path(), "person");

    assert!(added.status.success(), "{added:?}");
    let report = json_stdout(&added);
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "module add consent");
    let explanation = &report["explanation"];
    assert_eq!(explanation["subject"], "person");
    assert_eq!(explanation["module"], "consent-person");
    assert_eq!(
        explanation["entities"],
        json!([
            "person-privacy-notice",
            "person-notice-clause",
            "person-consent-link",
            "person-consent-decision"
        ])
    );
    assert_eq!(
        explanation["actions"],
        json!([
            "give-person-consent",
            "refuse-person-consent",
            "withdraw-person-consent",
            "record-person-consent-assisted",
            "invalidate-person-consent",
            "import-person-consent"
        ])
    );
    assert_eq!(
        explanation["accessProfiles"],
        json!([
            "person-consent-self",
            "person-consent-assisted-capture",
            "person-consent-steward",
            "person-consent-link-steward",
            "person-consent-recipient"
        ])
    );
    assert_eq!(
        explanation["vocabularies"],
        json!({
            "added": ["consent-decision", "consent-channel", "consent-invalidation-reason"],
            "reused": ["data-use-purpose"]
        })
    );
    assert_eq!(
        explanation["requireConsent"],
        json!([
            {"entity": "person", "line": "{record: person-consent-decision, on: id}"},
            {"entity": "household", "line": "{record: person-consent-decision, on: head}"}
        ])
    );
    // No profile requires consent yet, so the synthesized scope vocabulary the
    // decision entity binds does not exist and the project cannot compile.
    assert_eq!(explanation["compiles"], false);
    assert!(report.get("revision").is_none(), "{report}");
    let steps = report["nextSteps"].as_array().expect("next steps");
    assert!(
        steps.iter().any(|step| step
            .as_str()
            .unwrap()
            .contains("requireConsent: [{record: person-consent-decision, on: id}]")),
        "{steps:?}"
    );
    assert_eq!(
        report["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|artifact| artifact["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["modules/consent-person/module.yaml", "registry.yaml"]
    );

    let module_source = fs::read(project.path().join("modules/consent-person/module.yaml"))
        .expect("the module is written");
    let module = parse_module_yaml(&module_source).expect("the module parses");
    let source = registry_source(project.path());
    let parsed = parse_project_yaml(source.as_bytes()).expect("the project parses");
    assert_eq!(parsed.modules.len(), 1);
    assert_eq!(parsed.modules[0].id, "consent-person");
    assert_eq!(
        parsed.modules[0].digest.as_deref(),
        Some(module_digest(&module).as_str())
    );
    // The author's comment above the purpose vocabulary survives the edit.
    assert!(source.contains("# Purposes the registry discloses data for.\n"));
    for profile in [
        "person-consent-self",
        "person-consent-assisted-capture",
        "person-consent-steward",
        "person-consent-link-steward",
        "person-consent-recipient",
    ] {
        assert!(
            parsed
                .access_profiles
                .iter()
                .any(|candidate| candidate.id == profile),
            "{profile} is appended"
        );
    }

    let gated = require_consent(
        &source,
        "given-name, district",
        "{record: person-consent-decision, on: id}",
    );
    let gated = gated.replacen(
        "  - entity: household\n    rowBoundaries: []\n    operations: [get, list]\n    readableFields: [head, label]\n",
        "  - entity: household\n    rowBoundaries: []\n    operations: [get, list]\n    readableFields: [head, label]\n    requireConsent:\n    - {record: person-consent-decision, on: head}\n",
        1,
    );
    fs::write(project.path().join("registry.yaml"), gated).expect("gated project writes");

    let checked = bregctl(&["--format", "json", "check", path(project.path())]);

    assert!(checked.status.success(), "{checked:?}");
    let report = json_stdout(&checked);
    let codes = finding_codes(&report);
    assert!(
        codes
            .iter()
            .all(|(code, _)| !code.starts_with("access.consent.")),
        "{codes:?}"
    );
    // A self-issued action is bound to its subject through the principal link,
    // so none of its targets is a registry-wide finding.
    assert!(
        codes.iter().all(|(_, path)| ["give", "refuse", "withdraw"]
            .iter()
            .all(|verb| !path.contains(&format!("actions[id={verb}-")))),
        "{codes:?}"
    );
    let mut expected = expected_steward_findings("person");
    expected.sort();
    assert_eq!(module_findings(&report, "person"), expected);
}

#[test]
fn module_add_consent_refuses_a_subject_already_generated_without_writing() {
    let project = TestProject::from_registry_source(BASE_PROJECT.as_bytes());
    let first = module_add(project.path(), "person");
    assert!(first.status.success(), "{first:?}");
    let before = registry_source(project.path());

    let second = module_add(project.path(), "person");

    assert!(!second.status.success(), "{second:?}");
    let report = json_stdout(&second);
    assert_eq!(report["ok"], false);
    assert_eq!(report["diagnostics"][0]["code"], "module.consent.present");
    assert_eq!(registry_source(project.path()), before);
}

#[test]
fn module_add_consent_refuses_an_incomplete_project_without_writing() {
    let no_recipients = {
        let (head, tail) = BASE_PROJECT.split_once("recipients:\n").unwrap();
        let (_, rest) = tail.split_once("vocabularies:\n").unwrap();
        format!("{head}vocabularies:\n{rest}")
    };
    let no_purposes = BASE_PROJECT.replace("- id: data-use-purpose\n", "- id: other-purpose\n");
    for (source, subject, code) in [
        (
            BASE_PROJECT.to_owned(),
            "citizen",
            "module.consent.subject_unknown",
        ),
        (
            BASE_PROJECT.to_owned(),
            "Person",
            "module.consent.subject_unknown",
        ),
        (no_recipients, "person", "module.consent.recipients_missing"),
        (no_purposes, "person", "module.consent.purposes_missing"),
    ] {
        let project = TestProject::from_registry_source(source.as_bytes());

        let refused = module_add(project.path(), subject);

        assert!(!refused.status.success(), "{subject}: {refused:?}");
        let report = json_stdout(&refused);
        assert_eq!(report["diagnostics"][0]["code"], code, "{report}");
        assert_eq!(registry_source(project.path()), source);
        assert!(!project.path().join("modules").exists());
    }
}

#[test]
fn module_add_consent_refuses_a_flow_style_profile_list_it_cannot_extend() {
    let source = BASE_PROJECT.replace(
        "accessProfiles:\n- id: food-targeting",
        "accessProfiles: [{id: other, principalClaim: principal, requiredScopes: ['records:other'], permissions: []}]\nretired:\n- id: food-targeting",
    );
    let (kept, _) = source.split_once("retired:\n").unwrap();
    let project = TestProject::from_registry_source(kept.as_bytes());

    let refused = module_add(project.path(), "person");

    assert!(!refused.status.success(), "{refused:?}");
    assert_eq!(
        json_stdout(&refused)["diagnostics"][0]["code"],
        "module.consent.render_failed"
    );
    assert_eq!(registry_source(project.path()), kept);
    assert!(!project.path().join("modules").exists());
}

/// Two subject types yield two consent modules, and the project-level
/// vocabularies the first run added are reused by the second. The indented
/// block style the product fixtures use is extended in the same style.
#[test]
fn module_add_consent_runs_once_per_subject_and_reuses_shared_vocabularies() {
    let indented = BASE_PROJECT
        .replace(
            "\n- id: data-use-purpose\n  values:",
            "\n  - id: data-use-purpose\n    values:",
        )
        .replace(
            "principalClaim: principal",
            "principalClaim: registry_principal",
        );
    let project = TestProject::from_registry_source(indented.as_bytes());

    let person = module_add(project.path(), "person");
    assert!(person.status.success(), "{person:?}");
    let household = module_add(project.path(), "household");

    assert!(household.status.success(), "{household:?}");
    let report = json_stdout(&household);
    assert_eq!(
        report["explanation"]["vocabularies"],
        json!({
            "added": [],
            "reused": ["data-use-purpose", "consent-decision", "consent-channel", "consent-invalidation-reason"]
        })
    );
    assert_eq!(
        report["explanation"]["requireConsent"],
        json!([{"entity": "household", "line": "{record: household-consent-decision, on: id}"}])
    );
    let source = registry_source(project.path());
    assert!(
        source.contains("\n  - id: consent-channel\n"),
        "the vocabulary item keeps the block's indentation:\n{source}"
    );
    let parsed = parse_project_yaml(source.as_bytes()).expect("the project parses");
    assert_eq!(
        parsed
            .modules
            .iter()
            .map(|lock| lock.id.as_str())
            .collect::<Vec<_>>(),
        ["consent-household", "consent-person"]
    );
    let self_profile = parsed
        .access_profiles
        .iter()
        .find(|profile| profile.id == "household-consent-self")
        .expect("the self profile is appended");
    assert_eq!(
        self_profile.principal_claim.as_deref(),
        Some("registry_principal")
    );

    let gated = require_consent(
        &source,
        "given-name, district",
        "{record: person-consent-decision, on: id}",
    );
    let gated = require_consent(
        &gated,
        "head, label",
        "{record: household-consent-decision, on: id}",
    );
    fs::write(project.path().join("registry.yaml"), gated).expect("gated project writes");

    let checked = bregctl(&["--format", "json", "check", path(project.path())]);

    assert!(checked.status.success(), "{checked:?}");
    let report = json_stdout(&checked);
    for subject in ["person", "household"] {
        let mut expected = expected_steward_findings(subject);
        expected.sort();
        assert_eq!(module_findings(&report, subject), expected, "{subject}");
    }
    assert!(finding_codes(&report)
        .iter()
        .all(|(code, _)| !code.starts_with("access.consent.")));
}
