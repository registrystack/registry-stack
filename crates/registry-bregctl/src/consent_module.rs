// SPDX-License-Identifier: Apache-2.0
//! `module add consent --subject <ENTITY>`: write the consent module for one
//! subject entity into an authoring project.
//!
//! The module is configuration only: a privacy notice, its clauses, the
//! principal link of a subject, and the create-only consent decision entity
//! that declares `consentRecord`, with the self-issued and steward-issued
//! actions over it. The project-level parts a module cannot carry, the shared
//! vocabularies and the access profiles, are appended to `registry.yaml`, and
//! the module is pinned in `modules`. Every name carries the subject, so a
//! registry with two subject types runs the command twice.
//!
//! Nothing is written unless the edited project parses to exactly the
//! authored document plus the appended items, and compiles. A project whose
//! profiles do not require consent yet has no `registry-consent-scopes`
//! vocabulary, so that one compile adds a retired scope in memory only; the
//! report then says the project compiles once a profile requires consent.

use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;

use registry_breg::compiler::module_digest_with_assets;
use registry_breg::contract::{FieldTypeSource, ModuleLockSource};
use registry_breg::{parse_module_yaml, parse_project_yaml, Diagnostic};
use serde_json::{json, Value};

use crate::safe_path::{SafeDir, SafePathError};
use crate::{
    artifact_report, capture_project_source, compile_captured_project, compiler_findings,
    diagnostic, first_diagnostic, render_project_module_locks, tool_diagnostic,
    validate_project_directory, write_project_registry, yaml_string, CapturedModuleSource,
    CapturedProjectSource, DiagnosticArtifact, FailureReport, ProfileArg, SuccessReport,
    SuggestedAction,
};

pub(crate) const COMMAND: &str = "module add consent";

const MODULE_TEMPLATE: &str = include_str!("consent_module/module.yaml");
const PROFILES_TEMPLATE: &str = include_str!("consent_module/profiles.yaml");
const SUBJECT_TOKEN: &str = "__SUBJECT__";
const CLAIM_TOKEN: &str = "__CLAIM__";

/// The purpose vocabulary the generated entities bind. Purposes are a
/// governance decision, so the command reuses the adopter's and never invents
/// one.
const PURPOSE_VOCABULARY: &str = "data-use-purpose";

/// Project vocabularies the module binds, added when absent and reused when
/// present. A reused vocabulary missing a code the module names fails the
/// compile below, before anything is written.
const SHARED_VOCABULARIES: [(&str, &[&str]); 3] = [
    (
        "consent-decision",
        &["given", "refused", "withdrawn", "invalidated"],
    ),
    (
        "consent-channel",
        &["self-service", "assisted", "steward-review", "import"],
    ),
    (
        "consent-invalidation-reason",
        &[
            "captured-in-error",
            "identity-mismatch",
            "notice-withdrawn",
            "controller-decision",
        ],
    ),
];

/// The retired scope the in-memory compile adds when no profile requires
/// consent yet. It is never written.
const SCOPE_PROBE: &str = "bregctl-module-add-probe";

/// Principal claim used when the project has no non-anonymous profile to take
/// it from.
const FALLBACK_PRINCIPAL_CLAIM: &str = "principal";

const MODULE_FILE: &str = "module.yaml";

pub(crate) fn add_consent_module(
    project_path: &Path,
    subject: &str,
) -> Result<SuccessReport, FailureReport> {
    let source = capture_project_source(project_path).map_err(|diagnostic| {
        failure(
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    let plan = plan(&source, subject)?;
    let rendered = render_registry(&source, &plan)?;
    let project = parse_project_yaml(&rendered).map_err(|failure| {
        render_failure(&format!(
            "the edited registry.yaml does not parse: {}",
            first_diagnostic(failure).message
        ))
    })?;

    let CapturedProjectSource {
        project_bytes: original,
        project_assets,
        mut modules,
        ..
    } = source;
    modules.push(CapturedModuleSource {
        id: plan.module_id.clone(),
        module: plan.module.clone(),
        bytes: plan.module_text.clone().into_bytes(),
        assets: Vec::new(),
    });
    let mut candidate = CapturedProjectSource {
        project,
        project_bytes: rendered.clone(),
        project_assets,
        modules,
    };
    let (compiled, compiles) =
        match compile_captured_project(&candidate, ProfileArg::Authoring, COMMAND) {
            Ok(compiled) => (compiled, true),
            Err(_) => {
                candidate
                    .project
                    .retired_consent_scopes
                    .push(SCOPE_PROBE.to_owned());
                (
                    compile_captured_project(&candidate, ProfileArg::Authoring, COMMAND)?,
                    false,
                )
            }
        };

    write_module_and_registry(project_path, &plan, &original, &rendered)?;

    Ok(SuccessReport {
        ok: true,
        command: COMMAND,
        profile: ProfileArg::Authoring,
        revision: compiles.then(|| compiled.revision().to_owned()),
        findings: compiler_findings(&compiled),
        artifacts: vec![
            artifact_report(
                &format!("modules/{}/{MODULE_FILE}", plan.module_id),
                "text/yaml",
                plan.module_text.as_bytes(),
            ),
            artifact_report("registry.yaml", "text/yaml", &rendered),
        ],
        explanation: Some(explanation(&plan, subject, compiles)),
        next_steps: next_steps(project_path, &plan, subject, compiles),
    })
}

/// Everything the command writes, decided before any of it is written.
struct Plan {
    module_id: String,
    module: registry_breg::RegistryModule,
    module_text: String,
    added_vocabularies: Vec<&'static str>,
    reused_vocabularies: Vec<&'static str>,
    vocabulary_items: String,
    profile_items: String,
    lock: ModuleLockSource,
    requirements: Vec<(String, String)>,
}

fn plan(source: &CapturedProjectSource, subject: &str) -> Result<Plan, FailureReport> {
    let project = &source.project;
    let owner = subject_owner(source, subject).ok_or_else(|| {
        argument_failure(
            "module.consent.subject_unknown",
            "subject",
            "the subject must name an entity the project or one of its modules declares",
        )
    })?;
    let module_id = format!("consent-{subject}");
    if project.modules.iter().any(|lock| lock.id == module_id)
        || source.modules.iter().any(|module| module.id == module_id)
    {
        return Err(authoring_failure(
            "module.consent.present",
            "modules",
            "the project already holds the consent module for this subject; it is project-owned, so edit it instead of generating it again",
        ));
    }
    if project
        .recipients
        .as_ref()
        .is_none_or(|recipients| recipients.organizations.is_empty())
    {
        return Err(authoring_failure(
            "module.consent.recipients_missing",
            "recipients",
            "declare the recipient organizations consent may be given to before adding the consent module",
        ));
    }
    let declared = project
        .vocabularies
        .iter()
        .map(|vocabulary| vocabulary.id.as_str())
        .collect::<Vec<_>>();
    if !declared.contains(&PURPOSE_VOCABULARY) {
        return Err(authoring_failure(
            "module.consent.purposes_missing",
            "vocabularies",
            "declare the data-use-purpose vocabulary of the purposes consent may be given for before adding the consent module",
        ));
    }

    let mut module_text = MODULE_TEMPLATE.replace(SUBJECT_TOKEN, subject);
    if let Some(owner) = owner {
        module_text = module_text.replacen(
            "\nversion: 0.1.0\n",
            &format!(
                "\nversion: 0.1.0\ndependencies: [{}]\n",
                yaml_string(&owner)
            ),
            1,
        );
    }
    let module = parse_module_yaml(module_text.as_bytes()).map_err(|failure| {
        render_failure(&format!(
            "the generated module does not parse: {}",
            first_diagnostic(failure).message
        ))
    })?;
    let digest = module_digest_with_assets(&module, &[]);

    let mut added_vocabularies = Vec::new();
    let mut reused_vocabularies = vec![PURPOSE_VOCABULARY];
    let mut vocabulary_items = String::new();
    for (id, values) in SHARED_VOCABULARIES {
        if declared.contains(&id) {
            reused_vocabularies.push(id);
        } else {
            added_vocabularies.push(id);
            vocabulary_items.push_str(&format!("- id: {id}\n  values: [{}]\n", values.join(", ")));
        }
    }
    let profile_items = PROFILES_TEMPLATE
        .replace(SUBJECT_TOKEN, subject)
        .replace(CLAIM_TOKEN, &yaml_scalar(&principal_claim(source)));

    Ok(Plan {
        lock: ModuleLockSource {
            id: module_id.clone(),
            version: module.version.clone(),
            digest: Some(digest),
        },
        module_id,
        module,
        module_text,
        added_vocabularies,
        reused_vocabularies,
        vocabulary_items,
        profile_items,
        requirements: requirements(source, subject),
    })
}

/// Where the subject entity is declared: `Some(None)` for the project itself,
/// `Some(Some(module))` for a module, which the consent module then depends on.
fn subject_owner(source: &CapturedProjectSource, subject: &str) -> Option<Option<String>> {
    if source
        .project
        .entities
        .iter()
        .any(|entity| entity.id == subject)
    {
        return Some(None);
    }
    source
        .modules
        .iter()
        .find(|module| {
            module
                .module
                .entities
                .iter()
                .any(|entity| entity.id == subject)
        })
        .map(|module| Some(module.id.clone()))
}

/// The claim the generated profiles bind principals with: the default
/// profile's, else the first authenticated profile's.
fn principal_claim(source: &CapturedProjectSource) -> String {
    let profiles = &source.project.access_profiles;
    profiles
        .iter()
        .filter(|profile| profile.default)
        .chain(profiles.iter())
        .filter(|profile| !profile.anonymous)
        .find_map(|profile| profile.principal_claim.clone())
        .filter(|claim| !claim.is_empty())
        .unwrap_or_else(|| FALLBACK_PRINCIPAL_CLAIM.to_owned())
}

/// A claim name as a YAML scalar: plain when it is a simple name, quoted
/// otherwise, so no authored claim can change the shape of the document.
fn yaml_scalar(value: &str) -> String {
    let plain = value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "y" | "n"
        );
    if plain {
        value.to_owned()
    } else {
        yaml_string(value)
    }
}

/// The `requireConsent` entries an adopter adds: the subject by its own id,
/// then every declared reference to the subject by that field.
fn requirements(source: &CapturedProjectSource, subject: &str) -> Vec<(String, String)> {
    let record = format!("{subject}-consent-decision");
    let mut requirements = vec![(subject.to_owned(), format!("{{record: {record}, on: id}}"))];
    let entities = source.project.entities.iter().chain(
        source
            .modules
            .iter()
            .flat_map(|module| module.module.entities.iter()),
    );
    for entity in entities {
        for field in &entity.fields {
            if matches!(&field.field_type, FieldTypeSource::Reference { target, .. } if target == subject)
            {
                requirements.push((
                    entity.id.clone(),
                    format!("{{record: {record}, on: {}}}", field.id),
                ));
            }
        }
    }
    requirements
}

/// The authored `registry.yaml` with the vocabularies and profiles appended and
/// the module pinned, proven to parse to exactly that document.
fn render_registry(source: &CapturedProjectSource, plan: &Plan) -> Result<Vec<u8>, FailureReport> {
    let original = std::str::from_utf8(&source.project_bytes)
        .map_err(|_| render_failure("registry.yaml is not UTF-8"))?;
    let mut edited = original.to_owned();
    for (key, items) in [
        ("vocabularies", &plan.vocabulary_items),
        ("accessProfiles", &plan.profile_items),
    ] {
        if items.is_empty() {
            continue;
        }
        edited = append_top_level_items(&edited, key, items).ok_or_else(|| {
            render_failure(&format!(
                "the top-level {key} list is not a block list this command can extend; write it as a block list and run the command again"
            ))
        })?;
    }
    let mut locks = source.project.modules.clone();
    locks.push(plan.lock.clone());
    locks.sort_by(|left, right| left.id.cmp(&right.id));
    let rendered = render_project_module_locks(edited.as_bytes(), &source.project.modules, &locks)
        .map_err(|diagnostic| render_failure(&diagnostic.message))?;
    if !renders_exactly(&source.project_bytes, &rendered, plan, &locks) {
        return Err(render_failure(
            "the edited registry.yaml would not hold exactly the authored project plus the consent module; nothing was written",
        ));
    }
    Ok(rendered)
}

/// Whether `rendered` parses to the authored document with the planned items
/// appended and the module locks replaced, and to nothing else.
fn renders_exactly(
    original: &[u8],
    rendered: &[u8],
    plan: &Plan,
    locks: &[ModuleLockSource],
) -> bool {
    let (Ok(mut expected), Ok(actual)) = (
        serde_norway::from_slice::<Value>(original),
        serde_norway::from_slice::<Value>(rendered),
    ) else {
        return false;
    };
    let Some(document) = expected.as_object_mut() else {
        return false;
    };
    for (key, items) in [
        ("vocabularies", &plan.vocabulary_items),
        ("accessProfiles", &plan.profile_items),
    ] {
        if items.is_empty() {
            continue;
        }
        let Ok(Value::Array(items)) = serde_norway::from_str::<Value>(items) else {
            return false;
        };
        let slot = document
            .entry(key.to_owned())
            .or_insert_with(|| Value::Array(Vec::new()));
        if slot.is_null() {
            *slot = Value::Array(Vec::new());
        }
        let Some(list) = slot.as_array_mut() else {
            return false;
        };
        list.extend(items);
    }
    document.insert(
        "modules".to_owned(),
        Value::Array(
            locks
                .iter()
                .map(|lock| json!({"id": lock.id, "version": lock.version, "digest": lock.digest}))
                .collect(),
        ),
    );
    expected == actual
}

/// Append block-list items to a top-level key of an authored YAML document,
/// in the indentation the list already uses, keeping every other line as
/// written. `items` is rendered at column zero. An absent key is added at the
/// end and an empty flow list (`[]`) becomes a block list; any other flow list
/// is refused, because extending it would mean rewriting what the author wrote.
fn append_top_level_items(source: &str, key: &str, items: &str) -> Option<String> {
    let lines = source.split_inclusive('\n').collect::<Vec<_>>();
    let Some(start) = lines
        .iter()
        .position(|line| crate::top_level_key(line) == Some(key))
    else {
        let mut rendered = source.to_owned();
        if !rendered.is_empty() && !rendered.ends_with('\n') {
            rendered.push('\n');
        }
        rendered.push_str(key);
        rendered.push_str(":\n");
        rendered.push_str(items);
        return Some(rendered);
    };
    let value = lines[start]
        .trim_end()
        .split_once(':')
        .map(|(_, value)| value.trim())?;
    let mut rendered = String::new();
    if value == "[]" {
        rendered.push_str(&lines[..start].concat());
        rendered.push_str(key);
        rendered.push_str(":\n");
        rendered.push_str(items);
        rendered.push_str(&lines[start + 1..].concat());
        return Some(rendered);
    }
    if !value.is_empty() && !value.starts_with('#') {
        return None;
    }
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| crate::top_level_key(line).is_some())
        .map_or(lines.len(), |(index, _)| index);
    let indent = lines[start + 1..end]
        .iter()
        .find(|line| line.trim_start().starts_with('-'))
        .map_or(0, |line| line.len() - line.trim_start_matches(' ').len());
    // Blank lines and column-zero comments that close the block introduce the
    // next key, so the items go above them.
    let insert_at = (start + 1..end)
        .rev()
        .find(|&index| {
            let line = lines[index];
            !line.trim().is_empty() && !line.starts_with('#')
        })
        .map_or(start + 1, |index| index + 1);
    rendered.push_str(&lines[..insert_at].concat());
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    for line in items.split_inclusive('\n') {
        if !line.trim().is_empty() {
            rendered.push_str(&" ".repeat(indent));
        }
        rendered.push_str(line);
    }
    rendered.push_str(&lines[insert_at..].concat());
    Some(rendered)
}

/// Write the module, then `registry.yaml`, and remove the module again when
/// the project file cannot be replaced, so a refusal leaves no half-added
/// module behind.
fn write_module_and_registry(
    project_path: &Path,
    plan: &Plan,
    original: &[u8],
    rendered: &[u8],
) -> Result<(), FailureReport> {
    let module_path = format!("modules/{}/{MODULE_FILE}", plan.module_id);
    let write_failed = || {
        failure(
            diagnostic(
                "module.consent.write_failed",
                &module_path,
                "the consent module could not be written",
            ),
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    };
    let project = validate_project_directory(project_path).map_err(|diagnostic| {
        failure(
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    let modules_name = OsStr::new("modules");
    let (modules, created_modules) = match project.open_directory(modules_name) {
        Ok(directory) => (directory, false),
        Err(SafePathError::NotFound) => {
            project
                .create_directory(modules_name, 0o777)
                .map_err(|_| write_failed())?;
            (
                project
                    .open_directory(modules_name)
                    .map_err(|_| write_failed())?,
                true,
            )
        }
        Err(_) => return Err(write_failed()),
    };
    let module_name = OsStr::new(&plan.module_id);
    if let Err(error) = modules.create_directory(module_name, 0o777) {
        let mut report = if error.kind() == std::io::ErrorKind::AlreadyExists {
            authoring_failure(
                "module.consent.present",
                &format!("modules/{}", plan.module_id),
                "the project already holds a directory for this subject's consent module",
            )
        } else {
            write_failed()
        };
        roll_back(&project, &modules, None, created_modules, &mut report);
        return Err(report);
    }
    let written = modules
        .open_directory(module_name)
        .map_err(SafePathError::into_io)
        .and_then(|directory| {
            let mut file = directory.create_new(OsStr::new(MODULE_FILE), 0o666)?;
            file.write_all(plan.module_text.as_bytes())?;
            file.sync_all()
        });
    if written.is_err() {
        let mut report = write_failed();
        roll_back(
            &project,
            &modules,
            Some(module_name),
            created_modules,
            &mut report,
        );
        return Err(report);
    }
    if let Err(diagnostic) = write_project_registry(project_path, original, rendered) {
        let mut report = failure(
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        );
        roll_back(
            &project,
            &modules,
            Some(module_name),
            created_modules,
            &mut report,
        );
        return Err(report);
    }
    Ok(())
}

/// Remove what this run created. A removal that fails is added to the report,
/// so the reader knows a partial module remains.
fn roll_back(
    project: &SafeDir,
    modules: &SafeDir,
    module: Option<&OsStr>,
    created_modules: bool,
    report: &mut FailureReport,
) {
    let removed = module
        .map_or(Ok(()), |name| modules.remove_tree(name))
        .and_then(|()| {
            if created_modules {
                project.remove_tree(OsStr::new("modules"))
            } else {
                Ok(())
            }
        });
    if removed.is_err() {
        report.diagnostics.push(tool_diagnostic(
            diagnostic(
                "module.consent.rollback_failed",
                "modules",
                "the partly written consent module could not be removed; delete it before running the command again",
            ),
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        ));
    }
}

fn explanation(plan: &Plan, subject: &str, compiles: bool) -> Value {
    let ids = |prefixes: &[&str], suffixes: &[&str]| -> Vec<String> {
        prefixes
            .iter()
            .zip(suffixes)
            .map(|(prefix, suffix)| format!("{prefix}{subject}{suffix}"))
            .collect()
    };
    json!({
        "subject": subject,
        "module": plan.module_id,
        "entities": plan.module.entities.iter().map(|entity| &entity.id).collect::<Vec<_>>(),
        "actions": plan.module.actions.iter().map(|action| &action.id).collect::<Vec<_>>(),
        "accessProfiles": ids(
            &["", "", "", "", ""],
            &[
                "-consent-self",
                "-consent-assisted-capture",
                "-consent-steward",
                "-consent-link-steward",
                "-consent-recipient",
            ],
        ),
        "vocabularies": {
            "added": plan.added_vocabularies,
            "reused": plan.reused_vocabularies,
        },
        "requireConsent": plan
            .requirements
            .iter()
            .map(|(entity, line)| json!({"entity": entity, "line": line}))
            .collect::<Vec<_>>(),
        "compiles": compiles,
    })
}

fn next_steps(project_path: &Path, plan: &Plan, subject: &str, compiles: bool) -> Vec<String> {
    let (_, own) = &plan.requirements[0];
    let require = format!(
        "under a profile's '- entity: {subject}' permission, add 'requireConsent: [{own}]', and do the same on each permission that reads {subject} rows only with consent; a permission on an entity that references {subject} uses the field it references by, as listed under requireConsent in this report"
    );
    // Until a profile requires consent, the decision's scope field binds
    // registry-consent-scopes, which is empty, so this step comes first.
    let mut steps = vec![if compiles {
        require
    } else {
        format!("the project compiles once a read permission requires consent: {require}")
    }];
    steps.push(format!("run 'bregctl check {}'", project_path.display()));
    steps.push(format!(
        "publish a privacy notice and its clauses through {subject}-consent-steward before subjects decide; provision principal links through {subject}-consent-link-steward only after identity proofing, because an active link lets its principal act as the subject"
    ));
    steps
}

fn failure(
    diagnostic: Diagnostic,
    artifact: DiagnosticArtifact,
    action: SuggestedAction,
) -> FailureReport {
    FailureReport {
        ok: false,
        command: COMMAND,
        diagnostics: vec![tool_diagnostic(diagnostic, artifact, action)],
    }
}

fn argument_failure(code: &str, path: &str, message: &str) -> FailureReport {
    failure(
        diagnostic(code, path, message),
        DiagnosticArtifact::CommandArguments,
        SuggestedAction::CorrectCommandUsage,
    )
}

fn authoring_failure(code: &str, path: &str, message: &str) -> FailureReport {
    failure(
        diagnostic(code, path, message),
        DiagnosticArtifact::RegistryProject,
        SuggestedAction::CorrectAuthoringSource,
    )
}

fn render_failure(message: &str) -> FailureReport {
    authoring_failure("module.consent.render_failed", "registry.yaml", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITEMS: &str = "- id: added\n  values: [a]\n";

    #[test]
    fn items_follow_the_block_indentation_and_stay_above_the_next_key() {
        let source = "a: 1\nlist:\n  - id: first\n    values: [x]\n\n# next\nb: 2\n";

        let rendered = append_top_level_items(source, "list", ITEMS).unwrap();

        assert_eq!(
            rendered,
            "a: 1\nlist:\n  - id: first\n    values: [x]\n  - id: added\n    values: [a]\n\n# next\nb: 2\n"
        );
    }

    #[test]
    fn an_absent_key_or_an_empty_flow_list_becomes_a_block_list() {
        assert_eq!(
            append_top_level_items("a: 1", "list", ITEMS).unwrap(),
            "a: 1\nlist:\n- id: added\n  values: [a]\n"
        );
        assert_eq!(
            append_top_level_items("list: []\nb: 2\n", "list", ITEMS).unwrap(),
            "list:\n- id: added\n  values: [a]\nb: 2\n"
        );
    }

    #[test]
    fn a_populated_flow_list_is_refused() {
        assert!(append_top_level_items("list: [{id: x}]\n", "list", ITEMS).is_none());
        assert!(append_top_level_items("list: &shared\n- id: x\n", "list", ITEMS).is_none());
    }

    #[test]
    fn a_claim_that_is_not_a_simple_name_is_quoted() {
        assert_eq!(yaml_scalar("registry_principal"), "registry_principal");
        assert_eq!(yaml_scalar("on"), "\"on\"");
        assert_eq!(
            yaml_scalar("https://id.example/sub"),
            "\"https://id.example/sub\""
        );
        assert_eq!(yaml_scalar("a: b"), "\"a: b\"");
    }
}
