// SPDX-License-Identifier: Apache-2.0

//! `adapterctl fixtures replay`: replay a project's fixture suites against
//! the deployment, offline (`products/adapter/CONCEPT.md` section 13.3).
//!
//! The command reads the project, profile, pack, and fixtures exactly as
//! `check` does, refuses any finding `check` would refuse, compiles the
//! deployment's concrete contract exactly as `compile` does, and then
//! holds every entry's expectation against that contract: an expected
//! response status must be one the compiled operation declares, its body
//! must validate against the response schema the contract carries for
//! that status, and an expected problem must resolve to a declared
//! problem whose status the compiled operation declares.
//!
//! After those authoring and contract checks, the command compiles the real
//! runtime interpreter over a network-free replay transport, drives every
//! entry's route, and compares the rendered facade result exactly.

use clap::{Args, Subcommand};
use registry_adapter_core::{
    check_project_pins, check_workspace, AdapterFixture, AdapterPack, AdapterProfile,
    AdapterProject, ExpectedFacade, Workspace,
};
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::Value;
use std::io;
use std::path::PathBuf;

use crate::check;
use crate::compile;

#[derive(Debug, Args)]
pub struct FixturesArgs {
    #[command(subcommand)]
    pub command: FixturesCommand,
}

#[derive(Debug, Subcommand)]
pub enum FixturesCommand {
    /// Replay the project's fixture suites against the compiled
    /// deployment contract, offline, and print the verdict.
    Replay(ReplayArgs),
}

#[derive(Debug, Args)]
pub struct ReplayArgs {
    /// Authored adapter project: its directory (holding `project.yaml`) or
    /// the `project.yaml` file itself. The profile, pack, and fixtures are
    /// read beside the project either way.
    #[arg(value_name = "PROJECT")]
    pub project: PathBuf,

    /// Profile file read instead of the `profile.yaml` beside the project.
    #[arg(long, value_name = "FILE")]
    pub profile: Option<PathBuf>,

    /// Pack file read instead of the `pack.yaml` beside the project.
    #[arg(long, value_name = "FILE")]
    pub pack: Option<PathBuf>,

    /// Fixture file read instead of the `fixtures/` directory beside the
    /// project; repeatable, and each given file replaces the whole set.
    #[arg(long, value_name = "FILE")]
    pub fixtures: Vec<PathBuf>,
}

/// One completed replay: the project as given, how many suites and entries
/// replayed, and how many upstream exchanges they carry.
pub(crate) struct ReplayRun {
    pub project: String,
    pub fixtures: usize,
    pub entries: usize,
    pub exchanges: usize,
    pub writes_simulated: usize,
}

/// Why the replay could not run to a verdict.
#[derive(Debug)]
pub(crate) enum ReplayFailure {
    /// A required file could not be read: the environment is broken, not
    /// the authoring.
    Io { path: String, source: io::Error },
    /// The reader, the pin checks, the core checks, or the contract check
    /// refused the replay.
    Refused { diagnostics: Vec<Diagnostic> },
}

/// Replay one project's fixture suites against its compiled contract.
pub(crate) fn run(args: &ReplayArgs) -> Result<ReplayRun, ReplayFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;

    // The reading half is `check`'s: the same resolution, the same
    // formats, the same fixture discovery, so a suite `check` refuses
    // never reaches the contract comparison.
    let (project_path, directory) = check::resolve_project(&args.project);
    let project = check::read::<AdapterProject>(
        &project_path,
        &check::PROJECT_FORMAT,
        &mut report,
        &mut files,
    )
    .map_err(io_failure)?;
    let profile_path = check::artifact_path(
        args.profile.as_deref(),
        &directory,
        "profile.yaml",
        "--profile",
    )
    .map_err(io_failure)?;
    let profile = check::read::<AdapterProfile>(
        &profile_path,
        &check::PROFILE_FORMAT,
        &mut report,
        &mut files,
    )
    .map_err(io_failure)?;
    let pack_path = check::artifact_path(args.pack.as_deref(), &directory, "pack.yaml", "--pack")
        .map_err(io_failure)?;
    let pack_directory = pack_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let pack = check::read::<AdapterPack>(&pack_path, &check::PACK_FORMAT, &mut report, &mut files)
        .map_err(io_failure)?;
    let fixture_paths = if args.fixtures.is_empty() {
        check::discovered_fixtures(&directory).map_err(|failure| match failure {
            check::CheckFailure::Io { path, source } => ReplayFailure::Io { path, source },
        })?
    } else {
        args.fixtures.clone()
    };
    let mut fixtures = Vec::new();
    for path in &fixture_paths {
        let decoded =
            check::read::<AdapterFixture>(path, &check::FIXTURE_FORMAT, &mut report, &mut files)
                .map_err(io_failure)?;
        if let Some((decoded, _)) = decoded {
            fixtures.push(decoded.value);
        }
    }

    // A document the reader refuses stops the replay: the contract
    // comparison needs parsed values.
    if report.has_errors() {
        return Err(ReplayFailure::Refused {
            diagnostics: report.into_diagnostics(),
        });
    }
    let (project_decoded, _) = project.expect("the project decoded");
    let (profile_decoded, profile_bytes) = profile.expect("the profile decoded");
    let (pack_decoded, pack_bytes) = pack.expect("the pack decoded");
    let project = project_decoded.value;
    let profile = profile_decoded.value;
    let pack = pack_decoded.value;

    for finding in check_project_pins(
        &project,
        &profile.version,
        &check::digest_of(&profile_bytes),
        &pack.version,
        &check::digest_of(&pack_bytes),
    ) {
        report.push(finding);
    }
    for finding in check_workspace(&Workspace {
        profile: &profile,
        pack: &pack,
        project: &project,
        runtime: None,
        fixtures: &fixtures,
    }) {
        report.push(finding);
    }
    check::check_fixture_bodies(&profile, &project, &fixtures, &mut report);
    if report.has_errors() {
        return Err(ReplayFailure::Refused {
            diagnostics: report.into_diagnostics(),
        });
    }

    // The contract half is `compile`'s: the same assembled document the
    // deployment publishes, so the replay holds expectations against what
    // callers actually receive.
    let compiled = compile::document::assemble(&profile, &project).map_err(|findings| {
        ReplayFailure::Refused {
            diagnostics: findings,
        }
    })?;
    replay_contract(&profile, &project, &compiled, &fixtures, &mut report);
    if report.has_errors() {
        return Err(ReplayFailure::Refused {
            diagnostics: report.into_diagnostics(),
        });
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|source| ReplayFailure::Io {
            path: "fixture replay runtime".to_owned(),
            source,
        })?;
    let mut writes_simulated = 0;
    for (fixture_index, fixture) in fixtures.iter().enumerate() {
        for (entry_index, entry) in fixture.entries.iter().enumerate() {
            let actual = match runtime.block_on(registry_adapter::replay_serve::run(
                &project,
                &profile,
                &pack,
                pack_directory,
                fixture,
                entry_index,
            )) {
                Ok(actual) => actual,
                Err(fault) => {
                    report.push(Diagnostic::error(
                        "adapterctl.fixtures.drive",
                        format!("/fixtures/{fixture_index}/entries/{entry_index}"),
                        format!("the runtime could not replay this entry: {fault}"),
                        "Correct the route or its recorded transcript so the actual engine completes it offline.",
                    ));
                    continue;
                }
            };
            if actual.write_durability
                == registry_adapter::replay_serve::ReplayDurability::Simulated
            {
                writes_simulated += 1;
            }
            if let Some(member) = facade_mismatch(&actual, &entry.expected) {
                report.push(Diagnostic::error(
                    "adapterctl.fixtures.facade-mismatch",
                    format!(
                        "/fixtures/{fixture_index}/entries/{entry_index}/expected/{member}"
                    ),
                    "the actual facade result differs from the fixture expectation",
                    "Record the intended facade result or correct the route, mapping, disclosure, or problem declaration.",
                ));
            }
        }
    }
    if report.has_errors() {
        return Err(ReplayFailure::Refused {
            diagnostics: report.into_diagnostics(),
        });
    }

    Ok(ReplayRun {
        project: args.project.display().to_string(),
        fixtures: fixtures.len(),
        entries: fixtures.iter().map(|fixture| fixture.entries.len()).sum(),
        exchanges: fixtures
            .iter()
            .flat_map(|fixture| fixture.entries.iter())
            .map(|entry| entry.upstream.len())
            .sum(),
        writes_simulated,
    })
}

fn facade_mismatch(
    actual: &registry_adapter::replay_serve::ReplayFacade,
    expected: &ExpectedFacade,
) -> Option<&'static str> {
    match expected {
        ExpectedFacade::Response {
            status,
            headers,
            body,
        } => {
            if actual.problem_code.is_some() {
                return Some("type");
            }
            if u32::from(actual.status) != status.get() {
                return Some("status");
            }
            if &actual.headers != headers {
                return Some("headers");
            }
            match (&actual.body, body) {
                (None, None) => None,
                (Some(actual), Some(expected))
                    if serde_json::to_vec(actual).ok()
                        == serde_json::to_vec(expected.as_value()).ok() =>
                {
                    None
                }
                _ => Some("body"),
            }
        }
        ExpectedFacade::Problem { class, code } => {
            if actual.problem_code.as_deref() != Some(code.as_str()) {
                return Some("code");
            }
            if !actual
                .problem_class
                .is_some_and(|actual| actual.is_within(*class))
            {
                return Some("class");
            }
            None
        }
    }
}

/// Hold every entry's expectation against the compiled contract: the
/// expected status must be one the operation's compiled responses declare,
/// and an expected response body must validate against the schema the
/// contract carries for that status (CONCEPT 13.3: the facade response
/// validates against the generated schema).
fn replay_contract(
    profile: &AdapterProfile,
    project: &AdapterProject,
    compiled: &Value,
    fixtures: &[AdapterFixture],
    report: &mut Report,
) {
    for (fixture_index, fixture) in fixtures.iter().enumerate() {
        for (entry_index, entry) in fixture.entries.iter().enumerate() {
            let Some(operation) =
                compiled_operation(compiled, project, &entry.facade_request.operation)
            else {
                // A bound operation always compiles to exactly one
                // concrete operation; the core checks refused anything
                // else before this ran.
                continue;
            };
            let responses = &operation["responses"];
            let expected_status = match &entry.expected {
                ExpectedFacade::Response { status, .. } => status.get(),
                ExpectedFacade::Problem { class, code } => {
                    // The expectation resolved in the core checks; the
                    // replay adds the contract half: the status of the
                    // problem it names must be one the compiled operation
                    // declares.
                    match profile.problems.iter().find(|declared| {
                        declared.code.as_str() == code.as_str()
                            && declared
                                .classes
                                .iter()
                                .any(|declared_class| class.is_within(*declared_class))
                    }) {
                        Some(declared) => declared.status.get(),
                        None => continue,
                    }
                }
            };
            let pointer = format!("/fixtures/{fixture_index}/entries/{entry_index}/expected");
            let Some(response) = responses.get(expected_status.to_string()) else {
                report.push(Diagnostic::error(
                    "adapterctl.fixtures.contract-status",
                    &pointer,
                    "the entry expects a status the compiled contract's operation does not declare",
                    "Expect a status the compiled operation declares, or declare the response in the profile.",
                ));
                continue;
            };
            let ExpectedFacade::Response { body, .. } = &entry.expected else {
                continue;
            };
            let Some(body) = body else {
                continue;
            };
            let schema =
                resolve_schema(compiled, &response["content"]["application/json"]["schema"]);
            for violation in registry_adapter_core::validate_result_schema(body.as_value(), &schema)
            {
                report.push(Diagnostic::error(
                    "adapterctl.fixtures.contract-body",
                    format!("{pointer}/body{violation}"),
                    "the entry's expected facade response body does not match the compiled contract",
                    "Bring the expected body in line with the compiled contract of the operation.",
                ));
            }
        }
    }
}

/// The compiled operation of one bound operation: the document names each
/// concrete operation `<operation>.<recordType>`, and a binding names the
/// record type, so the first binding of the operation decides the pair.
fn compiled_operation<'a>(
    compiled: &'a Value,
    project: &AdapterProject,
    operation: &registry_platform_yaml::ExternalId,
) -> Option<&'a Value> {
    let record_type = project
        .bindings
        .iter()
        .find(|binding| binding.operation.as_str() == operation.as_str())?;
    let wanted = format!(
        "{}.{}",
        operation.as_str(),
        record_type.record_type.as_str()
    );
    compiled["paths"].as_object()?.values().find_map(|item| {
        item.as_object()?.values().find(|operation| {
            operation
                .get("operationId")
                .and_then(Value::as_str)
                .is_some_and(|id| id == wanted)
        })
    })
}

/// Resolve the one reference form the compiled contract carries
/// (`#/components/schemas/Problem`); any other schema is already inline.
fn resolve_schema<'a>(compiled: &'a Value, schema: &'a Value) -> Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let name = reference.rsplit('/').next().unwrap_or_default();
            compiled["components"]["schemas"][name].clone()
        }
        None => schema.clone(),
    }
}

/// One unreadable file, in the replay's own failure type.
fn io_failure(failure: check::CheckFailure) -> ReplayFailure {
    let check::CheckFailure::Io { path, source } = failure;
    ReplayFailure::Io { path, source }
}

/// The exit class and diagnostics of a replay failure, written by the
/// shared failure path in `lib.rs`.
pub(crate) fn failure(failure: &ReplayFailure) -> (u8, Vec<Value>) {
    match failure {
        ReplayFailure::Io { path, source } => (
            crate::report::OPERATIONAL_FAILURE_EXIT,
            vec![serde_json::json!({
                "severity": "error",
                "code": "adapterctl.io-failure",
                "artifact": "filesystem",
                "path": path,
                "message": format!("the file could not be read: {source}"),
                "suggestedAction": "Correct the path or permissions, then retry.",
            })],
        ),
        ReplayFailure::Refused { diagnostics } => (
            crate::report::DOMAIN_REFUSAL_EXIT,
            diagnostics
                .iter()
                .map(|diagnostic| {
                    serde_json::to_value(diagnostic).expect("a diagnostic serializes")
                })
                .collect(),
        ),
    }
}
