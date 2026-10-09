// SPDX-License-Identifier: Apache-2.0

//! Project loading and the offline init, check, test, and explain reports.
//!
//! Everything here runs without a network, a database, or a clock: the
//! authored policy, its records, and its fixtures are read from the project
//! directory through the shared reader, checked and replayed through the
//! pure core, and rendered as one JSON report per command. A refused project
//! is the reader's own report, every diagnostic at its position.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use registry_platform_config::package::{plan_package, write_package};
use registry_platform_config::{sha256_uri, UNAVAILABLE_CODE};
use registry_platform_yaml::{Decoded, Diagnostic, Report, Source};
use registry_scheduling::config::{
    check_runtime, package_limits, startup_report, RuntimeConfig, RuntimeConfigError,
    PACKAGE_COMMAND,
};
use registry_scheduling_core::{
    findings_report, CaseStatus, FindingArea, FixtureExpectation, ReplayError, SchedulingFacts,
    SchedulingFixture, SchedulingPolicy, SchedulingRecords, AUTHORED_POLICY_FILE,
    SCHEDULING_FIXTURE_KIND, SCHEDULING_RECORDS_FILE,
};
use serde_json::{json, Value};

use crate::templates;

/// The directory an authored project keeps its replay fixtures in.
const FIXTURES_DIRECTORY: &str = "fixtures";

/// The code `test` refuses a project with when it has no fixture to replay.
const NO_FIXTURES_CODE: &str = "scheduling.fixture.none";

pub(super) fn init(project: &Path, template: &str) -> Result<Value> {
    let Some(files) = templates::template_files(template) else {
        anyhow::bail!(
            "unknown template {template:?}; available templates: standalone-exact-time, standalone-arrival-window"
        );
    };
    match fs::symlink_metadata(project) {
        Ok(_) => anyhow::bail!("destination already exists; init never overwrites a project"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("checking the project destination"),
    }
    let parent = project
        .parent()
        .context("project destination has no parent")?;
    fs::create_dir_all(parent).context("creating project parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".scheduling-init-")
        .tempdir_in(parent)
        .context("creating project staging directory")?;
    fs::create_dir(staging.path().join(FIXTURES_DIRECTORY))?;
    let mut created = Vec::new();
    for (relative, contents) in &files {
        fs::write(staging.path().join(relative), contents)?;
        created.push((*relative).to_owned());
    }
    let staging_path = staging.keep();
    fs::rename(&staging_path, project)
        .context("publishing scheduling project without replacement")?;
    Ok(json!({
        "ok": true,
        "command": "init",
        "template": template,
        "project": project,
        "created": created,
        "next": [
            "Run schedulingctl check PROJECT, then schedulingctl test PROJECT.",
            "Copy runtime.example.yaml to runtime.yaml, set its absolute paths, run schedulingctl check PROJECT --runtime-config runtime.yaml, run schedulingctl plan --runtime-config runtime.yaml then schedulingctl apply --runtime-config runtime.yaml, apply records.yaml, then run scheduling serve with it.",
        ],
    }))
}

/// What reading a project found: each document that decoded, and one report
/// carrying every diagnostic of every file read.
struct ProjectReading {
    policy: Option<Decoded<SchedulingPolicy>>,
    facts: Option<SchedulingFacts>,
    fixtures: Vec<(PathBuf, SchedulingFixture)>,
    report: Report,
}

/// Read `scheduling.yaml`, `records.yaml`, and, with `fixtures` set, every
/// fixture under `fixtures/`. A file the reader refuses is reported and the
/// others are still read, so one run names every problem; a file that cannot
/// be read at all is an error. The records and the fixtures are checked
/// against the policy only once the policy passes its own checks, so a
/// broken policy never shows up a second time as findings against them.
fn read_project(project: &Path, fixtures: bool) -> Result<ProjectReading> {
    let mut report = Report::new(Vec::new());
    let mut files = 0;

    let policy_path = project.join(AUTHORED_POLICY_FILE);
    files += 1;
    let policy = match SchedulingPolicy::decode(
        &policy_path.display().to_string(),
        &read_input(&policy_path)?,
    ) {
        Ok(decoded) => {
            report.extend(findings_report(&decoded.document, &decoded.value.check()));
            Some(decoded)
        }
        Err(refusal) => {
            report.extend(refusal);
            None
        }
    };
    let checked = policy.as_ref().filter(|_| !report.has_errors());

    let records_path = project.join(SCHEDULING_RECORDS_FILE);
    files += 1;
    let facts = match SchedulingRecords::decode(
        &records_path.display().to_string(),
        &read_input(&records_path)?,
    ) {
        Ok(decoded) => {
            match checked {
                Some(policy) => {
                    let (records, project_findings): (Vec<_>, Vec<_>) = decoded
                        .value
                        .facts()
                        .check(&policy.value)
                        .into_iter()
                        .partition(|finding| finding.area == FindingArea::Records);
                    report.extend(findings_report(&decoded.document, &records));
                    // An offering's reference to a window the records do not
                    // carry is a finding against the project file.
                    for finding in project_findings {
                        report.push(finding.to_diagnostic(&policy.document));
                    }
                }
                None => report.extend(decoded.document.warnings()),
            }
            Some(decoded.value.into_facts())
        }
        Err(refusal) => {
            report.extend(refusal);
            None
        }
    };

    let mut readings = Vec::new();
    if fixtures {
        for path in fixture_paths(project)? {
            files += 1;
            let relative = path.strip_prefix(project).unwrap_or(&path).to_owned();
            match SchedulingFixture::decode(&path.display().to_string(), &read_input(&path)?) {
                Ok(decoded) => {
                    report.extend(match checked {
                        Some(policy) => findings_report(
                            &decoded.document,
                            &decoded.value.findings(&policy.value),
                        ),
                        None => decoded.document.warnings(),
                    });
                    readings.push((relative, decoded.value));
                }
                Err(refusal) => report.extend(refusal),
            }
        }
    }
    report.set_files_checked(files);
    Ok(ProjectReading {
        policy,
        facts,
        fixtures: readings,
        report,
    })
}

/// Every fixture file under `project/fixtures`, in name order. A project
/// without the directory has no fixtures.
fn fixture_paths(project: &Path) -> Result<Vec<PathBuf>> {
    let directory = project.join(FIXTURES_DIRECTORY);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", directory.display()))
        }
    };
    // An entry the directory cannot hand over is a filesystem failure, not a
    // fixture that does not exist: swallowing it here would report a partial
    // replay as a complete, passing one.
    let mut paths = entries
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .with_context(|| format!("reading an entry of {}", directory.display()))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| {
            matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("yaml" | "yml")
            )
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

/// The bytes of one project file. The shared reader decides what they may
/// hold, so a file that cannot be read at all is the only failure here.
pub(crate) fn read_input(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}

/// A project whose every file read and checked clean.
struct CheckedProject {
    policy: SchedulingPolicy,
    facts: SchedulingFacts,
    fixtures: Vec<(PathBuf, SchedulingFixture)>,
    report: Report,
}

/// Read and check every file of `project`. A refusal is the report naming
/// every error, or, under `deny_warnings`, every warning too.
fn checked_project(project: &Path, fixtures: bool, deny_warnings: bool) -> Result<CheckedProject> {
    let ProjectReading {
        policy,
        facts,
        fixtures,
        report,
    } = read_project(project, fixtures)?;
    match (policy, facts) {
        (Some(policy), Some(facts)) if !refuses(&report, deny_warnings) => Ok(CheckedProject {
            policy: policy.value,
            facts,
            fixtures,
            report,
        }),
        _ => Err(report.into()),
    }
}

/// Whether `report` refuses what it describes: any error does, and with
/// `deny_warnings` any warning does too.
fn refuses(report: &Report, deny_warnings: bool) -> bool {
    report.has_errors() || (deny_warnings && report.warning_count() > 0)
}

pub(super) fn check(project: &Path, deny_warnings: bool) -> Result<Value> {
    let checked = checked_project(project, true, deny_warnings)?;
    Ok(json!({
        "ok": true,
        "command": "check",
        "project": project,
        "filesChecked": checked.report.files_checked(),
        "diagnostics": checked.report.to_json_value(),
        "effective": effective(&checked.policy, &checked.facts),
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

pub(super) fn test(project: &Path) -> Result<Value> {
    let checked = checked_project(project, true, false)?;
    if checked.fixtures.is_empty() {
        let mut diagnostic = Diagnostic::error(
            NO_FIXTURES_CODE,
            "",
            "test replays the fixtures under fixtures/, and the project has none",
            "Add a SchedulingFixture YAML file under fixtures/, then rerun schedulingctl test PROJECT.",
        );
        diagnostic.artifact = Some(SCHEDULING_FIXTURE_KIND.to_owned());
        diagnostic.source = Some(Source {
            file: project.join(FIXTURES_DIRECTORY).display().to_string(),
            line: None,
            column: None,
        });
        let mut report = checked.report;
        report.push(diagnostic);
        return Err(report.into());
    }
    let reports = checked
        .fixtures
        .iter()
        .map(|(file, fixture)| run_fixture(file, &checked.policy, fixture))
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "ok": true,
        "command": "test",
        "project": project,
        "filesChecked": checked.report.files_checked(),
        "diagnostics": checked.report.to_json_value(),
        "fixtures": reports,
        "proofBoundary": "offline_synthetic",
        "productionClosure": false,
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

pub(super) fn explain(project: &Path) -> Result<Value> {
    let CheckedProject { policy, facts, .. } = checked_project(project, false, false)?;
    let offerings = policy
        .offerings
        .iter()
        .map(|offering| {
            let mut report = json!({
                "id": offering.id,
                "service": offering.service,
                "mode": offering.mode,
                "location": offering.location,
            });
            if let Some(exact) = &offering.exact_time {
                report["exactTime"] = serde_json::to_value(exact)?;
            }
            if let Some(arrival) = &offering.arrival {
                report["arrival"] = serde_json::to_value(arrival)?;
            }
            Ok(report)
        })
        .collect::<Result<Vec<_>>>()?;
    let windows = facts
        .windows
        .iter()
        .map(|window| {
            let mut units_policy = serde_json::to_value(&window.units_policy)?;
            units_policy["subquotas"] = json!(window
                .subquotas
                .iter()
                .map(|subquota| json!({
                    "channel": subquota.channel.as_str(),
                    "units": subquota.units,
                }))
                .collect::<Vec<_>>());
            Ok(json!({
                "id": window.id,
                "revision": window.revision,
                "start": window.start,
                "end": window.end,
                "units": window.units,
                "unitsPolicy": units_policy,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "ok": true,
        "command": "explain",
        "project": {
            "id": policy.project.id,
            "version": policy.project.version,
        },
        "policyDigest": policy.policy_digest(),
        "offerings": offerings,
        "windows": windows,
        "holdPolicy": {
            "ttlMinutes": policy.hold_policy.ttl_minutes,
            "maximumPerCaller": policy.hold_policy.maximum_per_caller,
            "because": policy.hold_policy.because,
        },
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

/// The project and the exact inputs a package of it carries.
struct PackageContents {
    project: PathBuf,
    inputs: BTreeMap<String, Vec<u8>>,
}

/// Canonicalize the project, check the authored policy, and assemble the one
/// file a package carries. Performs no writes, so both `package` and
/// `package_dry_run` share it. A policy that does not pass its checks is
/// refused with the reader's report, each diagnostic naming the file as the
/// project path was given.
fn compute_package(project: &Path) -> Result<PackageContents> {
    let given = project.join(AUTHORED_POLICY_FILE);
    let project =
        fs::canonicalize(project).context("resolving the Scheduling authoring project")?;
    let bytes = read_input(&project.join(AUTHORED_POLICY_FILE))?;
    SchedulingPolicy::read(&given.display().to_string(), &bytes)?;
    let inputs = BTreeMap::from([(AUTHORED_POLICY_FILE.to_owned(), bytes)]);
    Ok(PackageContents { project, inputs })
}

fn package_files(inputs: &BTreeMap<String, Vec<u8>>) -> Vec<Value> {
    inputs
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path,
                "sha256": sha256_uri(bytes),
                "bytes": bytes.len(),
            })
        })
        .collect()
}

/// Write the checked policy into `output`, a new directory, as the package
/// the runtime verifies at startup. The package is written once: an existing
/// output is refused, so each candidate lands in its own directory.
pub(super) fn package(project: &Path, output: &Path, revision: Option<&str>) -> Result<Value> {
    let PackageContents { project, inputs } = compute_package(project)?;
    let written = write_package(
        output,
        &inputs,
        revision,
        &package_limits(),
        PACKAGE_COMMAND,
    )?;
    Ok(json!({
        "ok": true,
        "command": "package",
        "project": project,
        "output": output,
        "dryRun": false,
        "packageDigest": written.digest(),
        "revision": written.revision(),
        "files": package_files(&inputs),
        "runtimeConfigurationIncluded": false,
        "secretsIncluded": false,
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

/// Report the exact `packageDigest` and `files` a package of this project
/// would carry, without writing anything.
pub(super) fn package_dry_run(project: &Path, revision: Option<&str>) -> Result<Value> {
    let PackageContents { project, inputs } = compute_package(project)?;
    let digest = plan_package(
        &project,
        &inputs,
        revision,
        &package_limits(),
        PACKAGE_COMMAND,
    )?;
    Ok(json!({
        "ok": true,
        "command": "package",
        "project": project,
        "dryRun": true,
        "packageDigest": digest,
        "revision": revision,
        "files": package_files(&inputs),
        "runtimeConfigurationIncluded": false,
        "secretsIncluded": false,
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

fn run_fixture(
    relative: &Path,
    policy: &SchedulingPolicy,
    fixture: &SchedulingFixture,
) -> Result<Value> {
    // A calendar gap or fold the check did not reach is reported the way any
    // other fixture failure is reported, instead of refusing the whole
    // command over one fixture.
    let outcomes = match fixture.replay(policy) {
        Err(ReplayError::Calendar(error)) => {
            return Ok(json!({
                "name": fixture.name,
                "status": "failed",
                "file": relative,
                "cases": [],
                "calendarRefusal": error.to_string(),
            }));
        }
        other => other.with_context(|| format!("replaying fixture {}", relative.display()))?,
    };
    let cases = outcomes
        .iter()
        .zip(fixture.cases.iter())
        .map(|(outcome, case)| {
            // A failing case names what the fixture expected beside what
            // replay actually produced, so a mismatched problem code is
            // legible from the report alone, never only from opening the
            // fixture file.
            let detail = match (outcome.status, &outcome.detail) {
                (CaseStatus::Fail, Some(actual)) => Some(format!(
                    "expected {}, actual {actual}",
                    expected_summary(&case.expect)
                )),
                (_, detail) => detail.clone(),
            };
            json!({
                "name": outcome.name,
                "status": outcome.status.as_str(),
                "detail": detail,
            })
        })
        .collect::<Vec<_>>();
    let status = if outcomes
        .iter()
        .all(|outcome| outcome.status == CaseStatus::Pass)
    {
        "passed"
    } else {
        "failed"
    };
    Ok(json!({
        "name": fixture.name,
        "status": status,
        "file": relative,
        "cases": cases,
    }))
}

/// Render a fixture case's expectation the same way replay renders what
/// actually happened, so the two read side by side.
fn expected_summary(expect: &FixtureExpectation) -> String {
    match expect {
        FixtureExpectation::Admitted { units, resource } => format!(
            "admitted onto {} for {units} unit(s)",
            resource.as_deref().unwrap_or("the window")
        ),
        FixtureExpectation::Refused { code } => format!("refused {}", code.code()),
    }
}

/// The effective policy a check saw: identity, digest, collection sizes and
/// identifiers, and the hold policy.
fn effective(policy: &SchedulingPolicy, facts: &SchedulingFacts) -> Value {
    fn summary<'a>(ids: impl Iterator<Item = &'a str>) -> Value {
        let all: Vec<&str> = ids.collect();
        json!({"count": all.len(), "ids": all})
    }
    json!({
        "projectId": policy.project.id,
        "projectVersion": policy.project.version,
        "policyDigest": policy.policy_digest(),
        "services": summary(policy.services.iter().map(|service| service.id.as_str())),
        "offerings": summary(policy.offerings.iter().map(|offering| offering.id.as_str())),
        "openings": summary(policy.openings.iter().map(|opening| opening.id.as_str())),
        "windows": summary(facts.windows.iter().map(|window| window.id.as_str())),
        "holdPolicy": {
            "ttlMinutes": policy.hold_policy.ttl_minutes,
            "maximumPerCaller": policy.hold_policy.maximum_per_caller,
        },
    })
}

/// A refused runtime file, with every diagnostic its check reported, and
/// for `check --runtime-config` those of the project beside them.
#[derive(Debug)]
pub(crate) struct RuntimeConfigRefusal {
    pub report: Report,
    /// The runtime file could not be read at all.
    pub unavailable: bool,
}

impl std::fmt::Display for RuntimeConfigRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the Scheduling runtime configuration was refused"
        )
    }
}

impl std::error::Error for RuntimeConfigRefusal {}

/// Add to `checked`, the project check's outcome, the check of the runtime
/// file at `runtime_config` as `scheduling serve` reads it: offline, with no
/// package, database, network, or secret material, and against the
/// project's policy when that passes its checks. Diagnostics name the file
/// as it was given, and `deny_warnings` refuses on a warning here as it does
/// in the project.
pub(super) fn check_runtime_config(
    project: &Path,
    runtime_config: &Path,
    environment: bool,
    deny_warnings: bool,
    checked: Result<Value>,
) -> Result<Value> {
    let policy_path = project.join(AUTHORED_POLICY_FILE);
    let policy = fs::read(&policy_path)
        .ok()
        .and_then(|bytes| SchedulingPolicy::read(&policy_path.display().to_string(), &bytes).ok())
        .map(|decoded| decoded.value);
    let given = runtime_config.display().to_string();
    let absolute = absolute_lexical(runtime_config)
        .context("resolving the --runtime-config path against the working directory")?;
    let runtime = check_runtime(&absolute, policy.as_ref(), environment);
    let absolute = absolute.display().to_string();
    let named = |mut diagnostic: Diagnostic| {
        if let Some(source) = &mut diagnostic.source {
            if source.file == absolute {
                source.file.clone_from(&given);
            }
        }
        for related in &mut diagnostic.related {
            if related.file == absolute {
                related.file.clone_from(&given);
            }
        }
        diagnostic
    };
    let mut report = Report::new(runtime.diagnostics.into_iter().map(named).collect());
    report.set_files_checked(1);
    if !refuses(&report, deny_warnings) {
        let mut checked = checked?;
        checked["runtimeConfig"] = json!(given);
        if let (Some(diagnostics), Value::Array(warnings)) = (
            checked["diagnostics"].as_array_mut(),
            report.to_json_value(),
        ) {
            diagnostics.extend(warnings);
        }
        if let Some(files) = checked["filesChecked"].as_u64() {
            checked["filesChecked"] = json!(files + 1);
        }
        return Ok(checked);
    }
    let refused = match checked {
        // The project passed: its warnings and the files it read stay in
        // the refusal beside the runtime file's diagnostics.
        Ok(checked) => {
            let mut project = Report::new(
                serde_json::from_value(checked["diagnostics"].clone())
                    .context("reading the project check's diagnostics")?,
            );
            if let Some(files) = checked["filesChecked"]
                .as_u64()
                .and_then(|files| usize::try_from(files).ok())
            {
                project.set_files_checked(files);
            }
            project.extend(report);
            project
        }
        Err(error) => match crate::configuration_report(&error) {
            Some(project) => {
                let mut project = project.clone();
                if project.files_checked().is_none() {
                    project.set_files_checked(1);
                }
                project.extend(report);
                project
            }
            None => return Err(error),
        },
    };
    Err(RuntimeConfigRefusal {
        report: refused,
        unavailable: runtime.unavailable,
    }
    .into())
}

/// Read the runtime file at `path` as `scheduling serve` does. A refusal of
/// the file itself carries every rule it breaks, each at its position,
/// exactly as the runtime prints them at startup.
pub(crate) fn load_runtime_config(path: &Path) -> Result<RuntimeConfig> {
    RuntimeConfig::load(path).map_err(|error| runtime_refusal(path, error))
}

/// `error`, a refusal of the runtime file at `path` or of the policy it
/// binds, as the report the runtime prints at startup. The runtime file
/// that cannot be read at all keeps its message.
pub(crate) fn runtime_refusal(path: &Path, error: RuntimeConfigError) -> anyhow::Error {
    let unavailable = matches!(
        &error,
        RuntimeConfigError::Load(load)
            if load.diagnostics().iter().any(|diagnostic| diagnostic.code == UNAVAILABLE_CODE)
    );
    match startup_report(path, &error) {
        Some(report) => RuntimeConfigRefusal {
            report,
            unavailable,
        }
        .into(),
        None => anyhow::Error::new(error).context("loading the Scheduling runtime configuration"),
    }
}

/// `path` made absolute against the working directory, with `.` and `..`
/// resolved by name, as the runtime loader requires.
fn absolute_lexical(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut normal = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Ok(normal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_scheduling::config::RuntimeConfig;

    /// A tempdir holding one freshly initialized template project, plus the
    /// paths the tempdir keeps alive.
    fn initialized(template: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        init(&project, template).unwrap();
        (root, project)
    }

    /// Replace the first `from` in the project file at `relative`.
    fn edit(project: &Path, relative: &str, from: &str, to: &str) {
        let path = project.join(relative);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(from), "{relative} carries {from}");
        fs::write(&path, text.replacen(from, to, 1)).unwrap();
    }

    /// The report a refused command carries, as `file:line pointer code`
    /// with the file relative to `project`.
    fn refusals(project: &Path, error: &anyhow::Error) -> Vec<String> {
        let report = crate::configuration_report(error)
            .unwrap_or_else(|| panic!("a positioned refusal, not {error:#}"));
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                let place = diagnostic
                    .source
                    .as_ref()
                    .map_or_else(String::new, |source| {
                        let file = Path::new(&source.file).strip_prefix(project).map_or_else(
                            |_| source.file.clone(),
                            |file| file.display().to_string(),
                        );
                        match source.line {
                            Some(line) => format!("{file}:{line}"),
                            None => file,
                        }
                    });
                format!("{place} {} {}", diagnostic.path, diagnostic.code)
            })
            .collect()
    }

    #[test]
    fn init_writes_every_template_file_without_overwriting() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let report = init(&project, "standalone-arrival-window").unwrap();
        assert_eq!(report["command"], "init");
        assert_eq!(report["template"], "standalone-arrival-window");
        assert_eq!(
            report["created"],
            json!([
                "scheduling.yaml",
                "runtime.example.yaml",
                "records.yaml",
                "fixtures/household-morning.yaml",
                "fixtures/household-afternoon.yaml"
            ])
        );
        assert!(project.join(AUTHORED_POLICY_FILE).is_file());
        assert!(project.join("runtime.example.yaml").is_file());
        assert!(project.join("records.yaml").is_file());
        assert!(project.join("fixtures/household-morning.yaml").is_file());
        assert!(project.join("fixtures/household-afternoon.yaml").is_file());
        let error = init(&project, "standalone-arrival-window").unwrap_err();
        assert!(error.to_string().contains("never overwrites"));
        let error = init(&root.path().join("other"), "no-such-template").unwrap_err();
        assert!(error.to_string().contains("standalone-arrival-window"));
    }

    /// The example's placeholder roots, replaced with real absolute paths so
    /// the emitted document can be loaded and checked as it stands.
    const EXAMPLE_PACKAGE_ROOT: &str = "/srv/registry-scheduling/package";
    const EXAMPLE_STATE_ROOT: &str = "/var/lib/registry-scheduling";

    #[test]
    fn init_writes_a_runtime_example_beside_the_authored_project() {
        let mut examples = Vec::new();
        for template in ["standalone-exact-time", "standalone-arrival-window"] {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            let report = init(&project, template).unwrap();
            assert!(
                report["created"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry == "runtime.example.yaml"),
                "{template}: {report}"
            );
            let text = fs::read_to_string(project.join("runtime.example.yaml")).unwrap();
            // Nothing in the document names the directory it was written
            // beside, so the committed example can never drift from what an
            // adopter initializes.
            assert!(!text.contains(root.path().to_str().unwrap()));
            examples.push(text);
        }
        // One document serves both templates.
        assert_eq!(examples[0], examples[1]);

        let root = tempfile::tempdir().unwrap();
        // The loader refuses a path through a symbolic link, and the system
        // temporary directory is one on some hosts.
        let base = root.path().canonicalize().unwrap();
        let project = base.join("project");
        init(&project, "standalone-exact-time").unwrap();
        let output = base.join("package");
        package(&project, &output, None).unwrap();
        let text = fs::read_to_string(project.join("runtime.example.yaml"))
            .unwrap()
            .replace(
                EXAMPLE_PACKAGE_ROOT,
                output.to_str().expect("utf-8 package path"),
            )
            .replace(EXAMPLE_STATE_ROOT, base.to_str().expect("utf-8 root path"));
        let runtime = base.join("runtime.yaml");
        fs::write(&runtime, &text).unwrap();
        let config = RuntimeConfig::load(&runtime).expect("the emitted example loads");
        assert_eq!(
            config.policy_path(),
            output.join(AUTHORED_POLICY_FILE),
            "the example selects the package it names"
        );
        assert_eq!(config.retention.attempt_receipt_retention_days, 7);
        assert!(config.destinations.reminders.is_none());
    }

    #[test]
    fn check_reads_every_project_file_and_reports_the_effective_policy() {
        let (_root, project) = initialized("standalone-exact-time");
        let report = check(&project, false).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["command"], "check");
        assert_eq!(report["diagnostics"], json!([]));
        // The policy, the records, and both fixtures.
        assert_eq!(report["filesChecked"], 4);
        assert_eq!(report["networkAccess"], false);
        assert_eq!(report["databaseAccess"], false);
        let effective = &report["effective"];
        assert_eq!(effective["projectId"], "registry-updates");
        assert_eq!(effective["projectVersion"], "1");
        assert!(effective["policyDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(
            effective["services"],
            json!({"count": 1, "ids": ["registry-update"]})
        );
        assert_eq!(effective["offerings"]["count"], 2);
        assert_eq!(effective["openings"]["count"], 2);
        assert_eq!(effective["windows"], json!({"count": 0, "ids": []}));
        assert_eq!(effective["holdPolicy"]["ttlMinutes"], 5);
        assert_eq!(effective["holdPolicy"]["maximumPerCaller"], 3);
    }

    /// Every file is read and every refusal is reported at its position in
    /// one run; a policy that fails its own checks is never checked again
    /// through the records or the fixtures that rely on it.
    #[test]
    fn check_reports_every_refusal_in_every_file_at_its_position() {
        let (_root, project) = initialized("standalone-arrival-window");
        edit(
            &project,
            AUTHORED_POLICY_FILE,
            "because: The hall opens on Saturday mornings.",
            "because: \"  \"",
        );
        edit(
            &project,
            SCHEDULING_RECORDS_FILE,
            "locations:",
            "stray: true\nlocations:",
        );
        edit(
            &project,
            "fixtures/household-morning.yaml",
            "now: 2026-10-09T20:00:00Z",
            "now: 2026-10-09T20:00:00Z\nstray: true",
        );
        let error = check(&project, false).unwrap_err();
        assert_eq!(
            refusals(&project, &error),
            [
                "scheduling.yaml:46 /openings/0/because scheduling.project.invalid-because",
                "records.yaml:4 /stray config.unknown-key",
                "fixtures/household-morning.yaml:6 /stray config.unknown-key",
            ]
        );
        let report = crate::configuration_report(&error).unwrap();
        assert_eq!(report.files_checked(), Some(4));
    }

    #[test]
    fn deny_warnings_refuses_a_report_with_a_warning_only_when_asked() {
        let mut report = Report::new(Vec::new());
        assert!(!refuses(&report, true));
        report.push(Diagnostic::warning(
            "config.deprecated-api-version",
            "/apiVersion",
            "the apiVersion is deprecated",
            "Write the current apiVersion.",
        ));
        assert!(!refuses(&report, false));
        assert!(refuses(&report, true));
        report.push(Diagnostic::error(
            "config.unknown-key",
            "/stray",
            "the key is not part of the format",
            "Remove the key.",
        ));
        assert!(refuses(&report, false));
    }

    #[test]
    fn test_reports_per_fixture_and_per_case_outcomes_with_the_proof_boundary() {
        let (_root, project) = initialized("standalone-exact-time");
        let report = test(&project).unwrap();
        assert_eq!(report["command"], "test");
        assert_eq!(report["diagnostics"], json!([]));
        assert_eq!(report["filesChecked"], 4);
        assert_eq!(report["proofBoundary"], "offline_synthetic");
        assert_eq!(report["productionClosure"], false);
        assert_eq!(report["networkAccess"], false);
        assert_eq!(report["databaseAccess"], false);
        let fixtures = report["fixtures"].as_array().unwrap();
        let names: Vec<&str> = fixtures
            .iter()
            .map(|fixture| fixture["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["counter-stations", "fold-day-rebooking"]);
        let counter = &fixtures[0];
        assert_eq!(counter["status"], "passed");
        assert_eq!(counter["file"], "fixtures/counter-stations.yaml");
        let cases = counter["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 4);
        assert!(cases.iter().all(|case| case["status"] == "pass"));
        // A refused case reports the public code it was refused with.
        let refused = cases
            .iter()
            .find(|case| case["name"] == "same-key-retry-is-refused")
            .unwrap();
        assert!(refused["detail"]
            .as_str()
            .unwrap()
            .contains("booking.duplicate-active"));
        // The fold fixture replays too, including its reschedule case.
        let fold = &fixtures[1];
        assert_eq!(fold["status"], "passed");
        let fold_cases = fold["cases"].as_array().unwrap();
        let rescheduled = fold_cases
            .iter()
            .find(|case| case["name"] == "reschedule-into-the-later-morning")
            .unwrap();
        assert_eq!(rescheduled["status"], "pass");
    }

    #[test]
    fn a_refused_policy_runs_no_fixture() {
        let (_root, project) = initialized("standalone-arrival-window");
        edit(
            &project,
            AUTHORED_POLICY_FILE,
            "because: The hall opens on Saturday mornings.",
            "because: \"  \"",
        );
        let error = test(&project).unwrap_err();
        assert_eq!(
            refusals(&project, &error),
            ["scheduling.yaml:46 /openings/0/because scheduling.project.invalid-because"]
        );
    }

    #[test]
    fn a_daylight_saving_gap_check_cannot_see_is_a_fixture_failure_not_a_command_refusal() {
        // Openings carry no timezone; only a fixture's location record does.
        // `check` never resolves a calendar, so it cannot see that an
        // opening's local wall-clock hours fall inside a real spring-forward
        // gap. Move `standalone-arrival-window`'s Saturday opening onto the
        // Sunday of 2026-03-08, 02:00-03:00 America/New_York: a nonexistent
        // local time, per registry-platform-calendar's own pinned case.
        let (_root, project) = initialized("standalone-arrival-window");
        for (from, to) in [
            ("weekdays: [sat]", "weekdays: [sun]"),
            ("startTime: \"08:00\"", "startTime: \"02:00\""),
            ("endTime: \"12:00\"", "endTime: \"03:00\""),
            (
                "effectiveFrom: \"2026-10-01\"",
                "effectiveFrom: \"2026-03-08\"",
            ),
            (
                "effectiveUntil: \"2026-12-31\"",
                "effectiveUntil: \"2026-03-08\"",
            ),
        ] {
            edit(&project, AUTHORED_POLICY_FILE, from, to);
        }
        edit(
            &project,
            "fixtures/household-morning.yaml",
            "timezone: Asia/Bangkok",
            "timezone: America/New_York",
        );

        // check() has no calendar to resolve, so it reports clean.
        let checked = check(&project, false).unwrap();
        assert_eq!(checked["diagnostics"], json!([]));

        // test() replays the calendar and must not let one fixture's
        // calendar refusal abort the whole command: it reports that
        // fixture as failed and names the calendar problem, the same way
        // any other fixture failure is reported.
        let tested = test(&project).unwrap();
        let fixture = tested["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|fixture| fixture["name"] == "household-morning")
            .unwrap();
        assert_eq!(fixture["status"], "failed");
        assert_eq!(fixture["cases"], json!([]));
        let detail = fixture["calendarRefusal"].as_str().unwrap();
        assert!(detail.contains("does not exist"), "{detail}");
    }

    #[test]
    fn explain_publishes_offerings_windows_hold_policy_and_digest() {
        let (_root, project) = initialized("standalone-arrival-window");
        let report = explain(&project).unwrap();
        assert_eq!(report["command"], "explain");
        assert_eq!(
            report["project"],
            json!({"id": "household-days", "version": "3"})
        );
        assert!(report["policyDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        let offerings = report["offerings"].as_array().unwrap();
        assert_eq!(offerings[0]["id"], "household-morning");
        assert_eq!(offerings[0]["mode"], "arrival-window");
        assert_eq!(offerings[0]["location"], "civic-hall");
        assert_eq!(
            offerings[0]["arrival"],
            json!({"window": "household-morning-window", "leadTimeMinutes": 60, "horizonDays": 45})
        );
        let windows = report["windows"].as_array().unwrap();
        assert_eq!(windows[0]["id"], "household-morning-window");
        assert_eq!(windows[0]["revision"], 2);
        assert_eq!(windows[0]["start"], "2026-10-10T01:00:00Z");
        assert_eq!(windows[0]["end"], "2026-10-10T03:00:00Z");
        assert_eq!(windows[0]["units"], 3);
        assert_eq!(windows[0]["unitsPolicy"]["type"], "per-recipient");
        assert_eq!(
            windows[0]["unitsPolicy"]["subquotas"],
            json!([{"channel": "public", "units": 2}, {"channel": "assisted", "units": 1}])
        );
        assert_eq!(report["holdPolicy"]["ttlMinutes"], 10);
        assert_eq!(report["holdPolicy"]["maximumPerCaller"], 2);
        assert_eq!(report["networkAccess"], false);
        assert_eq!(report["databaseAccess"], false);

        // The exact-time template explains its fold-day offering's block.
        let (_root, project) = initialized("standalone-exact-time");
        let report = explain(&project).unwrap();
        let offerings = report["offerings"].as_array().unwrap();
        let fold = offerings
            .iter()
            .find(|offering| offering["id"] == "fold-day-update-30")
            .unwrap();
        assert_eq!(fold["exactTime"]["durationMinutes"], 30);
        assert_eq!(fold["exactTime"]["startIncrementMinutes"], 30);
        assert!(fold["arrival"].is_null());
    }

    #[test]
    fn explain_refuses_a_policy_that_fails_its_check() {
        let (_root, project) = initialized("standalone-arrival-window");
        edit(
            &project,
            AUTHORED_POLICY_FILE,
            "because: The hall opens on Saturday mornings.",
            "because: \"  \"",
        );
        let error = explain(&project).unwrap_err();
        assert_eq!(
            refusals(&project, &error),
            ["scheduling.yaml:46 /openings/0/because scheduling.project.invalid-because"]
        );
    }

    #[test]
    fn a_project_without_fixtures_cannot_test() {
        let (_root, project) = initialized("standalone-exact-time");
        let fixtures = project.join(FIXTURES_DIRECTORY);
        for entry in fs::read_dir(&fixtures).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        // An empty directory and a missing one are the same authoring gap.
        for _ in 0..2 {
            let error = test(&project).unwrap_err();
            assert_eq!(
                refusals(&project, &error),
                ["fixtures  scheduling.fixture.none"]
            );
            // A check has nothing to replay, so it passes.
            assert_eq!(check(&project, false).unwrap()["filesChecked"], 2);
            fs::remove_dir(&fixtures).unwrap_or(());
        }
    }

    #[test]
    fn a_missing_policy_is_a_reading_failure_naming_the_file() {
        let root = tempfile::tempdir().unwrap();
        let error = check(&root.path().join("nowhere"), false).unwrap_err();
        assert!(crate::configuration_report(&error).is_none());
        let message = format!("{error:#}");
        assert!(message.contains("nowhere"), "{message}");
        assert!(message.contains(AUTHORED_POLICY_FILE), "{message}");
        assert!(error
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some()));
    }

    #[test]
    fn check_runtime_config_names_the_runtime_file_as_given() {
        // The loader refuses a path through a symbolic link, and the system
        // temporary directory is one on some hosts.
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().canonicalize().unwrap();
        let project = root.join("project");
        init(&project, "standalone-exact-time").unwrap();
        let runtime = root.join("runtime.yaml");
        let example = fs::read_to_string(project.join("runtime.example.yaml")).unwrap();
        fs::write(&runtime, &example).unwrap();
        let checked =
            check_runtime_config(&project, &runtime, false, false, check(&project, false)).unwrap();
        assert_eq!(checked["runtimeConfig"], runtime.display().to_string());
        assert_eq!(checked["filesChecked"], 5);

        fs::write(
            &runtime,
            example.replacen("retention:\n", "retention:\n  stray: 1\n", 1),
        )
        .unwrap();
        let error = check_runtime_config(&project, &runtime, false, false, check(&project, false))
            .unwrap_err();
        let refused = refusals(&root, &error);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].starts_with("runtime.yaml:")
                && refused[0].ends_with(" /retention/stray config.unknown-key"),
            "{refused:?}"
        );
        // The refusal still counts the project files the check read.
        let report = crate::configuration_report(&error).unwrap();
        assert_eq!(report.files_checked(), Some(5));
    }
}
