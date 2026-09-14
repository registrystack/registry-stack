// SPDX-License-Identifier: Apache-2.0

//! Project loading and the offline init, check, test, and explain reports.
//!
//! Everything here runs without a network, a database, or a clock: the
//! authored policy and its fixtures are read from the project directory,
//! checked and replayed through the pure core, and rendered as one JSON
//! report per command.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use registry_scheduling_core::{
    parse_fixture_yaml, parse_policy_yaml, CaseStatus, SchedulingDiagnostic, SchedulingFixture,
    SchedulingPolicy, AUTHORED_POLICY_FILE,
};
use serde_json::{json, Value};

use crate::templates;

/// The largest policy or fixture an authoring project may carry.
const MAXIMUM_INPUT_BYTES: usize = 1024 * 1024;

/// The directory an authored project keeps its replay fixtures in.
const FIXTURES_DIRECTORY: &str = "fixtures";

pub(super) fn init(project: &Path, template: &str) -> Result<Value> {
    let Some(files) = templates::template_files(template) else {
        bail!(
            "unknown template {template:?}; available templates: standalone-exact-time, standalone-arrival-window"
        );
    };
    match fs::symlink_metadata(project) {
        Ok(_) => bail!("destination already exists; init never overwrites a project"),
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
        "next": ["Run schedulingctl check PROJECT, then schedulingctl test PROJECT."],
    }))
}

pub(super) fn check(project: &Path) -> Result<Value> {
    let policy = load_policy(project)?;
    let findings = policy.check();
    let status = if findings.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    Ok(json!({
        "ok": true,
        "command": "check",
        "status": status,
        "project": project,
        "findings": findings_json(&findings),
        "effective": effective(&policy),
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

pub(super) fn test(project: &Path) -> Result<Value> {
    let policy = load_policy(project)?;
    let findings = policy.check();
    let authoring_status = if findings.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    let fixture_dir = project.join(FIXTURES_DIRECTORY);
    let mut paths = fs::read_dir(&fixture_dir)
        .context("reading fixtures directory")?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("yaml"))
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        bail!("test requires at least one YAML fixture");
    }
    let mut reports = Vec::new();
    for path in paths {
        reports.push(run_fixture(project, &policy, &path)?);
    }
    Ok(json!({
        "ok": true,
        "command": "test",
        "project": project,
        "authoringStatus": authoring_status,
        "findings": findings_json(&findings),
        "fixtures": reports,
        "proofBoundary": "offline_synthetic",
        "productionClosure": false,
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

pub(super) fn explain(project: &Path) -> Result<Value> {
    let policy = load_policy(project)?;
    let findings = policy.check();
    if !findings.is_empty() {
        bail!(
            "explain requires a policy that passes its check; run schedulingctl check first. Findings: {}",
            findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
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
    let windows = policy
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
        "scheduling": {
            "id": policy.scheduling.id,
            "version": policy.scheduling.version,
        },
        "policyDigest": policy.policy_digest(),
        "offerings": offerings,
        "windows": windows,
        "holdPolicy": {
            "ttlMinutes": policy.hold_policy.ttl_minutes,
            "maxPerCaller": policy.hold_policy.max_per_caller,
            "because": policy.hold_policy.because,
        },
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

fn run_fixture(project: &Path, policy: &SchedulingPolicy, path: &Path) -> Result<Value> {
    let relative: PathBuf = path.strip_prefix(project).unwrap_or(path).to_owned();
    let fixture = load_fixture(path)?;
    let outcomes = fixture
        .replay(policy)
        .with_context(|| format!("replaying fixture {}", relative.display()))?;
    let cases = outcomes
        .iter()
        .map(|outcome| {
            json!({
                "name": outcome.name,
                "status": outcome.status.as_str(),
                "detail": outcome.detail,
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

fn load_policy(project: &Path) -> Result<SchedulingPolicy> {
    let bytes = read_authoring_input(&project.join(AUTHORED_POLICY_FILE))?;
    parse_policy_yaml(&bytes).with_context(|| format!("parsing {AUTHORED_POLICY_FILE}"))
}

fn load_fixture(path: &Path) -> Result<SchedulingFixture> {
    let bytes = read_authoring_input(path)?;
    parse_fixture_yaml(&bytes).with_context(|| format!("parsing fixture {}", path.display()))
}

fn read_authoring_input(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > MAXIMUM_INPUT_BYTES {
        bail!("{} exceeds the one MiB authoring limit", path.display());
    }
    String::from_utf8(bytes).with_context(|| format!("reading {}", path.display()))
}

/// Every check finding as its path and closed reason, ready for a report.
fn findings_json(findings: &[SchedulingDiagnostic]) -> Vec<Value> {
    findings
        .iter()
        .map(|finding| json!({"path": finding.path, "reason": finding.reason.as_str()}))
        .collect()
}

/// The effective policy a check saw: identity, digest, collection sizes and
/// identifiers, and the hold policy.
fn effective(policy: &SchedulingPolicy) -> Value {
    fn summary<'a>(ids: impl Iterator<Item = &'a String>) -> Value {
        let all: Vec<&str> = ids.map(String::as_str).collect();
        json!({"count": all.len(), "ids": all})
    }
    json!({
        "schedulingId": policy.scheduling.id,
        "schedulingVersion": policy.scheduling.version,
        "policyDigest": policy.policy_digest(),
        "services": summary(policy.services.iter().map(|service| &service.id)),
        "offerings": summary(policy.offerings.iter().map(|offering| &offering.id)),
        "openings": summary(policy.openings.iter().map(|opening| &opening.id)),
        "windows": summary(policy.windows.iter().map(|window| &window.id)),
        "holdPolicy": {
            "ttlMinutes": policy.hold_policy.ttl_minutes,
            "maxPerCaller": policy.hold_policy.max_per_caller,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tempdir holding one freshly initialized template project, plus the
    /// paths the tempdir keeps alive.
    fn initialized(template: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        init(&project, template).unwrap();
        (root, project)
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
            json!(["scheduling.yaml", "fixtures/household-morning.yaml"])
        );
        assert!(project.join(AUTHORED_POLICY_FILE).is_file());
        assert!(project.join("fixtures/household-morning.yaml").is_file());
        let error = init(&project, "standalone-arrival-window").unwrap_err();
        assert!(error.to_string().contains("never overwrites"));
        let error = init(&root.path().join("other"), "no-such-template").unwrap_err();
        assert!(error.to_string().contains("standalone-arrival-window"));
    }

    #[test]
    fn check_reports_the_effective_policy_and_no_findings_for_a_template() {
        let (_root, project) = initialized("standalone-exact-time");
        let report = check(&project).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["command"], "check");
        assert_eq!(report["status"], "complete");
        assert_eq!(report["findings"], json!([]));
        assert_eq!(report["networkAccess"], false);
        assert_eq!(report["databaseAccess"], false);
        let effective = &report["effective"];
        assert_eq!(effective["schedulingId"], "registry-updates");
        assert_eq!(effective["schedulingVersion"], 1);
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
        assert_eq!(effective["holdPolicy"]["maxPerCaller"], 3);
    }

    #[test]
    fn a_policy_because_breach_is_a_finding_pair_with_an_incomplete_status() {
        let (_root, project) = initialized("standalone-arrival-window");
        let policy_path = project.join(AUTHORED_POLICY_FILE);
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "because: The hall opens on Saturday mornings.",
            "because:  ",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();
        let report = check(&project).unwrap();
        assert_eq!(report["status"], "incomplete");
        assert_eq!(
            report["findings"],
            json!([{"path": "openings[0].because", "reason": "invalid-because"}])
        );
    }

    #[test]
    fn test_reports_per_fixture_and_per_case_outcomes_with_the_proof_boundary() {
        let (_root, project) = initialized("standalone-exact-time");
        let report = test(&project).unwrap();
        assert_eq!(report["command"], "test");
        assert_eq!(report["authoringStatus"], "complete");
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
    fn an_incomplete_policy_still_runs_its_fixtures_and_reports_the_status() {
        let (_root, project) = initialized("standalone-arrival-window");
        let policy_path = project.join(AUTHORED_POLICY_FILE);
        // A blank because fails the check but never changes what replay does.
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "because: The hall opens on Saturday mornings.",
            "because:  ",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();
        let report = test(&project).unwrap();
        assert_eq!(report["authoringStatus"], "incomplete");
        assert_eq!(
            report["findings"],
            json!([{"path": "openings[0].because", "reason": "invalid-because"}])
        );
        assert!(report["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .all(|fixture| fixture["status"] == "passed"));
    }

    #[test]
    fn explain_publishes_offerings_windows_hold_policy_and_digest() {
        let (_root, project) = initialized("standalone-arrival-window");
        let report = explain(&project).unwrap();
        assert_eq!(report["command"], "explain");
        assert_eq!(
            report["scheduling"],
            json!({"id": "household-days", "version": 3})
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
        assert_eq!(windows[0]["unitsPolicy"]["kind"], "perRecipient");
        assert_eq!(
            windows[0]["unitsPolicy"]["subquotas"],
            json!([{"channel": "public", "units": 2}, {"channel": "assisted", "units": 1}])
        );
        assert_eq!(report["holdPolicy"]["ttlMinutes"], 10);
        assert_eq!(report["holdPolicy"]["maxPerCaller"], 2);
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
        let (_root, project) = initialized("standalone-exact-time");
        let policy_path = project.join(AUTHORED_POLICY_FILE);
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "version: 1\n",
            "version: 0\n",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();
        let error = explain(&project).unwrap_err();
        assert!(error.to_string().contains("passes its check"));
    }

    #[test]
    fn a_project_without_fixtures_cannot_test() {
        let (_root, project) = initialized("standalone-exact-time");
        // An empty fixtures directory is the authoring error; a missing one is
        // a filesystem failure the CLI reports separately.
        let fixtures = project.join(FIXTURES_DIRECTORY);
        for entry in std::fs::read_dir(&fixtures).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let error = test(&project).unwrap_err();
        assert!(error.to_string().contains("at least one YAML fixture"));
    }

    #[test]
    fn a_missing_or_unparsable_policy_is_a_reading_failure() {
        let root = tempfile::tempdir().unwrap();
        let error = check(&root.path().join("nowhere")).unwrap_err();
        assert!(error.to_string().contains("nowhere"));
        assert!(error.to_string().contains("scheduling.yaml"));

        let project = root.path().join("project");
        init(&project, "standalone-exact-time").unwrap();
        let policy_path = project.join(AUTHORED_POLICY_FILE);
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "windows: []\n",
            "windows: []\nsurprise: true\n",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();
        let error = check(&project).unwrap_err();
        assert!(error.to_string().contains("parsing scheduling.yaml"));
    }
}
