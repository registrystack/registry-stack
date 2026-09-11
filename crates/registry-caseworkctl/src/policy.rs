// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use registry_casework_core::{
    check_routing_policy, evaluate_activity_clock, evaluate_routing, evaluate_subject_clock,
    CaseworkProject, ClockPolicy, HolidaySetDocument, ReviewTiming, RoutingActivity,
    RoutingContext, RoutingFieldDescriptor, RoutingSourceMetadata, SourcePolicy,
    SourceRequestPolicy,
};
use serde::Deserialize;
use serde_json::{json, Value};

const MAXIMUM_SOURCE_DESCRIPTION_BYTES: usize = 1024 * 1024;

/// Compile source metadata against authored routing. Runtime startup, explain,
/// and simulation use this same boundary.
pub(super) fn check(project: &Path, policy: &CaseworkProject) -> Result<()> {
    let queues = policy
        .queues
        .iter()
        .map(|queue| queue.id.clone())
        .collect::<BTreeSet<_>>();
    for source in &policy.sources {
        let description = load_source_description(project, source)?;
        for request in &source.requests {
            let metadata = metadata_for_request(&description, request)?;
            check_routing_policy(
                &request.queue,
                &request.projection,
                &request.routing,
                &queues,
                Some(&metadata),
            )
            .with_context(|| request_path(source, request))?;
        }
    }
    Ok(())
}

pub(super) fn explain(project: &Path, policy: &CaseworkProject) -> Result<Value> {
    check(project, policy)?;
    let mut requests = Vec::new();
    for source in &policy.sources {
        let description = load_source_description(project, source)?;
        for request in &source.requests {
            let metadata = metadata_for_request(&description, request)?;
            requests.push(json!({
                "source": source.id,
                "entity": request.entity,
                "defaultQueue": request.queue,
                "projection": request.projection,
                "routing": request.routing,
                "clock": request.clock,
                "sourceStages": metadata.stages,
                "sourceFields": metadata.fields.iter().map(|field| json!({
                    "field": field.field,
                    "apiName": field.api_name,
                })).collect::<Vec<_>>(),
            }));
        }
    }
    Ok(json!({
        "ok": true,
        "command": "explain",
        "projectId": policy.casework.id,
        "policyVersion": policy.casework.version,
        "requests": requests,
        "calendars": policy.calendars,
        "clocks": policy.clocks,
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

pub(super) fn simulate(
    project: &Path,
    policy: &CaseworkProject,
    fixture_path: &Path,
) -> Result<Value> {
    check(project, policy)?;
    let fixture: SimulationFixture = load_yaml(fixture_path, "simulation fixture")?;
    let source = policy
        .sources
        .iter()
        .find(|source| source.id == fixture.source)
        .context("fixture source is not declared")?;
    let request = source
        .requests
        .iter()
        .find(|request| request.entity == fixture.subject.entity)
        .context("fixture subject entity is not declared for the source")?;
    let description = load_source_description(project, source)?;
    let metadata = metadata_for_request(&description, request)?;
    let decision = evaluate_routing(
        &request.queue,
        &request.projection,
        &request.routing,
        &metadata,
        &RoutingContext {
            activity: fixture.subject.activity,
            stage: fixture.subject.stage.clone(),
            fields: fixture.subject.fields.clone(),
        },
    )
    .with_context(|| request_path(source, request))?;

    let mut clock_report = Value::Null;
    if let Some(clock_id) = request.clock.as_deref() {
        let clock = policy
            .clocks
            .iter()
            .find(|clock| clock.id() == clock_id)
            .context("request clock is not declared")?;
        match clock {
            ClockPolicy::Activity { calendar, .. } => {
                if fixture.subject.activity != RoutingActivity::Review {
                    bail!("an activity clock anchored to stageEnteredAt requires review activity");
                }
                let anchor = fixture
                    .subject
                    .stage_entered_at
                    .context("fixture requires subject.stageEnteredAt for its activity clock")?;
                let calendar = policy
                    .calendars
                    .iter()
                    .find(|candidate| candidate.id == *calendar)
                    .context("activity clock calendar is not declared")?;
                let revision = fixture
                    .holiday_revisions
                    .get(&calendar.holiday_set)
                    .copied()
                    .context("fixture does not pin the calendar holiday-set revision")?;
                let holiday_path =
                    holiday_fixture_path(fixture_path, &calendar.holiday_set, revision)?;
                let holidays: HolidaySetDocument = load_yaml(&holiday_path, "holiday-set fixture")?;
                let evaluated = evaluate_activity_clock(clock, calendar, &holidays, anchor)
                    .context("activity clock evaluation failed")?;
                let now = fixture.now;
                let state = if now >= evaluated.due_at {
                    "due"
                } else if evaluated.at_risk_at.is_some_and(|at| now >= at) {
                    "atRisk"
                } else {
                    "pending"
                };
                clock_report = json!({
                    "id": clock_id,
                    "dueAt": evaluated.due_at,
                    "dueState": state,
                    "atRiskAt": evaluated.at_risk_at,
                    "eligibleReminders": evaluated.reminders.iter()
                        .filter(|occurrence| now >= occurrence.at)
                        .map(|occurrence| occurrence.id.as_str())
                        .collect::<Vec<_>>(),
                    "eligibleSteps": evaluated.steps.iter()
                        .filter(|occurrence| now >= occurrence.at)
                        .map(|occurrence| occurrence.id.as_str())
                        .collect::<Vec<_>>(),
                    "calendar": calendar.id,
                    "holidaySet": holidays.holiday_set,
                    "holidayRevision": evaluated.calendar_revision,
                });
            }
            ClockPolicy::Subject { .. } => {
                let timing = fixture
                    .subject
                    .review_timing
                    .as_ref()
                    .context("fixture requires subject.reviewTiming for its subject clock")?;
                let evaluated = evaluate_subject_clock(clock, timing, fixture.now)
                    .context("subject clock evaluation failed")?;
                clock_report = json!({
                    "id": clock_id,
                    "state": evaluated.state,
                    "elapsedMilliseconds": evaluated.elapsed_milliseconds,
                    "remainingMilliseconds": evaluated.remaining_milliseconds,
                    "dueAt": evaluated.due_at,
                });
            }
        }
    }

    let report = json!({
        "ok": true,
        "command": "simulate",
        "fixture": fixture.id,
        "projectId": policy.casework.id,
        "policyVersion": policy.casework.version,
        "source": source.id,
        "subject": {"entity": fixture.subject.entity, "id": fixture.subject.id, "version": fixture.subject.version},
        "routing": decision,
        "clock": clock_report,
        "networkAccess": false,
        "databaseAccess": false,
    });
    validate_expectations(&fixture.expect, &report)?;
    Ok(report)
}

fn metadata_for_request(
    description: &Value,
    request: &SourceRequestPolicy,
) -> Result<RoutingSourceMetadata> {
    let described = &description["request"];
    if described["requestEntity"] != request.entity {
        bail!("source description request entity does not match casework.yaml");
    }
    let stages = described["stages"]
        .as_array()
        .context("source description request stages are missing")?
        .iter()
        .map(|stage| {
            stage["id"]
                .as_str()
                .map(str::to_owned)
                .context("source description stage id is invalid")
        })
        .collect::<Result<Vec<_>>>()?;
    let fields = serde_json::from_value::<Vec<RoutingFieldDescriptor>>(
        described
            .get("fields")
            .cloned()
            .context("source description request fields are missing")?,
    )
    .context("source description request fields are invalid")?;
    Ok(RoutingSourceMetadata { stages, fields })
}

fn load_source_description(project: &Path, source: &SourcePolicy) -> Result<Value> {
    let path = project.join(&source.description);
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > MAXIMUM_SOURCE_DESCRIPTION_BYTES {
        bail!("source description exceeds the one MiB authoring limit");
    }
    let description: Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    if description["apiVersion"]
        != "registry.registrystack.org/casework-source-description/v1alpha1"
        || description["kind"] != "BRegCaseworkSourceDescription"
        || description["sourceId"] != source.id
        || description["authority"] != "none"
    {
        bail!("source description is not bound to the declared source");
    }
    Ok(description)
}

fn request_path(source: &SourcePolicy, request: &SourceRequestPolicy) -> String {
    format!(
        "sources[id={}].requests[entity={}]",
        source.id, request.entity
    )
}

fn holiday_fixture_path(fixture: &Path, holiday_set: &str, revision: u64) -> Result<PathBuf> {
    let directory = fixture.parent().context("fixture path has no parent")?;
    Ok(directory
        .join("holiday-sets")
        .join(format!("{holiday_set}-{revision}.yaml")))
}

fn load_yaml<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {label} {}", path.display()))?;
    if bytes.len() > 1024 * 1024 {
        bail!("{label} exceeds the one MiB authoring limit");
    }
    serde_norway::from_slice(&bytes).with_context(|| format!("parsing {label} {}", path.display()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SimulationFixture {
    id: String,
    source: String,
    #[serde(default)]
    holiday_revisions: BTreeMap<String, u64>,
    subject: SimulationSubject,
    now: DateTime<Utc>,
    expect: SimulationExpectation,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SimulationSubject {
    entity: String,
    id: String,
    version: String,
    activity: RoutingActivity,
    #[serde(default)]
    stage: Option<String>,
    #[serde(default)]
    fields: BTreeMap<String, Value>,
    #[serde(default)]
    stage_entered_at: Option<DateTime<Utc>>,
    #[serde(default)]
    review_timing: Option<ReviewTiming>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SimulationExpectation {
    queue: String,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    due_at: Option<DateTime<Utc>>,
    #[serde(default)]
    due_state: Option<String>,
    #[serde(default)]
    eligible_reminders: Vec<String>,
    #[serde(default)]
    eligible_steps: Vec<String>,
    #[serde(default)]
    remaining_milliseconds: Option<i64>,
}

fn validate_expectations(expect: &SimulationExpectation, report: &Value) -> Result<()> {
    if report["routing"]["queue"] != expect.queue
        || report["routing"].get("ruleId")
            != expect.rule_id.as_ref().map(|value| json!(value)).as_ref()
        || expect
            .due_at
            .is_some_and(|value| report["clock"]["dueAt"] != json!(value))
        || expect
            .due_state
            .as_ref()
            .is_some_and(|value| report["clock"]["dueState"] != json!(value))
        || (report["clock"].get("eligibleReminders").is_some()
            && report["clock"]["eligibleReminders"] != json!(expect.eligible_reminders))
        || (report["clock"].get("eligibleSteps").is_some()
            && report["clock"]["eligibleSteps"] != json!(expect.eligible_steps))
        || expect
            .remaining_milliseconds
            .is_some_and(|value| report["clock"]["remainingMilliseconds"] != json!(value))
    {
        bail!("simulation result does not match the fixture expectations");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn uc2_uc4_uc5_fixture_compiles_and_uses_the_runtime_evaluators() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("sources")).unwrap();
        fs::create_dir_all(directory.path().join("fixtures/holiday-sets")).unwrap();
        fs::write(
            directory.path().join("sources/professional.json"),
            r#"{"apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1","kind":"BRegCaseworkSourceDescription","sourceId":"professional-register","authority":"none","request":{"requestEntity":"scope-correction","stages":[{"id":"technical"},{"id":"authorization"}],"fields":[{"field":"region","apiName":"region","schema":{"type":"string","enum":["north","south","islands"]}}]}}"#,
        )
        .unwrap();
        fs::write(
            directory
                .path()
                .join("fixtures/holiday-sets/office-holidays-7.yaml"),
            "holidaySet: office-holidays\nrevision: 7\ndates: [2026-09-07]\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("fixtures/friday-review.yaml"),
            r#"id: friday-review
source: professional-register
holidayRevisions: {office-holidays: 7}
subject:
  entity: scope-correction
  id: request-0042
  version: "1"
  activity: review
  stage: technical
  fields: {region: north}
  stageEnteredAt: "2026-09-04T15:00:00+07:00"
now: "2026-09-11T17:00:00+07:00"
expect:
  queue: northern-review
  ruleId: northern-requests
  dueAt: "2026-09-14T17:00:00+07:00"
  dueState: atRisk
  eligibleReminders: [due-soon]
  eligibleSteps: []
"#,
        )
        .unwrap();
        let policy: CaseworkProject = serde_norway::from_str(
            r#"apiVersion: registry.registrystack.org/casework/v1alpha1
kind: CaseworkProject
casework: {id: regional-review, version: "1"}
accessProfiles:
  - {id: staff, principalClaim: sub, requiredScopes: [staff], role: staff}
  - {id: supervisor, principalClaim: sub, requiredScopes: [supervisor], role: supervisor}
  - {id: administrator, principalClaim: sub, requiredScopes: [admin], role: administrator}
queues:
  - {id: triage, label: Triage}
  - {id: northern-review, label: Northern review}
  - {id: overdue-review, label: Overdue review}
sources:
  - id: professional-register
    adapter: breg
    description: sources/professional.json
    requests:
      - entity: scope-correction
        queue: triage
        projection: [region]
        clock: review-deadline
        routing:
          - id: northern-requests
            because: The request's governed region is north.
            when: {fields: {region: {equals: north}}}
            queue: northern-review
calendars:
  - id: office
    timezone: Asia/Bangkok
    workingWeekdays: [monday, tuesday, wednesday, thursday, friday]
    holidaySet: office-holidays
clocks:
  - id: review-deadline
    scope: activity
    anchor: stageEnteredAt
    calendar: office
    after: {workingDays: 5}
    dueTime: "17:00"
    atRisk: {workingDaysBefore: 1}
    reminders: [{id: due-soon, workingDaysBefore: 1}]
    steps:
      - id: supervisor-at-deadline
        because: The review deadline passed while the review remained active.
        at: due
        action: {reassign: {queue: overdue-review}}
"#,
        )
        .unwrap();
        policy.check().unwrap();
        let report = simulate(
            directory.path(),
            &policy,
            &directory.path().join("fixtures/friday-review.yaml"),
        )
        .unwrap();
        assert_eq!(report["routing"]["ruleId"], "northern-requests");
        assert_eq!(report["clock"]["dueState"], "atRisk");
        assert_eq!(report["clock"]["holidayRevision"], 7);
    }

    #[test]
    fn uc3_fixture_uses_authoritative_request_wide_timing() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("sources")).unwrap();
        fs::create_dir_all(directory.path().join("fixtures")).unwrap();
        fs::write(
            directory.path().join("sources/professional.json"),
            r#"{"apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1","kind":"BRegCaseworkSourceDescription","sourceId":"professional-register","authority":"none","request":{"requestEntity":"scope-correction","stages":[{"id":"review"}],"fields":[]}}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("fixtures/resubmitted-review.yaml"),
            r#"id: resubmitted-review
source: professional-register
subject:
  entity: scope-correction
  id: request-0042
  version: "2"
  activity: review
  stage: review
  reviewTiming:
    firstSubmittedAt: "2026-09-10T09:00:00+07:00"
    pausedMilliseconds: 86400000
    pauseStartedAt: null
    completedAt: null
now: "2026-09-11T13:00:00+07:00"
expect:
  queue: corrections
  dueAt: "2026-09-13T09:00:00+07:00"
  remainingMilliseconds: 158400000
"#,
        )
        .unwrap();
        let policy: CaseworkProject = serde_norway::from_str(
            r#"apiVersion: registry.registrystack.org/casework/v1alpha1
kind: CaseworkProject
casework: {id: response-budget, version: "1"}
accessProfiles:
  - {id: staff, principalClaim: sub, requiredScopes: [staff], role: staff}
  - {id: supervisor, principalClaim: sub, requiredScopes: [supervisor], role: supervisor}
  - {id: administrator, principalClaim: sub, requiredScopes: [admin], role: administrator}
queues: [{id: corrections, label: Corrections}]
sources:
  - id: professional-register
    adapter: breg
    description: sources/professional.json
    requests:
      - {entity: scope-correction, queue: corrections, clock: response-budget}
clocks:
  - id: response-budget
    scope: subject
    anchor: firstSubmittedAt
    completeOn: reviewCompleted
    after: {elapsed: PT48H}
    pauseWhile: [awaitingApplicant]
"#,
        )
        .unwrap();
        policy.check().unwrap();
        let report = simulate(
            directory.path(),
            &policy,
            &directory.path().join("fixtures/resubmitted-review.yaml"),
        )
        .unwrap();
        assert_eq!(report["clock"]["remainingMilliseconds"], 158_400_000);
        assert_eq!(report["clock"]["dueAt"], "2026-09-13T02:00:00Z");
    }
}
