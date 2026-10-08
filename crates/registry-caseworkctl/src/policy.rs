// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use registry_casework_core::{
    evaluate_activity_clock, evaluate_routing, evaluate_subject_clock, routing_policy_findings,
    CaseworkProject, CaseworkSimulation, ClockPolicy, ClockPolicyError, ConfigFinding, DueState,
    HolidaySetDocument, RoutingDecision, RoutingDiagnosticReason, RoutingFieldDescriptor,
    RoutingSourceMetadata, SourcePolicy, SourceRequestPolicy, NO_RULE,
};
use registry_platform_yaml::{Decoded, Diagnostic, Document, LocalId, Severity};
use serde_json::{json, Value};

use crate::display_schema::{json_types, render_types};
use crate::offline::{admits, json_type, project_related};

pub(crate) const MAXIMUM_SOURCE_DESCRIPTION_BYTES: usize = 1024 * 1024;

/// Compile one source's metadata against its authored routing, placing each
/// finding under `/sources/{index}/requests/{n}` in `casework.yaml`. Runtime
/// startup, check, explain, and simulation use this same boundary.
pub(super) fn routing_findings(
    project: &Path,
    policy: &CaseworkProject,
    index: usize,
) -> Result<Vec<ConfigFinding>> {
    let queues = policy
        .queues
        .iter()
        .map(|queue| queue.id.clone())
        .collect::<BTreeSet<_>>();
    let source = &policy.sources[index];
    let description = load_source_description(project, source)?;
    let mut findings = Vec::new();
    for (request_index, request) in source.requests.iter().enumerate() {
        let metadata = metadata_for_request(&description, request)?;
        findings.extend(
            routing_policy_findings(
                &request.queue,
                &request.projection,
                &request.routing,
                &queues,
                Some(&metadata),
            )
            .into_iter()
            .map(|routing| {
                ConfigFinding::new(
                    routing.reason.code(),
                    format!("/sources/{index}/requests/{request_index}{}", routing.path),
                    routing.reason.message(),
                    routing.reason.suggested_action(),
                )
            }),
        );
    }
    Ok(findings)
}

/// Explain a project `check_source_descriptions` already accepted.
pub(super) fn explain(project: &Path, policy: &CaseworkProject) -> Result<Value> {
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
        "accessProfiles": policy.access_profiles,
        "queues": policy.queues,
        "reviewKinds": policy.review_kinds,
        "calendars": policy.calendars,
        "clocks": policy.clocks,
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

const SIMULATION_NOT_MET: &str = "casework.simulation.expectation-not-met";
const NOT_MET_ACTION: &str = "Remove the member, run caseworkctl simulate on this file to read the value the project computes, and write it back if it is the one you expect; otherwise change the subject or casework.yaml.";

/// What one simulation computes, and each expectation it does not meet.
pub(crate) struct SimulationOutcome {
    pub report: Value,
    pub failures: Vec<Diagnostic>,
}

/// The source, request, and request pointer a simulation names, once
/// `crate::offline::resolve` has accepted it.
fn simulated_request<'a>(
    policy: &'a CaseworkProject,
    simulation: &CaseworkSimulation,
) -> Option<(&'a SourcePolicy, &'a SourceRequestPolicy, String)> {
    let source_index = policy
        .sources
        .iter()
        .position(|source| source.id == simulation.source.as_str())?;
    let source = &policy.sources[source_index];
    let request_index = source
        .requests
        .iter()
        .position(|request| request.entity == simulation.subject.entity.as_str())?;
    Some((
        source,
        &source.requests[request_index],
        format!("/sources/{source_index}/requests/{request_index}"),
    ))
}

/// Check a simulation's subject against the source description of the
/// request it names: the stage its activity allows and each field value
/// against the field's schema (CFG-VAL-9). A simulation whose source
/// description is not imported yet is left to `test`.
pub(crate) fn simulation_input_diagnostics(
    project_dir: &Path,
    project: &Decoded<CaseworkProject>,
    simulation: &Decoded<CaseworkSimulation>,
) -> Result<Vec<Diagnostic>> {
    let Some((source, request, request_at)) = simulated_request(&project.value, &simulation.value)
    else {
        return Ok(Vec::new());
    };
    if !project_dir.join(&source.description).is_file() {
        return Ok(Vec::new());
    }
    let description = load_source_description(project_dir, source)?;
    let metadata = metadata_for_request(&description, request)?;
    Ok(route(project, simulation, request, &request_at, &metadata)
        .err()
        .into_iter()
        .map(|diagnostic| *diagnostic)
        .collect())
}

/// Route the simulated subject with the runtime's evaluator, placing a
/// refusal at the subject member the runtime would have refused.
fn route(
    project: &Decoded<CaseworkProject>,
    simulation: &Decoded<CaseworkSimulation>,
    request: &SourceRequestPolicy,
    request_at: &str,
    metadata: &RoutingSourceMetadata,
) -> std::result::Result<RoutingDecision, Box<Diagnostic>> {
    let document = &simulation.document;
    let error = match evaluate_routing(
        &request.queue,
        &request.projection,
        &request.routing,
        metadata,
        &simulation.value.subject.routing_context(),
    ) {
        Ok(decision) => return Ok(decision),
        Err(error) => error,
    };
    if error.path == "/source/stage" {
        let pointer = if simulation.value.subject.stage.is_some() {
            "/subject/stage"
        } else {
            "/subject"
        };
        return Err(Box::new(document.diagnostic_at_value(
            Severity::Error,
            "casework.simulation.stage-mismatch",
            pointer,
            "the subject's stage does not fit its activity: a record under review is in a stage, and a record being applied is in none",
            "Write subject.stage for activity: review, and no stage for activity: apply.",
        )));
    }
    if let Some(field) = error.path.strip_prefix("/source/fields/") {
        let pointer = format!("/subject/fields/{field}");
        if error.reason == RoutingDiagnosticReason::UnknownField {
            let mut diagnostic = document.diagnostic_at_key(
                Severity::Error,
                "casework.simulation.unknown-field",
                &pointer,
                "the source description declares no usable schema for this field",
                "Use a field the source description lists, or import a description that declares it.",
            );
            diagnostic.related.push(project_related(
                project,
                &format!("{request_at}/projection"),
                "the request projects its fields here",
            ));
            return Err(Box::new(diagnostic));
        }
        let name = field.replace("~1", "/").replace("~0", "~");
        let declared = metadata
            .fields
            .iter()
            .find(|descriptor| descriptor.field == name)
            .and_then(|descriptor| json_types(&descriptor.schema));
        let written = simulation
            .value
            .subject
            .fields
            .iter()
            .find(|(key, _)| key.as_str() == name)
            .and_then(|(_, value)| serde_json::to_value(value).ok());
        let message = match (declared, written) {
            (Some(types), Some(written)) if !admits(&types, json_type(&written)) => format!(
                "the source description declares this field as {}, and it is written as {}",
                render_types(&types),
                json_type(&written)
            ),
            _ => "this value is outside what the source description's schema allows for the field"
                .to_owned(),
        };
        return Err(Box::new(document.diagnostic_at_value(
            Severity::Error,
            "casework.simulation.field-mismatch",
            &pointer,
            &message,
            "Write a value the field's schema in the source description allows.",
        )));
    }
    let mut diagnostic = document.diagnostic_at_value(
        Severity::Error,
        error.reason.code(),
        "/source",
        error.reason.message(),
        error.reason.suggested_action(),
    );
    diagnostic.related.push(project_related(
        project,
        &format!("{request_at}{}", error.path),
        "the request's routing is declared here",
    ));
    Err(Box::new(diagnostic))
}

/// Evaluate one simulation `crate::offline::resolve` accepted with the
/// runtime's routing and clock evaluators, against the holiday-set
/// revisions it pins.
pub(crate) fn simulate(
    project_dir: &Path,
    project: &Decoded<CaseworkProject>,
    simulation: &Decoded<CaseworkSimulation>,
    holidays: &BTreeMap<(String, u64), HolidaySetDocument>,
) -> Result<SimulationOutcome> {
    let policy = &project.value;
    let document = &simulation.document;
    let value = &simulation.value;
    let (source, request, request_at) =
        simulated_request(policy, value).context("the simulation names no declared request")?;
    let mut failures = Vec::new();
    if !project_dir.join(&source.description).is_file() {
        let mut diagnostic = document.diagnostic_at_value(
            Severity::Error,
            crate::project::MISSING_SOURCE_DESCRIPTION,
            "/source",
            "the source description routing reads is not imported",
            "Import the source description with caseworkctl source add.",
        );
        let index = request_at.split('/').nth(2).unwrap_or_default().to_owned();
        diagnostic.related.push(project_related(
            project,
            &format!("/sources/{index}/description"),
            "the source names its description here",
        ));
        failures.push(diagnostic);
        return Ok(SimulationOutcome {
            report: Value::Null,
            failures,
        });
    }
    let description = load_source_description(project_dir, source)?;
    let metadata = metadata_for_request(&description, request)?;
    let decision = match route(project, simulation, request, &request_at, &metadata) {
        Ok(decision) => decision,
        Err(diagnostic) => {
            failures.push(*diagnostic);
            return Ok(SimulationOutcome {
                report: Value::Null,
                failures,
            });
        }
    };
    let now = value.now.get();
    let expect = &value.expect;
    let mut clock_report = Value::Null;
    if let Some(clock_id) = request.clock.as_deref() {
        let clock_index = policy
            .clocks
            .iter()
            .position(|clock| clock.id() == clock_id)
            .context("the request's clock is not declared")?;
        let clock = &policy.clocks[clock_index];
        match clock {
            ClockPolicy::Activity { calendar, .. } => {
                let calendar = policy
                    .calendars
                    .iter()
                    .find(|candidate| candidate.id == *calendar)
                    .context("the activity clock's calendar is not declared")?;
                let revision = value
                    .holiday_revisions
                    .iter()
                    .find(|(pinned, _)| pinned.as_str() == calendar.holiday_set)
                    .map(|(_, revision)| revision.get())
                    .context("the simulation pins no revision of the calendar's holiday set")?;
                let holidays = holidays
                    .get(&(calendar.holiday_set.clone(), revision))
                    .context("no holiday-set file holds the pinned revision")?;
                let anchor = value
                    .subject
                    .stage_entered_at
                    .context("the simulation states no subject.stageEnteredAt")?
                    .get();
                let evaluated = match evaluate_activity_clock(clock, calendar, holidays, anchor) {
                    Ok(evaluated) => evaluated,
                    Err(error) => {
                        failures.push(clock_failed(
                            project,
                            document,
                            "/subject/stageEnteredAt",
                            clock_index,
                            &error,
                        ));
                        return Ok(SimulationOutcome {
                            report: Value::Null,
                            failures,
                        });
                    }
                };
                let state = if now >= evaluated.due_at {
                    DueState::Due
                } else if evaluated.at_risk_at.is_some_and(|at| now >= at) {
                    DueState::AtRisk
                } else {
                    DueState::Pending
                };
                let reminders = evaluated
                    .reminders
                    .iter()
                    .filter(|occurrence| now >= occurrence.at)
                    .map(|occurrence| occurrence.id.as_str())
                    .collect::<Vec<_>>();
                let steps = evaluated
                    .steps
                    .iter()
                    .filter(|occurrence| now >= occurrence.at)
                    .map(|occurrence| occurrence.id.as_str())
                    .collect::<Vec<_>>();
                let clock_at = format!("/clocks/{clock_index}");
                if expect
                    .due_at
                    .is_some_and(|due_at| due_at.get() != evaluated.due_at)
                {
                    failures.push(not_met(
                        project,
                        document,
                        "/expect/dueAt",
                        "the clock falls due at another instant",
                        &clock_at,
                    ));
                }
                if expect.due_state.is_some_and(|expected| expected != state) {
                    failures.push(not_met(
                        project,
                        document,
                        "/expect/dueState",
                        "the clock is in another state at now",
                        &clock_at,
                    ));
                }
                if expect
                    .eligible_reminders
                    .as_ref()
                    .is_some_and(|expected| !same_ids(expected, &reminders))
                {
                    failures.push(not_met(
                        project,
                        document,
                        "/expect/eligibleReminders",
                        "another set of reminders is eligible at now",
                        &format!("{clock_at}/reminders"),
                    ));
                }
                if expect
                    .eligible_steps
                    .as_ref()
                    .is_some_and(|expected| !same_ids(expected, &steps))
                {
                    failures.push(not_met(
                        project,
                        document,
                        "/expect/eligibleSteps",
                        "another set of steps is eligible at now",
                        &format!("{clock_at}/steps"),
                    ));
                }
                clock_report = json!({
                    "id": clock_id,
                    "dueAt": evaluated.due_at,
                    "dueState": match state {
                        DueState::Due => "due",
                        DueState::AtRisk => "atRisk",
                        DueState::Pending => "pending",
                    },
                    "atRiskAt": evaluated.at_risk_at,
                    "eligibleReminders": reminders,
                    "eligibleSteps": steps,
                    "calendar": calendar.id,
                    "holidaySet": holidays.holiday_set,
                    "holidayRevision": evaluated.calendar_revision,
                });
            }
            ClockPolicy::Subject { .. } => {
                let timing = value
                    .subject
                    .review_timing
                    .as_ref()
                    .context("the simulation states no subject.reviewTiming")?
                    .to_timing();
                let evaluated = match evaluate_subject_clock(clock, &timing, now) {
                    Ok(evaluated) => evaluated,
                    Err(error) => {
                        failures.push(clock_failed(
                            project,
                            document,
                            "/subject/reviewTiming",
                            clock_index,
                            &error,
                        ));
                        return Ok(SimulationOutcome {
                            report: Value::Null,
                            failures,
                        });
                    }
                };
                let clock_at = format!("/clocks/{clock_index}");
                if expect
                    .due_at
                    .is_some_and(|due_at| Some(due_at.get()) != evaluated.due_at)
                {
                    failures.push(not_met(
                        project,
                        document,
                        "/expect/dueAt",
                        "the clock falls due at another instant, or has no due instant at now",
                        &clock_at,
                    ));
                }
                if expect.remaining_milliseconds.is_some_and(|remaining| {
                    i64::try_from(remaining.get()).ok() != Some(evaluated.remaining_milliseconds)
                }) {
                    failures.push(not_met(
                        project,
                        document,
                        "/expect/remainingMilliseconds",
                        "the clock has another budget left at now",
                        &clock_at,
                    ));
                }
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
    if decision.queue != expect.queue.as_str() {
        let declared_at = match decision.rule_id.as_deref() {
            Some(rule) => request
                .routing
                .iter()
                .position(|declared| declared.id == rule)
                .map_or_else(
                    || format!("{request_at}/routing"),
                    |index| format!("{request_at}/routing/{index}/queue"),
                ),
            None => format!("{request_at}/queue"),
        };
        failures.push(not_met(
            project,
            document,
            "/expect/queue",
            "the project routes this subject to another queue",
            &declared_at,
        ));
    }
    if let Some(rule) = &expect.rule {
        let expected = (rule.as_str() != NO_RULE).then_some(rule.as_str());
        if decision.rule_id.as_deref() != expected {
            let message = match (expected, decision.rule_id.is_some()) {
                (None, _) => "a routing rule matches this subject",
                (Some(_), false) => "no routing rule matches this subject",
                (Some(_), true) => "another routing rule matches this subject first",
            };
            failures.push(not_met(
                project,
                document,
                "/expect/rule",
                message,
                &format!("{request_at}/routing"),
            ));
        }
    }
    let report = json!({
        "ok": true,
        "command": "simulate",
        "fixture": value.id,
        "projectId": policy.casework.id,
        "policyVersion": policy.casework.version,
        "source": source.id,
        "subject": {
            "entity": value.subject.entity,
            "id": value.subject.record_id,
            "version": value.subject.version,
        },
        "routing": decision,
        "clock": clock_report,
        "networkAccess": false,
        "databaseAccess": false,
    });
    Ok(SimulationOutcome { report, failures })
}

fn same_ids(expected: &[LocalId], computed: &[&str]) -> bool {
    expected
        .iter()
        .map(LocalId::as_str)
        .collect::<BTreeSet<_>>()
        == computed.iter().copied().collect::<BTreeSet<_>>()
}

fn not_met(
    project: &Decoded<CaseworkProject>,
    document: &Document,
    pointer: &str,
    message: &str,
    declared_at: &str,
) -> Diagnostic {
    let mut diagnostic = document.diagnostic_at_value(
        Severity::Error,
        SIMULATION_NOT_MET,
        pointer,
        message,
        NOT_MET_ACTION,
    );
    diagnostic.related.push(project_related(
        project,
        declared_at,
        "the project computes this from the declaration here",
    ));
    diagnostic
}

fn clock_failed(
    project: &Decoded<CaseworkProject>,
    document: &Document,
    pointer: &str,
    clock_index: usize,
    error: &ClockPolicyError,
) -> Diagnostic {
    let mut diagnostic = document.diagnostic_at_value(
        Severity::Error,
        "casework.simulation.clock-failed",
        pointer,
        &format!("the request's clock cannot be evaluated from this input: {error}"),
        "Change this input or the clock in casework.yaml so the clock falls due within its bounds.",
    );
    diagnostic.related.push(project_related(
        project,
        &format!("/clocks/{clock_index}"),
        "the request's clock is declared here",
    ));
    diagnostic
}

pub(crate) fn metadata_for_request(
    description: &Value,
    request: &SourceRequestPolicy,
) -> Result<RoutingSourceMetadata> {
    let described = match description.get("requests").and_then(Value::as_array) {
        Some(requests) => requests
            .iter()
            .find(|described| described["requestEntity"] == request.entity)
            .context("source description does not describe a request entity in casework.yaml")?,
        None => &description["request"],
    };
    if described["requestEntity"] != request.entity {
        bail!("source description request entity does not match casework.yaml");
    }
    let stages = described
        .get("stages")
        .map(|stages| {
            stages
                .as_array()
                .context("source description request stages are invalid")?
                .iter()
                .map(|stage| {
                    stage["id"]
                        .as_str()
                        .map(str::to_owned)
                        .context("source description stage id is invalid")
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let fields = serde_json::from_value::<Vec<RoutingFieldDescriptor>>(
        described
            .get("fields")
            .cloned()
            .context("source description request fields are missing")?,
    )
    .context("source description request fields are invalid")?;
    Ok(RoutingSourceMetadata { stages, fields })
}

pub(crate) fn load_source_description(project: &Path, source: &SourcePolicy) -> Result<Value> {
    let path = project.join(&source.description);
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > MAXIMUM_SOURCE_DESCRIPTION_BYTES {
        bail!("source description exceeds the one MiB authoring limit");
    }
    let description: Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    let request_member = match description["apiVersion"].as_str() {
        Some("registry.registrystack.org/casework-source-description/v1alpha1") => "request",
        Some("registry.registrystack.org/casework-source-description/v1alpha2") => "requests",
        _ => bail!("source description is not bound to the declared source"),
    };
    if description.get(request_member).is_none()
        || description["kind"] != "BRegCaseworkSourceDescription"
        || description["sourceId"] != source.id
        || description["authority"] != "none"
    {
        bail!("source description is not bound to the declared source");
    }
    Ok(description)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn a_requests_description_supplies_each_declared_entity_its_own_metadata() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("sources")).unwrap();
        fs::write(
            directory.path().join("sources/farmers.json"),
            r#"{"apiVersion":"registry.registrystack.org/casework-source-description/v1alpha2","kind":"BRegCaseworkSourceDescription","sourceId":"farmers","authority":"none","requests":[{"requestEntity":"correction","stages":[{"id":"technical"}],"fields":[]},{"requestEntity":"renewal","stages":[{"id":"renewal-review"}],"fields":[]}]}"#,
        )
        .unwrap();
        let source: SourcePolicy = serde_norway::from_str(
            "id: farmers\nadapter: breg\ndescription: sources/farmers.json\nrequests:\n  - {entity: correction, queue: triage}\n  - {entity: renewal, queue: triage}\n",
        )
        .unwrap();
        let description = load_source_description(directory.path(), &source).unwrap();

        let stages = source
            .requests
            .iter()
            .map(|request| metadata_for_request(&description, request).unwrap().stages)
            .collect::<Vec<_>>();
        assert_eq!(stages, [vec!["technical"], vec!["renewal-review"]]);

        let mut undeclared = source.requests[0].clone();
        undeclared.entity = "transfer".to_owned();
        assert!(metadata_for_request(&description, &undeclared).is_err());
    }

    /// Read the simulation at `relative` the way `caseworkctl simulate`
    /// does, resolve it against the project, and evaluate it.
    fn run(directory: &Path, project: &[u8], relative: &str) -> SimulationOutcome {
        let project = CaseworkProject::read("casework.yaml", project).unwrap();
        let files = crate::offline::read_simulation_file(&directory.join(relative)).unwrap();
        let resolved = crate::offline::resolve(&project, &files);
        assert!(resolved.is_empty(), "{}", resolved.render_human());
        simulate(
            directory,
            &project,
            &files.simulations[0].decoded,
            &files.holiday_documents(),
        )
        .unwrap()
    }

    const REGIONAL_PROJECT: &str = r#"apiVersion: registry.registrystack.org/casework/v1alpha1
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
"#;

    const FRIDAY_REVIEW: &str = r#"apiVersion: id.registrystack.org/formats/casework/simulation/v1alpha1
kind: CaseworkSimulation
id: friday-review
source: professional-register
holidayRevisions: {office-holidays: 7}
subject:
  entity: scope-correction
  recordId: request-0042
  version: "1"
  activity: review
  stage: technical
  fields: {region: north}
  stageEnteredAt: "2026-09-04T15:00:00+07:00"
now: "2026-09-11T17:00:00+07:00"
expect:
  queue: northern-review
  rule: northern-requests
  dueAt: "2026-09-14T17:00:00+07:00"
  dueState: at-risk
  eligibleReminders: [due-soon]
  eligibleSteps: []
"#;

    fn regional_directory(simulation: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("sources")).unwrap();
        fs::create_dir_all(directory.path().join("simulations/holiday-sets")).unwrap();
        fs::write(
            directory.path().join("sources/professional.json"),
            r#"{"apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1","kind":"BRegCaseworkSourceDescription","sourceId":"professional-register","authority":"none","request":{"requestEntity":"scope-correction","stages":[{"id":"technical"},{"id":"authorization"}],"fields":[{"field":"region","apiName":"region","schema":{"type":"string","enum":["north","south","islands"]}}]}}"#,
        )
        .unwrap();
        fs::write(
            directory
                .path()
                .join("simulations/holiday-sets/office-holidays-7.yaml"),
            "apiVersion: id.registrystack.org/formats/casework/holiday-set/v1alpha1\nkind: CaseworkHolidaySet\nholidaySet: office-holidays\nrevision: 7\ndates: [2026-09-07]\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("simulations/friday-review.yaml"),
            simulation,
        )
        .unwrap();
        directory
    }

    #[test]
    fn uc2_uc4_uc5_simulation_compiles_and_uses_the_runtime_evaluators() {
        let directory = regional_directory(FRIDAY_REVIEW);
        let outcome = run(
            directory.path(),
            REGIONAL_PROJECT.as_bytes(),
            "simulations/friday-review.yaml",
        );
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        let report = outcome.report;
        assert_eq!(report["routing"]["ruleId"], "northern-requests");
        assert_eq!(report["clock"]["dueState"], "atRisk");
        assert_eq!(report["clock"]["holidayRevision"], 7);
        assert_eq!(report["subject"]["id"], "request-0042");
    }

    #[test]
    fn an_unmet_simulation_expectation_is_placed_at_its_member_without_its_value() {
        let directory = regional_directory(
            &FRIDAY_REVIEW
                .replace("queue: northern-review", "queue: triage")
                .replace("rule: northern-requests", "rule: none")
                .replace("dueState: at-risk", "dueState: due")
                .replace(
                    "eligibleSteps: []",
                    "eligibleSteps: [supervisor-at-deadline]",
                ),
        );
        let outcome = run(
            directory.path(),
            REGIONAL_PROJECT.as_bytes(),
            "simulations/friday-review.yaml",
        );
        let placed = outcome
            .failures
            .iter()
            .map(|failure| {
                (
                    failure.code.as_str(),
                    failure.path.as_str(),
                    failure.source.as_ref().and_then(|source| source.line),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            placed,
            [
                (
                    "casework.simulation.expectation-not-met",
                    "/expect/dueState",
                    Some(19)
                ),
                (
                    "casework.simulation.expectation-not-met",
                    "/expect/eligibleSteps",
                    Some(21)
                ),
                (
                    "casework.simulation.expectation-not-met",
                    "/expect/queue",
                    Some(16)
                ),
                (
                    "casework.simulation.expectation-not-met",
                    "/expect/rule",
                    Some(17)
                ),
            ]
        );
        let queue = &outcome.failures[2];
        assert_eq!(
            queue.related[0].path,
            "/sources/0/requests/0/routing/0/queue"
        );
        let rendered = serde_json::to_string(
            &outcome
                .failures
                .iter()
                .map(|failure| failure.message.clone() + &failure.suggested_action)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        for value in [
            "northern-review",
            "triage",
            "supervisor-at-deadline",
            "2026-09-14",
        ] {
            assert!(!rendered.contains(value), "{value} repeated in {rendered}");
        }
    }

    #[test]
    fn a_subject_field_outside_the_source_schema_is_refused_naming_the_declared_type() {
        let directory =
            regional_directory(&FRIDAY_REVIEW.replace("{region: north}", "{region: 2031}"));
        let project = CaseworkProject::read("casework.yaml", REGIONAL_PROJECT.as_bytes()).unwrap();
        let files = crate::offline::read_simulation_file(
            &directory.path().join("simulations/friday-review.yaml"),
        )
        .unwrap();
        let found =
            simulation_input_diagnostics(directory.path(), &project, &files.simulations[0].decoded)
                .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, "casework.simulation.field-mismatch");
        assert_eq!(found[0].path, "/subject/fields/region");
        assert_eq!(
            found[0].message,
            "the source description declares this field as string, and it is written as integer"
        );
        assert!(!found[0].message.contains("2031"));
    }

    #[test]
    fn uc3_simulation_uses_authoritative_request_wide_timing() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("sources")).unwrap();
        fs::create_dir_all(directory.path().join("simulations")).unwrap();
        fs::write(
            directory.path().join("sources/professional.json"),
            r#"{"apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1","kind":"BRegCaseworkSourceDescription","sourceId":"professional-register","authority":"none","request":{"requestEntity":"scope-correction","stages":[{"id":"review"}],"fields":[]}}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("simulations/resubmitted-review.yaml"),
            r#"apiVersion: id.registrystack.org/formats/casework/simulation/v1alpha1
kind: CaseworkSimulation
id: resubmitted-review
source: professional-register
subject:
  entity: scope-correction
  recordId: request-0042
  version: "2"
  activity: review
  stage: review
  reviewTiming:
    firstSubmittedAt: "2026-09-10T09:00:00+07:00"
    pausedMilliseconds: 86400000
now: "2026-09-11T13:00:00+07:00"
expect:
  queue: corrections
  dueAt: "2026-09-13T09:00:00+07:00"
  remainingMilliseconds: 158400000
"#,
        )
        .unwrap();
        let outcome = run(
            directory.path(),
            br#"apiVersion: registry.registrystack.org/casework/v1alpha1
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
            "simulations/resubmitted-review.yaml",
        );
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        let report = outcome.report;
        assert_eq!(report["clock"]["remainingMilliseconds"], 158_400_000);
        assert_eq!(report["clock"]["dueAt"], "2026-09-13T02:00:00Z");
    }
}
