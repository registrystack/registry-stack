// SPDX-License-Identifier: Apache-2.0
//! Authored Proposal journeys exercise only the ordinary authenticated source API.
use super::*;
use crate::contract::ProposalOperation;
use crate::model::{CompiledActionExecution, CompiledProposalPermission};

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(super) enum ProposalJourneyOperation {
    Start,
    Get,
    Edit,
    Submit,
    Revise,
    Rebase,
    Retry,
    Cancel,
    Apply,
    GetReviewContext,
    GetReviewStatus,
}

impl ProposalJourneyOperation {
    fn grant(self) -> Option<ProposalOperation> {
        Some(match self {
            Self::Start => return None,
            Self::Get => ProposalOperation::Get,
            Self::Edit => ProposalOperation::Edit,
            Self::Submit => ProposalOperation::Submit,
            Self::Revise => ProposalOperation::Revise,
            Self::Rebase => ProposalOperation::Rebase,
            Self::Retry => ProposalOperation::Retry,
            Self::Cancel => ProposalOperation::Cancel,
            Self::Apply => ProposalOperation::Apply,
            Self::GetReviewContext => ProposalOperation::GetReviewContext,
            Self::GetReviewStatus => ProposalOperation::GetReviewStatus,
        })
    }
    fn path(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Get => "",
            Self::Edit => "edit",
            Self::Submit => "submit",
            Self::Revise => "revise",
            Self::Rebase => "rebase",
            Self::Retry => "retry",
            Self::Cancel => "cancel",
            Self::Apply => "apply",
            Self::GetReviewContext => "review-context",
            Self::GetReviewStatus => "review-status",
        }
    }
    fn reads(self) -> bool {
        matches!(
            self,
            Self::Get | Self::GetReviewContext | Self::GetReviewStatus
        )
    }
}

fn profile(grant: &CompiledProposalPermission) -> Result<AccessProfileSource, FixtureError> {
    // Reuse the same claim and target-boundary projection as Action journeys.
    action_profile_from_grant(&CompiledActionPermission {
        profile_id: grant.profile_id.clone(),
        default: grant.default,
        actor_kind: grant.actor_kind,
        task_grant: grant.task_grant.clone(),
        requester_clients: grant.requester_clients.clone(),
        principal_claim: grant.principal_claim.clone(),
        required_scopes: grant.required_scopes.clone(),
        required_purposes: grant.required_purposes.clone(),
        operations: BTreeSet::new(),
        results: BTreeSet::new(),
        targets: grant
            .targets
            .iter()
            .map(|target| crate::model::CompiledActionTargetPermission {
                entity_id: target.entity_id.clone(),
                operation: Operation::Get,
                source: crate::model::CompiledActionTargetUseSource::Input {
                    input: "target".to_owned(),
                },
                row_boundaries: target.row_boundaries.clone(),
            })
            .collect(),
    })
}

pub(super) fn validate_step(
    step: StepSource,
    registry: &CompiledRegistry,
    captures: &mut BTreeMap<String, CaptureSource>,
    ids: &mut BTreeSet<String>,
) -> Result<ValidatedStep, FixtureError> {
    let ActionSource::Proposal {
        operation,
        proposal_capture,
        etag_capture,
        submission_capture,
        input,
        idempotency_key,
    } = &step.request
    else {
        return Err(FixtureError::JourneyShapeRefused);
    };
    if !step.entity.is_empty() || !step.capture_results.is_empty() {
        return Err(FixtureError::JourneyShapeRefused);
    }
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| Some(&action.id) == step.action.as_ref())
        .ok_or(FixtureError::LogicalReferenceRefused)?;
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Err(FixtureError::LogicalReferenceRefused);
    };
    let is_start = *operation == ProposalJourneyOperation::Start;
    let profile = if is_start {
        action_profile_from_grant(
            action
                .permissions
                .iter()
                .find(|grant| {
                    grant.profile_id == step.access_profile
                        && grant.operations.contains(&Operation::Start)
                })
                .ok_or(FixtureError::LogicalReferenceRefused)?,
        )?
    } else {
        profile(
            proposal
                .permissions
                .iter()
                .find(|grant| {
                    grant.profile_id == step.access_profile
                        && operation
                            .grant()
                            .is_some_and(|operation| grant.operations.contains(&operation))
                })
                .ok_or(FixtureError::LogicalReferenceRefused)?,
        )?
    };
    validate_claims(&step.claims, &profile, step.expect.outcome)?;
    if idempotency_key
        .as_deref()
        .is_some_and(|key| validate_idempotency_key_source(key).is_err())
    {
        return Err(FixtureError::LogicalReferenceRefused);
    }
    if is_start != proposal_capture.is_none()
        || is_start && (etag_capture.is_some() || submission_capture.is_some())
        || *operation != ProposalJourneyOperation::Apply && submission_capture.is_some()
        || operation.reads() && (etag_capture.is_some() || idempotency_key.is_some())
    {
        return Err(FixtureError::JourneyShapeRefused);
    }
    for reference in [proposal_capture, etag_capture, submission_capture]
        .into_iter()
        .flatten()
    {
        if captures
            .get(reference)
            .and_then(|source| source.proposal_action.as_deref())
            != Some(action.id.as_str())
        {
            return Err(FixtureError::LogicalReferenceRefused);
        }
    }
    if matches!(
        *operation,
        ProposalJourneyOperation::Start
            | ProposalJourneyOperation::Edit
            | ProposalJourneyOperation::Rebase
    ) || *operation == ProposalJourneyOperation::Revise && !input.is_empty()
    {
        validate_action_input_map(input, action, captures, None, false)?;
    } else if !input.is_empty() {
        return Err(FixtureError::JourneyShapeRefused);
    }
    let mut expect = step.expect.clone();
    if expect.fields.keys().any(|key| {
        !matches!(
            key.as_str(),
            "state" | "submissionVersion" | "effectDigest" | "applicationStatus"
        )
    }) {
        return Err(FixtureError::JourneyShapeRefused);
    }
    expect.fields.clear();
    // Start returns 201; other Proposal representations return 200.
    if is_start && expect.outcome == ExpectedOutcome::Success {
        if expect.status != 201 {
            return Err(FixtureError::JourneyShapeRefused);
        }
        expect.status = 200;
    }
    validate_expectation(
        &expect,
        Operation::Invoke,
        &profile,
        step.capture.is_some(),
        false,
    )?;
    if step.capture.is_some()
        && matches!(
            *operation,
            ProposalJourneyOperation::GetReviewContext | ProposalJourneyOperation::GetReviewStatus
        )
    {
        return Err(FixtureError::JourneyShapeRefused);
    }
    if let Some(alias) = &step.capture {
        if !ids.insert(alias.clone()) {
            return Err(FixtureError::DuplicateIdentifier);
        }
        captures.insert(
            alias.clone(),
            CaptureSource {
                entity: None,
                has_etag: true,
                condition_map: false,
                proposal_action: Some(action.id.clone()),
            },
        );
    }
    let path = if is_start {
        action.route.clone()
    } else {
        format!(
            "/v1/proposals/{{proposal_id}}{}{}",
            if operation.path().is_empty() { "" } else { "/" },
            operation.path()
        )
    };
    let problem_bindings = compile_problem_bindings(
        &step.expect,
        &step.request,
        None,
        Some(&action.id),
        registry,
    )?;
    Ok(ValidatedStep {
        id: step.id,
        entity: None,
        action_id: Some(action.id.clone()),
        access_profile: step.access_profile,
        claims: step.claims,
        route: FixtureRoute::Proposal(path),
        profile,
        response_readable_fields: BTreeSet::new(),
        action: step.request,
        expect: step.expect,
        problem_bindings,
        capture: step.capture,
        capture_results: BTreeMap::new(),
    })
}

fn observed<'a>(
    observations: &'a BTreeMap<String, Observation>,
    reference: &str,
) -> Result<(&'a Value, &'a str), FixtureError> {
    match &observations
        .get(reference)
        .ok_or(FixtureError::RequestConstructionRefused)?
        .kind
    {
        ObservationKind::Proposal { document, etag } => Ok((document, etag)),
        _ => Err(FixtureError::RequestConstructionRefused),
    }
}

pub(super) fn request(
    journey: &str,
    step: &ValidatedStep,
    observations: &BTreeMap<String, Observation>,
    token: &str,
) -> Result<Request<Body>, FixtureError> {
    let ActionSource::Proposal {
        operation,
        proposal_capture,
        etag_capture,
        submission_capture,
        input,
        idempotency_key,
    } = &step.action
    else {
        return Err(FixtureError::RequestConstructionRefused);
    };
    let mut path = step.route.path().to_owned();
    let mut if_match = None;
    if let Some(reference) = proposal_capture {
        let (document, etag) = observed(observations, reference)?;
        let id = document["id"]
            .as_str()
            .ok_or(FixtureError::RequestConstructionRefused)?;
        path = path.replace("{proposal_id}", id);
        if !operation.reads() {
            if_match = Some(
                etag_capture
                    .as_deref()
                    .map(|reference| observed(observations, reference).map(|(_, etag)| etag))
                    .transpose()?
                    .unwrap_or(etag),
            );
        }
    }
    path.push_str("?accessProfile=");
    percent_encode_query_value(&step.access_profile, &mut path);
    let body = match *operation {
        ProposalJourneyOperation::Start
        | ProposalJourneyOperation::Edit
        | ProposalJourneyOperation::Rebase => {
            json!({"input":resolve_fixture_value_refs(&Value::Object(input.clone()), observations)?})
        }
        ProposalJourneyOperation::Revise if !input.is_empty() => {
            json!({"input":resolve_fixture_value_refs(&Value::Object(input.clone()), observations)?})
        }
        ProposalJourneyOperation::Apply => {
            let reference = submission_capture
                .as_ref()
                .or(proposal_capture.as_ref())
                .ok_or(FixtureError::RequestConstructionRefused)?;
            let (document, _) = observed(observations, reference)?;
            json!({"submissionVersion":document["submissionVersion"],"effectDigest":document["effectDigest"]})
        }
        _ => json!({}),
    };
    let mut request = authenticated_json_request(
        if operation.reads() {
            Method::GET
        } else {
            Method::POST
        },
        &path,
        token,
        &body,
    )?;
    if operation.reads() {
        *request.body_mut() = Body::empty();
        request.headers_mut().remove(CONTENT_TYPE);
    } else {
        let key = format!(
            "fixture-{journey}-{}-{}",
            step.action_id
                .as_deref()
                .ok_or(FixtureError::RequestConstructionRefused)?,
            idempotency_key.as_deref().unwrap_or(&step.id)
        );
        request.headers_mut().insert(
            "idempotency-key",
            key.parse()
                .map_err(|_| FixtureError::RequestConstructionRefused)?,
        );
    }
    if let Some(etag) = if_match {
        request.headers_mut().insert(
            IF_MATCH,
            etag.parse()
                .map_err(|_| FixtureError::RequestConstructionRefused)?,
        );
    }
    Ok(request)
}

pub(super) fn assert_response(step: &ValidatedStep, document: &Value) -> Result<(), FixtureError> {
    let ActionSource::Proposal { operation, .. } = &step.action else {
        return Err(FixtureError::ResponseShapeRefused);
    };
    if !matches!(
        *operation,
        ProposalJourneyOperation::GetReviewContext | ProposalJourneyOperation::GetReviewStatus
    ) && (document["actionId"].as_str() != step.action_id.as_deref()
        || document["id"]
            .as_str()
            .is_none_or(|id| uuid::Uuid::parse_str(id).is_err())
        || !matches!(
            document["state"].as_str(),
            Some("draft" | "submitted" | "applied" | "cancelled")
        ))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    if step
        .expect
        .fields
        .iter()
        .any(|(key, value)| document.get(key) != Some(value))
    {
        return Err(FixtureError::ExpectationMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> CompiledRegistry {
        let source = parse_project_yaml(include_bytes!(
            "../../../../products/breg/examples/facility/registry.yaml"
        ))
        .unwrap();
        compile_project_with_assets(
            &source,
            &[],
            &[ModuleAssetSource {
                module: None,
                path: "plans/correct-address.rhai".to_owned(),
                bytes: include_bytes!(
                    "../../../../products/breg/examples/facility/plans/correct-address.rhai"
                )
                .to_vec(),
            }],
            CompileProfile::Authoring,
        )
        .unwrap()
    }

    #[test]
    fn canonical_proposal_journey_validates_and_builds_only_public_requests() {
        let registry = registry();
        let suite = validate_fixture_journeys(
            include_bytes!("../../../../products/breg/examples/facility/tests/journeys.yaml"),
            &registry,
        )
        .unwrap();
        assert!(suite.journeys[0]
            .steps
            .iter()
            .any(|step| matches!(step.action, ActionSource::Proposal { .. })));
        let start = suite.journeys[0]
            .steps
            .iter()
            .find(|step| step.id == "start-deactivation")
            .unwrap();
        let record = uuid::Uuid::new_v4();
        let observations = BTreeMap::from([(
            "facility".to_owned(),
            Observation {
                kind: ObservationKind::Record {
                    record_id: record.to_string(),
                    etag: "\"record-1\"".to_owned(),
                },
            },
        )]);
        let request =
            fixture_request("canonical", start, &observations, "synthetic-token").unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(
            request.uri().path(),
            "/v1/actions/deactivate-facility/proposals"
        );
        assert_eq!(
            request.uri().query(),
            Some("accessProfile=facility-correction-author")
        );
    }

    #[tokio::test]
    async fn apply_uses_applier_conditions_and_the_captured_frozen_submission() {
        let suite = validate_fixture_journeys(
            include_bytes!("../../../../products/breg/examples/facility/tests/journeys.yaml"),
            &registry(),
        )
        .unwrap();
        let apply = suite.journeys[0]
            .steps
            .iter()
            .find(|step| step.id == "apply-deactivation")
            .unwrap();
        let id = uuid::Uuid::new_v4();
        let observations = BTreeMap::from([
            (
                "deactivation-submitted".to_owned(),
                Observation {
                    kind: ObservationKind::Proposal {
                        document: json!({"id":id,"submissionVersion":1,"effectDigest":"frozen-effects"}),
                        etag: "\"author-condition\"".to_owned(),
                    },
                },
            ),
            (
                "deactivation-for-apply".to_owned(),
                Observation {
                    kind: ObservationKind::Proposal {
                        document: json!({"id":id}),
                        etag: "\"applier-condition\"".to_owned(),
                    },
                },
            ),
        ]);
        let request =
            fixture_request("canonical", apply, &observations, "synthetic-token").unwrap();
        assert_eq!(request.headers()[IF_MATCH], "\"applier-condition\"");
        let bytes = axum::body::to_bytes(request.into_body(), 4096)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            json!({"submissionVersion":1,"effectDigest":"frozen-effects"})
        );
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "tests edit a checked-in synthetic authored journey to assert refusals"
    )]
    fn proposal_journeys_refuse_approval_injection_and_record_alias_confusion() {
        let registry = registry();
        let bytes =
            include_bytes!("../../../../products/breg/examples/facility/tests/journeys.yaml");
        let original: Value = serde_norway::from_slice(bytes).unwrap();
        let mut changed = original.clone();
        let steps = changed["journeys"][0]["steps"].as_array_mut().unwrap();
        let start = steps
            .iter_mut()
            .find(|step| step["id"] == "start-deactivation")
            .unwrap();
        start["request"]["transition"] = json!("approve");
        assert!(
            validate_fixture_journeys(&serde_json::to_vec(&changed).unwrap(), &registry).is_err()
        );
        let mut changed = original;
        let steps = changed["journeys"][0]["steps"].as_array_mut().unwrap();
        let submit = steps
            .iter_mut()
            .find(|step| step["id"] == "submit-deactivation")
            .unwrap();
        submit["request"]["proposalCapture"] = json!("facility");
        assert!(
            validate_fixture_journeys(&serde_json::to_vec(&changed).unwrap(), &registry).is_err()
        );
    }

    #[test]
    fn proposal_unknown_members_use_positioned_closed_union_diagnostics() {
        let bytes = b"apiVersion: id.registrystack.org/formats/breg/journeys/v1\nkind: BRegJourneys\njourneys:\n  - id: example\n    steps:\n      - id: start\n        action: deactivate-facility\n        accessProfile: facility-correction-author\n        claims: {principal: example}\n        request:\n          type: proposal\n          transition: start\n          approve: true\n        expect: {outcome: success, status: 201}\n";
        let Err(FixtureError::JourneyDocument(report)) = read_journey_document(bytes) else {
            panic!("unknown Proposal member must be refused by the shared reader");
        };
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "config.unknown-key")
            .unwrap();
        assert_eq!(diagnostic.path, "/journeys/0/steps/0/request/approve");
        assert!(diagnostic.source.is_some());
    }
}
