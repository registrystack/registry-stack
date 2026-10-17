// SPDX-License-Identifier: Apache-2.0
//! Proposal steps use the same public clients and retained attempts as record steps.
use super::*;

pub(super) const PENDING_OBSERVATION: &str = "Proposal state differs from the authored expectation; resume this attempt after independent work completes";

pub(super) fn validate_step(
    step: &Step,
    at: &str,
    refuse: &mut impl FnMut(&str, &str, &str, &str),
) {
    let start = step.operation == Operation::Start;
    let edits = matches!(step.operation, Operation::Edit | Operation::Rebase);
    if step.action.is_none()
        || step.record.is_some()
        || step.result.is_some()
        || step.capture_results.is_some()
        || start && (step.capture.is_none() || step.input.is_none() || step.proposal.is_some())
        || !start && (step.proposal.is_none() || step.capture.is_some())
        || edits && step.input.is_none()
        || !start && !edits && step.operation != Operation::Revise && step.input.is_some()
    {
        refuse(at, "breg.examples.step-members", "the Proposal step members do not match its operation",
            "Declare action; start also needs input and capture; other steps need proposal, with input for edit or rebase and optionally revise. Delete record, result, and captureResults.");
    }
    if let Some(expect) = &step.expect {
        if expect.problem_code.is_some() != expect.status.is_some()
            || expect.status.is_some() && (expect.state.is_some() || start)
            || expect.state.as_ref().is_some_and(|state| {
                !matches!(
                    state.as_str(),
                    "draft" | "submitted" | "cancelled" | "applied"
                )
            })
        {
            refuse(at, "breg.examples.expectation", "the Proposal expectation is invalid",
                "Use a Proposal state, or a refusal status and problemCode; start must capture a successful Proposal.");
        }
    }
}

fn binding(contract: &BRegMetadata, step: &Step) -> Result<BRegActionBinding> {
    let action = contract.select_action(
        step.action.as_deref().context("Proposal action missing")?,
        &step.access_profile,
    )?;
    if action.mode() != BRegActionMode::Proposal {
        bail!("start requires an advertised Proposal Action");
    }
    Ok(action)
}

pub(super) fn preflight(
    step: &Step,
    contract: &BRegMetadata,
    input: &Value,
    records: &BTreeMap<String, Capture>,
    proposals: &mut BTreeMap<String, ProposalCapture>,
    attempt: &Attempt,
) -> Result<()> {
    if step.operation == Operation::Start {
        let action = binding(contract, step)?;
        action_inputs(step, &action, input, records)?;
        let alias = step.capture.as_ref().context("Proposal capture missing")?;
        if records.contains_key(alias)
            || proposals.contains_key(alias) && !attempt.completed.contains_key(&step.id)
        {
            bail!("Proposal captures must be unique and distinct from record captures");
        }
        proposals.entry(alias.clone()).or_insert(ProposalCapture {
            action: step.action.clone().context("Proposal action missing")?,
            id: uuid::Uuid::new_v4(),
            submission_version: None,
            effect_digest: None,
            action_revision: None,
        });
    } else {
        contract.select_proposal_get(&step.access_profile)?;
        let capture = proposals
            .get(
                step.proposal
                    .as_deref()
                    .context("Proposal capture missing")?,
            )
            .context("Proposal step requires an earlier or inherited Proposal capture")?;
        if Some(&capture.action) != step.action.as_ref() {
            bail!("Proposal capture belongs to another Action");
        }
        if let Some(key) = &step.input {
            if !input.get(key).is_some_and(Value::is_object) {
                bail!("Proposal edit input must be an object");
            }
            resolve(&input[key], records, 0)?;
        }
    }
    Ok(())
}

fn transition_body(
    step: &Step,
    current: &BRegProposal,
    input: &Value,
    records: &BTreeMap<String, Capture>,
) -> Result<Value> {
    if step.operation == Operation::Apply {
        Ok(
            json!({"submissionVersion":current.submission_version(), "effectDigest":current.effect_digest().context("Proposal has no frozen effects")?}),
        )
    } else if let Some(key) = &step.input {
        Ok(json!({"input":resolve(&input[key], records, 0)?}))
    } else {
        Ok(json!({}))
    }
}

pub(super) async fn execute(
    step: &Step,
    client: &BaseRegistryClient,
    contract: &BRegMetadata,
    input: &Value,
    directory: &Path,
    attempt: &mut Attempt,
) -> Result<Value> {
    let key = BRegIdempotencyKey::parse(format!("examples-{}-{}", attempt.id, step.id))?;
    let outcome = if step.operation == Operation::Start {
        let action = binding(contract, step)?;
        let inputs = action_inputs(step, &action, input, &attempt.captures)?;
        let prepared = if let Some(pending) = &attempt.pending {
            if pending.step != step.id {
                bail!("resume the pending original Proposal step first");
            }
            BRegPreparedAction::from_slice(&serde_json::to_vec(&pending.capsule)?)?
        } else {
            let request = BRegActionInvocationRequest::new(&action, inputs.clone(), None)?;
            let prepared = client.prepare_action(&action, &request, &key)?;
            attempt.pending = Some(Pending {
                step: step.id.clone(),
                capsule: serde_json::from_slice(prepared.as_bytes())?,
            });
            attempt.save(directory)?;
            prepared
        };
        let request = client.recover_action(&action, &prepared, &inputs, &key)?;
        client.start_proposal(&action, &request, &key).await
    } else {
        let capture = attempt
            .proposals
            .get(
                step.proposal
                    .as_deref()
                    .context("Proposal capture missing")?,
            )
            .context("Proposal capture missing")?
            .clone();
        let get = contract.select_proposal_get(&step.access_profile)?;
        let current = client.get_proposal(&get, &capture.id.to_string()).await;
        if !matches!(step.operation, Operation::Revise | Operation::Rebase) {
            if let Ok(response) = &current {
                require_submission(&capture, &response.value)?;
            }
        }
        match current {
            Ok(response) if step.operation != Operation::Inspect => {
                let current = response.value;
                let prepared = if let Some(pending) = &attempt.pending {
                    if pending.step != step.id {
                        bail!("resume the pending original Proposal step first");
                    }
                    let saved =
                        BRegPreparedProposal::from_slice(&serde_json::to_vec(&pending.capsule)?)?;
                    client.recover_proposal(&current, &saved)?
                } else {
                    let body = transition_body(step, &current, input, &attempt.captures)?;
                    let prepared = client.prepare_proposal(
                        &current,
                        step.operation.transition(),
                        body,
                        &key,
                    )?;
                    attempt.pending = Some(Pending {
                        step: step.id.clone(),
                        capsule: serde_json::from_slice(prepared.as_bytes())?,
                    });
                    attempt.save(directory)?;
                    prepared
                };
                client.execute_proposal(&prepared).await
            }
            result => result,
        }
    };
    let result = match outcome {
        Ok(response) => {
            if step
                .expect
                .as_ref()
                .is_some_and(|expect| expect.status.is_some())
            {
                bail!("Proposal step succeeded where a refusal was expected");
            }
            let value = serde_json::to_value(&response.value)?;
            if step
                .expect
                .as_ref()
                .and_then(|expect| expect.state.as_deref())
                .is_some_and(|state| value["state"].as_str() != Some(state))
            {
                bail!(PENDING_OBSERVATION);
            }
            #[cfg(test)]
            super::tests::interrupt_after_commit(step);
            if step.operation == Operation::Start {
                attempt.proposals.insert(
                    step.capture.clone().context("Proposal capture missing")?,
                    ProposalCapture {
                        action: response.value.action_id().to_owned(),
                        id: response.value.id().parse()?,
                        submission_version: None,
                        effect_digest: None,
                        action_revision: Some(response.value.action_revision().to_owned()),
                    },
                );
            } else if step.operation == Operation::Submit {
                let capture = attempt
                    .proposals
                    .get_mut(
                        step.proposal
                            .as_deref()
                            .context("Proposal capture missing")?,
                    )
                    .context("Proposal capture missing")?;
                capture.submission_version = Some(response.value.submission_version());
                capture.effect_digest = Some(
                    response
                        .value
                        .effect_digest()
                        .context("submitted Proposal has no effect digest")?
                        .to_owned(),
                );
                capture.action_revision = Some(response.value.action_revision().to_owned());
            } else if matches!(step.operation, Operation::Revise | Operation::Rebase) {
                let capture = attempt
                    .proposals
                    .get_mut(
                        step.proposal
                            .as_deref()
                            .context("Proposal capture missing")?,
                    )
                    .context("Proposal capture missing")?;
                capture.submission_version = None;
                capture.effect_digest = None;
            }
            value
        }
        Err(error) => {
            let Some(expect) = step.expect.as_ref() else {
                return Err(error.into());
            };
            if error.status().map(u32::from) != expect.status.map(|status| status.get())
                || error.problem_code().map(|code| code.code()) != expect.problem_code.as_deref()
            {
                return Err(error.into());
            }
            json!({"status":expect.status,"problemCode":expect.problem_code})
        }
    };
    retain(attempt, step, directory, result.clone())?;
    Ok(result)
}

/// A later revision of the same Proposal must not satisfy an earlier submission's wait.
fn require_submission(capture: &ProposalCapture, current: &BRegProposal) -> Result<()> {
    if current.action_id() != capture.action
        || capture
            .action_revision
            .as_deref()
            .is_some_and(|revision| revision != current.action_revision())
        || capture
            .submission_version
            .is_some_and(|version| version != current.submission_version())
        || capture
            .effect_digest
            .as_deref()
            .is_some_and(|digest| Some(digest) != current.effect_digest())
    {
        bail!("Proposal no longer matches the captured exact Action and frozen submission");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_requires_the_captured_frozen_submission() {
        let id = uuid::Uuid::new_v4();
        let revision = format!("sha256:{}", "a".repeat(64));
        let digest = format!("sha256:{}", "b".repeat(64));
        let value = json!({"id":id,"actionId":"correct-entry","actionRevision":revision,
            "submissionVersion":1,"revision":2,"state":"submitted","effectDigest":digest,"links":{}});
        let current = BRegProposal::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        let capture = ProposalCapture {
            id,
            action: "correct-entry".to_owned(),
            action_revision: Some(revision),
            submission_version: Some(1),
            effect_digest: Some(digest),
        };
        require_submission(&capture, &current).unwrap();
        for (key, changed) in [
            ("submissionVersion", json!(2)),
            ("effectDigest", json!(format!("sha256:{}", "c".repeat(64)))),
            (
                "actionRevision",
                json!(format!("sha256:{}", "d".repeat(64))),
            ),
        ] {
            let mut changed_value = value.clone();
            changed_value[key] = changed;
            let current =
                BRegProposal::from_slice(&serde_json::to_vec(&changed_value).unwrap()).unwrap();
            assert!(require_submission(&capture, &current).is_err(), "{key}");
        }
    }

    #[test]
    fn refusal_expectations_only_accept_http_error_statuses() {
        for status in [400, 404, 409, 599] {
            let expectation: ProposalExpectation =
                serde_json::from_value(json!({"status":status,"problemCode":"registry.refused"}))
                    .unwrap();
            assert_eq!(expectation.status.unwrap().get(), status);
        }
        for status in [0, 200, 399, 600, 65535] {
            assert!(serde_json::from_value::<ProposalExpectation>(
                json!({"status":status,"problemCode":"registry.refused"})
            )
            .is_err());
        }
    }

    #[test]
    fn proposal_steps_are_closed_and_keep_record_captures_separate() {
        let value = json!({"id":"start","operation":"start","recordType":"entry","client":"author",
            "accessProfile":"author","action":"correct-entry","input":"correction","capture":"proposal"});
        let step: Step = serde_json::from_value(value.clone()).unwrap();
        let mut problems = Vec::new();
        validate_step(&step, "/step", &mut |_, code, _, _| {
            problems.push(code.to_owned())
        });
        assert!(problems.is_empty());
        let mut injected = value.clone();
        injected["approval"] = json!(true);
        assert!(serde_json::from_value::<Step>(injected).is_err());
        let mut invalid = step;
        invalid.proposal = Some("record".to_owned());
        validate_step(&invalid, "/step", &mut |_, code, _, _| {
            problems.push(code.to_owned())
        });
        assert_eq!(problems, ["breg.examples.step-members"]);

        let mut invalid: Step = serde_json::from_value(value).unwrap();
        invalid.capture_results = Some(BTreeMap::from([("entry".to_owned(), "entry".to_owned())]));
        let mut diagnostic = None;
        validate_step(&invalid, "/step", &mut |_, code, _, action| {
            diagnostic = Some((code.to_owned(), action.to_owned()))
        });
        let (code, action) = diagnostic.expect("Proposal captureResults is refused");
        assert_eq!(code, "breg.examples.step-members");
        assert!(action.contains("captureResults"));
    }
}
