// SPDX-License-Identifier: Apache-2.0
//! Proposal steps use the same public clients and retained attempts as record steps.
use super::*;
use std::{future::Future, time::Duration};

pub(super) const PENDING_OBSERVATION: &str = "Proposal state differs from the authored expectation; resume this attempt after independent work completes";
/// Automatic application completes after submit returns, so an inspect step
/// expecting `applied` re-reads the Proposal at this interval, up to the limit.
const APPLICATION_POLL_INTERVAL: Duration = Duration::from_millis(250);
const APPLICATION_WAIT_LIMIT: Duration = Duration::from_secs(10);

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
    let mut waited = None;
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
        let id = capture.id.to_string();
        let mut current = client.get_proposal(&get, &id).await;
        if step.operation == Operation::Inspect {
            (current, waited) = await_application(
                step.expect
                    .as_ref()
                    .and_then(|expect| expect.state.as_deref()),
                current,
                |response| &response.value,
                || client.get_proposal(&get, &id),
                APPLICATION_POLL_INTERVAL,
                APPLICATION_WAIT_LIMIT,
            )
            .await;
        }
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
            let expected = step
                .expect
                .as_ref()
                .and_then(|expect| expect.state.as_deref());
            if expected.is_some_and(|state| value["state"].as_str() != Some(state)) {
                return Err(observation_refusal(expected, &response.value, waited));
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

/// Whether an inspect expecting `applied` observed automatic application still in progress.
fn awaits_automatic_application(expected: Option<&str>, observed: &BRegProposal) -> bool {
    expected == Some("applied")
        && observed.application_status().is_some_and(|status| {
            status.mode == BRegProposalApplicationMode::Automatic
                && matches!(
                    status.state,
                    BRegProposalApplicationState::Pending | BRegProposalApplicationState::Applying
                )
        })
}

/// Automatic application ended short of `applied`; resuming the attempt cannot change it.
#[derive(Debug)]
pub(super) struct SettledApplication(&'static str);

impl std::fmt::Display for SettledApplication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "automatic application settled as {}; the Proposal cannot reach the authored applied state",
            self.0
        )
    }
}

impl std::error::Error for SettledApplication {}

/// Refuses an observation that differs from the authored state. Automatic
/// application that settled short of `applied` cannot change on resume, so it
/// is named instead. The resume refusal keeps `PENDING_OBSERVATION` last,
/// which the review example matches on, and mentions the wait only when the
/// final read was still in progress.
fn observation_refusal(
    expected: Option<&str>,
    observed: &BRegProposal,
    waited: Option<Duration>,
) -> anyhow::Error {
    if let Some(status) = observed.application_status().filter(|status| {
        expected == Some("applied") && status.mode == BRegProposalApplicationMode::Automatic
    }) {
        let settled = match status.state {
            BRegProposalApplicationState::Blocked => Some("blocked"),
            BRegProposalApplicationState::Cancelled => Some("cancelled"),
            BRegProposalApplicationState::Rejected => Some("rejected"),
            _ => None,
        };
        if let Some(settled) = settled {
            return SettledApplication(settled).into();
        }
    }
    let refusal = anyhow::anyhow!(PENDING_OBSERVATION);
    match waited {
        Some(waited) if awaits_automatic_application(expected, observed) => {
            refusal.context(format!(
                "automatic application was still pending after waiting {:.1} s",
                waited.as_secs_f64()
            ))
        }
        _ => refusal,
    }
}

/// Re-reads while automatic application is in progress, until it settles or
/// `limit` elapses. Returns the last read and, when it re-read at all, how long it waited.
async fn await_application<R, E, F>(
    expected: Option<&str>,
    mut current: Result<R, E>,
    proposal: impl Fn(&R) -> &BRegProposal,
    mut read: impl FnMut() -> F,
    interval: Duration,
    limit: Duration,
) -> (Result<R, E>, Option<Duration>)
where
    F: Future<Output = Result<R, E>>,
{
    let started = std::time::Instant::now();
    let mut waited = None;
    while let Ok(response) = &current {
        if !awaits_automatic_application(expected, proposal(response)) || started.elapsed() >= limit
        {
            break;
        }
        tokio::time::sleep(interval).await;
        current = read().await;
        waited = Some(started.elapsed());
    }
    (current, waited)
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

    fn proposal(state: &str, application: Option<(&str, &str)>) -> BRegProposal {
        let mut value = json!({"id":uuid::Uuid::new_v4(),"actionId":"register-contact",
            "actionRevision":format!("sha256:{}", "a".repeat(64)),"submissionVersion":1,"revision":2,
            "state":state,"effectDigest":format!("sha256:{}", "b".repeat(64)),"links":{}});
        if let Some((state, mode)) = application {
            let mut status = json!({"state":state,"mode":mode});
            if mode == "automatic" && state != "applied" {
                status["automaticRetry"] = json!({"scheduled":state == "pending",
                    "attempts":u8::from(state != "pending"),"maximumAttempts":3});
            }
            if state == "blocked" {
                status["reason"] = json!("dependency-outage");
                status["recovery"] = json!("retry");
            }
            if state == "applied" {
                value["application"] = json!({"applicationId":uuid::Uuid::new_v4(),"submissionVersion":1,
                    "effectDigest":value["effectDigest"],"resultLinks":[]});
            }
            value["applicationStatus"] = status;
        }
        BRegProposal::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    #[test]
    fn only_in_progress_automatic_application_delays_an_applied_expectation() {
        let pending = proposal("submitted", Some(("pending", "automatic")));
        assert!(awaits_automatic_application(Some("applied"), &pending));
        assert!(awaits_automatic_application(
            Some("applied"),
            &proposal("submitted", Some(("applying", "automatic")))
        ));
        assert!(!awaits_automatic_application(Some("submitted"), &pending));
        assert!(!awaits_automatic_application(None, &pending));
        for settled in [
            proposal("submitted", None),
            proposal("submitted", Some(("pending", "manual"))),
            proposal("submitted", Some(("blocked", "automatic"))),
            proposal("applied", Some(("applied", "automatic"))),
        ] {
            assert!(!awaits_automatic_application(Some("applied"), &settled));
        }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn application_wait_returns_the_settled_read() {
        let mut reads = 0;
        let (current, waited) = block_on(await_application(
            Some("applied"),
            Ok::<_, ()>(proposal("submitted", Some(("pending", "automatic")))),
            |response| response,
            || {
                reads += 1;
                let next = if reads < 3 {
                    proposal("submitted", Some(("applying", "automatic")))
                } else {
                    proposal("applied", Some(("applied", "automatic")))
                };
                async move { Ok(next) }
            },
            Duration::from_millis(1),
            Duration::from_secs(10),
        ));
        assert_eq!(reads, 3);
        assert_eq!(
            serde_json::to_value(current.unwrap()).unwrap()["state"],
            "applied"
        );
        assert!(waited.is_some());
    }

    #[test]
    fn application_wait_is_bounded_and_skipped_when_nothing_is_pending() {
        let limit = Duration::from_millis(20);
        let (current, waited) = block_on(await_application(
            Some("applied"),
            Ok::<_, ()>(proposal("submitted", Some(("pending", "automatic")))),
            |response| response,
            || async { Ok(proposal("submitted", Some(("pending", "automatic")))) },
            Duration::from_millis(2),
            limit,
        ));
        assert_eq!(
            serde_json::to_value(current.unwrap()).unwrap()["state"],
            "submitted"
        );
        let waited = waited.unwrap();
        assert!(waited >= limit);
        let pending = proposal("submitted", Some(("pending", "automatic")));
        let refusal = format!(
            "{:#}",
            observation_refusal(Some("applied"), &pending, Some(waited))
        );
        assert!(refusal.starts_with("automatic application was still pending after waiting 0.0"));
        assert!(refusal.ends_with(PENDING_OBSERVATION), "{refusal}");
        assert_eq!(
            format!("{:#}", observation_refusal(Some("applied"), &pending, None)),
            PENDING_OBSERVATION
        );
        let (_, waited) = block_on(await_application(
            Some("applied"),
            Ok::<_, ()>(proposal("submitted", Some(("pending", "manual")))),
            |response| response,
            || async { panic!("a manual application is never polled") },
            Duration::from_millis(2),
            limit,
        ));
        assert!(waited.is_none());
    }

    #[test]
    fn settled_application_is_named_without_claiming_pending_or_resume() {
        let (current, waited) = block_on(await_application(
            Some("applied"),
            Ok::<_, ()>(proposal("submitted", Some(("pending", "automatic")))),
            |response| response,
            || async { Ok(proposal("submitted", Some(("blocked", "automatic")))) },
            Duration::from_millis(1),
            Duration::from_secs(10),
        ));
        let refusal = observation_refusal(Some("applied"), &current.unwrap(), waited);
        assert!(
            refusal.downcast_ref::<SettledApplication>().is_some(),
            "the run skips its resume advice for a settled application"
        );
        let refusal = format!("{refusal:#}");
        assert!(waited.is_some());
        assert!(refusal.contains("settled as blocked"), "{refusal}");
        assert!(!refusal.contains("pending"), "{refusal}");
        assert!(!refusal.contains("resume"), "{refusal}");
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
