// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, env, fs, path::PathBuf, process::ExitCode};

use registry_casework::problem::{
    OperationContract, ProblemCode, FRAMEWORK_PROBLEMS, OPERATION_CONTRACTS,
};
use registry_casework::ReviewTaskDecisionRequest;
use registry_casework_core::{
    ReviewCancelRequest, ReviewCancelResponse, ReviewClockCorrelation, ReviewCreateRequest,
    ReviewRequestAccepted, ReviewRequestView, ReviewResult, ReviewResultFeedPage,
    ReviewerTaskState,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProblemCatalog<'a> {
    entries: Vec<ProblemEntry<'a>>,
    framework_problems: Vec<&'a str>,
    operations: Vec<OperationEntry<'a>>,
    review_wire_examples: BTreeMap<&'static str, Vec<Value>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationEntry<'a> {
    method: &'a str,
    path: &'a str,
    success_statuses: &'a [u16],
    extracts_path: bool,
    extracts_query: bool,
    accepts_json: bool,
    problems: Vec<&'a str>,
}

impl<'a> From<&'a OperationContract> for OperationEntry<'a> {
    fn from(operation: &'a OperationContract) -> Self {
        Self {
            method: operation.method,
            path: operation.path,
            success_statuses: operation.success_statuses,
            extracts_path: operation.extracts_path,
            extracts_query: operation.extracts_query,
            accepts_json: operation.accepts_json,
            problems: operation
                .problems
                .iter()
                .map(|problem| problem.code())
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProblemEntry<'a> {
    uri: String,
    code: &'a str,
    title: &'a str,
    description: &'a str,
    http_statuses: [u16; 1],
}

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(flag) = arguments.next() else {
        eprintln!("usage: problem-catalog --output <file>");
        return ExitCode::from(2);
    };
    let Some(output) = arguments.next() else {
        eprintln!("usage: problem-catalog --output <file>");
        return ExitCode::from(2);
    };
    if flag != "--output" || arguments.next().is_some() {
        eprintln!("usage: problem-catalog --output <file>");
        return ExitCode::from(2);
    }

    let review_wire_examples = match review_wire_examples() {
        Ok(examples) => examples,
        Err(error) => {
            eprintln!("review wire examples could not be typed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = ProblemCatalog {
        entries: ProblemCode::ALL
            .iter()
            .copied()
            .map(|problem| ProblemEntry {
                uri: problem.type_uri(),
                code: problem.code(),
                title: problem.title(),
                description: problem.detail(),
                http_statuses: [problem.status().as_u16()],
            })
            .collect(),
        framework_problems: FRAMEWORK_PROBLEMS
            .iter()
            .map(|problem| problem.code())
            .collect(),
        operations: OPERATION_CONTRACTS
            .iter()
            .map(OperationEntry::from)
            .collect(),
        review_wire_examples,
    };
    let mut bytes = match serde_json::to_vec_pretty(&catalog) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("problem catalog could not be serialized");
            return ExitCode::FAILURE;
        }
    };
    bytes.push(b'\n');
    if fs::write(PathBuf::from(output), bytes).is_err() {
        eprintln!("problem catalog could not be written");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn review_wire_examples() -> Result<BTreeMap<&'static str, Vec<Value>>, serde_json::Error> {
    let digest = format!("sha256:{}", "a".repeat(64));
    let subject = json!({
        "source":"breg-a", "type":"change-request", "id":"request-1",
        "version":"7", "digest":digest
    });
    let policy = json!({"id":"address-review", "version":"1", "digest":digest});
    let result = json!({
        "resultId":"00000000-0000-4000-8000-000000000003",
        "requestId":"00000000-0000-4000-8000-000000000002",
        "subject":subject, "policy":policy, "submissionDigest":digest,
        "status":"rejected", "outcome":"not-supported", "result":{"reason":"fixture"},
        "completedAt":"2026-09-20T01:00:00Z", "availableUntil":"2026-10-20T01:00:00Z"
    });
    let mut cancelled = result.clone();
    cancelled["status"] = json!("cancelled");
    cancelled.as_object_mut().unwrap().remove("outcome");
    cancelled.as_object_mut().unwrap().remove("result");
    Ok(BTreeMap::from([
        (
            "ReviewCreateRequest",
            typed_examples::<ReviewCreateRequest>(vec![
                json!({"kind":"address-review","subject":subject,"requesterReference":"case-1","context":{"strategy":"submitted","snapshot":{"field":"value"}},"resultConstraints":{"type":"object"}}),
                json!({"kind":"address-review","subject":subject,"requesterReference":"case-1","initiator":{"issuer":"https://issuer.example","subject":"person-1"},"context":{"strategy":"source","binding":{"reference":"source-ref"}}}),
            ])?,
        ),
        (
            "ReviewRequestAccepted",
            typed_examples::<ReviewRequestAccepted>(vec![json!({
                "requestId":"00000000-0000-4000-8000-000000000002",
                "subject":subject,"policy":policy,"submissionDigest":digest
            })])?,
        ),
        (
            "ReviewRequestView",
            typed_examples::<ReviewRequestView>(vec![json!({
                "requestId":"00000000-0000-4000-8000-000000000002",
                "subject":subject,"policy":policy,"submissionDigest":digest,
                "requesterReference":"case-1","lifecycle":"reviewing","activeStage":"supervisor",
                "createdAt":"2026-09-20T00:00:00Z","updatedAt":"2026-09-20T01:00:00Z"
            })])?,
        ),
        (
            "ReviewResult",
            typed_examples::<ReviewResult>(vec![result.clone(), cancelled.clone()])?,
        ),
        (
            "ReviewResultFeedPage",
            typed_examples::<ReviewResultFeedPage>(vec![json!({
                "items":[{"eventId":"00000000-0000-4000-8000-000000000004","requestId":"00000000-0000-4000-8000-000000000002","resultId":"00000000-0000-4000-8000-000000000003","completedAt":"2026-09-20T01:00:00Z"}],
                "nextCursor":"00000000-0000-4000-8000-000000000004"
            })])?,
        ),
        (
            "ReviewCancelRequest",
            typed_examples::<ReviewCancelRequest>(vec![
                json!({"subject":subject,"reason":"withdrawn"}),
            ])?,
        ),
        (
            "ReviewCancelResponse",
            typed_examples::<ReviewCancelResponse>(vec![
                json!({"outcome":"cancelled","result":cancelled}),
                json!({"outcome":"already_terminal","result":result}),
            ])?,
        ),
        (
            "ReviewerTaskState",
            typed_examples::<ReviewerTaskState>(vec![
                json!("open"),
                json!({"held":{"holder":{"issuer":"https://issuer.example","subject":"person-1"}}}),
                json!("decided"),
            ])?,
        ),
        (
            "ReviewTaskDecisionRequest",
            typed_examples::<ReviewTaskDecisionRequest>(vec![
                json!({"decision":{"type":"approve"}}),
                json!({"decision":{"type":"reject","outcome":"not-supported","reason":"reason","result":{"field":"value"}}}),
                json!({"decision":{"type":"changes_requested","outcome":"needs-change"}}),
                json!({"decision":{"type":"answer","outcome":"answered","result":{"answer":true}}}),
            ])?,
        ),
        (
            "ReviewClockCorrelation",
            typed_examples::<ReviewClockCorrelation>(vec![
                json!({"scope":"subject","source":"breg-a","subjectType":"change-request","id":"request-1"}),
                json!({"scope":"activity","taskId":"00000000-0000-4000-8000-000000000005","stageId":"supervisor"}),
            ])?,
        ),
    ]))
}

fn typed_examples<T>(examples: Vec<Value>) -> Result<Vec<Value>, serde_json::Error>
where
    T: DeserializeOwned + Serialize,
{
    examples
        .into_iter()
        .map(|example| serde_json::from_value::<T>(example).and_then(serde_json::to_value))
        .collect()
}
