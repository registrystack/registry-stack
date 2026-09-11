// SPDX-License-Identifier: Apache-2.0

use std::{env, fs, path::PathBuf, process::ExitCode};

use registry_casework::problem::{
    OperationContract, ProblemCode, FRAMEWORK_PROBLEMS, OPERATION_CONTRACTS,
};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProblemCatalog<'a> {
    entries: Vec<ProblemEntry<'a>>,
    framework_problems: Vec<&'a str>,
    operations: Vec<OperationEntry<'a>>,
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
