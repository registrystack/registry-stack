// SPDX-License-Identifier: Apache-2.0

use registry_scheduling_core::{type_uri, ProblemCode};
use serde::Serialize;
use std::{env, fs, path::PathBuf, process::ExitCode};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProblemCatalog<'a> {
    entries: Vec<ProblemEntry<'a>>,
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
        return usage();
    };
    let Some(output) = arguments.next() else {
        return usage();
    };
    if flag != "--output" || arguments.next().is_some() {
        return usage();
    }

    let catalog = ProblemCatalog {
        entries: ProblemCode::ALL
            .iter()
            .copied()
            .map(|problem| ProblemEntry {
                uri: type_uri(problem.code()),
                code: problem.code(),
                title: problem.title(),
                description: problem.detail(),
                http_statuses: [problem.http_status()],
            })
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

fn usage() -> ExitCode {
    eprintln!("usage: problem-catalog --output <file>");
    ExitCode::from(2)
}
