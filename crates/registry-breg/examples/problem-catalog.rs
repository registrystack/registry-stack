// SPDX-License-Identifier: Apache-2.0

use std::{env, fs, path::PathBuf, process::ExitCode};

use registry_breg::problem::ProblemCode;
use serde::Serialize;

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
                description: problem.description(),
                http_statuses: [problem.status()],
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
    let output = PathBuf::from(output);
    if fs::write(output, bytes).is_err() {
        eprintln!("problem catalog could not be written");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
