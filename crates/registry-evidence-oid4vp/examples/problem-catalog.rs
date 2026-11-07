// SPDX-License-Identifier: Apache-2.0

use std::{env, fs, path::PathBuf, process::ExitCode};

use registry_evidence_oid4vp::problem::ProblemCode;
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
    let (Some(flag), Some(output)) = (arguments.next(), arguments.next()) else {
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
                uri: problem.type_uri(),
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
