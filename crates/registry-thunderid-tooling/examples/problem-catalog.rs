// SPDX-License-Identifier: Apache-2.0

//! Writes the front gateway's problem inventory for the identifier catalog.

use registry_thunderid_tooling::front_gateway::ProblemKind;
use serde_json::json;
use std::{env, fs, path::PathBuf, process::ExitCode};

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
    let entries: Vec<_> = ProblemKind::ALL
        .into_iter()
        .map(|kind| {
            json!({
                "uri": kind.type_uri(),
                "code": kind.code(),
                "title": kind.title(),
                "description": kind.description(),
                "httpStatuses": [kind.http_status()],
            })
        })
        .collect();
    let mut bytes = match serde_json::to_vec_pretty(&json!({"entries": entries})) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("Problem catalog serialization failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    bytes.push(b'\n');
    if let Err(error) = fs::write(PathBuf::from(output), bytes) {
        eprintln!("Problem catalog write failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("usage: problem-catalog --output <file>");
    ExitCode::from(2)
}
