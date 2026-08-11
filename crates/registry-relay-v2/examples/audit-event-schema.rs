// SPDX-License-Identifier: Apache-2.0

use std::{env, fs, path::PathBuf, process::ExitCode};

use registry_relay_v2::artifacts::audit_event_schema;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(flag) = arguments.next() else {
        eprintln!("usage: audit-event-schema --output <file>");
        return ExitCode::from(2);
    };
    let Some(output) = arguments.next() else {
        eprintln!("usage: audit-event-schema --output <file>");
        return ExitCode::from(2);
    };
    if flag != "--output" || arguments.next().is_some() {
        eprintln!("usage: audit-event-schema --output <file>");
        return ExitCode::from(2);
    }

    let mut bytes = match serde_json::to_vec_pretty(&audit_event_schema()) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("audit event schema could not be serialized");
            return ExitCode::FAILURE;
        }
    };
    bytes.push(b'\n');
    if fs::write(PathBuf::from(output), bytes).is_err() {
        eprintln!("audit event schema could not be written");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
