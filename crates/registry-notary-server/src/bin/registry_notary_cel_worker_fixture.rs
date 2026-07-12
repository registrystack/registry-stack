// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "registry-notary-cel")]

use std::env;
use std::io::{self, BufRead, Write};
use std::process;
use std::thread;
use std::time::Duration;

use registry_notary_server::cel_worker::{
    CelWorkerRequest, CelWorkerResponse, CelWorkerResponseOutcome, CEL_WORKER_PROTOCOL_V1,
};
use serde_json::Value;

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => process::exit(2),
        };
        let request = match serde_json::from_str::<CelWorkerRequest>(&line) {
            Ok(request) => request,
            Err(_) => {
                write_response(&mut stdout, None, None, Some("invalid_request"));
                continue;
            }
        };
        if request.protocol != CEL_WORKER_PROTOCOL_V1 {
            write_response(
                &mut stdout,
                request.policy_hash.as_deref(),
                None,
                Some("invalid_request"),
            );
            continue;
        }

        match request.expression.as_str() {
            "fixture.hang" => loop {
                thread::sleep(Duration::from_secs(60));
            },
            "fixture.big_stdout" => {
                let bytes = request
                    .root_bindings
                    .get("stdout_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(1024) as usize;
                let _ = stdout.write_all(vec![b'x'; bytes].as_slice());
                let _ = stdout.write_all(b"\n");
                let _ = stdout.flush();
            }
            "fixture.stderr_then_crash" => {
                let secret = request
                    .root_bindings
                    .get("secret")
                    .and_then(Value::as_str)
                    .unwrap_or("fixture-secret");
                let bytes = request
                    .root_bindings
                    .get("stderr_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(1024) as usize;
                let mut written = 0_usize;
                while written < bytes {
                    let chunk = secret.as_bytes();
                    let remaining = bytes - written;
                    let size = remaining.min(chunk.len());
                    let _ = stderr.write_all(&chunk[..size]);
                    written += size;
                }
                let _ = stderr.flush();
                process::exit(7);
            }
            "fixture.env" => {
                let mut values = serde_json::Map::new();
                for key in request
                    .root_bindings
                    .get("env_keys")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    values.insert(
                        key.to_string(),
                        env::var(key).map_or(Value::Null, Value::String),
                    );
                }
                write_response(
                    &mut stdout,
                    request.policy_hash.as_deref(),
                    Some(Value::Object(values)),
                    None,
                );
            }
            "fixture.value" => {
                write_response(
                    &mut stdout,
                    request.policy_hash.as_deref(),
                    Some(
                        request
                            .root_bindings
                            .get("value")
                            .cloned()
                            .unwrap_or(Value::Null),
                    ),
                    None,
                );
            }
            _ => write_response(
                &mut stdout,
                request.policy_hash.as_deref(),
                None,
                Some("evaluate"),
            ),
        }
    }
}

fn write_response(
    stdout: &mut io::Stdout,
    policy_hash: Option<&str>,
    value: Option<Value>,
    error: Option<&str>,
) {
    let outcome = match (value, error) {
        (Some(value), None) => CelWorkerResponseOutcome::Success { value },
        (None, Some(error)) => CelWorkerResponseOutcome::Error {
            error: error.to_string(),
        },
        _ => panic!("fixture response must be exactly one of success or error"),
    };
    let response = CelWorkerResponse {
        protocol: CEL_WORKER_PROTOCOL_V1.to_string(),
        policy_hash: policy_hash.map(str::to_string),
        outcome,
    };
    serde_json::to_writer(&mut *stdout, &response).expect("write fixture response");
    stdout
        .write_all(b"\n")
        .expect("write fixture response newline");
    stdout.flush().expect("flush fixture response");
}
