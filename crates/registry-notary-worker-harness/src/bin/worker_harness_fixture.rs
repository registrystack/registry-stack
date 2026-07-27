use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env, fs,
    io::{self, BufRead, Write},
    process, thread,
    time::Duration,
};

#[derive(Deserialize)]
struct FixtureRequest {
    mode: Option<String>,
    sleep_ms: Option<u64>,
    stdout_bytes: Option<usize>,
    stderr_bytes: Option<usize>,
    stderr_payload: Option<String>,
    env_keys: Option<Vec<String>>,
    value: Option<Value>,
}

fn main() {
    let start_ordinal = claim_start_ordinal_if_configured();
    fail_start_ordinal_if_configured(start_ordinal);
    exit_once_on_start_if_configured();
    fail_after_first_start_if_configured();

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    prewrite_stdout_if_configured(&mut stdout);

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => process::exit(2),
        };
        let request = match serde_json::from_str::<FixtureRequest>(&line) {
            Ok(request) => request,
            Err(error) => {
                let _ = writeln!(stderr, "invalid request: {error}");
                process::exit(2);
            }
        };

        match request.mode.as_deref() {
            Some("startup") => {
                write_json(&mut stdout, json!({ "ready": true }));
                exit_initial_workers_after_startup_if_configured(start_ordinal);
            }
            Some("startup-sleep") => {
                thread::sleep(Duration::from_millis(request.sleep_ms.unwrap_or(100)));
                write_json(&mut stdout, json!({ "ready": true }));
            }
            Some("sleep") => {
                thread::sleep(Duration::from_millis(request.sleep_ms.unwrap_or(100)));
                write_json(&mut stdout, json!({ "ok": true, "pid": process::id() }));
            }
            Some("hang") => loop {
                thread::sleep(Duration::from_secs(60));
            },
            Some("big-stdout") => {
                let bytes = request.stdout_bytes.unwrap_or(1024);
                let _ = stdout.write_all(vec![b'x'; bytes].as_slice());
                let _ = stdout.write_all(b"\n");
                let _ = stdout.flush();
            }
            Some("stderr-then-crash") => {
                let bytes = request.stderr_bytes.unwrap_or(1024);
                let payload = request.stderr_payload.unwrap_or_else(|| "e".to_string());
                write_repeated(&mut stderr, payload.as_bytes(), bytes);
                let _ = stderr.flush();
                process::exit(7);
            }
            Some("env") => {
                let mut values = serde_json::Map::new();
                for key in request.env_keys.unwrap_or_default() {
                    values.insert(
                        key.clone(),
                        env::var(&key).map_or(Value::Null, Value::String),
                    );
                }
                write_json(
                    &mut stdout,
                    json!({ "ok": true, "pid": process::id(), "env": values }),
                );
            }
            Some("exit") => {
                process::exit(6);
            }
            _ => {
                write_json(
                    &mut stdout,
                    json!({
                        "ok": true,
                        "pid": process::id(),
                        "value": request.value,
                    }),
                );
            }
        }
    }
}

fn claim_start_ordinal_if_configured() -> Option<usize> {
    let directory = env::var_os("WORKER_HARNESS_START_ORDINAL_DIR")?;
    for ordinal in 1..=1024 {
        match fs::create_dir(std::path::Path::new(&directory).join(ordinal.to_string())) {
            Ok(()) => return Some(ordinal),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => process::exit(8),
        }
    }
    process::exit(8);
}

fn fail_start_ordinal_if_configured(start_ordinal: Option<usize>) {
    let Some(fail_ordinal) = env::var("WORKER_HARNESS_FAIL_START_ORDINAL")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return;
    };
    if start_ordinal == Some(fail_ordinal) {
        process::exit(7);
    }
}

fn exit_initial_workers_after_startup_if_configured(start_ordinal: Option<usize>) {
    let Some(exit_through) = env::var("WORKER_HARNESS_EXIT_START_ORDINALS_THROUGH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return;
    };
    if start_ordinal.is_none_or(|ordinal| ordinal > exit_through) {
        return;
    }
    let delay = env::var("WORKER_HARNESS_EXIT_AFTER_STARTUP_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100);
    thread::sleep(Duration::from_millis(delay));
    process::exit(0);
}

fn fail_after_first_start_if_configured() {
    let Some(path) = env::var_os("WORKER_HARNESS_FAIL_AFTER_FIRST_START_STATE") else {
        return;
    };
    match fs::read_to_string(&path) {
        Ok(contents) if contents.trim() == "started" => process::exit(7),
        _ => fs::write(path, "started\n").expect("write fixture first-start state"),
    }
}

fn prewrite_stdout_if_configured(stdout: &mut io::Stdout) {
    let Some(bytes) = env::var("WORKER_HARNESS_PREWRITE_STDOUT_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return;
    };
    write_json(
        stdout,
        json!({
            "ok": true,
            "pid": process::id(),
            "prewritten": "x".repeat(bytes),
        }),
    );
}

fn exit_once_on_start_if_configured() {
    let Some(path) = env::var_os("WORKER_HARNESS_EXIT_ONCE_STATE") else {
        return;
    };
    match fs::read_to_string(&path) {
        Ok(contents) if contents.trim() == "exited" => {}
        _ => {
            fs::write(path, "exited\n").expect("write fixture state");
            process::exit(7);
        }
    }
}

fn write_json(stdout: &mut io::Stdout, value: Value) {
    serde_json::to_writer(&mut *stdout, &value).expect("write fixture response");
    stdout.write_all(b"\n").expect("write fixture newline");
    stdout.flush().expect("flush fixture response");
}

fn write_repeated(stderr: &mut io::Stderr, payload: &[u8], bytes: usize) {
    if payload.is_empty() {
        let _ = stderr.write_all(vec![b'e'; bytes].as_slice());
        return;
    }

    let mut written = 0;
    while written < bytes {
        let remaining = bytes - written;
        let chunk_len = remaining.min(payload.len());
        let _ = stderr.write_all(&payload[..chunk_len]);
        written += chunk_len;
    }
}
