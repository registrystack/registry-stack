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
    env_keys: Option<Vec<String>>,
    value: Option<Value>,
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

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
                let _ = stderr.write_all(vec![b'e'; bytes].as_slice());
                let _ = stderr.flush();
                process::exit(7);
            }
            Some("fail-once-invalid-json") => {
                if mark_first_failure() {
                    let _ = writeln!(stdout, "not-json");
                    let _ = stdout.flush();
                } else {
                    write_json(&mut stdout, json!({ "ok": true, "pid": process::id() }));
                }
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
            #[cfg(unix)]
            Some("rlimits") => {
                write_json(
                    &mut stdout,
                    json!({
                        "ok": true,
                        "pid": process::id(),
                        "rlimits": resource_limits(),
                    }),
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

#[cfg(unix)]
fn resource_limits() -> serde_json::Map<String, Value> {
    let limits = serde_json::Map::from_iter([
        ("cpu".to_string(), resource_limit(libc::RLIMIT_CPU)),
        ("fsize".to_string(), resource_limit(libc::RLIMIT_FSIZE)),
        ("nofile".to_string(), resource_limit(libc::RLIMIT_NOFILE)),
        ("core".to_string(), resource_limit(libc::RLIMIT_CORE)),
    ]);
    #[cfg(target_os = "linux")]
    {
        let mut limits = limits;
        limits.insert("nproc".to_string(), resource_limit(libc::RLIMIT_NPROC));
        limits
    }
    #[cfg(not(target_os = "linux"))]
    limits
}

#[cfg(unix)]
#[cfg(target_os = "linux")]
type RlimitResource = libc::__rlimit_resource_t;

#[cfg(unix)]
#[cfg(not(target_os = "linux"))]
type RlimitResource = libc::c_int;

#[cfg(unix)]
fn resource_limit(resource: RlimitResource) -> Value {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe { libc::getrlimit(resource, &mut limit) };
    if result == 0 {
        json!({
            "soft": limit.rlim_cur,
            "hard": limit.rlim_max,
        })
    } else {
        Value::Null
    }
}

fn write_json(stdout: &mut io::Stdout, value: Value) {
    serde_json::to_writer(&mut *stdout, &value).expect("write fixture response");
    stdout.write_all(b"\n").expect("write fixture newline");
    stdout.flush().expect("flush fixture response");
}

fn mark_first_failure() -> bool {
    let Some(path) = env::var_os("WORKER_FIXTURE_STATE") else {
        return true;
    };

    match fs::read_to_string(&path) {
        Ok(contents) if contents.trim() == "failed" => false,
        _ => {
            fs::write(path, "failed\n").expect("write fixture state");
            true
        }
    }
}
