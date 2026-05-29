// SPDX-License-Identifier: Apache-2.0
//! Deterministic worker used by sidecar integration tests.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, BufRead, Write},
    path::PathBuf,
    process,
    time::Duration,
};

use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
struct Scenarios {
    records: BTreeMap<String, Vec<Value>>,
    outcomes: BTreeMap<String, Outcome>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Outcome {
    Records { records: Vec<Value> },
    SleepThenRecords { sleep_ms: u64, records: Vec<Value> },
    Stdout { stdout: String },
    OversizedRecords { repeat_bytes: usize },
    Exit { code: i32, stderr: Option<String> },
}

fn main() {
    if std::env::args().any(|arg| arg == "--version") {
        println!("cli_build_tool=1.36.0 runtime=1.36.0 @openfn/language-http@7.2.0");
        return;
    }

    let args = Args::parse();
    let scenarios = args
        .scenario_file
        .as_ref()
        .map(|path| {
            let raw = fs::read_to_string(path).expect("read scenario file");
            serde_json::from_str::<Scenarios>(&raw).expect("parse scenario file")
        })
        .unwrap_or_else(|| Scenarios {
            records: BTreeMap::new(),
            outcomes: BTreeMap::new(),
        });

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(_) => {
                println!("{}", json!({ "error": { "code": "invalid_request" } }));
                continue;
            }
        };
        let value = request["lookup"]["value"].as_str().unwrap_or_default();
        args.record_attempt(value);

        if let Some(outcome) = scenarios.outcomes.get(value) {
            handle_outcome(outcome, &mut stdout);
            continue;
        }

        let records = scenarios.records.get(value).cloned().unwrap_or_default();
        println!("{}", json!({ "data": records }));
    }
}

fn handle_outcome(outcome: &Outcome, stdout: &mut io::Stdout) {
    match outcome {
        Outcome::Records { records } => println!("{}", json!({ "data": records })),
        Outcome::SleepThenRecords { sleep_ms, records } => {
            std::thread::sleep(Duration::from_millis(*sleep_ms));
            println!("{}", json!({ "data": records }));
        }
        Outcome::Stdout { stdout: raw } => {
            let _ = write!(stdout, "{raw}");
            let _ = stdout.flush();
        }
        Outcome::OversizedRecords { repeat_bytes } => {
            println!(
                "{}",
                json!({ "data": [{ "blob": "x".repeat(*repeat_bytes) }] })
            )
        }
        Outcome::Exit { code, stderr } => {
            if let Some(stderr) = stderr {
                let _ = writeln!(io::stderr(), "{stderr}");
            }
            process::exit(*code);
        }
    }
}

#[derive(Debug, Default)]
struct Args {
    scenario_file: Option<PathBuf>,
    attempt_log: Option<PathBuf>,
}

impl Args {
    fn parse() -> Self {
        let mut args = std::env::args().skip(1);
        let mut parsed = Self::default();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--scenario-file" => parsed.scenario_file = args.next().map(PathBuf::from),
                "--attempt-log" => parsed.attempt_log = args.next().map(PathBuf::from),
                _ => {}
            }
        }
        parsed
    }

    fn record_attempt(&self, lookup_value: &str) {
        let Some(path) = &self.attempt_log else {
            return;
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open attempt log");
        writeln!(file, "{}", json!({ "lookup": lookup_value })).expect("write attempt log");
    }
}
