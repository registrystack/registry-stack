// SPDX-License-Identifier: Apache-2.0
//! Relay audit lines captured in memory through the platform audit writer.
//!
//! `AuditLines` is a `std::io::Write` destination handed to
//! `AuditWriter::from_line_sink`, so every test drives the production writer:
//! a failed line stops that writer exactly as a failed file write would.
//! Reading the captured lines back checks the envelope contract every Relay
//! entry must meet.

#![allow(dead_code)]

use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use jsonschema::{Draft, JSONSchema};
use registry_platform_audit::AuditWriter;
use registry_relay_v2::artifacts::audit_event_schema;
use registry_relay_v2::audit::AUDIT_SCHEMA;
use serde_json::Value;

#[derive(Clone, Copy)]
enum Failure {
    Never,
    /// Refuse the Nth line (1-based). The writer then stops, so no later line
    /// reaches this destination.
    OnLine(usize),
    /// Refuse every `request` entry: the request entry is the last step before
    /// source access, so reaching it means the source would be read.
    OnRequestEntry,
}

struct State {
    failure: Failure,
    writes: AtomicUsize,
    request_entries: AtomicUsize,
    lines: Mutex<Vec<Value>>,
}

/// A shared, in-memory audit destination for one test.
#[derive(Clone)]
pub struct AuditLines {
    state: Arc<State>,
}

impl AuditLines {
    fn with_failure(failure: Failure) -> Self {
        Self {
            state: Arc::new(State {
                failure,
                writes: AtomicUsize::new(0),
                request_entries: AtomicUsize::new(0),
                lines: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Accept every line.
    pub fn recording() -> Self {
        Self::with_failure(Failure::Never)
    }

    /// Refuse the Nth line written (1-based).
    pub fn failing_on_line(line: usize) -> Self {
        Self::with_failure(Failure::OnLine(line))
    }

    /// Accept `successes` lines, then refuse the next one.
    pub fn failing_after(successes: usize) -> Self {
        Self::with_failure(Failure::OnLine(successes + 1))
    }

    /// Refuse every `request` entry and count how many reached this
    /// destination.
    pub fn source_access_tripwire() -> Self {
        Self::with_failure(Failure::OnRequestEntry)
    }

    /// A production audit writer over this destination.
    pub fn writer(&self) -> AuditWriter {
        AuditWriter::from_line_sink(Box::new(LineSink {
            state: Arc::clone(&self.state),
        }))
    }

    /// Lines offered to this destination, including a refused one.
    pub fn writes(&self) -> usize {
        self.state.writes.load(Ordering::SeqCst)
    }

    /// `request` entries that reached a tripwire destination.
    pub fn request_entries_reached(&self) -> usize {
        self.state.request_entries.load(Ordering::SeqCst)
    }

    /// Every accepted line, after checking the envelope contract.
    pub fn entries(&self) -> Vec<Value> {
        let entries = self.state.lines.lock().expect("audit lines lock").clone();
        for entry in &entries {
            assert_relay_envelope(entry);
        }
        entries
    }

    /// The Relay record nested in every accepted line.
    pub fn values(&self) -> Vec<Value> {
        self.entries()
            .into_iter()
            .map(|mut entry| entry["record"].take())
            .collect()
    }
}

/// Check one Relay audit line: the platform envelope with exactly its six
/// members, Relay's schema, the phase implied by the record's own phase, the
/// operation identifier as the correlation, and conformance to the audit
/// event schema every package publishes.
pub fn assert_relay_envelope(entry: &Value) {
    let published = audit_event_schema();
    let validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&published)
        .expect("the published audit event schema compiles");
    if let Err(errors) = validator.validate(entry) {
        let errors = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("audit line does not match the published schema: {errors:?}");
    }
    let object = entry.as_object().expect("an audit line is a JSON object");
    let mut members = object.keys().map(String::as_str).collect::<Vec<_>>();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "correlation",
            "eventId",
            "phase",
            "record",
            "schema",
            "time"
        ],
        "an audit line carries only the envelope members"
    );
    assert_eq!(entry["schema"], AUDIT_SCHEMA);
    assert!(entry["eventId"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(entry["time"]
        .as_str()
        .is_some_and(|time| time.ends_with('Z')));
    let record = entry["record"]
        .as_object()
        .expect("the Relay record is a JSON object");
    assert!(
        !record.contains_key("schema"),
        "the schema identifier lives in the envelope"
    );
    let expected_phase = match record.get("phase").and_then(Value::as_str) {
        Some("attempt") => "request",
        Some("refusal" | "terminal") => "response",
        other => panic!("unexpected Relay audit phase {other:?}"),
    };
    assert_eq!(entry["phase"], expected_phase);
    assert_eq!(
        entry["correlation"], record["operationId"],
        "the operation identifier correlates request and response entries"
    );
}

struct LineSink {
    state: Arc<State>,
}

impl Write for LineSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let line = self.state.writes.fetch_add(1, Ordering::SeqCst) + 1;
        let text = std::str::from_utf8(buffer).expect("an audit line is UTF-8");
        let text = text
            .strip_suffix('\n')
            .expect("the writer offers one complete line per write");
        let entry: Value = serde_json::from_str(text).expect("an audit line is JSON");
        match self.state.failure {
            Failure::OnLine(failing) if failing == line => {
                return Err(io::Error::other("controlled audit failure"));
            }
            Failure::OnRequestEntry if entry["phase"] == "request" => {
                self.state.request_entries.fetch_add(1, Ordering::SeqCst);
                return Err(io::Error::other("source access tripwire reached"));
            }
            _ => {}
        }
        self.state
            .lines
            .lock()
            .expect("audit lines lock")
            .push(entry);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
