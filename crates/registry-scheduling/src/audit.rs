// SPDX-License-Identifier: Apache-2.0
//! Scheduling audit entries written through the platform audit writer.
//!
//! A commitment appends one `request` entry before its capacity transaction
//! opens and one `response` entry once the decision is known: after commit
//! for an allowed commitment, after rollback for a refused one. Both share a
//! correlation, which is also the `eventId` the response record carries.
//! Entries carry only pseudonymized references and closed codes, never a raw
//! principal, grant, claim identifier, or free-text reason.

use registry_platform_audit::{AuditEntry, AuditUnavailable, AuditWriter};
use serde_json::Value;
use uuid::Uuid;

/// The schema identifier every Scheduling audit entry carries.
pub const SCHEDULING_AUDIT_SCHEMA: &str = "registry-scheduling-audit/v1";

/// The process-wide Scheduling audit destination.
#[derive(Clone, Debug)]
pub struct SchedulingAudit {
    writer: AuditWriter,
}

impl SchedulingAudit {
    #[must_use]
    pub fn new(writer: AuditWriter) -> Self {
        Self { writer }
    }

    /// Whether the destination can still accept entries.
    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }

    /// Append one entry whose correlation is not a commitment's, such as a
    /// hook delivery attempt's.
    pub(crate) async fn append(&self, entry: AuditEntry) -> Result<(), AuditUnavailable> {
        self.writer.append(entry).await
    }

    /// Append the `request` entry of one audited operation. The caller opens
    /// no transaction unless this is accepted.
    pub async fn request(&self, correlation: Uuid, record: Value) -> Result<(), AuditUnavailable> {
        self.writer
            .append(AuditEntry::request(
                SCHEDULING_AUDIT_SCHEMA,
                correlation.to_string(),
                record,
            ))
            .await
    }

    /// Append the `response` entry of one audited operation.
    pub async fn response(&self, correlation: Uuid, record: Value) -> Result<(), AuditUnavailable> {
        self.writer
            .append(AuditEntry::response(
                SCHEDULING_AUDIT_SCHEMA,
                correlation.to_string(),
                record,
            ))
            .await
    }
}

/// The `request` form of an authorization record: every field the decision
/// is taken over, without the `outcome` and `reason` only the decision names.
#[must_use]
pub fn request_record(mut record: Value) -> Value {
    if let Some(fields) = record.as_object_mut() {
        fields.remove("outcome");
        fields.remove("reason");
    }
    record
}

/// Stamp a `response` record with its audit identity, refusing a record that
/// already carries a different one.
#[must_use]
pub fn with_event_id(event_id: Uuid, mut record: Value) -> Option<Value> {
    let fields = record.as_object_mut()?;
    let event_id = event_id.to_string();
    match fields.get("eventId") {
        Some(Value::String(existing)) if existing == &event_id => {}
        Some(_) => return None,
        None => {
            fields.insert("eventId".to_owned(), Value::String(event_id));
        }
    }
    Some(record)
}

#[cfg(any(test, feature = "postgres-test"))]
mod capture {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use registry_platform_audit::AuditWriter;
    use serde_json::Value;

    use super::SchedulingAudit;

    #[derive(Default)]
    struct CaptureState {
        bytes: Vec<u8>,
        accepted_lines: Option<usize>,
    }

    /// The lines a test audit destination accepted, and a switch that makes
    /// it refuse every line past a count.
    #[derive(Clone, Default)]
    pub struct AuditCapture(Arc<Mutex<CaptureState>>);

    impl AuditCapture {
        /// Every accepted entry, parsed, in write order.
        #[must_use]
        pub fn entries(&self) -> Vec<Value> {
            let state = self.0.lock().expect("audit capture");
            String::from_utf8(state.bytes.clone())
                .expect("audit lines are UTF-8")
                .lines()
                .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
                .collect()
        }

        /// The records of the accepted entries in `phase`, in write order.
        #[must_use]
        pub fn records(&self, phase: &str) -> Vec<Value> {
            self.entries()
                .into_iter()
                .filter(|entry| entry["phase"] == phase)
                .map(|entry| entry["record"].clone())
                .collect()
        }

        /// Refuse every line once `lines` in total have been accepted. A
        /// refused line stops the writer, as a failed destination does.
        pub fn refuse_after(&self, lines: usize) {
            self.0.lock().expect("audit capture").accepted_lines = Some(lines);
        }
    }

    impl Write for AuditCapture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut state = self.0.lock().expect("audit capture");
            let written = state.bytes.iter().filter(|byte| **byte == b'\n').count();
            if state.accepted_lines.is_some_and(|limit| written >= limit) {
                return Err(io::Error::other("audit destination refused the line"));
            }
            state.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SchedulingAudit {
        /// An audit destination held in memory, for tests.
        #[must_use]
        pub fn capture() -> (Self, AuditCapture) {
            let capture = AuditCapture::default();
            let writer = AuditWriter::from_line_sink(Box::new(capture.clone()));
            (Self::new(writer), capture)
        }
    }
}

#[cfg(any(test, feature = "postgres-test"))]
pub use capture::AuditCapture;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_response_record_is_stamped_with_its_identity_exactly_once() {
        let event_id = Uuid::new_v4();
        let record = with_event_id(event_id, json!({"event": "x"})).unwrap();
        assert_eq!(record["eventId"], event_id.to_string());
        // An agreeing stamp is accepted; a disagreeing one is refused.
        assert!(with_event_id(event_id, record.clone()).is_some());
        assert!(with_event_id(Uuid::new_v4(), json!({"eventId": "another"})).is_none());
    }

    #[test]
    fn a_request_record_omits_only_the_decision() {
        let record = request_record(json!({
            "actorKind": "service",
            "principalPseudonym": "p",
            "operation": "hold.create",
            "outcome": "allowed",
            "reason": "authorization.allowed",
        }));
        assert_eq!(
            record,
            json!({"actorKind": "service", "principalPseudonym": "p", "operation": "hold.create"})
        );
    }

    #[tokio::test]
    async fn request_and_response_share_one_correlation_under_the_schema() {
        let (audit, capture) = SchedulingAudit::capture();
        let correlation = Uuid::new_v4();
        audit
            .request(correlation, json!({"operation": "hold.create"}))
            .await
            .unwrap();
        audit
            .response(
                correlation,
                json!({"operation": "hold.create", "outcome": "allowed"}),
            )
            .await
            .unwrap();
        let entries = capture.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        for entry in &entries {
            assert_eq!(entry["schema"], SCHEDULING_AUDIT_SCHEMA);
            assert_eq!(entry["correlation"], correlation.to_string());
        }
    }

    #[tokio::test]
    async fn a_refused_line_stops_the_destination() {
        let (audit, capture) = SchedulingAudit::capture();
        capture.refuse_after(0);
        assert!(audit
            .request(Uuid::new_v4(), json!({"operation": "hold.create"}))
            .await
            .is_err());
        assert!(capture.entries().is_empty());
        assert!(!audit.ready().await);
    }
}
