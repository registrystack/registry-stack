// SPDX-License-Identifier: Apache-2.0
//! Casework audit entries written through the platform audit writer.
//!
//! Every audited operation appends one `request` entry before its transaction
//! opens and, once the transaction commits, one `response` entry per domain
//! event it recorded, all sharing one correlation. A caller-requested
//! operation that recorded no domain event, such as an idempotent replay,
//! appends one `response` entry naming its terminal outcome instead, so no
//! caller-requested result is released without an accepted `response` entry.
//! One that returns without committing, a refusal, a failure, or a canceled
//! request, appends `{event, outcome: "unfinished"}` as its `response` entry
//! when its operation is dropped, so no `request` entry stays unpaired.
//! Entries carry only event metadata and keyed references, never source
//! selectors, free-text reasons, receipts, or issuer and subject identities.

use registry_platform_audit::{AuditEntry, AuditKeyHasher, AuditRequest, AuditWriter};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::StoreError;

/// The schema identifier every Casework audit entry carries.
pub const CASEWORK_AUDIT_SCHEMA: &str = "registry-casework-audit/v1";

/// The profile the task-grant invalidation trigger records its events under.
const TASK_GRANT_SYSTEM_PROFILE: &str = "system:task-grants";

/// The process-wide Casework audit destination and the key that pseudonymizes
/// identifiers before they reach it.
#[derive(Clone)]
pub struct CaseworkAudit {
    writer: AuditWriter,
    identifiers: AuditKeyHasher,
}

impl std::fmt::Debug for CaseworkAudit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaseworkAudit")
            .field("writer", &self.writer)
            .finish_non_exhaustive()
    }
}

impl CaseworkAudit {
    #[must_use]
    pub fn new(writer: AuditWriter, identifiers: AuditKeyHasher) -> Self {
        Self {
            writer,
            identifiers,
        }
    }

    /// Whether the destination can still accept entries.
    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }

    /// Append the `request` entry of one audited operation. The caller opens
    /// no transaction and reads no protected row unless this is accepted.
    pub(crate) async fn begin(&self, request: Value) -> Result<AuditOperation, StoreError> {
        let record = self.minimized(request)?;
        let event = record
            .get("event")
            .and_then(Value::as_str)
            .ok_or(StoreError::Corrupt)?
            .to_owned();
        let unfinished = self.minimized(json!({"event": event, "outcome": "unfinished"}))?;
        let request = self
            .writer
            .begin(
                CASEWORK_AUDIT_SCHEMA,
                Uuid::new_v4().to_string(),
                record,
                unfinished,
            )
            .await
            .map_err(|_| StoreError::AuditUnavailable)?;
        Ok(AuditOperation {
            audit: self.clone(),
            pairing: Pairing::Requested { request, event },
            outcome: None,
            responses: Vec::new(),
        })
    }

    /// Start an audited unit of background work that no caller requested,
    /// such as reconciliation or a clock pass. It writes no `request` entry;
    /// its `response` entries share a correlation that identifies this run.
    /// A stopped destination refuses the work before its transaction opens.
    pub(crate) async fn begin_background(&self) -> Result<AuditOperation, StoreError> {
        if !self.writer.ready().await {
            return Err(StoreError::AuditUnavailable);
        }
        Ok(AuditOperation {
            audit: self.clone(),
            pairing: Pairing::Background {
                correlation: Uuid::new_v4().to_string(),
            },
            outcome: None,
            responses: Vec::new(),
        })
    }

    /// The key that pseudonymizes identifiers for this destination.
    #[must_use]
    pub(crate) fn identifiers(&self) -> AuditKeyHasher {
        self.identifiers.clone()
    }

    fn minimized(&self, record: Value) -> Result<Value, StoreError> {
        published_audit_record(record, &self.identifiers).map_err(|()| StoreError::Corrupt)
    }
}

/// `identifiers` is a JSON object of the identifiers the request names, keyed
/// by the record field that carries them (`itemId`, `grantId`, `teamId`,
/// `queueId`); minimization keeps only their keyed pseudonyms.
///
/// The `request` fields an audited operation names before it opens its
/// transaction: the event it performs, the caller's profile and pseudonymized
/// principal, and the identifiers the request names.
pub(crate) fn request_record(
    event: &str,
    actor: Option<&registry_casework_core::ActorContext>,
    profile_id: &str,
    identifiers: Value,
) -> Value {
    let mut record = Map::new();
    record.insert(
        "event".to_owned(),
        Value::String(format!("casework.{event}")),
    );
    record.insert("profileId".to_owned(), Value::String(profile_id.to_owned()));
    if let Some(actor) = actor {
        record.insert(
            "actor".to_owned(),
            json!({"issuer": actor.principal.issuer, "subject": actor.principal.subject}),
        );
    }
    if let Value::Object(identifiers) = identifiers {
        record.extend(identifiers);
    }
    Value::Object(record)
}

/// The terminal outcome of a caller-requested operation that succeeded
/// without recording a domain event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditOutcome {
    /// It returned the result retained for an earlier request it repeats,
    /// such as one under the same idempotency key.
    Replayed,
    /// The state it asked for already held, so it recorded no domain event.
    Unchanged,
}

impl AuditOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Replayed => "replayed",
            Self::Unchanged => "unchanged",
        }
    }
}

/// One audited operation whose `request` entry was accepted. It collects the
/// minimized `response` records its transaction produces and appends them
/// once the transaction commits. Dropped before then, a caller-requested
/// operation appends its `unfinished` response entry.
#[must_use = "an audited operation appends its response entries only when completed"]
pub(crate) struct AuditOperation {
    audit: CaseworkAudit,
    pairing: Pairing,
    outcome: Option<AuditOutcome>,
    responses: Vec<(Uuid, Value)>,
}

/// How an operation's `response` entries are correlated.
enum Pairing {
    /// A caller-requested operation: its accepted `request` entry, which owes
    /// the `response` entries, and the event that entry names.
    Requested {
        request: AuditRequest,
        event: String,
    },
    /// Background work no caller requested, which writes no `request` entry.
    Background { correlation: String },
}

impl AuditOperation {
    /// Name the terminal outcome of a caller-requested operation that may
    /// record no domain event. It is appended as the operation's `response`
    /// entry only when no domain event was recorded; background work ignores
    /// it.
    pub(crate) fn record_outcome(&mut self, outcome: AuditOutcome) {
        self.outcome = Some(outcome);
    }

    /// Refuse a caller-requested operation that has neither a domain event
    /// nor a terminal outcome to append, since its result would leave without
    /// an accepted `response` entry.
    fn ensure_terminal(&self) -> Result<(), StoreError> {
        if matches!(self.pairing, Pairing::Requested { .. })
            && self.responses.is_empty()
            && self.outcome.is_none()
        {
            tracing::error!(
                "a Casework audited operation has no response entry to append; its result is withheld"
            );
            return Err(StoreError::AuditUnavailable);
        }
        Ok(())
    }

    /// Record one domain event. A record that cannot be minimized fails the
    /// caller before its transaction commits.
    pub(crate) fn record(&mut self, event_id: Uuid, record: Value) -> Result<(), StoreError> {
        let record =
            audit_record_with_event_id(event_id, record).map_err(|()| StoreError::Corrupt)?;
        let record = self.audit.minimized(record)?;
        self.responses.push((event_id, record));
        Ok(())
    }

    /// Record the task-grant invalidations the directory and item triggers
    /// wrote inside this transaction. Call it immediately before commit.
    pub(crate) async fn collect_task_invalidations(
        &mut self,
        transaction: &tokio_postgres::Transaction<'_>,
    ) -> Result<(), StoreError> {
        let rows = transaction
            .query(
                "SELECT event_id,item_id,detail->>'grantId' FROM casework_history
                 WHERE kind='task_invalidated' AND profile_id=$1 AND occurred_at=now()
                   AND xmin=pg_current_xact_id()::xid
                 ORDER BY event_id",
                &[&TASK_GRANT_SYSTEM_PROFILE],
            )
            .await?;
        for row in rows {
            let event_id: Uuid = row.get(0);
            if self
                .responses
                .iter()
                .any(|(recorded, _)| *recorded == event_id)
            {
                continue;
            }
            let item_id: Uuid = row.get(1);
            let grant_id: Option<String> = row.get(2);
            self.record(
                event_id,
                json!({
                    "event": "casework.task_invalidated",
                    "eventId": event_id,
                    "itemId": item_id,
                    "grantId": grant_id.ok_or(StoreError::Corrupt)?,
                    "profileId": TASK_GRANT_SYSTEM_PROFILE,
                }),
            )?;
        }
        Ok(())
    }

    /// Collect the trigger-written invalidations, commit `transaction`, and
    /// append one `response` entry per recorded event, or the terminal
    /// outcome when none was recorded. A caller-requested operation with
    /// neither is refused before `transaction` commits.
    pub(crate) async fn commit(
        mut self,
        transaction: deadpool_postgres::Transaction<'_>,
    ) -> Result<(), StoreError> {
        self.collect_task_invalidations(&transaction).await?;
        self.ensure_terminal()?;
        transaction.commit().await?;
        self.complete().await
    }

    /// Append one `response` entry per recorded event, or one naming the
    /// terminal outcome of a caller-requested operation that recorded none.
    /// The caller's transaction has committed, so a refusal here reports the
    /// destination unavailable while the committed change stays in place.
    pub(crate) async fn complete(self) -> Result<(), StoreError> {
        self.ensure_terminal()?;
        let Self {
            audit,
            mut pairing,
            outcome,
            responses,
        } = self;
        let mut records: Vec<Value> = responses.into_iter().map(|(_, record)| record).collect();
        if records.is_empty() {
            if let (Pairing::Requested { event, .. }, Some(outcome)) = (&pairing, outcome) {
                records
                    .push(audit.minimized(json!({"event": event, "outcome": outcome.as_str()}))?);
            }
        }
        for record in records {
            match &mut pairing {
                Pairing::Requested { request, .. } => request.respond(record).await,
                Pairing::Background { correlation } => {
                    audit
                        .writer
                        .append(AuditEntry::response(
                            CASEWORK_AUDIT_SCHEMA,
                            correlation.clone(),
                            record,
                        ))
                        .await
                }
            }
            .map_err(|_| StoreError::AuditUnavailable)?;
        }
        Ok(())
    }
}

/// The journal carries only event metadata and keyed references, never source
/// selectors, free-text reasons, receipts, or issuer/subject identities.
fn published_audit_record(record: Value, identifiers: &AuditKeyHasher) -> Result<Value, ()> {
    let raw = record.as_object().ok_or(())?;
    let mut published = Map::new();
    for field in [
        "event",
        "eventId",
        "profileId",
        "itemRevision",
        "directoryRevision",
        "actorRef",
        "accountabilityEventId",
        "outcome",
    ] {
        if let Some(value) = raw.get(field) {
            published.insert(field.to_owned(), value.clone());
        }
    }
    for (field, output) in [
        ("itemId", "itemPseudonym"),
        ("grantId", "grantPseudonym"),
        ("teamId", "teamPseudonym"),
        ("queueId", "queuePseudonym"),
    ] {
        if let Some(value) = raw.get(field) {
            let value = value.as_str().ok_or(())?;
            let hash = reference_pseudonym(identifiers, field, value)?;
            published.insert(output.to_owned(), Value::String(hash));
        }
    }
    if let Some(actor) = raw.get("actor").filter(|value| !value.is_null()) {
        let issuer = actor.get("issuer").and_then(Value::as_str).ok_or(())?;
        let subject = actor.get("subject").and_then(Value::as_str).ok_or(())?;
        let hash = principal_pseudonym(identifiers, issuer, subject)?;
        published.insert("principalPseudonym".to_owned(), Value::String(hash));
    }
    Ok(Value::Object(published))
}

/// The keyed pseudonym of an identifier the record names in `field`.
fn reference_pseudonym(
    identifiers: &AuditKeyHasher,
    field: &str,
    value: &str,
) -> Result<String, ()> {
    identifiers
        .audit_reference_hash("casework-reference-v1", field, value)
        .map_err(|_| ())
}

/// The keyed pseudonym of an issuer-scoped principal.
fn principal_pseudonym(
    identifiers: &AuditKeyHasher,
    issuer: &str,
    subject: &str,
) -> Result<String, ()> {
    let canonical = serde_json::to_string(&(issuer, subject)).map_err(|_| ())?;
    identifiers
        .audit_reference_hash("casework-principal-v1", "", &canonical)
        .map_err(|_| ())
}

fn audit_record_with_event_id(event_id: Uuid, mut record: Value) -> Result<Value, ()> {
    let fields = record.as_object_mut().ok_or(())?;
    let event_id = event_id.to_string();
    match fields.get("eventId") {
        Some(Value::String(existing)) if existing == &event_id => {}
        Some(_) => return Err(()),
        None => {
            fields.insert("eventId".to_owned(), Value::String(event_id));
        }
    }
    Ok(record)
}

#[cfg(any(test, feature = "postgres-test"))]
mod capture {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use registry_platform_audit::{AuditKeyHasher, AuditWriter};
    use serde_json::Value;

    use super::CaseworkAudit;

    #[derive(Default)]
    struct CaptureState {
        bytes: Vec<u8>,
        accepted_lines: Option<usize>,
        /// The writer recording here, so a read can wait for the entries it
        /// writes when a request handle is dropped.
        writer: Option<AuditWriter>,
    }

    /// The lines a test audit destination accepted, and a switch that makes
    /// it refuse every line past a count.
    #[derive(Clone, Default)]
    pub struct AuditCapture(Arc<Mutex<CaptureState>>);

    impl AuditCapture {
        /// Every accepted entry, parsed, in write order.
        #[must_use]
        pub fn entries(&self) -> Vec<Value> {
            let writer = self.0.lock().expect("audit capture").writer.clone();
            if let Some(writer) = writer {
                writer.wait_for_detached_entries();
            }
            let state = self.0.lock().expect("audit capture");
            String::from_utf8(state.bytes.clone())
                .expect("audit lines are UTF-8")
                .lines()
                .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
                .collect()
        }

        /// The records of the accepted `response` entries for `event`
        /// (without its `casework.` prefix), in write order.
        #[must_use]
        pub fn responses(&self, event: &str) -> Vec<Value> {
            let event = format!("casework.{event}");
            self.entries()
                .into_iter()
                .filter(|entry| entry["phase"] == "response" && entry["record"]["event"] == event)
                .map(|entry| entry["record"].clone())
                .collect()
        }

        /// The pseudonym an identifier named in `field` carries in the
        /// entries of this destination.
        #[must_use]
        pub fn reference(&self, field: &str, value: &str) -> String {
            super::reference_pseudonym(&AuditKeyHasher::unkeyed_dev_only(), field, value)
                .expect("pseudonymize a test identifier")
        }

        /// The pseudonym a principal carries in the entries of this
        /// destination.
        #[must_use]
        pub fn principal(&self, issuer: &str, subject: &str) -> String {
            super::principal_pseudonym(&AuditKeyHasher::unkeyed_dev_only(), issuer, subject)
                .expect("pseudonymize a test principal")
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

    impl CaseworkAudit {
        /// An audit destination held in memory, for tests.
        #[must_use]
        pub fn capture() -> (Self, AuditCapture) {
            let capture = AuditCapture::default();
            let writer = AuditWriter::from_line_sink(Box::new(capture.clone()));
            capture.0.lock().expect("audit capture").writer = Some(writer.clone());
            (
                Self::new(writer, AuditKeyHasher::unkeyed_dev_only()),
                capture,
            )
        }
    }
}

#[cfg(any(test, feature = "postgres-test"))]
pub use capture::AuditCapture;

#[cfg(test)]
mod tests {
    use registry_casework_core::{ActorContext, CaseworkRole, IssuerPrincipal};

    use super::*;

    fn actor() -> ActorContext {
        ActorContext {
            principal: IssuerPrincipal {
                issuer: "https://identity.example.test".to_owned(),
                subject: "officer-7".to_owned(),
            },
            profile_id: "officer".to_owned(),
            role: CaseworkRole::Staff,
        }
    }

    #[tokio::test]
    async fn one_operation_shares_its_correlation_across_request_and_responses() {
        let (audit, capture) = CaseworkAudit::capture();
        let item = Uuid::new_v4();
        let actor = actor();
        let mut operation = audit
            .begin(request_record(
                "claimed",
                Some(&actor),
                &actor.profile_id,
                json!({"itemId": item}),
            ))
            .await
            .unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        operation
            .record(first, json!({"event": "casework.claimed", "eventId": first, "itemId": item, "itemRevision": 2, "profileId": "officer"}))
            .unwrap();
        operation
            .record(second, json!({"event": "casework.task_invalidated", "itemId": item, "grantId": Uuid::new_v4().to_string(), "profileId": "system:task-grants"}))
            .unwrap();
        operation.complete().await.unwrap();

        let entries = capture.entries();
        assert_eq!(entries.len(), 3);
        let correlation = entries[0]["correlation"].as_str().unwrap();
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[2]["phase"], "response");
        for entry in &entries {
            assert_eq!(entry["schema"], CASEWORK_AUDIT_SCHEMA);
            assert_eq!(entry["correlation"], correlation);
        }
        let request = entries[0]["record"].as_object().unwrap();
        let mut fields: Vec<_> = request.keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            ["event", "itemPseudonym", "principalPseudonym", "profileId"]
        );
        assert_eq!(request["event"], "casework.claimed");
        assert_eq!(entries[1]["record"]["eventId"], first.to_string());
        assert_eq!(entries[1]["record"]["itemRevision"], 2);
        assert_eq!(entries[2]["record"]["eventId"], second.to_string());
        let rendered = serde_json::to_string(&entries).unwrap();
        for raw in [
            item.to_string().as_str(),
            "officer-7",
            "https://identity.example.test",
        ] {
            assert!(
                !rendered.contains(raw),
                "an entry repeats {raw} in the clear"
            );
        }
    }

    #[tokio::test]
    async fn a_refused_request_entry_starts_no_operation() {
        let (audit, capture) = CaseworkAudit::capture();
        capture.refuse_after(0);
        let refused = audit
            .begin(request_record("claimed", None, "officer", json!({})))
            .await;
        assert!(matches!(refused, Err(StoreError::AuditUnavailable)));
        assert!(capture.entries().is_empty());
        assert!(!audit.ready().await);
    }

    #[tokio::test]
    async fn a_refused_response_entry_reports_the_destination_unavailable() {
        let (audit, capture) = CaseworkAudit::capture();
        let mut operation = audit
            .begin(request_record("claimed", None, "officer", json!({})))
            .await
            .unwrap();
        let event = Uuid::new_v4();
        operation
            .record(
                event,
                json!({"event": "casework.claimed", "profileId": "officer"}),
            )
            .unwrap();
        capture.refuse_after(1);
        assert!(matches!(
            operation.complete().await,
            Err(StoreError::AuditUnavailable)
        ));
        assert_eq!(capture.entries().len(), 1);
    }

    #[tokio::test]
    async fn a_requested_operation_without_a_response_record_is_refused() {
        let (audit, capture) = CaseworkAudit::capture();
        let operation = audit
            .begin(request_record("task_claimed", None, "officer", json!({})))
            .await
            .unwrap();
        assert!(matches!(
            operation.complete().await,
            Err(StoreError::AuditUnavailable)
        ));
        // The result is withheld, and the request entry is still paired: the
        // operation writes its unfinished outcome as the response.
        let entries = capture.entries();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[1]["correlation"], entries[0]["correlation"]);
        assert_eq!(
            entries[1]["record"],
            json!({"event": "casework.task_claimed", "outcome": "unfinished"})
        );
    }

    #[tokio::test]
    async fn a_replayed_operation_appends_one_minimized_terminal_outcome() {
        let (audit, capture) = CaseworkAudit::capture();
        let actor = actor();
        let mut operation = audit
            .begin(request_record(
                "review_decided",
                Some(&actor),
                &actor.profile_id,
                json!({"itemId": Uuid::new_v4()}),
            ))
            .await
            .unwrap();
        operation.record_outcome(AuditOutcome::Replayed);
        operation.complete().await.unwrap();

        let entries = capture.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[1]["correlation"], entries[0]["correlation"]);
        assert_eq!(
            entries[1]["record"],
            json!({"event": "casework.review_decided", "outcome": "replayed"})
        );
    }

    #[tokio::test]
    async fn a_refused_terminal_outcome_reports_the_destination_unavailable() {
        let (audit, capture) = CaseworkAudit::capture();
        let mut operation = audit
            .begin(request_record(
                "review_cancelled",
                None,
                "producer",
                json!({}),
            ))
            .await
            .unwrap();
        operation.record_outcome(AuditOutcome::Unchanged);
        capture.refuse_after(1);
        assert!(matches!(
            operation.complete().await,
            Err(StoreError::AuditUnavailable)
        ));
        assert_eq!(capture.entries().len(), 1);
    }

    #[tokio::test]
    async fn a_domain_event_is_the_terminal_entry_when_one_was_recorded() {
        let (audit, capture) = CaseworkAudit::capture();
        let mut operation = audit
            .begin(request_record("task_revoked", None, "officer", json!({})))
            .await
            .unwrap();
        operation.record_outcome(AuditOutcome::Unchanged);
        let event = Uuid::new_v4();
        operation
            .record(
                event,
                json!({"event": "casework.task_invalidated", "profileId": "system:task-grants"}),
            )
            .unwrap();
        operation.complete().await.unwrap();
        let entries = capture.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1]["record"]["eventId"], event.to_string());
        assert!(entries[1]["record"].get("outcome").is_none());
    }

    #[tokio::test]
    async fn background_work_without_a_domain_event_appends_nothing() {
        let (audit, capture) = CaseworkAudit::capture();
        let operation = audit.begin_background().await.unwrap();
        operation.complete().await.unwrap();
        assert!(capture.entries().is_empty());
    }

    #[test]
    fn a_record_that_cannot_be_minimized_is_refused_before_commit() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();
        assert!(published_audit_record(json!(["not", "an", "object"]), &hasher).is_err());
        assert!(published_audit_record(json!({"itemId": 7}), &hasher).is_err());
        assert!(
            published_audit_record(json!({"actor": {"subject": "officer-7"}}), &hasher).is_err()
        );
        let event = Uuid::new_v4();
        assert!(audit_record_with_event_id(event, json!({"eventId": Uuid::new_v4()})).is_err());
    }

    #[test]
    fn audit_publication_separates_protected_identity_and_source_data() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();
        let raw = json!({"event":"casework.task_approved", "eventId":"event", "actor":{"issuer":"https://issuer.test","subject":"raw-human"}, "itemId":"raw-item", "grantId":"raw-grant", "detail":{"person_reference":"raw-person"}, "reason":"private reason", "sourceReceipt":{"body":"private body"}, "profileId":"staff"});
        let published = published_audit_record(raw.clone(), &hasher).unwrap();
        let serialized = published.to_string();
        for secret in [
            "raw-human",
            "https://issuer.test",
            "raw-item",
            "raw-grant",
            "raw-person",
            "private reason",
            "private body",
        ] {
            assert!(!serialized.contains(secret));
        }
        assert_eq!(published["eventId"], "event");
        assert_eq!(published["profileId"], "staff");
        assert!(published["principalPseudonym"].as_str().is_some());
        assert_ne!(published["itemPseudonym"], published["grantPseudonym"]);
        assert_eq!(published, published_audit_record(raw, &hasher).unwrap());
        assert!(
            published_audit_record(json!({"actor":{"subject":"missing-issuer"}}), &hasher).is_err()
        );
    }
}
