//! Event record projection: a caller-filtered, read-only view of one record
//! revision that says what happened, to whom, when it took effect, when the
//! registry recorded it, and which evidence points at it.
//!
//! The projection is pure. It reads no clock and performs no exchange; every
//! timestamp in a view comes from the record or from supplied evidence. Instants
//! are emitted with an uppercase `T` and `Z` and the authored offset. Dates
//! stay dates, a declared unknown stays distinct from an absent value, and no
//! member is derived from another.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};
use uuid::Uuid;

use crate::{decode_exact_json, BRegActionReceipt, BRegProposalApplication, RegistryRecord};

/// Contract identifier carried by every event record view.
pub const EVENT_RECORD_VIEW_CONTRACT: &str =
    "id.registrystack.org/formats/breg/event-record-view/v1alpha1";

/// The only runtime descriptor version this client projects.
pub const EVENT_RECORD_DESCRIPTOR_VERSION: u64 = 1;

const CREATION_REVISION: &str = "1";
const CREATION_REVISION_SOURCE: &str = "creation-revision";

/// Why an event record descriptor, evidence document, or view input was refused.
/// No variant carries a record value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegEventRecordError {
    #[error("the record type does not declare an event record")]
    NotAnEventRecord,
    #[error("event record descriptor version {found} is not supported")]
    UnsupportedVersion { found: u64 },
    #[error("the event record descriptor is malformed at {path}")]
    MalformedDescriptor { path: String },
    #[error("the evidence does not describe this record: {reason}")]
    WrongRecordEvidence { reason: String },
    #[error("expected revision {expected} but found revision {found}")]
    RevisionMismatch { expected: String, found: String },
    #[error("the record does not fit the event record descriptor: {reason}")]
    IncompatibleMetadata { reason: String },
    #[error("the event record view input is invalid: {reason}")]
    InvalidInput { reason: String },
}

impl BRegEventRecordError {
    /// A stable kebab-case code for the error class.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotAnEventRecord => "not-an-event-record",
            Self::UnsupportedVersion { .. } => "unsupported-version",
            Self::MalformedDescriptor { .. } => "malformed-descriptor",
            Self::WrongRecordEvidence { .. } => "wrong-record-evidence",
            Self::RevisionMismatch { .. } => "revision-mismatch",
            Self::IncompatibleMetadata { .. } => "incompatible-metadata",
            Self::InvalidInput { .. } => "invalid-input",
        }
    }
}

fn malformed(path: impl Into<String>) -> BRegEventRecordError {
    BRegEventRecordError::MalformedDescriptor { path: path.into() }
}

fn wrong_evidence(reason: impl Into<String>) -> BRegEventRecordError {
    BRegEventRecordError::WrongRecordEvidence {
        reason: reason.into(),
    }
}

fn invalid_input(reason: impl Into<String>) -> BRegEventRecordError {
    BRegEventRecordError::InvalidInput {
        reason: reason.into(),
    }
}

// ---- Descriptor ----

#[derive(Clone, Debug, Eq, PartialEq)]
struct FieldRef {
    id: String,
    api_name: String,
    value_type: String,
    target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RoleKind {
    Native,
    External {
        namespace: String,
    },
    /// A role kind this client does not know, retained with its `namespace`
    /// (when the descriptor carries one) for the descriptor round trip.
    Unsupported {
        kind: String,
        namespace: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RoleDescriptor {
    role: String,
    label: Option<String>,
    kind: RoleKind,
    field: FieldRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IntervalMeaning {
    Span,
    Within,
    Other(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TimeDescriptor {
    Point {
        at: FieldRef,
    },
    Interval {
        meaning: IntervalMeaning,
        start: FieldRef,
        end: Option<FieldRef>,
    },
    /// A time type this client does not know, retained for the descriptor
    /// round trip.
    Unsupported {
        time_type: String,
        raw: Value,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CorrectionDescriptor {
    relation: String,
    field: FieldRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Namespace {
    Literal(String),
    Field(FieldRef),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceEventDescriptor {
    field: FieldRef,
    namespace: Namespace,
    duplicates: String,
    constraint: Option<String>,
}

/// The runtime event record descriptor of one record type, already filtered for
/// the caller: undeclared and withheld optional members are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BRegEventRecordDescriptor {
    label: String,
    subjects: Vec<RoleDescriptor>,
    summary: Option<FieldRef>,
    occurred_at: Option<TimeDescriptor>,
    effective: Option<TimeDescriptor>,
    sources: Vec<RoleDescriptor>,
    correction: Option<CorrectionDescriptor>,
    source_event_id: Option<SourceEventDescriptor>,
}

fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Value, BRegEventRecordError> {
    match object.get(key) {
        Some(value) if !value.is_null() => Ok(value),
        _ => Err(malformed(path)),
    }
}

fn optional<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

fn text(value: &Value, path: &str) -> Result<String, BRegEventRecordError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| malformed(path))
}

fn object_at<'a>(
    value: &'a Value,
    path: &str,
) -> Result<&'a Map<String, Value>, BRegEventRecordError> {
    value.as_object().ok_or_else(|| malformed(path))
}

fn parse_field(value: &Value, path: &str) -> Result<FieldRef, BRegEventRecordError> {
    let object = object_at(value, path)?;
    let child = |name: &str| format!("{path}.{name}");
    Ok(FieldRef {
        id: text(required(object, "id", &child("id"))?, &child("id"))?,
        api_name: text(
            required(object, "apiName", &child("apiName"))?,
            &child("apiName"),
        )?,
        value_type: text(required(object, "type", &child("type"))?, &child("type"))?,
        target: optional(object, "target")
            .map(|value| text(value, &child("target")))
            .transpose()?,
    })
}

fn parse_roles(value: &Value, path: &str) -> Result<Vec<RoleDescriptor>, BRegEventRecordError> {
    let items = value.as_array().ok_or_else(|| malformed(path))?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let item_path = format!("{path}[{index}]");
            let child = |name: &str| format!("{item_path}.{name}");
            let object = object_at(item, &item_path)?;
            let kind =
                match text(required(object, "kind", &child("kind"))?, &child("kind"))?.as_str() {
                    "native" => RoleKind::Native,
                    "external" => RoleKind::External {
                        namespace: text(
                            required(object, "namespace", &child("namespace"))?,
                            &child("namespace"),
                        )?,
                    },
                    other => RoleKind::Unsupported {
                        kind: other.to_owned(),
                        namespace: optional(object, "namespace")
                            .map(|value| text(value, &child("namespace")))
                            .transpose()?,
                    },
                };
            Ok(RoleDescriptor {
                role: text(required(object, "role", &child("role"))?, &child("role"))?,
                label: optional(object, "label")
                    .map(|value| text(value, &child("label")))
                    .transpose()?,
                kind,
                field: parse_field(required(object, "field", &child("field"))?, &child("field"))?,
            })
        })
        .collect()
}

fn parse_time(value: &Value, path: &str) -> Result<TimeDescriptor, BRegEventRecordError> {
    let object = object_at(value, path)?;
    let child = |name: &str| format!("{path}.{name}");
    let time_type = text(required(object, "type", &child("type"))?, &child("type"))?;
    match time_type.as_str() {
        "point" => Ok(TimeDescriptor::Point {
            at: parse_field(required(object, "at", &child("at"))?, &child("at"))?,
        }),
        "interval" => {
            let meaning = match text(
                required(object, "meaning", &child("meaning"))?,
                &child("meaning"),
            )?
            .as_str()
            {
                "span" => IntervalMeaning::Span,
                "within" => IntervalMeaning::Within,
                other => IntervalMeaning::Other(other.to_owned()),
            };
            Ok(TimeDescriptor::Interval {
                meaning,
                start: parse_field(required(object, "start", &child("start"))?, &child("start"))?,
                end: optional(object, "end")
                    .map(|value| parse_field(value, &child("end")))
                    .transpose()?,
            })
        }
        _ => Ok(TimeDescriptor::Unsupported {
            time_type,
            raw: value.clone(),
        }),
    }
}

fn parse_correction(value: &Value) -> Result<CorrectionDescriptor, BRegEventRecordError> {
    let object = object_at(value, "correction")?;
    Ok(CorrectionDescriptor {
        relation: text(
            required(object, "relation", "correction.relation")?,
            "correction.relation",
        )?,
        field: parse_field(
            required(object, "field", "correction.field")?,
            "correction.field",
        )?,
    })
}

fn parse_source_event(value: &Value) -> Result<SourceEventDescriptor, BRegEventRecordError> {
    let object = object_at(value, "sourceEventId")?;
    let namespace = match (
        optional(object, "namespace"),
        optional(object, "namespaceField"),
    ) {
        (Some(literal), None) => Namespace::Literal(text(literal, "sourceEventId.namespace")?),
        (None, Some(field)) => {
            Namespace::Field(parse_field(field, "sourceEventId.namespaceField")?)
        }
        _ => return Err(malformed("sourceEventId")),
    };
    Ok(SourceEventDescriptor {
        field: parse_field(
            required(object, "field", "sourceEventId.field")?,
            "sourceEventId.field",
        )?,
        namespace,
        duplicates: text(
            required(object, "duplicates", "sourceEventId.duplicates")?,
            "sourceEventId.duplicates",
        )?,
        constraint: optional(object, "constraint")
            .map(|value| text(value, "sourceEventId.constraint"))
            .transpose()?,
    })
}

impl BRegEventRecordDescriptor {
    /// Parse the `eventRecord` member of one caller-filtered record type.
    ///
    /// The version is checked first. Unknown members are ignored; a member
    /// whose declared kind this client does not know is kept and renders as
    /// `unsupported` in a view.
    pub fn from_value(value: &Value) -> Result<Self, BRegEventRecordError> {
        let root = object_at(value, "eventRecord")?;
        let version = match root.get("descriptorVersion").map(Value::as_u64) {
            Some(Some(version)) => version,
            _ => return Err(malformed("descriptorVersion")),
        };
        if version != EVENT_RECORD_DESCRIPTOR_VERSION {
            return Err(BRegEventRecordError::UnsupportedVersion { found: version });
        }
        let label = text(required(root, "label", "label")?, "label")?;
        let subjects = parse_roles(required(root, "subjects", "subjects")?, "subjects")?;
        let sources = parse_roles(required(root, "sources", "sources")?, "sources")?;
        let recorded_time = object_at(
            required(root, "recordedTime", "recordedTime")?,
            "recordedTime",
        )?;
        if recorded_time.get("source").and_then(Value::as_str) != Some(CREATION_REVISION_SOURCE) {
            return Err(malformed("recordedTime.source"));
        }
        Ok(Self {
            label,
            subjects,
            summary: optional(root, "summary")
                .map(|value| parse_field(value, "summary"))
                .transpose()?,
            occurred_at: optional(root, "occurredAt")
                .map(|value| parse_time(value, "occurredAt"))
                .transpose()?,
            effective: optional(root, "effective")
                .map(|value| parse_time(value, "effective"))
                .transpose()?,
            sources,
            correction: optional(root, "correction")
                .map(parse_correction)
                .transpose()?,
            source_event_id: optional(root, "sourceEventId")
                .map(parse_source_event)
                .transpose()?,
        })
    }

    /// The canonical runtime form: absent optional members are omitted.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut root = Map::new();
        root.insert(
            "descriptorVersion".into(),
            Value::from(EVENT_RECORD_DESCRIPTOR_VERSION),
        );
        root.insert("label".into(), Value::from(self.label.clone()));
        root.insert("subjects".into(), roles_value(&self.subjects));
        if let Some(summary) = &self.summary {
            root.insert("summary".into(), field_value(summary));
        }
        if let Some(time) = &self.occurred_at {
            root.insert("occurredAt".into(), time_value(time));
        }
        if let Some(time) = &self.effective {
            root.insert("effective".into(), time_value(time));
        }
        root.insert("sources".into(), roles_value(&self.sources));
        if let Some(correction) = &self.correction {
            root.insert(
                "correction".into(),
                serde_json::json!({
                    "relation": correction.relation,
                    "field": field_value(&correction.field),
                }),
            );
        }
        if let Some(event) = &self.source_event_id {
            let mut member = Map::new();
            member.insert("field".into(), field_value(&event.field));
            match &event.namespace {
                Namespace::Literal(namespace) => {
                    member.insert("namespace".into(), Value::from(namespace.clone()));
                }
                Namespace::Field(field) => {
                    member.insert("namespaceField".into(), field_value(field));
                }
            }
            member.insert("duplicates".into(), Value::from(event.duplicates.clone()));
            if let Some(constraint) = &event.constraint {
                member.insert("constraint".into(), Value::from(constraint.clone()));
            }
            root.insert("sourceEventId".into(), Value::Object(member));
        }
        root.insert(
            "recordedTime".into(),
            serde_json::json!({"source": CREATION_REVISION_SOURCE}),
        );
        Value::Object(root)
    }
}

fn field_value(field: &FieldRef) -> Value {
    let mut member = Map::new();
    member.insert("id".into(), Value::from(field.id.clone()));
    member.insert("apiName".into(), Value::from(field.api_name.clone()));
    member.insert("type".into(), Value::from(field.value_type.clone()));
    if let Some(target) = &field.target {
        member.insert("target".into(), Value::from(target.clone()));
    }
    Value::Object(member)
}

fn roles_value(roles: &[RoleDescriptor]) -> Value {
    Value::Array(
        roles
            .iter()
            .map(|role| {
                let mut member = Map::new();
                member.insert("role".into(), Value::from(role.role.clone()));
                if let Some(label) = &role.label {
                    member.insert("label".into(), Value::from(label.clone()));
                }
                match &role.kind {
                    RoleKind::Native => {
                        member.insert("kind".into(), Value::from("native"));
                    }
                    RoleKind::External { namespace } => {
                        member.insert("kind".into(), Value::from("external"));
                        member.insert("namespace".into(), Value::from(namespace.clone()));
                    }
                    RoleKind::Unsupported { kind, namespace } => {
                        member.insert("kind".into(), Value::from(kind.clone()));
                        if let Some(namespace) = namespace {
                            member.insert("namespace".into(), Value::from(namespace.clone()));
                        }
                    }
                }
                member.insert("field".into(), field_value(&role.field));
                Value::Object(member)
            })
            .collect(),
    )
}

fn time_value(time: &TimeDescriptor) -> Value {
    match time {
        TimeDescriptor::Point { at } => {
            serde_json::json!({"type": "point", "at": field_value(at)})
        }
        TimeDescriptor::Interval {
            meaning,
            start,
            end,
        } => {
            let mut member = Map::new();
            member.insert("type".into(), Value::from("interval"));
            member.insert(
                "meaning".into(),
                Value::from(match meaning {
                    IntervalMeaning::Span => "span",
                    IntervalMeaning::Within => "within",
                    IntervalMeaning::Other(other) => other.as_str(),
                }),
            );
            member.insert("start".into(), field_value(start));
            if let Some(end) = end {
                member.insert("end".into(), field_value(end));
            }
            Value::Object(member)
        }
        TimeDescriptor::Unsupported { raw, .. } => raw.clone(),
    }
}

// ---- Creation revision ----

/// The recorded time of a record, read from the revision that created it.
///
/// Only revision 1 of the record, with no predecessor and a create mutation,
/// states when the registry first recorded it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BRegCreationRevision {
    record_type: String,
    record_id: String,
    created_at: String,
}

impl BRegCreationRevision {
    /// Read a Registry Record revision envelope (`{"data": {...}, "meta": {...}}`)
    /// and keep only the creation evidence for `record_id`.
    pub fn from_document(record_id: &str, document: &Value) -> Result<Self, BRegEventRecordError> {
        let record_type = document
            .get("meta")
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("entityTypeIdentifier"))
            .and_then(Value::as_str)
            .ok_or_else(|| wrong_evidence("the revision has no record type"))?;
        let data = document
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| wrong_evidence("the revision document has no data member"))?;
        if data.get("recordIdentifier").and_then(Value::as_str) != Some(record_id) {
            return Err(wrong_evidence("the revision belongs to another record"));
        }
        let revision = data
            .get("revisionIdentifier")
            .and_then(Value::as_str)
            .ok_or_else(|| wrong_evidence("the revision has no revision identifier"))?;
        require_creation_revision(revision)?;
        if data
            .get("predecessorRevision")
            .is_some_and(|value| !value.is_null())
        {
            return Err(wrong_evidence("revision 1 names a predecessor"));
        }
        if data.get("mutationKind").and_then(Value::as_str) != Some("create") {
            return Err(wrong_evidence("revision 1 is not a create"));
        }
        let created_at = data
            .get("createdAt")
            .and_then(Value::as_str)
            .ok_or_else(|| wrong_evidence("the revision has no creation time"))?;
        Self::new(record_type, record_id, created_at)
    }

    /// Read the compact `{"recordType", "recordId", "revision", "createdAt"}`
    /// form that `Serialize` writes.
    pub fn from_value(value: &Value) -> Result<Self, BRegEventRecordError> {
        let object = value
            .as_object()
            .ok_or_else(|| wrong_evidence("the creation revision is not an object"))?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "recordType" | "recordId" | "revision" | "createdAt"
            )
        }) {
            return Err(wrong_evidence(
                "the creation revision has an unknown member",
            ));
        }
        let member = |name: &str| {
            object
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| wrong_evidence(format!("the creation revision has no {name}")))
        };
        require_creation_revision(member("revision")?)?;
        Self::new(
            member("recordType")?,
            member("recordId")?,
            member("createdAt")?,
        )
    }

    fn new(
        record_type: &str,
        record_id: &str,
        created_at: &str,
    ) -> Result<Self, BRegEventRecordError> {
        if OffsetDateTime::parse(created_at, &Rfc3339).is_err() {
            return Err(wrong_evidence(
                "the creation time is not an RFC 3339 timestamp",
            ));
        }
        Ok(Self {
            record_type: record_type.to_owned(),
            record_id: record_id.to_owned(),
            created_at: created_at.to_owned(),
        })
    }

    #[must_use]
    pub fn record_type_identifier(&self) -> &str {
        &self.record_type
    }

    #[must_use]
    pub fn record_identifier(&self) -> &str {
        &self.record_id
    }

    /// The creation time exactly as the registry stated it.
    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }
}

/// Accept revision 1. Another revision number is a mismatch that names it; any
/// other text is refused without echoing it, so errors stay value-free.
fn require_creation_revision(revision: &str) -> Result<(), BRegEventRecordError> {
    if revision == CREATION_REVISION {
        return Ok(());
    }
    let is_revision_number = !revision.is_empty()
        && revision.len() <= 20
        && !revision.starts_with('0')
        && revision.bytes().all(|byte| byte.is_ascii_digit());
    if !is_revision_number {
        return Err(wrong_evidence(
            "the revision identifier is not a revision number",
        ));
    }
    Err(BRegEventRecordError::RevisionMismatch {
        expected: CREATION_REVISION.to_owned(),
        found: revision.to_owned(),
    })
}

impl Serialize for BRegCreationRevision {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_json::json!({
            "recordType": self.record_type,
            "recordId": self.record_id,
            "revision": CREATION_REVISION,
            "createdAt": self.created_at,
        })
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BRegCreationRevision {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(&value).map_err(serde::de::Error::custom)
    }
}

// ---- Evidence and view ----

/// Evidence that may point at the projected record revision. Evidence that
/// does not match the exact record type, record identifier and revision is
/// listed in the view as ignored and never contributes provenance.
#[derive(Clone, Copy, Default)]
pub struct BRegEventRecordEvidence<'a> {
    /// The creation revision of the projected record, when readable.
    pub creation_revision: Option<&'a BRegCreationRevision>,
    /// Action receipts, each paired with the identifier of the result effect
    /// that produced the projected record.
    pub action_receipts: &'a [(&'a BRegActionReceipt, &'a str)],
    pub proposal_applications: &'a [&'a BRegProposalApplication],
}

impl std::fmt::Debug for BRegEventRecordEvidence<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BRegEventRecordEvidence")
            .field("creation_revision", &self.creation_revision)
            .field("action_receipts", &self.action_receipts.len())
            .field("proposal_applications", &self.proposal_applications.len())
            .finish()
    }
}

/// The event record view of one record revision, as an inert JSON document.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BRegEventRecordView {
    document: Value,
}

impl BRegEventRecordView {
    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.document
    }

    #[must_use]
    pub fn into_value(self) -> Value {
        self.document
    }
}

struct ResultRef<'a> {
    effect: Option<&'a str>,
    record_type: &'a str,
    record_id: String,
    revision: u64,
}

enum EvidenceRef<'a> {
    Receipt {
        action: &'a str,
        application_id: String,
        effect: &'a str,
        results: Vec<ResultRef<'a>>,
    },
    Application {
        application_id: &'a str,
        submission_version: u32,
        applied_at: Option<&'a str>,
        applied_by: Option<&'a str>,
        results: Vec<ResultRef<'a>>,
    },
}

enum EvidenceMatch {
    Exact,
    RevisionMismatch,
    NoResult,
}

struct RecordRef<'a> {
    record_type: &'a str,
    record_id: &'a str,
    revision: &'a str,
    domain_data: &'a BTreeMap<String, Value>,
}

fn classify<'r, 'a: 'r>(
    results: impl Iterator<Item = &'r ResultRef<'a>>,
    record: &RecordRef<'_>,
) -> EvidenceMatch {
    let mut outcome = EvidenceMatch::NoResult;
    for result in results {
        if result.record_type == record.record_type && result.record_id == record.record_id {
            if result.revision.to_string() == record.revision {
                return EvidenceMatch::Exact;
            }
            outcome = EvidenceMatch::RevisionMismatch;
        }
    }
    outcome
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.to_string() == value)
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    if !(digits(0..4) && digits(5..7) && digits(8..10)) {
        return false;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u8>().ok();
    let (Ok(year), Some(month), Some(day)) =
        (value[0..4].parse::<i32>(), number(5..7), number(8..10))
    else {
        return false;
    };
    Month::try_from(month)
        .ok()
        .and_then(|month| Date::from_calendar_date(year, month, day).ok())
        .is_some()
}

fn available(value_type: &str, value: &str, target: Option<&str>) -> Value {
    let mut member = Map::new();
    member.insert("status".into(), Value::from("available"));
    member.insert("type".into(), Value::from(value_type));
    member.insert("value".into(), Value::from(value));
    if let Some(target) = target {
        member.insert("target".into(), Value::from(target));
    }
    Value::Object(member)
}

/// An RFC 3339 instant with an uppercase `T` separator and `Z` zone letter.
/// Only letter case changes: the authored offset and fraction are kept, so an
/// offset instant is never converted to UTC. The input is already validated.
fn canonical_instant(value: &str) -> String {
    let mut text = value.to_owned();
    if text.len() > 10 && text.is_char_boundary(10) && text.is_char_boundary(11) {
        text.replace_range(10..11, "T");
    }
    if text.ends_with('z') {
        text.replace_range(text.len() - 1.., "Z");
    }
    text
}

fn status(name: &str) -> Value {
    serde_json::json!({ "status": name })
}

fn unsupported(detail: &str) -> Value {
    serde_json::json!({"status": "unsupported", "detail": detail})
}

/// One record member rendered as a view value. A key that is absent from the
/// record is `unavailable`; a null is `declaredUnknown`.
fn value_member(field: &FieldRef, record: &RecordRef<'_>) -> Result<Value, BRegEventRecordError> {
    let Some(raw) = record.domain_data.get(&field.api_name) else {
        return Ok(status("unavailable"));
    };
    if raw.is_null() {
        return Ok(status("declaredUnknown"));
    }
    let (value_type, check): (&str, fn(&str) -> bool) = match field.value_type.as_str() {
        "date" => ("date", valid_date),
        "timestamp" | "instant" => ("instant", |value| {
            OffsetDateTime::parse(value, &Rfc3339).is_ok()
        }),
        "string" | "text" | "vocabulary-code" => ("text", |_| true),
        "uuid" => ("uuid", canonical_uuid),
        "reference" => ("reference", canonical_uuid),
        other => return Ok(unsupported(&format!("value type {other}"))),
    };
    let value = raw.as_str().filter(|value| check(value)).ok_or_else(|| {
        BRegEventRecordError::IncompatibleMetadata {
            reason: format!(
                "record member {} does not hold a {} value",
                field.api_name, field.value_type
            ),
        }
    })?;
    let target = (value_type == "reference")
        .then_some(field.target.as_deref())
        .flatten();
    if value_type == "instant" {
        return Ok(available(value_type, &canonical_instant(value), target));
    }
    Ok(available(value_type, value, target))
}

fn time_member(
    time: Option<&TimeDescriptor>,
    record: &RecordRef<'_>,
) -> Result<Value, BRegEventRecordError> {
    let Some(time) = time else {
        return Ok(status("unavailable"));
    };
    match time {
        TimeDescriptor::Point { at } => Ok(serde_json::json!({
            "type": "point",
            "at": value_member(at, record)?,
        })),
        TimeDescriptor::Interval {
            meaning,
            start,
            end,
        } => {
            let meaning = match meaning {
                IntervalMeaning::Span => "span",
                IntervalMeaning::Within => "within",
                IntervalMeaning::Other(other) => {
                    return Ok(unsupported(&format!("interval meaning {other}")));
                }
            };
            let end = match end {
                Some(end) => value_member(end, record)?,
                None => status("unavailable"),
            };
            Ok(serde_json::json!({
                "type": "interval",
                "meaning": meaning,
                "start": value_member(start, record)?,
                "end": end,
            }))
        }
        TimeDescriptor::Unsupported { time_type, .. } => {
            Ok(unsupported(&format!("time type {time_type}")))
        }
    }
}

fn role_members(
    roles: &[RoleDescriptor],
    record: &RecordRef<'_>,
) -> Result<Vec<Value>, BRegEventRecordError> {
    roles
        .iter()
        .map(|role| {
            let mut member = Map::new();
            member.insert("role".into(), Value::from(role.role.clone()));
            if let Some(label) = &role.label {
                member.insert("label".into(), Value::from(label.clone()));
            }
            match &role.kind {
                RoleKind::Native => {
                    member.insert("kind".into(), Value::from("native"));
                }
                RoleKind::External { namespace } => {
                    member.insert("kind".into(), Value::from("external"));
                    member.insert("namespace".into(), Value::from(namespace.clone()));
                }
                RoleKind::Unsupported { kind, .. } => {
                    member.insert("value".into(), unsupported(&format!("role kind {kind}")));
                    return Ok(Value::Object(member));
                }
            }
            member.insert("value".into(), value_member(&role.field, record)?);
            Ok(Value::Object(member))
        })
        .collect()
}

fn correction_member(
    correction: Option<&CorrectionDescriptor>,
    record: &RecordRef<'_>,
) -> Result<Value, BRegEventRecordError> {
    let Some(correction) = correction else {
        return Ok(status("unavailable"));
    };
    if !matches!(correction.relation.as_str(), "corrects" | "supersedes") {
        return Ok(unsupported(&format!(
            "correction relation {}",
            correction.relation
        )));
    }
    Ok(serde_json::json!({
        "relation": correction.relation,
        "reference": value_member(&correction.field, record)?,
    }))
}

fn source_event_member(
    event: Option<&SourceEventDescriptor>,
    record: &RecordRef<'_>,
) -> Result<Value, BRegEventRecordError> {
    let Some(event) = event else {
        return Ok(status("unavailable"));
    };
    if !matches!(event.duplicates.as_str(), "reject" | "allow") {
        return Ok(unsupported(&format!(
            "duplicates policy {}",
            event.duplicates
        )));
    }
    let namespace = match &event.namespace {
        Namespace::Literal(namespace) => available("text", namespace, None),
        Namespace::Field(field) => value_member(field, record)?,
    };
    Ok(serde_json::json!({
        "namespace": namespace,
        "value": value_member(&event.field, record)?,
        "duplicates": event.duplicates,
    }))
}

fn build_view(
    registry_revision: &str,
    descriptor: &BRegEventRecordDescriptor,
    record: &RecordRef<'_>,
    creation_revision: Option<&BRegCreationRevision>,
    evidence: &[EvidenceRef<'_>],
) -> Result<BRegEventRecordView, BRegEventRecordError> {
    if !canonical_uuid(record.record_id) {
        return Err(wrong_evidence("the record identifier is not a UUID"));
    }
    if record
        .revision
        .parse::<u64>()
        .map_or(true, |revision| revision == 0)
    {
        return Err(wrong_evidence(
            "the record revision identifier is not a positive integer",
        ));
    }
    let recorded_at = match creation_revision {
        Some(creation)
            if creation.record_type != record.record_type
                || creation.record_id != record.record_id =>
        {
            return Err(wrong_evidence(
                "the creation revision belongs to another record",
            ));
        }
        Some(creation) => available("instant", &canonical_instant(&creation.created_at), None),
        None => status("unavailable"),
    };

    let mut provenance = Vec::new();
    let mut ignored = Vec::new();
    for entry in evidence {
        let (kind, application_id, outcome) = match entry {
            EvidenceRef::Receipt {
                application_id,
                effect,
                results,
                ..
            } => (
                "action-receipt",
                application_id.as_str(),
                classify(
                    results
                        .iter()
                        .filter(|result| result.effect == Some(*effect)),
                    record,
                ),
            ),
            EvidenceRef::Application {
                application_id,
                results,
                ..
            } => (
                "proposal-application",
                *application_id,
                classify(results.iter(), record),
            ),
        };
        match outcome {
            EvidenceMatch::Exact => {
                let item = match entry {
                    EvidenceRef::Receipt {
                        action,
                        application_id,
                        effect,
                        ..
                    } => serde_json::json!({
                        "kind": kind,
                        "action": action,
                        "applicationId": application_id,
                        "effect": effect,
                    }),
                    EvidenceRef::Application {
                        application_id,
                        submission_version,
                        applied_at,
                        applied_by,
                        ..
                    } => {
                        let mut member = Map::new();
                        member.insert("kind".into(), Value::from(kind));
                        member.insert("applicationId".into(), Value::from(*application_id));
                        member.insert("submissionVersion".into(), Value::from(*submission_version));
                        if let Some(applied_at) = applied_at {
                            if OffsetDateTime::parse(applied_at, &Rfc3339).is_err() {
                                return Err(wrong_evidence(
                                    "the proposal application time is not an RFC 3339 timestamp",
                                ));
                            }
                            member.insert(
                                "appliedAt".into(),
                                Value::from(canonical_instant(applied_at)),
                            );
                        }
                        if let Some(applied_by) = applied_by {
                            member.insert("appliedBy".into(), Value::from(*applied_by));
                        }
                        Value::Object(member)
                    }
                };
                // Evidence repeated by the caller adds no second entry; the
                // first one keeps its place.
                if !provenance.contains(&item) {
                    provenance.push(item);
                }
            }
            EvidenceMatch::RevisionMismatch | EvidenceMatch::NoResult => {
                let reason = if matches!(outcome, EvidenceMatch::RevisionMismatch) {
                    "revision-mismatch"
                } else {
                    "no-matching-result"
                };
                ignored.push(serde_json::json!({
                    "kind": kind,
                    "applicationId": application_id,
                    "reason": reason,
                }));
            }
        }
    }

    let summary = match &descriptor.summary {
        Some(field) => value_member(field, record)?,
        None => status("unavailable"),
    };
    let document = serde_json::json!({
        "contract": EVENT_RECORD_VIEW_CONTRACT,
        "descriptorVersion": EVENT_RECORD_DESCRIPTOR_VERSION,
        "registryRevision": registry_revision,
        "source": {
            "recordType": record.record_type,
            "recordId": record.record_id,
            "revision": record.revision,
        },
        "label": descriptor.label,
        "subjects": role_members(&descriptor.subjects, record)?,
        "summary": summary,
        "occurredAt": time_member(descriptor.occurred_at.as_ref(), record)?,
        "effective": time_member(descriptor.effective.as_ref(), record)?,
        "recordedAt": recorded_at,
        "recordedAtSource": CREATION_REVISION_SOURCE,
        "sources": role_members(&descriptor.sources, record)?,
        "correction": correction_member(descriptor.correction.as_ref(), record)?,
        "sourceEventId": source_event_member(descriptor.source_event_id.as_ref(), record)?,
        "provenance": provenance,
        "ignoredEvidence": ignored,
    });
    Ok(BRegEventRecordView { document })
}

/// Project one record revision into an event record view.
///
/// Pure: no exchange and no clock. `registry_revision` is the revision of the
/// metadata that supplied `descriptor`.
pub fn event_record_view(
    registry_revision: &str,
    record_type: &str,
    descriptor: &BRegEventRecordDescriptor,
    record: &RegistryRecord,
    evidence: &BRegEventRecordEvidence<'_>,
) -> Result<BRegEventRecordView, BRegEventRecordError> {
    let mut refs = Vec::new();
    for (receipt, effect) in evidence.action_receipts {
        refs.push(EvidenceRef::Receipt {
            action: receipt.action_identifier(),
            application_id: receipt.application_identifier().to_string(),
            effect,
            results: receipt
                .results()
                .iter()
                .map(|(effect, result)| ResultRef {
                    effect: Some(effect.as_str()),
                    record_type: result.record_type_identifier(),
                    record_id: result.record_identifier().to_string(),
                    revision: result.revision(),
                })
                .collect(),
        });
    }
    for application in evidence.proposal_applications {
        refs.push(application_ref(application));
    }
    build_view(
        registry_revision,
        descriptor,
        &RecordRef {
            record_type,
            record_id: &record.record_identifier,
            revision: &record.revision_identifier,
            domain_data: &record.domain_data,
        },
        evidence.creation_revision,
        &refs,
    )
}

fn application_ref(application: &BRegProposalApplication) -> EvidenceRef<'_> {
    EvidenceRef::Application {
        application_id: &application.application_id,
        submission_version: application.submission_version,
        applied_at: application.applied_at.as_deref(),
        applied_by: application.applied_by.as_deref(),
        results: application
            .result_links
            .iter()
            .map(|link| ResultRef {
                effect: None,
                record_type: &link.record_type,
                record_id: link.record_id.clone(),
                revision: link.revision,
            })
            .collect(),
    }
}

// ---- JSON entry point ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ViewArguments {
    registry_revision: String,
    record_type: String,
    descriptor: Value,
    record: Value,
    #[serde(default)]
    creation_revision: Option<Value>,
    #[serde(default)]
    action_receipts: Vec<ReceiptArgument>,
    #[serde(default)]
    proposal_applications: Vec<BRegProposalApplication>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptArgument {
    effect: String,
    receipt: ReceiptDocument,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptDocument {
    action: String,
    application_id: Uuid,
    results: BTreeMap<String, ResultDocument>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResultDocument {
    record_type: String,
    record_id: String,
    revision: u64,
}

/// Project from one JSON arguments document:
/// `{registryRevision, recordType, descriptor, record, creationRevision?,
/// actionReceipts?: [{effect, receipt}], proposalApplications?}`.
///
/// Duplicate members, unknown members and malformed shapes are refused as
/// `InvalidInput` with a fixed reason that never quotes the input; the
/// descriptor and the evidence keep their own errors.
pub fn event_record_view_from_json(
    bytes: &[u8],
) -> Result<BRegEventRecordView, BRegEventRecordError> {
    let document =
        decode_exact_json(bytes).map_err(|_| invalid_input("the arguments are not exact JSON"))?;
    // The serde message is dropped: it quotes the offending value or member name.
    let arguments: ViewArguments = serde_json::from_value(document)
        .map_err(|_| invalid_input("the arguments do not match the contract"))?;
    let record = arguments
        .record
        .as_object()
        .ok_or_else(|| invalid_input("record must be an object"))?;
    let string_member = |name: &str| {
        record
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input(format!("record.{name} must be a string")))
    };
    let domain_data: BTreeMap<String, Value> = record
        .get("domainData")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_input("record.domainData must be an object"))?
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let descriptor = BRegEventRecordDescriptor::from_value(&arguments.descriptor)?;
    let creation = arguments
        .creation_revision
        .as_ref()
        .map(BRegCreationRevision::from_value)
        .transpose()?;
    let mut refs = Vec::new();
    for argument in &arguments.action_receipts {
        refs.push(EvidenceRef::Receipt {
            action: &argument.receipt.action,
            application_id: argument.receipt.application_id.to_string(),
            effect: &argument.effect,
            results: argument
                .receipt
                .results
                .iter()
                .map(|(effect, result)| ResultRef {
                    effect: Some(effect.as_str()),
                    record_type: &result.record_type,
                    record_id: result.record_id.clone(),
                    revision: result.revision,
                })
                .collect(),
        });
    }
    for application in &arguments.proposal_applications {
        refs.push(application_ref(application));
    }
    build_view(
        &arguments.registry_revision,
        &descriptor,
        &RecordRef {
            record_type: &arguments.record_type,
            record_id: string_member("recordIdentifier")?,
            revision: string_member("revisionIdentifier")?,
            domain_data: &domain_data,
        },
        creation.as_ref(),
        &refs,
    )
}
