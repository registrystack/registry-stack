// SPDX-License-Identifier: Apache-2.0
//! Domain occurrence descriptors.
//!
//! A record type may declare which of its stored fields say what a row is
//! about, when it happened, when it takes effect, what it was recorded from and
//! which earlier row it corrects. The descriptor maps roles onto existing typed
//! fields. It creates no storage, endpoint, authority, schedule or constraint,
//! and no execution identity reads it: recorded time is never authored, it is
//! the creation time of the record's first revision.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    ConstraintSource, DuplicatePolicy, EffectiveTimeSource, EntitySource, FieldSource,
    FieldTypeSource, IntervalMeaning, OccurrenceRoleSource, OccurrenceSource, OccurrenceTimeSource,
    MAX_OCCURRENCE_NAMESPACE_BYTES, MAX_OCCURRENCE_ROLES,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    CompiledEntity, CompiledOccurrence, CompiledOccurrenceCorrection, CompiledOccurrenceField,
    CompiledOccurrenceRole, CompiledOccurrenceTime, CompiledRecordedTime, CompiledSourceEventId,
    OccurrenceRoleKind, OccurrenceValueType, RecordedTimeSource, OCCURRENCE_DESCRIPTOR_VERSION,
};

const REFERENCE: &[OccurrenceValueType] = &[OccurrenceValueType::Reference];
const OPAQUE_IDENTIFIER: &[OccurrenceValueType] =
    &[OccurrenceValueType::String, OccurrenceValueType::Uuid];
const SUMMARY: &[OccurrenceValueType] = &[OccurrenceValueType::String, OccurrenceValueType::Text];
const MOMENT: &[OccurrenceValueType] = &[OccurrenceValueType::Date, OccurrenceValueType::Timestamp];
const NAMESPACE: &[OccurrenceValueType] = &[
    OccurrenceValueType::String,
    OccurrenceValueType::VocabularyCode,
];

fn expected_name(allowed: &[OccurrenceValueType]) -> &'static str {
    match allowed {
        REFERENCE => "reference",
        OPAQUE_IDENTIFIER => "string or uuid",
        SUMMARY => "string or text",
        MOMENT => "date or timestamp",
        NAMESPACE => "string or vocabulary-code",
        _ => unreachable!("every allowed set is one of the constants above"),
    }
}

/// The mapped value type of a stored field, when occurrences can map it.
fn value_type(field: &FieldSource) -> Option<OccurrenceValueType> {
    match &field.field_type {
        FieldTypeSource::Reference { .. } => Some(OccurrenceValueType::Reference),
        FieldTypeSource::String { .. } => Some(OccurrenceValueType::String),
        FieldTypeSource::Text { .. } => Some(OccurrenceValueType::Text),
        FieldTypeSource::Date => Some(OccurrenceValueType::Date),
        FieldTypeSource::Timestamp => Some(OccurrenceValueType::Timestamp),
        FieldTypeSource::Uuid => Some(OccurrenceValueType::Uuid),
        FieldTypeSource::VocabularyCode { .. } => Some(OccurrenceValueType::VocabularyCode),
        FieldTypeSource::Boolean
        | FieldTypeSource::Int64
        | FieldTypeSource::Decimal { .. }
        | FieldTypeSource::Crs84Point { .. }
        | FieldTypeSource::Structured { .. } => None,
    }
}

/// The kebab-case name of any field type, for refusals.
fn field_type_name(field_type: &FieldTypeSource) -> &'static str {
    match field_type {
        FieldTypeSource::Boolean => "boolean",
        FieldTypeSource::String { .. } => "string",
        FieldTypeSource::Text { .. } => "text",
        FieldTypeSource::Int64 => "int64",
        FieldTypeSource::Decimal { .. } => "decimal",
        FieldTypeSource::Date => "date",
        FieldTypeSource::Timestamp => "timestamp",
        FieldTypeSource::Uuid => "uuid",
        FieldTypeSource::VocabularyCode { .. } => "vocabulary-code",
        FieldTypeSource::Reference { .. } => "reference",
        FieldTypeSource::Crs84Point { .. } => "crs84-point",
        FieldTypeSource::Structured { .. } => "structured",
    }
}

fn valid_role(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_namespace(value: &str) -> bool {
    value.len() <= MAX_OCCURRENCE_NAMESPACE_BYTES && url::Url::parse(value).is_ok()
}

struct Checker<'a> {
    entity: &'a EntitySource,
    entities: &'a BTreeMap<String, EntitySource>,
    base: String,
    errors: &'a mut Vec<Diagnostic>,
    /// Members that already claimed a stored field, by field id.
    claimed: BTreeMap<String, String>,
}

impl Checker<'_> {
    fn error(&mut self, code: &str, path: String, message: String) {
        self.errors.push(Diagnostic::error(code, path, &message));
    }

    fn field(&self, id: &str) -> Option<&FieldSource> {
        self.entity.fields.iter().find(|field| field.id == id)
    }

    /// Resolves a mapped field and checks its type; `member` is the path
    /// relative to the occurrence, used in the type message.
    fn check_field(
        &mut self,
        field_id: &str,
        member: &str,
        allowed: &[OccurrenceValueType],
    ) -> Option<OccurrenceValueType> {
        let path = format!("{}.{member}", self.base);
        let Some(field) = self.field(field_id) else {
            self.error(
                "breg.occurrence.field-unknown",
                path,
                format!(
                    "occurrence field \"{field_id}\" names no stored field of record type \"{}\"",
                    self.entity.id
                ),
            );
            return None;
        };
        let actual = field_type_name(&field.field_type);
        let mapped = value_type(field);
        match mapped {
            Some(kind) if allowed.contains(&kind) => Some(kind),
            _ => {
                self.error(
                    "breg.occurrence.field-type",
                    path,
                    format!(
                        "{member} requires a {} field; field \"{field_id}\" is {actual}",
                        expected_name(allowed)
                    ),
                );
                None
            }
        }
    }

    /// Records that `member` maps `field_id` and refuses a second mapping.
    fn claim(&mut self, field_id: &str, member: &str, path_member: &str) {
        if let Some(earlier) = self.claimed.get(field_id) {
            let message = format!("field \"{field_id}\" is already mapped by {earlier}");
            self.error(
                "breg.occurrence.field-reused",
                format!("{}.{path_member}", self.base),
                message,
            );
        } else {
            self.claimed.insert(field_id.to_owned(), member.to_owned());
        }
    }

    fn check_namespace(&mut self, namespace: &str, member: &str) {
        if !valid_namespace(namespace) {
            self.error(
                "breg.occurrence.external-namespace",
                format!("{}.{member}", self.base),
                "namespace must be an absolute URI of at most 512 bytes".to_owned(),
            );
        }
    }

    fn check_roles(
        &mut self,
        list: &str,
        roles: &[OccurrenceRoleSource],
        seen: &mut BTreeSet<String>,
    ) {
        if roles.len() > MAX_OCCURRENCE_ROLES {
            let noun = if list == "subjects" {
                "subjects"
            } else {
                "sources"
            };
            self.error(
                "breg.occurrence.roles-too-many",
                format!("{}.{list}", self.base),
                format!("an occurrence declares at most {MAX_OCCURRENCE_ROLES} {noun}"),
            );
        }
        for (index, item) in roles.iter().enumerate() {
            let mut addressable = true;
            if !valid_role(&item.role) {
                addressable = false;
                self.error(
                    "breg.occurrence.role-invalid",
                    format!("{}.{list}[{index}].role", self.base),
                    format!(
                        "role \"{}\" must start with a lowercase letter and contain only lowercase letters, digits, hyphens and underscores, at most 64 characters",
                        item.role
                    ),
                );
            } else if !seen.insert(item.role.clone()) {
                addressable = false;
                self.error(
                    "breg.occurrence.role-duplicate",
                    format!("{}.{list}[{index}].role", self.base),
                    format!(
                        "role \"{}\" is declared more than once in this occurrence",
                        item.role
                    ),
                );
            }
            let address = if addressable {
                format!("{list}[role={}]", item.role)
            } else {
                format!("{list}[{index}]")
            };
            self.check_role(item, &address);
        }
    }

    fn check_role(&mut self, item: &OccurrenceRoleSource, address: &str) {
        let allowed = if item.external.is_some() {
            OPAQUE_IDENTIFIER
        } else {
            REFERENCE
        };
        let field_member = format!("{address}.field");
        let kind = self.check_field(&item.field, &field_member, allowed);
        if kind.is_some() {
            self.claim(&item.field, address, &field_member);
        }
        if let Some(external) = &item.external {
            self.check_namespace(
                &external.namespace,
                &format!("{address}.external.namespace"),
            );
            if item.target.is_some() {
                self.error(
                    "breg.occurrence.external-target",
                    format!("{}.{address}.target", self.base),
                    "an external reference has no native target".to_owned(),
                );
            }
        } else if let (Some(target), Some(OccurrenceValueType::Reference)) =
            (item.target.as_deref(), kind)
        {
            let actual = self
                .field(&item.field)
                .and_then(|field| match &field.field_type {
                    FieldTypeSource::Reference { target, .. } => Some(target.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            if actual != target {
                self.error(
                    "breg.occurrence.reference-target",
                    format!("{}.{address}.target", self.base),
                    format!(
                        "target \"{target}\" does not match reference target \"{actual}\" of field \"{}\"",
                        item.field
                    ),
                );
            }
        }
    }

    /// The path-relative shape rules shared by `occurredAt` and `effective`.
    fn check_time(
        &mut self,
        member: &str,
        at: Option<&str>,
        start: Option<&str>,
        end: Option<&str>,
        meaning: Option<IntervalMeaning>,
        allows_meaning: bool,
    ) {
        let shape = if at.is_some() && start.is_some() {
            Some("declare either \"at\" or \"start\", not both")
        } else if at.is_none() && start.is_none() && end.is_none() {
            Some("declare \"at\" or \"start\"")
        } else if end.is_some() && start.is_none() {
            Some("\"end\" requires \"start\"")
        } else if at.is_some() && meaning.is_some() {
            Some("\"meaning\" applies only to an interval")
        } else if allows_meaning && start.is_some() && meaning.is_none() {
            Some("an interval declares \"meaning\": span or within")
        } else if meaning == Some(IntervalMeaning::Within) && end.is_none() {
            Some("\"within\" requires \"end\"")
        } else {
            None
        };
        if let Some(message) = shape {
            self.error(
                "breg.occurrence.time-shape",
                format!("{}.{member}", self.base),
                message.to_owned(),
            );
        }
        if let Some(id) = at {
            self.check_field(id, &format!("{member}.at"), MOMENT);
        }
        let start_type =
            start.and_then(|id| self.check_field(id, &format!("{member}.start"), MOMENT));
        let end_type = end.and_then(|id| self.check_field(id, &format!("{member}.end"), MOMENT));
        if shape.is_none() {
            if let (Some(start_type), Some(end_type)) = (start_type, end_type) {
                if start_type != end_type {
                    self.error(
                        "breg.occurrence.interval-type-mismatch",
                        format!("{}.{member}.end", self.base),
                        format!(
                            "interval bounds must share one type; start is {}, end is {}",
                            start_type.name(),
                            end_type.name()
                        ),
                    );
                }
            }
        }
    }

    fn check_occurred_at(&mut self, time: &OccurrenceTimeSource) {
        self.check_time(
            "occurredAt",
            time.at.as_deref(),
            time.start.as_deref(),
            time.end.as_deref(),
            time.meaning,
            true,
        );
    }

    fn check_effective(&mut self, time: &EffectiveTimeSource) {
        self.check_time(
            "effective",
            time.at.as_deref(),
            time.start.as_deref(),
            time.end.as_deref(),
            None,
            false,
        );
    }

    fn check_correction(&mut self, field_id: &str) {
        if self
            .check_field(field_id, "correction.field", REFERENCE)
            .is_none()
        {
            return;
        }
        self.claim(field_id, "correction", "correction.field");
        let target = self
            .field(field_id)
            .and_then(|field| match &field.field_type {
                FieldTypeSource::Reference { target, .. } => Some(target.clone()),
                _ => None,
            });
        // An unknown target is reported by reference validation.
        if let Some(target) = target {
            let declares = self
                .entities
                .get(&target)
                .is_some_and(|entity| entity.occurrence.is_some());
            if self.entities.contains_key(&target) && !declares {
                self.error(
                    "breg.occurrence.correction-target",
                    format!("{}.correction.field", self.base),
                    format!(
                        "correction field \"{field_id}\" targets record type \"{target}\", which declares no occurrence"
                    ),
                );
            }
        }
    }

    fn check_source_event_id(&mut self, source: &crate::contract::SourceEventIdSource) {
        let member = "sourceEventId";
        self.check_field(&source.field, "sourceEventId.field", OPAQUE_IDENTIFIER);
        match (&source.namespace, &source.namespace_field) {
            (Some(namespace), None) => self.check_namespace(namespace, "sourceEventId.namespace"),
            (None, Some(field)) => {
                self.check_field(field, "sourceEventId.namespaceField", NAMESPACE);
            }
            _ => self.error(
                "breg.occurrence.source-event-namespace",
                format!("{}.{member}", self.base),
                "declare exactly one of \"namespace\" or \"namespaceField\"".to_owned(),
            ),
        }
        let path = format!("{}.{member}.constraint", self.base);
        match (source.duplicates, source.constraint.as_deref()) {
            (DuplicatePolicy::Reject, None) => self.error(
                "breg.occurrence.source-event-constraint",
                path,
                "duplicates: reject requires \"constraint\"".to_owned(),
            ),
            (DuplicatePolicy::Allow, Some(_)) => self.error(
                "breg.occurrence.source-event-constraint",
                path,
                "\"constraint\" applies only to duplicates: reject".to_owned(),
            ),
            (DuplicatePolicy::Reject, Some(id)) => self.check_unique_constraint(source, id, path),
            (DuplicatePolicy::Allow, None) => {}
        }
    }

    fn check_unique_constraint(
        &mut self,
        source: &crate::contract::SourceEventIdSource,
        id: &str,
        path: String,
    ) {
        let unique = self
            .entity
            .constraints
            .iter()
            .find_map(|constraint| match constraint {
                ConstraintSource::Unique {
                    id: Some(candidate),
                    fields,
                    when,
                } if candidate == id => Some((fields, when)),
                _ => None,
            });
        let Some((fields, when)) = unique else {
            self.error(
                "breg.occurrence.source-event-constraint",
                path,
                format!(
                    "constraint \"{id}\" is not a unique constraint of record type \"{}\"",
                    self.entity.id
                ),
            );
            return;
        };
        let mut expected = vec![source.field.as_str()];
        expected.extend(source.namespace_field.as_deref());
        let covers = fields.iter().map(String::as_str).collect::<BTreeSet<_>>()
            == expected.iter().copied().collect::<BTreeSet<_>>()
            && fields.len() == expected.len();
        if when.is_some() || !covers {
            let listed = expected
                .iter()
                .map(|field| format!("\"{field}\""))
                .collect::<Vec<_>>()
                .join(", ");
            self.error(
                "breg.occurrence.source-event-constraint",
                path,
                format!("constraint \"{id}\" must cover exactly {listed} without \"when\""),
            );
        }
    }
}

pub(crate) fn validate(entities: &BTreeMap<String, EntitySource>, errors: &mut Vec<Diagnostic>) {
    for entity in entities.values() {
        if let Some(occurrence) = &entity.occurrence {
            validate_entity(entity, occurrence, entities, errors);
        }
    }
}

fn validate_entity(
    entity: &EntitySource,
    occurrence: &OccurrenceSource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let mut checker = Checker {
        entity,
        entities,
        base: format!("recordTypes[id={}].occurrence", entity.id),
        errors,
        claimed: BTreeMap::new(),
    };
    if occurrence.subjects.is_empty() {
        checker.error(
            "breg.occurrence.subjects-empty",
            format!("{}.subjects", checker.base),
            "an occurrence declares at least one subject".to_owned(),
        );
    }
    let mut seen = BTreeSet::new();
    checker.check_roles("subjects", &occurrence.subjects, &mut seen);
    checker.check_roles("sources", &occurrence.sources, &mut seen);
    if let Some(correction) = &occurrence.correction {
        checker.check_correction(&correction.field);
    }
    if let Some(summary) = &occurrence.summary {
        if checker.check_field(summary, "summary", SUMMARY).is_some() {
            checker.claim(summary, "summary", "summary");
        }
    }
    if let Some(time) = &occurrence.occurred_at {
        checker.check_occurred_at(time);
    }
    if let Some(time) = &occurrence.effective {
        checker.check_effective(time);
    }
    if let Some(source) = &occurrence.source_event_id {
        checker.check_source_event_id(source);
    }
    crate::compiler::validate_display_text_at(
        occurrence.label.as_deref(),
        &format!("{}.label", checker.base),
        checker.errors,
    );
    for (list, roles) in [
        ("subjects", &occurrence.subjects),
        ("sources", &occurrence.sources),
    ] {
        for (index, item) in roles.iter().enumerate() {
            let address = if valid_role(&item.role) {
                format!("[role={}]", item.role)
            } else {
                format!("[{index}]")
            };
            crate::compiler::validate_display_text_at(
                item.label.as_deref(),
                &format!("{}.{list}{address}.label", checker.base),
                checker.errors,
            );
        }
    }
}

fn compiled_field(entity: &CompiledEntity, id: &str) -> CompiledOccurrenceField {
    let stored = entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == id)
        .expect("validated occurrence fields are stored fields");
    let (value_type, target) = match &stored.logical.field_type {
        FieldTypeSource::Reference { target, .. } => {
            (OccurrenceValueType::Reference, Some(target.clone()))
        }
        FieldTypeSource::String { .. } => (OccurrenceValueType::String, None),
        FieldTypeSource::Text { .. } => (OccurrenceValueType::Text, None),
        FieldTypeSource::Date => (OccurrenceValueType::Date, None),
        FieldTypeSource::Timestamp => (OccurrenceValueType::Timestamp, None),
        FieldTypeSource::Uuid => (OccurrenceValueType::Uuid, None),
        FieldTypeSource::VocabularyCode { .. } => (OccurrenceValueType::VocabularyCode, None),
        _ => unreachable!("validated occurrence fields have a mappable type"),
    };
    CompiledOccurrenceField {
        id: id.to_owned(),
        api_name: stored.logical.api_name.clone(),
        value_type,
        target,
    }
}

fn compiled_roles(
    entity: &CompiledEntity,
    roles: &[OccurrenceRoleSource],
) -> Vec<CompiledOccurrenceRole> {
    roles
        .iter()
        .map(|item| CompiledOccurrenceRole {
            role: item.role.clone(),
            label: item.label.clone(),
            kind: if item.external.is_some() {
                OccurrenceRoleKind::External
            } else {
                OccurrenceRoleKind::Native
            },
            namespace: item
                .external
                .as_ref()
                .map(|external| external.namespace.clone()),
            field: compiled_field(entity, &item.field),
        })
        .collect()
}

fn compiled_time(
    entity: &CompiledEntity,
    at: Option<&str>,
    start: Option<&str>,
    end: Option<&str>,
    meaning: IntervalMeaning,
) -> Option<CompiledOccurrenceTime> {
    if let Some(at) = at {
        return Some(CompiledOccurrenceTime::Point {
            at: compiled_field(entity, at),
        });
    }
    start.map(|start| CompiledOccurrenceTime::Interval {
        meaning,
        start: compiled_field(entity, start),
        end: end.map(|end| compiled_field(entity, end)),
    })
}

/// Resolves every declared occurrence onto its compiled record type.
pub(crate) fn compile(
    sources: &BTreeMap<String, EntitySource>,
    entities: &mut BTreeMap<String, CompiledEntity>,
) {
    for source in sources.values() {
        let Some(occurrence) = &source.occurrence else {
            continue;
        };
        let entity = entities.get_mut(&source.id).expect("compiled entity");
        let label = occurrence
            .label
            .clone()
            .or_else(|| entity.display.label.clone())
            .unwrap_or_else(|| entity.id.clone());
        let compiled = CompiledOccurrence {
            descriptor_version: OCCURRENCE_DESCRIPTOR_VERSION,
            label,
            subjects: compiled_roles(entity, &occurrence.subjects),
            summary: occurrence
                .summary
                .as_deref()
                .map(|id| compiled_field(entity, id)),
            occurred_at: occurrence.occurred_at.as_ref().and_then(|time| {
                compiled_time(
                    entity,
                    time.at.as_deref(),
                    time.start.as_deref(),
                    time.end.as_deref(),
                    time.meaning.unwrap_or(IntervalMeaning::Span),
                )
            }),
            effective: occurrence.effective.as_ref().and_then(|time| {
                compiled_time(
                    entity,
                    time.at.as_deref(),
                    time.start.as_deref(),
                    time.end.as_deref(),
                    IntervalMeaning::Span,
                )
            }),
            sources: compiled_roles(entity, &occurrence.sources),
            correction: occurrence.correction.as_ref().map(|correction| {
                CompiledOccurrenceCorrection {
                    relation: correction.relation,
                    field: compiled_field(entity, &correction.field),
                }
            }),
            source_event_id: occurrence.source_event_id.as_ref().map(|event| {
                CompiledSourceEventId {
                    field: compiled_field(entity, &event.field),
                    namespace: event.namespace.clone(),
                    namespace_field: event
                        .namespace_field
                        .as_deref()
                        .map(|id| compiled_field(entity, id)),
                    duplicates: event.duplicates,
                    constraint: event.constraint.clone(),
                }
            }),
            recorded_time: CompiledRecordedTime {
                source: RecordedTimeSource::CreationRevision,
            },
        };
        entity.occurrence = Some(compiled);
    }
}
