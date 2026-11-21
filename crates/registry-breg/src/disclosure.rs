// SPDX-License-Identifier: Apache-2.0

//! The one evaluator of disclosure conditions.
//!
//! Every surface that reads a record, its history or its fields asks this
//! module whether a profile may see it, and none writes its own predicate.
//! A condition applies to a profile it does not exempt, and only while the
//! record's current values match its `when`. The values are the row on
//! current tables and the latest retained revision on history surfaces.
//!
//! State maps are keyed by field identifier, as a loaded Proposal row is. A
//! member that is absent is null, in the Rust form and in the SQL form alike.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::contract::{DisclosureWhenPredicate, FieldTypeSource};
use crate::generated_ddl::{quote_identifier, quote_literal, typed_literal_sql};
use crate::model::{CompiledDisclosureCondition, CompiledEntity, DisclosureWithhold};

/// The profile the record timer runs under. It is never withheld from, so a
/// timer keeps firing on a record a protected state hides from people.
pub const TIMER_ACCESS_PROFILE: &str = "system-record-timer";

/// A state that cannot be evaluated. A caller treats the record as withheld.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisclosureError {
    /// A member's value does not have the type its field declares.
    InvalidState { field: String },
}

impl std::fmt::Display for DisclosureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState { field } => {
                write!(
                    formatter,
                    "the value of `{field}` does not match its declared type"
                )
            }
        }
    }
}

impl std::error::Error for DisclosureError {}

/// The conditions that bind one profile on one record type.
#[derive(Clone, Debug)]
pub struct DisclosurePlan<'a> {
    entity: &'a CompiledEntity,
    conditions: Vec<&'a CompiledDisclosureCondition>,
}

/// The conditions of `entity` that apply to `profile`. The plan is empty when
/// the profile is exempt from every condition or is the record timer.
pub fn plan<'a>(entity: &'a CompiledEntity, profile: &str) -> DisclosurePlan<'a> {
    let conditions = if profile == TIMER_ACCESS_PROFILE {
        Vec::new()
    } else {
        entity
            .disclosure_conditions
            .iter()
            .filter(|condition| !condition.exempt_profiles.contains(profile))
            .collect()
    };
    DisclosurePlan { entity, conditions }
}

impl DisclosurePlan<'_> {
    /// Whether no condition binds the profile.
    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    /// Whether a `record` condition matches `state`, so the record behaves as absent.
    pub fn withholds_record(&self, state: &Map<String, Value>) -> Result<bool, DisclosureError> {
        self.any_matching(state, |withhold| {
            matches!(withhold, DisclosureWithhold::Record)
        })
    }

    /// Whether a `record` or `history` condition matches `state`, so the
    /// record's revisions and snapshots behave as absent.
    pub fn withholds_history(&self, state: &Map<String, Value>) -> Result<bool, DisclosureError> {
        self.any_matching(state, |withhold| {
            matches!(
                withhold,
                DisclosureWithhold::Record | DisclosureWithhold::History
            )
        })
    }

    /// The field identifiers omitted from a read of `state`.
    pub fn withheld_fields(
        &self,
        state: &Map<String, Value>,
    ) -> Result<BTreeSet<&str>, DisclosureError> {
        let mut withheld = BTreeSet::new();
        for condition in &self.conditions {
            if let DisclosureWithhold::Fields(fields) = &condition.withhold {
                if when_matches(self.entity, &condition.when, state)? {
                    withheld.extend(fields.iter().map(String::as_str));
                }
            }
        }
        Ok(withheld)
    }

    /// `readable` without every field a bound `fields` condition names. A
    /// write response uses this because it never evaluates the state: a
    /// response that omits the field whatever the state is cannot leak a value
    /// captured before the record was marked.
    pub fn response_fields(&self, readable: &BTreeSet<String>) -> BTreeSet<String> {
        let named = self.named_fields();
        readable
            .iter()
            .filter(|field| !named.contains(field.as_str()))
            .cloned()
            .collect()
    }

    /// Every field a bound `fields` condition names, whatever the state.
    pub fn named_fields(&self) -> BTreeSet<&str> {
        self.conditions
            .iter()
            .filter_map(|condition| match &condition.withhold {
                DisclosureWithhold::Fields(fields) => Some(fields),
                DisclosureWithhold::Record | DisclosureWithhold::History => None,
            })
            .flatten()
            .map(String::as_str)
            .collect()
    }

    /// The bound conditions, in authored order.
    pub fn conditions(&self) -> &[&CompiledDisclosureCondition] {
        &self.conditions
    }

    /// Whether the profile may not write `written` over `before`. A bound
    /// `fields` or `history` condition that matches `before` refuses a write
    /// that names one of its `fields`, the `null` a read showed included, and
    /// a write that leaves it unmatched, which lifts the mark. Setting a mark
    /// on a record the condition does not match stays allowed. A `record`
    /// condition is decided on the resulting state by the row boundary check.
    pub fn refuses_write(
        &self,
        before: &Map<String, Value>,
        written: &Map<String, Value>,
    ) -> Result<bool, DisclosureError> {
        let mut after = before.clone();
        after.extend(
            written
                .iter()
                .map(|(field, value)| (field.clone(), value.clone())),
        );
        for condition in &self.conditions {
            let names_a_written_field = match &condition.withhold {
                DisclosureWithhold::Record => continue,
                DisclosureWithhold::History => false,
                DisclosureWithhold::Fields(fields) => {
                    written.keys().any(|field| fields.contains(field))
                }
            };
            if when_matches(self.entity, &condition.when, before)?
                && (names_a_written_field || !when_matches(self.entity, &condition.when, &after)?)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn any_matching(
        &self,
        state: &Map<String, Value>,
        selects: impl Fn(&DisclosureWithhold) -> bool,
    ) -> Result<bool, DisclosureError> {
        for condition in &self.conditions {
            if selects(&condition.withhold) && when_matches(self.entity, &condition.when, state)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Whether every predicate holds for `state`. A predicate on an absent or null
/// member is false, except `field-is-null`.
pub fn when_matches(
    entity: &CompiledEntity,
    when: &[DisclosureWhenPredicate],
    state: &Map<String, Value>,
) -> Result<bool, DisclosureError> {
    for predicate in when {
        let holds = match predicate {
            DisclosureWhenPredicate::FieldEquals { field, value } => {
                match state_value(entity, field, state)? {
                    Some(actual) => literal_equals(entity, field, &actual, value)?,
                    None => false,
                }
            }
            DisclosureWhenPredicate::FieldIn { field, values } => {
                match state_value(entity, field, state)? {
                    Some(actual) => {
                        let mut found = false;
                        for value in values {
                            if literal_equals(entity, field, &actual, value)? {
                                found = true;
                                break;
                            }
                        }
                        found
                    }
                    None => false,
                }
            }
            DisclosureWhenPredicate::FieldIsNull { field } => {
                state_value(entity, field, state)?.is_none()
            }
            DisclosureWhenPredicate::FieldIsNotNull { field } => {
                state_value(entity, field, state)?.is_some()
            }
        };
        if !holds {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The value of `field` in `state`, or `None` when it is absent or null.
fn state_value(
    entity: &CompiledEntity,
    field: &str,
    state: &Map<String, Value>,
) -> Result<Option<Value>, DisclosureError> {
    let invalid = || DisclosureError::InvalidState {
        field: field.to_owned(),
    };
    let Some(compiled) = entity.fields.get(field) else {
        return Err(invalid());
    };
    match state.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            if literal_matches_type(value, &compiled.field_type) {
                Ok(Some(value.clone()))
            } else {
                Err(invalid())
            }
        }
    }
}

fn literal_equals(
    entity: &CompiledEntity,
    field: &str,
    actual: &Value,
    literal: &Value,
) -> Result<bool, DisclosureError> {
    if !entity.fields.contains_key(field) {
        return Err(DisclosureError::InvalidState {
            field: field.to_owned(),
        });
    }
    Ok(actual == literal)
}

/// Whether `value` has the JSON shape a stored value of `field_type` has.
fn literal_matches_type(value: &Value, field_type: &FieldTypeSource) -> bool {
    match field_type {
        FieldTypeSource::Boolean => value.is_boolean(),
        FieldTypeSource::Int64 => value.is_i64(),
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::VocabularyCode { .. }
        | FieldTypeSource::Decimal { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Timestamp
        | FieldTypeSource::Uuid
        | FieldTypeSource::Reference { .. } => value.is_string(),
        FieldTypeSource::Crs84Point { .. }
        | FieldTypeSource::Crs84Polygon { .. }
        | FieldTypeSource::Structured { .. } => false,
    }
}

/// The SQL form of `when`, two-valued so a null column never yields a null
/// (a null inside a row policy hides the row). `column` maps a field
/// identifier to the SQL expression that reads it, typed as the field is.
///
/// A field that is not a compiled field of `entity` is a compiler bug, so it
/// panics rather than producing SQL that matches nothing.
pub fn when_sql(
    entity: &CompiledEntity,
    when: &[DisclosureWhenPredicate],
    column: &dyn Fn(&str) -> String,
) -> String {
    let predicates = when
        .iter()
        .map(|predicate| match predicate {
            DisclosureWhenPredicate::FieldEquals { field, value } => format!(
                "{} = {}",
                column(field),
                typed_literal_sql(value, &entity.fields[field].field_type)
            ),
            DisclosureWhenPredicate::FieldIn { field, values } => format!(
                "{} IN ({})",
                column(field),
                values
                    .iter()
                    .map(|value| typed_literal_sql(value, &entity.fields[field].field_type))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            DisclosureWhenPredicate::FieldIsNull { field } => format!("{} IS NULL", column(field)),
            DisclosureWhenPredicate::FieldIsNotNull { field } => {
                format!("{} IS NOT NULL", column(field))
            }
        })
        .collect::<Vec<_>>();
    format!("COALESCE(({}), false)", predicates.join(" AND "))
}

/// The `USING` expression of the restrictive row policy for one `record`
/// condition: a row is visible when the condition does not match, or when the
/// selected profile is exempt or is the record timer. The policy names no
/// role, so it binds every role that reads the table.
pub fn record_guard_sql(
    entity: &CompiledEntity,
    condition: &CompiledDisclosureCondition,
) -> String {
    let when = when_sql(entity, &condition.when, &|field| {
        quote_identifier(&entity.fields[field].physical_name)
    });
    let exempt = condition
        .exempt_profiles
        .iter()
        .map(String::as_str)
        .chain([TIMER_ACCESS_PROFILE])
        .map(quote_literal)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "NOT {when} OR NULLIF(current_setting('registry.access_profile', true), '') IN ({exempt})"
    )
}

/// The field identifiers each `fields` condition names, keyed by condition id.
pub fn named_fields_by_condition(entity: &CompiledEntity) -> BTreeMap<&str, &BTreeSet<String>> {
    entity
        .disclosure_conditions
        .iter()
        .filter_map(|condition| match &condition.withhold {
            DisclosureWithhold::Fields(fields) => Some((condition.id.as_str(), fields)),
            DisclosureWithhold::Record | DisclosureWithhold::History => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::parse_project_json;
    use serde_json::json;

    fn entity() -> CompiledEntity {
        let source = json!({"datasets":[{"id":"d"}],
            "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
            "project":{"id":"unit","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://unit.example.test"},
            "recordTypes":[{"id":"person","primaryDataset":"d","route":"people","mutationMode":"mutable","classification":"internal",
              "fields":[{"id":"level","type":"string","maximumLength":16,"classification":"internal"},
                        {"id":"age","type":"int64","classification":"internal"},
                        {"id":"phone","type":"string","maximumLength":16,"classification":"internal"}],
              "disclosureConditions":[
                {"id":"hide-record","when":[{"type":"field-equals","field":"level","value":"secret"}],
                 "withhold":"record","exemptProfiles":["officer"]},
                {"id":"hide-history","when":[{"type":"field-is-not-null","field":"age"}],
                 "withhold":"history","exemptProfiles":["officer"]},
                {"id":"hide-phone","when":[{"type":"field-in","field":"level","values":["a","b"]}],
                 "withhold":"fields","fields":["phone"],"exemptProfiles":["officer"]}]}],
            "accessProfiles":[
              {"id":"registrar","default":true,"principalClaim":"p","requiredScopes":"unrestricted","permissions":{"records":[
                {"recordType":"person","operations":["get"],"rowBoundaries":"unrestricted","readableFields":["level","age","phone"]}]}},
              {"id":"officer","principalClaim":"p","requiredScopes":"unrestricted","permissions":{"records":[
                {"recordType":"person","operations":["get"],"rowBoundaries":"unrestricted","readableFields":["level","age","phone"]}]}}]});
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("unit project compiles")
            .entities()["person"]
            .clone()
    }

    fn state(value: serde_json::Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn exempt_profiles_and_the_timer_have_an_empty_plan() {
        let entity = entity();
        assert!(plan(&entity, "officer").is_empty());
        assert!(plan(&entity, TIMER_ACCESS_PROFILE).is_empty());
        assert!(!plan(&entity, "registrar").is_empty());
        assert!(!plan(&entity, "an-unknown-profile").is_empty());
    }

    #[test]
    fn record_history_and_fields_conditions_evaluate_separately() {
        let entity = entity();
        let registrar = plan(&entity, "registrar");
        let secret = state(json!({"level": "secret"}));
        assert!(registrar.withholds_record(&secret).unwrap());
        assert!(registrar.withholds_history(&secret).unwrap());
        assert!(registrar.withheld_fields(&secret).unwrap().is_empty());

        let aged = state(json!({"level": "a", "age": 4}));
        assert!(!registrar.withholds_record(&aged).unwrap());
        assert!(registrar.withholds_history(&aged).unwrap());
        assert_eq!(
            registrar
                .withheld_fields(&aged)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            ["phone"]
        );

        let open = state(json!({"level": "c"}));
        assert!(!registrar.withholds_history(&open).unwrap());
    }

    #[test]
    fn an_absent_member_is_null() {
        let entity = entity();
        let registrar = plan(&entity, "registrar");
        for absent in [state(json!({})), state(json!({"level": null, "age": null}))] {
            assert!(!registrar.withholds_record(&absent).unwrap());
            assert!(!registrar.withholds_history(&absent).unwrap());
        }
    }

    #[test]
    fn response_fields_drops_every_named_field_whatever_the_state() {
        let entity = entity();
        let readable: BTreeSet<String> = ["level", "age", "phone"].map(str::to_owned).into();
        let registrar = plan(&entity, "registrar").response_fields(&readable);
        assert_eq!(registrar.into_iter().collect::<Vec<_>>(), ["age", "level"]);
        assert_eq!(
            plan(&entity, "officer").response_fields(&readable),
            readable
        );
    }

    #[test]
    fn a_bound_write_cannot_lift_a_mark_or_name_a_withheld_field() {
        let entity = entity();
        let registrar = plan(&entity, "registrar");
        let refuses = |before: Value, written: Value| {
            registrar
                .refuses_write(&state(before), &state(written))
                .unwrap()
        };
        // Writing a withheld field, a null included, or lifting either mark.
        assert!(refuses(json!({"level": "a"}), json!({"phone": "555"})));
        assert!(refuses(json!({"level": "a"}), json!({"phone": null})));
        assert!(refuses(json!({"level": "a"}), json!({"level": "c"})));
        assert!(refuses(json!({"age": 4}), json!({"age": null})));
        // Moving between two matching values keeps the mark.
        assert!(!refuses(json!({"level": "a"}), json!({"level": "b"})));
        // A field no condition names, and setting a mark, stay allowed.
        assert!(!refuses(json!({"level": "a", "age": 4}), json!({"age": 5})));
        assert!(!refuses(
            json!({"level": "c"}),
            json!({"level": "a", "phone": "555", "age": 4})
        ));
        // A `record` condition is left to the row boundary check.
        assert!(!refuses(json!({"level": "secret"}), json!({"level": "c"})));
        // An exempt profile writes anything.
        assert!(!plan(&entity, "officer")
            .refuses_write(
                &state(json!({"level": "a", "age": 4})),
                &state(json!({"level": "c", "age": null, "phone": null}))
            )
            .unwrap());
        // A state that cannot be evaluated is an error.
        assert!(registrar
            .refuses_write(&state(json!({"level": 7})), &state(json!({"phone": "555"})))
            .is_err());
    }

    #[test]
    fn a_value_of_the_wrong_type_is_an_error() {
        let entity = entity();
        let registrar = plan(&entity, "registrar");
        assert_eq!(
            registrar.withholds_record(&state(json!({"level": 7}))),
            Err(DisclosureError::InvalidState {
                field: "level".to_owned()
            })
        );
        assert!(registrar
            .withholds_history(&state(json!({"age": "old"})))
            .is_err());
    }

    #[test]
    fn the_sql_form_is_two_valued() {
        let entity = entity();
        let when = &entity.disclosure_conditions[0].when;
        let sql = when_sql(&entity, when, &|field| format!("\"{field}\""));
        assert!(
            sql.starts_with("COALESCE((") && sql.ends_with("), false)"),
            "{sql}"
        );
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn the_timer_profile_matches_the_mutation_runtime() {
        assert_eq!(TIMER_ACCESS_PROFILE, crate::mutation::TIMER_ACCESS_PROFILE);
    }
}
