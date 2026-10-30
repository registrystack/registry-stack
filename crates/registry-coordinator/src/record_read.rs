// SPDX-License-Identifier: Apache-2.0
//! `breg.lookup-record/v1` and `breg.read-record/v2`: single-record reads that
//! tell a workflow when the Coordinator looked.
//!
//! A lookup resolves one record from the identifier fields of the person or
//! thing a run is about, through BReg's compiled `:lookup` selector. BReg
//! answers one value-free `lookup.unresolved` whether no record matched, two
//! matched, the row is hidden from this profile or a claim was missing, and the
//! adapter passes that on as the one declared refusal `unresolved`. The second
//! operation is the plain record read with the same provenance block added to
//! its output; `breg.read-record/v1` is unchanged.

use std::collections::BTreeMap;

use chrono::{SecondsFormat, Utc};
use registry_breg_client::{
    BRegComplete, BRegLookupRequest, BRegProblemCode, BRegRecordOptions, BaseRegistryClient,
    RegistryRecordSingleResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    adapters::{read_failure, refused},
    protocol::{CallOutcome, DeclaredRefusal},
};

/// The code a step receives on `onDeclaredRefusal` when a lookup did not
/// resolve exactly one visible record.
pub(crate) const UNRESOLVED: &str = "unresolved";

/// The most identifier fields one lookup can carry, as BReg's client allows.
pub(crate) const MAX_LOOKUP_VALUES: usize = 16;

/// The Coordinator's clock as an RFC 3339 instant in UTC, to the second.
pub(crate) fn observed_at_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Where a record came from and when the workflow looked at it.
///
/// `observedAt` is the Coordinator's clock when the read returned. It says when
/// the workflow looked, not when the fact became true.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct Provenance {
    record_identifier: String,
    revision_identifier: String,
    /// The entity tag BReg sent with the record, where it sends one.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    etag: Option<String>,
    observed_at: String,
}

/// The one record a lookup resolved, with its provenance.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct LookedUpRecord {
    record_identifier: String,
    revision_identifier: String,
    domain_data: BTreeMap<String, Value>,
    provenance: Provenance,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct LookupRequest {
    /// The BReg record-type route, for example `registrants`.
    entity: String,
    /// The compiled lookup selector, for example `by-national-id`.
    selector: String,
    /// The identifier fields the selector matches, each by equality.
    values: BTreeMap<String, LookupValue>,
}

/// A value BReg's lookup accepts: text, a whole number or a flag.
#[derive(Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) enum LookupValue {
    Text(String),
    Integer(i64),
    Flag(bool),
}

impl LookupValue {
    fn into_value(self) -> Value {
        match self {
            Self::Text(text) => Value::String(text),
            Self::Integer(number) => Value::from(number),
            Self::Flag(flag) => Value::Bool(flag),
        }
    }
}

/// The BReg request for a validated lookup input, or `None` when the selector,
/// a field name or a value falls outside what BReg's lookup accepts.
fn lookup_request(input: LookupRequest, options: &BRegRecordOptions) -> Option<BRegLookupRequest> {
    if input.values.is_empty() || input.values.len() > MAX_LOOKUP_VALUES {
        return None;
    }
    let mut request = BRegLookupRequest::new(input.selector)
        .ok()?
        .options(options.clone());
    for (name, value) in input.values {
        request = request.value(name, value.into_value()).ok()?;
    }
    Some(request)
}

pub(crate) async fn lookup_record(
    client: &BaseRegistryClient,
    options: &BRegRecordOptions,
    input: &Value,
) -> CallOutcome {
    let Ok(input) = serde_json::from_value::<LookupRequest>(input.clone()) else {
        return refused("invalid-command");
    };
    let entity = input.entity.clone();
    let Some(request) = lookup_request(input, options) else {
        return refused("invalid-command");
    };
    match client.lookup_record(&entity, &request).await {
        Ok(answer) => looked_up(answer),
        Err(error) if error.problem_code() == Some(BRegProblemCode::LookupUnresolved) => {
            DeclaredRefusal::new(UNRESOLVED)
                .map(CallOutcome::DeclaredRefusal)
                .unwrap_or_else(|| refused("invalid-response"))
        }
        Err(error) => read_failure(error),
    }
}

fn looked_up(answer: BRegComplete<RegistryRecordSingleResponse>) -> CallOutcome {
    let observed_at = observed_at_now();
    let record = answer.value.data;
    match serde_json::to_value(LookedUpRecord {
        provenance: Provenance {
            record_identifier: record.record_identifier.clone(),
            revision_identifier: record.revision_identifier.clone(),
            etag: None,
            observed_at,
        },
        record_identifier: record.record_identifier,
        revision_identifier: record.revision_identifier,
        domain_data: record.domain_data,
    }) {
        Ok(value) => CallOutcome::Success(value),
        Err(_) => refused("invalid-response"),
    }
}

/// `breg.read-record/v2`: the record envelope `breg.read-record/v1` returns,
/// plus a `provenance` member. An answer that already has a `provenance`
/// member is refused rather than overwritten.
pub(crate) fn with_provenance(answer: BRegComplete<RegistryRecordSingleResponse>) -> CallOutcome {
    let observed_at = observed_at_now();
    let provenance = Provenance {
        record_identifier: answer.value.data.record_identifier.clone(),
        revision_identifier: answer.value.data.revision_identifier.clone(),
        etag: answer.metadata.etag().map(|etag| etag.as_str().to_owned()),
        observed_at,
    };
    let (Ok(Value::Object(mut envelope)), Ok(provenance)) = (
        serde_json::to_value(&answer.value),
        serde_json::to_value(provenance),
    ) else {
        return refused("invalid-response");
    };
    if envelope
        .insert("provenance".to_owned(), provenance)
        .is_some()
    {
        return refused("invalid-response");
    }
    CallOutcome::Success(Value::Object(envelope))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn input(values: Value) -> Value {
        json!({"entity": "registrants", "selector": "by-national-id", "values": values})
    }

    fn parse(value: Value) -> Option<BRegLookupRequest> {
        let request = serde_json::from_value::<LookupRequest>(value).ok()?;
        lookup_request(request, &BRegRecordOptions::default())
    }

    #[test]
    fn identifier_fields_of_every_accepted_kind_build_a_request() {
        assert!(parse(input(json!({"id": "x", "year": 1980, "active": true}))).is_some());
    }

    #[test]
    fn a_shape_the_register_cannot_carry_builds_no_request() {
        for (case, value) in [
            ("no values", input(json!({}))),
            ("a nested object", input(json!({"id": {"inner": "x"}}))),
            ("a list", input(json!({"id": ["x"]}))),
            ("a null", input(json!({"id": null}))),
            ("a fraction", input(json!({"id": 1.5}))),
            (
                "a field name the register would not accept",
                input(json!({"Bad Name": "x"})),
            ),
            (
                "a selector that is not a compiled name",
                json!({"entity": "r", "selector": "By-Id", "values": {"id": "x"}}),
            ),
            (
                "an unknown member",
                json!({"entity": "r", "selector": "by-id", "values": {"id": "x"}, "filter": "x"}),
            ),
            ("values as text", input(json!("id=x"))),
        ] {
            assert!(parse(value).is_none(), "{case}");
        }
        let many: serde_json::Map<String, Value> = (0..=MAX_LOOKUP_VALUES)
            .map(|index| (format!("f{index}"), json!("x")))
            .collect();
        assert!(
            parse(input(Value::Object(many))).is_none(),
            "more than sixteen values"
        );
    }

    #[test]
    fn provenance_leaves_out_an_etag_that_was_not_sent() {
        let without = serde_json::to_value(Provenance {
            record_identifier: "r".into(),
            revision_identifier: "1".into(),
            etag: None,
            observed_at: "2026-10-09T09:00:00Z".into(),
        })
        .unwrap();
        assert!(without.get("etag").is_none());
        let with = serde_json::to_value(Provenance {
            record_identifier: "r".into(),
            revision_identifier: "1".into(),
            etag: Some("\"e\"".into()),
            observed_at: "2026-10-09T09:00:00Z".into(),
        })
        .unwrap();
        assert_eq!(with["etag"], "\"e\"");
    }

    #[test]
    fn the_observation_time_is_a_utc_instant_to_the_second() {
        let observed = observed_at_now();
        assert!(observed.ends_with('Z') && observed.len() == "2026-10-09T09:00:00Z".len());
        assert!(chrono::DateTime::parse_from_rfc3339(&observed).is_ok());
    }
}
