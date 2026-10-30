// SPDX-License-Identifier: Apache-2.0

//! A target-local observation, never a reservation or an authorization grant.
//! Use the ordinary GET path so row, membership, disclosure and audit decisions
//! remain owned by the existing read service. No action program runs here.

use super::*;
use crate::contract::FieldTypeSource;

pub(super) enum Availability {
    Satisfied {
        revision: u64,
    },
    NotSatisfied {
        revision: u64,
        guard_reason: Option<String>,
    },
    InputRequired {
        revision: u64,
        inputs: BTreeSet<String>,
    },
    NotDisclosed,
}

impl Availability {
    pub(super) fn value(&self) -> Value {
        match self {
            Self::Satisfied { revision } => json!({
                "available": true, "observedRevision": revision,
            }),
            Self::NotSatisfied {
                revision,
                guard_reason,
            } => {
                let mut value = json!({
                    "available": false, "observedRevision": revision,
                    "reason": "guard-not-satisfied", "recovery": "none",
                });
                if let Some(reason) = guard_reason {
                    value["guardReason"] = json!(reason);
                }
                value
            }
            Self::InputRequired { revision, inputs } => json!({
                "available": null, "observedRevision": revision,
                "reason": "input-required", "recovery": "correct-input", "missingInputs": inputs,
            }),
            Self::NotDisclosed => json!({
                "available": null, "observedRevision": null,
                "reason": "not-disclosed", "recovery": "none",
            }),
        }
    }
}

#[allow(clippy::too_many_arguments)] // One request's observation inputs plus the instant it reads at.
pub(super) async fn observe(
    service: &HttpService,
    action: &AuthorizedActionSurface<'_>,
    claims: &VerifiedRequestClaims,
    headers: &HeaderMap,
    input: &Map<String, Value>,
    target_input: &str,
    correlation: &RequestCorrelation,
    now: time::OffsetDateTime,
) -> Result<Availability, Response> {
    let reference = action
        .action
        .inputs
        .iter()
        .find(|value| value.id == target_input)
        .ok_or_else(unavailable)?;
    let FieldTypeSource::Reference { target, .. } = &reference.field_type else {
        return Err(unavailable());
    };
    let record_id = input
        .get(target_input)
        .and_then(Value::as_str)
        .filter(|id| valid_canonical_record_uuid(id))
        .ok_or_else(unavailable)?;
    let entity = service
        .registry
        .entities()
        .get(target)
        .ok_or_else(unavailable)?;
    let guards = action
        .action
        .requires
        .iter()
        .filter(|guard| guard.input == target_input && !guard.revision_unchanged)
        .collect::<Vec<_>>();
    let Some(boundaries) = action.context.target_authority().get(target) else {
        return Ok(Availability::NotDisclosed);
    };
    let boundaries = boundaries
        .iter()
        .map(crate::postgres::api_boundary)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| unavailable())?;
    let guard_fields = guards
        .iter()
        .map(|guard| guard.field.clone())
        .collect::<BTreeSet<_>>();
    let Some(observed) = observe_target(
        service,
        action.context.selected_profile(),
        claims,
        headers,
        entity,
        record_id,
        &guard_fields,
        &boundaries,
        correlation,
    )
    .await?
    else {
        return Ok(Availability::NotDisclosed);
    };
    let ObservedTarget { revision, current } = observed;
    let mut missing = BTreeSet::new();
    for guard in guards {
        if let Some(input_id) = guard.compared_input() {
            if !input.contains_key(input_id) {
                let declared = action
                    .action
                    .inputs
                    .iter()
                    .find(|input| input.id == input_id)
                    .ok_or_else(unavailable)?;
                missing.insert(declared.api_name.clone());
                continue;
            }
        }
        let field = entity.fields.get(&guard.field).ok_or_else(unavailable)?;
        if !crate::commit_guard::guard_matches(
            guard,
            input,
            &current,
            &service.registry,
            now,
            matches!(field.field_type, FieldTypeSource::Timestamp),
        ) {
            return Ok(Availability::NotSatisfied {
                revision,
                guard_reason: guard.reason.clone(),
            });
        }
    }
    Ok(if missing.is_empty() {
        Availability::Satisfied { revision }
    } else {
        Availability::InputRequired {
            revision,
            inputs: missing,
        }
    })
}

/// The guard and boundary facts of one Record, read back through the ordinary
/// GET path under the selected profile.
pub(in crate::api) struct ObservedTarget {
    pub(in crate::api) revision: u64,
    pub(in crate::api) current: Map<String, Value>,
}

/// Re-read one target under the selected profile only, never the GET route's
/// default profile and never a combination of profiles. `Ok(None)` means the
/// profile cannot disclose every fact the guards and row boundaries need, or
/// has no ordinary GET route for the entity; the Record is then not probed.
/// A concealed error means the Record is outside the profile's boundaries now.
#[allow(clippy::too_many_arguments)]
pub(in crate::api) async fn observe_target(
    service: &HttpService,
    selected_profile: &str,
    claims: &VerifiedRequestClaims,
    headers: &HeaderMap,
    entity: &crate::model::CompiledEntity,
    record_id: &str,
    guard_fields: &BTreeSet<String>,
    boundaries: &[crate::postgres::RowBoundaryContext],
    correlation: &RequestCorrelation,
) -> Result<Option<ObservedTarget>, Response> {
    let target = &entity.id;
    let fields = guard_fields
        .iter()
        .cloned()
        .chain(
            boundaries
                .iter()
                .filter(|boundary| boundary.field() != entity.canonical_id.id)
                .map(|boundary| boundary.field().to_owned()),
        )
        .collect::<BTreeSet<_>>();
    let Some(route) = service
        .registry
        .routes()
        .routes
        .iter()
        .find(|route| route.entity_id == *target && route.operation == Operation::Get)
    else {
        return Ok(None);
    };
    let mut options = QueryOptions::default();
    options.parsed.access_profile = Some(selected_profile.to_owned());
    let Ok(mut surface) = authorize_direct_route(service, route, claims, &options) else {
        return Ok(None);
    };
    if !fields.is_subset(&surface.readable_fields) {
        // Do not even probe the record when any required fact is undisclosed.
        return Ok(None);
    }
    if surface
        .context
        .bind_access_attribution(entity, headers)
        .is_err()
    {
        return Err(concealed());
    }
    if let Some(refusal) = field_encryption_refusal(service, entity) {
        return Err(refusal);
    }
    let read = service
        .records
        .get(RecordReadRequest {
            entity_id: target.clone(),
            operation_id: route.id.clone(),
            method: route.method,
            context: surface.context,
            selected_fields: fields.clone(),
            representation: CursorRepresentation::Json,
            adapter: CursorAdapter::Native,
            adapter_origin: None,
            geojson_next_link_prefix: None,
            kind: RecordReadKind::Get {
                id: record_id.to_owned(),
            },
            maximum_records: 1,
            correlation: correlation.clone(),
        })
        .await
        .map_err(|error| match error {
            ReadServiceError::FieldEncryptionUnavailable => field_encryption_unavailable(),
            _ => unavailable(),
        })?
        .ok_or_else(concealed)?;
    // Held bytes have already passed the ordinary GET terminal audit gate.
    let value: Value = serde_json::from_slice(read.body()).map_err(|_| unavailable())?;
    let data = value
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(unavailable)?;
    if data.get("recordIdentifier").and_then(Value::as_str) != Some(record_id) {
        return Err(unavailable());
    }
    let revision = data
        .get("revisionIdentifier")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|revision| *revision > 0)
        .ok_or_else(unavailable)?;
    let wire = data
        .get("domainData")
        .and_then(Value::as_object)
        .ok_or_else(unavailable)?;
    let mut current = Map::new();
    for field_id in &fields {
        let field = entity.fields.get(field_id).ok_or_else(unavailable)?;
        let api_name =
            crate::postgres::compiled_api_name(entity, field_id).ok_or_else(unavailable)?;
        if let Some(value) = wire.get(api_name) {
            current.insert(field_id.clone(), value.clone());
        } else if field.required {
            return Err(unavailable());
        }
    }
    if !crate::postgres::snapshot_matches_boundaries(
        entity,
        &current,
        Uuid::parse_str(record_id).map_err(|_| unavailable())?,
        boundaries,
    )
    .map_err(|_| unavailable())?
    {
        return Err(concealed());
    }
    Ok(Some(ObservedTarget { revision, current }))
}
