// SPDX-License-Identifier: Apache-2.0

//! Binary slot routes inherit the compiled request's get/patch authorities.

use super::*;
use crate::model::HttpMethod;

#[derive(Clone)]
struct AttachmentRoute {
    base: CompiledRoute,
    slot: String,
    removal: bool,
}

pub(super) fn routes(service: &HttpService) -> Router<Arc<HttpService>> {
    let mut app = Router::new();
    for entity in service.registry.entities().values() {
        for slot in entity.attachments.values() {
            for base in service.registry.routes().routes.iter().filter(|route| {
                route.entity_id == entity.id
                    && matches!(route.operation, Operation::Get | Operation::Patch)
            }) {
                let path = format!("{}/attachments/{}", base.path, slot.id);
                let binding = AttachmentRoute {
                    base: base.clone(),
                    slot: slot.id.clone(),
                    removal: false,
                };
                if base.operation == Operation::Get {
                    app = app.route(&path, get(download).layer(Extension(binding)));
                } else if service.mutations.is_some() {
                    app = app.route(&path, patch(mutate).layer(Extension(binding.clone())));
                    app = app.route(
                        &path,
                        delete(mutate).layer(Extension(AttachmentRoute {
                            removal: true,
                            ..binding
                        })),
                    );
                }
            }
        }
    }
    app
}

#[allow(clippy::too_many_arguments)]
async fn mutate(
    State(service): State<Arc<HttpService>>,
    Extension(binding): Extension<AttachmentRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let route = &binding.base;
    let attachment_route = crate::attachment::route(
        route,
        &binding.slot,
        if binding.removal {
            HttpMethod::Delete
        } else {
            HttpMethod::Patch
        },
    );
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(record_id) = path.get("record_id") else {
        return invalid_request();
    };
    let options = QueryOptions::parse(raw_query.as_deref(), false);
    let surface = options
        .as_ref()
        .ok()
        .and_then(|options| authorize_route(&service, route, &claims, options))
        .filter(|surface| {
            claims.principal().is_some()
                && valid_canonical_record_uuid(record_id)
                && surface.entity.access_profiles[surface.context.selected_profile()]
                    .writable_fields
                    .contains(&binding.slot)
        });
    let Some(surface) = surface else {
        let selected_access_profile =
            options
                .as_ref()
                .ok()
                .and_then(|options| match options.access_profile() {
                    Some(profile) => route
                        .access_profiles
                        .iter()
                        .any(|value| value == profile)
                        .then_some(profile.as_str()),
                    None => route.default_access_profile.as_deref(),
                });
        return attachment_refusal(
            mutations,
            crate::audit::HttpRefusalAudit {
                method: attachment_route.method,
                operation_id: &attachment_route.id,
                target_record: Some(record_id),
                action_id: None,
                principal: claims.principal(),
                selected_access_profile,
                purpose_present: claims.purpose().is_some(),
                correlation: &correlation,
            },
            &binding.slot,
            concealed(),
        )
        .await;
    };
    let refusal = |response| {
        attachment_refusal(
            mutations,
            crate::audit::HttpRefusalAudit {
                method: attachment_route.method,
                operation_id: &attachment_route.id,
                target_record: Some(record_id),
                action_id: None,
                principal: surface.context.principal(),
                selected_access_profile: Some(surface.context.selected_profile()),
                purpose_present: surface.context.purpose().is_some(),
                correlation: &correlation,
            },
            &binding.slot,
            response,
        )
    };
    let Some(key) = single_header(&headers, "idempotency-key") else {
        return refusal(missing_idempotency_key()).await;
    };
    if !valid_idempotency_key(key) {
        return refusal(invalid_request()).await;
    }
    let Some(if_match) = single_header(&headers, IF_MATCH.as_str()) else {
        return refusal(precondition_required()).await;
    };
    if !valid_if_match(if_match) {
        return refusal(precondition_failed()).await;
    }
    let slot = &surface.entity.attachments[&binding.slot];
    let (content_type, bytes) = if binding.removal {
        if !to_bytes(body, 0).await.is_ok_and(|bytes| bytes.is_empty()) {
            return refusal(invalid_request()).await;
        }
        (None, None)
    } else {
        let Some(content_type) = single_header(&headers, CONTENT_TYPE.as_str()) else {
            return refusal(unsupported_media_type()).await;
        };
        if !slot
            .content_types
            .iter()
            .any(|allowed| allowed == content_type)
        {
            return refusal(unsupported_media_type()).await;
        }
        let content_type = content_type.to_owned();
        let Ok(bytes) = bounded_body_to(body, slot.maximum_bytes as usize).await else {
            return refusal(invalid_request()).await;
        };
        if bytes.is_empty() {
            return refusal(invalid_request()).await;
        }
        (Some(content_type), Some(bytes.to_vec()))
    };
    match mutations
        .attachment(
            ConditionalMutationInput {
                route_id: &route.id,
                idempotency_key: key,
                if_match,
                context: &surface.context,
                entity_id: &route.entity_id,
                record_id,
                response_fields: surface.readable_fields,
                representation: negotiated_record_representation(&headers),
                correlation: &correlation,
            },
            crate::attachment::AttachmentMutation {
                slot_id: binding.slot,
                content_type,
                bytes,
            },
        )
        .await
    {
        Ok(outcome) => exact_mutation(
            outcome.response(),
            Some(surface.response_entity),
            public_deployment_prefix(&service),
        ),
        Err(error) => mutation_problem(error),
    }
}

async fn attachment_refusal(
    mutations: &crate::postgres::PostgresRecordMutationService,
    event: crate::audit::HttpRefusalAudit<'_>,
    slot_id: &str,
    response: Response,
) -> Response {
    if event.principal.is_none() {
        return anonymous_refusal(response, AnonymousRefusalReason::MutationRefused);
    }
    match mutations.record_attachment_refusal(event, slot_id).await {
        Ok(()) => response,
        Err(_) => mutation_problem(MutationError::Unavailable),
    }
}

async fn download(
    State(service): State<Arc<HttpService>>,
    Extension(binding): Extension<AttachmentRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let route = &binding.base;
    let attachment_route = crate::attachment::route(route, &binding.slot, HttpMethod::Get);
    let parsed = parse_download_query(raw_query.as_deref());
    let record_id = path.get("record_id");
    let surface = parsed
        .as_ref()
        .ok()
        .and_then(|(options, _)| authorize_route(&service, route, &claims, options))
        .filter(|surface| {
            claims.principal().is_some()
                && record_id.is_some_and(|id| valid_canonical_record_uuid(id))
                && surface.readable_fields.contains(&binding.slot)
        });
    let Some(surface) = surface else {
        return audited_known_read_refusal(
            &service,
            &attachment_route,
            &claims,
            record_id,
            concealed(),
            &correlation,
        )
        .await;
    };
    let (_, version) = parsed.expect("authorized parsed attachment query");
    let request = RecordReadRequest {
        entity_id: route.entity_id.clone(),
        operation_id: route.id.clone(),
        method: route.method,
        context: surface.context,
        selected_fields: BTreeSet::from([binding.slot.clone()]),
        representation: CursorRepresentation::Json,
        adapter: CursorAdapter::Native,
        adapter_origin: None,
        geojson_next_link_prefix: None,
        kind: RecordReadKind::Get {
            id: record_id.expect("authorized record id").clone(),
        },
        maximum_records: 1,
        request_history_after_proposal_version: None,
        correlation,
    };
    match service
        .records
        .attachment(request, binding.slot, version)
        .await
    {
        Ok(Some(held)) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, held.content_type())
            .header(
                "content-disposition",
                crate::attachment::DOWNLOAD_CONTENT_DISPOSITION,
            )
            .header("x-content-type-options", "nosniff")
            .header(CACHE_CONTROL, "no-store")
            .header(VARY, "authorization")
            .body(Body::from(held.body().to_vec()))
            .unwrap_or_else(|_| unavailable()),
        Ok(None) => concealed(),
        Err(_) => unavailable(),
    }
}

fn parse_download_query(raw: Option<&str>) -> Result<(QueryOptions, u32), QueryParseError> {
    let raw = raw.ok_or(QueryParseError::Invalid)?;
    if raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(QueryParseError::Invalid);
    }
    let mut version = None;
    let mut rest = Vec::new();
    for pair in raw.split('&') {
        let (name, value) = pair.split_once('=').ok_or(QueryParseError::Invalid)?;
        if percent_decode(name)? == "proposalVersion" {
            let value = percent_decode(value)?;
            let parsed = value.parse::<u32>().map_err(|_| QueryParseError::Invalid)?;
            if parsed == 0 || parsed.to_string() != value || version.replace(parsed).is_some() {
                return Err(QueryParseError::Invalid);
            }
        } else {
            rest.push(pair);
        }
    }
    let rest = rest.join("&");
    Ok((
        QueryOptions::parse((!rest.is_empty()).then_some(rest.as_str()), false)?,
        version.ok_or(QueryParseError::Invalid)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_requires_one_canonical_proposal_version() {
        for invalid in [
            "",
            "accessProfile=owner",
            "proposalVersion=0",
            "proposalVersion=01",
            "proposalVersion=1&proposalVersion=2",
            "proposalVersion=1&%70roposalVersion=2",
            "proposalVersion=4294967296",
            "proposalVersion=1&$select=id",
        ] {
            assert!(parse_download_query(Some(invalid)).is_err(), "{invalid}");
        }
        assert_eq!(
            parse_download_query(Some("proposalVersion=2&accessProfile=owner"))
                .unwrap()
                .1,
            2
        );
    }
}
