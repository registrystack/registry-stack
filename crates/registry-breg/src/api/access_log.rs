// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn routes(service: &HttpService) -> Router<Arc<HttpService>> {
    let mut app = Router::new();
    for route in &service.registry.routes().routes {
        if route.operation != Operation::Get || read_path_for_route(service, route).is_some() {
            continue;
        }
        if service
            .registry
            .entities()
            .get(&route.entity_id)
            .is_some_and(|entity| entity.access_log.is_some())
        {
            app = app.route(
                &format!("{}/access-log", route.path),
                get(read).layer(Extension(route.clone())),
            );
        }
    }
    app
}

async fn read(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let parsed = parse_options(raw_query.as_deref());
    let (options, cursor, limit) = match parsed {
        Ok(value) => value,
        Err(()) => {
            return audited_known_read_refusal(
                &service,
                &route,
                &claims,
                path.get("record_id"),
                invalid_query(),
                &correlation,
            )
            .await
        }
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_read_concealment(
            &service,
            &route,
            &options,
            &claims,
            path.get("record_id"),
            &correlation,
        )
        .await;
    };
    let record_id = path.get("record_id");
    if claims.principal().is_none()
        || record_id.is_none_or(|id| !valid_canonical_record_uuid(id))
        || headers.contains_key(crate::subject_access_log::REQUESTER_HEADER)
        || headers.contains_key(crate::subject_access_log::PURPOSE_HEADER)
    {
        return audited_read_refusal(
            &service,
            &route,
            &surface,
            record_id,
            concealed(),
            &correlation,
        )
        .await;
    }
    let request = RecordReadRequest {
        entity_id: route.entity_id.clone(),
        operation_id: route.id.clone(),
        method: route.method,
        context: surface.context,
        selected_fields: surface.readable_fields.clone(),
        representation: CursorRepresentation::Json,
        adapter: CursorAdapter::Native,
        adapter_origin: None,
        geojson_next_link_prefix: None,
        kind: RecordReadKind::Get {
            id: record_id.expect("validated record id").clone(),
        },
        maximum_records: 1,
        request_history_after_proposal_version: None,
        correlation: correlation.clone(),
    };
    match service.records.access_log(request, cursor, limit).await {
        Ok(Some(held)) => {
            let mut response = (
                [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
                held.body().to_vec(),
            )
                .into_response();
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(None) => concealed(),
        Err(ReadServiceError::CursorInvalid) => cursor_invalid(),
        Err(_) => unavailable(),
    }
}

fn parse_options(raw: Option<&str>) -> Result<(QueryOptions, Option<String>, u16), ()> {
    let mut profile = None;
    let mut cursor = None;
    let mut limit = None;
    if raw.is_some_and(|value| value.len() > 2048) {
        return Err(());
    }
    for pair in raw
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (name, value) = pair.split_once('=').ok_or(())?;
        let name = percent_decode(name).map_err(|_| ())?;
        let value = percent_decode(value).map_err(|_| ())?;
        match name.as_str() {
            "accessProfile" if profile.is_none() => profile = Some(value),
            "cursor" if cursor.is_none() && valid_canonical_record_uuid(&value) => {
                cursor = Some(value)
            }
            "limit" if limit.is_none() => {
                let parsed: u16 = value.parse().map_err(|_| ())?;
                if !(1..=100).contains(&parsed) || parsed.to_string() != value {
                    return Err(());
                }
                limit = Some(parsed);
            }
            _ => return Err(()),
        }
    }
    let mut options = QueryOptions::default();
    options.parsed.access_profile = profile;
    Ok((options, cursor, limit.unwrap_or(50)))
}
