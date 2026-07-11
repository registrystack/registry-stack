use super::*;

pub(in super::super) async fn read_remote_source_adapter_sidecar_many_context(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    bindings: &[(SourceBindingConfig, EvidenceRequestContext)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    if bindings.is_empty() {
        return Vec::new();
    }
    if ensure_source_adapter_sidecar_assurance(sources, connection)
        .await
        .is_err()
    {
        return bindings
            .iter()
            .map(|_| Err(EvidenceError::SourceUnavailable))
            .collect();
    }
    let url = match source_adapter_sidecar_batch_url(&connection.base_url, &bindings[0].0) {
        Ok(url) => url,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };

    let mut query_values: Vec<Result<Vec<SourceQueryValue>, EvidenceError>> =
        Vec::with_capacity(bindings.len());
    for (binding, context) in bindings {
        query_values.push(source_query_values_for_context(binding, context));
    }
    let Some((first_binding, _)) = bindings.first() else {
        return Vec::new();
    };
    let first_values = match query_values.iter().find_map(|values| values.as_ref().ok()) {
        Some(values) => values,
        None => {
            return query_values
                .into_iter()
                .map(|values| match values {
                    Err(error) => Err(error),
                    Ok(_) => Err(EvidenceError::SourceUnavailable),
                })
                .collect()
        }
    };
    if first_values.iter().any(|value| value.op != "eq") {
        return bindings
            .iter()
            .map(|_| Err(EvidenceError::InvalidRequest))
            .collect();
    }
    let query_signature: Vec<Value> = first_values
        .iter()
        .map(|value| json!({ "field": value.field, "op": value.op }))
        .collect();
    let fields = projected_source_fields_with_query_values(first_binding, first_values);
    let mut items = Vec::new();
    let mut item_ids: Vec<Option<String>> = Vec::with_capacity(bindings.len());
    for (idx, values_result) in query_values.iter().enumerate() {
        match values_result {
            Err(_) => item_ids.push(None),
            Ok(values) => {
                let signature_matches = values.len() == first_values.len()
                    && values.iter().zip(first_values).all(|(value, expected)| {
                        value.field == expected.field && value.op == expected.op
                    });
                if !signature_matches || values.iter().any(|value| value.op != "eq") {
                    item_ids.push(None);
                    continue;
                }
                let id = idx.to_string();
                items.push(json!({
                    "id": id,
                    "values": values.iter().map(|value| value.value.clone()).collect::<Vec<_>>(),
                }));
                item_ids.push(Some(id));
            }
        }
    }
    if items.is_empty() {
        return query_values
            .into_iter()
            .map(|values| match values {
                Err(error) => Err(error),
                Ok(_) => Err(EvidenceError::SourceUnavailable),
            })
            .collect();
    }
    let request_body = json!({
        "fields": fields,
        "query_signature": query_signature,
        "items": items,
    });
    let timeout_budget = bulk_timeout(connection, items.len());
    let body_result = send_request_with_retry(
        sources,
        connection,
        "source_adapter_sidecar",
        &url,
        reqwest::Method::POST,
        timeout_budget,
        move |request, token| {
            add_correlation_header(
                request
                    .bearer_auth(token)
                    .header("accept", "application/json")
                    .header("content-type", "application/json")
                    .header("data-purpose", purpose),
            )
            .json(&request_body)
        },
    )
    .await;
    let mut body = match body_result {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(
                target: "registry_notary_server::bulk",
                connection_id = %connection.id,
                error = %error,
                "source_adapter_sidecar_batch_request_failed",
            );
            return query_values
                .into_iter()
                .map(|values| match values {
                    Err(error) => Err(error),
                    Ok(_) => Err(EvidenceError::SourceUnavailable),
                })
                .collect();
        }
    };
    let response_items = body
        .as_object_mut()
        .and_then(|object| object.remove("items"))
        .and_then(|value| match value {
            Value::Array(items) => Some(items),
            _ => None,
        })
        .unwrap_or_default();
    let mut by_id: BTreeMap<String, Value> = BTreeMap::new();
    let requested_ids = item_ids
        .iter()
        .filter_map(|id| id.as_deref())
        .collect::<BTreeSet<_>>();
    for item in response_items {
        let Some(id) = item
            .get("id")
            .and_then(Value::as_str)
            .map(ToString::to_string)
        else {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect();
        };
        if !requested_ids.contains(id.as_str()) {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect();
        }
        if by_id.insert(id, item).is_some() {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect();
        }
    }

    let mut results = Vec::with_capacity(bindings.len());
    for (idx, values_result) in query_values.into_iter().enumerate() {
        match (values_result, item_ids.get(idx).cloned().flatten()) {
            (Err(error), _) => results.push(Err(error)),
            (Ok(_), None) => results.push(Err(EvidenceError::SourceUnavailable)),
            (Ok(_), Some(id)) => {
                let Some(mut item) = by_id.remove(&id) else {
                    results.push(Err(EvidenceError::SourceUnavailable));
                    continue;
                };
                if let Some(error) = item.get("error").and_then(Value::as_object) {
                    results.push(Err(source_adapter_item_error(error)));
                    continue;
                }
                let rows = item
                    .as_object_mut()
                    .and_then(|object| object.remove("data"))
                    .and_then(|value| match value {
                        Value::Array(rows) => Some(rows),
                        _ => None,
                    })
                    .unwrap_or_default();
                let outcome = match rows.len() {
                    0 => Err(EvidenceError::SourceNotFound),
                    1 => rows
                        .into_iter()
                        .next()
                        .ok_or(EvidenceError::SourceUnavailable),
                    _ => Err(EvidenceError::SourceAmbiguous),
                };
                results.push(outcome);
            }
        }
    }
    results
}

pub(in super::super) fn source_adapter_item_error(error: &Map<String, Value>) -> EvidenceError {
    match error.get("code").and_then(Value::as_str) {
        Some(
            "target_auth"
            | "target_rate_limit"
            | "source.target_auth"
            | "source.target_rate_limit"
            | "source.timeout"
            | "source.unavailable",
        ) => EvidenceError::SourceUnavailable,
        _ => EvidenceError::SourceUnavailable,
    }
}

pub(in super::super) fn source_adapter_sidecar_batch_url(
    base_url: &str,
    binding: &SourceBindingConfig,
) -> Result<reqwest::Url, EvidenceError> {
    let mut url = registry_data_api_url(base_url, binding)?;
    let path = format!("{}:batchMatch", url.path());
    url.set_path(&path);
    Ok(url)
}
