use super::*;
use crate::json_path::get_json_path;

pub(in super::super) async fn read_external_dci_http_one(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let lookup_value = lookup_value(binding, subject)?;
    read_external_dci_http_one_lookup(sources, connection, binding, lookup_value, purpose).await
}

pub(in super::super) async fn read_external_dci_http_one_for_context(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    if binding.query_fields.is_empty() {
        let lookup_value = lookup_value_for_context(binding, context)?;
        return read_external_dci_http_one_lookup(
            sources,
            connection,
            binding,
            lookup_value,
            purpose,
        )
        .await;
    }
    let lookup_values = source_query_values_for_context(binding, context)?;
    read_external_dci_http_one_query_values(sources, connection, binding, lookup_values, purpose)
        .await
}

pub(in super::super) async fn read_external_dci_source_observed_at_for_context(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
) -> Result<Option<OffsetDateTime>, EvidenceError> {
    let Some(observed_field) = binding.matching.source_observed_at_field.as_deref() else {
        return Ok(None);
    };
    let lookup_values = source_query_values_for_context(binding, context)?;
    let url = source_url(&connection.base_url, &connection.dci.search_path)?;
    let request_body =
        dci_search_request_body_for_values(&connection.dci, binding, &lookup_values)?;
    let body = send_request_with_retry(
        sources,
        connection,
        "dci_observed_at",
        &url,
        reqwest::Method::POST,
        sources.request_timeout,
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
    .await?;
    let rows = match get_json_path(&body, &connection.dci.records_path).and_then(Value::as_array) {
        Some(rows) => rows,
        None if dci_search_response_not_found(&body) => return Err(EvidenceError::SourceNotFound),
        None => return Err(EvidenceError::SourceUnavailable),
    };
    let row = match rows.len() {
        0 => return Err(EvidenceError::SourceNotFound),
        1 => {
            source_observed_at_dci_row(connection, &lookup_values, observed_field, &body, &rows[0])
        }
        _ => return Err(EvidenceError::SourceAmbiguous),
    };
    parse_source_observed_at(binding, &row)
}

pub(in super::super) async fn read_external_dci_http_one_lookup(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    lookup_value: Value,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let url = source_url(&connection.base_url, &connection.dci.search_path)?;
    let request_body = dci_search_request_body(&connection.dci, binding, &lookup_value)?;
    let body = send_request_with_retry(
        sources,
        connection,
        "dci",
        &url,
        reqwest::Method::POST,
        sources.request_timeout,
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
    .await?;
    let rows = match get_json_path(&body, &connection.dci.records_path).and_then(Value::as_array) {
        Some(rows) => rows,
        None if dci_search_response_not_found(&body) => return Err(EvidenceError::SourceNotFound),
        None => return Err(EvidenceError::SourceUnavailable),
    };
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => project_dci_record(connection, binding, &lookup_value, &body, &rows[0]),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

pub(in super::super) async fn read_external_dci_http_one_query_values(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    lookup_values: Vec<SourceQueryValue>,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let url = source_url(&connection.base_url, &connection.dci.search_path)?;
    let request_body =
        dci_search_request_body_for_values(&connection.dci, binding, &lookup_values)?;
    let body = send_request_with_retry(
        sources,
        connection,
        "dci",
        &url,
        reqwest::Method::POST,
        sources.request_timeout,
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
    .await?;
    let rows = match get_json_path(&body, &connection.dci.records_path).and_then(Value::as_array) {
        Some(rows) => rows,
        None if dci_search_response_not_found(&body) => return Err(EvidenceError::SourceNotFound),
        None => return Err(EvidenceError::SourceUnavailable),
    };
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => project_dci_record_for_values(connection, binding, &lookup_values, &body, &rows[0]),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

/// DCI bulk specialization: one POST with N `search_request` entries, each
/// carrying a unique `reference_id`. Responses are matched back to subjects
/// by `reference_id`; per-entry projection runs through
/// `dci.bulk_records_path` (defaults to `/data/reg_records` inside one
/// `search_response[i]` entry).
pub(in super::super) async fn read_external_dci_http_many(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    let url = match source_url(&connection.base_url, &connection.dci.search_path) {
        Ok(url) => url,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    // Resolve per-subject lookup values; subjects with bad lookups produce
    // an Err in the corresponding position and are excluded from the wire
    // request.
    let mut lookup_values: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (binding, subject) in bindings {
        lookup_values.push(lookup_value(binding, subject));
    }
    // Build (reference_id, search_criteria) entries for each valid subject.
    let mut entry_ids: Vec<Option<String>> = Vec::with_capacity(bindings.len());
    let mut search_request: Vec<Value> = Vec::new();
    let n_valid = lookup_values.iter().filter(|r| r.is_ok()).count();
    let timestamp = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(ts) => ts,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    for (idx, lv_result) in lookup_values.iter().enumerate() {
        match lv_result {
            Err(_) => entry_ids.push(None),
            Ok(lv) => {
                let binding = &bindings[idx].0;
                let reference_id = Ulid::new().to_string();
                let criteria = match dci_search_criteria(&connection.dci, binding, lv, n_valid) {
                    Ok(c) => c,
                    Err(_) => {
                        entry_ids.push(None);
                        continue;
                    }
                };
                search_request.push(json!({
                    "reference_id": reference_id,
                    "timestamp": timestamp,
                    "search_criteria": criteria,
                }));
                entry_ids.push(Some(reference_id));
            }
        }
    }
    if search_request.is_empty() {
        return lookup_values
            .into_iter()
            .map(|r| match r {
                Err(e) => Err(e),
                Ok(_) => Err(EvidenceError::SourceUnavailable),
            })
            .collect();
    }
    let message_id = Ulid::new().to_string();
    let mut request_body = json!({
        "header": {
            "message_id": message_id,
            "message_ts": timestamp,
            "action": "search",
            "sender_id": connection.dci.sender_id,
            "total_count": search_request.len(),
            "is_msg_encrypted": false,
        },
        "message": {
            "transaction_id": message_id,
            "search_request": search_request,
        },
    });
    add_dci_envelope_options(&connection.dci, &mut request_body);
    let timeout_budget = bulk_timeout(connection, n_valid);
    let body_result = send_request_with_retry(
        sources,
        connection,
        "dci_bulk",
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
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            tracing::warn!(
                target: "registry_notary_server::bulk",
                connection_id = %connection.id,
                error = %e,
                "dci_bulk_request_failed",
            );
            return lookup_values
                .into_iter()
                .map(|r| match r {
                    Err(invalid) => Err(invalid),
                    Ok(_) => Err(EvidenceError::SourceUnavailable),
                })
                .collect();
        }
    };
    // Walk message.search_response[] and index by reference_id.
    let response_entries = body
        .pointer("/message/search_response")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut by_ref: BTreeMap<String, &Value> = BTreeMap::new();
    for entry in &response_entries {
        if let Some(rid) = entry.get("reference_id").and_then(Value::as_str) {
            by_ref.insert(rid.to_string(), entry);
        }
    }
    let mut results: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (idx, lv_result) in lookup_values.into_iter().enumerate() {
        match (lv_result, entry_ids.get(idx).cloned().flatten()) {
            (Err(e), _) => results.push(Err(e)),
            (Ok(_), None) => results.push(Err(EvidenceError::SourceUnavailable)),
            (Ok(lookup_value_for_subject), Some(reference_id)) => {
                let binding = &bindings[idx].0;
                let entry = match by_ref.get(reference_id.as_str()) {
                    Some(e) => *e,
                    None => {
                        results.push(Err(EvidenceError::SourceNotFound));
                        continue;
                    }
                };
                let rows = get_json_path(entry, &connection.dci.bulk_records_path)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let outcome = match rows.len() {
                    0 => Err(EvidenceError::SourceNotFound),
                    1 => project_dci_record(
                        connection,
                        binding,
                        &lookup_value_for_subject,
                        &body,
                        &rows[0],
                    ),
                    _ => Err(EvidenceError::SourceAmbiguous),
                };
                results.push(outcome);
            }
        }
    }
    results
}

/// Shared helper for building one DCI `search_criteria` object. Extracted
/// from `dci_search_request_body` so the batched path can produce N entries
/// without duplicating the query-shape logic. `page_size` is set to
/// `max(dci.max_results, batch_size)` so the upstream does not truncate
/// N-subject responses.
pub(in super::super) fn dci_search_criteria(
    dci: &DciSourceConnectionConfig,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
    batch_size: usize,
) -> Result<Value, EvidenceError> {
    let query_value = SourceQueryValue {
        field: binding.lookup.field.clone(),
        op: binding.lookup.op.clone(),
        value: lookup_value.clone(),
    };
    dci_search_criteria_for_values(dci, binding, &[query_value], batch_size)
}

pub(in super::super) fn dci_search_criteria_for_values(
    dci: &DciSourceConnectionConfig,
    binding: &SourceBindingConfig,
    lookup_values: &[SourceQueryValue],
    batch_size: usize,
) -> Result<Value, EvidenceError> {
    let query = match dci.query_type.as_str() {
        "idtype-value" => {
            let Some(value) = lookup_values.first() else {
                return Err(EvidenceError::InvalidRequest);
            };
            if lookup_values.len() != 1 {
                return Err(EvidenceError::InvalidRequest);
            }
            json!({
                "type": value.field,
                "value": value.value,
            })
        }
        "expression" if binding.query_fields.is_empty() => {
            let Some(value) = lookup_values.first() else {
                return Err(EvidenceError::InvalidRequest);
            };
            if lookup_values.len() != 1 {
                return Err(EvidenceError::InvalidRequest);
            }
            json!({
                value.field.clone(): {
                    value.op.clone(): value.value.clone(),
                },
            })
        }
        "expression" => {
            let mut query = Map::new();
            for value in lookup_values {
                query.insert(value.field.clone(), dci_expression_filter(value)?);
            }
            json!({
                "type": "ns:org:QueryType:expression",
                "value": {
                    "expression": {
                        "query": Value::Object(query),
                    },
                },
            })
        }
        "predicate" => Value::Array(
            lookup_values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    let expression_key = format!("expression{}", index + 1);
                    json!({
                        expression_key: {
                            "attribute_name": value.field,
                            "operator": value.op,
                            "attribute_value": value.value,
                        },
                    })
                })
                .collect(),
        ),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    let mut search_criteria = Map::from_iter([
        (
            "query_type".to_string(),
            Value::String(dci.query_type.clone()),
        ),
        ("query".to_string(), query),
        (
            "pagination".to_string(),
            json!({ "page_size": dci.max_results.max(batch_size), "page_number": 1 }),
        ),
    ]);
    if let Some(registry_type) = &dci.registry_type {
        search_criteria.insert("reg_type".to_string(), Value::String(registry_type.clone()));
    }
    if let Some(registry_event_type) = &dci.registry_event_type {
        search_criteria.insert(
            "reg_event_type".to_string(),
            Value::String(registry_event_type.clone()),
        );
    }
    if let Some(record_type) = &dci.record_type {
        search_criteria.insert(
            "reg_record_type".to_string(),
            Value::String(record_type.clone()),
        );
    }
    Ok(Value::Object(search_criteria))
}

pub(in super::super) fn dci_expression_filter(
    query_value: &SourceQueryValue,
) -> Result<Value, EvidenceError> {
    let value = match &query_value.value {
        Value::String(value) => Value::String(value.clone()),
        Value::Number(value) => Value::String(value.to_string()),
        Value::Bool(value) => Value::String(value.to_string()),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    match query_value.op.as_str() {
        "eq" => Ok(json!({ "type": "exact", "term": value })),
        "ge" | "gte" => Ok(json!({ "type": "range", "gte": value })),
        "le" | "lte" => Ok(json!({ "type": "range", "lte": value })),
        "gt" => Ok(json!({ "type": "range", "gt": value })),
        "lt" => Ok(json!({ "type": "range", "lt": value })),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

/// Send an outbound HTTP request to a `source_connection`, holding the
/// connection's process-global semaphore permit for the full duration of the
/// call including any retries. Single retry on transport error or HTTP 5xx,
/// with 50-150ms jittered backoff. Reads the response body into a JSON value
/// on success; treats >=400 responses as `SourceUnavailable`.
pub(in super::super) fn dci_search_request_body(
    dci: &DciSourceConnectionConfig,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
) -> Result<Value, EvidenceError> {
    let query_value = SourceQueryValue {
        field: binding.lookup.field.clone(),
        op: binding.lookup.op.clone(),
        value: lookup_value.clone(),
    };
    dci_search_request_body_for_values(dci, binding, &[query_value])
}

pub(in super::super) fn dci_search_request_body_for_values(
    dci: &DciSourceConnectionConfig,
    binding: &SourceBindingConfig,
    lookup_values: &[SourceQueryValue],
) -> Result<Value, EvidenceError> {
    let message_id = Ulid::new().to_string();
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    let search_criteria = dci_search_criteria_for_values(dci, binding, lookup_values, 2)?;
    let mut body = json!({
        "header": {
            "message_id": message_id,
            "message_ts": timestamp,
            "action": "search",
            "sender_id": dci.sender_id,
            "total_count": 1,
            "is_msg_encrypted": false,
        },
        "message": {
            "transaction_id": message_id,
            "search_request": [{
                "reference_id": message_id,
                "timestamp": timestamp,
                "search_criteria": search_criteria,
            }],
        },
    });
    add_dci_envelope_options(dci, &mut body);
    Ok(body)
}

#[derive(Debug, Clone)]
pub(in super::super) struct SourceQueryValue {
    pub(in super::super) field: String,
    pub(in super::super) op: String,
    pub(in super::super) value: Value,
}

pub(in super::super) fn source_query_values_for_context(
    binding: &SourceBindingConfig,
    context: &EvidenceRequestContext,
) -> Result<Vec<SourceQueryValue>, EvidenceError> {
    if binding.query_fields.is_empty() {
        return Ok(vec![SourceQueryValue {
            field: binding.lookup.field.clone(),
            op: binding.lookup.op.clone(),
            value: lookup_value_for_context(binding, context)?,
        }]);
    }
    binding
        .query_fields
        .iter()
        .map(|field| {
            let value = context
                .lookup_value(field.input.as_str())
                .ok_or_else(|| registry_notary_core::missing_context_error(field.input.as_str()))?;
            Ok(SourceQueryValue {
                field: field.field.clone(),
                op: field.op.clone(),
                value,
            })
        })
        .collect()
}

pub(in super::super) fn single_source_row(body: Value) -> Result<Value, EvidenceError> {
    let rows = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::SourceUnavailable)?;
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => rows
            .first()
            .cloned()
            .ok_or(EvidenceError::SourceUnavailable),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

pub(in super::super) fn parse_source_observed_at(
    binding: &SourceBindingConfig,
    row: &Value,
) -> Result<Option<OffsetDateTime>, EvidenceError> {
    let Some(field) = binding.matching.source_observed_at_field.as_deref() else {
        return Ok(None);
    };
    let Some(value) = get_json_path(row, field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_str() else {
        return Err(EvidenceError::TargetMatchingPolicyRejected);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map(Some)
        .map_err(|_| EvidenceError::TargetMatchingPolicyRejected)
}

pub(in super::super) fn source_observed_at_fields_with_lookup(
    lookup_field: &str,
    observed_field: &str,
) -> Vec<String> {
    let mut fields = vec![lookup_field.to_string(), observed_field.to_string()];
    fields.sort();
    fields.dedup();
    fields
}

pub(in super::super) fn source_observed_at_fields_with_query_values(
    query_values: &[SourceQueryValue],
    observed_field: &str,
) -> Vec<String> {
    let mut fields = query_values
        .iter()
        .map(|value| value.field.clone())
        .collect::<Vec<_>>();
    fields.push(observed_field.to_string());
    fields.sort();
    fields.dedup();
    fields
}

pub(in super::super) fn source_observed_at_dci_row(
    connection: &ResolvedEvidenceSourceConnection,
    lookup_values: &[SourceQueryValue],
    observed_field: &str,
    response: &Value,
    record: &Value,
) -> Value {
    let mut row = Map::new();
    for lookup_value in lookup_values {
        insert_row_path(&mut row, &lookup_value.field, lookup_value.value.clone());
    }
    let path = connection
        .dci
        .field_paths
        .get(observed_field)
        .map(String::as_str)
        .unwrap_or(observed_field);
    if let Some(value) = get_dci_json_path(response, record, path).cloned() {
        insert_row_path(&mut row, observed_field, value);
    }
    Value::Object(row)
}

pub(in super::super) fn add_dci_envelope_options(
    dci: &DciSourceConnectionConfig,
    body: &mut Value,
) {
    if let Some(receiver_id) = &dci.receiver_id {
        if let Some(header) = body.pointer_mut("/header").and_then(Value::as_object_mut) {
            header.insert(
                "receiver_id".to_string(),
                Value::String(receiver_id.clone()),
            );
        }
    }
    if let Some(signature) = &dci.signature {
        if let Some(object) = body.as_object_mut() {
            object.insert("signature".to_string(), Value::String(signature.clone()));
        }
    }
}

pub(in super::super) fn dci_search_response_not_found(body: &Value) -> bool {
    body.pointer("/message/search_response/0")
        .is_some_and(dci_entry_not_found)
}

pub(in super::super) fn dci_entry_not_found(entry: &Value) -> bool {
    let status = entry.get("status").and_then(Value::as_str);
    let reason_code = entry.get("status_reason_code").and_then(Value::as_str);
    let reason_message = entry
        .get("status_reason_message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    status == Some("rjct")
        && (reason_code == Some("REG-ERR-001")
            || reason_message.contains("register_not_found")
            || reason_message.contains("not found"))
}

pub(in super::super) fn project_dci_record(
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
    response: &Value,
    record: &Value,
) -> Result<Value, EvidenceError> {
    let lookup_values = [SourceQueryValue {
        field: binding.lookup.field.clone(),
        op: binding.lookup.op.clone(),
        value: lookup_value.clone(),
    }];
    project_dci_record_for_values(connection, binding, &lookup_values, response, record)
}

pub(in super::super) fn project_dci_record_for_values(
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    lookup_values: &[SourceQueryValue],
    response: &Value,
    record: &Value,
) -> Result<Value, EvidenceError> {
    let mut row = Map::new();
    for lookup_value in lookup_values {
        insert_row_path(&mut row, &lookup_value.field, lookup_value.value.clone());
    }
    for (alias, field) in &binding.fields {
        let path = connection
            .dci
            .field_paths
            .get(&field.field)
            .or_else(|| connection.dci.field_paths.get(alias))
            .map(String::as_str)
            .unwrap_or(field.field.as_str());
        let value = get_dci_json_path(response, record, path)
            .cloned()
            .unwrap_or(Value::Null);
        insert_row_path(&mut row, &field.field, value);
    }
    if let Some(observed_field) = binding.matching.source_observed_at_field.as_deref() {
        let path = connection
            .dci
            .field_paths
            .get(observed_field)
            .map(String::as_str)
            .unwrap_or(observed_field);
        if let Some(value) = get_dci_json_path(response, record, path).cloned() {
            insert_row_path(&mut row, observed_field, value);
        }
    }
    Ok(Value::Object(row))
}

pub(in super::super) fn get_dci_json_path<'a>(
    response: &'a Value,
    record: &'a Value,
    path: &str,
) -> Option<&'a Value> {
    const RESPONSE_PREFIX: &str = "$response:";
    if let Some(response_path) = path.strip_prefix(RESPONSE_PREFIX) {
        return get_json_path(response, response_path);
    }
    get_json_path(record, path)
}

pub(in super::super) fn insert_row_path(row: &mut Map<String, Value>, path: &str, value: Value) {
    let mut parts = path.split('.').filter(|part| !part.is_empty()).peekable();
    let Some(first) = parts.next() else {
        return;
    };
    if parts.peek().is_none() {
        row.insert(first.to_string(), value);
        return;
    }
    let mut current = row
        .entry(first.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            if let Value::Object(object) = current {
                object.insert(part.to_string(), value);
            }
            return;
        }
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        current = current
            .as_object_mut()
            .expect("object was just initialized")
            .entry(part.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
}
