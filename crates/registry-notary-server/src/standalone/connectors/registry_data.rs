use super::*;

pub(in super::super) async fn read_remote_registry_data_api_one(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let lookup_value = lookup_value(binding, subject)?;
    read_remote_registry_data_api_one_lookup(sources, connection, binding, lookup_value, purpose)
        .await
}

pub(in super::super) async fn read_remote_registry_data_api_one_for_context(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    if !binding.query_fields.is_empty() {
        let query_values = source_query_values_for_context(binding, context)?;
        return read_remote_registry_data_api_one_query_values(
            sources,
            connection,
            binding,
            query_values,
            purpose,
        )
        .await;
    }
    let lookup_value = lookup_value_for_context(binding, context)?;
    read_remote_registry_data_api_one_lookup(sources, connection, binding, lookup_value, purpose)
        .await
}

pub(in super::super) async fn read_remote_registry_data_api_source_observed_at_for_context(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
) -> Result<Option<OffsetDateTime>, EvidenceError> {
    let Some(observed_field) = binding.matching.source_observed_at_field.as_deref() else {
        return Ok(None);
    };
    if !binding.query_fields.is_empty() {
        let query_values = source_query_values_for_context(binding, context)?;
        let row = read_remote_registry_data_api_observed_at_query_values(
            sources,
            connection,
            binding,
            query_values,
            observed_field,
            purpose,
        )
        .await?;
        return parse_source_observed_at(binding, &row);
    }
    let lookup_value = lookup_value_for_context(binding, context)?;
    let row = read_remote_registry_data_api_observed_at_lookup(
        sources,
        connection,
        binding,
        lookup_value,
        observed_field,
        purpose,
    )
    .await?;
    parse_source_observed_at(binding, &row)
}

pub(in super::super) async fn read_remote_registry_data_api_one_lookup(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    lookup_value: Value,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    ensure_source_adapter_sidecar_assurance(sources, connection).await?;
    let lookup_field = binding.lookup.field.clone();
    let fields = projected_source_fields_with_lookup(binding, &lookup_field);
    let url = registry_data_api_url(&connection.base_url, binding)?;
    let query_pairs = vec![
        ("limit".to_string(), "2".to_string()),
        ("fields".to_string(), fields.join(",")),
        (lookup_field.clone(), value_query_string(&lookup_value)?),
    ];
    let body = send_request_with_retry(
        sources,
        connection,
        "rda",
        &url,
        reqwest::Method::GET,
        sources.request_timeout,
        move |request, token| {
            add_correlation_header(
                request
                    .bearer_auth(token)
                    .header("accept", "application/json")
                    .header("data-purpose", purpose),
            )
            .query(&query_pairs)
        },
    )
    .await?;
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

pub(in super::super) async fn read_remote_registry_data_api_observed_at_lookup(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    lookup_value: Value,
    observed_field: &str,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    ensure_source_adapter_sidecar_assurance(sources, connection).await?;
    let lookup_field = binding.lookup.field.clone();
    let fields = source_observed_at_fields_with_lookup(&lookup_field, observed_field);
    let url = registry_data_api_url(&connection.base_url, binding)?;
    let query_pairs = vec![
        ("limit".to_string(), "2".to_string()),
        ("fields".to_string(), fields.join(",")),
        (lookup_field.clone(), value_query_string(&lookup_value)?),
    ];
    let body = send_request_with_retry(
        sources,
        connection,
        "rda_observed_at",
        &url,
        reqwest::Method::GET,
        sources.request_timeout,
        move |request, token| {
            add_correlation_header(
                request
                    .bearer_auth(token)
                    .header("accept", "application/json")
                    .header("data-purpose", purpose),
            )
            .query(&query_pairs)
        },
    )
    .await?;
    single_source_row(body)
}

pub(in super::super) async fn read_remote_registry_data_api_one_query_values(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    query_values: Vec<SourceQueryValue>,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    ensure_source_adapter_sidecar_assurance(sources, connection).await?;
    let fields = projected_source_fields_with_query_values(binding, &query_values);
    let url = registry_data_api_url(&connection.base_url, binding)?;
    let mut query_pairs = vec![
        ("limit".to_string(), "2".to_string()),
        ("fields".to_string(), fields.join(",")),
    ];
    for query_value in &query_values {
        query_pairs.push(registry_data_api_query_pair(query_value)?);
    }
    let body = send_request_with_retry(
        sources,
        connection,
        "rda",
        &url,
        reqwest::Method::GET,
        sources.request_timeout,
        move |request, token| {
            add_correlation_header(
                request
                    .bearer_auth(token)
                    .header("accept", "application/json")
                    .header("data-purpose", purpose),
            )
            .query(&query_pairs)
        },
    )
    .await?;
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

pub(in super::super) async fn read_remote_registry_data_api_observed_at_query_values(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    query_values: Vec<SourceQueryValue>,
    observed_field: &str,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    ensure_source_adapter_sidecar_assurance(sources, connection).await?;
    let fields = source_observed_at_fields_with_query_values(&query_values, observed_field);
    let url = registry_data_api_url(&connection.base_url, binding)?;
    let mut query_pairs = vec![
        ("limit".to_string(), "2".to_string()),
        ("fields".to_string(), fields.join(",")),
    ];
    for query_value in &query_values {
        query_pairs.push(registry_data_api_query_pair(query_value)?);
    }
    let body = send_request_with_retry(
        sources,
        connection,
        "rda_observed_at",
        &url,
        reqwest::Method::GET,
        sources.request_timeout,
        move |request, token| {
            add_correlation_header(
                request
                    .bearer_auth(token)
                    .header("accept", "application/json")
                    .header("data-purpose", purpose),
            )
            .query(&query_pairs)
        },
    )
    .await?;
    single_source_row(body)
}

/// RDA bulk specialization: one collection GET with an `.in` filter carrying
/// all subjects' lookup values, then split rows back to subjects by lookup
/// field equality.
///
/// If the response exceeds N rows we fall back to per-subject `read_one` for
/// the whole batch (a `bulk_collision_fallback` tracing event flags the
/// misconfiguration). This preserves correctness when an operator has
/// attested uniqueness but the upstream data violates it.
pub(in super::super) async fn read_remote_registry_data_api_many(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    let first_binding = &bindings[0].0;
    let lookup_field = first_binding.lookup.field.clone();
    let fields = projected_source_fields_with_lookup(first_binding, &lookup_field);
    let url = match registry_data_api_url(&connection.base_url, first_binding) {
        Ok(url) => url,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    // Compute per-subject lookup values up front. If any subject's lookup
    // cannot be derived (e.g. unsupported op), surface that error for that
    // position and exclude it from the bulk request.
    let mut lookup_values: Vec<Result<String, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (binding, subject) in bindings {
        let lv = lookup_value(binding, subject)
            .and_then(|v| value_query_string(&v).map_err(|_| EvidenceError::InvalidRequest));
        lookup_values.push(lv);
    }
    // Build the in-filter CSV from the successfully-derived lookup values.
    let in_values: Vec<String> = lookup_values
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    if in_values.is_empty() {
        // Every position carries an Err already; preserve it. We can't run
        // a bulk request against an empty `.in` set.
        return lookup_values
            .into_iter()
            .map(|r| match r {
                Err(invalid) => Err(invalid),
                Ok(_) => Err(EvidenceError::InvalidRequest),
            })
            .collect();
    }
    let n = in_values.len();
    // Relay parses `<field>.in=v1,v2,...` (see registry-relay/src/api/entity.rs
    // parse_filter_name). We replicate that wire format rather than the
    // value-prefix variant.
    let filter_name = format!("{}.in", lookup_field);
    let query_pairs = vec![
        ("limit".to_string(), (n + 1).to_string()),
        ("fields".to_string(), fields.join(",")),
        (filter_name, in_values.join(",")),
    ];
    let timeout_budget = bulk_timeout(connection, n);
    let body_result = send_request_with_retry(
        sources,
        connection,
        "rda_bulk",
        &url,
        reqwest::Method::GET,
        timeout_budget,
        move |request, token| {
            add_correlation_header(
                request
                    .bearer_auth(token)
                    .header("accept", "application/json")
                    .header("data-purpose", purpose),
            )
            .query(&query_pairs)
        },
    )
    .await;
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            // Bulk call failed: log the underlying error once and surface
            // SourceUnavailable for every subject with a valid lookup;
            // preserve per-subject InvalidRequest for lookups that could
            // not be derived. We can't fan the same EvidenceError value
            // out (it isn't Clone), but the bulk failure mode is always
            // wire-level for connection scope, so SourceUnavailable is
            // the right discriminant for each affected position.
            tracing::warn!(
                target: "registry_notary_server::bulk",
                connection_id = %connection.id,
                error = %e,
                "rda_bulk_request_failed",
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
    let rows: Vec<Value> = body
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Collision fallback: more rows than subjects means the upstream data
    // violates the operator's uniqueness attestation. Switch to per-subject
    // reads so each subject can still surface its own ambiguity error.
    if rows.len() > n {
        tracing::warn!(
            target: "registry_notary_server::bulk",
            connection_id = %connection.id,
            batch_size = n,
            row_count = rows.len(),
            "bulk_collision_fallback",
        );
        return fallback_concurrent_read_one(sources, bindings, purpose).await;
    }
    // Bucket rows by lookup field equality against each subject's lookup
    // value. The `data[i][lookup_field]` is compared against the string
    // form of the subject's lookup value.
    let mut results: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for lv_result in lookup_values {
        match lv_result {
            Err(e) => results.push(Err(e)),
            Ok(lv) => {
                let mut matching: Vec<&Value> = rows
                    .iter()
                    .filter(|row| {
                        row.get(&lookup_field)
                            .map(|val| value_query_string(val).ok().as_deref() == Some(lv.as_str()))
                            .unwrap_or(false)
                    })
                    .collect();
                let outcome = match matching.len() {
                    0 => Err(EvidenceError::SourceNotFound),
                    1 => Ok(matching.remove(0).clone()),
                    _ => Err(EvidenceError::SourceAmbiguous),
                };
                results.push(outcome);
            }
        }
    }
    results
}
