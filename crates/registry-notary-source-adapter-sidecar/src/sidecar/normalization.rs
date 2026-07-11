use super::*;

pub(super) fn normalize_worker_response(
    response: Value,
    fields: &[String],
    limit: usize,
) -> Response {
    if let Some(error) = response.get("error").and_then(Value::as_object) {
        return target_error_response(error);
    }

    let Some(records) = response.get("data").and_then(Value::as_array) else {
        return problem(
            StatusCode::BAD_GATEWAY,
            "worker response missing data array",
        );
    };

    let projected = records
        .iter()
        .take(limit)
        .map(|record| project_record(record, fields))
        .collect::<Result<Vec<_>, _>>();
    match projected {
        Ok(data) => (StatusCode::OK, Json(json!({ "data": data }))).into_response(),
        Err(response) => *response,
    }
}

pub(super) fn normalize_batch_worker_response(
    response: Value,
    fields: &[String],
    requested_ids: &[String],
) -> Response {
    let mut response = response;
    if let Some(error) = response.get("error").and_then(Value::as_object) {
        return target_error_response(error);
    }

    let Some(items) = response
        .as_object_mut()
        .and_then(|object| object.remove("items"))
        .and_then(|value| match value {
            Value::Array(items) => Some(items),
            _ => None,
        })
    else {
        return problem(
            StatusCode::BAD_GATEWAY,
            "worker response missing items array",
        );
    };

    let mut seen = BTreeSet::new();
    let mut by_id = BTreeMap::new();
    let requested = requested_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for item in items {
        let Value::Object(object) = item else {
            return problem(StatusCode::BAD_GATEWAY, "worker items must be JSON objects");
        };
        let Some(id) = object
            .get("id")
            .and_then(Value::as_str)
            .map(ToString::to_string)
        else {
            return problem(StatusCode::BAD_GATEWAY, "worker item missing id");
        };
        if !seen.insert(id.clone()) {
            return problem(StatusCode::BAD_GATEWAY, "worker item id duplicated");
        }
        if !requested.contains(id.as_str()) {
            return problem(StatusCode::BAD_GATEWAY, "worker item id was not requested");
        }
        by_id.insert(id, object);
    }

    let mut normalized = Vec::with_capacity(requested_ids.len());
    for id in requested_ids {
        let Some(mut item) = by_id.remove(id) else {
            normalized.push(json!({
                "id": id,
                "error": { "code": "source_unavailable" }
            }));
            continue;
        };
        if let Some(error) = item.get("error").and_then(Value::as_object) {
            normalized.push(json!({ "id": id, "error": normalize_item_error(error) }));
            continue;
        }
        let Some(records) = item.remove("data").and_then(|value| match value {
            Value::Array(records) => Some(records),
            _ => None,
        }) else {
            return problem(StatusCode::BAD_GATEWAY, "worker item missing data array");
        };
        let projected = records
            .into_iter()
            .take(2)
            .map(|record| project_record(&record, fields))
            .collect::<Result<Vec<_>, _>>();
        match projected {
            Ok(data) => normalized.push(json!({ "id": id, "data": data })),
            Err(response) => return *response,
        }
    }

    (StatusCode::OK, Json(json!({ "items": normalized }))).into_response()
}

pub(super) fn normalize_item_error(error: &Map<String, Value>) -> Value {
    match error.get("code").and_then(Value::as_str) {
        Some("target_auth" | "source.target_auth") => json!({ "code": "target_auth" }),
        Some("target_rate_limit" | "source.target_rate_limit") => {
            let mut normalized = json!({ "code": "target_rate_limit" });
            if let Some(retry_after) = error.get("retry_after_seconds").and_then(Value::as_u64) {
                normalized["retry_after_seconds"] = json!(retry_after);
            }
            normalized
        }
        _ => json!({ "code": "source_unavailable" }),
    }
}

pub(super) fn project_record(record: &Value, fields: &[String]) -> Result<Value, Box<Response>> {
    let Some(object) = record.as_object() else {
        return Err(Box::new(problem(
            StatusCode::BAD_GATEWAY,
            "worker data records must be JSON objects",
        )));
    };
    if fields.is_empty() {
        return Ok(Value::Object(object.clone()));
    }

    let mut projected = Map::new();
    for field in fields {
        if let Some(value) = object.get(field) {
            projected.insert(field.clone(), value.clone());
        }
    }
    Ok(Value::Object(projected))
}

pub(super) fn target_error_response(error: &Map<String, Value>) -> Response {
    match error.get("code").and_then(Value::as_str) {
        Some("target_rate_limit" | "source.target_rate_limit") => {
            let mut response = problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "target rate limited",
                "source.target_rate_limit",
            );
            if let Some(seconds) = error
                .get("retry_after_seconds")
                .and_then(Value::as_u64)
                .and_then(|seconds| HeaderValue::from_str(&seconds.to_string()).ok())
            {
                response.headers_mut().insert(header::RETRY_AFTER, seconds);
            }
            response
        }
        Some("target_auth" | "source.target_auth") => problem_with_code(
            StatusCode::BAD_GATEWAY,
            "target auth failed",
            "source.target_auth",
        ),
        Some("source.timeout") => problem_with_code(
            StatusCode::GATEWAY_TIMEOUT,
            "source timeout",
            "source.timeout",
        ),
        Some("source.unavailable" | "source_unavailable") => problem_with_code(
            StatusCode::BAD_GATEWAY,
            "source unavailable",
            "source.unavailable",
        ),
        _ => problem_with_code(
            StatusCode::BAD_GATEWAY,
            "source adapter execution failed",
            "source.unavailable",
        ),
    }
}
