// SPDX-License-Identifier: Apache-2.0
//! Shared HTTP request parsing and content-negotiation helpers.

use super::*;

pub(super) fn negotiate_request_format(
    evidence: &EvidenceConfig,
    headers: &HeaderMap,
    body_format: Option<&str>,
) -> Result<String, EvidenceError> {
    let supported = RegistryNotaryRuntime::list_formats(evidence)
        .into_iter()
        .filter(|format| format.status == "enabled")
        .map(|format| format.id)
        .collect::<Vec<_>>();
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    if let Some(format) = body_format.filter(|format| !format.trim().is_empty()) {
        if accept_permits(accept, format) {
            return Ok(format.to_string());
        }
        return Err(EvidenceError::FormatUnsupported);
    }
    match accept {
        None => Ok(FORMAT_CLAIM_RESULT_JSON.to_string()),
        Some(value) if accept_is_default(value) => Ok(FORMAT_CLAIM_RESULT_JSON.to_string()),
        Some(value) => {
            accept_preferred_format(value, &supported).ok_or(EvidenceError::FormatUnsupported)
        }
    }
}

pub(super) fn accept_is_default(value: &str) -> bool {
    accept_entries(value)
        .into_iter()
        .find(|entry| entry.q > 0.0)
        .is_some_and(|entry| entry.media_range == "*/*" || entry.media_range.trim().is_empty())
}

pub(super) fn accept_permits(accept: Option<&str>, format: &str) -> bool {
    let Some(accept) = accept else {
        return true;
    };
    accept_entries(accept)
        .into_iter()
        .any(|entry| entry.q > 0.0 && media_range_matches(&entry.media_range, format))
}

pub(super) fn accept_preferred_format(accept: &str, supported: &[String]) -> Option<String> {
    accept_entries(accept).into_iter().find_map(|entry| {
        if entry.q <= 0.0 {
            return None;
        }
        supported
            .iter()
            .find(|format| media_range_matches(&entry.media_range, format))
            .cloned()
    })
}

#[derive(Debug)]
pub(super) struct AcceptEntry {
    pub(super) media_range: String,
    pub(super) q: f32,
    pub(super) order: usize,
}

pub(super) fn accept_entries(accept: &str) -> Vec<AcceptEntry> {
    let mut entries = accept
        .split(',')
        .enumerate()
        .filter_map(|(order, part)| {
            let mut segments = part.split(';').map(str::trim);
            let media_type = segments.next()?.to_ascii_lowercase();
            let mut params = Vec::new();
            let mut q = 1.0;
            for segment in segments {
                if let Some(raw_q) = segment.strip_prefix("q=") {
                    q = raw_q.parse::<f32>().unwrap_or(0.0);
                } else if !segment.is_empty() {
                    params.push(segment.to_ascii_lowercase());
                }
            }
            let suffix = if params.is_empty() {
                String::new()
            } else {
                format!("; {}", params.join("; "))
            };
            Some(AcceptEntry {
                media_range: format!("{media_type}{suffix}"),
                q,
                order,
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .q
            .partial_cmp(&left.q)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.order.cmp(&right.order))
    });
    entries
}

pub(super) fn media_range_matches(range: &str, format: &str) -> bool {
    let format = format.to_ascii_lowercase();
    if range == "*/*" || range == format {
        return true;
    }
    range
        .strip_suffix("/*")
        .and_then(|prefix| format.split_once('/').map(|(kind, _)| (prefix, kind)))
        .is_some_and(|(prefix, kind)| prefix == kind)
}

pub(super) fn purpose_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(DATA_PURPOSE_HEADER)
        .and_then(|value| value.to_str().ok())
}

pub(super) fn parse_json_body<T>(
    request: Result<Json<T>, JsonRejection>,
) -> Result<T, EvidenceError> {
    request
        .map(|Json(request)| request)
        .map_err(|_| EvidenceError::InvalidRequest)
}

pub(super) fn resolved_evaluate_audit_purposes(
    header_purpose: Option<&str>,
    body_purpose: Option<&str>,
) -> Option<Vec<String>> {
    match (header_purpose, body_purpose) {
        (Some(header), Some(body)) if header != body => None,
        (Some(header), _) if !header.trim().is_empty() => Some(vec![header.to_string()]),
        (_, Some(body)) if !body.trim().is_empty() => Some(vec![body.to_string()]),
        _ => None,
    }
}

pub(super) fn resolved_batch_audit_purposes(
    header_purpose: Option<&str>,
    body_purpose: Option<&str>,
    subjects: &[BatchEvaluateItemRequest],
) -> Option<Vec<String>> {
    let default = match (header_purpose, body_purpose) {
        (Some(header), Some(body)) if header != body => return None,
        (Some(header), _) if !header.trim().is_empty() => Some(header),
        (_, Some(body)) if !body.trim().is_empty() => Some(body),
        (Some(_), _) | (_, Some(_)) => return None,
        _ => None,
    };
    subjects
        .iter()
        .map(|subject| match subject.purpose.as_deref() {
            Some(purpose) if !purpose.trim().is_empty() => Some(purpose.to_string()),
            Some(_) => None,
            None => default.map(str::to_string),
        })
        .collect()
}

pub(super) fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
}

pub(super) fn has_idempotency_key(headers: &HeaderMap) -> bool {
    headers.contains_key(IDEMPOTENCY_KEY_HEADER)
}
