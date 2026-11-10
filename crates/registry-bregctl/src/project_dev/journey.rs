// SPDX-License-Identifier: Apache-2.0
//! Execute the bounded HTTP journey declared by a development plan.

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::header::{HeaderMap, ETAG};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    thread,
    time::{Duration, Instant},
};

use super::{
    clock,
    issuer::Issuer,
    plan::{self, Capture, CapturedHeader, Check, Product, Step},
    RunInput,
};

const RESPONSE_LIMIT: usize = 1024 * 1024;
const JOURNEY_TRANSFER_LIMIT: usize = 8 * 1024 * 1024;
const JOURNEY_ATTEMPT_LIMIT: usize = 512;

#[derive(Serialize)]
pub(super) struct JourneyReport {
    pub id: String,
    pub result: &'static str,
    pub steps: Vec<StepReport>,
}

#[derive(Serialize)]
pub(super) struct StepReport {
    id: String,
    status: u16,
    expected_status: u16,
    result: &'static str,
}

struct ResponseData {
    status: u16,
    headers: HeaderMap,
    body: Value,
}

pub(super) fn run(
    input: &RunInput,
    issuer: &Issuer,
    urls: &BTreeMap<Product, String>,
    active: impl Fn() -> Result<()>,
) -> Result<JourneyReport> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let journey = &input.plan.journey;
    let mut report = JourneyReport {
        id: journey.id.clone(),
        result: "passed",
        steps: Vec::new(),
    };
    let mut captures = BTreeMap::<String, Value>::new();
    let mut transferred = 0usize;
    let mut attempts = 0usize;

    for step in &journey.steps {
        active()?;
        let outcome = execute_step(
            input,
            issuer,
            urls,
            step,
            &captures,
            &http,
            &runtime,
            &active,
            &mut transferred,
            &mut attempts,
        );
        let (status, passed, updates) = outcome.unwrap_or_else(|_| (0, false, BTreeMap::new()));
        if passed {
            captures.extend(updates);
        }
        report.steps.push(StepReport {
            id: step.id.clone(),
            status,
            expected_status: step.expect.status.first(),
            result: if passed { "passed" } else { "failed" },
        });
        if !passed {
            report.result = "failed";
            break;
        }
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn execute_step(
    input: &RunInput,
    issuer: &Issuer,
    urls: &BTreeMap<Product, String>,
    step: &Step,
    captures: &BTreeMap<String, Value>,
    http: &reqwest::Client,
    runtime: &tokio::runtime::Runtime,
    active: &impl Fn() -> Result<()>,
    transferred: &mut usize,
    attempts: &mut usize,
) -> Result<(u16, bool, BTreeMap<String, Value>)> {
    let lookup = |name: &str| {
        captures
            .get(name)
            .cloned()
            .context("missing journey capture")
    };
    let path = expand_text(&step.path, lookup)?;
    let mut url = request_url(&urls[&step.product], &path)?;
    let person = &input.plan.people[&step.person];
    let grant = &person.grants[&step.product];
    if step.product == Product::Breg {
        ensure!(
            !url.query_pairs().any(|(name, _)| name == "accessProfile"),
            "the plan's grant selects the BReg profile"
        );
        url.query_pairs_mut()
            .append_pair("accessProfile", &grant.profile);
    }

    let headers = step
        .headers
        .iter()
        .map(|(name, value)| Ok((name.clone(), expand_text(value, lookup)?)))
        .collect::<Result<Vec<_>>>()?;
    let json_body = step
        .body
        .as_ref()
        .map(|body| expand_json(body, lookup))
        .transpose()?;
    let raw_body = step
        .raw
        .as_ref()
        .map(|body| BASE64.decode(&body.base64))
        .transpose()?;
    let request_bytes = json_body
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()?
        .map_or_else(|| raw_body.as_ref().map_or(0, Vec::len), |body| body.len());
    let poll_deadline = step
        .poll
        .as_ref()
        .map(|poll| Instant::now() + Duration::from_millis(poll.timeout_ms));

    loop {
        active()?;
        add_attempt(attempts)?;
        add_transfer(transferred, request_bytes)?;
        let token = issuer.token(input, person, step.product, clock()? + 300)?;
        let mut request = http
            .request((&step.method).into(), url.clone())
            .bearer_auth(&*token);
        if step.product == Product::Casework {
            request = request
                .header("Registry-Casework-Profile", &grant.profile)
                .header("Registry-Review-Profile", &grant.profile);
        }
        for (name, value) in &headers {
            request = request.header(name, value);
        }
        if let Some(body) = &json_body {
            request = request.json(body);
        } else if let (Some(spec), Some(body)) = (&step.raw, &raw_body) {
            request = request
                .header(reqwest::header::CONTENT_TYPE, &spec.content_type)
                .body(body.clone());
        }
        let (response, response_bytes) = runtime.block_on(read_response(request))?;
        add_transfer(transferred, response_bytes)?;
        let captures = matches_expectation(step, &response, lookup)?
            .then(|| capture_updates(step, &response, lookup))
            .and_then(Result::ok);
        if let Some(updates) = captures {
            return Ok((response.status, true, updates));
        }
        let Some((poll, deadline)) = step.poll.as_ref().zip(poll_deadline) else {
            return Ok((response.status, false, BTreeMap::new()));
        };
        let now = Instant::now();
        if now >= deadline {
            return Ok((response.status, false, BTreeMap::new()));
        }
        thread::sleep(Duration::from_millis(poll.interval_ms).min(deadline - now));
    }
}

fn request_url(base: &str, path: &str) -> Result<url::Url> {
    ensure!(plan::valid_path(path), "invalid journey path");
    let base = url::Url::parse(base)?;
    ensure!(
        base.scheme() == "http"
            && base.username().is_empty()
            && base.password().is_none()
            && base.query().is_none()
            && base.fragment().is_none()
            && base.path() == "/"
            && matches!(base.host(), Some(url::Host::Ipv4(address)) if address.is_loopback()),
        "journey product URL is not a numeric loopback HTTP origin"
    );
    let url = base.join(path)?;
    ensure!(
        url.scheme() == base.scheme()
            && url.host() == base.host()
            && url.port_or_known_default() == base.port_or_known_default()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path().starts_with("/v1/"),
        "journey path leaves the product API"
    );
    Ok(url)
}

fn matches_expectation(
    step: &Step,
    response: &ResponseData,
    lookup: impl Fn(&str) -> Result<Value> + Copy,
) -> Result<bool> {
    if !step.expect.status.contains(response.status) {
        return Ok(false);
    }
    for (pointer, expected) in &step.expect.json {
        if response.body.pointer(pointer) != Some(&expand_json(expected, lookup)?) {
            return Ok(false);
        }
    }
    if let Some(code) = &step.expect.code {
        if response.body.pointer("/code").and_then(Value::as_str)
            != Some(expand_text(code, lookup)?.as_str())
        {
            return Ok(false);
        }
    }
    for check in &step.expect.checks {
        if !matches_check(check, &response.body, lookup)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn matches_check(
    check: &Check,
    body: &Value,
    lookup: impl Fn(&str) -> Result<Value> + Copy,
) -> Result<bool> {
    let Some(actual) = body.pointer(&check.pointer) else {
        return Ok(false);
    };
    if let Some(expected) = &check.equals {
        return Ok(actual == &expand_json(expected, lookup)?);
    }
    if let Some(expected) = check.length {
        let length = match actual {
            Value::Array(value) => value.len(),
            Value::Object(value) => value.len(),
            Value::String(value) => value.chars().count(),
            _ => return Ok(false),
        };
        return Ok(length == expected);
    }
    if let Some(expected) = &check.contains {
        let expected = expand_json(expected, lookup)?;
        return Ok(match (actual, expected) {
            (Value::Array(values), expected) => values.contains(&expected),
            (Value::String(value), Value::String(expected)) => value.contains(&expected),
            (Value::Object(values), Value::String(expected)) => values.contains_key(&expected),
            _ => false,
        });
    }
    Ok(false)
}

fn capture_updates(
    step: &Step,
    response: &ResponseData,
    lookup: impl Fn(&str) -> Result<Value> + Copy,
) -> Result<BTreeMap<String, Value>> {
    step.capture
        .iter()
        .map(|(name, capture)| {
            Ok((
                name.clone(),
                scalar_capture(capture_value(capture, response, lookup)?)?,
            ))
        })
        .collect()
}

fn capture_value(
    capture: &Capture,
    response: &ResponseData,
    lookup: impl Fn(&str) -> Result<Value> + Copy,
) -> Result<Value> {
    match capture {
        Capture::Pointer { pointer } => response
            .body
            .pointer(pointer)
            .cloned()
            .context("journey capture pointer was not present"),
        Capture::Header { header } => match header {
            CapturedHeader::Etag => Ok(Value::String(
                response
                    .headers
                    .get(ETAG)
                    .context("journey response had no ETag")?
                    .to_str()
                    .context("journey response ETag was not text")?
                    .to_owned(),
            )),
        },
        Capture::Value { pointer, query } => {
            let value = response
                .body
                .pointer(pointer)
                .cloned()
                .context("journey capture pointer was not present")?;
            if let Some(query) = query {
                let text = value
                    .as_str()
                    .context("journey query capture did not select text")?;
                let url = url::Url::parse(text)
                    .or_else(|_| url::Url::parse("http://127.0.0.1/")?.join(text))?;
                let value = url
                    .query_pairs()
                    .find_map(|(name, value)| (name == query.as_str()).then(|| value.into_owned()))
                    .context("journey capture query parameter was not present")?;
                Ok(Value::String(value))
            } else {
                Ok(value)
            }
        }
        Capture::Find {
            find,
            r#where,
            pointer,
        } => {
            let expected = expand_json(&r#where.equals, lookup)?;
            let items = response
                .body
                .pointer(find)
                .and_then(Value::as_array)
                .context("journey find capture did not select an array")?;
            let mut matches = items
                .iter()
                .filter(|item| item.pointer(&r#where.pointer) == Some(&expected));
            let item = matches
                .next()
                .context("journey find capture found no item")?;
            ensure!(
                matches.next().is_none(),
                "journey find capture matched more than one item"
            );
            item.pointer(pointer)
                .cloned()
                .context("journey find capture pointer was not present")
        }
    }
}

fn scalar_capture(value: Value) -> Result<Value> {
    ensure!(
        matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
            && serde_json::to_vec(&value).is_ok_and(|bytes| bytes.len() <= 4096),
        "journey captures must be bounded scalar values"
    );
    Ok(value)
}

fn expand_json(value: &Value, lookup: impl Fn(&str) -> Result<Value> + Copy) -> Result<Value> {
    match value {
        Value::String(value) => {
            if let Some(name) = exact_reference(value) {
                lookup(name)
            } else {
                Ok(Value::String(expand_text(value, lookup)?))
            }
        }
        Value::Array(values) => values
            .iter()
            .map(|value| expand_json(value, lookup))
            .collect(),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), expand_json(value, lookup)?)))
            .collect(),
        value => Ok(value.clone()),
    }
}

fn expand_text(value: &str, lookup: impl Fn(&str) -> Result<Value> + Copy) -> Result<String> {
    plan::expand(value, |name| scalar_text(&lookup(name)?))
}

fn exact_reference(value: &str) -> Option<&str> {
    let name = value.strip_prefix("{{")?.strip_suffix("}}")?;
    (!name.is_empty() && !name.contains(['{', '}'])).then_some(name)
}

fn scalar_text(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => anyhow::bail!("journey interpolation requires a scalar capture"),
    }
}

fn add_transfer(transferred: &mut usize, bytes: usize) -> Result<()> {
    *transferred = transferred
        .checked_add(bytes)
        .context("journey transfer bound overflowed")?;
    ensure!(
        *transferred <= JOURNEY_TRANSFER_LIMIT,
        "journey transferred too much data"
    );
    Ok(())
}

fn add_attempt(attempts: &mut usize) -> Result<()> {
    *attempts = attempts
        .checked_add(1)
        .context("journey attempt bound overflowed")?;
    ensure!(
        *attempts <= JOURNEY_ATTEMPT_LIMIT,
        "journey made too many requests"
    );
    Ok(())
}

async fn read_response(request: reqwest::RequestBuilder) -> Result<(ResponseData, usize)> {
    let mut response = request.send().await?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= RESPONSE_LIMIT,
            "journey response is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let length = bytes.len();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((
        ResponseData {
            status,
            headers,
            body,
        },
        length,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_dev::plan::ExpectedStatus;
    use serde_json::json;

    fn no_capture(_: &str) -> Result<Value> {
        anyhow::bail!("unexpected capture")
    }

    #[test]
    fn exact_capture_reference_preserves_scalar_type() {
        let captures = BTreeMap::from([("revision", json!(7))]);
        let expanded = expand_json(
            &json!({
                "revision": "{{revision}}", "label": "revision-{{revision}}"
            }),
            |name| Ok(captures[name].clone()),
        )
        .unwrap();
        assert_eq!(expanded, json!({"revision": 7, "label": "revision-7"}));
    }

    #[test]
    fn request_url_stays_on_the_numeric_loopback_v1_origin() {
        let url = request_url("http://127.0.0.1:31415/", "/v1/records?id=one").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:31415/v1/records?id=one");
        assert!(request_url("http://localhost:31415/", "/v1/records").is_err());
        assert!(request_url("http://127.0.0.1:31415/", "/v1/../admin").is_err());
    }

    #[test]
    fn checks_compare_typed_values_lengths_and_membership() {
        let body = json!({"state": true, "items": [1, 2], "label": "ready-now"});
        for check in [
            Check {
                pointer: "/state".into(),
                equals: Some(json!(true)),
                length: None,
                contains: None,
            },
            Check {
                pointer: "/items".into(),
                equals: None,
                length: Some(2),
                contains: None,
            },
            Check {
                pointer: "/items".into(),
                equals: None,
                length: None,
                contains: Some(json!(2)),
            },
            Check {
                pointer: "/label".into(),
                equals: None,
                length: None,
                contains: Some(json!("now")),
            },
        ] {
            assert!(matches_check(&check, &body, no_capture).unwrap());
        }
    }

    #[test]
    fn expectation_accepts_any_declared_status_and_problem_code() {
        let step: Step = serde_json::from_value(json!({
            "id": "read", "product": "breg", "as": "person", "method": "GET",
            "path": "/v1/records", "expect": {"status": [404, 409], "code": "missing"}
        }))
        .unwrap();
        let response = ResponseData {
            status: 409,
            headers: HeaderMap::new(),
            body: json!({"code": "missing"}),
        };
        assert!(matches_expectation(&step, &response, no_capture).unwrap());
        assert_eq!(step.expect.status.first(), 404);
    }

    #[test]
    fn find_capture_requires_one_matching_item() {
        let capture: Capture = serde_json::from_value(json!({
            "type": "find",
            "find": "/items", "where": {"pointer": "/id", "equals": "two"},
            "pointer": "/revision"
        }))
        .unwrap();
        let response = ResponseData {
            status: 200,
            headers: HeaderMap::new(),
            body: json!({"items": [
                {"id": "one", "revision": 1}, {"id": "two", "revision": 2}
            ]}),
        };
        assert_eq!(
            capture_value(&capture, &response, no_capture).unwrap(),
            json!(2)
        );
    }

    #[test]
    fn expected_status_helpers_keep_the_first_for_reports() {
        let status: ExpectedStatus = serde_json::from_value(json!([202, 200])).unwrap();
        assert_eq!(status.first(), 202);
        assert!(status.contains(200));
        assert_eq!(serde_json::to_value(&status).unwrap(), json!([202, 200]));
    }

    #[test]
    fn total_request_work_is_bounded_across_steps() {
        let mut attempts = 0;
        for _ in 0..JOURNEY_ATTEMPT_LIMIT {
            add_attempt(&mut attempts).unwrap();
        }
        assert!(add_attempt(&mut attempts).is_err());
    }
}
