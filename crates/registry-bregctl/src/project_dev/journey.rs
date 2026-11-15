// SPDX-License-Identifier: Apache-2.0
//! Execute the bounded HTTP journey declared by a development plan.

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use registry_platform_httpsec::{response_trace_id, ProblemDocument, TraceId};
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
    plan::{self, Capture, CapturedHeader, Check, Journey, Product, Step},
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
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<FailureMetadata>,
}

// Public response metadata is diagnostic only, never an expectation or grant.
const PROBLEM_LIMIT: usize = 16 * 1024;

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    KnownProblem,
    UnknownProblem,
    InvalidProblem,
    NonProblem,
    Unavailable,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum HttpClass {
    ClientError,
    ServerError,
}

#[derive(Clone, Serialize)]
struct FailureMetadata {
    kind: FailureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_class: Option<HttpClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<TraceId>,
}

impl FailureMetadata {
    fn new(kind: FailureKind, status: u16) -> Self {
        Self {
            kind,
            code: None,
            http_class: match status {
                400..=499 => Some(HttpClass::ClientError),
                500..=599 => Some(HttpClass::ServerError),
                _ => None,
            },
            trace_id: None,
        }
    }
}

fn known_problem_code(product: Product, problem: &ProblemDocument) -> Option<&'static str> {
    match product {
        Product::Breg => registry_breg::problem::ProblemCode::ALL
            .iter()
            .find(|known| {
                known.code() == problem.code
                    && known.status() == problem.status
                    && registry_breg::problem::type_uri(known.code()) == problem.type_uri
            })
            .map(|known| known.code()),
        Product::Casework => {
            // Consume the existing public generated catalog, not the runtime crate
            // or a second hand-maintained code vocabulary. Only its fixed consts
            // can enter a receipt; incoming strings are never returned.
            static CATALOG: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
            let catalog = CATALOG.get_or_init(|| {
                serde_json::from_str(include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../products/casework/generated/registry-casework.openapi.json"
                )))
                .unwrap_or(Value::Null)
            });
            catalog
                .pointer("/components/schemas")?
                .as_object()?
                .values()
                .filter_map(|schema| schema.get("allOf")?.as_array())
                .flatten()
                .filter_map(|part| part.get("properties"))
                .find_map(|properties| {
                    let code = properties.pointer("/code/const")?.as_str()?;
                    (code == problem.code
                        && properties.pointer("/status/const")?.as_u64()?
                            == u64::from(problem.status)
                        && properties.pointer("/type/const")?.as_str()? == problem.type_uri)
                        .then_some(code)
                })
        }
    }
}

fn failure_metadata(
    product: Product,
    status: u16,
    headers: &HeaderMap,
    bytes: &[u8],
) -> FailureMetadata {
    // This smaller diagnostic budget never changes the transport/body budget.
    if bytes.len() > PROBLEM_LIMIT {
        return FailureMetadata::new(FailureKind::Unavailable, status);
    }
    let mut content_types = headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    let is_problem = match (content_types.next(), content_types.next()) {
        (Some(value), None) => value.to_str().ok().is_some_and(|value| {
            value.split(';').next().is_some_and(|media| {
                media
                    .trim()
                    .eq_ignore_ascii_case("application/problem+json")
            })
        }),
        _ => false,
    };
    if !is_problem {
        return FailureMetadata::new(FailureKind::NonProblem, status);
    }
    let Ok(problem) = ProblemDocument::parse_exact(bytes, PROBLEM_LIMIT) else {
        return FailureMetadata::new(FailureKind::InvalidProblem, status);
    };
    if problem.status != status {
        return FailureMetadata::new(FailureKind::InvalidProblem, status);
    }
    let Some(code) = known_problem_code(product, &problem) else {
        return FailureMetadata::new(FailureKind::UnknownProblem, status);
    };
    let trace_id = response_trace_id(headers)
        .ok()
        .filter(|trace| *trace == problem.trace_id);
    FailureMetadata {
        code: Some(code),
        trace_id,
        ..FailureMetadata::new(FailureKind::KnownProblem, status)
    }
}

const REASON_LIMIT: usize = 512;

fn bounded_reason(text: &str) -> String {
    text.chars().take(REASON_LIMIT).collect()
}

/// What one step observed. `reason` is set when the step failed.
struct StepOutcome {
    status: u16,
    reason: Option<String>,
    updates: BTreeMap<String, Value>,
    failure: Option<FailureMetadata>,
}

struct ResponseData {
    status: u16,
    headers: HeaderMap,
    body: Value,
    failure: Option<FailureMetadata>,
}

pub(super) fn run(
    input: &RunInput,
    issuer: &Issuer,
    urls: &BTreeMap<Product, String>,
    journey: &Journey,
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
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                // A stop signal or the startup deadline interrupts the
                // journey; it is not a failure of this step.
                active()?;
                StepOutcome {
                    status: 0,
                    reason: Some(bounded_reason(&format!("{error:#}"))),
                    updates: BTreeMap::new(),
                    failure: None,
                }
            }
        };
        let passed = outcome.reason.is_none();
        if passed {
            captures.extend(outcome.updates);
        }
        report.steps.push(StepReport {
            id: step.id.clone(),
            status: outcome.status,
            expected_status: step.expect.status.first(),
            result: if passed { "passed" } else { "failed" },
            reason: outcome.reason,
            failure: outcome.failure,
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
) -> Result<StepOutcome> {
    let lookup = |name: &str| {
        if name == "run.issuer" {
            Ok(Value::String(input.plan.issuer.clone()))
        } else {
            captures
                .get(name)
                .cloned()
                .context("missing journey capture")
        }
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
    let mut last_status = 0;
    let mut last_reason = None;
    let mut last_failure = None;

    loop {
        active()?;
        if poll_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(poll_timed_out(last_status, last_reason, last_failure));
        }
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
        let Some(response) = read_response_before_deadline(
            runtime,
            request,
            poll_deadline,
            transferred,
            step.product,
        )?
        else {
            return Ok(poll_timed_out(last_status, last_reason, last_failure));
        };
        last_status = response.status;
        let reason = match first_mismatch(step, &response, lookup)? {
            Some(reason) => reason,
            None => match capture_updates(step, &response, lookup) {
                Ok(updates) => {
                    return Ok(StepOutcome {
                        status: response.status,
                        reason: None,
                        updates,
                        failure: None,
                    })
                }
                Err(error) => format!("capture failed: {error:#}"),
            },
        };
        let failed = |reason: &str| StepOutcome {
            status: response.status,
            reason: Some(bounded_reason(reason)),
            updates: BTreeMap::new(),
            failure: response.failure.clone(),
        };
        let Some((poll, deadline)) = step.poll.as_ref().zip(poll_deadline) else {
            return Ok(failed(&reason));
        };
        let now = Instant::now();
        if now >= deadline {
            return Ok(failed(&reason));
        }
        last_reason = Some(reason);
        last_failure = response.failure;
        thread::sleep(Duration::from_millis(poll.interval_ms).min(deadline - now));
    }
}

/// A poll whose deadline passed keeps the last completed status and says why
/// that response did not match.
fn poll_timed_out(
    status: u16,
    last_reason: Option<String>,
    failure: Option<FailureMetadata>,
) -> StepOutcome {
    let reason = match last_reason {
        Some(reason) => format!("poll deadline passed; last response: {reason}"),
        None => "poll deadline passed before a response arrived".to_owned(),
    };
    StepOutcome {
        status,
        reason: Some(bounded_reason(&reason)),
        updates: BTreeMap::new(),
        failure,
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

/// Describe the first expectation the response misses, as
/// `<pointer> expected <json> observed <json>`.
fn first_mismatch(
    step: &Step,
    response: &ResponseData,
    lookup: impl Fn(&str) -> Result<Value> + Copy,
) -> Result<Option<String>> {
    let observed_at = |pointer: &str| {
        response
            .body
            .pointer(pointer)
            .map_or_else(|| "nothing".to_owned(), Value::to_string)
    };
    if !step.expect.status.contains(response.status) {
        return Ok(Some(format!(
            "/status expected {} observed {}",
            serde_json::to_string(&step.expect.status)?,
            response.status
        )));
    }
    for (pointer, expected) in &step.expect.json {
        let expected = expand_json(expected, lookup)?;
        if response.body.pointer(pointer) != Some(&expected) {
            return Ok(Some(format!(
                "{pointer} expected {expected} observed {}",
                observed_at(pointer)
            )));
        }
    }
    if let Some(code) = &step.expect.code {
        let expected = expand_text(code, lookup)?;
        if response.body.pointer("/code").and_then(Value::as_str) != Some(expected.as_str()) {
            return Ok(Some(format!(
                "/code expected {} observed {}",
                Value::String(expected),
                observed_at("/code")
            )));
        }
    }
    for check in &step.expect.checks {
        if !matches_check(check, &response.body, lookup)? {
            return Ok(Some(format!(
                "{} expected {} observed {}",
                check.pointer,
                describe_check(check, lookup)?,
                observed_at(&check.pointer)
            )));
        }
    }
    Ok(None)
}

fn describe_check(check: &Check, lookup: impl Fn(&str) -> Result<Value> + Copy) -> Result<String> {
    Ok(if let Some(expected) = &check.equals {
        expand_json(expected, lookup)?.to_string()
    } else if let Some(length) = check.length {
        format!("length {length}")
    } else if let Some(expected) = &check.contains {
        format!("containing {}", expand_json(expected, lookup)?)
    } else {
        "a check".to_owned()
    })
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

fn read_response_before_deadline(
    runtime: &tokio::runtime::Runtime,
    request: reqwest::RequestBuilder,
    deadline: Option<Instant>,
    transferred: &mut usize,
    product: Product,
) -> Result<Option<ResponseData>> {
    let response = read_response(request, transferred, product);
    let Some(deadline) = deadline else {
        return runtime.block_on(response).map(Some);
    };
    if Instant::now() >= deadline {
        return Ok(None);
    }
    let timeout = tokio::time::Instant::from_std(deadline);
    match runtime.block_on(async { tokio::time::timeout_at(timeout, response).await }) {
        Ok(response) if Instant::now() < deadline => response.map(Some),
        Ok(_) => Ok(None),
        Err(_) => Ok(None),
    }
}

async fn read_response(
    request: reqwest::RequestBuilder,
    transferred: &mut usize,
    product: Product,
) -> Result<ResponseData> {
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
        add_transfer(transferred, chunk.len())?;
    }
    let failure = Some(failure_metadata(product, status, &headers, &bytes));
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok(ResponseData {
        status,
        headers,
        body,
        failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_dev::plan::ExpectedStatus;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, TcpListener, TcpStream},
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    static POLL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn no_capture(_: &str) -> Result<Value> {
        anyhow::bail!("unexpected capture")
    }

    struct SyntheticServer {
        url: String,
        requests: Arc<AtomicUsize>,
        thread: thread::JoinHandle<()>,
    }

    impl SyntheticServer {
        fn finish(self) -> usize {
            self.thread.join().unwrap();
            self.requests.load(Ordering::SeqCst)
        }
    }

    /// How long a synthetic server accepts requests. A journey run spends a few
    /// hundred milliseconds before its first request, so the poll budgets below
    /// leave room for a busy machine.
    const SERVER_WINDOW: Duration = Duration::from_secs(2);

    fn synthetic_server(responses: Vec<(Duration, u16, &'static str)>) -> SyntheticServer {
        synthetic_server_with_headers(responses, "application/json", "")
    }

    fn synthetic_server_with_headers(
        responses: Vec<(Duration, u16, &'static str)>,
        media: &'static str,
        extra: &'static str,
    ) -> SyntheticServer {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let thread = thread::spawn(move || {
            let end = Instant::now() + SERVER_WINDOW;
            let mut response = 0;
            while Instant::now() < end {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        observed.fetch_add(1, Ordering::SeqCst);
                        stream.set_nonblocking(false).unwrap();
                        read_request(&mut stream);
                        let &(delay, status, body) = responses
                            .get(response)
                            .unwrap_or_else(|| responses.last().unwrap());
                        response += 1;
                        let reason = if status == 200 { "OK" } else { "Accepted" };
                        let headers = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: {media}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        if write_to_client(&mut stream, headers.as_bytes()) {
                            thread::sleep(delay);
                            write_to_client(&mut stream, body.as_bytes());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("synthetic server accept failed: {error}"),
                }
            }
        });
        SyntheticServer {
            url,
            requests,
            thread,
        }
    }

    fn read_request(stream: &mut TcpStream) -> (bool, bool) {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 2048];
        while request.len() < 16 * 1024 && !request.windows(4).any(|part| part == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(length) => request.extend_from_slice(&chunk[..length]),
            }
        }
        assert!(request.windows(4).any(|part| part == b"\r\n\r\n"));
        // Return only fixed observations, never a header/token dump on failure.
        (
            request.starts_with(b"GET /v1/result?accessProfile=reader "),
            request
                .windows(b"authorization: Bearer ".len())
                .any(|part| part == b"authorization: Bearer "),
        )
    }

    fn write_to_client(stream: &mut TcpStream, bytes: &[u8]) -> bool {
        match stream.write_all(bytes) {
            Ok(()) => true,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                false
            }
            Err(error) => panic!("synthetic server write failed: {error}"),
        }
    }

    fn polling_input(maximum_wait: u64, interval: u64) -> RunInput {
        let plan = serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "products": [{"product": "breg", "project": ".", "audience": "registry"}],
            "people": {"reader": {
                "subject": "reader", "client": "reader-client",
                "grants": {"breg": {"profile": "reader", "scopes": ["registry:read"]}}
            }},
            "journey": {"id": "poll", "steps": [{
                "id": "wait", "product": "breg", "as": "reader", "method": "GET",
                "path": "/v1/result", "expect": {"status": 200, "json": {"/state": "ready"}},
                "poll": {
                    "maximumWaitMilliseconds": maximum_wait,
                    "pollIntervalMilliseconds": interval
                }
            }]}
        }))
        .unwrap();
        RunInput {
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            project: PathBuf::from("/tmp/project"),
            application_root: None,
            application_node: None,
            plan,
            scenarios: Vec::new(),
            scenario_digest: None,
            ttl_seconds: 300,
            schema_people: Vec::new(),
            breg_authority: Some(super::super::BregAuthority {
                principal: "sub".to_owned(),
                purpose: false,
                requires_postgis: false,
                encrypts_fields: false,
                named_clients: Default::default(),
            }),
            casework_principals: BTreeMap::new(),
            casework_source_digest: None,
            binaries: BTreeMap::new(),
        }
    }

    #[test]
    fn separate_scenario_runs_do_not_share_captures() {
        let server = synthetic_server(vec![(Duration::ZERO, 200, r#"{"id":"record-1"}"#)]);
        let root = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(root.path()).unwrap();
        let input = polling_input(1000, 50);
        let urls = BTreeMap::from([(Product::Breg, server.url.clone())]);
        let first: Journey = serde_json::from_value(json!({
            "id": "first", "steps": [{
                "id": "capture", "product": "breg", "as": "reader", "method": "GET",
                "path": "/v1/records", "expect": {"status": 200},
                "capture": {"record": {"type": "pointer", "pointer": "/id"}}
            }]
        }))
        .unwrap();
        // Plan validation refuses this reference. Execute it directly to prove
        // that a later run cannot inherit the earlier run's captured value.
        let second: Journey = serde_json::from_value(json!({
            "id": "second", "steps": [{
                "id": "use", "product": "breg", "as": "reader", "method": "GET",
                "path": "/v1/records/{{record}}", "expect": {"status": 200}
            }]
        }))
        .unwrap();

        let first_report = run(&input, &issuer, &urls, &first, || Ok(())).unwrap();
        let second_report = run(&input, &issuer, &urls, &second, || Ok(())).unwrap();

        assert_eq!(first_report.result, "passed");
        assert_eq!(second_report.result, "failed");
        assert!(second_report.steps[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("missing journey capture")));
        assert_eq!(server.finish(), 1);
    }

    #[test]
    fn poll_refuses_a_matching_response_that_finishes_after_its_deadline() {
        let _lock = POLL_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let server = synthetic_server(vec![
            (Duration::ZERO, 202, r#"{"state":"waiting"}"#),
            (Duration::from_millis(1500), 200, r#"{"state":"ready"}"#),
        ]);
        let root = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(root.path()).unwrap();
        let input = polling_input(1000, 50);
        let urls = BTreeMap::from([(Product::Breg, server.url.clone())]);

        let report = run(
            &input,
            &issuer,
            &urls,
            input.plan.journey.as_ref().unwrap(),
            || Ok(()),
        )
        .unwrap();

        assert_eq!(report.result, "failed");
        assert_eq!(report.steps[0].status, 202);
        assert!(report.steps[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("poll deadline passed; last response: ")));
        assert_eq!(server.finish(), 2);
    }

    #[test]
    fn poll_starts_no_retry_after_its_deadline() {
        let _lock = POLL_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let server = synthetic_server(vec![(Duration::ZERO, 202, r#"{"state":"waiting"}"#)]);
        let root = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(root.path()).unwrap();
        let input = polling_input(1000, 1000);
        let urls = BTreeMap::from([(Product::Breg, server.url.clone())]);

        let report = run(
            &input,
            &issuer,
            &urls,
            input.plan.journey.as_ref().unwrap(),
            || Ok(()),
        )
        .unwrap();

        assert_eq!(report.result, "failed");
        assert_eq!(report.steps[0].status, 202);
        assert!(report.steps[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("poll deadline passed; last response: ")));
        assert_eq!(server.finish(), 1);
    }

    #[test]
    fn poll_sends_nothing_with_zero_remaining_budget() {
        let _lock = POLL_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let server = synthetic_server(vec![(Duration::ZERO, 200, r#"{"state":"ready"}"#)]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let request = reqwest::Client::new().get(format!("{}v1/result", server.url));
        let mut transferred = 0;

        let response = read_response_before_deadline(
            &runtime,
            request,
            Some(Instant::now()),
            &mut transferred,
            Product::Breg,
        )
        .unwrap();

        assert!(response.is_none());
        assert_eq!(transferred, 0);
        assert_eq!(server.finish(), 0);
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
            failure: None,
            body: json!({"code": "missing"}),
        };
        assert!(first_mismatch(&step, &response, no_capture)
            .unwrap()
            .is_none());
        assert_eq!(step.expect.status.first(), 404);
    }

    #[test]
    fn mismatch_names_the_pointer_expected_and_observed_values() {
        let step: Step = serde_json::from_value(json!({
            "id": "read", "product": "breg", "as": "person", "method": "GET",
            "path": "/v1/records", "expect": {"status": 200, "json": {"/state": "open"}}
        }))
        .unwrap();
        let mut response = ResponseData {
            status: 500,
            headers: HeaderMap::new(),
            failure: None,
            body: json!({"state": "closed"}),
        };
        assert_eq!(
            first_mismatch(&step, &response, no_capture)
                .unwrap()
                .unwrap(),
            "/status expected 200 observed 500"
        );
        response.status = 200;
        assert_eq!(
            first_mismatch(&step, &response, no_capture)
                .unwrap()
                .unwrap(),
            "/state expected \"open\" observed \"closed\""
        );
        response.body = json!({"state": "open"});
        assert!(first_mismatch(&step, &response, no_capture)
            .unwrap()
            .is_none());
    }

    #[test]
    fn failure_receipt_public_http_status_mismatch_keeps_known_problem() {
        // A public neutral problem, unrelated to any retained private scenario.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (selected_profile, bearer_present) = read_request(&mut stream);
            assert!(selected_profile && bearer_present);
            let body = r#"{"type":"https://id.registrystack.org/problems/registry-breg/request/invalid","title":"Invalid request","status":400,"detail":"synthetic ignored detail","code":"request.invalid","traceId":"11111111111111111111111111111111"}"#;
            let response = format!("HTTP/1.1 400 Result\r\nContent-Type: application/problem+json\r\ntraceparent: 00-11111111111111111111111111111111-2222222222222222-01\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            write_to_client(&mut stream, response.as_bytes());
        });
        let root = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(root.path()).unwrap();
        let mut input = polling_input(1000, 50);
        input.plan.journey.as_mut().unwrap().steps[0].poll = None;
        input.plan.journey.as_mut().unwrap().steps[0].expect.status =
            serde_json::from_value(json!(404)).unwrap();
        let report = run(
            &input,
            &issuer,
            &BTreeMap::from([(Product::Breg, url)]),
            input.plan.journey.as_ref().unwrap(),
            || Ok(()),
        )
        .unwrap();
        server.join().unwrap();
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["result"], "failed");
        assert_eq!(value["steps"][0]["status"], 400);
        assert_eq!(value["steps"][0]["expected_status"], 404);
        assert_eq!(
            value["steps"][0]["reason"],
            "/status expected 404 observed 400"
        );
        assert_eq!(value["steps"][0]["failure"]["code"], "request.invalid");
        assert_eq!(
            value["steps"][0]["failure"]["trace_id"],
            "11111111111111111111111111111111"
        );
    }

    fn public_problem() -> Value {
        json!({
            "type": "https://id.registrystack.org/problems/registry-breg/request/invalid",
            "title": "ignored", "detail": "ignored", "status": 400,
            "code": "request.invalid", "traceId": "11111111111111111111111111111111"
        })
    }

    fn problem_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/problem+json".parse().unwrap(),
        );
        headers.insert(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01"
                .parse()
                .unwrap(),
        );
        headers
    }

    fn projection(body: &[u8], headers: &HeaderMap) -> Value {
        serde_json::to_value(failure_metadata(Product::Breg, 400, headers, body)).unwrap()
    }

    #[test]
    fn failure_receipt_retains_only_closed_fields_not_short_canaries_or_forged_codes() {
        for canary in ["x", "sub", "secret42", "request.secret42"] {
            let mut body = public_problem();
            body["title"] = json!(canary);
            body["detail"] = json!(canary);
            body["fieldPath"] = json!(canary);
            body["class"] = json!(canary);
            body["schema"] = json!(canary);
            body["extension"] = json!({"token": canary});
            let result = projection(&serde_json::to_vec(&body).unwrap(), &problem_headers());
            assert_eq!(
                result,
                json!({"kind":"known_problem", "code":"request.invalid", "http_class":"client_error", "trace_id":"11111111111111111111111111111111"})
            );
            body["code"] = json!(format!("request.{canary}"));
            assert_eq!(
                projection(&serde_json::to_vec(&body).unwrap(), &problem_headers()),
                json!({"kind":"unknown_problem", "http_class":"client_error"})
            );
        }
    }

    #[test]
    fn failure_receipt_rejects_malformed_duplicates_unknown_types_and_status_bindings() {
        let headers = problem_headers();
        for bytes in [
            b"{".as_slice(),
            b"[]",
            b"null",
            b"",
            br#"{"code":"request.invalid","code":"secret42"}"#,
        ] {
            assert_eq!(
                projection(bytes, &headers),
                json!({"kind":"invalid_problem", "http_class":"client_error"})
            );
        }
        let body = serde_json::to_string(&public_problem()).unwrap();
        for member in [
            r#""code":"secret42""#,
            r#""extension":"secret42","extension":"secret42""#,
        ] {
            let duplicate = format!("{{{member},{}", &body[1..]);
            assert_eq!(
                projection(duplicate.as_bytes(), &headers),
                json!({"kind":"invalid_problem", "http_class":"client_error"})
            );
        }
        for (member, value, kind) in [
            ("code", json!("request.invalid.secret42"), "unknown_problem"),
            (
                "type",
                json!("https://secret.example.invalid/request/invalid"),
                "unknown_problem",
            ),
            ("status", json!(404), "invalid_problem"),
            ("code", json!("resource.not_found"), "unknown_problem"),
        ] {
            let mut body = public_problem();
            body[member] = value;
            assert_eq!(
                projection(&serde_json::to_vec(&body).unwrap(), &headers),
                json!({"kind":kind, "http_class":"client_error"})
            );
        }
    }

    #[test]
    fn failure_receipt_trace_requires_valid_body_and_exactly_one_matching_header() {
        let bytes = serde_json::to_vec(&public_problem()).unwrap();
        for header in [
            None,
            Some("secret42"),
            Some("00-00000000000000000000000000000000-2222222222222222-01"),
            Some("00-33333333333333333333333333333333-2222222222222222-01"),
            Some("00-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-2222222222222222-01"),
        ] {
            let mut headers = problem_headers();
            headers.remove("traceparent");
            if let Some(value) = header {
                headers.insert("traceparent", value.parse().unwrap());
            }
            let result = projection(&bytes, &headers);
            assert_eq!(result["code"], "request.invalid");
            assert!(result.get("trace_id").is_none());
        }
        let mut headers = problem_headers();
        headers.append(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01"
                .parse()
                .unwrap(),
        );
        assert!(projection(&bytes, &headers).get("trace_id").is_none());
        for trace in [
            "secret42".to_owned(),
            "0".repeat(32),
            "A".repeat(32),
            "1".repeat(33),
        ] {
            let mut body = public_problem();
            body["traceId"] = json!(trace);
            assert_eq!(
                projection(&serde_json::to_vec(&body).unwrap(), &problem_headers())["kind"],
                "invalid_problem"
            );
        }
    }

    #[test]
    fn failure_receipt_diagnostic_budget_media_and_http_classes_are_fixed() {
        let headers = problem_headers();
        let mut body = serde_json::to_vec(&public_problem()).unwrap();
        body.resize(PROBLEM_LIMIT, b' ');
        assert_eq!(projection(&body, &headers)["kind"], "known_problem");
        body.push(b' ');
        assert_eq!(
            projection(&body, &headers),
            json!({"kind":"unavailable", "http_class":"client_error"})
        );
        for value in ["application/json", "text/plain"] {
            let mut other = headers.clone();
            other.insert(reqwest::header::CONTENT_TYPE, value.parse().unwrap());
            assert_eq!(projection(b"secret42", &other)["kind"], "non_problem");
        }
        let mut duplicate = headers.clone();
        duplicate.append(
            reqwest::header::CONTENT_TYPE,
            "application/problem+json".parse().unwrap(),
        );
        assert_eq!(projection(b"secret42", &duplicate)["kind"], "non_problem");
        for (status, class) in [
            (200, None),
            (399, None),
            (400, Some("client_error")),
            (499, Some("client_error")),
            (500, Some("server_error")),
            (599, Some("server_error")),
        ] {
            let result = serde_json::to_value(failure_metadata(
                Product::Breg,
                status,
                &HeaderMap::new(),
                b"secret42",
            ))
            .unwrap();
            assert_eq!(result.get("http_class").and_then(Value::as_str), class);
        }
    }

    #[test]
    fn failure_receipt_closed_catalogs_bind_each_product_type_and_status() {
        for code in registry_breg::problem::ProblemCode::ALL {
            let mut body = public_problem();
            body["code"] = json!(code.code());
            body["status"] = json!(code.status());
            body["type"] = json!(registry_breg::problem::type_uri(code.code()));
            let document =
                ProblemDocument::parse_exact(&serde_json::to_vec(&body).unwrap(), PROBLEM_LIMIT)
                    .unwrap();
            assert_eq!(
                known_problem_code(Product::Breg, &document),
                Some(code.code())
            );
            assert!(known_problem_code(Product::Casework, &document).is_none());
        }
        let catalog: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../products/casework/generated/registry-casework.openapi.json"
        )))
        .unwrap();
        let mut checked = 0;
        for schema in catalog["components"]["schemas"]
            .as_object()
            .unwrap()
            .values()
        {
            if let Some(parts) = schema["allOf"].as_array() {
                for part in parts {
                    let properties = &part["properties"];
                    if let (Some(code), Some(status), Some(uri)) = (
                        properties["code"]["const"].as_str(),
                        properties["status"]["const"].as_u64(),
                        properties["type"]["const"].as_str(),
                    ) {
                        let mut body = public_problem();
                        body["code"] = json!(code);
                        body["status"] = json!(status);
                        body["type"] = json!(uri);
                        let document = ProblemDocument::parse_exact(
                            &serde_json::to_vec(&body).unwrap(),
                            PROBLEM_LIMIT,
                        )
                        .unwrap();
                        assert_eq!(known_problem_code(Product::Casework, &document), Some(code));
                        assert!(known_problem_code(Product::Breg, &document).is_none());
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn failure_receipt_poll_retains_last_completed_response_and_none_before_any_response() {
        let first = failure_metadata(
            Product::Breg,
            400,
            &problem_headers(),
            &serde_json::to_vec(&public_problem()).unwrap(),
        );
        let last = failure_metadata(Product::Breg, 503, &HeaderMap::new(), b"secret42");
        let outcome = poll_timed_out(503, Some("last status mismatch".into()), Some(last));
        let result = serde_json::to_value(outcome.failure).unwrap();
        assert_eq!(
            result,
            json!({"kind":"non_problem","http_class":"server_error"})
        );
        assert!(poll_timed_out(0, None, None).failure.is_none());
        assert_eq!(
            serde_json::to_value(
                poll_timed_out(400, Some("status mismatch".into()), Some(first)).failure
            )
            .unwrap()["code"],
            "request.invalid"
        );
    }

    const PUBLIC_INVALID: &str = r#"{"type":"https://id.registrystack.org/problems/registry-breg/request/invalid","title":"ignored","detail":"ignored","status":400,"code":"request.invalid","traceId":"11111111111111111111111111111111"}"#;
    const PUBLIC_UNAVAILABLE: &str = r#"{"type":"https://id.registrystack.org/problems/registry-breg/service/unavailable","title":"ignored","detail":"ignored","status":503,"code":"service.unavailable","traceId":"11111111111111111111111111111111"}"#;
    const PUBLIC_TRACE_HEADER: &str =
        "traceparent: 00-11111111111111111111111111111111-2222222222222222-01\r\n";

    #[test]
    fn failure_receipt_expected_error_passes_and_failed_capture_updates_stay_empty() {
        for expected_status in [400, 404] {
            let server = synthetic_server_with_headers(
                vec![(Duration::ZERO, 400, PUBLIC_INVALID)],
                "application/problem+json",
                PUBLIC_TRACE_HEADER,
            );
            let root = tempfile::tempdir().unwrap();
            let issuer = Issuer::create(root.path()).unwrap();
            let input = polling_input(1000, 50);
            let mut step: Step=serde_json::from_value(json!({"id":"read","product":"breg","as":"reader","method":"GET","path":"/v1/result","expect":{"status":expected_status}})).unwrap();
            step.poll = None;
            step.expect.status = serde_json::from_value(json!(expected_status)).unwrap();
            step.expect.json.clear();
            step.capture.insert(
                "observed".into(),
                Capture::Pointer {
                    pointer: "/code".into(),
                },
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let result = execute_step(
                &input,
                &issuer,
                &BTreeMap::from([(Product::Breg, server.url.clone())]),
                &step,
                &BTreeMap::new(),
                &client,
                &runtime,
                &|| Ok(()),
                &mut 0,
                &mut 0,
            )
            .unwrap();
            assert_eq!(result.status, 400);
            if expected_status == 400 {
                assert!(result.reason.is_none());
                assert!(result.failure.is_none());
                assert_eq!(
                    result.updates.get("observed"),
                    Some(&json!("request.invalid"))
                );
            } else {
                assert!(result.reason.is_some());
                assert!(result.updates.is_empty());
                assert_eq!(
                    serde_json::to_value(result.failure).unwrap()["code"],
                    "request.invalid"
                );
            }
            assert_eq!(server.finish(), 1);
        }
    }

    #[test]
    fn failure_receipt_actual_poll_keeps_last_completed_problem_not_late_response() {
        let _lock = POLL_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let server = synthetic_server_with_headers(
            vec![
                (Duration::ZERO, 400, PUBLIC_INVALID),
                (Duration::ZERO, 503, PUBLIC_UNAVAILABLE),
                (Duration::from_millis(1500), 400, PUBLIC_INVALID),
            ],
            "application/problem+json",
            PUBLIC_TRACE_HEADER,
        );
        let root = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(root.path()).unwrap();
        let input = polling_input(1000, 50);
        let report = run(
            &input,
            &issuer,
            &BTreeMap::from([(Product::Breg, server.url.clone())]),
            input.plan.journey.as_ref().unwrap(),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(report.result, "failed");
        assert_eq!(report.steps[0].status, 503);
        let failure = serde_json::to_value(&report.steps[0].failure).unwrap();
        assert_eq!(failure["code"], "service.unavailable");
        assert_eq!(failure["http_class"], "server_error");
        assert_eq!(failure["trace_id"], "11111111111111111111111111111111");
        assert_eq!(server.finish(), 3);
    }

    #[test]
    fn failure_receipt_does_not_change_existing_transport_response_limit() {
        static BODY: [u8; RESPONSE_LIMIT + 1] = [b'x'; RESPONSE_LIMIT + 1];
        let body = std::str::from_utf8(&BODY).unwrap();
        let server = synthetic_server(vec![(Duration::ZERO, 400, body)]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut transferred = 0;
        let result = runtime.block_on(read_response(
            client.get(format!("{}v1/result", server.url)),
            &mut transferred,
            Product::Breg,
        ));
        assert!(result.is_err());
        assert!(transferred <= RESPONSE_LIMIT);
        assert_eq!(server.finish(), 1);
    }

    #[test]
    fn reasons_are_bounded_and_omitted_when_the_step_passes() {
        assert_eq!(bounded_reason(&"é".repeat(2000)).chars().count(), 512);
        let report = StepReport {
            id: "a".into(),
            status: 200,
            expected_status: 200,
            result: "passed",
            reason: None,
            failure: None,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert!(value.get("reason").is_none());
        assert!(value.get("failure").is_none());
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
            failure: None,
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
