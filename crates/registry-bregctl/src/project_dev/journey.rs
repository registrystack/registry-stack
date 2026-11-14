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

    loop {
        active()?;
        if poll_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(poll_timed_out(last_status, last_reason));
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
        let Some(response) =
            read_response_before_deadline(runtime, request, poll_deadline, transferred)?
        else {
            return Ok(poll_timed_out(last_status, last_reason));
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
                    })
                }
                Err(error) => format!("capture failed: {error:#}"),
            },
        };
        let failed = |reason: &str| StepOutcome {
            status: response.status,
            reason: Some(bounded_reason(reason)),
            updates: BTreeMap::new(),
        };
        let Some((poll, deadline)) = step.poll.as_ref().zip(poll_deadline) else {
            return Ok(failed(&reason));
        };
        let now = Instant::now();
        if now >= deadline {
            return Ok(failed(&reason));
        }
        last_reason = Some(reason);
        thread::sleep(Duration::from_millis(poll.interval_ms).min(deadline - now));
    }
}

/// A poll whose deadline passed keeps the last completed status and says why
/// that response did not match.
fn poll_timed_out(status: u16, last_reason: Option<String>) -> StepOutcome {
    let reason = match last_reason {
        Some(reason) => format!("poll deadline passed; last response: {reason}"),
        None => "poll deadline passed before a response arrived".to_owned(),
    };
    StepOutcome {
        status,
        reason: Some(bounded_reason(&reason)),
        updates: BTreeMap::new(),
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
) -> Result<Option<ResponseData>> {
    let response = read_response(request, transferred);
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
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok(ResponseData {
        status,
        headers,
        body,
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
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

    fn read_request(stream: &mut TcpStream) {
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
            scenario_revision: None,
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
            binaries: BTreeMap::new(),
        }
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
    fn reasons_are_bounded_and_omitted_when_the_step_passes() {
        assert_eq!(bounded_reason(&"é".repeat(2000)).chars().count(), 512);
        let report = StepReport {
            id: "a".into(),
            status: 200,
            expected_status: 200,
            result: "passed",
            reason: None,
        };
        assert!(serde_json::to_value(&report)
            .unwrap()
            .get("reason")
            .is_none());
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
