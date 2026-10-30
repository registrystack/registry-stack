// SPDX-License-Identifier: Apache-2.0

//! The route model (`products/adapter/CONCEPT.md` sections 8.3 and 8.4).
//!
//! A route is a sequence of EIP steps read from a pack's route templates
//! and internal routes in the platform YAML formats, in the shape of
//! Camel's YAML DSL: an externally tagged step union keyed by the Camel
//! EIP name. The engine's boundedness rules hold here: one route has one
//! `from`, `from` URIs are `direct:` only, the route call graph through
//! `direct:` is acyclic and depth bounded, every `loop` and `split`
//! declares its maximum, and inline code is refused, so `rhai` always
//! names a digest-pinned file.
//!
//! Route templates carry typed parameters instantiated at `check` time
//! and at startup, never per request; a parameter carries authored values
//! only, never environment values. A template omits `from`, and the
//! instantiated route's `from` is `direct:<routeId>`.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use registry_adapter_core::{
    ErrorClass, Expression, HttpMethod, OnExceptionStep, SendComponent, SetPropertyStep, Step,
    ToParameters, ToStep,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Value};

use crate::auth::{
    AuthError, AuthEvent, AuthKind, AuthPlan, AuthorizeContext, ClientAssertion,
    ClientAssertionSigner, ProtectedText, TokenBudget, TokenRequest, TokenSend, TokenWire,
    TransportFailure, UpstreamStatusAction,
};
use crate::exchange::{
    Exchange, NEXT_CONTINUATION_PROPERTY, REDELIVERED_HEADER, REDELIVERY_COUNTER_HEADER,
    REDELIVERY_MAX_COUNTER_HEADER, RESERVED_PROPERTY_PREFIX,
};
use crate::scripts::ScriptSet;
use crate::upstream::{EgressError, OutboundSend, SendMethod, UpstreamSend};

/// The step kinds this runtime interprets. Every other kind of the route
/// model is refused at load by [`check_servable`], by name.
const DEFAULT_OK_RANGE: (u16, u16) = (200, 299);

/// The name a route author writes for a step kind, for refusal texts.
fn step_name(step: &Step) -> &'static str {
    match step {
        Step::To(_) => "to",
        Step::SetBody(_) => "setBody",
        Step::Transform(_) => "transform",
        Step::SetHeader(_) => "setHeader",
        Step::SetProperty(_) => "setProperty",
        Step::RemoveHeader(_) => "removeHeader",
        Step::RemoveProperty(_) => "removeProperty",
        Step::Script(_) => "script",
        Step::Choice(_) => "choice",
        Step::Filter(_) => "filter",
        Step::Validate(_) => "validate",
        Step::Stop(_) => "stop",
        Step::ThrowException(_) => "throwException",
        Step::Split(_) => "split",
        Step::Loop(_) => "loop",
        Step::Enrich(_) => "enrich",
        Step::CircuitBreaker(_) => "circuitBreaker",
        Step::Throttle(_) => "throttle",
        Step::IdempotentConsumer(_) => "idempotentConsumer",
        Step::ErrorHandler(_) => "errorHandler",
        Step::OnException(_) => "onException",
        Step::DoTry(_) => "doTry",
    }
}

/// Refuse, by name, anything in `steps` the interpreter does not run. A
/// route that passes runs exactly as written; a route that does not is never
/// registered, so nothing it says can be silently skipped.
pub fn check_servable(steps: &[Step]) -> Result<(), String> {
    check_steps(steps, false)
}

fn check_steps(steps: &[Step], in_clause: bool) -> Result<(), String> {
    for step in steps {
        match step {
            Step::To(to) => check_to(to)?,
            Step::SetBody(expression) => check_expression("setBody", expression)?,
            Step::SetProperty(property) => check_set_property(property)?,
            Step::ThrowException(_) => {}
            Step::OnException(clause) if !in_clause => check_clause(clause)?,
            other => {
                return Err(format!(
                    "the {} step is not served by this runtime yet",
                    step_name(other)
                ))
            }
        }
    }
    Ok(())
}

fn check_expression(site: &str, expression: &Expression) -> Result<(), String> {
    match expression {
        Expression::JsonPath(_) => Err(format!(
            "a jsonpath expression in {site} is not served by this runtime yet"
        )),
        _ => Ok(()),
    }
}

/// A route sets its own properties and the one reserved property the
/// facade reads back; every other `Adapter` name belongs to the engine.
fn check_set_property(property: &SetPropertyStep) -> Result<(), String> {
    if property.name.starts_with(RESERVED_PROPERTY_PREFIX)
        && property.name != NEXT_CONTINUATION_PROPERTY
    {
        return Err(format!(
            "setProperty may not write the reserved property {}",
            property.name
        ));
    }
    check_expression("setProperty", &property.value)
}

fn check_clause(clause: &OnExceptionStep) -> Result<(), String> {
    if clause.handled == Some(true) || clause.continued == Some(true) {
        return Err("onException handled and continued are not served by this runtime yet".into());
    }
    if let Some(expression) = &clause.on_when {
        check_expression("onWhen", expression)?;
    }
    if let Some(policy) = &clause.redelivery_policy {
        if policy.use_exponential_back_off
            || policy.use_collision_avoidance
            || policy.retry_while.is_some()
        {
            return Err(
                "redelivery with a back-off, collision avoidance or retryWhile is not served by this runtime yet"
                    .into(),
            );
        }
    }
    check_steps(&clause.steps, true)
}

fn check_to(to: &ToStep) -> Result<(), String> {
    if to.uri.component != SendComponent::Http {
        return Err("a to step is served for the http component only".into());
    }
    let Some(parameters) = &to.parameters else {
        return Err("a to step without parameters is not served".into());
    };
    if !matches!(parameters.http_method, None | Some(HttpMethod::Get)) {
        return Err("a to step is served for GET only".into());
    }
    if parameters.path.is_none() {
        return Err("a to step without a path is not served".into());
    }
    if parameters.http_uri.is_some()
        || parameters.body.is_some()
        || !parameters.resume_bindings.is_empty()
    {
        return Err("a to step with httpUri, body or resumeBindings is not served".into());
    }
    for expression in parameters.query.values() {
        check_expression("query", expression)?;
    }
    for expression in parameters.path_parameters.values() {
        check_expression("pathParameters", expression)?;
    }
    parse_ok_range(parameters)?;
    Ok(())
}

fn parse_ok_range(parameters: &ToParameters) -> Result<(u16, u16), String> {
    let Some(text) = &parameters.ok_status_code_range else {
        return Ok(DEFAULT_OK_RANGE);
    };
    let single = || -> Option<(u16, u16)> {
        let (low, high) = match text.split_once('-') {
            Some((low, high)) => (low.trim().parse().ok()?, high.trim().parse().ok()?),
            None => {
                let code = text.trim().parse().ok()?;
                (code, code)
            }
        };
        Some((low, high))
    };
    single().ok_or_else(|| "an okStatusCodeRange list is not served; write one range".to_owned())
}

/// One upstream endpoint as the interpreter reaches it.
pub struct EndpointRuntime {
    pub plan: AuthPlan,
    /// The origin and base path every link of this endpoint starts with.
    pub base: String,
    pub sender: Box<dyn UpstreamSend>,
    pub attempt: Duration,
    pub maximum_response_bytes: usize,
}

/// What a route run needs beside the exchange.
pub struct RouteContext<'a> {
    pub endpoints: &'a BTreeMap<String, EndpointRuntime>,
    pub scripts: &'a ScriptSet,
    pub resolver: &'a SecretResolver,
    /// The binding's `maximumUpstreamCalls`.
    pub maximum_upstream_calls: u64,
}

/// A value-free journal fact the run produced, for the caller to append.
#[derive(Clone, Debug)]
pub struct RouteEvent {
    pub kind: &'static str,
    pub detail: Value,
}

/// How a route run failed: the class it raised and, when a
/// `throwException` raised it, the message that fills `problemDetail`.
#[derive(Clone, Debug)]
pub struct RouteFailure {
    pub class: ErrorClass,
    pub message: Option<String>,
}

impl RouteFailure {
    fn of(class: ErrorClass) -> Self {
        Self {
            class,
            message: None,
        }
    }
}

/// One run's result: the exchange as it ended or the failure, and the
/// events in order.
pub struct RouteOutcome {
    pub result: Result<Exchange, RouteFailure>,
    pub events: Vec<RouteEvent>,
}

/// Run `steps` over `exchange`.
pub async fn run_route(
    context: &RouteContext<'_>,
    steps: &[Step],
    exchange: Exchange,
) -> RouteOutcome {
    let mut run = Run {
        context,
        exchange,
        events: Vec::new(),
        sends: 0,
    };
    let clauses: Vec<&OnExceptionStep> = steps
        .iter()
        .filter_map(|step| match step {
            Step::OnException(clause) => Some(clause),
            _ => None,
        })
        .collect();
    let mut result = Ok(());
    for step in steps.iter().filter(|s| !matches!(s, Step::OnException(_))) {
        if let Err(failure) = run.step_with_clauses(step, &clauses).await {
            result = Err(failure);
            break;
        }
    }
    let Run {
        exchange, events, ..
    } = run;
    RouteOutcome {
        result: result.map(|()| exchange),
        events,
    }
}

struct Run<'a, 'c> {
    context: &'a RouteContext<'c>,
    exchange: Exchange,
    events: Vec<RouteEvent>,
    sends: u64,
}

impl Run<'_, '_> {
    /// Run one body step; on failure, apply the closest matching clause:
    /// redeliver an upstream send while the policy allows, then run the
    /// clause's steps. An error inside a clause is final.
    async fn step_with_clauses(
        &mut self,
        step: &Step,
        clauses: &[&OnExceptionStep],
    ) -> Result<(), RouteFailure> {
        let mut redeliveries = 0_u32;
        loop {
            let failure = match self.step(step).await {
                Ok(()) => return Ok(()),
                Err(failure) => failure,
            };
            let Some(clause) = self.select_clause(&failure, clauses) else {
                return Err(failure);
            };
            if let (Some(policy), Step::To(_)) = (&clause.redelivery_policy, step) {
                if redeliveries < policy.maximum_redeliveries.get() {
                    redeliveries += 1;
                    self.events.push(RouteEvent {
                        kind: "exchangeRedelivery",
                        detail: json!({
                            "class": failure.class.class(),
                            "counter": redeliveries,
                        }),
                    });
                    tokio::time::sleep(Duration::from_secs(u64::from(
                        policy.retry_delay_seconds.get(),
                    )))
                    .await;
                    let message = &mut self.exchange.message;
                    message.set_header(REDELIVERED_HEADER, json!(true));
                    message.set_header(REDELIVERY_COUNTER_HEADER, json!(redeliveries));
                    message.set_header(
                        REDELIVERY_MAX_COUNTER_HEADER,
                        json!(policy.maximum_redeliveries.get()),
                    );
                    continue;
                }
            }
            self.events.push(RouteEvent {
                kind: "exchangeFailureHandled",
                detail: json!({ "class": failure.class.class() }),
            });
            for clause_step in &clause.steps {
                // An error inside a clause replaces the failure and is final.
                self.step(clause_step).await?;
            }
            return Err(failure);
        }
    }

    /// The clause whose declared class is closest to the raised class,
    /// among those whose `onWhen` holds. An `onWhen` that raises is no
    /// match. Equally close clauses resolve to the earlier one.
    fn select_clause<'k>(
        &self,
        failure: &RouteFailure,
        clauses: &[&'k OnExceptionStep],
    ) -> Option<&'k OnExceptionStep> {
        let mut best: Option<(usize, &'k OnExceptionStep)> = None;
        for clause in clauses {
            let declared: Vec<ErrorClass> = clause.exception.iter().copied().collect();
            let Some(matched) = ErrorClass::closest_match(&[failure.class], &declared) else {
                continue;
            };
            if let Some(condition) = &clause.on_when {
                match self.eval(condition) {
                    Ok(Value::Bool(true)) => {}
                    _ => continue,
                }
            }
            let depth = matched.class().split('.').count();
            if best.is_none_or(|(held, _)| depth > held) {
                best = Some((depth, clause));
            }
        }
        best.map(|(_, clause)| clause)
    }

    async fn step(&mut self, step: &Step) -> Result<(), RouteFailure> {
        match step {
            Step::SetBody(expression) => {
                self.exchange.message.body = self.eval(expression)?;
                Ok(())
            }
            Step::SetProperty(property) => {
                let value = self.eval(&property.value)?;
                self.exchange.set_property(&property.name, value);
                Ok(())
            }
            Step::ThrowException(throw) => Err(RouteFailure {
                class: throw.exception_type,
                message: throw.message.clone(),
            }),
            Step::To(to) => self.send(to).await,
            _ => Err(RouteFailure::of(ErrorClass::Script)),
        }
    }

    fn eval(&self, expression: &Expression) -> Result<Value, RouteFailure> {
        match expression {
            Expression::Constant(value) => Ok(value.clone()),
            Expression::Header(name) => Ok(self
                .exchange
                .message
                .header(name)
                .cloned()
                .unwrap_or(Value::Null)),
            Expression::ExchangeProperty(name) => {
                Ok(self.exchange.property(name).cloned().unwrap_or(Value::Null))
            }
            Expression::Rhai(script) => self
                .context
                .scripts
                .call(
                    &script.file,
                    &script.entrypoint,
                    &self.exchange.as_script_value(),
                )
                .map_err(|failure| RouteFailure::of(failure.class())),
            Expression::JsonPath(_) => Err(RouteFailure::of(ErrorClass::Script)),
        }
    }

    async fn send(&mut self, to: &ToStep) -> Result<(), RouteFailure> {
        let parameters = to
            .parameters
            .as_ref()
            .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
        let endpoint = self
            .context
            .endpoints
            .get(&to.uri.id)
            .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
        self.sends += 1;
        if self.sends > self.context.maximum_upstream_calls {
            return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
        }
        let path = self.render_path(parameters)?;
        let query = self.render_query(parameters)?;
        let link = format!("{}{path}{query}", endpoint.base);
        let ok_range = parse_ok_range(parameters).unwrap_or(DEFAULT_OK_RANGE);

        let mut budget = TokenBudget::new_exchange();
        let mut auth_events: Vec<AuthEvent> = Vec::new();
        let credential = endpoint
            .plan
            .authorize(&mut AuthorizeContext {
                resolver: self.context.resolver,
                budget: &mut budget,
                send: &NoTokenSend,
                signer: &NoSigner,
                events: &mut auth_events,
            })
            .await
            .map_err(|error| {
                RouteFailure::of(
                    ErrorClass::from_class(error.class()).unwrap_or(ErrorClass::CredentialRejected),
                )
            })?;

        self.events.push(RouteEvent {
            kind: "exchangeSending",
            detail: json!({ "endpoint": to.uri.id, "method": "GET", "operation": parameters.operation.as_ref().map(|o| o.as_str()) }),
        });
        let headers = self.exchange.message.string_headers();
        let started = Instant::now();
        let reply = endpoint
            .sender
            .send(OutboundSend {
                link: &link,
                exchange_headers: &headers,
                method: SendMethod::Get,
                authorization: credential.as_ref().map(|c| &c.header),
                attempt: endpoint.attempt,
                maximum_response_bytes: endpoint.maximum_response_bytes,
                ok_status_range: ok_range,
                throw_exception_on_failure: parameters.throw_exception_on_failure,
            })
            .await;
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let status = match &reply {
            Ok(reply) => Some(reply.status),
            Err(EgressError::Upstream(failure)) => failure.status,
            Err(EgressError::Refused(_)) => None,
        };
        if let Some(status) = status {
            let mut refreshed = true;
            let action = endpoint
                .plan
                .on_upstream_status(
                    status,
                    credential.as_ref().and_then(|c| c.generation),
                    &mut refreshed,
                    &mut auth_events,
                )
                .await;
            if action != UpstreamStatusAction::Continue {
                return Err(RouteFailure::of(ErrorClass::CredentialRejected));
            }
        }
        match reply {
            Ok(reply) => {
                self.events.push(RouteEvent {
                    kind: "exchangeSent",
                    detail: json!({ "endpoint": to.uri.id, "status": reply.status, "durationMs": elapsed }),
                });
                let message = &mut self.exchange.message;
                message.body = reply.body;
                message.set_header("CamelHttpResponseCode", json!(reply.status));
                for (name, value) in reply.headers {
                    message.set_header(&name, Value::String(value));
                }
                Ok(())
            }
            Err(error) => {
                let class = error.class();
                if let EgressError::Refused(reason) = &error {
                    tracing::warn!(endpoint = %to.uri.id, reason = %reason, "an upstream send was refused");
                }
                self.events.push(RouteEvent {
                    kind: "exchangeSent",
                    detail: json!({ "endpoint": to.uri.id, "class": class.class(), "status": status, "durationMs": elapsed }),
                });
                if let EgressError::Upstream(failure) = error {
                    let message = &mut self.exchange.message;
                    message.body = failure.body.unwrap_or(Value::Null);
                    if let Some(status) = failure.status {
                        message.set_header("CamelHttpResponseCode", json!(status));
                    }
                }
                Err(RouteFailure::of(class))
            }
        }
    }

    /// The query string of the send: each declared parameter in name
    /// order, its value rendered from the expression and percent-encoded.
    /// A null value leaves the parameter out.
    fn render_query(&self, parameters: &ToParameters) -> Result<String, RouteFailure> {
        let mut pairs = Vec::new();
        for (name, expression) in &parameters.query {
            let text = match self.eval(expression)? {
                Value::Null => continue,
                Value::String(text) => text,
                Value::Number(number) => number.to_string(),
                Value::Bool(flag) => flag.to_string(),
                Value::Array(_) | Value::Object(_) => {
                    return Err(RouteFailure::of(ErrorClass::Validation))
                }
            };
            pairs.push(format!(
                "{}={}",
                percent_encode(name.as_str()),
                percent_encode(&text)
            ));
        }
        if pairs.is_empty() {
            Ok(String::new())
        } else {
            Ok(format!("?{}", pairs.join("&")))
        }
    }

    /// Fill each `{{name}}` of the path from its `pathParameters`
    /// expression, percent-encoded as one path segment.
    fn render_path(&self, parameters: &ToParameters) -> Result<String, RouteFailure> {
        let template = parameters.path.as_deref().unwrap_or_default();
        fill_path(template, |name| {
            let expression = parameters
                .path_parameters
                .get(name)
                .ok_or_else(|| RouteFailure::of(ErrorClass::Validation))?;
            self.eval(expression)
        })
    }
}

/// Fill a path template's `{{name}}` slots from `value`. A slot is one path
/// segment value: it must be a non-empty string or a number, and never `.`
/// or `..`, which the outbound URI parser would collapse into a different
/// path once the request is built.
fn fill_path(
    template: &str,
    mut value: impl FnMut(&str) -> Result<Value, RouteFailure>,
) -> Result<String, RouteFailure> {
    let mut path = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        path.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .ok_or_else(|| RouteFailure::of(ErrorClass::Validation))?;
        let text = match value(&after[..end])? {
            Value::String(text) if !text.is_empty() && text != "." && text != ".." => text,
            Value::Number(number) => number.to_string(),
            _ => return Err(RouteFailure::of(ErrorClass::Validation)),
        };
        path.push_str(&percent_encode(&text));
        rest = &after[end + 2..];
    }
    path.push_str(rest);
    Ok(path)
}

/// Percent-encode everything but the RFC 3986 unreserved set.
fn percent_encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// The kinds of endpoint authentication this runtime serves: those that need
/// no token endpoint.
#[must_use]
pub fn is_served_auth(kind: AuthKind) -> bool {
    !kind.is_oauth2()
}

/// A token send that refuses: no served authentication kind reaches a token
/// endpoint, so reaching it is a fault, never a request.
struct NoTokenSend;

impl TokenSend for NoTokenSend {
    fn send<'a>(
        &'a self,
        _request: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>> {
        Box::pin(async { Err(TransportFailure::PolicyRefused) })
    }
}

/// A client-assertion signer that refuses, for the same reason.
struct NoSigner;

impl ClientAssertionSigner for NoSigner {
    fn sign_client_assertion(
        &self,
        _request: ClientAssertion<'_>,
    ) -> Result<ProtectedText, AuthError> {
        Err(AuthError::Credential)
    }
}

#[cfg(test)]
mod served_tests {
    use super::*;

    fn steps(value: Value) -> Vec<Step> {
        serde_json::from_value(value).expect("the steps parse")
    }

    #[test]
    fn a_get_send_with_a_bound_path_is_served() {
        let steps = steps(json!([
            {"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "GET",
                "path": "/api/items/{{id}}",
                "pathParameters": {"id": {"header": "recordId"}}
            }}}
        ]));
        check_servable(&steps).expect("served");
    }

    #[test]
    fn a_step_the_runtime_does_not_run_is_refused_by_name() {
        let steps =
            steps(json!([{"idempotentConsumer": {"expression": {"header": "x"}, "steps": []}}]));
        let refusal = check_servable(&steps).expect_err("refused");
        assert!(refusal.contains("idempotentConsumer"), "{refusal}");
        assert!(refusal.contains("not served"), "{refusal}");
    }

    #[test]
    fn a_route_may_set_its_own_property_and_the_next_continuation_only() {
        let own = steps(json!([{"setProperty": {"name": "page", "value": {"constant": 1}}}]));
        check_servable(&own).expect("served");
        let next = steps(json!([
            {"setProperty": {"name": "AdapterNextContinuation", "value": {"constant": 2}}}
        ]));
        check_servable(&next).expect("served");
        for reserved in ["AdapterContinuation", "AdapterFilters", "AdapterAnything"] {
            let steps = steps(json!([
                {"setProperty": {"name": reserved, "value": {"constant": 1}}}
            ]));
            let refusal = check_servable(&steps).expect_err("refused");
            assert!(refusal.contains(reserved), "{refusal}");
        }
    }

    #[test]
    fn a_send_with_query_expressions_is_served_and_a_jsonpath_one_is_not() {
        let served = steps(json!([
            {"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "GET",
                "path": "/api/items",
                "query": {"page": {"exchangeProperty": "page"}, "all": {"constant": true}}
            }}}
        ]));
        check_servable(&served).expect("served");
        let refused = steps(json!([
            {"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "GET",
                "path": "/api/items",
                "query": {"page": {"jsonpath": "$.page"}}
            }}}
        ]));
        let refusal = check_servable(&refused).expect_err("refused");
        assert!(refusal.contains("jsonpath"), "{refusal}");
    }

    #[test]
    fn a_path_slot_that_is_a_dot_segment_is_refused_anywhere_in_the_path() {
        for template in [
            "/api/v1/patients/{{id}}",
            "/api/v1/patients/{{id}}/consents",
        ] {
            for refused in ["", ".", ".."] {
                let result = fill_path(template, |_| Ok(json!(refused)));
                let failure = result.expect_err("refused");
                assert_eq!(
                    failure.class,
                    ErrorClass::Validation,
                    "{template} {refused}"
                );
            }
            let filled = fill_path(template, |_| Ok(json!("a.b/..c"))).expect("filled");
            assert!(filled.contains("a.b%2F..c"), "{filled}");
        }
    }

    #[test]
    fn a_post_send_is_refused() {
        let steps = steps(json!([
            {"to": {"uri": "http:tracker", "parameters": {"httpMethod": "POST", "path": "/x"}}}
        ]));
        assert!(check_servable(&steps).is_err());
    }
}
