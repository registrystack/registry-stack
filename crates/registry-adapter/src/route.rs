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
use std::time::{Duration, Instant, SystemTime};

use registry_adapter_core::{
    is_route_unwritable_header_name, ErrorClass, Expression, HttpMethod, OnExceptionStep,
    SendComponent, SetPropertyStep, Step, ToParameters, ToStep,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Value};

use crate::auth::{
    AuthError, AuthEvent, AuthKind, AuthorizeContext, ClientAssertion, ClientAssertionSigner,
    ProtectedText, TokenBudget, TokenRequest, TokenSend, TokenWire, TransportFailure,
    UpstreamStatusAction,
};
use crate::component::http::uri::{encode_path_segment, percent_encode, LinkRefusal};
use crate::egress::{EgressError, EndpointEgress, OutboundSend, SendShape};
use crate::exchange::{
    Exchange, NEXT_CONTINUATION_PROPERTY, REDELIVERED_HEADER, REDELIVERY_COUNTER_HEADER,
    REDELIVERY_MAX_COUNTER_HEADER, RESERVED_PROPERTY_PREFIX,
};
use crate::language::{compile_selector, JsonPathResult, LanguageError};
use crate::processor;
use crate::scripts::ScriptSet;

/// The step kinds this runtime interprets. Every other kind of the route
/// model is refused at load by [`check_servable`], by name.
const DEFAULT_OK_RANGE: (u16, u16) = (200, 299);

/// The longest one exchange may run, across every attempt, redelivery
/// pause, and script. It sits above the largest declared attempt timeout so
/// a single attempt always finishes under its own timeout first.
const EXCHANGE_DEADLINE: Duration = Duration::from_secs(60);

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
            Step::Transform(expression) => check_expression("transform", expression)?,
            Step::SetHeader(header) => {
                if is_route_unwritable_header_name(&header.name) {
                    return Err(format!(
                        "setHeader may not write the read-only header {}",
                        header.name
                    ));
                }
                check_expression("setHeader", &header.value)?;
            }
            Step::SetProperty(property) => check_set_property(property)?,
            Step::RemoveHeader(name) => {
                if is_route_unwritable_header_name(name) {
                    return Err(format!(
                        "removeHeader may not remove the read-only header {name}"
                    ));
                }
            }
            Step::RemoveProperty(name) => {
                if name.starts_with(RESERVED_PROPERTY_PREFIX) && name != NEXT_CONTINUATION_PROPERTY
                {
                    return Err(format!(
                        "removeProperty may not remove the reserved property {name}"
                    ));
                }
            }
            Step::Script(expression) => check_expression("script", expression)?,
            Step::Choice(choice) => {
                for clause in &choice.when {
                    check_predicate("choice", &clause.predicate())?;
                    check_steps(&clause.steps, true)?;
                }
                if let Some(otherwise) = &choice.otherwise {
                    check_steps(&otherwise.steps, true)?;
                }
            }
            Step::Filter(filter) => {
                check_predicate("filter", &filter.predicate())?;
                if let Some(name) = &filter.status_property_name {
                    if name.starts_with(RESERVED_PROPERTY_PREFIX) {
                        return Err(format!(
                            "filter statusPropertyName may not take the reserved name {name}"
                        ));
                    }
                }
                check_steps(&filter.steps, true)?;
            }
            Step::Validate(validate) => {
                check_predicate_expression("validate", &validate.expression)?
            }
            Step::Stop(_) => {}
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

/// A `jsonpath` expression compiles under the declared bounds before the
/// route is registered, so nothing the bounds refuse evaluates per
/// exchange (section 8.11.8).
fn check_expression(site: &str, expression: &Expression) -> Result<(), String> {
    if let Expression::JsonPath(selector) = expression {
        compile_selector(selector).map_err(|fault| format!("the {site} jsonpath {fault}"))?;
    }
    Ok(())
}

/// A predicate additionally must be one singular query: a node list has
/// no boolean meaning (section 8.11.8).
fn check_predicate_expression(site: &str, expression: &Expression) -> Result<(), String> {
    check_expression(site, expression)?;
    if let Expression::JsonPath(selector) = expression {
        let compiled =
            compile_selector(selector).map_err(|fault| format!("the {site} jsonpath {fault}"))?;
        if !compiled.is_singular() {
            return Err(format!(
                "a {site} predicate must be one singular jsonpath query, not a node list"
            ));
        }
    }
    Ok(())
}

/// The inline single-language-key predicate of a `choice` clause or a
/// `filter`: exactly one member, then the predicate rules.
fn check_predicate(site: &str, predicate: &Option<Expression>) -> Result<(), String> {
    match predicate {
        Some(expression) => check_predicate_expression(site, expression),
        None => Err(format!(
            "a {site} clause must carry exactly one predicate language member"
        )),
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
        check_predicate_expression("onWhen", expression)?;
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
    /// The endpoint's compiled outbound state: the authentication plan, the
    /// origin pin, the header filter and the frozen destination policy.
    pub egress: EndpointEgress,
    /// The origin and base path every link of this endpoint starts with.
    pub base: String,
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
    /// The runtime clock at the event, which the journal stamps the row with.
    pub at: SystemTime,
    pub detail: Value,
}

/// The authentication events of one send as value-free journal facts: the
/// fixed event name and, where the event carries one, a fixed code name,
/// status or failure kind. Never a token, a header or server text.
fn auth_events_detail(events: &[AuthEvent]) -> Value {
    Value::Array(
        events
            .iter()
            .map(|event| match event {
                AuthEvent::TokenRequested => json!({ "event": "tokenRequested" }),
                AuthEvent::TokenIssued => json!({ "event": "tokenIssued" }),
                AuthEvent::TokenCacheHit => json!({ "event": "tokenCacheHit" }),
                AuthEvent::TokenRefused { code } => {
                    json!({ "event": "tokenRefused", "code": code })
                }
                AuthEvent::TokenProtocolRefused => json!({ "event": "tokenProtocolRefused" }),
                AuthEvent::TokenRedirected => json!({ "event": "tokenRedirected" }),
                AuthEvent::TokenUnavailable { status } => {
                    json!({ "event": "tokenUnavailable", "status": status })
                }
                AuthEvent::TokenTransportFailed { kind } => {
                    json!({ "event": "tokenTransportFailed", "kind": kind })
                }
                AuthEvent::TokenEgressRefused { detail } => {
                    json!({ "event": "tokenEgressRefused", "detail": detail })
                }
                AuthEvent::TokenAdmissionShed => json!({ "event": "tokenAdmissionShed" }),
                AuthEvent::TokenInvalidatedAfterUnauthorized => {
                    json!({ "event": "tokenInvalidatedAfterUnauthorized" })
                }
                AuthEvent::CredentialRejected => json!({ "event": "credentialRejected" }),
                AuthEvent::TokenBudgetExhausted => json!({ "event": "tokenBudgetExhausted" }),
            })
            .collect(),
    )
}

/// How a route run failed: the class it raised and, when a
/// `throwException` raised it, the message that fills `problemDetail`.
#[derive(Clone, Debug)]
pub struct RouteFailure {
    pub class: ErrorClass,
    pub message: Option<String>,
    /// The value-free authentication events of a send that failed at its
    /// credential, for the failure's own journal row.
    pub auth: Option<Value>,
}

impl RouteFailure {
    pub(crate) fn of(class: ErrorClass) -> Self {
        Self {
            class,
            message: None,
            auth: None,
        }
    }
}

/// A selector or predicate evaluation fault as a route failure: the
/// matched-node budget is the script budget, every other fault is a
/// script fault (sections 8.5 and 8.11.8).
fn language_failure(fault: LanguageError) -> RouteFailure {
    match fault {
        LanguageError::MatchedNodeBudgetExceeded { .. } => {
            RouteFailure::of(ErrorClass::ScriptBudgetExceeded)
        }
        _ => RouteFailure::of(ErrorClass::Script),
    }
}

/// One run's result: the exchange as it ended or the failure, and the
/// events in order.
pub struct RouteOutcome {
    pub result: Result<Exchange, RouteFailure>,
    pub events: Vec<RouteEvent>,
}

/// How a step body ended: `stop` ends the route without failing the
/// exchange (`products/adapter/CONCEPT.md` section 8.6), so it is not an
/// error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Flow {
    Continue,
    Stop,
}

/// Run `steps` over `exchange` within the exchange deadline.
pub async fn run_route(
    context: &RouteContext<'_>,
    steps: &[Step],
    exchange: Exchange,
) -> RouteOutcome {
    run_route_within(context, steps, exchange, EXCHANGE_DEADLINE).await
}

/// Run `steps` over `exchange`, failing it as `budget.exhausted` when
/// `deadline` passes first. Every attempt, redelivery pause, and script
/// spends the one clock; the failure keeps the events produced so far and
/// carries no body.
pub async fn run_route_within(
    context: &RouteContext<'_>,
    steps: &[Step],
    exchange: Exchange,
    deadline: Duration,
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
    let body = async {
        for step in steps.iter().filter(|s| !matches!(s, Step::OnException(_))) {
            match run.step_with_clauses(step, &clauses).await {
                Ok(Flow::Continue) => {}
                Ok(Flow::Stop) => break,
                Err(failure) => return Err(failure),
            }
        }
        Ok(())
    };
    let result = tokio::time::timeout(deadline, body)
        .await
        .unwrap_or_else(|_| Err(RouteFailure::of(ErrorClass::BudgetExhausted)));
    let Run {
        exchange, events, ..
    } = run;
    RouteOutcome {
        result: result.map(|()| exchange),
        events,
    }
}

pub(crate) struct Run<'a, 'c> {
    pub(crate) context: &'a RouteContext<'c>,
    pub(crate) exchange: Exchange,
    events: Vec<RouteEvent>,
    sends: u64,
}

impl Run<'_, '_> {
    /// Run one body step; on failure, apply the closest matching clause:
    /// redeliver an upstream send while the policy allows, then run the
    /// clause's steps. An error inside a clause is final. A `stop` in the
    /// step or in the clause's steps ends the route without failing.
    async fn step_with_clauses(
        &mut self,
        step: &Step,
        clauses: &[&OnExceptionStep],
    ) -> Result<Flow, RouteFailure> {
        let mut redeliveries = 0_u32;
        loop {
            let failure = match self.step(step).await {
                Ok(flow) => return Ok(flow),
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
                        at: SystemTime::now(),
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
                at: SystemTime::now(),
                detail: json!({ "class": failure.class.class() }),
            });
            for clause_step in &clause.steps {
                // An error inside a clause replaces the failure and is final.
                if self.step(clause_step).await? == Flow::Stop {
                    break;
                }
            }
            return Err(failure);
        }
    }

    /// Run a nested step body (a `choice` branch, a `filter`'s steps): no
    /// clause of its own, the failure bubbles to the enclosing step, and
    /// a `stop` ends the whole route. Boxed, because a nested body can
    /// hold another `choice` or `filter`, and the interpreter's call
    /// graph is depth-bounded at load, not statically acyclic.
    pub(crate) fn run_steps<'r>(
        &'r mut self,
        steps: &'r [Step],
    ) -> Pin<Box<dyn Future<Output = Result<Flow, RouteFailure>> + Send + 'r>> {
        Box::pin(async move {
            for step in steps {
                if self.step(step).await? == Flow::Stop {
                    return Ok(Flow::Stop);
                }
            }
            Ok(Flow::Continue)
        })
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
                match self.predicate(condition) {
                    Ok(true) => {}
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

    pub(crate) async fn step(&mut self, step: &Step) -> Result<Flow, RouteFailure> {
        match step {
            Step::SetBody(expression) => processor::set_body::assign(self, expression),
            Step::Transform(expression) => processor::transform::run(self, expression),
            Step::SetHeader(header) => processor::set_header::run(self, header),
            Step::SetProperty(property) => {
                let value = self.eval(&property.value)?;
                self.exchange.set_property(&property.name, value);
                Ok(Flow::Continue)
            }
            Step::RemoveHeader(name) => processor::remove_header::run(self, name),
            Step::RemoveProperty(name) => processor::remove_property::run(self, name),
            Step::Script(expression) => processor::script::run(self, expression),
            Step::Choice(choice) => processor::choice::run(self, choice).await,
            Step::Filter(filter) => processor::filter::run(self, filter).await,
            Step::Validate(validate) => processor::validate::run(self, validate),
            Step::Stop(_) => Ok(Flow::Stop),
            Step::ThrowException(throw) => Err(RouteFailure {
                class: throw.exception_type,
                message: throw.message.clone(),
                auth: None,
            }),
            Step::To(to) => self.send(to).await,
            // The unserved kinds never reach here: check_servable refuses
            // them by name before a route is registered.
            _ => Err(RouteFailure::of(ErrorClass::Script)),
        }
    }

    pub(crate) fn eval(&self, expression: &Expression) -> Result<Value, RouteFailure> {
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
            Expression::JsonPath(selector) => {
                let compiled = compile_selector(selector)
                    .map_err(|_| RouteFailure::of(ErrorClass::Validation))?;
                match compiled.evaluate(&self.exchange.message.body) {
                    Ok(JsonPathResult::Singular(None)) => Ok(Value::Null),
                    Ok(JsonPathResult::Singular(Some(value))) => Ok(value.clone()),
                    Ok(JsonPathResult::List(nodes)) => {
                        Ok(Value::Array(nodes.into_iter().cloned().collect()))
                    }
                    Err(fault) => Err(language_failure(fault)),
                }
            }
        }
    }

    /// An expression whose site requires a value: an absent singular
    /// jsonpath result raises `validation` instead of null (section
    /// 8.11.8 names `setBody` and a `pathParameters` entry; the path
    /// slot rule already refuses null in `fill_path`).
    pub(crate) fn eval_required(&self, expression: &Expression) -> Result<Value, RouteFailure> {
        match expression {
            Expression::JsonPath(selector) => {
                let compiled = compile_selector(selector)
                    .map_err(|_| RouteFailure::of(ErrorClass::Validation))?;
                match compiled.evaluate(&self.exchange.message.body) {
                    Ok(JsonPathResult::Singular(None)) => {
                        Err(RouteFailure::of(ErrorClass::Validation))
                    }
                    Ok(JsonPathResult::Singular(Some(value))) => Ok(value.clone()),
                    Ok(JsonPathResult::List(nodes)) => {
                        Ok(Value::Array(nodes.into_iter().cloned().collect()))
                    }
                    Err(fault) => Err(language_failure(fault)),
                }
            }
            other => self.eval(other),
        }
    }

    /// An expression used as a predicate: its result is a boolean or the
    /// evaluation fails, never a truthiness guess (section 8.5). A jsonpath
    /// predicate follows section 8.11.8's singular-boolean rule, absent
    /// counting as false.
    pub(crate) fn predicate(&self, expression: &Expression) -> Result<bool, RouteFailure> {
        match expression {
            Expression::JsonPath(selector) => {
                let compiled = compile_selector(selector)
                    .map_err(|_| RouteFailure::of(ErrorClass::Validation))?;
                compiled
                    .evaluate_predicate(&self.exchange.message.body)
                    .map_err(language_failure)
            }
            other => match self.eval(other)? {
                Value::Bool(flag) => Ok(flag),
                _ => Err(RouteFailure::of(ErrorClass::Script)),
            },
        }
    }

    async fn send(&mut self, to: &ToStep) -> Result<Flow, RouteFailure> {
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
        // A link the destination's URL bound cannot hold names nothing the
        // source can serve: it is answered as no such record, before any
        // credential is acquired and with no send.
        if endpoint.egress.origin().pin(&link) == Err(LinkRefusal::TooLong) {
            return Err(RouteFailure::of(ErrorClass::OutcomeNotFound));
        }
        let ok_range = parse_ok_range(parameters).unwrap_or(DEFAULT_OK_RANGE);

        let mut budget = TokenBudget::new_exchange();
        let mut auth_events: Vec<AuthEvent> = Vec::new();
        let authorized = endpoint
            .egress
            .plan()
            .authorize(&mut AuthorizeContext {
                resolver: self.context.resolver,
                budget: &mut budget,
                send: &NoTokenSend,
                signer: &NoSigner,
                events: &mut auth_events,
            })
            .await;
        let mut sending = json!({ "endpoint": to.uri.id, "method": "GET", "operation": parameters.operation.as_ref().map(|o| o.as_str()) });
        if !auth_events.is_empty() {
            sending["auth"] = auth_events_detail(&auth_events);
        }
        // The send is announced only once its credential is in hand; a
        // credential failure never reads as a send that began.
        let credential = authorized.map_err(|error| {
            let mut failure = RouteFailure::of(
                ErrorClass::from_class(error.class()).unwrap_or(ErrorClass::CredentialRejected),
            );
            if !auth_events.is_empty() {
                failure.auth = Some(auth_events_detail(&auth_events));
            }
            failure
        })?;
        self.events.push(RouteEvent {
            kind: "exchangeSending",
            at: SystemTime::now(),
            detail: sending,
        });
        auth_events.clear();
        let headers = self.exchange.message.string_headers();
        let started = Instant::now();
        let reply = endpoint
            .egress
            .send(OutboundSend {
                link: &link,
                exchange_headers: &headers,
                shape: SendShape::Get,
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
                .egress
                .plan()
                .on_upstream_status(
                    status,
                    credential.as_ref().and_then(|c| c.generation),
                    &mut refreshed,
                    &mut auth_events,
                )
                .await;
            if action != UpstreamStatusAction::Continue {
                let mut sent = json!({
                    "endpoint": to.uri.id,
                    "class": ErrorClass::CredentialRejected.class(),
                    "status": status,
                    "durationMs": elapsed,
                });
                if !auth_events.is_empty() {
                    sent["auth"] = auth_events_detail(&auth_events);
                }
                self.events.push(RouteEvent {
                    kind: "exchangeSent",
                    at: SystemTime::now(),
                    detail: sent,
                });
                return Err(RouteFailure::of(ErrorClass::CredentialRejected));
            }
        }
        match reply {
            Ok(reply) => {
                let mut sent =
                    json!({ "endpoint": to.uri.id, "status": reply.status, "durationMs": elapsed });
                if !auth_events.is_empty() {
                    sent["auth"] = auth_events_detail(&auth_events);
                }
                self.events.push(RouteEvent {
                    kind: "exchangeSent",
                    at: SystemTime::now(),
                    detail: sent,
                });
                let message = &mut self.exchange.message;
                message.body = reply.body;
                message.set_header("CamelHttpResponseCode", json!(reply.status));
                for (name, value) in reply.headers.iter() {
                    message.set_header(name, Value::String(value.to_owned()));
                }
                Ok(Flow::Continue)
            }
            Err(error) => {
                let class = error.class();
                if let EgressError::Refused(reason) = &error {
                    tracing::warn!(endpoint = %to.uri.id, reason = %reason, "an upstream send was refused");
                }
                let mut sent = json!({ "endpoint": to.uri.id, "class": class.class(), "status": status, "durationMs": elapsed });
                match &error {
                    EgressError::Upstream(failure) => {
                        sent["certainty"] = json!(failure.certainty_journal_name());
                    }
                    // A refusal happens before any byte leaves.
                    EgressError::Refused(reason) => {
                        sent["certainty"] = json!("not-sent");
                        sent["refusal"] = json!(reason.journal_name());
                    }
                }
                if !auth_events.is_empty() {
                    sent["auth"] = auth_events_detail(&auth_events);
                }
                self.events.push(RouteEvent {
                    kind: "exchangeSent",
                    at: SystemTime::now(),
                    detail: sent,
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
/// segment value: it must be a string or a number whose percent-encoded form
/// is one canonical path segment (see `encode_path_segment`). The rendered
/// link's length is bounded separately, in `send`, because the URL bound
/// covers the whole link, not one slot.
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
            Value::String(text) => text,
            Value::Number(number) => number.to_string(),
            _ => return Err(RouteFailure::of(ErrorClass::Validation)),
        };
        let segment =
            encode_path_segment(&text).ok_or_else(|| RouteFailure::of(ErrorClass::Validation))?;
        path.push_str(&segment);
        rest = &after[end + 2..];
    }
    path.push_str(rest);
    Ok(path)
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
        Box::pin(async {
            Err(TransportFailure::PolicyRefused {
                journal_name: "invalid-frozen-policy",
            })
        })
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
    fn a_send_with_query_expressions_is_served_including_jsonpath() {
        let served = steps(json!([
            {"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "GET",
                "path": "/api/items",
                "query": {
                    "page": {"exchangeProperty": "page"},
                    "all": {"constant": true},
                    "first": {"jsonpath": "$.items[0].id"}
                }
            }}}
        ]));
        check_servable(&served).expect("served");
        let refused = steps(json!([
            {"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "GET",
                "path": "/api/items",
                "query": {"page": {"jsonpath": "$["}}
            }}}
        ]));
        let refusal = check_servable(&refused).expect_err("refused");
        assert!(refusal.contains("jsonpath"), "{refusal}");
    }

    #[test]
    fn a_path_slot_that_is_not_one_segment_is_refused_anywhere_in_the_path() {
        for template in [
            "/api/v1/patients/{{id}}",
            "/api/v1/patients/{{id}}/consents",
        ] {
            for refused in ["", ".", "..", "a.b/..c", "a?b", "a%b"] {
                let result = fill_path(template, |_| Ok(json!(refused)));
                let failure = result.expect_err("refused");
                assert_eq!(
                    failure.class,
                    ErrorClass::Validation,
                    "{template} {refused}"
                );
            }
            let filled = fill_path(template, |_| Ok(json!("a.b ..c"))).expect("filled");
            assert!(filled.contains("a.b%20..c"), "{filled}");
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

#[cfg(test)]
mod auth_journal_tests {
    use super::*;

    #[test]
    fn auth_events_reach_the_journal_as_fixed_names_and_codes_only() {
        let detail = auth_events_detail(&[
            AuthEvent::TokenRequested,
            AuthEvent::TokenRefused {
                code: "invalid_scope",
            },
            AuthEvent::TokenUnavailable { status: 503 },
            AuthEvent::CredentialRejected,
        ]);
        assert_eq!(
            detail,
            json!([
                { "event": "tokenRequested" },
                { "event": "tokenRefused", "code": "invalid_scope" },
                { "event": "tokenUnavailable", "status": 503 },
                { "event": "credentialRejected" },
            ])
        );
    }
}

#[cfg(test)]
mod credential_order_tests {
    use super::*;
    use registry_adapter_core::{AdapterRuntimeConfig, Endpoint};
    use registry_platform_yaml::SecretProvider;

    #[allow(clippy::disallowed_methods)]
    fn runtime_config(base_url: &str, key_env: &str) -> AdapterRuntimeConfig {
        serde_norway::from_str(&format!(
            r#"
id: credential-order
endpoints:
  - endpoint: tracker
    baseUrl: {base_url}
    credential:
      type: static-api-key
      valueRef: secret:env/{key_env}
listener:
  bind: 127.0.0.1:8080
database:
  runtimeUrlRef: secret:env/ROUTE_CREDENTIAL_ORDER_DB
  migrationUrlRef: secret:env/ROUTE_CREDENTIAL_ORDER_DB
oidc:
  issuer: https://issuer.example.invalid
  audience: credential-order
allowedClients: [credential-order-client]
allowedPrivateCidrs: [192.168.0.0/16]
audit:
  retentionDays: 90
"#
        ))
        .expect("the runtime config parses")
    }

    #[allow(clippy::disallowed_methods)]
    fn pack_endpoint() -> Endpoint {
        serde_norway::from_str(
            r#"
id: tracker
component: http
authentication:
  type: static-api-key
  headerName: x-api-key
attemptTimeoutMilliseconds: 10000
maximumResponseBytes: 1024
responseHeaders: []
requestHeaders: []
operations: []
testedVersions: []
"#,
        )
        .expect("the pack endpoint parses")
    }

    fn compiled(
        base_url: &str,
        key_env: &str,
        resolver: &SecretResolver,
    ) -> BTreeMap<String, EndpointRuntime> {
        let config = runtime_config(base_url, key_env);
        let binding = config.endpoints.iter().next().expect("binding");
        let egress = EndpointEgress::compile(binding, &pack_endpoint(), &config, resolver)
            .expect("compiled");
        let base = format!(
            "{}{}",
            egress.origin().origin_url().trim_end_matches('/'),
            egress.origin().base_path()
        );
        let mut endpoints = BTreeMap::new();
        endpoints.insert(
            "tracker".to_owned(),
            EndpointRuntime {
                egress,
                base,
                attempt: Duration::from_secs(10),
                maximum_response_bytes: 1024,
            },
        );
        endpoints
    }

    fn get_steps() -> Vec<Step> {
        serde_json::from_value(json!([
            {"to": {"uri": "http:tracker", "parameters": {"httpMethod": "GET", "path": "/x"}}}
        ]))
        .expect("the steps parse")
    }

    /// A credential that cannot be produced fails the exchange before the
    /// send is announced: the journal never says an exchange was sending
    /// when no send could happen.
    #[tokio::test]
    async fn a_credential_failure_leaves_no_sending_event() {
        let key_env = "ROUTE_CREDENTIAL_ORDER_KEY";
        std::env::set_var(key_env, "order-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let endpoints = compiled("http://127.0.0.1:9/", key_env, &resolver);
        let scripts = ScriptSet::default();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            maximum_upstream_calls: 4,
        };
        // The key resolved at compile time; it is gone when the send needs it.
        std::env::remove_var(key_env);

        let outcome = run_route(&context, &get_steps(), Exchange::new("order".to_owned())).await;

        assert!(outcome.result.is_err(), "the exchange fails");
        assert!(
            outcome
                .events
                .iter()
                .all(|event| event.kind != "exchangeSending"),
            "no exchangeSending precedes a credential failure: {:?}",
            outcome.events
        );
    }

    /// An upstream that accepts and never answers cannot hold the exchange
    /// past its deadline, however long the attempt timeout allows: the
    /// exchange fails as budget-exhausted with the events it produced and
    /// no response body.
    #[tokio::test]
    async fn a_hung_upstream_cannot_outlive_the_exchange_deadline() {
        let key_env = "ROUTE_DEADLINE_KEY";
        std::env::set_var(key_env, "deadline-key");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let port = listener.local_addr().expect("the bound address").port();
        let _hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let endpoints = compiled(&format!("http://127.0.0.1:{port}/"), key_env, &resolver);
        let scripts = ScriptSet::default();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            maximum_upstream_calls: 4,
        };

        let started = Instant::now();
        let outcome = run_route_within(
            &context,
            &get_steps(),
            Exchange::new("deadline".to_owned()),
            Duration::from_millis(300),
        )
        .await;

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline cut it"
        );
        let failure = outcome.result.expect_err("the exchange fails");
        assert_eq!(failure.class, ErrorClass::BudgetExhausted);
        assert!(
            outcome
                .events
                .iter()
                .any(|event| event.kind == "exchangeSending"),
            "the events the run produced are kept: {:?}",
            outcome.events
        );
    }
}
