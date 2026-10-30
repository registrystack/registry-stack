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
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use registry_adapter_core::{
    is_route_unwritable_header_name, AdapterRuntimeConfig, AggregationStrategy, Endpoint,
    EndpointBinding, EnrichStep, ErrorClass, Expression, HttpMethod, OnExceptionStep,
    RedeliveryOptions, SendComponent, SetPropertyStep, Step, ToParameters, ToStep,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Value};

use crate::auth::{
    AuthError, AuthEvent, AuthKind, AuthorizeContext, ClientAssertion, ClientAssertionSigner,
    ProtectedText, TokenBudget, TokenRequest, TokenSend, TokenWire, TransportFailure,
    UpstreamStatusAction,
};
use crate::component::http::uri::{encode_path_segment, percent_encode, LinkRefusal};
use crate::egress::{
    EgressError, EgressFault, EndpointEgress, OutboundSend, SendBody, SendBodyFormat, SendShape,
};
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
    // An errorHandler step configures the whole route; a second one
    // would silently shadow the first (section 8.7).
    if steps
        .iter()
        .filter(|step| matches!(step, Step::ErrorHandler(_)))
        .count()
        > 1
    {
        return Err("a route carries more than one errorHandler step".to_owned());
    }
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
            Step::Split(split) => {
                if split.maximum_items.is_none() {
                    return Err(
                        "the split step declares no maximumItems bound; declare it".to_owned()
                    );
                }
                // Stopping at the first failure leaves no threshold to
                // reach; the authoring checks refuse the pair too.
                if split.stop_on_exception
                    && (split.error_threshold.is_some() || split.maximum_failed_records.is_some())
                {
                    return Err(
                        "the split step sets stopOnException beside its failure accounting"
                            .to_owned(),
                    );
                }
                check_expression("split", &split.expression)?;
                check_strategy(split.aggregation_strategy.as_ref())?;
                check_steps(&split.steps, true)?;
            }
            Step::Loop(looped) => {
                match looped.language_members() {
                    0 => {
                        return Err(
                            "the loop step carries no count or predicate language key".to_owned()
                        )
                    }
                    1 => {}
                    _ => {
                        return Err(
                            "the loop step carries more than one count or predicate language key"
                                .to_owned(),
                        )
                    }
                }
                if looped.maximum_iterations.is_none() {
                    return Err(
                        "the loop step declares no maximumIterations bound; declare it".to_owned(),
                    );
                }
                if let Some(expression) = looped.expression() {
                    if looped.do_while {
                        check_predicate_expression("loop", &expression)?;
                    } else {
                        check_expression("loop", &expression)?;
                    }
                }
                check_steps(&looped.steps, true)?;
            }
            Step::Enrich(enrich) => {
                check_enrich(enrich)?;
                check_strategy(enrich.aggregation_strategy.as_ref())?;
            }
            Step::CircuitBreaker(breaker) => {
                if breaker.steps.is_empty() {
                    return Err("a circuitBreaker guards no steps".to_owned());
                }
                // A minimum above the window can never be reached inside
                // it, so the breaker would never judge (section 8.7).
                if breaker.minimum_number_of_calls.get() > breaker.sliding_window_calls.get() {
                    return Err(
                        "a circuitBreaker judges from more calls than its window holds".to_owned(),
                    );
                }
                if let Some(fallback) = &breaker.on_fallback {
                    if fallback.steps.is_empty() {
                        return Err("an onFallback declares no steps".to_owned());
                    }
                    check_steps(&fallback.steps, true)?;
                }
                check_steps(&breaker.steps, true)?;
            }
            Step::Throttle(throttle) => {
                if throttle.steps.is_empty() {
                    return Err("a throttle paces no steps".to_owned());
                }
                // A constant limit is whole and checkable at load; every
                // other expression form is read per exchange and fails
                // the exchange when it is not a positive integer.
                if let Expression::Constant(Value::Number(number)) = &throttle.limit {
                    if number.as_u64().is_none_or(|limit| limit == 0) {
                        return Err("a throttle limit must be a positive integer".to_owned());
                    }
                }
                check_expression("throttle", &throttle.limit)?;
                check_steps(&throttle.steps, true)?;
            }
            Step::OnException(clause) if !in_clause => check_clause(clause)?,
            Step::OnException(_) => {
                return Err("an onException clause is served at route top level only".to_owned())
            }
            Step::ErrorHandler(handler) => {
                if in_clause {
                    return Err("an errorHandler step is served at route top level only".to_owned());
                }
                if let Some(policy) = handler
                    .default_error_handler
                    .as_ref()
                    .and_then(|handler| handler.redelivery_policy.as_ref())
                {
                    check_policy("errorHandler", policy)?;
                }
            }
            Step::DoTry(block) => {
                for catch in &block.do_catch {
                    if catch.exception.is_empty() {
                        return Err("a doCatch names no exception class".to_owned());
                    }
                    for class in catch.exception.iter() {
                        if class.is_uncatchable() || class.is_facade() {
                            return Err(format!(
                                "a doCatch may not name the class {}",
                                class.class()
                            ));
                        }
                    }
                    if let Some(expression) = &catch.on_when {
                        check_predicate_expression("doCatch onWhen", expression)?;
                    }
                    check_steps(&catch.steps, true)?;
                }
                if let Some(finally) = &block.do_finally {
                    check_steps(&finally.steps, true)?;
                }
                check_steps(&block.steps, true)?;
            }
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
    if clause.exception.is_empty() {
        return Err("an onException clause names no exception class".to_owned());
    }
    for class in clause.exception.iter() {
        if class.is_uncatchable() || class.is_facade() {
            return Err(format!(
                "an onException clause may not name the class {}",
                class.class()
            ));
        }
    }
    if clause.handled == Some(true) && clause.continued == Some(true) {
        return Err("an onException clause cannot set handled and continued together".into());
    }
    if let Some(expression) = &clause.on_when {
        check_predicate_expression("onWhen", expression)?;
    }
    if let Some(policy) = &clause.redelivery_policy {
        check_policy("onException", policy)?;
    }
    check_steps(&clause.steps, true)
}

/// A policy whose `retryWhile` could never fire, because no redelivery
/// stands behind it (section 8.7).
fn check_policy(site: &str, policy: &RedeliveryOptions) -> Result<(), String> {
    if policy.retry_while.is_some() && policy.maximum_redeliveries.get() == 0 {
        return Err(format!(
            "a {site} retryWhile has no redeliveries behind it; raise maximumRedeliveries or drop retryWhile"
        ));
    }
    Ok(())
}

fn check_to(to: &ToStep) -> Result<(), String> {
    if to.uri.component == SendComponent::Direct {
        if to.parameters.is_some() {
            return Err("a direct send carries no parameters".into());
        }
        return Ok(());
    }
    if to.uri.component == SendComponent::GraphQl {
        // The graphql shape carries `operation` and `body` only (section
        // 8.8): no address members, no method of its own, no status
        // range of its own. `body` names the send's variables and is
        // checked beside them.
        let Some(parameters) = &to.parameters else {
            return Ok(());
        };
        if parameters.http_method.is_some() {
            return Err("a graphql send declares no httpMethod".into());
        }
        if parameters.path.is_some() {
            return Err("a graphql send declares no path".into());
        }
        if parameters.http_uri.is_some() {
            return Err("a graphql send declares no httpUri".into());
        }
        if !parameters.path_parameters.is_empty() {
            return Err("a graphql send declares no pathParameters".into());
        }
        if !parameters.query.is_empty() {
            return Err("a graphql send declares no query".into());
        }
        if parameters.ok_status_code_range.is_some() {
            return Err("a graphql send declares no okStatusCodeRange".into());
        }
        if !parameters.resume_bindings.is_empty() {
            return Err("a graphql send with resumeBindings is not served".into());
        }
        if let Some(expression) = &parameters.body {
            check_expression("body", expression)?;
        }
        return Ok(());
    }
    if to.uri.component != SendComponent::Http {
        return Err("a to step is served for the http component only".into());
    }
    let Some(parameters) = &to.parameters else {
        return Err("a to step without parameters is not served".into());
    };
    if !matches!(parameters.http_method, None | Some(HttpMethod::Get)) {
        return Err("a to step is served for GET only".into());
    }
    if parameters.body.is_some() || !parameters.resume_bindings.is_empty() {
        return Err("a to step with a body or resumeBindings is not served".into());
    }
    if let Some(expression) = &parameters.http_uri {
        // The one dynamic form (section 8.11.5): exactly one of `path`
        // and `httpUri`, and nothing that would build a second address
        // beside the link.
        if parameters.path.is_some() {
            return Err("a to step with both a path and an httpUri is not served".into());
        }
        if !parameters.query.is_empty() {
            return Err("a to step with a query beside an httpUri is not served".into());
        }
        if !parameters.path_parameters.is_empty() {
            return Err("a to step with pathParameters beside an httpUri is not served".into());
        }
        check_expression("httpUri", expression)?;
    } else {
        if parameters.path.is_none() {
            return Err("a to step without a path is not served".into());
        }
        for expression in parameters.query.values() {
            check_expression("query", expression)?;
        }
        for expression in parameters.path_parameters.values() {
            check_expression("pathParameters", expression)?;
        }
    }
    parse_ok_range(parameters)?;
    Ok(())
}

/// An `enrich` send holds to the same served surface as a `to` send:
/// http component, GET, a declared path, no origin or body members. The
/// strategy is checked beside it.
fn check_enrich(enrich: &EnrichStep) -> Result<(), String> {
    if enrich.uri.component != SendComponent::Http {
        return Err("an enrich step is served for the http component only".into());
    }
    let Some(parameters) = &enrich.parameters else {
        return Err("an enrich step without parameters is not served".into());
    };
    if !matches!(parameters.http_method, None | Some(HttpMethod::Get)) {
        return Err("an enrich step is served for GET only".into());
    }
    if parameters.path.is_none() {
        return Err("an enrich step without a path is not served".into());
    }
    if parameters.http_uri.is_some()
        || parameters.body.is_some()
        || !parameters.resume_bindings.is_empty()
    {
        return Err("an enrich step with httpUri, body or resumeBindings is not served".into());
    }
    for expression in parameters.query.values() {
        check_expression("query", expression)?;
    }
    for expression in parameters.path_parameters.values() {
        check_expression("pathParameters", expression)?;
    }
    parse_ok_range(parameters)?;
    if matches!(
        enrich.aggregation_strategy,
        Some(AggregationStrategy::GroupedBody {})
    ) {
        return Err("the grouped-body strategy is served for split only".into());
    }
    Ok(())
}

/// The JSON strategies' `properties` selectors compile under the declared
/// bounds before the route is registered, and the names they write stay
/// out of the engine's reserved `Adapter` namespace, the same line
/// `setProperty` holds (section 8.11.7).
fn check_strategy(strategy: Option<&AggregationStrategy>) -> Result<(), String> {
    if let Some(
        AggregationStrategy::JsonArrayAppend { properties, .. }
        | AggregationStrategy::JsonMerge { properties, .. },
    ) = strategy
    {
        for selector in properties.values() {
            compile_selector(selector)
                .map_err(|fault| format!("the strategy properties jsonpath {fault}"))?;
        }
        for name in properties.keys() {
            if name.starts_with(RESERVED_PROPERTY_PREFIX) {
                return Err(format!(
                    "the strategy may not write the reserved property {name}"
                ));
            }
        }
    }
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
    /// The pinned GraphQL query, filled by the loader on a `graphql`
    /// endpoint; `None` on every other endpoint and on a graphql
    /// endpoint a caller assembled without the loader.
    pub graphql: Option<crate::component::graphql::GraphQlQuery>,
    pub attempt: Duration,
    pub maximum_response_bytes: usize,
}

impl EndpointRuntime {
    /// Compile one endpoint's outbound state over its binding: the same
    /// construction the loader performs per endpoint, for callers that
    /// assemble a route context directly.
    pub fn compile(
        binding: &EndpointBinding,
        declared: &Endpoint,
        config: &AdapterRuntimeConfig,
        resolver: &SecretResolver,
    ) -> Result<Self, EgressFault> {
        let egress = EndpointEgress::compile(binding, declared, config, resolver)?;
        let base = format!(
            "{}{}",
            egress.origin().origin_url().trim_end_matches('/'),
            egress.origin().base_path()
        );
        Ok(Self {
            attempt: egress.attempt(),
            maximum_response_bytes: egress.maximum_response_bytes(),
            graphql: None,
            egress,
            base,
        })
    }
}

/// What a route run needs beside the exchange.
pub struct RouteContext<'a> {
    pub endpoints: &'a BTreeMap<String, EndpointRuntime>,
    pub scripts: &'a ScriptSet,
    pub resolver: &'a SecretResolver,
    /// The process-local breaker and throttle state of the deployment's
    /// routes, built at load and shared by every exchange.
    pub resilience: &'a crate::resilience::ResilienceRuntime,
    /// Every route the deployment declares, pack routes and instantiated
    /// templated routes, keyed by route id: the table a `to: direct:`
    /// send resolves against (section 8.11.7).
    pub routes: &'a RouteTable,
    /// The binding's `maximumUpstreamCalls`.
    pub maximum_upstream_calls: u64,
}

/// The deployment's declared routes by id, each entry the route's whole
/// step list, clauses and error handler included, so a direct call runs
/// its target under the target's own error handling. One route holds one
/// list for its whole lifetime: the binding that serves it and every
/// direct call into it run the same steps, so a breaker or throttler the
/// route guards with is the same node either way.
pub type RouteTable = BTreeMap<String, Arc<Vec<Step>>>;

/// Every `direct:` send the table holds resolves against the table
/// itself, so a route that calls a route the deployment never declared
/// is refused at load, not at the first exchange (section 8.11.7). The
/// authoring checks bound the call graph statically; this holds the
/// runtime's table to the same name discipline.
///
/// # Errors
///
/// The first undeclared `direct:` target, by route id.
pub fn check_direct_targets(routes: &RouteTable) -> Result<(), String> {
    let mut missing: Vec<&str> = Vec::new();
    for steps in routes.values() {
        registry_adapter_core::walk_steps(steps, &mut |step, _pointer| {
            if let Step::To(sent) = step {
                if sent.uri.component == SendComponent::Direct
                    && !routes.contains_key(&sent.uri.id)
                    && !missing.contains(&sent.uri.id.as_str())
                {
                    missing.push(sent.uri.id.as_str());
                }
            }
        });
    }
    if let Some(id) = missing.first() {
        return Err(format!(
            "the direct route {id} is declared by no route in the deployment"
        ));
    }
    Ok(())
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
/// error. A clause that `handled` its failure ends the route's own
/// remaining steps the same way, with one difference a `direct:` call
/// sees (section 8.11.7): the caller continues after a handled failure
/// and stops for a `stop`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Flow {
    Continue,
    Stop,
    Handled,
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
        direct_depth: 0,
        deadline: tokio::time::Instant::now() + deadline,
    };
    let body = run.run_route_body(steps);
    let result = tokio::time::timeout(deadline, body)
        .await
        .unwrap_or_else(|_| Err(RouteFailure::of(ErrorClass::BudgetExhausted)));
    let Run {
        exchange, events, ..
    } = run;
    RouteOutcome {
        result: result.map(|_| exchange),
        events,
    }
}

pub(crate) struct Run<'a, 'c> {
    pub(crate) context: &'a RouteContext<'c>,
    pub(crate) exchange: Exchange,
    events: Vec<RouteEvent>,
    sends: u64,
    /// How many `direct:` calls deep this run is. The authoring checks
    /// bound the call graph statically; this holds the same bound at
    /// run for a table that never saw them.
    direct_depth: u32,
    /// The instant the whole run must end by: a step that waits (the
    /// throttler's pause, a redelivery delay) refuses with its own class
    /// when the wait cannot finish before this, instead of letting the
    /// run's budget expire it as `budget.exhausted`.
    pub(crate) deadline: tokio::time::Instant,
}

impl Run<'_, '_> {
    /// Run one route's step list under that route's own error handling
    /// (section 8.7): the clauses and handler policy its top level
    /// declares, with a breaker block bare. The route the facade
    /// dispatches and the route a `to: direct:` send calls run through
    /// here alike; a `stop` anywhere in the body ends that route and is
    /// carried out as the flow.
    async fn run_route_body(&mut self, steps: &[Step]) -> Result<Flow, RouteFailure> {
        // The route's error handler: `noErrorHandler` withdraws every
        // clause, `defaultErrorHandler` supplies the redelivery policy
        // for a failing send no clause claims. The handler is held to
        // one by check_servable.
        let clauses_enabled = !steps.iter().any(
            |step| matches!(step, Step::ErrorHandler(handler) if handler.no_error_handler.is_some()),
        );
        let handler_policy = steps.iter().find_map(|step| match step {
            Step::ErrorHandler(handler) => handler
                .default_error_handler
                .as_ref()
                .and_then(|handler| handler.redelivery_policy.as_ref()),
            _ => None,
        });
        let clauses: Vec<&OnExceptionStep> = if clauses_enabled {
            steps
                .iter()
                .filter_map(|step| match step {
                    Step::OnException(clause) => Some(clause),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };
        for step in steps.iter().filter(|s| !matches!(s, Step::OnException(_))) {
            // A breaker and its steps run bare (section 8.7): the route
            // error handler does not wrap them, so no clause claims
            // their failures and no policy redelivers them.
            let attempted = match step {
                Step::CircuitBreaker(_) => self.step(step).await,
                other => {
                    self.step_with_clauses(other, &clauses, handler_policy)
                        .await
                }
            };
            match attempted {
                Ok(Flow::Continue) => {}
                ended @ (Ok(Flow::Stop) | Ok(Flow::Handled)) => return ended,
                Err(failure) => return Err(failure),
            }
        }
        Ok(Flow::Continue)
    }
}

impl Run<'_, '_> {
    /// Run one body step; on failure, apply the closest matching clause:
    /// redeliver an upstream send while the policy allows, then run the
    /// clause's steps. An error inside a clause is final. A `stop` in the
    /// step or in the clause's steps ends the route without failing.
    ///
    /// Redelivery reaches only a failing upstream component send
    /// (section 8.7): the matched clause's policy for its classes, the
    /// handler's for every other failure. `retryWhile` only stops
    /// redelivery earlier; `maximumRedeliveries` stays the hard cap.
    async fn step_with_clauses(
        &mut self,
        step: &Step,
        clauses: &[&OnExceptionStep],
        handler_policy: Option<&RedeliveryOptions>,
    ) -> Result<Flow, RouteFailure> {
        let mut redeliveries = 0_u32;
        let mut previous_delay: Option<Duration> = None;
        loop {
            let failure = match self.step(step).await {
                Ok(flow) => return Ok(flow),
                Err(failure) => failure,
            };
            let clause = self.select_clause(&failure, clauses);
            // Redelivery reaches only a failing upstream send, never a
            // direct call (section 8.11.7): the target's own sends carry
            // their redelivery inside the target.
            let endpoint_send =
                matches!(step, Step::To(sent) if sent.uri.component != SendComponent::Direct);
            let policy = match (clause, endpoint_send) {
                (Some(clause), true) => clause.redelivery_policy.as_ref().or(handler_policy),
                (None, true) => handler_policy,
                _ => None,
            };
            if let Some(policy) = policy {
                if redeliveries < policy.maximum_redeliveries.get()
                    && self.retry_while_allows(policy)
                {
                    redeliveries += 1;
                    let delay = crate::processor::redelivery::calculate_redelivery_delay(
                        previous_delay,
                        policy,
                        crate::processor::redelivery::draw_variance(policy),
                    );
                    previous_delay = Some(delay);
                    self.record(
                        "exchangeRedelivery",
                        json!({
                            "class": failure.class.class(),
                            "counter": redeliveries,
                            "delaySeconds": delay.as_secs_f64(),
                        }),
                    );
                    tokio::time::sleep(delay).await;
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
            let Some(clause) = clause else {
                return Err(failure);
            };
            self.record(
                "exchangeFailureHandled",
                json!({ "class": failure.class.class() }),
            );
            let mut stopped = false;
            for clause_step in &clause.steps {
                // An error inside a clause replaces the failure and is final.
                if self.step(clause_step).await? == Flow::Stop {
                    stopped = true;
                    break;
                }
            }
            // `handled` ends the exchange successfully with the clause's
            // result and `continued` resumes the route after the failure
            // point; with neither, the failure surfaces (section 8.7).
            // A `stop` inside the clause's steps outranks both: it ends
            // the whole route, a `direct:` caller included.
            if stopped {
                return Ok(Flow::Stop);
            }
            if clause.handled == Some(true) {
                return Ok(Flow::Handled);
            }
            if clause.continued == Some(true) {
                return Ok(Flow::Continue);
            }
            return Err(failure);
        }
    }

    /// Whether the policy's `retryWhile` still allows another redelivery:
    /// absent is yes; a predicate that does not hold, or one that raises,
    /// stops the redelivery (section 8.7).
    fn retry_while_allows(&self, policy: &RedeliveryOptions) -> bool {
        policy
            .retry_while
            .as_ref()
            .is_none_or(|condition| self.predicate(condition).unwrap_or(false))
    }

    /// One journal-bound engine event.
    pub(crate) fn record(&mut self, kind: &'static str, detail: Value) {
        self.events.push(RouteEvent {
            kind,
            at: SystemTime::now(),
            detail,
        });
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
                match self.step(step).await? {
                    Flow::Continue => {}
                    // A nested body holds no clauses of its own, so it
                    // only ever sees a `stop`; should a deeper clause's
                    // `handled` reach here, the body ends the same way.
                    Flow::Stop | Flow::Handled => return Ok(Flow::Stop),
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
            Step::Split(split) => processor::split::run(self, split).await,
            Step::Loop(counted) => processor::r#loop::run(self, counted).await,
            // Boxed: enrich sends through this same dispatcher, so an
            // unboxed pair of futures would recurse without bound.
            Step::Enrich(enrich) => Box::pin(processor::enrich::run(self, enrich)).await,
            // Boxed the same way: the block's steps dispatch through
            // this dispatcher too.
            Step::DoTry(block) => Box::pin(processor::do_try::run(self, block)).await,
            // Boxed for the same reason, and keyed by the step's address
            // into the operation's resilience state.
            Step::CircuitBreaker(breaker) => {
                let key = std::ptr::from_ref(step) as usize;
                Box::pin(processor::circuit_breaker::run(self, breaker, key)).await
            }
            Step::Throttle(throttle) => {
                let key = std::ptr::from_ref(step) as usize;
                Box::pin(processor::throttle::run(self, throttle, key)).await
            }
            // Configuration the runner collected before the first step;
            // in the body it runs nothing.
            Step::ErrorHandler(_) => Ok(Flow::Continue),
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
        if to.uri.component == SendComponent::Direct {
            return self.direct(to).await;
        }
        // A graphql send names its variables in `body`, so its parameters
        // are optional; every other send carries them.
        let graphql = to.uri.component == SendComponent::GraphQl;
        let parameters = if graphql {
            to.parameters.as_ref()
        } else {
            Some(
                to.parameters
                    .as_ref()
                    .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?,
            )
        };
        let endpoint = self
            .context
            .endpoints
            .get(&to.uri.id)
            .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
        self.sends += 1;
        if self.sends > self.context.maximum_upstream_calls {
            return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
        }
        let ok_range = match parameters.map(parse_ok_range) {
            Some(Ok(range)) => range,
            // A refused range never reaches the transport: the authoring
            // checks hold it, and a graphql send declares none.
            Some(Err(_)) | None => DEFAULT_OK_RANGE,
        };
        // A graphql send posts one document over the endpoint's base link:
        // the pinned query text, the endpoint's operation name, and the
        // variables the send's body member yields, or the endpoint's
        // expression when the send carries none (section 8.8). Every
        // other send travels in the query string.
        let mut post_body: Option<Vec<u8>> = None;
        let link = if graphql {
            let query = endpoint
                .graphql
                .as_ref()
                .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
            let variables = match parameters
                .and_then(|parameters| parameters.body.as_ref())
                .or(query.variables.as_ref())
            {
                Some(expression) => self.eval(expression)?,
                None => Value::Null,
            };
            if !variables.is_null() && !variables.is_object() {
                return Err(RouteFailure {
                    class: ErrorClass::Validation,
                    message: Some("graphql variables must yield an object".to_owned()),
                    auth: None,
                });
            }
            let mut request = json!({ "query": query.text, "variables": variables });
            if let Some(operation) = &query.operation {
                request["operationName"] = json!(operation);
            }
            post_body = Some(serde_json::to_vec(&request).expect("a graphql request serializes"));
            endpoint.base.clone()
        } else {
            let parameters = parameters.expect("an http send always carries parameters");
            if let Some(expression) = &parameters.http_uri {
                self.pinned_link(&endpoint.egress, expression)?
            } else {
                let path = self.render_path(parameters)?;
                let query = self.render_query(parameters)?;
                let link = format!("{}{path}{query}", endpoint.base);
                // A link the destination's URL bound cannot hold names nothing the
                // source can serve: it is answered as no such record, before any
                // credential is acquired and with no send.
                if endpoint.egress.origin().pin(&link) == Err(LinkRefusal::TooLong) {
                    return Err(RouteFailure::of(ErrorClass::OutcomeNotFound));
                }
                link
            }
        };

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
        let method = if post_body.is_some() { "POST" } else { "GET" };
        let mut sending = json!({ "endpoint": to.uri.id, "method": method, "operation": parameters.and_then(|parameters| parameters.operation.as_ref()).map(|o| o.as_str()) });
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
                shape: match &post_body {
                    Some(bytes) => SendShape::Post(SendBody {
                        format: SendBodyFormat::Json,
                        bytes,
                    }),
                    None => SendShape::Get,
                },
                authorization: credential.as_ref().map(|c| &c.header),
                attempt: endpoint.attempt,
                maximum_response_bytes: endpoint.maximum_response_bytes,
                ok_status_range: ok_range,
                throw_exception_on_failure: parameters
                    .map(|parameters| parameters.throw_exception_on_failure)
                    .unwrap_or(false),
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
                // A GraphQL `errors` array fails the exchange (section
                // 8.8), whatever the status said: the reply keeps its
                // body and status on the exchange for a clause to read,
                // and the failure carries the declared detail only,
                // never the source's error text. Partial data fails with
                // it.
                if graphql {
                    let failed = message
                        .body
                        .get("errors")
                        .and_then(|errors| errors.as_array())
                        .is_some_and(|errors| !errors.is_empty());
                    if failed {
                        return Err(RouteFailure {
                            class: ErrorClass::UpstreamHttp,
                            message: Some("the graphql reply carries an errors array".to_owned()),
                            auth: None,
                        });
                    }
                    // The `data` member is the body (section 8.8); a
                    // reply without one leaves JSON null.
                    message.body = message.body.get("data").cloned().unwrap_or(Value::Null);
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
    /// One synchronous in-process call (section 8.11.7): the target
    /// route runs on this same exchange under its own clauses, an
    /// unhandled error propagates unchanged to the caller's clauses, and
    /// the call is never redelivered. The authoring checks hold the call
    /// graph acyclic and bounded; the depth counter holds the bound at
    /// run for a table that never saw them.
    async fn direct(&mut self, to: &ToStep) -> Result<Flow, RouteFailure> {
        if to.parameters.is_some() {
            return Err(RouteFailure::of(ErrorClass::EgressRefused));
        }
        let Some(target) = self.context.routes.get(&to.uri.id) else {
            return Err(RouteFailure::of(ErrorClass::EgressRefused));
        };
        if self.direct_depth >= registry_adapter_core::MAX_DIRECT_DEPTH as u32 {
            return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
        }
        self.direct_depth += 1;
        // One boxed edge holds the cycle this call closes (direct to a
        // route body to a step to a send back to direct); the call graph
        // is bounded, so the box is bounded with it.
        let outcome = Box::pin(self.run_route_body(target)).await;
        self.direct_depth -= 1;
        // A `stop` in the target ends the caller's route too, the way a
        // stop in any nested body does; a failure the target's own
        // clause handled ends only the target, and the caller continues
        // (section 8.11.7).
        match outcome {
            Ok(Flow::Handled) => Ok(Flow::Continue),
            outcome => outcome,
        }
    }

    /// One origin-pinned link (section 8.11.5): the expression must
    /// yield a string, the parsed link must stay inside the endpoint's
    /// origin and base path, and the parsed value is what the engine
    /// sends, never a reparse. Every pin refusal is the uncatchable
    /// `egress.refused`, raised before any credential is acquired or
    /// send announced.
    fn pinned_link(
        &self,
        egress: &EndpointEgress,
        expression: &Expression,
    ) -> Result<String, RouteFailure> {
        let link = match self.eval(expression)? {
            Value::String(link) => link,
            _ => {
                return Err(RouteFailure {
                    class: ErrorClass::Validation,
                    message: Some("an httpUri must yield a string".to_owned()),
                    auth: None,
                })
            }
        };
        match egress.origin().pin(&link) {
            // The parsed link's own serialization is the value sent;
            // the sender never sees the expression's raw text.
            Ok(pinned) => Ok(pinned.as_url().as_str().to_owned()),
            Err(_) => Err(RouteFailure::of(ErrorClass::EgressRefused)),
        }
    }

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
                graphql: None,
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
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
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
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
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
