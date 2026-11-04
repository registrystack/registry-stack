// SPDX-License-Identifier: Apache-2.0

//! The route model (`products/adapter/CONCEPT.md` sections 8.3 and 8.4).
//!
//! A route run interprets the ordered EIP steps compiled from pack routes
//! and instantiated route templates. The authored YAML follows Camel's DSL:
//! steps are an externally tagged union keyed by the Camel EIP name. The
//! engine's boundedness rules hold here: authored routes have one `direct:`
//! consumer, the route call graph is acyclic and depth bounded, every `loop`
//! and `split` declares its maximum, and inline code is refused, so `rhai`
//! always names a digest-pinned file.
//!
//! Route templates carry typed parameters instantiated at `check` time and
//! startup, never per request. The runtime table stores the resulting step
//! lists by route id; the `direct:<routeId>` consumer is represented by that
//! table key rather than interpreted as a step.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use registry_adapter_core::{
    effective_clause_redelivery_policy, is_facade_input_header_name,
    is_route_unwritable_header_name, is_route_unwritable_property_name, origin_relative_path_fault,
    path_parameter_faults, problem_data_schema, resolve_problem, validate_result_schema,
    AdapterEndpointBindings, AdapterProfile, AggregationStrategy, ConvertStep, Endpoint,
    EndpointBinding, EnrichStep, ErrorClass, Expression, GraphQlOperationKind, HttpMethod,
    OnExceptionStep, RecordLocator, RedeliveryOptions, SendComponent, SetPropertyStep, Step,
    ToParameters, ToStep, MAX_PROBLEM_DATA_BYTES, RESUME_PROPERTY_PREFIX,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Map, Value};

use crate::async_completion::{
    fresh_status_exchange, validate_status_outcome, AsyncSourceAcceptance, AsyncStatusPollOutcome,
    ServedAsyncOperation,
};
use crate::auth::{
    AuthError, AuthEvent, AuthKind, PlatformAssertionSigner, TokenBudget, UpstreamStatusAction,
};
use crate::component::http::uri::{encode_path_segment, percent_encode, LinkRefusal};
use crate::egress::{
    EgressError, EgressFault, EndpointEgress, OkStatusCodeRanges, OutboundSend,
    ProtocolOutboundSend, ProtocolSentReply, SendBody, SendBodyFormat, SendShape, SentReply,
    SourceRecoveryHeader,
};
use crate::exchange::{
    Exchange, ResumeExecution, FILTERS_PROPERTY, NEXT_CONTINUATION_PROPERTY, REDELIVERED_HEADER,
    REDELIVERY_COUNTER_HEADER, REDELIVERY_MAX_COUNTER_HEADER,
};
use crate::host_protocol::{
    HostProtocolMethod, HostProtocolRequestContext, HostProtocolResponseRefusal,
    HostProtocolResponseVerifier, HostProtocolWireResponse, PreparedHostProtocolBody,
};
use crate::language::{compile_selector, JsonPathResult, LanguageError};
use crate::processor;
use crate::scripts::ScriptSet;

/// The step kinds this runtime interprets. Every other kind of the route
/// model is refused at load by [`check_servable`], by name.
/// The longest one exchange may run, across every attempt, redelivery
/// pause, and script. It sits above the largest declared attempt timeout so
/// a single attempt always finishes under its own timeout first.
/// Absolute execution bound for one facade route, also used to bound durable recovery leases.
pub const EXCHANGE_DEADLINE: Duration = Duration::from_secs(60);

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
    check_steps(steps, false, false, false)
}

/// The served-shape walk for a listener-free Evidence route. Evidence starts
/// from validated JSON inputs rather than a facade exchange, so a pack may
/// use facade-input header names as its own internal values. Engine-owned
/// headers and every other served-step restriction remain unchanged.
pub(crate) fn check_evidence_servable(steps: &[Step]) -> Result<(), String> {
    if steps
        .iter()
        .filter(|step| matches!(step, Step::ErrorHandler(_)))
        .count()
        > 1
    {
        return Err("a route carries more than one errorHandler step".to_owned());
    }
    check_steps(steps, false, false, true)
}

/// The same served-shape walk for a job source route
/// (`products/adapter/CONCEPT.md` section 17.2): the one difference is
/// the pollEnrich read step, which the job compiler serves and the
/// facade never does.
pub(crate) fn check_job_servable(steps: &[Step]) -> Result<(), String> {
    if steps
        .iter()
        .filter(|step| matches!(step, Step::ErrorHandler(_)))
        .count()
        > 1
    {
        return Err("a route carries more than one errorHandler step".to_owned());
    }
    check_steps(steps, false, true, false)
}

/// The served shape of a `pollEnrich` read: a static `file:`, `rabbitmq:`, or `sftp:`
/// uri and a mandatory timeout (`products/adapter/CONCEPT.md` sections
/// 17.1 and 17.2). The authoring checks hold the endpoint and the
/// decoder; the engine holds the step shape again so a source route
/// assembled without them is refused by name.
fn check_poll(poll: &registry_adapter_core::PollEnrichStep) -> Result<(), String> {
    match registry_adapter_core::SendUri::parse(&poll.uri) {
        Some(uri)
            if matches!(
                uri.component,
                SendComponent::File | SendComponent::RabbitMq | SendComponent::Sftp
            ) => {}
        _ => {
            return Err(
                "a pollEnrich step is served over a file:, rabbitmq:, or sftp: endpoint only"
                    .to_owned(),
            );
        }
    }
    if poll.timeout_milliseconds.is_none() {
        return Err("a pollEnrich step declares no timeoutMilliseconds".to_owned());
    }
    if let Some(decoder) = &poll.decoder {
        if !registry_adapter_core::POLL_DECODER_NAMES.contains(&decoder.name()) {
            return Err("the pollEnrich names no decoder the engine carries".to_owned());
        }
    }
    if !poll.valid_key_pointer() {
        return Err(
            "a row decoder requires one bounded RFC 6901 keyPointer, forbidden for other decoders"
                .to_owned(),
        );
    }
    if matches!(
        poll.aggregation_strategy,
        Some(AggregationStrategy::GroupedBody {})
    ) {
        return Err("the grouped-body strategy is served for split only".to_owned());
    }
    Ok(())
}

fn check_steps(
    steps: &[Step],
    in_clause: bool,
    job_polls: bool,
    evidence_route: bool,
) -> Result<(), String> {
    // The redeliveries behind a clause's retryWhile are its own policy's,
    // or the route handler's when the clause declares none (section 8.7).
    // Nested bodies serve no errorHandler, so their clauses find none.
    let handler_policy = steps.iter().find_map(|step| match step {
        Step::ErrorHandler(handler) => handler
            .default_error_handler
            .as_ref()
            .and_then(|handler| handler.redelivery_policy.as_ref()),
        _ => None,
    });
    for step in steps {
        match step {
            Step::To(to) => check_to(to)?,
            // The poll is a job-only read step (section 17.2): the facade
            // never serves it, so a bound route carrying one is left
            // unserved by name, while a job source route is held to the
            // poll's own served shape.
            Step::PollEnrich(poll) if job_polls => check_poll(poll)?,
            Step::PollEnrich(_) => {
                return Err("a pollEnrich step is served in a job source route only".to_owned());
            }
            Step::SetBody(expression) => check_expression("setBody", expression)?,
            Step::Transform(expression) => check_expression("transform", expression)?,
            Step::SetHeader(header) => {
                if is_route_unwritable_header_name(&header.name)
                    && !(evidence_route && is_facade_input_header_name(&header.name))
                {
                    return Err(format!(
                        "setHeader may not write the read-only header {}",
                        header.name
                    ));
                }
                check_expression("setHeader", &header.value)?;
            }
            Step::SetProperty(property) => check_set_property(property)?,
            Step::RemoveHeader(name) => {
                if is_route_unwritable_header_name(name)
                    && !(evidence_route && is_facade_input_header_name(name))
                {
                    return Err(format!(
                        "removeHeader may not remove the read-only header {name}"
                    ));
                }
            }
            Step::RemoveProperty(name) => {
                if is_route_unwritable_property_name(name) {
                    return Err(format!(
                        "removeProperty may not remove the reserved property {name}"
                    ));
                }
            }
            Step::Script(expression) => check_expression("script", expression)?,
            Step::ConvertBodyTo(convert) => {
                check_convert("convertBodyTo", convert, evidence_route)?
            }
            Step::ConvertHeaderTo(convert) => {
                check_convert("convertHeaderTo", convert, evidence_route)?
            }
            Step::ConvertPropertyTo(convert) => {
                check_convert("convertPropertyTo", convert, evidence_route)?
            }
            Step::Choice(choice) => {
                for clause in &choice.when {
                    check_predicate("choice", &clause.predicate())?;
                    check_steps(&clause.steps, true, job_polls, evidence_route)?;
                }
                if let Some(otherwise) = &choice.otherwise {
                    check_steps(&otherwise.steps, true, job_polls, evidence_route)?;
                }
            }
            Step::Filter(filter) => {
                check_predicate("filter", &filter.predicate())?;
                if let Some(name) = &filter.status_property_name {
                    if is_route_unwritable_property_name(name) || name == NEXT_CONTINUATION_PROPERTY
                    {
                        return Err(format!(
                            "filter statusPropertyName may not take the reserved name {name}"
                        ));
                    }
                }
                check_steps(&filter.steps, true, job_polls, evidence_route)?;
            }
            Step::Validate(validate) => {
                check_predicate_expression("validate", &validate.expression)?
            }
            Step::ValidateSchema(_) => {}
            Step::Stop(_) => {}
            Step::ThrowException(throw) => {
                if let Some(data) = &throw.data {
                    check_expression("throwException data", data)?;
                }
            }
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
                check_steps(&split.steps, true, job_polls, evidence_route)?;
            }
            Step::Loop(looped) => {
                match looped.language_members() {
                    0 => {
                        return Err(
                            "the loop step carries no count or predicate language key".to_owned()
                        );
                    }
                    1 => {}
                    _ => {
                        return Err(
                            "the loop step carries more than one count or predicate language key"
                                .to_owned(),
                        );
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
                check_steps(&looped.steps, true, job_polls, evidence_route)?;
            }
            Step::Enrich(enrich) => {
                check_enrich(enrich)?;
                check_strategy(enrich.aggregation_strategy.as_ref())?;
            }
            Step::IdempotentConsumer(idempotent) => {
                if idempotent.steps.is_empty() {
                    return Err("an idempotentConsumer guards no steps".to_owned());
                }
                if !matches!(
                    &idempotent.expression,
                    Expression::Header(name) if name.eq_ignore_ascii_case("Idempotency-Key")
                ) {
                    return Err(
                        "an idempotentConsumer key must be the Idempotency-Key header".to_owned(),
                    );
                }
                check_steps(&idempotent.steps, true, job_polls, evidence_route)?;
            }
            Step::CircuitBreaker(breaker) => {
                if breaker.steps.is_empty() {
                    return Err("a circuitBreaker guards no steps".to_owned());
                }
                for (name, classes) in [
                    ("recordException", breaker.record_exception.as_ref()),
                    ("ignoreException", breaker.ignore_exception.as_ref()),
                ] {
                    if let Some(classes) = classes {
                        for class in classes.iter() {
                            if class.is_uncatchable() || class.is_facade() {
                                return Err(format!(
                                    "a circuitBreaker {name} may not name the class {}",
                                    class.class()
                                ));
                            }
                        }
                    }
                }
                // A minimum above the window can never be reached inside
                // it, so the breaker would never judge (section 8.7).
                if breaker.minimum_number_of_calls.get() > breaker.sliding_window_calls.get() {
                    return Err(
                        "a circuitBreaker judges from more calls than its window holds".to_owned(),
                    );
                }
                if evidence_route {
                    for (member, declared) in [
                        ("onFallback", breaker.on_fallback.is_some()),
                        ("ignoreException", breaker.ignore_exception.is_some()),
                        ("recordException", breaker.record_exception.is_some()),
                    ] {
                        if declared {
                            return Err(format!(
                                "an Evidence route circuitBreaker may not declare {member}: it would let a source failure continue as an answer; drop {member} so the breaker records every failure and an open breaker stays a failure"
                            ));
                        }
                    }
                }
                if let Some(fallback) = &breaker.on_fallback {
                    if fallback.steps.is_empty() {
                        return Err("an onFallback declares no steps".to_owned());
                    }
                    check_steps(&fallback.steps, true, job_polls, evidence_route)?;
                }
                check_steps(&breaker.steps, true, job_polls, evidence_route)?;
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
                check_steps(&throttle.steps, true, job_polls, evidence_route)?;
            }
            Step::OnException(clause) if !in_clause => {
                check_clause(clause, handler_policy, job_polls, evidence_route)?
            }
            Step::OnException(_) => {
                return Err("an onException clause is served at route top level only".to_owned());
            }
            Step::ErrorHandler(handler) => {
                if in_clause {
                    return Err("an errorHandler step is served at route top level only".to_owned());
                }
                if let Some(handler) = handler.default_error_handler.as_ref() {
                    check_retry_while(
                        "errorHandler",
                        handler.retry_while.as_ref(),
                        handler.redelivery_policy.as_ref(),
                    )?;
                }
            }
            Step::DoTry(block) => {
                if block.do_catch.is_empty() && block.do_finally.is_none() {
                    return Err("doTry declares neither doCatch nor doFinally".to_owned());
                }
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
                    if evidence_route {
                        check_evidence_catch(
                            "a doCatch may not catch",
                            &catch.exception,
                            catch.on_when.is_some(),
                        )?;
                    }
                    if let Some(expression) = &catch.on_when {
                        check_predicate_expression("doCatch onWhen", expression)?;
                    }
                    check_steps(&catch.steps, true, job_polls, evidence_route)?;
                }
                if let Some(finally) = &block.do_finally {
                    check_steps(&finally.steps, true, job_polls, evidence_route)?;
                }
                check_steps(&block.steps, true, job_polls, evidence_route)?;
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
/// The served shape of a conversion step (section 8.6). The authoring
/// checks hold it first; the engine repeats it so a route assembled
/// without them is refused by name, never silently misrun.
fn check_convert(form: &str, convert: &ConvertStep, evidence_route: bool) -> Result<(), String> {
    let body_form = form == "convertBodyTo";
    if body_form && (convert.name.is_some() || convert.to_name.is_some()) {
        return Err(format!(
            "a {form} declares no name or toName; it converts the body"
        ));
    }
    if !body_form && convert.name.is_none() {
        return Err(format!("a {form} names no header or property to convert"));
    }
    if convert.name.is_none() && convert.to_name.is_some() {
        return Err("a conversion with toName and no name names no source".to_owned());
    }
    let reserved = |name: &str| match form {
        "convertHeaderTo" => {
            is_route_unwritable_header_name(name)
                && !(evidence_route && is_facade_input_header_name(name))
        }
        "convertPropertyTo" => is_route_unwritable_property_name(name),
        _ => false,
    };
    if let Some(name) = convert.name.as_deref() {
        if reserved(name) {
            return Err(format!(
                "a {form} may not use the reserved source name {name}"
            ));
        }
    }
    if let Some(name) = convert.to_name.as_deref() {
        if reserved(name) {
            return Err(format!(
                "a {form} may not use the reserved target name {name}"
            ));
        }
    }
    if convert.code_map_id().is_none() {
        return Err(format!(
            "a {form} names no code map; write type as codeMap:<id>"
        ));
    }
    Ok(())
}

fn check_set_property(property: &SetPropertyStep) -> Result<(), String> {
    if is_route_unwritable_property_name(&property.name) {
        return Err(format!(
            "setProperty may not write the reserved property {}",
            property.name
        ));
    }
    check_expression("setProperty", &property.value)
}

/// The failures an Evidence route must leave as failures: a source that is
/// down, slow, malformed or refusing, and the route's own script and schema
/// faults. Evidence maps them to `source.unavailable`; a handler that turned
/// one into a lookup answer would record an outage as "no record".
fn is_evidence_source_failure(class: ErrorClass) -> bool {
    class.is_within(ErrorClass::Upstream)
        || matches!(
            class,
            ErrorClass::BreakerOpen
                | ErrorClass::ThrottleRejected
                | ErrorClass::Script
                | ErrorClass::Validation
        )
}

/// An Evidence route handler may name a source failure only as an
/// `upstream.http` answer it selects with `onWhen`, such as a 404 status
/// test; every other source failure stays a failure.
fn check_evidence_catch(site: &str, classes: &[ErrorClass], on_when: bool) -> Result<(), String> {
    for class in classes {
        if *class == ErrorClass::UpstreamHttp && on_when {
            continue;
        }
        if is_evidence_source_failure(*class) {
            return Err(format!(
                "in an Evidence route {site} {}: a source failure must stay a failure, not become an answer; to answer a declared status such as 404, catch upstream.http with an onWhen status test, or use the registry-lookup-v1 host protocol",
                class.class()
            ));
        }
    }
    Ok(())
}

fn check_clause(
    clause: &OnExceptionStep,
    handler_policy: Option<&RedeliveryOptions>,
    job_polls: bool,
    evidence_route: bool,
) -> Result<(), String> {
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
    // A clause that only redelivers leaves the failure a failure; steps,
    // handled or continued can turn it into an answer.
    let retry_only =
        clause.steps.is_empty() && clause.handled != Some(true) && clause.continued != Some(true);
    if evidence_route && !retry_only {
        check_evidence_catch(
            "an onException clause may not handle",
            &clause.exception,
            clause.on_when.is_some(),
        )?;
    }
    if let Some(expression) = &clause.on_when {
        check_predicate_expression("onWhen", expression)?;
    }
    if let Some(expression) = &clause.retry_while {
        check_predicate_expression("retryWhile", expression)?;
    }
    check_retry_while(
        "onException",
        clause.retry_while.as_ref(),
        effective_clause_redelivery_policy(clause, handler_policy),
    )?;
    check_steps(&clause.steps, true, job_polls, evidence_route)
}

/// A `retryWhile` that could never fire, because no redelivery stands
/// behind it: the redeliveries are the site's own policy's, or none at
/// all when the site declares no policy (section 8.7).
fn check_retry_while(
    site: &str,
    retry_while: Option<&Expression>,
    policy: Option<&RedeliveryOptions>,
) -> Result<(), String> {
    if retry_while.is_some()
        && policy
            .map(|policy| policy.maximum_redeliveries.get())
            .unwrap_or(0)
            == 0
    {
        return Err(format!(
            "a {site} retryWhile has no redeliveries behind it; raise maximumRedeliveries or drop retryWhile"
        ));
    }
    Ok(())
}

/// Hold the engine's served static HTTP path to the core authoring grammar.
/// This runs during compilation, before endpoint authority or credentials are
/// bound, and is shared by `to` and `enrich`.
fn check_static_http_path(parameters: &ToParameters) -> Result<(), String> {
    let path = parameters
        .path
        .as_deref()
        .ok_or("an HTTP step without a path is not served")?;
    if let Some(fault) = origin_relative_path_fault(path) {
        return Err(format!("an HTTP path was refused: {fault}"));
    }
    if let Some((_, fault)) = path_parameter_faults(path, &parameters.path_parameters).first() {
        return Err(format!("an HTTP path was refused: {fault}"));
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
    if to.uri.component == SendComponent::SqliteExtract {
        let parameters = to
            .parameters
            .as_ref()
            .ok_or("a sqlite-extract send requires queryParameters")?;
        if parameters.http_method.is_some()
            || parameters.path.is_some()
            || parameters.http_uri.is_some()
            || !parameters.path_parameters.is_empty()
            || !parameters.query.is_empty()
            || parameters.ok_status_code_range.is_some()
            || parameters.body.is_some()
            || !parameters.resume_bindings.is_empty()
            || parameters.operation.is_some()
        {
            return Err("a sqlite-extract send carries queryParameters only".into());
        }
        for expression in parameters.query_parameters.values() {
            check_expression("queryParameters", expression)?;
        }
        return Ok(());
    }
    if to.uri.component == SendComponent::Postgres {
        #[cfg(feature = "job-postgres")]
        {
            // The postgres source send carries its named parameters and
            // nothing else: no address, method, body, or status range of
            // its own (section 8.10, the SQL row).
            let Some(parameters) = &to.parameters else {
                return Err("a postgres send declares no parameters".into());
            };
            if parameters.http_method.is_some()
                || parameters.path.is_some()
                || parameters.http_uri.is_some()
                || !parameters.path_parameters.is_empty()
                || !parameters.query.is_empty()
                || parameters.ok_status_code_range.is_some()
                || parameters.body.is_some()
                || !parameters.resume_bindings.is_empty()
                || parameters.operation.is_some()
            {
                return Err("a postgres send carries queryParameters only".into());
            }
            return Ok(());
        }
        #[cfg(not(feature = "job-postgres"))]
        {
            return Err(
                "the postgres source component is not compiled into this binary; use an adapter-job build with the job-postgres feature"
                    .into(),
            );
        }
    }
    if to.uri.component != SendComponent::Http {
        return Err("a to step is served for the http component only".into());
    }
    let Some(parameters) = &to.parameters else {
        return Err("a to step without parameters is not served".into());
    };
    if matches!(
        parameters.http_method,
        Some(HttpMethod::Put | HttpMethod::Patch)
    ) {
        return Err("a to step is served for GET or POST only in this slice".into());
    }
    if matches!(parameters.http_method, None | Some(HttpMethod::Get)) && parameters.body.is_some() {
        return Err("a GET to step carries no body".into());
    }
    if parameters.http_method == Some(HttpMethod::Post) {
        let Some(body) = &parameters.body else {
            return Err("a POST to step declares a body".into());
        };
        check_expression("body", body)?;
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
        check_static_http_path(parameters)?;
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

/// An `enrich` resource is either a parameter-free static `direct:` route or
/// the same served HTTP surface as a `to` send: GET, a declared path, and no
/// origin or body members. The strategy is checked beside it.
fn check_enrich(enrich: &EnrichStep) -> Result<(), String> {
    if enrich.uri.component == SendComponent::Direct {
        if enrich.parameters.is_some() {
            return Err("a direct enrich resource carries no parameters".into());
        }
    } else {
        if enrich.uri.component != SendComponent::Http {
            return Err("an enrich step is served for the http or direct component only".into());
        }
        let Some(parameters) = &enrich.parameters else {
            return Err("an enrich step without parameters is not served".into());
        };
        if !matches!(parameters.http_method, None | Some(HttpMethod::Get)) {
            return Err("an enrich step is served for GET only".into());
        }
        if parameters.http_uri.is_some()
            || parameters.body.is_some()
            || !parameters.resume_bindings.is_empty()
        {
            return Err("an enrich step with httpUri, body or resumeBindings is not served".into());
        }
        check_static_http_path(parameters)?;
        for expression in parameters.query.values() {
            check_expression("query", expression)?;
        }
        for expression in parameters.path_parameters.values() {
            check_expression("pathParameters", expression)?;
        }
        parse_ok_range(parameters)?;
    }
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
            if is_route_unwritable_property_name(name) || name == NEXT_CONTINUATION_PROPERTY {
                return Err(format!(
                    "the strategy may not write the reserved property {name}"
                ));
            }
        }
    }
    Ok(())
}

fn parse_ok_range(parameters: &ToParameters) -> Result<OkStatusCodeRanges, String> {
    let Some(text) = &parameters.ok_status_code_range else {
        return Ok(OkStatusCodeRanges::default());
    };
    let ranges = text
        .split(',')
        .map(|entry| {
            let (low, high) = match entry.split_once('-') {
                Some((low, high)) => (low.trim().parse().ok()?, high.trim().parse().ok()?),
                None => {
                    let code = entry.trim().parse().ok()?;
                    (code, code)
                }
            };
            Some((low, high))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "okStatusCodeRange is not a comma-separated status range list".to_owned())?;
    OkStatusCodeRanges::try_from_ranges(ranges)
        .map_err(|_| "okStatusCodeRange contains an invalid status range".to_owned())
}

/// One upstream endpoint as the interpreter reaches it.
#[derive(Clone, Debug)]
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
    /// HTTP POST operations whose endpoint declaration carries the
    /// reviewed `safeUpstream` claim. Other POST, PUT and PATCH sends
    /// are effects; GraphQL safety comes from the parsed query kind.
    pub safe_post_operations: BTreeSet<String>,
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
        config: &AdapterEndpointBindings,
        resolver: &SecretResolver,
    ) -> Result<Self, EgressFault> {
        let egress = EndpointEgress::compile(binding, declared, config, resolver)?;
        Ok(Self::from_egress(declared, egress))
    }

    pub(crate) fn compile_with_captured_ca(
        binding: &EndpointBinding,
        declared: &Endpoint,
        config: &AdapterEndpointBindings,
        resolver: &SecretResolver,
        captured_ca: Option<&[u8]>,
    ) -> Result<Self, EgressFault> {
        let egress = EndpointEgress::compile_with_captured_ca(
            binding,
            declared,
            config,
            resolver,
            captured_ca,
        )?;
        Ok(Self::from_egress(declared, egress))
    }

    pub(crate) fn compile_evidence_replay(
        declared: &Endpoint,
        transcript: Arc<crate::replay::ReplayTranscript>,
    ) -> Result<Self, EgressFault> {
        let egress = EndpointEgress::compile_evidence_replay(declared, transcript)?;
        Ok(Self::from_egress(declared, egress))
    }

    fn from_egress(declared: &Endpoint, egress: EndpointEgress) -> Self {
        let base = format!(
            "{}{}",
            egress.origin().origin_url().trim_end_matches('/'),
            egress.origin().base_path()
        );
        Self {
            attempt: egress.attempt(),
            maximum_response_bytes: egress.maximum_response_bytes(),
            graphql: None,
            safe_post_operations: declared
                .operations
                .iter()
                .filter(|operation| operation.safe_upstream)
                .map(|operation| operation.id.as_str().to_owned())
                .collect(),
            egress,
            base,
        }
    }

    /// Whether one data send is safe by reviewed semantic metadata,
    /// never by its rendered transport shape alone.
    fn send_is_safe(&self, component: SendComponent, parameters: Option<&ToParameters>) -> bool {
        match component {
            SendComponent::Direct => true,
            SendComponent::Http => {
                let method = parameters
                    .and_then(|parameters| parameters.http_method)
                    .unwrap_or(HttpMethod::Post);
                method.is_safe()
                    || method == HttpMethod::Post
                        && parameters
                            .and_then(|parameters| parameters.operation.as_ref())
                            .is_some_and(|operation| {
                                self.safe_post_operations.contains(operation.as_str())
                            })
            }
            SendComponent::GraphQl => self
                .graphql
                .as_ref()
                .is_some_and(|query| query.kind == Some(GraphQlOperationKind::Query)),
            // The read-only postgres source send repeats safely: one
            // parameterized SELECT under a read-only transaction. The
            // job-only file and sftp sources are never sends, so a send
            // that reaches one is not a safe data send (the loader
            // refuses it before any run).
            SendComponent::Postgres | SendComponent::SqliteExtract => true,
            SendComponent::File | SendComponent::RabbitMq | SendComponent::Sftp => false,
        }
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
    /// Every route the deployment declares, keyed by the direct name the
    /// active profile resolves: facade route id or Evidence `from` URI id.
    pub routes: &'a RouteTable,
    /// The deployment's declared code maps (section 8.6): the one
    /// table the conversion steps and the Rhai `code_map` helper read.
    pub code_maps: crate::scripts::CodeMaps,
    /// The binding's `maximumUpstreamCalls`.
    pub maximum_upstream_calls: u64,
    /// The governed-ingestion state a job source route runs under:
    /// empty in every facade deployment, whose routes carry no job step.
    pub job: crate::job_sources::JobPageState,
}

/// The deployment's declared routes by their profile-specific direct name,
/// each entry the route's whole step list, clauses and error handler included,
/// so a direct call runs its target under the target's own error handling.
/// One route holds one list for its whole lifetime: the binding that serves it
/// and every direct call into it run the same steps, so a breaker or throttler
/// the route guards with is the same node either way.
pub type RouteTable = BTreeMap<String, Arc<Vec<Step>>>;

/// Every `direct:` send the table holds resolves against the table
/// itself, so a route that calls a route the deployment never declared
/// is refused at load, not at the first exchange (section 8.11.7). The
/// authoring checks bound the call graph statically; this holds the
/// runtime's table to the same name discipline.
///
/// # Errors
///
/// The first undeclared `direct:` target, by direct name.
pub fn check_direct_targets(routes: &RouteTable) -> Result<(), String> {
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut missing: Vec<&str> = Vec::new();
    for (route, steps) in routes {
        let targets = edges.entry(route.as_str()).or_default();
        registry_adapter_core::walk_steps(steps, &mut |step, _pointer| {
            let target = match step {
                Step::To(sent) if sent.uri.component == SendComponent::Direct => {
                    Some(sent.uri.id.as_str())
                }
                Step::Enrich(enrich) if enrich.uri.component == SendComponent::Direct => {
                    Some(enrich.uri.id.as_str())
                }
                _ => None,
            };
            if let Some(target) = target {
                targets.push(target);
                if !routes.contains_key(target) && !missing.contains(&target) {
                    missing.push(target);
                }
            }
        });
    }
    if let Some(id) = missing.first() {
        return Err(format!(
            "the direct route {id} is declared by no route in the deployment"
        ));
    }

    fn visit<'a>(
        route: &'a str,
        edges: &BTreeMap<&'a str, Vec<&'a str>>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Option<&'a str> {
        if visiting.contains(route) {
            return Some(route);
        }
        if visited.contains(route) {
            return None;
        }
        visiting.insert(route);
        for target in edges.get(route).into_iter().flatten() {
            if let Some(cycle) = visit(target, edges, visiting, visited) {
                return Some(cycle);
            }
        }
        visiting.remove(route);
        visited.insert(route);
        None
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for route in edges.keys() {
        if let Some(cycle) = visit(route, &edges, &mut visiting, &mut visited) {
            return Err(format!(
                "the direct route graph contains a cycle at {cycle}"
            ));
        }
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

fn auth_failure(error: &AuthError, events: &[AuthEvent]) -> RouteFailure {
    let class = if *error == AuthError::BudgetExhausted {
        ErrorClass::BudgetExhausted
    } else {
        ErrorClass::from_class(error.class()).unwrap_or(ErrorClass::CredentialRejected)
    };
    let mut failure = RouteFailure::of(class);
    if !events.is_empty() {
        failure.auth = Some(Box::new(auth_events_detail(events)));
    }
    failure
}

fn evidence_terminal_failure(error: crate::evidence::EvidenceTerminalError) -> RouteFailure {
    let (class, code) = match error {
        crate::evidence::EvidenceTerminalError::Authority => {
            (ErrorClass::EgressRefused, "evidence.authority-refused")
        }
        crate::evidence::EvidenceTerminalError::Audit => {
            (ErrorClass::DisclosureViolation, "evidence.audit-failed")
        }
        crate::evidence::EvidenceTerminalError::Budget => {
            (ErrorClass::BudgetExhausted, "evidence.budget-exhausted")
        }
        crate::evidence::EvidenceTerminalError::Protocol => {
            (ErrorClass::DisclosureViolation, "evidence.protocol-failed")
        }
    };
    let mut failure = RouteFailure::of(class);
    failure.code = Some(code);
    failure
}

fn evidence_http_diagnostic(
    status: Option<u16>,
    refusal: Option<HostProtocolResponseRefusal>,
) -> Option<EvidenceHttpDiagnostic> {
    match status {
        Some(401) => Some(EvidenceHttpDiagnostic::Unauthorized),
        Some(403) => Some(EvidenceHttpDiagnostic::Forbidden),
        Some(404) => Some(
            if matches!(
                refusal,
                Some(HostProtocolResponseRefusal::DeclaredNotFoundMismatch)
            ) {
                EvidenceHttpDiagnostic::DeclaredNotFoundMismatch
            } else {
                EvidenceHttpDiagnostic::UndeclaredNotFound
            },
        ),
        Some(429) => Some(EvidenceHttpDiagnostic::RateLimited),
        Some(500..=599) => Some(EvidenceHttpDiagnostic::ServerError),
        _ if matches!(refusal, Some(HostProtocolResponseRefusal::Verification)) => {
            Some(EvidenceHttpDiagnostic::Verification)
        }
        _ => None,
    }
}

fn attach_evidence_http_diagnostic(
    failure: &mut RouteFailure,
    endpoint: &str,
    status: Option<u16>,
    refusal: Option<HostProtocolResponseRefusal>,
) {
    if let Some(cause) = evidence_http_diagnostic(status, refusal) {
        failure.evidence_diagnostic =
            Some(Box::new(EvidenceRouteDiagnostic::http(endpoint, cause)));
    }
}

enum PhysicalSendReply {
    Ordinary(Result<SentReply, EgressError>),
    Protocol {
        reply: Result<ProtocolSentReply, EgressError>,
        verifier: Box<dyn HostProtocolResponseVerifier>,
    },
}

impl PhysicalSendReply {
    fn response_bytes(&self) -> usize {
        match self {
            Self::Ordinary(Ok(reply)) => reply.response_bytes,
            Self::Protocol {
                reply: Ok(reply), ..
            } => reply.response_bytes,
            Self::Ordinary(Err(EgressError::Upstream(failure)))
            | Self::Protocol {
                reply: Err(EgressError::Upstream(failure)),
                ..
            } => failure.response_bytes,
            Self::Ordinary(Err(EgressError::Refused(_)))
            | Self::Protocol {
                reply: Err(EgressError::Refused(_)),
                ..
            } => 0,
        }
    }

    fn status(&self) -> Option<u16> {
        match self {
            Self::Ordinary(Ok(reply)) => Some(reply.status),
            Self::Protocol {
                reply: Ok(reply), ..
            } => Some(reply.status),
            Self::Ordinary(Err(EgressError::Upstream(failure)))
            | Self::Protocol {
                reply: Err(EgressError::Upstream(failure)),
                ..
            } => failure.status,
            Self::Ordinary(Err(EgressError::Refused(_)))
            | Self::Protocol {
                reply: Err(EgressError::Refused(_)),
                ..
            } => None,
        }
    }
}

/// How a route run failed: the class it raised and, when a
/// `throwException` raised it, the message that fills `problemDetail`.
#[derive(Clone)]
pub enum EvidenceRouteDiagnostic {
    Http {
        endpoint: String,
        cause: EvidenceHttpDiagnostic,
    },
    #[cfg(feature = "sqlite-extract")]
    Sqlite {
        endpoint: String,
        cause: crate::component::sqlite_extract::SqliteExtractError,
    },
}

/// Closed HTTP response facts retained only for the embedding Evidence host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceHttpDiagnostic {
    Unauthorized,
    Forbidden,
    RateLimited,
    ServerError,
    Verification,
    UndeclaredNotFound,
    DeclaredNotFoundMismatch,
}

impl EvidenceRouteDiagnostic {
    fn http(endpoint: impl Into<String>, cause: EvidenceHttpDiagnostic) -> Self {
        Self::Http {
            endpoint: endpoint.into(),
            cause,
        }
    }

    pub fn http_parts(&self) -> Option<(&str, EvidenceHttpDiagnostic)> {
        match self {
            Self::Http { endpoint, cause } => Some((endpoint, *cause)),
            #[cfg(feature = "sqlite-extract")]
            Self::Sqlite { .. } => None,
        }
    }

    #[cfg(feature = "sqlite-extract")]
    pub(crate) fn sqlite(
        endpoint: impl Into<String>,
        cause: crate::component::sqlite_extract::SqliteExtractError,
    ) -> Self {
        Self::Sqlite {
            endpoint: endpoint.into(),
            cause,
        }
    }

    #[cfg(feature = "sqlite-extract")]
    pub(crate) fn sqlite_parts(
        &self,
    ) -> Option<(&str, crate::component::sqlite_extract::SqliteExtractError)> {
        match self {
            Self::Http { .. } => None,
            Self::Sqlite { endpoint, cause } => Some((endpoint, *cause)),
        }
    }
}

impl fmt::Debug for EvidenceRouteDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { cause, .. } => formatter
                .debug_tuple("EvidenceRouteDiagnostic::Http")
                .field(cause)
                .finish(),
            #[cfg(feature = "sqlite-extract")]
            Self::Sqlite { .. } => {
                formatter.write_str("EvidenceRouteDiagnostic::Sqlite(<governed>)")
            }
        }
    }
}

#[derive(Clone)]
pub struct RouteFailure {
    pub class: ErrorClass,
    pub message: Option<String>,
    /// The unevaluated route never carries this value. A `throwException`
    /// may attach one evaluated JSON value within the hard problem-data
    /// byte bound; the facade still validates it against the selected
    /// problem's exact closed declaration before release.
    pub data: Option<Value>,
    /// The value-free authentication events of a send that failed at its
    /// credential, for the failure's own journal row.
    pub auth: Option<Box<Value>>,
    /// The closed engine-read code a job read or Evidence SQLite source
    /// raised. Job entries report their read code beside the class; Evidence
    /// maps its SQLite code to a categorical request failure.
    pub code: Option<&'static str>,
    /// A value-free source record ordinal for a job row refusal. This typed
    /// structural locator is never inferred from a problem message.
    pub record: Option<Box<RecordLocator>>,
    /// Evidence-only typed context retained separately from problem detail,
    /// journal data and authentication events.
    pub evidence_diagnostic: Option<Box<EvidenceRouteDiagnostic>>,
}

#[cfg(test)]
const _: () = assert!(
    std::mem::size_of::<RouteFailure>() < 128,
    "route failures must stay below Clippy's large Result error boundary"
);

impl fmt::Debug for RouteFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RouteFailure");
        debug.field("class", &self.class);
        debug.field("message", &self.message);
        debug.field("data", &self.data.as_ref().map(|_| "<redacted>"));
        debug.field("auth", &self.auth);
        debug.field("code", &self.code);
        debug.field("record", &self.record);
        debug.field(
            "evidence_diagnostic",
            &self.evidence_diagnostic.as_ref().map(|_| "<governed>"),
        );
        debug.finish()
    }
}

impl RouteFailure {
    pub fn of(class: ErrorClass) -> Self {
        Self {
            class,
            message: None,
            data: None,
            auth: None,
            code: None,
            record: None,
            evidence_diagnostic: None,
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

/// Which source-native status proof one host poll requests. The engine selects
/// the compiled route and, for uncertainty recovery, its one declared trusted
/// header; callers cannot supply either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsyncStatusPollKind {
    Primary,
    UncertaintyRecovery,
}

enum AsyncRoutePolicy<'a> {
    Initial(&'a ServedAsyncOperation),
    Status {
        recovery_endpoint: Option<&'a str>,
        recovery_header: Option<SourceRecoveryHeader>,
    },
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
    run_route_within_profile(
        context,
        None,
        steps,
        exchange,
        EXCHANGE_DEADLINE,
        crate::exchange::MAXIMUM_EXCHANGE_BYTES,
        None,
        None,
        None,
        None,
    )
    .await
}

fn transform_item_page(
    exchange: &mut Exchange,
    transform: &crate::project_transform::CompiledProjectTransform,
    support: &registry_adapter_core::SourceReadSupport,
    pagination: Option<&crate::load::ServedPagination>,
    code_maps: &crate::scripts::CodeMaps,
    absolute_deadline: tokio::time::Instant,
) -> Result<(), RouteFailure> {
    let mut page: registry_adapter_core::ItemPage =
        serde_json::from_value(exchange.message.body.clone())
            .map_err(|_| RouteFailure::of(ErrorClass::UpstreamMalformed))?;
    if page
        .items
        .iter()
        .any(|item| !crate::consultation::source_key_is_public_record_id(&item.key))
    {
        return Err(RouteFailure::of(ErrorClass::UpstreamMalformed));
    }
    match support {
        registry_adapter_core::SourceReadSupport::ReadOne { .. } => {
            if page.items.len() > 1 || page.next.as_ref().is_some_and(|next| !next.is_null()) {
                return Err(RouteFailure::of(ErrorClass::UpstreamMalformed));
            }
        }
        registry_adapter_core::SourceReadSupport::ReadPage { .. } => {
            let maximum = pagination
                .map(|pagination| pagination.page_size_maximum)
                .unwrap_or(1_000);
            if u64::try_from(page.items.len()).map_or(true, |count| count > maximum) {
                return Err(RouteFailure::of(ErrorClass::UpstreamMalformed));
            }
        }
    }
    let deadline = absolute_deadline.into_std();
    for item in &mut page.items {
        item.value = transform
            .apply(code_maps, &item.value, deadline)
            .map_err(project_transform_failure)?;
    }
    let mut wrapped = page
        .items
        .into_iter()
        .map(|item| {
            let mut record = Map::from_iter([
                ("recordIdentifier".to_owned(), Value::String(item.key)),
                ("domainData".to_owned(), item.value),
            ]);
            if let Some(revision) = item.revision {
                record.insert("revisionIdentifier".to_owned(), Value::String(revision));
            }
            Value::Object(record)
        })
        .collect::<Vec<_>>();
    exchange.message.body = match support {
        registry_adapter_core::SourceReadSupport::ReadOne { .. } => wrapped
            .pop()
            .ok_or_else(|| RouteFailure::of(ErrorClass::OutcomeNotFound))?,
        registry_adapter_core::SourceReadSupport::ReadPage { .. } => {
            match page.next {
                Some(next) if !next.is_null() => {
                    exchange.set_property(NEXT_CONTINUATION_PROPERTY, next);
                }
                _ => exchange.remove_property(NEXT_CONTINUATION_PROPERTY),
            }
            Value::Array(wrapped)
        }
    };
    exchange.ensure_bounded().map_err(RouteFailure::of)?;
    if std::time::Instant::now() > deadline {
        return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
    }
    Ok(())
}

fn project_transform_failure(
    error: crate::project_transform::ProjectTransformError,
) -> RouteFailure {
    use crate::project_transform::ProjectTransformError;
    match error {
        ProjectTransformError::Budget => RouteFailure::of(ErrorClass::BudgetExhausted),
        ProjectTransformError::OutputInvalid => RouteFailure::of(ErrorClass::DisclosureViolation),
        ProjectTransformError::TransformMissing
        | ProjectTransformError::ScriptMissing
        | ProjectTransformError::SchemaMissing
        | ProjectTransformError::ScriptInvalid
        | ProjectTransformError::SchemaInvalid
        | ProjectTransformError::Failed => RouteFailure::of(ErrorClass::Script),
    }
}

fn prepare_project_source_input(
    operation: &crate::load::ServedOperation,
    exchange: &mut Exchange,
) -> Result<(), RouteFailure> {
    let Some(support) = operation.read_support.as_ref() else {
        return Ok(());
    };
    let body = match (operation.operation.as_str(), support) {
        ("retrieve", registry_adapter_core::SourceReadSupport::ReadOne { inputs }) => {
            let [input] = &**inputs else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            let value = exchange
                .message
                .header("recordId")
                .filter(|value| value.as_str().is_some_and(|text| !text.is_empty()))
                .cloned()
                .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?;
            Value::Object(Map::from_iter([(input.as_str().to_owned(), value)]))
        }
        ("lookup", registry_adapter_core::SourceReadSupport::ReadOne { .. })
        | ("search", registry_adapter_core::SourceReadSupport::ReadPage { .. }) => exchange
            .property(FILTERS_PROPERTY)
            .and_then(Value::as_object)
            .cloned()
            .map(Value::Object)
            .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?,
        ("list", registry_adapter_core::SourceReadSupport::ReadPage { .. }) => {
            Value::Object(Map::new())
        }
        _ => return Err(RouteFailure::of(ErrorClass::Facade)),
    };
    if operation
        .project_input_schema
        .as_ref()
        .is_some_and(|schema| !schema.validates(&body))
    {
        return Err(RouteFailure::of(ErrorClass::FacadeInvalidField));
    }
    exchange.message.body = body;
    Ok(())
}

/// Run a route with the checked facade profile that governs any optional
/// `throwException.data`. A data-bearing throw without this trusted profile
/// fails closed as `disclosure.violation`; live serving and fixture replay
/// always call this entry point.
pub async fn run_route_with_profile(
    context: &RouteContext<'_>,
    profile: &AdapterProfile,
    steps: &[Step],
    exchange: Exchange,
) -> RouteOutcome {
    run_route_within_profile(
        context,
        Some(profile),
        steps,
        exchange,
        EXCHANGE_DEADLINE,
        crate::exchange::MAXIMUM_EXCHANGE_BYTES,
        None,
        None,
        None,
        None,
    )
    .await
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
    run_route_within_profile(
        context,
        None,
        steps,
        exchange,
        deadline,
        crate::exchange::MAXIMUM_EXCHANGE_BYTES,
        None,
        None,
        None,
        None,
    )
    .await
}

/// Run a job page's source route
/// (`products/adapter/CONCEPT.md` sections 17.1 and 17.2): the same
/// interpreter with the caller's deadline and the job profile's
/// retained-JSON ceiling instead of the facade's one-exchange budget,
/// which a job endpoint's raised response bound may exceed. The
/// interpreter itself is unchanged; no facade state is consulted.
pub async fn run_job_route(
    context: &RouteContext<'_>,
    steps: &[Step],
    exchange: Exchange,
    deadline: Duration,
    maximum_exchange_bytes: usize,
) -> RouteOutcome {
    run_route_within_profile(
        context,
        None,
        steps,
        exchange,
        deadline,
        maximum_exchange_bytes,
        None,
        None,
        None,
        None,
    )
    .await
}

/// Run one reviewed Evidence route call inside the acquisition's shared
/// deadline, data-operation, response-byte, and token budgets.
pub async fn run_evidence_route(
    context: &RouteContext<'_>,
    steps: &[Step],
    exchange: Exchange,
    acquisition: &crate::evidence::EvidenceAcquisition,
) -> RouteOutcome {
    let remaining = acquisition
        .deadline()
        .saturating_duration_since(tokio::time::Instant::now());
    run_route_within_profile(
        context,
        None,
        steps,
        exchange,
        remaining,
        acquisition.maximum_response_bytes(),
        Some(acquisition),
        None,
        None,
        None,
    )
    .await
}

/// Run a facade operation with its compiled asynchronous acceptance policy.
/// Every existing route entry point remains profile-neutral and therefore
/// treats a 202 as unsupported incomplete.
pub async fn run_served_route(
    context: &RouteContext<'_>,
    profile: &AdapterProfile,
    operation: &crate::load::ServedOperation,
    exchange: Exchange,
) -> RouteOutcome {
    run_served_route_until(
        context,
        profile,
        operation,
        exchange,
        tokio::time::Instant::now() + EXCHANGE_DEADLINE,
    )
    .await
}

/// Run a facade operation under the host's already-minted absolute deadline.
/// The host uses this same bound when it durably precommits asynchronous
/// recovery authority before a non-safe send.
pub async fn run_served_route_until(
    context: &RouteContext<'_>,
    profile: &AdapterProfile,
    operation: &crate::load::ServedOperation,
    mut exchange: Exchange,
    absolute_deadline: tokio::time::Instant,
) -> RouteOutcome {
    if operation.async_completion.is_some() && !exchange.has_write_custody() {
        return RouteOutcome {
            result: Err(RouteFailure::of(ErrorClass::Facade)),
            events: Vec::new(),
        };
    }
    let now = tokio::time::Instant::now();
    if absolute_deadline <= now || absolute_deadline.duration_since(now) > EXCHANGE_DEADLINE {
        return RouteOutcome {
            result: Err(RouteFailure::of(ErrorClass::BudgetExhausted)),
            events: Vec::new(),
        };
    }
    if operation.project_transform.is_some() {
        if let Err(failure) = prepare_project_source_input(operation, &mut exchange) {
            return RouteOutcome {
                result: Err(failure),
                events: Vec::new(),
            };
        }
    }
    let mut outcome = run_route_within_profile(
        context,
        Some(profile),
        &operation.steps,
        exchange,
        EXCHANGE_DEADLINE,
        crate::exchange::MAXIMUM_EXCHANGE_BYTES,
        None,
        Some(absolute_deadline),
        operation
            .async_completion
            .as_ref()
            .map(AsyncRoutePolicy::Initial),
        operation.resume.as_ref(),
    )
    .await;
    if let (Ok(exchange), Some(transform), Some(support)) = (
        outcome.result.as_mut(),
        operation.project_transform.as_ref(),
        operation.read_support.as_ref(),
    ) {
        if let Err(failure) = transform_item_page(
            exchange,
            transform,
            support,
            operation.pagination.as_ref(),
            &context.code_maps,
            absolute_deadline,
        ) {
            outcome.result = Err(failure);
        }
    }
    outcome
}

/// Execute one safe source-native status poll within the host's absolute
/// deadline. Route or DTO failures remain uncertain to the host.
pub async fn run_async_status_poll(
    context: &RouteContext<'_>,
    profile: &AdapterProfile,
    operation: &crate::load::ServedOperation,
    kind: AsyncStatusPollKind,
    source_operation_id: &str,
    exchange_id: &str,
    absolute_deadline: tokio::time::Instant,
) -> AsyncStatusPollOutcome {
    let Some(completion) = operation.async_completion.as_ref() else {
        return AsyncStatusPollOutcome {
            result: Err(RouteFailure::of(ErrorClass::Facade)),
            events: Vec::new(),
        };
    };
    let (status, recovery_endpoint, recovery_header) = match kind {
        AsyncStatusPollKind::Primary => (&completion.status, None, None),
        AsyncStatusPollKind::UncertaintyRecovery => {
            let Some(recovery) = completion.uncertainty.as_ref() else {
                return AsyncStatusPollOutcome {
                    result: Err(RouteFailure::of(ErrorClass::Facade)),
                    events: Vec::new(),
                };
            };
            let header = match SourceRecoveryHeader::try_new(
                &recovery.request_header,
                source_operation_id,
            ) {
                Ok(header) => header,
                Err(_) => {
                    return AsyncStatusPollOutcome {
                        result: Err(RouteFailure::of(ErrorClass::EgressRefused)),
                        events: Vec::new(),
                    }
                }
            };
            (
                &recovery.status,
                Some(completion.initial.endpoint.as_str()),
                Some(header),
            )
        }
    };
    let exchange = match fresh_status_exchange(exchange_id, source_operation_id) {
        Ok(exchange) => exchange,
        Err(failure) => {
            return AsyncStatusPollOutcome {
                result: Err(failure),
                events: Vec::new(),
            }
        }
    };
    let poll_context = RouteContext {
        endpoints: context.endpoints,
        scripts: context.scripts,
        resolver: context.resolver,
        resilience: context.resilience,
        routes: context.routes,
        code_maps: context.code_maps.clone(),
        maximum_upstream_calls: status.maximum_upstream_calls,
        job: crate::job_sources::JobPageState::default(),
    };
    let outcome = run_route_within_profile(
        &poll_context,
        Some(profile),
        &status.steps,
        exchange,
        EXCHANGE_DEADLINE,
        crate::exchange::MAXIMUM_EXCHANGE_BYTES,
        None,
        Some(absolute_deadline),
        Some(AsyncRoutePolicy::Status {
            recovery_endpoint,
            recovery_header,
        }),
        None,
    )
    .await;
    let result = outcome.result.and_then(|exchange| {
        let status = serde_json::from_value(exchange.message.body)
            .map_err(|_| RouteFailure::of(ErrorClass::DisclosureViolation))?;
        validate_status_outcome(operation, &status, Some(profile))?;
        Ok(status)
    });
    AsyncStatusPollOutcome {
        result,
        events: outcome.events,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_route_within_profile<'a>(
    context: &'a RouteContext<'_>,
    problem_profile: Option<&'a AdapterProfile>,
    steps: &[Step],
    exchange: Exchange,
    deadline: Duration,
    maximum_exchange_bytes: usize,
    evidence: Option<&'a crate::evidence::EvidenceAcquisition>,
    absolute_deadline: Option<tokio::time::Instant>,
    async_policy: Option<AsyncRoutePolicy<'a>>,
    resume_plan: Option<&'a crate::resume::ServedResumeOperation>,
) -> RouteOutcome {
    if let Err(class) = exchange.ensure_bounded_within(maximum_exchange_bytes) {
        return RouteOutcome {
            result: Err(RouteFailure::of(class)),
            events: Vec::new(),
        };
    }
    let absolute_deadline = absolute_deadline.unwrap_or_else(|| {
        evidence.map_or_else(
            || tokio::time::Instant::now() + deadline,
            crate::evidence::EvidenceAcquisition::deadline,
        )
    });
    let mut run = Run {
        context,
        problem_profile,
        exchange,
        events: Vec::new(),
        sends: 0,
        direct_depth: 0,
        exception_clause_depth: 0,
        token_budget: TokenBudget::new_exchange(),
        evidence,
        deferred_write_completion: None,
        failure_handled_for_completion: false,
        deadline: absolute_deadline,
        maximum_exchange_bytes,
        async_policy,
        async_source_acceptance: None,
        resume_plan,
        resume: None,
    };
    let body = run.run_route_body(steps);
    let mut result = tokio::time::timeout_at(absolute_deadline, body)
        .await
        .unwrap_or_else(|_| Err(RouteFailure::of(ErrorClass::BudgetExhausted)));
    if result.is_ok() {
        if let Err(class) = run.exchange.ensure_bounded_within(maximum_exchange_bytes) {
            result = Err(RouteFailure::of(class));
        }
    }
    // A proven source acceptance outranks every later local completion
    // callback. The host commits the accepted custody state; completing the
    // ordinary idempotent-consumer membership here could lose the only typed
    // acceptance marker behind a local repository error.
    if run.async_accepted() {
        result = Ok(Flow::Stop);
        run.deferred_write_completion = None;
    }
    if let Some(remove_on_failure) = run.deferred_write_completion.take() {
        let succeeded = run.completion_succeeded(result.is_ok());
        if let Err(failure) = run
            .exchange
            .complete_write_key(succeeded, remove_on_failure)
            .await
        {
            result = Err(failure);
        }
    }
    let Run {
        mut exchange,
        events,
        async_source_acceptance,
        ..
    } = run;
    if let Some(acceptance) = async_source_acceptance {
        if let Err(failure) = exchange.set_async_source_acceptance(acceptance) {
            return RouteOutcome {
                result: Err(failure),
                events,
            };
        }
    }
    RouteOutcome {
        result: result.map(|_| exchange),
        events,
    }
}

/// A script failure as a route failure: an unmapped lookup keeps its
/// map id in the message (section 8.6); the class alone answers for
/// the rest.
pub(crate) fn script_failure(failure: crate::scripts::ScriptFailure) -> RouteFailure {
    match failure {
        crate::scripts::ScriptFailure::Unmapped(_) => RouteFailure {
            class: failure.class(),
            message: Some(failure.to_string()),
            data: None,
            auth: None,
            code: None,
            record: None,
            evidence_diagnostic: None,
        },
        other => RouteFailure::of(other.class()),
    }
}

pub(crate) struct Run<'a, 'c> {
    pub(crate) context: &'a RouteContext<'c>,
    /// The checked facade profile whose closest problem declaration governs
    /// `throwException.data`. Absent in profile-neutral engine tests only.
    problem_profile: Option<&'a AdapterProfile>,
    pub(crate) exchange: Exchange,
    events: Vec<RouteEvent>,
    sends: u64,
    /// How many `direct:` calls deep this run is. The authoring checks
    /// bound the call graph statically; this holds the same bound at
    /// run for a table that never saw them.
    direct_depth: u32,
    /// Exception-clause steps are a terminal fallback scope. A `direct:`
    /// route called from one stays in that scope and cannot recursively
    /// activate the callee's own handler (section 8.7 divergence).
    exception_clause_depth: u32,
    /// Token endpoint calls are budgeted per endpoint across this whole
    /// exchange, including direct calls and redelivery.
    token_budget: TokenBudget,
    /// The acquisition-wide Evidence budget, absent from facade and job
    /// runs. Its token allowance and data-operation count survive repeated
    /// route calls in the same lookup.
    evidence: Option<&'a crate::evidence::EvidenceAcquisition>,
    /// A default `completionEager: false` idempotent consumer completes only
    /// after the whole top-level route, its timeout, and its final exchange
    /// bound. The durable completion call itself is outside that timeout.
    deferred_write_completion: Option<bool>,
    /// Camel's `FAILURE_HANDLED` exchange property for completion callbacks.
    /// A handled failure remains visible when `direct:` resumes its caller;
    /// `continued: true` explicitly clears it before resuming.
    failure_handled_for_completion: bool,
    /// The instant the whole run must end by: a step that waits (the
    /// throttler's pause, a redelivery delay) refuses with its own class
    /// when the wait cannot finish before this, instead of letting the
    /// run's budget expire it as `budget.exhausted`.
    pub(crate) deadline: tokio::time::Instant,
    /// The retained-JSON ceiling this run applies to the exchange: the
    /// facade's fixed budget, or the job profile's response bound for a
    /// job page run (section 17.2).
    pub(crate) maximum_exchange_bytes: usize,
    async_policy: Option<AsyncRoutePolicy<'a>>,
    async_source_acceptance: Option<AsyncSourceAcceptance>,
    resume_plan: Option<&'a crate::resume::ServedResumeOperation>,
    resume: Option<ResumeRun>,
}

struct ResumeRun {
    next_step: usize,
    cursor: usize,
    bindings: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
enum ResumeSend {
    Ordinary,
    Skip,
    Execute { ordinal: usize, checkpoint: bool },
}

impl Run<'_, '_> {
    pub(crate) fn async_accepted(&self) -> bool {
        self.async_source_acceptance.is_some()
    }

    pub(crate) fn begin_resume(
        &mut self,
        execution: Option<ResumeExecution>,
    ) -> Result<(), RouteFailure> {
        let Some(plan) = self.resume_plan else {
            return if execution.is_none() {
                Ok(())
            } else {
                Err(RouteFailure::of(ErrorClass::Facade))
            };
        };
        let (next_step, bindings) = execution.map_or_else(
            || (0, BTreeMap::new()),
            |execution| {
                (
                    usize::try_from(execution.next_step()).unwrap_or(usize::MAX),
                    execution.bindings().clone(),
                )
            },
        );
        if next_step >= plan.step_count() || !plan.validates_checkpoint(next_step, &bindings) {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        self.resume = Some(ResumeRun {
            next_step,
            cursor: 0,
            bindings,
        });
        Ok(())
    }

    fn resume_send(&mut self) -> Result<ResumeSend, RouteFailure> {
        let Some(resume) = self.resume.as_mut() else {
            return Ok(ResumeSend::Ordinary);
        };
        let plan = self
            .resume_plan
            .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?;
        let ordinal = resume.cursor;
        resume.cursor = resume
            .cursor
            .checked_add(1)
            .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?;
        if ordinal >= plan.step_count() || ordinal > resume.next_step {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        if ordinal < resume.next_step {
            return Ok(ResumeSend::Skip);
        }
        Ok(ResumeSend::Execute {
            ordinal,
            checkpoint: ordinal + 1 < plan.step_count(),
        })
    }

    async fn checkpoint_resume_reply(
        &mut self,
        send: ResumeSend,
        body: &Value,
    ) -> Result<(), RouteFailure> {
        let ResumeSend::Execute {
            ordinal,
            checkpoint: true,
        } = send
        else {
            return Ok(());
        };
        let bindings = self
            .resume_plan
            .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?
            .extract(ordinal, body)?;
        self.exchange
            .checkpoint_resume_step(
                u32::try_from(ordinal).map_err(|_| RouteFailure::of(ErrorClass::Facade))?,
                bindings.clone(),
            )
            .await?;
        self.events.push(RouteEvent {
            kind: "resumeStepCheckpointed",
            at: SystemTime::now(),
            detail: json!({
                "bindingCount": bindings.len(),
                "completedOrdinal": ordinal,
                "nextOrdinal": ordinal + 1,
            }),
        });
        let resume = self
            .resume
            .as_mut()
            .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?;
        for binding in bindings {
            resume
                .bindings
                .insert(binding.name().to_owned(), binding.value().to_owned());
        }
        resume.next_step = ordinal + 1;
        Ok(())
    }

    pub(crate) fn completion_succeeded(&self, completed_without_error: bool) -> bool {
        completed_without_error && !self.failure_handled_for_completion
    }

    pub(crate) fn defer_write_completion(
        &mut self,
        remove_on_failure: bool,
    ) -> Result<(), RouteFailure> {
        if self
            .deferred_write_completion
            .replace(remove_on_failure)
            .is_some()
        {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        Ok(())
    }

    /// Run one route's step list under that route's own error handling
    /// (section 8.7): the clauses and handler policy its top level
    /// declares, with breaker and top-level `doTry` blocks bare. The route the facade
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
        let handler_retry_while = steps.iter().find_map(|step| match step {
            Step::ErrorHandler(handler) => handler
                .default_error_handler
                .as_ref()
                .and_then(|handler| handler.retry_while.as_ref()),
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
            if self.async_accepted() {
                return Ok(Flow::Stop);
            }
            // A breaker and a top-level doTry run bare (section 8.7):
            // the route error handler does not wrap either scope.
            let attempted = match step {
                Step::CircuitBreaker(_) | Step::DoTry(_) => self.step(step).await,
                other => {
                    self.step_with_clauses(other, &clauses, handler_policy, handler_retry_while)
                        .await
                }
            };
            match attempted {
                Ok(Flow::Continue) if !self.async_accepted() => {}
                Ok(Flow::Continue) => return Ok(Flow::Stop),
                ended @ (Ok(Flow::Stop) | Ok(Flow::Handled)) => return ended,
                Err(failure) => return Err(failure),
            }
        }
        Ok(Flow::Continue)
    }

    /// Run a route body without its error handler or exception clauses.
    /// This is the terminal fallback scope used by a `direct:` call made
    /// from inside an exception clause (section 8.7 divergence).
    async fn run_route_body_bare(&mut self, steps: &[Step]) -> Result<Flow, RouteFailure> {
        for step in steps
            .iter()
            .filter(|step| !matches!(step, Step::OnException(_) | Step::ErrorHandler(_)))
        {
            if self.async_accepted() {
                return Ok(Flow::Stop);
            }
            let flow = self.step(step).await?;
            if self.async_accepted() {
                return Ok(Flow::Stop);
            }
            match flow {
                Flow::Continue => {}
                ended @ (Flow::Stop | Flow::Handled) => return Ok(ended),
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
    /// handler's for every other failure. The `retryWhile` in force
    /// follows the same split: a matched clause's own predicate governs
    /// its classes, the handler's governs every other failure. It only
    /// stops redelivery earlier; `maximumRedeliveries` stays the hard cap.
    async fn step_with_clauses(
        &mut self,
        step: &Step,
        clauses: &[&OnExceptionStep],
        handler_policy: Option<&RedeliveryOptions>,
        handler_retry_while: Option<&Expression>,
    ) -> Result<Flow, RouteFailure> {
        let mut redeliveries = 0_u32;
        let mut previous_delay: Option<Duration> = None;
        // Redelivery reaches only a failing upstream send, never a
        // direct call (section 8.11.7): the target's own sends carry
        // their redelivery inside the target.
        let endpoint_send =
            matches!(step, Step::To(sent) if sent.uri.component != SendComponent::Direct);
        let redeliverable = endpoint_send
            && (handler_policy.is_some()
                || clauses.iter().any(|clause| {
                    effective_clause_redelivery_policy(clause, handler_policy).is_some()
                }));
        // A failed send leaves the source's reply on the message for the
        // clauses and `retryWhile` to read; a redelivery resends the
        // request the first attempt rendered, from the message it started
        // with.
        let request = redeliverable.then(|| self.exchange.message.clone());
        loop {
            let failure = match self.step(step).await {
                Ok(_) if self.async_accepted() => return Ok(Flow::Stop),
                Ok(flow) => return Ok(flow),
                Err(failure) => failure,
            };
            let clause = self.select_clause(&failure, clauses);
            let retryable_upstream = failure.class.is_within(ErrorClass::Upstream);
            let policy = match (clause, endpoint_send && retryable_upstream) {
                (Some(clause), true) => effective_clause_redelivery_policy(clause, handler_policy),
                (None, true) => handler_policy,
                _ => None,
            };
            // The predicate follows the clause that claimed the failure,
            // not the site the policy came from (section 8.7).
            let retry_while = match clause {
                Some(clause) => clause.retry_while.as_ref(),
                None => handler_retry_while,
            };
            if let Some(policy) = policy {
                if redeliveries < policy.maximum_redeliveries.get()
                    && self.retry_while_allows(retry_while)
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
                    if let Some(request) = &request {
                        self.exchange.message = request.clone();
                    }
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
            self.record_consumed_failure("onException", &failure);
            self.exception_clause_depth += 1;
            let clause_outcome = async {
                let mut stopped = false;
                for clause_step in &clause.steps {
                    // An error inside a clause replaces the failure and is final.
                    if self.step(clause_step).await? == Flow::Stop {
                        stopped = true;
                        break;
                    }
                }
                Ok::<bool, RouteFailure>(stopped)
            }
            .await;
            self.exception_clause_depth -= 1;
            let stopped = clause_outcome?;
            // `handled` ends the exchange successfully with the clause's
            // result and `continued` resumes the route after the failure
            // point; with neither, the failure surfaces (section 8.7).
            // A `stop` inside the clause's steps outranks both: it ends
            // the whole route, a `direct:` caller included.
            if stopped {
                return Ok(Flow::Stop);
            }
            if clause.handled == Some(true) {
                self.failure_handled_for_completion = true;
                return Ok(Flow::Handled);
            }
            if clause.continued == Some(true) {
                // Camel's `prepareExchangeForContinue` clears the handled
                // failure so completion-scoped EIPs see successful flow.
                self.failure_handled_for_completion = false;
                return Ok(Flow::Continue);
            }
            return Err(failure);
        }
    }

    /// Whether the `retryWhile` in force still allows another redelivery:
    /// absent is yes; a predicate that does not hold, or one that raises,
    /// stops the redelivery (section 8.7).
    fn retry_while_allows(&self, retry_while: Option<&Expression>) -> bool {
        retry_while.is_none_or(|condition| self.predicate(condition).unwrap_or(false))
    }

    /// One journal-bound engine event.
    pub(crate) fn record(&mut self, kind: &'static str, detail: Value) {
        self.events.push(RouteEvent {
            kind,
            at: SystemTime::now(),
            detail,
        });
    }

    /// Record a failure that an EIP consumed. `source` is closed here even
    /// though the cross-processor API is a static string, so no authored or
    /// upstream value can become a journal label.
    pub(crate) fn record_consumed_failure(&mut self, source: &'static str, failure: &RouteFailure) {
        let source = match source {
            "onException" => "onException",
            "doCatch" => "doCatch",
            "enrich" => "enrich",
            "split" => "split",
            "circuitBreaker" => "circuitBreaker",
            other => {
                debug_assert!(false, "unknown consumed-failure source: {other}");
                "engine"
            }
        };
        let mut detail = json!({
            "source": source,
            "class": failure.class.class(),
        });
        if let Some(auth) = &failure.auth {
            detail["auth"] = auth.as_ref().clone();
        }
        self.record("exchangeFailureHandled", detail);
    }

    /// Run a nested step body (an EIP branch, guarded block, or fallback):
    /// it has no route clauses of its own, failures bubble to the owning
    /// EIP, and `stop` ends the whole route. Boxed because nested bodies
    /// recursively dispatch through this interpreter.
    pub(crate) fn run_steps<'r>(
        &'r mut self,
        steps: &'r [Step],
    ) -> Pin<Box<dyn Future<Output = Result<Flow, RouteFailure>> + Send + 'r>> {
        Box::pin(async move {
            for step in steps {
                if self.async_accepted() {
                    return Ok(Flow::Stop);
                }
                let flow = self.step(step).await?;
                if self.async_accepted() {
                    return Ok(Flow::Stop);
                }
                match flow {
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
        self.ensure_deadline()?;
        self.ensure_exchange_bounded()?;
        let outcome = match step {
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
            Step::ConvertBodyTo(convert) => processor::convert::body(self, convert),
            Step::ConvertHeaderTo(convert) => processor::convert::header(self, convert),
            Step::ConvertPropertyTo(convert) => processor::convert::property(self, convert),
            Step::Choice(choice) => processor::choice::run(self, choice).await,
            Step::Filter(filter) => processor::filter::run(self, filter).await,
            Step::Validate(validate) => processor::validate::run(self, validate),
            Step::ValidateSchema(schema) => processor::validate_schema::run(self, schema),
            Step::Stop(_) => Ok(Flow::Stop),
            Step::ThrowException(throw) => {
                let data = match &throw.data {
                    Some(expression) => {
                        let value = self.eval(expression)?;
                        let within_bound = serde_json::to_vec(&value)
                            .is_ok_and(|bytes| bytes.len() <= MAX_PROBLEM_DATA_BYTES);
                        let declared = self
                            .problem_profile
                            .and_then(|profile| resolve_problem(profile, throw.exception_type))
                            .and_then(problem_data_schema)
                            .is_some_and(|schema| {
                                validate_result_schema(&value, &schema).is_empty()
                            });
                        if !within_bound || !declared {
                            return Err(RouteFailure::of(ErrorClass::DisclosureViolation));
                        }
                        Some(value)
                    }
                    None => None,
                };
                Err(RouteFailure {
                    class: throw.exception_type,
                    message: throw.message.clone(),
                    data,
                    auth: None,
                    code: None,
                    record: None,
                    evidence_diagnostic: None,
                })
            }
            // Keep the synchronous `direct:` call out of the endpoint-send
            // future. That future carries every transport and authentication
            // state, and polling one at every bounded direct hop can exhaust
            // the executor thread's stack before the depth guard runs.
            Step::To(to) if to.uri.component == SendComponent::Direct => {
                Box::pin(self.direct(to)).await
            }
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
            Step::IdempotentConsumer(idempotent) => {
                Box::pin(processor::idempotent_consumer::run(self, idempotent)).await
            }
            // A job-only read step. A route that reaches the interpreter
            // with one was never checked: the facade loader refuses the
            // step by name and the job compiler serves it, so the
            // runtime holds the boundary, uncatchably, before anything
            // reads a source. The gate holds the same line in a build
            // that compiles no file source.
            #[cfg(any(feature = "job-file", feature = "job-rabbitmq"))]
            Step::PollEnrich(poll) => Box::pin(processor::poll_enrich::run(self, poll)).await,
            #[cfg(not(any(feature = "job-file", feature = "job-rabbitmq")))]
            Step::PollEnrich(_) => Err(RouteFailure {
                class: ErrorClass::EgressRefused,
                message: Some(
                    "a pollEnrich step reads a job source, and no job source component is compiled into this binary; use an adapter-job build with the job-file or job-rabbitmq feature".to_owned(),
                ),
                data: None,
                auth: None,
                code: Some("adapter.job.component-unavailable"),
                record: None,
                evidence_diagnostic: None,
            }),
            // Configuration the runner collected before the first step;
            // in the body it runs nothing.
            Step::ErrorHandler(_) | Step::OnException(_) => Ok(Flow::Continue),
        };
        self.ensure_exchange_bounded()?;
        outcome
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
                if let Some(binding) = name.strip_prefix(RESUME_PROPERTY_PREFIX) {
                    return self
                        .resume
                        .as_ref()
                        .and_then(|resume| resume.bindings.get(binding))
                        .cloned()
                        .map(Value::String)
                        .ok_or_else(|| RouteFailure::of(ErrorClass::Facade));
                }
                Ok(self.exchange.property(name).cloned().unwrap_or(Value::Null))
            }
            Expression::Rhai(script) => {
                self.ensure_deadline()?;
                self.context
                    .scripts
                    .call_with_deadline(
                        &self.context.code_maps,
                        &script.file,
                        &script.entrypoint,
                        &self.exchange.as_script_value(),
                        self.deadline.into_std(),
                    )
                    .map_err(script_failure)
            }
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

    /// Refuse work that begins at or after the route-wide deadline. The
    /// outer timeout remains the final guard for an in-flight operation.
    pub(crate) fn ensure_deadline(&self) -> Result<(), RouteFailure> {
        if tokio::time::Instant::now() >= self.deadline {
            Err(RouteFailure::of(ErrorClass::BudgetExhausted))
        } else {
            Ok(())
        }
    }

    fn ensure_exchange_bounded(&self) -> Result<(), RouteFailure> {
        self.exchange
            .ensure_bounded_within(self.maximum_exchange_bytes)
            .map_err(RouteFailure::of)
    }

    #[cfg(feature = "sqlite-extract")]
    async fn send_sqlite_extract(&mut self, to: &ToStep) -> Result<Flow, RouteFailure> {
        use registry_platform_sqlite::Value as SqlValue;
        let acquisition = self
            .evidence
            .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
        let source = acquisition
            .sqlite_source(&to.uri.id)
            .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
        let declared = to
            .parameters
            .as_ref()
            .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
        check_to(to).map_err(|_| RouteFailure::of(ErrorClass::EgressRefused))?;
        let mut parameters = BTreeMap::new();
        for (name, expression) in &declared.query_parameters {
            let value = match self.eval(expression)? {
                Value::Null => SqlValue::Null,
                Value::String(value) => SqlValue::String(value),
                Value::Bool(value) => SqlValue::Boolean(value),
                Value::Number(value) => match value.as_i64() {
                    Some(value) => SqlValue::Integer(value),
                    None => SqlValue::Number(
                        value
                            .as_f64()
                            .ok_or_else(|| RouteFailure::of(ErrorClass::Validation))?,
                    ),
                },
                _ => return Err(RouteFailure::of(ErrorClass::Validation)),
            };
            parameters.insert(name.as_str().to_owned(), value);
        }
        self.sends += 1;
        if self.sends > self.context.maximum_upstream_calls {
            return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
        }
        acquisition
            .before_data_send(crate::evidence::EvidenceSendIntent {
                endpoint: to.uri.id.clone(),
                operation: None,
                method: crate::evidence::EvidenceSendMethod::SqliteExtract,
            })
            .await
            .map_err(evidence_terminal_failure)?;
        let response = tokio::time::timeout_at(
            acquisition.deadline(),
            source.execute_before(
                &parameters,
                acquisition.evaluation_instant(),
                acquisition.deadline().into_std(),
            ),
        )
        .await
        .map_err(|_| evidence_terminal_failure(crate::evidence::EvidenceTerminalError::Budget))?;
        // The platform also stops the SQLite worker at this absolute deadline.
        // If both layers observe expiry together, the acquisition-wide budget
        // remains the terminal, uncatchable boundary rather than becoming a
        // catchable statement diagnostic.
        if tokio::time::Instant::now() >= acquisition.deadline() {
            return Err(evidence_terminal_failure(
                crate::evidence::EvidenceTerminalError::Budget,
            ));
        }
        let response = response.map_err(|error| {
            let mut failure = RouteFailure::of(ErrorClass::EgressRefused);
            failure.code = Some(error.code());
            failure.evidence_diagnostic = Some(Box::new(EvidenceRouteDiagnostic::sqlite(
                to.uri.id.as_str(),
                error,
            )));
            failure
        })?;
        let bytes = serde_json::to_vec(&response)
            .map_err(|_| RouteFailure::of(ErrorClass::Validation))?
            .len();
        acquisition
            .record_response_bytes(bytes)
            .await
            .map_err(evidence_terminal_failure)?;
        self.exchange.message.body = response;
        Ok(Flow::Continue)
    }

    #[cfg(not(feature = "sqlite-extract"))]
    async fn send_sqlite_extract(&mut self, _to: &ToStep) -> Result<Flow, RouteFailure> {
        Err(RouteFailure::of(ErrorClass::EgressRefused))
    }

    async fn send(&mut self, to: &ToStep) -> Result<Flow, RouteFailure> {
        // The job-only sources are never send destinations: a file or
        // sftp endpoint is read through the pollEnrich step, and the
        // postgres source is a job send served by the job compiler's
        // own component state. The runtime holds the line before any
        // endpoint lookup, uncatchably, the way the origin pin does.
        match to.uri.component {
            SendComponent::SqliteExtract => return self.send_sqlite_extract(to).await,
            SendComponent::File | SendComponent::RabbitMq | SendComponent::Sftp => {
                return Err(RouteFailure {
                    class: ErrorClass::EgressRefused,
                    message: Some("a job source endpoint is read through the pollEnrich step only, never sent to".to_owned()),
                    data: None,
                    auth: None,
                    code: None,
                    record: None,
                    evidence_diagnostic: None,
                });
            }
            #[cfg(feature = "job-postgres")]
            SendComponent::Postgres => {
                let Some(plan) = self.context.job.postgres.get(&to.uri.id) else {
                    return Err(RouteFailure {
                        class: ErrorClass::EgressRefused,
                        message: Some(
                            "a postgres source send names an endpoint this build carries no source for"
                                .to_owned(),
                        ),
                        data: None,
                        auth: None,
                        code: Some("adapter.job.source-unbound"),
                        record: None,
                        evidence_diagnostic: None,
                    });
                };
                let Some(source) = self.context.job.postgres_clients.get(&to.uri.id) else {
                    return Err(RouteFailure {
                        class: ErrorClass::EgressRefused,
                        message: Some(
                            "a postgres source send runs with no client registered for its endpoint"
                                .to_owned(),
                        ),
                        data: None,
                        auth: None,
                        code: Some("adapter.job.source-unbound"),
                        record: None,
                        evidence_diagnostic: None,
                    });
                };
                // The read-only source send counts against the run's
                // upstream-call budget like every other send.
                self.sends += 1;
                if self.sends > self.context.maximum_upstream_calls {
                    return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
                }
                return crate::component::postgres::send(self, plan, source.as_ref(), to).await;
            }
            #[cfg(not(feature = "job-postgres"))]
            SendComponent::Postgres => {
                return Err(RouteFailure {
                    class: ErrorClass::EgressRefused,
                    message: Some(
                        "the postgres source component is not compiled into this binary; use an adapter-job build with the job-postgres feature".to_owned(),
                    ),
                    data: None,
                    auth: None,
                    code: Some("adapter.job.component-unavailable"),
                    record: None,
                    evidence_diagnostic: None,
                });
            }
            SendComponent::Direct | SendComponent::Http | SendComponent::GraphQl => {}
        }
        let resume_send = self.resume_send()?;
        if matches!(resume_send, ResumeSend::Skip) {
            return Ok(Flow::Continue);
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
        let ok_range = match parameters.map(parse_ok_range) {
            Some(Ok(range)) => range,
            // A refused range never reaches the transport: the authoring
            // checks hold it, and a graphql send declares none.
            Some(Err(_)) | None => OkStatusCodeRanges::default(),
        };
        // A graphql send posts one document over the endpoint's base link:
        // the pinned query text, the endpoint's operation name, and the
        // variables the send's body member yields, or the endpoint's
        // expression when the send carries none (section 8.8). Every
        // other send travels in the query string.
        let host_protocol = self
            .evidence
            .and_then(|acquisition| acquisition.host_protocol(to.uri.id.as_str()))
            .cloned();
        if graphql && host_protocol.is_some() {
            return Err(evidence_terminal_failure(
                crate::evidence::EvidenceTerminalError::Protocol,
            ));
        }
        let mut post_body: Option<Vec<u8>> = None;
        let mut protocol_route_body: Option<Value> = None;
        let link = if graphql {
            let query = endpoint
                .graphql
                .as_ref()
                .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
            let operation = parameters.and_then(|parameters| parameters.operation.as_ref());
            if !query.accepts_operation(operation) {
                return Err(RouteFailure::of(ErrorClass::EgressRefused));
            }
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
                    data: None,
                    auth: None,
                    code: None,
                    record: None,
                    evidence_diagnostic: None,
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
            if parameters.http_method == Some(HttpMethod::Post) {
                let body = parameters
                    .body
                    .as_ref()
                    .ok_or_else(|| RouteFailure::of(ErrorClass::EgressRefused))?;
                let evaluated = self.eval(body)?;
                if host_protocol.is_some() {
                    protocol_route_body = Some(evaluated.clone());
                }
                post_body = Some(
                    serde_json::to_vec(&evaluated)
                        .map_err(|_| RouteFailure::of(ErrorClass::Validation))?,
                );
            } else if host_protocol.is_some() {
                protocol_route_body = Some(Value::Null);
            }
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
        let protocol_target = if host_protocol.is_some() {
            let target = url::Url::parse(&link).map_err(|_| {
                evidence_terminal_failure(crate::evidence::EvidenceTerminalError::Protocol)
            })?;
            Some((
                if parameters
                    .is_some_and(|parameters| parameters.http_method == Some(HttpMethod::Post))
                {
                    HostProtocolMethod::Post
                } else {
                    HostProtocolMethod::Get
                },
                target.path().to_owned(),
                target.query().is_some(),
            ))
        } else {
            None
        };

        let mut auth_events: Vec<AuthEvent> = Vec::new();
        self.sends += 1;
        if self.sends > self.context.maximum_upstream_calls {
            return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
        }
        self.ensure_deadline()?;
        let (method, evidence_method) = if host_protocol.is_some() {
            (
                match protocol_target
                    .as_ref()
                    .expect("a selected protocol has a parsed target")
                    .0
                {
                    HostProtocolMethod::Get => "GET",
                    HostProtocolMethod::Post => "POST",
                },
                crate::evidence::EvidenceSendMethod::HostProtocol,
            )
        } else if graphql {
            ("POST", crate::evidence::EvidenceSendMethod::GraphQlQuery)
        } else if parameters
            .is_some_and(|parameters| parameters.http_method == Some(HttpMethod::Post))
        {
            ("POST", crate::evidence::EvidenceSendMethod::ReadOnlyPost)
        } else {
            ("GET", crate::evidence::EvidenceSendMethod::Get)
        };
        if let Some(acquisition) = self.evidence {
            acquisition
                .before_data_send(crate::evidence::EvidenceSendIntent {
                    endpoint: to.uri.id.as_str().to_owned(),
                    operation: parameters
                        .and_then(|parameters| parameters.operation.as_ref())
                        .map(|operation| operation.as_str().to_owned()),
                    method: evidence_method,
                })
                .await
                .map_err(evidence_terminal_failure)?;
        }
        // The named connection's physical permit is acquired only after the
        // durable Evidence intent and before any credential material is read.
        // Waiting remains inside the acquisition deadline, and the owned
        // permit releases on every return, cancellation, or panic path.
        let _data_permit =
            tokio::time::timeout_at(self.deadline, endpoint.egress.acquire_data_permit())
                .await
                .map_err(|_| RouteFailure::of(ErrorClass::BudgetExhausted))?;
        let mut prepared_protocol = match (&host_protocol, &protocol_route_body) {
            (Some(protocol), Some(body)) => Some(
                protocol
                    .prepare_attempt(
                        HostProtocolRequestContext::new(
                            protocol_target
                                .as_ref()
                                .expect("a selected protocol has a parsed target")
                                .0,
                            &protocol_target
                                .as_ref()
                                .expect("a selected protocol has a parsed target")
                                .1,
                            protocol_target
                                .as_ref()
                                .expect("a selected protocol has a parsed target")
                                .2,
                            if protocol_target
                                .as_ref()
                                .expect("a selected protocol has a parsed target")
                                .0
                                == HostProtocolMethod::Post
                            {
                                Some(body)
                            } else {
                                None
                            },
                        ),
                        self.evidence
                            .and_then(|acquisition| acquisition.attribution()),
                        registry_platform_httputil::destination::MAX_DESTINATION_REQUEST_BODY_BYTES,
                    )
                    .map_err(|_| {
                        evidence_terminal_failure(crate::evidence::EvidenceTerminalError::Protocol)
                    })?,
            ),
            (Some(_), None) => {
                return Err(evidence_terminal_failure(
                    crate::evidence::EvidenceTerminalError::Protocol,
                ));
            }
            (None, _) => None,
        };
        let authorized = if let Some(acquisition) = self.evidence {
            let mut budget = acquisition.token_budget.lock().await;
            tokio::time::timeout_at(
                self.deadline,
                endpoint.egress.authorize(
                    &mut budget,
                    self.context.resolver,
                    &PlatformAssertionSigner,
                    &mut auth_events,
                ),
            )
            .await
        } else {
            tokio::time::timeout_at(
                self.deadline,
                endpoint.egress.authorize(
                    &mut self.token_budget,
                    self.context.resolver,
                    &PlatformAssertionSigner,
                    &mut auth_events,
                ),
            )
            .await
        }
        .map_err(|_| RouteFailure::of(ErrorClass::BudgetExhausted))?;
        // The send is announced only once its credential is in hand; a
        // credential failure never reads as a send that began.
        let mut credential = authorized.map_err(|error| auth_failure(&error, &auth_events))?;
        let headers = self.exchange.message.string_headers();
        let safe = endpoint.send_is_safe(to.uri.component, parameters);
        if matches!(&self.async_policy, Some(AsyncRoutePolicy::Status { .. })) && !safe {
            return Err(RouteFailure::of(ErrorClass::EgressRefused));
        }
        let initial_async = match &self.async_policy {
            Some(AsyncRoutePolicy::Initial(completion))
                if !safe
                    && to.uri.id == completion.initial.endpoint
                    && parameters
                        .and_then(|parameters| parameters.operation.as_ref())
                        .is_some_and(|operation| {
                            operation.as_str() == completion.initial.operation
                        }) =>
            {
                Some((
                    completion.accepted_id.clone(),
                    completion
                        .uncertainty
                        .as_ref()
                        .map(|recovery| recovery.request_header.clone()),
                ))
            }
            _ => None,
        };
        let status_recovery_header = match &self.async_policy {
            Some(AsyncRoutePolicy::Status {
                recovery_endpoint: Some(endpoint),
                recovery_header: Some(header),
            }) if to.uri.id == *endpoint => Some(header.clone()),
            _ => None,
        };
        let mut refresh_used = false;
        loop {
            let mut sending = json!({ "endpoint": to.uri.id, "method": method, "operation": parameters.and_then(|parameters| parameters.operation.as_ref()).map(|o| o.as_str()) });
            if !auth_events.is_empty() {
                sending["auth"] = auth_events_detail(&auth_events);
            }
            self.events.push(RouteEvent {
                kind: "exchangeSending",
                at: SystemTime::now(),
                detail: sending,
            });
            auth_events.clear();
            self.ensure_deadline()?;
            if !safe {
                match resume_send {
                    ResumeSend::Execute { ordinal, .. } => {
                        self.exchange
                            .before_resume_step(
                                u32::try_from(ordinal)
                                    .map_err(|_| RouteFailure::of(ErrorClass::Facade))?,
                            )
                            .await?;
                        self.events.push(RouteEvent {
                            kind: "resumeStepStarted",
                            at: SystemTime::now(),
                            detail: json!({"ordinal": ordinal}),
                        });
                    }
                    ResumeSend::Ordinary => self.exchange.before_upstream_effect().await?,
                    ResumeSend::Skip => return Err(RouteFailure::of(ErrorClass::Facade)),
                }
            }
            let recovery_header = if let Some((_, Some(name))) = &initial_async {
                let Some(id) = self.exchange.source_recovery_id()? else {
                    return Err(RouteFailure::of(ErrorClass::EgressRefused));
                };
                Some(
                    SourceRecoveryHeader::try_new(name, &id)
                        .map_err(|_| RouteFailure::of(ErrorClass::EgressRefused))?,
                )
            } else {
                status_recovery_header.clone()
            };
            self.ensure_deadline()?;
            let remaining = self
                .deadline
                .saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
            }
            let started = Instant::now();
            if recovery_header.is_some() && prepared_protocol.is_some() {
                return Err(RouteFailure::of(ErrorClass::EgressRefused));
            }
            let reply = if let Some(prepared) = prepared_protocol.take() {
                let crate::host_protocol::PreparedHostProtocolParts {
                    body,
                    headers: protocol_headers,
                    verifier,
                } = prepared.into_parts();
                if !host_protocol
                    .as_ref()
                    .expect("a prepared attempt has a selected protocol")
                    .validates_request_headers(&protocol_headers)
                {
                    return Err(evidence_terminal_failure(
                        crate::evidence::EvidenceTerminalError::Protocol,
                    ));
                }
                if let Some(verifier) = verifier {
                    let mut protocol_headers = protocol_headers;
                    if matches!(&body, PreparedHostProtocolBody::Unchanged) {
                        protocol_headers.extend(
                            headers
                                .iter()
                                .map(|(name, value)| {
                                    Ok((
                                        http::HeaderName::from_bytes(name.as_bytes()).map_err(
                                            |_| {
                                                evidence_terminal_failure(
                                                    crate::evidence::EvidenceTerminalError::Protocol,
                                                )
                                            },
                                        )?,
                                        http::HeaderValue::from_str(value).map_err(|_| {
                                            evidence_terminal_failure(
                                                crate::evidence::EvidenceTerminalError::Protocol,
                                            )
                                        })?,
                                    ))
                                })
                                .collect::<Result<Vec<_>, RouteFailure>>()?,
                        );
                    }
                    let protocol_body = match &body {
                        PreparedHostProtocolBody::Unchanged => post_body.as_deref(),
                        PreparedHostProtocolBody::SealedBytes(body) => Some(body.as_slice()),
                    };
                    let reply = tokio::time::timeout_at(
                        self.deadline,
                        endpoint.egress.send_protocol(ProtocolOutboundSend {
                            link: &link,
                            protocol_headers: &protocol_headers,
                            response_headers: host_protocol
                                .as_ref()
                                .expect("a prepared attempt has a selected protocol")
                                .response_header_names(),
                            body: protocol_body,
                            authorization: credential.as_ref().map(|c| &c.header),
                            attempt: endpoint.attempt.min(remaining),
                            maximum_response_bytes: endpoint.maximum_response_bytes,
                            readable_replay_body: host_protocol
                                .as_ref()
                                .expect("a prepared attempt has a selected protocol")
                                .replays_readable_body(),
                        }),
                    )
                    .await
                    .map_err(|_| RouteFailure::of(ErrorClass::BudgetExhausted))?;
                    PhysicalSendReply::Protocol { reply, verifier }
                } else {
                    if !matches!(body, PreparedHostProtocolBody::Unchanged) {
                        return Err(evidence_terminal_failure(
                            crate::evidence::EvidenceTerminalError::Protocol,
                        ));
                    }
                    let mut passthrough_headers = protocol_headers
                        .iter()
                        .map(|(name, value)| {
                            value
                                .to_str()
                                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                                .map_err(|_| {
                                    evidence_terminal_failure(
                                        crate::evidence::EvidenceTerminalError::Protocol,
                                    )
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    passthrough_headers.extend(headers.iter().cloned());
                    PhysicalSendReply::Ordinary(
                        tokio::time::timeout_at(
                            self.deadline,
                            endpoint.egress.send_with_recovery_header(
                                OutboundSend {
                                    link: &link,
                                    exchange_headers: &passthrough_headers,
                                    shape: match &post_body {
                                        Some(bytes) => SendShape::Post(SendBody {
                                            format: SendBodyFormat::Json,
                                            bytes,
                                        }),
                                        None => SendShape::Get,
                                    },
                                    authorization: credential.as_ref().map(|c| &c.header),
                                    attempt: endpoint.attempt.min(remaining),
                                    maximum_response_bytes: endpoint.maximum_response_bytes,
                                    ok_status_ranges: ok_range.clone(),
                                    throw_exception_on_failure: parameters
                                        .map(|parameters| parameters.throw_exception_on_failure)
                                        .unwrap_or(false),
                                },
                                recovery_header.as_ref(),
                            ),
                        )
                        .await
                        .map_err(|_| RouteFailure::of(ErrorClass::BudgetExhausted))?,
                    )
                }
            } else {
                PhysicalSendReply::Ordinary(
                    tokio::time::timeout_at(
                        self.deadline,
                        endpoint.egress.send_with_recovery_header(
                            OutboundSend {
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
                                attempt: endpoint.attempt.min(remaining),
                                maximum_response_bytes: endpoint.maximum_response_bytes,
                                ok_status_ranges: ok_range.clone(),
                                throw_exception_on_failure: parameters
                                    .map(|parameters| parameters.throw_exception_on_failure)
                                    .unwrap_or(graphql),
                            },
                            recovery_header.as_ref(),
                        ),
                    )
                    .await
                    .map_err(|_| RouteFailure::of(ErrorClass::BudgetExhausted))?,
                )
            };
            self.ensure_deadline()?;
            if let Some(acquisition) = self.evidence {
                let response_bytes = reply.response_bytes();
                if response_bytes != 0 {
                    acquisition
                        .record_response_bytes(response_bytes)
                        .await
                        .map_err(evidence_terminal_failure)?;
                }
            }
            let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let status = reply.status();
            let mut action = match status {
                Some(status) => {
                    endpoint
                        .egress
                        .plan()
                        .on_upstream_status(
                            status,
                            credential
                                .as_ref()
                                .and_then(|credential| credential.generation),
                            &mut refresh_used,
                            &mut auth_events,
                        )
                        .await
                }
                None => UpstreamStatusAction::Continue,
            };
            if action == UpstreamStatusAction::RetryWithFreshCredential
                && host_protocol
                    .as_ref()
                    .is_some_and(|protocol| !protocol.allows_credential_refresh_retry())
            {
                action = UpstreamStatusAction::CredentialRejected;
            }
            if action == UpstreamStatusAction::RetryWithFreshCredential {
                let mut sent = json!({
                    "endpoint": to.uri.id,
                    "class": ErrorClass::UpstreamHttp.class(),
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
                auth_events.clear();
                self.sends += 1;
                if self.sends > self.context.maximum_upstream_calls {
                    return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
                }
                self.ensure_deadline()?;
                if let Some(acquisition) = self.evidence {
                    acquisition
                        .before_data_send(crate::evidence::EvidenceSendIntent {
                            endpoint: to.uri.id.as_str().to_owned(),
                            operation: parameters
                                .and_then(|parameters| parameters.operation.as_ref())
                                .map(|operation| operation.as_str().to_owned()),
                            method: evidence_method,
                        })
                        .await
                        .map_err(evidence_terminal_failure)?;
                }
                if let (Some(protocol), Some(body)) = (&host_protocol, &protocol_route_body) {
                    prepared_protocol = Some(
                        protocol
                            .prepare_attempt(
                                HostProtocolRequestContext::new(
                                    protocol_target
                                        .as_ref()
                                        .expect("a selected protocol has a parsed target")
                                        .0,
                                    &protocol_target
                                        .as_ref()
                                        .expect("a selected protocol has a parsed target")
                                        .1,
                                    protocol_target
                                        .as_ref()
                                        .expect("a selected protocol has a parsed target")
                                        .2,
                                    if protocol_target
                                        .as_ref()
                                        .expect("a selected protocol has a parsed target")
                                        .0
                                        == HostProtocolMethod::Post
                                    {
                                        Some(body)
                                    } else {
                                        None
                                    },
                                ),
                                self.evidence
                                    .and_then(|acquisition| acquisition.attribution()),
                                registry_platform_httputil::destination::MAX_DESTINATION_REQUEST_BODY_BYTES,
                            )
                            .map_err(|_| {
                                evidence_terminal_failure(
                                    crate::evidence::EvidenceTerminalError::Protocol,
                                )
                            })?,
                    );
                }
                let refreshed = if let Some(acquisition) = self.evidence {
                    let mut budget = acquisition.token_budget.lock().await;
                    tokio::time::timeout_at(
                        self.deadline,
                        endpoint.egress.authorize(
                            &mut budget,
                            self.context.resolver,
                            &PlatformAssertionSigner,
                            &mut auth_events,
                        ),
                    )
                    .await
                } else {
                    tokio::time::timeout_at(
                        self.deadline,
                        endpoint.egress.authorize(
                            &mut self.token_budget,
                            self.context.resolver,
                            &PlatformAssertionSigner,
                            &mut auth_events,
                        ),
                    )
                    .await
                };
                credential = refreshed
                    .map_err(|_| RouteFailure::of(ErrorClass::BudgetExhausted))?
                    .map_err(|error| auth_failure(&error, &auth_events))?;
                continue;
            }
            if action == UpstreamStatusAction::CredentialRejected {
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
                let mut failure = RouteFailure::of(ErrorClass::CredentialRejected);
                if !auth_events.is_empty() {
                    failure.auth = Some(Box::new(auth_events_detail(&auth_events)));
                }
                if self.evidence.is_some() {
                    attach_evidence_http_diagnostic(&mut failure, to.uri.id.as_str(), status, None);
                }
                return Err(failure);
            }
            let (reply, keep_response_headers) = match reply {
                PhysicalSendReply::Ordinary(reply) => (reply, true),
                PhysicalSendReply::Protocol { reply, verifier } => match reply {
                    Ok(reply) => {
                        let response_bytes = reply.response_bytes;
                        let status = reply.status;
                        let verified = verifier
                            .verify(HostProtocolWireResponse::new(
                                status,
                                reply.trusted_headers,
                                reply.body,
                            ))
                            .map_err(|refusal| {
                                let mut failure = evidence_terminal_failure(
                                    crate::evidence::EvidenceTerminalError::Protocol,
                                );
                                if self.evidence.is_some() {
                                    attach_evidence_http_diagnostic(
                                        &mut failure,
                                        to.uri.id.as_str(),
                                        Some(status),
                                        Some(refusal),
                                    );
                                }
                                failure
                            })?;
                        let (body, valid_until, keep_response_headers) = verified.into_parts();
                        if let (Some(acquisition), Some(valid_until)) = (self.evidence, valid_until)
                        {
                            acquisition
                                .record_protocol_validity(to.uri.id.as_str(), valid_until)
                                .await;
                        }
                        (
                            Ok(SentReply {
                                status,
                                body,
                                response_bytes,
                                headers: reply.headers,
                            }),
                            keep_response_headers,
                        )
                    }
                    Err(error) => (Err(error), true),
                },
            };
            return match reply {
                Ok(reply) => {
                    let mut sent = json!({ "endpoint": to.uri.id, "status": reply.status, "durationMs": elapsed });
                    if !auth_events.is_empty() {
                        sent["auth"] = auth_events_detail(&auth_events);
                    }
                    self.events.push(RouteEvent {
                        kind: "exchangeSent",
                        at: SystemTime::now(),
                        detail: sent,
                    });
                    if reply.status == 202 && matches!(resume_send, ResumeSend::Execute { .. }) {
                        // A generic linear step declares no source-native
                        // status operation. Acceptance is therefore not a
                        // completed checkpoint: keep this ordinal resumable
                        // under the operation's reviewed idempotency semantic.
                        return Err(RouteFailure::of(ErrorClass::UpstreamHttp));
                    }
                    self.checkpoint_resume_reply(resume_send, &reply.body)
                        .await?;
                    if reply.status == 202 {
                        if let Some((selector, _)) = &initial_async {
                            match selector.extract(&reply.body) {
                                Ok(source_id) => {
                                    self.async_source_acceptance =
                                        Some(AsyncSourceAcceptance { source_id });
                                    return Ok(Flow::Stop);
                                }
                                Err(failure) => {
                                    self.exchange.mark_unsupported_incomplete_write().await?;
                                    return Err(failure);
                                }
                            }
                        }
                        if self.exchange.mark_unsupported_incomplete_write().await? {
                            return Err(RouteFailure::of(ErrorClass::UpstreamHttp));
                        }
                    }
                    let message = &mut self.exchange.message;
                    message.body = reply.body;
                    message.set_header("CamelHttpResponseCode", json!(reply.status));
                    if keep_response_headers {
                        for (name, value) in reply.headers.iter() {
                            message.set_header(name, Value::String(value.to_owned()));
                        }
                    }
                    // A GraphQL `errors` array fails the exchange (section
                    // 8.8), whatever the status said: the reply keeps its
                    // body and status on the exchange for a clause to read,
                    // and the failure carries the declared detail only,
                    // never the source's error text. Partial data fails with
                    // it.
                    if graphql {
                        match graphql_reply_body(&message.body) {
                            Ok(body) => message.body = body,
                            Err(mut failure) => {
                                if !auth_events.is_empty() {
                                    failure.auth = Some(Box::new(auth_events_detail(&auth_events)));
                                }
                                return Err(failure);
                            }
                        }
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
                    let mut failure = RouteFailure::of(class);
                    if !auth_events.is_empty() {
                        failure.auth = Some(Box::new(auth_events_detail(&auth_events)));
                    }
                    if self.evidence.is_some() {
                        attach_evidence_http_diagnostic(
                            &mut failure,
                            to.uri.id.as_str(),
                            status,
                            None,
                        );
                    }
                    // A 202 is a source that accepted asynchronous work
                    // even when the authored success range excludes it or
                    // its reply failed to read: the write is marked
                    // incomplete before any clause can normalize the
                    // failure, as on the success path.
                    if status == Some(202) {
                        if matches!(resume_send, ResumeSend::Execute { .. }) {
                            // As on the success path: acceptance on a
                            // linear resume step is no checkpoint, so the
                            // ordinal stays resumable.
                            return Err(failure);
                        }
                        if let Some((selector, _)) = &initial_async {
                            let accepted = match &error {
                                EgressError::Upstream(upstream) => upstream
                                    .body
                                    .as_ref()
                                    .and_then(|body| selector.extract(body).ok()),
                                EgressError::Refused(_) => None,
                            };
                            if let Some(source_id) = accepted {
                                self.async_source_acceptance =
                                    Some(AsyncSourceAcceptance { source_id });
                                return Ok(Flow::Stop);
                            }
                            self.exchange.mark_unsupported_incomplete_write().await?;
                            return Err(failure);
                        }
                        if self.exchange.mark_unsupported_incomplete_write().await? {
                            return Err(failure);
                        }
                    }
                    if let EgressError::Upstream(upstream) = error {
                        let message = &mut self.exchange.message;
                        message.body = upstream.body.unwrap_or(Value::Null);
                        if let Some(status) = upstream.status {
                            message.set_header("CamelHttpResponseCode", json!(status));
                        }
                    }
                    Err(failure)
                }
            };
        }
    }

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
        let outcome = if self.exception_clause_depth > 0 {
            Box::pin(self.run_route_body_bare(target)).await
        } else {
            Box::pin(self.run_route_body(target)).await
        };
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
                    data: None,
                    auth: None,
                    code: None,
                    record: None,
                    evidence_diagnostic: None,
                });
            }
        };
        match egress.origin().pin(&link) {
            // The parsed link's own serialization is the value sent;
            // the sender never sees the expression's raw text.
            Ok(pinned) => Ok(pinned.as_url().as_str().to_owned()),
            Err(_) => Err(RouteFailure::of(ErrorClass::EgressRefused)),
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
                    return Err(RouteFailure::of(ErrorClass::Validation));
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

/// Validate the closed GraphQL response envelope and return its `data`
/// member. A malformed `errors` member, a non-object response, or an object
/// carrying neither `data` nor `errors` is a source protocol failure rather
/// than a successful null result (section 8.8).
fn graphql_reply_body(body: &Value) -> Result<Value, RouteFailure> {
    let Some(object) = body.as_object() else {
        return Err(RouteFailure::of(ErrorClass::UpstreamMalformed));
    };
    let has_data = object.contains_key("data");
    let Some(errors) = object.get("errors") else {
        return if has_data {
            Ok(object.get("data").cloned().unwrap_or(Value::Null))
        } else {
            Err(RouteFailure::of(ErrorClass::UpstreamMalformed))
        };
    };
    let Some(errors) = errors.as_array() else {
        return Err(RouteFailure::of(ErrorClass::UpstreamMalformed));
    };
    if !errors.is_empty() {
        return Err(RouteFailure {
            class: ErrorClass::UpstreamHttp,
            message: Some("the graphql reply carries an errors array".to_owned()),
            data: None,
            auth: None,
            code: None,
            record: None,
            evidence_diagnostic: None,
        });
    }
    Ok(object.get("data").cloned().unwrap_or(Value::Null))
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
    matches!(
        kind,
        AuthKind::None
            | AuthKind::Basic
            | AuthKind::StaticAuthorization
            | AuthKind::StaticApiKey
            | AuthKind::Oauth2ClientCredentials
            | AuthKind::Oauth2PrivateKeyJwt
    )
}

#[cfg(test)]
mod served_tests {
    use super::*;

    #[test]
    fn every_compiled_authentication_kind_is_served() {
        for kind in [
            AuthKind::None,
            AuthKind::Basic,
            AuthKind::StaticAuthorization,
            AuthKind::StaticApiKey,
            AuthKind::Oauth2ClientCredentials,
            AuthKind::Oauth2PrivateKeyJwt,
        ] {
            assert!(is_served_auth(kind), "{} must be served", kind.tag());
        }
    }

    fn steps(value: Value) -> Vec<Step> {
        serde_json::from_value(value).expect("the steps parse")
    }

    #[test]
    fn graphql_replies_require_the_closed_data_errors_envelope() {
        assert_eq!(
            graphql_reply_body(&json!({"data": {"record": 1}})).expect("data is a complete reply"),
            json!({"record": 1})
        );
        assert_eq!(
            graphql_reply_body(&json!({"errors": []}))
                .expect("an empty errors array is a complete null reply"),
            Value::Null
        );
        for malformed in [
            json!({}),
            json!([]),
            json!({"errors": {"message": "not-an-array"}}),
        ] {
            assert_eq!(
                graphql_reply_body(&malformed)
                    .expect_err("the malformed reply is refused")
                    .class,
                ErrorClass::UpstreamMalformed
            );
        }
        assert_eq!(
            graphql_reply_body(&json!({"data": {"record": 1}, "errors": [{}]}))
                .expect_err("partial data with errors fails")
                .class,
            ErrorClass::UpstreamHttp
        );
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

    /// Served HTTP paths use the core authoring grammar before an endpoint
    /// or credential is touched. Both sends and enrichments refuse missing
    /// and surplus bindings, facade braces, and paths that are not relative
    /// to the endpoint origin; the existing exact-destination rule still
    /// refuses a send with neither `path` nor `httpUri`.
    #[test]
    fn served_http_paths_match_core_authoring_admission() {
        let cases = [
            ("/api/items/{{id}}", json!({}), "missing binding"),
            (
                "/api/items",
                json!({"id": {"constant": "P-1"}}),
                "surplus binding",
            ),
            (
                "/api/items/{id}",
                json!({"id": {"constant": "P-1"}}),
                "facade braces",
            ),
            (
                "api/items/{{id}}",
                json!({"id": {"constant": "P-1"}}),
                "non-origin-relative path",
            ),
        ];
        for (path, path_parameters, reason) in cases {
            let send = steps(json!([{
                "to": {"uri": "http:tracker", "parameters": {
                    "httpMethod": "GET",
                    "path": path,
                    "pathParameters": path_parameters.clone()
                }}
            }]));
            assert!(check_servable(&send).is_err(), "to accepted {reason}");

            let enrichment = steps(json!([{
                "enrich": {"uri": "http:tracker", "parameters": {
                    "httpMethod": "GET",
                    "path": path,
                    "pathParameters": path_parameters
                }}
            }]));
            assert!(
                check_servable(&enrichment).is_err(),
                "enrich accepted {reason}"
            );
        }

        let missing_destination = steps(json!([{
            "to": {"uri": "http:tracker", "parameters": {"httpMethod": "GET"}}
        }]));
        assert!(check_servable(&missing_destination).is_err());
    }

    #[test]
    fn evidence_routes_may_own_facade_named_headers_but_not_engine_headers() {
        let facade_named = steps(json!([{
            "setHeader": {"name": "recordId", "value": {"constant": "P-1"}}
        }]));
        assert!(check_servable(&facade_named).is_err());
        check_evidence_servable(&facade_named)
            .expect("Evidence has no facade exchange whose recordId could be overwritten");

        let engine_owned = steps(json!([{
            "setHeader": {"name": "CamelSplitIndex", "value": {"constant": 1}}
        }]));
        assert!(check_servable(&engine_owned).is_err());
        assert!(check_evidence_servable(&engine_owned).is_err());
    }

    #[test]
    fn evidence_routes_refuse_handlers_that_turn_source_failures_into_answers() {
        let send = json!({"to": {"uri": "http:source", "parameters": {"httpMethod": "GET", "path": "/records"}}});
        let answer = json!({"setBody": {"constant": {"lookup": "no-match"}}});
        let not_found = json!({"header": "CamelHttpResponseCode"});
        let breaker = |extra: Value| {
            let mut breaker = json!({
                "failureRateThreshold": 50,
                "slidingWindowCalls": 2,
                "minimumNumberOfCalls": 2,
                "steps": [send.clone()]
            });
            for (key, value) in extra.as_object().expect("breaker members") {
                breaker[key] = value.clone();
            }
            json!([{"circuitBreaker": breaker}])
        };
        let cases = [
            (
                "doCatch without onWhen",
                json!([{"doTry": {"steps": [send.clone()], "doCatch": [{"exception": ["upstream"], "steps": [answer.clone()]}]}}]),
                "doCatch may not catch upstream",
            ),
            (
                "doCatch of a transport failure even with onWhen",
                json!([{"doTry": {"steps": [send.clone()], "doCatch": [{"exception": ["upstream.connection"], "onWhen": not_found.clone(), "steps": [answer.clone()]}]}}]),
                "doCatch may not catch upstream.connection",
            ),
            (
                "doCatch of upstream.http without onWhen",
                json!([{"doTry": {"steps": [send.clone()], "doCatch": [{"exception": ["upstream.http"], "steps": [answer.clone()]}]}}]),
                "doCatch may not catch upstream.http",
            ),
            (
                "handled onException",
                json!([{"onException": {"exception": ["upstream"], "handled": true, "steps": [answer.clone()]}}, send.clone()]),
                "onException clause may not handle upstream",
            ),
            (
                "continued onException on a script failure",
                json!([{"onException": {"exception": ["script"], "continued": true}}, send.clone()]),
                "onException clause may not handle script",
            ),
            (
                "onException that rethrows as another class",
                json!([{"onException": {"exception": ["validation"], "steps": [{"throwException": {"exceptionType": "outcome.not-found"}}]}}, send.clone()]),
                "onException clause may not handle validation",
            ),
            (
                "breaker fallback",
                breaker(json!({"onFallback": {"steps": [answer.clone()]}})),
                "circuitBreaker may not declare onFallback",
            ),
            (
                "breaker ignoreException",
                breaker(json!({"ignoreException": ["upstream.http"]})),
                "circuitBreaker may not declare ignoreException",
            ),
            (
                "breaker recordException",
                breaker(json!({"recordException": ["upstream.timeout"]})),
                "circuitBreaker may not declare recordException",
            ),
        ];
        for (shape, value, expected) in cases {
            let route = steps(value);
            check_servable(&route)
                .unwrap_or_else(|fault| panic!("{shape}: the facade still serves it: {fault}"));
            let refusal = check_evidence_servable(&route)
                .expect_err(&format!("{shape}: an Evidence route accepted it"));
            assert!(refusal.contains(expected), "{shape}: {refusal}");
            assert!(
                refusal.contains("registry-lookup-v1") || refusal.contains("every failure"),
                "{shape}: the refusal names no fix: {refusal}"
            );
        }
    }

    #[test]
    fn evidence_routes_keep_status_tested_catches_and_retry_only_clauses() {
        let send = json!({"to": {"uri": "http:source", "parameters": {"httpMethod": "GET", "path": "/records"}}});
        let answer = json!({"setBody": {"constant": {"lookup": "no-match"}}});
        let status = json!({"header": "CamelHttpResponseCode"});
        for (shape, value) in [
            (
                "status-tested doCatch",
                json!([{"doTry": {"steps": [send.clone()], "doCatch": [{"exception": ["upstream.http"], "onWhen": status.clone(), "steps": [answer.clone()]}]}}]),
            ),
            (
                "status-tested handled onException",
                json!([{"onException": {"exception": ["upstream.http"], "onWhen": status.clone(), "handled": true, "steps": [answer.clone()]}}, send.clone()]),
            ),
            (
                "retry-only onException",
                json!([{"onException": {"exception": ["upstream.timeout", "upstream.connection"], "redeliveryPolicy": {"maximumRedeliveries": 1}}}, send.clone()]),
            ),
            (
                "catch of the pack's own outcome",
                json!([{"doTry": {"steps": [{"throwException": {"exceptionType": "outcome.not-found"}}], "doCatch": [{"exception": ["outcome.not-found"], "steps": [answer.clone()]}]}}]),
            ),
            (
                "plain breaker",
                json!([{"circuitBreaker": {"failureRateThreshold": 50, "slidingWindowCalls": 2, "minimumNumberOfCalls": 2, "steps": [send.clone()]}}]),
            ),
        ] {
            check_evidence_servable(&steps(value))
                .unwrap_or_else(|fault| panic!("{shape}: refused: {fault}"));
        }
    }

    #[test]
    fn an_empty_idempotent_consumer_is_refused() {
        let steps =
            steps(json!([{"idempotentConsumer": {"expression": {"header": "x"}, "steps": []}}]));
        let refusal = check_servable(&steps).expect_err("refused");
        assert!(refusal.contains("idempotentConsumer"), "{refusal}");
        assert!(refusal.contains("guards no steps"), "{refusal}");
    }

    #[test]
    fn an_idempotent_consumer_uses_the_caller_idempotency_key_header() {
        let served = steps(json!([{"idempotentConsumer": {
            "expression": {"header": "idempotency-key"},
            "steps": [{"stop": {}}]
        }}]));
        check_servable(&served).expect("the caller header is served case-insensitively");

        let refused = steps(json!([{"idempotentConsumer": {
            "expression": {"constant": "shared-key"},
            "steps": [{"stop": {}}]
        }}]));
        let refusal = check_servable(&refused).expect_err("an authored key is refused");
        assert!(refusal.contains("Idempotency-Key"), "{refusal}");
    }

    #[test]
    fn a_route_may_set_its_own_property_and_the_next_continuation_only() {
        let own = steps(json!([{"setProperty": {"name": "page", "value": {"constant": 1}}}]));
        check_servable(&own).expect("served");
        let next = steps(json!([
            {"setProperty": {"name": "AdapterNextContinuation", "value": {"constant": 2}}}
        ]));
        check_servable(&next).expect("served");
        for reserved in [
            "AdapterContinuation",
            "AdapterFilters",
            "AdapterAnything",
            "CamelSplitIndex",
            "CamelLoopIndex",
        ] {
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
    fn a_post_send_requires_a_body() {
        let steps = steps(json!([
            {"to": {"uri": "http:tracker", "parameters": {"httpMethod": "POST", "path": "/x"}}}
        ]));
        assert!(check_servable(&steps).is_err());
    }

    fn parameters(range: Option<&str>) -> ToParameters {
        serde_json::from_value(match range {
            Some(range) => json!({ "okStatusCodeRange": range }),
            None => json!({}),
        })
        .expect("send parameters parse")
    }

    #[test]
    fn ok_status_code_range_parses_sparse_comma_lists() {
        let ranges =
            parse_ok_range(&parameters(Some("200-299, 400, 404"))).expect("sparse ranges parse");
        for status in [200, 299, 400, 404] {
            assert!(ranges.contains(status), "{status} is declared");
        }
        for status in [199, 300, 399, 401, 403, 405] {
            assert!(!ranges.contains(status), "{status} is a hole");
        }
        assert!(parse_ok_range(&parameters(None))
            .expect("default range")
            .contains(200));
    }

    #[test]
    fn ok_status_code_range_refusals_are_value_free() {
        for invalid in ["", "200-", "99", "200-600", "299-200", "200,,201"] {
            let error = parse_ok_range(&parameters(Some(invalid))).expect_err("range refuses");
            if !invalid.is_empty() {
                assert!(
                    !error.contains(invalid),
                    "diagnostic repeated authored value"
                );
            }
        }
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
    use crate::evidence::{
        EvidenceAcquisition, EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks,
        EvidenceLimits, EvidenceSendIntent,
    };
    use registry_adapter_core::{AdapterEndpointBindings, Endpoint};
    use registry_platform_yaml::SecretProvider;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The empty code-map table: the credential-order lanes convert
    /// nothing.
    fn empty_code_maps() -> crate::scripts::CodeMaps {
        std::sync::Arc::new(BTreeMap::new())
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "the test parses an inline YAML literal to build its input; it reads no operator configuration"
    )]
    fn runtime_config(base_url: &str, key_env: &str) -> AdapterEndpointBindings {
        serde_norway::from_str(&format!(
            r#"
id: credential-order
endpoints:
  - endpoint: tracker
    baseUrl: {base_url}
    credential:
      type: static-api-key
      valueRef: secret:env/{key_env}
allowedPrivateCidrs: [192.168.0.0/16]
"#
        ))
        .expect("the runtime bindings parse")
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "the test parses an inline YAML literal to build its input; it reads no operator configuration"
    )]
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

    pub(super) fn compiled(
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
                safe_post_operations: BTreeSet::new(),
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
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
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
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
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

    struct CredentialGate {
        key_env: String,
        sends: AtomicUsize,
    }

    impl EvidenceHostHooks for CredentialGate {
        fn before_acquisition<'a>(
            &'a self,
            _intent: EvidenceAcquisitionIntent,
        ) -> EvidenceHookFuture<'a> {
            Box::pin(async { Ok(()) })
        }

        fn before_credentials<'a>(&'a self, _intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            std::env::set_var(&self.key_env, "released-only-after-hook");
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn evidence_acquisition_shares_calls_and_runs_hook_before_credentials() {
        let key_env = "ROUTE_EVIDENCE_CREDENTIAL_ORDER_KEY";
        std::env::set_var(key_env, "compile-only");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let endpoints = compiled("http://127.0.0.1:9/", key_env, &resolver);
        std::env::remove_var(key_env);
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
        };
        let hooks = Arc::new(CredentialGate {
            key_env: key_env.to_owned(),
            sends: AtomicUsize::new(0),
        });
        let acquisition = EvidenceAcquisition::begin(
            EvidenceLimits::try_new(1, 30_000, 1024).expect("limits"),
            hooks.clone(),
            EvidenceAcquisitionIntent {
                pack: "pack".to_owned(),
                route: "lookup".to_owned(),
            },
        )
        .await
        .expect("acquisition");

        let first = run_evidence_route(
            &context,
            &get_steps(),
            Exchange::new("first".to_owned()),
            &acquisition,
        )
        .await;
        assert!(
            first
                .events
                .iter()
                .any(|event| event.kind == "exchangeSending"),
            "the hook supplied the credential before the send"
        );

        std::env::remove_var(key_env);
        let second = run_evidence_route(
            &context,
            &get_steps(),
            Exchange::new("second".to_owned()),
            &acquisition,
        )
        .await;
        assert_eq!(
            second.result.expect_err("shared call budget").class,
            ErrorClass::BudgetExhausted
        );
        assert_eq!(hooks.sends.load(Ordering::SeqCst), 1);
        assert!(
            second
                .events
                .iter()
                .all(|event| event.kind != "exchangeSending"),
            "budget refusal is terminal before credentials or transport"
        );
    }
}

#[cfg(test)]
mod provider_schema_route_tests {
    use super::*;
    use crate::artifacts::PackArtifactBytes;
    use registry_adapter_core::ScriptReference;
    use serde_json::json;

    fn schema_reference(bytes: &[u8]) -> ScriptReference {
        serde_json::from_value(json!({
            "path": "schemas/provider.json",
            "digest": registry_platform_config::sha256_uri(bytes)
        }))
        .expect("reference")
    }

    async fn run(body: Value) -> Result<Exchange, RouteFailure> {
        let schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["birthDate"],
            "properties": {"birthDate": {"type": "string", "format": "date"}}
        }))
        .expect("schema");
        let reference = schema_reference(&schema);
        let artifacts = PackArtifactBytes::new([("schemas/provider.json".to_owned(), schema)]);
        let mut scripts = ScriptSet::default();
        scripts
            .add_provider_schema_from(&artifacts, &reference)
            .expect("schema compiles before the route runs");
        let endpoints = BTreeMap::new();
        let resolver = SecretResolver::disabled();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 0,
            job: crate::job_sources::JobPageState::default(),
        };
        let mut exchange = Exchange::new("provider-schema".to_owned());
        exchange.message.body = body;
        run_route(&context, &[Step::ValidateSchema(reference)], exchange)
            .await
            .result
    }

    #[tokio::test]
    async fn provider_schema_validation_is_digest_pinned_and_terminal() {
        assert!(run(json!({"birthDate": "2000-02-29"})).await.is_ok());

        let failure = run(json!({"birthDate": "2026-02-31"}))
            .await
            .expect_err("an invalid provider envelope is terminal");
        assert_eq!(failure.class, ErrorClass::DisclosureViolation);
        assert_eq!(failure.code, Some("adapter.source.response-schema"));
        assert!(failure.class.is_uncatchable());
    }
}

#[cfg(test)]
mod send_attempt_tests {
    use super::*;
    use crate::evidence::{
        EvidenceAcquisition, EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks,
        EvidenceLimits,
    };
    use registry_platform_yaml::SecretProvider;
    use std::io::{Read, Write};
    use std::sync::Mutex;

    /// A loopback source that answers each connection with the next
    /// canned `(status, JSON body)` reply and records every request body
    /// it received, parsed as JSON (an empty body is null).
    fn canned_source<T: Into<String> + Send + 'static>(
        replies: Vec<(u16, T)>,
    ) -> (String, Arc<Mutex<Vec<Value>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let port = listener.local_addr().expect("the bound address").port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&received);
        std::thread::spawn(move || {
            for (status, body) in replies {
                let body = body.into();
                let (mut stream, _) = listener.accept().expect("a source connection");
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                let head_end = loop {
                    let read = stream.read(&mut chunk).expect("read the request");
                    assert!(read > 0, "the request ended inside its head");
                    request.extend_from_slice(&chunk[..read]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let head = String::from_utf8_lossy(&request[..head_end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map_or(0, |value| value.trim().parse::<usize>().expect("a length"));
                while request.len() < head_end + length {
                    let read = stream.read(&mut chunk).expect("read the request body");
                    assert!(read > 0, "the request ended inside its body");
                    request.extend_from_slice(&chunk[..read]);
                }
                let sent = &request[head_end..head_end + length];
                recorded
                    .lock()
                    .expect("the record")
                    .push(if sent.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(sent).expect("a JSON request body")
                    });
                let reply = format!(
                    "HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).expect("write the reply");
            }
        });
        (format!("http://127.0.0.1:{port}/"), received)
    }

    fn steps(value: Value) -> Vec<Step> {
        serde_json::from_value(value).expect("the steps parse")
    }

    #[derive(Debug)]
    struct AcceptanceCustody;

    impl crate::exchange::WriteCustody for AcceptanceCustody {
        fn claim<'a>(
            &'a self,
            _key: &'a str,
            _eager: bool,
        ) -> Pin<
            Box<dyn Future<Output = Result<crate::exchange::WriteClaim, RouteFailure>> + Send + 'a>,
        > {
            Box::pin(async { Ok(crate::exchange::WriteClaim::Execute) })
        }

        fn before_effect<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn mark_unsupported_incomplete<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<bool, RouteFailure>> + Send + 'a>> {
            Box::pin(async { panic!("a valid declared acceptance is not unsupported") })
        }

        fn complete<'a>(
            &'a self,
            _succeeded: bool,
            _remove_on_failure: bool,
        ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
            Box::pin(async { panic!("accepted custody is completed by the host") })
        }
    }

    struct EvidenceHooks;

    impl EvidenceHostHooks for EvidenceHooks {
        fn before_acquisition<'a>(
            &'a self,
            _intent: EvidenceAcquisitionIntent,
        ) -> EvidenceHookFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    async fn evidence_acquisition(
        maximum_operations: u64,
        maximum_bytes: usize,
    ) -> EvidenceAcquisition {
        EvidenceAcquisition::begin(
            EvidenceLimits::try_new(maximum_operations, 30_000, maximum_bytes).expect("limits"),
            Arc::new(EvidenceHooks),
            EvidenceAcquisitionIntent {
                pack: "wire-byte-pack".to_owned(),
                route: "wire-byte-route".to_owned(),
            },
        )
        .await
        .expect("acquisition")
    }

    #[tokio::test]
    async fn evidence_budget_counts_wire_whitespace_before_json_normalization() {
        let key_env = "ROUTE_EVIDENCE_WIRE_BYTES_KEY";
        std::env::set_var(key_env, "wire-byte-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let body = format!("{}{{\"ok\":true}}{}", " ".repeat(80), " ".repeat(80));
        let (base_url, _) = canned_source(vec![(200, body)]);
        let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 2,
            job: crate::job_sources::JobPageState::default(),
        };
        let acquisition = evidence_acquisition(2, 128).await;
        let route = steps(json!([{"to": {"uri": "http:tracker", "parameters": {
            "httpMethod": "GET", "path": "/lookup"
        }}}]));

        let outcome = run_evidence_route(
            &context,
            &route,
            Exchange::new("wire-whitespace".to_owned()),
            &acquisition,
        )
        .await;

        assert_eq!(
            outcome
                .result
                .expect_err("raw body exceeds acquisition budget")
                .class,
            ErrorClass::BudgetExhausted
        );
    }

    #[tokio::test]
    async fn evidence_budget_aggregates_wire_bytes_across_retried_error_replies() {
        let key_env = "ROUTE_EVIDENCE_RETRY_BYTES_KEY";
        std::env::set_var(key_env, "retry-byte-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let busy = format!("{}{{\"busy\":true}}{}", " ".repeat(48), " ".repeat(48));
        let found = format!("{}{{\"ok\":true}}{}", " ".repeat(24), " ".repeat(24));
        let (base_url, received) = canned_source(vec![(503, busy), (200, found)]);
        let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 3,
            job: crate::job_sources::JobPageState::default(),
        };
        let acquisition = evidence_acquisition(3, 128).await;
        let route = steps(json!([
            {"errorHandler": {"defaultErrorHandler": {
                "redeliveryPolicy": {"maximumRedeliveries": 1, "retryDelaySeconds": 1},
                "retryWhile": {"jsonpath": "$.busy"}
            }}},
            {"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "GET", "path": "/lookup"
            }}}
        ]));

        let outcome = run_evidence_route(
            &context,
            &route,
            Exchange::new("wire-retry".to_owned()),
            &acquisition,
        )
        .await;

        assert_eq!(
            outcome
                .result
                .expect_err("aggregate raw bodies exceed budget")
                .class,
            ErrorClass::BudgetExhausted
        );
        assert_eq!(received.lock().expect("requests").len(), 2);
    }

    #[tokio::test]
    async fn evidence_budget_aggregates_wire_bytes_across_repeated_page_calls() {
        let key_env = "ROUTE_EVIDENCE_PAGE_BYTES_KEY";
        std::env::set_var(key_env, "page-byte-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let page_one = format!("{}{{\"page\":1}}{}", " ".repeat(32), " ".repeat(32));
        let page_two = format!("{}{{\"page\":2}}{}", " ".repeat(32), " ".repeat(32));
        let (base_url, received) = canned_source(vec![(200, page_one), (200, page_two)]);
        let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 3,
            job: crate::job_sources::JobPageState::default(),
        };
        let acquisition = evidence_acquisition(3, 128).await;
        let route = steps(json!([{"to": {"uri": "http:tracker", "parameters": {
            "httpMethod": "GET", "path": "/page"
        }}}]));

        let first = run_evidence_route(
            &context,
            &route,
            Exchange::new("page-one".to_owned()),
            &acquisition,
        )
        .await;
        assert_eq!(
            first.result.expect("first page").message.body,
            json!({"page": 1})
        );
        let second = run_evidence_route(
            &context,
            &route,
            Exchange::new("page-two".to_owned()),
            &acquisition,
        )
        .await;
        assert_eq!(
            second
                .result
                .expect_err("aggregate pages exceed budget")
                .class,
            ErrorClass::BudgetExhausted
        );
        assert_eq!(received.lock().expect("requests").len(), 2);
    }

    /// An upstream 202 to a write is an incomplete effect whatever the
    /// send's authored success range says: a range that excludes 202
    /// raises the failure, and a handled clause answering a valid record
    /// still leaves the write marked unsupported-incomplete, so the
    /// facade never records it as completed.
    #[tokio::test]
    async fn an_upstream_202_marks_the_write_incomplete_whatever_the_ok_range() {
        for (key_env, range) in [
            ("ROUTE_ACCEPTED_DEFAULT_RANGE_KEY", None),
            ("ROUTE_ACCEPTED_NARROW_RANGE_KEY", Some("200-201")),
        ] {
            std::env::set_var(key_env, "accepted-key");
            let resolver =
                SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
            let (base_url, _) = canned_source(vec![(202, r#"{"id":"person-1"}"#)]);
            let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
            let scripts = ScriptSet::default();
            let resilience = crate::resilience::ResilienceRuntime::empty();
            let routes = RouteTable::new();
            let context = RouteContext {
                endpoints: &endpoints,
                scripts: &scripts,
                resolver: &resolver,
                resilience: &resilience,
                routes: &routes,
                code_maps: Arc::new(BTreeMap::new()),
                maximum_upstream_calls: 4,
                job: crate::job_sources::JobPageState::default(),
            };
            let mut parameters = json!({
                "httpMethod": "POST",
                "path": "/records",
                "body": {"jsonpath": "$"},
                "operation": "create-record"
            });
            if let Some(range) = range {
                parameters["okStatusCodeRange"] = json!(range);
            }
            let route = steps(json!([
                {"onException": {
                    "exception": ["upstream.http"],
                    "handled": true,
                    "steps": [{"setBody": {"jsonpath": "$"}}]
                }},
                {"idempotentConsumer": {
                    "expression": {"header": "Idempotency-Key"},
                    "steps": [{"to": {"uri": "http:tracker", "parameters": parameters}}]
                }}
            ]));
            let mut exchange = Exchange::new("accepted".to_owned());
            exchange.message.body = json!({"id": "person-1"});
            exchange
                .message
                .set_header("Idempotency-Key", json!("accepted-key"));
            let write = crate::replay::ReplayWriteContext::install(&mut exchange)
                .expect("the write capability installs");

            let _outcome = run_route(&context, &route, exchange).await;

            assert!(
                write.is_unsupported_incomplete().await,
                "an upstream 202 under range {range:?} leaves the write incomplete"
            );
        }
    }

    /// A 202 on a linear-resume step is acceptance, not a checkpoint: the
    /// ordinal stays resumable whether the reply read cleanly (success
    /// path) or failed to read (error path), and the write is never marked
    /// unsupported-incomplete.
    #[tokio::test]
    async fn a_202_on_a_resume_step_keeps_the_write_resumable_on_both_paths() {
        for (key_env, accepted_body) in [
            ("ROUTE_RESUME_ACCEPTED_JSON_KEY", r#"{"queued":true}"#),
            ("ROUTE_RESUME_ACCEPTED_UNREADABLE_KEY", "not json"),
        ] {
            std::env::set_var(key_env, "resume-key");
            let resolver =
                SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
            let (base_url, received) =
                canned_source(vec![(200, r#"{"id":"first"}"#), (202, accepted_body)]);
            let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
            let scripts = ScriptSet::default();
            let resilience = crate::resilience::ResilienceRuntime::empty();
            let routes = RouteTable::new();
            let context = RouteContext {
                endpoints: &endpoints,
                scripts: &scripts,
                resolver: &resolver,
                resilience: &resilience,
                routes: &routes,
                code_maps: Arc::new(BTreeMap::new()),
                maximum_upstream_calls: 4,
                job: crate::job_sources::JobPageState::default(),
            };
            let send = |path: &str| {
                json!({"to": {"uri": "http:tracker", "parameters": {
                    "httpMethod": "POST", "path": path, "body": {"jsonpath": "$"}
                }}})
            };
            let mut operation = async_served_operation(steps(json!([{"idempotentConsumer": {
                "expression": {"header": "Idempotency-Key"},
                "steps": [send("/first"), send("/second")]
            }}])));
            operation.async_completion = None;
            operation.resume = Some(crate::resume::ServedResumeOperation::linear_for_tests(2));
            let mut exchange = Exchange::new("resume-accepted".to_owned());
            exchange.message.body = json!({"name": "Ada"});
            exchange
                .message
                .set_header("Idempotency-Key", json!("resume-key"));
            let write = crate::replay::ReplayWriteContext::install(&mut exchange)
                .expect("write capability");
            let profile = crate::load::two_record_types_inputs().0;

            let failure = run_served_route(&context, &profile, &operation, exchange)
                .await
                .result
                .expect_err("an accepted resume step is not a completed checkpoint");

            assert_eq!(received.lock().expect("requests").len(), 2);
            assert!(
                !write.is_unsupported_incomplete().await,
                "a 202 with body {accepted_body:?} on a resume step keeps the write resumable (class {:?})",
                failure.class
            );
        }
    }

    /// A job source step that reaches the interpreter of a build without
    /// its component says so under the closed job code, rather than
    /// blaming the route kind.
    #[cfg(not(any(
        feature = "job-postgres",
        feature = "job-file",
        feature = "job-rabbitmq"
    )))]
    #[tokio::test]
    async fn a_job_source_step_in_a_build_without_its_component_names_the_missing_component() {
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let endpoints = BTreeMap::new();
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
        };
        for (route, cause, feature) in [
            (
                steps(
                    json!([{"to": {"uri": "postgres:ledger", "parameters": {"queryParameters": {}}}}]),
                ),
                "the postgres source component",
                "job-postgres",
            ),
            (
                steps(json!([{"pollEnrich": {
                    "uri": "file:inbox", "timeoutMilliseconds": 1000, "decoder": "raw"
                }}])),
                "no job source component",
                "job-file or job-rabbitmq",
            ),
        ] {
            let failure = run_route(&context, &route, Exchange::new("job".to_owned()))
                .await
                .result
                .expect_err("the step is refused");
            let message = failure.message.as_deref().unwrap_or_default();
            assert_eq!(
                failure.code,
                Some("adapter.job.component-unavailable"),
                "{message}"
            );
            assert!(
                message.contains(cause)
                    && message.contains("compiled into this binary")
                    && message.contains(feature),
                "{message}"
            );
        }
    }

    fn async_served_operation(steps: Vec<Step>) -> crate::load::ServedOperation {
        use crate::async_completion::{
            AcceptedIdSelector, AsyncSourceOperation, ServedAsyncOperation, ServedAsyncStatusRoute,
        };

        crate::load::ServedOperation {
            operation: "records-create".to_owned(),
            method: HttpMethod::Post,
            method_path: "/v1/records/{recordType}".to_owned(),
            request_template: None,
            request_maximum_bytes: 1024,
            filters: Vec::new(),
            record_type_parameter: "recordType".to_owned(),
            record_id_parameter: None,
            binding: "person-create".to_owned(),
            record_type: "person".to_owned(),
            route_id: "create".to_owned(),
            steps: Arc::new(steps),
            resilience: crate::resilience::ResilienceRuntime::empty(),
            maximum_upstream_calls: 4,
            response_envelope: crate::envelope::CompiledEnvelope::compile("{}", &BTreeMap::new())
                .expect("envelope"),
            item_envelope: None,
            record_schema: json!({
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": false
            }),
            pagination: None,
            async_completion: Some(ServedAsyncOperation {
                initial: AsyncSourceOperation {
                    endpoint: "tracker".to_owned(),
                    operation: "create-record".to_owned(),
                },
                accepted_id: AcceptedIdSelector::compile("$.id").expect("selector"),
                status: ServedAsyncStatusRoute {
                    route_id: "status".to_owned(),
                    steps: Arc::new(Vec::new()),
                    maximum_upstream_calls: 1,
                    endpoint_ids: BTreeSet::from(["tracker".to_owned()]),
                },
                uncertainty: None,
            }),
            resume: None,
            project_transform: None,
            project_input_schema: None,
            read_support: None,
        }
    }

    /// Source acceptance is an engine control result, not an ordinary route
    /// reply. No authored handler, continuation step, or doFinally cleanup may
    /// normalize it or issue another source request.
    #[tokio::test]
    async fn a_declared_202_bypasses_handlers_finally_and_later_steps() {
        let key_env = "ROUTE_ASYNC_ACCEPTED_KEY";
        std::env::set_var(key_env, "accepted-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let (base_url, received) = canned_source(vec![(202, r#"{"id":"source-17"}"#)]);
        let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
        };
        let operation = async_served_operation(steps(json!([
            {"onException": {
                "exception": ["upstream.http"],
                "handled": true,
                "steps": [{"setBody": {"constant": {"normalized": true}}}]
            }},
            {"idempotentConsumer": {
                "expression": {"header": "Idempotency-Key"},
                "completionEager": true,
                "steps": [
                    {"doTry": {
                        "steps": [{"to": {"uri": "http:tracker", "parameters": {
                            "httpMethod": "POST",
                            "path": "/records",
                            "body": {"jsonpath": "$"},
                            "operation": "create-record",
                            "okStatusCodeRange": "200-201"
                        }}}],
                        "doFinally": {"steps": [{"to": {"uri": "http:tracker", "parameters": {
                            "httpMethod": "GET", "path": "/must-not-run"
                        }}}]}
                    }},
                    {"setBody": {"constant": {"normalized": true}}},
                    {"throwException": {"exceptionType": "outcome.rejected"}}
                ]
            }}
        ])));
        let mut exchange = Exchange::new("accepted".to_owned());
        exchange.message.body = json!({"name": "Ada"});
        exchange
            .message
            .set_header("Idempotency-Key", json!("accepted-key"));
        exchange.install_write(Arc::new(AcceptanceCustody));
        let profile = crate::load::two_record_types_inputs().0;

        let done = run_served_route(&context, &profile, &operation, exchange)
            .await
            .result
            .expect("acceptance is returned to the host");

        assert_eq!(
            done.async_source_acceptance()
                .expect("typed acceptance")
                .source_id,
            "source-17"
        );
        assert_eq!(received.lock().expect("requests").len(), 1);
    }

    #[tokio::test]
    async fn a_declared_202_with_no_bounded_id_remains_spent_and_uncertain() {
        let key_env = "ROUTE_ASYNC_BAD_ACCEPTED_KEY";
        std::env::set_var(key_env, "accepted-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let (base_url, _) =
            canned_source(vec![(202, r#"{"id":"https://source.invalid/jobs/17"}"#)]);
        let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
        };
        let operation = async_served_operation(steps(json!([{"idempotentConsumer": {
            "expression": {"header": "Idempotency-Key"},
            "steps": [{"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "POST", "path": "/records", "body": {"jsonpath": "$"},
                "operation": "create-record"
            }}}]
        }}])));
        let mut exchange = Exchange::new("bad-accepted".to_owned());
        exchange.message.body = json!({"name": "Ada"});
        exchange
            .message
            .set_header("Idempotency-Key", json!("accepted-key"));
        let write =
            crate::replay::ReplayWriteContext::install(&mut exchange).expect("write capability");
        let profile = crate::load::two_record_types_inputs().0;

        let failure = run_served_route(&context, &profile, &operation, exchange)
            .await
            .result
            .expect_err("unparseable acceptance is uncertain");

        assert_eq!(failure.class, ErrorClass::UpstreamHttp);
        assert!(write.is_unsupported_incomplete().await);
    }

    #[tokio::test]
    async fn a_status_poll_uses_a_fresh_exchange_and_malformed_terminal_stays_uncertain() {
        let key_env = "ROUTE_ASYNC_STATUS_KEY";
        std::env::set_var(key_env, "status-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let (base_url, received) = canned_source(vec![
            (200, r#"{"state":"pending"}"#),
            (200, r#"{"state":"succeeded","result":{"undeclared":true}}"#),
        ]);
        let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let status_steps = steps(json!([{"to": {"uri": "http:tracker", "parameters": {
            "httpMethod": "GET",
            "path": "/status/{{id}}",
            "pathParameters": {
                "id": {"exchangeProperty": "AdapterAsyncOperationId"}
            },
            "operation": "status-record"
        }}}]));
        let routes = RouteTable::from([("status".to_owned(), Arc::new(status_steps.clone()))]);
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
        };
        let mut operation = async_served_operation(Vec::new());
        operation
            .async_completion
            .as_mut()
            .expect("async")
            .status
            .steps = Arc::new(status_steps);
        let profile = crate::load::two_record_types_inputs().0;

        let pending = run_async_status_poll(
            &context,
            &profile,
            &operation,
            AsyncStatusPollKind::Primary,
            "source-17",
            "poll-01",
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .result
        .expect("pending status");
        assert!(matches!(
            pending,
            registry_adapter_core::AsyncStatusOutcome::Pending {}
        ));

        let malformed = run_async_status_poll(
            &context,
            &profile,
            &operation,
            AsyncStatusPollKind::Primary,
            "source-17",
            "poll-02",
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .result
        .expect_err("malformed terminal proof stays uncertain");
        assert_eq!(malformed.class, ErrorClass::DisclosureViolation);
        assert_eq!(
            received.lock().expect("requests").as_slice(),
            [Value::Null, Value::Null]
        );
    }

    #[tokio::test]
    async fn a_host_deadline_that_already_elapsed_starts_no_served_route_io() {
        let key_env = "ROUTE_ASYNC_ELAPSED_KEY";
        std::env::set_var(key_env, "elapsed-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let (base_url, received) = canned_source(vec![(202, r#"{"id":"source-17"}"#)]);
        let endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
        };
        let operation = async_served_operation(steps(json!([{"idempotentConsumer": {
            "expression": {"header": "Idempotency-Key"},
            "steps": [{"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "POST", "path": "/records", "body": {"jsonpath": "$"},
                "operation": "create-record"
            }}}]
        }}])));
        let mut exchange = Exchange::new("elapsed".to_owned());
        exchange.message.body = json!({"name": "Ada"});
        exchange
            .message
            .set_header("Idempotency-Key", json!("elapsed-key"));
        crate::replay::ReplayWriteContext::install(&mut exchange).expect("write capability");
        let profile = crate::load::two_record_types_inputs().0;

        let outcome = run_served_route_until(
            &context,
            &profile,
            &operation,
            exchange,
            tokio::time::Instant::now(),
        )
        .await;

        assert_eq!(
            outcome.result.expect_err("elapsed deadline").class,
            ErrorClass::BudgetExhausted
        );
        assert!(received.lock().expect("requests").is_empty());
    }

    /// A redelivered send renders its request from the message it was
    /// first sent with, not from the failure the attempt left on the
    /// exchange; the `retryWhile` predicate still reads that failure, and
    /// the redelivery headers ride on the restored message.
    #[tokio::test]
    async fn a_redelivered_send_resends_its_original_request_body() {
        let key_env = "ROUTE_REDELIVERY_BODY_KEY";
        std::env::set_var(key_env, "redelivery-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let (base_url, received) =
            canned_source(vec![(503, r#"{"busy":true}"#), (200, r#"{"found":1}"#)]);
        let mut endpoints = super::credential_order_tests::compiled(&base_url, key_env, &resolver);
        endpoints
            .get_mut("tracker")
            .expect("the endpoint")
            .safe_post_operations
            .insert("search".to_owned());
        let scripts = ScriptSet::default();
        let resilience = crate::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: Arc::new(BTreeMap::new()),
            maximum_upstream_calls: 4,
            job: crate::job_sources::JobPageState::default(),
        };
        let route = steps(json!([
            {"errorHandler": {"defaultErrorHandler": {
                "redeliveryPolicy": {"maximumRedeliveries": 1, "retryDelaySeconds": 1},
                "retryWhile": {"jsonpath": "$.busy"}
            }}},
            {"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "POST",
                "path": "/search",
                "body": {"jsonpath": "$"},
                "operation": "search"
            }}}
        ]));
        let mut exchange = Exchange::new("redelivery".to_owned());
        exchange.message.body = json!({"q": "original"});

        let outcome = run_route(&context, &route, exchange).await;

        let exchange = outcome.result.expect("the redelivered send succeeds");
        assert_eq!(
            *received.lock().expect("the record"),
            vec![json!({"q": "original"}), json!({"q": "original"})],
            "both attempts send the original request body"
        );
        assert_eq!(exchange.message.body, json!({"found": 1}));
        assert_eq!(
            exchange.message.header(REDELIVERED_HEADER),
            Some(&json!(true))
        );
        assert_eq!(
            exchange.message.header(REDELIVERY_COUNTER_HEADER),
            Some(&json!(1))
        );
    }
}
