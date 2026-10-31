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
    effective_clause_redelivery_policy, is_route_unwritable_header_name,
    is_route_unwritable_property_name, problem_data_schema, resolve_problem,
    validate_result_schema, AdapterEndpointBindings, AdapterProfile, AggregationStrategy,
    ConvertStep, Endpoint, EndpointBinding, EnrichStep, ErrorClass, Expression,
    GraphQlOperationKind, HttpMethod, OnExceptionStep, RedeliveryOptions, SendComponent,
    SetPropertyStep, Step, ToParameters, ToStep, MAX_PROBLEM_DATA_BYTES,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Value};

use crate::engine::auth::{
    AuthError, AuthEvent, AuthKind, PlatformAssertionSigner, TokenBudget, UpstreamStatusAction,
};
use crate::engine::component::http::uri::{encode_path_segment, percent_encode, LinkRefusal};
use crate::engine::egress::{
    EgressError, EgressFault, EndpointEgress, OkStatusCodeRanges, OutboundSend, SendBody,
    SendBodyFormat, SendShape,
};
use crate::engine::exchange::{
    Exchange, NEXT_CONTINUATION_PROPERTY, REDELIVERED_HEADER, REDELIVERY_COUNTER_HEADER,
    REDELIVERY_MAX_COUNTER_HEADER,
};
use crate::engine::language::{compile_selector, JsonPathResult, LanguageError};
use crate::engine::processor;
use crate::engine::scripts::ScriptSet;

/// The step kinds this runtime interprets. Every other kind of the route
/// model is refused at load by [`check_servable`], by name.
/// The longest one exchange may run, across every attempt, redelivery
/// pause, and script. It sits above the largest declared attempt timeout so
/// a single attempt always finishes under its own timeout first.
const EXCHANGE_DEADLINE: Duration = Duration::from_secs(60);

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
    check_steps(steps, false, false)
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
    check_steps(steps, false, true)
}

/// The served shape of a `pollEnrich` read: a static `file:` or `sftp:`
/// uri and a mandatory timeout (`products/adapter/CONCEPT.md` sections
/// 17.1 and 17.2). The authoring checks hold the endpoint and the
/// decoder; the engine holds the step shape again so a source route
/// assembled without them is refused by name.
fn check_poll(poll: &registry_adapter_core::PollEnrichStep) -> Result<(), String> {
    match registry_adapter_core::SendUri::parse(&poll.uri) {
        Some(uri) if matches!(uri.component, SendComponent::File | SendComponent::Sftp) => {}
        _ => {
            return Err(
                "a pollEnrich step is served over a file: or sftp: endpoint only".to_owned(),
            )
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
    if matches!(
        poll.aggregation_strategy,
        Some(AggregationStrategy::GroupedBody {})
    ) {
        return Err("the grouped-body strategy is served for split only".to_owned());
    }
    Ok(())
}

fn check_steps(steps: &[Step], in_clause: bool, job_polls: bool) -> Result<(), String> {
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
                return Err("a pollEnrich step is served in a job source route only".to_owned())
            }
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
                if is_route_unwritable_property_name(name) {
                    return Err(format!(
                        "removeProperty may not remove the reserved property {name}"
                    ));
                }
            }
            Step::Script(expression) => check_expression("script", expression)?,
            Step::ConvertBodyTo(convert) => check_convert("convertBodyTo", convert)?,
            Step::ConvertHeaderTo(convert) => check_convert("convertHeaderTo", convert)?,
            Step::ConvertPropertyTo(convert) => check_convert("convertPropertyTo", convert)?,
            Step::Choice(choice) => {
                for clause in &choice.when {
                    check_predicate("choice", &clause.predicate())?;
                    check_steps(&clause.steps, true, job_polls)?;
                }
                if let Some(otherwise) = &choice.otherwise {
                    check_steps(&otherwise.steps, true, job_polls)?;
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
                check_steps(&filter.steps, true, job_polls)?;
            }
            Step::Validate(validate) => {
                check_predicate_expression("validate", &validate.expression)?
            }
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
                check_steps(&split.steps, true, job_polls)?;
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
                check_steps(&looped.steps, true, job_polls)?;
            }
            Step::Enrich(enrich) => {
                check_enrich(enrich)?;
                check_strategy(enrich.aggregation_strategy.as_ref())?;
            }
            Step::IdempotentConsumer(idempotent) => {
                if !idempotent.eager || idempotent.completion_eager {
                    return Err(
                        "an idempotentConsumer is served only with eager true and completionEager false"
                            .to_owned(),
                    );
                }
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
                check_steps(&idempotent.steps, true, job_polls)?;
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
                if let Some(fallback) = &breaker.on_fallback {
                    if fallback.steps.is_empty() {
                        return Err("an onFallback declares no steps".to_owned());
                    }
                    check_steps(&fallback.steps, true, job_polls)?;
                }
                check_steps(&breaker.steps, true, job_polls)?;
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
                check_steps(&throttle.steps, true, job_polls)?;
            }
            Step::OnException(clause) if !in_clause => {
                check_clause(clause, handler_policy, job_polls)?
            }
            Step::OnException(_) => {
                return Err("an onException clause is served at route top level only".to_owned())
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
                    if let Some(expression) = &catch.on_when {
                        check_predicate_expression("doCatch onWhen", expression)?;
                    }
                    check_steps(&catch.steps, true, job_polls)?;
                }
                if let Some(finally) = &block.do_finally {
                    check_steps(&finally.steps, true, job_polls)?;
                }
                check_steps(&block.steps, true, job_polls)?;
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
fn check_convert(form: &str, convert: &ConvertStep) -> Result<(), String> {
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
        "convertHeaderTo" => is_route_unwritable_header_name(name),
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

fn check_clause(
    clause: &OnExceptionStep,
    handler_policy: Option<&RedeliveryOptions>,
    job_polls: bool,
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
    check_steps(&clause.steps, true, job_polls)
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
            return Err("a to step is served for the http component only".into());
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
    if !parameters.resume_bindings.is_empty() {
        return Err("a to step with resumeBindings is not served".into());
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
#[derive(Debug)]
pub struct EndpointRuntime {
    /// The endpoint's compiled outbound state: the authentication plan, the
    /// origin pin, the header filter and the frozen destination policy.
    pub egress: EndpointEgress,
    /// The origin and base path every link of this endpoint starts with.
    pub base: String,
    /// The pinned GraphQL query, filled by the loader on a `graphql`
    /// endpoint; `None` on every other endpoint and on a graphql
    /// endpoint a caller assembled without the loader.
    pub graphql: Option<crate::engine::component::graphql::GraphQlQuery>,
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
        let base = format!(
            "{}{}",
            egress.origin().origin_url().trim_end_matches('/'),
            egress.origin().base_path()
        );
        Ok(Self {
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
        })
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
            SendComponent::Postgres => true,
            SendComponent::File | SendComponent::Sftp => false,
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
    pub resilience: &'a crate::engine::resilience::ResilienceRuntime,
    /// Every route the deployment declares, pack routes and instantiated
    /// templated routes, keyed by route id: the table a `to: direct:`
    /// send resolves against (section 8.11.7).
    pub routes: &'a RouteTable,
    /// The deployment's declared code maps (section 8.6): the one
    /// table the conversion steps and the Rhai `code_map` helper read.
    pub code_maps: crate::engine::scripts::CodeMaps,
    /// The binding's `maximumUpstreamCalls`.
    pub maximum_upstream_calls: u64,
    /// The governed-ingestion state a job source route runs under:
    /// empty in every facade deployment, whose routes carry no job step.
    pub job: crate::engine::job_sources::JobPageState,
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
        failure.auth = Some(auth_events_detail(events));
    }
    failure
}

/// How a route run failed: the class it raised and, when a
/// `throwException` raised it, the message that fills `problemDetail`.
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
    pub auth: Option<Value>,
    /// The closed engine-read code a job read raised, when the failure
    /// is the read's own (`adapter.job.read-bound`,
    /// `adapter.job.decoder-row`); the job entry reports it beside the
    /// class, and every other failure carries none.
    pub code: Option<&'static str>,
}

impl fmt::Debug for RouteFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RouteFailure");
        debug.field("class", &self.class);
        debug.field("message", &self.message);
        debug.field("data", &self.data.as_ref().map(|_| "<redacted>"));
        debug.field("auth", &self.auth);
        debug.field("code", &self.code);
        debug.finish()
    }
}

impl RouteFailure {
    pub(crate) fn of(class: ErrorClass) -> Self {
        Self {
            class,
            message: None,
            data: None,
            auth: None,
            code: None,
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
    run_route_within_profile(
        context,
        None,
        steps,
        exchange,
        EXCHANGE_DEADLINE,
        crate::engine::exchange::MAXIMUM_EXCHANGE_BYTES,
    )
    .await
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
        crate::engine::exchange::MAXIMUM_EXCHANGE_BYTES,
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
        crate::engine::exchange::MAXIMUM_EXCHANGE_BYTES,
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
    )
    .await
}

async fn run_route_within_profile<'a>(
    context: &'a RouteContext<'_>,
    problem_profile: Option<&'a AdapterProfile>,
    steps: &[Step],
    exchange: Exchange,
    deadline: Duration,
    maximum_exchange_bytes: usize,
) -> RouteOutcome {
    if let Err(class) = exchange.ensure_bounded_within(maximum_exchange_bytes) {
        return RouteOutcome {
            result: Err(RouteFailure::of(class)),
            events: Vec::new(),
        };
    }
    let mut run = Run {
        context,
        problem_profile,
        exchange,
        events: Vec::new(),
        sends: 0,
        direct_depth: 0,
        exception_clause_depth: 0,
        token_budget: TokenBudget::new_exchange(),
        deadline: tokio::time::Instant::now() + deadline,
        maximum_exchange_bytes,
    };
    let body = run.run_route_body(steps);
    let mut result = tokio::time::timeout(deadline, body)
        .await
        .unwrap_or_else(|_| Err(RouteFailure::of(ErrorClass::BudgetExhausted)));
    if result.is_ok() {
        if let Err(class) = run.exchange.ensure_bounded_within(maximum_exchange_bytes) {
            result = Err(RouteFailure::of(class));
        }
    }
    let Run {
        exchange, events, ..
    } = run;
    RouteOutcome {
        result: result.map(|_| exchange),
        events,
    }
}

/// A script failure as a route failure: an unmapped lookup keeps its
/// map id in the message (section 8.6); the class alone answers for
/// the rest.
pub(crate) fn script_failure(failure: crate::engine::scripts::ScriptFailure) -> RouteFailure {
    match failure {
        crate::engine::scripts::ScriptFailure::Unmapped(_) => RouteFailure {
            class: failure.class(),
            message: Some(failure.to_string()),
            data: None,
            auth: None,
            code: None,
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
    /// The instant the whole run must end by: a step that waits (the
    /// throttler's pause, a redelivery delay) refuses with its own class
    /// when the wait cannot finish before this, instead of letting the
    /// run's budget expire it as `budget.exhausted`.
    pub(crate) deadline: tokio::time::Instant,
    /// The retained-JSON ceiling this run applies to the exchange: the
    /// facade's fixed budget, or the job profile's response bound for a
    /// job page run (section 17.2).
    pub(crate) maximum_exchange_bytes: usize,
}

impl Run<'_, '_> {
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
                Ok(Flow::Continue) => {}
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
            match self.step(step).await? {
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
                    let delay = crate::engine::processor::redelivery::calculate_redelivery_delay(
                        previous_delay,
                        policy,
                        crate::engine::processor::redelivery::draw_variance(policy),
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
                return Ok(Flow::Handled);
            }
            if clause.continued == Some(true) {
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
            detail["auth"] = auth.clone();
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
                })
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
            #[cfg(feature = "job-file")]
            Step::PollEnrich(poll) => Box::pin(processor::poll_enrich::run(self, poll)).await,
            #[cfg(not(feature = "job-file"))]
            Step::PollEnrich(_) => Err(RouteFailure {
                class: ErrorClass::EgressRefused,
                message: Some("a pollEnrich step is served in a job source route only".to_owned()),
                data: None,
                auth: None,
                code: None,
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

    async fn send(&mut self, to: &ToStep) -> Result<Flow, RouteFailure> {
        if to.uri.component == SendComponent::Direct {
            return self.direct(to).await;
        }
        // The job-only sources are never send destinations: a file or
        // sftp endpoint is read through the pollEnrich step, and the
        // postgres source is a job send served by the job compiler's
        // own component state. The runtime holds the line before any
        // endpoint lookup, uncatchably, the way the origin pin does.
        match to.uri.component {
            SendComponent::File | SendComponent::Sftp => {
                return Err(RouteFailure {
                    class: ErrorClass::EgressRefused,
                    message: Some("a job source endpoint is read through the pollEnrich step only, never sent to".to_owned()),
                    data: None,
                    auth: None,
                code: None,
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
                        code: None,
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
                        code: None,
                    });
                };
                // The read-only source send counts against the run's
                // upstream-call budget like every other send.
                self.sends += 1;
                if self.sends > self.context.maximum_upstream_calls {
                    return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
                }
                return crate::engine::component::postgres::send(self, plan, source.as_ref(), to)
                    .await;
            }
            #[cfg(not(feature = "job-postgres"))]
            SendComponent::Postgres => {
                return Err(RouteFailure {
                    class: ErrorClass::EgressRefused,
                    message: Some(
                        "a postgres source send is served in a job source route only".to_owned(),
                    ),
                    data: None,
                    auth: None,
                    code: None,
                });
            }
            SendComponent::Direct | SendComponent::Http | SendComponent::GraphQl => {}
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
        let mut post_body: Option<Vec<u8>> = None;
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
                post_body = Some(
                    serde_json::to_vec(&self.eval(body)?)
                        .map_err(|_| RouteFailure::of(ErrorClass::Validation))?,
                );
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

        let mut auth_events: Vec<AuthEvent> = Vec::new();
        self.sends += 1;
        if self.sends > self.context.maximum_upstream_calls {
            return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
        }
        self.ensure_deadline()?;
        let authorized = tokio::time::timeout_at(
            self.deadline,
            endpoint.egress.authorize(
                &mut self.token_budget,
                self.context.resolver,
                &PlatformAssertionSigner,
                &mut auth_events,
            ),
        )
        .await
        .map_err(|_| RouteFailure::of(ErrorClass::BudgetExhausted))?;
        let method = if graphql
            || parameters.is_some_and(|parameters| parameters.http_method == Some(HttpMethod::Post))
        {
            "POST"
        } else {
            "GET"
        };
        // The send is announced only once its credential is in hand; a
        // credential failure never reads as a send that began.
        let mut credential = authorized.map_err(|error| auth_failure(&error, &auth_events))?;
        let headers = self.exchange.message.string_headers();
        let safe = endpoint.send_is_safe(to.uri.component, parameters);
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
                self.exchange.before_upstream_effect().await?;
            }
            self.ensure_deadline()?;
            let remaining = self
                .deadline
                .saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
            }
            let started = Instant::now();
            let reply = tokio::time::timeout_at(
                self.deadline,
                endpoint.egress.send(OutboundSend {
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
                }),
            )
            .await
            .map_err(|_| RouteFailure::of(ErrorClass::BudgetExhausted))?;
            self.ensure_deadline()?;
            let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let status = match &reply {
                Ok(reply) => Some(reply.status),
                Err(EgressError::Upstream(failure)) => failure.status,
                Err(EgressError::Refused(_)) => None,
            };
            let action = match status {
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
                credential = tokio::time::timeout_at(
                    self.deadline,
                    endpoint.egress.authorize(
                        &mut self.token_budget,
                        self.context.resolver,
                        &PlatformAssertionSigner,
                        &mut auth_events,
                    ),
                )
                .await
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
                    failure.auth = Some(auth_events_detail(&auth_events));
                }
                return Err(failure);
            }
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
                    if reply.status == 202
                        && self.exchange.mark_unsupported_incomplete_write().await?
                    {
                        return Err(RouteFailure::of(ErrorClass::UpstreamHttp));
                    }
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
                        match graphql_reply_body(&message.body) {
                            Ok(body) => message.body = body,
                            Err(mut failure) => {
                                if !auth_events.is_empty() {
                                    failure.auth = Some(auth_events_detail(&auth_events));
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
                    if let EgressError::Upstream(failure) = error {
                        let message = &mut self.exchange.message;
                        message.body = failure.body.unwrap_or(Value::Null);
                        if let Some(status) = failure.status {
                            message.set_header("CamelHttpResponseCode", json!(status));
                        }
                    }
                    let mut failure = RouteFailure::of(class);
                    if !auth_events.is_empty() {
                        failure.auth = Some(auth_events_detail(&auth_events));
                    }
                    Err(failure)
                }
            };
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
    use registry_adapter_core::{AdapterEndpointBindings, Endpoint};
    use registry_platform_yaml::SecretProvider;

    /// The empty code-map table: the credential-order lanes convert
    /// nothing.
    fn empty_code_maps() -> crate::engine::scripts::CodeMaps {
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
        let resilience = crate::engine::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 4,
            job: crate::engine::job_sources::JobPageState::default(),
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
        let resilience = crate::engine::resilience::ResilienceRuntime::empty();
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &endpoints,
            scripts: &scripts,
            resolver: &resolver,
            resilience: &resilience,
            routes: &routes,
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 4,
            job: crate::engine::job_sources::JobPageState::default(),
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
