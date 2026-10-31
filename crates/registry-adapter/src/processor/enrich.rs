// SPDX-License-Identifier: Apache-2.0

//! The `enrich` processor, Camel's Content Enricher
//! (`products/adapter/CONCEPT.md` sections 8.6 and 8.11.7).
//!
//! The resource send runs on a copy of the exchange, and the reply
//! merges back through the `aggregationStrategy`, which by default
//! replaces the body with the resource reply. `aggregateOnException`
//! (default false) sends the failure to the error handler instead, so a
//! record is never served without its enrichment unless the pack
//! handles the failure. The built-in strategies merge bodies only:
//! properties set by the resource route are carried out of the reply
//! only where the strategy names them through `properties`, a map from
//! property name to a JSONPath on the reply, which is how a pagination
//! loop carries the next cursor or link.
//!
//! The send's `CamelHttpResponseCode` header reaches the route exchange
//! whatever the strategy does with the body: the code is the engine's
//! own record of the reply, not a body value.

use registry_adapter_core::{
    AggregationStrategy, EnrichStep, ErrorClass, HttpMethod, SendComponent, Step, ToStep,
};

use crate::processor::aggregation;
use crate::route::{Flow, RouteFailure, Run};

pub(crate) async fn run(run: &mut Run<'_, '_>, step: &EnrichStep) -> Result<Flow, RouteFailure> {
    // The served shapes are refused at load; the runtime holds the same
    // line so a hand-built context cannot slip past it.
    let parameters = match step.uri.component {
        SendComponent::Direct if step.parameters.is_none() => None,
        SendComponent::Http => {
            let Some(parameters) = &step.parameters else {
                return Err(RouteFailure::of(ErrorClass::EgressRefused));
            };
            if !matches!(parameters.http_method, None | Some(HttpMethod::Get)) {
                return Err(RouteFailure::of(ErrorClass::EgressRefused));
            }
            Some(parameters.clone())
        }
        SendComponent::Direct | SendComponent::GraphQl => {
            return Err(RouteFailure::of(ErrorClass::EgressRefused));
        }
        // The job-only components are never facade enrich resources: a
        // file or sftp endpoint is read through the pollEnrich step and
        // a postgres endpoint is a job source send. The authoring
        // checks refuse the pair; the runtime holds the same line so a
        // hand-built context cannot slip past it.
        SendComponent::Postgres | SendComponent::File | SendComponent::Sftp => {
            return Err(RouteFailure::of(ErrorClass::EgressRefused));
        }
    };
    let strategy = step
        .aggregation_strategy
        .clone()
        .unwrap_or(AggregationStrategy::UseLatest {});
    // The resource send runs on a copy of the exchange; the route
    // exchange stands while the copy carries the send and its reply.
    let mut resource = run.exchange.clone();
    std::mem::swap(&mut run.exchange, &mut resource);
    let send = Step::To(ToStep {
        uri: step.uri.clone(),
        parameters,
    });
    let sent = run.step(&send).await;
    std::mem::swap(&mut run.exchange, &mut resource);
    match sent {
        Ok(_) => {}
        // Without aggregateOnException the failure goes to the error
        // handler; the copy's failure state merges only when the pack
        // asked for it.
        Err(failure) if !step.aggregate_on_exception || failure.class.is_uncatchable() => {
            return Err(failure)
        }
        Err(failure) => run.record_consumed_failure("enrich", &failure),
    }
    let old_body = run.exchange.message.body.clone();
    // A custom aggregation strategy may enter Rhai, so the route deadline
    // is checked at the script seam as well as at the enclosing EIP step.
    run.ensure_deadline()?;
    let merged = aggregation::fold_enrich(
        run.context.scripts,
        &run.context.code_maps,
        &strategy,
        &old_body,
        &resource,
        run.deadline,
        run.maximum_exchange_bytes,
    )?;
    run.exchange.message.body = merged.body;
    for (name, value) in merged.properties {
        match value {
            Some(value) => run.exchange.set_property(&name, value),
            None => run.exchange.remove_property(&name),
        }
    }
    if let Some(code) = resource.message.header("CamelHttpResponseCode") {
        run.exchange
            .message
            .set_header("CamelHttpResponseCode", code.clone());
    }
    Ok(Flow::Continue)
}
