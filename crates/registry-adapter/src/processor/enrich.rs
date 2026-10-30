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
    if step.uri.component != SendComponent::Http {
        return Err(RouteFailure::of(ErrorClass::EgressRefused));
    }
    let Some(parameters) = &step.parameters else {
        return Err(RouteFailure::of(ErrorClass::EgressRefused));
    };
    if !matches!(parameters.http_method, None | Some(HttpMethod::Get)) {
        return Err(RouteFailure::of(ErrorClass::EgressRefused));
    }
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
        parameters: Some(parameters.clone()),
    });
    let sent = run.step(&send).await;
    std::mem::swap(&mut run.exchange, &mut resource);
    match sent {
        Ok(_) => {}
        // Without aggregateOnException the failure goes to the error
        // handler; the copy's failure state merges only when the pack
        // asked for it.
        Err(failure) if !step.aggregate_on_exception => return Err(failure),
        Err(_) => {}
    }
    let old_body = run.exchange.message.body.clone();
    let merged = aggregation::fold(
        run.context.scripts,
        &run.context.code_maps,
        &strategy,
        &old_body,
        &resource,
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
