// SPDX-License-Identifier: Apache-2.0

//! The conversion processors (`products/adapter/CONCEPT.md` section
//! 8.6): `convertBodyTo`, `convertHeaderTo`, and `convertPropertyTo`
//! over one declared code map, Camel's type converter in the port's
//! form. The lookup is exact and case-sensitive over a string input; a
//! null or absent input passes through unchanged whatever `mandatory`
//! says, any other non-string input or a miss raises
//! `conversion.unmapped`, and with `mandatory: false` a miss leaves the
//! target absent. A header or property conversion with `toName` writes
//! the result there and leaves the source untouched, as Camel's
//! `convertHeaderTo` does.

use registry_adapter_core::{ConvertStep, ErrorClass};

use crate::route::{Flow, RouteFailure, Run};

/// The failure a refused conversion answers with: the class and the
/// reviewed map id, never the key or the input value.
fn unmapped(map_id: &str, condition: &str) -> RouteFailure {
    RouteFailure {
        class: ErrorClass::ConversionUnmapped,
        message: Some(format!("code map {map_id} {condition}")),
        auth: None,
    }
}

/// The result one conversion writes, if it writes one: `None` stands
/// for "leave the target as it is" (a null or absent input, or a miss
/// under `mandatory: false`).
fn lookup(
    run: &Run<'_, '_>,
    step: &ConvertStep,
    input: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, RouteFailure> {
    // A null or absent input passes through unchanged whatever
    // `mandatory` says (Camel's `ConvertBodyTest.testConvertNullBody`).
    let key = match input {
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(serde_json::Value::String(key)) => key.as_str(),
        Some(_) => {
            let map_id = declared_map_id(step)?;
            return Err(unmapped(map_id, "takes a string key"));
        }
    };
    let map_id = declared_map_id(step)?;
    let map = run.context.code_maps.get(map_id).ok_or_else(|| {
        // The loader resolves every literal id at load; a table without
        // the map never served this step.
        unmapped(map_id, "is not declared")
    })?;
    match map.lookup(key) {
        Some(value) => Ok(Some(value.clone())),
        None if step.mandatory.unwrap_or(true) => Err(unmapped(map_id, "has no entry for the key")),
        None => Ok(None),
    }
}

/// The map id the step's `type` names; the served-shape check holds the
/// `codeMap:<id>` spelling, so this only keeps the run time honest.
fn declared_map_id(step: &ConvertStep) -> Result<&str, RouteFailure> {
    step.code_map_id()
        .ok_or_else(|| RouteFailure::of(ErrorClass::Validation))
}

/// `convertBodyTo`: the body is both the source and the target.
pub(crate) fn body(run: &mut Run<'_, '_>, step: &ConvertStep) -> Result<Flow, RouteFailure> {
    if let Some(value) = lookup(run, step, Some(&run.exchange.message.body))? {
        run.exchange.message.body = value;
    }
    Ok(Flow::Continue)
}

/// `convertHeaderTo`: convert the header `name` names, in place unless
/// `toName` redirects the result.
pub(crate) fn header(run: &mut Run<'_, '_>, step: &ConvertStep) -> Result<Flow, RouteFailure> {
    let Some(source) = step.name.as_deref() else {
        return Err(RouteFailure::of(ErrorClass::Validation));
    };
    let input = run.exchange.message.header(source);
    if let Some(value) = lookup(run, step, input)? {
        let target = step.to_name.as_deref().unwrap_or(source);
        run.exchange.message.set_header(target, value);
    }
    Ok(Flow::Continue)
}

/// `convertPropertyTo`: the property form of the header conversion.
pub(crate) fn property(run: &mut Run<'_, '_>, step: &ConvertStep) -> Result<Flow, RouteFailure> {
    let Some(source) = step.name.as_deref() else {
        return Err(RouteFailure::of(ErrorClass::Validation));
    };
    let input = run.exchange.property(source);
    if let Some(value) = lookup(run, step, input)? {
        let target = step.to_name.as_deref().unwrap_or(source);
        run.exchange.set_property(target, value);
    }
    Ok(Flow::Continue)
}
