// SPDX-License-Identifier: Apache-2.0

//! Source-native asynchronous completion contracts compiled for a served
//! facade write. Durable custody and caller-facing status remain host-owned.

use std::collections::BTreeSet;
use std::sync::Arc;

use registry_adapter_core::{
    async_source_id_fault, problem_data_schema, resolve_problem, validate_result_schema,
    AdapterProfile, AsyncStatusOutcome, ErrorClass, Step, MAX_PROBLEM_DATA_BYTES,
};
use serde_json::{json, Value};

use crate::exchange::Exchange;
use crate::language::{compile_selector, JsonPathResult, JsonPathSelector};
use crate::load::ServedOperation;
use crate::route::{RouteEvent, RouteFailure};

/// The sole host-owned property installed on a fresh source-status exchange.
pub const ASYNC_OPERATION_ID_PROPERTY: &str = "AdapterAsyncOperationId";

/// One bounded selector compiled once from the source operation contract.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedIdSelector(JsonPathSelector);

impl AcceptedIdSelector {
    /// Compile one singular RFC 9535 selector.
    pub fn compile(selector: &str) -> Result<Self, String> {
        let compiled = compile_selector(selector).map_err(|error| error.to_string())?;
        if !compiled.is_singular() {
            return Err("the accepted id selector is not singular".to_owned());
        }
        Ok(Self(compiled))
    }

    /// Extract one bounded source-owned identifier from a decoded 202 body.
    pub fn extract(&self, body: &Value) -> Result<String, RouteFailure> {
        let selected = self
            .0
            .evaluate(body)
            .map_err(|_| RouteFailure::of(ErrorClass::UpstreamHttp))?;
        let JsonPathResult::Singular(Some(Value::String(id))) = selected else {
            return Err(RouteFailure::of(ErrorClass::UpstreamHttp));
        };
        if async_source_id_fault(id).is_some() {
            return Err(RouteFailure::of(ErrorClass::UpstreamHttp));
        }
        Ok(id.clone())
    }
}

/// The one non-safe source operation whose 202 is meaningful for a served
/// asynchronous write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsyncSourceOperation {
    pub endpoint: String,
    pub operation: String,
}

/// One checked safe private status-route closure.
#[derive(Clone, Debug)]
pub struct ServedAsyncStatusRoute {
    pub route_id: String,
    pub steps: Arc<Vec<Step>>,
    pub maximum_upstream_calls: u64,
    /// Every data endpoint reachable through the route's direct closure.
    pub endpoint_ids: BTreeSet<String>,
}

/// Source-native uncertainty lookup by a host-generated correlation id.
#[derive(Clone, Debug)]
pub struct ServedAsyncUncertainty {
    pub request_header: String,
    pub status: ServedAsyncStatusRoute,
}

/// The closed asynchronous contract compiled onto one served operation.
#[derive(Clone, Debug)]
pub struct ServedAsyncOperation {
    pub initial: AsyncSourceOperation,
    pub accepted_id: AcceptedIdSelector,
    pub status: ServedAsyncStatusRoute,
    pub uncertainty: Option<ServedAsyncUncertainty>,
}

/// A declared 202 accepted by the source. The marker is engine-owned and is
/// never exposed to authored route code.
#[derive(Clone, Eq, PartialEq)]
pub struct AsyncSourceAcceptance {
    pub source_id: String,
}

impl std::fmt::Debug for AsyncSourceAcceptance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AsyncSourceAcceptance")
            .field("source_id", &"[REDACTED]")
            .finish()
    }
}

/// One status poll as the host receives it. An `Err` is an uncertain poll,
/// never proof that the source operation failed.
pub struct AsyncStatusPollOutcome {
    pub result: Result<AsyncStatusOutcome, RouteFailure>,
    pub events: Vec<RouteEvent>,
}

/// Create a value-free status exchange. Its caller-generated id remains the
/// physical exchange id; only the bounded source id reaches authored status
/// routes, through one fixed host property.
pub fn fresh_status_exchange(exchange_id: &str, source_id: &str) -> Result<Exchange, RouteFailure> {
    if async_source_id_fault(source_id).is_some() {
        return Err(RouteFailure::of(ErrorClass::FacadeInvalidField));
    }
    let mut exchange = Exchange::new(exchange_id.to_owned());
    exchange.set_property(ASYNC_OPERATION_ID_PROPERTY, json!(source_id));
    Ok(exchange)
}

/// Validate the source DTO before the host may treat it as terminal proof.
/// A malformed DTO remains an uncertain poll at the caller-facing boundary.
pub fn validate_status_outcome(
    operation: &ServedOperation,
    outcome: &AsyncStatusOutcome,
    profile: Option<&AdapterProfile>,
) -> Result<(), RouteFailure> {
    match outcome {
        AsyncStatusOutcome::Pending {} => Ok(()),
        AsyncStatusOutcome::Succeeded { result } => validate_terminal_result(operation, result)
            .map_err(|()| RouteFailure::of(ErrorClass::DisclosureViolation)),
        AsyncStatusOutcome::Failed { class, data } => {
            let Some(profile) = profile else {
                return Err(RouteFailure::of(ErrorClass::DisclosureViolation));
            };
            let Some(problem) = resolve_problem(profile, *class) else {
                return Err(RouteFailure::of(ErrorClass::DisclosureViolation));
            };
            if let Some(data) = data {
                let value = serde_json::to_value(data)
                    .map_err(|_| RouteFailure::of(ErrorClass::DisclosureViolation))?;
                let valid = serde_json::to_vec(&value)
                    .is_ok_and(|bytes| bytes.len() <= MAX_PROBLEM_DATA_BYTES)
                    && problem_data_schema(problem)
                        .is_some_and(|schema| validate_result_schema(&value, &schema).is_empty());
                if !valid {
                    return Err(RouteFailure::of(ErrorClass::DisclosureViolation));
                }
            }
            Ok(())
        }
    }
}

fn validate_terminal_result(operation: &ServedOperation, result: &Value) -> Result<(), ()> {
    if operation.pagination.is_some() {
        return Err(());
    }
    if validate_result_schema(result, &operation.record_schema).is_empty() {
        return Ok(());
    }
    const MEMBERS: [&str; 3] = ["recordIdentifier", "revisionIdentifier", "domainData"];
    let Value::Object(object) = result else {
        return Err(());
    };
    let wrapper_shaped = object.contains_key("recordIdentifier")
        && object.len() <= MEMBERS.len()
        && object.keys().all(|key| MEMBERS.contains(&key.as_str()));
    let (Some(Value::String(_)), Some(domain)) =
        (object.get("recordIdentifier"), object.get("domainData"))
    else {
        return Err(());
    };
    if wrapper_shaped && validate_result_schema(domain, &operation.record_schema).is_empty() {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::Duration;

    use registry_adapter_core::{AsyncStatusOutcome, ErrorClass};
    use serde_json::json;

    use super::*;
    use crate::envelope::CompiledEnvelope;
    use crate::load::ServedOperation;

    fn operation() -> ServedOperation {
        ServedOperation {
            operation: "records-create".to_owned(),
            method: registry_adapter_core::HttpMethod::Post,
            method_path: "/v1/records/{recordType}".to_owned(),
            request_template: None,
            request_maximum_bytes: 1024,
            filters: Vec::new(),
            record_type_parameter: "recordType".to_owned(),
            record_id_parameter: None,
            binding: "person-create".to_owned(),
            record_type: "person".to_owned(),
            route_id: "create".to_owned(),
            steps: Arc::new(Vec::new()),
            resilience: crate::resilience::ResilienceRuntime::empty(),
            maximum_upstream_calls: 3,
            response_envelope: CompiledEnvelope::compile("{}", &BTreeMap::new()).expect("envelope"),
            item_envelope: None,
            record_schema: json!({
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": false
            }),
            pagination: None,
            async_completion: None,
            resume: None,
            project_transform: None,
            project_input_transform: None,
            project_input_schema: None,
            read_support: None,
            write_support: None,
            source_input: None,
            item_projection: None,
            target_contract: None,
        }
    }

    #[test]
    fn accepted_id_is_one_bounded_opaque_string() {
        let selector = AcceptedIdSelector::compile("$.operation.id").expect("selector");
        assert_eq!(
            selector
                .extract(&json!({"operation": {"id": "source-17"}}))
                .expect("accepted id"),
            "source-17"
        );
        for refused in [
            json!({"operation": {}}),
            json!({"operation": {"id": ["source-17"]}}),
            json!({"operation": {"id": "https://source.invalid/jobs/17"}}),
        ] {
            assert!(selector.extract(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn fresh_status_exchange_carries_only_the_host_operation_id() {
        let exchange = fresh_status_exchange("poll-01", "source-17").expect("fresh exchange");
        assert_eq!(exchange.message.body, serde_json::Value::Null);
        assert!(exchange.message.string_headers().is_empty());
        assert_eq!(
            exchange.property(ASYNC_OPERATION_ID_PROPERTY),
            Some(&json!("source-17"))
        );
        assert_eq!(
            exchange.as_script_value()["properties"]
                .as_object()
                .expect("properties")
                .len(),
            1
        );
    }

    #[test]
    fn terminal_success_accepts_the_same_direct_or_normalized_record_as_sync() {
        let operation = operation();
        for result in [
            json!({"name": "Ada"}),
            json!({
                "recordIdentifier": "person-17",
                "revisionIdentifier": "v2",
                "domainData": {"name": "Ada"}
            }),
        ] {
            let outcome = AsyncStatusOutcome::Succeeded { result };
            validate_status_outcome(&operation, &outcome, None).expect("valid terminal result");
        }
        let malformed = AsyncStatusOutcome::Succeeded {
            result: json!({"recordIdentifier": "person-17", "name": "Ada"}),
        };
        assert_eq!(
            validate_status_outcome(&operation, &malformed, None)
                .expect_err("malformed result stays uncertain")
                .class,
            ErrorClass::DisclosureViolation
        );
    }

    #[test]
    fn status_descriptor_keeps_every_endpoint_in_its_safe_closure() {
        let route = ServedAsyncStatusRoute {
            route_id: "status".to_owned(),
            steps: Arc::new(Vec::new()),
            maximum_upstream_calls: 2,
            endpoint_ids: BTreeSet::from(["source".to_owned(), "token-source".to_owned()]),
        };
        assert_eq!(
            route.endpoint_ids.into_iter().collect::<Vec<_>>(),
            ["source", "token-source"]
        );
        assert!(Duration::from_millis(1) < crate::route::EXCHANGE_DEADLINE);
    }
}
