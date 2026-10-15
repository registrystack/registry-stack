// SPDX-License-Identifier: Apache-2.0
//! Authenticated committed product events admitted into the ordinary Run machine.
//!
//! Products own event capture and disclosure. A reviewed trigger names one exact
//! source, event contract and typed mapping; deployment configuration supplies
//! only that source's authentication. Neither the event nor its signature grants
//! authority for a later product call.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use registry_platform_config::{sha256_uri, SecretProvidersConfig, SecretReference};
use registry_platform_crypto::delivery_signature::{
    verify_v1, SignatureFields, MIN_HMAC_SHA256_KEY_BYTES,
};
use registry_platform_dispatch::idempotency_key;
use registry_platform_hooks::{EnvelopeLimits, HookEnvelope};
use registry_platform_yaml::{ExternalId, LocalId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    definition::{Definition, Mapping, Step, Workflow},
    http::HttpState,
    store::Actor,
    CoordinatorError, Result,
};

/// Matches the bounded Coordinator HTTP ingress and structured-value profile.
pub const MAXIMUM_EVENT_BYTES: usize = 65_536;
/// Delivery time is refreshed by the producer for every attempt. Event commit
/// time is immutable and may be older after an outage or operator replay.
pub const DELIVERY_SKEW: Duration = Duration::from_secs(30);
const EVENT_KEY_DOMAIN: &[u8] = b"registry-coordinator-event-start/v1";
const EVENT_OWNER_DOMAIN: &[u8] = b"registry-coordinator-event-owner/v1";

/// Trusted producer binding. Event vocabulary and mapping stay in the package.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventSourceConfig {
    /// Exact absolute producer URI that signed event envelopes must declare.
    pub source: ExternalId,
    /// Protected reference to the raw HMAC-SHA-256 key, at least 32 bytes.
    pub signing_key_ref: SecretReference,
}

/// Resolved governed trigger. The package revision covers every member, the
/// event schema and all referenced Function implementation bytes.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventTrigger {
    pub source: String,
    pub event_type: String,
    pub data_schema: String,
    pub event: Value,
    pub input: Mapping,
}

impl EventTrigger {
    /// Evaluate only after durable duplicate lookup. Exact replay must not be
    /// reinterpreted by an edited active mapping or Function.
    pub(crate) fn map(&self, definition: &Definition, event: &Value) -> Result<Value> {
        crate::functions::check_value(event)?;
        let schema = crate::definition::compile_schema(&self.event)?;
        if schema.validate(event).is_err() {
            return Err(invalid_event());
        }
        let input = definition.evaluate_mapping(&self.input, event, "eventTriggers.input")?;
        definition.validate_input(&input)?;
        Ok(input)
    }
}

/// Validate source bindings without resolving secret bytes.
pub(crate) fn source_findings(
    sources: &BTreeMap<String, EventSourceConfig>,
    secrets: &SecretProvidersConfig,
) -> Vec<CoordinatorError> {
    let mut errors = Vec::new();
    if sources.len() > 16 {
        errors.push(configuration(
            "eventSources",
            "Declare at most sixteen authenticated event sources.",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (name, source) in sources {
        let field = format!("eventSources.{name}");
        if LocalId::new(name.clone()).is_err() {
            errors.push(configuration(
                &field,
                "Use one bounded local event source ID.",
            ));
        }
        if !registry_platform_httputil::valid_resource_uri(source.source.as_ref())
            || !seen.insert(source.source.as_ref())
        {
            errors.push(configuration(&format!("{field}.source"), "Bind each exact absolute event source URI once, without credentials, whitespace or fragment."));
        }
        if secrets
            .check_reference(
                &format!("{field}.signingKeyRef"),
                source.signing_key_ref.as_str(),
            )
            .is_err()
        {
            errors.push(configuration(
                &format!("{field}.signingKeyRef"),
                "Enable the secret provider named by the event signing key reference.",
            ));
        }
    }
    errors
}

/// Startup readiness checks the same secret references the receiver consumes.
pub(crate) fn check_keys(config: &crate::runtime::RuntimeConfig) -> Result<()> {
    let resolver = config
        .secret_providers
        .resolver()
        .map_err(|_| source_unavailable())?;
    for source in config.event_sources.values() {
        let key = resolver
            .resolve_reference(&source.signing_key_ref)
            .map_err(|_| source_unavailable())?;
        if key.len() < MIN_HMAC_SHA256_KEY_BYTES {
            return Err(source_unavailable());
        }
    }
    Ok(())
}

/// Reuse the ordinary mapping validator with a single synthetic finish whose
/// input is the event schema and whose outcome is the Workflow start schema.
/// This is compile-time checking only, never a second execution graph.
pub(crate) fn workflow_findings(workflow: &Workflow) -> Vec<CoordinatorError> {
    let mut errors = Vec::new();
    if workflow.event_triggers.len() > 16 {
        errors.push(workflow_configuration(
            "workflow.eventTriggers",
            "Declare at most sixteen finite event triggers.",
        ));
    }
    for (name, trigger) in &workflow.event_triggers {
        let base = format!("workflow.eventTriggers.{name}");
        if LocalId::new(name.clone()).is_err()
            || LocalId::new(trigger.source.clone()).is_err()
            || ExternalId::new(trigger.event_type.clone()).is_err()
            || ExternalId::new(trigger.data_schema.clone()).is_err()
            || !registry_platform_httputil::valid_resource_uri(&trigger.data_schema)
        {
            errors.push(workflow_configuration(
                &base,
                "Name a local source, exact bounded event type and absolute data schema URI.",
            ));
            continue;
        }
        if let Err(error) = crate::definition::compile_schema(&trigger.event) {
            errors.push(error.at("workflow.yaml", format!("{base}.event")));
            continue;
        }
        let mut mapping = workflow.clone();
        mapping.input = trigger.event.clone();
        mapping.event_triggers.clear();
        mapping.start = "event-input".into();
        mapping.steps = BTreeMap::from([(
            "event-input".into(),
            Step::Finish {
                finish: "event-input".into(),
                output: Some(trigger.input.clone()),
            },
        )]);
        mapping.outcomes = BTreeMap::from([("event-input".into(), workflow.input.clone())]);
        if let Err(error) = crate::definition::validate_mapping(
            &mapping,
            "event-input",
            &trigger.input,
            &BTreeMap::new(),
        ) {
            errors.push(mapping_location(error, &base));
            continue;
        }
    }
    errors
}

/// Stronger schema navigation checks apply to authored projects only. Restored
/// Runs retain the mapping guarantees of the originally admitted snapshot.
pub(crate) fn mapping_findings(workflow: &Workflow) -> Vec<CoordinatorError> {
    workflow
        .event_triggers
        .iter()
        .flat_map(|(name, trigger)| {
            let mut mapping = workflow.clone();
            mapping.input = trigger.event.clone();
            mapping.event_triggers.clear();
            mapping.start = "event-input".into();
            mapping.steps = BTreeMap::from([(
                "event-input".into(),
                Step::Finish {
                    finish: "event-input".into(),
                    output: Some(trigger.input.clone()),
                },
            )]);
            mapping.outcomes = BTreeMap::from([("event-input".into(), workflow.input.clone())]);
            crate::mapping_check::check(&mapping)
                .into_iter()
                .map(|error| mapping_location(error, &format!("workflow.eventTriggers.{name}")))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn mapping_location(mut error: CoordinatorError, base: &str) -> CoordinatorError {
    if let Some(field) = error.field.as_deref() {
        error.field = Some(
            field
                .replacen("steps.event-input.output", &format!("{base}.input"), 1)
                .into_boxed_str(),
        );
    }
    error
}

/// Only authenticated, exact canonical envelope bytes reach admission.
pub struct VerifiedEvent {
    pub value: Value,
    pub digest: String,
    pub key: String,
    pub actor: Actor,
}

#[expect(
    clippy::too_many_arguments,
    reason = "The verifier binds exact received wire fields, configured producer, subscription, and receiver clock"
)]
pub fn verify_delivery(
    source: &EventSourceConfig,
    source_name: &str,
    trigger: &EventTrigger,
    trigger_name: &str,
    method: &Method,
    request_target: &str,
    headers: &HeaderMap,
    body: &[u8],
    key: &[u8],
    now: SystemTime,
) -> Result<VerifiedEvent> {
    if body.is_empty() || body.len() > MAXIMUM_EVENT_BYTES || method != Method::POST {
        return Err(invalid_event());
    }
    let specversion = header(headers, "ce-specversion")?;
    let content_type = header(headers, "content-type")?;
    let id = header(headers, "ce-id")?;
    let event_source = header(headers, "ce-source")?;
    let event_type = header(headers, "ce-type")?;
    let time = header(headers, "ce-time")?;
    let data_schema = header(headers, "ce-dataschema")?;
    let generation = header(headers, "x-registry-event-generation")?;
    let attempt = header(headers, "x-registry-delivery-attempt")?;
    let delivery_time = header(headers, "x-registry-delivery-time")?;
    let delivery_key = header(headers, "idempotency-key")?;
    let signature = header(headers, "x-registry-signature")?;
    if specversion != "1.0"
        || content_type != "application/json"
        || event_source != source.source.as_ref()
        || trigger.source != source_name
        || event_type != trigger.event_type
        || data_schema != trigger.data_schema
        || !positive(generation)
        || !positive(attempt)
        || delivery_key.is_empty()
        || delivery_key.len() > 256
    {
        return Err(unauthenticated());
    }
    verify_v1(
        key,
        SignatureFields {
            id,
            source: event_source,
            event_type,
            time,
            data_schema,
            generation,
            attempt,
            delivery_time,
            method: method.as_str(),
            request_target,
            content_type,
            idempotency_key: delivery_key,
            body,
        },
        signature,
        now,
        DELIVERY_SKEW,
    )
    .map_err(|_| unauthenticated())?;
    let envelope = HookEnvelope::from_canonical_bytes(
        body,
        &EnvelopeLimits::tightened_to(MAXIMUM_EVENT_BYTES),
    )
    .map_err(|_| invalid_event())?;
    let value = serde_json::to_value(&envelope).map_err(|_| invalid_event())?;
    if envelope.id != id
        || envelope.source != event_source
        || envelope.event_type != event_type
        || envelope.dataschema != data_schema
        || value["time"].as_str() != Some(time)
    {
        return Err(invalid_event());
    }
    crate::functions::check_value(&value).map_err(|_| invalid_event())?;
    // The platform envelope accepts UUID wire spellings. Normalize only the
    // dedup identity, preserving exact bytes for the conflicting-content check.
    let event_id = uuid::Uuid::parse_str(id).map_err(|_| invalid_event())?;
    // Local source aliases select authentication; the authenticated producer URI
    // owns the Run even when an operator renames that alias.
    let owner = idempotency_key(EVENT_OWNER_DOMAIN, &[event_source.as_bytes()]);
    Ok(VerifiedEvent {
        value,
        digest: sha256_uri(body),
        key: idempotency_key(
            EVENT_KEY_DOMAIN,
            &[
                event_source.as_bytes(),
                event_id.as_bytes(),
                trigger_name.as_bytes(),
            ],
        ),
        actor: Actor {
            issuer: "urn:registrystack:coordinator:event-source".into(),
            subject: owner.clone(),
            client_id: owner,
            operator: false,
        },
    })
}

fn header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or_else(unauthenticated)?;
    if values.next().is_some() {
        return Err(unauthenticated());
    }
    first.to_str().map_err(|_| unauthenticated())
}

fn positive(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u32>().is_ok_and(|number| number > 0)
}

/// A successful hook answer is empty: it proposes no source-product change.
/// The Run reference is value-free response metadata for producer diagnostics.
pub async fn receive(
    State(state): State<HttpState>,
    Path((workflow_name, trigger_name)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        if state.recovery_only {
            return Err(CoordinatorError::new(
                "recovery-only",
                "event admissions are disabled during recovery",
            ));
        }
        let package = state
            .workflows
            .get(&workflow_name)
            .ok_or_else(unauthenticated)?;
        let trigger = package
            .definition
            .workflow
            .event_triggers
            .get(&trigger_name)
            .ok_or_else(unauthenticated)?;
        let source = state
            .runtime
            .event_sources
            .get(&trigger.source)
            .ok_or_else(source_unavailable)?;
        let resolver = state
            .runtime
            .secret_providers
            .resolver()
            .map_err(|_| source_unavailable())?;
        let key = resolver
            .resolve_reference(&source.signing_key_ref)
            .map_err(|_| source_unavailable())?;
        let verified = verify_delivery(
            source,
            &trigger.source,
            trigger,
            &trigger_name,
            &method,
            &uri.to_string(),
            &headers,
            &body,
            key.expose_secret(),
            SystemTime::now(),
        )?;
        crate::deployment::check(&state.store, &state.runtime, state.workflows.digest()).await?;
        let binding = state
            .runtime
            .binding_digest_for(&package.definition.workflow)?;
        state
            .store
            .admit_event_owned(
                &package.definition,
                verified.value,
                trigger,
                &verified.actor,
                &verified.key,
                &binding,
                &state.runtime,
                &verified.digest,
            )
            .await
    }
    .await;
    match result {
        Ok(run) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().insert(
                "x-coordinator-run-id",
                HeaderValue::from_str(&run.to_string()).expect("UUID header"),
            );
            response
        }
        Err(error) => event_problem(error),
    }
}

fn event_problem(error: CoordinatorError) -> Response {
    let signature_refused = error.code == "event-unauthenticated";
    let mut response = crate::http::problem(error);
    if signature_refused {
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Registry-Signature version=\"v1\""),
        );
    }
    response
}

fn invalid_event() -> CoordinatorError {
    CoordinatorError::new(
        "event-invalid",
        "the committed event does not satisfy the accepted canonical envelope and typed contract",
    )
}
fn unauthenticated() -> CoordinatorError {
    CoordinatorError::new(
        "event-unauthenticated",
        "a fresh signed delivery from the configured event source is required",
    )
}
fn source_unavailable() -> CoordinatorError {
    CoordinatorError::new(
        "event-source-unavailable",
        "the configured event source authentication is unavailable",
    )
}
fn configuration(field: &str, advice: &str) -> CoordinatorError {
    CoordinatorError::new(
        "coordinator.event.configuration",
        "the event trigger configuration was refused",
    )
    .at("runtime.yaml", crate::runtime::pointer(field))
    .suggest(advice)
}

#[cfg(test)]
#[path = "event_trigger_tests.rs"]
mod tests;

fn workflow_configuration(field: &str, advice: &str) -> CoordinatorError {
    CoordinatorError::new(
        "coordinator.event.configuration",
        "the event trigger configuration was refused",
    )
    .at("workflow.yaml", crate::runtime::pointer(field))
    .suggest(advice)
}
