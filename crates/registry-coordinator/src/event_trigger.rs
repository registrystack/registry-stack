// SPDX-License-Identifier: Apache-2.0
//! Authenticated committed product events admitted into the ordinary Run machine.
//!
//! Products own event capture and disclosure. A reviewed trigger names one exact
//! source, event contract and typed mapping; deployment configuration supplies
//! only that source's authentication. Neither the event nor its signature grants
//! authority for a later product call.

use std::{collections::BTreeMap, time::SystemTime};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use registry_platform_authcommon::FailedCheck;
use registry_platform_config::{
    sha256_uri, SecretProvidersConfig, SecretReference, SecretResolver,
};
use registry_platform_crypto::delivery_signature::{
    DeliveryKey, DeliveryKeyError, DeliveryKeys, DeliverySignatureError, MAX_BODY_BYTES,
};
use registry_platform_dispatch::idempotency_key;
use registry_platform_hooks::receiver::{
    verify_hook_delivery, DeliveryFreshness, HookDelivery, HookDeliveryError, VerifiedHookDelivery,
};
use registry_platform_yaml::{ExternalId, LocalId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    definition::{Definition, Mapping, Step, Workflow},
    http::HttpState,
    store::Actor,
    CoordinatorError, Result,
};

/// Signed event bodies are bounded to 1 MiB. Admitted values also fit the
/// structured-value profile.
pub const MAXIMUM_EVENT_BYTES: usize = MAX_BODY_BYTES;
const EVENT_KEY_DOMAIN: &[u8] = b"registry-coordinator-event-start/v1";
const EVENT_OWNER_DOMAIN: &[u8] = b"registry-coordinator-event-owner/v1";

/// Trusted producer binding. Event vocabulary and mapping stay in the package.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventSourceConfig {
    /// Exact absolute producer URI that signed event envelopes must declare.
    pub source: ExternalId,
    /// Workflow IDs and trigger names identify the keys for each event URL.
    #[cfg_attr(feature = "schema", schemars(extend("maxProperties" = 16)))]
    pub triggers: BTreeMap<LocalId, WorkflowTriggerKeys>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct WorkflowTriggerKeys(
    #[cfg_attr(feature = "schema", schemars(extend("maxProperties" = 16)))]
    pub  BTreeMap<LocalId, TriggerKeyConfig>,
);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriggerKeyConfig {
    pub hmac_sha256_key_ref: SecretReference,
    #[serde(
        default,
        deserialize_with = "present_hook_key_reference",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub previous_hmac_sha256_key_ref: Option<SecretReference>,
}

pub(crate) fn present_hook_key_reference<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<SecretReference>, D::Error> {
    SecretReference::deserialize(deserializer).map(Some)
}

/// Resolved Standard Webhooks keys and the operator paths that identify them.
pub(crate) struct IngressKeys {
    pub keys: DeliveryKeys,
    path: String,
    previous_path: String,
}

pub(crate) type EventKeys = BTreeMap<(LocalId, LocalId), IngressKeys>;

impl IngressKeys {
    pub(crate) fn resolve(
        resolver: &SecretResolver,
        path: String,
        current: &SecretReference,
        previous: Option<&SecretReference>,
    ) -> Result<Self> {
        let current_path = format!("{path}.hmacSha256KeyRef");
        let previous_path = format!("{path}.previousHmacSha256KeyRef");
        let current = resolve_key(resolver, &current_path, current)?;
        let previous = previous
            .map(|reference| resolve_key(resolver, &previous_path, reference))
            .transpose()?;
        let keys = DeliveryKeys::new(current, previous)
            .map_err(|_| duplicate_key(&current_path, &previous_path))?;
        Ok(Self {
            keys,
            path: current_path,
            previous_path,
        })
    }

    pub(crate) fn labelled(&self) -> impl Iterator<Item = (&str, &DeliveryKey)> {
        std::iter::once((self.path.as_str(), self.keys.current())).chain(
            self.keys
                .previous()
                .map(|key| (self.previous_path.as_str(), key)),
        )
    }
}

fn resolve_key(
    resolver: &SecretResolver,
    path: &str,
    reference: &SecretReference,
) -> Result<DeliveryKey> {
    let secret = resolver.resolve_binary_reference(reference).map_err(|_| {
        configuration(
            path,
            &format!("Make the key at {path} available to Coordinator."),
        )
    })?;
    let bytes = secret.expose_secret();
    let length = bytes.len();
    let trailing_newline = bytes.ends_with(b"\n");
    DeliveryKey::new(bytes).map_err(|error| {
        configuration(path, &key_diagnostic(path, length, trailing_newline, error))
    })
}

fn key_diagnostic(
    path: &str,
    length: usize,
    trailing_newline: bool,
    error: DeliveryKeyError,
) -> String {
    let suffix = if trailing_newline {
        ", ending in a newline"
    } else {
        ""
    };
    let reason = match error {
        DeliveryKeyError::TooShort { .. } | DeliveryKeyError::TooLong { .. } => {
            "Supply 32 to 64 exact key bytes."
        }
        DeliveryKeyError::SecretText => "Supply exact key bytes without the whsec_ encoding.",
        DeliveryKeyError::PreviousEqualsCurrent => "Use distinct current and previous keys.",
    };
    format!("{path} resolved to {length} bytes{suffix}. {reason}")
}

pub(crate) fn duplicate_key(first: &str, second: &str) -> CoordinatorError {
    CoordinatorError::new(
        "adapter.configuration",
        format!("`{first}` and `{second}` resolve to the same key bytes. Give `{second}` its own key by writing 32 new random bytes to another secret and referencing it there."),
    )
}

pub(crate) fn check_key_references(
    errors: &mut Vec<CoordinatorError>,
    secrets: &SecretProvidersConfig,
    path: &str,
    current: &SecretReference,
    previous: Option<&SecretReference>,
) {
    for (name, reference) in std::iter::once(("hmacSha256KeyRef", current))
        .chain(previous.map(|reference| ("previousHmacSha256KeyRef", reference)))
    {
        let field = format!("{path}.{name}");
        if secrets.check_reference(&field, reference.as_str()).is_err() {
            errors.push(configuration(
                &field,
                "Enable the secretProviders entry named by the delivery key reference.",
            ));
        }
    }
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
        if source.triggers.len() > 16 {
            errors.push(configuration(
                &format!("{field}.triggers"),
                "Declare keys for at most sixteen workflows per source.",
            ));
        }
        for (workflow, triggers) in &source.triggers {
            let workflow_path = format!("{field}.triggers.{workflow}");
            if triggers.0.len() > 16 {
                errors.push(configuration(
                    &workflow_path,
                    "Declare at most sixteen trigger keys per workflow.",
                ));
            }
            for (trigger, key) in &triggers.0 {
                check_key_references(
                    &mut errors,
                    secrets,
                    &format!("{workflow_path}.{trigger}"),
                    &key.hmac_sha256_key_ref,
                    key.previous_hmac_sha256_key_ref.as_ref(),
                );
            }
        }
    }
    errors
}

pub(crate) fn resolve_keys(config: &crate::runtime::RuntimeConfig) -> Result<EventKeys> {
    let mut keys = BTreeMap::new();
    if config.event_sources.is_empty() {
        return Ok(keys);
    }
    let resolver = config.secret_providers.resolver().map_err(|_| {
        configuration(
            "eventSources",
            "Make the event source secret providers available.",
        )
    })?;
    for (alias, source) in &config.event_sources {
        for (workflow, triggers) in &source.triggers {
            for (trigger, key) in &triggers.0 {
                let path = format!("eventSources.{alias}.triggers.{workflow}.{trigger}");
                let keys_for_trigger = IngressKeys::resolve(
                    &resolver,
                    path.clone(),
                    &key.hmac_sha256_key_ref,
                    key.previous_hmac_sha256_key_ref.as_ref(),
                )?;
                if keys
                    .insert((workflow.clone(), trigger.clone()), keys_for_trigger)
                    .is_some()
                {
                    return Err(configuration(
                        &path,
                        "Configure only one source for this workflow trigger.",
                    ));
                }
            }
        }
    }
    Ok(keys)
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

pub fn verify_delivery(
    source: &EventSourceConfig,
    trigger: &EventTrigger,
    trigger_name: &str,
    headers: &HeaderMap,
    body: &[u8],
    keys: &DeliveryKeys,
    now: SystemTime,
) -> Result<VerifiedEvent> {
    check_body(body)?;
    let VerifiedHookDelivery { id, envelope, .. } = verify_hook_delivery(
        HookDelivery {
            headers: headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
            body,
            keys,
        },
        DeliveryFreshness::default_at(now),
    )
    .map_err(|error| match error {
        HookDeliveryError::InvalidEnvelope => invalid_event(),
        HookDeliveryError::IdMismatch | HookDeliveryError::InvalidContentType => {
            unauthenticated(FailedCheck::DeliveryBinding)
        }
        HookDeliveryError::Signature(
            DeliverySignatureError::StaleDelivery | DeliverySignatureError::InvalidTimestamp,
        ) => unauthenticated(FailedCheck::DeliveryFreshness),
        HookDeliveryError::Signature(DeliverySignatureError::BodyTooLarge) => body_too_large(),
        _ => unauthenticated(FailedCheck::DeliverySignature),
    })?;
    if envelope.source != source.source.as_ref()
        || envelope.event_type != trigger.event_type
        || envelope.dataschema != trigger.data_schema
    {
        return Err(unauthenticated(FailedCheck::DeliveryBinding));
    }
    let event_source = envelope.source.as_str();
    let value = serde_json::to_value(&envelope).map_err(|_| invalid_event())?;
    crate::functions::check_value(&value).map_err(|error| {
        if error.code == "function.value_limit" {
            event_too_large()
        } else {
            invalid_event()
        }
    })?;
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

/// A successful hook answer is empty: it proposes no source-product change.
/// The Run reference is value-free response metadata for producer diagnostics.
pub async fn receive(
    State(state): State<HttpState>,
    Path((workflow_name, trigger_name)): Path<(String, String)>,
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
        check_body(&body)?;
        let package = state
            .workflows
            .get(&workflow_name)
            .ok_or_else(|| unauthenticated(FailedCheck::DeliveryBinding))?;
        let trigger = package
            .definition
            .workflow
            .event_triggers
            .get(&trigger_name)
            .ok_or_else(|| unauthenticated(FailedCheck::DeliveryBinding))?;
        let source = state
            .runtime
            .event_sources
            .get(&trigger.source)
            .ok_or_else(|| unauthenticated(FailedCheck::DeliveryBinding))?;
        let keys = state
            .adapters
            .event_keys(&workflow_name, &trigger_name)
            .ok_or_else(|| unauthenticated(FailedCheck::DeliveryBinding))?;
        let verified = verify_delivery(
            source,
            trigger,
            &trigger_name,
            &headers,
            &body,
            keys,
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
            HeaderValue::from_static(crate::http::WEBHOOK_CHALLENGE),
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
fn event_too_large() -> CoordinatorError {
    CoordinatorError::new(
        "event-too-large",
        format!(
            "the committed event exceeds the event value profile of {} canonical bytes, {} levels of nesting, {} values, {} items per array, {} members per object, and {} bytes per string; project fewer or smaller fields into the event",
            crate::functions::MAXIMUM_VALUE_BYTES,
            crate::functions::MAXIMUM_VALUE_DEPTH,
            crate::functions::MAXIMUM_VALUE_NODES,
            crate::functions::MAXIMUM_VALUE_ARRAY_ITEMS,
            crate::functions::MAXIMUM_VALUE_OBJECT_MEMBERS,
            crate::functions::MAXIMUM_VALUE_STRING_BYTES,
        ),
    )
}
fn body_too_large() -> CoordinatorError {
    CoordinatorError::new(
        "request.body-too-large",
        format!(
            "the signed event delivery exceeds the {MAXIMUM_EVENT_BYTES}-byte body bound; send a smaller event"
        ),
    )
}
fn unauthenticated(check: FailedCheck) -> CoordinatorError {
    CoordinatorError::new(
        "event-unauthenticated",
        "a fresh signed delivery from the configured event source is required",
    )
    .failing(check)
}
fn check_body(body: &[u8]) -> Result<()> {
    if body.len() > MAXIMUM_EVENT_BYTES {
        return Err(body_too_large());
    }
    if body.is_empty() {
        return Err(invalid_event());
    }
    Ok(())
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
