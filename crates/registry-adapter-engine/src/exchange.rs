// SPDX-License-Identifier: Apache-2.0

//! The exchange and message model, ported from Camel's `Exchange` and
//! `Message` (`products/adapter/CONCEPT.md` section 8.2).
//!
//! An exchange carries an exchange id, an `InOut` message pattern, one
//! message of headers and body, exchange properties, and an exception
//! slot. Headers are a bounded, case-insensitive map; the body is a
//! size-bounded JSON value once unmarshalled; the `http` component
//! marshals and unmarshals JSON itself instead of Camel's explicit
//! `marshal` and `unmarshal` steps, because the components speak exactly
//! one data format.
//!
//! What enters the exchange is declared: the `rest` consumer places only
//! the bound operation's validated inputs on it, under the closed names
//! of section 8.11.1, and credentials, base URLs, and secrets never
//! enter it, so no expression or header can carry them out.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::Arc;

use http::HeaderValue;
use registry_adapter_core::ErrorClass;
use registry_platform_config::sha256_uri;
use serde_json::Value;

use crate::replay::ReplayWriteCapability;
use crate::route::RouteFailure;

/// The total JSON-encoded state one live facade exchange may retain. The
/// body, headers, and properties share the same conservative ceiling as one
/// maximum upstream response; a route cannot multiply that response bound
/// by moving values into other exchange slots. A job page run raises the
/// ceiling to its profile's response bound through
/// [`Exchange::ensure_bounded_within`].
pub(crate) const MAXIMUM_EXCHANGE_BYTES: usize =
    registry_adapter_core::MAXIMUM_RESPONSE_BYTES as usize;

/// The prefix of the exchange properties the engine owns.
pub const RESERVED_PROPERTY_PREFIX: &str = "Adapter";
/// The facade's filter inputs, as an object of the declared filters the
/// caller sent.
pub const FILTERS_PROPERTY: &str = "AdapterFilters";
/// The continuation the caller's cursor restored; absent on a first page.
pub const CONTINUATION_PROPERTY: &str = "AdapterContinuation";
/// The one reserved property a route sets: the continuation the engine
/// seals as the next cursor. Absent or null is the last page.
pub const NEXT_CONTINUATION_PROPERTY: &str = "AdapterNextContinuation";
/// Split piece position, matching Camel's `Exchange.SPLIT_INDEX` property.
pub const SPLIT_INDEX_PROPERTY: &str = "CamelSplitIndex";
/// Total split size, matching Camel's `Exchange.SPLIT_SIZE` property.
pub const SPLIT_SIZE_PROPERTY: &str = "CamelSplitSize";
/// Whether this is the final split piece, matching Camel's
/// `Exchange.SPLIT_COMPLETE` property.
pub const SPLIT_COMPLETE_PROPERTY: &str = "CamelSplitComplete";
/// Split failure-accounting summary, matching Camel's
/// `Exchange.SPLIT_RESULT` property.
pub const SPLIT_RESULT_PROPERTY: &str = "CamelSplitResult";
/// Loop iteration position, matching Camel's `Exchange.LOOP_INDEX` property.
pub const LOOP_INDEX_PROPERTY: &str = "CamelLoopIndex";
/// Count-loop size, matching Camel's `Exchange.LOOP_SIZE` property.
pub const LOOP_SIZE_PROPERTY: &str = "CamelLoopSize";
/// The page size header the facade sets on a search.
pub const PAGE_SIZE_HEADER: &str = "pageSize";
/// A host-owned strong source condition exposed read-only to a reviewed pack
/// while it prepares the source-native request body.
pub const SOURCE_CONDITION_PROPERTY: &str = "AdapterSourceCondition";

/// Headers the redelivery loop sets while an upstream send is retried
/// (section 8.7).
pub const REDELIVERED_HEADER: &str = "camelredelivered";
pub const REDELIVERY_COUNTER_HEADER: &str = "camelredeliverycounter";
pub const REDELIVERY_MAX_COUNTER_HEADER: &str = "camelredeliverymaxcounter";
/// The header the engine sets to the caught class while a `doCatch`'s
/// steps run (Camel's `CamelExceptionCaught`, section 8.7); it does not
/// outlive the catch. Two recorded changes from Camel: the slot is a
/// header here where Camel sets an exchange property, and the value is
/// the closed error-class name where Camel carries the throwable
/// itself, the value-free contract.
pub const EXCEPTION_CAUGHT_HEADER: &str = "camelexceptioncaught";

/// One message: lowercased header names and one JSON body.
#[derive(Clone, Debug, Default)]
pub struct Message {
    pub body: Value,
    headers: BTreeMap<String, Value>,
}

impl Message {
    pub fn set_header(&mut self, name: &str, value: Value) {
        self.headers.insert(name.to_ascii_lowercase(), value);
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.remove(&name.to_ascii_lowercase());
    }

    /// A header by name, compared without case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&Value> {
        self.headers.get(&name.to_ascii_lowercase())
    }

    /// Every header as a name and its string value, the form an outbound
    /// header filter reads; a non-string value is stringified.
    #[must_use]
    pub fn string_headers(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .map(|(name, value)| {
                let text = match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                (name.clone(), text)
            })
            .collect()
    }
}

/// The longest idempotency key the write custody seam accepts, the
/// contract every custody implementation holds: the facade's store and
/// the offline replay's simulation refuse the same length the engine
/// refuses here, before any custody state is reached
/// (`products/adapter/CONCEPT.md` section 9).
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Host-owned inputs for exactly one source-backed write. The public caller
/// key and body never fill these members: the host supplies a canonical,
/// caller-scoped digest and an independently validated source condition.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceWriteInputs {
    key_scope_digest: String,
    condition: Option<String>,
}

impl std::fmt::Debug for SourceWriteInputs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceWriteInputs")
            .field("has_condition", &self.condition.is_some())
            .finish_non_exhaustive()
    }
}

impl SourceWriteInputs {
    /// Admit a host-computed 32-byte scope digest and optional unwrapped
    /// source validator. Neither value is logged or copied to message headers.
    pub fn try_new(
        key_scope_digest: impl Into<String>,
        condition: Option<&str>,
    ) -> Result<Self, ErrorClass> {
        let key_scope_digest = key_scope_digest.into();
        if key_scope_digest.len() != 64
            || !key_scope_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ErrorClass::Facade);
        }
        let condition = condition.map(str::to_owned);
        if condition.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
                || value.bytes().any(|byte| byte.is_ascii_control())
        }) {
            return Err(ErrorClass::Facade);
        }
        Ok(Self {
            key_scope_digest,
            condition,
        })
    }

    /// Derive the opaque source key for one resume ordinal. Framing and a
    /// fixed domain keep callers, operations, and steps disjoint while the
    /// same host scope repeats byte-for-byte across retries.
    #[must_use]
    pub(crate) fn native_idempotency_key(&self, ordinal: u32) -> String {
        let domain = b"registry-adapter:source-write-key:v1";
        let mut framed = Vec::with_capacity(domain.len() + self.key_scope_digest.len() + 20);
        for member in [domain.as_slice(), self.key_scope_digest.as_bytes()] {
            framed.extend_from_slice(&(member.len() as u64).to_be_bytes());
            framed.extend_from_slice(member);
        }
        framed.extend_from_slice(&ordinal.to_be_bytes());
        sha256_uri(&framed)
            .strip_prefix("sha256:")
            .expect("sha256_uri always returns a sha256 label")
            .to_owned()
    }
}

/// Source-neutral result of exactly one source write. The host owns public
/// wire rendering; the engine retains the source validator as typed control
/// state rather than an HTTP header bag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalSourceResult {
    pub key: String,
    pub native_version: String,
    pub data: serde_json::Map<String, Value>,
}

/// The write custody seam the engine owns and the facade installs
/// (`products/adapter/CONCEPT.md` section 9): the engine
/// names no custody store, no idempotency type, and no client; the
/// facade implements the seam over its journal transaction and
/// idempotency store, and offline replay implements it over its
/// simulation. No method here returns custody state: a claim's engine
/// meaning is the closed [`WriteClaim`], and everything else is the
/// route failure the caller already carries.
pub trait WriteCustody: std::fmt::Debug + Send + Sync {
    #[allow(clippy::type_complexity)]
    fn claim<'a>(
        &'a self,
        key: &'a str,
        eager: bool,
    ) -> Pin<Box<dyn Future<Output = Result<WriteClaim, RouteFailure>> + Send + 'a>>;
    #[allow(clippy::type_complexity)]
    fn before_effect<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>>;
    /// Durably mark one resumable source step before any byte is sent.
    /// The default refuses, so a host cannot accidentally run a compiled
    /// resume plan through ordinary single-effect custody.
    #[allow(clippy::type_complexity)]
    fn before_resume_step<'a>(
        &'a self,
        _ordinal: u32,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async { Err(RouteFailure::of(ErrorClass::Facade)) })
    }
    /// Mark a source-native conditional rejection as a definitive non-effect.
    /// The default refuses so only a host that owns terminal response custody
    /// can distinguish this from ambiguous transport failure.
    #[allow(clippy::type_complexity)]
    fn mark_definitive_source_rejection<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async { Err(RouteFailure::of(ErrorClass::Facade)) })
    }
    /// Atomically checkpoint one successful non-final step's declared source
    /// identifiers and advance the next ordinal. The default refuses.
    #[allow(clippy::type_complexity)]
    fn checkpoint_resume_step<'a>(
        &'a self,
        _ordinal: u32,
        _bindings: Vec<crate::ResumeValue>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async { Err(RouteFailure::of(ErrorClass::Facade)) })
    }
    /// A host-generated 32-byte correlation id encoded as lowercase hex,
    /// persisted by `before_effect` before the engine may read it. Ordinary
    /// writes and offline replay expose none.
    fn source_recovery_id(&self) -> Option<String> {
        None
    }
    /// Mark a possible source effect irreversible; the bool answers
    /// whether a real write capability ran (a replay simulation marks
    /// too, and an exchange with neither capability runs nothing).
    #[allow(clippy::type_complexity)]
    fn mark_unsupported_incomplete<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RouteFailure>> + Send + 'a>>;
    #[allow(clippy::type_complexity)]
    fn complete<'a>(
        &'a self,
        succeeded: bool,
        remove_on_failure: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>>;
}

/// One exchange: an id, the `InOut` message, and its properties.
#[derive(Clone, Debug)]
pub struct Exchange {
    id: String,
    pub message: Message,
    properties: BTreeMap<String, Value>,
    /// Server-owned write capability behind the [`WriteCustody`] seam.
    /// It is shared by exchange clones but is absent from scripts,
    /// serialization, retained-JSON accounting, and debug output.
    write_execution: Option<Arc<dyn WriteCustody>>,
    replay_write: Option<Arc<dyn WriteCustody>>,
    /// A source acceptance is engine control state, not message data. It is
    /// absent from scripts, serialization, and retained-JSON accounting.
    async_source_acceptance: Option<crate::async_completion::AsyncSourceAcceptance>,
    /// Host-only source write authority, absent from scripts and debug values.
    source_write_inputs: Option<SourceWriteInputs>,
    /// Typed normalized source result retained beside the generic body.
    final_source_result: Option<FinalSourceResult>,
    /// Trusted W3C context installed by a serving host. It is not a message
    /// header, script input, retained JSON, or authored configuration value.
    system_traceparent: Option<HeaderValue>,
}

impl Exchange {
    #[must_use]
    pub fn new(id: String) -> Self {
        Self {
            id,
            message: Message::default(),
            properties: BTreeMap::new(),
            write_execution: None,
            replay_write: None,
            async_source_acceptance: None,
            source_write_inputs: None,
            final_source_result: None,
            system_traceparent: None,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Install the serving host's effective W3C context exactly once.
    pub fn install_system_traceparent(&mut self, value: HeaderValue) -> Result<(), ErrorClass> {
        if self.system_traceparent.is_some() {
            return Err(ErrorClass::Facade);
        }
        self.system_traceparent = Some(value);
        Ok(())
    }

    #[must_use]
    pub(crate) fn system_traceparent(&self) -> Option<&HeaderValue> {
        self.system_traceparent.as_ref()
    }

    /// Install the host's source-key scope and optional strong condition once.
    /// The condition snapshot is reserved route input; the authoritative copy
    /// stays private and can restore the snapshot before preparation or send.
    pub fn install_source_write_inputs(
        &mut self,
        inputs: SourceWriteInputs,
    ) -> Result<(), ErrorClass> {
        if self.source_write_inputs.is_some() {
            return Err(ErrorClass::Facade);
        }
        self.source_write_inputs = Some(inputs);
        self.refresh_source_condition_snapshot();
        Ok(())
    }

    pub(crate) fn refresh_source_condition_snapshot(&mut self) {
        match self
            .source_write_inputs
            .as_ref()
            .and_then(|inputs| inputs.condition.as_ref())
        {
            Some(condition) => {
                self.properties.insert(
                    SOURCE_CONDITION_PROPERTY.to_owned(),
                    Value::String(condition.clone()),
                );
            }
            None => {
                self.properties.remove(SOURCE_CONDITION_PROPERTY);
            }
        }
    }

    #[must_use]
    pub(crate) fn source_condition(&self) -> Option<&str> {
        self.source_write_inputs
            .as_ref()
            .and_then(|inputs| inputs.condition.as_deref())
    }

    #[must_use]
    pub(crate) fn source_idempotency_key(&self, ordinal: u32) -> Option<String> {
        self.source_write_inputs
            .as_ref()
            .map(|inputs| inputs.native_idempotency_key(ordinal))
    }

    pub(crate) fn set_final_source_result(
        &mut self,
        result: FinalSourceResult,
    ) -> Result<(), RouteFailure> {
        if self.final_source_result.is_some() {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        self.message.body = Value::Object(serde_json::Map::from_iter([
            ("key".to_owned(), Value::String(result.key.clone())),
            ("data".to_owned(), Value::Object(result.data.clone())),
        ]));
        self.final_source_result = Some(result);
        Ok(())
    }

    #[must_use]
    pub fn final_source_result(&self) -> Option<&FinalSourceResult> {
        self.final_source_result.as_ref()
    }

    pub fn set_property(&mut self, name: &str, value: Value) {
        self.properties.insert(name.to_owned(), value);
    }

    pub fn remove_property(&mut self, name: &str) {
        self.properties.remove(name);
    }

    #[must_use]
    pub fn property(&self, name: &str) -> Option<&Value> {
        self.properties.get(name)
    }

    /// Install the served write's custody capability behind the
    /// [`WriteCustody`] seam. The facade constructs its concrete context
    /// over its own store and keeps that concrete arc beside itself; the
    /// engine sees the trait only. Installed beside a replay simulation,
    /// it never runs: every custody call then refuses with `facade`, so a
    /// simulation never stands in for real custody.
    pub fn install_write(&mut self, capability: Arc<dyn WriteCustody>) {
        self.write_execution = Some(capability);
    }

    /// The source acceptance produced by a declared asynchronous write.
    #[must_use]
    pub fn async_source_acceptance(
        &self,
    ) -> Option<&crate::async_completion::AsyncSourceAcceptance> {
        self.async_source_acceptance.as_ref()
    }

    pub(crate) fn set_async_source_acceptance(
        &mut self,
        acceptance: crate::async_completion::AsyncSourceAcceptance,
    ) -> Result<(), RouteFailure> {
        if self.async_source_acceptance.is_some() {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        self.async_source_acceptance = Some(acceptance);
        Ok(())
    }

    pub(crate) fn has_write_custody(&self) -> bool {
        matches!(
            (&self.write_execution, &self.replay_write),
            (Some(_), None) | (None, Some(_))
        )
    }

    /// Read the host correlation capability only after `before_effect` has
    /// committed. The route runner owns that ordering.
    pub(crate) fn source_recovery_id(&self) -> Result<Option<String>, RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => Ok(context.source_recovery_id()),
            (None, Some(context)) => Ok(context.source_recovery_id()),
            (None, None) => Ok(None),
            (Some(_), Some(_)) => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    /// Claim the key produced by `idempotentConsumer` before running its
    /// guarded steps.
    pub(crate) async fn claim_write_key(
        &self,
        key: &str,
        eager: bool,
    ) -> Result<WriteClaim, RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.claim(key, eager).await,
            (None, Some(context)) => context.claim(key, eager).await,
            _ => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    /// Durably mark a possible source effect before a non-safe data send is
    /// attempted. A repeated call belongs to the same attempted effect, such
    /// as the one permitted OAuth refresh retry, and does not reopen the
    /// database transition.
    pub(crate) async fn before_upstream_effect(&self) -> Result<(), RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.before_effect().await,
            (None, Some(context)) => context.before_effect().await,
            _ => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    pub(crate) async fn before_resume_step(&self, ordinal: u32) -> Result<(), RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.before_resume_step(ordinal).await,
            (None, Some(context)) => context.before_resume_step(ordinal).await,
            _ => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    /// Preserve a definite source refusal for the host's terminal response
    /// transaction instead of reopening native replay recovery.
    pub(crate) async fn mark_definitive_source_rejection(&self) -> Result<(), RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.mark_definitive_source_rejection().await,
            (None, Some(context)) => context.mark_definitive_source_rejection().await,
            _ => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    pub(crate) async fn checkpoint_resume_step(
        &self,
        ordinal: u32,
        bindings: Vec<crate::ResumeValue>,
    ) -> Result<(), RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.checkpoint_resume_step(ordinal, bindings).await,
            (None, Some(context)) => context.checkpoint_resume_step(ordinal, bindings).await,
            _ => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    /// Make an actual upstream 202 irreversible for a served write before
    /// route-level handlers can normalize its body. Offline write replay
    /// mirrors the private marker; an exchange with no write capability is a
    /// read and remains unaffected.
    pub(crate) async fn mark_unsupported_incomplete_write(&self) -> Result<bool, RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.mark_unsupported_incomplete().await,
            (None, Some(context)) => context.mark_unsupported_incomplete().await,
            (None, None) => Ok(false),
            (Some(_), Some(_)) => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    /// Complete the idempotent-consumer membership at the timing the EIP
    /// selected. Durable effect custody stays independent: the host may
    /// release a failed reservation only while no non-safe effect may have
    /// happened.
    pub(crate) async fn complete_write_key(
        &self,
        succeeded: bool,
        remove_on_failure: bool,
    ) -> Result<(), RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.complete(succeeded, remove_on_failure).await,
            (None, Some(context)) => context.complete(succeeded, remove_on_failure).await,
            _ => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    /// Install the explicitly simulated write capability for one offline
    /// replay. Only the replay module constructs the
    /// [`ReplayWriteCapability`] seal, so nothing else fills this slot. A
    /// real custody capability already installed refuses, so a simulation
    /// never replaces real custody, and a second simulation never resets
    /// the first.
    pub(crate) fn install_replay_write(
        &mut self,
        capability: Arc<dyn WriteCustody>,
        _seal: ReplayWriteCapability,
    ) -> Result<(), RouteFailure> {
        if self.write_execution.is_some() || self.replay_write.is_some() {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        self.replay_write = Some(capability);
        Ok(())
    }

    /// Refuse an exchange whose retained JSON state exceeds the runtime's
    /// fixed memory budget. The exchange id is bounded at admission and is
    /// not route-controlled, so this counts the message body, header names
    /// and values, and property names and values.
    pub fn ensure_bounded(&self) -> Result<(), ErrorClass> {
        self.ensure_bounded_within(MAXIMUM_EXCHANGE_BYTES)
    }

    /// Apply the retained-JSON ceiling the caller names: the facade's own
    /// budget for a served exchange, or the job profile's response bound
    /// for a job page run, which a source-route-only endpoint's raised
    /// bound may exceed (section 17.2). The bound is never raised above
    /// what the caller passes, and a served exchange keeps the fixed
    /// budget.
    pub fn ensure_bounded_within(&self, maximum_bytes: usize) -> Result<(), ErrorClass> {
        self.ensure_body_bounded_within(&self.message.body, maximum_bytes)
    }

    /// Check an accumulator as though it were this exchange's body,
    /// without cloning or installing it first, under the caller's
    /// ceiling: the facade's fixed budget, or the job profile's response
    /// bound for a job page run.
    pub(crate) fn ensure_body_bounded_within(
        &self,
        body: &Value,
        maximum_bytes: usize,
    ) -> Result<(), ErrorClass> {
        ensure_serialized_bounded(
            &(body, &self.message.headers, &self.properties),
            maximum_bytes,
        )
    }

    /// The `exchange` argument of a Rhai entrypoint (section 8.11.3):
    /// `#{body, headers, properties}` with lowercased header names and a
    /// null body as `()`.
    #[must_use]
    pub fn as_script_value(&self) -> Value {
        serde_json::json!({
            "body": self.message.body,
            "headers": self.message.headers,
            "properties": self.properties,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
/// Host-proved checkpoint state for the first unfinished linear source step.
pub struct ResumeExecution {
    next_step: u32,
    bindings: BTreeMap<String, String>,
}

impl ResumeExecution {
    /// Construct checkpoint state after the host has validated caller,
    /// request, artifact, lease and expiry authority.
    #[must_use]
    pub fn new(next_step: u32, bindings: BTreeMap<String, String>) -> Self {
        Self {
            next_step,
            bindings,
        }
    }

    /// The zero-based first unfinished source step.
    #[must_use]
    pub fn next_step(&self) -> u32 {
        self.next_step
    }

    /// Declared source identifiers from completed steps, never payloads.
    #[must_use]
    pub fn bindings(&self) -> &BTreeMap<String, String> {
        &self.bindings
    }
}

impl std::fmt::Debug for ResumeExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResumeExecution")
            .field("next_step", &self.next_step)
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum WriteClaim {
    Execute,
    Resume(ResumeExecution),
    Stop,
}

/// Apply the caller's retained-JSON ceiling to a body or accumulator
/// before it is installed on an exchange: the facade's fixed budget, or
/// the job profile's response bound for a job page run, whose endpoints
/// may declare a raised bound (section 17.2).
pub(crate) fn ensure_value_bounded(value: &Value, maximum_bytes: usize) -> Result<(), ErrorClass> {
    ensure_serialized_bounded(value, maximum_bytes)
}

/// Apply the same ceiling to a borrowed list before a split clones it.
pub(crate) fn ensure_values_bounded(
    values: &[&Value],
    maximum_bytes: usize,
) -> Result<(), ErrorClass> {
    ensure_serialized_bounded(&values, maximum_bytes)
}

/// Count JSON bytes without building a second serialized copy in memory.
fn ensure_serialized_bounded(
    value: &impl serde::Serialize,
    maximum_bytes: usize,
) -> Result<(), ErrorClass> {
    let mut counter = BoundedWriter {
        remaining: maximum_bytes,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| ErrorClass::BudgetExhausted)
}

struct BoundedWriter {
    remaining: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("exchange budget exhausted"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A stub capability for the install-refusal tests: the seam's
    /// methods are unreachable here, so each panics if called.
    #[derive(Debug)]
    struct StubCustody;

    impl WriteCustody for StubCustody {
        fn claim<'a>(
            &'a self,
            _key: &'a str,
            _eager: bool,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<WriteClaim, RouteFailure>>
                    + std::marker::Send
                    + 'a,
            >,
        > {
            unreachable!("the install-refusal tests never run a route")
        }
        fn before_effect<'a>(
            &'a self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a,
            >,
        > {
            unreachable!("the install-refusal tests never run a route")
        }
        fn mark_unsupported_incomplete<'a>(
            &'a self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<bool, RouteFailure>>
                    + std::marker::Send
                    + 'a,
            >,
        > {
            unreachable!("the install-refusal tests never run a route")
        }
        fn complete<'a>(
            &'a self,
            _succeeded: bool,
            _remove_on_failure: bool,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a,
            >,
        > {
            unreachable!("the install-refusal tests never run a route")
        }
    }

    /// A real custody installed beside the simulation never runs: with
    /// both installed, every custody call refuses with `facade`, so a
    /// simulation never stands in for the served write's store.
    #[tokio::test]
    async fn custody_beside_a_simulation_refuses_every_call() {
        let mut exchange = Exchange::new("capability-isolation".to_owned());
        crate::replay::ReplayWriteContext::install(&mut exchange)
            .expect("the fresh replay exchange accepts its capability");
        exchange.install_write(std::sync::Arc::new(StubCustody));
        assert_eq!(
            exchange
                .claim_write_key("key", true)
                .await
                .err()
                .map(|failure| failure.class),
            Some(ErrorClass::Facade)
        );
        assert_eq!(
            exchange
                .mark_unsupported_incomplete_write()
                .await
                .err()
                .map(|failure| failure.class),
            Some(ErrorClass::Facade)
        );
    }

    /// A real custody already installed refuses the simulation, and a
    /// second simulation never resets the first.
    #[test]
    fn a_simulation_never_lands_beside_custody_or_twice() {
        let mut served = Exchange::new("served".to_owned());
        served.install_write(std::sync::Arc::new(StubCustody));
        assert!(crate::replay::ReplayWriteContext::install(&mut served).is_err());

        let mut replayed = Exchange::new("replayed".to_owned());
        crate::replay::ReplayWriteContext::install(&mut replayed)
            .expect("the fresh replay exchange accepts its capability");
        assert!(crate::replay::ReplayWriteContext::install(&mut replayed).is_err());
    }

    #[test]
    fn headers_are_case_insensitive() {
        let mut exchange = Exchange::new("x".to_owned());
        exchange.message.set_header("recordId", json!("a"));
        assert_eq!(exchange.message.header("RECORDID"), Some(&json!("a")));
        exchange.message.remove_header("RecordId");
        assert!(exchange.message.header("recordid").is_none());
    }

    #[test]
    fn script_value_lowercases_headers_and_keeps_a_null_body() {
        let mut exchange = Exchange::new("x".to_owned());
        exchange.message.set_header("recordId", json!("a"));
        let value = exchange.as_script_value();
        assert_eq!(value["headers"]["recordid"], json!("a"));
        assert!(value["body"].is_null());
    }

    #[test]
    fn source_write_inputs_derive_repeatable_ordinal_scoped_native_keys() {
        let inputs = SourceWriteInputs::try_new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Some("revision-17"),
        )
        .expect("host-scoped digest and condition");

        let first = inputs.native_idempotency_key(0);
        assert_eq!(first, inputs.native_idempotency_key(0));
        assert_ne!(first, inputs.native_idempotency_key(1));
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!first.contains("revision-17"));
        let other_caller = SourceWriteInputs::try_new(
            "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Some("revision-17"),
        )
        .expect("other caller scope");
        assert_ne!(first, other_caller.native_idempotency_key(0));
    }

    #[test]
    fn source_condition_snapshot_cannot_replace_the_private_authority() {
        let mut exchange = Exchange::new("source-write".to_owned());
        exchange
            .install_source_write_inputs(
                SourceWriteInputs::try_new(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    Some("revision-17"),
                )
                .expect("inputs"),
            )
            .expect("one install");

        exchange.set_property(SOURCE_CONDITION_PROPERTY, json!("attacker-value"));
        assert_eq!(exchange.source_condition(), Some("revision-17"));
        exchange.refresh_source_condition_snapshot();
        assert_eq!(
            exchange.property(SOURCE_CONDITION_PROPERTY),
            Some(&json!("revision-17"))
        );
    }

    #[test]
    fn source_write_inputs_are_single_install_and_never_enter_headers() {
        let mut exchange = Exchange::new("source-write".to_owned());
        let inputs = || {
            SourceWriteInputs::try_new(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                None,
            )
            .expect("inputs")
        };
        exchange
            .install_source_write_inputs(inputs())
            .expect("first install");
        assert_eq!(
            exchange.install_source_write_inputs(inputs()),
            Err(ErrorClass::Facade)
        );
        assert!(exchange.message.header("Idempotency-Key").is_none());
        assert!(exchange.as_script_value()["headers"]
            .as_object()
            .expect("headers")
            .is_empty());
    }
}
