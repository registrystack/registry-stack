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

use registry_adapter_core::ErrorClass;
use serde_json::Value;

use crate::engine::replay::ReplayWriteCapability;
use crate::engine::route::RouteFailure;

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
    ) -> Pin<Box<dyn Future<Output = Result<WriteClaim, RouteFailure>> + Send + 'a>>;
    #[allow(clippy::type_complexity)]
    fn before_effect<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>>;
    /// Mark a possible source effect irreversible; the bool answers
    /// whether a real write capability ran (a replay simulation marks
    /// too, and an exchange with neither capability runs nothing).
    #[allow(clippy::type_complexity)]
    fn mark_unsupported_incomplete<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RouteFailure>> + Send + 'a>>;
    #[allow(clippy::type_complexity)]
    fn release_before_effect<'a>(
        &'a self,
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
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
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
    pub(crate) fn install_write(&mut self, capability: Arc<dyn WriteCustody>) {
        self.write_execution = Some(capability);
    }

    /// Claim the key produced by `idempotentConsumer` before running its
    /// guarded steps.
    pub(crate) async fn claim_write_key(&self, key: &str) -> Result<WriteClaim, RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.claim(key).await,
            (None, Some(context)) => context.claim(key).await,
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

    /// Apply Camel's `removeOnFailure` only if no non-safe effect may have
    /// happened. Once the effect marker is durable, the key stays spent and
    /// the facade records the terminal problem instead.
    pub(crate) async fn release_write_before_effect(&self) -> Result<(), RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => context.release_before_effect().await,
            (None, Some(context)) => context.release_before_effect().await,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteClaim {
    Execute,
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
        fn release_before_effect<'a>(
            &'a self,
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
        crate::engine::replay::ReplayWriteContext::install(&mut exchange)
            .expect("the fresh replay exchange accepts its capability");
        exchange.install_write(std::sync::Arc::new(StubCustody));
        assert_eq!(
            exchange
                .claim_write_key("key")
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
        assert!(crate::engine::replay::ReplayWriteContext::install(&mut served).is_err());

        let mut replayed = Exchange::new("replayed".to_owned());
        crate::engine::replay::ReplayWriteContext::install(&mut replayed)
            .expect("the fresh replay exchange accepts its capability");
        assert!(crate::engine::replay::ReplayWriteContext::install(&mut replayed).is_err());
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
}
