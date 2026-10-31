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
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::SystemTime;

use crate::replay::{ReplayWriteCapability, ReplayWriteContext};
use deadpool_postgres::GenericClient;
use registry_adapter_core::ErrorClass;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::idempotent::{
    Claim, ClaimRequest, Execution, IdempotencyError, PostgresIdempotencyStore, StoredResponse,
    TerminalOutcome, VerifiedCallerIdentity,
};
use crate::route::RouteFailure;

/// The total JSON-encoded state one live exchange may retain. The body,
/// headers, and properties share the same conservative ceiling as one
/// maximum upstream response; a route cannot multiply that response bound
/// by moving values into other exchange slots.
const MAXIMUM_EXCHANGE_BYTES: usize = registry_adapter_core::MAXIMUM_RESPONSE_BYTES as usize;

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
/// outlive the catch.
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

/// One exchange: an id, the `InOut` message, and its properties.
#[derive(Clone, Debug)]
pub struct Exchange {
    id: String,
    pub message: Message,
    properties: BTreeMap<String, Value>,
    /// Server-owned write capability. It is shared by exchange clones but is
    /// absent from scripts, serialization, retained-JSON accounting, and
    /// debug output.
    write_execution: Option<Arc<WriteExecutionContext>>,
    replay_write: Option<Arc<ReplayWriteContext>>,
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

    /// Attach the authenticated, request-bound idempotency capability a
    /// served write's `idempotentConsumer` will claim. Raw identity values
    /// remain process-local and only their domain-separated digest reaches
    /// PostgreSQL.
    pub(crate) fn prepare_write(
        &mut self,
        store: PostgresIdempotencyStore,
        caller: VerifiedCallerIdentity,
        deployment: String,
        concrete_operation: String,
        request_digest: [u8; 32],
    ) -> Arc<WriteExecutionContext> {
        let context = Arc::new(WriteExecutionContext {
            store,
            caller,
            deployment,
            concrete_operation,
            request_digest,
            state: Mutex::new(WriteState::Ready),
        });
        self.write_execution = Some(Arc::clone(&context));
        context
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
            (Some(context), None) => context.before_upstream_effect().await,
            (None, Some(context)) => context.before_upstream_effect().await,
            _ => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    /// Make an actual upstream 202 irreversible for a served write before
    /// route-level handlers can normalize its body. Offline write replay
    /// mirrors the private marker; an exchange with no write capability is a
    /// read and remains unaffected.
    pub(crate) async fn mark_unsupported_incomplete_write(&self) -> Result<bool, RouteFailure> {
        match (&self.write_execution, &self.replay_write) {
            (Some(context), None) => {
                context.mark_unsupported_incomplete().await?;
                Ok(true)
            }
            (None, Some(context)) => {
                context.mark_unsupported_incomplete().await?;
                Ok(true)
            }
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

    /// Install the explicitly simulated write state for one offline replay.
    /// Only the replay runner can construct the required sealed capability.
    pub(crate) fn prepare_replay_write(
        &mut self,
        capability: ReplayWriteCapability,
    ) -> Result<Arc<ReplayWriteContext>, RouteFailure> {
        if self.write_execution.is_some() || self.replay_write.is_some() {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        let context = Arc::new(ReplayWriteContext::new(capability));
        self.replay_write = Some(Arc::clone(&context));
        Ok(context)
    }

    /// Refuse an exchange whose retained JSON state exceeds the runtime's
    /// fixed memory budget. The exchange id is bounded at admission and is
    /// not route-controlled, so this counts the message body, header names
    /// and values, and property names and values.
    pub fn ensure_bounded(&self) -> Result<(), ErrorClass> {
        self.ensure_body_bounded(&self.message.body)
    }

    /// Check an accumulator as though it were this exchange's body,
    /// without cloning or installing it first.
    pub(crate) fn ensure_body_bounded(&self, body: &Value) -> Result<(), ErrorClass> {
        ensure_serialized_bounded(&(body, &self.message.headers, &self.properties))
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

/// What `idempotentConsumer` does after its atomic claim attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteClaim {
    Execute,
    Stop,
}

/// The facade-visible result of running the idempotency processor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WriteResolution {
    Pending,
    Replay {
        outcome: TerminalOutcome,
        response: StoredResponse,
    },
    Conflict,
    Mismatch,
    ResponseExpired,
    UnsupportedIncomplete,
    Released,
    Finished,
}

enum WriteState {
    Ready,
    Executing {
        execution: Option<Execution>,
        effect_marked: bool,
    },
    Replay {
        outcome: TerminalOutcome,
        response: StoredResponse,
    },
    Conflict,
    Mismatch,
    ResponseExpired,
    UnsupportedIncomplete {
        execution: Option<Execution>,
    },
    Released,
    Finished,
}

/// A process-private idempotency capability shared across exchange clones.
/// Its Debug implementation deliberately reports no caller, operation, key,
/// request digest, response, or database detail.
pub(crate) struct WriteExecutionContext {
    store: PostgresIdempotencyStore,
    caller: VerifiedCallerIdentity,
    deployment: String,
    concrete_operation: String,
    request_digest: [u8; 32],
    state: Mutex<WriteState>,
}

impl fmt::Debug for WriteExecutionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WriteExecutionContext")
            .finish_non_exhaustive()
    }
}

impl WriteExecutionContext {
    async fn claim(&self, key: &str) -> Result<WriteClaim, RouteFailure> {
        let mut state = self.state.lock().await;
        if !matches!(*state, WriteState::Ready) {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        let claimed = self
            .store
            .claim(
                ClaimRequest {
                    caller: &self.caller,
                    deployment: &self.deployment,
                    concrete_operation: &self.concrete_operation,
                    key,
                    request_digest: self.request_digest,
                },
                SystemTime::now(),
            )
            .await
            .map_err(idempotency_failure)?;
        match claimed {
            Claim::Execute(execution) => {
                *state = WriteState::Executing {
                    execution: Some(execution),
                    effect_marked: false,
                };
                Ok(WriteClaim::Execute)
            }
            Claim::Replay { outcome, response } => {
                *state = WriteState::Replay { outcome, response };
                Ok(WriteClaim::Stop)
            }
            Claim::InFlight | Claim::EffectUnknown => {
                *state = WriteState::Conflict;
                Ok(WriteClaim::Stop)
            }
            Claim::Mismatch => {
                *state = WriteState::Mismatch;
                Ok(WriteClaim::Stop)
            }
            Claim::ResponseExpired { .. } => {
                *state = WriteState::ResponseExpired;
                Ok(WriteClaim::Stop)
            }
        }
    }

    async fn before_upstream_effect(&self) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        let WriteState::Executing {
            execution,
            effect_marked,
        } = &mut *state
        else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        if *effect_marked {
            return Ok(());
        }
        let Some(execution) = execution.as_mut() else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        self.store
            .mark_effect_attempted(execution, SystemTime::now())
            .await
            .map_err(idempotency_failure)?;
        *effect_marked = true;
        Ok(())
    }

    async fn release_before_effect(&self) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        let WriteState::Executing {
            execution,
            effect_marked,
        } = &mut *state
        else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        if *effect_marked {
            return Ok(());
        }
        let Some(execution) = execution.take() else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        self.store
            .release_before_effect(execution)
            .await
            .map_err(idempotency_failure)?;
        *state = WriteState::Released;
        Ok(())
    }

    async fn mark_unsupported_incomplete(&self) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        let WriteState::Executing {
            execution,
            effect_marked,
        } = &mut *state
        else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        if !*effect_marked {
            let Some(execution) = execution.as_mut() else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            self.store
                .mark_effect_attempted(execution, SystemTime::now())
                .await
                .map_err(idempotency_failure)?;
            *effect_marked = true;
        }
        *state = WriteState::UnsupportedIncomplete {
            execution: execution.take(),
        };
        Ok(())
    }

    pub(crate) async fn resolution(&self) -> WriteResolution {
        match &*self.state.lock().await {
            WriteState::Ready | WriteState::Executing { .. } => WriteResolution::Pending,
            WriteState::Replay { outcome, response } => WriteResolution::Replay {
                outcome: *outcome,
                response: response.clone(),
            },
            WriteState::Conflict => WriteResolution::Conflict,
            WriteState::Mismatch => WriteResolution::Mismatch,
            WriteState::ResponseExpired => WriteResolution::ResponseExpired,
            WriteState::UnsupportedIncomplete { .. } => WriteResolution::UnsupportedIncomplete,
            WriteState::Released => WriteResolution::Released,
            WriteState::Finished => WriteResolution::Finished,
        }
    }

    /// Persist the terminal response on the facade's journal transaction so
    /// terminal audit and response custody have one commit boundary.
    pub(crate) async fn finish_with_client(
        &self,
        client: &impl GenericClient,
        outcome: TerminalOutcome,
        response: StoredResponse,
    ) -> Result<(), IdempotencyError> {
        let mut state = self.state.lock().await;
        let execution = match &mut *state {
            WriteState::Executing { execution, .. }
            | WriteState::UnsupportedIncomplete { execution } => execution,
            _ => return Err(IdempotencyError::StateConflict),
        };
        let execution = execution.take().ok_or(IdempotencyError::StateConflict)?;
        self.store
            .finish_with_client(client, execution, outcome, response, SystemTime::now())
            .await?;
        *state = WriteState::Finished;
        Ok(())
    }
}

fn idempotency_failure(error: IdempotencyError) -> RouteFailure {
    tracing::error!(%error, "the idempotency store refused a write transition");
    RouteFailure::of(ErrorClass::Facade)
}

/// Apply the exchange's retained-JSON ceiling to a body or accumulator
/// before it is installed on an exchange.
pub(crate) fn ensure_value_bounded(value: &Value) -> Result<(), ErrorClass> {
    ensure_serialized_bounded(value)
}

/// Apply the same ceiling to a borrowed list before a split clones it.
pub(crate) fn ensure_values_bounded(values: &[&Value]) -> Result<(), ErrorClass> {
    ensure_serialized_bounded(&values)
}

/// Count JSON bytes without building a second serialized copy in memory.
fn ensure_serialized_bounded(value: &impl serde::Serialize) -> Result<(), ErrorClass> {
    let mut counter = BoundedWriter {
        remaining: MAXIMUM_EXCHANGE_BYTES,
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

    #[tokio::test]
    async fn a_replay_capability_cannot_replace_a_postgres_write() {
        let manager =
            deadpool_postgres::Manager::new(tokio_postgres::Config::new(), tokio_postgres::NoTls);
        let pool = deadpool_postgres::Pool::builder(manager)
            .max_size(1)
            .build()
            .expect("the unused pool builds without connecting");
        let store = PostgresIdempotencyStore::new(pool, std::time::Duration::from_secs(60))
            .expect("the retention is bounded");
        let caller = VerifiedCallerIdentity::new("https://fixture.invalid", "actor", "machine")
            .expect("the synthetic identity is bounded");
        let mut exchange = Exchange::new("capability-isolation".to_owned());
        let original = exchange.prepare_write(
            store,
            caller,
            "deployment".to_owned(),
            "create:person".to_owned(),
            [0; 32],
        );

        let refusal = exchange
            .prepare_replay_write(crate::replay::test_write_capability())
            .expect_err("a simulation must never replace PostgreSQL state");
        assert_eq!(refusal.class, ErrorClass::Facade);
        assert!(Arc::ptr_eq(
            exchange
                .write_execution
                .as_ref()
                .expect("the real context remains"),
            &original,
        ));
        assert!(exchange.replay_write.is_none());
    }

    #[test]
    fn a_replay_capability_cannot_replace_an_existing_simulation() {
        let mut exchange = Exchange::new("one-simulation".to_owned());
        let original = exchange
            .prepare_replay_write(crate::replay::test_write_capability())
            .expect("a fresh replay exchange accepts its sealed capability");
        let refusal = exchange
            .prepare_replay_write(crate::replay::test_write_capability())
            .expect_err("a second simulation must not reset the first");
        assert_eq!(refusal.class, ErrorClass::Facade);
        assert!(Arc::ptr_eq(
            exchange.replay_write.as_ref().expect("the context remains"),
            &original,
        ));
        assert!(exchange.write_execution.is_none());
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
