// SPDX-License-Identifier: Apache-2.0

//! The route definition model: the ported Camel EIPs as reader types
//! (`products/adapter/CONCEPT.md` sections 8.3 and 8.6, port table 8.10).
//!
//! A step is an externally tagged union keyed by the Camel EIP name, as
//! Camel's YAML DSL writes it (CFG-ID-7); every variant refuses unknown
//! keys. Camel defaults are the house defaults unless the port table says
//! otherwise. Two bounds Camel leaves open are mandatory here: `split`
//! carries `maximumItems` and `loop` carries `maximumIterations`
//! (`products/adapter/CONCEPT.md` section 5.5); the authoring checks in
//! `crate::checks` refuse their absence.

use crate::model::{
    AggregationStrategy, ErrorClass, Expression, HttpMethod, RhaiExpression, SendUri,
};
use registry_platform_yaml::{BoundedU64, ExternalId};
use serde::{Deserialize, Serialize};

/// A route as Camel's YAML DSL writes it: one `from`, `direct:` only, and
/// an ordered step list (`products/adapter/CONCEPT.md` section 8.3). Pack
/// templates carry the same steps without the `from`; the instantiated
/// route's `from` is `direct:<routeId>`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteDefinition {
    /// The route identifier `direct:` targets and bindings name.
    pub id: ExternalId,
    /// The route consumer; `direct:` only.
    pub from: RouteFrom,
    /// The ordered steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// The `from` of a route: Camel's route consumer, bounded to `direct:`
/// (divergence: the `rest` consumer dispatches to `direct:` routes;
/// section 8.8).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteFrom {
    /// A `direct:<routeId>` URI.
    pub uri: SendUri,
}

/// One step of a route body, externally tagged by the Camel EIP name
/// (CFG-ID-7). Every port-table row for Increments 0 to 3 has a variant,
/// so the format does not change when a later increment lands
/// (`products/adapter/CONCEPT.md` section 8.10).
///
/// Step round-trip forms are pinned one per variant by the tests of this
/// module; each test names the Camel 4.x page the variant's semantics port
/// from.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Step {
    /// Send to a static endpoint or route. No `toD` is ported.
    To(ToStep),
    /// Set the message body from an expression.
    SetBody(Expression),
    /// Set the message body from an expression (Camel's `transform`).
    Transform(Expression),
    /// Set one message header.
    SetHeader(SetHeaderStep),
    /// Set one exchange property.
    SetProperty(SetPropertyStep),
    /// Remove one message header by name.
    RemoveHeader(String),
    /// Remove one exchange property by name.
    RemoveProperty(String),
    /// Run an expression for effect on properties without changing the
    /// body, as Camel's `script` EIP.
    Script(Expression),
    /// Content-based router: the first matching `when` wins.
    Choice(ChoiceStep),
    /// Message filter: nested steps run only on match; the route continues
    /// after the filter either way.
    Filter(FilterStep),
    /// A failing predicate raises the `validation` class.
    Validate(ValidateStep),
    /// Stop routing the exchange.
    Stop(StopStep),
    /// Split a message into pieces and aggregate them.
    Split(SplitStep),
    /// Repeat a block a bounded number of times.
    Loop(LoopStep),
    /// Call a static endpoint and merge its reply.
    Enrich(EnrichStep),
    /// Wrap steps in a resilience4j circuit breaker with `onFallback`.
    CircuitBreaker(CircuitBreakerStep),
    /// Throttle sends; a waiting exchange waits at most until its
    /// deadline, then raises `throttle.rejected`.
    Throttle(ThrottleStep),
    /// Wrap a write route in idempotent consumption
    /// (`products/adapter/CONCEPT.md` section 9).
    IdempotentConsumer(IdempotentConsumerStep),
    /// The route's error handler: `defaultErrorHandler` or
    /// `noErrorHandler`. The exhausted exchange is always journaled; the
    /// journal is the fixed dead letter.
    ErrorHandler(ErrorHandlerStep),
    /// An exception clause over the closed error-class hierarchy.
    OnException(OnExceptionStep),
    /// `doTry` with `doCatch` and `doFinally` clauses.
    DoTry(DoTryStep),
}

/// A `to` send: the static destination and its parameters
/// (`products/adapter/CONCEPT.md` section 8.8). The `http` component
/// builds the request from the declared template; no expression can change
/// the origin or inject a path segment.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToStep {
    /// The static destination.
    pub uri: SendUri,
    /// The send parameters; `direct:` sends carry none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ToParameters>,
}

/// The parameters of an upstream send, Camel's `http` component options
/// (`products/adapter/CONCEPT.md` section 8.8). The path template's
/// `{name}` segments are filled from `pathParameters` expressions and
/// percent-encoded by the engine as single segments; query members are
/// engine-encoded.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToParameters {
    /// The request method. Its safety carries the write-safety rules of
    /// `crate::checks`.
    pub http_method: HttpMethod,
    /// The path template, e.g. `/v2/cases/{type}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Path-template segment name to expression.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub path_parameters: std::collections::BTreeMap<String, Expression>,
    /// Query parameter name to expression.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub query: std::collections::BTreeMap<String, Expression>,
    /// The request body expression, marshalled to JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Expression>,
    /// The endpoint operation this send invokes, when the pack declares
    /// endpoint operations; write-safety checks read its
    /// `idempotentUpstream` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<ExternalId>,
    /// Whether a failure status raises an error (Camel default true).
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub throw_exception_on_failure: bool,
    /// The inclusive status range treated as success (Camel default
    /// `200-299`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok_status_code_range: Option<String>,
    /// The source-native identifiers a later write-resume step needs
    /// (Increment 3; `products/adapter/CONCEPT.md` section 9).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resume_bindings: Vec<ResumeBinding>,
}

/// One resume binding of a non-safe send: the source-native identifier a
/// later step needs, read by an RFC 9535 selector and stored typed as an
/// identifier, never as an arbitrary value
/// (`products/adapter/CONCEPT.md` section 9).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeBinding {
    /// The binding name later steps reference.
    pub name: registry_platform_yaml::LocalId,
    /// The RFC 9535 selector that reads the identifier from the reply.
    pub path: String,
}

/// One `when` clause of a `choice`: an inline predicate expression (the
/// language key sits beside `steps`, as Camel's YAML DSL writes it) and
/// the steps it guards. Exactly one language key must be present;
/// `crate::checks` refuses zero or several under an adapter code, and the
/// reader refuses any unknown key (`config.unknown-key`, CFG-SCHEMA-8).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct When {
    /// The `constant` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constant: Option<serde_json::Value>,
    /// The `header` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// The `exchangeProperty` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange_property: Option<String>,
    /// The `jsonpath` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonpath: Option<String>,
    /// The `rhai` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rhai: Option<RhaiExpression>,
    /// The steps the clause runs on match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

impl When {
    /// How many language keys the clause carries.
    pub fn language_members(&self) -> usize {
        self.constant.is_some() as usize
            + self.header.is_some() as usize
            + self.exchange_property.is_some() as usize
            + self.jsonpath.is_some() as usize
            + self.rhai.is_some() as usize
    }

    /// The decoded predicate, when exactly one language key is present;
    /// `None` for zero or several keys. `crate::checks` reports the
    /// malformed shapes under `adapter.route.predicate-*` codes, so a
    /// caller only ever sees a well-formed expression.
    pub fn predicate(&self) -> Option<Expression> {
        if self.language_members() != 1 {
            return None;
        }
        self.predicate_unchecked()
    }

    fn predicate_unchecked(&self) -> Option<Expression> {
        if let Some(value) = &self.constant {
            return Some(Expression::Constant(value.clone()));
        }
        if let Some(name) = &self.header {
            return Some(Expression::Header(name.clone()));
        }
        if let Some(name) = &self.exchange_property {
            return Some(Expression::ExchangeProperty(name.clone()));
        }
        if let Some(path) = &self.jsonpath {
            return Some(Expression::JsonPath(path.clone()));
        }
        self.rhai.clone().map(Expression::Rhai)
    }
}

/// The `otherwise` clause of a `choice`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Otherwise {
    /// The steps the clause runs when no `when` matched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// A `choice` step: first matching predicate wins, as Camel's Content-Based
/// Router.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChoiceStep {
    /// The clauses, in declaration order.
    pub when: Vec<When>,
    /// The fallback clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otherwise: Option<Otherwise>,
}

/// A `filter` step: an inline predicate beside the guarded steps, as
/// Camel's Message Filter writes it. `CamelFilterMatched` records the
/// outcome; the route continues after the filter either way. Exactly one
/// language key must be present; `crate::checks` refuses zero or several
/// under an adapter code, and the reader refuses any unknown key
/// (`config.unknown-key`, CFG-SCHEMA-8).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilterStep {
    /// The `constant` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constant: Option<serde_json::Value>,
    /// The `header` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// The `exchangeProperty` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange_property: Option<String>,
    /// The `jsonpath` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonpath: Option<String>,
    /// The `rhai` language member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rhai: Option<RhaiExpression>,
    /// The steps that run only on match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

impl FilterStep {
    /// How many language keys the step carries.
    pub fn language_members(&self) -> usize {
        self.constant.is_some() as usize
            + self.header.is_some() as usize
            + self.exchange_property.is_some() as usize
            + self.jsonpath.is_some() as usize
            + self.rhai.is_some() as usize
    }

    /// The decoded predicate, when exactly one language key is present;
    /// `None` for zero or several keys. `crate::checks` reports the
    /// malformed shapes under `adapter.route.predicate-*` codes, so a
    /// caller only ever sees a well-formed expression.
    pub fn predicate(&self) -> Option<Expression> {
        if self.language_members() != 1 {
            return None;
        }
        if let Some(value) = &self.constant {
            return Some(Expression::Constant(value.clone()));
        }
        if let Some(name) = &self.header {
            return Some(Expression::Header(name.clone()));
        }
        if let Some(name) = &self.exchange_property {
            return Some(Expression::ExchangeProperty(name.clone()));
        }
        if let Some(path) = &self.jsonpath {
            return Some(Expression::JsonPath(path.clone()));
        }
        self.rhai.clone().map(Expression::Rhai)
    }
}

/// A `validate` step.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateStep {
    /// The predicate; failure raises the `validation` class.
    pub expression: Expression,
}

/// A `stop` step. The empty mapping `{}` is the whole variant.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StopStep {}

/// A `setHeader` step.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetHeaderStep {
    /// The header name; bounded and engine-validated.
    pub name: String,
    /// The value expression.
    pub value: Expression,
}

/// A `setProperty` step.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPropertyStep {
    /// The exchange property name.
    pub name: String,
    /// The value expression.
    pub value: Expression,
}

/// A `split` step (`products/adapter/CONCEPT.md` sections 8.6 and 5.5).
/// `parallelProcessing`, `streaming`, and `timeout` are not ported.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitStep {
    /// The expression that produces the pieces.
    pub expression: Expression,
    /// The mandatory piece bound; the check refuses its absence and the
    /// runtime enforces it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_items: Option<BoundedU64<1, 100_000>>,
    /// The aggregation strategy; absent, the original message is returned,
    /// Camel's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation_strategy: Option<AggregationStrategy>,
    /// Whether a failing piece stops the split (Camel default false). A
    /// non-safe send inside a split requires true.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stop_on_exception: bool,
    /// Camel's failure accounting: failed pieces that stop the split.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_threshold: Option<BoundedU64<1, 100_000>>,
    /// Camel's failure accounting: the maximum failed pieces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_failed_records: Option<BoundedU64<1, 100_000>>,
    /// The steps applied to each piece.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// A `loop` step (`products/adapter/CONCEPT.md` sections 8.6 and 5.5).
/// Pagination is `loop` with `doWhile` over the upstream cursor.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoopStep {
    /// The mandatory iteration bound; the check refuses its absence and
    /// the runtime enforces it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_iterations: Option<BoundedU64<1, 100_000>>,
    /// The do-while predicate: continue while it holds, bounded by
    /// `maximumIterations`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub do_while: Option<Expression>,
    /// Whether each iteration works on a copy of the message (Camel
    /// default false).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub copy: bool,
    /// The repeated steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// An `enrich` step: call a static endpoint and merge the reply. Static URI
/// only; no `pollEnrich`. Absent a strategy, the reply replaces the body
/// (Camel's default).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrichStep {
    /// The static destination.
    pub uri: SendUri,
    /// The aggregation strategy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation_strategy: Option<AggregationStrategy>,
    /// Whether to aggregate the reply of a failed call (Camel default
    /// false; failure propagates to the error handler).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub aggregate_on_exception: bool,
}

/// A `circuitBreaker` step: resilience4j semantics and defaults
/// (`products/adapter/CONCEPT.md` section 8.7), per EIP node,
/// process-local. Divergence: a rejected call always raises
/// `breaker.open`, and `onFallback` runs on failure and on rejection.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerStep {
    /// Failure-rate percentage that opens the breaker (resilience4j
    /// default 50).
    #[serde(
        default = "default_failure_rate_threshold",
        skip_serializing_if = "is_default_failure_rate_threshold"
    )]
    pub failure_rate_threshold: u8,
    /// The count-based window size (default 100); the window type is fixed
    /// count-based and not configurable.
    #[serde(
        default = "default_sliding_window_size",
        skip_serializing_if = "is_default_sliding_window_size"
    )]
    pub sliding_window_size: u32,
    /// Calls recorded before the breaker judges (default 100).
    #[serde(
        default = "default_minimum_number_of_calls",
        skip_serializing_if = "is_default_minimum_number_of_calls"
    )]
    pub minimum_number_of_calls: u32,
    /// Seconds the breaker stays open (resilience4j
    /// `waitDurationInOpenState`, default 60).
    #[serde(
        default = "default_open_state_wait_seconds",
        skip_serializing_if = "is_default_open_state_wait_seconds"
    )]
    pub open_state_wait_seconds: u32,
    /// Permitted half-open calls (default 10).
    #[serde(
        default = "default_maximum_half_open_calls",
        skip_serializing_if = "is_default_maximum_half_open_calls"
    )]
    pub maximum_half_open_calls: u32,
    /// Automatic open-to-half-open transition (default false).
    #[serde(
        default = "default_automatic_transition",
        skip_serializing_if = "is_default_automatic_transition"
    )]
    pub automatic_transition_from_open_to_half_open_enabled: bool,
    /// Slow-call-rate percentage that opens the breaker (default 100).
    #[serde(
        default = "default_slow_call_rate_threshold",
        skip_serializing_if = "is_default_slow_call_rate_threshold"
    )]
    pub slow_call_rate_threshold: u8,
    /// Seconds over which a call counts as slow (default 60).
    #[serde(
        default = "default_slow_call_duration_threshold_seconds",
        skip_serializing_if = "is_default_slow_call_duration_threshold_seconds"
    )]
    pub slow_call_duration_threshold_seconds: u32,
    /// The guarded steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
    /// The fallback, run on failure and on rejection; its output is
    /// validated like any route output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_fallback: Option<OnFallback>,
}

/// The `onFallback` of a `circuitBreaker`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OnFallback {
    /// The fallback steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// Throttle mode, Camel 4's `mode` option.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum ThrottleMode {
    /// Total requests per period (Camel default).
    TotalRequests,
    /// Concurrent requests.
    ConcurrentRequests,
}

/// A `throttle` step (`products/adapter/CONCEPT.md` section 8.6).
/// Divergence: a waiting exchange waits at most until its deadline, then
/// raises `throttle.rejected`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThrottleStep {
    /// The request limit per period, an expression as Camel 4 reads it.
    pub limit: Expression,
    /// Total or concurrent requests (Camel default total).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ThrottleMode>,
    /// The period in milliseconds (Camel default 1000).
    #[serde(
        default = "default_time_period_milliseconds",
        skip_serializing_if = "is_default_time_period_milliseconds"
    )]
    pub time_period_milliseconds: u32,
    /// Whether to reject immediately instead of waiting (Camel default
    /// false).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reject_execution: bool,
    /// The throttled steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// An `idempotentConsumer` step (`products/adapter/CONCEPT.md` section 9).
/// The key is namespaced by caller identity and concrete operation and
/// bound to the request digest; a duplicate replays the recorded facade
/// response; `skipDuplicate` is not ported.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdempotentConsumerStep {
    /// The key expression, conventionally the caller's `Idempotency-Key`
    /// header.
    pub expression: Expression,
    /// Add the key before processing (Camel default true).
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub eager: bool,
    /// Remove the key on failure before any upstream effect (Camel default
    /// true).
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub remove_on_failure: bool,
    /// Release the key on completion (Camel default false).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub completion_eager: bool,
    /// The guarded steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// The route `errorHandler` step: `defaultErrorHandler` (no redelivery,
/// the error propagates) or `noErrorHandler`. Exactly one member is set.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorHandlerStep {
    /// The default error handler with its redelivery policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_error_handler: Option<DefaultErrorHandler>,
    /// The no-op error handler: failures propagate untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_error_handler: Option<NoErrorHandler>,
}

/// Camel's `defaultErrorHandler`: a redelivery policy nested under
/// `redeliveryPolicy`, as Camel's YAML DSL writes it
/// (`products/adapter/CONCEPT.md` section 8.7; CFG-NAME spelling inside).
/// `delayPattern` is not ported. Redelivery is per failing endpoint send,
/// as in Camel.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefaultErrorHandler {
    /// The nested redelivery policy; the default carries no redelivery,
    /// so the error propagates after the first attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redelivery_policy: Option<RedeliveryOptions>,
}

/// Camel's `noErrorHandler`. The empty mapping `{}` is the whole variant.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoErrorHandler {}

/// An `onException` clause over the closed error-class hierarchy
/// (`products/adapter/CONCEPT.md` section 8.7). No clause may name an
/// uncatchable class; `crate::checks` refuses one that does. Redelivery
/// nests under `redeliveryPolicy`, as Camel's exception clause does in
/// YAML (`manual/exception-clause.html`, `manual/exception-redelivery.html`).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OnExceptionStep {
    /// The matched classes.
    pub exception: Vec<ErrorClass>,
    /// Narrow the clause with a predicate (Camel `onWhen`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_when: Option<Expression>,
    /// Whether the clause consumes the error (Camel `handled`). True ends
    /// the exchange with the clause's result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handled: Option<bool>,
    /// Whether the route resumes after the failure point (Camel
    /// `continued`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continued: Option<bool>,
    /// Redelivery options, as on the error handler, nested under
    /// `redeliveryPolicy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redelivery_policy: Option<RedeliveryOptions>,
    /// The clause's steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// The redelivery option set, shared by the error handler and an
/// `onException` clause (`products/adapter/CONCEPT.md` section 8.7; the
/// nesting under `redeliveryPolicy` follows Camel's own YAML DSL,
/// `manual/exception-clause.html` and `manual/exception-redelivery.html`).
/// Option spellings stay ours (CFG-NAME); only the nesting is Camel's.
/// Only the non-default members serialize.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedeliveryOptions {
    /// Redeliveries after the first attempt (default 0).
    #[serde(default, skip_serializing_if = "is_default_zero_u32")]
    pub maximum_redeliveries: u32,
    /// Delay between redeliveries (default 1 s).
    #[serde(
        default = "default_retry_delay_seconds",
        skip_serializing_if = "is_default_retry_delay_seconds"
    )]
    pub retry_delay_seconds: u32,
    /// Grow the delay exponentially (default false).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub use_exponential_back_off: bool,
    /// The exponential multiplier (default 2).
    #[serde(
        default = "default_back_off_multiplier",
        skip_serializing_if = "is_default_back_off_multiplier"
    )]
    pub back_off_multiplier: f64,
    /// The delay ceiling (default 60 s).
    #[serde(
        default = "default_maximum_retry_delay_seconds",
        skip_serializing_if = "is_default_maximum_retry_delay_seconds"
    )]
    pub maximum_retry_delay_seconds: u32,
    /// Add collision avoidance jitter (default false).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub use_collision_avoidance: bool,
    /// The jitter fraction (default 0.15).
    #[serde(
        default = "default_collision_avoidance_factor",
        skip_serializing_if = "is_default_collision_avoidance_factor"
    )]
    pub collision_avoidance_factor: f64,
    /// Stop redelivering early while this predicate holds (Camel
    /// `retryWhile`). Divergence from Camel: the predicate only stops
    /// redelivery earlier and `maximumRedeliveries` remains the hard cap,
    /// where Camel lets `retryWhile` override it, so
    /// `maximumUpstreamCalls` stays a check-time guarantee. The checks
    /// refuse the predicate together with `maximumRedeliveries` 0, where
    /// it could never fire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_while: Option<Expression>,
}

/// A `doCatch` clause of a `doTry`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoCatch {
    /// The matched classes.
    pub exception: Vec<ErrorClass>,
    /// Narrow the clause with a predicate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_when: Option<Expression>,
    /// The clause's steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// The `doFinally` clause of a `doTry`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DoFinally {
    /// The always-run steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// A `doTry` step, ported as in Camel (`manual/try-catch-finally.html`).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DoTryStep {
    /// The guarded steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
    /// The catch clauses, in declaration order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub do_catch: Vec<DoCatch>,
    /// The finally clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub do_finally: Option<DoFinally>,
}

/// A route template parameter (`products/adapter/CONCEPT.md` section 8.4).
/// Divergence from Camel: typed and checked under CFG-VAL-9, where Camel
/// parameters are untyped strings.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateParameter {
    /// The parameter name, referenced as `{{name}}` or `{{?name}}`.
    pub name: ExternalId,
    /// The value type checked at instantiation.
    pub r#type: TemplateParameterType,
    /// Whether instantiation without the parameter is refused.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    /// The value used when the instantiation omits the parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,
    /// What the parameter means, for the reviewed pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A template parameter's value type (CFG-VAL-9).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum TemplateParameterType {
    String,
    Integer,
    Number,
    Boolean,
}

/// A route template, Camel's `routeTemplate` without its `from`
/// (`products/adapter/CONCEPT.md` section 8.4): the instantiated route's
/// `from` is `direct:<routeId>`, bound by the contract.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteTemplate {
    /// The template identifier `templatedRoutes` reference.
    pub id: ExternalId,
    /// The typed parameters the template body references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<TemplateParameter>,
    /// The template body, with `{{name}}` and `{{?name}}` placeholders.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

/// A template instantiation in a project, Camel's `templatedRoute`
/// (`manual/route-template.html`). Placeholders resolve at instantiation,
/// during `adapterctl check` and at startup, never per request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplatedRoute {
    /// The pack template this instantiation references.
    pub route_template_ref: ExternalId,
    /// The instantiated route id; its `from` becomes `direct:<routeId>`.
    pub route_id: ExternalId,
    /// Parameter value by parameter name.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub parameters: std::collections::BTreeMap<String, serde_json::Value>,
}

// The two `f64` members of the policy (Camel's `backOffMultiplier` and
// `collisionAvoidanceFactor`) keep the Camel spelling; equality and the
// hash derived from it are bitwise so the type stays `Eq` and `Hash`
// for the unique-list readers.
impl PartialEq for RedeliveryOptions {
    fn eq(&self, other: &Self) -> bool {
        self.maximum_redeliveries == other.maximum_redeliveries
            && self.retry_delay_seconds == other.retry_delay_seconds
            && self.use_exponential_back_off == other.use_exponential_back_off
            && self.back_off_multiplier.to_bits() == other.back_off_multiplier.to_bits()
            && self.maximum_retry_delay_seconds == other.maximum_retry_delay_seconds
            && self.use_collision_avoidance == other.use_collision_avoidance
            && self.collision_avoidance_factor.to_bits()
                == other.collision_avoidance_factor.to_bits()
            && self.retry_while == other.retry_while
    }
}

impl Eq for RedeliveryOptions {}

impl std::hash::Hash for RedeliveryOptions {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.maximum_redeliveries.hash(state);
        self.retry_delay_seconds.hash(state);
        self.use_exponential_back_off.hash(state);
        self.back_off_multiplier.to_bits().hash(state);
        self.maximum_retry_delay_seconds.hash(state);
        self.use_collision_avoidance.hash(state);
        self.collision_avoidance_factor.to_bits().hash(state);
        self.retry_while.hash(state);
    }
}

impl registry_platform_yaml::Identified for RouteDefinition {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

impl registry_platform_yaml::Identified for RouteTemplate {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

impl registry_platform_yaml::Identified for TemplatedRoute {
    fn id(&self) -> &str {
        self.route_id.as_str()
    }
}

fn default_true() -> bool {
    true
}

fn is_default_true(value: &bool) -> bool {
    *value
}

fn is_default_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn default_failure_rate_threshold() -> u8 {
    50
}

fn is_default_failure_rate_threshold(value: &u8) -> bool {
    *value == 50
}

fn default_sliding_window_size() -> u32 {
    100
}

fn is_default_sliding_window_size(value: &u32) -> bool {
    *value == 100
}

fn default_minimum_number_of_calls() -> u32 {
    100
}

fn is_default_minimum_number_of_calls(value: &u32) -> bool {
    *value == 100
}

fn default_open_state_wait_seconds() -> u32 {
    60
}

fn is_default_open_state_wait_seconds(value: &u32) -> bool {
    *value == 60
}

fn default_maximum_half_open_calls() -> u32 {
    10
}

fn is_default_maximum_half_open_calls(value: &u32) -> bool {
    *value == 10
}

fn default_automatic_transition() -> bool {
    false
}

fn is_default_automatic_transition(value: &bool) -> bool {
    !*value
}

fn default_slow_call_rate_threshold() -> u8 {
    100
}

fn is_default_slow_call_rate_threshold(value: &u8) -> bool {
    *value == 100
}

fn default_slow_call_duration_threshold_seconds() -> u32 {
    60
}

fn is_default_slow_call_duration_threshold_seconds(value: &u32) -> bool {
    *value == 60
}

fn default_time_period_milliseconds() -> u32 {
    1000
}

fn is_default_time_period_milliseconds(value: &u32) -> bool {
    *value == 1000
}

fn default_retry_delay_seconds() -> u32 {
    1
}

fn is_default_retry_delay_seconds(value: &u32) -> bool {
    *value == 1
}

fn default_back_off_multiplier() -> f64 {
    2.0
}

fn is_default_back_off_multiplier(value: &f64) -> bool {
    *value == 2.0
}

fn default_maximum_retry_delay_seconds() -> u32 {
    60
}

fn is_default_maximum_retry_delay_seconds(value: &u32) -> bool {
    *value == 60
}

fn default_collision_avoidance_factor() -> f64 {
    0.15
}

fn is_default_collision_avoidance_factor(value: &f64) -> bool {
    *value == 0.15
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RhaiExpression, SendComponent};

    fn rhai(file: &str, entrypoint: &str) -> Expression {
        Expression::Rhai(RhaiExpression {
            file: file.to_string(),
            entrypoint: entrypoint.to_string(),
        })
    }

    /// Route and YAML DSL shape, ported from
    /// <https://camel.apache.org/manual/routes.html>.
    #[test]
    fn route_definition_round_trips_with_direct_from() {
        let route: RouteDefinition = serde_json::from_str(
            r#"{
                "id": "fetchCase",
                "from": { "uri": "direct:fetchCase" },
                "steps": [
                    { "setBody": { "constant": null } }
                ]
            }"#,
        )
        .expect("parse");
        assert_eq!(route.from.uri.component, SendComponent::Direct);
        assert_eq!(route.steps.len(), 1);
        let json = serde_json::to_string(&route).expect("serialize");
        assert_eq!(
            serde_json::from_str::<RouteDefinition>(&json).ok(),
            Some(route)
        );
        assert!(
            serde_json::from_str::<RouteDefinition>(
                r#"{"id": "x", "from": {"uri": "rest:facade"}}"#
            )
            .is_err(),
            "a from outside direct:, http:, and graphql: is refused at the reader; the direct-only rule is checked"
        );
    }

    /// `to` shape, ported from
    /// <https://camel.apache.org/components/next/eips/to-eip.html> and the
    /// `http` component options of
    /// <https://camel.apache.org/components/next/http-component.html>.
    #[test]
    fn to_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{
                "to": {
                    "uri": "http:cases",
                    "parameters": {
                        "httpMethod": "GET",
                        "path": "/v2/cases/{type}",
                        "pathParameters": { "id": { "header": "recordId" } },
                        "query": { "program": { "constant": "{{program}}" } },
                        "throwExceptionOnFailure": true
                    }
                }
            }"#,
        )
        .expect("parse");
        let Step::To(to) = &step else {
            panic!("expected a to step");
        };
        assert_eq!(
            to.parameters.as_ref().expect("parameters").http_method,
            HttpMethod::Get
        );
        assert_eq!(
            serde_json::to_value(&step).expect("serialize"),
            serde_json::from_str::<serde_json::Value>(
                r#"{
                    "to": {
                        "uri": "http:cases",
                        "parameters": {
                            "httpMethod": "GET",
                            "path": "/v2/cases/{type}",
                            "pathParameters": { "id": { "header": "recordId" } },
                            "query": { "program": { "constant": "{{program}}" } }
                        }
                    }
                }"#
            )
            .expect("expected form")
        );
    }

    /// `setBody` and `transform`, ported from
    /// <https://camel.apache.org/components/next/eips/setBody-eip.html> and
    /// <https://camel.apache.org/components/next/eips/transform-eip.html>.
    #[test]
    fn set_body_and_transform_round_trip() {
        for key in ["setBody", "transform"] {
            let json = format!(
                r#"{{ "{key}": {{ "rhai": {{ "file": "scripts/x.rhai", "entrypoint": "toRecord" }} }} }}"#
            );
            let step: Step = serde_json::from_str(&json).expect("parse");
            let expected = match key {
                "setBody" => Step::SetBody(rhai("scripts/x.rhai", "toRecord")),
                _ => Step::Transform(rhai("scripts/x.rhai", "toRecord")),
            };
            assert_eq!(step, expected);
            let back = serde_json::to_string(&step).expect("serialize");
            assert!(back.contains(&format!("\"{key}\"")));
        }
    }

    /// `setHeader` and its siblings, ported from
    /// <https://camel.apache.org/components/next/eips/setHeader-eip.html>.
    #[test]
    fn header_and_property_steps_round_trip() {
        let set_header: Step = serde_json::from_str(
            r#"{ "setHeader": { "name": "recordType", "value": { "constant": "case" } } }"#,
        )
        .expect("parse setHeader");
        assert_eq!(
            serde_json::to_string(&set_header).expect("serialize"),
            r#"{"setHeader":{"name":"recordType","value":{"constant":"case"}}}"#
        );
        let set_property: Step = serde_json::from_str(
            r#"{ "setProperty": { "name": "cursor", "value": { "jsonpath": "$.nextCursor" } } }"#,
        )
        .expect("parse setProperty");
        assert!(serde_json::to_string(&set_property).is_ok());
        let remove_header: Step =
            serde_json::from_str(r#"{ "removeHeader": "scratch" }"#).expect("parse removeHeader");
        assert!(matches!(remove_header, Step::RemoveHeader(_)));
        let remove_property: Step = serde_json::from_str(r#"{ "removeProperty": "scratch" }"#)
            .expect("parse removeProperty");
        assert!(matches!(remove_property, Step::RemoveProperty(_)));
    }

    /// The `script` EIP, ported from
    /// <https://camel.apache.org/components/next/eips/script-eip.html>;
    /// Rhai only.
    #[test]
    fn script_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{ "script": { "rhai": { "file": "scripts/annotate.rhai", "entrypoint": "annotate" } } }"#,
        )
        .expect("parse");
        assert!(matches!(step, Step::Script(_)));
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(serde_json::from_str::<Step>(&back).ok(), Some(step));
    }

    /// The Content-Based Router, ported from
    /// <https://camel.apache.org/components/next/eips/choice-eip.html>; the
    /// language key sits beside `steps` as Camel's YAML DSL writes it.
    #[test]
    fn choice_step_round_trips_with_inline_predicate() {
        let step: Step = serde_json::from_str(
            r#"{
                "choice": {
                    "when": [
                        { "jsonpath": "$.inactive", "steps": [ { "setBody": { "constant": null } } ] }
                    ],
                    "otherwise": { "steps": [ { "stop": {} } ] }
                }
            }"#,
        )
        .expect("parse");
        let Step::Choice(choice) = &step else {
            panic!("expected a choice step");
        };
        assert_eq!(choice.when.len(), 1);
        assert_eq!(
            choice.when[0].predicate(),
            Some(Expression::JsonPath("$.inactive".to_string()))
        );
        assert_eq!(choice.when[0].language_members(), 1);
        assert!(choice.otherwise.is_some());
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
        assert!(
            serde_json::from_str::<Step>(r#"{ "choice": { "when": [ { "bogus": 1 } ] } }"#)
                .is_err(),
            "a when with no known predicate key is refused"
        );
    }

    /// The Message Filter, ported from
    /// <https://camel.apache.org/components/next/eips/filter-eip.html>.
    #[test]
    fn filter_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{ "filter": { "rhai": { "file": "scripts/guard.rhai", "entrypoint": "admits" }, "steps": [ { "stop": {} } ] } }"#,
        )
        .expect("parse");
        let Step::Filter(filter) = &step else {
            panic!("expected a filter step");
        };
        assert_eq!(filter.steps.len(), 1);
        assert_eq!(
            filter.predicate(),
            Some(Expression::Rhai(RhaiExpression {
                file: "scripts/guard.rhai".to_string(),
                entrypoint: "admits".to_string(),
            }))
        );
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
        // CFG-SCHEMA-8: the reader refuses any unknown key beside the
        // language members; the platform codes that refusal
        // `config.unknown-key` with the key's path, line, and column. The
        // zero-or-several-key rule is an authoring check in
        // `crate::checks` under `adapter.route.predicate-*`.
        assert!(
            serde_json::from_str::<Step>(
                r#"{ "filter": { "jsonpath": "$.active", "bogus": 1, "steps": [] } }"#,
            )
            .is_err(),
            "an unknown key beside a valid predicate language key is refused"
        );
        assert!(
            serde_json::from_str::<Step>(r#"{ "choice": { "when": [ { "bogus": 1 } ] } }"#,)
                .is_err(),
            "a when with no known predicate key is refused"
        );
    }

    /// `validate`, ported from
    /// <https://camel.apache.org/components/next/eips/validate-eip.html>.
    #[test]
    fn validate_step_round_trips() {
        let step: Step =
            serde_json::from_str(r#"{ "validate": { "expression": { "jsonpath": "$.id" } } }"#)
                .expect("parse");
        let Step::Validate(validate) = &step else {
            panic!("expected a validate step");
        };
        assert_eq!(
            validate.expression,
            Expression::JsonPath("$.id".to_string())
        );
    }

    /// `stop`, ported from
    /// <https://camel.apache.org/components/next/eips/stop-eip.html>.
    #[test]
    fn stop_step_round_trips() {
        let step: Step = serde_json::from_str(r#"{ "stop": {} }"#).expect("parse");
        assert_eq!(step, Step::Stop(StopStep {}));
        assert_eq!(
            serde_json::to_string(&step).expect("serialize"),
            r#"{"stop":{}}"#
        );
    }

    /// The Splitter, ported from
    /// <https://camel.apache.org/components/next/eips/split-eip.html>;
    /// `maximumItems` is mandatory in the checks, `parallelProcessing` and
    /// `streaming` are not ported.
    #[test]
    fn split_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{
                "split": {
                    "expression": { "jsonpath": "$.instances" },
                    "maximumItems": 100,
                    "stopOnException": true,
                    "aggregationStrategy": { "jsonArrayAppend": { "from": "pages", "into": "records", "uniqueBy": "id" } },
                    "steps": [ { "setBody": { "constant": 1 } } ]
                }
            }"#,
        )
        .expect("parse");
        let Step::Split(split) = &step else {
            panic!("expected a split step");
        };
        assert_eq!(split.maximum_items.map(|bound| bound.get()), Some(100));
        assert!(split.stop_on_exception);
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
    }

    /// The Loop, ported from
    /// <https://camel.apache.org/components/next/eips/loop-eip.html>;
    /// `maximumIterations` is mandatory in the checks.
    #[test]
    fn loop_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{
                "loop": {
                    "maximumIterations": 20,
                    "doWhile": { "jsonpath": "$.nextCursor" },
                    "steps": [ { "to": { "uri": "http:cases" } } ]
                }
            }"#,
        )
        .expect("parse");
        let Step::Loop(loop_step) = &step else {
            panic!("expected a loop step");
        };
        assert!(loop_step.do_while.is_some());
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
    }

    /// The Content Enricher, ported from
    /// <https://camel.apache.org/components/next/eips/enrich-eip.html>;
    /// static URI only, no `pollEnrich`.
    #[test]
    fn enrich_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{
                "enrich": {
                    "uri": "http:lookup",
                    "aggregationStrategy": { "jsonMerge": { "from": "extra", "into": "record" } }
                }
            }"#,
        )
        .expect("parse");
        let Step::Enrich(enrich) = &step else {
            panic!("expected an enrich step");
        };
        assert!(!enrich.aggregate_on_exception);
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
    }

    /// The Circuit Breaker and `onFallback`, ported from
    /// <https://camel.apache.org/components/next/eips/circuitBreaker-eip.html>
    /// and <https://camel.apache.org/components/next/eips/resilience4j-eip.html>;
    /// rejection always raises `breaker.open`.
    #[test]
    fn circuit_breaker_step_round_trips_with_defaults() {
        let step: Step = serde_json::from_str(
            r#"{
                "circuitBreaker": {
                    "steps": [ { "to": { "uri": "http:cases" } } ],
                    "onFallback": { "steps": [ { "setBody": { "constant": null } } ] }
                }
            }"#,
        )
        .expect("parse");
        let Step::CircuitBreaker(breaker) = &step else {
            panic!("expected a circuitBreaker step");
        };
        // resilience4j defaults, as CONCEPT 8.7 pins them.
        assert_eq!(breaker.failure_rate_threshold, 50);
        assert_eq!(breaker.sliding_window_size, 100);
        assert_eq!(breaker.minimum_number_of_calls, 100);
        assert_eq!(breaker.open_state_wait_seconds, 60);
        assert_eq!(breaker.maximum_half_open_calls, 10);
        assert!(!breaker.automatic_transition_from_open_to_half_open_enabled);
        assert_eq!(breaker.slow_call_rate_threshold, 100);
        assert_eq!(breaker.slow_call_duration_threshold_seconds, 60);
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
        let plain = serde_json::to_value(&step).expect("serialize");
        assert!(
            !plain.to_string().contains("slidingWindowSize"),
            "default members do not serialize"
        );
    }

    /// The Throttler, ported from
    /// <https://camel.apache.org/components/next/eips/throttle-eip.html>;
    /// a waiting exchange waits at most until its deadline.
    #[test]
    fn throttle_step_round_trips_with_defaults() {
        let step: Step = serde_json::from_str(
            r#"{
                "throttle": {
                    "limit": { "constant": 10 },
                    "steps": [ { "to": { "uri": "http:cases" } } ]
                }
            }"#,
        )
        .expect("parse");
        let Step::Throttle(throttle) = &step else {
            panic!("expected a throttle step");
        };
        assert_eq!(throttle.time_period_milliseconds, 1000);
        assert!(!throttle.reject_execution);
        assert!(
            throttle.mode.is_none(),
            "the Camel default is total requests"
        );
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
    }

    /// The Idempotent Consumer, ported from
    /// <https://camel.apache.org/components/next/eips/idempotentConsumer-eip.html>;
    /// duplicates replay the recorded response, `skipDuplicate` is not
    /// ported.
    #[test]
    fn idempotent_consumer_step_round_trips_with_defaults() {
        let step: Step = serde_json::from_str(
            r#"{
                "idempotentConsumer": {
                    "expression": { "header": "Idempotency-Key" },
                    "steps": [ { "to": { "uri": "http:cases", "parameters": { "httpMethod": "POST" } } } ]
                }
            }"#,
        )
        .expect("parse");
        let Step::IdempotentConsumer(idempotent) = &step else {
            panic!("expected an idempotentConsumer step");
        };
        assert!(idempotent.eager);
        assert!(idempotent.remove_on_failure);
        assert!(!idempotent.completion_eager);
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
    }

    /// The default error handler and its nested redelivery policy, ported
    /// from <https://camel.apache.org/manual/defaulterrorhandler.html>,
    /// <https://camel.apache.org/manual/error-handler.html>, and
    /// <https://camel.apache.org/manual/exception-redelivery.html> (the
    /// `redeliveryPolicy:` nesting is Camel's own YAML DSL shape);
    /// `delayPattern` is not ported and the journal is the fixed dead
    /// letter.
    #[test]
    fn error_handler_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{
                "errorHandler": {
                    "defaultErrorHandler": {
                        "redeliveryPolicy": {
                            "maximumRedeliveries": 3,
                            "useExponentialBackOff": true
                        }
                    }
                }
            }"#,
        )
        .expect("parse");
        let Step::ErrorHandler(handler) = &step else {
            panic!("expected an errorHandler step");
        };
        let policy = handler
            .default_error_handler
            .as_ref()
            .expect("handler")
            .redelivery_policy
            .as_ref()
            .expect("policy");
        assert_eq!(policy.maximum_redeliveries, 3);
        assert_eq!(policy.retry_delay_seconds, 1);
        assert_eq!(policy.back_off_multiplier, 2.0);
        assert_eq!(policy.maximum_retry_delay_seconds, 60);
        assert_eq!(policy.collision_avoidance_factor, 0.15);
        // Unknown keys inside redeliveryPolicy are refused by the reader
        // (CFG-SCHEMA-8); the platform codes the refusal
        // `config.unknown-key` with the key's path, line, and column.
        assert!(
            serde_json::from_str::<Step>(
                r#"{ "errorHandler": { "defaultErrorHandler": { "redeliveryPolicy": { "bogus": 1 } } } }"#,
            )
            .is_err(),
            "an unknown key inside redeliveryPolicy is refused"
        );
        let none: Step =
            serde_json::from_str(r#"{ "errorHandler": { "noErrorHandler": {} } }"#).expect("parse");
        assert!(matches!(
            none,
            Step::ErrorHandler(ErrorHandlerStep {
                no_error_handler: Some(_),
                ..
            })
        ));
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
    }

    /// The exception clause, ported from
    /// <https://camel.apache.org/manual/exception-clause.html> with the
    /// redelivery nesting of
    /// <https://camel.apache.org/manual/exception-redelivery.html>; closed
    /// class hierarchy, uncatchable classes refused by the checks.
    #[test]
    fn on_exception_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{
                "onException": {
                    "exception": ["upstream.timeout"],
                    "onWhen": { "jsonpath": "$.retryable" },
                    "handled": true,
                    "redeliveryPolicy": { "maximumRedeliveries": 2 },
                    "steps": [ { "setBody": { "constant": null } } ]
                }
            }"#,
        )
        .expect("parse");
        let Step::OnException(clause) = &step else {
            panic!("expected an onException step");
        };
        assert_eq!(clause.exception, vec![ErrorClass::UpstreamTimeout]);
        assert_eq!(
            clause
                .redelivery_policy
                .as_ref()
                .expect("policy")
                .maximum_redeliveries,
            2
        );
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
    }

    /// Try, catch, finally, ported from
    /// <https://camel.apache.org/manual/try-catch-finally.html>.
    #[test]
    fn do_try_step_round_trips() {
        let step: Step = serde_json::from_str(
            r#"{
                "doTry": {
                    "steps": [ { "to": { "uri": "http:cases" } } ],
                    "doCatch": [
                        { "exception": ["upstream.http"], "steps": [ { "setBody": { "constant": null } } ] }
                    ],
                    "doFinally": { "steps": [ { "removeProperty": "scratch" } ] }
                }
            }"#,
        )
        .expect("parse");
        let Step::DoTry(do_try) = &step else {
            panic!("expected a doTry step");
        };
        assert_eq!(do_try.do_catch.len(), 1);
        assert!(do_try.do_finally.is_some());
        let back = serde_json::to_string(&step).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Step>(&back).ok().as_ref(),
            Some(&step)
        );
    }

    /// Route templates and typed parameters, ported from
    /// <https://camel.apache.org/manual/route-template.html>; typed
    /// parameters and no `from` are divergences CONCEPT 8.4 records.
    #[test]
    fn route_template_and_templated_route_round_trip() {
        let template: RouteTemplate = serde_json::from_str(
            r#"{
                "id": "pagedFetch",
                "parameters": [
                    { "name": "program", "type": "string", "required": true },
                    { "name": "pageSize", "type": "integer", "defaultValue": 50, "description": "page size" }
                ],
                "steps": [ { "setBody": { "constant": "{{?pageSize}}" } } ]
            }"#,
        )
        .expect("parse template");
        assert_eq!(template.parameters.len(), 2);
        assert!(template.parameters[0].required);
        let templated: TemplatedRoute = serde_json::from_str(
            r#"{
                "routeTemplateRef": "pagedFetch",
                "routeId": "listCases",
                "parameters": { "program": "salsa" }
            }"#,
        )
        .expect("parse instantiation");
        assert_eq!(templated.route_id.as_str(), "listCases");
        for value in [
            &serde_json::to_value(&template).expect("template"),
            &serde_json::to_value(&templated).expect("instantiation"),
        ] {
            let text = serde_json::to_string(value).expect("text");
            assert!(serde_json::from_str::<serde_json::Value>(&text).is_ok());
        }
    }

    /// Every step variant serializes with exactly one Camel EIP key, and an
    /// unknown step key is refused by the closed union.
    #[test]
    fn unknown_step_keys_are_refused() {
        assert!(serde_json::from_str::<Step>(r#"{ "wireTap": {} }"#).is_err());
        assert!(serde_json::from_str::<Step>(r#"{ "toD": {} }"#).is_err());
        assert!(serde_json::from_str::<Step>(r#"{ "multicast": {} }"#).is_err());
    }

    /// Resume bindings, the Increment 3 write-resume addition of CONCEPT 9.
    #[test]
    fn resume_bindings_round_trip() {
        let binding: ResumeBinding =
            serde_json::from_str(r#"{ "name": "case_id", "path": "$.id" }"#).expect("parse");
        assert_eq!(binding.name.as_str(), "case_id");
        let json = serde_json::to_string(&binding).expect("serialize");
        assert_eq!(
            serde_json::from_str::<ResumeBinding>(&json).ok(),
            Some(binding)
        );
    }
}
