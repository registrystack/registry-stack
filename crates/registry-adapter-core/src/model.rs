// SPDX-License-Identifier: Apache-2.0

//! Vocabulary shared by the Adapter artifacts: envelope kinds, HTTP methods,
//! expressions, aggregation strategies, the closed error-class hierarchy,
//! component kinds, and script seams (`products/adapter/CONCEPT.md`
//! sections 8.5, 8.6, and 8.7).

use std::collections::BTreeMap;

use registry_platform_yaml::Digest;
/// Serialize an externally tagged serde form under a `type` member, the
/// shape `registry-platform-yaml`'s `tagged_union!` reads. The same helper
/// pattern lives beside every tagged union in the workspace.
pub(crate) fn serialize_tagged<S: Serializer>(
    external: Result<serde_json::Value, serde_json::Error>,
    tag: &'static str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap as _;

    let external = external.map_err(serde::ser::Error::custom)?;
    let serde_json::Value::Object(entries) = external else {
        return Err(serde::ser::Error::custom(
            "a tagged union serialized as a non-object",
        ));
    };
    let mut entries = entries.into_iter();
    let (Some((variant, members)), None) = (entries.next(), entries.next()) else {
        return Err(serde::ser::Error::custom(
            "a tagged union serialized without exactly one variant",
        ));
    };
    let serde_json::Value::Object(members) = members else {
        return Err(serde::ser::Error::custom(
            "a tagged union variant serialized as a non-object",
        ));
    };
    let mut map = serializer.serialize_map(Some(members.len() + 1))?;
    map.serialize_entry(tag, &variant)?;
    for (key, value) in &members {
        map.serialize_entry(key, value)?;
    }
    map.end()
}

macro_rules! serialize_tagged_union {
    ($type:ty, tag = $tag:literal) => {
        impl Serialize for $type {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                crate::model::serialize_tagged(
                    <$type>::serialize(self, serde_json::value::Serializer),
                    $tag,
                    serializer,
                )
            }
        }
    };
}
use serde::{Deserialize, Serialize, Serializer};
pub(crate) use serialize_tagged_union;

/// A mapping keyed by local identifiers (CFG-ID-1): each key is refused at
/// its own position unless it is a `LocalId`, and the model keeps the
/// keys as text.
pub fn local_id_map<'de, D, V>(
    deserializer: D,
) -> Result<std::collections::BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: serde::Deserialize<'de>,
{
    let map = std::collections::BTreeMap::<registry_platform_yaml::LocalId, V>::deserialize(
        deserializer,
    )?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value))
        .collect())
}

/// The schema of a [`local_id_map`] member: an object whose property names
/// are `LocalId` and whose values are `V`.
#[cfg(feature = "schema")]
pub fn local_id_map_schema<V: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    let names = generator.subschema_for::<registry_platform_yaml::LocalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": generator.subschema_for::<V>(),
    })
}

/// The schema of a map whose keys are the upstream's wire names
/// (`ExternalId`, CFG-ID-1): an object whose property names are
/// `ExternalId` and whose values are `V`.
#[cfg(feature = "schema")]
pub fn external_id_map_schema<V: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    let names = generator.subschema_for::<registry_platform_yaml::ExternalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": generator.subschema_for::<V>(),
    })
}

/// The wire envelope an artifact speaks: the closed set of envelope
/// executors compiled into the engine (`products/adapter/CONCEPT.md`
/// section 8.8). Executors are named for mechanisms, never products.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Envelope {
    #[default]
    RestJson,
    GraphQl,
}

impl Envelope {
    /// The complete closed set, in name order.
    pub const ALL: &'static [Self] = &[Self::GraphQl, Self::RestJson];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RestJson => "rest-json",
            Self::GraphQl => "graphql",
        }
    }

    /// Resolve an envelope name back to its variant, or `None` for any
    /// string outside the closed set.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.name() == name)
    }
}

/// An HTTP method a facade operation or an upstream send may declare. The
/// method decides send safety: `GET` is safe, the write methods are not
/// (`products/adapter/CONCEPT.md` sections 8.7 and 9).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
}

impl HttpMethod {
    /// The complete closed set, in name order.
    pub const ALL: &'static [Self] = &[Self::Get, Self::Patch, Self::Post, Self::Put];

    /// Whether the method can repeat without an upstream effect. Redelivery
    /// over a non-safe send needs the endpoint operation to declare
    /// `idempotentUpstream` (`products/adapter/CONCEPT.md` section 8.7).
    #[must_use]
    pub const fn is_safe(self) -> bool {
        matches!(self, Self::Get)
    }
}

/// A script seam: code in its own file beside the pack, referenced by a
/// relative path and pinned by digest (CFG-EMBED-1). Scripts never carry
/// credentials and never construct URLs; the `http` component builds every
/// request from its declared template
/// (`products/adapter/CONCEPT.md` section 5.6).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptReference {
    /// The script file, relative to the pack document.
    pub path: String,
    /// The `sha256:` digest the file must hash to.
    pub digest: Digest,
}

/// A Rhai expression reference: the digest-pinned file from the pack's
/// script inventory and the precompiled entrypoint to call
/// (`products/adapter/CONCEPT.md` sections 5.6 and 8.5). Inline code is
/// refused (CFG-EMBED-1).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RhaiExpression {
    /// The script file path, resolved against the pack's script inventory.
    pub file: String,
    /// The precompiled entrypoint the engine calls.
    pub entrypoint: String,
}

/// An expression in one of the ported languages, externally tagged by
/// language name as in Camel's YAML DSL (`products/adapter/CONCEPT.md`
/// section 8.5). `rhai` replaces Simple, Groovy, JavaScript, and `bean`.
/// A predicate is an expression whose result is a boolean; the runtime
/// never coerces.
///
/// Round-trip forms are covered beside the steps that carry them, in
/// `crate::route`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Expression {
    /// A literal JSON value, Camel's `constant` language.
    Constant(serde_json::Value),
    /// A message header by name, Camel's `header` language.
    Header(String),
    /// An exchange property by name, Camel's `exchangeProperty` language.
    ExchangeProperty(String),
    /// An inline RFC 9535 JSONPath selector over the message body, as
    /// Camel's `jsonpath` language but on the IETF standard.
    #[serde(rename = "jsonpath")]
    JsonPath(String),
    /// A digest-pinned Rhai script and entrypoint.
    Rhai(RhaiExpression),
}

/// An aggregation strategy, compiled in and named after Camel's built-ins,
/// plus two JSON additions marked as such in
/// `products/adapter/CONCEPT.md` section 8.6. Tagged by `type` on the
/// wire; every variant is a struct variant, the shape
/// `registry-platform-yaml`'s `tagged_union!` reads.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AggregationStrategy {
    /// Keep the newest exchange: the default for `enrich`, which replaces
    /// the body with the resource reply.
    UseLatest {},
    /// Keep the original exchange: the default for `split`. With
    /// `propagateException` false, the split's item failures are
    /// swallowed and the original message returns
    /// (manual/split-eip.html, `UseOriginalAggregationStrategy`).
    UseOriginal {
        /// Whether an item failure is raised after the split completes;
        /// Camel's default is true.
        #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
        propagate_exception: bool,
    },
    /// Concatenate the split results into one list, Camel's `groupedBody`.
    GroupedBody {},
    /// Append one array's elements into another, refusing a duplicate
    /// `uniqueBy` value with the `aggregation.duplicate` class.
    JsonArrayAppend {
        /// The array property the elements are appended into.
        from: String,
        /// The message body member the array lands in.
        into: String,
        /// Member whose value must stay unique across appended elements.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unique_by: Option<String>,
        /// Property names carried out of each reply, each naming a
        /// singular `jsonpath` on the reply body; an absent selection
        /// removes the property (section 8.11.7).
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        properties: BTreeMap<String, String>,
    },
    /// Merge one JSON object into another. No duplicate refusal.
    JsonMerge {
        /// The object property merged into the body.
        from: String,
        /// The message body member the object lands in.
        into: String,
        /// Property names carried out of each reply, each naming a
        /// singular `jsonpath` on the reply body; an absent selection
        /// removes the property (section 8.11.7).
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        properties: BTreeMap<String, String>,
    },
    /// A custom strategy: a Rhai entrypoint over the old and new bodies,
    /// named `oldExchange` and `newExchange` after Camel's own
    /// `AggregationStrategy.aggregate`.
    Rhai {
        /// The script file and entrypoint, resolved against the pack's
        /// script inventory.
        expression: RhaiExpression,
    },
}

registry_platform_yaml::tagged_union!(AggregationStrategy, tag = "type");
serialize_tagged_union!(AggregationStrategy, tag = "type");

fn default_true() -> bool {
    true
}

fn is_default_true(value: &bool) -> bool {
    *value
}

/// A closed error class, the port of Camel's Java exception hierarchy
/// (`products/adapter/CONCEPT.md` section 8.7). Clauses match the closest
/// class across the error and its cause; the five uncatchable classes name
/// the boundary no `onException` or `doCatch` may handle.
///
/// The wire form is the class string (`upstream`, `breaker.open`), which
/// the serde impls of this enum carry, so the schema impl enumerates the
/// same strings by hand: a derive would render the Rust variant names and
/// admit nothing the reader accepts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorClass {
    Upstream,
    UpstreamHttp,
    UpstreamTimeout,
    UpstreamConnection,
    UpstreamMalformed,
    UpstreamTooLarge,
    UpstreamRedirect,
    BreakerOpen,
    ThrottleRejected,
    LoopMaximumIterationsReached,
    Validation,
    ConversionUnmapped,
    AggregationDuplicate,
    Script,
    BudgetExhausted,
    CredentialRejected,
    DisclosureViolation,
    EgressRefused,
    ScriptBudgetExceeded,
    Outcome,
    OutcomeNotFound,
    OutcomeConflict,
    OutcomeInvalidRequest,
    OutcomeRejected,
    Facade,
    FacadeUnauthenticated,
    FacadeForbidden,
    FacadeInvalidRequest,
    FacadeInvalidField,
    FacadeInvalidCursor,
    FacadeNotFound,
    FacadeMethodNotAllowed,
    FacadePayloadTooLarge,
    FacadeUnsupportedMediaType,
    FacadeNotAcceptable,
    FacadeConflict,
    FacadeIdempotencyMismatch,
}

impl ErrorClass {
    /// The complete closed hierarchy, in class-string order.
    pub const ALL: &'static [Self] = &[
        Self::AggregationDuplicate,
        Self::BreakerOpen,
        Self::BudgetExhausted,
        Self::ConversionUnmapped,
        Self::CredentialRejected,
        Self::DisclosureViolation,
        Self::EgressRefused,
        Self::LoopMaximumIterationsReached,
        Self::Script,
        Self::ScriptBudgetExceeded,
        Self::ThrottleRejected,
        Self::Upstream,
        Self::UpstreamConnection,
        Self::UpstreamHttp,
        Self::UpstreamMalformed,
        Self::UpstreamRedirect,
        Self::UpstreamTimeout,
        Self::UpstreamTooLarge,
        Self::Validation,
        Self::Outcome,
        Self::OutcomeConflict,
        Self::OutcomeInvalidRequest,
        Self::OutcomeNotFound,
        Self::OutcomeRejected,
        Self::Facade,
        Self::FacadeConflict,
        Self::FacadeForbidden,
        Self::FacadeIdempotencyMismatch,
        Self::FacadeInvalidCursor,
        Self::FacadeInvalidField,
        Self::FacadeInvalidRequest,
        Self::FacadeMethodNotAllowed,
        Self::FacadeNotAcceptable,
        Self::FacadeNotFound,
        Self::FacadePayloadTooLarge,
        Self::FacadeUnauthenticated,
        Self::FacadeUnsupportedMediaType,
    ];

    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::UpstreamHttp => "upstream.http",
            Self::UpstreamTimeout => "upstream.timeout",
            Self::UpstreamConnection => "upstream.connection",
            Self::UpstreamMalformed => "upstream.malformed",
            Self::UpstreamTooLarge => "upstream.too-large",
            Self::UpstreamRedirect => "upstream.redirect",
            Self::BreakerOpen => "breaker.open",
            Self::ThrottleRejected => "throttle.rejected",
            Self::LoopMaximumIterationsReached => "loop.maximum-iterations-reached",
            Self::Validation => "validation",
            Self::ConversionUnmapped => "conversion.unmapped",
            Self::AggregationDuplicate => "aggregation.duplicate",
            Self::Script => "script",
            Self::BudgetExhausted => "budget.exhausted",
            Self::CredentialRejected => "credential.rejected",
            Self::DisclosureViolation => "disclosure.violation",
            Self::EgressRefused => "egress.refused",
            Self::ScriptBudgetExceeded => "script.budget-exceeded",
            Self::Outcome => "outcome",
            Self::OutcomeNotFound => "outcome.not-found",
            Self::OutcomeConflict => "outcome.conflict",
            Self::OutcomeInvalidRequest => "outcome.invalid-request",
            Self::OutcomeRejected => "outcome.rejected",
            Self::Facade => "facade",
            Self::FacadeUnauthenticated => "facade.unauthenticated",
            Self::FacadeForbidden => "facade.forbidden",
            Self::FacadeInvalidRequest => "facade.invalid-request",
            Self::FacadeInvalidField => "facade.invalid-field",
            Self::FacadeInvalidCursor => "facade.invalid-cursor",
            Self::FacadePayloadTooLarge => "facade.payload-too-large",
            Self::FacadeNotFound => "facade.not-found",
            Self::FacadeMethodNotAllowed => "facade.method-not-allowed",
            Self::FacadeUnsupportedMediaType => "facade.unsupported-media-type",
            Self::FacadeNotAcceptable => "facade.not-acceptable",
            Self::FacadeConflict => "facade.conflict",
            Self::FacadeIdempotencyMismatch => "facade.idempotency-mismatch",
        }
    }

    /// Resolve a class string back to its variant, or `None` for any string
    /// outside the closed hierarchy.
    #[must_use]
    pub fn from_class(class: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.class() == class)
    }

    /// Whether no `onException` or `doCatch` may name this class. The five
    /// uncatchable classes guard the boundary
    /// (`products/adapter/CONCEPT.md` section 8.7).
    #[must_use]
    pub const fn is_uncatchable(self) -> bool {
        matches!(
            self,
            Self::BudgetExhausted
                | Self::CredentialRejected
                | Self::DisclosureViolation
                | Self::EgressRefused
                | Self::ScriptBudgetExceeded
        )
    }

    /// Whether this class is raised by the `rest` consumer outside any
    /// route (`products/adapter/CONCEPT.md` section 8.7): neither a clause
    /// may name it nor a pack raise it, and the profile maps it like every
    /// other class.
    #[must_use]
    pub const fn is_facade(self) -> bool {
        matches!(
            self,
            Self::Facade
                | Self::FacadeUnauthenticated
                | Self::FacadeForbidden
                | Self::FacadeInvalidRequest
                | Self::FacadeInvalidField
                | Self::FacadeInvalidCursor
                | Self::FacadePayloadTooLarge
                | Self::FacadeNotFound
                | Self::FacadeMethodNotAllowed
                | Self::FacadeUnsupportedMediaType
                | Self::FacadeNotAcceptable
                | Self::FacadeConflict
                | Self::FacadeIdempotencyMismatch
        )
    }

    /// Whether this class is the named clause class or one of its
    /// subclasses in the closed hierarchy: a clause naming a parent
    /// matches the classes under it, as Camel's `instanceof` clause
    /// matching does. A clause naming a subclass never matches this class
    /// when this class is the bare superclass.
    #[must_use]
    pub fn is_within(self, clause: Self) -> bool {
        let raised = self.class().split('.').count();
        let declared = clause.class().split('.').count();
        declared <= raised
            && self
                .class()
                .split('.')
                .zip(clause.class().split('.'))
                .all(|(raised, declared)| raised == declared)
    }

    /// The class a clause fires for: the closest match across the error
    /// and its cause chain, Camel's rule
    /// (`manual/exception-clause.html`). `raised` carries the error's
    /// class followed by its causes. Over every clause class a raised
    /// class is within, the smallest distance in hierarchy segments wins;
    /// equally close matches resolve to the clause matching the most
    /// nested cause, later in the chain. Any uncatchable class anywhere in
    /// the chain matches no clause whatever prefix the clause names: the
    /// boundary is not caught through its own causes.
    #[must_use]
    pub fn closest_match(raised: &[Self], clause: &[Self]) -> Option<Self> {
        if raised.iter().any(|error| error.is_uncatchable()) {
            return None;
        }
        let mut best: Option<(usize, Self)> = None;
        for error in raised {
            for declared in clause.iter().copied() {
                if error.is_within(declared) {
                    let distance =
                        error.class().split('.').count() - declared.class().split('.').count();
                    // A smaller distance wins; an equal distance keeps
                    // replacing so the later, most nested cause wins.
                    if best.is_none_or(|(best_distance, _)| best_distance >= distance) {
                        best = Some((distance, declared));
                    }
                }
            }
        }
        best.map(|(_, declared)| declared)
    }
}

impl serde::Serialize for ErrorClass {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.class())
    }
}

impl<'de> serde::Deserialize<'de> for ErrorClass {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let class = String::deserialize(deserializer)?;
        Self::from_class(&class).ok_or_else(|| {
            serde::de::Error::custom(registry_platform_yaml::Invalid::expected(
                "an error class from the closed Adapter hierarchy",
                "Name one class of the error hierarchy in CONCEPT.md section 8.7.",
            ))
        })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ErrorClass {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ErrorClass".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let wire_names = ErrorClass::ALL
            .iter()
            .map(|class| class.class())
            .collect::<Vec<_>>();
        schemars::json_schema!({
            "description": "A closed error class, the port of Camel's Java exception hierarchy (`products/adapter/CONCEPT.md` section 8.7).",
            "type": "string",
            "enum": wire_names,
        })
    }
}

/// A component kind, the ported subset of Camel's component library
/// (`products/adapter/CONCEPT.md` section 8.8). `rest` is the facade
/// consumer; `direct` calls routes in process; `http` and `graphql` are the
/// upstream producers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentKind {
    Direct,
    Http,
    Rest,
    GraphQl,
}

impl ComponentKind {
    /// The complete closed set, in name order.
    pub const ALL: &'static [Self] = &[Self::Direct, Self::GraphQl, Self::Http, Self::Rest];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Http => "http",
            Self::Rest => "rest",
            Self::GraphQl => "graphql",
        }
    }

    /// Resolve a component name back to its variant, or `None` outside the
    /// closed set.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.name() == name)
    }

    /// Whether a pack endpoint may declare this component. Only the two
    /// producer components name upstream endpoints; `direct` names routes
    /// and `rest` is the engine-owned facade consumer.
    #[must_use]
    pub const fn is_producer(self) -> bool {
        matches!(self, Self::Http | Self::GraphQl)
    }
}

/// An expression language a pack may require of the engine
/// (`products/adapter/CONCEPT.md` section 8.5).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Language {
    Constant,
    Header,
    ExchangeProperty,
    #[serde(rename = "jsonpath")]
    JsonPath,
    Rhai,
}

impl Language {
    /// The complete closed set, in name order.
    pub const ALL: &'static [Self] = &[
        Self::Constant,
        Self::ExchangeProperty,
        Self::Header,
        Self::JsonPath,
        Self::Rhai,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Constant => "constant",
            Self::ExchangeProperty => "exchangeProperty",
            Self::Header => "header",
            Self::JsonPath => "jsonpath",
            Self::Rhai => "rhai",
        }
    }

    /// Resolve a language name back to its variant, or `None` outside the
    /// closed set.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.name() == name)
    }
}

/// An EIP a pack may require of the engine, named after the step union in
/// `crate::route` (`products/adapter/CONCEPT.md` section 8.6).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Eip {
    Choice,
    CircuitBreaker,
    DoTry,
    Enrich,
    ErrorHandler,
    Filter,
    IdempotentConsumer,
    Loop,
    OnException,
    RemoveHeader,
    RemoveProperty,
    Script,
    SetBody,
    SetHeader,
    SetProperty,
    Split,
    Stop,
    Throttle,
    ThrowException,
    To,
    Transform,
    Validate,
}

impl Eip {
    /// The complete closed set, in name order.
    pub const ALL: &'static [Self] = &[
        Self::Choice,
        Self::CircuitBreaker,
        Self::DoTry,
        Self::Enrich,
        Self::ErrorHandler,
        Self::Filter,
        Self::IdempotentConsumer,
        Self::Loop,
        Self::OnException,
        Self::RemoveHeader,
        Self::RemoveProperty,
        Self::Script,
        Self::SetBody,
        Self::SetHeader,
        Self::SetProperty,
        Self::Split,
        Self::Stop,
        Self::Throttle,
        Self::ThrowException,
        Self::To,
        Self::Transform,
        Self::Validate,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Choice => "choice",
            Self::CircuitBreaker => "circuitBreaker",
            Self::DoTry => "doTry",
            Self::Enrich => "enrich",
            Self::ErrorHandler => "errorHandler",
            Self::Filter => "filter",
            Self::IdempotentConsumer => "idempotentConsumer",
            Self::Loop => "loop",
            Self::OnException => "onException",
            Self::RemoveHeader => "removeHeader",
            Self::RemoveProperty => "removeProperty",
            Self::Script => "script",
            Self::SetBody => "setBody",
            Self::SetHeader => "setHeader",
            Self::SetProperty => "setProperty",
            Self::Split => "split",
            Self::Stop => "stop",
            Self::Throttle => "throttle",
            Self::ThrowException => "throwException",
            Self::To => "to",
            Self::Transform => "transform",
            Self::Validate => "validate",
        }
    }

    /// Resolve an EIP name back to its variant, or `None` outside the
    /// closed set.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.name() == name)
    }
}

/// The destination of a `to` or `enrich` send: a `direct:` route, an
/// `http:` endpoint, or a `graphql:` endpoint declared in the pack
/// (`products/adapter/CONCEPT.md` sections 8.3 and 8.8). The URI is static;
/// no `toD` is ported.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SendUri {
    /// The component the URI names.
    pub component: SendComponent,
    /// The route or endpoint identifier after the prefix.
    pub id: String,
}

/// The component prefix a send URI may carry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum SendComponent {
    Direct,
    Http,
    GraphQl,
}

impl SendUri {
    /// Parse a static send URI of the form `<component>:<id>`.
    #[must_use]
    pub fn parse(uri: &str) -> Option<Self> {
        let (prefix, id) = uri.split_once(':')?;
        let component = match prefix {
            "direct" => SendComponent::Direct,
            "http" => SendComponent::Http,
            "graphql" => SendComponent::GraphQl,
            _ => return None,
        };
        if id.is_empty() {
            return None;
        }
        Some(Self {
            component,
            id: id.to_string(),
        })
    }

    /// The URI text this reference serializes to.
    #[must_use]
    pub fn uri(&self) -> String {
        let prefix = match self.component {
            SendComponent::Direct => "direct",
            SendComponent::Http => "http",
            SendComponent::GraphQl => "graphql",
        };
        format!("{prefix}:{}", self.id)
    }
}

impl Serialize for SendUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.uri())
    }
}

impl<'de> Deserialize<'de> for SendUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let uri = String::deserialize(deserializer)?;
        Self::parse(&uri).ok_or_else(|| {
            serde::de::Error::custom(registry_platform_yaml::Invalid::expected(
                "a static send URI: direct:<routeId>, http:<endpointId>, or graphql:<endpointId>",
                "Write a static `direct:`, `http:`, or `graphql:` URI; `toD` is not ported.",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_EXAMPLE: &str =
        "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9";

    #[test]
    fn envelopes_round_trip_and_refuse_outside_names() {
        for envelope in Envelope::ALL {
            assert_eq!(Envelope::from_name(envelope.name()), Some(*envelope));
            let json = serde_json::to_string(envelope).expect("serialize");
            assert_eq!(
                serde_json::from_str::<Envelope>(&json).ok(),
                Some(*envelope)
            );
        }
        assert_eq!(Envelope::from_name("soap-xml"), None);
        assert!(serde_json::from_str::<Envelope>("\"soap-xml\"").is_err());
    }

    #[test]
    fn http_methods_round_trip_and_only_get_is_safe() {
        for method in HttpMethod::ALL {
            let json = serde_json::to_string(method).expect("serialize");
            assert_eq!(
                serde_json::from_str::<HttpMethod>(&json).ok(),
                Some(*method)
            );
            assert_eq!(method.is_safe(), *method == HttpMethod::Get);
        }
        assert_eq!(
            serde_json::from_str::<HttpMethod>("\"DELETE\"").ok(),
            None,
            "DELETE is outside the closed method set"
        );
    }

    #[test]
    fn error_classes_round_trip() {
        for class in ErrorClass::ALL {
            assert_eq!(ErrorClass::from_class(class.class()), Some(*class));
            let json = serde_json::to_string(class).expect("serialize");
            assert_eq!(serde_json::from_str::<ErrorClass>(&json).ok(), Some(*class));
        }
        assert_eq!(ErrorClass::from_class("upstream.exploded"), None);
        assert!(serde_json::from_str::<ErrorClass>("\"upstream.exploded\"").is_err());
    }

    /// The generated schema enumerates the wire class strings, not the
    /// Rust variant names a `schemars` derive renders: the schema admits
    /// exactly what the reader accepts, so no authored class validates
    /// against one and fails the other (CFG-SCHEMA).
    #[cfg(feature = "schema")]
    #[test]
    fn the_error_class_schema_enumerates_the_wire_names() {
        let schema = serde_json::to_value(schemars::schema_for!(ErrorClass)).expect("schema");
        let enum_values = schema
            .get("enum")
            .or_else(|| {
                schema
                    .get("$defs")
                    .and_then(|definitions| definitions.get("ErrorClass"))
                    .and_then(|entry| entry.get("enum"))
            })
            .and_then(|values| values.as_array())
            .expect("the ErrorClass schema carries an enum");
        let names: Vec<&str> = enum_values
            .iter()
            .map(|value| value.as_str().expect("a string enum entry"))
            .collect();
        let expected: Vec<&str> = ErrorClass::ALL.iter().map(|class| class.class()).collect();
        assert_eq!(
            names, expected,
            "the schema enumerates exactly the wire class strings"
        );
        for leaked in ["Upstream", "BreakerOpen", "Outcome", "Facade"] {
            assert!(
                !names.contains(&leaked),
                "the Rust variant name {leaked} leaks into the schema"
            );
        }
    }

    #[test]
    fn uncatchable_set_is_exactly_the_boundary() {
        let uncatchable: Vec<_> = ErrorClass::ALL
            .iter()
            .copied()
            .filter(|class| class.is_uncatchable())
            .map(|class| class.class())
            .collect();
        assert_eq!(
            uncatchable,
            [
                "budget.exhausted",
                "credential.rejected",
                "disclosure.violation",
                "egress.refused",
                "script.budget-exceeded",
            ]
        );
    }

    /// The loop-bound class is catchable: a clause may name it, and no
    /// prefix of another class resolves to it (staff review P0-3).
    #[test]
    fn loop_bound_class_is_catchable() {
        let class = ErrorClass::from_class("loop.maximum-iterations-reached");
        assert_eq!(class, Some(ErrorClass::LoopMaximumIterationsReached));
        assert!(!class.unwrap().is_uncatchable());
    }

    /// The outcome branch is a pack-raisable, catchable addition
    /// (`products/adapter/CONCEPT.md` section 8.7): every outcome class
    /// resolves under the `outcome` root, is neither uncatchable nor
    /// facade, and a clause naming the root matches its leaves.
    #[test]
    fn outcome_branch_is_catchable_under_its_root() {
        for name in [
            "outcome.not-found",
            "outcome.conflict",
            "outcome.invalid-request",
            "outcome.rejected",
        ] {
            let class = ErrorClass::from_class(name).expect("an outcome class resolves");
            assert!(!class.is_uncatchable(), "{name} stays catchable");
            assert!(!class.is_facade(), "{name} is not a facade class");
            assert!(
                class.is_within(ErrorClass::Outcome),
                "{name} sits under outcome"
            );
            assert_eq!(
                ErrorClass::closest_match(&[class], &[ErrorClass::Outcome]),
                Some(ErrorClass::Outcome)
            );
        }
        let root = ErrorClass::from_class("outcome").expect("the outcome root resolves");
        assert!(!root.is_uncatchable());
        assert!(!root.is_facade());
    }

    /// The facade branch is raised by the `rest` consumer outside any
    /// route (`products/adapter/CONCEPT.md` section 8.7): every facade
    /// class resolves under the `facade` root, is facade, catchable by no
    /// clause rule, and the two media classes the profile maps to 415 and
    /// 406 resolve.
    #[test]
    fn facade_branch_is_outside_any_route() {
        for name in [
            "facade.unauthenticated",
            "facade.forbidden",
            "facade.invalid-request",
            "facade.invalid-field",
            "facade.invalid-cursor",
            "facade.payload-too-large",
            "facade.not-found",
            "facade.method-not-allowed",
            "facade.unsupported-media-type",
            "facade.not-acceptable",
            "facade.conflict",
            "facade.idempotency-mismatch",
        ] {
            let class = ErrorClass::from_class(name).expect("a facade class resolves");
            assert!(class.is_facade(), "{name} is a facade class");
            assert!(
                !class.is_uncatchable(),
                "{name} is not boundary-uncatchable"
            );
            assert!(
                class.is_within(ErrorClass::Facade),
                "{name} sits under facade"
            );
        }
        assert_eq!(
            ErrorClass::from_class("facade.unsupported-media-type"),
            Some(ErrorClass::FacadeUnsupportedMediaType)
        );
        assert_eq!(
            ErrorClass::from_class("facade.not-acceptable"),
            Some(ErrorClass::FacadeNotAcceptable)
        );
        let facade_count = ErrorClass::ALL
            .iter()
            .filter(|class| class.is_facade())
            .count();
        assert_eq!(
            facade_count, 13,
            "the facade branch carries the root and twelve leaves"
        );
    }

    /// Every multi-word class segment is kebab-case; the old camelCase
    /// spellings resolve to nothing.
    #[test]
    fn class_segments_are_kebab() {
        assert_eq!(
            ErrorClass::from_class("upstream.too-large"),
            Some(ErrorClass::UpstreamTooLarge)
        );
        assert_eq!(ErrorClass::from_class("upstream.tooLarge"), None);
        assert_eq!(
            ErrorClass::from_class("script.budget-exceeded"),
            Some(ErrorClass::ScriptBudgetExceeded)
        );
        assert_eq!(ErrorClass::from_class("script.budgetExceeded"), None);
        for class in ErrorClass::ALL {
            for segment in class.class().split('.') {
                assert!(
                    segment
                        .chars()
                        .all(|character| character.is_ascii_lowercase() || character == '-'),
                    "segment {segment} of {} is not kebab",
                    class.class()
                );
            }
        }
    }

    /// Clause matching is Camel's closest match across the error and its
    /// cause chain: a subclass clause never matches a bare superclass
    /// error, the closest match across the whole chain wins, equally
    /// close matches resolve to the most nested cause, and an uncatchable
    /// class anywhere in the chain matches no clause whatever prefix the
    /// clause names (staff review P1-10; reviewer defects M1 through M3).
    #[test]
    fn closest_match_walks_the_cause_chain_and_skips_the_boundary() {
        // The most specific declared match on a cause wins.
        assert_eq!(
            ErrorClass::closest_match(
                &[ErrorClass::UpstreamHttp],
                &[ErrorClass::UpstreamHttp, ErrorClass::Upstream],
            ),
            Some(ErrorClass::UpstreamHttp)
        );
        // A clause naming the parent matches the subclass.
        assert_eq!(
            ErrorClass::closest_match(&[ErrorClass::UpstreamTimeout], &[ErrorClass::Upstream],),
            Some(ErrorClass::Upstream)
        );
        // A clause naming a subclass never matches the bare superclass
        // error (M2).
        assert_eq!(
            ErrorClass::closest_match(&[ErrorClass::Upstream], &[ErrorClass::UpstreamHttp]),
            None
        );
        // An exact match on a nested cause beats a superclass match on the
        // outermost error: the closest match wins across the whole chain
        // (M3).
        assert_eq!(
            ErrorClass::closest_match(
                &[ErrorClass::UpstreamTimeout, ErrorClass::Validation],
                &[ErrorClass::Upstream, ErrorClass::Validation],
            ),
            Some(ErrorClass::Validation)
        );
        // Equally close matches resolve to the clause matching the most
        // nested cause, later in the chain (M3).
        assert_eq!(
            ErrorClass::closest_match(
                &[ErrorClass::UpstreamHttp, ErrorClass::Validation],
                &[ErrorClass::UpstreamHttp, ErrorClass::Validation],
            ),
            Some(ErrorClass::Validation)
        );
        // An exact match matches.
        assert_eq!(
            ErrorClass::closest_match(&[ErrorClass::Script], &[ErrorClass::Script]),
            Some(ErrorClass::Script)
        );
        // The boundary never matches, not even through its own causes: the
        // uncatchable class sits in the chain beside a catchable cause
        // (M1).
        assert_eq!(
            ErrorClass::closest_match(
                &[
                    ErrorClass::ScriptBudgetExceeded,
                    ErrorClass::UpstreamTimeout
                ],
                &[ErrorClass::Upstream],
            ),
            None
        );
        assert_eq!(
            ErrorClass::closest_match(&[ErrorClass::ScriptBudgetExceeded], &[ErrorClass::Script],),
            None
        );
        // No declared match matches nothing.
        assert_eq!(
            ErrorClass::closest_match(&[ErrorClass::UpstreamTimeout], &[ErrorClass::Validation]),
            None
        );
    }

    /// The aggregation strategies tag by `type` on the wire, the
    /// parameterless ones carry no payload, and an unknown member is
    /// refused (CFG-ID-7, CFG-SCHEMA-8, CFG-NAME-2).
    #[test]
    fn aggregation_strategies_tag_by_type_with_empty_payloads() {
        assert_eq!(
            serde_json::to_string(&AggregationStrategy::UseLatest {}).expect("serialize"),
            r#"{"type":"use-latest"}"#
        );
        let grouped: AggregationStrategy =
            serde_json::from_str(r#"{"type": "grouped-body"}"#).expect("read");
        assert!(matches!(grouped, AggregationStrategy::GroupedBody {}));
        let rhai: AggregationStrategy = serde_json::from_str(
            r#"{"type": "rhai", "expression": {"file": "s.rhai", "entrypoint": "go"}}"#,
        )
        .expect("read");
        let rhai_wire = serde_json::to_value(&rhai).expect("serialize");
        assert_eq!(rhai_wire["type"], "rhai");
        assert_eq!(rhai_wire["expression"]["file"], "s.rhai");
        assert_eq!(rhai_wire["expression"]["entrypoint"], "go");
        assert!(
            serde_json::from_str::<AggregationStrategy>(
                r#"{"type": "json-merge", "from": "a", "into": "b", "extra": 1}"#,
            )
            .is_err(),
            "an unknown member is refused"
        );
        assert!(serde_json::from_str::<AggregationStrategy>(r#"{"useLatest": {}}"#).is_err());
    }

    /// `is_within` goes down the hierarchy only: a clause naming a
    /// subclass never covers the bare superclass, and the named class
    /// itself covers (reviewer defect M2).
    #[test]
    fn within_never_rises_up_the_hierarchy() {
        assert!(ErrorClass::UpstreamTimeout.is_within(ErrorClass::Upstream));
        assert!(ErrorClass::UpstreamHttp.is_within(ErrorClass::UpstreamHttp));
        assert!(!ErrorClass::Upstream.is_within(ErrorClass::UpstreamHttp));
        assert!(!ErrorClass::UpstreamTimeout.is_within(ErrorClass::UpstreamHttp));
    }

    #[test]
    fn component_kinds_round_trip() {
        for component in ComponentKind::ALL {
            assert_eq!(ComponentKind::from_name(component.name()), Some(*component));
            let json = serde_json::to_string(component).expect("serialize");
            assert_eq!(
                serde_json::from_str::<ComponentKind>(&json).ok(),
                Some(*component)
            );
        }
        assert_eq!(
            ComponentKind::ALL
                .iter()
                .filter(|component| component.is_producer())
                .count(),
            2
        );
    }

    #[test]
    fn languages_and_eips_round_trip() {
        for language in Language::ALL {
            assert_eq!(Language::from_name(language.name()), Some(*language));
        }
        for eip in Eip::ALL {
            assert_eq!(Eip::from_name(eip.name()), Some(*eip));
        }
        assert_eq!(Language::from_name("simple"), None);
        assert_eq!(Eip::from_name("wireTap"), None);
    }

    #[test]
    fn send_uris_round_trip_over_the_three_components() {
        for uri in ["direct:fetchRecord", "http:cases", "graphql:patient"] {
            let parsed = SendUri::parse(uri).expect("parse");
            assert_eq!(parsed.uri(), uri);
            let json = serde_json::to_string(&parsed).expect("serialize");
            assert_eq!(json, format!("\"{uri}\""));
            assert_eq!(serde_json::from_str::<SendUri>(&json).ok(), Some(parsed));
        }
        assert_eq!(SendUri::parse("kafka:topic"), None);
        assert_eq!(SendUri::parse("direct:"), None);
        assert!(serde_json::from_str::<SendUri>("\"rest:facade\"").is_err());
    }

    #[test]
    fn script_references_carry_a_digest_pin() {
        let script = ScriptReference {
            path: "scripts/tracked-entity.rhai".to_string(),
            digest: Digest::new(SHA256_EXAMPLE).expect("digest"),
        };
        let json = serde_json::to_string(&script).expect("serialize");
        assert!(json.contains("\"digest\""));
        assert_eq!(
            serde_json::from_str::<ScriptReference>(&json).ok(),
            Some(script)
        );
        assert!(
            serde_json::from_str::<ScriptReference>(r#"{"path": "x.rhai"}"#).is_err(),
            "a script without its digest pin is refused"
        );
    }
}
