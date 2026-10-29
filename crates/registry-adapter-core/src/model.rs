// SPDX-License-Identifier: Apache-2.0

//! Vocabulary shared by the Adapter artifacts: envelope kinds, HTTP methods,
//! expressions, aggregation strategies, the closed error-class hierarchy,
//! component kinds, and script seams (`products/adapter/CONCEPT.md`
//! sections 8.5, 8.6, and 8.7).

use registry_platform_yaml::Digest;
use serde::{Deserialize, Serialize};

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
/// `products/adapter/CONCEPT.md` section 8.6. Externally tagged by name.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum AggregationStrategy {
    /// Keep the newest exchange: the default for `enrich`, which replaces
    /// the body with the resource reply.
    UseLatest,
    /// Keep the original exchange: the default for `split`.
    UseOriginal,
    /// Concatenate the split results into one list, Camel's `groupedBody`.
    GroupedBody,
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
    },
    /// Merge one JSON object into another. No duplicate refusal.
    JsonMerge {
        /// The object property merged into the body.
        from: String,
        /// The message body member the object lands in.
        into: String,
    },
    /// A custom strategy: a Rhai entrypoint over the old and new bodies.
    Rhai(RhaiExpression),
}

/// A closed error class, the port of Camel's Java exception hierarchy
/// (`products/adapter/CONCEPT.md` section 8.7). Clauses match the closest
/// class across the error and its cause; the five uncatchable classes name
/// the boundary no `onException` or `doCatch` may handle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

    /// Whether this class is the named clause class or one of its
    /// subclasses in the closed hierarchy: a clause naming a parent
    /// matches the classes under it, as Camel's clause matching does.
    #[must_use]
    pub fn is_within(self, clause: Self) -> bool {
        self.class()
            .split('.')
            .zip(clause.class().split('.'))
            .all(|(raised, declared)| raised == declared)
    }

    /// The class a clause fires for: the closest match across the error
    /// and its cause chain, Camel's rule
    /// (`manual/exception-clause.html`). `raised` carries the error's
    /// class followed by its causes; the first cause with a declared
    /// match wins, and the most specific declared match on it. An
    /// uncatchable class matches no clause, whatever prefix the clause
    /// names.
    #[must_use]
    pub fn closest_match(raised: &[Self], clause: &[Self]) -> Option<Self> {
        raised
            .iter()
            .copied()
            .filter(|error| !error.is_uncatchable())
            .find_map(|error| {
                clause
                    .iter()
                    .copied()
                    .filter(|declared| error.is_within(*declared))
                    .max_by_key(|declared| declared.class().split('.').count())
            })
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
    /// cause chain, and an uncatchable class matches no clause whatever
    /// prefix the clause names (staff review P1-10).
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
        // The first cause with a declared match wins over a deeper match
        // further out.
        assert_eq!(
            ErrorClass::closest_match(
                &[ErrorClass::UpstreamTimeout, ErrorClass::Validation],
                &[ErrorClass::Upstream, ErrorClass::Validation],
            ),
            Some(ErrorClass::Upstream)
        );
        // An exact match matches.
        assert_eq!(
            ErrorClass::closest_match(&[ErrorClass::Script], &[ErrorClass::Script]),
            Some(ErrorClass::Script)
        );
        // The boundary never matches: the clause names the parent and the
        // raised class sits under it.
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
