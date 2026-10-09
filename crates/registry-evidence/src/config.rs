//! Typed Evidence Version 1 deployment configuration.
//!
//! Configuration is trusted deployment data, but it is still parsed as a
//! closed contract. Secret-bearing fields contain only [`SecretReference`]
//! values; this module never resolves them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_audit::{AuditDestination, AuditDestinationError, AuditDestinationKind};
pub use registry_platform_config::SecretReference;
use registry_platform_config::{
    contains_environment_expression, AuditKeyConfig, JwksSource, ListenerBind, LoadedRuntimeConfig,
    OidcIssuerConfig, PackageConfig, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope,
    SecretProvidersConfig,
};
use registry_platform_yaml::{
    BoundedU32, BoundedU64, Document, EnvelopeRule, Expect, FormatSpec, Invalid, Reader, Refusal,
    Report, ScalarHook, ScalarSite, Severity, UniqueList,
};
use schemars::JsonSchema;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_norway::Value as YamlValue;
use thiserror::Error;
use url::{Host, Url};
use utoipa::ToSchema;

use crate::model::EVIDENCE_REQUEST_BATCH_MAX_ITEMS;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub const MAXIMUM_SOURCE_BATCH_ITEMS: u16 = 16;

/// Writes one tagged union in its documented flat form: the tag member names
/// the variant and the variant's members follow it. The derived serializer of
/// a `remote = "Self"` union produces the externally tagged form
/// `{variant: {members}}`; this helper flattens that single entry so the
/// serialized document, and every digest computed over it, is unchanged.
fn serialize_tagged<S: Serializer>(
    external: Result<serde_json::Value, serde_json::Error>,
    tag: &'static str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
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

/// Implements `Serialize` for a `remote = "Self"` union whose `Deserialize`
/// comes from `registry_platform_yaml::tagged_union!`.
macro_rules! serialize_tagged_union {
    ($type:ty, tag = $tag:literal) => {
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize_tagged(
                    <$type>::serialize(self, serde_json::value::Serializer),
                    $tag,
                    serializer,
                )
            }
        }
    };
}

/// Serialize a struct that hosts a platform shared block with the block's
/// members beside the host's own, the shape the bundle is written in.
fn serialize_with_shared_block<S: Serializer>(
    external: Result<serde_json::Value, serde_json::Error>,
    block: &'static str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let external = external.map_err(serde::ser::Error::custom)?;
    let serde_json::Value::Object(mut members) = external else {
        return Err(serde::ser::Error::custom(
            "a shared-block host serialized as a non-object",
        ));
    };
    let Some(serde_json::Value::Object(block_members)) = members.remove(block) else {
        return Err(serde::ser::Error::custom(
            "a shared-block host serialized without its block",
        ));
    };
    let mut map = serializer.serialize_map(Some(members.len() + block_members.len()))?;
    for (key, value) in block_members.iter().chain(members.iter()) {
        map.serialize_entry(key, value)?;
    }
    map.end()
}

/// Implement `Deserialize` and `Serialize` for a struct declared with
/// `#[serde(remote = "Self")]` whose `$block` field carries the shared-block
/// marker, so the reader keeps positions inside the block (CFG-SCHEMA-8) and
/// the serialized form places the block's members beside the host's.
macro_rules! shared_block_host {
    ($type:ty, block = $block:literal) => {
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                <$type>::deserialize(deserializer)
            }
        }

        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize_with_shared_block(
                    <$type>::serialize(self, serde_json::value::Serializer),
                    $block,
                    serializer,
                )
            }
        }
    };
}

/// Whether one logical request batch can use a source's optional one-call
/// optimization. Selection is complete before preparation, credential
/// resolution, or source I/O, and an optimized execution never falls back to
/// the sequential path after it starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceBatchPlan {
    Sequential,
    Optimized { source_id: String },
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ConfigError {
    /// The shared configuration reader refused the document. The report
    /// carries the reader's diagnostics unchanged (CFG-DIAG-1): each names
    /// the file, the pointer, the line and column, and the fix, and none
    /// repeats a value from the document or the environment.
    #[error("{}", render_refusal(.0))]
    Refused(Box<Report>),
    #[error("configuration YAML does not match the Evidence Version 1 schema: {0}")]
    InvalidYaml(SchemaFault),
    #[error("configuration exceeds the Evidence Version 1 size limit")]
    TooLarge,
    #[error("configuration violates the Evidence Version 1 contract: {0}")]
    Invalid(&'static str),
    /// A contract violation a validator can attribute to one closed field
    /// label. The label is the validator's own static name for the field, so
    /// the diagnostic stays value-free while naming where to look.
    #[error("configuration violates the Evidence Version 1 contract: {0} ({1})")]
    InvalidField(&'static str, &'static str),
}

impl ConfigError {
    /// The value-free diagnostic for this failure.
    ///
    /// Deployment tooling reports this instead of the error itself so that
    /// every configuration failure carries the same safe shape.
    pub fn fault(&self) -> SchemaFault {
        match self {
            Self::Refused(_) => {
                SchemaFault::because("the configuration reader refused the document")
            }
            Self::InvalidYaml(fault) => fault.clone(),
            Self::TooLarge => SchemaFault::because("document exceeds the Version 1 size limit"),
            Self::Invalid(cause) => SchemaFault::because(cause),
            Self::InvalidField(cause, field) => SchemaFault::because_in_field(cause, field),
        }
    }
}

impl ConfigError {
    /// The reader's diagnostics, when the shared configuration reader refused
    /// the document.
    pub fn report(&self) -> Option<&Report> {
        match self {
            Self::Refused(report) => Some(report),
            _ => None,
        }
    }

    /// The same refusal with every diagnostic naming `file`, the path the
    /// document was read from as the command was given it (CFG-DIAG-1).
    #[must_use]
    pub fn in_file(self, file: &str) -> Self {
        match self {
            Self::Refused(report) => Self::Refused(Box::new(report_in_file(*report, file))),
            other => other,
        }
    }
}

/// Every diagnostic in the human form (CFG-DIAG-2), ending in the summary
/// line and without a trailing newline.
pub(crate) fn render_refusal(report: &Report) -> String {
    let mut rendered = report.render_human();
    rendered.truncate(rendered.trim_end().len());
    rendered
}

/// The report with every diagnostic's file, and every related location's
/// file, renamed to `file`. A document read from bytes carries the name it
/// was read under; the command knows the path it was given.
pub(crate) fn report_in_file(report: Report, file: &str) -> Report {
    let files_checked = report.files_checked();
    let diagnostics = report
        .into_diagnostics()
        .into_iter()
        .map(|mut diagnostic| {
            if let Some(source) = diagnostic.source.as_mut() {
                source.file = file.to_owned();
            }
            for related in &mut diagnostic.related {
                related.file = file.to_owned();
            }
            diagnostic
        })
        .collect();
    let mut renamed = Report::new(diagnostics);
    if let Some(files) = files_checked {
        renamed.set_files_checked(files);
    }
    renamed
}

/// A one-based text position inside a deployment artifact.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TextLocation {
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for TextLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {} column {}", self.line, self.column)
    }
}

/// A value-free reason one deployment document was rejected.
///
/// Only three things are kept: a schema path built from mapping keys and
/// sequence indices, a text location, and one static cause. The decoder's own
/// message is classified and then discarded, because it quotes scalars, and a
/// deployment scalar can be a selector value, a secret reference, or a source
/// identifier. The optional field label is the static name a validator holds
/// for the field it bound, which is structure, not content.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SchemaFault {
    location: Option<CompactLocation>,
    path: Option<Box<str>>,
    cause: &'static str,
    field: Option<&'static str>,
    remedy: Option<&'static str>,
}

/// A text position held in 32-bit fields, keeping `SchemaFault` small enough
/// to travel inside every error that wraps it. A configuration document is
/// bounded far below `u32::MAX` lines or columns; a larger value saturates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompactLocation {
    line: u32,
    column: u32,
}

impl From<TextLocation> for CompactLocation {
    fn from(location: TextLocation) -> Self {
        Self {
            line: u32::try_from(location.line).unwrap_or(u32::MAX),
            column: u32::try_from(location.column).unwrap_or(u32::MAX),
        }
    }
}

impl From<CompactLocation> for TextLocation {
    fn from(location: CompactLocation) -> Self {
        Self {
            line: location.line as usize,
            column: location.column as usize,
        }
    }
}

impl SchemaFault {
    /// A fault that names only its cause.
    pub fn because(cause: &'static str) -> Self {
        Self {
            location: None,
            path: None,
            cause,
            field: None,
            remedy: None,
        }
    }

    /// A fault that also names the closed field label its cause applies to.
    ///
    /// The label is the static name a validator holds for the collection or
    /// value it bound (for example `publication jurisdictions`), so the fault
    /// stays value-free while telling an operator which field refused.
    pub fn because_in_field(cause: &'static str, field: &'static str) -> Self {
        Self {
            field: Some(field),
            ..Self::because(cause)
        }
    }

    /// The same fault, pointing at a position inside the artifact it came from.
    ///
    /// A line and a column are structure, so they are safe to keep. The text
    /// standing at that position is content, and this type never sees it.
    pub fn at(mut self, location: TextLocation) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn cause(&self) -> &'static str {
        self.cause
    }

    /// The closed field label this fault applies to, when the refusing
    /// validator named one.
    pub fn field(&self) -> Option<&'static str> {
        self.field
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn location(&self) -> Option<TextLocation> {
        self.location.map(TextLocation::from)
    }

    /// The fixed sentence telling an operator what to write instead, when the
    /// refusal has one.
    pub fn remedy(&self) -> Option<&'static str> {
        self.remedy
    }
}

impl fmt::Display for SchemaFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.cause)?;
        if let Some(field) = self.field {
            write!(formatter, " ({field})")?;
        }
        if let Some(path) = &self.path {
            write!(formatter, " at {path}")?;
        }
        if let Some(location) = self.location {
            write!(formatter, " ({})", TextLocation::from(location))?;
        }
        if let Some(remedy) = self.remedy {
            write!(formatter, "; {remedy}")?;
        }
        Ok(())
    }
}

/// The kind the reader names an Evidence bundle by in its diagnostics.
pub const EVIDENCE_BUNDLE_KIND: &str = "EvidenceBundle";

/// The name the reader gives a bundle read from bytes. The command that read
/// the file renames it to the path it was given.
const BUNDLE_DOCUMENT_NAME: &str = "evidence.yaml";

/// The Evidence bundle format. The frozen Version 1 grammar declares
/// `version: 1` and neither `apiVersion` nor `kind`; the envelope arrives
/// with the move to the stable format line.
pub const EVIDENCE_BUNDLE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: EVIDENCE_BUNDLE_KIND,
    envelope: EnvelopeRule::Exempt {
        reason: "the frozen Version 1 bundle grammar declares version: 1 and no apiVersion or kind",
    },
    removed_keys: EVIDENCE_BUNDLE_REMOVED_KEYS,
};

/// Bundle keys an earlier grammar accepted, each refused with the key that
/// replaced it. The access-token rules moved under `authentication.oidc`.
pub const EVIDENCE_BUNDLE_REMOVED_KEYS: &[registry_platform_yaml::RemovedKey<'static>] = &[
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/kind",
        replacement:
            "Evidence accepts OIDC access tokens only; declare the rules under authentication.oidc.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/issuer",
        replacement: "Declare authentication.oidc.issuer instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/audiences",
        replacement: "Declare the one accepted audience as authentication.oidc.audience.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/jwksUri",
        replacement: "Declare authentication.oidc.jwksSource with kind: uri and uri: <JWKS URL>.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/tokenTypes",
        replacement: "Declare authentication.oidc.tokenTypes instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/algorithms",
        replacement: "Declare authentication.oidc.algorithms instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/principalClaim",
        replacement: "Declare authentication.oidc.principalClaim instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/requesterTagsClaim",
        replacement: "Declare authentication.oidc.requesterTagsClaim instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/evidenceAudienceClaim",
        replacement: "Declare authentication.oidc.evidenceAudienceClaim instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/claims",
        replacement: "Declare authentication.oidc.claims instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/maximumTokenLifetimeSeconds",
        replacement: "Declare authentication.oidc.maximumTokenLifetimeSeconds instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/revokedKeyIds",
        replacement: "Declare authentication.oidc.revokedKeyIds instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/allowedClients",
        replacement: "Declare authentication.oidc.allowedClients instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/assertionIssuers",
        replacement: "Declare authentication.oidc.assertionIssuers instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/requiredScopes",
        replacement: "Declare authentication.oidc.requiredScopes instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/actorClaim",
        replacement: "Declare authentication.oidc.actorClaim instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/tlsTrustProfile",
        replacement: "Declare authentication.oidc.tlsTrustProfile instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/oidc/kind",
        replacement: "Evidence accepts OIDC access tokens only; remove kind.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/oidc/audiences",
        replacement: "Declare the one accepted audience as authentication.oidc.audience.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/oidc/jwksUri",
        replacement: "Declare authentication.oidc.jwksSource with kind: uri and uri: <JWKS URL>.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/audit/hashSecretRef",
        replacement: "Declare audit.hashKeyRef instead.",
    },
];

/// The code a bundle rule's refusal carries (CFG-DIAG-3), one per top-level
/// block of the bundle.
fn bundle_rule_code(pointer: &str) -> &'static str {
    match pointer.split('/').nth(1).unwrap_or_default() {
        "service" => "evidence.bundle.invalid-service",
        "issuer" => "evidence.bundle.invalid-issuer",
        "publication" => "evidence.bundle.invalid-publication",
        "authentication" => "evidence.bundle.invalid-authentication",
        "subjectBinding" => "evidence.bundle.invalid-subject-binding",
        "signing" => "evidence.bundle.invalid-signing",
        "responseFormats" => "evidence.bundle.invalid-response-formats",
        "selectorProfiles" => "evidence.bundle.invalid-selector-profile",
        "sources" => "evidence.bundle.invalid-source",
        "sourceConnections" => "evidence.bundle.invalid-source-connection",
        "authorityProfiles" => "evidence.bundle.invalid-authority-profile",
        "acquisitionCapabilities" => "evidence.bundle.invalid-acquisition-capabilities",
        "requirements" => "evidence.bundle.invalid-requirement",
        _ => "evidence.bundle.invalid-configuration",
    }
}

/// The action a bundle rule's refusal names when the rule carries none of
/// its own.
const BUNDLE_RULE_ACTION: &str = "Change this member so it meets the rule the message states.";

impl Violation {
    /// The violation as a diagnostic placed in `document`. A member the rule
    /// concerns that is not written, such as a missing optional block, is
    /// placed at the nearest member that is.
    fn diagnostic(&self, document: &Document) -> registry_platform_yaml::Diagnostic {
        let fault = self.error.fault();
        let message = match fault.field() {
            Some(field) => format!("{} ({field})", fault.cause()),
            None => fault.cause().to_owned(),
        };
        let action = fault.remedy().unwrap_or(BUNDLE_RULE_ACTION);
        let code = bundle_rule_code(&self.pointer);
        let mut written = self.pointer.as_str();
        while document.span_of(written).is_none() {
            written = written.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
        let mut diagnostic = if self.at_key && written == self.pointer {
            document.diagnostic_at_key(Severity::Error, code, written, &message, action)
        } else {
            document.diagnostic_at_value(Severity::Error, code, written, &message, action)
        };
        diagnostic.path.clone_from(&self.pointer);
        diagnostic
    }
}

/// Refuses a `${...}` expression in a bundle key or text value.
///
/// Substitution applies to `runtime.yaml` only, so the reviewed bundle is the
/// one that runs. There is no escape for a literal `${NAME}` in the bundle.
pub(crate) struct BundleExpressions;

impl BundleExpressions {
    fn check(text: &str) -> Result<(), Refusal> {
        if contains_environment_expression(text) {
            return Err(Refusal {
                code: "config.substitution-not-allowed".to_owned(),
                message: "a `${...}` expression is written in the governed bundle; \
                          substitution applies to runtime.yaml only"
                    .to_owned(),
                suggested_action: "Write the value in the bundle directly.".to_owned(),
            });
        }
        Ok(())
    }
}

impl ScalarHook for BundleExpressions {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        Self::check(site.text)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Self::check(site.text).map(|()| None)
    }
}

/// A mapping that rejects duplicate keys and preserves declaration order.
///
/// Selector declaration order is part of canonical selector encoding, so a
/// sorted map is not sufficient for this contract.
#[derive(Clone, Eq, PartialEq)]
pub struct OrderedMap<T>(Vec<(String, T)>);

impl<T> Default for OrderedMap<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> OrderedMap<T> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        self.0
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &T)> {
        self.0.iter().map(|(key, value)| (key.as_str(), value))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(key, _)| key.as_str())
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut().map(|(_, value)| value)
    }

    /// Set `key` to `value`, in place when the key is present and appended
    /// when it is not, so each key stays named once.
    pub fn insert(&mut self, key: String, value: T) {
        match self.0.iter_mut().find(|(candidate, _)| *candidate == key) {
            Some((_, slot)) => *slot = value,
            None => self.0.push((key, value)),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for OrderedMap<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_map()
            .entries(self.0.iter().map(|(key, value)| (key, value)))
            .finish()
    }
}

impl<'de, T> Deserialize<'de> for OrderedMap<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OrderedMapVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> Visitor<'de> for OrderedMapVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = OrderedMap<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a mapping with unique string keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
                let mut seen = BTreeSet::new();
                while let Some((key, value)) = map.next_entry::<String, T>()? {
                    if !seen.insert(key.clone()) {
                        return Err(Invalid::expected(
                            "a mapping that names each key once",
                            "Remove the repeated key.",
                        )
                        .into_error());
                    }
                    entries.push((key, value));
                }
                Ok(OrderedMap(entries))
            }
        }

        deserializer.deserialize_map(OrderedMapVisitor(std::marker::PhantomData))
    }
}

impl<T: Serialize> Serialize for OrderedMap<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceConfig {
    pub version: BoundedU32<1, 1>,
    /// The governed assurance boundary for this immutable bundle.
    pub assurance_profile: AssuranceProfile,
    pub service: ServiceConfig,
    pub issuer: IssuerConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication: Option<PublicationConfig>,
    pub authentication: AuthenticationConfig,
    pub audit: AuditConfig,
    pub subject_binding: SubjectBindingConfig,
    pub rate_limits: RateLimitConfig,
    pub signing: SigningConfig,
    /// Closed enabled response formats for the whole immutable bundle. Signed
    /// flattened JWS is mandatory and the default; unsigned JSON must be
    /// enabled here and permitted by the complete matched grant.
    #[serde(default = "default_response_formats")]
    pub response_formats: Vec<ResponseFormat>,
    pub selector_profiles: OrderedMap<SelectorProfile>,
    pub sources: OrderedMap<SourceConfig>,
    /// Optional explicit resource owners, resolved into concrete source plans
    /// by the authoring build and checked again when the bundle starts.
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub source_connections: OrderedMap<SourceConnectionConfig>,
    pub authority_profiles: OrderedMap<AuthorityProfile>,
    /// Acquisition kinds this bundle opts in to beyond the single fixed call.
    /// A kind absent from this list cannot be served, so an existing bundle
    /// keeps serving exactly what it served before. The list is omitted when
    /// empty because the projected configuration is what a requirement's
    /// `configurationRevision` digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acquisition_capabilities: Vec<String>,
    /// Ceiling on how many assertions one holder-bound release may carry.
    /// Omission means one, so a bundle written before batch release cannot
    /// serve a batch, and the key is omitted when absent because the projected
    /// configuration is what a requirement's `configurationRevision` digests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_bound_batch_max_size:
        Option<BoundedU32<1, { MAXIMUM_HOLDER_BOUND_BATCH_SIZE as u32 }>>,
    pub requirements: Vec<RequirementConfig>,
}

pub use registry_evidence_verifier::model::SubjectBindingMode;
/// The declared assurance boundary travels with every response, so the
/// portable `registry-evidence-verifier` crate owns it and configuration serves
/// it at the runtime's own path.
pub use registry_evidence_verifier::AssuranceProfile;

pub type SourceSelectorSet = Vec<(String, String)>;

/// The ceiling one holder-bound release may carry when the bundle declares no
/// other, which is one assertion. Silence enables nothing.
const DEFAULT_HOLDER_BOUND_BATCH_SIZE: u16 = 1;

/// The compile-time ceiling on a declared holder-bound batch size. It bounds
/// the released set an audit record has to name, so the two limits move
/// together.
pub const MAXIMUM_HOLDER_BOUND_BATCH_SIZE: u16 = 16;

/// The serializations a holder-bound assertion may take.
///
/// A holder-bound assertion names no relying party, so it can only travel in a
/// serialization that carries the holder key confirmation the verifier checks
/// possession against. The signed flattened JWS and unsigned JSON forms carry
/// no such confirmation, so neither may transport one.
const HOLDER_BOUND_RESPONSE_FORMATS: [ResponseFormat; 2] =
    [ResponseFormat::SdJwtVc, ResponseFormat::SdJwtVcBatch];

/// The serializations an audience-scoped assertion may take.
///
/// The three formats an audience-scoped requirement served before batch
/// issuance existed, and no more. The batch container carries exactly one
/// member per presented holder key, and an audience-scoped assertion binds the
/// authenticated audience rather than a key, so there is nothing for its
/// members to differ by.
const AUDIENCE_SCOPED_RESPONSE_FORMATS: [ResponseFormat; 3] = [
    ResponseFormat::SignedJws,
    ResponseFormat::UnsignedJson,
    ResponseFormat::SdJwtVc,
];

/// Report whether a binding mode allows one response format at all.
///
/// This is the third term of the effective format set, alongside the bundle
/// half and the one matched grant's half. It restricts a single requirement,
/// never a bundle or a grant, so a deployment that serves one holder-bound
/// requirement keeps serving every other requirement over the formats it
/// already served.
pub fn subject_binding_permits_response_format(
    mode: SubjectBindingMode,
    format: ResponseFormat,
) -> bool {
    match mode {
        SubjectBindingMode::AudienceScoped => AUDIENCE_SCOPED_RESPONSE_FORMATS.contains(&format),
        SubjectBindingMode::HolderBound => HOLDER_BOUND_RESPONSE_FORMATS.contains(&format),
    }
}

/// A burst smaller than the largest request cost the bundle admits.
///
/// A principal's bucket never holds more than the burst, so a request that
/// costs more is refused however long its caller waits. That can be deliberate,
/// a way to cap how much one principal asks for at once, so it is reported as
/// a warning rather than refused. It names which ceiling sets the cost, never
/// a configured value.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BurstShortfall {
    /// The request-batch route's item ceiling, a product constant, sets the
    /// cost.
    RequestBatch,
    /// The declared `holderBoundBatchMaxSize` sets the cost.
    HolderBoundBatch,
}

impl EvidenceConfig {
    /// The declared holder-bound batch ceiling, or one when none is declared.
    pub fn holder_bound_batch_ceiling(&self) -> u16 {
        self.holder_bound_batch_max_size
            .map_or(DEFAULT_HOLDER_BOUND_BATCH_SIZE, |size| {
                u16::try_from(size.get()).unwrap_or(MAXIMUM_HOLDER_BOUND_BATCH_SIZE)
            })
    }

    /// The largest request-rate cost a request this bundle can serve charges.
    ///
    /// A request batch costs one token per item and is served for every
    /// audience-scoped requirement up to the route's item ceiling. A source's
    /// own `batch.maximumItems` does not bound it: items above that ceiling run
    /// sequentially rather than being refused. A holder-bound release costs one
    /// token per holder key, and more than one key is served only when the
    /// bundle both enables the batch container and declares a holder-bound
    /// requirement, up to the declared ceiling. Every other request costs one.
    pub fn largest_request_cost(&self) -> u16 {
        let (request_batch, holder_bound_release) = self.request_costs();
        request_batch.max(holder_bound_release).max(1)
    }

    /// The largest request-batch cost and the largest holder-bound release
    /// cost, as [`Self::largest_request_cost`] describes them.
    fn request_costs(&self) -> (u16, u16) {
        let request_batch = if self.requirements.iter().any(|requirement| {
            requirement.subject_binding_mode() == SubjectBindingMode::AudienceScoped
        }) {
            u16::try_from(EVIDENCE_REQUEST_BATCH_MAX_ITEMS).unwrap_or(u16::MAX)
        } else {
            1
        };
        let holder_bound_release = if self
            .response_formats
            .contains(&ResponseFormat::SdJwtVcBatch)
            && self.requirements.iter().any(|requirement| {
                requirement.subject_binding_mode() == SubjectBindingMode::HolderBound
            }) {
            self.holder_bound_batch_ceiling()
        } else {
            1
        };
        (request_batch, holder_bound_release)
    }

    /// The ceiling that sets the largest request cost when the configured
    /// burst cannot hold it, so some requests could never be admitted.
    pub fn burst_shortfall(&self) -> Option<BurstShortfall> {
        let (request_batch, holder_bound_release) = self.request_costs();
        let bound = if holder_bound_release > request_batch {
            BurstShortfall::HolderBoundBatch
        } else {
            BurstShortfall::RequestBatch
        };
        (self.rate_limits.burst_per_principal.get() < u32::from(self.largest_request_cost()))
            .then_some(bound)
    }

    pub fn requirement_acquisition_posture(
        &self,
        requirement_id: &str,
    ) -> Option<AcquisitionPosture> {
        let requirement = self
            .requirements
            .iter()
            .find(|requirement| requirement.id == requirement_id)?;
        requirement
            .acquisition
            .source_ids()
            .into_iter()
            .filter_map(|source_id| self.sources.get(source_id).map(SourceConfig::posture))
            .reduce(AcquisitionPosture::weakest)
    }

    /// [`Self::parse_yaml`], with a bundle rule's refusal returned as the
    /// rule's own error after checking that the reader placed it.
    #[cfg(test)]
    pub(crate) fn parse_yaml_reporting_rule(bytes: &[u8]) -> Result<Self, ConfigError> {
        match Self::parse_yaml(bytes) {
            Err(ConfigError::Refused(report))
                if report.diagnostics().first().is_some_and(|diagnostic| {
                    diagnostic.code.starts_with("evidence.bundle.invalid-")
                }) =>
            {
                let diagnostic = &report.diagnostics()[0];
                assert!(
                    diagnostic
                        .source
                        .as_ref()
                        .is_some_and(|source| source.line.is_some()),
                    "a bundle rule's refusal is placed in the document"
                );
                Err(Self::decode_without_rules(bytes)
                    .check_rules()
                    .expect_err("a bundle rule refused the document")
                    .error)
            }
            other => other,
        }
    }

    /// A bundle the closed schema accepts, decoded without its rules, for
    /// tests that build a configuration no deployment could load.
    #[cfg(test)]
    pub(crate) fn decode_without_rules(bytes: &[u8]) -> Self {
        Reader::new(BUNDLE_DOCUMENT_NAME)
            .decode::<Self>(bytes, &Expect::one(&EVIDENCE_BUNDLE_FORMAT))
            .expect("the schema accepted the document")
            .value
    }

    /// Read one bundle through the shared reader and check its rules. Every
    /// refusal is a [`ConfigError::Refused`] report whose diagnostics name
    /// the member, its line and column, and the fix (CFG-DIAG-1).
    pub fn parse_yaml(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let mut hook = BundleExpressions;
        let decoded = Reader::new(BUNDLE_DOCUMENT_NAME)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&EVIDENCE_BUNDLE_FORMAT))
            .map_err(|report| ConfigError::Refused(Box::new(report)))?;
        if let Err(violation) = decoded.value.check_rules() {
            return Err(ConfigError::Refused(Box::new(Report::new(vec![
                violation.diagnostic(&decoded.document)
            ]))));
        }
        Ok(decoded.value)
    }

    /// Refuse the bundle with the first rule it breaks, as startup does.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.check_rules().map_err(|violation| violation.error)
    }

    /// The first rule this decoded bundle breaks, with the member it
    /// concerns, in the order startup checks them.
    pub(crate) fn check_rules(&self) -> Result<(), Violation> {
        validate_uri(&self.service.provider_id).at("/service/providerId")?;
        validate_uri(&self.service.trust_domain).at("/service/trustDomain")?;
        validate_public_origin(&self.service.public_origin, self.assurance_profile)
            .at("/service/publicOrigin")?;
        validate_uri(&self.issuer.id).at("/issuer/id")?;
        if let Some(publication) = &self.publication {
            publication
                .validate(self.assurance_profile)
                .at("/publication")?;
        }
        self.authentication
            .validate(self.assurance_profile)
            .at("/authentication/oidc")?;
        if self.audit.key.hash_key_ref == self.subject_binding.secret_ref {
            return invalid("audit and subject-binding secret references must be distinct")
                .at("/subjectBinding/secretRef");
        }
        self.signing.validate().at("/signing")?;
        validate_response_formats(&self.response_formats, "bundle response formats")
            .at("/responseFormats")?;
        // Both SD-JWT VC serializations name their issuer by origin, the batch
        // container as much as the singular form it batches, so either one
        // enabled outside the local assurance profile forces the origin.
        if self.assurance_profile != AssuranceProfile::Local
            && self
                .response_formats
                .iter()
                .any(|format| HOLDER_BOUND_RESPONSE_FORMATS.contains(format))
        {
            validate_https_origin(&self.service.provider_id).at("/service/providerId")?;
        }
        validate_named_map(
            &self.selector_profiles,
            1,
            128,
            "/selectorProfiles",
            |profile| profile.validate(),
        )?;
        validate_named_map(&self.sources, 1, 128, "/sources", |source| {
            source.validate(self.assurance_profile)
        })?;
        validate_named_map(
            &self.source_connections,
            0,
            128,
            "/sourceConnections",
            |connection| connection.validate(self.assurance_profile),
        )?;
        for (source_id, source) in self.sources.iter() {
            if let Some(connection_id) = source.connection() {
                let at = format!("{}/connection", named("/sources", source_id));
                let connection = self
                    .source_connections
                    .get(connection_id)
                    .ok_or(ConfigError::Invalid(
                        "source connection reference is not declared",
                    ))
                    .at(&at)?;
                if !connection.matches_source(source) {
                    return invalid("resolved source differs from its named connection").at(at);
                }
            }
        }
        validate_named_map(
            &self.authority_profiles,
            1,
            128,
            "/authorityProfiles",
            |profile| profile.validate(),
        )?;
        let task_grant_profiles = self
            .authority_profiles
            .iter()
            .filter(|(_, profile)| !profile.requester_clients.is_empty())
            .collect::<Vec<_>>();
        if !task_grant_profiles.is_empty() {
            let allowed_clients = self
                .authentication
                .oidc
                .allowed_clients
                .as_ref()
                .ok_or(ConfigError::Invalid(
                    "task-grant authority profiles require authentication allowedClients",
                ))
                .at("/authentication/oidc/allowedClients")?;
            if let Some((profile_id, _)) = task_grant_profiles.iter().find(|(_, profile)| {
                profile
                    .requester_clients
                    .iter()
                    .any(|client| !allowed_clients.contains(client))
            }) {
                return invalid(
                    "task-grant requester clients must be admitted by authentication allowedClients",
                )
                .at(format!(
                    "{}/requesterClients",
                    named("/authorityProfiles", profile_id)
                ));
            }
        }
        validate_len(self.requirements.len(), 1, 128, "requirements").at("/requirements")?;

        let mut requirement_ids = BTreeSet::new();
        let mut requirement_handles = BTreeSet::new();
        let mut evidence_types = BTreeSet::new();
        let mut concept_ids = BTreeSet::new();
        let mut disclosure_families = BTreeSet::new();
        // One artifact carries one schema role for the whole bundle: reviewing
        // it as a response contract must not silently also accept it as a fact
        // or adapter-parameter contract somewhere else.
        let response_schemas = self
            .sources
            .iter()
            .flat_map(|(_, source)| {
                std::iter::once(source.response_schema().as_str())
                    .chain(source.batch().map(|batch| batch.response_schema.as_str()))
            })
            .collect::<BTreeSet<_>>();
        let fact_schemas = self
            .sources
            .iter()
            .map(|(_, source)| source.fact_schema().as_str())
            .collect::<BTreeSet<_>>();
        let parameter_schemas = self
            .sources
            .iter()
            .filter_map(|(_, source)| source.adapter_parameters_schema().map(ArtifactPath::as_str))
            .collect::<BTreeSet<_>>();
        if !fact_schemas.is_disjoint(&parameter_schemas)
            || !response_schemas.is_disjoint(&fact_schemas)
            || !response_schemas.is_disjoint(&parameter_schemas)
        {
            return invalid("source schema roles must not overlap across sources").at("/sources");
        }
        for (index, requirement) in self.requirements.iter().enumerate() {
            let at = format!("/requirements/{index}");
            requirement.validate().at(&at)?;
            if self.assurance_profile.requires_fixtures() && requirement.fixtures.is_none() {
                return invalid("production and evidence-grade requirements must declare fixtures")
                    .at(at);
            }
            if !requirement_ids.insert(requirement.id.as_str()) {
                return invalid("requirement identifiers must be unique").at(format!("{at}/id"));
            }
            if !requirement_handles.insert(requirement.handle.as_str()) {
                return invalid("requirement handles must be unique").at(format!("{at}/handle"));
            }
            if !evidence_types.insert(requirement.evidence_type.as_str()) {
                return invalid("Evidence Type identifiers must be unique")
                    .at(format!("{at}/evidenceType"));
            }
            for (concept_index, concept) in requirement.concepts.iter().enumerate() {
                if !concept_ids.insert(concept.id.as_str()) {
                    return invalid("concept identifiers must be unique")
                        .at(format!("{at}/concepts/{concept_index}/id"));
                }
            }
            for (family_index, family) in requirement.disclosure_guard.families.iter().enumerate() {
                if !disclosure_families.insert(family.as_str()) {
                    return invalid("enabled requirements share a disclosure family")
                        .at(format!("{at}/disclosureGuard/families/{family_index}"));
                }
            }
        }

        self.validate_acquisition_capabilities()?;
        self.validate_holder_bound_requirements()?;
        self.validate_cross_references()?;
        if self.publication.is_some() && crate::discovery::render(self).is_err() {
            return invalid("provider publication cannot be rendered").at("/publication");
        }
        Ok(())
    }

    /// Refuse a holder-bound requirement no request could ever reach, and one
    /// whose disclosure would defeat the mode.
    ///
    /// Both refusals happen while the bundle is loading, before the listener
    /// binds, so a deployment either serves every holder-bound requirement it
    /// declares or does not start. Each cause names the rule and no configured
    /// value.
    fn validate_holder_bound_requirements(&self) -> Result<(), Violation> {
        for (index, requirement) in self.requirements.iter().enumerate() {
            if requirement.subject_binding_mode() != SubjectBindingMode::HolderBound {
                continue;
            }
            let at = format!("/requirements/{index}");
            // An entity reference is a pointer only the one relying party it was
            // scoped to can resolve. A holder-bound assertion has no such party,
            // so a value form that emits one cannot be disclosed under this mode.
            if requirement.concepts.iter().any(|concept| {
                matches!(
                    concept.form,
                    ConceptForm::AudienceScopedEntityReference | ConceptForm::EntityReferenceList
                )
            }) {
                return invalid(
                    "holder-bound requirement must not disclose an entity-reference value form",
                )
                .at(format!("{at}/concepts"));
            }
            let bundle_permits = self.response_formats.iter().any(|format| {
                subject_binding_permits_response_format(SubjectBindingMode::HolderBound, *format)
            });
            if !bundle_permits {
                return invalid(
                    "holder-bound requirement needs a bundle response format its mode permits",
                )
                .at(at);
            }
            // Both permission halves, on the one grant that would have to carry
            // the request. Permissions are never unioned across grants, so a
            // grant permitting the mode and another permitting the format leave
            // the requirement unreachable.
            let reachable = self
                .authority_profiles
                .iter()
                .flat_map(|(_, authority)| &authority.grants)
                .filter(|grant| grant.requirement == requirement.id)
                .any(|grant| {
                    grant.permits_subject_binding(SubjectBindingMode::HolderBound)
                        && grant.response_formats.iter().any(|format| {
                            self.response_formats.contains(format)
                                && subject_binding_permits_response_format(
                                    SubjectBindingMode::HolderBound,
                                    *format,
                                )
                        })
                });
            if !reachable {
                return invalid(
                    "holder-bound requirement needs one grant permitting the mode and a permitted response format",
                )
                .at(at);
            }
        }
        Ok(())
    }

    /// A bundle serves the fetch-set acquisition only where it declared it, so
    /// adding the form to the runtime cannot widen what an already-deployed
    /// bundle does. The forms that predate the declaration keep serving
    /// without one.
    fn validate_acquisition_capabilities(&self) -> Result<(), Violation> {
        let declared = declared_acquisition_capabilities(
            &self.acquisition_capabilities,
            "bundle acquisition capabilities name an unknown acquisition kind",
            "bundle acquisition capabilities must be unique",
            "bundle acquisition capabilities",
        )
        .at("/acquisitionCapabilities")?;
        if let Some((source_id, _)) = self
            .sources
            .iter()
            .find(|(_, source)| source.batch().is_some())
        {
            if !declared.contains(SOURCE_BATCH_CAPABILITY) {
                return invalid("source batch optimization is not a declared bundle capability")
                    .at(format!("{}/batch", named("/sources", source_id)));
            }
        }
        for (index, requirement) in self.requirements.iter().enumerate() {
            if requirement
                .acquisition
                .required_capability()
                .is_some_and(|capability| !declared.contains(capability))
            {
                return invalid("requirement acquisition kind is not a declared bundle capability")
                    .at(format!("/requirements/{index}/acquisition"));
            }
        }
        Ok(())
    }

    /// Return the complete selector tuple sets that an authorized request may
    /// activate for one source. The configuration has already proven that
    /// every grant is complete and references the named requirement source.
    pub fn source_selector_sets(&self, source_id: &str) -> Vec<SourceSelectorSet> {
        let Some(source) = self.sources.get(source_id) else {
            return Vec::new();
        };
        let requirement_sources = self
            .requirements
            .iter()
            .filter(|requirement| requirement.acquisition.uses_source(source_id))
            .map(|requirement| requirement.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut sets = BTreeSet::new();
        for (_, authority) in self.authority_profiles.iter() {
            for grant in &authority.grants {
                if !requirement_sources.contains(grant.requirement.as_str()) {
                    continue;
                }
                let mut set = grant
                    .subjects
                    .iter()
                    .filter(|subject| {
                        source.selector_inputs().iter().any(|input| {
                            input.role == subject.role
                                && input.alternatives.iter().any(|alternative| {
                                    alternative.profile == subject.selector_profile
                                })
                        })
                    })
                    .map(|subject| (subject.role.clone(), subject.selector_profile.clone()))
                    .collect::<SourceSelectorSet>();
                if set.is_empty() && !source.selector_inputs().is_empty() {
                    continue;
                }
                set.sort();
                sets.insert(set);
            }
        }
        sets.into_iter().collect()
    }

    /// Select the optional one-call source optimization for a logical request
    /// batch, or the ordinary sequential strategy.
    ///
    /// The optimized lane is deliberately narrower than ordinary source
    /// execution: both governed documents opt in, the requirement is a
    /// `single` acquisition, the source is HTTP with a fixed path and a batch
    /// block, and the complete item set fits that block's ceiling. Every other
    /// case is decided as sequential without touching credentials or a source.
    pub fn source_batch_plan(
        &self,
        runtime: &RuntimeConfig,
        requirement_id: &str,
        item_count: usize,
    ) -> SourceBatchPlan {
        if item_count == 0
            || !self
                .acquisition_capabilities
                .iter()
                .any(|capability| capability == SOURCE_BATCH_CAPABILITY)
            || !runtime.enables_acquisition_capability(SOURCE_BATCH_CAPABILITY)
        {
            return SourceBatchPlan::Sequential;
        }
        let Some(requirement) = self
            .requirements
            .iter()
            .find(|requirement| requirement.id == requirement_id)
        else {
            return SourceBatchPlan::Sequential;
        };
        let AcquisitionConfig::Single { source } = &requirement.acquisition else {
            return SourceBatchPlan::Sequential;
        };
        let Some(SourceConfig::HttpJson { request, batch, .. }) = self.sources.get(source) else {
            return SourceBatchPlan::Sequential;
        };
        let Some(batch) = batch else {
            return SourceBatchPlan::Sequential;
        };
        if request.path.is_none()
            || request.path_template.is_some()
            || u64::try_from(item_count)
                .map_or(true, |count| count > u64::from(batch.maximum_items.get()))
        {
            return SourceBatchPlan::Sequential;
        }
        SourceBatchPlan::Optimized {
            source_id: source.clone(),
        }
    }

    fn validate_cross_references(&self) -> Result<(), Violation> {
        for (source_id, source) in self.sources.iter() {
            let at = named("/sources", source_id);
            for input in source.selector_inputs() {
                for alternative in &input.alternatives {
                    let profile = self
                        .selector_profiles
                        .get(&alternative.profile)
                        .ok_or(ConfigError::Invalid(
                            "source selector input references an unknown selector profile",
                        ))
                        .at(&at)?;
                    if alternative
                        .fields
                        .iter()
                        .any(|field| !profile.fields.contains_key(field))
                    {
                        return invalid(
                            "source selector input references an unknown selector field",
                        )
                        .at(at);
                    }
                }
            }
            for binding in source.selector_bindings() {
                let profile_config = self
                    .selector_profiles
                    .get(binding.profile)
                    .ok_or(ConfigError::Invalid(
                        "source path binding references an unknown selector profile",
                    ))
                    .at(&at)?;
                if !profile_config.fields.contains_key(binding.field) {
                    return invalid("source path binding references an unknown selector field")
                        .at(at);
                }
                if !source.selector_inputs().iter().any(|input| {
                    input.role == binding.role
                        && input.alternatives.iter().any(|alternative| {
                            alternative.profile == binding.profile
                                && alternative
                                    .fields
                                    .iter()
                                    .any(|field| field == binding.field)
                        })
                }) {
                    return invalid("source path binding is not declared as a selector input")
                        .at(at);
                }
            }
        }

        let initial_sources = self
            .requirements
            .iter()
            .map(|requirement| requirement.acquisition.initial_source())
            .collect::<BTreeSet<_>>();
        let fetch_sources = self
            .requirements
            .iter()
            .flat_map(|requirement| requirement.acquisition.fetch_sources())
            .collect::<BTreeSet<_>>();
        for (source_id, source) in self.sources.iter() {
            if initial_sources.contains(source_id) && source.selector_inputs().is_empty() {
                return invalid("single and search sources must declare selector inputs")
                    .at(named("/sources", source_id));
            }
            if !source.prior_fact_bindings().is_empty()
                && (!fetch_sources.contains(source_id) || initial_sources.contains(source_id))
            {
                return invalid("prior-fact path bindings are permitted only on fetch sources")
                    .at(named("/sources", source_id));
            }
        }

        for (index, requirement) in self.requirements.iter().enumerate() {
            let at = format!("/requirements/{index}");
            for source_id in requirement.acquisition.source_ids() {
                if !self.sources.contains_key(source_id) {
                    return invalid("requirement acquisition references an unknown source")
                        .at(format!("{at}/acquisition"));
                }
            }
            if requirement.validity_seconds > self.signing.maximum_assertion_validity_seconds {
                return invalid("requirement validity exceeds signing maximum validity")
                    .at(format!("{at}/validitySeconds"));
            }
            for (role_index, role) in requirement.subject_roles.iter().enumerate() {
                for profile_id in &role.selector_profiles {
                    self.selector_profiles
                        .get(profile_id)
                        .ok_or(ConfigError::Invalid(
                            "requirement references an unknown selector profile",
                        ))
                        .at(format!("{at}/subjectRoles/{role_index}/selectorProfiles"))?;
                }
            }
            validate_derivation_selector_inputs(requirement, &self.selector_profiles).at(&at)?;
        }

        let requirements = self
            .requirements
            .iter()
            .map(|requirement| (requirement.id.as_str(), requirement))
            .collect::<BTreeMap<_, _>>();
        let mut authorized_combinations = BTreeSet::new();
        let mut source_selector_sets: BTreeMap<String, BTreeSet<SourceSelectorSet>> =
            BTreeMap::new();
        for (authority_id, authority) in self.authority_profiles.iter() {
            let authority_at = named("/authorityProfiles", authority_id);
            for (grant_index, grant) in authority.grants.iter().enumerate() {
                let at = format!("{authority_at}/grants/{grant_index}");
                let requirement = requirements
                    .get(grant.requirement.as_str())
                    .ok_or(ConfigError::Invalid(
                        "authority grant references an unknown requirement",
                    ))
                    .at(format!("{at}/requirement"))?;
                if !requirement
                    .purposes
                    .iter()
                    .any(|purpose| purpose == &grant.purpose)
                {
                    return invalid("authority grant references an unauthorized purpose")
                        .at(format!("{at}/purpose"));
                }
                if grant.subjects.len() != requirement.subject_roles.len() {
                    return invalid("authority grant must bind the complete subject-role set")
                        .at(format!("{at}/subjects"));
                }
                let mut seen_roles = BTreeSet::new();
                for (subject_index, subject) in grant.subjects.iter().enumerate() {
                    let subject_at = format!("{at}/subjects/{subject_index}");
                    if !seen_roles.insert(subject.role.as_str()) {
                        return invalid("authority grant subject roles must be unique")
                            .at(format!("{subject_at}/role"));
                    }
                    let role = requirement
                        .subject_roles
                        .iter()
                        .find(|role| role.role == subject.role)
                        .ok_or(ConfigError::Invalid(
                            "authority grant references an unknown subject role",
                        ))
                        .at(format!("{subject_at}/role"))?;
                    if !role
                        .selector_profiles
                        .iter()
                        .any(|profile| profile == &subject.selector_profile)
                    {
                        return invalid("authority grant selector profile is not allowed for role")
                            .at(format!("{subject_at}/selectorProfile"));
                    }
                    let profile = self
                        .selector_profiles
                        .get(&subject.selector_profile)
                        .ok_or(ConfigError::Invalid(
                            "authority grant references an unknown selector profile",
                        ))
                        .at(format!("{subject_at}/selectorProfile"))?;
                    subject.validate_value_claims(profile).at(&subject_at)?;
                    authorized_combinations.insert((
                        grant.requirement.as_str(),
                        grant.purpose.as_str(),
                        subject.role.as_str(),
                        subject.selector_profile.as_str(),
                    ));
                }
                if requirement
                    .subject_roles
                    .iter()
                    .any(|role| !seen_roles.contains(role.role.as_str()))
                {
                    return invalid("authority grant omits a required subject role")
                        .at(format!("{at}/subjects"));
                }
                for source_id in requirement.acquisition.source_ids() {
                    let source = self
                        .sources
                        .get(source_id)
                        .ok_or(ConfigError::Invalid(
                            "requirement acquisition references an unknown source",
                        ))
                        .at(&at)?;
                    let mut source_selector_set = grant
                        .subjects
                        .iter()
                        .filter(|subject| {
                            source.selector_inputs().iter().any(|input| {
                                input.role == subject.role
                                    && input.alternatives.iter().any(|alternative| {
                                        alternative.profile == subject.selector_profile
                                    })
                            })
                        })
                        .map(|subject| (subject.role.clone(), subject.selector_profile.clone()))
                        .collect::<SourceSelectorSet>();
                    if source_selector_set.is_empty() && !source.selector_inputs().is_empty() {
                        return invalid(
                            "authority path does not activate any declared source selector input",
                        )
                        .at(at);
                    }
                    source_selector_set.sort();
                    source_selector_sets
                        .entry(source_id.to_owned())
                        .or_default()
                        .insert(source_selector_set);
                }
            }
            if !authority.uses_task_grant()
                && (!authority.requester_clients.is_empty()
                    || authority.grant_source_issuer.is_some())
            {
                return invalid(
                    "requesterClients and grantSourceIssuer require an authenticated-grant subject",
                )
                .at(authority_at);
            }
        }

        for (index, requirement) in self.requirements.iter().enumerate() {
            for purpose in &requirement.purposes {
                for role in &requirement.subject_roles {
                    for profile in &role.selector_profiles {
                        if !authorized_combinations.contains(&(
                            requirement.id.as_str(),
                            purpose.as_str(),
                            role.role.as_str(),
                            profile.as_str(),
                        )) {
                            return invalid(
                                "requirement role and selector profile lack an authority path",
                            )
                            .at(format!("/requirements/{index}/subjectRoles"));
                        }
                    }
                }
            }
        }
        self.validate_source_selector_sets(&source_selector_sets)?;
        Ok(())
    }

    fn validate_source_selector_sets(
        &self,
        allowed: &BTreeMap<String, BTreeSet<SourceSelectorSet>>,
    ) -> Result<(), Violation> {
        for (source_id, source) in self.sources.iter() {
            let at = named("/sources", source_id);
            let sets = allowed
                .get(source_id)
                .ok_or(ConfigError::Invalid(
                    "configured source is unreachable from every authority grant",
                ))
                .at(&at)?;
            let reachable = sets
                .iter()
                .flatten()
                .map(|(role, profile)| (role.as_str(), profile.as_str()))
                .collect::<BTreeSet<_>>();
            if source.selector_inputs().iter().any(|input| {
                input.alternatives.iter().any(|alternative| {
                    !reachable.contains(&(input.role.as_str(), alternative.profile.as_str()))
                })
            }) {
                return invalid(
                    "source selector input is unreachable from every complete authority path",
                )
                .at(at);
            }
        }
        Ok(())
    }
}

fn validate_https_origin(value: &str) -> Result<(), ConfigError> {
    let url = Url::parse(value)
        .map_err(|_| ConfigError::Invalid("service providerId is not a stable HTTPS origin"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || value.ends_with('/')
    {
        return invalid("SD-JWT VC requires service.providerId to be a stable HTTPS origin");
    }
    Ok(())
}

/// Validate the one externally visible origin a relying party is allowed to
/// use as this protected resource's identity.
///
/// Production origins are canonical HTTPS origins. The local assurance
/// profile additionally permits one deliberately narrow tutorial form:
/// canonical HTTP on numeric 127.0.0.1 with an explicit non-zero port. Host
/// names, paths, credentials, queries, fragments, and alternative loopback
/// spellings are refused so discovery cannot redirect trust to another host.
fn validate_public_origin(
    value: &str,
    assurance_profile: AssuranceProfile,
) -> Result<(), ConfigError> {
    if value.chars().count() > 512 {
        return invalid("service publicOrigin exceeds its maximum length");
    }
    let url = Url::parse(value)
        .map_err(|_| ConfigError::Invalid("service publicOrigin is not a canonical origin"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || value.ends_with('/')
        || url.origin().ascii_serialization() != value
    {
        return invalid("service publicOrigin is not a canonical origin");
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    if assurance_profile == AssuranceProfile::Local
        && url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some_and(|port| port != 0)
    {
        return Ok(());
    }
    invalid("service publicOrigin must be HTTPS outside the local loopback profile")
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub provider_id: String,
    pub trust_domain: String,
    /// Exact public resource-server origin used by RFC 9728 discovery.
    pub public_origin: registry_platform_yaml::Url,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    pub id: String,
}

/// Public facts that cannot be derived from the governed Evidence service,
/// issuer, formats, bindings, and requirement inventory.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationConfig {
    pub service_id: String,
    pub title: String,
    pub description: String,
    pub endpoint_url: registry_platform_yaml::Url,
    pub jurisdictions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
}

impl PublicationConfig {
    fn validate(&self, assurance_profile: AssuranceProfile) -> Result<(), ConfigError> {
        validate_publication_identifier(&self.service_id)?;
        if !registry_discovery_profile::is_valid_public_text(&self.title) {
            return invalid("publication title is invalid");
        }
        if !registry_discovery_profile::is_valid_public_text(&self.description) {
            return invalid("publication description is invalid");
        }
        if self.endpoint_url.chars().count() > 512
            || !registry_discovery_profile::is_valid_endpoint_url(
                &self.endpoint_url,
                assurance_profile == AssuranceProfile::Local,
            )
        {
            return invalid("publication endpoint URL is invalid");
        }
        validate_len(
            self.jurisdictions.len(),
            1,
            128,
            "publication jurisdictions",
        )?;
        if self
            .jurisdictions
            .iter()
            .any(|jurisdiction| validate_publication_identifier(jurisdiction).is_err())
            || self.jurisdictions.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return invalid(
                "publication jurisdictions must be sorted, unique, globally scoped URIs",
            );
        }
        for role in [&self.publisher_id, &self.operator_id]
            .into_iter()
            .flatten()
        {
            validate_publication_identifier(role)?;
        }
        Ok(())
    }
}

fn validate_publication_identifier(value: &str) -> Result<(), ConfigError> {
    if value.chars().count() > 512 || !registry_discovery_profile::is_valid_identifier(value) {
        return invalid("publication URI is invalid");
    }
    Ok(())
}

/// The `apiVersion` every Evidence runtime file declares.
pub const EVIDENCE_RUNTIME_API_VERSION: &str =
    "registry.registrystack.org/evidence-runtime/v1alpha1";
/// The `kind` every Evidence runtime file declares.
pub const EVIDENCE_RUNTIME_KIND: &str = "EvidenceRuntimeConfig";

/// The envelope every Evidence runtime file carries.
pub const EVIDENCE_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: EVIDENCE_RUNTIME_API_VERSION,
    kind: EVIDENCE_RUNTIME_KIND,
};

/// The name the shared loader gives a runtime document read from bytes. The
/// command that read the file renames it to the path it was given.
const RUNTIME_DOCUMENT_NAME: &str = "runtime.yaml";

/// The reader's refusal of bytes that are not text it can read: larger than
/// its bound or not UTF-8.
fn unreadable_document(file: &str, bytes: &[u8]) -> ConfigError {
    match Reader::new(file).scan(bytes) {
        Err(report) => ConfigError::Refused(Box::new(report)),
        Ok(_) => ConfigError::Invalid("document is not UTF-8"),
    }
}

/// Keys an earlier Evidence runtime file accepted, each refused with the key
/// that replaced it.
pub const EVIDENCE_RUNTIME_REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "version",
        replacement: "Declare apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1 \
             and kind: EvidenceRuntimeConfig.",
    },
    RemovedKey {
        path: "bundleDirectory",
        replacement: "Declare package.root as the absolute path of the package directory.",
    },
    RemovedKey {
        path: "listener.bindHost",
        replacement: "Declare listener.bind as host:port, such as 127.0.0.1:8080.",
    },
    RemovedKey {
        path: "listener.port",
        replacement: "Declare listener.bind as host:port, such as 127.0.0.1:8080.",
    },
    RemovedKey {
        path: "metricsListener.bindHost",
        replacement: "Declare metricsListener.bind as host:port, such as 127.0.0.1:9090.",
    },
    RemovedKey {
        path: "metricsListener.port",
        replacement: "Declare metricsListener.bind as host:port, such as 127.0.0.1:9090.",
    },
];

/// The codes a runtime file's semantic findings carry (CFG-DIAG-3), one per
/// block of the file.
pub const RUNTIME_PACKAGE_CODE: &str = "evidence.runtime.invalid-package";
pub const RUNTIME_LISTENER_CODE: &str = "evidence.runtime.invalid-listener";
pub const RUNTIME_METRICS_LISTENER_CODE: &str = "evidence.runtime.invalid-metrics-listener";
pub const RUNTIME_SECRET_PROVIDERS_CODE: &str = "evidence.runtime.invalid-secret-providers";
pub const RUNTIME_SIGNER_CODE: &str = "evidence.runtime.invalid-signer";
pub const RUNTIME_AUDIT_CODE: &str = "evidence.runtime.invalid-audit";
pub const RUNTIME_OUTBOUND_TLS_CODE: &str = "evidence.runtime.invalid-outbound-tls";
pub const RUNTIME_SOURCE_EXTRACT_CODE: &str = "evidence.runtime.invalid-source-extract";
pub const RUNTIME_ACQUISITION_CAPABILITIES_CODE: &str =
    "evidence.runtime.invalid-acquisition-capabilities";

const ABSOLUTE_PATH_ACTION: &str =
    "Write an absolute path of at most 512 bytes, without . or .. segments.";
const LOCAL_ID_ACTION: &str = "Write a local identifier of at most 128 bytes: a lowercase ASCII letter, then lowercase letters, digits, dots, underscores, or hyphens.";
const LISTENER_PORT_ACTION: &str = "Name a port from 1 to 65535 after the host.";

/// One rule a decoded runtime document breaks, naming the member it
/// concerns. The message is the error's fixed cause and the action a fixed
/// sentence, so neither repeats a value from the document (CFG-SEC-3).
#[derive(Debug)]
pub struct RuntimeFinding {
    pub code: &'static str,
    /// RFC 6901 pointer of the member the finding concerns.
    pub pointer: String,
    /// Whether the finding points at the member's key, as it does for a
    /// member that is missing or not allowed, rather than at its value.
    pub at_key: bool,
    pub error: ConfigError,
    pub action: String,
}

impl RuntimeFinding {
    fn at_value(code: &'static str, pointer: &str, error: ConfigError, action: &str) -> Self {
        Self {
            code,
            pointer: pointer.to_owned(),
            at_key: false,
            error,
            action: action.to_owned(),
        }
    }

    fn at_key(code: &'static str, pointer: &str, error: ConfigError, action: &str) -> Self {
        Self {
            at_key: true,
            ..Self::at_value(code, pointer, error, action)
        }
    }

    /// The fixed cause the finding reports.
    pub fn message(&self) -> &'static str {
        self.error.fault().cause()
    }
}

/// The findings of a named map whose entries each bind one absolute path:
/// at most 64 entries, each named by a local identifier.
fn absolute_path_map_findings<T>(
    map: &OrderedMap<T>,
    pointer: &str,
    code: &'static str,
    member: &str,
    path_of: impl Fn(&T) -> &String,
    findings: &mut Vec<RuntimeFinding>,
) {
    if let Err(error) = validate_len(map.len(), 0, 64, "named configuration map") {
        findings.push(RuntimeFinding::at_key(
            code,
            pointer,
            error,
            "Bind at most 64 entries.",
        ));
    }
    for (name, value) in map.iter() {
        let entry = format!(
            "{pointer}/{}",
            registry_platform_yaml::escape_pointer_segment(name)
        );
        if !valid_local_id(name) {
            findings.push(RuntimeFinding::at_key(
                code,
                &entry,
                ConfigError::Invalid("local identifier is invalid"),
                LOCAL_ID_ACTION,
            ));
        }
        if let Err(error) = validate_absolute_path(path_of(value)) {
            findings.push(RuntimeFinding::at_value(
                code,
                &format!("{entry}/{member}"),
                error,
                ABSOLUTE_PATH_ACTION,
            ));
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    /// The one governed package directory this process verifies and loads at startup.
    pub package: PackageConfig,
    pub listener: ListenerConfig,
    /// Optional operator-only metrics listener. Absent means the deployment
    /// serves no metrics endpoint at all, which is the default posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_listener: Option<MetricsListenerConfig>,
    pub secret_providers: SecretProvidersConfig,
    /// Process-local binding to the signer that controls the governed active
    /// public key. This cannot change the governed key set or algorithm.
    pub signer: RuntimeSignerConfig,
    /// Where this process writes its audit entries.
    pub audit: RuntimeAuditConfig,
    pub outbound_tls: OutboundTlsConfig,
    /// Process-local files bound to the logical extract names the bundle's
    /// statement sources read. Absent binds none, which is what a runtime file
    /// for a bundle with no extract source says.
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub source_extracts: OrderedMap<SourceExtractBinding>,
    /// Acquisition kinds this deployment enables beyond the frozen Version 1
    /// forms. Absent enables none of them, so adopting a form is a deliberate
    /// operator decision rather than a consequence of the bundle that arrived.
    /// A bundle requiring a kind absent here is refused before the deployment
    /// serves anything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acquisition_capabilities: Vec<String>,
}

impl RuntimeConfig {
    /// The shared loader configured with the Evidence envelope and the keys
    /// it no longer accepts.
    pub fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(EVIDENCE_RUNTIME_ENVELOPE)
            .removed_keys(EVIDENCE_RUNTIME_REMOVED_KEYS)
            .max_bytes(MAX_CONFIG_BYTES as u64)
    }

    /// Parse and validate one runtime document with no environment: an
    /// environment expression resolves only through its own default.
    pub fn parse_yaml(bytes: &[u8]) -> Result<Self, ConfigError> {
        Self::parse_yaml_with(bytes, |_| None).map(|loaded| loaded.config)
    }

    /// Parse and validate one runtime document, substituting environment
    /// expressions in string values from `lookup`. The returned digest covers
    /// the document after substitution.
    pub fn parse_yaml_with(
        bytes: &[u8],
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<LoadedRuntimeConfig<Self>, ConfigError> {
        let loaded = Self::decode_yaml_with(bytes, lookup)?;
        loaded.config.validate()?;
        Ok(loaded)
    }

    /// Read and decode one runtime document through the shared loader,
    /// substituting environment expressions in string values from `lookup`,
    /// without the semantic checks [`RuntimeConfig::findings`] applies.
    pub fn decode_yaml_with(
        bytes: &[u8],
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<LoadedRuntimeConfig<Self>, ConfigError> {
        // The reader refuses a document over its size bound or not in UTF-8
        // with its own diagnostic; text it can read goes to the loader, which
        // substitutes environment expressions while the reader builds it.
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Err(unreadable_document(RUNTIME_DOCUMENT_NAME, bytes));
        };
        Self::loader()
            .parse_str::<Self>(text, lookup)
            .map_err(|error| {
                ConfigError::Refused(Box::new(Report::new(error.diagnostics().to_vec())))
            })
    }

    /// Refuse the document with the first rule it breaks, as startup does.
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.findings().into_iter().next() {
            Some(finding) => Err(finding.error),
            None => Ok(()),
        }
    }

    /// Every rule this decoded document breaks, each naming the member it
    /// concerns, in the order startup checks them: the first is the refusal
    /// [`RuntimeConfig::validate`] returns.
    pub fn findings(&self) -> Vec<RuntimeFinding> {
        let mut findings = Vec::new();
        match self.package.check() {
            Err(error)
                if error.kind()
                    == registry_platform_config::ConfigBlockErrorKind::InvalidDigest =>
            {
                findings.push(RuntimeFinding::at_value(
                    RUNTIME_PACKAGE_CODE,
                    "/package/expectedDigest",
                    ConfigError::InvalidField(
                        "package expectedDigest must be sha256: followed by 64 lowercase hex digits",
                        "package.expectedDigest",
                    ),
                    "Write the digest `evidencectl package` printed, sha256: followed by 64 lowercase hex digits.",
                ));
            }
            Err(_) => findings.push(RuntimeFinding::at_value(
                RUNTIME_PACKAGE_CODE,
                "/package/root",
                ConfigError::InvalidField("package root must be an absolute path", "package.root"),
                ABSOLUTE_PATH_ACTION,
            )),
            Ok(()) => {
                if let Err(error) = validate_absolute_path(&self.package.root.to_string_lossy()) {
                    findings.push(RuntimeFinding::at_value(
                        RUNTIME_PACKAGE_CODE,
                        "/package/root",
                        error,
                        ABSOLUTE_PATH_ACTION,
                    ));
                }
            }
        }
        self.listener.findings(&mut findings);
        if let Some(metrics) = &self.metrics_listener {
            metrics.findings(&self.listener, &mut findings);
        }
        let providers_enabled = self.secret_providers.check().is_ok();
        if !providers_enabled {
            findings.push(RuntimeFinding::at_key(
                RUNTIME_SECRET_PROVIDERS_CODE,
                "/secretProviders",
                ConfigError::InvalidField(
                    "secretProviders must enable file, environment, or both, and a file root must be absolute",
                    "secretProviders",
                ),
                "Enable file with an absolute root, environment, or both.",
            ));
        }
        if let Some(file) = &self.secret_providers.file {
            if let Err(error) = validate_absolute_path(&file.root.to_string_lossy()) {
                findings.push(RuntimeFinding::at_value(
                    RUNTIME_SECRET_PROVIDERS_CODE,
                    "/secretProviders/file/root",
                    error,
                    ABSOLUTE_PATH_ACTION,
                ));
            }
        }
        self.signer
            .findings(&self.secret_providers, providers_enabled, &mut findings);
        self.audit.findings(&mut findings);
        self.outbound_tls.findings(&mut findings);
        absolute_path_map_findings(
            &self.source_extracts,
            "/sourceExtracts",
            RUNTIME_SOURCE_EXTRACT_CODE,
            "path",
            |binding| &binding.path,
            &mut findings,
        );
        if let Err(error) = declared_acquisition_capabilities(
            &self.acquisition_capabilities,
            "runtime acquisition capabilities name an unknown acquisition kind",
            "runtime acquisition capabilities must be unique",
            "runtime acquisition capabilities",
        ) {
            findings.push(RuntimeFinding::at_key(
                RUNTIME_ACQUISITION_CAPABILITIES_CODE,
                "/acquisitionCapabilities",
                error,
                "Name each gated acquisition kind this deployment serves once.",
            ));
        }
        findings
    }

    /// Whether the operator enabled one gated acquisition kind on this
    /// deployment. The answer is read only through the enabled list, so a
    /// deployment that says nothing enables nothing.
    pub fn enables_acquisition_capability(&self, capability: &str) -> bool {
        self.acquisition_capabilities
            .iter()
            .any(|enabled| enabled == capability)
    }
}

/// Closed process-local signer binding. Production deployments reach Transit
/// only over a workload-local Unix socket and never receive a provider token.
///
/// The `kind` member names the variant. The shared reader chooses the variant
/// from the node itself, so a refusal inside a variant keeps its full path,
/// line, and column.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeSignerConfig {
    LocalJwk {
        private_key_ref: SecretReference,
    },
    Transit {
        unix_socket_path: String,
        mount: String,
        key_name: String,
        key_version: BoundedU32<1, { u32::MAX }>,
        timeout_milliseconds: BoundedU64<1, 30_000>,
    },
}
registry_platform_yaml::tagged_union!(RuntimeSignerConfig, tag = "kind");

/// The tagged form the file is written in: `kind` beside the variant's
/// members.
impl Serialize for RuntimeSignerConfig {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::LocalJwk { private_key_ref } => {
                map.serialize_entry("kind", "local-jwk")?;
                map.serialize_entry("privateKeyRef", private_key_ref)?;
            }
            Self::Transit {
                unix_socket_path,
                mount,
                key_name,
                key_version,
                timeout_milliseconds,
            } => {
                map.serialize_entry("kind", "transit")?;
                map.serialize_entry("unixSocketPath", unix_socket_path)?;
                map.serialize_entry("mount", mount)?;
                map.serialize_entry("keyName", key_name)?;
                map.serialize_entry("keyVersion", key_version)?;
                map.serialize_entry("timeoutMilliseconds", timeout_milliseconds)?;
            }
        }
        map.end()
    }
}

impl RuntimeSignerConfig {
    /// The signer's findings. A secret reference is checked against the
    /// enabled providers only when `secretProviders` itself is valid, so one
    /// mistake there is not reported twice.
    fn findings(
        &self,
        secret_providers: &SecretProvidersConfig,
        providers_enabled: bool,
        findings: &mut Vec<RuntimeFinding>,
    ) {
        match self {
            Self::LocalJwk { private_key_ref } => {
                if providers_enabled
                    && secret_providers
                        .check_reference("signer.privateKeyRef", private_key_ref.as_str())
                        .is_err()
                {
                    findings.push(RuntimeFinding::at_value(
                        RUNTIME_SIGNER_CODE,
                        "/signer/privateKeyRef",
                        ConfigError::InvalidField(
                            "the secret reference names a provider secretProviders does not enable",
                            "signer.privateKeyRef",
                        ),
                        "Enable the provider the reference names under secretProviders, or reference the key through an enabled provider.",
                    ));
                }
            }
            Self::Transit {
                unix_socket_path,
                mount,
                key_name,
                ..
            } => {
                if let Err(error) = validate_absolute_path(unix_socket_path) {
                    findings.push(RuntimeFinding::at_value(
                        RUNTIME_SIGNER_CODE,
                        "/signer/unixSocketPath",
                        error,
                        ABSOLUTE_PATH_ACTION,
                    ));
                }
                for (pointer, name) in [("/signer/mount", mount), ("/signer/keyName", key_name)] {
                    if !valid_local_id(name) {
                        findings.push(RuntimeFinding::at_value(
                            RUNTIME_SIGNER_CODE,
                            pointer,
                            ConfigError::Invalid(
                                "Transit signer mount and keyName must be local identifiers",
                            ),
                            LOCAL_ID_ACTION,
                        ));
                    }
                }
            }
        }
    }

    pub fn is_local_jwk(&self) -> bool {
        matches!(self, Self::LocalJwk { .. })
    }

    pub fn is_transit(&self) -> bool {
        matches!(self, Self::Transit { .. })
    }

    pub fn private_key_ref(&self) -> Option<&SecretReference> {
        match self {
            Self::LocalJwk { private_key_ref } => Some(private_key_ref),
            Self::Transit { .. } => None,
        }
    }
}

/// The process-local audit destination: an append-only JSON Lines file this
/// process alone writes, or standard output for a collector that owns
/// durability.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAuditConfig {
    #[serde(default)]
    pub destination: AuditDestinationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_bytes: Option<
        BoundedU64<{ registry_platform_audit::MIN_AUDIT_ROTATE_BYTES }, { u32::MAX as u64 }>,
    >,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_days: Option<BoundedU32<1, { registry_platform_audit::MAX_AUDIT_RETAIN_DAYS }>>,
}

impl RuntimeAuditConfig {
    fn findings(&self, findings: &mut Vec<RuntimeFinding>) {
        if let Some(Err(error)) = self.path.as_deref().map(validate_absolute_path) {
            findings.push(RuntimeFinding::at_value(
                RUNTIME_AUDIT_CODE,
                "/audit/path",
                error,
                ABSOLUTE_PATH_ACTION,
            ));
            return;
        }
        if let Err(error) = self.settings() {
            let refusal = audit_refusal(&error);
            findings.push(RuntimeFinding {
                code: RUNTIME_AUDIT_CODE,
                pointer: refusal.pointer,
                at_key: refusal.at_key,
                error: ConfigError::Invalid(refusal.cause),
                action: refusal.action,
            });
        }
    }

    fn settings(&self) -> Result<AuditDestination, AuditDestinationError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.as_deref().map(PathBuf::from),
            self.rotate_bytes.map(BoundedU64::get),
            self.retain_days.map(BoundedU32::get),
        )
    }

    /// The destination the writer opens, with the platform defaults applied
    /// and file-only settings refused for `stdout`.
    pub fn destination(&self) -> Result<AuditDestination, ConfigError> {
        self.settings()
            .map_err(|error| ConfigError::Invalid(audit_refusal(&error).cause))
    }
}

/// How a refused audit destination is reported: the fixed cause, the member
/// it concerns, and the fix.
struct AuditRefusal {
    cause: &'static str,
    pointer: String,
    at_key: bool,
    action: String,
}

fn audit_refusal(error: &AuditDestinationError) -> AuditRefusal {
    let refusal = |cause, pointer: &str, at_key, action: &str| AuditRefusal {
        cause,
        pointer: pointer.to_owned(),
        at_key,
        action: action.to_owned(),
    };
    match error {
        AuditDestinationError::MissingPath => refusal(
            "audit path is required when audit destination is file",
            "/audit",
            true,
            "Add audit.path, the absolute path of the audit file, or write destination: stdout.",
        ),
        AuditDestinationError::RelativePath => refusal(
            "audit path must be absolute",
            "/audit/path",
            false,
            ABSOLUTE_PATH_ACTION,
        ),
        AuditDestinationError::FileOnlyField { field } => refusal(
            "audit path, rotateBytes, and retainDays apply only when audit destination is file",
            &format!("/audit/{field}"),
            true,
            "Remove the key, or write destination: file.",
        ),
        AuditDestinationError::RotateBytesOutOfRange { minimum, maximum } => AuditRefusal {
            action: format!("Write a whole number of bytes from {minimum} to {maximum}."),
            ..refusal(
                "audit rotateBytes is outside the platform bounds",
                "/audit/rotateBytes",
                false,
                "",
            )
        },
        AuditDestinationError::RetainDaysOutOfRange { maximum } => AuditRefusal {
            action: format!("Write a whole number of days from 1 to {maximum}."),
            ..refusal(
                "audit retainDays is outside the platform bounds",
                "/audit/retainDays",
                false,
                "",
            )
        },
        _ => refusal(
            "audit destination is invalid",
            "/audit/path",
            false,
            "Write the absolute path of the audit file, ending in a short file name.",
        ),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutboundTlsConfig {
    pub system_roots: bool,
    pub trust_profiles: OrderedMap<TrustProfileBinding>,
}

impl OutboundTlsConfig {
    fn findings(&self, findings: &mut Vec<RuntimeFinding>) {
        if !self.system_roots {
            findings.push(RuntimeFinding::at_value(
                RUNTIME_OUTBOUND_TLS_CODE,
                "/outboundTls/systemRoots",
                ConfigError::Invalid("outbound TLS system roots must remain enabled"),
                "Write true; a trust profile adds its CA bundle beside the system roots.",
            ));
        }
        absolute_path_map_findings(
            &self.trust_profiles,
            "/outboundTls/trustProfiles",
            RUNTIME_OUTBOUND_TLS_CODE,
            "caBundleFile",
            |binding| &binding.ca_bundle_file,
            findings,
        );
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustProfileBinding {
    pub ca_bundle_file: String,
}

/// One logical extract name bound to the process-local file that holds it.
///
/// A bundle names the extract its statement reads and never a filesystem
/// location, so the operator decides where the file sits without editing
/// reviewed material.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceExtractBinding {
    pub path: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerConfig {
    /// Numeric `host:port` the evidence API binds.
    pub bind: ListenerBind,
    #[serde(default)]
    pub network_exposure: ListenerNetworkExposure,
    pub tls_termination: TlsTermination,
    pub trust_proxy_identity_headers: bool,
    pub maximum_request_bytes: BoundedU64<1_024, 1_048_576>,
    pub maximum_concurrent_requests: BoundedU32<1, 4_096>,
    pub request_timeout_milliseconds: BoundedU64<1, 30_000>,
    pub shutdown_grace_milliseconds: BoundedU64<1, 120_000>,
}

impl ListenerConfig {
    fn findings(&self, findings: &mut Vec<RuntimeFinding>) {
        let host = match self.network_exposure {
            ListenerNetworkExposure::PrivateAddress => validate_private_bind_host(self.bind.ip()),
            ListenerNetworkExposure::ContainerPrivate => {
                validate_container_private_bind_host(self.bind.ip())
            }
        };
        if let Err(error) = host {
            findings.push(RuntimeFinding::at_value(
                RUNTIME_LISTENER_CODE,
                "/listener/bind",
                error,
                "Bind a loopback or private address, or declare networkExposure: container-private on a container network.",
            ));
        }
        if let Err(error) = validate_listener_port(self.bind.socket_addr().port()) {
            findings.push(RuntimeFinding::at_value(
                RUNTIME_LISTENER_CODE,
                "/listener/bind",
                error,
                LISTENER_PORT_ACTION,
            ));
        }
        if self.trust_proxy_identity_headers {
            findings.push(RuntimeFinding::at_value(
                RUNTIME_LISTENER_CODE,
                "/listener/trustProxyIdentityHeaders",
                ConfigError::Invalid("proxy identity headers must not be trusted"),
                "Write false; Evidence authenticates every request itself.",
            ));
        }
    }
}

/// Operator-declared network placement for the Evidence API listener.
///
/// `ContainerPrivate` permits a wildcard bind only because the container
/// network and upstream TLS boundary remain operator-owned deployment facts.
/// It does not enable direct public exposure or change request authentication.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerNetworkExposure {
    #[default]
    PrivateAddress,
    ContainerPrivate,
}

/// Operator-only telemetry listener.
///
/// It is a separate binding rather than a route on the evidence listener so
/// that reaching the counters requires reaching a different socket. It carries
/// no request limits of its own: it serves one static rendering of in-process
/// counters, reads no request body, and touches no source or signing material.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricsListenerConfig {
    /// Numeric `host:port` the metrics endpoint binds.
    pub bind: ListenerBind,
}

impl MetricsListenerConfig {
    fn findings(&self, evidence_listener: &ListenerConfig, findings: &mut Vec<RuntimeFinding>) {
        for (error, action) in [
            (
                validate_private_bind_host(self.bind.ip()),
                "Bind the metrics listener to a loopback or private address.",
            ),
            (
                validate_listener_port(self.bind.socket_addr().port()),
                LISTENER_PORT_ACTION,
            ),
            (
                self.validate_separate(evidence_listener),
                "Bind the metrics listener to a port the evidence listener does not use.",
            ),
        ] {
            if let Err(error) = error {
                findings.push(RuntimeFinding::at_value(
                    RUNTIME_METRICS_LISTENER_CODE,
                    "/metricsListener/bind",
                    error,
                    action,
                ));
            }
        }
    }

    fn validate_separate(&self, evidence_listener: &ListenerConfig) -> Result<(), ConfigError> {
        // Sharing the evidence binding would publish the counters on the
        // listener the public contract describes, which is the separation this
        // block exists to enforce.
        let metrics_ip = self.bind.ip();
        let evidence_ip = evidence_listener.bind.ip();
        // Linux commonly creates an IPv6 wildcard socket as dual-stack, so
        // `[::]:port` can also occupy the corresponding IPv4 port. Evidence
        // does not force IPV6_V6ONLY, and configuration validation must be
        // portable across the hosts on which the process can run. Treat the
        // IPv6 wildcard as covering both families; the IPv4 wildcard covers
        // only IPv4.
        let wildcard_covers_metrics = match evidence_ip {
            IpAddr::V4(ip) => ip.is_unspecified() && metrics_ip.is_ipv4(),
            IpAddr::V6(ip) => ip.is_unspecified(),
        };
        let binding_overlaps = metrics_ip == evidence_ip || wildcard_covers_metrics;
        if binding_overlaps
            && self.bind.socket_addr().port() == evidence_listener.bind.socket_addr().port()
        {
            return invalid("metricsListener must not share the evidence listener binding");
        }
        Ok(())
    }
}

/// Refuse port 0, which asks the kernel for an arbitrary ephemeral port rather
/// than naming one.
///
/// Every listener here is an operator-network binding that something upstream
/// firewalls, health-checks, or terminates TLS for, and none of that can follow
/// a port that is chosen at bind time and changes on every restart. The
/// published runtime schema already states the bound, so this is the loader
/// agreeing with the contract an operator validated against.
fn validate_listener_port(port: u16) -> Result<(), ConfigError> {
    validate_range(u64::from(port), 1, 65_535, "port")
}

/// Accept only numeric loopback, RFC 1918 private IPv4, and RFC 4193
/// unique-local IPv6 bindings. Every listener this service opens is an
/// operator-network listener; TLS and exposure are upstream concerns.
fn validate_private_bind_host(ip: IpAddr) -> Result<(), ConfigError> {
    let private = match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || is_unique_local(ip),
    };
    if !private || ip.is_unspecified() || ip.is_multicast() {
        return invalid("listener bind address must be loopback or private");
    }
    Ok(())
}

/// Accept a wildcard or private numeric address only when the operator has
/// explicitly placed the listener on a container-private network.
fn validate_container_private_bind_host(ip: IpAddr) -> Result<(), ConfigError> {
    let private_or_unspecified = match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_loopback() || is_unique_local(ip),
    };
    if !private_or_unspecified || ip.is_multicast() {
        return invalid(
            "container-private listener bind address must be unspecified, loopback, or private",
        );
    }
    Ok(())
}

fn is_unique_local(ip: Ipv6Addr) -> bool {
    ip.octets()[0] & 0xfe == 0xfc
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsTermination {
    OperatorControlledUpstream,
}

/// The governed access-token rules. Evidence accepts OIDC access tokens only,
/// so the block holds exactly one member.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub oidc: OidcAuthenticationConfig,
}

impl AuthenticationConfig {
    fn validate(&self, assurance_profile: AssuranceProfile) -> Result<(), ConfigError> {
        self.oidc.validate(assurance_profile)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(remote = "Self", rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcAuthenticationConfig {
    /// The exact issuer, the one audience every token carries, and the JWKS
    /// source. Evidence reads keys only from an explicit `uri` source.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/provider"))]
    pub provider: OidcIssuerConfig,
    pub token_types: Vec<AccessTokenType>,
    pub algorithms: Vec<AccessTokenAlgorithm>,
    pub principal_claim: String,
    pub requester_tags_claim: String,
    pub evidence_audience_claim: String,
    /// Shared, direct contextual-authorization claim names. Product-specific
    /// requester, actor identity, and relying-party audience claims remain
    /// separate because they have Evidence-specific meaning.
    #[serde(default)]
    pub claims: registry_platform_oidc::ClaimNames,
    /// Maximum lifetime accepted for inbound access tokens. The verifier
    /// requires `iat`, requires `exp > iat`, and applies this bound.
    pub maximum_token_lifetime_seconds: BoundedU64<1, 86_400>,
    /// Emergency denylist applied before JWKS cache selection.
    pub revoked_key_ids: UniqueList<String>,
    /// Explicit machine-client admission, matched against the token's
    /// `client_id`/`azp` the platform verifier already reads. Absent keeps
    /// the issuer-vouched-client behavior; present requires a nonempty,
    /// bounded, unique list and admits exactly those clients.
    ///
    /// Audience plus static issuer-governed attributes alone cannot establish
    /// that the client was granted this resource's permission: an issuer may
    /// issue a correctly signed token for a known resource with zero scopes
    /// while still emitting the client's attributes. `required_scopes` closes
    /// that gap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_clients: Option<UniqueList<String>>,
    /// Per-client assertion-authority admission for a token that carries the
    /// platform verifier's `registry_assertion_issuer` claim, keyed by the
    /// client (matched against the token's `azp`, falling back to
    /// `client_id`, the same way `allowed_clients` is matched) and naming the
    /// issuers that client may present the claim as. Absent applies no rule,
    /// so every exchanged token is admitted regardless of the claim; present
    /// admits a claim-bearing token only when its client is a listed key and
    /// its claim value is one of that client's listed issuers. A token that
    /// carries no such claim, an ordinary client-credentials token, is never
    /// affected by this admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_issuers: Option<BTreeMap<String, UniqueList<String>>>,
    /// Scopes every inbound token must carry, checked against the verified
    /// token's scope set after signature verification and before any authority
    /// claim is read. Absent keeps the no-scope-gate behavior; present
    /// requires a nonempty, bounded, unique list of RFC 6749 scope-tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scopes: Option<UniqueList<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_claim: Option<String>,
    /// Logical name of the private certificate authority the runtime file
    /// binds for the JWKS connection, trusted beside the system roots
    /// for that connection alone. Absent trusts the system roots only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust_profile: Option<String>,
}

shared_block_host!(OidcAuthenticationConfig, block = "provider");

impl OidcAuthenticationConfig {
    /// The exact issuer accepted in `iss`.
    pub fn issuer(&self) -> &str {
        &self.provider.issuer
    }

    /// The one audience every accepted token carries in `aud`.
    pub fn audience(&self) -> &str {
        &self.provider.audience
    }

    /// The JWKS URI. Validation refuses every source other than `uri`, so a
    /// validated configuration always has one; an unvalidated one answers
    /// with an empty string, which no URL parser accepts.
    pub fn jwks_uri(&self) -> &str {
        self.provider.jwks_source.uri().unwrap_or("")
    }

    fn validate(&self, assurance_profile: AssuranceProfile) -> Result<(), ConfigError> {
        let JwksSource::Uri { .. } = &self.provider.jwks_source else {
            return Err(ConfigError::InvalidField(
                "Evidence reads access-token keys only from jwksSource kind uri",
                "authentication.oidc.jwksSource",
            ));
        };
        let issuer = Url::parse(self.issuer())
            .map_err(|_| ConfigError::Invalid("authentication issuer is invalid"))?;
        let jwks_uri = Url::parse(self.jwks_uri())
            .map_err(|_| ConfigError::Invalid("authentication JWKS URI is invalid"))?;
        if issuer.scheme() == "http" || jwks_uri.scheme() == "http" {
            if assurance_profile != AssuranceProfile::Local {
                return invalid("production and evidence-grade authentication requires HTTPS");
            }
            // The local permission is for a supervised issuer on this
            // deployment's own loopback: a canonical numeric origin, with the
            // JWKS served from that exact origin. It is not a permission for
            // private-network HTTP, and a JWKS origin or port other than the
            // issuer's is not supervised by the issuer that vouches for it.
            let origin = validate_local_issuer_origin(self.issuer())?;
            if jwks_uri.scheme() != "http"
                || jwks_uri.host_str() != Some("127.0.0.1")
                || jwks_uri.port() != issuer.port()
                || !jwks_uri.path().starts_with('/')
                || jwks_uri.query().is_some()
                || jwks_uri.fragment().is_some()
                || !jwks_uri.username().is_empty()
                || jwks_uri.password().is_some()
                || self.jwks_uri() != format!("{origin}{}", jwks_uri.path())
            {
                return invalid(
                    "local authentication JWKS URI must use the exact issuer origin, an absolute path, and no query or fragment",
                );
            }
            if self.tls_trust_profile.is_some() {
                return invalid(
                    "a local HTTP authentication JWKS URI cannot use a TLS trust profile",
                );
            }
        } else {
            validate_https_issuer(self.issuer())?;
            validate_https_url(self.jwks_uri(), false)?;
        }
        self.provider
            .check(
                "authentication.oidc",
                assurance_profile == AssuranceProfile::Local,
            )
            .map_err(|_| {
                ConfigError::InvalidField(
                    "the OIDC issuer, audience, or JWKS source is invalid",
                    "authentication.oidc",
                )
            })?;
        if self
            .tls_trust_profile
            .as_deref()
            .is_some_and(|profile| !valid_local_id(profile))
        {
            return invalid("authentication TLS trust profile identifier is invalid");
        }
        validate_unique(&self.token_types, 1, 4, "authentication tokenTypes")?;
        validate_unique(&self.algorithms, 1, 3, "authentication algorithms")?;
        validate_strings(
            &self.revoked_key_ids,
            0,
            32,
            1,
            256,
            "authentication revokedKeyIds",
        )?;
        // Admission lists are optional, but a present list is a statement the
        // deployment means: an empty allowlist admits nothing and an empty
        // scope requirement gates nothing, and both are almost certainly a
        // mis-authored key rather than a deliberate posture.
        if let Some(clients) = &self.allowed_clients {
            validate_strings(clients, 1, 32, 1, 128, "authentication allowedClients")?;
        }
        if let Some(assertion_issuers) = &self.assertion_issuers {
            let clients: Vec<String> = assertion_issuers.keys().cloned().collect();
            validate_strings(&clients, 1, 32, 1, 128, "authentication assertionIssuers")?;
            for issuers in assertion_issuers.values() {
                validate_strings(issuers, 1, 8, 1, 512, "authentication assertionIssuers")?;
            }
        }
        if let Some(scopes) = &self.required_scopes {
            validate_strings(scopes, 1, 32, 1, 256, "authentication requiredScopes")?;
            if scopes
                .iter()
                .any(|scope| !registry_platform_httputil::valid_scope_token(scope))
            {
                return invalid("authentication requiredScopes must be RFC 6749 scope-tokens");
            }
        }
        if self
            .revoked_key_ids
            .iter()
            .any(|kid| kid.chars().any(char::is_control))
        {
            return invalid("authentication revokedKeyIds contain a control character");
        }
        // Ordered principal first, because `sub` is legitimate for that claim
        // alone and the shadowing check below reads the rest of the list.
        self.claims.validate().map_err(|_| {
            ConfigError::Invalid("contextual authorization claim names are invalid")
        })?;
        let product_claims = [
            Some(&self.principal_claim),
            Some(&self.requester_tags_claim),
            Some(&self.evidence_audience_claim),
            self.actor_claim.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        for claim in &product_claims {
            validate_claim_name(claim)?;
        }
        // Two claims naming one member means the same value is read as two
        // different things, such as requester tags read as a principal or a
        // grant id read as a grant source issuer.
        let contextual_claims = [
            &self.claims.actor_kind,
            &self.claims.purpose,
            &self.claims.grant_id,
            &self.claims.grant_source_issuer,
            &self.claims.grant_client,
            &self.claims.grant_resource,
            &self.claims.grant_exp,
            &self.claims.grant_bounds,
            &self.claims.approver,
        ];
        if product_claims
            .iter()
            .chain(contextual_claims.iter())
            .collect::<BTreeSet<_>>()
            .len()
            != product_claims.len() + contextual_claims.len()
        {
            return invalid("authority claim names must be distinct");
        }
        // These are defined by the token itself, so reading contextual
        // authorization out of one reads something the issuer wrote for
        // another purpose.
        //
        // `sub` is the exception, and only for the principal. It carries the
        // principal already, so naming it there reads the same value; naming it
        // anywhere else reads the principal as something it is not.
        if product_claims
            .iter()
            .any(|claim| REGISTERED_JWT_CLAIMS.contains(&claim.as_str()))
            || product_claims
                .iter()
                .skip(1)
                .any(|claim| claim.as_str() == "sub")
        {
            return invalid("authority claim names must not shadow registered JWT claims");
        }
        Ok(())
    }

    pub(crate) fn uses_local_issuer_http(&self, assurance_profile: AssuranceProfile) -> bool {
        if assurance_profile != AssuranceProfile::Local {
            return false;
        }
        let Ok(issuer) = Url::parse(self.issuer()) else {
            return false;
        };
        let Ok(jwks_uri) = Url::parse(self.jwks_uri()) else {
            return false;
        };
        issuer.scheme() == "http"
            && jwks_uri.scheme() == "http"
            && validate_local_issuer_origin(self.issuer()).is_ok()
            && jwks_uri.host_str() == Some("127.0.0.1")
            && jwks_uri.port() == issuer.port()
            && jwks_uri.path().starts_with('/')
            && jwks_uri.query().is_none()
            && jwks_uri.fragment().is_none()
            && jwks_uri.username().is_empty()
            && jwks_uri.password().is_none()
    }
}

/// Registered JWT claims no authority claim may be read from. `sub` is handled
/// separately, because the principal claim may legitimately name it.
///
/// Evidence refuses to read these as authority regardless of what the
/// configured issuer writes.
///
/// `cnf` is reserved for a second reason: the authenticator denies any token
/// carrying it, because Version 1 validates no proof of possession and will not
/// downgrade a sender-constrained token to a bearer one. Naming it here would
/// otherwise produce a deployment that loads and checks clean but answers 401 to
/// every authenticated request.
const REGISTERED_JWT_CLAIMS: [&str; 8] =
    ["iss", "aud", "exp", "iat", "nbf", "jti", "client_id", "cnf"];

fn validate_local_issuer_origin(value: &str) -> Result<&str, ConfigError> {
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .filter(|port| !port.starts_with('0'))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(ConfigError::Invalid(
            "local authentication issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
        ))?;
    if value != format!("http://127.0.0.1:{port}") {
        return invalid(
            "local authentication issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
        );
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum AccessTokenType {
    #[serde(rename = "at+jwt")]
    AtJwt,
    #[serde(rename = "application/at+jwt")]
    ApplicationAtJwt,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum AccessTokenAlgorithm {
    EdDSA,
    ES256,
    RS256,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(remote = "Self", rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    /// The secret keying audit pseudonyms.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/key"))]
    pub key: AuditKeyConfig,
    /// Labels the pseudonym key generation, so a rotated key is told apart
    /// from the one it replaced.
    pub hash_key_version: BoundedU32<1, MAXIMUM_BUNDLE_KEY_VERSION>,
}

shared_block_host!(AuditConfig, block = "key");

/// The bundle contract's ceiling for the audit and subject-binding key
/// versions.
const MAXIMUM_BUNDLE_KEY_VERSION: u32 = 2_147_483_647;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectBindingConfig {
    pub secret_ref: SecretReference,
    pub key_version: BoundedU32<1, MAXIMUM_BUNDLE_KEY_VERSION>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitConfig {
    pub requests_per_principal_per_minute: BoundedU32<1, 1_000_000>,
    pub burst_per_principal: BoundedU32<1, 100_000>,
    pub failed_selector_attempts_per_principal_authority_per_minute: BoundedU32<1, 100_000>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningConfig {
    pub format: SigningFormat,
    pub algorithm: SigningAlgorithm,
    pub active_public_jwk_file: PublicJwkPath,
    pub published_public_jwk_files: Vec<PublicJwkPath>,
    pub revoked_key_ids: UniqueList<String>,
    pub jwks_path: String,
    pub maximum_assertion_validity_seconds: BoundedU64<1, 31_536_000>,
    pub verifier_clock_skew_seconds: BoundedU64<0, 300>,
}

impl SigningConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_unique(
            &self.published_public_jwk_files,
            0,
            32,
            "published public JWK paths",
        )?;
        if self
            .published_public_jwk_files
            .iter()
            .any(|path| path == &self.active_public_jwk_file)
        {
            return invalid("the active public JWK file must not also be published");
        }
        validate_key_identifiers(&self.revoked_key_ids, 33, "signing revokedKeyIds")?;
        if self.jwks_path != "/.well-known/evidence/jwks.json" {
            return invalid("JWKS path is not the Version 1 discovery path");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningFormat {
    FlattenedJwsJson,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum SigningAlgorithm {
    ES256,
}

fn validate_key_identifiers(
    identifiers: &[String],
    maximum: usize,
    label: &'static str,
) -> Result<(), ConfigError> {
    validate_strings(identifiers, 0, maximum, 43, 43, label)?;
    if identifiers.iter().any(|identifier| {
        let alphabet_is_valid = identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        let encoding_is_canonical = URL_SAFE_NO_PAD.decode(identifier).is_ok_and(|decoded| {
            decoded.len() == 32 && URL_SAFE_NO_PAD.encode(&decoded) == *identifier
        });
        !alphabet_is_valid || !encoding_is_canonical
    }) {
        return invalid("key identifiers must be RFC 7638 SHA-256 thumbprints");
    }
    Ok(())
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct PublicJwkPath(String);

impl PublicJwkPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PublicJwkPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PublicJwkPath")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for PublicJwkPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if is_public_jwk_path(&value) {
            Ok(Self(value))
        } else {
            Err(Invalid::expected(
                "a path public-keys/<name>.jwk.json, where the name uses ASCII letters, digits, dots, underscores, or hyphens",
                "Name a public key file under public-keys/ ending in .jwk.json.",
            )
            .into_error())
        }
    }
}

impl Serialize for PublicJwkPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn is_public_jwk_path(value: &str) -> bool {
    let Some(name) = value.strip_prefix("public-keys/") else {
        return false;
    };
    let Some(stem) = name.strip_suffix(".jwk.json") else {
        return false;
    };
    !stem.is_empty()
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectorProfile {
    pub maximum_aggregate_bytes: BoundedU64<1, 8_192>,
    pub fields: OrderedMap<SelectorField>,
}

impl SelectorProfile {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_len(self.fields.len(), 1, 16, "selector fields")?;
        for (name, field) in self.fields.iter() {
            if !valid_field_name(name) {
                return invalid("selector field name is invalid");
            }
            field.validate(self.maximum_aggregate_bytes.get())?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SelectorField {
    String {
        #[serde(rename = "minimumBytes")]
        minimum_bytes: BoundedU64<1, 8_192>,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: BoundedU64<1, 8_192>,
    },
    Date {},
    Integer {
        minimum: i64,
        maximum: i64,
    },
    Boolean {},
    ControlledCode {
        codelist: ArtifactPath,
        #[serde(rename = "codelistVersion")]
        codelist_version: String,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: BoundedU64<1, 8_192>,
    },
}

registry_platform_yaml::tagged_union!(SelectorField, tag = "type");
serialize_tagged_union!(SelectorField, tag = "type");

impl SelectorField {
    fn validate(&self, aggregate_maximum: u64) -> Result<(), ConfigError> {
        match self {
            Self::String {
                minimum_bytes,
                maximum_bytes,
            } => {
                if minimum_bytes > maximum_bytes || maximum_bytes.get() > aggregate_maximum {
                    return invalid("selector string byte bounds are inconsistent");
                }
            }
            Self::Integer { minimum, maximum } => {
                if minimum > maximum || *minimum < -MAX_SAFE_INTEGER || *maximum > MAX_SAFE_INTEGER
                {
                    return invalid("selector integer bounds are inconsistent");
                }
            }
            Self::ControlledCode {
                codelist,
                codelist_version,
                maximum_bytes,
            } => {
                require_artifact_prefix(codelist, "codelists/")?;
                validate_string(codelist_version, 1, 128, "selector codelist version")?;
                if maximum_bytes.get() > aggregate_maximum {
                    return invalid("selector code exceeds aggregate byte bound");
                }
            }
            Self::Date {} | Self::Boolean {} => {}
        }
        Ok(())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct ArtifactPath(String);

impl ArtifactPath {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        if !valid_artifact_path(value) {
            return invalid("artifact path is invalid");
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArtifactPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArtifactPath")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for ArtifactPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|_| {
            Invalid::expected(
                "a relative path under adapters/, derivations/, schemas/, codelists/, fixtures/, or queries/, using ASCII letters, digits, dots, underscores, hyphens, and slashes, without . or .. segments",
                "Name a package file by its relative path under one of the package directories.",
            )
            .into_error()
        })
    }
}

impl Serialize for ArtifactPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn valid_artifact_path(value: &str) -> bool {
    const ROOTS: [&str; 6] = [
        "adapters/",
        "derivations/",
        "schemas/",
        "codelists/",
        "fixtures/",
        "queries/",
    ];
    ROOTS.iter().any(|root| value.starts_with(root))
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// One optional, governed owner of HTTP destination, workload credentials,
/// TLS trust and process-local resource bounds. It never owns source facts or
/// an authorization result. Independent names always have independent state.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceConnectionConfig {
    pub base_url: registry_platform_yaml::Url,
    pub authentication: Box<SourceAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust_profile: Option<String>,
    #[serde(default = "default_connection_concurrency")]
    pub concurrency_limit: BoundedU32<1, 256>,
    #[serde(default = "default_connection_timeout")]
    pub admission_timeout_milliseconds: BoundedU64<1, 30_000>,
    #[serde(default = "default_connection_timeout")]
    pub token_timeout_milliseconds: BoundedU64<1, 30_000>,
}

fn default_connection_concurrency() -> BoundedU32<1, 256> {
    BoundedU32::new(4).expect("the default connection concurrency is in range")
}
fn default_connection_timeout() -> BoundedU64<1, 30_000> {
    BoundedU64::new(5_000).expect("the default connection timeout is in range")
}

impl SourceConnectionConfig {
    fn validate(&self, assurance_profile: AssuranceProfile) -> Result<(), ConfigError> {
        validate_source_origin(&self.base_url)?;
        self.authentication.validate()?;
        if self
            .tls_trust_profile
            .as_deref()
            .is_some_and(|profile| !valid_local_id(profile))
        {
            return invalid("source connection TLS trust profile identifier is invalid");
        }
        if matches!(*self.authentication, SourceAuthentication::None {}) {
            if assurance_profile != AssuranceProfile::Local {
                return invalid("unauthenticated source connections require local assurance");
            }
            validate_local_unauthenticated_source_origin(&self.base_url)?;
            if self.tls_trust_profile.is_some() {
                return invalid(
                    "an unauthenticated local HTTP connection cannot use a TLS trust profile",
                );
            }
        }
        Ok(())
    }

    pub(crate) fn matches_source(&self, source: &SourceConfig) -> bool {
        matches!(source, SourceConfig::HttpJson { base_url, authentication, tls_trust_profile, request, .. }
            if base_url == &self.base_url && authentication == &self.authentication
                && tls_trust_profile == &self.tls_trust_profile && request.concurrency_limit == self.concurrency_limit)
    }
}

/// One reviewed source, closed over the transport that reaches it.
///
/// The transports agree on the acquisition posture, the three artifact roles,
/// and the bounds a response is read under, and disagree on request material.
/// A caller that only needs the agreed contract reads it through the accessors
/// on this type rather than by matching a transport it does not care about:
/// `posture`, `tls_trust_profile`, `extract_profile`, `response_schema`,
/// `extract_script`, `fact_schema`, `statement`, `prepare_script`, `adapter_parameters`,
/// `adapter_parameters_schema`, `selector_inputs`, `selector_bindings`,
/// `prior_fact_bindings`, `fixed_headers`, `projection`,
/// `forwards_access_attribution`,
/// `timeout_milliseconds`, `maximum_response_bytes`, and `concurrency_limit`.
///
/// The tag is internal, so a field belonging to one transport is an unknown
/// field of the other and the closed schema rejects it. Request and credential
/// material sits behind a pointer, so one transport's request does not set the
/// size of every source.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceConfig {
    /// One fixed HTTP request against a JSON API.
    #[serde(rename_all = "camelCase")]
    HttpJson {
        base_url: registry_platform_yaml::Url,
        /// Optional explicit resource owner. The resolved values stay fixed in
        /// this bundle and must equal the named connection's governed values.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connection: Option<String>,
        /// Digest of the provider's selected read behavior, independent of
        /// unrelated export provenance and whole-provider package changes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        behavior_revision: Option<String>,
        /// Forward the verified, authorized Evidence requester and purpose in
        /// Rust-owned reserved headers to a source that is explicitly prepared
        /// to account for an intermediary read.
        #[serde(default, skip_serializing_if = "is_false")]
        forward_access_attribution: bool,
        posture: AcquisitionPosture,
        /// Optional exact upstream Problem Details tuple which means that the
        /// source deliberately did not resolve this lookup. The transport
        /// remains source-neutral: no provider code is built in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unresolved_problem: Option<DeclaredUnresolvedProblem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls_trust_profile: Option<String>,
        authentication: Box<SourceAuthentication>,
        request: Box<FixedRequest>,
        /// Optional signed Evidence protocol over this same fixed HTTP channel.
        /// Its governed contract supplies requirement and purpose; Rust owns
        /// the fresh nonce and verifies the answer before extraction.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence: Option<Box<crate::source_evidence::EvidenceSourceConfig>>,
        /// Shape contract for the projected response, validated by Rust before
        /// extraction runs, so the script maps a response it can rely on.
        response_schema: ArtifactPath,
        extract_script: ArtifactPath,
        fact_schema: ArtifactPath,
        /// Optional reviewed one-call optimization for a logical request
        /// batch. It reuses the ordinary source authority and all transport
        /// bounds; only preparation, response projection, and extraction are
        /// batch-specific.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        batch: Option<Box<HttpBatchConfig>>,
    },
    /// One reviewed SQL statement against a read-only extract file.
    #[serde(rename_all = "camelCase")]
    SqliteExtract {
        posture: AcquisitionPosture,
        /// Logical name of the extract this source reads. The runtime document
        /// binds the name to a file, so no bundle names a filesystem location.
        extract_profile: String,
        request: Box<SqliteRequest>,
        /// Oldest extract this source accepts, so a stale file is refused
        /// rather than answered from.
        maximum_extract_age_seconds: BoundedU64<1, 2_592_000>,
        /// Shape contract for the projected result, validated by Rust before
        /// extraction runs, so the script maps a result it can rely on.
        response_schema: ArtifactPath,
        extract_script: ArtifactPath,
        fact_schema: ArtifactPath,
    },
}

registry_platform_yaml::tagged_union!(SourceConfig, tag = "transport");
serialize_tagged_union!(SourceConfig, tag = "transport");

impl SourceConfig {
    fn validate(&self, assurance_profile: AssuranceProfile) -> Result<(), ConfigError> {
        match self {
            Self::HttpJson {
                base_url,
                connection,
                behavior_revision,
                tls_trust_profile,
                authentication,
                request,
                batch,
                unresolved_problem,
                evidence,
                forward_access_attribution,
                ..
            } => {
                validate_source_origin(base_url)?;
                if connection
                    .as_deref()
                    .is_some_and(|name| !valid_local_id(name))
                {
                    return invalid("source connection identifier is invalid");
                }
                if behavior_revision.as_deref().is_some_and(|revision| {
                    !revision.strip_prefix("sha256:").is_some_and(|digest| {
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                }) {
                    return invalid("source behavior revision must be a lowercase sha256 digest");
                }
                if tls_trust_profile
                    .as_deref()
                    .is_some_and(|profile| !valid_local_id(profile))
                {
                    return invalid("source TLS trust profile identifier is invalid");
                }
                if matches!(**authentication, SourceAuthentication::None {}) {
                    if assurance_profile != AssuranceProfile::Local {
                        return invalid(
                            "unauthenticated sources are permitted only by the local assurance profile",
                        );
                    }
                    validate_local_unauthenticated_source_origin(base_url)?;
                    if tls_trust_profile.is_some() {
                        return invalid(
                            "an unauthenticated local HTTP source cannot use a TLS trust profile",
                        );
                    }
                }
                authentication.validate()?;
                request.validate()?;
                if let Some(evidence) = evidence {
                    evidence.validate(request)?;
                    if batch.is_some() || unresolved_problem.is_some() {
                        return invalid("signed Evidence sources cannot declare source batching or unresolved Problem Details");
                    }
                    if *forward_access_attribution {
                        return invalid("a signed Evidence source cannot set forwardAccessAttribution, because the upstream authorizes and audits this service's own source credential");
                    }
                    if matches!(**authentication, SourceAuthentication::None {}) {
                        return invalid("a signed Evidence source requires source authentication, because the upstream authorizes and audits this service's own source credential");
                    }
                }
                if let Some(problem) = unresolved_problem {
                    problem.validate()?;
                    if batch.is_some() {
                        return invalid(
                            "declared unresolved problems are not supported by source batching",
                        );
                    }
                }
                if let Some(batch) = batch {
                    if request.path.is_none() || request.path_template.is_some() {
                        return invalid("source batch optimization requires a fixed request path");
                    }
                    batch.validate()?;
                }
            }
            Self::SqliteExtract {
                extract_profile,
                request,
                ..
            } => {
                if !valid_local_id(extract_profile) {
                    return invalid("source extract profile identifier is invalid");
                }
                request.validate()?;
            }
        }
        let extract_script = self.extract_script();
        require_artifact_prefix(extract_script, "adapters/")?;
        if !extract_script.as_str().ends_with(".rhai") {
            return invalid("source extraction script must be a Rhai file");
        }
        let adapter_id = Path::new(extract_script.as_str())
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| valid_local_id(value))
            .ok_or(ConfigError::Invalid(
                "source adapter name must be a local identifier",
            ))?;
        debug_assert!(!adapter_id.is_empty());
        require_artifact_prefix(self.response_schema(), "schemas/")?;
        require_artifact_prefix(self.fact_schema(), "schemas/")?;
        let mut roles = vec![self.response_schema().as_str(), self.fact_schema().as_str()];
        roles.extend(
            self.adapter_parameters_schema()
                .map(|schema| schema.as_str()),
        );
        if let Some(batch) = self.batch() {
            roles.push(batch.response_schema.as_str());
        }
        let distinct = roles.iter().collect::<BTreeSet<_>>();
        if distinct.len() != roles.len() {
            return invalid("source schema roles must be distinct artifacts");
        }
        Ok(())
    }

    /// Explicit connection identity. Inline sources never share an owner.
    pub fn connection(&self) -> Option<&str> {
        match self {
            Self::HttpJson { connection, .. } => connection.as_deref(),
            Self::SqliteExtract { .. } => None,
        }
    }

    pub fn posture(&self) -> AcquisitionPosture {
        match self {
            Self::HttpJson { posture, .. } | Self::SqliteExtract { posture, .. } => *posture,
        }
    }

    /// The credentials an inline HTTP source presents, where the transport
    /// opens a connection of its own.
    pub fn authentication(&self) -> Option<&SourceAuthentication> {
        match self {
            Self::HttpJson { authentication, .. } => Some(authentication),
            Self::SqliteExtract { .. } => None,
        }
    }

    /// The private trust profile an outbound connection uses, where the
    /// transport opens one.
    pub fn tls_trust_profile(&self) -> Option<&str> {
        match self {
            Self::HttpJson {
                tls_trust_profile, ..
            } => tls_trust_profile.as_deref(),
            Self::SqliteExtract { .. } => None,
        }
    }

    /// The logical extract a source reads, where the transport reads one. The
    /// runtime document binds the name to a file; this never names one.
    pub fn extract_profile(&self) -> Option<&str> {
        match self {
            Self::HttpJson { .. } => None,
            Self::SqliteExtract {
                extract_profile, ..
            } => Some(extract_profile),
        }
    }

    pub fn response_schema(&self) -> &ArtifactPath {
        match self {
            Self::HttpJson {
                response_schema, ..
            }
            | Self::SqliteExtract {
                response_schema, ..
            } => response_schema,
        }
    }

    pub fn extract_script(&self) -> &ArtifactPath {
        match self {
            Self::HttpJson { extract_script, .. } | Self::SqliteExtract { extract_script, .. } => {
                extract_script
            }
        }
    }

    pub fn fact_schema(&self) -> &ArtifactPath {
        match self {
            Self::HttpJson { fact_schema, .. } | Self::SqliteExtract { fact_schema, .. } => {
                fact_schema
            }
        }
    }

    pub fn batch(&self) -> Option<&HttpBatchConfig> {
        match self {
            Self::HttpJson { batch, .. } => batch.as_deref(),
            Self::SqliteExtract { .. } => None,
        }
    }

    /// The exact source-neutral unresolved tuple this HTTP source recognizes.
    ///
    /// Callers receive only the governed declaration, never an upstream
    /// Problem Details body. Statement sources cannot declare this outcome.
    pub fn unresolved_problem(&self) -> Option<&DeclaredUnresolvedProblem> {
        match self {
            Self::HttpJson {
                unresolved_problem, ..
            } => unresolved_problem.as_ref(),
            Self::SqliteExtract { .. } => None,
        }
    }

    /// The reviewed statement artifact, where the transport runs one.
    pub fn statement(&self) -> Option<&ArtifactPath> {
        match self {
            Self::HttpJson { .. } => None,
            Self::SqliteExtract { request, .. } => Some(&request.statement),
        }
    }

    /// The request-preparation script, which only a transport that prepares a
    /// request declares.
    pub fn prepare_script(&self) -> Option<&ArtifactPath> {
        match self {
            Self::HttpJson { request, .. } => Some(&request.prepare_script),
            Self::SqliteExtract { request, .. } => request.prepare_script.as_ref(),
        }
    }

    pub fn adapter_parameters(&self) -> &OrderedMap<AdapterParameterValue> {
        match self {
            Self::HttpJson { request, .. } => &request.adapter_parameters,
            Self::SqliteExtract { request, .. } => &request.adapter_parameters,
        }
    }

    /// The closed schema the adapter parameters are validated against, which
    /// is present exactly when a transport declares parameters.
    pub fn adapter_parameters_schema(&self) -> Option<&ArtifactPath> {
        match self {
            Self::HttpJson { request, .. } => Some(&request.adapter_parameters_schema),
            Self::SqliteExtract { request, .. } => request.adapter_parameters_schema.as_ref(),
        }
    }

    pub fn selector_inputs(&self) -> &[SelectorInput] {
        match self {
            Self::HttpJson { request, .. } => &request.selector_inputs,
            Self::SqliteExtract { request, .. } => &request.selector_inputs,
        }
    }

    /// Every request value this source fills from a selector field, whatever
    /// the transport calls the channel.
    pub fn selector_bindings(&self) -> Vec<SelectorBinding<'_>> {
        match self {
            Self::HttpJson { request, .. } => request
                .path_bindings
                .iter()
                .filter_map(|(_, binding)| match binding {
                    PathBindingConfig::Selector {
                        role,
                        profile,
                        field,
                    } => Some(SelectorBinding {
                        role,
                        profile,
                        field,
                    }),
                    PathBindingConfig::PriorFact { .. } => None,
                })
                .collect(),
            Self::SqliteExtract { request, .. } => request
                .parameter_bindings
                .iter()
                .filter_map(|(_, binding)| match binding {
                    SqliteParameterBinding::Selector {
                        role,
                        profile,
                        field,
                    } => Some(SelectorBinding {
                        role,
                        profile,
                        field,
                    }),
                    SqliteParameterBinding::Prepared {} => None,
                })
                .collect(),
        }
    }

    /// Every prior-fact field this source binds into its request. Only a
    /// transport with a prior-fact channel returns any.
    pub fn prior_fact_bindings(&self) -> Vec<&str> {
        match self {
            Self::HttpJson { request, .. } => request
                .path_bindings
                .iter()
                .filter_map(|(_, binding)| match binding {
                    PathBindingConfig::PriorFact { field } => Some(field.as_str()),
                    PathBindingConfig::Selector { .. } => None,
                })
                .collect(),
            Self::SqliteExtract { .. } => Vec::new(),
        }
    }

    pub fn fixed_headers(&self) -> &[FixedHeader] {
        match self {
            Self::HttpJson { request, .. } => &request.fixed_headers,
            Self::SqliteExtract { .. } => &[],
        }
    }

    /// Whether this fixed HTTP source receives the verified requester and
    /// authorized purpose as host-owned access-attribution headers.
    pub fn forwards_access_attribution(&self) -> bool {
        match self {
            Self::HttpJson {
                forward_access_attribution,
                ..
            } => *forward_access_attribution,
            Self::SqliteExtract { .. } => false,
        }
    }

    pub fn projection(&self) -> &[String] {
        match self {
            Self::HttpJson { request, .. } => &request.projection,
            Self::SqliteExtract { request, .. } => &request.projection,
        }
    }

    pub fn timeout_milliseconds(&self) -> u64 {
        match self {
            Self::HttpJson { request, .. } => request.timeout_milliseconds.get(),
            Self::SqliteExtract { request, .. } => request.timeout_milliseconds.get(),
        }
    }

    pub fn maximum_response_bytes(&self) -> u64 {
        match self {
            Self::HttpJson { request, .. } => request.maximum_response_bytes.get(),
            Self::SqliteExtract { request, .. } => request.maximum_response_bytes.get(),
        }
    }

    pub fn concurrency_limit(&self) -> u32 {
        match self {
            Self::HttpJson { request, .. } => request.concurrency_limit.get(),
            Self::SqliteExtract { request, .. } => request.concurrency_limit.get(),
        }
    }
}

/// Exact, source-neutral Problem Details tuple an HTTP source may declare as
/// an explicit unresolved lookup outcome.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeclaredUnresolvedProblem {
    pub status: BoundedU32<404, 404>,
    #[serde(rename = "type")]
    pub type_uri: String,
    pub code: String,
}

impl DeclaredUnresolvedProblem {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.type_uri.chars().count() > 512 {
            return invalid("declared unresolved problem type is too long");
        }
        let uri = Url::parse(&self.type_uri)
            .map_err(|_| ConfigError::Invalid("declared unresolved problem type is invalid"))?;
        if uri.scheme() != "https"
            || uri.host().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
        {
            return invalid("declared unresolved problem type must be an absolute HTTPS URI");
        }
        let bytes = self.code.as_bytes();
        if !(1..=64).contains(&bytes.len())
            || !matches!(bytes.first(), Some(b'a'..=b'z'))
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return invalid("declared unresolved problem code is invalid");
        }
        Ok(())
    }
}

/// One request value filled from a named field of a named selector profile.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SelectorBinding<'a> {
    pub role: &'a str,
    pub profile: &'a str,
    pub field: &'a str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionPosture {
    SourceDerived,
    FieldProjected,
    RecordTransformed,
}

impl AcquisitionPosture {
    /// Return the least-minimized posture in a bounded acquisition. A chained
    /// requirement may claim no stronger posture than either of its sources.
    pub fn weakest(self, other: Self) -> Self {
        use AcquisitionPosture::{FieldProjected, RecordTransformed, SourceDerived};
        match (self, other) {
            (RecordTransformed, _) | (_, RecordTransformed) => RecordTransformed,
            (FieldProjected, _) | (_, FieldProjected) => FieldProjected,
            (SourceDerived, SourceDerived) => SourceDerived,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceAuthentication {
    /// No outbound credential is sent.
    ///
    /// The containing bundle validator admits this only for the local
    /// assurance profile and a canonical numeric-loopback HTTP origin with an
    /// explicit non-zero port. It is not a production authentication mode.
    None {},
    Basic {
        #[serde(rename = "usernameRef")]
        username_ref: SecretReference,
        #[serde(rename = "passwordRef")]
        password_ref: SecretReference,
    },
    StaticAuthorization {
        #[serde(rename = "tokenRef")]
        token_ref: SecretReference,
        /// Authentication scheme the resolved token is presented under.
        ///
        /// RFC 9110 section 11.1 lets the origin choose the scheme, and
        /// `static-api-key` cannot reach the Authorization header because its
        /// header name is refused by the collision denylist. Absent, the
        /// runtime sends `Bearer`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
    },
    StaticApiKey {
        #[serde(rename = "headerName")]
        header_name: String,
        #[serde(rename = "valueRef")]
        value_ref: SecretReference,
    },
    Oauth2ClientCredentials {
        #[serde(rename = "tokenEndpoint")]
        token_endpoint: String,
        #[serde(rename = "clientIdRef")]
        client_id_ref: SecretReference,
        /// Shared client secret, for the RFC 6749 section 2.3.1 form.
        ///
        /// Present with `credentialPlacement` and without
        /// `clientAssertionKeyRef`, or absent with both.
        #[serde(
            rename = "clientSecretRef",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        client_secret_ref: Option<SecretReference>,
        /// Private JWK the client assertion is signed with, for the RFC 7523
        /// section 2.2 form.
        ///
        /// Its presence selects assertion authentication, which is the form
        /// SMART on FHIR Backend Services requires.
        #[serde(
            rename = "clientAssertionKeyRef",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        client_assertion_key_ref: Option<SecretReference>,
        /// Audience claim of the signed assertion; set only with
        /// `clientAssertionKeyRef`, and defaulting to `tokenEndpoint`.
        ///
        /// RFC 7523 section 3 asks only that the value identify the
        /// authorization server and leaves the exact string to out-of-band
        /// agreement, so a server reached through a proxy, or one naming its
        /// issuer identifier, expects a value the client never dials. The
        /// server compares it by Simple String Comparison, so it is an opaque
        /// identifier rather than a URL and travels to the claim byte for byte.
        #[serde(
            rename = "clientAssertionAudience",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        client_assertion_audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// Fixed `audience` form parameter.
        ///
        /// An authorization server may key the issued token to an audience the
        /// scope cannot express and return a token usable against nothing when
        /// it is absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        /// RFC 8707 resource indicator sent as a token-request form parameter.
        /// Unlike the assertion audience, this names the intended resource server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        /// Where the shared client secret travels; set only with
        /// `clientSecretRef`.
        #[serde(
            rename = "credentialPlacement",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        credential_placement: Option<CredentialPlacement>,
        #[serde(rename = "maximumCacheSeconds")]
        maximum_cache_seconds: BoundedU64<0, 86_400>,
        /// Lifetime assumed when the provider omits `expires_in`.
        ///
        /// RFC 6749 section 5.1 makes `expires_in` recommended rather than
        /// required, so a compliant provider may return only `access_token`
        /// and `token_type`. The operator states the lifetime here rather than
        /// the runtime inferring one from the token, and the cache is still
        /// clamped to `maximumCacheSeconds`.
        #[serde(
            rename = "assumedLifetimeSeconds",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        assumed_lifetime_seconds: Option<BoundedU64<1, 86_400>>,
    },
}

registry_platform_yaml::tagged_union!(SourceAuthentication, tag = "kind");
serialize_tagged_union!(SourceAuthentication, tag = "kind");

impl SourceAuthentication {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::None {} => Ok(()),
            Self::Basic {
                username_ref: _,
                password_ref: _,
            } => Ok(()),
            Self::StaticAuthorization {
                token_ref: _,
                scheme,
            } => {
                if let Some(scheme) = scheme {
                    validate_authorization_scheme(scheme)?;
                }
                Ok(())
            }
            Self::StaticApiKey {
                header_name,
                value_ref: _,
            } => validate_configurable_header_name(header_name),
            Self::Oauth2ClientCredentials {
                token_endpoint,
                client_secret_ref,
                client_assertion_key_ref,
                client_assertion_audience,
                scope,
                audience,
                resource,
                credential_placement,
                ..
            } => {
                let token_endpoint = validate_source_url(token_endpoint, false)?;
                if token_endpoint.query().is_some() {
                    return invalid("OAuth token endpoint must not contain a query");
                }
                if client_secret_ref.is_some() == client_assertion_key_ref.is_some() {
                    return invalid(
                        "OAuth client authentication must declare either a client secret or a client assertion key",
                    );
                }
                if credential_placement.is_some() != client_secret_ref.is_some() {
                    return invalid(
                        "OAuth credential placement is required with a client secret and forbidden without one",
                    );
                }
                if client_assertion_audience.is_some() && client_assertion_key_ref.is_none() {
                    return invalid(
                        "OAuth client assertion audience is set without a client assertion key",
                    );
                }
                if let Some(client_assertion_audience) = client_assertion_audience {
                    validate_string(
                        client_assertion_audience,
                        1,
                        512,
                        "OAuth client assertion audience",
                    )?;
                    // Signing refuses a whitespace-only audience, so a bundle
                    // that carried one would satisfy its own contract and then
                    // fail at the first token request as a credential error
                    // naming nothing the operator can act on.
                    if client_assertion_audience.trim().is_empty() {
                        return invalid("OAuth client assertion audience is blank");
                    }
                }
                if let Some(scope) = scope {
                    validate_string(scope, 1, 512, "OAuth scope")?;
                }
                if let Some(audience) = audience {
                    validate_string(audience, 1, 512, "OAuth audience")?;
                    // The token request sends this value as it stands, with no
                    // fallback, so a blank one asks the authorization server
                    // for an audience named by spaces. Refusing it here names
                    // the key the operator must correct; the server's refusal
                    // arrives at readiness and names nothing.
                    if audience.trim().is_empty() {
                        return invalid("OAuth audience is blank");
                    }
                }
                if let Some(resource) = resource {
                    validate_oauth_resource(resource)?;
                }
                Ok(())
            }
        }
    }

    pub fn secret_refs(&self) -> Vec<&SecretReference> {
        match self {
            Self::None {} => Vec::new(),
            Self::Basic {
                username_ref,
                password_ref,
            } => vec![username_ref, password_ref],
            Self::StaticAuthorization { token_ref, .. } => vec![token_ref],
            Self::StaticApiKey { value_ref, .. } => vec![value_ref],
            Self::Oauth2ClientCredentials {
                client_id_ref,
                client_secret_ref,
                client_assertion_key_ref,
                ..
            } => [
                Some(client_id_ref),
                client_secret_ref.as_ref(),
                client_assertion_key_ref.as_ref(),
            ]
            .into_iter()
            .flatten()
            .collect(),
        }
    }
}

/// Accept an authentication scheme the runtime may prefix to a static token.
///
/// RFC 9110 section 11.1 defines the scheme as a token, so the byte set is the
/// same one field names use. Holding to it keeps a configured value from
/// carrying a space, a separator, or a line break into the header the runtime
/// writes.
fn validate_authorization_scheme(scheme: &str) -> Result<(), ConfigError> {
    validate_string(scheme, 1, 32, "authentication scheme")?;
    if !scheme.bytes().all(is_http_token_byte) {
        return invalid("authentication scheme must be an HTTP token");
    }
    Ok(())
}

/// Where the token request carries the client credentials.
///
/// RFC 6749 section 2.3.1 defines Basic authentication and the request-body
/// parameters and states that those parameters must not be placed in the
/// request URI, so Version 1 offers no query-string placement.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialPlacement {
    BasicHeader,
    FormBody,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixedRequest {
    pub method: HttpMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_template: Option<String>,
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub path_bindings: OrderedMap<PathBindingConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed_headers: Vec<FixedHeader>,
    pub selector_inputs: Vec<SelectorInput>,
    pub prepare_script: ArtifactPath,
    pub adapter_parameters: OrderedMap<AdapterParameterValue>,
    pub adapter_parameters_schema: ArtifactPath,
    pub preparation_limits: PreparationLimits,
    pub projection: UniqueList<String>,
    pub redirects: RedirectPolicy,
    pub timeout_milliseconds: BoundedU64<1, 30_000>,
    pub maximum_response_bytes: BoundedU64<1, 1_048_576>,
    pub concurrency_limit: BoundedU32<1, 256>,
}

/// Reviewed scripts and response contract for one physical HTTP call serving
/// several independent logical source lookups.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpBatchConfig {
    pub maximum_items: BoundedU32<1, { MAXIMUM_SOURCE_BATCH_ITEMS as u32 }>,
    pub prepare_script: ArtifactPath,
    pub extract_script: ArtifactPath,
    pub response_schema: ArtifactPath,
    pub projection: UniqueList<String>,
}

impl HttpBatchConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for script in [&self.prepare_script, &self.extract_script] {
            require_artifact_prefix(script, "adapters/")?;
            if !script.as_str().ends_with(".rhai") {
                return invalid("source batch script must be a Rhai file");
            }
        }
        if self.prepare_script == self.extract_script {
            return invalid("source batch scripts must be distinct artifacts");
        }
        Path::new(self.extract_script.as_str())
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| valid_local_id(value))
            .ok_or(ConfigError::Invalid(
                "source batch adapter name must be a local identifier",
            ))?;
        require_artifact_prefix(&self.response_schema, "schemas/")?;
        validate_projection(&self.projection)
    }
}

impl FixedRequest {
    fn validate(&self) -> Result<(), ConfigError> {
        match (&self.path, &self.path_template) {
            (Some(path), None) => {
                validate_normalized_request_path(path)?;
                if !self.path_bindings.is_empty() {
                    return invalid("fixed source path must not define pathBindings");
                }
            }
            (None, Some(template)) => validate_path_template(template, &self.path_bindings)?,
            _ => return invalid("source request must define exactly one of path or pathTemplate"),
        }
        validate_fixed_headers(&self.fixed_headers)?;
        validate_selector_inputs(&self.selector_inputs)?;
        require_artifact_prefix(&self.prepare_script, "adapters/")?;
        if !self.prepare_script.as_str().ends_with(".rhai") {
            return invalid("source preparation script must be a Rhai file");
        }
        validate_len(self.adapter_parameters.len(), 0, 64, "adapter parameters")?;
        for (name, value) in self.adapter_parameters.iter() {
            if !valid_parameter_key(name) {
                return invalid("adapter parameter name is invalid");
            }
            value.validate(0)?;
        }
        require_artifact_prefix(&self.adapter_parameters_schema, "schemas/")?;
        self.preparation_limits.validate()?;
        if self.method == HttpMethod::GET
            && self.preparation_limits.json_body != PreparationChannelPolicy::Forbidden
        {
            return invalid("GET source requests must forbid the JSON body channel");
        }
        validate_projection(&self.projection)?;

        Ok(())
    }
}

/// A statement's select list is already its minimum-disclosure projection.
///
/// The generic projection may retain the whole rows array, every row object, or
/// each declared member individually. It may add extract metadata paths, but it
/// must not remove a column after SQLite has already materialized it.
fn statement_projection_preserves_columns(projection: &[String], columns: &[SqliteColumn]) -> bool {
    if projection
        .iter()
        .any(|path| path == "/rows" || path == "/rows/*")
    {
        return true;
    }
    columns.iter().all(|column| {
        let expected = format!("/rows/*/{}", column.name);
        projection.iter().any(|path| path == &expected)
    })
}

/// The parameter name the runtime keeps for its own evaluation instant, so a
/// statement never reads a clock of its own. A bundle that binds the name is
/// rejected.
pub const RESERVED_SQL_PARAMETER: &str = "evidence_now";

/// One reviewed statement, and the bounds its result is read under.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqliteRequest {
    /// The statement itself, held as a bundle artifact so review and revision
    /// reach it the way they reach a script.
    pub statement: ArtifactPath,
    /// The result contract the statement is read against, in result order.
    pub columns: Vec<SqliteColumn>,
    pub selector_inputs: Vec<SelectorInput>,
    /// Statement parameters, by the name the statement binds them under.
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub parameter_bindings: OrderedMap<SqliteParameterBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepare_script: Option<ArtifactPath>,
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub adapter_parameters: OrderedMap<AdapterParameterValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_parameters_schema: Option<ArtifactPath>,
    /// Bounds on what `prepare_script` may return, written only where there is
    /// a preparation script to bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preparation_limits: Option<SqlitePreparationLimits>,
    pub maximum_rows: BoundedU64<1, 256>,
    pub maximum_cell_bytes: BoundedU64<1, 65_536>,
    pub maximum_statement_steps: BoundedU64<1, 1_000_000>,
    pub projection: UniqueList<String>,
    pub timeout_milliseconds: BoundedU64<1, 30_000>,
    pub maximum_response_bytes: BoundedU64<1, 1_048_576>,
    pub concurrency_limit: BoundedU32<1, 256>,
}

impl SqliteRequest {
    fn validate(&self) -> Result<(), ConfigError> {
        require_artifact_prefix(&self.statement, "queries/")?;
        if !self.statement.as_str().ends_with(".sql") {
            return invalid("source statement must be a SQL file");
        }
        validate_len(self.columns.len(), 1, 64, "statement columns")?;
        let mut column_names = BTreeSet::new();
        for column in &self.columns {
            if !valid_field_name(&column.name) || !column_names.insert(column.name.as_str()) {
                return invalid("statement column names must be valid and unique");
            }
        }
        validate_selector_inputs(&self.selector_inputs)?;
        validate_len(
            self.parameter_bindings.len(),
            0,
            64,
            "statement parameter bindings",
        )?;
        for (name, binding) in self.parameter_bindings.iter() {
            if !valid_parameter_key(name) {
                return invalid("statement parameter name is invalid");
            }
            if name == RESERVED_SQL_PARAMETER {
                return invalid("statement parameter name is reserved by the runtime");
            }
            // A prepared name travels back from the preparation script, and the
            // preparation ABI admits 64 bytes of parameter name, half of what a
            // binding key may carry. A longer prepared name is a deployment that
            // loads and can never execute: a script returning the name is
            // refused by the ABI, and a script omitting it leaves the parameter
            // unfilled. A selector binding is filled from the request and never
            // crosses that boundary, so it keeps the full key bound.
            if matches!(binding, SqliteParameterBinding::Prepared {}) && name.len() > 64 {
                return invalid("prepared statement parameter name is too long to be prepared");
            }
            binding.validate()?;
        }
        if let Some(prepare_script) = &self.prepare_script {
            require_artifact_prefix(prepare_script, "adapters/")?;
            if !prepare_script.as_str().ends_with(".rhai") {
                return invalid("source preparation script must be a Rhai file");
            }
        }
        validate_len(self.adapter_parameters.len(), 0, 64, "adapter parameters")?;
        for (name, value) in self.adapter_parameters.iter() {
            if !valid_parameter_key(name) {
                return invalid("adapter parameter name is invalid");
            }
            value.validate(0)?;
        }
        match &self.adapter_parameters_schema {
            Some(schema) => require_artifact_prefix(schema, "schemas/")?,
            // Parameters a reviewer cannot check against a closed schema are
            // parameters the extraction script reads unchecked.
            None if !self.adapter_parameters.is_empty() => {
                return invalid("adapter parameters require their closed schema")
            }
            None => {}
        }
        // A script with nothing prepared to fill could only ever return a name
        // the source refuses, and a prepared parameter with no script could
        // never be filled at all, so the two are written together or not at all.
        let prepared_parameters = self
            .parameter_bindings
            .iter()
            .filter(|(_, binding)| matches!(binding, SqliteParameterBinding::Prepared {}))
            .count() as u64;
        match (&self.prepare_script, prepared_parameters) {
            (Some(_), 0) => return invalid("statement preparation requires a prepared parameter"),
            (None, 1..) => return invalid("a prepared parameter requires a preparation script"),
            _ => {}
        }
        // Bounds on a preparation that does not happen say nothing, and a
        // preparation nobody bounded is unbounded, so the two are written
        // together or not at all.
        match (&self.prepare_script, &self.preparation_limits) {
            (Some(_), Some(limits)) => {
                // A script allowed to return fewer parameters than the source
                // declares prepared can never fill them all, so the bound is
                // read against the work it has to admit.
                if limits.maximum_parameters.get() < prepared_parameters {
                    return invalid(
                        "statement preparation limits must admit every prepared parameter",
                    );
                }
            }
            (Some(_), None) => {
                return invalid("statement preparation requires its preparation limits")
            }
            (None, Some(_)) => {
                return invalid("statement preparation limits require a preparation script")
            }
            (None, None) => {}
        }
        validate_projection(&self.projection)?;
        if !statement_projection_preserves_columns(&self.projection, &self.columns) {
            return invalid("statement projection must preserve every declared result column");
        }

        Ok(())
    }
}

/// One column of a statement result, named and typed by the deployment.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqliteColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub value_type: SqliteColumnType,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SqliteColumnType {
    String,
    Integer,
    Number,
    Boolean,
}

/// How one statement parameter is filled.
///
/// A parameter has one origin and exactly one, so reading the declared bindings
/// is enough to know where every value the statement binds came from.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SqliteParameterBinding {
    Selector {
        role: String,
        profile: String,
        field: String,
    },
    /// Filled by the preparation script, for a value no selector holds: a
    /// normalized reference, a derived bound. It names no selector because
    /// naming one would be a second origin.
    ///
    /// Written as a braced variant with no fields rather than a unit variant,
    /// because serde applies `deny_unknown_fields` to an internally tagged unit
    /// variant's siblings and not to the variant itself, so a unit variant would
    /// silently accept `{kind: prepared, role: subject}`.
    Prepared {},
}

registry_platform_yaml::tagged_union!(SqliteParameterBinding, tag = "kind");
serialize_tagged_union!(SqliteParameterBinding, tag = "kind");

impl SqliteParameterBinding {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Selector {
                role,
                profile,
                field,
            } => {
                if !valid_local_id(role) || !valid_local_id(profile) || !valid_field_name(field) {
                    return invalid("source selector binding identifier is invalid");
                }
            }
            Self::Prepared {} => {}
        }
        Ok(())
    }
}

/// What a statement source's preparation script may produce.
///
/// A statement takes no query string and no request body, so the script's one
/// output channel is a `parameters` map, and a parameter value is a scalar
/// bound straight into the statement. Two things about that map are not
/// settled anywhere else in the source, so they are settled here: how many
/// entries the script may return, and how large one entry's value may be.
/// Nothing further needs a bound, because an integer and a boolean are
/// fixed-width, and a returned parameter is only usable under a name the
/// source declares as a prepared `parameterBindings` key, which
/// [`SqliteRequest::validate`] holds to the preparation ABI's own name bound.
///
/// `kernel.rs` compiles these bounds into the script host beside the compiled
/// script, the way it does for the HTTP transport's own [`PreparationLimits`],
/// and the host applies them to the returned `parameters` map before any value
/// reaches the statement.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqlitePreparationLimits {
    /// Entries the returned `parameters` map may carry.
    pub maximum_parameters: BoundedU64<1, 64>,
    /// Bytes one returned parameter value may carry.
    pub maximum_parameter_value_bytes: BoundedU64<1, 4_096>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum HttpMethod {
    GET,
    POST,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RedirectPolicy {
    Deny,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectorInput {
    pub role: String,
    pub alternatives: Vec<SelectorInputAlternative>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorInputAlternative {
    pub profile: String,
    pub fields: UniqueList<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PathBindingConfig {
    Selector {
        role: String,
        profile: String,
        field: String,
    },
    PriorFact {
        field: String,
    },
}

registry_platform_yaml::tagged_union!(PathBindingConfig, tag = "from");
serialize_tagged_union!(PathBindingConfig, tag = "from");

impl PathBindingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Selector {
                role,
                profile,
                field,
            } => {
                if !valid_local_id(role) || !valid_local_id(profile) || !valid_field_name(field) {
                    return invalid("source selector binding identifier is invalid");
                }
            }
            Self::PriorFact { field } => {
                if !valid_field_name(field) {
                    return invalid("source prior-fact binding identifier is invalid");
                }
            }
        }
        Ok(())
    }

    pub fn is_prior_fact(&self) -> bool {
        matches!(self, Self::PriorFact { .. })
    }
}

/// One adapter parameter value: a scalar, a list of values, or a mapping of
/// values, chosen by the node's kind (CFG-SCHEMA-8).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AdapterParameterValue {
    Scalar(ScalarParameter),
    Array(Vec<AdapterParameterValue>),
    Object(OrderedMap<AdapterParameterValue>),
}

registry_platform_yaml::shape_union!(AdapterParameterValue {
    scalar => Scalar,
    list => Array,
    mapping => Object,
});

impl Serialize for AdapterParameterValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Scalar(value) => value.serialize(serializer),
            Self::Array(values) => values.serialize(serializer),
            Self::Object(values) => values.serialize(serializer),
        }
    }
}

/// One scalar parameter value: text, an integer, or a boolean, as the
/// scalar resolves. Any other scalar is refused.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ScalarParameter {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl<'de> Deserialize<'de> for ScalarParameter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ScalarVisitor;

        impl Visitor<'_> for ScalarVisitor {
            type Value = ScalarParameter;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("text, an integer, or a boolean")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(ScalarParameter::Boolean(value))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(ScalarParameter::Integer(value))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                i64::try_from(value)
                    .map(ScalarParameter::Integer)
                    .map_err(|_| E::custom(Invalid::out_of_range(i64::MIN, i64::MAX)))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(ScalarParameter::String(value.to_owned()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(ScalarParameter::String(value))
            }
        }

        deserializer.deserialize_any(ScalarVisitor)
    }
}

impl Serialize for ScalarParameter {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::String(value) => serializer.serialize_str(value),
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::Boolean(value) => serializer.serialize_bool(*value),
        }
    }
}

impl AdapterParameterValue {
    fn validate(&self, depth: usize) -> Result<(), ConfigError> {
        if depth > 32 {
            return invalid("adapter parameter nesting exceeds Version 1 bounds");
        }
        match self {
            Self::Scalar(ScalarParameter::Boolean(_) | ScalarParameter::Integer(_)) => Ok(()),
            Self::Scalar(ScalarParameter::String(value)) => {
                validate_string(value, 0, 16_384, "adapter parameter string")
            }
            Self::Array(values) => {
                validate_len(values.len(), 0, 256, "adapter parameter array")?;
                for value in values {
                    value.validate(depth + 1)?;
                }
                Ok(())
            }
            Self::Object(values) => {
                validate_len(values.len(), 0, 256, "adapter parameter object")?;
                for (name, value) in values.iter() {
                    if !valid_parameter_key(name) {
                        return invalid("adapter parameter object key is invalid");
                    }
                    value.validate(depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparationLimits {
    pub query: PreparationChannelPolicy,
    pub json_body: PreparationChannelPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_query_pairs: Option<BoundedU64<1, 64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_query_name_bytes: Option<BoundedU64<1, 64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_query_value_bytes: Option<BoundedU64<1, 4_096>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_json_depth: Option<BoundedU64<1, 32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_collection_items: Option<BoundedU64<1, 256>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_string_bytes: Option<BoundedU64<1, 16_384>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_normalized_bytes: Option<BoundedU64<1, 65_536>>,
}

impl PreparationLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.query == PreparationChannelPolicy::Forbidden
            && self.json_body == PreparationChannelPolicy::Forbidden
        {
            return invalid("at least one preparation output channel must be usable");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PreparationChannelPolicy {
    Required,
    Allowed,
    Forbidden,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityProfile {
    pub kind: AuthorityKind,
    /// Restrict this profile to the verified actor kind. Required for agents
    /// exercising standing authority without an authenticated task grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<registry_platform_oidc::ActorKind>,
    pub requester_tags: UniqueList<String>,
    /// Verified OAuth clients allowed to exercise a grant-bound authority
    /// path. Required only when one of this profile's subjects is sourced from
    /// an authenticated task grant.
    #[serde(default, skip_serializing_if = "<[String]>::is_empty")]
    pub requester_clients: UniqueList<String>,
    /// Trusted issuer that supplied the immutable grant context before token
    /// exchange. The resource server compares it exactly with the signed grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_source_issuer: Option<String>,
    pub grants: Vec<AuthorityGrant>,
}

impl AuthorityProfile {
    fn uses_task_grant(&self) -> bool {
        self.grants.iter().any(|grant| {
            grant
                .subjects
                .iter()
                .any(|subject| subject.value_origin == ValueOrigin::AuthenticatedGrant)
        })
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_strings(&self.requester_tags, 1, 32, 1, 128, "requester tags")?;
        if self.requester_tags.iter().any(|tag| !valid_local_id(tag)) {
            return invalid("requester tag is invalid");
        }
        validate_strings(
            &self.requester_clients,
            0,
            32,
            1,
            128,
            "authority requester clients",
        )?;
        validate_len(self.grants.len(), 1, 128, "authority grants")?;
        for grant in &self.grants {
            grant.validate()?;
        }
        if self.uses_task_grant() {
            validate_len(
                self.requester_clients.len(),
                1,
                32,
                "task-grant requester clients",
            )?;
            let source = self
                .grant_source_issuer
                .as_deref()
                .ok_or(ConfigError::Invalid(
                    "task-grant authority profile requires grantSourceIssuer",
                ))?;
            validate_uri(source)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityKind {
    Statutory,
    Organizational,
    Consent,
    Delegated,
    ExplicitRequest,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityGrant {
    pub requirement: String,
    pub purpose: String,
    pub audience_from: AudienceFrom,
    /// Closed response formats this complete grant permits. Selection through
    /// the API creates no permission; the bundle formats and this grant must
    /// both allow the requested format. Formats are never unioned across
    /// grants.
    #[serde(default = "default_response_formats")]
    pub response_formats: Vec<ResponseFormat>,
    /// Closed subject-binding modes this complete grant permits. Omission and
    /// an explicit empty list both mean audience-scoped alone, so a grant that
    /// was widened to permit a serialization does not thereby gain the right to
    /// issue under another binding mode. The two permissions are separate on
    /// purpose: one names how a response is serialized, the other names what
    /// the subject bindings inside it are derived under.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_binding_modes: Vec<SubjectBindingMode>,
    pub subjects: Vec<GrantedSubject>,
}

impl AuthorityGrant {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_uri(&self.requirement)?;
        validate_purpose(&self.purpose)?;
        validate_response_formats(&self.response_formats, "authority grant response formats")?;
        validate_subject_binding_modes(&self.subject_binding_modes)?;
        validate_len(self.subjects.len(), 1, 8, "authority grant subjects")
    }

    /// Report whether this one complete matched grant permits the binding mode.
    /// Permissions are never unioned across grants.
    pub fn permits_subject_binding(&self, mode: SubjectBindingMode) -> bool {
        if self.subject_binding_modes.is_empty() {
            return mode == SubjectBindingMode::AudienceScoped;
        }
        self.subject_binding_modes.contains(&mode)
    }
}

fn validate_subject_binding_modes(modes: &[SubjectBindingMode]) -> Result<(), ConfigError> {
    validate_len(modes.len(), 0, 2, "authority grant subject binding modes")?;
    let mut seen = BTreeSet::new();
    for mode in modes {
        if !seen.insert(subject_binding_mode_discriminant(*mode)) {
            return invalid("authority grant subject binding modes must be unique");
        }
    }
    Ok(())
}

fn subject_binding_mode_discriminant(mode: SubjectBindingMode) -> u8 {
    match mode {
        SubjectBindingMode::AudienceScoped => 0,
        SubjectBindingMode::HolderBound => 1,
    }
}

/// Closed Version 1 response-format vocabulary.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseFormat {
    SignedJws,
    UnsignedJson,
    /// Audience-scoped SD-JWT VC serialization of the same assertion.
    SdJwtVc,
    /// Holder-bound issuance container carrying one SD-JWT VC serialization per
    /// presented holder key.
    SdJwtVcBatch,
}

fn default_response_formats() -> Vec<ResponseFormat> {
    vec![ResponseFormat::SignedJws]
}

fn validate_response_formats(
    formats: &[ResponseFormat],
    description: &'static str,
) -> Result<(), ConfigError> {
    validate_len(formats.len(), 1, 4, description)?;
    let mut seen = BTreeSet::new();
    for format in formats {
        if !seen.insert(format_discriminant(*format)) {
            return invalid("response formats must be unique");
        }
    }
    if !formats.contains(&ResponseFormat::SignedJws) {
        return invalid("signed JWS must remain an enabled response format");
    }
    Ok(())
}

fn format_discriminant(format: ResponseFormat) -> u8 {
    match format {
        ResponseFormat::SignedJws => 0,
        ResponseFormat::UnsignedJson => 1,
        ResponseFormat::SdJwtVc => 2,
        ResponseFormat::SdJwtVcBatch => 3,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AudienceFrom {
    AuthenticatedRequester,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedSubject {
    pub role: String,
    pub selector_profile: String,
    pub value_origin: ValueOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_claims: Option<OrderedMap<String>>,
}

impl GrantedSubject {
    fn validate_value_claims(&self, profile: &SelectorProfile) -> Result<(), ConfigError> {
        if !valid_local_id(&self.role) || !valid_local_id(&self.selector_profile) {
            return invalid("authority subject identifier is invalid");
        }
        match self.value_origin {
            ValueOrigin::Request => {
                if self.value_claims.is_some() {
                    return invalid("request-derived subject must not define valueClaims");
                }
            }
            ValueOrigin::AuthenticatedContext | ValueOrigin::AuthenticatedGrant => {
                let claims = self.value_claims.as_ref().ok_or(ConfigError::Invalid(
                    "context-derived subject requires valueClaims",
                ))?;
                if claims.len() != profile.fields.len()
                    || profile
                        .fields
                        .keys()
                        .any(|field| !claims.contains_key(field))
                    || claims
                        .keys()
                        .any(|field| !profile.fields.contains_key(field))
                {
                    return invalid("valueClaims must exactly equal selector profile fields");
                }
                let mut targets = BTreeSet::new();
                for (_, claim) in claims.iter() {
                    validate_claim_path(claim)?;
                    if !targets.insert(claim.as_str()) {
                        return invalid("valueClaims targets must be unique");
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueOrigin {
    AuthenticatedContext,
    AuthenticatedGrant,
    Request,
}

/// The closed set of acquisition kinds a bundle must opt in to before a
/// deployment serves them, in the order the forms were added.
///
/// The Version 1 forms are deliberately absent: `single` and `search-then-fetch`
/// are the frozen acquisition surface every bundle already had, so declaring
/// them would say nothing, and omitting them would have to mean something. A
/// capability list therefore names only the forms added after that surface
/// froze, and a bundle written before any of them existed keeps serving exactly
/// what it served before without carrying a list at all.
pub const SOURCE_BATCH_CAPABILITY: &str = "source-batch";
const GATED_ACQUISITION_KINDS: [&str; 2] = ["search-then-fetch-set", SOURCE_BATCH_CAPABILITY];

/// The gated acquisition kinds one document declares, as a set.
///
/// The gate has two halves written by two people in two files: the bundle
/// author names the kinds the bundle needs, and the operator names the kinds
/// this deployment may serve. Both halves read the same closed vocabulary
/// through this one derivation, so neither can drift into naming a kind the
/// other cannot. Each half supplies its own sentences, because an operator
/// fixes a runtime file and a bundle author fixes a bundle.
fn declared_acquisition_capabilities<'a>(
    capabilities: &'a [String],
    unknown: &'static str,
    duplicate: &'static str,
    field: &'static str,
) -> Result<BTreeSet<&'a str>, ConfigError> {
    // Entry by entry before the collection bound: with one gated kind the
    // bound would otherwise answer a duplicate with generic cardinality
    // where a naming sentence says what to change.
    let mut declared = BTreeSet::new();
    for capability in capabilities {
        if !GATED_ACQUISITION_KINDS.contains(&capability.as_str()) {
            return invalid(unknown);
        }
        if !declared.insert(capability.as_str()) {
            return invalid(duplicate);
        }
    }
    validate_len(capabilities.len(), 0, GATED_ACQUISITION_KINDS.len(), field)?;
    Ok(declared)
}

const MINIMUM_FETCH_SET_MEMBERS: usize = 2;
const MAXIMUM_FETCH_SET_MEMBERS: usize = 4;
const MAXIMUM_FETCH_SET_FACT_INPUTS: usize = 16;
/// The ceiling on the whole fetch-set acquisition, matching the ceiling one
/// source request already carries.
const MAXIMUM_ACQUISITION_MILLISECONDS: u64 = 30_000;

/// The complete bounded evidence-data acquisition profile for one requirement.
///
/// Each named source remains one immutable HTTP request. `search-then-fetch`
/// and `search-then-fetch-set` are the only multi-call forms, and each names
/// every call it may make in configuration, so the acquisition ceiling stays
/// fixed at read time without introducing a general workflow or
/// source-planning model.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AcquisitionConfig {
    Single {
        source: String,
    },
    SearchThenFetch {
        search: String,
        fetch: String,
    },
    SearchThenFetchSet {
        search: String,
        fetch: Vec<FetchSetMember>,
        #[serde(rename = "maximumAcquisitionMilliseconds")]
        maximum_acquisition_milliseconds: BoundedU64<1, MAXIMUM_ACQUISITION_MILLISECONDS>,
    },
}

registry_platform_yaml::tagged_union!(AcquisitionConfig, tag = "kind");
serialize_tagged_union!(AcquisitionConfig, tag = "kind");

impl AcquisitionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Single { source } => {
                if !valid_local_id(source) {
                    return invalid("requirement acquisition source identifier is invalid");
                }
            }
            Self::SearchThenFetch { search, fetch } => {
                if !valid_local_id(search) || !valid_local_id(fetch) || search == fetch {
                    return invalid("search-then-fetch source identifiers are invalid");
                }
            }
            Self::SearchThenFetchSet { search, fetch, .. } => {
                if fetch.len() < MINIMUM_FETCH_SET_MEMBERS {
                    return invalid("requirement acquisition declares too few fetch members");
                }
                if fetch.len() > MAXIMUM_FETCH_SET_MEMBERS {
                    return invalid("requirement acquisition declares too many fetch members");
                }
                if !valid_local_id(search)
                    || fetch.iter().any(|member| !valid_local_id(&member.source))
                {
                    return invalid("search-then-fetch-set source identifiers are invalid");
                }
                let mut members = BTreeSet::new();
                for member in fetch {
                    if !members.insert(member.source.as_str()) {
                        return invalid("requirement acquisition fetch members must be distinct");
                    }
                    if &member.source == search {
                        return invalid(
                            "requirement acquisition fetch member repeats the search source",
                        );
                    }
                    member.validate()?;
                }
            }
        }
        Ok(())
    }

    pub fn source_ids(&self) -> Vec<&str> {
        match self {
            Self::Single { source } => vec![source.as_str()],
            Self::SearchThenFetch { search, fetch } => {
                vec![search.as_str(), fetch.as_str()]
            }
            Self::SearchThenFetchSet { search, fetch, .. } => std::iter::once(search.as_str())
                .chain(fetch.iter().map(|member| member.source.as_str()))
                .collect(),
        }
    }

    pub fn uses_source(&self, source_id: &str) -> bool {
        self.source_ids().contains(&source_id)
    }

    pub fn initial_source(&self) -> &str {
        match self {
            Self::Single { source } => source,
            Self::SearchThenFetch { search, .. } | Self::SearchThenFetchSet { search, .. } => {
                search
            }
        }
    }

    /// The sources this acquisition reaches after its search has resolved, and
    /// therefore the only sources that may bind a prior fact into a request.
    pub fn fetch_sources(&self) -> Vec<&str> {
        match self {
            Self::Single { .. } => Vec::new(),
            Self::SearchThenFetch { fetch, .. } => vec![fetch.as_str()],
            Self::SearchThenFetchSet { fetch, .. } => {
                fetch.iter().map(|member| member.source.as_str()).collect()
            }
        }
    }

    /// The ordered acquisition this requirement performs, read from
    /// configuration alone: no request, no response, and no clock take part.
    /// Every form describes itself the same way, so the runtime, the offline
    /// fixture harness, and adopter tooling read one derivation of the order
    /// and of what each stage may carry, rather than three that can drift.
    pub fn plan(&self) -> AcquisitionPlan {
        let stage = |source: &String, role, inputs| PlannedStage {
            source: source.clone(),
            role,
            inputs,
        };
        match self {
            Self::Single { source } => AcquisitionPlan {
                stages: vec![stage(source, StageRole::Search, StageInputs::None)],
                budget_milliseconds: None,
            },
            Self::SearchThenFetch { search, fetch } => AcquisitionPlan {
                stages: vec![
                    stage(search, StageRole::Search, StageInputs::None),
                    stage(fetch, StageRole::Member, StageInputs::EveryPriorFact),
                ],
                budget_milliseconds: None,
            },
            Self::SearchThenFetchSet {
                search,
                fetch,
                maximum_acquisition_milliseconds,
            } => AcquisitionPlan {
                stages: std::iter::once(stage(search, StageRole::Search, StageInputs::None))
                    .chain(fetch.iter().map(|member| {
                        stage(
                            &member.source,
                            StageRole::Member,
                            StageInputs::Declared(member.fact_inputs.clone()),
                        )
                    }))
                    .collect(),
                budget_milliseconds: Some(maximum_acquisition_milliseconds.get()),
            },
        }
    }

    /// The acquisition capability a bundle must declare before a deployment
    /// may serve this requirement, or `None` for the frozen Version 1 forms,
    /// which every bundle already carried and so declare nothing.
    pub fn required_capability(&self) -> Option<&'static str> {
        match self {
            Self::Single { .. } | Self::SearchThenFetch { .. } => None,
            Self::SearchThenFetchSet { .. } => Some("search-then-fetch-set"),
        }
    }
}

/// One declared member of a fetch set: a source, and the closed allowlist of
/// search facts that member's request may read.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FetchSetMember {
    pub source: String,
    pub fact_inputs: Vec<String>,
}

impl FetchSetMember {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.fact_inputs.is_empty() {
            return invalid("requirement acquisition fetch member declares no fact inputs");
        }
        if self.fact_inputs.len() > MAXIMUM_FETCH_SET_FACT_INPUTS {
            return invalid("requirement acquisition fetch member declares too many fact inputs");
        }
        let mut names = BTreeSet::new();
        for name in &self.fact_inputs {
            if !valid_field_name(name) {
                return invalid("requirement acquisition fetch member fact input is invalid");
            }
            if !names.insert(name.as_str()) {
                return invalid("requirement acquisition fetch member fact inputs must be unique");
            }
        }
        Ok(())
    }
}

/// The complete ordered acquisition one requirement performs, as a value that
/// can be printed, compared, and tested without executing anything.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcquisitionPlan {
    pub stages: Vec<PlannedStage>,
    /// The ceiling on the whole acquisition, where the form declares one. The
    /// forms that predate the declaration bound each call on its own.
    pub budget_milliseconds: Option<u64>,
}

/// One planned source call: which source, why it is called, and what an
/// earlier stage's facts may contribute to its request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PlannedStage {
    pub source: String,
    pub role: StageRole,
    pub inputs: StageInputs,
}

/// Whether a stage resolves the subject or reads a resolved reference.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StageRole {
    Search,
    Member,
}

/// What an earlier stage's facts may contribute to one stage's request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StageInputs {
    /// Nothing, because no stage has run yet.
    None,
    /// Every fact the preceding stage produced. This is `search-then-fetch` as
    /// Version 1 froze it, and the reason that form stops at one fetch.
    EveryPriorFact,
    /// Only the named search facts, in the order the member declared them.
    Declared(Vec<String>),
}

impl StageInputs {
    /// Narrow the facts an earlier stage produced to what this stage declared.
    /// For a declared allowlist every name is a required search fact, proven
    /// when the bundle validated its fact schemas, so a missing name is
    /// impossible here rather than tolerated: the projection carries no
    /// failure mode of its own.
    pub fn project(
        &self,
        prior_facts: &BTreeMap<String, serde_json::Value>,
    ) -> BTreeMap<String, serde_json::Value> {
        match self {
            Self::None => BTreeMap::new(),
            Self::EveryPriorFact => prior_facts.clone(),
            Self::Declared(names) => names
                .iter()
                .filter_map(|name| {
                    prior_facts
                        .get(name)
                        .map(|value| (name.clone(), value.clone()))
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequirementConfig {
    /// Stable application-facing handle for the complete published
    /// definition. It is explicit rather than inferred from the requirement
    /// URI so URI revisions cannot silently rename application code.
    pub handle: String,
    pub id: String,
    pub kind: RequirementKind,
    /// What the subject bindings in this requirement's assertions are derived
    /// under. Omission means audience-scoped, and the key is omitted when
    /// absent, so every requirement written before binding modes existed keeps
    /// exactly the projected configuration, and therefore exactly the
    /// `configurationRevision`, it already had.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_binding: Option<SubjectBindingMode>,
    pub acquisition: AcquisitionConfig,
    pub purposes: UniqueList<String>,
    pub subject_roles: Vec<SubjectRole>,
    pub reference_frameworks: UniqueList<String>,
    pub evidence_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_timezone: Option<String>,
    pub validity_seconds: BoundedU64<1, 31_536_000>,
    pub derivation: DerivationConfig,
    pub concepts: Vec<ConceptConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixtures: Option<ArtifactPath>,
    pub disclosure_guard: DisclosureGuard,
    pub existence_disclosure: ExistenceDisclosure,
}

impl RequirementConfig {
    pub fn initial_source(&self) -> &str {
        self.acquisition.initial_source()
    }

    /// The binding mode this requirement issues under. An undeclared mode is
    /// audience-scoped, which is what every requirement already did.
    pub fn subject_binding_mode(&self) -> SubjectBindingMode {
        self.subject_binding
            .unwrap_or(SubjectBindingMode::AudienceScoped)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_local_id(&self.handle) {
            return invalid("requirement handle is invalid");
        }
        validate_uri(&self.id)?;
        self.acquisition.validate()?;
        validate_strings(&self.purposes, 1, 32, 1, 128, "requirement purposes")?;
        for purpose in &self.purposes {
            validate_purpose(purpose)?;
        }
        validate_len(self.subject_roles.len(), 1, 8, "requirement subject roles")?;
        let mut roles = BTreeSet::new();
        for role in &self.subject_roles {
            role.validate()?;
            if !roles.insert(role.role.as_str()) {
                return invalid("requirement subject roles must be unique");
            }
        }
        validate_strings(
            &self.reference_frameworks,
            1,
            16,
            1,
            512,
            "reference frameworks",
        )?;
        for reference in &self.reference_frameworks {
            validate_uri(reference)?;
        }
        validate_uri(&self.evidence_type)?;
        if let Some(timezone) = &self.observation_timezone {
            validate_string(timezone, 1, 128, "observation timezone")?;
            chrono_tz::Tz::from_str(timezone).map_err(|_| {
                ConfigError::Invalid("observation timezone is not an IANA timezone")
            })?;
        }
        self.derivation.validate()?;
        validate_len(self.concepts.len(), 1, 16, "requirement concepts")?;
        let mut concepts = BTreeSet::new();
        let mut concept_handles = BTreeSet::new();
        let mut sd_jwt_claims = BTreeSet::new();
        for concept in &self.concepts {
            concept.validate()?;
            if !concepts.insert(concept.id.as_str()) {
                return invalid("requirement concepts must be unique");
            }
            if !concept_handles.insert(concept.handle.as_str()) {
                return invalid("requirement concept handles must be unique");
            }
            if let Some(projection) = &concept.sd_jwt_vc {
                if !sd_jwt_claims.insert(projection.claim.as_str()) {
                    return invalid("requirement SD-JWT VC claim names must be unique");
                }
            }
        }
        if let Some(fixtures) = &self.fixtures {
            require_artifact_prefix(fixtures, "fixtures/")?;
        }
        self.disclosure_guard.validate()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementKind {
    Criterion,
    InformationRequirement,
    Constraint,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectRole {
    pub role: String,
    pub cardinality: SubjectCardinality,
    pub selector_profiles: UniqueList<String>,
}

impl SubjectRole {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.role.len() > 64 || !valid_local_id(&self.role) {
            return invalid("subject role identifier is invalid");
        }
        validate_strings(
            &self.selector_profiles,
            1,
            16,
            1,
            128,
            "role selector profiles",
        )?;
        if self
            .selector_profiles
            .iter()
            .any(|profile| !valid_local_id(profile))
        {
            return invalid("role selector profile identifier is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectCardinality {
    One,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DerivationConfig {
    pub script: ArtifactPath,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_inputs: Vec<SelectorInput>,
    pub parameters: OrderedMap<ParameterValue>,
}

impl DerivationConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        require_artifact_prefix(&self.script, "derivations/")?;
        if !self.script.as_str().ends_with(".rhai") {
            return invalid("derivation script must be a Rhai file");
        }
        validate_derivation_input_shape(&self.selector_inputs)?;
        validate_len(self.parameters.len(), 0, 32, "derivation parameters")?;
        for (name, value) in self.parameters.iter() {
            if !valid_field_name(name) {
                return invalid("derivation parameter name is invalid");
            }
            value.validate()?;
        }
        Ok(())
    }
}

/// One derivation parameter value: a scalar, a decimal mapping, or a list of
/// bucket boundaries, chosen by the node's kind (CFG-SCHEMA-8).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParameterValue {
    Scalar(ScalarParameter),
    Decimal(DecimalValue),
    BucketBoundaries(Vec<BucketBoundary>),
}

registry_platform_yaml::shape_union!(ParameterValue {
    scalar => Scalar,
    mapping => Decimal,
    list => BucketBoundaries,
});

impl Serialize for ParameterValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Scalar(value) => value.serialize(serializer),
            Self::Decimal(value) => value.serialize(serializer),
            Self::BucketBoundaries(boundaries) => boundaries.serialize(serializer),
        }
    }
}

impl ParameterValue {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Scalar(ScalarParameter::String(value)) => {
                validate_string(value, 0, 1_024, "derivation string parameter")
            }
            Self::Scalar(ScalarParameter::Integer(value)) => {
                if value.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                    invalid("derivation integer parameter exceeds safe bounds")
                } else {
                    Ok(())
                }
            }
            Self::Scalar(ScalarParameter::Boolean(_)) => Ok(()),
            Self::Decimal(value) => value.validate(),
            Self::BucketBoundaries(boundaries) => validate_bucket_boundaries(boundaries),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecimalValue {
    #[serde(rename = "type")]
    pub value_type: DecimalMarker,
    pub value: String,
}

impl DecimalValue {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_decimal(&self.value)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DecimalMarker {
    Decimal,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BucketBoundary {
    pub minimum_inclusive: DecimalValue,
    pub maximum_exclusive: DecimalValue,
    pub code: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConceptConfig {
    /// Stable key used in high-level client result maps.
    pub handle: String,
    pub id: String,
    pub form: ConceptForm,
    pub required: bool,
    #[serde(default)]
    pub constraints: OrderedMap<YamlValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd_jwt_vc: Option<SdJwtVcConceptProjection>,
}

impl ConceptConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_local_id(&self.handle) {
            return invalid("concept handle is invalid");
        }
        validate_uri(&self.id)?;
        validate_len(self.constraints.len(), 0, 32, "concept constraints")?;
        validate_concept_constraints(self)?;
        if let Some(projection) = &self.sd_jwt_vc {
            if self.form != ConceptForm::ReviewedStructuredValue {
                return invalid("SD-JWT VC field projection requires a reviewed structured value");
            }
            projection.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SdJwtVcConceptProjection {
    pub claim: String,
    pub disclosure: SdJwtVcDisclosureMode,
}

impl SdJwtVcConceptProjection {
    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_sd_jwt_claim_name(&self.claim) {
            return invalid("SD-JWT VC structured claim name is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SdJwtVcDisclosureMode {
    TopLevel,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConceptForm {
    Boolean,
    ControlledCode,
    ControlledCategory,
    BoundedIdentifier,
    BoundedInteger,
    BoundedDecimal,
    DateBucket,
    TimeBucket,
    AudienceScopedEntityReference,
    ControlledCodeList,
    EntityReferenceList,
    ReviewedStructuredValue,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureGuard {
    pub families: UniqueList<String>,
}

impl DisclosureGuard {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_strings(&self.families, 1, 16, 1, 512, "disclosure families")?;
        for family in &self.families {
            validate_uri(family)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExistenceDisclosure {
    CollapseUnresolved,
}

/// Validate a map of named items written at `pointer`: its size, each name,
/// and each item, naming the item a rule concerns.
fn validate_named_map<T>(
    map: &OrderedMap<T>,
    minimum: usize,
    maximum: usize,
    pointer: &str,
    validate: impl Fn(&T) -> Result<(), ConfigError>,
) -> Result<(), Violation> {
    validate_len(map.len(), minimum, maximum, "named configuration map").at(pointer)?;
    for (name, value) in map.iter() {
        let at = named(pointer, name);
        if !valid_local_id(name) {
            return invalid("local identifier is invalid").at_key(at);
        }
        validate(value).at(at)?;
    }
    Ok(())
}

/// The pointer of the item `name` inside the map at `pointer`.
fn named(pointer: &str, name: &str) -> String {
    format!(
        "{pointer}/{}",
        registry_platform_yaml::escape_pointer_segment(name)
    )
}

/// One rule a decoded bundle breaks and the member it concerns, as an RFC
/// 6901 pointer into the document. The error carries a fixed cause, so the
/// violation never repeats a value from the document (CFG-SEC-3).
#[derive(Debug)]
pub(crate) struct Violation {
    pub(crate) pointer: String,
    /// Whether the rule concerns the member's key, as a malformed item name
    /// does, rather than its value.
    pub(crate) at_key: bool,
    pub(crate) error: ConfigError,
}

/// Names the member a failed check concerns.
trait At<T> {
    fn at(self, pointer: impl Into<String>) -> Result<T, Violation>;
    fn at_key(self, pointer: impl Into<String>) -> Result<T, Violation>;
}

impl<T> At<T> for Result<T, ConfigError> {
    fn at(self, pointer: impl Into<String>) -> Result<T, Violation> {
        self.map_err(|error| Violation {
            pointer: pointer.into(),
            at_key: false,
            error,
        })
    }

    fn at_key(self, pointer: impl Into<String>) -> Result<T, Violation> {
        self.map_err(|error| Violation {
            pointer: pointer.into(),
            at_key: true,
            error,
        })
    }
}

fn require_artifact_prefix(path: &ArtifactPath, prefix: &'static str) -> Result<(), ConfigError> {
    if path.as_str().starts_with(prefix) {
        Ok(())
    } else {
        invalid("artifact path has the wrong bundle directory")
    }
}

fn validate_selector_inputs(inputs: &[SelectorInput]) -> Result<(), ConfigError> {
    validate_len(inputs.len(), 0, 8, "source selector inputs")?;
    validate_derivation_input_shape(inputs)
}

fn validate_derivation_input_shape(inputs: &[SelectorInput]) -> Result<(), ConfigError> {
    validate_len(inputs.len(), 0, 8, "selector inputs")?;
    let mut roles = BTreeSet::new();
    for input in inputs {
        if !valid_local_id(&input.role) || !roles.insert(input.role.as_str()) {
            return invalid("selector-input roles must be valid and unique");
        }
        validate_len(
            input.alternatives.len(),
            1,
            16,
            "selector-input alternatives",
        )?;
        let mut profiles = BTreeSet::new();
        for alternative in &input.alternatives {
            if !valid_local_id(&alternative.profile)
                || !profiles.insert(alternative.profile.as_str())
            {
                return invalid("selector-input profiles must be valid and unique per role");
            }
            validate_strings(&alternative.fields, 1, 16, 1, 64, "selector-input fields")?;
            if alternative
                .fields
                .iter()
                .any(|field| !valid_field_name(field))
            {
                return invalid("selector-input field name is invalid");
            }
        }
    }
    Ok(())
}

fn validate_derivation_selector_inputs(
    requirement: &RequirementConfig,
    profiles: &OrderedMap<SelectorProfile>,
) -> Result<(), ConfigError> {
    for input in &requirement.derivation.selector_inputs {
        let role = requirement
            .subject_roles
            .iter()
            .find(|role| role.role == input.role)
            .ok_or(ConfigError::Invalid(
                "derivation selector input references an unknown requirement role",
            ))?;
        for alternative in &input.alternatives {
            if !role.selector_profiles.contains(&alternative.profile) {
                return invalid(
                    "derivation selector input profile is not allowed for the requirement role",
                );
            }
            let profile = profiles
                .get(&alternative.profile)
                .ok_or(ConfigError::Invalid(
                    "derivation selector input references an unknown selector profile",
                ))?;
            if alternative
                .fields
                .iter()
                .any(|field| !profile.fields.contains_key(field))
            {
                return invalid("derivation selector input references an unknown selector field");
            }
        }
    }
    Ok(())
}

fn validate_fixed_headers(headers: &[FixedHeader]) -> Result<(), ConfigError> {
    validate_len(headers.len(), 0, 32, "fixed headers")?;
    let mut names = BTreeSet::new();
    for header in headers {
        validate_configurable_header_name(&header.name)?;
        if !names.insert(header.name.to_ascii_lowercase()) {
            return invalid("fixed header names must be unique ignoring ASCII case");
        }
        validate_string(&header.value, 0, 4_096, "fixed header value")?;
        if header.value.chars().any(char::is_control) {
            return invalid("fixed header value contains a control character");
        }
    }
    Ok(())
}

fn validate_configurable_header_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().all(is_http_token_byte)
        || is_reserved_header_name(name)
    {
        return invalid("configured header name is prohibited");
    }
    Ok(())
}

pub(crate) fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

const fn is_false(value: &bool) -> bool {
    !*value
}

/// The complete closed set of header names no bundle may configure.
///
/// Authentication, host and routing, cookie, framing, hop-by-hop, forwarding,
/// proxy, and tracing headers are owned by Rust or by the operator's network
/// path. A bundle that could set them could redirect a source request, forge a
/// client identity, or smuggle a second request past the reviewed contract.
const RESERVED_HEADER_NAMES: [&str; 40] = [
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
    "host",
    "cookie",
    "set-cookie",
    "content-length",
    "content-type",
    "transfer-encoding",
    "expect",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "forwarded",
    "via",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-appengine-user-ip",
    "x-azure-clientip",
    "traceparent",
    "tracestate",
    "baggage",
    "b3",
    "x-cloud-trace-context",
    "x-request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-original-url",
    "x-rewrite-url",
    "x-original-method",
    "registry-access-requester",
    "registry-access-purpose",
];

/// The complete closed set of reserved header-name prefix families.
///
/// A prefix family is denied before any exact name so that a new vendor
/// forwarding or tracing member cannot be configured before this contract
/// learns its exact name.
const RESERVED_HEADER_PREFIXES: [&str; 7] = [
    "x-forwarded-",
    "proxy-",
    "sec-",
    "x-b3-",
    "x-envoy-",
    "x-datadog-",
    "x-http-method",
];

/// Representative reserved names, case variants, and prefix-family members.
///
/// Both the startup configuration contract and the source plan compiler are
/// tested against this one list, which is how their shared classifier is
/// proven to be a single closed deny set rather than two drifting copies.
pub const RESERVED_HEADER_CONTRACT_CASES: [&str; 53] = [
    "Authorization",
    "authorization",
    "AUTHORIZATION",
    "Proxy-Authorization",
    "Proxy-Authenticate",
    "WWW-Authenticate",
    "Host",
    "Cookie",
    "Set-Cookie",
    "Content-Length",
    "Content-Type",
    "Transfer-Encoding",
    "Expect",
    "Connection",
    "Keep-Alive",
    "TE",
    "Trailer",
    "Upgrade",
    "Proxy-Connection",
    "Forwarded",
    "Via",
    "X-Real-IP",
    "X-Client-IP",
    "x-client-ip",
    "X-Cluster-Client-IP",
    "True-Client-IP",
    "true-client-ip",
    "CF-Connecting-IP",
    "cf-connecting-ip",
    "Fastly-Client-IP",
    "X-Appengine-User-IP",
    "X-Azure-ClientIP",
    "TraceParent",
    "Tracestate",
    "Baggage",
    "b3",
    "B3",
    "X-Cloud-Trace-Context",
    "X-Request-ID",
    "X-Correlation-ID",
    "X-Amzn-Trace-ID",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "X-Original-Method",
    "X-Forwarded-For",
    "X-Forwarded-Proto",
    "X-B3-TraceId",
    "X-Envoy-External-Address",
    "X-Datadog-Trace-Id",
    "Sec-Fetch-Mode",
    "Registry-Access-Requester",
    "Registry-Access-Purpose",
];

/// The one closed reserved-header classifier.
///
/// `name` may be in any ASCII case. Configuration validation rejects a
/// reserved name at startup and source plan compilation rejects it again
/// before any credential is resolved, so both call sites share this function
/// rather than duplicating the deny set.
pub(crate) fn is_reserved_header_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    RESERVED_HEADER_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || RESERVED_HEADER_NAMES.contains(&name.as_str())
}

fn validate_path_template(
    template: &str,
    bindings: &OrderedMap<PathBindingConfig>,
) -> Result<(), ConfigError> {
    validate_string(template, 2, 2_048, "source path template")?;
    if !template.starts_with('/')
        || template.starts_with("//")
        || template.contains(['?', '#', '\\'])
        || !template.is_ascii()
    {
        return invalid("source path template is invalid");
    }
    let mut placeholders = BTreeSet::new();
    let mut normalized = String::new();
    for segment in template.split('/').skip(1) {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return invalid("source path template contains an empty or dot segment");
        }
        normalized.push('/');
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|segment| segment.strip_suffix('}'))
        {
            if !valid_field_name(name) || !placeholders.insert(name) {
                return invalid("source path-template placeholders must be valid and unique");
            }
            normalized.push('x');
        } else {
            if segment.contains(['{', '}']) {
                return invalid("source path-template placeholder must occupy a complete segment");
            }
            normalized.push_str(segment);
        }
    }
    validate_normalized_request_path(&normalized)?;
    if placeholders.is_empty() || placeholders != bindings.keys().collect::<BTreeSet<_>>() {
        return invalid("pathBindings must exactly match path-template placeholders");
    }
    for (_, binding) in bindings.iter() {
        binding.validate()?;
    }
    Ok(())
}

fn validate_projection(projection: &[String]) -> Result<(), ConfigError> {
    validate_strings(projection, 1, 64, 2, 256, "source projection")?;
    let paths = projection
        .iter()
        .map(|path| parse_projection_pointer(path))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            if projection_paths_overlap(left, right) {
                return invalid("source projection paths must not duplicate or overlap");
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ProjectionSegment {
    Wildcard,
    Key(String),
}

fn parse_projection_pointer(pointer: &str) -> Result<Vec<ProjectionSegment>, ConfigError> {
    if !pointer.starts_with('/')
        || pointer.starts_with("//")
        || pointer.chars().any(char::is_control)
    {
        return invalid("source projection is not an extended JSON Pointer");
    }
    pointer[1..]
        .split('/')
        .map(|raw| {
            if raw.is_empty() {
                return invalid("source projection contains an empty segment");
            }
            if raw == "*" {
                return Ok(ProjectionSegment::Wildcard);
            }
            let mut decoded = String::with_capacity(raw.len());
            let mut chars = raw.chars();
            while let Some(character) = chars.next() {
                if character == '~' {
                    match chars.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        _ => return invalid("source projection contains an invalid escape"),
                    }
                } else {
                    decoded.push(character);
                }
            }
            Ok(ProjectionSegment::Key(decoded))
        })
        .collect()
}

fn projection_paths_overlap(left: &[ProjectionSegment], right: &[ProjectionSegment]) -> bool {
    let common = left.len().min(right.len());
    left.iter().zip(right).take(common).all(|(left, right)| {
        left == right
            || matches!(left, ProjectionSegment::Wildcard)
            || matches!(right, ProjectionSegment::Wildcard)
    })
}

fn validate_source_origin(value: &str) -> Result<(), ConfigError> {
    let url = validate_source_url(value, true)?;
    if url.path() != "/" || url.query().is_some() {
        return invalid("source baseUrl must contain only scheme, host, and optional port");
    }
    Ok(())
}

/// Validate the only credential-free source boundary.
///
/// This is deliberately narrower than the numeric-loopback exception used by
/// authenticated deterministic source mocks. The unauthenticated local mode
/// requires one exact origin spelling and an explicit port so a tutorial
/// bundle cannot silently inherit a default port, path, alias, or userinfo.
pub(crate) fn validate_local_unauthenticated_source_origin(value: &str) -> Result<(), ConfigError> {
    let url = validate_source_url(value, true)?;
    let port = url.port_or_known_default().ok_or(ConfigError::Invalid(
        "unauthenticated local source origin requires an explicit non-zero port",
    ))?;
    let canonical = match url.host() {
        Some(Host::Ipv4(ip)) if ip.is_loopback() => format!("http://{ip}:{port}"),
        Some(Host::Ipv6(ip)) if ip.is_loopback() => format!("http://[{ip}]:{port}"),
        _ => {
            return invalid(
                "unauthenticated local source origin must use a numeric loopback HTTP host",
            )
        }
    };
    if url.scheme() != "http" || value != canonical {
        return invalid(
            "unauthenticated local source origin must be a canonical numeric loopback HTTP origin with an explicit non-zero port",
        );
    }
    Ok(())
}

/// Validate an RFC 8707 resource identifier without rewriting its governed bytes.
/// It is an identifier in a form body, not an origin Evidence will connect to.
pub(crate) fn validate_oauth_resource(value: &str) -> Result<(), ConfigError> {
    let invalid_resource = || {
        ConfigError::Invalid(
            "OAuth resource must be an absolute URI without a fragment or user information",
        )
    };
    if value.len() > 512 || !registry_platform_httputil::valid_resource_uri(value) {
        return Err(invalid_resource());
    }
    Ok(())
}

fn validate_source_url(value: &str, origin_only: bool) -> Result<Url, ConfigError> {
    if !value.bytes().all(is_uri_byte) {
        return invalid("source URL contains characters a URI cannot carry");
    }
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("source URL is invalid"))?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return invalid("source URL contains prohibited authority or fragment data");
    }
    if origin_only && url.query().is_some() {
        return invalid("source origin must not contain a query");
    }
    match url.scheme() {
        "https" => {}
        "http" => {
            match url.host() {
                Some(Host::Ipv4(ip)) if ip.is_loopback() => {}
                Some(Host::Ipv6(ip)) if ip.is_loopback() => {}
                _ => return invalid("insecure source URL must use a numeric loopback host"),
            }
            if !has_canonical_loopback_authority(value) {
                return invalid("insecure source URL host syntax is ambiguous");
            }
        }
        _ => return invalid("source URL scheme is not permitted"),
    }
    Ok(url)
}

/// The characters RFC 3986 admits in a URI without percent-encoding.
///
/// `Url::parse` accepts a wider input and rewrites the difference: it strips
/// tab, newline, and carriage return from anywhere in the string, strips
/// leading and trailing C0 controls and spaces, and percent-encodes or
/// punycodes most of what is left that it does not recognize. A source URL is
/// read twice, once parsed to address the request and once as configured to
/// stand in for a client assertion audience the bundle does not state, so a
/// character the parser rewrites leaves those two naming different strings and
/// signs an audience no authorization server published. Refusing the character
/// keeps them one URL, and costs no deployment that could have worked, because
/// a URI carrying any of these has to percent-encode it anyway.
pub(crate) fn is_uri_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'#'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
        )
}

fn has_canonical_loopback_authority(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if let Some(suffix) = authority.strip_prefix("[::1]") {
        return suffix.is_empty() || valid_port_suffix(suffix);
    }
    let (host, port) = authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if port.is_some_and(|port| !valid_port(port)) {
        return false;
    }
    let octets = host.split('.').collect::<Vec<_>>();
    octets.len() == 4
        && octets[0] == "127"
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && (octet == &"0" || !octet.starts_with('0'))
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u8>().is_ok()
        })
}

fn valid_port_suffix(value: &str) -> bool {
    value.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(value: &str) -> bool {
    !value.starts_with('0') && value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn validate_https_url(value: &str, origin_only: bool) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("HTTPS URL is invalid"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (origin_only && (url.path() != "/" || url.query().is_some()))
    {
        return invalid("HTTPS URL violates the strict origin contract");
    }
    Ok(())
}

fn validate_https_issuer(value: &str) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("HTTPS issuer is invalid"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return invalid("HTTPS issuer violates the exact issuer contract");
    }
    Ok(())
}

fn validate_normalized_request_path(value: &str) -> Result<(), ConfigError> {
    if value.len() < 2
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains(['?', '#', '\\'])
        || !value.is_ascii()
    {
        return invalid("source request path is invalid");
    }
    let mut index = 0;
    let bytes = value.as_bytes();
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
                || bytes[index + 1].is_ascii_lowercase()
                || bytes[index + 2].is_ascii_lowercase()
            {
                return invalid("source request path contains a non-canonical escape");
            }
            let decoded = u8::from_str_radix(&value[index + 1..index + 3], 16)
                .map_err(|_| ConfigError::Invalid("source request path escape is invalid"))?;
            if decoded.is_ascii_alphanumeric()
                || matches!(decoded, b'-' | b'.' | b'_' | b'~' | b'/' | b'\\')
            {
                return invalid("source request path contains an ambiguous escape");
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'-'
            ))
        {
            return invalid("source request path contains a prohibited character");
        }
        index += 1;
    }
    if value
        .split('/')
        .skip(1)
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return invalid("source request path contains a dot segment");
    }
    Ok(())
}

fn validate_bucket_boundaries(boundaries: &[BucketBoundary]) -> Result<(), ConfigError> {
    validate_len(boundaries.len(), 1, 64, "bucket boundaries")?;
    let mut codes = BTreeSet::new();
    let mut previous_maximum: Option<&str> = None;
    for boundary in boundaries {
        boundary.minimum_inclusive.validate()?;
        boundary.maximum_exclusive.validate()?;
        if compare_decimal_text(
            &boundary.minimum_inclusive.value,
            &boundary.maximum_exclusive.value,
        ) != std::cmp::Ordering::Less
        {
            return invalid("bucket interval must be non-empty");
        }
        if previous_maximum.is_some_and(|previous| {
            compare_decimal_text(previous, &boundary.minimum_inclusive.value)
                != std::cmp::Ordering::Equal
        }) {
            return invalid("bucket intervals must be ordered and contiguous");
        }
        if !valid_code(&boundary.code) || !codes.insert(boundary.code.as_str()) {
            return invalid("bucket code is invalid or duplicated");
        }
        previous_maximum = Some(&boundary.maximum_exclusive.value);
    }
    Ok(())
}

fn validate_concept_constraints(concept: &ConceptConfig) -> Result<(), ConfigError> {
    let required: &[&str] = match concept.form {
        ConceptForm::Boolean => &[],
        ConceptForm::ControlledCode => &["codelist", "codelistVersion", "maximumBytes"],
        ConceptForm::ControlledCategory => &[
            "categoryScheme",
            "schemeVersion",
            "maximumBytes",
            "codelist",
        ],
        ConceptForm::BoundedIdentifier => &["prefix", "minimumBytes", "maximumBytes"],
        ConceptForm::BoundedInteger => &["minimum", "maximum"],
        ConceptForm::BoundedDecimal => &["minimum", "maximum", "maximumScale"],
        ConceptForm::DateBucket | ConceptForm::TimeBucket => &["bucketScheme", "schemeVersion"],
        ConceptForm::AudienceScopedEntityReference => &["maximumBytes"],
        ConceptForm::ControlledCodeList => &[
            "codelist",
            "codelistVersion",
            "minimumItems",
            "maximumItems",
            "unique",
        ],
        ConceptForm::EntityReferenceList => &["minimumItems", "maximumItems", "unique"],
        ConceptForm::ReviewedStructuredValue => &["schema", "maximumSerializedBytes"],
    };
    if concept.constraints.len() != required.len()
        || required
            .iter()
            .any(|name| !concept.constraints.contains_key(name))
    {
        return invalid("concept constraints do not exactly match the declared value form");
    }

    match concept.form {
        ConceptForm::Boolean => {}
        ConceptForm::ControlledCode => {
            validate_codelist_constraints(&concept.constraints, "codelistVersion")?;
        }
        ConceptForm::ControlledCategory => {
            validate_uri(yaml_string(&concept.constraints, "categoryScheme")?)?;
            validate_string(
                yaml_string(&concept.constraints, "schemeVersion")?,
                1,
                128,
                "scheme version",
            )?;
            validate_codelist_path(yaml_string(&concept.constraints, "codelist")?)?;
            validate_constraint_u64(&concept.constraints, "maximumBytes", 1, 8_192)?;
        }
        ConceptForm::BoundedIdentifier => {
            let prefix = yaml_string(&concept.constraints, "prefix")?;
            if prefix.is_empty()
                || prefix.len() > 512
                || !prefix.is_ascii()
                || !prefix.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'#')
                })
                || !matches!(
                    prefix.as_bytes().last(),
                    Some(b'.' | b'_' | b'-' | b':' | b'/' | b'#')
                )
            {
                return invalid("bounded identifier prefix is invalid");
            }
            let minimum = validate_constraint_u64(&concept.constraints, "minimumBytes", 1, 1_024)?;
            let maximum = validate_constraint_u64(&concept.constraints, "maximumBytes", 1, 1_024)?;
            if minimum > maximum || maximum <= prefix.len() as u64 {
                return invalid("bounded identifier byte bounds are invalid");
            }
        }
        ConceptForm::BoundedInteger => {
            let minimum = yaml_i64(&concept.constraints, "minimum")?;
            let maximum = yaml_i64(&concept.constraints, "maximum")?;
            if minimum > maximum || minimum < -MAX_SAFE_INTEGER || maximum > MAX_SAFE_INTEGER {
                return invalid("bounded integer constraints are invalid");
            }
        }
        ConceptForm::BoundedDecimal => {
            let minimum = yaml_string(&concept.constraints, "minimum")?;
            let maximum = yaml_string(&concept.constraints, "maximum")?;
            validate_decimal(minimum)?;
            validate_decimal(maximum)?;
            if compare_decimal_text(minimum, maximum) == std::cmp::Ordering::Greater {
                return invalid("bounded decimal constraints are invalid");
            }
            validate_constraint_u64(&concept.constraints, "maximumScale", 0, 9)?;
        }
        ConceptForm::DateBucket | ConceptForm::TimeBucket => {
            validate_uri(yaml_string(&concept.constraints, "bucketScheme")?)?;
            validate_string(
                yaml_string(&concept.constraints, "schemeVersion")?,
                1,
                128,
                "scheme version",
            )?;
        }
        ConceptForm::AudienceScopedEntityReference => {
            validate_constraint_u64(&concept.constraints, "maximumBytes", 1, 8_192)?;
        }
        ConceptForm::ControlledCodeList => {
            validate_codelist_path(yaml_string(&concept.constraints, "codelist")?)?;
            validate_string(
                yaml_string(&concept.constraints, "codelistVersion")?,
                1,
                128,
                "codelist version",
            )?;
            validate_collection_constraints(&concept.constraints)?;
        }
        ConceptForm::EntityReferenceList => validate_collection_constraints(&concept.constraints)?,
        ConceptForm::ReviewedStructuredValue => {
            validate_uri(yaml_string(&concept.constraints, "schema")?)?;
            validate_constraint_u64(&concept.constraints, "maximumSerializedBytes", 1, 65_536)?;
        }
    }
    Ok(())
}

fn validate_codelist_constraints(
    constraints: &OrderedMap<YamlValue>,
    version_key: &str,
) -> Result<(), ConfigError> {
    validate_codelist_path(yaml_string(constraints, "codelist")?)?;
    validate_string(
        yaml_string(constraints, version_key)?,
        1,
        128,
        "codelist version",
    )?;
    validate_constraint_u64(constraints, "maximumBytes", 1, 8_192).map(|_| ())
}

fn validate_collection_constraints(constraints: &OrderedMap<YamlValue>) -> Result<(), ConfigError> {
    let minimum = validate_constraint_u64(constraints, "minimumItems", 1, 64)?;
    let maximum = validate_constraint_u64(constraints, "maximumItems", 1, 64)?;
    if minimum > maximum || !yaml_bool(constraints, "unique")? {
        return invalid("collection constraints are invalid");
    }
    Ok(())
}

fn validate_codelist_path(value: &str) -> Result<(), ConfigError> {
    let path = ArtifactPath::parse(value)?;
    require_artifact_prefix(&path, "codelists/")
}

fn yaml_string<'a>(map: &'a OrderedMap<YamlValue>, key: &str) -> Result<&'a str, ConfigError> {
    map.get(key)
        .and_then(YamlValue::as_str)
        .ok_or(ConfigError::Invalid(
            "concept constraint has the wrong scalar type",
        ))
}

fn yaml_i64(map: &OrderedMap<YamlValue>, key: &str) -> Result<i64, ConfigError> {
    map.get(key)
        .and_then(YamlValue::as_i64)
        .ok_or(ConfigError::Invalid(
            "concept constraint has the wrong integer type",
        ))
}

fn yaml_bool(map: &OrderedMap<YamlValue>, key: &str) -> Result<bool, ConfigError> {
    map.get(key)
        .and_then(YamlValue::as_bool)
        .ok_or(ConfigError::Invalid(
            "concept constraint has the wrong boolean type",
        ))
}

fn validate_constraint_u64(
    map: &OrderedMap<YamlValue>,
    key: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ConfigError> {
    let value = map
        .get(key)
        .and_then(YamlValue::as_u64)
        .ok_or(ConfigError::Invalid(
            "concept constraint has the wrong integer type",
        ))?;
    validate_range(value, minimum, maximum, "concept constraint")?;
    Ok(value)
}

fn validate_decimal(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.starts_with('+')
        || value == "-0"
        || value.starts_with("-0.")
        || value.contains(['e', 'E'])
    {
        return invalid("decimal text is not canonical");
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
        || fraction.is_some_and(|fraction| {
            fraction.is_empty()
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
                || fraction.ends_with('0')
        })
    {
        return invalid("decimal text is not canonical");
    }
    let scale = fraction.map_or(0, str::len);
    let precision = integer.len() + scale;
    if precision > 28 || scale > 9 {
        return invalid("decimal precision or scale exceeds Version 1 bounds");
    }
    Ok(())
}

fn compare_decimal_text(left: &str, right: &str) -> std::cmp::Ordering {
    fn parts(value: &str) -> (bool, &str, &str) {
        let negative = value.starts_with('-');
        let unsigned = value.strip_prefix('-').unwrap_or(value);
        let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
        (negative, integer, fraction)
    }
    let (left_negative, left_integer, left_fraction) = parts(left);
    let (right_negative, right_integer, right_fraction) = parts(right);
    if left_negative != right_negative {
        return if left_negative {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    }
    let magnitude = left_integer
        .len()
        .cmp(&right_integer.len())
        .then_with(|| left_integer.cmp(right_integer))
        .then_with(|| {
            let width = left_fraction.len().max(right_fraction.len());
            left_fraction
                .bytes()
                .chain(std::iter::repeat(b'0'))
                .take(width)
                .cmp(
                    right_fraction
                        .bytes()
                        .chain(std::iter::repeat(b'0'))
                        .take(width),
                )
        });
    if left_negative {
        magnitude.reverse()
    } else {
        magnitude
    }
}

/// Validate a URI-typed bundle scalar against the one identifier definition
/// this repository has.
///
/// `registry_discovery_profile::is_valid_identifier` already carries the
/// character rule the publication projection enforces: an absolute URI carries
/// no control character and no whitespace of any script, only the ASCII space
/// family. Reading that rule from the profile instead of restating a narrower
/// `is_ascii_whitespace` test here keeps the bundle and its projection on one
/// definition, so no scalar can be accepted at load and then refused when the
/// same bytes are published. The 512-byte bound stays local because the
/// profile's own bound is the far looser public-text one.
fn validate_uri(value: &str) -> Result<(), ConfigError> {
    validate_string(value, 1, 512, "URI")?;
    if !registry_discovery_profile::is_valid_identifier(value) {
        return invalid("URI is invalid");
    }
    Ok(())
}

fn validate_absolute_path(value: &str) -> Result<(), ConfigError> {
    let path = Path::new(value);
    if value.len() > 512
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return invalid("absolute operator path is invalid");
    }
    Ok(())
}

fn validate_claim_name(value: &str) -> Result<(), ConfigError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return invalid("claim name is invalid");
    }
    Ok(())
}

fn validate_claim_path(value: &str) -> Result<(), ConfigError> {
    if value.len() > 512 {
        return invalid("claim path is too long");
    }
    for segment in value.split('.') {
        let bytes = segment.as_bytes();
        if bytes.is_empty()
            || !matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
            || !bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return invalid("claim path is invalid");
        }
    }
    Ok(())
}

fn validate_purpose(value: &str) -> Result<(), ConfigError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !matches!(bytes.first(), Some(b'a'..=b'z'))
        || !bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return invalid("purpose code is invalid");
    }
    Ok(())
}

fn valid_local_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_sd_jwt_claim_name(value: &str) -> bool {
    const RESERVED: [&str; 24] = [
        "iss",
        "sub",
        "aud",
        "iat",
        "nbf",
        "exp",
        "vct",
        "id",
        "jti",
        "_sd",
        "_sd_alg",
        "cnf",
        "status",
        "issuedBy",
        "providedBy",
        "supportsRequirement",
        "purpose",
        "audience",
        "assuranceProfile",
        "observedAt",
        "configurationRevision",
        "requestNonce",
        "subjects",
        "structuredValues",
    ];
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && !RESERVED.contains(&value)
}

fn valid_field_name(value: &str) -> bool {
    value.len() <= 64 && valid_local_id(value)
}

fn valid_parameter_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn validate_len(
    length: usize,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ConfigError> {
    if (minimum..=maximum).contains(&length) {
        Ok(())
    } else {
        Err(ConfigError::InvalidField(
            "collection cardinality is outside Version 1 bounds",
            field,
        ))
    }
}

fn validate_range(
    value: u64,
    minimum: u64,
    maximum: u64,
    field: &'static str,
) -> Result<(), ConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::InvalidField(
            "numeric value is outside Version 1 bounds",
            field,
        ))
    }
}

fn validate_string(
    value: &str,
    minimum: usize,
    maximum: usize,
    _field: &'static str,
) -> Result<(), ConfigError> {
    if (minimum..=maximum).contains(&value.len()) && !value.contains('\0') {
        Ok(())
    } else {
        invalid("string length is outside Version 1 bounds")
    }
}

fn validate_unique<T: Ord>(
    values: &[T],
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ConfigError> {
    validate_len(values.len(), minimum, maximum, field)?;
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return invalid("collection values must be unique");
    }
    Ok(())
}

fn validate_strings(
    values: &[String],
    minimum_items: usize,
    maximum_items: usize,
    minimum_bytes: usize,
    maximum_bytes: usize,
    field: &'static str,
) -> Result<(), ConfigError> {
    validate_len(values.len(), minimum_items, maximum_items, field)?;
    for value in values {
        validate_string(value, minimum_bytes, maximum_bytes, field)?;
    }
    Ok(())
}

fn invalid<T>(reason: &'static str) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(reason))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;

    #[test]
    fn a_repeated_string_in_a_set_is_refused_at_the_repeated_item() {
        let bytes = String::from_utf8(
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            )
            .to_vec(),
        )
        .expect("acceptance configuration is UTF-8")
        .replace(
            "requesterTags: [fixture-agency]",
            "requesterTags: [fixture-agency, fixture-agency]",
        );
        let ConfigError::Refused(report) =
            EvidenceConfig::parse_yaml(bytes.as_bytes()).expect_err("a repeated tag is refused")
        else {
            panic!("the refusal is a report");
        };
        let diagnostic = report.diagnostics().first().expect("a diagnostic");
        assert_eq!(diagnostic.code, "config.duplicate-item");
        assert!(
            diagnostic.path.ends_with("/requesterTags/1"),
            "{}",
            diagnostic.path
        );
    }

    #[test]
    fn named_source_connections_reject_retargeting_and_preserve_authentication_defaults() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("acceptance configuration parses");
        let connection: SourceConnectionConfig = serde_json::from_value(serde_json::json!({
            "baseUrl": "https://source.example",
            "authentication": {
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://issuer.example/token",
                "clientIdRef": "secret:file/client-id",
                "clientAssertionKeyRef": "secret:file/client-key",
                "clientAssertionAudience": "https://issuer.example/client-auth",
                "audience": "https://resource.example",
                "resource": "https://resource.example/records",
                "maximumCacheSeconds": 60
            },
            "tlsTrustProfile": "private-ca"
        }))
        .expect("the complete authentication union parses");
        assert_eq!(connection.concurrency_limit.get(), 4);
        assert_eq!(connection.admission_timeout_milliseconds.get(), 5000);
        assert_eq!(connection.token_timeout_milliseconds.get(), 5000);
        if let SourceConfig::HttpJson {
            base_url,
            authentication,
            tls_trust_profile,
            request,
            connection: name,
            ..
        } = &mut config.sources.0[0].1
        {
            *name = Some("shared".to_owned());
            *base_url = connection.base_url.clone();
            *authentication = connection.authentication.clone();
            *tls_trust_profile = connection.tls_trust_profile.clone();
            request.concurrency_limit = connection.concurrency_limit;
        }
        config.source_connections = OrderedMap(vec![("shared".to_owned(), connection)]);
        config.validate().expect("the resolved candidate validates");
        let before = config.clone();
        if let SourceConfig::HttpJson { base_url, .. } = &mut config.sources.0[0].1 {
            *base_url = typed_url("https://another.example");
        }
        assert!(
            config.validate().is_err(),
            "a copied endpoint cannot retarget a named source"
        );
        config = before.clone();
        if let SourceConfig::HttpJson { authentication, .. } = &mut config.sources.0[0].1 {
            if let SourceAuthentication::Oauth2ClientCredentials { resource, .. } =
                authentication.as_mut()
            {
                *resource = Some("https://other.example/records".to_owned());
            } else {
                panic!("expected OAuth source");
            }
        }
        assert!(
            config.validate().is_err(),
            "a source cannot retarget its named connection's OAuth resource"
        );
        for field in ["authentication", "tlsTrustProfile", "concurrencyLimit"] {
            config = before.clone();
            if let SourceConfig::HttpJson {
                authentication,
                tls_trust_profile,
                request,
                ..
            } = &mut config.sources.0[0].1
            {
                match field {
                    "authentication" => {
                        **authentication = SourceAuthentication::StaticAuthorization {
                            token_ref: SecretReference::parse("secret:file/different-token")
                                .unwrap(),
                            scheme: None,
                        }
                    }
                    "tlsTrustProfile" => *tls_trust_profile = None,
                    _ => {
                        request.concurrency_limit =
                            BoundedU32::new(2).expect("two is a valid concurrency limit");
                    }
                }
            }
            assert!(
                config.validate().is_err(),
                "connection-owned fields cannot differ"
            );
        }
        config = before;
        config.source_connections.0.clear();
        assert!(
            config.validate().is_err(),
            "a named source cannot lose its owner"
        );
    }

    #[test]
    fn source_behavior_revision_is_an_optional_strict_sha256_digest() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .unwrap();
        for revision in [
            "sha256:short".to_owned(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha512:{}", "a".repeat(64)),
        ] {
            if let SourceConfig::HttpJson {
                behavior_revision, ..
            } = &mut config.sources.0[0].1
            {
                *behavior_revision = Some(revision);
            }
            assert!(config.validate().is_err());
        }
        if let SourceConfig::HttpJson {
            behavior_revision, ..
        } = &mut config.sources.0[0].1
        {
            *behavior_revision = Some(format!("sha256:{}", "a".repeat(64)));
        }
        config.validate().expect("the versioned digest parses");
    }

    #[test]
    fn public_origin_is_canonical_https_or_the_exact_local_loopback_exception() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config.assurance_profile = AssuranceProfile::Production;
        config.service.public_origin = typed_url("https://evidence.example.test");
        config.validate().expect("canonical HTTPS origin validates");

        for invalid in [
            "https://evidence.example.test/",
            "https://evidence.example.test/path",
            "https://evidence.example.test?tenant=other",
            "https://user@evidence.example.test",
            "http://evidence.example.test",
            "http://127.0.0.1:8080",
        ] {
            assert!(
                url_refused(invalid, |url| {
                    let mut candidate = config.clone();
                    candidate.service.public_origin = url;
                    candidate.validate().is_err()
                }),
                "accepted {invalid}"
            );
        }

        config.assurance_profile = AssuranceProfile::Local;
        config.service.public_origin = typed_url("http://127.0.0.1:8080");
        config
            .validate()
            .expect("the exact tutorial loopback origin validates locally");
        for invalid in [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://127.0.0.2:8080",
            "http://[::1]:8080",
        ] {
            assert!(
                url_refused(invalid, |url| {
                    let mut candidate = config.clone();
                    candidate.service.public_origin = url;
                    candidate.validate().is_err()
                }),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn bundle_urls_are_read_through_the_shared_url_type_the_schema_names() {
        let validator = bundle_contract_validator();
        for (from, to) in [
            (
                "publicOrigin: https://evidence.invalid,",
                "publicOrigin: https://operator@evidence.invalid,",
            ),
            (
                "endpointUrl: https://evidence.example.invalid,",
                "endpointUrl: https://operator@evidence.example.invalid,",
            ),
            (
                "    baseUrl: https://source.invalid\n",
                "    baseUrl: https://operator@source.invalid\n",
            ),
            (
                "    baseUrl: https://source.invalid\n",
                "    baseUrl: source.invalid\n",
            ),
        ] {
            let document = edited(acceptance_fixture(), from, to);
            assert_eq!(decode_cause(&document), "config.invalid-value", "{to}");
            assert!(
                !validator.is_valid(&bundle_contract_instance(document.as_bytes())),
                "the schema accepted {to}"
            );
        }
        // The shared OIDC block reads these two as text; validation holds
        // them to the rule the schema's `Url` states.
        for (from, to) in [
            (
                "    issuer: https://identity.invalid\n",
                "    issuer: https://operator@identity.invalid\n",
            ),
            (
                "      uri: https://identity.invalid/.well-known/jwks.json\n",
                "      uri: https://operator@identity.invalid/.well-known/jwks.json\n",
            ),
        ] {
            let document = edited(acceptance_fixture(), from, to);
            assert!(
                EvidenceConfig::parse_yaml(document.as_bytes()).is_err(),
                "the reader accepted {to}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(document.as_bytes())),
                "the schema accepted {to}"
            );
        }
    }

    #[test]
    fn public_origin_enforces_the_schema_character_bound() {
        let boundary = format!("https://{}xx", "a.".repeat(251));
        let oversized = format!("{boundary}x");
        assert_eq!(boundary.chars().count(), 512);
        assert_eq!(oversized.chars().count(), 513);

        assert!(
            validate_public_origin(&boundary, AssuranceProfile::Production).is_ok(),
            "the schema boundary must remain accepted"
        );
        assert_eq!(
            validate_public_origin(&oversized, AssuranceProfile::Production),
            invalid("service publicOrigin exceeds its maximum length")
        );
    }

    #[test]
    fn stable_handles_are_explicit_unique_and_name_one_complete_definition() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("strict fixture validates");

        config.requirements[1].handle = config.requirements[0].handle.clone();
        assert_eq!(
            config.validate(),
            invalid("requirement handles must be unique")
        );

        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("strict fixture validates");
        let second_handle = config.requirements[1].concepts[0].handle.clone();
        config.requirements[0].concepts.push(ConceptConfig {
            handle: second_handle,
            id: "urn:example:fixture:concept:another".to_owned(),
            form: ConceptForm::Boolean,
            required: false,
            constraints: OrderedMap::default(),
            sd_jwt_vc: None,
        });
        config.requirements[0].concepts[1].handle =
            config.requirements[0].concepts[0].handle.clone();
        assert_eq!(
            config.validate(),
            invalid("requirement concept handles must be unique")
        );
    }
    // The bound `SqliteRequest::validate` holds a prepared parameter name to,
    // read from the preparation ABI itself so the two cannot drift apart
    // unnoticed.
    use crate::rhai_runtime::MAXIMUM_STATEMENT_PARAMETER_NAME_BYTES;

    /// Text as the shared URL type a bundle URL member is read into.
    fn typed_url(text: &str) -> registry_platform_yaml::Url {
        registry_platform_yaml::Url::new(text).expect("the shared URL type accepts the text")
    }

    /// Whether a bundle URL member holding `text` is refused: either the
    /// shared URL type refuses it while the bundle is read, or `validated`
    /// reports that validation refuses the typed value.
    fn url_refused(
        text: &str,
        validated: impl FnOnce(registry_platform_yaml::Url) -> bool,
    ) -> bool {
        registry_platform_yaml::Url::new(text).map_or(true, validated)
    }

    /// Borrow the base URL of a parsed fixture's first source.
    ///
    /// Every acceptance fixture these tests parse declares one `http-json`
    /// source, so a test that mutates HTTP request material names the
    ///
    /// Every acceptance fixture these tests parse declares one `http-json`
    /// source, so a test that mutates HTTP request material names the
    /// transport through these four helpers rather than at each call.
    fn http_base_url(config: &mut EvidenceConfig) -> &mut registry_platform_yaml::Url {
        match &mut config.sources.0[0].1 {
            SourceConfig::HttpJson { base_url, .. } => base_url,
            SourceConfig::SqliteExtract { .. } => panic!("{NOT_HTTP_JSON}"),
        }
    }

    fn http_tls_trust_profile(config: &mut EvidenceConfig) -> &mut Option<String> {
        match &mut config.sources.0[0].1 {
            SourceConfig::HttpJson {
                tls_trust_profile, ..
            } => tls_trust_profile,
            SourceConfig::SqliteExtract { .. } => panic!("{NOT_HTTP_JSON}"),
        }
    }

    fn http_authentication(config: &mut EvidenceConfig) -> &mut SourceAuthentication {
        match &mut config.sources.0[0].1 {
            SourceConfig::HttpJson { authentication, .. } => authentication,
            SourceConfig::SqliteExtract { .. } => panic!("{NOT_HTTP_JSON}"),
        }
    }

    fn http_request(config: &mut EvidenceConfig) -> &mut FixedRequest {
        match &mut config.sources.0[0].1 {
            SourceConfig::HttpJson { request, .. } => request,
            SourceConfig::SqliteExtract { .. } => panic!("{NOT_HTTP_JSON}"),
        }
    }

    const NOT_HTTP_JSON: &str = "the fixture source does not use the http-json transport";

    #[test]
    fn assurance_profile_is_explicit_and_strict_profiles_require_fixtures() {
        let strict = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");

        let omitted_profile = strict.replace("assuranceProfile: evidence-grade\n", "");
        assert_ne!(omitted_profile, strict, "profile mutation must apply");
        assert!(EvidenceConfig::parse_yaml(omitted_profile.as_bytes()).is_err());

        let without_fixtures = strict
            .lines()
            .filter(|line| !line.trim_start().starts_with("fixtures:"))
            .collect::<Vec<_>>()
            .join("\n");
        for profile in ["production", "evidence-grade"] {
            let candidate = without_fixtures.replace("evidence-grade", profile);
            assert!(
                EvidenceConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "{profile} accepted a requirement without fixtures"
            );
        }

        let local = without_fixtures.replace("evidence-grade", "local");
        let parsed = EvidenceConfig::parse_yaml(local.as_bytes())
            .expect("local authoring accepts an omitted fixture reference");
        assert_eq!(parsed.assurance_profile, AssuranceProfile::Local);
        assert!(parsed.requirements[0].fixtures.is_none());
    }

    /// The supervised-local issuer rule: a canonical numeric loopback origin
    /// for the issuer, and a JWKS on that exact origin at any absolute path
    /// without query or fragment. Local assurance only; strict profiles keep
    /// the HTTPS requirement.
    #[test]
    fn only_local_assurance_accepts_a_canonical_loopback_issuer_with_same_origin_jwks() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config.assurance_profile = AssuranceProfile::Local;
        config.authentication.oidc.provider.issuer = "http://127.0.0.1:8081".to_owned();
        config.authentication.oidc.provider.jwks_source =
            registry_platform_config::JwksSource::Uri {
                uri: "http://127.0.0.1:8081/.well-known/jwks.json".to_owned(),
            };
        config
            .validate()
            .expect("local profile accepts the supervised loopback identity");
        // The JWKS path is the configured issuer's to choose.
        config.authentication.oidc.provider.jwks_source =
            registry_platform_config::JwksSource::Uri {
                uri: "http://127.0.0.1:8081/oauth2/jwks".to_owned(),
            };
        config
            .validate()
            .expect("local profile accepts any same-origin absolute JWKS path");

        for invalid in [
            "http://localhost:8081",
            "http://127.0.0.2:8081",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:08081",
            "http://127.0.0.1:65536",
            "http://user@127.0.0.1:8081",
            "http://127.0.0.1:8081/",
        ] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.provider.issuer = invalid.to_owned();
            assert!(
                candidate.validate().is_err(),
                "local assurance accepted issuer {invalid}"
            );
        }
        for invalid in [
            // A different port, host, or scheme is not the issuer's origin.
            "http://127.0.0.1:8082/oauth2/jwks",
            "http://localhost:8081/oauth2/jwks",
            "https://127.0.0.1:8081/oauth2/jwks",
            // No path stated at all, or one carrying a query, fragment, or
            // userinfo. The root path itself is an absolute path and stays
            // legal: the rule fixes the origin, not the route.
            "http://127.0.0.1:8081",
            "http://127.0.0.1:8081/oauth2/jwks?cache=1",
            "http://127.0.0.1:8081/oauth2/jwks#fragment",
            "http://user@127.0.0.1:8081/oauth2/jwks",
        ] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.provider.jwks_source =
                registry_platform_config::JwksSource::Uri {
                    uri: invalid.to_owned(),
                };
            assert!(
                candidate.validate().is_err(),
                "local assurance accepted JWKS URI {invalid}"
            );
        }

        for profile in [
            AssuranceProfile::Production,
            AssuranceProfile::EvidenceGrade,
        ] {
            let mut candidate = config.clone();
            candidate.assurance_profile = profile;
            assert!(
                candidate.validate().is_err(),
                "{profile:?} inherited the local HTTP exception"
            );
        }
    }

    /// The issuer's trust profile is a logical id the runtime file binds, and
    /// it has nothing to trust on the supervised local HTTP issuer, where no
    /// certificate is presented.
    #[test]
    fn an_issuer_trust_profile_is_a_local_id_for_an_https_key_set_only() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config.authentication.oidc.tls_trust_profile = Some("issuer-pki".to_owned());
        config
            .validate()
            .expect("an HTTPS key set accepts a named trust profile");

        for invalid in ["", "Issuer-PKI", "issuer pki", "../issuer"] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.tls_trust_profile = Some(invalid.to_owned());
            assert!(
                matches!(
                    candidate.validate(),
                    Err(ConfigError::Invalid(
                        "authentication TLS trust profile identifier is invalid"
                    ))
                ),
                "accepted trust profile {invalid:?}"
            );
        }

        let mut local = config.clone();
        local.assurance_profile = AssuranceProfile::Local;
        local.authentication.oidc.provider.issuer = "http://127.0.0.1:8081".to_owned();
        local.authentication.oidc.provider.jwks_source =
            registry_platform_config::JwksSource::Uri {
                uri: "http://127.0.0.1:8081/.well-known/jwks.json".to_owned(),
            };
        assert!(matches!(
            local.validate(),
            Err(ConfigError::Invalid(
                "a local HTTP authentication JWKS URI cannot use a TLS trust profile"
            ))
        ));
    }

    /// The admission fields are optional, but a present list must be a
    /// nonempty, bounded, unique list — and required scopes must be scope
    /// tokens, because they are compared against verified token scopes.
    #[test]
    fn admission_lists_are_optional_but_present_means_nonempty_and_bounded() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config
            .validate()
            .expect("absent admission fields keep the existing behavior");

        config.authentication.oidc.allowed_clients = Some(set(["records-reader".to_owned()]));
        config.authentication.oidc.required_scopes = Some(set(["evidence:invoke".to_owned()]));
        config.validate().expect("stated admission validates");

        for clients in [
            Vec::new(),
            vec!["".to_owned()],
            vec!["a".repeat(129)],
            (0..33).map(|index| format!("reader-{index}")).collect(),
        ] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.allowed_clients = Some(set(clients.clone()));
            assert!(
                candidate.validate().is_err(),
                "accepted allowedClients {clients:?}"
            );
        }
        for scopes in [
            Vec::new(),
            vec!["".to_owned()],
            vec!["a".repeat(257)],
            vec!["not a scope".to_owned()],
            (0..33).map(|index| format!("scope:{index}")).collect(),
        ] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.required_scopes = Some(set(scopes.clone()));
            assert!(
                candidate.validate().is_err(),
                "accepted requiredScopes {scopes:?}"
            );
        }
    }

    /// `assertionIssuers` is optional, but a present map must be a nonempty,
    /// bounded, unique set of client keys, each naming a nonempty, bounded,
    /// unique list of issuer strings.
    #[test]
    fn assertion_issuers_are_optional_but_present_means_nonempty_and_bounded() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config
            .validate()
            .expect("absent assertionIssuers keeps the existing behavior");

        config.authentication.oidc.assertion_issuers = Some(BTreeMap::from([
            (
                "evidence-task-agent".to_owned(),
                set(["https://identity.invalid".to_owned()]),
            ),
            (
                "portal-exchange".to_owned(),
                set([
                    "https://casework.invalid".to_owned(),
                    "https://portal.invalid".to_owned(),
                ]),
            ),
        ]));
        config
            .validate()
            .expect("stated assertionIssuers validates");

        for clients in [
            BTreeMap::new(),
            BTreeMap::from([("".to_owned(), set(["https://issuer.invalid".to_owned()]))]),
            BTreeMap::from([("a".repeat(129), set(["https://issuer.invalid".to_owned()]))]),
            (0..33)
                .map(|index| {
                    (
                        format!("client-{index}"),
                        set(["https://issuer.invalid".to_owned()]),
                    )
                })
                .collect(),
        ] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.assertion_issuers = Some(clients.clone());
            assert!(
                candidate.validate().is_err(),
                "accepted assertionIssuers {clients:?}"
            );
        }
        for issuers in [
            Vec::new(),
            vec!["".to_owned()],
            vec!["a".repeat(513)],
            (0..9)
                .map(|index| format!("https://issuer-{index}.invalid"))
                .collect(),
        ] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.assertion_issuers = Some(BTreeMap::from([(
                "evidence-task-agent".to_owned(),
                set(issuers.clone()),
            )]));
            assert!(
                candidate.validate().is_err(),
                "accepted assertionIssuers issuer list {issuers:?}"
            );
        }
    }

    #[test]
    fn publication_endpoint_requires_https_or_local_loopback_http() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        let publication = config.publication.as_mut().expect("publication configured");
        publication.endpoint_url = typed_url("http://evidence.example.invalid");
        assert!(
            config.validate().is_err(),
            "a non-local deployment must reject cleartext publication"
        );

        config.assurance_profile = AssuranceProfile::Local;
        for endpoint in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            config
                .publication
                .as_mut()
                .expect("publication configured")
                .endpoint_url = typed_url(endpoint);
            config
                .validate()
                .unwrap_or_else(|_| panic!("local assurance rejected {endpoint}"));
            crate::discovery::render(&config)
                .unwrap_or_else(|_| panic!("valid local publication did not render: {endpoint}"));
        }
        for endpoint in [
            "http://127.0.0.2:8080",
            "http://127.1:8080",
            "http://LOCALHOST:8080",
            "http://[::2]:8080",
            " http://127.0.0.1:8080",
            "http://127.0.0.1:8080\n",
            "http://127.0.0.1:8080/catalog .jsonld",
            "http://127.0.0.1:8080/catalog\u{0007}.jsonld",
        ] {
            assert!(
                url_refused(endpoint, |url| {
                    config
                        .publication
                        .as_mut()
                        .expect("publication configured")
                        .endpoint_url = url;
                    config.validate().is_err()
                }),
                "accepted {endpoint:?}"
            );
        }
    }

    #[test]
    fn publication_public_text_matches_shared_profile_and_schema_and_always_renders() {
        let validator = bundle_contract_validator();
        let fixture = include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );
        for field in ["title", "description"] {
            for (value, accepted) in [
                (
                    "é".repeat(registry_discovery_profile::MAX_STRING_CHARACTERS),
                    true,
                ),
                (
                    "é".repeat(registry_discovery_profile::MAX_STRING_CHARACTERS + 1),
                    false,
                ),
                (" leading".to_owned(), false),
                ("trailing ".to_owned(), false),
                ("embedded\u{0007}control".to_owned(), false),
            ] {
                let mut config = EvidenceConfig::parse_yaml(fixture)
                    .expect("strict fixture validates before the mutation");
                let publication = config.publication.as_mut().expect("publication configured");
                match field {
                    "title" => publication.title.clone_from(&value),
                    "description" => publication.description.clone_from(&value),
                    _ => unreachable!("closed publication field list"),
                }
                assert_eq!(
                    config.validate().is_ok(),
                    accepted,
                    "Rust/profile parity for {field} at {} scalars",
                    value.chars().count()
                );

                let mut instance = bundle_contract_instance(fixture);
                instance["publication"][field] = serde_json::json!(value);
                assert_eq!(
                    validator.is_valid(&instance),
                    accepted,
                    "schema/profile parity for {field}"
                );

                if accepted {
                    let rendered = crate::discovery::render(&config)
                        .expect("every valid publication renders")
                        .expect("publication remains configured");
                    registry_discovery_profile::parse_description(&rendered)
                        .expect("every valid publication renders a parseable description");
                }
            }
        }
    }

    #[test]
    fn publication_uri_bounds_count_unicode_characters_and_always_render() {
        let validator = bundle_contract_validator();
        let fixture = include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );
        let prefix = "https://example.invalid/";
        let boundary = format!("{prefix}{}", "é".repeat(512 - prefix.chars().count()));
        let oversized = format!("{boundary}é");
        assert!(
            boundary.len() > 512,
            "the boundary must exceed 512 UTF-8 bytes"
        );

        for field in [
            "serviceId",
            "endpointUrl",
            "jurisdictions",
            "publisherId",
            "operatorId",
        ] {
            for (value, accepted) in [(&boundary, true), (&oversized, false)] {
                let mut config = EvidenceConfig::parse_yaml(fixture)
                    .expect("strict fixture validates before the mutation");
                let publication = config.publication.as_mut().expect("publication configured");
                match field {
                    "serviceId" => publication.service_id.clone_from(value),
                    "endpointUrl" => publication.endpoint_url = typed_url(value),
                    "jurisdictions" => publication.jurisdictions = vec![value.clone()],
                    "publisherId" => publication.publisher_id = Some(value.clone()),
                    "operatorId" => publication.operator_id = Some(value.clone()),
                    _ => unreachable!("closed publication URI field list"),
                }
                assert_eq!(
                    config.validate().is_ok(),
                    accepted,
                    "Rust/profile parity for {field} at {} scalars",
                    value.chars().count()
                );

                let mut instance = bundle_contract_instance(fixture);
                instance["publication"][field] = if field == "jurisdictions" {
                    serde_json::json!([value])
                } else {
                    serde_json::json!(value)
                };
                assert_eq!(
                    validator.is_valid(&instance),
                    accepted,
                    "schema/profile parity for {field}"
                );

                if accepted {
                    let rendered = crate::discovery::render(&config)
                        .expect("every valid publication renders")
                        .expect("publication remains configured");
                    registry_discovery_profile::parse_description(&rendered)
                        .expect("every valid publication renders a parseable description");
                }
            }
        }
    }
    /// Every URI-typed bundle scalar refuses the same characters the shared
    /// public profile refuses, not only the ASCII whitespace `str::is_ascii_whitespace`
    /// names.
    ///
    /// A URI carries no whitespace and no control character at all. Accepting
    /// `U+00A0` or `U+3000` inside an issuer id, a requirement id, or a concept
    /// id lets two identifiers that render alike compare unequal, so a bundle
    /// can name one authority twice and an operator reading the audit trail
    /// cannot tell the two apart. `validate_uri` therefore delegates the
    /// character rule to `registry_discovery_profile::is_valid_identifier`, the
    /// single definition the publication projection already enforces.
    ///
    /// The rule covers the whitespace and control classes. A zero-width format
    /// character such as `U+FEFF` is neither, so both definitions still accept
    /// it; that is one gap in the shared profile, not two divergent rules here.
    #[test]
    fn uri_scalars_refuse_every_whitespace_and_control_character_the_public_profile_refuses() {
        let fixture = include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );
        let config = EvidenceConfig::parse_yaml(fixture).expect("strict fixture validates");
        config.validate().expect("the fixture URIs are sound");

        for separator in [
            "\u{a0}",   // no-break space
            "\u{2007}", // figure space
            "\u{3000}", // ideographic space
            " ",        // ASCII space
            "\t", "\n", "\u{7}", // a control character no URI carries
        ] {
            let value = format!("urn:example:fixture:issuer{separator}authority");
            let mut candidate = config.clone();
            candidate.issuer.id.clone_from(&value);
            assert_eq!(
                candidate.validate(),
                invalid("URI is invalid"),
                "issuer id carrying {separator:?}"
            );
            assert!(
                !registry_discovery_profile::is_valid_identifier(&value),
                "the shared public profile refuses {separator:?} as well"
            );
        }

        for surrounded in [
            "\u{a0}urn:example:fixture:issuer",
            "urn:example:fixture:issuer\u{a0}",
        ] {
            let mut candidate = config.clone();
            candidate.issuer.id = surrounded.to_owned();
            assert_eq!(
                candidate.validate(),
                invalid("URI is invalid"),
                "issuer id bounded by a no-break space"
            );
        }

        let mut scheme_free = config.clone();
        scheme_free.issuer.id = "example:fixture".to_owned();
        assert!(
            scheme_free.validate().is_ok(),
            "an ordinary scheme stays acceptable"
        );
    }

    /// Two contextual claims naming one JWT member, or naming a member the token
    /// already defines, is a configuration the verifier must refuse.
    ///
    /// Evidence accepts any configured OIDC issuer, so it enforces this rule at
    /// its own resource-server boundary without assuming an issuer-side check.
    /// A grant source issuer claim named `aud` would read Evidence's own audience
    /// as the source that issued the grant.
    #[test]
    fn authority_claim_names_must_be_distinct_and_must_not_shadow_registered_claims() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config
            .validate()
            .expect("the fixture claim names are sound");

        let mut duplicate = config.clone();
        duplicate
            .authentication
            .oidc
            .claims
            .grant_id
            .clone_from(&config.authentication.oidc.claims.grant_source_issuer);
        assert_eq!(
            duplicate.validate(),
            invalid("contextual authorization claim names are invalid"),
            "one member read as both the grant id and the grant source issuer"
        );

        let mut duplicate_actor = config.clone();
        duplicate_actor.authentication.oidc.actor_claim =
            Some(config.authentication.oidc.requester_tags_claim.clone());
        assert_eq!(
            duplicate_actor.validate(),
            invalid("authority claim names must be distinct"),
            "one member read as both the actor and the requester tags"
        );

        let mut shared_shadows_product = config.clone();
        shared_shadows_product.authentication.oidc.claims.purpose =
            config.authentication.oidc.requester_tags_claim.clone();
        assert_eq!(
            shared_shadows_product.validate(),
            invalid("authority claim names must be distinct"),
            "a shared claim cannot reuse an Evidence product claim"
        );

        // `cnf` is here for a different reason than the rest. The others would
        // read a member the issuer owns; `cnf` would name one the authenticator
        // refuses outright, because Version 1 validates no proof of possession
        // and denies a sender-constrained token rather than downgrading it. A
        // deployment naming it would load, pass `evidence check`, and then answer
        // 401 to every authenticated request, with nothing in the configuration
        // to explain why.
        for reserved in ["iss", "aud", "exp", "iat", "nbf", "jti", "client_id", "cnf"] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.claims.grant_source_issuer = reserved.to_owned();
            assert_eq!(
                candidate.validate(),
                invalid("contextual authorization claim names are invalid"),
                "grant source issuer read from the registered claim {reserved}"
            );
        }

        // `sub` carries the principal, so the principal claim may name it and
        // the fixture does. Any other claim naming it would read the principal.
        let mut principal_is_subject = config.clone();
        principal_is_subject.authentication.oidc.principal_claim = "sub".to_owned();
        principal_is_subject
            .validate()
            .expect("the principal may be read from sub");
        // Moved off `sub` first, so this proves the shadowing rule rather than
        // colliding with the principal and tripping distinctness instead.
        let mut source_issuer_is_subject = config.clone();
        source_issuer_is_subject.authentication.oidc.principal_claim =
            "evidence_principal".to_owned();
        source_issuer_is_subject
            .authentication
            .oidc
            .claims
            .grant_source_issuer = "sub".to_owned();
        assert_eq!(
            source_issuer_is_subject.validate(),
            invalid("contextual authorization claim names are invalid"),
            "the grant source issuer read from the principal member"
        );

        let mut distinct = config.clone();
        distinct.authentication.oidc.actor_claim = Some("evidence_actor".to_owned());
        distinct
            .validate()
            .expect("distinct, unreserved claim names load");
    }

    #[test]
    fn task_grant_profiles_bind_trusted_source_and_verified_client() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml"
        ))
        .expect("task-grant fixture validates");

        let mut no_profile_clients = config.clone();
        no_profile_clients.authority_profiles.0[0]
            .1
            .requester_clients = UniqueList::default();
        assert!(no_profile_clients.validate().is_err());

        let mut no_source = config.clone();
        no_source.authority_profiles.0[0].1.grant_source_issuer = None;
        assert_eq!(
            no_source.validate(),
            invalid("task-grant authority profile requires grantSourceIssuer")
        );

        let mut no_global_admission = config.clone();
        no_global_admission.authentication.oidc.allowed_clients = None;
        assert_eq!(
            no_global_admission.validate(),
            invalid("task-grant authority profiles require authentication allowedClients")
        );

        let mut client_not_admitted = config;
        client_not_admitted.authentication.oidc.allowed_clients =
            Some(set(["other-client".to_owned()]));
        assert_eq!(
            client_not_admitted.validate(),
            invalid(
                "task-grant requester clients must be admitted by authentication allowedClients"
            )
        );
    }

    #[test]
    fn standing_authority_rejects_task_grant_only_constraints() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("standing-authority fixture validates");
        let expected = invalid(
            "requesterClients and grantSourceIssuer require an authenticated-grant subject",
        );

        let mut requester_clients = config.clone();
        requester_clients.authentication.oidc.allowed_clients =
            Some(set(["evidence-cli".to_owned()]));
        requester_clients.authority_profiles.0[0]
            .1
            .requester_clients = set(["evidence-cli".to_owned()]);
        assert_eq!(requester_clients.validate(), expected);

        let mut source_issuer = config;
        source_issuer.authority_profiles.0[0].1.grant_source_issuer =
            Some("https://casework.invalid".to_owned());
        assert_eq!(source_issuer.validate(), expected);
    }

    #[test]
    fn unauthenticated_source_is_local_loopback_only_and_matches_the_bundle_schema() {
        let mut local = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        local.assurance_profile = AssuranceProfile::Local;
        *http_authentication(&mut local) = SourceAuthentication::None {};

        for origin in [
            "http://127.0.0.1:80",
            "http://127.0.0.1:18081",
            "http://127.42.5.9:1",
            "http://[::1]:65535",
        ] {
            let mut candidate = local.clone();
            *http_base_url(&mut candidate) = typed_url(origin);
            candidate
                .validate()
                .unwrap_or_else(|_| panic!("local assurance rejected {origin}"));
            assert!(http_authentication(&mut candidate).secret_refs().is_empty());
        }

        for origin in [
            "https://127.0.0.1:18081",
            "http://localhost:18081",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:018081",
            "http://127.0.0.1:65536",
            "http://127.00.0.1:18081",
            "http://127.0.0.1:18081/",
            "http://127.0.0.1:18081/data",
            "http://127.0.0.1:18081?query=true",
            "http://127.0.0.1:18081#fragment",
            "http://user@127.0.0.1:18081",
            "http://192.168.1.2:18081",
        ] {
            assert!(
                url_refused(origin, |url| {
                    let mut candidate = local.clone();
                    *http_base_url(&mut candidate) = url;
                    candidate.validate().is_err()
                }),
                "local assurance accepted unauthenticated origin {origin}"
            );
        }

        let mut with_tls_profile = local.clone();
        *http_base_url(&mut with_tls_profile) = typed_url("http://127.0.0.1:18081");
        *http_tls_trust_profile(&mut with_tls_profile) = Some("unused-local-ca".to_owned());
        assert!(with_tls_profile.validate().is_err());

        for profile in [
            AssuranceProfile::Production,
            AssuranceProfile::EvidenceGrade,
        ] {
            let mut candidate = local.clone();
            candidate.assurance_profile = profile;
            *http_base_url(&mut candidate) = typed_url("http://127.0.0.1:18081");
            assert!(
                candidate.validate().is_err(),
                "{profile:?} accepted an unauthenticated source"
            );
        }

        let validator = bundle_contract_validator();
        let mut instance = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ));
        instance["assuranceProfile"] = serde_json::json!("local");
        instance["sources"]["source-a"]["baseUrl"] = serde_json::json!("http://127.0.0.1:18081");
        instance["sources"]["source-a"]["authentication"] = serde_json::json!({"kind": "none"});
        assert!(
            validator.is_valid(&instance),
            "schema accepts the local form"
        );
        instance["assuranceProfile"] = serde_json::json!("production");
        assert!(
            !validator.is_valid(&instance),
            "schema rejects the local exception in a deployable profile"
        );

        assert!(
            serde_json::from_value::<SourceAuthentication>(
                serde_json::json!({"kind": "none", "tokenRef": "secret:file/unexpected"})
            )
            .is_err(),
            "the none variant is closed"
        );
    }

    /// The published bundle contract must refuse a `sourceConnections` entry
    /// exactly where `SourceConnectionConfig::validate` refuses it. A schema
    /// that publishes a connection shape the runtime denies describes a
    /// deployment nobody can load, so both sides read the same document here.
    #[test]
    fn source_connections_are_constrained_alike_by_the_bundle_schema_and_the_runtime() {
        let validator = bundle_contract_validator();

        let owned = source_connection_document(
            acceptance_fixture(),
            concat!(
                "    baseUrl: https://source.invalid\n",
                "    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}\n",
                "    concurrencyLimit: 8\n",
            ),
        );
        let owned = edited(
            &owned,
            "    transport: http-json\n",
            "    transport: http-json\n    connection: shared\n",
        );
        EvidenceConfig::parse_yaml(owned.as_bytes())
            .expect("a source resolved to its named connection validates");
        assert!(
            validator.is_valid(&bundle_contract_instance(owned.as_bytes())),
            "the bundle contract rejected a resolved named connection"
        );

        let local = edited(
            acceptance_fixture(),
            "assuranceProfile: evidence-grade\n",
            "assuranceProfile: local\n",
        );
        let loopback = source_connection_document(
            &local,
            "    baseUrl: http://127.0.0.1:18081\n    authentication: {kind: none}\n",
        );
        EvidenceConfig::parse_yaml(loopback.as_bytes())
            .expect("an unauthenticated local loopback connection validates");
        assert!(
            validator.is_valid(&bundle_contract_instance(loopback.as_bytes())),
            "the bundle contract rejected the local loopback exception"
        );

        let mut refused = vec![
            (
                "an unauthenticated connection at a public origin",
                "    baseUrl: https://source.invalid\n    authentication: {kind: none}\n"
                    .to_owned(),
            ),
            (
                "an unauthenticated loopback connection carrying a private trust profile",
                concat!(
                    "    baseUrl: http://127.0.0.1:18081\n",
                    "    authentication: {kind: none}\n",
                    "    tlsTrustProfile: private-ca\n",
                )
                .to_owned(),
            ),
        ];
        // The unauthenticated exception is one exact origin spelling, so a
        // default port, a zero or out-of-range port, a padded port, and a
        // padded octet all sit outside it.
        for origin in [
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:018081",
            "http://127.00.0.1:18081",
        ] {
            refused.push((
                "an unauthenticated connection at a non-canonical loopback origin",
                format!("    baseUrl: {origin}\n    authentication: {{kind: none}}\n"),
            ));
        }
        // The authenticated branch is no looser. The runtime refuses user
        // information, a port outside the range a port can hold, and a
        // loopback literal that is not the canonical spelling, so the
        // published contract has to refuse them rather than describe a
        // connection that only fails at startup.
        for origin in [
            "https://user:token@source.invalid",
            "https://source.invalid:99999",
            "http://127.0.0.1:99999",
            "http://127.00.0.1:18081",
        ] {
            refused.push((
                "an authenticated connection at a non-canonical origin",
                format!(
                    "    baseUrl: {origin}\n    authentication: {{kind: static-authorization, tokenRef: secret:file/source-a-token}}\n"
                ),
            ));
        }
        for (reason, connection) in refused {
            let document = source_connection_document(&local, &connection);
            assert!(
                EvidenceConfig::parse_yaml(document.as_bytes()).is_err(),
                "the runtime accepted {reason}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(document.as_bytes())),
                "the bundle contract accepted {reason}"
            );
        }

        // An unused connection is still declared, and the assurance-profile
        // conditional must refuse it the same way it refuses a declared
        // source, regardless of whether any requirement resolves to it.
        let unused_loopback =
            "    baseUrl: http://127.0.0.1:18081\n    authentication: {kind: none}\n";
        let evidence_grade = source_connection_document(acceptance_fixture(), unused_loopback);
        let production = source_connection_document(
            &edited(
                acceptance_fixture(),
                "assuranceProfile: evidence-grade\n",
                "assuranceProfile: production\n",
            ),
            unused_loopback,
        );
        for (reason, document) in [
            (
                "an unauthenticated loopback connection under evidence-grade assurance",
                evidence_grade,
            ),
            (
                "an unauthenticated loopback connection under production assurance",
                production,
            ),
        ] {
            assert!(
                EvidenceConfig::parse_yaml(document.as_bytes()).is_err(),
                "the runtime accepted {reason}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(document.as_bytes())),
                "the bundle contract accepted {reason}"
            );
        }
    }

    /// One `sourceConnections` entry named `shared`, spliced into a whole
    /// document so the runtime and the published contract both read the block
    /// the way a bundle carries it.
    fn source_connection_document(document: &str, connection: &str) -> String {
        edited(
            document,
            "sources:\n",
            &format!("sourceConnections:\n  shared:\n{connection}sources:\n"),
        )
    }

    /// The acceptance fixture's one source, restated on the statement
    /// transport, so a whole document exercises it the way a bundle would.
    const SQLITE_SOURCE: &str = r#"  source-a:
    transport: sqlite-extract
    posture: field-projected
    extractProfile: residence-register
    request:
      statement: queries/residence-region.sql
      columns: [{name: id, type: string}, {name: region, type: string}]
      selectorInputs:
        - role: subject
          alternatives:
            - {profile: person-demographics-v1, fields: [given_name, family_name, birth_date]}
      parameterBindings:
        record_reference: {kind: selector, role: subject, profile: person-demographics-v1, field: given_name}
      maximumRows: 2
      maximumCellBytes: 4096
      maximumStatementSteps: 50000
      projection: [/rows/*/id, /rows/*/region, /extract/publishedAt]
      timeoutMilliseconds: 1000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    maximumExtractAgeSeconds: 86400
    responseSchema: schemas/response.schema.yaml
    extractScript: adapters/source-a.rhai
    factSchema: schemas/facts.schema.yaml
"#;

    fn acceptance_fixture() -> &'static str {
        include_str!("../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml")
    }

    fn source_batch_document() -> String {
        let with_capability = edited(
            acceptance_fixture(),
            "version: 1\n",
            "version: 1\nacquisitionCapabilities: [source-batch]\n",
        );
        edited(
            &with_capability,
            "    factSchema: schemas/facts.schema.yaml\n",
            "    factSchema: schemas/facts.schema.yaml\n    batch:\n      maximumItems: 2\n      prepareScript: adapters/source-prepare-batch.rhai\n      extractScript: adapters/source-extract-batch.rhai\n      responseSchema: schemas/source-batch-response.schema.yaml\n      projection: [/results/*]\n",
        )
    }

    fn runtime_for_source_batch(enabled: bool) -> RuntimeConfig {
        let base = include_str!(
            "../../../products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence/runtime.yaml"
        );
        let document = if enabled {
            format!("{base}acquisitionCapabilities: [source-batch]\n")
        } else {
            base.to_owned()
        };
        RuntimeConfig::parse_yaml(document.as_bytes()).expect("runtime configuration validates")
    }

    /// The acceptance fixture with its HTTP source replaced by a statement one.
    fn sqlite_source_document() -> String {
        let fixture = acceptance_fixture();
        let (head, rest) = fixture
            .split_once("sources:\n")
            .expect("the fixture declares sources");
        let (_, tail) = rest
            .split_once("authorityProfiles:\n")
            .expect("the fixture declares authority profiles after its sources");
        format!("{head}sources:\n{SQLITE_SOURCE}authorityProfiles:\n{tail}")
    }

    /// A set built from items the test knows to be distinct.
    fn set<I: IntoIterator<Item = String>>(items: I) -> UniqueList<String> {
        UniqueList::new(items.into_iter().collect()).expect("the items are distinct")
    }

    /// Replace exactly one line of a document, and prove the edit applied.
    fn edited(document: &str, from: &str, to: &str) -> String {
        assert_eq!(document.matches(from).count(), 1, "{from} is not unique");
        document.replace(from, to)
    }

    /// The code of the first diagnostic the reader reports for a document
    /// the closed schema refuses.
    fn decode_cause(document: &str) -> String {
        let error =
            EvidenceConfig::parse_yaml(document.as_bytes()).expect_err("the document was accepted");
        let ConfigError::Refused(report) = error else {
            panic!("the document was not refused by the reader: {error}");
        };
        let diagnostic = report.diagnostics().first().expect("a diagnostic");
        assert!(
            !diagnostic.code.starts_with("evidence.bundle."),
            "the document was refused by a bundle rule, not the schema: {}",
            diagnostic.message
        );
        diagnostic.code.clone()
    }

    /// The reason a bundle rule gives for a document the schema accepts.
    fn invalid_reason(document: &str) -> &'static str {
        match EvidenceConfig::parse_yaml_reporting_rule(document.as_bytes()) {
            Err(ConfigError::Invalid(reason) | ConfigError::InvalidField(reason, _)) => reason,
            Err(error) => panic!("the document was not rejected by a validation rule: {error}"),
            Ok(_) => panic!("the document was accepted"),
        }
    }

    #[test]
    fn a_statement_source_parses_and_the_transports_reject_each_others_fields() {
        let document = sqlite_source_document();
        let config = EvidenceConfig::parse_yaml(document.as_bytes())
            .expect("a sqlite-extract source parses and validates");
        let SourceConfig::SqliteExtract {
            extract_profile,
            request,
            maximum_extract_age_seconds,
            ..
        } = &config.sources.0[0].1
        else {
            panic!("the restated fixture source uses the sqlite-extract transport");
        };
        assert_eq!(extract_profile, "residence-register");
        assert_eq!(request.statement.as_str(), "queries/residence-region.sql");
        assert_eq!(maximum_extract_age_seconds.get(), 86_400);
        assert_eq!(config.sources.0[0].1.prepare_script(), None);
        assert_eq!(config.sources.0[0].1.adapter_parameters_schema(), None);
        assert!(config.sources.0[0].1.fixed_headers().is_empty());
        assert_eq!(config.sources.0[0].1.concurrency_limit(), 8);

        for (label, candidate) in [
            (
                "baseUrl on a statement source",
                edited(
                    &document,
                    "    extractProfile: residence-register\n",
                    "    extractProfile: residence-register\n    baseUrl: https://source.invalid\n",
                ),
            ),
            (
                "an unknown key on a statement source",
                edited(
                    &document,
                    "    maximumExtractAgeSeconds: 86400\n",
                    "    maximumExtractAgeSeconds: 86400\n    surprise: true\n",
                ),
            ),
            (
                "an unknown key in a statement request",
                edited(
                    &document,
                    "      maximumRows: 2\n",
                    "      maximumRows: 2\n      surprise: true\n",
                ),
            ),
            (
                "extractProfile on an HTTP source",
                edited(
                    acceptance_fixture(),
                    "    posture: field-projected\n",
                    "    posture: field-projected\n    extractProfile: residence-register\n",
                ),
            ),
            (
                "an unknown key on an HTTP source",
                edited(
                    acceptance_fixture(),
                    "    posture: field-projected\n",
                    "    posture: field-projected\n    surprise: true\n",
                ),
            ),
        ] {
            assert_eq!(decode_cause(&candidate), "config.unknown-key", "{label}");
        }

        assert_eq!(
            decode_cause(&edited(
                &document,
                "    transport: sqlite-extract\n",
                "    transport: sqlite-extracts\n",
            )),
            "config.unknown-variant",
        );
        assert_eq!(
            decode_cause(&edited(&document, "    transport: sqlite-extract\n", "")),
            "config.missing-key",
        );
    }

    #[test]
    fn a_statement_is_a_reviewed_sql_artifact_under_the_queries_root() {
        let document = sqlite_source_document();
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "      statement: queries/residence-region.sql\n",
                "      statement: adapters/residence-region.sql\n",
            )),
            "artifact path has the wrong bundle directory",
        );
        assert_eq!(
            decode_cause(&edited(
                &document,
                "      statement: queries/residence-region.sql\n",
                "      statement: residence-region.sql\n",
            )),
            "config.invalid-value",
            "a path under no bundle root is not an artifact path at all",
        );
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "      statement: queries/residence-region.sql\n",
                "      statement: queries/residence-region.rhai\n",
            )),
            "source statement must be a SQL file",
        );
    }

    #[test]
    fn a_statement_projection_cannot_discard_a_declared_result_column() {
        let document = sqlite_source_document();
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "      projection: [/rows/*/id, /rows/*/region, /extract/publishedAt]\n",
                "      projection: [/rows/*/id, /extract/publishedAt]\n",
            )),
            "statement projection must preserve every declared result column"
        );

        EvidenceConfig::parse_yaml(
            edited(
                &document,
                "      projection: [/rows/*/id, /rows/*/region, /extract/publishedAt]\n",
                "      projection: [/rows, /extract/publishedAt]\n",
            )
            .as_bytes(),
        )
        .expect("retaining the complete rows array preserves every declared column");
    }

    #[test]
    fn statement_parameters_are_named_selector_bindings_and_the_runtime_instant_is_reserved() {
        let document = sqlite_source_document();
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "        record_reference: {kind: selector,",
                "        evidence_now: {kind: selector,",
            )),
            "statement parameter name is reserved by the runtime",
        );
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "        record_reference: {kind: selector,",
                "        record reference: {kind: selector,",
            )),
            "statement parameter name is invalid",
        );
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "profile: person-demographics-v1, field: given_name}",
                "profile: person-demographics-v1, field: unknown_field}",
            )),
            "source path binding references an unknown selector field",
        );
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "record_reference: {kind: selector, role: subject,",
                "record_reference: {kind: selector, role: unbound-role,",
            )),
            "source path binding is not declared as a selector input",
        );
        assert_eq!(
            decode_cause(&edited(
                &document,
                "record_reference: {kind: selector,",
                "record_reference: {kind: prior-fact,",
            )),
            "config.unknown-variant",
        );
    }

    /// A name one byte past the preparation ABI's own bound.
    fn overlong_prepared_name() -> String {
        format!("p{}", "a".repeat(MAXIMUM_STATEMENT_PARAMETER_NAME_BYTES))
    }

    /// A prepared name is filled by a script across the preparation ABI, which
    /// admits fewer bytes of name than a binding key may carry. A name in
    /// between loads and can never execute, so it is refused where the author
    /// can still act on it.
    #[test]
    fn a_prepared_statement_parameter_name_is_held_to_the_preparation_abi() {
        let document = prepared_statement_document(true, Some(&preparation_limits(8, 1_024)));
        let named = |name: &str| {
            edited(
                &document,
                PREPARED_BINDING,
                &format!("        {name}: {{kind: prepared}}\n"),
            )
        };
        assert_eq!(
            invalid_reason(&named(&overlong_prepared_name())),
            "prepared statement parameter name is too long to be prepared",
        );
        EvidenceConfig::parse_yaml(
            named(&"a".repeat(MAXIMUM_STATEMENT_PARAMETER_NAME_BYTES)).as_bytes(),
        )
        .expect("a prepared name of exactly the preparation ABI bound is admitted");
    }

    /// A selector parameter is filled from the request and never crosses the
    /// preparation ABI, so the prepared bound stays on prepared names alone.
    #[test]
    fn a_selector_statement_parameter_name_keeps_the_full_key_bound() {
        let long_selector = edited(
            &sqlite_source_document(),
            SELECTOR_BINDING,
            &format!(
                "        {}: {{kind: selector, role: subject, profile: person-demographics-v1, field: given_name}}\n",
                overlong_prepared_name(),
            ),
        );
        EvidenceConfig::parse_yaml(long_selector.as_bytes())
            .expect("a selector parameter name is bounded by the binding key alone");
    }

    #[test]
    fn statement_columns_declare_a_unique_typed_result_contract() {
        let document = sqlite_source_document();
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "columns: [{name: id, type: string}, {name: region, type: string}]",
                "columns: [{name: id, type: string}, {name: id, type: string}]",
            )),
            "statement column names must be valid and unique",
        );
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "columns: [{name: id, type: string}, {name: region, type: string}]",
                "columns: [{name: Id, type: string}, {name: region, type: string}]",
            )),
            "statement column names must be valid and unique",
        );
        assert_eq!(
            invalid_reason(&edited(
                &document,
                "columns: [{name: id, type: string}, {name: region, type: string}]",
                "columns: []",
            )),
            "collection cardinality is outside Version 1 bounds",
        );
        assert_eq!(
            decode_cause(&edited(
                &document,
                "columns: [{name: id, type: string}, {name: region, type: string}]",
                "columns: [{name: id, type: blob}, {name: region, type: string}]",
            )),
            "config.unknown-variant",
        );
    }

    #[test]
    fn statement_source_bounds_reject_zero_and_an_oversized_value() {
        let document = sqlite_source_document();
        for (declared, maximum) in [
            ("      maximumRows: 2", 256_u64),
            ("      maximumCellBytes: 4096", 65_536),
            ("      maximumStatementSteps: 50000", 1_000_000),
            ("      timeoutMilliseconds: 1000", 30_000),
            ("      maximumResponseBytes: 65536", 1_048_576),
            ("      concurrencyLimit: 8", 256),
            ("    maximumExtractAgeSeconds: 86400", 2_592_000),
        ] {
            let (key, _) = declared
                .split_once(':')
                .expect("every bound is declared as a mapping entry");
            for value in [0, maximum + 1] {
                assert_eq!(
                    decode_cause(&edited(&document, declared, &format!("{key}: {value}"))),
                    "config.out-of-range",
                    "{key} accepted {value}",
                );
            }
            EvidenceConfig::parse_yaml(
                edited(&document, declared, &format!("{key}: {maximum}")).as_bytes(),
            )
            .unwrap_or_else(|error| panic!("{key} rejected its own maximum: {error}"));
        }
    }

    /// One statement-source preparation limits mapping, written out in full.
    fn preparation_limits(parameters: u64, value_bytes: u64) -> String {
        format!("{{maximumParameters: {parameters}, maximumParameterValueBytes: {value_bytes}}}")
    }

    /// The selector binding the statement source already declares, restated so
    /// a test can add a second binding beside it as a unique replacement.
    const SELECTOR_BINDING: &str = "        record_reference: {kind: selector, role: subject, profile: person-demographics-v1, field: given_name}\n";

    /// The prepared parameter a preparation script exists to fill.
    const PREPARED_BINDING: &str = "        normalized_reference: {kind: prepared}\n";

    /// The statement source with a preparation script, its limits, or neither.
    ///
    /// The script and its limits are written immediately before `maximumRows`,
    /// which is the one line of the request every variant keeps. The script also
    /// brings the prepared parameter it exists to fill, because the source
    /// refuses the two apart.
    fn prepared_statement_document(prepare_script: bool, limits: Option<&str>) -> String {
        let mut document = sqlite_source_document();
        if let Some(limits) = limits {
            document = edited(
                &document,
                "      maximumRows: 2\n",
                &format!("      preparationLimits: {limits}\n      maximumRows: 2\n"),
            );
        }
        if prepare_script {
            document = edited(
                &document,
                "      maximumRows: 2\n",
                "      prepareScript: adapters/source-a-prepare.rhai\n      maximumRows: 2\n",
            );
            document = edited(
                &document,
                SELECTOR_BINDING,
                &format!("{SELECTOR_BINDING}{PREPARED_BINDING}"),
            );
        }
        document
    }

    /// A source that prepares nothing states no bounds on the preparation it
    /// does not do, and a source that prepares something states them all.
    #[test]
    fn statement_preparation_limits_stand_or_fall_with_the_preparation_script() {
        let limits = preparation_limits(8, 1_024);
        EvidenceConfig::parse_yaml(prepared_statement_document(false, None).as_bytes())
            .expect("a statement source that prepares nothing needs no preparation limits");
        EvidenceConfig::parse_yaml(prepared_statement_document(true, Some(&limits)).as_bytes())
            .expect("a preparation script and its bounds are accepted together");
        assert_eq!(
            invalid_reason(&prepared_statement_document(true, None)),
            "statement preparation requires its preparation limits",
        );
        assert_eq!(
            invalid_reason(&prepared_statement_document(false, Some(&limits))),
            "statement preparation limits require a preparation script",
        );
        assert_eq!(
            decode_cause(&prepared_statement_document(
                true,
                Some("{maximumParameters: 8, maximumParameterValueBytes: 1024, surprise: 1}"),
            )),
            "config.unknown-key",
        );
    }

    /// A parameter states where its value comes from, and a prepared parameter
    /// says the preparation script. Neither half stands alone: a script with
    /// nothing prepared to fill could only ever return a name the source
    /// refuses, and a prepared parameter with no script could never be filled.
    #[test]
    fn statement_preparation_stands_or_falls_with_a_prepared_parameter() {
        let limits = preparation_limits(8, 1_024);
        let script_without_a_prepared_parameter = edited(
            &prepared_statement_document(true, Some(&limits)),
            PREPARED_BINDING,
            "",
        );
        let prepared_parameter_without_a_script = edited(
            &sqlite_source_document(),
            SELECTOR_BINDING,
            &format!("{SELECTOR_BINDING}{PREPARED_BINDING}"),
        );
        assert_eq!(
            invalid_reason(&script_without_a_prepared_parameter),
            "statement preparation requires a prepared parameter",
        );
        assert_eq!(
            invalid_reason(&prepared_parameter_without_a_script),
            "a prepared parameter requires a preparation script",
        );

        // The published grammar refuses the same two halves, so an author
        // editing a bundle against the contract is told before a deployment
        // reads it.
        let validator = bundle_contract_validator();
        for refused in [
            &script_without_a_prepared_parameter,
            &prepared_parameter_without_a_script,
        ] {
            assert!(
                !validator.is_valid(&bundle_contract_instance(refused.as_bytes())),
                "the bundle contract accepted half of a preparation",
            );
        }
        for accepted in [
            prepared_statement_document(true, Some(&limits)),
            sqlite_source_document(),
        ] {
            assert!(
                validator.is_valid(&bundle_contract_instance(accepted.as_bytes())),
                "the bundle contract refused a whole statement source",
            );
        }
    }

    #[test]
    fn a_prepared_parameter_carries_its_kind_and_nothing_else() {
        let document = prepared_statement_document(true, Some(&preparation_limits(8, 1_024)));
        let config = EvidenceConfig::parse_yaml(document.as_bytes())
            .expect("a prepared parameter binding parses");
        let SourceConfig::SqliteExtract { request, .. } = &config.sources.0[0].1 else {
            panic!("the restated fixture source uses the sqlite-extract transport");
        };
        assert_eq!(
            request.parameter_bindings.get("normalized_reference"),
            Some(&SqliteParameterBinding::Prepared {}),
        );
        // A prepared parameter has no selector to name, so naming one is the
        // author saying two origins where the source admits exactly one.
        let two_origins = edited(
            &document,
            PREPARED_BINDING,
            "        normalized_reference: {kind: prepared, role: subject}\n",
        );
        assert_eq!(decode_cause(&two_origins), "config.unknown-key");
        assert!(
            !bundle_contract_validator()
                .is_valid(&bundle_contract_instance(two_origins.as_bytes())),
            "the bundle contract accepted a prepared parameter naming a selector",
        );
    }

    #[test]
    fn statement_preparation_bounds_must_admit_every_prepared_parameter() {
        let two_prepared = edited(
            &prepared_statement_document(true, Some(&preparation_limits(1, 1_024))),
            PREPARED_BINDING,
            &format!("{PREPARED_BINDING}        normalized_region: {{kind: prepared}}\n"),
        );
        assert_eq!(
            invalid_reason(&two_prepared),
            "statement preparation limits must admit every prepared parameter",
        );
        EvidenceConfig::parse_yaml(
            edited(
                &two_prepared,
                "maximumParameters: 1",
                "maximumParameters: 2",
            )
            .as_bytes(),
        )
        .expect("a bound equal to the prepared parameter count is admitted");
    }

    #[test]
    fn statement_preparation_bounds_reject_zero_and_an_oversized_value() {
        // Each bound is moved off its own maximum while the other stays valid,
        // so the rejection can only have come from the bound under test.
        for (key, maximum) in [
            ("maximumParameters", 64),
            ("maximumParameterValueBytes", 4_096),
        ] {
            let limits = |value| match key {
                "maximumParameters" => preparation_limits(value, 1_024),
                _ => preparation_limits(8, value),
            };
            for value in [0, maximum + 1] {
                assert_eq!(
                    decode_cause(&prepared_statement_document(true, Some(&limits(value)))),
                    "config.out-of-range",
                    "{key} accepted {value}",
                );
            }
            EvidenceConfig::parse_yaml(
                prepared_statement_document(true, Some(&limits(maximum))).as_bytes(),
            )
            .unwrap_or_else(|error| panic!("{key} rejected its own maximum: {error}"));
        }
    }

    fn bundle_contract_validator() -> jsonschema::JSONSchema {
        let schema: serde_norway::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/contracts/bundle.schema.yaml"
        ))
        .expect("bundle contract is YAML");
        let schema = serde_json::to_value(schema).expect("bundle contract converts to JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema)
            .expect("bundle contract compiles")
    }

    fn runtime_contract_validator() -> jsonschema::JSONSchema {
        let schema: serde_norway::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/contracts/runtime.schema.yaml"
        ))
        .expect("runtime contract is YAML");
        let schema = serde_json::to_value(schema).expect("runtime contract converts to JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema)
            .expect("runtime contract compiles")
    }

    fn bundle_contract_instance(yaml: &[u8]) -> serde_json::Value {
        let value: serde_norway::Value =
            serde_norway::from_slice(yaml).expect("bundle instance is YAML");
        serde_json::to_value(value).expect("bundle instance converts to JSON")
    }

    /// Canary scalars planted in a malformed document.
    ///
    /// A diagnostic that ever reproduces one of these has leaked a deployment
    /// value, which is exactly what the safe-diagnostic contract forbids.
    const CANARY_VALUES: [&str; 4] = [
        "s3cr3t-selector-value",
        "urn:gov:example:canary:subject:9910",
        "secret:file/canary-private-key",
        "https://canary.internal.example",
    ];

    #[test]
    fn decode_failures_report_a_pointer_a_position_and_no_document_value() {
        let reference = include_str!("../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle/evidence.yaml");
        let unknown_nested = reference.replacen(
            "      timeoutMilliseconds: 3000",
            "      timeoutMilliseconds: 3000\n      surprise: s3cr3t-selector-value",
            1,
        );
        assert_ne!(unknown_nested, reference, "nested mutation applies");
        let unknown_nested_line = line_of(&unknown_nested, "surprise:");
        // Label, document, code, pointer, and line of the expected refusal.
        type Case = (
            &'static str,
            String,
            &'static str,
            Option<&'static str>,
            Option<usize>,
        );
        let out_of_range = reference.replacen(
            "      timeoutMilliseconds: 3000",
            "      timeoutMilliseconds: 987654321",
            1,
        );
        assert_ne!(out_of_range, reference, "range mutation applies");
        let out_of_range_line = line_of(&out_of_range, "timeoutMilliseconds: 987654321");
        let cases: [Case; 7] = [
            (
                "malformed YAML",
                format!("version: 1\nbroken: [{}\n", CANARY_VALUES[0]),
                "yaml.unexpected-end",
                None,
                None,
            ),
            (
                "unknown top-level field",
                format!("version: 1\nbogusField: {}\n", CANARY_VALUES[1]),
                "config.unknown-key",
                Some("/bogusField"),
                Some(2),
            ),
            (
                // A source is read through its tagged transport with
                // positions kept inside the variant, so the refusal names the
                // member itself.
                "unknown nested field",
                unknown_nested,
                "config.unknown-key",
                None,
                Some(unknown_nested_line),
            ),
            (
                "wrong type",
                format!("version: {}\n", CANARY_VALUES[2]),
                "config.expected-integer",
                Some("/version"),
                Some(1),
            ),
            (
                "integer outside its bound",
                out_of_range,
                "config.out-of-range",
                None,
                Some(out_of_range_line),
            ),
            (
                "missing field",
                "version: 1\n".to_owned(),
                "config.missing-key",
                Some(""),
                Some(1),
            ),
            (
                "more than one document",
                format!("version: 1\n---\nversion: {}\n", CANARY_VALUES[3]),
                "yaml.multiple-documents",
                None,
                None,
            ),
        ];
        for (label, document, expected_code, expected_pointer, expected_line) in cases {
            let diagnostics = bundle_refusal(&document);
            let found = diagnostics
                .iter()
                .find(|diagnostic| {
                    diagnostic.code == expected_code
                        && expected_pointer.is_none_or(|pointer| diagnostic.path == pointer)
                })
                .unwrap_or_else(|| panic!("{label}: no {expected_code} in {diagnostics:?}"));
            if let Some(line) = expected_line {
                assert_eq!(
                    found.source.as_ref().and_then(|source| source.line),
                    Some(line),
                    "{label} line"
                );
            }
            let rendered = serde_json::to_string(&diagnostics).expect("diagnostics serialize");
            for canary in CANARY_VALUES
                .iter()
                .chain(["s3cr3t-selector-value", "987654321"].iter())
            {
                assert!(
                    !rendered.contains(canary),
                    "{label} diagnostic leaked a document value: {rendered}"
                );
            }
        }
    }

    #[test]
    fn exact_secret_reference_grammars_are_closed() {
        for valid in [
            "secret:file/a",
            "secret:file/source-token_v2.json",
            "secret:env/SOURCE_2_PASSWORD",
        ] {
            assert!(SecretReference::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "secret:env/",
            "secret:env/lower",
            "secret:env/A-B",
            "secret:file/Upper",
            "secret:file/../token",
            "secret:file/.token",
            "plain-value",
        ] {
            assert!(SecretReference::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn decimal_comparison_is_exact() {
        assert_eq!(
            compare_decimal_text("-10.5", "-2"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_decimal_text("1.2", "1.20"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(compare_decimal_text("10", "2"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn all_coequal_acceptance_definitions_use_the_same_typed_config() {
        for yaml in [
            include_bytes!("../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/residence-region/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/professional-licence/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml").as_slice(),
        ] {
            EvidenceConfig::parse_yaml(yaml).expect("acceptance definition must validate");
        }
    }

    #[test]
    fn requirement_validity_cannot_exceed_the_signing_maximum() {
        // Startup validation is the enforcement point: runtime construction
        // derives validUntil from the validated requirement validity, so no
        // constructed assertion can exceed the bundle signing maximum and no
        // redundant signing-time check exists.
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        assert!(EvidenceConfig::parse_yaml_reporting_rule(yaml.as_bytes()).is_ok());
        let shrunk_maximum = yaml.replace(
            "maximumAssertionValiditySeconds: 300",
            "maximumAssertionValiditySeconds: 299",
        );
        assert_ne!(
            shrunk_maximum, yaml,
            "fixture mutation must remain effective"
        );
        assert!(matches!(
            EvidenceConfig::parse_yaml_reporting_rule(shrunk_maximum.as_bytes()),
            Err(ConfigError::Invalid(
                "requirement validity exceeds signing maximum validity"
            ))
        ));
    }

    #[test]
    fn the_advertised_verifier_skew_stays_within_what_a_policy_may_express() {
        // A deployment advertises `verifierClockSkewSeconds` so a relying party
        // can adopt it, and a relying party expresses what it adopted as
        // `clockSkewSeconds`. An advertised value no conformant policy can hold
        // would be unusable advice, so the two bounds are one bound. Both are
        // read from the contracts here rather than restated, so moving either
        // one alone fails.
        let bundle: serde_json::Value = serde_json::to_value(
            serde_norway::from_slice::<serde_norway::Value>(include_bytes!(
                "../../../products/evidence/contracts/bundle.schema.yaml"
            ))
            .expect("bundle contract is YAML"),
        )
        .expect("bundle contract converts to JSON");
        let policy: serde_json::Value = serde_json::to_value(
            serde_norway::from_slice::<serde_norway::Value>(include_bytes!(
                "../../../products/evidence/contracts/verification-policy.schema.yaml"
            ))
            .expect("verification policy contract is YAML"),
        )
        .expect("verification policy contract converts to JSON");
        let advertised = bundle["properties"]["signing"]["properties"]["verifierClockSkewSeconds"]
            ["maximum"]
            .as_u64()
            .expect("the advertised skew declares an integer maximum");
        let expressible = policy["properties"]["clockSkewSeconds"]["maximum"]
            .as_u64()
            .expect("the expressible skew declares an integer maximum");
        assert_eq!(
            advertised, expressible,
            "a deployment may advertise a skew no conformant verification policy can express"
        );

        // Startup validation is the enforcement point, and it must agree with
        // the contract rather than carry its own bound.
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        assert!(EvidenceConfig::parse_yaml(yaml.as_bytes()).is_ok());
        let validator = bundle_contract_validator();
        for (skew, accepted) in [(expressible, true), (expressible + 1, false)] {
            let mutated = yaml.replace(
                "verifierClockSkewSeconds: 30",
                &format!("verifierClockSkewSeconds: {skew}"),
            );
            assert_ne!(mutated, yaml, "{skew}");
            assert_eq!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_ok(),
                accepted,
                "startup validation disagrees with the contract at {skew}"
            );
            assert_eq!(
                validator
                    .validate(&bundle_contract_instance(mutated.as_bytes()))
                    .is_ok(),
                accepted,
                "the bundle contract disagrees with startup validation at {skew}"
            );
        }
    }

    #[test]
    fn response_formats_are_closed_unique_and_keep_signed_mandatory() {
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        for (from, to) in [
            // The bundle cannot drop the mandatory signed format.
            (
                "\nresponseFormats: [signed-jws, unsigned-json]",
                "\nresponseFormats: [unsigned-json]",
            ),
            // Formats must be unique.
            (
                "\nresponseFormats: [signed-jws, unsigned-json]",
                "\nresponseFormats: [signed-jws, signed-jws]",
            ),
            // A grant cannot drop the mandatory signed format either.
            (
                "        responseFormats: [signed-jws, unsigned-json]\n        subjects:\n          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}",
                "        responseFormats: [unsigned-json]\n        subjects:\n          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}",
            ),
            // The vocabulary is closed.
            (
                "\nresponseFormats: [signed-jws, unsigned-json]",
                "\nresponseFormats: [signed-jws, jws-detached]",
            ),
        ] {
            let mutated = yaml.replace(from, to);
            assert_ne!(mutated, yaml, "{to}");
            assert!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn subject_roles_fit_the_evidence_request_contract() {
        let role = |length: usize| SubjectRole {
            role: format!("a{}", "b".repeat(length - 1)),
            cardinality: SubjectCardinality::One,
            selector_profiles: set(["person-demographics-v1".to_owned()]),
        };
        assert!(role(64).validate().is_ok());
        assert!(role(65).validate().is_err());
    }

    #[test]
    fn bundle_contract_accepts_every_complete_version_one_bundle() {
        let validator = bundle_contract_validator();
        for yaml in [
            include_bytes!("../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/professional-licence/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/residence-region/evidence.yaml").as_slice(),
            // A profile bundle rather than a fifth coequal acceptance
            // definition, so it belongs here, where the claim is only that a
            // complete bundle satisfies the published contract, and not in the
            // coequal-definition list next door.
            include_bytes!("../../../products/evidence/fixtures/acceptance/surviving-spouse-status/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/conformance/selectors/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence/bundle/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle/evidence.yaml").as_slice(),
        ] {
            assert!(validator.is_valid(&bundle_contract_instance(yaml)));
        }
    }

    #[test]
    fn bundle_contract_closes_concept_constraints_by_form() {
        let validator = bundle_contract_validator();
        let valid = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ));
        assert!(validator.is_valid(&valid));

        let mut misspelled = valid.clone();
        let constraints = misspelled["requirements"][0]["concepts"][1]["constraints"]
            .as_object_mut()
            .expect("controlled-code constraints are an object");
        let version = constraints
            .remove("codelistVersion")
            .expect("canonical constraint exists");
        constraints.insert("codelist_version".to_owned(), version);
        assert!(!validator.is_valid(&misspelled));

        let mut unsupported = valid;
        unsupported["requirements"][0]["concepts"][0]["constraints"]["maximumBytes"] =
            serde_json::json!(32);
        assert!(!validator.is_valid(&unsupported));

        let mut invalid_identifier = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ));
        invalid_identifier["requirements"][0]["concepts"][3]["constraints"]["prefix"] =
            serde_json::json!("urn:example:report:bad space:");
        assert!(!validator.is_valid(&invalid_identifier));

        let mut structured_projection = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ));
        structured_projection["requirements"][0]["concepts"][11]["sdJwtVc"] =
            serde_json::json!({"claim": "birthCertificate", "disclosure": "top-level"});
        assert!(validator.is_valid(&structured_projection));
        structured_projection["requirements"][0]["concepts"][11]
            .as_object_mut()
            .expect("concept is an object")
            .remove("sdJwtVc");
        structured_projection["requirements"][0]["concepts"][0]["sdJwtVc"] =
            serde_json::json!({"claim": "birthCertificate", "disclosure": "top-level"});
        assert!(!validator.is_valid(&structured_projection));
    }

    /// A list concept's declared cardinality is checked while the bundle
    /// loads, not when a question first reaches the concept.
    ///
    /// The kernel checks an actual list length against the declared range
    /// every time it projects one, but that check runs only for a concept some
    /// question reached. An incoherent range on a concept no fixture case and
    /// no configured grant exercises would otherwise sit in a deployment that
    /// started cleanly and refuse the first real request that ever reached it.
    /// `validate_collection_constraints` runs over every concept of every
    /// requirement during `EvidenceConfig::validate`, so the deployment does
    /// not start at all.
    ///
    /// The cause names the rule and not the concept: `ConfigError::Invalid`
    /// carries fixed text by contract, and a concept handle or id is
    /// configured content.
    #[test]
    fn list_concept_cardinality_is_refused_at_load_not_when_a_question_reaches_it() {
        const SUPPORTED_VALUES: &str = include_str!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        );
        EvidenceConfig::parse_yaml_reporting_rule(SUPPORTED_VALUES.as_bytes())
            .expect("the conformance fixture validates as written");

        const INCOHERENT: &str = "collection constraints are invalid";
        const OUT_OF_BOUNDS: &str = "numeric value is outside Version 1 bounds";
        for (form, sound, unsound) in [
            (
                ConceptForm::ControlledCodeList,
                "minimumItems: 1, maximumItems: 3, unique: true",
                [
                    ("minimumItems: 3, maximumItems: 1, unique: true", INCOHERENT),
                    (
                        "minimumItems: 1, maximumItems: 3, unique: false",
                        INCOHERENT,
                    ),
                    (
                        "minimumItems: 1, maximumItems: 65, unique: true",
                        OUT_OF_BOUNDS,
                    ),
                    (
                        "minimumItems: 0, maximumItems: 3, unique: true",
                        OUT_OF_BOUNDS,
                    ),
                ],
            ),
            (
                ConceptForm::EntityReferenceList,
                "minimumItems: 1, maximumItems: 2, unique: true",
                [
                    ("minimumItems: 2, maximumItems: 1, unique: true", INCOHERENT),
                    (
                        "minimumItems: 1, maximumItems: 2, unique: false",
                        INCOHERENT,
                    ),
                    (
                        "minimumItems: 1, maximumItems: 65, unique: true",
                        OUT_OF_BOUNDS,
                    ),
                    (
                        "minimumItems: 0, maximumItems: 2, unique: true",
                        OUT_OF_BOUNDS,
                    ),
                ],
            ),
        ] {
            for (replacement, cause) in unsound {
                let document = edited(SUPPORTED_VALUES, sound, replacement);
                assert_eq!(
                    invalid_reason(&document),
                    cause,
                    "{form:?} accepted {replacement}"
                );
            }
        }

        // The concept the fixture cases never disclose is refused just the
        // same, so the refusal cannot depend on a question reaching it.
        let unreached = edited(
            SUPPORTED_VALUES,
            "minimumItems: 1, maximumItems: 2, unique: true",
            "minimumItems: 2, maximumItems: 1, unique: true",
        );
        let error = EvidenceConfig::parse_yaml_reporting_rule(unreached.as_bytes())
            .expect_err("an unreached list concept is refused before anything is evaluated");
        assert_eq!(error.fault().cause(), INCOHERENT);
    }

    #[test]
    fn structured_sd_jwt_claim_projection_is_generic_unique_and_non_reserved() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ))
        .expect("supported values fixture validates");
        let structured_index = config.requirements[0]
            .concepts
            .iter()
            .position(|concept| concept.form == ConceptForm::ReviewedStructuredValue)
            .expect("fixture has a structured concept");
        config.requirements[0].concepts[structured_index].sd_jwt_vc =
            Some(SdJwtVcConceptProjection {
                claim: "anyReviewedRecord".to_owned(),
                disclosure: SdJwtVcDisclosureMode::TopLevel,
            });
        config.validate().expect("generic claim name is accepted");

        config.requirements[0].concepts[structured_index]
            .sd_jwt_vc
            .as_mut()
            .expect("projection exists")
            .claim = "iss".to_owned();
        assert!(
            config.validate().is_err(),
            "profile claim names are reserved"
        );

        config.requirements[0].concepts[structured_index]
            .sd_jwt_vc
            .as_mut()
            .expect("projection exists")
            .claim = "duplicateClaim".to_owned();
        let mut duplicate = config.requirements[0].concepts[structured_index].clone();
        duplicate.handle = "another-structured-value".to_owned();
        duplicate.id = "urn:example:fixture:concept:another-structured-value".to_owned();
        config.requirements[0].concepts.push(duplicate);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid(
                "requirement SD-JWT VC claim names must be unique"
            ))
        ));

        config.requirements[0].concepts.pop();
        let projection = config.requirements[0].concepts[structured_index]
            .sd_jwt_vc
            .take();
        config.requirements[0].concepts[0].sd_jwt_vc = projection;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid(
                "SD-JWT VC field projection requires a reviewed structured value"
            ))
        ));
    }

    #[test]
    fn typed_config_rejects_noncanonical_constraint_names() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/residence-region/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        let misspelled = valid.replacen("codelistVersion", "codelist_version", 1);
        assert_ne!(misspelled, valid, "fixture mutation must remain effective");
        assert!(EvidenceConfig::parse_yaml(misspelled.as_bytes()).is_err());
    }

    #[test]
    fn source_schema_roles_are_mandatory_distinct_and_directory_scoped() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        assert!(EvidenceConfig::parse_yaml(valid.as_bytes()).is_ok());

        for (from, to) in [
            // The response contract is mandatory, so extraction never runs
            // behind an undeclared response shape.
            ("    responseSchema: schemas/response.schema.yaml\n", ""),
            // Every schema artifact is directory-scoped like the other roles.
            (
                "responseSchema: schemas/response.schema.yaml",
                "responseSchema: adapters/response.schema.yaml",
            ),
            // One artifact cannot carry two schema roles inside one source.
            (
                "responseSchema: schemas/response.schema.yaml",
                "responseSchema: schemas/facts.schema.yaml",
            ),
            (
                "responseSchema: schemas/response.schema.yaml",
                "responseSchema: schemas/adapter-parameters.schema.yaml",
            ),
        ] {
            let mutated = valid.replace(from, to);
            assert_ne!(mutated, valid, "fixture mutation must remain effective");
            assert!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn schema_roles_do_not_overlap_across_sources() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        assert!(EvidenceConfig::parse_yaml_reporting_rule(valid.as_bytes()).is_ok());

        // One artifact validating a response for one source and facts for
        // another would make a single review cover two different contracts.
        let crossed = valid.replacen(
            "responseSchema: schemas/adult-status-response.schema.yaml",
            "responseSchema: schemas/residence-region-facts.schema.yaml",
            1,
        );
        assert_ne!(crossed, valid, "fixture mutation must remain effective");
        assert!(matches!(
            EvidenceConfig::parse_yaml_reporting_rule(crossed.as_bytes()),
            Err(ConfigError::Invalid(
                "source schema roles must not overlap across sources"
            ))
        ));
    }

    #[test]
    fn yaml_names_and_secret_references_are_strict() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        assert!(
            EvidenceConfig::parse_yaml(valid.replace("providerId", "provider_id").as_bytes())
                .is_err()
        );
        let unexpected = valid.replacen(
            "service: {providerId: urn:example:fixture:provider:evidence, publicOrigin: https://evidence.invalid, trustDomain: urn:example:fixture:trust-domain:acceptance}",
            "service: {providerId: urn:example:fixture:provider:evidence, publicOrigin: https://evidence.invalid, trustDomain: urn:example:fixture:trust-domain:acceptance, unexpected: true}",
            1,
        );
        assert_ne!(unexpected, valid, "fixture mutation must remain effective");
        assert!(EvidenceConfig::parse_yaml(unexpected.as_bytes()).is_err());
        let literal_secret = valid.replacen(
            "hashKeyRef: secret:file/audit-hash-key",
            "hashKeyRef: literal-audit-key",
            1,
        );
        assert_ne!(
            literal_secret, valid,
            "fixture mutation must remain effective"
        );
        assert!(EvidenceConfig::parse_yaml(literal_secret.as_bytes(),).is_err());
        let invalid_revocation = valid.replacen(
            "revokedKeyIds: []",
            "revokedKeyIds: [\"invalid\\u000Akey\"]",
            1,
        );
        assert_ne!(
            invalid_revocation, valid,
            "fixture mutation must remain effective"
        );
        assert!(EvidenceConfig::parse_yaml(invalid_revocation.as_bytes()).is_err());

        let external_revocation = valid.replacen(
            "revokedKeyIds: []",
            "revokedKeyIds: [external-issuer-key-v7]",
            1,
        );
        assert_ne!(
            external_revocation, valid,
            "fixture mutation must remain effective"
        );
        assert!(EvidenceConfig::parse_yaml(external_revocation.as_bytes()).is_ok());
    }

    #[test]
    fn context_and_grant_claim_maps_are_exact_and_non_aliasing() {
        let profile: SelectorProfile = serde_norway::from_str(
            "maximumAggregateBytes: 32\nfields:\n  alpha: {type: string, minimumBytes: 1, maximumBytes: 16}\n  beta: {type: boolean}\n",
        )
        .expect("selector profile parses");
        let exact: GrantedSubject = serde_norway::from_str(
            "role: subject\nselectorProfile: opaque-v1\nvalueOrigin: authenticated-context\nvalueClaims: {alpha: claims.alpha, beta: claims.beta}\n",
        )
        .expect("subject parses");
        assert!(exact.validate_value_claims(&profile).is_ok());

        for invalid_subject in [
            "role: subject\nselectorProfile: opaque-v1\nvalueOrigin: authenticated-context\nvalueClaims: {alpha: claims.alpha}\n",
            "role: subject\nselectorProfile: opaque-v1\nvalueOrigin: authenticated-grant\nvalueClaims: {alpha: claims.same, beta: claims.same}\n",
            "role: subject\nselectorProfile: opaque-v1\nvalueOrigin: request\nvalueClaims: {alpha: claims.alpha, beta: claims.beta}\n",
        ] {
            let subject: GrantedSubject =
                serde_norway::from_str(invalid_subject).expect("subject shape parses");
            assert!(subject.validate_value_claims(&profile).is_err());
        }
    }

    #[test]
    fn complete_authority_paths_cannot_be_unioned_across_partial_grants() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml"
        ))
        .expect("fixture validates");
        config.authority_profiles.0[0].1.grants[0].subjects.pop();
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid(
                "authority grant must bind the complete subject-role set"
            ))
        );
    }

    #[test]
    fn active_source_role_sets_reject_unreachable_inputs_at_startup() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml"
        ))
        .expect("fixture validates");
        http_request(&mut config).selector_inputs[0]
            .alternatives
            .push(SelectorInputAlternative {
                profile: "person-reference-v1".to_owned(),
                fields: set(["person_reference".to_owned()]),
            });
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid(
                "source selector input is unreachable from every complete authority path"
            ))
        );
    }

    #[test]
    fn one_source_may_serve_mutually_exclusive_complete_role_sets() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("adult fixture validates");

        let mut alternative = config.requirements[0].clone();
        alternative.handle = "adult-status-alternative".to_owned();
        alternative.id = "urn:example:fixture:requirement:adult-status-alternative:v1".to_owned();
        alternative.subject_roles[0].role = "alternate-subject".to_owned();
        alternative.evidence_type =
            "urn:example:fixture:evidence-type:adult-status-alternative:v1".to_owned();
        alternative.derivation.script =
            ArtifactPath::parse("derivations/adult-status-alternative.rhai")
                .expect("alternative derivation path");
        alternative.concepts[0].id =
            "urn:example:fixture:concept:adult-status-alternative".to_owned();
        alternative.concepts[0].handle = "adult-status-alternative".to_owned();
        alternative.disclosure_guard.families =
            set(["urn:example:fixture:disclosure-family:adult-status-alternative".to_owned()]);

        let mut grant = config.authority_profiles.0[0].1.grants[0].clone();
        grant.requirement = alternative.id.clone();
        grant.subjects[0].role = "alternate-subject".to_owned();
        config.authority_profiles.0[0].1.grants.push(grant);

        let alternative_inputs = http_request(&mut config)
            .selector_inputs
            .iter()
            .cloned()
            .map(|mut input| {
                input.role = "alternate-subject".to_owned();
                input
            })
            .collect::<Vec<_>>();
        http_request(&mut config)
            .selector_inputs
            .extend(alternative_inputs);
        config.requirements.push(alternative);

        config
            .validate()
            .expect("mutually exclusive role sets may reuse fixed placements");
        assert_eq!(
            config.source_selector_sets("source-a"),
            vec![
                vec![(
                    "alternate-subject".to_owned(),
                    "person-demographics-v1".to_owned()
                )],
                vec![("subject".to_owned(), "person-demographics-v1".to_owned())]
            ]
        );
    }

    #[test]
    fn one_trust_domain_and_native_token_identity_are_closed_configuration() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        let invalid = valid.replacen(
            "service: {providerId: urn:example:fixture:provider:evidence, publicOrigin: https://evidence.invalid, trustDomain: urn:example:fixture:trust-domain:acceptance}",
            "service: {providerId: urn:example:fixture:provider:evidence, publicOrigin: https://evidence.invalid, trustDomains: [urn:example:fixture:trust-domain:a, urn:example:fixture:trust-domain:b]}",
            1,
        );
        assert_ne!(invalid, valid, "fixture mutation must remain effective");
        assert!(EvidenceConfig::parse_yaml(invalid.as_bytes()).is_err());
    }

    #[test]
    fn source_urls_reject_insecure_aliases_and_ambiguous_numeric_hosts() {
        for valid in [
            "https://source.invalid",
            "http://127.0.0.1:18081",
            "http://127.42.5.9",
            "http://[::1]:18083",
        ] {
            assert!(validate_source_origin(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "http://localhost:18081",
            "http://127.1:18081",
            "http://127.00.0.1:18081",
            "http://192.168.1.2",
            "https://user@source.invalid",
            "https://source.invalid/path",
            "https://source.invalid#fragment",
        ] {
            assert!(validate_source_origin(invalid).is_err(), "{invalid}");
        }
    }

    /// `Url::parse` is forgiving in ways a deployment contract cannot be. It
    /// strips tab, newline, and carriage return from anywhere in the string,
    /// strips leading and trailing C0 controls and spaces, and percent-encodes
    /// or punycodes most of what is left that it does not recognize. Requests
    /// are sent to the parsed form while a client assertion audience that the
    /// bundle does not state is signed as the configured form, so any character
    /// the parser rewrites leaves those two naming different strings, and the
    /// audience names one no authorization server ever published. RFC 3986
    /// admits none of these characters in a URI unencoded, so refusing them
    /// costs no deployment that could have worked.
    #[test]
    fn source_urls_reject_characters_a_uri_cannot_carry() {
        let origins = [
            "https://source.invalid ",
            " https://source.invalid",
            "https://source.invalid\u{9}",
            "https://source.invalid\u{a}",
            "https://source.invalid\u{d}",
            "https://source.invalid\u{0}",
            "https://source.invalid\u{7f}",
            "https://sourcé.invalid",
        ];
        let accepted = origins
            .iter()
            .filter(|value| validate_source_origin(value).is_ok())
            .collect::<Vec<_>>();
        assert!(
            accepted.is_empty(),
            "baseUrl accepted characters a URI cannot carry: {accepted:?}"
        );

        let endpoints = [
            "https://source.invalid/token ",
            "https://source.invalid/to\u{9}ken",
            "https://source.invalid/to\u{a}ken",
            "https://source.invalid/to\u{d}ken",
            "https://source.invalid/token\u{0}",
            "https://source.invalid/token\u{7f}",
            "https://source.invalid/tokén",
        ];
        let accepted = endpoints
            .iter()
            .filter(|value| validate_source_url(value, false).is_ok())
            .collect::<Vec<_>>();
        assert!(
            accepted.is_empty(),
            "tokenEndpoint accepted characters a URI cannot carry: {accepted:?}"
        );
    }

    #[test]
    fn source_adapter_name_is_audit_safe_and_oauth_endpoint_has_no_query() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");

        let uppercase_adapter = valid.replace(
            "extractScript: adapters/source-a.rhai",
            "extractScript: adapters/Source-a.rhai",
        );
        assert_eq!(
            EvidenceConfig::parse_yaml_reporting_rule(uppercase_adapter.as_bytes()),
            Err(ConfigError::Invalid(
                "source adapter name must be a local identifier"
            ))
        );

        for query in [
            "?client_secret=plaintext",
            "?client_id=duplicate",
            "?fixed=true",
        ] {
            let mut oauth = EvidenceConfig::parse_yaml_reporting_rule(valid.as_bytes())
                .expect("fixture validates");
            *http_authentication(&mut oauth) = SourceAuthentication::Oauth2ClientCredentials {
                token_endpoint: format!("https://source.invalid/token{query}"),
                client_id_ref: SecretReference::parse("secret:file/oauth-client-id")
                    .expect("secret ref"),
                client_secret_ref: Some(
                    SecretReference::parse("secret:file/oauth-client-secret").expect("secret ref"),
                ),
                client_assertion_key_ref: None,
                client_assertion_audience: None,
                scope: None,
                audience: None,
                resource: None,
                credential_placement: Some(CredentialPlacement::FormBody),
                maximum_cache_seconds: BoundedU64::new(60).expect("a valid cache bound"),
                assumed_lifetime_seconds: None,
            };
            assert_eq!(
                oauth.validate(),
                Err(ConfigError::Invalid(
                    "OAuth token endpoint must not contain a query"
                )),
                "{query}"
            );
        }
    }

    /// A bound violation names the closed field label it applies to, so an
    /// operator reading a deployment diagnostic learns which collection or
    /// value refused without any configured value being carried.
    #[test]
    fn a_field_labelled_fault_names_its_field_and_nothing_else() {
        let fault = SchemaFault::because_in_field(
            "collection cardinality is outside Version 1 bounds",
            "publication jurisdictions",
        );
        assert_eq!(
            fault.to_string(),
            "collection cardinality is outside Version 1 bounds (publication jurisdictions)"
        );
        assert_eq!(fault.field(), Some("publication jurisdictions"));
        assert_eq!(
            fault.cause(),
            "collection cardinality is outside Version 1 bounds"
        );
        assert!(
            SchemaFault::because("a cause").field().is_none(),
            "an unlabelled fault stays unlabelled"
        );
        let labelled = ConfigError::InvalidField(
            "numeric value is outside Version 1 bounds",
            "OAuth assumed token lifetime",
        );
        assert_eq!(
            labelled.fault().to_string(),
            "numeric value is outside Version 1 bounds (OAuth assumed token lifetime)"
        );
    }

    /// The assumed lifetime is a governed positive duration, so a zero or
    /// oversized value is a configuration error rather than a silent clamp.
    #[test]
    fn oauth_assumed_token_lifetime_is_a_bounded_positive_duration() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");

        for (assumed_lifetime_seconds, accepted) in [
            (Some(0), false),
            (Some(1), true),
            (Some(86_400), true),
            (Some(86_401), false),
            (None, true),
        ] {
            // The bound is the member's own type, so a value outside it
            // cannot be constructed, let alone validated.
            let Ok(assumed) = assumed_lifetime_seconds.map(BoundedU64::new).transpose() else {
                assert!(!accepted, "{assumed_lifetime_seconds:?} was refused");
                continue;
            };
            assert!(accepted, "{assumed_lifetime_seconds:?} was constructed");
            let mut oauth =
                EvidenceConfig::parse_yaml(valid.as_bytes()).expect("fixture validates");
            *http_authentication(&mut oauth) = SourceAuthentication::Oauth2ClientCredentials {
                token_endpoint: "https://source.invalid/token".to_owned(),
                client_id_ref: SecretReference::parse("secret:file/oauth-client-id")
                    .expect("secret ref"),
                client_secret_ref: Some(
                    SecretReference::parse("secret:file/oauth-client-secret").expect("secret ref"),
                ),
                client_assertion_key_ref: None,
                client_assertion_audience: None,
                scope: None,
                audience: None,
                resource: None,
                credential_placement: Some(CredentialPlacement::FormBody),
                maximum_cache_seconds: BoundedU64::new(60).expect("a valid cache bound"),
                assumed_lifetime_seconds: assumed,
            };
            assert_eq!(oauth.validate(), Ok(()), "{assumed_lifetime_seconds:?}");
        }
    }

    /// Query-string placement puts the client id and secret in a URL that
    /// authorization-server, proxy, and ingress logs capture, and RFC 6749
    /// section 2.3.1 requires those parameters to travel in the request body.
    /// Version 1 accepts only the two placements the specification defines,
    /// and the runtime and the published contract must agree on that.
    #[test]
    fn oauth_credential_placement_rejects_the_query_string_placement() {
        let validator = bundle_contract_validator();
        for (placement, accepted) in [
            ("basic-header", true),
            ("form-body", true),
            ("query-string", false),
        ] {
            let authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://source.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "clientSecretRef": "secret:file/oauth-client-secret",
                "credentialPlacement": placement,
                "maximumCacheSeconds": 60,
            });
            assert_eq!(
                serde_json::from_value::<SourceAuthentication>(authentication.clone()).is_ok(),
                accepted,
                "{placement} runtime deserialization"
            );

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{placement} bundle contract"
            );
        }
    }

    /// The resource indicator is an exact governed URI, not an outbound URL
    /// or the client assertion audience. Invalid values fail at configuration
    /// validation before a credential or token request can be made.
    #[test]
    fn oauth_resource_indicator_is_optional_and_rejects_relative_or_ambiguous_values() {
        let validator = bundle_contract_validator();
        for (resource, accepted) in [
            (None, true),
            (Some("https://api.invalid:443/records"), true),
            (Some("https://api.invalid/records%20archive"), true),
            (Some("https://[::1]/records"), true),
            (Some("urn:example:records"), true),
            (Some(""), false),
            (Some("api.invalid/records"), false),
            (Some("https://api.invalid/records#fragment"), false),
            (Some("https://user@api.invalid/records"), false),
            (Some("https://api.invalid/é"), false),
            (Some("https://api.invalid/records with space"), false),
            (Some("https://api.invalid/%GG"), false),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://issuer.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "clientSecretRef": "secret:file/oauth-client-secret",
                "credentialPlacement": "form-body",
                "maximumCacheSeconds": 60,
            });
            if let Some(resource) = resource {
                authentication["resource"] = serde_json::json!(resource);
            }
            let parsed: SourceAuthentication = serde_json::from_value(authentication.clone())
                .expect("the closed authentication shape deserializes");
            assert_eq!(parsed.validate().is_ok(), accepted, "runtime: {resource:?}");
            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "schema: {resource:?}"
            );
        }
    }

    /// The kind writes the Authorization header, and RFC 9110 section 11.1
    /// makes the scheme a token the origin chooses. Deployed sources ask for
    /// schemes other than Bearer, and `static-api-key` cannot serve them
    /// because it refuses the Authorization header by name, so the scheme has
    /// to be statable here. It stays a token so no configured value can inject
    /// a second header field.
    #[test]
    fn static_authorization_scheme_is_an_optional_http_token() {
        let validator = bundle_contract_validator();
        for (scheme, accepted) in [
            (Some("Bearer"), true),
            (Some("Token"), true),
            (Some("SSWS"), true),
            (Some("A"), true),
            (Some("x".repeat(32).as_str()), true),
            (Some(""), false),
            (Some("x".repeat(33).as_str()), false),
            (Some("Bearer token"), false),
            (Some("Bear\ner"), false),
            (Some("Bearer:"), false),
            (None, true),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "static-authorization",
                "tokenRef": "secret:file/source-a-token",
            });
            if let Some(scheme) = scheme {
                authentication["scheme"] = serde_json::json!(scheme);
            }

            let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
                .expect("the member set is closed but every scheme string parses");
            assert_eq!(parsed.validate().is_ok(), accepted, "{scheme:?} validation");

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{scheme:?} bundle contract"
            );
        }
    }

    /// RFC 7523 section 2.2 authenticates the client with a signed assertion
    /// instead of a shared secret, and SMART on FHIR Backend Services requires
    /// that form. The two forms are alternatives, not a spectrum: a bundle that
    /// declares both leaves the runtime to guess which credential the operator
    /// meant, and one that declares neither cannot authenticate at all. Both
    /// fail closed at startup rather than at the first token request.
    #[test]
    fn oauth_client_authentication_declares_exactly_one_credential_form() {
        let validator = bundle_contract_validator();
        for (secret_ref, placement, key_ref, accepted) in [
            (
                Some("secret:file/oauth-client-secret"),
                Some("basic-header"),
                None,
                true,
            ),
            (
                Some("secret:file/oauth-client-secret"),
                Some("form-body"),
                None,
                true,
            ),
            (None, None, Some("secret:file/oauth-client-key"), true),
            // A secret with no placement leaves the runtime to pick where the
            // credential travels, which RFC 6749 section 2.3.1 makes the
            // operator's decision.
            (Some("secret:file/oauth-client-secret"), None, None, false),
            // A placement with no secret names a channel for a credential that
            // does not exist.
            (
                None,
                Some("basic-header"),
                Some("secret:file/oauth-client-key"),
                false,
            ),
            (None, Some("basic-header"), None, false),
            // Both forms at once, with and without a placement for the secret.
            // The placement is what makes these two distinct presence shapes
            // rather than one: dropping it must not turn a two-credential
            // bundle into an accepted assertion-only one.
            (
                Some("secret:file/oauth-client-secret"),
                Some("basic-header"),
                Some("secret:file/oauth-client-key"),
                false,
            ),
            (
                Some("secret:file/oauth-client-secret"),
                None,
                Some("secret:file/oauth-client-key"),
                false,
            ),
            // Neither form.
            (None, None, None, false),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://source.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "maximumCacheSeconds": 60,
            });
            if let Some(secret_ref) = secret_ref {
                authentication["clientSecretRef"] = serde_json::json!(secret_ref);
            }
            if let Some(placement) = placement {
                authentication["credentialPlacement"] = serde_json::json!(placement);
            }
            if let Some(key_ref) = key_ref {
                authentication["clientAssertionKeyRef"] = serde_json::json!(key_ref);
            }
            let label = format!("{secret_ref:?}/{placement:?}/{key_ref:?}");

            let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
                .expect("every combination is inside the closed member set");
            assert_eq!(parsed.validate().is_ok(), accepted, "{label} validation");

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{label} bundle contract"
            );
        }
    }

    /// The assertion key is a credential like any other, so bundle validation
    /// has to see it. `secret_refs` is what reports the set a bundle depends
    /// on, and a form whose only credential is invisible there would look
    /// credential-free.
    #[test]
    fn the_client_assertion_key_is_reported_as_a_bundle_secret() {
        let key_form = serde_json::from_value::<SourceAuthentication>(serde_json::json!({
            "kind": "oauth2-client-credentials",
            "tokenEndpoint": "https://source.invalid/token",
            "clientIdRef": "secret:file/oauth-client-id",
            "clientAssertionKeyRef": "secret:file/oauth-client-key",
            "maximumCacheSeconds": 60,
        }))
        .expect("the key form parses");
        assert_eq!(
            key_form
                .secret_refs()
                .iter()
                .map(|reference| reference.as_str())
                .collect::<Vec<_>>(),
            [
                "secret:file/oauth-client-id",
                "secret:file/oauth-client-key"
            ]
        );
    }

    /// Some authorization servers key the issued token to an audience the
    /// scope cannot express, and return a token usable against nothing when it
    /// is absent. The value is a fixed bundle string, never derived per
    /// request.
    #[test]
    fn oauth_audience_is_a_bounded_optional_string() {
        let validator = bundle_contract_validator();
        for (audience, accepted) in [
            (Some("https://api.invalid/"), true),
            (Some("a"), true),
            (Some("a".repeat(512).as_str()), true),
            (Some(""), false),
            // The token request sends this value as it stands, so a blank one
            // asks the authorization server for an audience named by spaces.
            // Refusing it here names the key; the server's refusal would not.
            (Some("   "), false),
            (Some("a".repeat(513).as_str()), false),
            (None, true),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://source.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "clientSecretRef": "secret:file/oauth-client-secret",
                "credentialPlacement": "basic-header",
                "maximumCacheSeconds": 60,
            });
            if let Some(audience) = audience {
                authentication["audience"] = serde_json::json!(audience);
            }
            let label = audience.map(str::len);

            let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
                .expect("the member set is closed but every audience string parses");
            assert_eq!(parsed.validate().is_ok(), accepted, "{label:?} validation");

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{label:?} bundle contract"
            );
        }
    }

    /// RFC 7523 section 3 asks only that the audience identify the
    /// authorization server and leaves the exact string to out-of-band
    /// agreement, so this is an opaque identifier rather than a URL. It is
    /// bounded like the sibling `audience` and validated by the same rule.
    #[test]
    fn the_client_assertion_audience_is_a_bounded_optional_string() {
        let validator = bundle_contract_validator();
        for (audience, accepted) in [
            (Some("https://issuer.invalid/"), true),
            // An issuer identifier that shares no origin with the token
            // endpoint is the case the key exists for, so it has to pass.
            (Some("https://elsewhere.invalid/oauth2"), true),
            (Some("a"), true),
            (Some("a".repeat(512).as_str()), true),
            (Some(""), false),
            // Blank is refused here rather than at the first token request,
            // where signing rejects a whitespace-only audience as empty. A
            // bundle that passes its own contract and then fails as a
            // credential error names nothing the operator can act on.
            (Some("   "), false),
            (Some("a".repeat(513).as_str()), false),
            (None, true),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://source.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "clientAssertionKeyRef": "secret:file/oauth-client-key",
                "maximumCacheSeconds": 60,
            });
            if let Some(audience) = audience {
                authentication["clientAssertionAudience"] = serde_json::json!(audience);
            }
            let label = audience.map(str::len);

            let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
                .expect("the member set is closed but every audience string parses");
            assert_eq!(parsed.validate().is_ok(), accepted, "{label:?} validation");

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{label:?} bundle contract"
            );
        }
    }

    /// Only a signed assertion carries an `aud` claim. Beside a shared secret
    /// the key names an audience nothing will ever send, so accepting it would
    /// leave an operator believing an authorization server was addressed that
    /// never was.
    #[test]
    fn a_client_assertion_audience_without_an_assertion_key_is_refused() {
        let validator = bundle_contract_validator();
        let authentication = serde_json::json!({
            "kind": "oauth2-client-credentials",
            "tokenEndpoint": "https://source.invalid/token",
            "clientIdRef": "secret:file/oauth-client-id",
            "clientSecretRef": "secret:file/oauth-client-secret",
            "credentialPlacement": "basic-header",
            "clientAssertionAudience": "https://issuer.invalid/",
            "maximumCacheSeconds": 60,
        });

        let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
            .expect("the combination is inside the closed member set");
        assert!(
            parsed.validate().is_err(),
            "an assertion audience was accepted beside a client secret"
        );

        let mut instance = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ));
        instance["sources"]["source-a"]["authentication"] = authentication;
        assert!(
            !validator.is_valid(&instance),
            "the bundle contract accepted an assertion audience beside a client secret"
        );
    }

    #[test]
    fn get_sources_must_forbid_the_json_body_channel() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture validates");
        http_request(&mut config).method = HttpMethod::GET;
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid(
                "GET source requests must forbid the JSON body channel"
            ))
        );

        let validator = bundle_contract_validator();
        let mut instance = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ));
        instance["sources"]["source-a"]["request"]["method"] = serde_json::json!("GET");
        assert!(!validator.is_valid(&instance));
    }

    #[test]
    fn a_shared_disclosure_family_rejects_the_complete_bundle() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture validates");
        let mut duplicate = config.requirements[0].clone();
        duplicate.handle = "other".to_owned();
        duplicate.id = "urn:example:fixture:requirement:other:v1".to_owned();
        duplicate.evidence_type = "urn:example:fixture:evidence-type:other:v1".to_owned();
        duplicate.derivation.script =
            ArtifactPath::parse("derivations/other.rhai").expect("artifact path");
        duplicate.concepts[0].id = "urn:example:fixture:concept:other".to_owned();
        duplicate.concepts[0].handle = "other".to_owned();
        config.requirements.push(duplicate);
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid(
                "enabled requirements share a disclosure family"
            ))
        );
    }

    /// A `listener.bind` value for `host` and `port`, bracketing an IPv6 host.
    fn bind_of(host: &str, port: u16) -> String {
        if host.contains(':') {
            format!("'[{host}]:{port}'")
        } else {
            format!("{host}:{port}")
        }
    }

    #[test]
    fn runtime_document_is_closed_and_contains_no_governed_override_surface() {
        let valid = br#"
apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: /etc/registry-evidence/bundle
listener:
  bind: 127.0.0.1:8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
audit:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
outboundTls:
  systemRoots: true
  trustProfiles:
    internal-pki: {caBundleFile: /etc/registry-evidence/ca/internal.pem}
"#;
        let parsed = RuntimeConfig::parse_yaml(valid).expect("closed runtime parses");
        assert_eq!(
            parsed.listener.network_exposure,
            ListenerNetworkExposure::PrivateAddress,
            "existing runtime files retain the private-address listener contract"
        );
        let validator = runtime_contract_validator();
        assert!(validator.is_valid(&bundle_contract_instance(valid)));
        for reference in [
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence/runtime.yaml").as_slice(),
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/runtime.yaml").as_slice(),
        ] {
            assert!(validator.is_valid(&bundle_contract_instance(reference)));
            RuntimeConfig::parse_yaml(reference).expect("reference runtime matches Rust contract");
        }
        for rejected_host in ["evidence.internal", "0.0.0.0", "8.8.8.8", "ff02::1"] {
            let candidate = String::from_utf8(valid.to_vec())
                .expect("runtime fixture is UTF-8")
                .replace(
                    "bind: 127.0.0.1:8080",
                    &format!("bind: {}", bind_of(rejected_host, 8080)),
                );
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "runtime accepted prohibited bind host {rejected_host}"
            );
        }

        for wildcard in ["0.0.0.0", "::"] {
            let candidate = String::from_utf8(valid.to_vec())
                .expect("runtime fixture is UTF-8")
                .replace(
                    "bind: 127.0.0.1:8080",
                    &format!(
                        "bind: {}\n  networkExposure: container-private",
                        bind_of(wildcard, 8080)
                    ),
                );
            let parsed = RuntimeConfig::parse_yaml(candidate.as_bytes())
                .expect("explicit container-private wildcard parses");
            assert_eq!(
                parsed.listener.network_exposure,
                ListenerNetworkExposure::ContainerPrivate
            );
            assert!(validator.is_valid(&bundle_contract_instance(candidate.as_bytes())));
        }
        for rejected_host in ["8.8.8.8", "ff02::1", "evidence.internal"] {
            let candidate = String::from_utf8(valid.to_vec())
                .expect("runtime fixture is UTF-8")
                .replace(
                    "bind: 127.0.0.1:8080",
                    &format!(
                        "bind: {}\n  networkExposure: container-private",
                        bind_of(rejected_host, 8080)
                    ),
                );
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "container-private mode accepted prohibited bind host {rejected_host}"
            );
        }
        for governed_key in [
            "service",
            "issuer",
            "authentication",
            "subjectBinding",
            "rateLimits",
            "signing",
            "selectorProfiles",
            "sources",
            "authorityProfiles",
            "requirements",
        ] {
            let mut candidate = valid.to_vec();
            candidate.extend_from_slice(format!("{governed_key}: {{}}\n").as_bytes());
            let rejection = RuntimeConfig::parse_yaml(&candidate)
                .expect_err("runtime accepted governed bundle key {governed_key}");
            let ConfigError::Refused(report) = &rejection else {
                panic!("runtime accepted governed bundle key {governed_key}: {rejection}");
            };
            let diagnostic = &report.diagnostics()[0];
            assert_eq!(
                diagnostic.code, "config.unknown-key",
                "governed bundle key {governed_key} was rejected for the wrong reason"
            );
            assert_eq!(
                diagnostic.path,
                format!("/{governed_key}"),
                "governed bundle key {governed_key} was rejected without naming it"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(&candidate)),
                "runtime schema accepted governed bundle key {governed_key}"
            );
        }
        // The runtime `audit` block names only the destination. The keyed
        // reference key and its version stay governed in the bundle.
        for governed_audit_key in ["hashKeyRef: secret:file/audit", "hashKeyVersion: 2"] {
            let candidate = String::from_utf8(valid.to_vec())
                .expect("runtime fixture is UTF-8")
                .replace(
                    "audit:\n  path:",
                    &format!("audit:\n  {governed_audit_key}\n  path:"),
                );
            assert_ne!(
                candidate.as_bytes(),
                valid,
                "fixture mutation must remain effective"
            );
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "runtime audit accepted governed key {governed_audit_key}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(candidate.as_bytes())),
                "runtime schema accepted governed audit key {governed_audit_key}"
            );
        }
    }

    /// The runtime `audit` block is validated by the platform destination
    /// rules: a file needs an absolute path, file-only settings are refused
    /// for `stdout`, and rotation and retention stay inside the platform
    /// bounds. The Rust contract and the frozen runtime schema agree on each.
    #[test]
    fn runtime_audit_destination_follows_the_platform_rules() {
        let base = String::from_utf8(
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence/runtime.yaml")
                .to_vec(),
        )
        .expect("reference runtime is UTF-8");
        let mut kept = Vec::new();
        let mut in_audit = false;
        for line in base.lines() {
            if line == "audit:" {
                in_audit = true;
                continue;
            }
            if in_audit && line.starts_with("  ") {
                continue;
            }
            in_audit = false;
            kept.push(line);
        }
        assert!(
            kept.len() < base.lines().count(),
            "reference runtime has an audit block"
        );
        let without_audit = kept.join("\n") + "\n";
        let with_audit = |block: &str| format!("{without_audit}{block}");
        let validator = runtime_contract_validator();

        let file = with_audit("audit:\n  destination: file\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 1048576\n  retainDays: 30\n");
        let parsed = RuntimeConfig::parse_yaml(file.as_bytes()).expect("file destination parses");
        assert!(matches!(
            parsed.audit.destination().expect("destination builds"),
            AuditDestination::File(_)
        ));
        assert!(validator.is_valid(&bundle_contract_instance(file.as_bytes())));

        let defaulted = with_audit("audit:\n  path: /var/lib/evidence/audit.jsonl\n");
        let parsed =
            RuntimeConfig::parse_yaml(defaulted.as_bytes()).expect("defaulted destination parses");
        assert_eq!(parsed.audit.destination, AuditDestinationKind::File);
        assert!(validator.is_valid(&bundle_contract_instance(defaulted.as_bytes())));

        let stdout = with_audit("audit:\n  destination: stdout\n");
        let parsed = RuntimeConfig::parse_yaml(stdout.as_bytes()).expect("stdout parses");
        assert!(matches!(
            parsed.audit.destination().expect("destination builds"),
            AuditDestination::Stdout
        ));
        assert!(validator.is_valid(&bundle_contract_instance(stdout.as_bytes())));

        for (name, block) in [
            ("file-without-path", "audit:\n  destination: file\n"),
            ("relative-path", "audit:\n  path: audit.jsonl\n"),
            (
                "stdout-with-path",
                "audit:\n  destination: stdout\n  path: /var/lib/evidence/audit.jsonl\n",
            ),
            (
                "stdout-with-rotation",
                "audit:\n  destination: stdout\n  rotateBytes: 1048576\n",
            ),
            (
                "stdout-with-retention",
                "audit:\n  destination: stdout\n  retainDays: 30\n",
            ),
            (
                "rotation-below-minimum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 1024\n",
            ),
            (
                "retention-zero",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  retainDays: 0\n",
            ),
            (
                "rotation-above-maximum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 4294967296\n",
            ),
            (
                "retention-above-maximum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  retainDays: 36501\n",
            ),
            ("unknown-destination", "audit:\n  destination: syslog\n"),
            (
                "legacy-maximum-file-bytes",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  maximumFileBytes: 1073741824\n",
            ),
        ] {
            let candidate = with_audit(block);
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "runtime accepted audit block {name}"
            );
        }
        for (name, block) in [
            ("file-without-path", "audit:\n  destination: file\n"),
            (
                "stdout-with-path",
                "audit:\n  destination: stdout\n  path: /var/lib/evidence/audit.jsonl\n",
            ),
            (
                "rotation-below-minimum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 1024\n",
            ),
            (
                "retention-zero",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  retainDays: 0\n",
            ),
            (
                "rotation-above-maximum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 4294967296\n",
            ),
            (
                "retention-above-maximum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  retainDays: 36501\n",
            ),
            ("unknown-destination", "audit:\n  destination: syslog\n"),
            (
                "legacy-maximum-file-bytes",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  maximumFileBytes: 1073741824\n",
            ),
        ] {
            assert!(
                !validator.is_valid(&bundle_contract_instance(with_audit(block).as_bytes())),
                "runtime schema accepted audit block {name}"
            );
        }
        let legacy = with_audit("auditStorage:\n  path: /var/lib/evidence/audit.jsonl\n  maximumFileBytes: 1073741824\n");
        assert!(
            RuntimeConfig::parse_yaml(legacy.as_bytes()).is_err(),
            "runtime accepted the retired auditStorage block"
        );
    }

    /// The metrics listener is opt-in operator surface. It must be absent
    /// unless an operator asks for it, must obey the same private-address rule
    /// as the evidence listener, and must not be able to reuse the evidence
    /// binding, which would publish counters on the contract listener.
    #[test]
    fn the_optional_metrics_listener_is_absent_by_default_and_stays_operator_private() {
        let base = r#"
apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: /etc/registry-evidence/bundle
listener:
  bind: 127.0.0.1:8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
audit:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
outboundTls:
  systemRoots: true
  trustProfiles: {}
"#;
        let validator = runtime_contract_validator();
        let default = RuntimeConfig::parse_yaml(base.as_bytes()).expect("closed runtime parses");
        assert!(
            default.metrics_listener.is_none(),
            "a deployment that asked for no metrics listener must not get one"
        );

        let configured = format!("{base}metricsListener:\n  bind: 127.0.0.1:9090\n");
        assert!(validator.is_valid(&bundle_contract_instance(configured.as_bytes())));
        let parsed =
            RuntimeConfig::parse_yaml(configured.as_bytes()).expect("metrics listener parses");
        let metrics = parsed
            .metrics_listener
            .expect("the configured metrics listener is retained");
        assert_eq!(metrics.bind.socket_addr().to_string(), "127.0.0.1:9090");

        for rejected_host in ["evidence.internal", "0.0.0.0", "8.8.8.8", "ff02::1"] {
            let candidate = format!(
                "{base}metricsListener:\n  bind: {}\n",
                bind_of(rejected_host, 9090)
            );
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "metrics listener accepted prohibited bind host {rejected_host}"
            );
        }

        // Reusing the evidence binding would put the counters on the listener
        // the public contract describes.
        let shared = format!("{base}metricsListener:\n  bind: 127.0.0.1:8080\n");
        assert!(matches!(
            RuntimeConfig::parse_yaml(shared.as_bytes()),
            Err(ConfigError::Invalid(
                "metricsListener must not share the evidence listener binding"
            ))
        ));

        for (wildcard, private) in [("0.0.0.0", "10.0.0.10"), ("::", "fd00::10")] {
            let wildcard_base = base.replace(
                "bind: 127.0.0.1:8080",
                &format!(
                    "bind: {}\n  networkExposure: container-private",
                    bind_of(wildcard, 8080)
                ),
            );
            let shared = format!(
                "{wildcard_base}metricsListener:\n  bind: {}\n",
                bind_of(private, 8080)
            );
            assert!(matches!(
                RuntimeConfig::parse_yaml(shared.as_bytes()),
                Err(ConfigError::Invalid(
                    "metricsListener must not share the evidence listener binding"
                ))
            ));
        }
        let dual_stack_base = base.replace(
            "bind: 127.0.0.1:8080",
            "bind: '[::]:8080'\n  networkExposure: container-private",
        );
        let dual_stack_collision =
            format!("{dual_stack_base}metricsListener:\n  bind: 127.0.0.1:8080\n");
        assert!(matches!(
            RuntimeConfig::parse_yaml(dual_stack_collision.as_bytes()),
            Err(ConfigError::Invalid(
                "metricsListener must not share the evidence listener binding"
            ))
        ));

        // The block is closed like every other level of the document.
        let unknown =
            format!("{base}metricsListener:\n  bind: 127.0.0.1:9090\n  path: /telemetry\n");
        assert!(RuntimeConfig::parse_yaml(unknown.as_bytes()).is_err());
        assert!(!validator.is_valid(&bundle_contract_instance(unknown.as_bytes())));
    }

    /// The operator half of the acquisition gate. A capability list a bundle
    /// author writes beside the requirement that uses it gates nothing, so the
    /// deployment states separately which gated kinds it may serve. Absent
    /// enables none of them, which is what every runtime file written before a
    /// gated form existed says.
    #[test]
    fn the_optional_operator_acquisition_capabilities_enable_nothing_by_default() {
        let base = r#"
apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: /etc/registry-evidence/bundle
listener:
  bind: 127.0.0.1:8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
audit:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
outboundTls:
  systemRoots: true
  trustProfiles: {}
"#;
        let validator = runtime_contract_validator();
        let default = RuntimeConfig::parse_yaml(base.as_bytes()).expect("closed runtime parses");
        assert!(
            default.acquisition_capabilities.is_empty(),
            "a deployment that enabled no gated acquisition kind must not get one"
        );
        assert!(!default.enables_acquisition_capability("search-then-fetch-set"));
        assert!(
            !serde_json::to_string(&default)
                .expect("the runtime configuration projects")
                .contains("acquisitionCapabilities"),
            "an absent capability list must serialize to nothing at all"
        );

        // Writing the list out and enabling nothing says what silence says, so
        // both halves of the closed surface have to read it the same way. The
        // loader accepts it, so the published contract must too: a schema
        // stricter than the loader refuses a file the deployment would load.
        let empty = format!("{base}acquisitionCapabilities: []\n");
        assert!(
            validator.is_valid(&bundle_contract_instance(empty.as_bytes())),
            "the contract refused an empty list startup accepts"
        );
        let parsed = RuntimeConfig::parse_yaml(empty.as_bytes()).expect("an empty list parses");
        assert!(!parsed.enables_acquisition_capability("search-then-fetch-set"));
        assert!(
            !serde_json::to_string(&parsed)
                .expect("the runtime configuration projects")
                .contains("acquisitionCapabilities"),
            "an empty capability list must project as the absent one does"
        );

        for declaration in [
            "acquisitionCapabilities: [search-then-fetch-set]\n",
            // The same declaration in block form, which is what an operator
            // editing the file by hand is most likely to write.
            "acquisitionCapabilities:\n  - search-then-fetch-set\n",
        ] {
            let enabled = format!("{base}{declaration}");
            assert!(
                validator.is_valid(&bundle_contract_instance(enabled.as_bytes())),
                "the contract refused a declaration startup accepts: {declaration}"
            );
            let parsed = RuntimeConfig::parse_yaml(enabled.as_bytes())
                .expect("the enabled capability parses");
            assert_eq!(parsed.acquisition_capabilities, ["search-then-fetch-set"]);
            assert!(parsed.enables_acquisition_capability("search-then-fetch-set"));
            assert!(!parsed.enables_acquisition_capability("search-then-fetch"));
        }

        let source_batch = format!("{base}acquisitionCapabilities: [source-batch]\n");
        let parsed = RuntimeConfig::parse_yaml(source_batch.as_bytes())
            .expect("the source-batch capability parses");
        assert!(parsed.enables_acquisition_capability(SOURCE_BATCH_CAPABILITY));
        assert!(!parsed.enables_acquisition_capability("search-then-fetch-set"));

        for (declaration, expected) in [
            (
                "acquisitionCapabilities: [search-then-fetch-sets]\n",
                "runtime acquisition capabilities name an unknown acquisition kind",
            ),
            // The frozen Version 1 forms are not nameable here. Every
            // deployment already serves them, so naming one would say nothing
            // and leaving one out would have to mean something.
            (
                "acquisitionCapabilities: [single]\n",
                "runtime acquisition capabilities name an unknown acquisition kind",
            ),
            (
                "acquisitionCapabilities: [search-then-fetch]\n",
                "runtime acquisition capabilities name an unknown acquisition kind",
            ),
            (
                "acquisitionCapabilities: [search-then-fetch-set, search-then-fetch-set]\n",
                "runtime acquisition capabilities must be unique",
            ),
            (
                "acquisitionCapabilities: [source-batch, source-batch]\n",
                "runtime acquisition capabilities must be unique",
            ),
        ] {
            let candidate = format!("{base}{declaration}");
            assert_eq!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).err(),
                Some(ConfigError::Invalid(expected)),
                "{declaration}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(candidate.as_bytes())),
                "the contract accepted a declaration startup refuses: {declaration}"
            );
        }

        // The list is a list of names, and the document stays closed around it.
        for malformed in [
            "acquisitionCapabilities: search-then-fetch-set\n",
            "acquisitionCapabilities: {searchThenFetchSet: true}\n",
            "acquisitionCapabilitie: [search-then-fetch-set]\n",
        ] {
            let candidate = format!("{base}{malformed}");
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "{malformed}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(candidate.as_bytes())),
                "{malformed}"
            );
        }
    }

    #[test]
    fn source_batch_optimization_is_fixed_route_two_author_and_pre_io_planned() {
        let document = source_batch_document();
        let config = EvidenceConfig::parse_yaml_reporting_rule(document.as_bytes())
            .expect("batch source validates");
        let requirement = &config.requirements[0].id;
        let runtime = runtime_for_source_batch(true);
        assert_eq!(
            config.source_batch_plan(&runtime, requirement, 2),
            SourceBatchPlan::Optimized {
                source_id: "source-a".to_owned()
            }
        );
        assert_eq!(
            config.source_batch_plan(&runtime, requirement, 3),
            SourceBatchPlan::Sequential,
            "a logical batch over the source ceiling must be selected sequentially"
        );
        assert_eq!(
            config.source_batch_plan(&runtime_for_source_batch(false), requirement, 2),
            SourceBatchPlan::Sequential,
            "the bundle author cannot activate the optimization without the operator"
        );

        let without_bundle_capability =
            edited(&document, "acquisitionCapabilities: [source-batch]\n", "");
        assert_eq!(
            EvidenceConfig::parse_yaml_reporting_rule(without_bundle_capability.as_bytes()).err(),
            Some(ConfigError::Invalid(
                "source batch optimization is not a declared bundle capability"
            )),
            "the source block cannot activate itself without the bundle author"
        );

        let templated = edited(
            &document,
            "      path: /v1/facts\n",
            "      pathTemplate: /v1/facts/{subject}\n      pathBindings:\n        subject: {from: selector, role: subject, profile: person-demographics-v1, field: given_name}\n",
        );
        assert_eq!(
            EvidenceConfig::parse_yaml_reporting_rule(templated.as_bytes()).err(),
            Some(ConfigError::Invalid(
                "source batch optimization requires a fixed request path"
            ))
        );

        let unsafe_adapter = edited(
            &document,
            "      extractScript: adapters/source-extract-batch.rhai\n",
            "      extractScript: adapters/Source-extract-batch.rhai\n",
        );
        assert_eq!(
            EvidenceConfig::parse_yaml_reporting_rule(unsafe_adapter.as_bytes()).err(),
            Some(ConfigError::Invalid(
                "source batch adapter name must be a local identifier"
            )),
            "the batch adapter identity emitted to audit must use the closed local grammar"
        );

        let unresolved_batch = edited(
            &document,
            "    batch:\n",
            "    unresolvedProblem: {status: 404, type: https://id.example.invalid/problems/unresolved, code: consultation.unresolved}\n    batch:\n",
        );
        assert_eq!(
            EvidenceConfig::parse_yaml_reporting_rule(unresolved_batch.as_bytes()).err(),
            Some(ConfigError::Invalid(
                "declared unresolved problems are not supported by source batching"
            )),
            "one physical response cannot resolve one logical batch item"
        );
    }

    #[test]
    fn declared_unresolved_problem_tuple_is_closed_and_bounded() {
        DeclaredUnresolvedProblem {
            status: BoundedU32::new(404).expect("404 is the declared status"),
            type_uri: "https://id.example.invalid/problems/unresolved".to_owned(),
            code: "consultation.unresolved".to_owned(),
        }
        .validate()
        .expect("the exact source-neutral tuple validates");

        for (label, problem) in [
            (
                "type",
                DeclaredUnresolvedProblem {
                    status: BoundedU32::new(404).expect("404 is the declared status"),
                    type_uri: "http://id.example.invalid/problems/unresolved".to_owned(),
                    code: "consultation.unresolved".to_owned(),
                },
            ),
            (
                "code",
                DeclaredUnresolvedProblem {
                    status: BoundedU32::new(404).expect("404 is the declared status"),
                    type_uri: "https://id.example.invalid/problems/unresolved".to_owned(),
                    code: "Consultation Unresolved".to_owned(),
                },
            ),
        ] {
            assert!(problem.validate().is_err(), "{label}");
        }

        // Only 404 is representable, so another status is refused as the
        // bundle is read rather than by the tuple's own rule.
        let other_status = acceptance_fixture().replacen(
            "    posture: field-projected\n",
            "    posture: field-projected\n    unresolvedProblem: {status: 403, type: https://id.example.invalid/problems/unresolved, code: consultation.unresolved}\n",
            1,
        );
        assert!(
            bundle_refusal(&other_status)
                .iter()
                .any(|diagnostic| diagnostic.code == "config.out-of-range"),
            "a status other than 404 is out of range"
        );

        let overlong_type = format!("https://id.example.invalid/problems/{}", "a".repeat(513));
        let candidate = acceptance_fixture().replacen(
            "    posture: field-projected\n",
            &format!(
                "    posture: field-projected\n    unresolvedProblem: {{status: 404, type: {overlong_type}, code: consultation.unresolved}}\n"
            ),
            1,
        );
        assert_eq!(
            EvidenceConfig::parse_yaml_reporting_rule(candidate.as_bytes()).err(),
            Some(ConfigError::Invalid(
                "declared unresolved problem type is too long"
            )),
            "runtime parsing must enforce the schema's 512-character type ceiling"
        );

        assert!(
            DeclaredUnresolvedProblem {
                status: BoundedU32::new(404).expect("404 is the declared status"),
                type_uri: "https://id.example.invalid/problems/unresolved".to_owned(),
                code: format!("a{}", "x".repeat(63)),
            }
            .validate()
            .is_ok(),
            "the bounded ASCII code grammar admits exactly 64 characters"
        );
        assert!(
            DeclaredUnresolvedProblem {
                status: BoundedU32::new(404).expect("404 is the declared status"),
                type_uri: "https://id.example.invalid/problems/unresolved".to_owned(),
                code: format!("a{}", "x".repeat(64)),
            }
            .validate()
            .is_err(),
            "the bounded ASCII code grammar rejects 65 characters"
        );
    }

    #[test]
    fn source_batch_optimization_is_silent_without_a_block_and_never_applies_to_multistage() {
        let with_capability = edited(
            acceptance_fixture(),
            "version: 1\n",
            "version: 1\nacquisitionCapabilities: [source-batch]\n",
        );
        let mut config = EvidenceConfig::parse_yaml(with_capability.as_bytes())
            .expect("a capability with no batch block leaves the source unchanged");
        let requirement = config.requirements[0].id.clone();
        let runtime = runtime_for_source_batch(true);
        assert_eq!(
            config.source_batch_plan(&runtime, &requirement, 2),
            SourceBatchPlan::Sequential
        );

        config = EvidenceConfig::parse_yaml(source_batch_document().as_bytes())
            .expect("batch source validates");
        config.requirements[0].acquisition = AcquisitionConfig::SearchThenFetch {
            search: "source-a".to_owned(),
            fetch: "source-a".to_owned(),
        };
        assert_eq!(
            config.source_batch_plan(&runtime, &requirement, 2),
            SourceBatchPlan::Sequential,
            "multi-stage acquisitions stay on their declared sequential plan"
        );

        let sqlite = EvidenceConfig::parse_yaml(sqlite_source_document().as_bytes())
            .expect("statement source fixture validates");
        assert_eq!(
            sqlite.source_batch_plan(&runtime, &requirement, 2),
            SourceBatchPlan::Sequential,
            "statement sources never enter HTTP batch execution"
        );
    }

    /// Port 0 is not a port. The kernel picks an arbitrary one, so the socket an
    /// operator firewalls, health-checks, and puts behind their TLS terminator
    /// is not the socket the service opens, and it changes on every restart.
    /// The published runtime schema already forbids it on both listeners; the
    /// loader accepting it meant a deployment could pass the documented contract
    /// check and still come up on an address nobody configured. On the metrics
    /// listener it also defeats the binding-collision refusal, which compares
    /// configured ports rather than bound ones.
    #[test]
    fn a_listener_port_of_zero_is_refused_on_both_listeners() {
        let base = r#"
apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: /etc/registry-evidence/bundle
listener:
  bind: 127.0.0.1:8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
audit:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
outboundTls:
  systemRoots: true
  trustProfiles: {}
"#;
        let validator = runtime_contract_validator();
        RuntimeConfig::parse_yaml(base.as_bytes()).expect("the configured ports load");

        let ephemeral_evidence = base.replace("bind: 127.0.0.1:8080", "bind: 127.0.0.1:0");
        assert!(
            RuntimeConfig::parse_yaml(ephemeral_evidence.as_bytes()).is_err(),
            "the evidence listener accepted an ephemeral port"
        );
        assert!(
            !validator.is_valid(&bundle_contract_instance(ephemeral_evidence.as_bytes())),
            "the published schema must already refuse this, so Rust is matching it"
        );

        let ephemeral_metrics = format!("{base}metricsListener:\n  bind: 127.0.0.1:0\n");
        assert!(
            RuntimeConfig::parse_yaml(ephemeral_metrics.as_bytes()).is_err(),
            "the metrics listener accepted an ephemeral port"
        );
        assert!(!validator.is_valid(&bundle_contract_instance(ephemeral_metrics.as_bytes())));

        // Both at zero would compare equal and trip the collision rule instead,
        // so the port rule has to be the one that fires.
        let both = format!(
            "{}metricsListener:\n  bind: 127.0.0.1:0\n",
            base.replace("bind: 127.0.0.1:8080", "bind: 127.0.0.1:0")
        );
        assert!(RuntimeConfig::parse_yaml(both.as_bytes()).is_err());
    }

    #[test]
    fn path_templates_headers_and_projection_fail_closed() {
        let bindings: OrderedMap<PathBindingConfig> = serde_norway::from_str(
            "record_reference: {from: selector, role: subject, profile: record-reference-v1, field: record_reference}\n",
        )
        .expect("path binding parses");
        assert!(validate_path_template("/records/{record_reference}", &bindings).is_ok());
        for invalid_template in [
            "/records/{record_reference}/",
            "/records/prefix-{record_reference}",
            "/records/{missing}",
            "/records/../{record_reference}",
            "/records/{record_reference}/{record_reference}",
        ] {
            assert!(validate_path_template(invalid_template, &bindings).is_err());
        }

        assert!(validate_configurable_header_name("X-API-Version").is_ok());
        for forbidden in RESERVED_HEADER_CONTRACT_CASES {
            assert!(
                validate_configurable_header_name(forbidden).is_err(),
                "{forbidden}"
            );
        }

        assert!(validate_projection(&[
            "/total".to_owned(),
            "/results/*/status".to_owned(),
            "/declaration/mother.personReference".to_owned(),
        ])
        .is_ok());
        for paths in [
            vec!["/results".to_owned(), "/results/*/status".to_owned()],
            vec![
                "/results/*/status".to_owned(),
                "/results/0/status".to_owned(),
            ],
            vec!["/bad/~2escape".to_owned()],
        ] {
            assert!(validate_projection(&paths).is_err());
        }
    }

    #[test]
    fn path_based_https_oidc_issuer_is_preserved_exactly() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture validates");
        config.authentication.oidc.provider.issuer =
            "https://identity.example.test/realms/registry".to_owned();
        assert!(config.validate().is_ok());
        config
            .authentication
            .oidc
            .provider
            .issuer
            .push_str("?tenant=wrong");
        assert!(config.validate().is_err());
    }

    /// A runtime document every refusal test below edits one member of.
    const LOADER_RUNTIME_DOCUMENT: &str =
        "apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: /etc/registry-evidence/bundle
listener:
  bind: 127.0.0.1:8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing-key
audit:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
outboundTls:
  systemRoots: true
  trustProfiles: {}
";

    fn runtime_report(text: &str) -> Report {
        match RuntimeConfig::parse_yaml(text.as_bytes()) {
            Err(ConfigError::Refused(report)) => *report,
            other => panic!("the runtime document was not refused by the reader: {other:?}"),
        }
    }

    fn deciding(report: &Report) -> &registry_platform_yaml::Diagnostic {
        report
            .diagnostics()
            .first()
            .expect("a refusal carries a diagnostic")
    }

    fn position(diagnostic: &registry_platform_yaml::Diagnostic) -> (usize, usize) {
        let source = diagnostic
            .source
            .as_ref()
            .expect("the diagnostic names its source");
        assert_eq!(source.file, "runtime.yaml");
        (
            source.line.expect("a line"),
            source.column.expect("a column"),
        )
    }

    #[test]
    fn the_runtime_document_declares_the_evidence_envelope() {
        RuntimeConfig::parse_yaml(LOADER_RUNTIME_DOCUMENT.as_bytes())
            .expect("the enveloped document loads");

        let unenveloped = LOADER_RUNTIME_DOCUMENT
            .replace(
                "apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1\n",
                "",
            )
            .replace("kind: EvidenceRuntimeConfig\n", "");
        let report = runtime_report(&unenveloped);
        let diagnostic = deciding(&report);
        assert_eq!(diagnostic.code, "config.missing-envelope");
        assert!(
            diagnostic
                .suggested_action
                .contains(EVIDENCE_RUNTIME_API_VERSION),
            "the fix names the apiVersion to write: {diagnostic:?}"
        );

        let other_kind = LOADER_RUNTIME_DOCUMENT
            .replace("kind: EvidenceRuntimeConfig", "kind: RelayRuntimeConfig");
        let report = runtime_report(&other_kind);
        assert_eq!(deciding(&report).code, "config.wrong-kind");
        assert_eq!(deciding(&report).path, "/kind");
        assert_eq!(position(deciding(&report)), (2, 7));
    }

    #[test]
    fn every_removed_runtime_key_is_refused_with_its_replacement_named() {
        let cases = [
            ("version: 1\n", "version"),
            (
                "bundleDirectory: /etc/registry-evidence/bundle\n",
                "bundleDirectory",
            ),
        ];
        for (member, path) in cases {
            let report = runtime_report(&format!("{LOADER_RUNTIME_DOCUMENT}{member}"));
            let diagnostic = deciding(&report);
            assert_eq!(diagnostic.code, "config.removed-key", "{path}");
            assert_eq!(diagnostic.path, format!("/{path}"));
            let expected = EVIDENCE_RUNTIME_REMOVED_KEYS
                .iter()
                .find(|removed| removed.path == path)
                .expect("the key is listed")
                .replacement;
            assert!(
                diagnostic.suggested_action.starts_with(expected),
                "{path}: {diagnostic:?}"
            );
        }
        for path in ["listener.bindHost", "listener.port"] {
            let member = path.rsplit('.').next().expect("a leaf");
            let value = if member == "port" {
                "8080"
            } else {
                "127.0.0.1"
            };
            let text = LOADER_RUNTIME_DOCUMENT.replace(
                "listener:\n  bind: 127.0.0.1:8080\n",
                &format!("listener:\n  bind: 127.0.0.1:8080\n  {member}: {value}\n"),
            );
            let report = runtime_report(&text);
            let diagnostic = deciding(&report);
            assert_eq!(diagnostic.path, format!("/listener/{member}"));
            assert!(
                diagnostic.suggested_action.contains("listener.bind"),
                "{path}"
            );
        }
        let metrics = format!(
            "{LOADER_RUNTIME_DOCUMENT}metricsListener:\n  bindHost: 127.0.0.1\n  port: 9090\n"
        );
        let report = runtime_report(&metrics);
        let removed: Vec<_> = report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.removed-key")
            .collect();
        assert_eq!(removed.len(), 2, "{report:?}");
        assert!(removed
            .iter()
            .all(|diagnostic| diagnostic.suggested_action.contains("metricsListener.bind")));
    }

    #[test]
    fn a_duplicated_runtime_key_is_refused() {
        let duplicated = format!("{LOADER_RUNTIME_DOCUMENT}kind: EvidenceRuntimeConfig\n");
        assert_eq!(
            deciding(&runtime_report(&duplicated)).code,
            "yaml.duplicate-key"
        );
    }

    /// The runtime reports the shared reader's diagnostics unchanged: the
    /// reader's code, the RFC 6901 path, the line and column, and the fix.
    /// No diagnostic and no rendering repeats the value that was refused.
    #[test]
    fn every_runtime_refusal_carries_the_reader_diagnostic_unchanged() {
        const CANARY: &str = "canary-runtime-value-7731";
        let replaced = |from: &str, to: &str| {
            let text = LOADER_RUNTIME_DOCUMENT.replace(from, to);
            assert_ne!(text, LOADER_RUNTIME_DOCUMENT, "{from} is in the document");
            text
        };
        let appended = |member: &str| format!("{LOADER_RUNTIME_DOCUMENT}{member}");
        let nested = format!("{}{CANARY}{}", "[".repeat(200), "]".repeat(200));
        let cases: Vec<(&str, String, &str, &str)> = vec![
            (
                "unknown key",
                appended(&format!("bogusField: {CANARY}\n")),
                "config.unknown-key",
                "/bogusField",
            ),
            (
                "missing key",
                replaced(
                    "audit:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\n",
                    "",
                ),
                "config.missing-key",
                "",
            ),
            (
                "wrong type",
                replaced(
                    "maximumRequestBytes: 65536",
                    &format!("maximumRequestBytes: {CANARY}"),
                ),
                "config.expected-integer",
                "/listener/maximumRequestBytes",
            ),
            (
                "null member",
                replaced(
                    "path: /var/lib/registry-evidence/audit/evidence.jsonl",
                    "path: ~",
                ),
                "config.null-value",
                "/audit/path",
            ),
            (
                "unknown variant",
                replaced(
                    "tlsTermination: operator-controlled-upstream",
                    &format!("tlsTermination: {CANARY}"),
                ),
                "config.unknown-variant",
                "/listener/tlsTermination",
            ),
            (
                "out of range",
                replaced(
                    "maximumConcurrentRequests: 64",
                    "maximumConcurrentRequests: 99999999999",
                ),
                "config.out-of-range",
                "/listener/maximumConcurrentRequests",
            ),
            (
                "above the member's own bound",
                replaced(
                    "maximumConcurrentRequests: 64",
                    "maximumConcurrentRequests: 4097",
                ),
                "config.out-of-range",
                "/listener/maximumConcurrentRequests",
            ),
            (
                "below the member's own bound",
                replaced("maximumRequestBytes: 65536", "maximumRequestBytes: 1023"),
                "config.out-of-range",
                "/listener/maximumRequestBytes",
            ),
            (
                "listener bind",
                replaced(
                    "bind: 127.0.0.1:8080",
                    &format!("bind: {CANARY}.internal:8080"),
                ),
                "config.invalid-value",
                "/listener/bind",
            ),
            (
                "secret reference inside the signer",
                replaced(
                    "privateKeyRef: secret:file/signing-key",
                    &format!("privateKeyRef: {CANARY}"),
                ),
                "config.invalid-value",
                "/signer/privateKeyRef",
            ),
            (
                "unknown signer kind",
                replaced("kind: local-jwk", &format!("kind: {CANARY}")),
                "config.unknown-variant",
                "/signer/kind",
            ),
            (
                "duplicate key",
                appended(&format!("audit: {CANARY}\n")),
                "yaml.duplicate-key",
                "/audit",
            ),
            (
                "more than one document",
                appended(&format!("---\nbogusField: {CANARY}\n")),
                "yaml.multiple-documents",
                "",
            ),
            (
                "nesting",
                appended(&format!("bogusField: {nested}\n")),
                "yaml.too-deep",
                "",
            ),
            (
                "tag",
                replaced(
                    "maximumRequestBytes: 65536",
                    "maximumRequestBytes: !!int 65536",
                ),
                "yaml.tag",
                "/listener/maximumRequestBytes",
            ),
            (
                "key that is not a string",
                appended(&format!("7: {CANARY}\n")),
                "yaml.non-string-key",
                "",
            ),
            (
                "anchor",
                replaced(
                    "privateKeyRef: secret:file/signing-key",
                    "privateKeyRef: &key secret:file/signing-key",
                ),
                "yaml.anchor",
                "/signer/privateKeyRef",
            ),
            (
                "not a mapping",
                format!("- {CANARY}\n"),
                "config.invalid-type",
                "",
            ),
        ];
        for (label, document, code, path) in cases {
            let report = runtime_report(&document);
            let diagnostic = deciding(&report);
            assert_eq!(diagnostic.code, code, "{label}: {diagnostic:?}");
            if !path.is_empty() {
                assert_eq!(diagnostic.path, path, "{label}");
            }
            assert!(
                !diagnostic.suggested_action.is_empty(),
                "{label}: the diagnostic names its fix"
            );
            let error = ConfigError::Refused(Box::new(report.clone()));
            assert!(
                !error.to_string().contains(CANARY)
                    && !report.to_json_value().to_string().contains(CANARY),
                "{label}: the refusal repeats the refused value"
            );
        }
    }

    /// The signer is a tagged union the reader decodes itself, so a refusal
    /// inside a variant keeps its full path, line, and column.
    #[test]
    fn a_bad_secret_reference_inside_the_signer_names_its_path_and_position() {
        let text = LOADER_RUNTIME_DOCUMENT.replace(
            "privateKeyRef: secret:file/signing-key",
            "privateKeyRef: file/signing-key",
        );
        let report = runtime_report(&text);
        let diagnostic = deciding(&report);
        assert_eq!(diagnostic.code, "config.invalid-value");
        assert_eq!(diagnostic.path, "/signer/privateKeyRef");
        assert_eq!(position(diagnostic), (17, 18));
        let rendered = ConfigError::Refused(Box::new(report)).to_string();
        assert!(
            rendered.contains("runtime.yaml:17:18 /signer/privateKeyRef"),
            "{rendered}"
        );

        let transit = LOADER_RUNTIME_DOCUMENT.replace(
            "  kind: local-jwk\n  privateKeyRef: secret:file/signing-key\n",
            "  kind: transit\n  unixSocketPath: /run/transit.sock\n  mount: transit\n  \
             keyName: evidence\n  keyVersion: seven\n  timeoutMilliseconds: 2000\n",
        );
        let report = runtime_report(&transit);
        assert_eq!(deciding(&report).path, "/signer/keyVersion");
        assert_eq!(position(deciding(&report)), (20, 15));
    }

    /// Substitution fills operator values from the environment. It never
    /// reaches a secret reference or the provider configuration, because a
    /// reference that the environment can rename is no longer the reference
    /// the file declares.
    #[test]
    fn environment_substitution_fills_values_and_never_a_secret_reference() {
        let templated = LOADER_RUNTIME_DOCUMENT.replace(
            "path: /var/lib/registry-evidence/audit/evidence.jsonl",
            "path: ${EVIDENCE_AUDIT_PATH}",
        );
        let loaded = RuntimeConfig::parse_yaml_with(templated.as_bytes(), |name| {
            (name == "EVIDENCE_AUDIT_PATH").then(|| "/srv/audit/evidence.jsonl".to_owned())
        })
        .expect("the substituted document loads");
        assert_eq!(
            loaded.config.audit.path.as_deref(),
            Some("/srv/audit/evidence.jsonl")
        );
        let plain = RuntimeConfig::parse_yaml_with(LOADER_RUNTIME_DOCUMENT.as_bytes(), |_| None)
            .expect("the plain document loads");
        assert_ne!(
            loaded.effective_digest, plain.effective_digest,
            "the effective digest covers the substituted value"
        );

        let unset = RuntimeConfig::parse_yaml_with(templated.as_bytes(), |_| None);
        assert!(
            unset.is_err(),
            "an unset variable without a default is refused"
        );

        for (from, to) in [
            (
                "privateKeyRef: secret:file/signing-key",
                "privateKeyRef: ${SIGNING_KEY_REF}",
            ),
            (
                "file: {root: /run/secrets/registry-evidence}",
                "file: {root: \"${SECRET_ROOT}\"}",
            ),
        ] {
            let text = LOADER_RUNTIME_DOCUMENT.replace(from, to);
            let refused = RuntimeConfig::parse_yaml_with(text.as_bytes(), |_| {
                Some("secret:file/other".to_owned())
            });
            let Err(ConfigError::Refused(report)) = refused else {
                panic!("substitution into {from} was accepted");
            };
            assert_eq!(
                report.diagnostics()[0].code,
                "config.substitution-not-allowed",
                "{from}"
            );
        }
    }

    #[test]
    fn the_environment_secret_provider_is_enabled_only_by_declaration() {
        let enabled = LOADER_RUNTIME_DOCUMENT.replace(
            "file: {root: /run/secrets/registry-evidence}",
            "file: {root: /run/secrets/registry-evidence}\n  environment: {}",
        );
        let config = RuntimeConfig::parse_yaml(enabled.as_bytes()).expect("both providers load");
        assert!(config.secret_providers.environment.is_some());

        let only_environment = LOADER_RUNTIME_DOCUMENT
            .replace(
                "file: {root: /run/secrets/registry-evidence}",
                "environment: {}",
            )
            .replace(
                "privateKeyRef: secret:file/signing-key",
                "privateKeyRef: secret:env/EVIDENCE_SIGNING_KEY",
            );
        RuntimeConfig::parse_yaml(only_environment.as_bytes())
            .expect("an environment-only deployment loads");

        let undeclared = LOADER_RUNTIME_DOCUMENT.replace(
            "privateKeyRef: secret:file/signing-key",
            "privateKeyRef: secret:env/EVIDENCE_SIGNING_KEY",
        );
        assert!(
            RuntimeConfig::parse_yaml(undeclared.as_bytes()).is_err(),
            "a runtime reference to a provider the file does not enable is refused"
        );

        let none = LOADER_RUNTIME_DOCUMENT.replace(
            "secretProviders:\n  file: {root: /run/secrets/registry-evidence}\n",
            "secretProviders: {}\n",
        );
        assert!(RuntimeConfig::parse_yaml(none.as_bytes()).is_err());
    }

    #[test]
    fn an_expected_package_digest_must_be_a_sha256_label() {
        let pinned = LOADER_RUNTIME_DOCUMENT.replace(
            "  root: /etc/registry-evidence/bundle\n",
            "  root: /etc/registry-evidence/bundle\n  expectedDigest: sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
        );
        RuntimeConfig::parse_yaml(pinned.as_bytes()).expect("a pinned package loads");
        let malformed = LOADER_RUNTIME_DOCUMENT.replace(
            "  root: /etc/registry-evidence/bundle\n",
            "  root: /etc/registry-evidence/bundle\n  expectedDigest: md5:00\n",
        );
        assert!(RuntimeConfig::parse_yaml(malformed.as_bytes()).is_err());
    }

    /// The adult-status acceptance bundle, which every bundle-reader test
    /// edits into the case it proves.
    fn acceptance_bundle() -> String {
        String::from_utf8(
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            )
            .to_vec(),
        )
        .expect("fixture is UTF-8")
    }

    /// The diagnostics a refused bundle carries.
    fn bundle_refusal(text: &str) -> Vec<registry_platform_yaml::Diagnostic> {
        match EvidenceConfig::parse_yaml(text.as_bytes()) {
            Err(ConfigError::Refused(report)) => report.into_diagnostics(),
            Err(other) => panic!("the bundle was refused outside the reader: {other}"),
            Ok(_) => panic!("the bundle was accepted"),
        }
    }

    /// The one-based line on which `needle` first appears in `text`.
    fn line_of(text: &str, needle: &str) -> usize {
        text.lines()
            .position(|line| line.contains(needle))
            .expect("the needle is in the text")
            + 1
    }

    #[test]
    fn every_removed_bundle_authentication_and_audit_key_is_refused_with_its_replacement_named() {
        let valid = acceptance_bundle();
        EvidenceConfig::parse_yaml(valid.as_bytes()).expect("fixture validates");
        for removed in EVIDENCE_BUNDLE_REMOVED_KEYS {
            let mut segments = removed.pointer[1..].split('/').collect::<Vec<_>>();
            let leaf = segments.pop().expect("a leaf");
            let mut value =
                serde_norway::from_str::<serde_norway::Value>(&valid).expect("fixture parses");
            let mut parent = &mut value;
            for segment in &segments {
                parent = parent
                    .as_mapping_mut()
                    .expect("a mapping")
                    .entry(serde_norway::Value::from(*segment))
                    .or_insert_with(|| serde_norway::Value::Mapping(Default::default()));
            }
            parent.as_mapping_mut().expect("a mapping").insert(
                serde_norway::Value::from(leaf),
                serde_norway::Value::from("x"),
            );
            let text = serde_norway::to_string(&value).expect("the candidate serializes");
            let diagnostics = bundle_refusal(&text);
            let refusal = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.path == removed.pointer)
                .unwrap_or_else(|| panic!("{} was not refused", removed.pointer));
            assert_eq!(refusal.code, "config.removed-key", "{}", removed.pointer);
            assert_eq!(
                refusal.suggested_action, removed.replacement,
                "{}",
                removed.pointer
            );
            let source = refusal.source.as_ref().expect("a position");
            assert!(source.line.is_some(), "{}", removed.pointer);
        }
    }

    #[test]
    fn an_authored_bundle_carrying_an_environment_expression_is_refused() {
        let valid = acceptance_bundle();
        let candidate = valid.replace(
            "publicOrigin: https://evidence.invalid",
            "publicOrigin: 'https://${EVIDENCE_HOST}'",
        );
        assert_ne!(candidate, valid, "the fixture carries the public origin");
        let diagnostics = bundle_refusal(&candidate);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        let refusal = &diagnostics[0];
        assert_eq!(refusal.code, "config.substitution-not-allowed");
        assert_eq!(refusal.path, "/service/publicOrigin");
        let source = refusal.source.as_ref().expect("a position");
        assert_eq!(source.line, Some(line_of(&candidate, "publicOrigin:")));
        let rendered = serde_json::to_string(&diagnostics).expect("diagnostics serialize");
        assert!(!rendered.contains("EVIDENCE_HOST"));
    }

    #[test]
    fn an_environment_expression_in_a_bundle_key_is_refused() {
        let valid = acceptance_bundle();
        let candidate = valid.replacen("    principalClaim:", "    ${EVIDENCE_KEY}:", 1);
        assert_ne!(candidate, valid);
        let diagnostics = bundle_refusal(&candidate);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.substitution-not-allowed")
            .expect("the expression in the key is refused");
        let source = refusal.source.as_ref().expect("a position");
        assert_eq!(source.line, Some(line_of(&candidate, "${EVIDENCE_KEY}:")));
    }

    #[test]
    fn a_bad_member_inside_a_tagged_source_reports_its_full_path_and_position() {
        let valid = acceptance_bundle();
        let candidate = valid.replacen(
            "    transport: http-json",
            "    transport: http-json\n    unexpectedMember: 1",
            1,
        );
        assert_ne!(candidate, valid, "the fixture declares an HTTP source");
        let diagnostics = bundle_refusal(&candidate);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        let refusal = &diagnostics[0];
        assert_eq!(refusal.code, "config.unknown-key");
        assert_eq!(refusal.path, "/sources/source-a/unexpectedMember");
        let source = refusal.source.as_ref().expect("a position");
        assert_eq!(source.line, Some(line_of(&candidate, "unexpectedMember")));
        assert_eq!(source.column, Some(5));
    }

    #[test]
    fn every_unknown_key_in_the_oidc_block_is_reported() {
        let valid = acceptance_bundle();
        let candidate = valid.replacen(
            "    issuer:",
            "    firstStray: 1\n    secondStray: 2\n    issuer:",
            1,
        );
        assert_ne!(candidate, valid, "the fixture declares an OIDC issuer");
        let diagnostics = bundle_refusal(&candidate);
        let paths = diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                ("config.unknown-key", "/authentication/oidc/firstStray"),
                ("config.unknown-key", "/authentication/oidc/secondStray"),
            ]
        );
    }

    #[test]
    fn a_bundle_rule_violation_is_placed_at_the_member_it_concerns() {
        let valid = acceptance_bundle();
        let candidate = valid.replacen(
            "subjectBinding: {secretRef: secret:file/subject-binding-key,",
            "subjectBinding: {secretRef: secret:file/audit-hash-key,",
            1,
        );
        assert_ne!(
            candidate, valid,
            "the fixture binds subjects with its own key"
        );
        let diagnostics = bundle_refusal(&candidate);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        let refusal = &diagnostics[0];
        assert_eq!(refusal.code, "evidence.bundle.invalid-subject-binding");
        assert_eq!(refusal.path, "/subjectBinding/secretRef");
        let source = refusal.source.as_ref().expect("a position");
        assert_eq!(source.line, Some(line_of(&candidate, "subjectBinding:")));
    }

    #[test]
    fn a_quoted_integer_and_a_null_are_refused_in_the_bundle() {
        let valid = acceptance_bundle();
        let quoted = valid.replacen("hashKeyVersion: 1", "hashKeyVersion: '1'", 1);
        assert_ne!(quoted, valid);
        let diagnostics = bundle_refusal(&quoted);
        assert_eq!(diagnostics[0].path, "/audit/hashKeyVersion");
        assert_eq!(diagnostics[0].code, "config.expected-integer");
        let null = valid.replacen("hashKeyVersion: 1", "hashKeyVersion: null", 1);
        let diagnostics = bundle_refusal(&null);
        assert_eq!(diagnostics[0].path, "/audit/hashKeyVersion");
        assert_eq!(diagnostics[0].code, "config.null-value");
    }

    #[test]
    fn bundle_key_versions_stay_inside_the_contract_range() {
        let valid = acceptance_bundle();
        let validator = bundle_contract_validator();
        for (member, path) in [
            ("hashKeyVersion: 1", "/audit/hashKeyVersion"),
            ("keyVersion: 1", "/subjectBinding/keyVersion"),
        ] {
            let name = member.trim_end_matches(" 1");
            for (version, accepted) in [
                (0_u64, false),
                (1, true),
                (2_147_483_647, true),
                (2_147_483_648, false),
            ] {
                let mutated = valid.replacen(member, &format!("{name} {version}"), 1);
                assert!(
                    version == 1 || mutated != valid,
                    "the mutation applies at {path}"
                );
                assert_eq!(
                    validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                    accepted,
                    "the contract disagrees at {path} {version}"
                );
                if accepted {
                    EvidenceConfig::parse_yaml(mutated.as_bytes())
                        .unwrap_or_else(|_| panic!("{path} {version} is inside the range"));
                } else {
                    let diagnostics = bundle_refusal(&mutated);
                    assert_eq!(
                        diagnostics[0].code, "config.out-of-range",
                        "{path} {version}"
                    );
                    assert_eq!(diagnostics[0].path, path, "{version}");
                }
            }
        }
    }

    #[test]
    fn access_token_keys_come_only_from_a_fixed_jwks_uri() {
        let valid = String::from_utf8(
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            )
            .to_vec(),
        )
        .expect("fixture is UTF-8");
        let config = EvidenceConfig::parse_yaml(valid.as_bytes()).expect("fixture validates");
        let JwksSource::Uri { uri } = &config.authentication.oidc.provider.jwks_source else {
            panic!("the fixture names a fixed JWKS URI");
        };
        for refused in [
            JwksSource::Discovery {},
            JwksSource::Static {
                document_ref: "secret:file/jwks".to_owned(),
            },
        ] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.provider.jwks_source = refused;
            assert_eq!(
                candidate.validate(),
                Err(ConfigError::InvalidField(
                    "Evidence reads access-token keys only from jwksSource kind uri",
                    "authentication.oidc.jwksSource",
                ))
            );
        }
        let omitted = valid.replace(
            &format!("    jwksSource:\n      kind: uri\n      uri: {uri}\n"),
            "",
        );
        assert_ne!(omitted, valid, "fixture mutation must remain effective");
        assert!(
            EvidenceConfig::parse_yaml(omitted.as_bytes()).is_err(),
            "an omitted key source means discovery, which Evidence refuses"
        );
    }

    #[test]
    fn governed_secret_references_name_a_provider_and_never_a_value() {
        assert!(SecretReference::parse("secret:file/source-token").is_ok());
        // Whether the runtime enables the environment provider is checked when
        // the bundle is bound to its runtime configuration.
        assert!(SecretReference::parse("secret:env/SOURCE_TOKEN").is_ok());
        assert!(SecretReference::parse("literal-token").is_err());
    }

    #[test]
    fn service_revoked_key_ids_require_canonical_sha256_thumbprints() {
        let canonical = "A".repeat(43);
        assert!(validate_key_identifiers(&[canonical], 33, "revoked keys").is_ok());

        let noncanonical = format!("{}B", "A".repeat(42));
        assert_eq!(noncanonical.len(), 43);
        assert!(validate_key_identifiers(&[noncanonical], 33, "revoked keys").is_err());
    }

    /// Two declared fetch members, each the ordinary fixed request every
    /// Version 1 source already is, bound to the reference the search resolved.
    const MEMBER_SOURCES: &str = r#"  source-e:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-e-token}
    request:
      method: GET
      pathTemplate: /v1/first/{record_id}
      pathBindings:
        record_id: {from: prior-fact, field: record_id}
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/first-member-prepare.rhai
      adapterParameters: {profile: first}
      adapterParametersSchema: schemas/first-member-adapter-parameters.schema.yaml
      preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
      projection: [/total]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/first-member-response.schema.yaml
    extractScript: adapters/first-member-source.rhai
    factSchema: schemas/first-member-facts.schema.yaml
  source-f:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-f-token}
    request:
      method: GET
      pathTemplate: /v1/second/{record_id}
      pathBindings:
        record_id: {from: prior-fact, field: record_id}
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/second-member-prepare.rhai
      adapterParameters: {profile: second}
      adapterParametersSchema: schemas/second-member-adapter-parameters.schema.yaml
      preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
      projection: [/total]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/second-member-response.schema.yaml
    extractScript: adapters/second-member-source.rhai
    factSchema: schemas/second-member-facts.schema.yaml
  source-b:
"#;

    const DECLARED_ACQUISITION: &str = "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n      maximumAcquisitionMilliseconds: 8000\n";

    const DECLARED_MEMBERS: &str = "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n";

    const FIRST_MEMBER: &str = "        - {source: source-e, factInputs: [record_id]}\n";

    /// One acceptance bundle rewritten into the declared fetch-set profile: the
    /// bundle declares the capability, and the first requirement resolves one
    /// reference through its search and reads that reference through two
    /// declared members.
    fn fetch_set_bundle() -> String {
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        let declared = yaml.replace(
            "\nselectorProfiles:\n",
            "\nacquisitionCapabilities: [search-then-fetch-set]\n\nselectorProfiles:\n",
        );
        assert_ne!(declared, yaml, "the capability declaration applies");
        let acquired = declared.replace(
            "    acquisition:\n      kind: single\n      source: source-a\n",
            DECLARED_ACQUISITION,
        );
        assert_ne!(acquired, declared, "the fetch-set acquisition applies");
        let members = acquired.replace("  source-b:\n", MEMBER_SOURCES);
        assert_ne!(members, acquired, "the declared members apply");
        members
    }

    #[test]
    fn fetch_set_acquisition_requires_two_to_four_distinct_configured_members() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        EvidenceConfig::parse_yaml_reporting_rule(yaml.as_bytes())
            .expect("the declared fetch set validates");
        assert!(
            validator.is_valid(&bundle_contract_instance(yaml.as_bytes())),
            "the contract rejects the declared fetch set"
        );

        // The contract closes the shape and the width; the identity relations
        // between the declared members and the search belong to the parser,
        // which is the only side that can read one identifier against another.
        for (members, expected, contract_accepts) in [
            (
                "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n",
                "requirement acquisition declares too few fetch members",
                false,
            ),
            (
                "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n        - {source: source-g, factInputs: [record_id]}\n        - {source: source-h, factInputs: [record_id]}\n        - {source: source-i, factInputs: [record_id]}\n",
                "requirement acquisition declares too many fetch members",
                false,
            ),
            (
                "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-e, factInputs: [record_namespace]}\n",
                "requirement acquisition fetch members must be distinct",
                true,
            ),
            (
                "      fetch:\n        - {source: source-a, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n",
                "requirement acquisition fetch member repeats the search source",
                true,
            ),
            (
                "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n        - {source: source-z, factInputs: [record_id]}\n",
                "requirement acquisition references an unknown source",
                true,
            ),
            (
                "      fetch:\n        - {source: Source-E, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n",
                "search-then-fetch-set source identifiers are invalid",
                false,
            ),
        ] {
            let mutated = yaml.replace(DECLARED_MEMBERS, members);
            assert_ne!(mutated, yaml, "{expected}");
            assert_eq!(
                EvidenceConfig::parse_yaml_reporting_rule(mutated.as_bytes()).err(),
                Some(ConfigError::Invalid(expected)),
                "{expected}"
            );
            assert_eq!(
                validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                contract_accepts,
                "{expected}"
            );
        }
    }

    #[test]
    fn fetch_set_acquisition_requires_a_budget_inside_the_declared_range() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        for (budget, accepted) in [(0, false), (1, true), (30_000, true), (30_001, false)] {
            let mutated = yaml.replace(
                "      maximumAcquisitionMilliseconds: 8000\n",
                &format!("      maximumAcquisitionMilliseconds: {budget}\n"),
            );
            assert_ne!(mutated, yaml, "{budget}");
            if accepted {
                EvidenceConfig::parse_yaml(mutated.as_bytes())
                    .unwrap_or_else(|_| panic!("the budget {budget} is inside the range"));
            } else {
                assert_eq!(decode_cause(&mutated), "config.out-of-range", "{budget}");
            }
            assert_eq!(
                validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                accepted,
                "the contract disagrees with startup validation at {budget}"
            );
        }
    }

    #[test]
    fn fetch_set_acquisition_requires_a_non_empty_fact_input_allowlist() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        let excessive = (0..17)
            .map(|index| format!("input_{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        for (member, expected) in [
            (
                "        - {source: source-e, factInputs: []}\n".to_owned(),
                "requirement acquisition fetch member declares no fact inputs",
            ),
            (
                format!("        - {{source: source-e, factInputs: [{excessive}]}}\n"),
                "requirement acquisition fetch member declares too many fact inputs",
            ),
            (
                "        - {source: source-e, factInputs: [record_id, record_id]}\n".to_owned(),
                "requirement acquisition fetch member fact inputs must be unique",
            ),
            (
                "        - {source: source-e, factInputs: [Record_Id]}\n".to_owned(),
                "requirement acquisition fetch member fact input is invalid",
            ),
        ] {
            let mutated = yaml.replace(FIRST_MEMBER, &member);
            assert_ne!(mutated, yaml, "{expected}");
            assert_eq!(
                EvidenceConfig::parse_yaml_reporting_rule(mutated.as_bytes()).err(),
                Some(ConfigError::Invalid(expected)),
                "{expected}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                "the contract accepted an allowlist startup validation refuses: {expected}"
            );
        }
    }

    #[test]
    fn fetch_set_acquisition_must_be_declared_in_bundle_acquisition_capabilities() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        for (capabilities, expected, contract_accepts) in [
            (
                "",
                Some("requirement acquisition kind is not a declared bundle capability"),
                false,
            ),
            // Writing the list out and declaring nothing says what silence
            // says, and the contract refuses both for the same reason it
            // refuses silence. The published contract is what an author
            // validates against before deploying, so a document it certifies
            // has to be one startup can serve; a gated kind whose capability
            // is undeclared is the one cross-declaration relation a schema can
            // state, and leaving it to the loader alone would certify a bundle
            // that cannot serve.
            (
                "acquisitionCapabilities: []\n",
                Some("requirement acquisition kind is not a declared bundle capability"),
                false,
            ),
            (
                "acquisitionCapabilities: [search-then-fetch-sets]\n",
                Some("bundle acquisition capabilities name an unknown acquisition kind"),
                false,
            ),
            (
                "acquisitionCapabilities: [search-then-fetch-set, search-then-fetch-set]\n",
                Some("bundle acquisition capabilities must be unique"),
                false,
            ),
            (
                "acquisitionCapabilities: [single, search-then-fetch-set]\n",
                Some("bundle acquisition capabilities name an unknown acquisition kind"),
                false,
            ),
            // The same declaration in block form: valid, and textually
            // distinct from the bundle's own flow-sequence spelling.
            (
                "acquisitionCapabilities:\n  - search-then-fetch-set\n",
                None,
                true,
            ),
        ] {
            let mutated = yaml.replace(
                "acquisitionCapabilities: [search-then-fetch-set]\n",
                capabilities,
            );
            assert_ne!(mutated, yaml, "{capabilities}");
            assert_eq!(
                EvidenceConfig::parse_yaml_reporting_rule(mutated.as_bytes())
                    .err()
                    .map(|error| match error {
                        ConfigError::Invalid(cause) => cause,
                        other => panic!("{capabilities} failed for another reason: {other}"),
                    }),
                expected,
                "{capabilities}"
            );
            assert_eq!(
                validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                contract_accepts,
                "{capabilities}"
            );
        }
    }

    #[test]
    fn bundle_contract_closes_the_fetch_set_acquisition_form() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        for (acquisition, reason) in [
            (
                "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n",
                "the budget is required",
            ),
            (
                "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id], order: 1}\n        - {source: source-f, factInputs: [record_id]}\n      maximumAcquisitionMilliseconds: 8000\n",
                "a member declares only its source and its fact inputs",
            ),
            (
                "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n      maximumAcquisitionMilliseconds: 8000\n      concurrent: true\n",
                "the acquisition form is closed",
            ),
            (
                "    acquisition:\n      kind: search-then-fetch-sets\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n      maximumAcquisitionMilliseconds: 8000\n",
                "the kind vocabulary is closed",
            ),
        ] {
            let mutated = yaml.replace(DECLARED_ACQUISITION, acquisition);
            assert_ne!(mutated, yaml, "{reason}");
            assert!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_err(),
                "{reason}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                "{reason}"
            );
        }
    }

    #[test]
    fn fetch_set_members_are_the_acquisitions_fetch_sources() {
        let yaml = fetch_set_bundle();
        let config = EvidenceConfig::parse_yaml_reporting_rule(yaml.as_bytes())
            .expect("the declared fetch set validates");
        let requirement = &config.requirements[0];
        assert_eq!(requirement.acquisition.initial_source(), "source-a");
        assert_eq!(
            requirement.acquisition.source_ids(),
            vec!["source-a", "source-e", "source-f"]
        );
        assert_eq!(
            requirement.acquisition.fetch_sources(),
            vec!["source-e", "source-f"]
        );
        assert!(requirement.acquisition.uses_source("source-f"));
        assert!(!requirement.acquisition.uses_source("source-b"));
        assert_eq!(
            config.requirement_acquisition_posture(&requirement.id),
            Some(AcquisitionPosture::FieldProjected)
        );

        // The members are the only sources this bundle fetches, so returning
        // the requirement to one call leaves their prior-fact bindings on
        // sources nothing fetches, which is the refusal that proves members
        // carry the fetch-source rule rather than escaping it.
        let unfetched = yaml.replace(
            DECLARED_ACQUISITION,
            "    acquisition:\n      kind: single\n      source: source-a\n",
        );
        assert_ne!(unfetched, yaml, "the single-call rewrite applies");
        assert_eq!(
            EvidenceConfig::parse_yaml_reporting_rule(unfetched.as_bytes()).err(),
            Some(ConfigError::Invalid(
                "prior-fact path bindings are permitted only on fetch sources"
            ))
        );
    }

    #[test]
    fn a_fetch_set_member_receives_only_its_declared_fact_inputs() {
        let search_facts = BTreeMap::from([
            (
                "record_id".to_owned(),
                serde_json::json!("urn:example:fixture:record:1"),
            ),
            (
                "record_namespace".to_owned(),
                serde_json::json!("urn:example:fixture:namespace"),
            ),
        ]);
        let declared = StageInputs::Declared(vec!["record_id".to_owned()]);
        assert_eq!(
            declared.project(&search_facts),
            BTreeMap::from([(
                "record_id".to_owned(),
                serde_json::json!("urn:example:fixture:record:1")
            )])
        );

        // The forms that predate the allowlist keep the inputs they froze: one
        // call reads no prior fact, and the single fetch reads all of them.
        assert!(StageInputs::None.project(&search_facts).is_empty());
        assert_eq!(
            StageInputs::EveryPriorFact.project(&search_facts),
            search_facts
        );
    }

    /// Every acquisition form describes itself as the same ordered value, so
    /// the runtime, the offline fixture harness, and adopter tooling read one
    /// derivation of the call order rather than three that can drift.
    #[test]
    fn every_acquisition_form_plans_its_stages_in_declared_order() {
        let single = AcquisitionConfig::Single {
            source: "source-a".to_owned(),
        };
        assert_eq!(
            single.plan(),
            AcquisitionPlan {
                stages: vec![PlannedStage {
                    source: "source-a".to_owned(),
                    role: StageRole::Search,
                    inputs: StageInputs::None,
                }],
                budget_milliseconds: None,
            }
        );

        let chained = AcquisitionConfig::SearchThenFetch {
            search: "source-a".to_owned(),
            fetch: "source-b".to_owned(),
        };
        assert_eq!(
            chained.plan(),
            AcquisitionPlan {
                stages: vec![
                    PlannedStage {
                        source: "source-a".to_owned(),
                        role: StageRole::Search,
                        inputs: StageInputs::None,
                    },
                    PlannedStage {
                        source: "source-b".to_owned(),
                        role: StageRole::Member,
                        inputs: StageInputs::EveryPriorFact,
                    },
                ],
                budget_milliseconds: None,
            }
        );

        let config = EvidenceConfig::parse_yaml(fetch_set_bundle().as_bytes())
            .expect("the fetch set parses");
        let plan = config.requirements[0].acquisition.plan();
        assert_eq!(
            plan,
            AcquisitionPlan {
                stages: vec![
                    PlannedStage {
                        source: "source-a".to_owned(),
                        role: StageRole::Search,
                        inputs: StageInputs::None,
                    },
                    PlannedStage {
                        source: "source-e".to_owned(),
                        role: StageRole::Member,
                        inputs: StageInputs::Declared(vec!["record_id".to_owned()]),
                    },
                    PlannedStage {
                        source: "source-f".to_owned(),
                        role: StageRole::Member,
                        inputs: StageInputs::Declared(vec!["record_id".to_owned()]),
                    },
                ],
                budget_milliseconds: Some(8000),
            }
        );

        // The planned sources are the configured sources, in the order the
        // requirement declared them, for every form.
        for acquisition in [&single, &chained, &config.requirements[0].acquisition] {
            assert_eq!(
                acquisition
                    .plan()
                    .stages
                    .iter()
                    .map(|stage| stage.source.as_str())
                    .collect::<Vec<_>>(),
                acquisition.source_ids()
            );
        }
    }

    /// A requirement's `configurationRevision` is a digest of the projected
    /// configuration, so a member every bundle serialized would move every
    /// revision an existing deployment has already published.
    #[test]
    fn an_undeclared_acquisition_capability_stays_out_of_the_projected_configuration() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("the acceptance bundle validates");
        assert!(config.acquisition_capabilities.is_empty());
        let projected = serde_json::to_value(&config).expect("the configuration projects");
        assert!(
            projected.get("acquisitionCapabilities").is_none(),
            "an undeclared capability list moves every existing configuration revision"
        );

        let declared = EvidenceConfig::parse_yaml(fetch_set_bundle().as_bytes())
            .expect("the declared fetch set validates");
        assert_eq!(
            serde_json::to_value(&declared).expect("the configuration projects")
                ["acquisitionCapabilities"],
            serde_json::json!(["search-then-fetch-set"])
        );
    }

    /// One acceptance bundle rewritten so a single requirement issues under the
    /// holder-bound mode, with both permission halves present: the bundle and
    /// the one matched grant permit the serialization that mode allows, and the
    /// grant names the mode itself.
    fn holder_bound_bundle() -> String {
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        let mut bundle = yaml.to_owned();
        for (name, from, to) in [
            (
                // Outside the local profile the SD-JWT VC issuer is an origin.
                "provider origin",
                "  providerId: urn:example:fixture:provider:evidence\n",
                "  providerId: https://provider.invalid\n",
            ),
            (
                "bundle formats",
                "\nresponseFormats: [signed-jws, unsigned-json]\n",
                "\nresponseFormats: [signed-jws, unsigned-json, sd-jwt-vc]\n",
            ),
            (
                "grant permission",
                "      - requirement: urn:example:fixture:requirement:adult-status:v1\n        purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json]\n",
                "      - requirement: urn:example:fixture:requirement:adult-status:v1\n        purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json, sd-jwt-vc]\n        subjectBindingModes: [holder-bound]\n",
            ),
            (
                "requirement mode",
                "  - handle: adult-status\n    id: urn:example:fixture:requirement:adult-status:v1\n    kind: criterion\n",
                "  - handle: adult-status\n    id: urn:example:fixture:requirement:adult-status:v1\n    kind: criterion\n    subjectBinding: holder-bound\n",
            ),
        ] {
            let rewritten = bundle.replace(from, to);
            assert_ne!(rewritten, bundle, "the {name} rewrite applies");
            bundle = rewritten;
        }
        bundle
    }

    #[test]
    fn an_undeclared_subject_binding_mode_stays_out_of_the_projected_configuration() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("the acceptance bundle validates");
        assert!(config.holder_bound_batch_max_size.is_none());
        assert!(config
            .requirements
            .iter()
            .all(|requirement| requirement.subject_binding.is_none()));
        assert!(config.authority_profiles.iter().all(|(_, profile)| profile
            .grants
            .iter()
            .all(|grant| grant.subject_binding_modes.is_empty())));

        let projected = serde_json::to_value(&config).expect("the configuration projects");
        assert!(
            projected.get("holderBoundBatchMaxSize").is_none(),
            "an undeclared batch ceiling moves every existing configuration revision"
        );
        for requirement in projected["requirements"]
            .as_array()
            .expect("the requirements project")
        {
            assert!(
                requirement.get("subjectBinding").is_none(),
                "an undeclared binding mode moves every existing configuration revision"
            );
        }
        for profile in projected["authorityProfiles"]
            .as_object()
            .expect("the authority profiles project")
            .values()
        {
            for grant in profile["grants"].as_array().expect("the grants project") {
                assert!(
                    grant.get("subjectBindingModes").is_none(),
                    "an undeclared grant mode list moves every existing configuration revision"
                );
            }
        }

        // Absence is a decided default, not an unresolved omission.
        assert!(config
            .requirements
            .iter()
            .all(|requirement| requirement.subject_binding_mode()
                == SubjectBindingMode::AudienceScoped));
        assert_eq!(config.holder_bound_batch_ceiling(), 1);
        assert!(config
            .authority_profiles
            .iter()
            .all(|(_, profile)| profile.grants.iter().all(|grant| grant
                .permits_subject_binding(SubjectBindingMode::AudienceScoped)
                && !grant.permits_subject_binding(SubjectBindingMode::HolderBound))));

        let declared = EvidenceConfig::parse_yaml(holder_bound_bundle().as_bytes())
            .expect("the bundle validates");
        let projected = serde_json::to_value(&declared).expect("the configuration projects");
        assert_eq!(
            projected["requirements"][0]["subjectBinding"],
            serde_json::json!("holder-bound")
        );
        assert_eq!(
            projected["authorityProfiles"]["statutory-caseworker-v1"]["grants"][0]
                ["subjectBindingModes"],
            serde_json::json!(["holder-bound"])
        );
    }

    #[test]
    fn permission_to_serialize_sd_jwt_vc_is_not_permission_to_issue_holder_bound() {
        let bundle = holder_bound_bundle();
        EvidenceConfig::parse_yaml(bundle.as_bytes()).expect("both permission halves validate");

        // The grant keeps the serialization it needs and loses only the mode.
        // Nothing else about it changes, so a bundle that still loads would say
        // format permission had silently carried mode permission with it.
        let format_only = bundle.replace("\n        subjectBindingModes: [holder-bound]", "");
        assert_ne!(format_only, bundle, "the mode withdrawal applies");
        assert!(
            EvidenceConfig::parse_yaml(format_only.as_bytes()).is_err(),
            "a grant permitting the SD-JWT VC serialization silently gained holder-bound issuance"
        );

        // The same grant read directly: it may serialize, and it may not issue.
        let audience_scoped = format_only.replace("\n    subjectBinding: holder-bound", "");
        assert_ne!(audience_scoped, format_only, "the mode removal applies");
        let config = EvidenceConfig::parse_yaml(audience_scoped.as_bytes())
            .expect("a grant may serialize SD-JWT VC with no binding-mode permission at all");
        let grant = &config
            .authority_profiles
            .get("statutory-caseworker-v1")
            .expect("the acceptance profile is configured")
            .grants[0];
        assert!(grant.response_formats.contains(&ResponseFormat::SdJwtVc));
        assert!(grant.permits_subject_binding(SubjectBindingMode::AudienceScoped));
        assert!(!grant.permits_subject_binding(SubjectBindingMode::HolderBound));
    }

    #[test]
    fn a_holder_bound_requirement_no_request_could_reach_is_refused_at_bundle_load() {
        let bundle = holder_bound_bundle();
        EvidenceConfig::parse_yaml(bundle.as_bytes()).expect("the reachable bundle validates");

        for (name, mutated) in [
            (
                // The bundle half withdraws the one serialization the mode permits.
                "bundle format",
                bundle.replace(
                    "\nresponseFormats: [signed-jws, unsigned-json, sd-jwt-vc]\n",
                    "\nresponseFormats: [signed-jws, unsigned-json]\n",
                ),
            ),
            (
                // The grant half withdraws it while still naming the mode.
                "grant format",
                bundle.replace(
                    "        responseFormats: [signed-jws, unsigned-json, sd-jwt-vc]\n        subjectBindingModes: [holder-bound]\n",
                    "        responseFormats: [signed-jws, unsigned-json]\n        subjectBindingModes: [holder-bound]\n",
                ),
            ),
            (
                // The grant half withdraws the mode while still permitting the format.
                "grant mode",
                bundle.replace("\n        subjectBindingModes: [holder-bound]", ""),
            ),
            (
                // No grant covers the requirement under the mode at all.
                "grant audience-scoped only",
                bundle.replace(
                    "\n        subjectBindingModes: [holder-bound]",
                    "\n        subjectBindingModes: [audience-scoped]",
                ),
            ),
        ] {
            assert_ne!(mutated, bundle, "the {name} mutation applies");
            let error = EvidenceConfig::parse_yaml(mutated.as_bytes()).expect_err(
                "an unreachable holder-bound requirement was accepted at bundle load",
            );
            assert!(
                !format!("{error}").contains("urn:example:fixture"),
                "the {name} refusal names a configured value"
            );
        }
    }

    #[test]
    fn a_holder_bound_requirement_may_not_disclose_an_entity_reference_value_form() {
        let bundle = holder_bound_bundle();
        let anchor = "      - {handle: is_adult, id: urn:example:fixture:concept:adult-status, form: boolean, required: true, constraints: {}}\n";
        for form in [
            "      - {handle: entity_reference, id: urn:example:fixture:concept:audience-scoped-entity-reference, form: audience-scoped-entity-reference, required: false, constraints: {maximumBytes: 160}}\n",
            "      - {handle: entity_references, id: urn:example:fixture:concept:entity-reference-list, form: entity-reference-list, required: false, constraints: {minimumItems: 1, maximumItems: 2, unique: true}}\n",
        ] {
            let mutated = bundle.replace(anchor, &format!("{anchor}{form}"));
            assert_ne!(mutated, bundle, "the {form} mutation applies");
            let refusal = EvidenceConfig::parse_yaml(mutated.as_bytes()).expect_err(
                "a holder-bound requirement disclosed an entity-reference value form",
            );

            // The refusal happens here, in parsing, which the server does
            // before it binds a listener, so no request can reach a deployment
            // configured this way. Its cause is a fixed sentence: it names the
            // rule that was broken and interpolates nothing from the rejected
            // bundle, so an operator reading a startup log learns no configured
            // identifier, endpoint, or constraint from it.
            let cause = refusal.to_string();
            assert!(
                cause.contains("must not disclose an entity-reference value form"),
                "the refusal does not name the rule that was broken: {cause}"
            );
            for interpolated in ["urn:example:", "maximumBytes", "minimumItems", "160"] {
                assert!(
                    !cause.contains(interpolated),
                    "the refusal echoes rejected bundle content: {cause}"
                );
            }

            // The refusal is about the mode, not about the value form: the same
            // concept on an audience-scoped requirement stays configurable.
            let audience_scoped = mutated
                .replace("\n    subjectBinding: holder-bound", "")
                .replace("\n        subjectBindingModes: [holder-bound]", "");
            EvidenceConfig::parse_yaml(audience_scoped.as_bytes())
                .expect("an audience-scoped requirement may disclose an entity reference");
        }
    }

    /// A request batch costs one token per item and a holder-bound release one
    /// per holder key, so the burst has to hold the larger of the two for any
    /// such request to be admitted at all. The request-batch route accepts up to
    /// sixteen items for every audience-scoped requirement whatever a source's
    /// own batch ceiling says, because items above that ceiling run
    /// sequentially rather than being refused.
    #[test]
    fn the_largest_request_cost_follows_the_batches_the_bundle_admits() {
        let all_definitions = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        let audience_scoped =
            EvidenceConfig::parse_yaml(all_definitions.as_bytes()).expect("fixture parses");
        assert_eq!(audience_scoped.largest_request_cost(), 16);
        let shortfall = audience_scoped
            .burst_shortfall()
            .expect("a burst of ten cannot hold a sixteen-item request batch");
        assert_eq!(shortfall, BurstShortfall::RequestBatch);

        let raised = all_definitions.replace("burstPerPrincipal: 10", "burstPerPrincipal: 16");
        assert_ne!(raised, all_definitions, "the burst mutation applies");
        let raised = EvidenceConfig::parse_yaml(raised.as_bytes()).expect("fixture parses");
        assert_eq!(raised.burst_shortfall(), None);

        // Every requirement here is holder-bound, so no request batch can name
        // one, and the release ceiling the bundle declares is the whole cost.
        let holder_bound = include_str!(
            "../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml"
        );
        let holder_only =
            EvidenceConfig::parse_yaml(holder_bound.as_bytes()).expect("fixture parses");
        assert_eq!(holder_only.largest_request_cost(), 4);
        assert_eq!(holder_only.burst_shortfall(), None);
        let narrow = holder_bound.replace("burstPerPrincipal: 10", "burstPerPrincipal: 3");
        assert_ne!(narrow, holder_bound, "the burst mutation applies");
        assert_eq!(
            EvidenceConfig::parse_yaml(narrow.as_bytes())
                .expect("fixture parses")
                .burst_shortfall(),
            Some(BurstShortfall::HolderBoundBatch)
        );
    }

    #[test]
    fn a_holder_bound_batch_ceiling_outside_the_permitted_range_is_refused() {
        let bundle = holder_bound_bundle();
        let validator = bundle_contract_validator();
        for (ceiling, accepted) in [("1", true), ("16", true), ("0", false), ("17", false)] {
            let mutated = bundle.replace(
                "\nrequirements:\n",
                &format!("\nholderBoundBatchMaxSize: {ceiling}\n\nrequirements:\n"),
            );
            assert_ne!(mutated, bundle, "the ceiling {ceiling} mutation applies");
            let config = EvidenceConfig::parse_yaml(mutated.as_bytes());
            assert_eq!(
                config.is_ok(),
                accepted,
                "startup validation disagrees on batch ceiling {ceiling}"
            );
            assert_eq!(
                validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                accepted,
                "the published contract disagrees on batch ceiling {ceiling}"
            );
            if let Ok(config) = config {
                assert_eq!(
                    config.holder_bound_batch_ceiling(),
                    ceiling.parse::<u16>().expect("the ceiling is an integer")
                );
            }
        }
    }

    #[test]
    fn only_the_sd_jwt_vc_serialization_may_carry_a_holder_bound_assertion() {
        for format in [
            ResponseFormat::SignedJws,
            ResponseFormat::UnsignedJson,
            ResponseFormat::SdJwtVc,
        ] {
            assert!(subject_binding_permits_response_format(
                SubjectBindingMode::AudienceScoped,
                format
            ));
        }
        assert!(subject_binding_permits_response_format(
            SubjectBindingMode::HolderBound,
            ResponseFormat::SdJwtVc
        ));
        assert!(!subject_binding_permits_response_format(
            SubjectBindingMode::HolderBound,
            ResponseFormat::SignedJws
        ));
        assert!(!subject_binding_permits_response_format(
            SubjectBindingMode::HolderBound,
            ResponseFormat::UnsignedJson
        ));

        // The batch envelope belongs to this mode alone, in both directions.
        // It carries one confirmation per member, so an audience-scoped
        // requirement has nothing to put in one, and there is no batch form of
        // an audience-scoped assertion for a caller to select.
        assert!(subject_binding_permits_response_format(
            SubjectBindingMode::HolderBound,
            ResponseFormat::SdJwtVcBatch
        ));
        assert!(!subject_binding_permits_response_format(
            SubjectBindingMode::AudienceScoped,
            ResponseFormat::SdJwtVcBatch
        ));

        // The restriction is per requirement. Signed JWS stays mandatory at
        // bundle and grant scope in a deployment that serves a holder-bound
        // requirement, so the mode never narrows the rest of the deployment.
        let config = EvidenceConfig::parse_yaml(holder_bound_bundle().as_bytes())
            .expect("the bundle validates");
        assert!(config.response_formats.contains(&ResponseFormat::SignedJws));
        assert!(config.authority_profiles.iter().all(|(_, profile)| profile
            .grants
            .iter()
            .all(|grant| grant.response_formats.contains(&ResponseFormat::SignedJws))));
        assert!(
            validate_response_formats(&[ResponseFormat::SdJwtVc], "bundle response formats")
                .is_err()
        );
    }

    #[test]
    fn the_bundle_contract_closes_the_binding_mode_vocabulary() {
        let bundle = holder_bound_bundle();
        let validator = bundle_contract_validator();
        assert!(
            validator.is_valid(&bundle_contract_instance(bundle.as_bytes())),
            "the contract rejects a declared holder-bound requirement"
        );

        for (name, mutated) in [
            (
                "unknown requirement mode",
                bundle.replace(
                    "\n    subjectBinding: holder-bound",
                    "\n    subjectBinding: bearer-bound",
                ),
            ),
            (
                "unknown grant mode",
                bundle.replace(
                    "\n        subjectBindingModes: [holder-bound]",
                    "\n        subjectBindingModes: [bearer-bound]",
                ),
            ),
            (
                "repeated grant mode",
                bundle.replace(
                    "\n        subjectBindingModes: [holder-bound]",
                    "\n        subjectBindingModes: [holder-bound, holder-bound]",
                ),
            ),
            (
                "overlong grant mode list",
                bundle.replace(
                    "\n        subjectBindingModes: [holder-bound]",
                    "\n        subjectBindingModes: [holder-bound, audience-scoped, holder-bound]",
                ),
            ),
        ] {
            assert_ne!(mutated, bundle, "the {name} mutation applies");
            assert!(
                !validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                "the contract accepts {name}"
            );
            assert!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_err(),
                "startup validation accepts {name}"
            );
        }
    }

    #[test]
    fn the_holder_bound_acceptance_bundle_declares_every_coequal_definition() {
        // The mode is not a property of one definition. A committed bundle that
        // declared it for a single requirement would make the other three a
        // later phase, which the coequality rule forbids, so the check is on
        // the committed fixture rather than on a rewrite of it.
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml"
        ))
        .expect("the holder-bound acceptance bundle validates");
        let declared: Vec<&str> = config
            .requirements
            .iter()
            .map(|requirement| requirement.id.as_str())
            .collect();
        assert_eq!(
            declared,
            [
                "urn:example:fixture:requirement:adult-status:v1",
                "urn:example:fixture:requirement:residence-region:v1",
                "urn:example:fixture:requirement:professional-licence-status:v1",
                "urn:example:fixture:requirement:legal-parent-relationship:v1",
            ]
        );
        for requirement in &config.requirements {
            assert_eq!(
                requirement.subject_binding_mode(),
                SubjectBindingMode::HolderBound,
                "{} does not issue under the holder-bound mode",
                requirement.id
            );
        }

        // Every definition is reachable: each requirement's matched grant
        // carries the mode permission as well as the serialization permission.
        for (_, profile) in config.authority_profiles.iter() {
            for grant in &profile.grants {
                assert!(
                    grant.permits_subject_binding(SubjectBindingMode::HolderBound),
                    "{} cannot be acquired under the mode it declares",
                    grant.requirement
                );
            }
        }
        assert_eq!(config.holder_bound_batch_ceiling(), 4);
        assert!(config.response_formats.contains(&ResponseFormat::SdJwtVc));
        assert!(config
            .response_formats
            .contains(&ResponseFormat::SdJwtVcBatch));
        assert!(!config
            .response_formats
            .contains(&ResponseFormat::UnsignedJson));
    }

    #[test]
    fn the_holder_bound_acceptance_bundle_differs_from_its_twin_only_by_binding_mode() {
        // Two acceptance bundles serve the same four definitions, and the
        // holder-bound one is the audience-scoped one plus the mode and the
        // consequences the mode forces. Withdrawing exactly those declarations
        // must land back on the twin's typed configuration: anything else in
        // the fixture would be a second variable, and a behavioural difference
        // between the two bundles could then be attributed to it instead of to
        // the mode.
        let holder_bound = include_str!(
            "../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml"
        );
        let mut normalized = holder_bound.to_owned();
        for (name, from, to) in [
            (
                "grant permission",
                "        responseFormats: [signed-jws, sd-jwt-vc, sd-jwt-vc-batch]\n        subjectBindingModes: [holder-bound]\n",
                "        responseFormats: [signed-jws, unsigned-json]\n",
            ),
            (
                "bundle permission and batch ceiling",
                "\nresponseFormats: [signed-jws, sd-jwt-vc, sd-jwt-vc-batch]\nholderBoundBatchMaxSize: 4\n",
                "\nresponseFormats: [signed-jws, unsigned-json]\n",
            ),
            (
                "requirement mode",
                "\n    subjectBinding: holder-bound",
                "",
            ),
            (
                // Forced by the serialization the mode permits, not chosen:
                // SD-JWT VC names its issuer by origin outside the local
                // assurance profile.
                "provider identifier",
                "  providerId: https://provider.invalid\n",
                "  providerId: urn:example:fixture:provider:evidence\n",
            ),
            (
                "public Evidence origin",
                "  publicOrigin: https://provider.invalid\n",
                "  publicOrigin: https://evidence.invalid\n",
            ),
        ] {
            let rewritten = normalized.replace(from, to);
            assert_ne!(rewritten, normalized, "the {name} withdrawal applies");
            normalized = rewritten;
        }

        let withdrawn = EvidenceConfig::parse_yaml(normalized.as_bytes())
            .expect("the withdrawn bundle validates");
        let twin = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("the audience-scoped acceptance bundle validates");
        assert_eq!(
            withdrawn, twin,
            "the holder-bound acceptance bundle carries a difference beyond its binding mode"
        );
    }

    #[test]
    fn a_batch_only_bundle_still_forces_the_https_origin_the_singular_form_forces() {
        // The batch container is a second SD-JWT VC serialization, not a
        // different one, so a bundle that drops the singular form and keeps
        // only the batch form must keep the same HTTPS-origin requirement on
        // service.providerId outside the local assurance profile.
        let holder_bound = include_str!(
            "../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml"
        );
        let batch_only = holder_bound.replace(
            "\nresponseFormats: [signed-jws, sd-jwt-vc, sd-jwt-vc-batch]\nholderBoundBatchMaxSize: 4\n",
            "\nresponseFormats: [signed-jws, sd-jwt-vc-batch]\nholderBoundBatchMaxSize: 4\n",
        );
        assert_ne!(
            batch_only, holder_bound,
            "the bundle format withdrawal applies"
        );

        let validator = bundle_contract_validator();
        assert!(
            EvidenceConfig::parse_yaml(batch_only.as_bytes()).is_ok(),
            "a batch-only bundle with an HTTPS provider identifier failed to validate"
        );
        assert!(
            validator.is_valid(&bundle_contract_instance(batch_only.as_bytes())),
            "the published contract rejects a batch-only bundle with an HTTPS provider identifier"
        );

        let urn_provider = batch_only.replace(
            "  providerId: https://provider.invalid\n",
            "  providerId: urn:example:fixture:provider:evidence\n",
        );
        assert_ne!(
            urn_provider, batch_only,
            "the provider identifier rewrite applies"
        );
        assert!(
            EvidenceConfig::parse_yaml(urn_provider.as_bytes()).is_err(),
            "a batch-only bundle accepted a URN provider identifier outside the local profile"
        );
        assert!(
            !validator.is_valid(&bundle_contract_instance(urn_provider.as_bytes())),
            "the published contract accepts a batch-only bundle with a URN provider identifier"
        );
    }
}
