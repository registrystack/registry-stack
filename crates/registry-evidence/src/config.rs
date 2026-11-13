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
use registry_adapter_core::{AdapterEndpointBindings, EvidenceConnectionPolicy};
use registry_platform_audit::{AuditDestination, AuditDestinationError, AuditDestinationKind};
pub use registry_platform_config::SecretReference;
use registry_platform_config::{
    contains_environment_expression, AuditKeyConfig, JwksSource, ListenerBind, LoadedRuntimeConfig,
    OidcIssuerConfig, PackageConfig, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope,
    SecretProvidersConfig,
};
use registry_platform_yaml::{
    local_id_collision_diagnostics, AuthoredId, BoundedU32, BoundedU64, Diagnostic, Digest,
    DisplayText, Document, EnvelopeRule, Expect, ExternalId, FormatSpec, Invalid, LocalId, Reader,
    Refusal, Related, Report, RetiredApiVersion, ScalarHook, ScalarSite, Severity, UniqueIdList,
    UniqueList,
};
use schemars::JsonSchema;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_norway::Value as YamlValue;
use thiserror::Error;
use url::{Host, Url};
use utoipa::ToSchema;

use crate::model::{ChannelKind, EVIDENCE_REQUEST_BATCH_MAX_ITEMS};

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// Writes one tagged union in its documented flat form: the tag member names
/// the variant and the variant's members follow it. The derived serializer of
/// a `remote = "Self"` union produces the externally tagged form
/// `{variant: {members}}`; this helper flattens that single entry so the
/// serialized document, and every digest computed over it, is unchanged.
pub(crate) fn serialize_tagged<S: Serializer>(
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

/// The `apiVersion` an Evidence bundle declares.
pub const EVIDENCE_BUNDLE_API_VERSION: &str = "id.registrystack.org/formats/evidence/bundle/v1";

/// The Evidence bundle format. The reader checks the envelope before it
/// decodes the grammar, so `apiVersion` and `kind` are not members of
/// [`EvidenceConfig`] and stay out of the projected configuration.
pub const EVIDENCE_BUNDLE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: EVIDENCE_BUNDLE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[registry_platform_yaml::ApiVersion::current(
            EVIDENCE_BUNDLE_API_VERSION,
        )],
        retired_api_versions: &[],
    },
    removed_keys: EVIDENCE_BUNDLE_REMOVED_KEYS,
};

/// The fix for a bundle compiled before Sources bound pack routes, reported
/// once at the Source's `type`.
const RETIRED_SOURCE_FORM: &str = "The tagged Source form is retired: a Source binds a reviewed Adapter pack route with `pack`, `route`, `connection` and `inputs`. Migrate the authoring project and rebuild this package with evidencectl 0.45.0 or later; see products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project.";

/// The fix for each other member of the retired tagged Source form.
const RETIRED_SOURCE_MEMBER: &str = "Retired with the tagged Source form; the Adapter pack route declares this now. See products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project.";

/// Bundle keys an earlier grammar accepted, each refused with the key that
/// replaced it. The envelope replaced the `version` member, the access-token
/// rules moved under `authentication.oidc`, a request's bounds took the
/// names the shared concept table gives them, the union tags took the name
/// `type`, and the issuer, each requirement, and each concept name their URI
/// as `uri`. A Source binds a pack route, so each member of the retired tagged
/// Source form names the migration. A `*` segment matches any key.
pub const EVIDENCE_BUNDLE_REMOVED_KEYS: &[registry_platform_yaml::RemovedKey<'static>] = &[
    registry_platform_yaml::RemovedKey {
        pointer: "/version",
        replacement: "The grammar version is replaced by the envelope: remove `version` and declare `apiVersion: id.registrystack.org/formats/evidence/bundle/v1` and `kind: EvidenceBundle`.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/kind",
        replacement: "Evidence accepts OIDC access tokens only; declare the rules under authentication.oidc.",
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
        replacement: "Declare authentication.oidc.jwksSource with type: uri and uri: <JWKS URL>.",
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
        replacement: "Declare authentication.oidc.jwksSource with type: uri and uri: <JWKS URL>.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/authentication/oidc/jwksSource/kind",
        replacement: "Declare type instead; keep the value.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/audit/hashSecretRef",
        replacement: "Declare audit.hashKeyRef instead.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sourceConnections/*/concurrencyLimit",
        replacement: "Declare maximumConcurrency instead; keep the value.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sourceConnections/*/authentication/kind",
        replacement: "Declare type instead; keep the value.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/type",
        replacement: RETIRED_SOURCE_FORM,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/baseUrl",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/extractProfile",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/maximumExtractAgeSeconds",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/behaviorRevision",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/forwardAccessAttribution",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/unresolvedProblem",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/tlsTrustProfile",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/authentication",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/request",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/evidence",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/batch",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/responseSchema",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/extractScript",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/sources/*/transport",
        replacement: RETIRED_SOURCE_MEMBER,
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/requirements/*/acquisition/kind",
        replacement: "Declare type instead; keep the value.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/issuer/id",
        replacement: "Declare uri instead; keep the value.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/requirements/*/id",
        replacement: "Declare uri instead; keep the value.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/requirements/*/concepts/*/id",
        replacement: "Declare uri instead; keep the value.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/requirements/*/concepts/*/form",
        replacement: "Declare type instead; keep the value.",
    },
    registry_platform_yaml::RemovedKey {
        pointer: "/holderBoundBatchMaxSize",
        replacement: "Declare maximumHolderBoundBatchSize instead; keep the value.",
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
        if let Concern::RepeatedId { first } = self.concern {
            return self.repeated_id(document, first);
        }
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
        let mut diagnostic = if self.concern == Concern::Key && written == self.pointer {
            document.diagnostic_at_key(Severity::Error, code, written, &message, action)
        } else {
            document.diagnostic_at_value(Severity::Error, code, written, &message, action)
        };
        diagnostic.path.clone_from(&self.pointer);
        diagnostic
    }

    /// The shared refusal of a list item whose identifying member repeats the
    /// one of the item at index `first` (CFG-DIAG-3): placed at the copy, with
    /// the first item as a related position. Neither names the identifier.
    fn repeated_id(&self, document: &Document, first: u32) -> registry_platform_yaml::Diagnostic {
        let mut parts = self.pointer.rsplitn(3, '/');
        let member = parts.next().unwrap_or_default();
        let list = parts.last().unwrap_or_default();
        let mut diagnostic = document.diagnostic_at_value(
            Severity::Error,
            "config.duplicate-id",
            &self.pointer,
            &format!(
                "this `{member}` repeats the `{member}` of the item at index {first}; it is unique in this list"
            ),
            &format!("Give each item its own `{member}`."),
        );
        let path = format!("{list}/{first}/{member}");
        let position = document.span_of(&path).map(|span| span.start);
        diagnostic.related.push(Related {
            file: document.file().to_owned(),
            line: position.map(|position| position.line),
            column: position.map(|position| position.column),
            path,
            message: "the first item with this id".to_owned(),
        });
        diagnostic
    }

    /// Marks the rule as an identifying member that repeats the one of the
    /// item at index `first` in the same list.
    fn repeating(mut self, first: u32) -> Self {
        self.concern = Concern::RepeatedId { first };
        self
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
    /// Stable project identity emitted by the normalized project compiler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
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
    pub source_connections: OrderedMap<SourceConnectionPolicies>,
    /// Effective target grants. Normalized packages leave this empty; startup
    /// installs only the atomically activated target authority snapshot.
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub authority_profiles: OrderedMap<AuthorityProfile>,
    /// Ceiling on how many assertions one holder-bound release may carry.
    /// Omission means one, so a bundle written before batch release cannot
    /// serve a batch, and the key is omitted when absent because the projected
    /// configuration is what a requirement's `configurationRevision` digests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_holder_bound_batch_size:
        Option<BoundedU32<1, { MAXIMUM_HOLDER_BOUND_BATCH_SIZE as u32 }>>,
    pub requirements: Vec<RequirementConfig>,
    /// The Requirement URI of the one definition the activated target
    /// authority opens as a public check. Startup installs it from the
    /// activated authority snapshot; a bundle never carries it.
    #[serde(skip)]
    pub public_check_requirement: Option<String>,
    /// Retired. An empty list is read and ignored for one release.
    #[serde(default, rename = "acquisitionCapabilities", skip_serializing)]
    pub retired_acquisition_capabilities: RetiredAcquisitionCapabilities,
}

/// The retired `acquisitionCapabilities` member of the bundle and the runtime
/// configuration. For one release an empty list is still read, and ignored,
/// so a file written for 0.44 loads; any capability is refused with the fix.
/// It never serializes, so it never changes a configuration revision.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct RetiredAcquisitionCapabilities;

impl<'de> Deserialize<'de> for RetiredAcquisitionCapabilities {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let capabilities = Vec::<de::IgnoredAny>::deserialize(deserializer)?;
        if capabilities.is_empty() {
            return Ok(Self);
        }
        Err(Invalid::expected(
            "no acquisition capability; the member is retired",
            "Delete `acquisitionCapabilities`; a Source binds a reviewed Adapter pack route, and the pack declares how it reads.",
        )
        .into_error())
    }
}

pub use registry_evidence_verifier::model::SubjectBindingMode;
/// The declared assurance boundary travels with every response, so the
/// portable `registry-evidence-verifier` crate owns it and configuration serves
/// it at the runtime's own path.
pub use registry_evidence_verifier::AssuranceProfile;

pub type SourceSelectorSet = Vec<(String, String)>;

const SOURCE_AUTHORITY_PATH_INCOMPLETE: &str = "an authority path that can activate a source does not supply every required route input; give one grant a subject for every input of one route input alternative";
const SOURCE_AUTHORITY_PATH_OVERLAPPING: &str = "an authority path that can activate a source supplies inputs for more than one route input alternative; narrow the grant's subjects so they fill exactly one alternative";
const SOURCE_AUTHORITY_PATH_UNFIT: &str = "an authority path that can activate a source does not fit the route input presence rules; give one grant subjects that fill exactly one route input alternative";

/// The route-input names one complete authority path must make available.
///
/// A root `required` list forms one required set. A presence-only root `oneOf`
/// forms mutually exclusive required alternatives; inputs not required by the
/// selected alternative remain optional.
#[derive(Clone, Debug)]
pub(crate) struct SourceInputPresenceContract {
    requirement: SourceInputPresenceRequirement,
    exclusive_alternatives: Option<Vec<BTreeSet<String>>>,
}

impl SourceInputPresenceContract {
    pub(crate) fn new(
        requirement: SourceInputPresenceRequirement,
        exclusive_alternatives: Option<Vec<BTreeSet<String>>>,
    ) -> Self {
        Self {
            requirement,
            exclusive_alternatives,
        }
    }

    /// Whether one actual complete grant can fill the reviewed route shape.
    #[cfg(test)]
    pub(crate) fn accepts_path(&self, available: &BTreeSet<&str>) -> bool {
        self.path_refusal(available).is_none()
    }

    /// The value-free reason one actual complete grant cannot fill the
    /// reviewed route shape, or `None` when it can. Presence-only
    /// alternatives say whether the grant supplies too few inputs or enough
    /// for more than one alternative; any other shape gets the general rule.
    pub(crate) fn path_refusal(&self, available: &BTreeSet<&str>) -> Option<&'static str> {
        if let Some(alternatives) = &self.exclusive_alternatives {
            let filled = alternatives
                .iter()
                .filter(|required| {
                    required
                        .iter()
                        .all(|input| available.contains(input.as_str()))
                })
                .count();
            match filled {
                0 => return Some(SOURCE_AUTHORITY_PATH_INCOMPLETE),
                1 => {}
                _ => return Some(SOURCE_AUTHORITY_PATH_OVERLAPPING),
            }
        }
        if self.requirement.accepts(available) {
            None
        } else if self.exclusive_alternatives.is_none() && self.requirement.is_plain_required() {
            Some(SOURCE_AUTHORITY_PATH_INCOMPLETE)
        } else {
            Some(SOURCE_AUTHORITY_PATH_UNFIT)
        }
    }

    /// Whether the Source maps enough names for at least one route alternative.
    /// This package-only check does not select an alternative: target authority
    /// does that later, and may legitimately narrow the package ceiling.
    pub(crate) fn has_mappable_alternative(&self, mapped: &BTreeSet<&str>) -> bool {
        self.requirement.positively_mappable(mapped)
    }
}

/// The bounded root-object presence logic that can be proved independently of
/// route input values. Value constraints remain owned by the full JSON Schema
/// validator at execution.
#[derive(Clone, Debug)]
pub(crate) enum SourceInputPresenceRequirement {
    Always,
    Never,
    Required(BTreeSet<String>),
    All(Vec<Self>),
    Any(Vec<Self>),
    ExactlyOne(Vec<Self>),
    Not(Box<Self>),
    DependentRequired {
        trigger: String,
        required: BTreeSet<String>,
    },
    DependentSchema {
        trigger: String,
        requirement: Box<Self>,
    },
}

impl SourceInputPresenceRequirement {
    /// Whether the requirement can only fail by a missing input, so a
    /// refusal can say the grant supplies too few.
    fn is_plain_required(&self) -> bool {
        match self {
            Self::Always | Self::Never | Self::Required(_) => true,
            Self::All(requirements) => requirements.iter().all(Self::is_plain_required),
            _ => false,
        }
    }

    fn accepts(&self, available: &BTreeSet<&str>) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Required(required) => required
                .iter()
                .all(|input| available.contains(input.as_str())),
            Self::All(requirements) => requirements
                .iter()
                .all(|requirement| requirement.accepts(available)),
            Self::Any(requirements) => requirements
                .iter()
                .any(|requirement| requirement.accepts(available)),
            Self::ExactlyOne(requirements) => {
                requirements
                    .iter()
                    .filter(|requirement| requirement.accepts(available))
                    .count()
                    == 1
            }
            Self::Not(requirement) => !requirement.accepts(available),
            Self::DependentRequired { trigger, required } => {
                !available.contains(trigger.as_str())
                    || required
                        .iter()
                        .all(|input| available.contains(input.as_str()))
            }
            Self::DependentSchema {
                trigger,
                requirement,
            } => !available.contains(trigger.as_str()) || requirement.accepts(available),
        }
    }

    /// Whether the Source maps the positive names needed by some structural
    /// path. Negative and trigger-dependent predicates are deliberately left
    /// to target activation, where one actual projected subset is known.
    fn positively_mappable(&self, mapped: &BTreeSet<&str>) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Required(required) => {
                required.iter().all(|input| mapped.contains(input.as_str()))
            }
            Self::All(requirements) => requirements
                .iter()
                .all(|requirement| requirement.positively_mappable(mapped)),
            Self::Any(requirements) | Self::ExactlyOne(requirements) => requirements
                .iter()
                .any(|requirement| requirement.positively_mappable(mapped)),
            Self::Not(_) | Self::DependentRequired { .. } | Self::DependentSchema { .. } => true,
        }
    }
}

fn source_selector_pairs(source: &SourceConfig) -> BTreeSet<(String, String)> {
    source
        .selector_bindings()
        .into_iter()
        .map(|binding| (binding.role.to_owned(), binding.profile.to_owned()))
        .collect()
}

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
    /// The declared `maximumHolderBoundBatchSize` sets the cost.
    HolderBoundBatch,
}

impl EvidenceConfig {
    /// The declared holder-bound batch ceiling, or one when none is declared.
    pub fn holder_bound_batch_ceiling(&self) -> u16 {
        self.maximum_holder_bound_batch_size
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
            .map_err(|report| ConfigError::Refused(Box::new(name_the_assertion_type(report))))?;
        let mut diagnostics = bundle_integrity_diagnostics(&decoded);
        if let Err(violation) = decoded.value.check_rules_after_integrity() {
            diagnostics.push(violation.diagnostic(&decoded.document));
        }
        if !diagnostics.is_empty() {
            return Err(ConfigError::Refused(Box::new(
                decoded.document.report_with(diagnostics),
            )));
        }
        if decoded.value.project.is_some() && !decoded.value.authority_profiles.is_empty() {
            return invalid(
                "normalized package authority must be activated separately from the target",
            );
        }
        Ok(decoded.value)
    }

    /// Read a bundle from the JSON form of a decoded configuration. That form
    /// carries no envelope, because the reader checks and removes it before
    /// it decodes the grammar, so this declares the current one and then
    /// applies everything [`Self::parse_yaml`] applies to a bundle file.
    pub fn parse_projection(projection: &serde_json::Value) -> Result<Self, ConfigError> {
        let mut document = projection.clone();
        if let Some(members) = document.as_object_mut() {
            members.insert("apiVersion".to_owned(), EVIDENCE_BUNDLE_API_VERSION.into());
            members.insert("kind".to_owned(), EVIDENCE_BUNDLE_KIND.into());
        }
        Self::parse_yaml(document.to_string().as_bytes())
    }

    /// Refuse the bundle with the first rule it breaks, as startup does.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.check_rules().map_err(|violation| violation.error)
    }

    /// The first rule this decoded bundle breaks, with the member it
    /// concerns, in the order startup checks them.
    pub(crate) fn check_rules(&self) -> Result<(), Violation> {
        self.check_rules_with_named_map_collisions(true)
    }

    /// Check rules after the authored document's positioned integrity pass has
    /// already reported top-level named-map separator collisions.
    fn check_rules_after_integrity(&self) -> Result<(), Violation> {
        self.check_rules_with_named_map_collisions(false)
    }

    fn check_rules_with_named_map_collisions(
        &self,
        check_named_map_collisions: bool,
    ) -> Result<(), Violation> {
        validate_uri(&self.service.provider_id).at("/service/providerId")?;
        validate_uri(&self.service.trust_domain).at("/service/trustDomain")?;
        validate_public_origin(&self.service.public_origin, self.assurance_profile)
            .at("/service/publicOrigin")?;
        validate_uri(&self.issuer.id).at("/issuer/uri")?;
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
            check_named_map_collisions,
            |profile| profile.validate(),
        )?;
        validate_named_map(
            &self.sources,
            1,
            128,
            "/sources",
            check_named_map_collisions,
            |source| source.validate(self.assurance_profile),
        )?;
        validate_named_map(
            &self.source_connections,
            0,
            128,
            "/sourceConnections",
            check_named_map_collisions,
            |_| Ok(()),
        )?;
        for (source_id, source) in self.sources.iter() {
            let at = format!("{}/connection", named("/sources", source_id));
            self.source_connections
                .get(source.connection())
                .ok_or(ConfigError::Invalid(
                    "source connection reference is not declared",
                ))
                .at(&at)?;
        }
        validate_named_map(
            &self.authority_profiles,
            usize::from(self.project.is_none()),
            128,
            "/authorityProfiles",
            check_named_map_collisions,
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
                .listed_values()
                .ok_or(ConfigError::Invalid(
                    "task-grant authority profiles require a list of authentication allowedClients",
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

        let mut requirement_ids = BTreeMap::new();
        let mut requirement_handles = BTreeSet::new();
        let mut evidence_types = BTreeSet::new();
        let mut concept_ids = BTreeSet::new();
        let mut disclosure_families = BTreeSet::new();
        for (index, requirement) in (0_u32..).zip(&self.requirements) {
            let at = format!("/requirements/{index}");
            requirement.validate().at(&at)?;
            requirement
                .acquisition
                .validate_channels(&requirement.subject_roles, &at)?;
            if requirement.acquisition.holder_presented.is_some()
                && requirement
                    .representations
                    .as_ref()
                    .unwrap_or(&self.response_formats)
                    .iter()
                    .any(|format| *format != ResponseFormat::SignedJws)
            {
                return invalid(
                    "a definition with holder-presented acquisition must offer only the signed JWS representation (signed-jws)",
                )
                .at(format!("{at}/representations"));
            }
            if self.project.is_some()
                && (requirement.grant_ceiling.is_none() || requirement.representations.is_none())
            {
                return invalid(
                    "normalized definitions require complete grant and representation ceilings",
                )
                .at(&at);
            }
            if requirement.representations.as_ref().is_some_and(|formats| {
                formats
                    .iter()
                    .any(|format| !self.response_formats.contains(format))
            }) {
                return invalid("definition representations exceed the package ceiling").at(&at);
            }
            if self.assurance_profile.requires_fixtures() && requirement.fixtures.is_none() {
                return invalid("production and evidence-grade requirements must declare fixtures")
                    .at(at);
            }
            if let Some(first) = requirement_ids.insert(requirement.id.as_str(), index) {
                return invalid("requirement identifiers must be unique")
                    .at(format!("{at}/uri"))
                    .map_err(|violation| violation.repeating(first));
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
                        .at(format!("{at}/concepts/{concept_index}/uri"));
                }
            }
            for (family_index, family) in requirement.disclosure_guard.families.iter().enumerate() {
                if !disclosure_families.insert(family.as_str()) {
                    return invalid("enabled requirements share a disclosure family")
                        .at(format!("{at}/disclosureGuard/families/{family_index}"));
                }
            }
        }

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
            if !reachable && self.project.is_none() {
                return invalid(
                    "holder-bound requirement needs one grant permitting the mode and a permitted response format",
                )
                .at(at);
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
        if self.no_authority_activated() {
            return self
                .declared_source_selector_sets(source_id)
                .unwrap_or_default();
        }
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
                if !self.requirements.iter().any(|requirement| {
                    requirement.id == grant.requirement
                        && requirement.acquisition.serves(
                            source_id,
                            grant
                                .subjects
                                .iter()
                                .map(|subject| subject.selector_profile.as_str()),
                        )
                }) {
                    continue;
                }
                let source_pairs = source_selector_pairs(source);
                let mut set = source_pairs
                    .iter()
                    .filter(|(role, profile)| {
                        grant.subjects.iter().any(|subject| {
                            subject.role == *role && subject.selector_profile == *profile
                        })
                    })
                    .cloned()
                    .collect::<SourceSelectorSet>();
                set.sort();
                sets.insert(set);
            }
        }
        if let Some((requirement, subject)) = self.public_check_subject() {
            if requirement.acquisition.uses_source(source_id) {
                let mut set = source_selector_pairs(source)
                    .into_iter()
                    .filter(|pair| *pair == subject)
                    .collect::<SourceSelectorSet>();
                set.sort();
                sets.insert(set);
            }
        }
        sets.into_iter().collect()
    }

    /// Whether a normalized project has no target authority yet: no profiles
    /// and no public-check activation. A check-only authority activates a
    /// definition with no profiles, so an empty profile map alone is not it.
    fn no_authority_activated(&self) -> bool {
        self.project.is_some()
            && self.authority_profiles.is_empty()
            && self.public_check_requirement.is_none()
    }

    /// The activated public-check requirement and its one `(role, selector
    /// profile)` subject. Validation has already proven the subject is single.
    fn public_check_subject(&self) -> Option<(&RequirementConfig, (String, String))> {
        let uri = self.public_check_requirement.as_deref()?;
        let requirement = self
            .requirements
            .iter()
            .find(|requirement| requirement.id == uri)?;
        let role = requirement.subject_roles.first()?;
        let profile = role.selector_profiles.first()?;
        Some((requirement, (role.role.to_string(), profile.to_string())))
    }

    /// The loaded public-check activation, when the activated target authority
    /// opens one definition as a public check.
    pub fn public_check_activation(&self) -> Option<PublicCheckActivation> {
        let uri = self.public_check_requirement.as_deref()?;
        let requirement = self
            .requirements
            .iter()
            .find(|requirement| requirement.id == uri)?;
        let declared = requirement.public_check.as_ref()?;
        Some(PublicCheckActivation {
            requirement: requirement.id.clone(),
            handle: requirement.handle.clone(),
            check_code_fact: declared.check_code_fact.clone(),
            status_output: declared.status_output.clone(),
            fields_output: declared.fields_output.clone(),
        })
    }

    /// Prove each effective complete grant can fill the reviewed input shape of
    /// every Source its requirement may activate. No path may borrow an input
    /// from another grant. A normalized package deliberately has no effective
    /// authority before target activation, so package-only compilation stops
    /// after proving that its Source maps at least one route alternative.
    pub(crate) fn validate_source_authority_paths(
        &self,
        contracts: &BTreeMap<String, SourceInputPresenceContract>,
    ) -> Result<(), ConfigError> {
        if self.no_authority_activated() {
            return Ok(());
        }

        let requirements = self
            .requirements
            .iter()
            .map(|requirement| (requirement.id.as_str(), requirement))
            .collect::<BTreeMap<_, _>>();
        for (_, authority) in self.authority_profiles.iter() {
            for grant in &authority.grants {
                let requirement =
                    requirements
                        .get(grant.requirement.as_str())
                        .ok_or(ConfigError::Invalid(
                            "authority grant references an unknown requirement",
                        ))?;
                for source_id in requirement.acquisition.source_ids() {
                    if !requirement.acquisition.serves(
                        source_id,
                        grant
                            .subjects
                            .iter()
                            .map(|subject| subject.selector_profile.as_str()),
                    ) {
                        continue;
                    }
                    let source = self.sources.get(source_id).ok_or(ConfigError::Invalid(
                        "requirement acquisition references an unknown source",
                    ))?;
                    let contract = contracts.get(source_id).ok_or(ConfigError::Invalid(
                        "configured source input contract is unavailable",
                    ))?;
                    let available = source
                        .inputs
                        .iter()
                        .filter(|(_, input)| {
                            grant.subjects.iter().any(|subject| {
                                subject.role.as_str() == input.selector.role.as_str()
                                    && subject.selector_profile.as_str()
                                        == input.selector.profile.as_str()
                            })
                        })
                        .map(|(name, _)| name.as_str())
                        .collect::<BTreeSet<_>>();
                    if let Some(reason) = contract.path_refusal(&available) {
                        return invalid(reason);
                    }
                }
            }
        }
        // The public subject is the activated definition's own one selector
        // profile; it must fill the Source's route inputs by itself.
        if let Some((requirement, subject)) = self.public_check_subject() {
            for source_id in requirement.acquisition.source_ids() {
                let source = self.sources.get(source_id).ok_or(ConfigError::Invalid(
                    "requirement acquisition references an unknown source",
                ))?;
                let contract = contracts.get(source_id).ok_or(ConfigError::Invalid(
                    "configured source input contract is unavailable",
                ))?;
                let available = source
                    .inputs
                    .iter()
                    .filter(|(_, input)| {
                        input.selector.role.as_str() == subject.0
                            && input.selector.profile.as_str() == subject.1
                    })
                    .map(|(name, _)| name.as_str())
                    .collect::<BTreeSet<_>>();
                if let Some(reason) = contract.path_refusal(&available) {
                    return invalid(reason);
                }
            }
        }
        Ok(())
    }

    fn declared_source_selector_sets(
        &self,
        source_id: &str,
    ) -> Result<Vec<SourceSelectorSet>, ConfigError> {
        let source = self
            .sources
            .get(source_id)
            .ok_or(ConfigError::Invalid("definition source is unknown"))?;
        let pairs = source_selector_pairs(source);
        let mut sets = BTreeSet::new();
        for definition in self
            .requirements
            .iter()
            .filter(|definition| definition.acquisition.uses_source(source_id))
        {
            let mut set = pairs
                .iter()
                .filter(|(role, profile)| {
                    definition.subject_roles.iter().any(|subject| {
                        subject.role.as_str() == role
                            && subject
                                .selector_profiles
                                .iter()
                                .any(|allowed| allowed.as_str() == profile)
                    })
                })
                .cloned()
                .collect::<SourceSelectorSet>();
            if set.is_empty() && !pairs.is_empty() {
                continue;
            }
            set.sort();
            sets.insert(set);
        }
        Ok(sets.into_iter().collect())
    }

    fn validate_cross_references(&self) -> Result<(), Violation> {
        for (source_id, source) in self.sources.iter() {
            let at = named("/sources", source_id);
            for binding in source.selector_bindings() {
                let profile_config = self
                    .selector_profiles
                    .get(binding.profile)
                    .ok_or(ConfigError::Invalid(
                        "source input references an unknown selector profile",
                    ))
                    .at(&at)?;
                if !profile_config.fields.contains_key(binding.field) {
                    return invalid("source input references an unknown selector field").at(at);
                }
            }
        }

        for (index, requirement) in self.requirements.iter().enumerate() {
            let at = format!("/requirements/{index}");
            if requirement.acquisition.source_channel_source().is_some()
                && requirement.acquisition.source_channel_source()
                    == requirement.acquisition.holder_presented_source()
            {
                return invalid("both acquisition channels name the same source")
                    .at(format!("{at}/acquisition/holderPresented/source"));
            }
            for source_id in requirement.acquisition.source_ids() {
                let Some(source) = self.sources.get(source_id) else {
                    return invalid("requirement acquisition references an unknown source")
                        .at(format!("{at}/acquisition"));
                };
                // A profile selects one channel, so a Source reads only the
                // profiles of its own channel.
                if let Some(channel) = requirement.acquisition.channel_of_source(source_id) {
                    if source.selector_bindings().iter().any(|binding| {
                        requirement.acquisition.channel_for_profile(binding.profile)
                            != Some(channel)
                    }) {
                        return invalid(
                            "a source reads a selector profile that selects the other acquisition channel",
                        )
                        .at(format!("{at}/acquisition"));
                    }
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
            if requirement.public_check.is_some() {
                let one_number = requirement.subject_roles.len() == 1
                    && requirement.subject_roles[0].selector_profiles.len() == 1
                    && self
                        .selector_profiles
                        .get(requirement.subject_roles[0].selector_profiles[0].as_str())
                        .is_some_and(|profile| {
                            // The route always presents the number as text.
                            profile.fields.len() == 1
                                && profile.fields.iter().all(|(_, field)| {
                                    !matches!(
                                        field,
                                        SelectorField::Integer { .. } | SelectorField::Boolean {}
                                    )
                                })
                        });
                if !one_number {
                    return invalid(
                        "publicCheck requires one subject role with one selector profile that has one text field",
                    )
                    .at(format!("{at}/subjectRoles"));
                }
            }
        }
        if let Some(uri) = &self.public_check_requirement {
            if !self
                .requirements
                .iter()
                .any(|requirement| requirement.id == *uri && requirement.public_check.is_some())
            {
                return invalid(
                    "the activated public check names a requirement without publicCheck",
                )
                .at("/publicCheck");
            }
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
                if let Some(ceiling) = &requirement.grant_ceiling {
                    if !ceiling.authorities.contains(&authority.kind)
                        || authority
                            .actor_kind
                            .is_some_and(|kind| !ceiling.actor_kinds.contains(&kind))
                        || grant
                            .subjects
                            .iter()
                            .any(|subject| !ceiling.value_origins.contains(&subject.value_origin))
                        || grant
                            .subject_binding_modes
                            .iter()
                            .any(|mode| *mode != requirement.subject_binding_mode())
                        || (grant.subject_binding_modes.is_empty()
                            && requirement.subject_binding_mode()
                                != SubjectBindingMode::AudienceScoped)
                        || requirement.representations.as_ref().is_some_and(|formats| {
                            grant
                                .response_formats
                                .iter()
                                .any(|format| !formats.contains(format))
                        })
                    {
                        return invalid("target authority exceeds the definition grant ceiling")
                            .at(&at);
                    }
                }
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
                let grant_profiles = grant
                    .subjects
                    .iter()
                    .map(|subject| subject.selector_profile.as_str())
                    .collect::<Vec<_>>();
                let channels = grant_profiles
                    .iter()
                    .map(|profile| requirement.acquisition.channel_for_profile(profile))
                    .collect::<BTreeSet<_>>();
                if channels.len() != 1 {
                    return invalid(
                        "authority grant selects both acquisition channels through its selector profiles",
                    )
                    .at(format!("{at}/subjects"));
                }
                for source_id in requirement.acquisition.source_ids() {
                    if !requirement
                        .acquisition
                        .serves(source_id, grant_profiles.iter().copied())
                    {
                        continue;
                    }
                    let source = self
                        .sources
                        .get(source_id)
                        .ok_or(ConfigError::Invalid(
                            "requirement acquisition references an unknown source",
                        ))
                        .at(&at)?;
                    let source_bindings = source.selector_bindings();
                    let mut source_selector_set = grant
                        .subjects
                        .iter()
                        .filter(|subject| {
                            source_bindings.iter().any(|binding| {
                                binding.role == subject.role
                                    && binding.profile == subject.selector_profile
                            })
                        })
                        .map(|subject| (subject.role.clone(), subject.selector_profile.clone()))
                        .collect::<SourceSelectorSet>();
                    if source_selector_set.is_empty() && !source_bindings.is_empty() {
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

        if self.project.is_some() {
            // Source plans are package contracts, so a target may narrow grants
            // without disabling unrelated source plans or fixture compilation.
            let mut declared = BTreeMap::<String, BTreeSet<SourceSelectorSet>>::new();
            for source_id in self.sources.keys() {
                declared.insert(
                    source_id.to_owned(),
                    self.declared_source_selector_sets(source_id)
                        .at(named("/sources", source_id))?
                        .into_iter()
                        .collect(),
                );
            }
            self.validate_source_selector_sets(&declared)?;
            return Ok(());
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
            if source
                .selector_bindings()
                .iter()
                .any(|binding| !reachable.contains(&(binding.role, binding.profile)))
            {
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
    /// The issuer's URI, written `uri`: `id` is the name of a local
    /// identifier (CFG-ID-1).
    #[serde(rename = "uri")]
    pub id: String,
}

/// Public facts that cannot be derived from the governed Evidence service,
/// issuer, formats, bindings, and requirement inventory.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationConfig {
    pub service_id: String,
    #[serde(deserialize_with = "registry_platform_yaml::display_text")]
    pub title: String,
    #[serde(deserialize_with = "registry_platform_yaml::display_text")]
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
    "id.registrystack.org/formats/evidence/runtime/v1alpha1";
/// The `kind` every Evidence runtime file declares.
pub const EVIDENCE_RUNTIME_KIND: &str = "EvidenceRuntimeConfig";

/// The `apiVersion` an Evidence runtime file declared before the format
/// took its identifier under `id.registrystack.org/formats`.
pub const RETIRED_EVIDENCE_RUNTIME_API_VERSION: &str =
    "registry.registrystack.org/evidence-runtime/v1alpha1";

/// The apiVersions an earlier Evidence runtime file carried, each refused
/// with the one that replaced it.
pub const EVIDENCE_RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] =
    &[RetiredApiVersion {
        api_version: RETIRED_EVIDENCE_RUNTIME_API_VERSION,
        replacement: "Write apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1.",
    }];

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
        replacement: "Declare apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1 \
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
    RemovedKey {
        path: "audit.retainDays",
        replacement: "Declare audit.retentionDays instead; keep the value.",
    },
    RemovedKey {
        path: "signer.timeoutMilliseconds",
        replacement: "Declare signer.attemptTimeoutMilliseconds instead; keep the value.",
    },
    RemovedKey {
        path: "signer.kind",
        replacement: "Declare signer.type instead; keep the value.",
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
pub const RUNTIME_SOURCE_CONNECTION_CODE: &str = "evidence.runtime.invalid-source-connection";
pub const RUNTIME_SOURCE_ACQUISITION_CODE: &str = "evidence.runtime.invalid-source-acquisition";
pub const RUNTIME_SOURCE_EXTRACT_CODE: &str = "evidence.runtime.invalid-source-extract";

const ABSOLUTE_PATH_ACTION: &str =
    "Write an absolute path of at most 512 bytes, without . or .. segments.";
const LOCAL_ID_ACTION: &str = "Write a local identifier of at most 64 characters: a lowercase letter, then lowercase letters, digits, underscores, or hyphens.";
const SIGNER_NAME_ACTION: &str = "Write a name of at most 128 bytes: a lowercase ASCII letter, then lowercase letters, digits, dots, underscores, or hyphens.";
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
        if !valid_shared_local_id(name) {
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Separately governed target authority, captured once before serving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<RuntimeAuthorityConfig>,
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
    /// Process-local endpoint material for each governed Evidence connection.
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub source_connections: OrderedMap<AdapterEndpointBindings>,
    /// Finite operational budget shared by every pack-route call in one
    /// Evidence acquisition. Omission uses the engine's maintained defaults.
    #[serde(default, skip_serializing_if = "SourceAcquisitionConfig::is_default")]
    pub source_acquisition: SourceAcquisitionConfig,
    /// Process-local files bound to the logical extract names the bundle's
    /// statement sources read. Absent binds none, which is what a runtime file
    /// for a bundle with no extract source says.
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub source_extracts: OrderedMap<SourceExtractBinding>,
    /// Retired. An empty list is read and ignored for one release.
    #[serde(default, rename = "acquisitionCapabilities", skip_serializing)]
    pub retired_acquisition_capabilities: RetiredAcquisitionCapabilities,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceAcquisitionConfig {
    pub maximum_data_operations: u64,
    #[serde(rename = "acquisitionDeadlineMilliseconds")]
    pub deadline_milliseconds: u64,
    pub maximum_response_bytes: u64,
}

impl Default for SourceAcquisitionConfig {
    fn default() -> Self {
        Self {
            maximum_data_operations:
                registry_adapter_engine::evidence::DEFAULT_MAXIMUM_DATA_OPERATIONS,
            deadline_milliseconds: 30_000,
            maximum_response_bytes: 1_048_576,
        }
    }
}

/// Upper bound on the configured acquisition deadline, equal to the authored
/// target's ceiling.
const MAX_ACQUISITION_DEADLINE_MILLISECONDS: u64 = 300_000;

impl SourceAcquisitionConfig {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn limits(self) -> Result<registry_adapter_engine::evidence::EvidenceLimits, ConfigError> {
        if self.deadline_milliseconds > MAX_ACQUISITION_DEADLINE_MILLISECONDS {
            // The number below is `MAX_ACQUISITION_DEADLINE_MILLISECONDS`; a
            // test pins it to the authoring ceiling too.
            return Err(ConfigError::Invalid(
                "sourceAcquisition.acquisitionDeadlineMilliseconds is above the maximum of 300000",
            ));
        }
        let maximum_response_bytes = usize::try_from(self.maximum_response_bytes)
            .map_err(|_| ConfigError::Invalid("source acquisition response bound is too large"))?;
        registry_adapter_engine::evidence::EvidenceLimits::try_new(
            self.maximum_data_operations,
            self.deadline_milliseconds,
            maximum_response_bytes,
        )
        .map_err(|_| ConfigError::Invalid("source acquisition limits must be finite and nonzero"))
    }
}

/// The target authority store is operator storage, never a package override.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAuthorityConfig {
    pub root: PathBuf,
    pub target: String,
}

impl RuntimeConfig {
    /// The shared loader configured with the Evidence envelope and the keys
    /// it no longer accepts.
    pub fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(EVIDENCE_RUNTIME_ENVELOPE)
            .removed_keys(EVIDENCE_RUNTIME_REMOVED_KEYS)
            .retired_api_versions(EVIDENCE_RETIRED_RUNTIME_API_VERSIONS)
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
        if let Some(authority) = &self.authority {
            if validate_absolute_path(&authority.root.to_string_lossy()).is_err()
                || !valid_local_id(&authority.target)
            {
                findings.push(RuntimeFinding::at_value(
                    "evidence.runtime.invalid-authority",
                    "/authority",
                    ConfigError::Invalid(
                        "authority requires an absolute root and local target identifier",
                    ),
                    "Bind an absolute authority store root and the governed target identifier.",
                ));
            }
        }
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
        for (name, bindings) in self.source_connections.iter() {
            let pointer = format!(
                "/sourceConnections/{}",
                registry_platform_yaml::escape_pointer_segment(name)
            );
            if !valid_shared_local_id(name) || name != bindings.id.as_str() {
                findings.push(RuntimeFinding::at_key(
                    RUNTIME_SOURCE_CONNECTION_CODE,
                    &pointer,
                    ConfigError::Invalid("source connection key must equal its local binding id"),
                    "Use the governed connection name as both the mapping key and binding id.",
                ));
            }
            for (endpoint_index, endpoint) in bindings.endpoints.iter().enumerate() {
                let endpoint_pointer = format!("{pointer}/endpoints/{endpoint_index}");
                let mut check_reference = |member: &str, reference: &str| {
                    if providers_enabled
                        && self
                            .secret_providers
                            .check_reference("source connection secret reference", reference)
                            .is_err()
                    {
                        findings.push(RuntimeFinding::at_value(
                            RUNTIME_SOURCE_CONNECTION_CODE,
                            &format!("{endpoint_pointer}/{member}"),
                            ConfigError::Invalid(
                                "the secret reference names a provider secretProviders does not enable",
                            ),
                            "Enable the provider the reference names under secretProviders, or reference the source credential through an enabled provider.",
                        ));
                    }
                };
                if let Some(credential) = &endpoint.credential {
                    match credential {
                        registry_adapter_core::RuntimeCredential::None {} => {}
                        registry_adapter_core::RuntimeCredential::Basic {
                            username_ref,
                            password_ref,
                        } => {
                            check_reference("credential/usernameRef", username_ref.as_str());
                            check_reference("credential/passwordRef", password_ref.as_str());
                        }
                        registry_adapter_core::RuntimeCredential::StaticAuthorization {
                            token_ref,
                        } => check_reference("credential/tokenRef", token_ref.as_str()),
                        registry_adapter_core::RuntimeCredential::StaticApiKey { value_ref } => {
                            check_reference("credential/valueRef", value_ref.as_str());
                        }
                        registry_adapter_core::RuntimeCredential::Oauth2ClientCredentials {
                            client_id_ref,
                            client_secret_ref,
                            ..
                        } => {
                            check_reference("credential/clientIdRef", client_id_ref.as_str());
                            check_reference(
                                "credential/clientSecretRef",
                                client_secret_ref.as_str(),
                            );
                        }
                        registry_adapter_core::RuntimeCredential::Oauth2PrivateKeyJwt {
                            client_id_ref,
                            client_assertion_key_ref,
                            ..
                        } => {
                            check_reference("credential/clientIdRef", client_id_ref.as_str());
                            check_reference(
                                "credential/clientAssertionKeyRef",
                                client_assertion_key_ref.as_str(),
                            );
                        }
                    }
                }
                if let Some(identity) = &endpoint.mtls_identity {
                    check_reference(
                        "mtlsIdentity/certificateRef",
                        identity.certificate_ref.as_str(),
                    );
                    check_reference("mtlsIdentity/keyRef", identity.key_ref.as_str());
                }
            }
        }
        if let Err(error) = self.source_acquisition.limits() {
            findings.push(RuntimeFinding::at_key(
                RUNTIME_SOURCE_ACQUISITION_CODE,
                "/sourceAcquisition",
                error,
                "Write finite positive acquisition operation, deadline, and response-byte bounds.",
            ));
        }
        absolute_path_map_findings(
            &self.source_extracts,
            "/sourceExtracts",
            RUNTIME_SOURCE_EXTRACT_CODE,
            "path",
            |binding| &binding.path,
            &mut findings,
        );
        findings
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
        attempt_timeout_milliseconds: BoundedU64<1, 30_000>,
    },
}
registry_platform_yaml::tagged_union!(RuntimeSignerConfig);

/// The tagged form the file is written in: `type` beside the variant's
/// members.
impl Serialize for RuntimeSignerConfig {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::LocalJwk { private_key_ref } => {
                map.serialize_entry("type", "local-jwk")?;
                map.serialize_entry("privateKeyRef", private_key_ref)?;
            }
            Self::Transit {
                unix_socket_path,
                mount,
                key_name,
                key_version,
                attempt_timeout_milliseconds,
            } => {
                map.serialize_entry("type", "transit")?;
                map.serialize_entry("unixSocketPath", unix_socket_path)?;
                map.serialize_entry("mount", mount)?;
                map.serialize_entry("keyName", key_name)?;
                map.serialize_entry("keyVersion", key_version)?;
                map.serialize_entry("attemptTimeoutMilliseconds", attempt_timeout_milliseconds)?;
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
                            SIGNER_NAME_ACTION,
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
    pub retention_days: Option<BoundedU32<1, { registry_platform_audit::MAX_AUDIT_RETAIN_DAYS }>>,
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
            self.retention_days.map(BoundedU32::get),
        )
    }

    /// The destination the writer opens, with the platform defaults applied
    /// and file-only settings refused for `stdout`.
    pub fn destination(&self) -> Result<AuditDestination, ConfigError> {
        self.settings()
            .map_err(|error| ConfigError::Invalid(audit_refusal(&error).cause))
    }
}

/// The key the runtime file writes for a file-only setting the audit writer
/// names. The writer's own name for the retention period differs from the
/// key.
fn audit_member(field: &str) -> &str {
    match field {
        "retainDays" => "retentionDays",
        other => other,
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
            "audit path, rotateBytes, and retentionDays apply only when audit destination is file",
            &format!("/audit/{}", audit_member(field)),
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
                "audit retentionDays is outside the platform bounds",
                "/audit/retentionDays",
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

/// What an admission gate reads: the keyword, or a list that names something.
const ADMISSION_GATE_FORM: &str = "unrestricted, or a list of at least one value";
const ADMISSION_GATE_ACTION: &str =
    "Write unrestricted to admit any value, or list the admitted values.";

/// The keyword `unrestricted`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UnrestrictedKeyword;

impl<'de> Deserialize<'de> for UnrestrictedKeyword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == "unrestricted" {
            Ok(Self)
        } else {
            Err(Invalid::expected(ADMISSION_GATE_FORM, ADMISSION_GATE_ACTION).into_error())
        }
    }
}

/// A nonempty list of distinct values.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ListedValues(UniqueList<String>);

impl<'de> Deserialize<'de> for ListedValues {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = UniqueList::<String>::deserialize(deserializer)?;
        if values.is_empty() {
            return Err(Invalid::expected(ADMISSION_GATE_FORM, ADMISSION_GATE_ACTION).into_error());
        }
        Ok(Self(values))
    }
}

/// Which values an admission gate admits: the keyword `unrestricted`, or a
/// nonempty list of the admitted values (CFG-EMPTY-2). An omitted gate and an
/// empty list are refused while the bundle is read, because either would read
/// as both "nothing" and "anything" (CFG-EMPTY-3).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AdmissionGate {
    Unrestricted(UnrestrictedKeyword),
    Listed(ListedValues),
}

registry_platform_yaml::shape_union!(AdmissionGate {
    scalar => Unrestricted,
    list => Listed,
});

impl Serialize for AdmissionGate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unrestricted(_) => serializer.serialize_str("unrestricted"),
            Self::Listed(values) => values.0.serialize(serializer),
        }
    }
}

impl AdmissionGate {
    /// The gate that admits any value.
    pub fn unrestricted() -> Self {
        Self::Unrestricted(UnrestrictedKeyword)
    }

    /// The gate that admits exactly `values`. Validation refuses an empty
    /// list built this way, as the reader refuses one a file writes.
    pub fn listed(values: UniqueList<String>) -> Self {
        Self::Listed(ListedValues(values))
    }

    /// The listed values, or `None` when the gate is unrestricted.
    pub fn listed_values(&self) -> Option<&UniqueList<String>> {
        match self {
            Self::Unrestricted(_) => None,
            Self::Listed(values) => Some(&values.0),
        }
    }

    /// The values the token verifier is given: the list, or none for an
    /// unrestricted gate, which is how the verifier spells "no gate".
    pub fn admitted(&self) -> Vec<String> {
        self.listed_values()
            .map(|values| values.iter().cloned().collect())
            .unwrap_or_default()
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
    #[serde(deserialize_with = "admitted_algorithms")]
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
    /// Machine-client admission every bundle decides, matched against the
    /// token's `client_id`/`azp` the platform verifier already reads.
    /// `unrestricted` admits every client the issuer vouched for; a list is
    /// nonempty, bounded, and unique and admits exactly those clients.
    ///
    /// Audience plus static issuer-governed attributes alone cannot establish
    /// that the client was granted this resource's permission: an issuer may
    /// issue a correctly signed token for a known resource with zero scopes
    /// while still emitting the client's attributes. `required_scopes` closes
    /// that gap.
    pub allowed_clients: AdmissionGate,
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
    /// The scope gate every bundle decides, checked against the verified
    /// token's scope set after signature verification and before any authority
    /// claim is read. `unrestricted` applies no scope gate; a list is a
    /// nonempty, bounded, unique list of RFC 6749 scope-tokens every inbound
    /// token must carry.
    pub required_scopes: AdmissionGate,
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
    pub(crate) fn insecure_http_startup_diagnostic(&self) -> Option<&'static str> {
        self.provider.allow_insecure_http.then_some(
            "authentication.oidc.allowInsecureHttp permits plain HTTP to the configured issuer and to a JWKS URI declared in configuration",
        )
    }

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
                "Evidence reads access-token keys only from jwksSource type uri",
                "authentication.oidc.jwksSource",
            ));
        };
        let issuer = Url::parse(self.issuer())
            .map_err(|_| ConfigError::Invalid("authentication issuer is invalid"))?;
        let jwks_uri = Url::parse(self.jwks_uri())
            .map_err(|_| ConfigError::Invalid("authentication JWKS URI is invalid"))?;
        let plain_http = issuer.scheme() == "http" || jwks_uri.scheme() == "http";
        // Deployable bundles require HTTPS for the issuer and the JWKS URI.
        // The plain HTTP opt-in exists for the local profile alone, so a
        // deployable bundle that sets it is refused rather than ignored.
        if assurance_profile != AssuranceProfile::Local {
            if self.provider.allow_insecure_http {
                return Err(ConfigError::InvalidField(
                    "production and evidence-grade authentication requires HTTPS; remove allowInsecureHttp, which only the local assurance profile accepts",
                    "authentication.oidc.allowInsecureHttp",
                ));
            }
            if plain_http {
                return invalid(
                    "production and evidence-grade authentication requires HTTPS for the issuer and JWKS URI; plain HTTP is accepted only under the local assurance profile",
                );
            }
        }
        if plain_http && !self.provider.allow_insecure_http {
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
        } else if issuer.scheme() == "https" && jwks_uri.scheme() == "https" {
            validate_https_issuer(self.issuer())?;
            validate_https_url(self.jwks_uri(), false)?;
        } else {
            if issuer.scheme() == "https" {
                validate_https_issuer(self.issuer())?;
            }
            if jwks_uri.scheme() == "https" {
                validate_https_url(self.jwks_uri(), false)?;
            } else {
                if jwks_uri.fragment().is_some() {
                    return invalid("authentication JWKS URI cannot carry a fragment");
                }
                if self.tls_trust_profile.is_some() {
                    return invalid(
                        "a plain HTTP authentication JWKS URI cannot use a TLS trust profile",
                    );
                }
            }
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
        // A listed gate is a statement the deployment means: an empty
        // allowlist admits nothing and an empty scope requirement gates
        // nothing, and both are almost certainly a mis-authored key rather
        // than a deliberate posture. `unrestricted` is the deliberate one.
        if let Some(clients) = self.allowed_clients.listed_values() {
            validate_strings(clients, 1, 32, 1, 128, "authentication allowedClients")?;
        }
        if let Some(assertion_issuers) = &self.assertion_issuers {
            let clients: Vec<String> = assertion_issuers.keys().cloned().collect();
            validate_strings(&clients, 1, 32, 1, 128, "authentication assertionIssuers")?;
            // A client identifier is its issuer's spelling, kept as written
            // (CFG-ID-2): any text without a control character.
            if clients
                .iter()
                .any(|client| registry_platform_yaml::ExternalId::new(client.as_str()).is_err())
            {
                return invalid("authentication assertionIssuers client identifier is invalid");
            }
            for issuers in assertion_issuers.values() {
                validate_strings(issuers, 1, 8, 1, 512, "authentication assertionIssuers")?;
            }
        }
        if let Some(scopes) = self.required_scopes.listed_values() {
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
            "local authentication issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port; any other plain HTTP issuer needs authentication.oidc.allowInsecureHttp: true",
        ))?;
    if value != format!("http://127.0.0.1:{port}") {
        return invalid(
            "local authentication issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port; any other plain HTTP issuer needs authentication.oidc.allowInsecureHttp: true",
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

/// The shared access-token roster, narrowed to the members Evidence admits by
/// [`admitted_algorithms`].
pub use registry_platform_oidc::AccessTokenAlgorithm;

/// The members of the shared roster Evidence admits on its resource-server
/// profile.
const ADMITTED_ALGORITHM_NAMES: [&str; 3] = ["EdDSA", "ES256", "RS256"];

/// One roster member, read only when Evidence admits it.
struct AdmittedAlgorithm(AccessTokenAlgorithm);

impl<'de> Deserialize<'de> for AdmittedAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let algorithm = AccessTokenAlgorithm::deserialize(deserializer)?;
        if ADMITTED_ALGORITHM_NAMES.contains(&algorithm.jwa_name()) {
            Ok(Self(algorithm))
        } else {
            Err(de::Error::unknown_variant(
                algorithm.jwa_name(),
                &ADMITTED_ALGORITHM_NAMES,
            ))
        }
    }
}

fn admitted_algorithms<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<AccessTokenAlgorithm>, D::Error> {
    let admitted = Vec::<AdmittedAlgorithm>::deserialize(deserializer)?;
    Ok(admitted.into_iter().map(|admitted| admitted.0).collect())
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
    /// The PEM certificate chain (leaf first) certifying the active signing
    /// key. It is public material held in the bundle beside the public JWK.
    /// Absent, credentials carry no `x5c` and the key set publishes none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_chain_file: Option<CertificateChainPath>,
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

/// A bundle path `public-keys/<name>.chain.pem` naming a PEM certificate chain.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct CertificateChainPath(String);

impl CertificateChainPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CertificateChainPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CertificateChainPath")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for CertificateChainPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if is_certificate_chain_path(&value) {
            Ok(Self(value))
        } else {
            Err(Invalid::expected(
                "a path public-keys/<name>.chain.pem, where the name uses ASCII letters, digits, dots, underscores, or hyphens",
                "Name a certificate chain file under public-keys/ ending in .chain.pem.",
            )
            .into_error())
        }
    }
}

impl Serialize for CertificateChainPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn is_certificate_chain_path(value: &str) -> bool {
    let Some(name) = value.strip_prefix("public-keys/") else {
        return false;
    };
    let Some(stem) = name.strip_suffix(".chain.pem") else {
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
            if !valid_shared_local_id(name) {
                return not_a_local_id("selector field name");
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
    Uuid {},
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
            Self::Uuid {} => {
                if aggregate_maximum < 36 {
                    return invalid("selector UUID exceeds aggregate byte bound");
                }
            }
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
                "a relative path under adapter-packs/, adapters/, derivations/, schemas/, codelists/, fixtures/, or queries/, using ASCII letters, digits, dots, underscores, hyphens, and slashes, without . or .. segments",
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
    const ROOTS: [&str; 7] = [
        "adapter-packs/",
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

/// The reviewed endpoint policies one authored connection name may select.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceConnectionPolicies {
    pub endpoints: UniqueIdList<EvidenceConnectionPolicy>,
}

/// One pinned Adapter pack selected by an Evidence Source.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourcePackConfig {
    pub id: LocalId,
    pub version: String,
    pub digest: Digest,
    pub artifact_prefix: ArtifactPath,
}

/// One authorized selector field bound to a named pack route input.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceInputConfig {
    pub selector: SourceInputSelector,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceInputSelector {
    pub role: LocalId,
    pub profile: LocalId,
    pub field: LocalId,
}

/// One Evidence source binding. Acquisition and extraction are pack route
/// logic; this contract selects only governed artifacts, authority and inputs.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceConfig {
    pub pack: SourcePackConfig,
    pub route: LocalId,
    pub connection: LocalId,
    #[serde(
        default,
        deserialize_with = "external_id_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub inputs: BTreeMap<String, SourceInputConfig>,
    pub posture: AcquisitionPosture,
    pub fact_schema: ArtifactPath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<SourceProjectionConfig>,
}

/// Package-owned projection of matched pack facts. It cannot affect source
/// inputs, lookup classification, credentials or the selected route.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceProjectionConfig {
    pub script: ArtifactPath,
    pub entrypoint: String,
    pub digest: Digest,
}

impl SourceConfig {
    fn validate(&self, _assurance_profile: AssuranceProfile) -> Result<(), ConfigError> {
        validate_string(&self.pack.version, 1, 128, "source pack version")?;
        if self.pack.version.chars().any(char::is_whitespace) {
            return invalid("source pack version must not contain whitespace");
        }
        let expected_prefix = format!("adapter-packs/{}/{}", self.pack.id, self.pack.digest.hex());
        if self.pack.artifact_prefix.as_str() != expected_prefix {
            return invalid("source pack artifact prefix must match its id and digest");
        }
        require_artifact_prefix(&self.fact_schema, "schemas/")?;
        if let Some(projection) = &self.projection {
            if self.posture != AcquisitionPosture::RecordTransformed {
                return invalid("a source projection requires record-transformed posture");
            }
            require_artifact_prefix(&projection.script, "derivations/")?;
            if !projection.script.as_str().ends_with(".rhai")
                || projection.entrypoint.is_empty()
                || projection.entrypoint.len() > 128
                || !projection
                    .entrypoint
                    .bytes()
                    .enumerate()
                    .all(|(index, byte)| {
                        byte == b'_'
                            || byte.is_ascii_alphabetic()
                            || (index > 0 && byte.is_ascii_digit())
                    })
            {
                return invalid(
                    "source projection must name a Rhai script and bounded function identifier",
                );
            }
        }
        Ok(())
    }

    pub fn connection(&self) -> &str {
        self.connection.as_str()
    }

    pub fn posture(&self) -> AcquisitionPosture {
        self.posture
    }

    pub fn fact_schema(&self) -> &ArtifactPath {
        &self.fact_schema
    }

    pub fn selector_bindings(&self) -> Vec<SelectorBinding<'_>> {
        self.inputs
            .values()
            .map(|input| SelectorBinding {
                role: input.selector.role.as_str(),
                profile: input.selector.profile.as_str(),
                field: input.selector.field.as_str(),
            })
            .collect()
    }
}

fn external_id_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    let map = BTreeMap::<ExternalId, V>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value))
        .collect())
}

/// An assertion member under another authentication type is refused by the
/// reader as an unknown key. Its fix names the one type that carries the
/// member, which the list of the written type's own keys cannot.
fn name_the_assertion_type(report: Report) -> Report {
    let files_checked = report.files_checked();
    let mut named = Report::new(
        report
            .into_diagnostics()
            .into_iter()
            .map(|mut diagnostic| {
                let assertion_member = ["clientAssertionKeyRef", "clientAssertionAudience"]
                    .iter()
                    .any(|member| {
                        diagnostic
                            .path
                            .strip_suffix(member)
                            .is_some_and(|parent| parent.ends_with("/authentication/"))
                    });
                if diagnostic.code == "config.unknown-key" && assertion_member {
                    diagnostic.suggested_action =
                        "Declare type: oauth2-private-key-jwt to authenticate with a client assertion key; no other authentication type carries this member."
                            .to_owned();
                }
                diagnostic
            })
            .collect(),
    );
    if let Some(files_checked) = files_checked {
        named.set_files_checked(files_checked);
    }
    named
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
        validate_len(
            self.response_formats.len(),
            1,
            4,
            "authority grant response formats",
        )?;
        for (index, format) in self.response_formats.iter().enumerate() {
            if self.response_formats[..index].contains(format) {
                return invalid("authority grant response formats must be unique");
            }
        }
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

/// The host protocol id of the wallet presentation protocol. A Source whose
/// pack route reaches an endpoint with this protocol acquires through the
/// holder-presented channel, and no other Source does.
pub(crate) const WALLET_PRESENTATION_PROTOCOL_ID: &str = "wallet-presentation-v1";

/// The holder-presented acquisition beside a definition's `source`: one Source
/// that uses the wallet presentation protocol, and the selector profiles whose
/// requests acquire through it.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolderPresentedAcquisition {
    pub source: String,
    pub selector_profiles: Vec<String>,
}

/// One pinned pack route supplies all acquisition work for a requirement per
/// channel: `source` for the source channel, and the optional
/// `holderPresented` block for the holder-presented channel. A request's
/// selector profile selects exactly one channel.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "AcquisitionDocument", into = "AcquisitionDocument")]
pub struct AcquisitionConfig {
    /// The Source acquisition starts from: the source channel's Source, or the
    /// holder-presented Source when the definition declares no `source`. Read
    /// the channel's own Source through [`Self::source_for_profile`].
    pub source: String,
    source_channel: bool,
    pub holder_presented: Option<HolderPresentedAcquisition>,
}

/// The authored shape of [`AcquisitionConfig`]. Each channel is omitted when
/// absent, so a definition written before holder-presented acquisition
/// existed keeps exactly the projected configuration, and therefore exactly the
/// `configurationRevision`, it already had.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcquisitionDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    holder_presented: Option<HolderPresentedAcquisition>,
}

impl TryFrom<AcquisitionDocument> for AcquisitionConfig {
    type Error = &'static str;

    fn try_from(document: AcquisitionDocument) -> Result<Self, Self::Error> {
        let source_channel = document.source.is_some();
        let source = document
            .source
            .or_else(|| {
                document
                    .holder_presented
                    .as_ref()
                    .map(|holder_presented| holder_presented.source.clone())
            })
            .ok_or("requirement acquisition names no source")?;
        Ok(Self {
            source,
            source_channel,
            holder_presented: document.holder_presented,
        })
    }
}

impl From<AcquisitionConfig> for AcquisitionDocument {
    fn from(acquisition: AcquisitionConfig) -> Self {
        Self {
            source: acquisition.source_channel.then_some(acquisition.source),
            holder_presented: acquisition.holder_presented,
        }
    }
}

impl AcquisitionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_local_id(&self.source) {
            return invalid("requirement acquisition source identifier is invalid");
        }
        if let Some(holder_presented) = &self.holder_presented {
            if !valid_local_id(&holder_presented.source) {
                return invalid("requirement holder-presented source identifier is invalid");
            }
        }
        Ok(())
    }

    /// The Source of the source channel, absent for a wallet-only definition.
    pub fn source_channel_source(&self) -> Option<&str> {
        self.source_channel.then_some(self.source.as_str())
    }

    /// The Source of the holder-presented channel, when the definition has one.
    pub fn holder_presented_source(&self) -> Option<&str> {
        self.holder_presented
            .as_ref()
            .map(|holder_presented| holder_presented.source.as_str())
    }

    /// The channel a request on `profile` acquires through. A profile the
    /// holder-presented block lists selects that channel; every other profile
    /// selects the source channel, which a wallet-only definition lacks.
    pub fn channel_for_profile(&self, profile: &str) -> Option<ChannelKind> {
        if self
            .holder_presented
            .as_ref()
            .is_some_and(|holder_presented| {
                holder_presented
                    .selector_profiles
                    .iter()
                    .any(|listed| listed == profile)
            })
        {
            Some(ChannelKind::HolderPresented)
        } else {
            self.source_channel.then_some(ChannelKind::Source)
        }
    }

    /// The only Source a request on `profile` may acquire through.
    pub fn source_for_profile(&self, profile: &str) -> Option<&str> {
        match self.channel_for_profile(profile)? {
            ChannelKind::Source => self.source_channel_source(),
            ChannelKind::HolderPresented => self.holder_presented_source(),
        }
    }

    pub fn source_ids(&self) -> Vec<&str> {
        let mut sources = Vec::with_capacity(2);
        sources.extend(self.source_channel_source());
        sources.extend(self.holder_presented_source());
        sources
    }

    pub fn uses_source(&self, source_id: &str) -> bool {
        self.source_ids().contains(&source_id)
    }

    pub fn initial_source(&self) -> &str {
        &self.source
    }

    /// The channel `source_id` serves for this definition.
    fn channel_of_source(&self, source_id: &str) -> Option<ChannelKind> {
        if self.source_channel_source() == Some(source_id) {
            Some(ChannelKind::Source)
        } else if self.holder_presented_source() == Some(source_id) {
            Some(ChannelKind::HolderPresented)
        } else {
            None
        }
    }

    /// Whether every one of `profiles` selects the channel `source_id` serves,
    /// so a request or grant on them can reach that Source.
    fn serves<'a>(&self, source_id: &str, profiles: impl IntoIterator<Item = &'a str>) -> bool {
        let Some(channel) = self.channel_of_source(source_id) else {
            return false;
        };
        profiles
            .into_iter()
            .all(|profile| self.channel_for_profile(profile) == Some(channel))
    }

    /// The channel rules that need the definition's subject roles. Each
    /// refusal names the member to repair and carries no value.
    fn validate_channels(&self, roles: &[SubjectRole], at: &str) -> Result<(), Violation> {
        let Some(holder_presented) = &self.holder_presented else {
            return Ok(());
        };
        let profiles_at = format!("{at}/acquisition/holderPresented/selectorProfiles");
        validate_len(
            holder_presented.selector_profiles.len(),
            1,
            16,
            "holder-presented selector profiles",
        )
        .at(&profiles_at)?;
        let mut listed = BTreeSet::new();
        for (index, profile) in holder_presented.selector_profiles.iter().enumerate() {
            let profile_at = format!("{profiles_at}/{index}");
            if !valid_local_id(profile) {
                return invalid("holder-presented selector profile identifier is invalid")
                    .at(profile_at);
            }
            if !listed.insert(profile.as_str()) {
                return invalid("holder-presented selector profiles must be unique").at(profile_at);
            }
            if !roles.iter().any(|role| {
                role.selector_profiles
                    .iter()
                    .any(|allowed| allowed == profile)
            }) {
                return invalid(
                    "holder-presented selector profile is not allowed by any subject role",
                )
                .at(profile_at);
            }
        }
        if !self.source_channel
            && roles
                .iter()
                .flat_map(|role| role.selector_profiles.iter())
                .any(|allowed| !listed.contains(allowed.as_str()))
        {
            return invalid(
                "a definition without a source lists every allowed selector profile under holderPresented",
            )
            .at(format!("{at}/acquisition"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequirementConfig {
    /// Human-facing presentation, excluded from the behavior revision.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    pub question: Option<String>,
    /// Package ceiling for every target grant serving this definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ceiling: Option<GrantCeiling>,
    /// Definition-specific representation ceiling, distinct from package formats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub representations: Option<Vec<ResponseFormat>>,
    /// Stable application-facing handle for the complete published
    /// definition. It is explicit rather than inferred from the requirement
    /// URI so URI revisions cannot silently rename application code.
    pub handle: String,
    /// The requirement's URI, written `uri`: `id` is the name of a local
    /// identifier (CFG-ID-1).
    #[serde(rename = "uri")]
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
    /// Experimental (`v1alpha1`). Declares that this definition can answer an
    /// unauthenticated certificate check once a target authority activates it.
    /// The key is omitted when absent, so a definition without it keeps exactly
    /// the projected configuration, and therefore exactly the
    /// `configurationRevision`, it already had.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_check: Option<PublicCheckConfig>,
}

/// The public-check declaration of one requirement: which Source fact carries
/// the check code, and which two concepts form the public answer.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicCheckConfig {
    pub check_code_fact: String,
    pub status_output: String,
    pub fields_output: String,
}

/// The loaded public-check activation: the requirement the activated target
/// authority opens, with the concept handles and Source fact its answer reads.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicCheckActivation {
    pub requirement: String,
    /// The requirement's stable application-facing handle.
    pub handle: String,
    pub check_code_fact: String,
    pub status_output: String,
    pub fields_output: String,
}

/// The dimensions not already bounded by the definition's purposes, subjects,
/// selector profiles, representations and subject-binding declaration.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantCeiling {
    pub authorities: Vec<AuthorityKind>,
    pub actor_kinds: Vec<registry_platform_oidc::ActorKind>,
    pub value_origins: Vec<ValueOrigin>,
    pub audiences: Vec<String>,
}

impl GrantCeiling {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_len(self.authorities.len(), 1, 5, "grant authority ceiling")?;
        validate_len(self.actor_kinds.len(), 1, 3, "grant actor-kind ceiling")?;
        validate_len(self.value_origins.len(), 1, 3, "grant value-origin ceiling")?;
        validate_strings(&self.audiences, 1, 32, 1, 2048, "grant audience ceiling")?;
        for audience in &self.audiences {
            validate_uri(audience)?;
        }
        if self.audiences.iter().collect::<BTreeSet<_>>().len() != self.audiences.len() {
            return invalid("grant audience ceiling contains a duplicate");
        }
        for i in 0..self.authorities.len() {
            if self.authorities[..i].contains(&self.authorities[i]) {
                return invalid("grant authority ceiling contains a duplicate");
            }
        }
        for i in 0..self.actor_kinds.len() {
            if self.actor_kinds[..i].contains(&self.actor_kinds[i]) {
                return invalid("grant actor-kind ceiling contains a duplicate");
            }
        }
        for i in 0..self.value_origins.len() {
            if self.value_origins[..i].contains(&self.value_origins[i]) {
                return invalid("grant value-origin ceiling contains a duplicate");
            }
        }
        Ok(())
    }
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
        if let Some(question) = &self.question {
            validate_len(question.len(), 1, 2048, "definition question")?;
            if DisplayText::new(question.as_str()).is_err() {
                return Err(ConfigError::InvalidField(
                    "display text contains a prohibited character",
                    "definition question",
                ));
            }
        }
        if let Some(ceiling) = &self.grant_ceiling {
            ceiling.validate()?;
        }
        if let Some(formats) = &self.representations {
            validate_len(formats.len(), 1, 4, "definition representations")?;
            for (index, format) in formats.iter().enumerate() {
                if formats[..index].contains(format)
                    || !subject_binding_permits_response_format(
                        self.subject_binding_mode(),
                        *format,
                    )
                {
                    return invalid("definition representations violate its binding ceiling");
                }
            }
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
        validate_len(
            self.reference_frameworks.len(),
            1,
            16,
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
        self.validate_public_check()?;
        self.disclosure_guard.validate()
    }

    /// The checks of a `publicCheck` declaration that need only this
    /// requirement. The subject shape needs the selector profiles and is
    /// checked with the cross references.
    fn validate_public_check(&self) -> Result<(), ConfigError> {
        let Some(public_check) = &self.public_check else {
            return Ok(());
        };
        validate_string(
            &public_check.check_code_fact,
            1,
            128,
            "publicCheck checkCodeFact",
        )?;
        let form_of = |handle: &str| {
            self.concepts
                .iter()
                .find(|concept| concept.handle == handle)
                .map(|concept| concept.form)
        };
        if form_of(&public_check.status_output) != Some(ConceptForm::ControlledCategory) {
            return invalid("publicCheck statusOutput must name a controlled-category concept");
        }
        if form_of(&public_check.fields_output) != Some(ConceptForm::ReviewedStructuredValue) {
            return invalid(
                "publicCheck fieldsOutput must name a reviewed-structured-value concept",
            );
        }
        // An entity reference is scoped to a relying party; a public check has
        // none, so the answer could never project one.
        if self.concepts.iter().any(|concept| {
            matches!(
                concept.form,
                ConceptForm::AudienceScopedEntityReference | ConceptForm::EntityReferenceList
            )
        }) {
            return invalid("publicCheck must not declare an entity-reference concept");
        }
        if self.acquisition.source_channel_source().is_none()
            || self.acquisition.holder_presented.is_some()
        {
            return invalid("publicCheck requires one Source and no holderPresented acquisition");
        }
        Ok(())
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
            if !valid_shared_local_id(name) {
                return not_a_local_id("derivation parameter name");
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
    Scalar(DerivationScalar),
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
            Self::Scalar(value) => value.0.serialize(serializer),
            Self::Decimal(value) => value.serialize(serializer),
            Self::BucketBoundaries(boundaries) => boundaries.serialize(serializer),
        }
    }
}

impl ParameterValue {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Scalar(DerivationScalar(ScalarParameter::String(value))) => {
                validate_string(value, 0, 1_024, "derivation string parameter")
            }
            Self::Scalar(DerivationScalar(ScalarParameter::Integer(value))) => {
                if value.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                    invalid("derivation integer parameter exceeds safe bounds")
                } else {
                    Ok(())
                }
            }
            Self::Scalar(DerivationScalar(ScalarParameter::Boolean(_))) => Ok(()),
            Self::Decimal(value) => value.validate(),
            Self::BucketBoundaries(boundaries) => validate_bucket_boundaries(boundaries),
        }
    }
}

/// One scalar derivation parameter: text, a safe integer, or a boolean. An
/// integer outside the safe integers is refused at the value while the bundle
/// is read (CFG-QTY-4).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DerivationScalar(pub ScalarParameter);

impl<'de> Deserialize<'de> for DerivationScalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let scalar = ScalarParameter::deserialize(deserializer)?;
        if matches!(scalar, ScalarParameter::Integer(value) if value.unsigned_abs() > MAX_SAFE_INTEGER as u64)
        {
            return Err(de::Error::custom(Invalid::out_of_range(
                -MAX_SAFE_INTEGER,
                MAX_SAFE_INTEGER,
            )));
        }
        Ok(Self(scalar))
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
    /// The concept's URI, written `uri`: `id` is the name of a local
    /// identifier (CFG-ID-1).
    #[serde(rename = "uri")]
    pub id: String,
    /// The concept's value form, written `type`: the tag that fixes the
    /// shape of `constraints` (CFG-ID-7).
    #[serde(rename = "type")]
    pub form: ConceptForm,
    pub required: bool,
    #[serde(default, deserialize_with = "concept_constraints")]
    pub constraints: OrderedMap<YamlValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd_jwt_vc: Option<SdJwtVcConceptProjection>,
}

/// The fewest and the most items a list concept may declare.
const MINIMUM_CONCEPT_ITEMS: u64 = 1;
const MAXIMUM_CONCEPT_ITEMS: u64 = 64;

/// Reads a concept's constraints, refusing an item count outside its bounds
/// at the value (CFG-QTY-4). `minimumItems` and `maximumItems` carry the same
/// bounds in every list form; each other constraint depends on the concept's
/// form and is checked with it.
fn concept_constraints<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<OrderedMap<YamlValue>, D::Error> {
    struct ItemCount(YamlValue);

    impl<'de> Deserialize<'de> for ItemCount {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let value = YamlValue::deserialize(deserializer)?;
            let integer = value.is_i64() || value.is_u64();
            let bounded = value.as_u64().is_some_and(|count| {
                (MINIMUM_CONCEPT_ITEMS..=MAXIMUM_CONCEPT_ITEMS).contains(&count)
            });
            if integer && !bounded {
                return Err(de::Error::custom(Invalid::out_of_range(
                    MINIMUM_CONCEPT_ITEMS,
                    MAXIMUM_CONCEPT_ITEMS,
                )));
            }
            Ok(Self(value))
        }
    }

    struct ConstraintsVisitor;

    impl<'de> Visitor<'de> for ConstraintsVisitor {
        type Value = OrderedMap<YamlValue>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a mapping with unique string keys")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut entries: Vec<(String, YamlValue)> = Vec::new();
            while let Some(key) = map.next_key::<String>()? {
                if entries.iter().any(|(seen, _)| *seen == key) {
                    return Err(Invalid::expected(
                        "a mapping that names each key once",
                        "Remove the repeated key.",
                    )
                    .into_error());
                }
                let value = if matches!(key.as_str(), "minimumItems" | "maximumItems") {
                    map.next_value::<ItemCount>()?.0
                } else {
                    map.next_value::<YamlValue>()?
                };
                entries.push((key, value));
            }
            Ok(OrderedMap(entries))
        }
    }

    deserializer.deserialize_map(ConstraintsVisitor)
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
        validate_len(self.families.len(), 1, 16, "disclosure families")?;
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
    check_separator_collisions: bool,
    validate: impl Fn(&T) -> Result<(), ConfigError>,
) -> Result<(), Violation> {
    validate_len(map.len(), minimum, maximum, "named configuration map").at(pointer)?;
    for (name, value) in map.iter() {
        let at = named(pointer, name);
        if !valid_shared_local_id(name) {
            return not_a_local_id("map key").at_key(at);
        }
        validate(value).at(at)?;
    }
    if check_separator_collisions {
        if let Some((_, second)) = registry_platform_yaml::lookalike_local_id_pairs(map.keys())
            .into_iter()
            .next()
        {
            return invalid("named map identifiers differ only by `-` versus `_`")
                .at_key(named(pointer, map.0[second].0.as_str()));
        }
    }
    Ok(())
}

/// Source-positioned integrity checks over the bundle's top-level named
/// definition maps. Invalid keys are left to the owning map rule, so only
/// validated local identifiers can be repeated in these diagnostics.
fn bundle_integrity_diagnostics(
    decoded: &registry_platform_yaml::Decoded<EvidenceConfig>,
) -> Vec<Diagnostic> {
    fn collisions<T>(
        document: &Document,
        code: &str,
        pointer: &str,
        values: &OrderedMap<T>,
    ) -> Vec<Diagnostic> {
        let owned = values
            .keys()
            .filter(|id| registry_platform_yaml::LocalId::new(*id).is_ok())
            .map(|id| (id.to_owned(), named(pointer, id)))
            .collect::<Vec<_>>();
        let entries = owned
            .iter()
            .map(|(id, pointer)| AuthoredId::at_key(id, pointer))
            .collect::<Vec<_>>();
        local_id_collision_diagnostics(document, code, &entries)
    }

    let mut diagnostics = collisions(
        &decoded.document,
        "evidence.bundle.selector-profile-id-collision",
        "/selectorProfiles",
        &decoded.value.selector_profiles,
    );
    diagnostics.extend(collisions(
        &decoded.document,
        "evidence.bundle.source-id-collision",
        "/sources",
        &decoded.value.sources,
    ));
    diagnostics.extend(collisions(
        &decoded.document,
        "evidence.bundle.source-connection-id-collision",
        "/sourceConnections",
        &decoded.value.source_connections,
    ));
    diagnostics.extend(collisions(
        &decoded.document,
        "evidence.bundle.authority-profile-id-collision",
        "/authorityProfiles",
        &decoded.value.authority_profiles,
    ));
    diagnostics
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
    pub(crate) concern: Concern,
    pub(crate) error: ConfigError,
}

/// What a failed rule concerns in the member a [`Violation`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Concern {
    /// The member's value.
    Value,
    /// The member's key, as a malformed item name does.
    Key,
    /// The member identifies a list item, and it repeats the same member of
    /// the item at index `first` in the same list.
    RepeatedId { first: u32 },
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
            concern: Concern::Value,
            error,
        })
    }

    fn at_key(self, pointer: impl Into<String>) -> Result<T, Violation> {
        self.map_err(|error| Violation {
            pointer: pointer.into(),
            concern: Concern::Key,
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
            );
        }
    };
    if url.scheme() != "http" || value != canonical {
        return invalid(
            "unauthenticated local source origin must be a canonical numeric loopback HTTP origin with an explicit non-zero port",
        );
    }
    Ok(())
}

pub(crate) fn validate_source_url(value: &str, origin_only: bool) -> Result<Url, ConfigError> {
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
    let minimum = validate_constraint_u64(
        constraints,
        "minimumItems",
        MINIMUM_CONCEPT_ITEMS,
        MAXIMUM_CONCEPT_ITEMS,
    )?;
    let maximum = validate_constraint_u64(
        constraints,
        "maximumItems",
        MINIMUM_CONCEPT_ITEMS,
        MAXIMUM_CONCEPT_ITEMS,
    )?;
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
/// same bytes are published. The 512-character bound stays local because the
/// profile's own bound is the far looser public-text one.
fn validate_uri(value: &str) -> Result<(), ConfigError> {
    if !(1..=512).contains(&value.chars().count()) {
        return invalid("string length is outside Version 1 bounds");
    }
    if !registry_discovery_profile::is_valid_identifier(value) {
        return invalid("URI is invalid");
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn uri_validation_counts_unicode_characters() {
    let boundary = format!("urn:example:{}", "é".repeat(500));
    assert_eq!(boundary.chars().count(), 512);
    validate_uri(&boundary).expect("512 Unicode characters");
    assert!(validate_uri(&format!("{boundary}é")).is_err());
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

/// Whether `value` is a local identifier as every Registry Stack format
/// writes one (CFG-ID-1): the grammar of the key of an id-keyed map.
fn valid_shared_local_id(value: &str) -> bool {
    registry_platform_yaml::LocalId::new(value).is_ok()
}

/// What the refusal of a name outside that grammar states.
const LOCAL_ID_RULE: &str = "the name is not a local identifier: a lowercase letter, then up to 63 lowercase letters, digits, `_`, or `-`";

/// Refuses the name `label` stands for as no local identifier.
fn not_a_local_id<T>(label: &'static str) -> Result<T, ConfigError> {
    Err(ConfigError::InvalidField(LOCAL_ID_RULE, label))
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

/// A normalized-project configuration that declares a public check: one
/// subject role, one selector profile with one field, a status and a fields
/// output, and no effective authority profiles.
#[cfg(test)]
pub(crate) fn public_check_test_config() -> EvidenceConfig {
    const FIXTURE: &str =
        include_str!("../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml");
    let text = FIXTURE
        .replace(
            "      family_name:\n        type: string\n        minimumBytes: 1\n        maximumBytes: 200\n      birth_date:\n        type: date\n",
            "",
        )
        .replace(
            "      family_name:\n        selector:\n          role: subject\n          profile: person-demographics-v1\n          field: family_name\n      birth_date:\n        selector:\n          role: subject\n          profile: person-demographics-v1\n          field: birth_date\n",
            "",
        )
        .replace(
            "      - handle: is_adult\n        uri: urn:example:fixture:concept:adult-status\n        type: boolean\n        required: true\n        constraints: {}\n",
            "      - handle: status\n        uri: urn:example:fixture:concept:status\n        type: controlled-category\n        required: true\n        constraints:\n          categoryScheme: urn:example:fixture:scheme:status\n          schemeVersion: \"1\"\n          maximumBytes: 16\n          codelist: codelists/status.yaml\n      - handle: fields\n        uri: urn:example:fixture:concept:fields\n        type: reviewed-structured-value\n        required: true\n        constraints:\n          schema: urn:example:fixture:schema:fields:v1\n          maximumSerializedBytes: 512\n      - handle: relying_only\n        uri: urn:example:fixture:concept:relying-only\n        type: boolean\n        required: false\n        constraints: {}\n",
        )
        .replace(
            "    existenceDisclosure: collapse-unresolved\n",
            "    existenceDisclosure: collapse-unresolved\n    publicCheck:\n      checkCodeFact: check_code\n      statusOutput: status\n      fieldsOutput: fields\n",
        );
    let mut config = EvidenceConfig::parse_yaml(text.as_bytes())
        .expect("public check fixture configuration parses");
    config.project = Some("standalone-evidence".to_owned());
    config.authority_profiles = OrderedMap::default();
    for definition in &mut config.requirements {
        definition.grant_ceiling = Some(GrantCeiling {
            authorities: vec![AuthorityKind::Statutory],
            actor_kinds: vec![registry_platform_oidc::ActorKind::Service],
            value_origins: vec![ValueOrigin::Request],
            audiences: vec!["urn:example:audience:relying-party".to_owned()],
        });
        definition.representations = Some(vec![ResponseFormat::SignedJws]);
    }
    config
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;

    fn current_adapter_contract_accepts(
        base_url: &str,
        pack_authentication: serde_json::Value,
        runtime_credential: serde_json::Value,
        policy_authentication: serde_json::Value,
    ) -> bool {
        use registry_adapter_core::{
            AdapterPack, AdapterProfile, AdapterProject, EvidenceConnectionPolicy, Workspace,
        };
        use registry_adapter_engine::artifacts::PackArtifactBytes;
        use registry_adapter_engine::evidence::{
            compile_evidence_with_protocols, EvidenceCompileInputs, EvidenceLimits,
            EvidenceRuntimeBindings,
        };
        use registry_platform_config::{SecretProvider, SecretResolver};

        let inputs = br#"{"type":"object","additionalProperties":false,"properties":{}}"#;
        let facts = br#"{"type":"object","additionalProperties":false,"properties":{"ok":{"type":"boolean"}}}"#;
        let pack: AdapterPack = serde_json::from_value(serde_json::json!({
            "id":"current-source-contract",
            "version":"1",
            "testedVersions":[],
            "endpoints":[{
                "id":"provider",
                "component":"http",
                "authentication":pack_authentication,
                "attemptTimeoutMilliseconds":1000,
                "maximumResponseBytes":4096,
                "requestHeaders":[],
                "operations":[{"id":"lookup","safeUpstream":true}],
                "testedVersions":[]
            }],
            "sourceRoutes":[{
                "id":"lookup",
                "evidence":{
                    "inputsSchema":{
                        "path":"schemas/inputs.json",
                        "digest":registry_platform_config::sha256_uri(inputs)
                    },
                    "factsSchema":{
                        "path":"schemas/facts.json",
                        "digest":registry_platform_config::sha256_uri(facts)
                    }
                },
                "steps":[{"to":{"uri":"http:provider","parameters":{
                    "httpMethod":"GET",
                    "path":"/data",
                    "operation":"lookup"
                }}}]
            }]
        }))
        .expect("the current pack shape parses");
        let artifacts = PackArtifactBytes::new([
            ("schemas/inputs.json".to_owned(), inputs.to_vec()),
            ("schemas/facts.json".to_owned(), facts.to_vec()),
        ]);
        let mut binding = serde_json::json!({
            "endpoint":"provider",
            "baseUrl":base_url,
            "credential":runtime_credential
        });
        if binding["credential"]["type"] == "none" && base_url.starts_with("https://") {
            binding["anonymousHttps"] = "operator-approved".into();
        }
        let Ok(bindings) = serde_json::from_value(serde_json::json!({
            "id":"current-source",
            "endpoints":[binding],
            "allowedPrivateCidrs":[]
        })) else {
            return false;
        };
        let Ok(resolver) = SecretResolver::new([SecretProvider::Environment], "") else {
            return false;
        };
        let profile: AdapterProfile = serde_json::from_value(serde_json::json!({
            "id":"unused-profile",
            "version":"1",
            "operations":[],
            "problems":[],
            "problemEnvelope":"{\"code\":\"{{problemCode}}\"}"
        }))
        .expect("minimal profile");
        let project: AdapterProject = serde_json::from_value(serde_json::json!({
            "project":{"id":"unused-project","version":"1"},
            "profile":{
                "id":"unused-profile",
                "version":"1",
                "digest":format!("sha256:{}", "1".repeat(64))
            },
            "pack":{
                "id":"current-source-contract",
                "version":"1",
                "digest":format!("sha256:{}", "2".repeat(64))
            },
            "recordTypes":[]
        }))
        .expect("minimal project");
        let workspace = Workspace {
            profile: &profile,
            pack: &pack,
            project: &project,
            runtime: None,
            fixtures: &[],
        };
        if !registry_adapter_core::check_endpoint_bindings(&workspace, &bindings).is_empty() {
            return false;
        }
        let runtime = EvidenceRuntimeBindings::new(bindings, resolver);
        let Ok(policy): Result<EvidenceConnectionPolicy, _> =
            serde_json::from_value(serde_json::json!({
                "endpoint":"provider",
                "baseUrl":base_url,
                "clientIdentity":"forbidden",
                "authentication":policy_authentication
            }))
        else {
            return false;
        };
        compile_evidence_with_protocols(
            &EvidenceCompileInputs {
                pack: &pack,
                route: "lookup",
                runtime: &runtime,
                connection_id: Some("current-source"),
                connection: &[policy],
                pack_artifacts: &artifacts,
                limits: EvidenceLimits::default(),
            },
            &crate::host_protocol::registry().expect("Evidence host protocols"),
        )
        .is_ok()
    }

    fn current_client_credential() -> serde_json::Value {
        serde_json::json!({
            "type":"oauth2-client-credentials",
            "tokenEndpoint":"https://issuer.invalid/token",
            "clientIdRef":"secret:env/CLIENT_ID",
            "clientSecretRef":"secret:env/CLIENT_SECRET",
            "credentialPlacement":"form-body",
            "maximumCacheSeconds":60
        })
    }

    fn current_client_policy() -> serde_json::Value {
        serde_json::json!({
            "type":"oauth2-client-credentials",
            "tokenEndpoint":"https://issuer.invalid/token",
            "credentialPlacement":"form-body"
        })
    }

    fn current_private_key_credential() -> serde_json::Value {
        serde_json::json!({
            "type":"oauth2-private-key-jwt",
            "tokenEndpoint":"https://issuer.invalid/token",
            "clientIdRef":"secret:env/CLIENT_ID",
            "clientAssertionKeyRef":"secret:env/CLIENT_ASSERTION_KEY",
            "maximumCacheSeconds":60
        })
    }

    #[test]
    fn source_acquisition_defaults_are_finite_and_zero_is_refused() {
        let defaults = SourceAcquisitionConfig::default();
        let limits = defaults.limits().expect("maintained defaults are valid");
        assert_eq!(limits.maximum_data_operations(), 5);
        assert_eq!(limits.deadline().as_millis(), 30_000);
        assert_eq!(limits.maximum_response_bytes(), 1_048_576);

        for invalid in [
            SourceAcquisitionConfig {
                maximum_data_operations: 0,
                ..defaults
            },
            SourceAcquisitionConfig {
                deadline_milliseconds: 0,
                ..defaults
            },
            SourceAcquisitionConfig {
                maximum_response_bytes: 0,
                ..defaults
            },
        ] {
            assert!(invalid.limits().is_err());
        }
    }

    #[test]
    fn source_acquisition_deadline_stops_at_the_authoring_ceiling() {
        assert_eq!(
            MAX_ACQUISITION_DEADLINE_MILLISECONDS,
            registry_evidence_authoring::target::MAX_ACQUISITION_DEADLINE_MILLISECONDS
        );
        let defaults = SourceAcquisitionConfig::default();
        let at_ceiling = SourceAcquisitionConfig {
            deadline_milliseconds:
                registry_evidence_authoring::target::MAX_ACQUISITION_DEADLINE_MILLISECONDS,
            ..defaults
        };
        at_ceiling.limits().expect("the ceiling itself loads");

        let above = SourceAcquisitionConfig {
            deadline_milliseconds:
                registry_evidence_authoring::target::MAX_ACQUISITION_DEADLINE_MILLISECONDS + 1,
            ..defaults
        };
        let error = above
            .limits()
            .expect_err("a deadline above the ceiling is refused at load");
        assert!(
            error.to_string().contains(
                &registry_evidence_authoring::target::MAX_ACQUISITION_DEADLINE_MILLISECONDS
                    .to_string()
            ),
            "the refusal names the maximum: {error}"
        );
    }

    #[test]
    fn pack_source_config_is_the_only_source_shape() {
        let source = serde_json::json!({
            "pack": {
                "id": "synthetic-register",
                "version": "0.1.0",
                "digest": format!("sha256:{}", "1".repeat(64)),
                "artifactPrefix": format!("adapter-packs/synthetic-register/{}", "1".repeat(64))
            },
            "route": "evidence-person",
            "connection": "register",
            "inputs": {
                "personId": {"selector":{"role":"person","profile":"person-by-id","field":"person-id"}}
            },
            "posture": "record-transformed",
            "factSchema": "schemas/source-facts/person.schema.json"
        });
        let decoded = serde_json::from_value::<SourceConfig>(source.clone())
            .expect("a Source selects one pinned pack route and reviewed connection policy");
        decoded
            .validate(AssuranceProfile::Production)
            .expect("the pinned pack Source validates without transport DSL");

        let mut wrong_prefix = source.clone();
        wrong_prefix["pack"]["artifactPrefix"] = serde_json::json!("adapter-packs/other/0000");
        assert!(serde_json::from_value::<SourceConfig>(wrong_prefix)
            .unwrap()
            .validate(AssuranceProfile::Production)
            .is_err());

        let mut bad_input = source;
        let binding = bad_input["inputs"]
            .as_object_mut()
            .unwrap()
            .remove("personId")
            .unwrap();
        bad_input["inputs"]
            .as_object_mut()
            .expect("inputs object")
            .insert("x".repeat(513), binding);
        assert!(serde_json::from_value::<SourceConfig>(bad_input).is_err());

        let legacy = serde_json::json!({
            "type":"http-json",
            "baseUrl":"https://source.invalid",
            "authentication":{"type":"none"}
        });
        assert!(serde_json::from_value::<SourceConfig>(legacy).is_err());
    }

    #[test]
    fn connection_policy_groups_allow_no_network_and_keep_endpoint_ids_unique() {
        let policy = |endpoint: &str, base_url: &str| {
            serde_json::json!({
                "endpoint": endpoint,
                "baseUrl": base_url,
                "authentication":{"type":"none"},
                "clientIdentity": "forbidden"
            })
        };
        let valid: SourceConnectionPolicies = serde_json::from_value(serde_json::json!({
            "endpoints":[policy("records", "https://source.invalid/api")]
        }))
        .expect("one reviewed endpoint policy parses");
        assert_eq!(valid.endpoints.len(), 1);

        let empty: SourceConnectionPolicies =
            serde_json::from_value(serde_json::json!({"endpoints":[]})).unwrap();
        assert!(empty.endpoints.is_empty());
        let duplicate = serde_json::from_value::<SourceConnectionPolicies>(serde_json::json!({
            "endpoints":[
                policy("records", "https://source.invalid/api"),
                policy("records", "https://other.invalid/api")
            ]
        }));
        assert!(duplicate.is_err());
    }

    #[test]
    fn reference_frameworks_accept_unicode_at_the_character_bound_through_the_bundle_reader() {
        assert_uri_array_character_bound("/requirements/0/referenceFrameworks");
    }

    #[test]
    fn disclosure_families_accept_unicode_at_the_character_bound_through_the_bundle_reader() {
        assert_uri_array_character_bound("/requirements/0/disclosureGuard/families");
    }

    fn assert_uri_array_character_bound(pointer: &str) {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture validates");
        let mut projection = serde_json::to_value(config).expect("configuration serializes");
        EvidenceConfig::parse_projection(&projection).expect("the valid baseline reads");
        let boundary = format!("urn:example:{}", "é".repeat(500));
        *projection.pointer_mut(pointer).expect("URI array exists") = serde_json::json!([boundary]);
        EvidenceConfig::parse_projection(&projection)
            .expect("the complete bundle reader accepts a 512-character URI");
        for rejected in [
            serde_json::json!([format!("{boundary}é")]),
            serde_json::json!([]),
            serde_json::json!([boundary, boundary]),
            serde_json::json!((0..17)
                .map(|index| format!("urn:example:{index}"))
                .collect::<Vec<_>>()),
        ] {
            *projection.pointer_mut(pointer).expect("URI array exists") = rejected;
            assert!(
                EvidenceConfig::parse_projection(&projection).is_err(),
                "{pointer}"
            );
        }
    }

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
            "    requesterTags:\n      - fixture-agency\n",
            "    requesterTags:\n      - fixture-agency\n      - fixture-agency\n",
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
    fn bundle_named_definition_maps_refuse_separator_lookalikes_at_both_keys() {
        fn baseline() -> EvidenceConfig {
            EvidenceConfig::parse_yaml(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ))
            .expect("acceptance configuration parses")
        }

        fn assert_collision(
            config: EvidenceConfig,
            code: &str,
            first_id: &str,
            second_id: &str,
            first_path: &str,
            second_path: &str,
        ) {
            assert!(
                config.validate().is_err(),
                "programmatic validation must reject {code}"
            );
            let projection = serde_json::to_value(config).expect("configuration serializes");
            let mut authored = projection.clone();
            let members = authored
                .as_object_mut()
                .expect("bundle projection is an object");
            members.insert("apiVersion".to_owned(), EVIDENCE_BUNDLE_API_VERSION.into());
            members.insert("kind".to_owned(), EVIDENCE_BUNDLE_KIND.into());
            let authored = authored.to_string();
            let key_column = |id: &str| {
                authored
                    .find(&format!("\"{id}\":"))
                    .expect("the named definition key is authored")
                    + 1
            };
            let ConfigError::Refused(report) = EvidenceConfig::parse_projection(&projection)
                .expect_err("the bundle reader rejects separator lookalikes")
            else {
                panic!("the bundle reader returns a positioned report");
            };
            assert_eq!(report.files_checked(), Some(1));
            assert_eq!(
                report
                    .diagnostics()
                    .iter()
                    .filter(|diagnostic| diagnostic.code == code)
                    .count(),
                1
            );
            assert!(!report.diagnostics().iter().any(|diagnostic| {
                diagnostic
                    .message
                    .contains("named map identifiers differ only by")
            }));
            let diagnostic = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .expect("the namespace collision is reported");
            assert_eq!(diagnostic.path, second_path);
            assert!(diagnostic.message.contains(first_id));
            assert!(diagnostic.message.contains(second_id));
            let source = diagnostic.source.as_ref().expect("primary source");
            assert_eq!(
                (source.line, source.column),
                (Some(1), Some(key_column(second_id)))
            );
            assert_eq!(diagnostic.related.len(), 1);
            assert_eq!(diagnostic.related[0].path, first_path);
            assert_eq!(
                (diagnostic.related[0].line, diagnostic.related[0].column),
                (Some(1), Some(key_column(first_id)))
            );
        }

        let mut selectors = baseline();
        let selector = selectors.selector_profiles.0[0].1.clone();
        selectors
            .selector_profiles
            .insert("person_demographics-v1".to_owned(), selector);
        assert_collision(
            selectors,
            "evidence.bundle.selector-profile-id-collision",
            "person-demographics-v1",
            "person_demographics-v1",
            "/selectorProfiles/person-demographics-v1",
            "/selectorProfiles/person_demographics-v1",
        );

        let mut sources = baseline();
        let source = sources.sources.0[0].1.clone();
        sources.sources.insert("source_a".to_owned(), source);
        assert_collision(
            sources,
            "evidence.bundle.source-id-collision",
            "source-a",
            "source_a",
            "/sources/source-a",
            "/sources/source_a",
        );

        let connection: SourceConnectionPolicies = serde_json::from_value(serde_json::json!({
            "endpoints": [{
                "endpoint": "records",
                "baseUrl": "https://source.example",
                "authentication": {
                    "type": "oauth2-private-key-jwt",
                    "tokenEndpoint": "https://issuer.example/token",
                    "clientAssertionAudience": "https://issuer.example/client-auth",
                    "audience": "https://resource.example",
                    "resource": "https://resource.example/records"
                },
                "tlsTrustProfile": "private-ca",
                "clientIdentity": "required"
            }]
        }))
        .expect("the reviewed connection policy parses");
        let mut connections = baseline();
        connections
            .source_connections
            .insert("source-connection".to_owned(), connection.clone());
        connections
            .source_connections
            .insert("source_connection".to_owned(), connection);
        assert_collision(
            connections,
            "evidence.bundle.source-connection-id-collision",
            "source-connection",
            "source_connection",
            "/sourceConnections/source-connection",
            "/sourceConnections/source_connection",
        );

        let mut authorities = baseline();
        let authority = authorities.authority_profiles.0[0].1.clone();
        authorities
            .authority_profiles
            .insert("statutory_caseworker-v1".to_owned(), authority);
        assert_collision(
            authorities,
            "evidence.bundle.authority-profile-id-collision",
            "statutory-caseworker-v1",
            "statutory_caseworker-v1",
            "/authorityProfiles/statutory-caseworker-v1",
            "/authorityProfiles/statutory_caseworker-v1",
        );
    }

    #[test]
    fn bundle_reader_reports_collisions_beside_the_first_independent_rule_violation() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("acceptance configuration parses");
        let source = config.sources.0[0].1.clone();
        config.sources.insert("source_a".to_owned(), source);
        config.service.provider_id = "relative-provider".to_owned();
        let projection = serde_json::to_value(config).expect("configuration serializes");

        let ConfigError::Refused(report) = EvidenceConfig::parse_projection(&projection)
            .expect_err("the bundle reader reports both independent refusals")
        else {
            panic!("the bundle reader returns a positioned report");
        };
        assert_eq!(report.files_checked(), Some(1));
        assert_eq!(report.diagnostics().len(), 2);
        assert_eq!(
            report.diagnostics()[0].code,
            "evidence.bundle.invalid-service"
        );
        assert_eq!(report.diagnostics()[0].path, "/service/providerId");
        assert_eq!(
            report.diagnostics()[1].code,
            "evidence.bundle.source-id-collision"
        );
        assert_eq!(report.diagnostics()[1].path, "/sources/source_a");
        assert_eq!(report.diagnostics()[1].related.len(), 1);
        assert_eq!(report.diagnostics()[1].related[0].path, "/sources/source-a");
    }

    #[test]
    fn bundle_integrity_report_bounds_a_collision_flood_once() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("acceptance configuration parses");
        let selector = config.selector_profiles.0[0].1.clone();
        for index in 0..=registry_platform_yaml::MAXIMUM_DIAGNOSTICS_PER_FILE {
            config
                .selector_profiles
                .insert(format!("overflow-{index:03}-selector"), selector.clone());
            config
                .selector_profiles
                .insert(format!("overflow_{index:03}_selector"), selector.clone());
        }
        let projection = serde_json::to_value(config).expect("configuration serializes");
        let ConfigError::Refused(report) = EvidenceConfig::parse_projection(&projection)
            .expect_err("the bundle reader bounds integrity diagnostics")
        else {
            panic!("the bundle reader returns a positioned report");
        };
        assert_eq!(report.files_checked(), Some(1));
        assert_eq!(
            report.diagnostics().len(),
            registry_platform_yaml::MAXIMUM_DIAGNOSTICS_PER_FILE + 1
        );
        let overflow = report
            .diagnostics()
            .last()
            .expect("the report has its overflow marker");
        assert_eq!(overflow.code, "config.too-many-problems");
        assert_eq!(
            overflow.message,
            "2 more problems in this file are not shown"
        );
        assert_eq!(overflow.severity, Severity::Error);
        assert!(report.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "evidence.bundle.invalid-selector-profile"
                && diagnostic.path == "/selectorProfiles"
        }));
    }

    #[test]
    fn bundle_rule_refusal_counts_its_authored_file() {
        let document = String::from_utf8(
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            )
            .to_vec(),
        )
        .expect("acceptance configuration is UTF-8")
        .replace(
            "providerId: urn:example:fixture:provider:evidence",
            "providerId: relative-provider",
        );
        let ConfigError::Refused(report) = EvidenceConfig::parse_yaml(document.as_bytes())
            .expect_err("the bundle rule refuses a relative provider identifier")
        else {
            panic!("the bundle rule returns a positioned report");
        };
        assert_eq!(report.files_checked(), Some(1));
        assert_eq!(report.diagnostics().len(), 1);
        assert_eq!(
            report.diagnostics()[0].code,
            "evidence.bundle.invalid-service"
        );
        assert_eq!(report.diagnostics()[0].path, "/service/providerId");
    }

    #[test]
    fn named_source_connections_bind_sources_to_closed_reviewed_endpoint_policies() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("acceptance configuration parses");
        let source = &mut config.sources.0[0].1;
        source.connection = LocalId::new("shared").unwrap();
        let policy: SourceConnectionPolicies = serde_json::from_value(serde_json::json!({
            "endpoints": [{
                "endpoint": "records",
                "baseUrl": "https://source.example/api",
                "tlsTrustProfile": "private-ca",
                "clientIdentity": "required",
                "authentication": {
                    "type": "oauth2-private-key-jwt",
                    "tokenEndpoint": "https://issuer.example/token",
                    "clientAssertionAudience": "https://issuer.example/client-auth",
                    "resource": "https://resource.example/records"
                }
            }]
        }))
        .expect("the closed reviewed policy parses");
        config.source_connections = OrderedMap(vec![("shared".to_owned(), policy.clone())]);
        config.validate().expect("the named owner exists");

        assert!(
            serde_json::from_value::<SourceConnectionPolicies>(serde_json::json!({
                "endpoints": [{
                    "endpoint": "records",
                    "baseUrl": "https://other.example/api",
                    "clientIdentity": "required",
                    "authentication": {"type": "none"},
                    "secretRef": "secret:file/not-governed-here"
                }]
            }))
            .is_err(),
            "credential material is not part of governed connection authority"
        );

        config.source_connections.0.clear();
        assert!(
            config.validate().is_err(),
            "a named source cannot lose its owner"
        );
    }

    #[test]
    fn source_pack_digest_is_strict_sha256_and_part_of_the_binding() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .unwrap();
        let source = &mut config.sources.0[0].1;
        let digest = source.pack.digest.clone();
        assert!(digest.as_str().starts_with("sha256:"));
        source.pack.artifact_prefix = ArtifactPath::parse(&format!(
            "adapter-packs/{}/{}",
            source.pack.id,
            "0".repeat(64)
        ))
        .unwrap();
        assert_eq!(
            config.validate(),
            invalid("source pack artifact prefix must match its id and digest")
        );
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
        let baseline = acceptance_fixture();
        EvidenceConfig::parse_yaml(baseline.as_bytes()).expect("the baseline bundle is valid");
        assert!(validator.is_valid(&bundle_contract_instance(baseline.as_bytes())));
        for (from, to) in [
            (
                "  publicOrigin: https://evidence.invalid\n",
                "  publicOrigin: https://operator@evidence.invalid\n",
            ),
            (
                "  endpointUrl: https://evidence.example.invalid\n",
                "  endpointUrl: https://operator@evidence.example.invalid\n",
            ),
            (
                "        baseUrl: https://source.invalid\n",
                "        baseUrl: https://operator@source.invalid\n",
            ),
            (
                "        baseUrl: https://source.invalid\n",
                "        baseUrl: source.invalid\n",
            ),
        ] {
            let document = edited(acceptance_fixture(), from, to);
            assert_eq!(decode_cause(&document), "config.invalid-value", "{to}");
            assert!(
                !validator.is_valid(&bundle_contract_instance(document.as_bytes())),
                "the schema accepted {to}"
            );
        }
        for url in [
            r"https://source.invalid\other",
            r"https://source.invalid/a\b",
            r"https://source.invalid?x=\y",
            r"https://source.invalid#\fragment",
        ] {
            let replacement = format!("        baseUrl: '{url}'\n");
            let document = edited(
                baseline,
                "        baseUrl: https://source.invalid\n",
                &replacement,
            );
            assert_eq!(decode_cause(&document), "config.invalid-value", "{url}");
            assert!(
                !validator.is_valid(&bundle_contract_instance(document.as_bytes())),
                "the schema accepted a backslash: {url}"
            );
        }
        let encoded = edited(
            baseline,
            "      uri: https://identity.invalid/.well-known/jwks.json\n",
            "      uri: https://identity.invalid/a%5Cb\n",
        );
        EvidenceConfig::parse_yaml(encoded.as_bytes()).expect("an encoded path backslash is valid");
        assert!(validator.is_valid(&bundle_contract_instance(encoded.as_bytes())));
        // Both shared OIDC fields use the same checked URL type as their schema.
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
        config.authentication.oidc.provider.issuer =
            registry_platform_yaml::Url::new("http://127.0.0.1:8081").expect("valid URL");
        config.authentication.oidc.provider.jwks_source =
            registry_platform_config::JwksSource::Uri {
                uri: registry_platform_yaml::Url::new(
                    "http://127.0.0.1:8081/.well-known/jwks.json",
                )
                .expect("valid URL"),
            };
        config
            .validate()
            .expect("local profile accepts the supervised loopback identity");
        // The JWKS path is the configured issuer's to choose.
        config.authentication.oidc.provider.jwks_source =
            registry_platform_config::JwksSource::Uri {
                uri: registry_platform_yaml::Url::new("http://127.0.0.1:8081/oauth2/jwks")
                    .expect("valid URL"),
            };
        config
            .validate()
            .expect("local profile accepts any same-origin absolute JWKS path");

        EvidenceConfig::parse_projection(
            &serde_json::to_value(&config).expect("configuration serializes"),
        )
        .expect("the valid configuration round-trips before invalid values are substituted");
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
            let mut candidate = serde_json::to_value(&config).expect("configuration serializes");
            candidate["authentication"]["oidc"]["issuer"] = serde_json::json!(invalid);
            assert!(
                EvidenceConfig::parse_projection(&candidate).is_err(),
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
            let mut candidate = serde_json::to_value(&config).expect("configuration serializes");
            candidate["authentication"]["oidc"]["jwksSource"]["uri"] = serde_json::json!(invalid);
            assert!(
                EvidenceConfig::parse_projection(&candidate).is_err(),
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

    fn plain_http_issuer_candidate(profile: &str, opt_in: bool) -> serde_json::Value {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        let mut candidate = serde_json::to_value(config).expect("configuration serializes");
        candidate["assuranceProfile"] = serde_json::json!(profile);
        candidate["authentication"]["oidc"]["issuer"] =
            serde_json::json!("http://identity.internal:8080");
        candidate["authentication"]["oidc"]["jwksSource"] = serde_json::json!({
            "type": "uri",
            "uri": "http://identity.internal:8080/oauth2/jwks"
        });
        if opt_in {
            candidate["authentication"]["oidc"]["allowInsecureHttp"] = serde_json::json!(true);
        }
        candidate
    }

    #[test]
    fn local_runtime_reads_the_explicit_http_issuer_opt_in() {
        let mut candidate = plain_http_issuer_candidate("local", true);
        let parsed = EvidenceConfig::parse_projection(&candidate)
            .expect("explicit HTTP issuer opt-in parses and validates under local");
        assert!(parsed.authentication.oidc.provider.allow_insecure_http);
        assert_eq!(
            parsed
                .authentication
                .oidc
                .insecure_http_startup_diagnostic(),
            Some(
                "authentication.oidc.allowInsecureHttp permits plain HTTP to the configured issuer and to a JWKS URI declared in configuration"
            )
        );

        candidate["authentication"]["oidc"]["tlsTrustProfile"] = serde_json::json!("private-ca");
        let error = EvidenceConfig::parse_projection(&candidate)
            .expect_err("plain HTTP has no TLS trust profile")
            .to_string();
        assert!(
            error.contains("plain HTTP authentication JWKS URI cannot use a TLS trust profile"),
            "{error}"
        );
    }

    #[test]
    fn local_http_issuer_refusal_names_the_explicit_opt_in() {
        let error = EvidenceConfig::parse_projection(&plain_http_issuer_candidate("local", false))
            .expect_err("a non-loopback HTTP issuer needs the opt-in")
            .to_string();
        assert!(
            error.contains("authentication.oidc.allowInsecureHttp: true"),
            "{error}"
        );
        assert!(!error.contains("identity.internal"), "{error}");
    }

    /// The frozen contract promises HTTPS for deployable bundles, so the
    /// plain HTTP opt-in is refused there rather than honored.
    #[test]
    fn deployable_profiles_refuse_plain_http_and_the_insecure_http_opt_in() {
        for profile in ["production", "evidence-grade"] {
            for opt_in in [false, true] {
                let error =
                    EvidenceConfig::parse_projection(&plain_http_issuer_candidate(profile, opt_in))
                        .expect_err("deployable bundles require HTTPS")
                        .to_string();
                assert!(
                    error.contains("production and evidence-grade authentication requires HTTPS"),
                    "{profile}: {error}"
                );
                assert!(
                    error.contains("local assurance profile"),
                    "{profile}: {error}"
                );
                assert!(!error.contains("identity.internal"), "{profile}: {error}");
            }

            // The opt-in is refused on its own, even when every URL is https.
            let config = EvidenceConfig::parse_yaml(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ))
            .expect("strict fixture validates");
            let mut https = serde_json::to_value(config).expect("configuration serializes");
            https["assuranceProfile"] = serde_json::json!(profile);
            https["authentication"]["oidc"]["allowInsecureHttp"] = serde_json::json!(true);
            let error = EvidenceConfig::parse_projection(&https)
                .expect_err("deployable bundles refuse the opt-in")
                .to_string();
            assert!(
                error.contains("remove allowInsecureHttp"),
                "{profile}: {error}"
            );
            assert!(
                error.contains("authentication.oidc.allowInsecureHttp"),
                "{profile}: {error}"
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
        local.authentication.oidc.provider.issuer =
            registry_platform_yaml::Url::new("http://127.0.0.1:8081").expect("valid URL");
        local.authentication.oidc.provider.jwks_source =
            registry_platform_config::JwksSource::Uri {
                uri: registry_platform_yaml::Url::new(
                    "http://127.0.0.1:8081/.well-known/jwks.json",
                )
                .expect("valid URL"),
            };
        assert!(matches!(
            local.validate(),
            Err(ConfigError::Invalid(
                "a local HTTP authentication JWKS URI cannot use a TLS trust profile"
            ))
        ));
    }

    /// The admission gates are stated, and a listed gate must be a nonempty,
    /// bounded, unique list; required scopes must also be scope tokens,
    /// because they are compared against verified token scopes.
    #[test]
    fn admission_gates_are_stated_and_a_list_is_nonempty_and_bounded() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config
            .validate()
            .expect("unrestricted admission gates validate");

        config.authentication.oidc.allowed_clients =
            AdmissionGate::listed(set(["records-reader".to_owned()]));
        config.authentication.oidc.required_scopes =
            AdmissionGate::listed(set(["evidence:invoke".to_owned()]));
        config.validate().expect("listed admission validates");

        for clients in [
            Vec::new(),
            vec!["".to_owned()],
            vec!["a".repeat(129)],
            (0..33).map(|index| format!("reader-{index}")).collect(),
        ] {
            let mut candidate = config.clone();
            candidate.authentication.oidc.allowed_clients =
                AdmissionGate::listed(set(clients.clone()));
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
            candidate.authentication.oidc.required_scopes =
                AdmissionGate::listed(set(scopes.clone()));
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
    fn an_assertion_issuers_client_identifier_carries_no_control_character() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        let issuers = || set(vec!["https://issuer.invalid".to_owned()]);
        // An external identifier is not reshaped: a case, a dot, and a colon
        // are its issuer's to choose.
        config.authentication.oidc.assertion_issuers = Some(BTreeMap::from([(
            "urn:Example.Client:1".to_owned(),
            issuers(),
        )]));
        config
            .validate()
            .expect("an external identifier is kept as written");
        config.authentication.oidc.assertion_issuers =
            Some(BTreeMap::from([("client\u{7}one".to_owned(), issuers())]));
        assert!(config.validate().is_err());
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
                ("review\u{202e}txt".to_owned(), false),
                ("review\u{2028}next".to_owned(), false),
                ("review\u{fdd0}text".to_owned(), false),
                ("review\u{10ffff}text".to_owned(), false),
                ("نام\u{200c}خانوادگی".to_owned(), true),
                ("العربية\u{200f} English".to_owned(), true),
                ("soft\u{00ad}hyphen".to_owned(), true),
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
    fn requirement_question_matches_display_text_runtime_and_schema_constraints() {
        let validator = bundle_contract_validator();
        let fixture = include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );
        let mut omitted = bundle_contract_instance(fixture);
        omitted["requirements"][0]
            .as_object_mut()
            .expect("requirement is an object")
            .remove("question");
        let omitted_yaml = serde_norway::to_string(&omitted).expect("bundle encodes as YAML");
        EvidenceConfig::parse_yaml(omitted_yaml.as_bytes())
            .expect("the optional question remains optional");
        assert!(validator.is_valid(&omitted));

        for (value, accepted) in [
            ("?".to_owned(), true),
            ("x".repeat(2048), true),
            (String::new(), false),
            ("x".repeat(2049), false),
            ("review\u{202e}txt?".to_owned(), false),
            ("review\u{2028}next?".to_owned(), false),
            ("review\u{fdd0}text?".to_owned(), false),
            ("review\u{10ffff}text?".to_owned(), false),
            ("نام\u{200c}خانوادگی؟".to_owned(), true),
            ("العربية\u{200f} English?".to_owned(), true),
            ("soft\u{00ad}hyphen?".to_owned(), true),
        ] {
            let mut config = EvidenceConfig::parse_yaml(fixture)
                .expect("strict fixture validates before the mutation");
            config.requirements[0].question = Some(value.clone());
            assert_eq!(
                config.validate().is_ok(),
                accepted,
                "programmatic runtime validation for {value:?}"
            );

            let mut instance = bundle_contract_instance(fixture);
            instance["requirements"][0]["question"] = serde_json::json!(value);
            let encoded = serde_norway::to_string(&instance).expect("bundle encodes as YAML");
            assert_eq!(
                EvidenceConfig::parse_yaml(encoded.as_bytes()).is_ok(),
                accepted,
                "runtime reader parity for the requirement question"
            );
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "published schema parity for the requirement question"
            );
        }

        let mut config = EvidenceConfig::parse_yaml(fixture).expect("strict fixture validates");
        config.requirements[0].question = Some("SECRET-question\u{202e}concealed".to_owned());
        let error = config
            .validate()
            .expect_err("the forbidden question character is refused");
        assert_eq!(
            error,
            ConfigError::InvalidField(
                "display text contains a prohibited character",
                "definition question"
            )
        );
        assert!(!error.to_string().contains("SECRET-question"));
        assert!(!error.fault().to_string().contains("SECRET-question"));

        let mut instance = bundle_contract_instance(fixture);
        instance["requirements"][0]["question"] =
            serde_json::json!("SECRET-question\u{202e}concealed");
        let encoded = serde_norway::to_string(&instance).expect("bundle encodes as YAML");
        let error = EvidenceConfig::parse_yaml(encoded.as_bytes())
            .expect_err("the reader refuses the forbidden question character");
        let report = error.report().expect("the reader returns a safe report");
        assert_eq!(report.error_count(), 1);
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.invalid-value");
        assert_eq!(diagnostic.path, "/requirements/0/question");
        let source = diagnostic.source.as_ref().expect("placed reader refusal");
        assert!(source.line.is_some());
        assert!(source.column.is_some());
        assert!(!report.render_human().contains("SECRET-question"));
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
        no_global_admission.authentication.oidc.allowed_clients = AdmissionGate::unrestricted();
        assert_eq!(
            no_global_admission.validate(),
            invalid(
                "task-grant authority profiles require a list of authentication allowedClients"
            )
        );

        let mut client_not_admitted = config;
        client_not_admitted.authentication.oidc.allowed_clients =
            AdmissionGate::listed(set(["other-client".to_owned()]));
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
            AdmissionGate::listed(set(["evidence-cli".to_owned()]));
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
    fn governed_connection_policies_are_closed_and_carry_no_runtime_secret_material() {
        let policy: SourceConnectionPolicies = serde_json::from_value(serde_json::json!({
            "endpoints": [{
                "endpoint": "records",
                "baseUrl": "https://source.invalid/api",
                "tlsTrustProfile": "private-ca",
                "clientIdentity": "required",
                "authentication": {
                    "type": "oauth2-client-credentials",
                    "tokenEndpoint": "https://issuer.invalid/token",
                    "scope": "evidence.read",
                    "credentialPlacement": "form-body"
                }
            }]
        }))
        .expect("the reviewed non-secret connection authority parses");
        assert_eq!(policy.endpoints.len(), 1);

        for extra in [
            (
                "clientSecretRef",
                serde_json::json!("secret:file/client-secret"),
            ),
            ("clientIdRef", serde_json::json!("secret:file/client-id")),
            ("maximumCacheSeconds", serde_json::json!(60)),
        ] {
            let mut candidate = serde_json::to_value(&policy).unwrap();
            candidate["endpoints"][0][extra.0] = extra.1;
            assert!(
                serde_json::from_value::<SourceConnectionPolicies>(candidate).is_err(),
                "runtime credential material {} entered governed policy",
                extra.0
            );
        }

        for base_url in [
            "https://user@source.invalid/api",
            "https://source.invalid/api with space",
            "source.invalid/api",
        ] {
            let candidate = serde_json::json!({
                "endpoints": [{
                    "endpoint": "records",
                    "baseUrl": base_url,
                    "clientIdentity": "forbidden",
                    "authentication": {"type": "none"}
                }]
            });
            assert!(
                serde_json::from_value::<SourceConnectionPolicies>(candidate).is_err(),
                "invalid reviewed base URL {base_url} parsed"
            );
        }
    }

    #[test]
    fn retired_transport_source_members_are_refused_by_the_pack_binding_grammar() {
        for retired in [
            serde_json::json!({
                "type": "http-json",
                "baseUrl": "https://source.invalid",
                "authentication": {"type": "none"}
            }),
            serde_json::json!({
                "type": "sqlite-extract",
                "extractProfile": "records",
                "request": {"statement": "queries/records.sql"}
            }),
        ] {
            assert!(serde_json::from_value::<SourceConfig>(retired).is_err());
        }
    }

    fn acceptance_fixture() -> &'static str {
        include_str!("../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml")
    }

    /// The current pack source with the retired statement surface written
    /// beside it, so required current members cannot mask the unknown keys.
    fn sqlite_source_document() -> String {
        edited(
            acceptance_fixture(),
            "  source-a:\n",
            concat!(
                "  source-a:\n",
                "    type: sqlite-extract\n",
                "    request:\n",
                "      statement: queries/residence-region.sql\n",
            ),
        )
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
    fn pack_source_exposes_only_its_reviewed_selector_bindings_and_fact_schema() {
        let config = EvidenceConfig::parse_yaml(acceptance_fixture().as_bytes())
            .expect("the maintained pack-source fixture validates");
        assert!(
            bundle_contract_validator()
                .is_valid(&bundle_contract_instance(acceptance_fixture().as_bytes())),
            "the normative bundle contract must accept the maintained pack-source fixture"
        );
        let source = &config.sources.0[0].1;
        assert_eq!(source.fact_schema().as_str(), "schemas/facts.schema.yaml");
        assert_eq!(
            source
                .selector_bindings()
                .into_iter()
                .map(|binding| (binding.role, binding.profile, binding.field))
                .collect::<Vec<_>>(),
            [
                ("subject", "person-demographics-v1", "birth_date"),
                ("subject", "person-demographics-v1", "family_name"),
                ("subject", "person-demographics-v1", "given_name"),
            ]
        );
        assert_eq!(source.connection(), "provider");
        assert_eq!(source.posture(), AcquisitionPosture::FieldProjected);
    }

    #[test]
    fn retired_sqlite_source_request_surface_is_refused_in_a_complete_bundle() {
        let document = sqlite_source_document();
        assert_eq!(decode_cause(&document), "config.removed-key");
        assert!(
            !bundle_contract_validator().is_valid(&bundle_contract_instance(document.as_bytes())),
            "the published bundle schema must refuse the retired transport surface"
        );
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

    #[test]
    fn runtime_contract_accepts_current_source_bindings_and_refuses_invalid_bounds() {
        let base = include_str!(
            "../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/runtime.yaml"
        );
        let current = format!(
            "{base}    allowedPrivateCidrs: []\nsourceAcquisition:\n  maximumDataOperations: 5\n  acquisitionDeadlineMilliseconds: 45000\n  maximumResponseBytes: 1048576\n"
        );
        RuntimeConfig::parse_yaml(current.as_bytes())
            .expect("current source runtime bindings parse");
        let validator = runtime_contract_validator();
        assert!(
            validator.is_valid(&bundle_contract_instance(current.as_bytes())),
            "the normative runtime contract must accept current source bindings"
        );

        for (field, valid) in [
            ("maximumDataOperations: 5", "maximumDataOperations: 0"),
            (
                "acquisitionDeadlineMilliseconds: 45000",
                "acquisitionDeadlineMilliseconds: 0",
            ),
            ("maximumResponseBytes: 1048576", "maximumResponseBytes: 0"),
        ] {
            let invalid = edited(&current, field, valid);
            assert!(RuntimeConfig::parse_yaml(invalid.as_bytes()).is_err());
            assert!(!validator.is_valid(&bundle_contract_instance(invalid.as_bytes())));
        }

        let at_concurrency_limit = edited(
            &current,
            "        maximumResponseBytes: 262144\n",
            "        maximumResponseBytes: 262144\n        maximumConcurrency: 256\n",
        );
        RuntimeConfig::parse_yaml(at_concurrency_limit.as_bytes())
            .expect("the maintained endpoint concurrency ceiling parses");
        assert!(validator.is_valid(&bundle_contract_instance(at_concurrency_limit.as_bytes())));
        let over_concurrency_limit = edited(
            &at_concurrency_limit,
            "        maximumConcurrency: 256\n",
            "        maximumConcurrency: 257\n",
        );
        assert!(RuntimeConfig::parse_yaml(over_concurrency_limit.as_bytes()).is_err());
        assert!(!validator.is_valid(&bundle_contract_instance(over_concurrency_limit.as_bytes())));
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
        let reference = include_str!(
            "../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle/evidence.yaml"
        );
        let unknown_nested = reference.replacen(
            "    factSchema: schemas/birth-adult-facts.schema.yaml",
            "    factSchema: schemas/birth-adult-facts.schema.yaml\n    surprise: s3cr3t-selector-value",
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
            "    maximumTokenLifetimeSeconds: 300",
            "    maximumTokenLifetimeSeconds: 987654321",
            1,
        );
        assert_ne!(out_of_range, reference, "range mutation applies");
        let out_of_range_line = line_of(&out_of_range, "maximumTokenLifetimeSeconds: 987654321");
        let cases: [Case; 7] = [
            (
                "malformed YAML",
                format!("{BUNDLE_ENVELOPE}broken: [{}\n", CANARY_VALUES[0]),
                "yaml.unexpected-end",
                None,
                None,
            ),
            (
                "unknown top-level field",
                format!("{BUNDLE_ENVELOPE}bogusField: {}\n", CANARY_VALUES[1]),
                "config.unknown-key",
                Some("/bogusField"),
                Some(3),
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
                format!(
                    "{BUNDLE_ENVELOPE}maximumHolderBoundBatchSize: {}\n",
                    CANARY_VALUES[2]
                ),
                "config.expected-integer",
                Some("/maximumHolderBoundBatchSize"),
                Some(3),
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
                BUNDLE_ENVELOPE.to_owned(),
                "config.missing-key",
                Some(""),
                Some(1),
            ),
            (
                "more than one document",
                format!("{BUNDLE_ENVELOPE}---\nkind: {}\n", CANARY_VALUES[3]),
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
                "\nresponseFormats:\n  - signed-jws\n  - unsigned-json",
                "\nresponseFormats:\n  - unsigned-json",
            ),
            // Formats must be unique.
            (
                "\nresponseFormats:\n  - signed-jws\n  - unsigned-json",
                "\nresponseFormats:\n  - signed-jws\n  - signed-jws",
            ),
            // A complete grant may narrow the enabled formats, but cannot duplicate one.
            (
                "        responseFormats:\n          - signed-jws\n          - unsigned-json\n        subjects:\n          - role: subject\n            selectorProfile: person-demographics-v1\n            valueOrigin: request",
                "        responseFormats:\n          - unsigned-json\n          - unsigned-json\n        subjects:\n          - role: subject\n            selectorProfile: person-demographics-v1\n            valueOrigin: request",
            ),
            // The vocabulary is closed.
            (
                "\nresponseFormats:\n  - signed-jws\n  - unsigned-json",
                "\nresponseFormats:\n  - signed-jws\n  - jws-detached",
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
        for (form, sound, incoherent, out_of_bounds) in [
            (
                ConceptForm::ControlledCodeList,
                "          minimumItems: 1\n          maximumItems: 3\n          unique: true",
                [
                    "          minimumItems: 3\n          maximumItems: 1\n          unique: true",
                    "          minimumItems: 1\n          maximumItems: 3\n          unique: false",
                ],
                [
                    "          minimumItems: 1\n          maximumItems: 65\n          unique: true",
                    "          minimumItems: 0\n          maximumItems: 3\n          unique: true",
                ],
            ),
            (
                ConceptForm::EntityReferenceList,
                "          minimumItems: 1\n          maximumItems: 2\n          unique: true",
                [
                    "          minimumItems: 2\n          maximumItems: 1\n          unique: true",
                    "          minimumItems: 1\n          maximumItems: 2\n          unique: false",
                ],
                [
                    "          minimumItems: 1\n          maximumItems: 65\n          unique: true",
                    "          minimumItems: 0\n          maximumItems: 2\n          unique: true",
                ],
            ),
        ] {
            for replacement in incoherent {
                let document = edited(SUPPORTED_VALUES, sound, replacement);
                assert_eq!(
                    invalid_reason(&document),
                    INCOHERENT,
                    "{form:?} accepted {replacement}"
                );
            }
            // A count outside the item bounds is refused by the reader at the
            // value, as every bounded integer is (CFG-QTY-4).
            for replacement in out_of_bounds {
                let document = edited(SUPPORTED_VALUES, sound, replacement);
                assert_eq!(
                    decode_cause(&document),
                    "config.out-of-range",
                    "{form:?} accepted {replacement}"
                );
            }
        }

        // The concept the fixture cases never disclose is refused just the
        // same, so the refusal cannot depend on a question reaching it.
        let unreached = edited(
            SUPPORTED_VALUES,
            "          minimumItems: 1\n          maximumItems: 2\n          unique: true",
            "          minimumItems: 2\n          maximumItems: 1\n          unique: true",
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
        let source = serde_json::json!({
            "pack": {
                "id": "synthetic-register",
                "version": "1",
                "digest": format!("sha256:{}", "1".repeat(64)),
                "artifactPrefix": format!("adapter-packs/synthetic-register/{}", "1".repeat(64))
            },
            "route": "evidence-person",
            "connection": "register",
            "inputs": {},
            "posture": "record-transformed",
            "factSchema": "schemas/source-facts/person.schema.json"
        });
        let parsed: SourceConfig =
            serde_json::from_value(source.clone()).expect("the current Source shape parses");
        parsed
            .validate(AssuranceProfile::Production)
            .expect("the Source fact schema is directory-scoped");

        let mut missing = source.clone();
        missing.as_object_mut().unwrap().remove("factSchema");
        assert!(serde_json::from_value::<SourceConfig>(missing).is_err());

        let mut outside = source.clone();
        outside["factSchema"] = "adapter-packs/synthetic-register/facts.json".into();
        let outside: SourceConfig = serde_json::from_value(outside).unwrap();
        assert!(outside.validate(AssuranceProfile::Production).is_err());

        for retired in ["responseSchema", "adapterParametersSchema"] {
            let mut legacy = source.clone();
            legacy[retired] = "schemas/retired.json".into();
            assert!(
                serde_json::from_value::<SourceConfig>(legacy).is_err(),
                "the current Source contract accepted retired {retired}"
            );
        }
    }

    #[test]
    fn schema_roles_do_not_overlap_across_sources() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        EvidenceConfig::parse_yaml(valid.as_bytes()).expect("the fixture loads");

        // Source no longer owns response or parameter schema roles. Those
        // contracts live inside the digest-pinned pack, so a bundle cannot
        // cross one source's fact schema into another Source-owned role.
        let crossed = valid.replacen(
            "    factSchema: schemas/adult-status-facts.schema.yaml",
            concat!(
                "    factSchema: schemas/adult-status-facts.schema.yaml\n",
                "    responseSchema: schemas/residence-region-facts.schema.yaml"
            ),
            1,
        );
        assert_ne!(crossed, valid, "fixture mutation must remain effective");
        let diagnostics = bundle_refusal(&crossed);
        let refused = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/sources/source-a/responseSchema")
            .unwrap_or_else(|| panic!("the retired schema role was not refused: {diagnostics:?}"));
        assert_eq!(refused.code, "config.removed-key");
        assert_eq!(
            refused.suggested_action, RETIRED_SOURCE_MEMBER,
            "the migration is named: {refused:?}"
        );
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
            "  trustDomain: urn:example:fixture:trust-domain:acceptance\n",
            "  trustDomain: urn:example:fixture:trust-domain:acceptance\n  unexpected: true\n",
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
        config.sources.0[0].1.inputs.insert(
            "unreachablePerson".to_owned(),
            SourceInputConfig {
                selector: SourceInputSelector {
                    role: LocalId::new("child").unwrap(),
                    profile: LocalId::new("person-reference-v1").unwrap(),
                    field: LocalId::new("person_reference").unwrap(),
                },
            },
        );
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

        let alternative_inputs = config.sources.0[0]
            .1
            .inputs
            .clone()
            .into_iter()
            .map(|(name, mut input)| {
                input.selector.role = LocalId::new("alternate-subject").unwrap();
                (format!("alternate_{name}"), input)
            })
            .collect::<Vec<_>>();
        config.sources.0[0].1.inputs.extend(alternative_inputs);
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
            "  trustDomain: urn:example:fixture:trust-domain:acceptance\n",
            "  trustDomains: [urn:example:fixture:trust-domain:a, urn:example:fixture:trust-domain:b]\n",
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
            assert!(
                current_adapter_contract_accepts(
                    valid,
                    serde_json::json!({"type":"none"}),
                    serde_json::json!({"type":"none"}),
                    serde_json::json!({"type":"none"}),
                ),
                "{valid}"
            );
        }
        for invalid in [
            "http://localhost:18081",
            "http://127.1:18081",
            "http://127.00.0.1:18081",
            "http://192.168.1.2",
            "https://user@source.invalid",
            "https://source.invalid#fragment",
        ] {
            assert!(
                !current_adapter_contract_accepts(
                    invalid,
                    serde_json::json!({"type":"none"}),
                    serde_json::json!({"type":"none"}),
                    serde_json::json!({"type":"none"}),
                ),
                "{invalid}"
            );
        }
        assert!(
            current_adapter_contract_accepts(
                "https://source.invalid/base/path",
                serde_json::json!({"type":"none"}),
                serde_json::json!({"type":"none"}),
                serde_json::json!({"type":"none"}),
            ),
            "a governed Adapter connection may select a reviewed base path"
        );
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
            .filter(|value| {
                current_adapter_contract_accepts(
                    value,
                    serde_json::json!({"type":"static-authorization"}),
                    serde_json::json!({
                        "type":"static-authorization",
                        "tokenRef":"secret:env/TOKEN"
                    }),
                    serde_json::json!({"type":"static-authorization"}),
                )
            })
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
            .filter(|value| {
                let mut credential = current_private_key_credential();
                credential["tokenEndpoint"] = serde_json::json!(value);
                let mut policy = serde_json::json!({
                    "type":"oauth2-private-key-jwt",
                    "tokenEndpoint":"https://issuer.invalid/token"
                });
                policy["tokenEndpoint"] = serde_json::json!(value);
                current_adapter_contract_accepts(
                    "https://source.invalid",
                    serde_json::json!({"type":"oauth2-private-key-jwt"}),
                    credential,
                    policy,
                )
            })
            .collect::<Vec<_>>();
        assert!(
            accepted.is_empty(),
            "tokenEndpoint accepted characters a URI cannot carry: {accepted:?}"
        );
    }

    #[test]
    fn oauth_endpoint_has_no_query() {
        for query in [
            "?client_secret=plaintext",
            "?client_id=duplicate",
            "?fixed=true",
        ] {
            let endpoint = format!("https://source.invalid/token{query}");
            let mut credential = current_client_credential();
            credential["tokenEndpoint"] = endpoint.clone().into();
            let mut policy = current_client_policy();
            policy["tokenEndpoint"] = endpoint.into();
            assert!(
                !current_adapter_contract_accepts(
                    "https://source.invalid",
                    serde_json::json!({"type":"oauth2-client-credentials"}),
                    credential,
                    policy,
                ),
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
        for (assumed_lifetime_seconds, accepted) in [
            (Some(0), false),
            (Some(1), true),
            (Some(86_400), true),
            (Some(86_401), false),
            (None, true),
        ] {
            let mut credential = current_client_credential();
            if let Some(value) = assumed_lifetime_seconds {
                credential["assumedLifetimeSeconds"] = value.into();
            }
            assert_eq!(
                serde_json::from_value::<registry_adapter_core::RuntimeCredential>(credential)
                    .is_ok(),
                accepted,
                "{assumed_lifetime_seconds:?}"
            );
        }
    }

    /// Query-string placement puts the client id and secret in a URL that
    /// authorization-server, proxy, and ingress logs capture, and RFC 6749
    /// section 2.3.1 requires those parameters to travel in the request body.
    /// Version 1 accepts only the two placements the specification defines,
    /// and the runtime and the published contract must agree on that.
    #[test]
    fn oauth_credential_placement_rejects_the_query_string_placement() {
        for (placement, accepted) in [
            ("basic-header", true),
            ("form-body", true),
            ("query-string", false),
        ] {
            let mut authentication = current_client_credential();
            authentication["credentialPlacement"] = placement.into();
            assert_eq!(
                serde_json::from_value::<registry_adapter_core::RuntimeCredential>(
                    authentication.clone()
                )
                .is_ok(),
                accepted,
                "{placement} runtime deserialization"
            );
        }
    }

    /// The resource indicator is an exact governed URI, not an outbound URL
    /// or the client assertion audience. Invalid values fail at configuration
    /// validation before a credential or token request can be made.
    #[test]
    fn oauth_resource_indicator_is_optional_and_rejects_relative_or_ambiguous_values() {
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
            let mut authentication = current_client_credential();
            let mut policy = current_client_policy();
            if let Some(resource) = resource {
                authentication["resource"] = serde_json::json!(resource);
                policy["resource"] = serde_json::json!(resource);
            }
            assert_eq!(
                current_adapter_contract_accepts(
                    "https://source.invalid",
                    serde_json::json!({"type":"oauth2-client-credentials"}),
                    authentication,
                    policy,
                ),
                accepted,
                "{resource:?}"
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
            let mut authentication = serde_json::json!({"type": "static-authorization"});
            if let Some(scheme) = scheme {
                authentication["scheme"] = serde_json::json!(scheme);
            }
            assert_eq!(
                current_adapter_contract_accepts(
                    "https://source.invalid",
                    authentication,
                    serde_json::json!({
                        "type":"static-authorization",
                        "tokenRef":"secret:env/TOKEN"
                    }),
                    serde_json::json!({"type":"static-authorization"}),
                ),
                accepted,
                "{scheme:?}"
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
        const SECRET: Option<&str> = Some("oauth2-client-credentials");
        const ASSERTION: Option<&str> = Some("oauth2-private-key-jwt");
        // Each member set is tried under both types; `accepting` names the
        // one type that takes it, if any.
        for (secret_ref, placement, key_ref, accepting) in [
            (
                Some("secret:file/oauth-client-secret"),
                Some("basic-header"),
                None,
                SECRET,
            ),
            (
                Some("secret:file/oauth-client-secret"),
                Some("form-body"),
                None,
                SECRET,
            ),
            (None, None, Some("secret:file/oauth-client-key"), ASSERTION),
            // A secret with no placement leaves the runtime to pick where the
            // credential travels, which RFC 6749 section 2.3.1 makes the
            // operator's decision.
            (Some("secret:file/oauth-client-secret"), None, None, None),
            // A placement with no secret names a channel for a credential that
            // does not exist.
            (
                None,
                Some("basic-header"),
                Some("secret:file/oauth-client-key"),
                None,
            ),
            (None, Some("basic-header"), None, None),
            // Both forms at once, with and without a placement for the secret.
            // The placement is what makes these two distinct presence shapes
            // rather than one: dropping it must not turn a two-credential
            // bundle into an accepted assertion-only one.
            (
                Some("secret:file/oauth-client-secret"),
                Some("basic-header"),
                Some("secret:file/oauth-client-key"),
                None,
            ),
            (
                Some("secret:file/oauth-client-secret"),
                None,
                Some("secret:file/oauth-client-key"),
                None,
            ),
            // Neither form.
            (None, None, None, None),
        ] {
            for written in [SECRET, ASSERTION] {
                let mut authentication = serde_json::json!({
                    "type": written,
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
                let accepted = written == accepting;
                let label = format!("{written:?}/{secret_ref:?}/{placement:?}/{key_ref:?}");

                let parsed = serde_json::from_value::<registry_adapter_core::RuntimeCredential>(
                    authentication,
                );
                assert_eq!(parsed.is_ok(), accepted, "{label} validation");
            }
        }
    }

    /// The assertion key is a credential like any other, so bundle validation
    /// has to see it. `secret_refs` is what reports the set a bundle depends
    /// on, and a form whose only credential is invisible there would look
    /// credential-free.
    #[test]
    fn the_client_assertion_key_is_reported_as_a_bundle_secret() {
        let key_form = serde_json::from_value::<registry_adapter_core::RuntimeCredential>(
            current_private_key_credential(),
        )
        .expect("the runtime key form parses");
        let projected = serde_json::to_value(key_form).expect("the credential projects");
        assert_eq!(
            projected["clientAssertionKeyRef"],
            "secret:env/CLIENT_ASSERTION_KEY"
        );
        assert!(
            serde_json::from_value::<registry_adapter_core::EvidenceAuthenticationPolicy>(
                projected
            )
            .is_err(),
            "credential material cannot move into the governed connection policy"
        );
    }

    /// Some authorization servers key the issued token to an audience the
    /// scope cannot express, and return a token usable against nothing when it
    /// is absent. The value is a fixed bundle string, never derived per
    /// request.
    #[test]
    fn oauth_audience_is_a_bounded_optional_string() {
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
            let mut authentication = current_client_credential();
            if let Some(audience) = audience {
                authentication["audience"] = serde_json::json!(audience);
            }
            let label = audience.map(str::len);
            let mut policy = current_client_policy();
            if let Some(audience) = audience {
                policy["audience"] = serde_json::json!(audience);
            }
            assert_eq!(
                current_adapter_contract_accepts(
                    "https://source.invalid",
                    serde_json::json!({"type":"oauth2-client-credentials"}),
                    authentication,
                    policy,
                ),
                accepted,
                "{label:?}"
            );
        }
    }

    /// RFC 7523 section 3 asks only that the audience identify the
    /// authorization server and leaves the exact string to out-of-band
    /// agreement, so this is an opaque identifier rather than a URL. It is
    /// bounded like the sibling `audience` and validated by the same rule.
    #[test]
    fn the_client_assertion_audience_is_a_bounded_optional_string() {
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
            let mut authentication = current_private_key_credential();
            if let Some(audience) = audience {
                authentication["clientAssertionAudience"] = serde_json::json!(audience);
            }
            let label = audience.map(str::len);
            let mut policy = serde_json::json!({
                "type":"oauth2-private-key-jwt",
                "tokenEndpoint":"https://issuer.invalid/token"
            });
            if let Some(audience) = audience {
                policy["clientAssertionAudience"] = serde_json::json!(audience);
            }
            assert_eq!(
                current_adapter_contract_accepts(
                    "https://source.invalid",
                    serde_json::json!({"type":"oauth2-private-key-jwt"}),
                    authentication,
                    policy,
                ),
                accepted,
                "{label:?}"
            );
        }
    }

    /// Only a signed assertion carries an `aud` claim. Beside a shared secret
    /// the key names an audience nothing will ever send, so accepting it would
    /// leave an operator believing an authorization server was addressed that
    /// never was.
    #[test]
    fn a_client_assertion_audience_without_an_assertion_key_is_refused() {
        let mut authentication = current_client_credential();
        authentication["clientAssertionAudience"] = "https://issuer.invalid/".into();

        assert!(
            serde_json::from_value::<registry_adapter_core::RuntimeCredential>(authentication)
                .is_err(),
            "an assertion audience was accepted beside a client secret"
        );
    }

    #[test]
    fn pack_sources_cannot_reintroduce_an_authored_http_request_channel() {
        let mut instance = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ));
        instance["sources"]["source-a"]["request"] = serde_json::json!({
            "method": "GET",
            "path": "/records"
        });
        assert!(serde_json::from_value::<EvidenceConfig>(instance.clone()).is_err());
        assert!(!bundle_contract_validator().is_valid(&instance));
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
apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
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
  type: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  attemptTimeoutMilliseconds: 2000
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

        let file = with_audit(
            "audit:\n  destination: file\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 1048576\n  retentionDays: 30\n",
        );
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
                "audit:\n  destination: stdout\n  retentionDays: 30\n",
            ),
            (
                "rotation-below-minimum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 1024\n",
            ),
            (
                "retention-zero",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  retentionDays: 0\n",
            ),
            (
                "rotation-above-maximum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 4294967296\n",
            ),
            (
                "retention-above-maximum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  retentionDays: 36501\n",
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
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  retentionDays: 0\n",
            ),
            (
                "rotation-above-maximum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  rotateBytes: 4294967296\n",
            ),
            (
                "retention-above-maximum",
                "audit:\n  path: /var/lib/evidence/audit.jsonl\n  retentionDays: 36501\n",
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
        let legacy = with_audit(
            "auditStorage:\n  path: /var/lib/evidence/audit.jsonl\n  maximumFileBytes: 1073741824\n",
        );
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
apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
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
  type: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  attemptTimeoutMilliseconds: 2000
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

    /// For one release the contract and reader both tolerate an empty retired
    /// capability list; any capability stays refused by both.
    #[test]
    fn published_runtime_contract_refuses_retired_acquisition_capabilities() {
        let validator = runtime_contract_validator();
        let empty = format!("{LOADER_RUNTIME_DOCUMENT}acquisitionCapabilities: []\n");
        assert!(
            validator.is_valid(&bundle_contract_instance(empty.as_bytes())),
            "the contract refused an empty retired capability list"
        );
        assert!(
            RuntimeConfig::parse_yaml(empty.as_bytes()).is_ok(),
            "the runtime reader refused an empty retired capability list"
        );
        let candidate =
            format!("{LOADER_RUNTIME_DOCUMENT}acquisitionCapabilities: [source-batch]\n");
        assert!(
            !validator.is_valid(&bundle_contract_instance(candidate.as_bytes())),
            "the contract accepted a retired runtime acquisition capability"
        );
        assert!(
            RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
            "the runtime reader accepted a retired acquisition capability"
        );
    }

    #[test]
    fn requirement_acquisition_names_one_pack_source_and_retired_workflow_fields_are_refused() {
        let config = EvidenceConfig::parse_yaml(acceptance_fixture().as_bytes())
            .expect("the maintained bundle parses");
        let acquisition = &config.requirements[0].acquisition;
        assert_eq!(acquisition.source_ids(), ["source-a"]);
        assert!(acquisition.uses_source("source-a"));
        assert!(!acquisition.uses_source("other"));

        for (label, candidate) in [
            (
                "source batch",
                edited(
                    acceptance_fixture(),
                    "    factSchema: schemas/facts.schema.yaml\n",
                    "    factSchema: schemas/facts.schema.yaml\n    batch: {maximumItems: 2}\n",
                ),
            ),
            (
                "source unresolved problem",
                edited(
                    acceptance_fixture(),
                    "    factSchema: schemas/facts.schema.yaml\n",
                    "    factSchema: schemas/facts.schema.yaml\n    unresolvedProblem: {status: 404, type: https://source.invalid/unresolved, code: source.unresolved}\n",
                ),
            ),
            (
                "bundle acquisition capabilities",
                edited(
                    acceptance_fixture(),
                    "kind: EvidenceBundle\n",
                    "kind: EvidenceBundle\nacquisitionCapabilities: [source-batch]\n",
                ),
            ),
        ] {
            assert!(
                EvidenceConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "retired {label} wire surface parsed"
            );
            assert!(
                !bundle_contract_validator().is_valid(&bundle_contract_instance(candidate.as_bytes())),
                "the published schema accepted retired {label}"
            );
        }
    }

    #[test]
    fn requirement_acquisition_is_closed_and_rejects_retired_multistage_forms() {
        let current: AcquisitionConfig =
            serde_json::from_value(serde_json::json!({"source": "source-a"}))
                .expect("the one-source pack route acquisition parses");
        assert_eq!(current.initial_source(), "source-a");

        for retired in [
            serde_json::json!({"type": "single", "source": "source-a"}),
            serde_json::json!({
                "type": "search-then-fetch",
                "search": "source-a",
                "fetch": "source-b"
            }),
            serde_json::json!({
                "type": "search-then-fetch-set",
                "search": "source-a",
                "fetch": [{"source": "source-b", "factInputs": ["record_id"]}],
                "maximumAcquisitionMilliseconds": 30000
            }),
        ] {
            assert!(serde_json::from_value::<AcquisitionConfig>(retired).is_err());
        }
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
apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
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
  type: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  attemptTimeoutMilliseconds: 2000
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
        assert_eq!(
            registry_adapter_core::placeholders("/records/{{record_reference}}"),
            vec![("record_reference".to_owned(), false)]
        );
        for invalid_template in [
            "/records/{{}}",
            "/records/{{record.reference}}",
            "/records/{{record reference}}",
            "/records/{{record_reference",
        ] {
            assert!(
                registry_adapter_core::has_malformed_placeholder(invalid_template),
                "{invalid_template}"
            );
        }

        assert!(registry_adapter_core::is_header_token("X-API-Version"));
        assert!(!registry_adapter_core::is_reserved_header_name(
            "X-API-Version"
        ));
        for forbidden in registry_adapter_core::RESERVED_HEADER_NAMES {
            assert!(
                registry_adapter_core::is_reserved_header_name(forbidden),
                "{forbidden}"
            );
        }

        let mut source = serde_json::json!({
            "pack": {
                "id": "synthetic-register",
                "version": "1",
                "digest": format!("sha256:{}", "1".repeat(64)),
                "artifactPrefix": format!("adapter-packs/synthetic-register/{}", "1".repeat(64))
            },
            "route": "lookup",
            "connection": "register",
            "inputs": {},
            "posture": "record-transformed",
            "factSchema": "schemas/facts.json"
        });
        source["request"] = serde_json::json!({"path":"/records/{{record_reference}}"});
        assert!(
            serde_json::from_value::<SourceConfig>(source.clone()).is_err(),
            "request construction belongs to the governed Adapter pack"
        );
        source.as_object_mut().unwrap().remove("request");
        source["projection"] = serde_json::json!(["/results/*/status"]);
        assert!(
            serde_json::from_value::<SourceConfig>(source).is_err(),
            "inline response projection is not a Source member"
        );
    }

    #[test]
    fn path_based_https_oidc_issuer_is_preserved_exactly() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture validates");
        config.authentication.oidc.provider.issuer =
            registry_platform_yaml::Url::new("https://identity.example.test/realms/registry")
                .expect("valid URL");
        assert!(config.validate().is_ok());
        config.authentication.oidc.provider.issuer = registry_platform_yaml::Url::new(format!(
            "{}?tenant=wrong",
            config.authentication.oidc.provider.issuer
        ))
        .expect("query-bearing URL is syntactically valid");
        assert!(config.validate().is_err());
    }

    /// A runtime document every refusal test below edits one member of.
    const LOADER_RUNTIME_DOCUMENT: &str =
        "apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
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
  type: local-jwk
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
    fn a_runtime_file_with_the_retired_api_version_is_refused_with_the_replacement_named() {
        let retired = LOADER_RUNTIME_DOCUMENT.replace(
            EVIDENCE_RUNTIME_API_VERSION,
            RETIRED_EVIDENCE_RUNTIME_API_VERSION,
        );
        assert_ne!(
            retired, LOADER_RUNTIME_DOCUMENT,
            "the retired value is written"
        );
        let report = runtime_report(&retired);
        let diagnostic = deciding(&report);
        assert_eq!(diagnostic.code, "config.retired-api-version");
        assert_eq!(diagnostic.path, "/apiVersion");
        assert!(
            diagnostic
                .suggested_action
                .contains(EVIDENCE_RUNTIME_API_VERSION),
            "the fix names the apiVersion that replaced it: {diagnostic:?}"
        );
        assert_eq!(position(diagnostic).0, 1, "the refusal names the line");
    }

    #[test]
    fn the_runtime_document_declares_the_evidence_envelope() {
        RuntimeConfig::parse_yaml(LOADER_RUNTIME_DOCUMENT.as_bytes())
            .expect("the enveloped document loads");

        let unenveloped = LOADER_RUNTIME_DOCUMENT
            .replace(
                "apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1\n",
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

    const TRANSIT_SIGNER_BLOCK: &str = "signer:
  type: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  attemptTimeoutMilliseconds: 2000
";

    #[test]
    fn the_respelled_runtime_keys_are_read_and_the_old_spellings_refused() {
        let local_signer = "signer:\n  type: local-jwk\n  privateKeyRef: secret:file/signing-key\n";
        let audit = "audit:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\n";
        let respelled = LOADER_RUNTIME_DOCUMENT
            .replace(local_signer, TRANSIT_SIGNER_BLOCK)
            .replace(audit, &format!("{audit}  retentionDays: 30\n"));
        assert!(respelled.contains("attemptTimeoutMilliseconds: 2000\naudit:"));
        let config =
            RuntimeConfig::parse_yaml(respelled.as_bytes()).expect("the respelled keys load");
        assert_eq!(
            config.audit.retention_days.map(BoundedU32::get),
            Some(30),
            "audit.retentionDays is the retention period"
        );
        match &config.signer {
            RuntimeSignerConfig::Transit {
                attempt_timeout_milliseconds,
                ..
            } => assert_eq!(attempt_timeout_milliseconds.get(), 2000),
            other => panic!("the transit signer was read as {other:?}"),
        }

        // Each key an earlier runtime file wrote, with the key that replaced
        // it. The value beside the old key is a canary no diagnostic repeats.
        let cases = [
            (
                respelled.replace("  retentionDays: 30\n", "  retainDays: 31\n"),
                "/audit/retainDays",
                "audit.retentionDays",
                "retainDays: 31",
            ),
            (
                respelled.replace(
                    "  attemptTimeoutMilliseconds: 2000\n",
                    "  timeoutMilliseconds: 2001\n",
                ),
                "/signer/timeoutMilliseconds",
                "signer.attemptTimeoutMilliseconds",
                "timeoutMilliseconds: 2001",
            ),
        ];
        for (document, pointer, replacement, needle) in cases {
            assert_ne!(document, respelled, "{pointer}: the mutation applies");
            let line = document
                .lines()
                .position(|line| line.contains(needle))
                .expect("the old key is in the document")
                + 1;
            let report = runtime_report(&document);
            let removed = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == "config.removed-key")
                .unwrap_or_else(|| panic!("{pointer}: no config.removed-key in {report:?}"));
            assert_eq!(removed.path, pointer);
            assert_eq!(position(removed).0, line, "{pointer}");
            assert!(
                removed.suggested_action.contains(replacement),
                "{pointer}: the fix names the replacement: {removed:?}"
            );
            let rendered = format!("{report:?}");
            assert!(
                !rendered.contains("31") && !rendered.contains("2001"),
                "{pointer}: a diagnostic repeated a value"
            );
        }
    }

    #[test]
    fn the_runtime_signer_is_tagged_by_type_and_the_old_tag_is_refused() {
        assert!(LOADER_RUNTIME_DOCUMENT.contains("signer:\n  type: local-jwk\n"));
        let config = RuntimeConfig::parse_yaml(LOADER_RUNTIME_DOCUMENT.as_bytes())
            .expect("the signer tagged by type loads");
        assert!(matches!(
            config.signer,
            RuntimeSignerConfig::LocalJwk { .. }
        ));
        let transit = LOADER_RUNTIME_DOCUMENT.replace(
            "signer:\n  type: local-jwk\n  privateKeyRef: secret:file/signing-key\n",
            TRANSIT_SIGNER_BLOCK,
        );
        let config =
            RuntimeConfig::parse_yaml(transit.as_bytes()).expect("the transit signer loads");
        assert!(matches!(config.signer, RuntimeSignerConfig::Transit { .. }));

        let old = LOADER_RUNTIME_DOCUMENT.replace("  type: local-jwk\n", "  kind: local-jwk\n");
        assert_ne!(old, LOADER_RUNTIME_DOCUMENT, "the mutation applies");
        let report = runtime_report(&old);
        let removed = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .unwrap_or_else(|| panic!("no config.removed-key in {report:?}"));
        assert_eq!(removed.path, "/signer/kind");
        assert_eq!(
            position(removed).0,
            line_of(&old, "  kind: local-jwk"),
            "the refusal points at the written key"
        );
        assert!(
            removed.suggested_action.contains("signer.type"),
            "the fix names the replacement: {removed:?}"
        );
    }

    #[test]
    fn a_file_only_audit_member_under_stdout_is_refused_at_its_written_key() {
        let audit = "audit:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\n";
        let document = LOADER_RUNTIME_DOCUMENT.replace(
            audit,
            "audit:\n  destination: stdout\n  retentionDays: 30\n",
        );
        let error = RuntimeConfig::parse_yaml(document.as_bytes())
            .expect_err("a retention period under stdout is refused");
        assert!(
            error.to_string().contains("retentionDays"),
            "the cause names the key as written: {error}"
        );
        // The audit writer names the setting its own way; the finding points
        // at the key the file wrote.
        let refusal = audit_refusal(&AuditDestinationError::FileOnlyField {
            field: "retainDays",
        });
        assert_eq!(refusal.pointer, "/audit/retentionDays");
        assert!(refusal.at_key);
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
                replaced("type: local-jwk", &format!("type: {CANARY}")),
                "config.unknown-variant",
                "/signer/type",
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
            "  type: local-jwk\n  privateKeyRef: secret:file/signing-key\n",
            "  type: transit\n  unixSocketPath: /run/transit.sock\n  mount: transit\n  \
             keyName: evidence\n  keyVersion: seven\n  attemptTimeoutMilliseconds: 2000\n",
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
    fn source_credentials_and_mtls_keys_require_an_enabled_secret_provider() {
        const SOURCE_BINDING: &str = "sourceConnections:
  provider:
    id: provider
    endpoints:
      - endpoint: provider
        baseUrl: https://source.invalid
        credential:
          type: oauth2-private-key-jwt
          tokenEndpoint: https://identity.invalid/token
          clientIdRef: secret:env/SOURCE_CLIENT_ID
          clientAssertionKeyRef: secret:env/SOURCE_CLIENT_KEY
          maximumCacheSeconds: 60
        mtlsIdentity:
          certificateRef: secret:env/SOURCE_CLIENT_CERTIFICATE
          keyRef: secret:env/SOURCE_MTLS_KEY
    allowedPrivateCidrs: []
";
        let disabled = format!("{LOADER_RUNTIME_DOCUMENT}{SOURCE_BINDING}");
        let decoded = RuntimeConfig::decode_yaml_with(disabled.as_bytes(), |_| None)
            .expect("the closed runtime wire shape decodes before semantic validation");
        let findings = decoded.config.findings();
        let expected = [
            "/sourceConnections/provider/endpoints/0/credential/clientIdRef",
            "/sourceConnections/provider/endpoints/0/credential/clientAssertionKeyRef",
            "/sourceConnections/provider/endpoints/0/mtlsIdentity/certificateRef",
            "/sourceConnections/provider/endpoints/0/mtlsIdentity/keyRef",
        ];
        assert_eq!(findings.len(), expected.len());
        for (finding, pointer) in findings.iter().zip(expected) {
            assert_eq!(finding.code, RUNTIME_SOURCE_CONNECTION_CODE);
            assert_eq!(finding.pointer, pointer);
            assert!(!finding.at_key, "the reference value is at fault");
            assert_eq!(
                finding.message(),
                "the secret reference names a provider secretProviders does not enable"
            );
        }
        assert_eq!(
            RuntimeConfig::parse_yaml(disabled.as_bytes()),
            Err(ConfigError::Invalid(
                "the secret reference names a provider secretProviders does not enable"
            ))
        );
        let rendered = format!("{findings:?}");
        for protected in [
            "SOURCE_CLIENT_ID",
            "SOURCE_CLIENT_KEY",
            "SOURCE_CLIENT_CERTIFICATE",
            "SOURCE_MTLS_KEY",
        ] {
            assert!(
                !rendered.contains(protected),
                "the refusal repeated a configured secret reference"
            );
        }

        let enabled = disabled.replace(
            "file: {root: /run/secrets/registry-evidence}",
            "file: {root: /run/secrets/registry-evidence}\n  environment: {}",
        );
        RuntimeConfig::parse_yaml(enabled.as_bytes())
            .expect("declaring the environment provider admits its source references");

        let file_bound = disabled
            .replace(
                "secret:env/SOURCE_CLIENT_ID",
                "secret:file/source-client-id",
            )
            .replace(
                "secret:env/SOURCE_CLIENT_KEY",
                "secret:file/source-client-key",
            )
            .replace(
                "secret:env/SOURCE_CLIENT_CERTIFICATE",
                "secret:file/source-client-certificate",
            )
            .replace("secret:env/SOURCE_MTLS_KEY", "secret:file/source-mtls-key");
        RuntimeConfig::parse_yaml(file_bound.as_bytes())
            .expect("the existing file provider admits source credential and mTLS references");
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

    const BUNDLE_ENVELOPE: &str =
        "apiVersion: id.registrystack.org/formats/evidence/bundle/v1\nkind: EvidenceBundle\n";

    #[test]
    fn the_bundle_declares_the_evidence_envelope() {
        let bundle = acceptance_bundle();
        assert!(
            bundle.starts_with(BUNDLE_ENVELOPE),
            "the fixture is enveloped"
        );
        EvidenceConfig::parse_yaml(bundle.as_bytes()).expect("the enveloped bundle loads");

        let unenveloped = bundle.replacen(BUNDLE_ENVELOPE, "", 1);
        let diagnostics = bundle_refusal(&unenveloped);
        let missing = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.missing-envelope")
            .unwrap_or_else(|| panic!("no config.missing-envelope in {diagnostics:?}"));
        assert!(
            missing
                .suggested_action
                .contains(EVIDENCE_BUNDLE_API_VERSION),
            "the fix names the apiVersion to write: {missing:?}"
        );

        let other_kind =
            bundle.replacen("kind: EvidenceBundle\n", "kind: EvidenceRuntimeConfig\n", 1);
        let diagnostics = bundle_refusal(&other_kind);
        assert_eq!(diagnostics[0].code, "config.wrong-kind");
        assert_eq!(diagnostics[0].path, "/kind");
    }

    #[test]
    fn a_bundle_written_with_the_version_member_is_refused_with_the_envelope_named() {
        // The header an earlier grammar wrote, beside the envelope and in its
        // place: both are refused at the member, with the envelope named.
        let beside = acceptance_bundle().replacen(
            BUNDLE_ENVELOPE,
            &format!("{BUNDLE_ENVELOPE}version: 1\n"),
            1,
        );
        let instead = acceptance_bundle().replacen(BUNDLE_ENVELOPE, "version: 1\n", 1);
        for (label, document, line) in [("beside", beside, 3), ("instead", instead, 1)] {
            let diagnostics = bundle_refusal(&document);
            let removed = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "config.removed-key")
                .unwrap_or_else(|| panic!("{label}: no config.removed-key in {diagnostics:?}"));
            assert_eq!(removed.path, "/version", "{label}");
            assert_eq!(
                removed.source.as_ref().and_then(|source| source.line),
                Some(line),
                "{label}"
            );
            assert!(
                removed
                    .suggested_action
                    .contains(EVIDENCE_BUNDLE_API_VERSION)
                    && removed.suggested_action.contains(EVIDENCE_BUNDLE_KIND),
                "{label}: the fix names the envelope: {removed:?}"
            );
        }
    }

    /// The adult-status acceptance bundle, which every bundle-reader test
    /// edits into the case it proves.
    /// Where the retired tagged Source form is migrated to pack Sources.
    const RETIRED_SOURCE_MIGRATION: &str =
        "products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project";

    fn acceptance_bundle() -> String {
        String::from_utf8(
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            )
            .to_vec(),
        )
        .expect("fixture is UTF-8")
    }

    #[test]
    fn a_legacy_transport_member_points_at_the_source_migration() {
        let valid = acceptance_bundle();
        let legacy = valid.replacen(
            "  source-a:\n",
            "  source-a:\n    transport: http-json\n",
            1,
        );
        assert_ne!(legacy, valid, "the legacy Source mutation applies");

        let diagnostics = bundle_refusal(&legacy);
        assert_eq!(
            diagnostics.len(),
            1,
            "one closed-reader refusal: {diagnostics:?}"
        );
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.code, "config.removed-key");
        assert_eq!(diagnostic.path, "/sources/source-a/transport");
        assert_eq!(
            diagnostic.source.as_ref().and_then(|source| source.line),
            Some(line_of(&legacy, "transport: http-json"))
        );
        assert_eq!(
            diagnostic.source.as_ref().and_then(|source| source.column),
            Some(5)
        );
        assert_eq!(diagnostic.suggested_action, RETIRED_SOURCE_MEMBER);
        assert!(RETIRED_SOURCE_MEMBER.contains(RETIRED_SOURCE_MIGRATION));
    }

    /// A bundle compiled before Sources bound pack routes is refused with one
    /// pointer to the migration at the Source's `type`, and a short reference
    /// at each other retired member, never with advice to delete them.
    #[test]
    fn a_retired_source_form_is_refused_with_the_migration_named() {
        let valid = acceptance_bundle();
        let start = valid
            .find("  source-a:\n")
            .expect("the fixture declares source-a");
        let end = valid
            .find("authorityProfiles:")
            .expect("the fixture declares authority profiles");
        let retired = format!(
            "{}{}{}",
            &valid[..start],
            "  source-a:\n    \
             type: http-json\n    \
             baseUrl: https://source.invalid\n    \
             connection: provider\n    \
             posture: field-projected\n    \
             authentication: {type: static-authorization, tokenRef: secret:file/source-a-token}\n    \
             request: {method: POST, path: /v1/facts}\n    \
             responseSchema: schemas/response.schema.yaml\n    \
             extractScript: adapters/source-a.rhai\n    \
             factSchema: schemas/facts.schema.yaml\n",
            &valid[end..]
        );

        let diagnostics = bundle_refusal(&retired);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != "config.unknown-key"),
            "no retired member is called unknown: {diagnostics:?}"
        );
        let at = |path: &str| {
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic.path == path)
                .unwrap_or_else(|| panic!("{path} was not refused: {diagnostics:?}"))
        };
        let form = at("/sources/source-a/type");
        assert_eq!(form.code, "config.removed-key");
        assert_eq!(form.suggested_action, RETIRED_SOURCE_FORM);
        for needle in [
            "pack",
            "route",
            "evidencectl 0.45.0",
            RETIRED_SOURCE_MIGRATION,
        ] {
            assert!(form.suggested_action.contains(needle), "{needle}: {form:?}");
        }
        for member in [
            "baseUrl",
            "authentication",
            "request",
            "responseSchema",
            "extractScript",
        ] {
            let refusal = at(&format!("/sources/source-a/{member}"));
            assert_eq!(refusal.code, "config.removed-key", "{member}");
            assert_eq!(refusal.suggested_action, RETIRED_SOURCE_MEMBER, "{member}");
        }
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.suggested_action == RETIRED_SOURCE_FORM)
                .count(),
            1,
            "the full migration paragraph appears once"
        );
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
        text[..text.find(needle).expect("the needle is in the text")]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1
    }

    #[test]
    fn the_respelled_request_bounds_are_read_and_the_old_spellings_refused() {
        let current = serde_json::json!({
            "id": "provider",
            "endpoints": [{
                "endpoint": "provider",
                "baseUrl": "https://source.invalid",
                "credential": {
                    "type": "static-authorization",
                    "tokenRef": "secret:file/source-token"
                },
                "attemptTimeoutMilliseconds": 3000,
                "maximumResponseBytes": 65536,
                "maximumConcurrency": 8
            }],
            "allowedPrivateCidrs": []
        });
        let bindings: registry_adapter_core::AdapterEndpointBindings =
            serde_json::from_value(current.clone()).expect("the current endpoint bounds read");
        let projection = serde_json::to_value(bindings).expect("the bindings project");
        let endpoint = &projection["endpoints"][0];
        assert_eq!(endpoint["attemptTimeoutMilliseconds"], 3000);
        assert_eq!(endpoint["maximumResponseBytes"], 65536);
        assert_eq!(endpoint["maximumConcurrency"], 8);

        for (current_name, retired_name) in [
            ("attemptTimeoutMilliseconds", "timeoutMilliseconds"),
            ("maximumResponseBytes", "maximumResponseSize"),
            ("maximumConcurrency", "concurrencyLimit"),
        ] {
            let mut candidate = current.clone();
            let endpoint = candidate["endpoints"][0]
                .as_object_mut()
                .expect("endpoint mapping");
            let value = endpoint.remove(current_name).expect("current member");
            endpoint.insert(retired_name.to_owned(), value);
            assert!(
                serde_json::from_value::<registry_adapter_core::AdapterEndpointBindings>(candidate)
                    .is_err(),
                "the runtime reader accepted retired `{retired_name}`"
            );
        }
    }

    #[test]
    fn a_requirement_repeating_a_uri_is_refused_with_the_shared_code_at_the_copy() {
        let valid = acceptance_bundle();
        let (before_requirements, requirements_and_after) = valid
            .split_once("requirements:\n")
            .expect("the fixture declares requirements");
        let (requirement, after_requirements) = requirements_and_after
            .split_once("sourceConnections:\n")
            .expect("source connections follow the requirements");
        let repeated = format!(
            "{before_requirements}requirements:\n{requirement}{requirement}sourceConnections:\n{after_requirements}"
        );
        let diagnostics = bundle_refusal(&repeated);
        assert_eq!(diagnostics.len(), 1, "one problem: {diagnostics:?}");
        let duplicate = &diagnostics[0];
        assert_eq!(duplicate.code, "config.duplicate-id");
        assert_eq!(duplicate.path, "/requirements/1/uri");
        let uri = "    uri: urn:example:fixture:requirement:";
        let first_line = line_of(&valid, uri);
        let copy_byte = repeated
            .match_indices(uri)
            .nth(1)
            .expect("the repeated requirement carries a second URI")
            .0;
        let copy_line = repeated[..copy_byte].lines().count() + 1;
        assert_eq!(
            duplicate.source.as_ref().and_then(|source| source.line),
            Some(copy_line)
        );
        assert!(
            duplicate
                .source
                .as_ref()
                .and_then(|source| source.column)
                .is_some(),
            "the copy is positioned by column: {duplicate:?}"
        );
        assert_eq!(duplicate.related.len(), 1, "{duplicate:?}");
        assert_eq!(duplicate.related[0].path, "/requirements/0/uri");
        assert_eq!(duplicate.related[0].line, Some(first_line));
        let rendered = format!("{} {}", duplicate.message, duplicate.suggested_action);
        assert!(
            rendered.contains("`uri`") && !rendered.contains("`id`"),
            "the refusal names the member that repeats: {duplicate:?}"
        );
        assert!(
            !format!("{duplicate:?}").contains("urn:example:fixture:requirement"),
            "the diagnostic repeated the identifier: {duplicate:?}"
        );
    }

    /// Every bundle decides its two admission gates (CFG-EMPTY-2): the keyword
    /// `unrestricted` or a list of at least one value. An omitted gate and an
    /// empty list would both read as "no gate", so the reader refuses both
    /// (CFG-EMPTY-3) and never repeats a written value.
    #[test]
    fn the_admission_gates_are_required_and_unrestricted_is_explicit() {
        let valid = acceptance_bundle();
        let config = EvidenceConfig::parse_yaml(valid.as_bytes())
            .expect("the bundle that states both gates loads");
        let projection = serde_json::to_value(&config).expect("the bundle projects");
        let oidc = &projection["authentication"]["oidc"];
        assert_eq!(oidc["allowedClients"], "unrestricted");
        assert_eq!(oidc["requiredScopes"], "unrestricted");

        let listed = edited(
            &edited(
                &valid,
                "    allowedClients: unrestricted\n",
                "    allowedClients: [records-reader]\n",
            ),
            "    requiredScopes: unrestricted\n",
            "    requiredScopes: [\"evidence:invoke\"]\n",
        );
        let config = EvidenceConfig::parse_yaml(listed.as_bytes())
            .expect("the bundle that lists both gates loads");
        let projection = serde_json::to_value(&config).expect("the bundle projects");
        let oidc = &projection["authentication"]["oidc"];
        assert_eq!(
            oidc["allowedClients"],
            serde_json::json!(["records-reader"])
        );
        assert_eq!(
            oidc["requiredScopes"],
            serde_json::json!(["evidence:invoke"])
        );

        for member in ["allowedClients", "requiredScopes"] {
            let stated = format!("    {member}: unrestricted\n");
            let line = line_of(&valid, stated.trim());

            let omitted = bundle_refusal(&edited(&valid, &stated, ""));
            assert_eq!(omitted.len(), 1, "one problem: {omitted:?}");
            assert_eq!(omitted[0].code, "config.missing-key", "{member}");
            assert!(
                omitted[0].message.contains(member),
                "the refusal does not name the member: {:?}",
                omitted[0]
            );

            for written in ["[]", "open-to-anyone"] {
                let document = edited(&valid, &stated, &format!("    {member}: {written}\n"));
                let diagnostics = bundle_refusal(&document);
                assert_eq!(diagnostics.len(), 1, "one problem: {diagnostics:?}");
                let refusal = &diagnostics[0];
                assert_eq!(refusal.code, "config.invalid-value", "{member} {written}");
                assert_eq!(refusal.path, format!("/authentication/oidc/{member}"));
                assert_eq!(
                    refusal.source.as_ref().expect("a position").line,
                    Some(line),
                    "{refusal:?}"
                );
                assert!(
                    refusal.suggested_action.contains("unrestricted"),
                    "the refusal does not name the keyword: {refusal:?}"
                );
                assert!(
                    !format!("{refusal:?}").contains("open-to-anyone"),
                    "the diagnostic repeated the value: {refusal:?}"
                );
            }
        }
    }

    /// An integer the schema bounds on both sides is refused at its value
    /// with the shared code, and not at the requirement that holds it
    /// (CFG-QTY-4, CFG-DIAG-1): a derivation parameter outside the safe
    /// integers, and a list concept's item count outside one to 64.
    #[test]
    fn an_integer_outside_its_bounds_is_refused_with_the_shared_code_at_the_value() {
        let valid = acceptance_bundle();
        let line = line_of(&valid, "minimum_age_years: 18");
        for written in ["9007199254740992", "-9007199254740992"] {
            let document = edited(
                &valid,
                "minimum_age_years: 18",
                &format!("minimum_age_years: {written}"),
            );
            let diagnostics = bundle_refusal(&document);
            assert_eq!(diagnostics.len(), 1, "one problem: {diagnostics:?}");
            let refusal = &diagnostics[0];
            assert_eq!(refusal.code, "config.out-of-range", "{written}");
            assert_eq!(
                refusal.path,
                "/requirements/0/derivation/parameters/minimum_age_years"
            );
            let source = refusal.source.as_ref().expect("a position");
            assert_eq!(source.line, Some(line), "{refusal:?}");
            assert!(source.column.is_some(), "{refusal:?}");
            assert!(
                !format!("{refusal:?}").contains(written),
                "the diagnostic repeated the value: {refusal:?}"
            );
        }
        let safe = edited(
            &valid,
            "minimum_age_years: 18",
            "minimum_age_years: 9007199254740991",
        );
        EvidenceConfig::parse_yaml(safe.as_bytes()).expect("the largest safe integer loads");

        const SUPPORTED_VALUES: &str = include_str!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        );
        let sound = "          minimumItems: 1\n          maximumItems: 2\n          unique: true";
        for (replacement, member) in [
            (
                "          minimumItems: 0\n          maximumItems: 2\n          unique: true",
                "minimumItems",
            ),
            (
                "          minimumItems: 1\n          maximumItems: 65\n          unique: true",
                "maximumItems",
            ),
        ] {
            let document = edited(SUPPORTED_VALUES, sound, replacement);
            let member_index = document
                .find(replacement)
                .expect("the replacement is present")
                + replacement
                    .find(member)
                    .expect("the replacement names the member");
            let line = document.as_bytes()[..member_index]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count()
                + 1;
            let diagnostics = bundle_refusal(&document);
            assert_eq!(diagnostics.len(), 1, "one problem: {diagnostics:?}");
            let refusal = &diagnostics[0];
            assert_eq!(refusal.code, "config.out-of-range", "{member}");
            assert!(
                refusal.path.starts_with("/requirements/0/concepts/")
                    && refusal.path.ends_with(&format!("/constraints/{member}")),
                "{refusal:?}"
            );
            let source = refusal.source.as_ref().expect("a position");
            assert_eq!(source.line, Some(line), "{refusal:?}");
            assert!(source.column.is_some(), "{refusal:?}");
        }
    }

    #[test]
    fn a_source_connection_written_with_the_old_concurrency_key_is_refused() {
        let governed = serde_json::json!({
            "endpoints": [{
                "endpoint": "provider",
                "baseUrl": "https://source.invalid",
                "authentication": {"type": "static-authorization"},
                "clientIdentity": "forbidden"
            }]
        });
        serde_json::from_value::<SourceConnectionPolicies>(governed.clone())
            .expect("the governed connection policy loads");
        for member in ["maximumConcurrency", "concurrencyLimit"] {
            let mut candidate = governed.clone();
            candidate["endpoints"][0][member] = 4.into();
            assert!(
                serde_json::from_value::<SourceConnectionPolicies>(candidate).is_err(),
                "governed connection authority accepted runtime member `{member}`"
            );
        }

        let runtime = serde_json::json!({
            "id": "provider",
            "endpoints": [{
                "endpoint": "provider",
                "baseUrl": "https://source.invalid",
                "credential": {
                    "type": "static-authorization",
                    "tokenRef": "secret:file/source-token"
                },
                "maximumConcurrency": 4
            }],
            "allowedPrivateCidrs": []
        });
        let parsed: registry_adapter_core::AdapterEndpointBindings =
            serde_json::from_value(runtime.clone()).expect("runtime concurrency loads");
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["endpoints"][0]["maximumConcurrency"],
            4
        );
        let mut retired = runtime;
        let endpoint = retired["endpoints"][0].as_object_mut().unwrap();
        endpoint.remove("maximumConcurrency");
        endpoint.insert("concurrencyLimit".to_owned(), 4.into());
        assert!(
            serde_json::from_value::<registry_adapter_core::AdapterEndpointBindings>(retired)
                .is_err(),
            "the runtime reader accepted retired `concurrencyLimit`"
        );
    }

    /// Asserts that `valid` loads, and that writing `old` where it writes
    /// `new` is refused as a removed key at `pointer` with `type` named.
    fn assert_union_tag_respelled(valid: &str, new: &str, old: &str, pointer: &str) {
        EvidenceConfig::parse_yaml(valid.as_bytes())
            .unwrap_or_else(|error| panic!("{pointer}: the bundle tagged by type loads: {error}"));
        let candidate = valid.replacen(new, old, 1);
        assert_ne!(candidate, valid, "{pointer}: the mutation applies");
        let diagnostics = bundle_refusal(&candidate);
        let removed = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .unwrap_or_else(|| panic!("{pointer}: no config.removed-key in {diagnostics:?}"));
        assert_eq!(removed.path, pointer);
        assert_eq!(
            removed.source.as_ref().and_then(|source| source.line),
            Some(line_of(&candidate, old)),
            "{pointer}"
        );
        assert!(
            removed.suggested_action.contains("type"),
            "{pointer}: the fix names the replacement: {removed:?}"
        );
    }

    #[test]
    fn a_request_path_is_a_literal_or_a_template_and_path_template_is_refused() {
        use registry_adapter_core::{AdapterPack, AdapterProject};

        let findings = |path: &str, path_parameters: serde_json::Value| {
            let pack: AdapterPack = serde_json::from_value(serde_json::json!({
                "id": "current-source-contract",
                "version": "1",
                "testedVersions": [],
                "endpoints": [{
                    "id": "provider",
                    "component": "http",
                    "authentication": {"type": "none"},
                    "maximumResponseBytes": 4096,
                    "operations": [{"id": "lookup", "safeUpstream": true}]
                }],
                "sourceRoutes": [{
                    "id": "lookup",
                    "steps": [{"to": {"uri": "http:provider", "parameters": {
                        "httpMethod": "GET",
                        "path": path,
                        "pathParameters": path_parameters,
                        "operation": "lookup"
                    }}}]
                }]
            }))
            .expect("the current pack path shape parses");
            let project: AdapterProject = serde_json::from_value(serde_json::json!({
                "project": {"id": "unused-project", "version": "1"},
                "profile": {
                    "id": "unused-profile",
                    "version": "1",
                    "digest": format!("sha256:{}", "1".repeat(64))
                },
                "pack": {
                    "id": "current-source-contract",
                    "version": "1",
                    "digest": format!("sha256:{}", "2".repeat(64))
                },
                "recordTypes": []
            }))
            .expect("minimal project");
            registry_adapter_core::check_routes(&pack, &project)
        };
        let path_faults = |path: &str, parameters: serde_json::Value| {
            findings(path, parameters)
                .into_iter()
                .filter(|finding| finding.code == "adapter.route.path-parameter-mismatch")
                .collect::<Vec<_>>()
        };

        assert!(path_faults("/v1/facts", serde_json::json!({})).is_empty());
        assert!(path_faults(
            "/v1/facts/{{given_name}}",
            serde_json::json!({"given_name": {"constant": "Ada"}}),
        )
        .is_empty());
        assert!(
            serde_json::from_value::<registry_adapter_core::ToParameters>(serde_json::json!({
                "httpMethod": "GET",
                "pathTemplate": "/v1/facts/{{given_name}}",
                "pathParameters": {"given_name": {"constant": "Ada"}},
                "operation": "lookup"
            }))
            .is_err(),
            "the pack reader accepted retired `pathTemplate`"
        );

        for (path, parameters, reason) in [
            (
                "/v1/facts/{{given_name}}",
                serde_json::json!({}),
                "a template without a binding",
            ),
            (
                "/v1/facts",
                serde_json::json!({"given_name": {"constant": "Ada"}}),
                "a binding beside a literal path",
            ),
            (
                "/v1/facts/{{family_name}}",
                serde_json::json!({"given_name": {"constant": "Ada"}}),
                "a placeholder no binding fills",
            ),
            (
                "/v1/facts/{given_name}",
                serde_json::json!({"given_name": {"constant": "Ada"}}),
                "the facade single-brace spelling in a pack path",
            ),
        ] {
            assert!(!path_faults(path, parameters).is_empty(), "{reason}");
        }
    }

    #[test]
    fn a_client_assertion_key_is_its_own_authentication_type() {
        let shared_secret = serde_json::json!({
            "type": "oauth2-client-credentials",
            "tokenEndpoint": "https://source.invalid/token",
            "clientIdRef": "secret:file/oauth-client-id",
            "clientSecretRef": "secret:file/oauth-client-secret",
            "credentialPlacement": "basic-header",
            "maximumCacheSeconds": 60
        });
        let assertion = serde_json::json!({
            "type": "oauth2-private-key-jwt",
            "tokenEndpoint": "https://source.invalid/token",
            "clientIdRef": "secret:file/oauth-client-id",
            "clientAssertionKeyRef": "secret:file/oauth-client-key",
            "clientAssertionAudience": "https://issuer.invalid/",
            "maximumCacheSeconds": 60
        });
        let parsed: registry_adapter_core::RuntimeCredential =
            serde_json::from_value(assertion.clone()).expect("the assertion form loads");
        let projection = serde_json::to_value(parsed).expect("the assertion form projects");
        assert_eq!(projection["type"], "oauth2-private-key-jwt");
        assert_eq!(
            projection["clientAssertionKeyRef"],
            "secret:file/oauth-client-key"
        );
        serde_json::from_value::<registry_adapter_core::RuntimeCredential>(shared_secret.clone())
            .expect("the shared-secret form loads");

        let mut key_under_secret = shared_secret.clone();
        key_under_secret["clientAssertionKeyRef"] = "secret:file/oauth-client-key".into();
        let mut secret_under_key = assertion.clone();
        secret_under_key["clientSecretRef"] = "secret:file/oauth-client-secret".into();
        secret_under_key["credentialPlacement"] = "basic-header".into();
        for (candidate, reason) in [
            (
                key_under_secret,
                "an assertion key under the shared-secret type",
            ),
            (secret_under_key, "a shared secret under the assertion type"),
        ] {
            assert!(
                serde_json::from_value::<registry_adapter_core::RuntimeCredential>(candidate)
                    .is_err(),
                "the runtime reader accepted {reason}"
            );
        }
    }

    #[test]
    fn the_issuer_and_a_concept_name_their_uri_and_the_old_id_is_refused() {
        let adult = acceptance_bundle();
        let config = EvidenceConfig::parse_yaml(adult.as_bytes()).expect("the bundle loads");
        let projection = serde_json::to_value(&config).expect("the bundle projects");
        assert_eq!(
            projection["issuer"]["uri"],
            "urn:example:fixture:issuer:authority"
        );
        assert!(projection["issuer"].get("id").is_none());
        let concept = &projection["requirements"][0]["concepts"][0];
        assert_eq!(concept["uri"], "urn:example:fixture:concept:adult-status");
        assert!(concept.get("id").is_none());

        for (new, old, pointer) in [
            ("issuer:\n  uri: ", "issuer:\n  id: ", "/issuer/id"),
            (
                "      - handle: is_adult\n        uri: ",
                "      - handle: is_adult\n        id: ",
                "/requirements/0/concepts/0/id",
            ),
        ] {
            let candidate = adult.replacen(new, old, 1);
            assert_ne!(candidate, adult, "{pointer}: the mutation applies");
            let diagnostics = bundle_refusal(&candidate);
            let removed = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "config.removed-key")
                .unwrap_or_else(|| panic!("{pointer}: no config.removed-key in {diagnostics:?}"));
            assert_eq!(removed.path, pointer);
            assert!(
                removed.suggested_action.contains("uri"),
                "{pointer}: the fix names the replacement: {removed:?}"
            );
            let rendered = format!("{} {}", removed.message, removed.suggested_action);
            assert!(
                !rendered.contains("urn:example"),
                "{pointer}: the written value is not repeated"
            );
        }
    }

    #[test]
    fn a_requirement_names_its_uri_and_the_old_id_is_refused() {
        let adult = acceptance_bundle();
        let config = EvidenceConfig::parse_yaml(adult.as_bytes()).expect("the bundle loads");
        let projection = serde_json::to_value(&config).expect("the bundle projects");
        let requirement = &projection["requirements"][0];
        assert_eq!(
            requirement["uri"],
            "urn:example:fixture:requirement:adult-status:v1"
        );
        assert!(requirement.get("id").is_none());

        let candidate = adult.replacen(
            "    uri: urn:example:fixture:requirement:",
            "    id: urn:example:fixture:requirement:",
            1,
        );
        assert_ne!(candidate, adult, "the mutation applies");
        let diagnostics = bundle_refusal(&candidate);
        let removed = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .unwrap_or_else(|| panic!("no config.removed-key in {diagnostics:?}"));
        assert_eq!(removed.path, "/requirements/0/id");
        assert!(
            removed.suggested_action.contains("uri"),
            "the fix names the replacement: {removed:?}"
        );
        let rendered = format!("{} {}", removed.message, removed.suggested_action);
        assert!(
            !rendered.contains("urn:example"),
            "the written value is not repeated"
        );

        let absent = adult
            .lines()
            .filter(|line| !line.starts_with("    uri: urn:example:fixture:requirement:"))
            .fold(String::new(), |text, line| text + line + "\n");
        assert_ne!(absent, adult, "the removal applies");
        let diagnostics = bundle_refusal(&absent);
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "config.missing-key" && diagnostic.message.contains("uri")
            }),
            "a requirement without its URI is refused: {diagnostics:?}"
        );
    }

    #[test]
    fn the_batch_ceiling_is_a_maximum_and_the_old_name_is_refused() {
        let adult = acceptance_bundle();
        let declared = adult.replacen(
            "\nrequirements:\n",
            "\nmaximumHolderBoundBatchSize: 4\n\nrequirements:\n",
            1,
        );
        assert_ne!(declared, adult, "the declaration applies");
        let config = EvidenceConfig::parse_yaml(declared.as_bytes()).expect("the bundle loads");
        assert_eq!(config.holder_bound_batch_ceiling(), 4);
        let projection = serde_json::to_value(&config).expect("the bundle projects");
        assert_eq!(projection["maximumHolderBoundBatchSize"], 4);
        assert!(projection.get("holderBoundBatchMaxSize").is_none());

        let old = declared.replacen(
            "\nmaximumHolderBoundBatchSize: 4\n",
            "\nholderBoundBatchMaxSize: 4\n",
            1,
        );
        let diagnostics = bundle_refusal(&old);
        let removed = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .unwrap_or_else(|| panic!("no config.removed-key in {diagnostics:?}"));
        assert_eq!(removed.path, "/holderBoundBatchMaxSize");
        assert!(
            removed
                .suggested_action
                .contains("maximumHolderBoundBatchSize"),
            "the fix names the replacement: {removed:?}"
        );

        // A Source no longer pins a definitions document; the retired member
        // is refused once at its key, with the migration named.
        let mut pinned =
            serde_norway::from_str::<serde_norway::Value>(&adult).expect("the fixture parses");
        let source = pinned["sources"]
            .as_mapping_mut()
            .expect("the sources are a mapping")
            .get_mut("source-a")
            .expect("the fixture declares source-a");
        source["evidence"] = serde_norway::from_str("contract:\n  holderBoundBatchMaxSize: 4\n")
            .expect("the pinned contract parses");
        let pinned = serde_norway::to_string(&pinned).expect("the candidate serializes");
        let diagnostics = bundle_refusal(&pinned);
        let removed = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .unwrap_or_else(|| panic!("no config.removed-key in {diagnostics:?}"));
        assert_eq!(removed.path, "/sources/source-a/evidence");
        assert_eq!(removed.suggested_action, RETIRED_SOURCE_MEMBER);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| !diagnostic.path.starts_with("/sources/source-a/evidence/")),
            "nothing inside the retired member is advised on: {diagnostics:?}"
        );
    }

    /// A Source no longer pins a definitions document, so a pinned concept
    /// form in any old shape is refused once, at the retired `evidence`
    /// member, with the migration named and no value repeated.
    #[test]
    fn a_pinned_concept_form_is_named_by_type_and_the_old_shapes_are_refused() {
        let adult = acceptance_bundle();
        let pinned = |form: &str| {
            let mut pinned =
                serde_norway::from_str::<serde_norway::Value>(&adult).expect("the fixture parses");
            let source = pinned["sources"]
                .as_mapping_mut()
                .expect("the sources are a mapping")
                .get_mut("source-a")
                .expect("the fixture declares source-a");
            source["evidence"] = serde_norway::from_str(&format!(
                "contract:\n  definitions:\n    - concepts:\n        - form: {form}\n"
            ))
            .expect("the pinned contract parses");
            serde_norway::to_string(&pinned).expect("the candidate serializes")
        };
        let diagnostics = bundle_refusal(&pinned(
            "{list: {items: string, minimumItems: 1, maximumItems: 2, unique: true}}",
        ));
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| !diagnostic.path.starts_with("/sources/source-a/evidence/")),
            "nothing inside the retired member is advised on: {diagnostics:?}"
        );
        let parent = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/sources/source-a/evidence")
            .unwrap_or_else(|| {
                panic!("the retired source parent was not refused: {diagnostics:?}")
            });
        assert_eq!(parent.code, "config.removed-key");
        assert_eq!(parent.suggested_action, RETIRED_SOURCE_MEMBER);
        assert!(!format!("{diagnostics:?}").contains("minimumItems: 1"));

        let diagnostics = bundle_refusal(&pinned("boolean"));
        let parent = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/sources/source-a/evidence")
            .unwrap_or_else(|| panic!("the retired boolean form was not refused: {diagnostics:?}"));
        assert_eq!(parent.code, "config.removed-key");
        assert_eq!(parent.suggested_action, RETIRED_SOURCE_MEMBER);
        assert!(!format!("{diagnostics:?}").contains("form: boolean"));

        let diagnostics = bundle_refusal(&pinned("{type: boolean, unique: true}"));
        let parent = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/sources/source-a/evidence")
            .unwrap_or_else(|| {
                panic!("the retired constrained form was not refused: {diagnostics:?}")
            });
        assert_eq!(parent.code, "config.removed-key");
        assert_eq!(parent.suggested_action, RETIRED_SOURCE_MEMBER);
        assert!(!format!("{diagnostics:?}").contains("unique: true"));

        let diagnostics = bundle_refusal(&pinned("{type: decimal}"));
        let parent = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/sources/source-a/evidence")
            .unwrap_or_else(|| panic!("the retired decimal form was not refused: {diagnostics:?}"));
        assert_eq!(parent.code, "config.removed-key");
        assert_eq!(parent.suggested_action, RETIRED_SOURCE_MEMBER);
        assert!(!format!("{diagnostics:?}").contains("type: decimal"));

        let diagnostics = bundle_refusal(&pinned("{type: boolean}"));
        let parent = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/sources/source-a/evidence")
            .unwrap_or_else(|| {
                panic!("the retired tagged boolean was not refused: {diagnostics:?}")
            });
        assert_eq!(parent.code, "config.removed-key");
        assert_eq!(parent.suggested_action, RETIRED_SOURCE_MEMBER);
        assert!(!format!("{diagnostics:?}").contains("type: boolean"));

        let diagnostics = bundle_refusal(&pinned(
            "{type: list, items: string, minimumItems: 1, maximumItems: 2, unique: true}",
        ));
        let parent = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/sources/source-a/evidence")
            .unwrap_or_else(|| panic!("the retired tagged list was not refused: {diagnostics:?}"));
        assert_eq!(parent.code, "config.removed-key");
        assert_eq!(parent.suggested_action, RETIRED_SOURCE_MEMBER);
        assert!(!format!("{diagnostics:?}").contains("maximumItems: 2"));

        let old_list = adult.replacen(
            "        type: boolean\n",
            "        form:\n          list: {items: string, minimumItems: 1, maximumItems: 2, unique: true}\n",
            1,
        );
        assert_ne!(old_list, adult, "the current concept mutation applies");
        let diagnostics = bundle_refusal(&old_list);
        let removed = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .unwrap_or_else(|| panic!("no current concept removal in {diagnostics:?}"));
        assert_eq!(removed.path, "/requirements/0/concepts/0/form");
        assert_eq!(
            removed.suggested_action,
            "Declare type instead; keep the value."
        );

        let wrong_type = adult.replacen("        type: boolean\n", "        type: [boolean]\n", 1);
        assert_ne!(wrong_type, adult, "the non-string type mutation applies");
        let diagnostics = bundle_refusal(&wrong_type);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "config.invalid-type"
                    && diagnostic.path == "/requirements/0/concepts/0/type"),
            "{diagnostics:?}"
        );

        let stray_constraint = adult.replacen(
            "        type: boolean\n",
            "        type: boolean\n        unique: true\n",
            1,
        );
        assert_ne!(
            stray_constraint, adult,
            "the stray constraint mutation applies"
        );
        let diagnostics = bundle_refusal(&stray_constraint);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "config.unknown-key"
                    && diagnostic.path == "/requirements/0/concepts/0/unique"),
            "{diagnostics:?}"
        );

        let unknown_form = adult.replacen("        type: boolean\n", "        type: decimal\n", 1);
        assert_ne!(unknown_form, adult, "the unknown type mutation applies");
        let diagnostics = bundle_refusal(&unknown_form);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "config.unknown-variant"
                    && diagnostic.path == "/requirements/0/concepts/0/type"),
            "{diagnostics:?}"
        );

        EvidenceConfig::parse_yaml(adult.as_bytes()).expect("the tagged boolean form reads");
        EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ))
        .expect("the tagged list forms read");
    }

    #[test]
    fn a_concept_states_its_form_as_type_and_the_old_tag_is_refused() {
        let adult = acceptance_bundle();
        let config = EvidenceConfig::parse_yaml(adult.as_bytes()).expect("the bundle loads");
        let projection = serde_json::to_value(&config).expect("the bundle projects");
        let concept = &projection["requirements"][0]["concepts"][0];
        assert_eq!(concept["type"], "boolean");
        assert!(concept.get("form").is_none());

        assert_union_tag_respelled(
            &adult,
            "        type: boolean\n",
            "        form: boolean\n",
            "/requirements/0/concepts/0/form",
        );
    }

    #[test]
    fn a_bundle_union_is_tagged_by_type_and_each_old_tag_is_refused() {
        let authentication = serde_json::json!({"type": "static-authorization"});
        let pack: registry_adapter_core::EndpointAuthentication =
            serde_json::from_value(authentication.clone()).expect("pack authentication loads");
        let governed: registry_adapter_core::EvidenceAuthenticationPolicy =
            serde_json::from_value(authentication.clone()).expect("governed authentication loads");
        let runtime: registry_adapter_core::RuntimeCredential =
            serde_json::from_value(serde_json::json!({
                "type": "static-authorization",
                "tokenRef": "secret:file/source-token"
            }))
            .expect("runtime credential loads");
        for projection in [
            serde_json::to_value(pack).unwrap(),
            serde_json::to_value(governed).unwrap(),
            serde_json::to_value(runtime).unwrap(),
        ] {
            assert_eq!(projection["type"], "static-authorization");
            assert!(projection.get("kind").is_none());
        }

        let old_authentication = serde_json::json!({"kind": "static-authorization"});
        assert!(
            serde_json::from_value::<registry_adapter_core::EndpointAuthentication>(
                old_authentication.clone()
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<registry_adapter_core::EvidenceAuthenticationPolicy>(
                old_authentication
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<registry_adapter_core::RuntimeCredential>(serde_json::json!({
                "kind": "static-authorization",
                "tokenRef": "secret:file/source-token"
            }))
            .is_err()
        );

        let acquisition: AcquisitionConfig =
            serde_json::from_value(serde_json::json!({"source": "source-a"}))
                .expect("the current acquisition shape loads");
        let projection = serde_json::to_value(acquisition).unwrap();
        assert_eq!(projection, serde_json::json!({"source": "source-a"}));
        for retired_tag in ["type", "kind"] {
            let mut retired = projection.clone();
            retired[retired_tag] = "single".into();
            assert!(
                serde_json::from_value::<AcquisitionConfig>(retired).is_err(),
                "the acquisition reader accepted retired `{retired_tag}`"
            );
        }
    }

    #[test]
    fn a_source_connection_authentication_tagged_by_kind_is_refused() {
        let current = serde_json::json!({
            "endpoints": [{
                "endpoint": "provider",
                "baseUrl": "https://source.invalid",
                "authentication": {"type": "static-authorization"},
                "clientIdentity": "forbidden"
            }]
        });
        let connection: SourceConnectionPolicies =
            serde_json::from_value(current.clone()).expect("the governed policy loads");
        let projection = serde_json::to_value(connection).unwrap();
        assert_eq!(
            projection["endpoints"][0]["authentication"]["type"],
            "static-authorization"
        );
        assert!(projection["endpoints"][0]["authentication"]
            .get("kind")
            .is_none());

        let mut retired = current;
        let authentication = retired["endpoints"][0]["authentication"]
            .as_object_mut()
            .unwrap();
        authentication.remove("type");
        authentication.insert("kind".to_owned(), "static-authorization".into());
        assert!(
            serde_json::from_value::<SourceConnectionPolicies>(retired).is_err(),
            "the governed connection reader accepted authentication tagged by `kind`"
        );
    }

    #[test]
    fn the_access_token_key_source_is_tagged_by_type_and_the_old_tag_is_refused() {
        let valid = acceptance_bundle();
        let config = EvidenceConfig::parse_yaml(valid.as_bytes()).expect("the bundle loads");
        let projection = serde_json::to_value(&config).expect("the bundle projects");
        let key_source = &projection["authentication"]["oidc"]["jwksSource"];
        assert_eq!(key_source["type"], "uri");
        assert!(key_source.get("kind").is_none());

        assert_union_tag_respelled(
            &valid,
            "      type: uri",
            "      kind: uri",
            "/authentication/oidc/jwksSource/kind",
        );
    }

    #[test]
    fn the_keys_of_an_id_keyed_bundle_map_are_shared_local_identifiers() {
        let valid = acceptance_bundle();
        EvidenceConfig::parse_yaml(valid.as_bytes()).expect("fixture validates");
        let overlong = format!("s{}", "a".repeat(64));
        // Each case respells one definition and every reference to it, so the
        // grammar of the key is the only rule the candidate breaks. A name of
        // 65 characters and a name with a dot were both accepted by the
        // grammar these maps had of their own.
        let source = |name: &str| valid.replacen("  source-a:\n", &format!("  {name}:\n"), 1);
        let cases = [
            (
                source("source.a"),
                "source.a",
                Some("/sources/source.a"),
                "evidence.bundle.invalid-source",
                "map key",
            ),
            (
                source(&overlong),
                overlong.as_str(),
                None,
                "evidence.bundle.invalid-source",
                "map key",
            ),
            (
                valid.replacen(
                    "  person-demographics-v1:\n",
                    "  person.demographics-v1:\n",
                    1,
                ),
                "person.demographics-v1",
                Some("/selectorProfiles/person.demographics-v1"),
                "evidence.bundle.invalid-selector-profile",
                "map key",
            ),
            (
                valid.replacen(
                    "  statutory-caseworker-v1:\n",
                    "  statutory.caseworker-v1:\n",
                    1,
                ),
                "statutory.caseworker-v1",
                Some("/authorityProfiles/statutory.caseworker-v1"),
                "evidence.bundle.invalid-authority-profile",
                "map key",
            ),
            (
                valid.replacen("      given_name:\n", "      given.name:\n", 1),
                "given.name",
                None,
                "evidence.bundle.invalid-selector-profile",
                "selector field name",
            ),
            (
                valid.replace("minimum_age_years", "minimum.age.years"),
                "minimum.age.years",
                None,
                "evidence.bundle.invalid-requirement",
                "derivation parameter name",
            ),
        ];
        for (candidate, name, pointer, code, label) in cases {
            assert_ne!(candidate, valid, "{label}: the mutation applies");
            let diagnostics = bundle_refusal(&candidate);
            let refusal = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.message.contains("local identifier"))
                .unwrap_or_else(|| panic!("{label}: no identifier refusal in {diagnostics:?}"));
            assert_eq!(refusal.code, code, "{label}");
            assert!(refusal.message.contains(label), "{label}: {refusal:?}");
            assert!(
                refusal.message.contains("up to 63"),
                "{label}: the grammar is stated: {refusal:?}"
            );
            if let Some(pointer) = pointer {
                assert_eq!(refusal.path, pointer, "{label}");
            }
            let rendered = format!("{} {}", refusal.message, refusal.suggested_action);
            assert!(
                !rendered.contains(name),
                "{label}: the name is not repeated"
            );
        }
    }

    #[test]
    fn a_path_template_placeholder_is_a_shared_local_identifier() {
        assert!(registry_adapter_core::is_placeholder_name("record_ref"));
        assert!(registry_adapter_core::is_placeholder_name("record-ref"));
        for name in ["record.ref", "record ref", "1record", ""] {
            assert!(
                !registry_adapter_core::is_placeholder_name(name),
                "{name:?}"
            );
        }
        assert_eq!(
            registry_adapter_core::placeholders("/records/{{record_ref}}"),
            vec![("record_ref".to_owned(), false)]
        );
    }

    #[test]
    fn the_keys_of_the_runtime_trust_profile_and_extract_maps_are_shared_local_identifiers() {
        let overlong = format!("p{}", "a".repeat(64));
        for name in ["private.ca", overlong.as_str()] {
            let trust = LOADER_RUNTIME_DOCUMENT.replace(
                "  trustProfiles: {}\n",
                &format!("  trustProfiles:\n    {name}: {{caBundleFile: /etc/registry-evidence/ca.pem}}\n"),
            );
            let extract = format!(
                "{LOADER_RUNTIME_DOCUMENT}sourceExtracts:\n  {name}: {{path: /var/lib/registry-evidence/extract.sqlite}}\n"
            );
            for (document, code, map) in [
                (
                    trust,
                    RUNTIME_OUTBOUND_TLS_CODE,
                    "/outboundTls/trustProfiles",
                ),
                (extract, RUNTIME_SOURCE_EXTRACT_CODE, "/sourceExtracts"),
            ] {
                assert_ne!(
                    document, LOADER_RUNTIME_DOCUMENT,
                    "{map}: the mutation applies"
                );
                let config = RuntimeConfig::decode_yaml_with(document.as_bytes(), |_| None)
                    .unwrap_or_else(|error| panic!("{map}: the document decodes: {error:?}"))
                    .config;
                let findings = config.findings();
                let refusal = findings
                    .iter()
                    .find(|finding| finding.pointer == format!("{map}/{name}"))
                    .unwrap_or_else(|| panic!("{map}: the key was not refused"));
                assert_eq!(refusal.code, code, "{map}");
                assert!(refusal.at_key, "{map}: the finding points at the key");
                assert!(
                    refusal.action.contains("at most 64"),
                    "{map}: the grammar is stated"
                );
                let rendered = format!("{} {}", refusal.message(), refusal.action);
                assert!(!rendered.contains(name), "{map}: the name is not repeated");
                assert!(
                    config.validate().is_err(),
                    "{map}: startup refuses the document"
                );
            }
        }
    }

    #[test]
    fn every_removed_bundle_authentication_and_audit_key_is_refused_with_its_replacement_named() {
        let valid = acceptance_bundle();
        EvidenceConfig::parse_yaml(valid.as_bytes()).expect("fixture validates");
        // A pointer with a `*` segment names no one member to stage here; the
        // request-bound tests beside this one cover those entries.
        for removed in EVIDENCE_BUNDLE_REMOVED_KEYS
            .iter()
            .filter(|removed| !removed.pointer.contains('*'))
        {
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
        let candidate =
            valid.replacen("  source-a:\n", "  source-a:\n    unexpectedMember: 1\n", 1);
        assert_ne!(candidate, valid, "the fixture declares a source");
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
            "  secretRef: secret:file/subject-binding-key\n",
            "  secretRef: secret:file/audit-hash-key\n",
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
        assert_eq!(
            source.line,
            Some(line_of(&candidate, "secretRef: secret:file/audit-hash-key"))
        );
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
                    "Evidence reads access-token keys only from jwksSource type uri",
                    "authentication.oidc.jwksSource",
                ))
            );
        }
        let omitted = valid.replace(
            &format!("    jwksSource:\n      type: uri\n      uri: {uri}\n"),
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

    #[test]
    fn retired_acquisition_fields_are_each_refused_without_masking_the_current_source_binding() {
        let baseline = acceptance_fixture();
        EvidenceConfig::parse_yaml(baseline.as_bytes())
            .expect("the current one-source acquisition parses");

        let acquisition_capabilities = edited(
            baseline,
            "kind: EvidenceBundle\n",
            "kind: EvidenceBundle\nacquisitionCapabilities: [search-then-fetch-set]\n",
        );
        assert_eq!(
            decode_cause(&acquisition_capabilities),
            "config.invalid-value"
        );
        // An empty list is tolerated, and ignored, for one release: it leaves
        // the parsed bundle, and so its configuration revision, unchanged.
        let empty_capabilities = edited(
            baseline,
            "kind: EvidenceBundle\n",
            "kind: EvidenceBundle\nacquisitionCapabilities: []\n",
        );
        assert_eq!(
            EvidenceConfig::parse_yaml(empty_capabilities.as_bytes())
                .expect("an empty retired capability list parses"),
            EvidenceConfig::parse_yaml(baseline.as_bytes()).expect("the baseline parses"),
        );
        assert!(
            bundle_contract_validator()
                .is_valid(&bundle_contract_instance(empty_capabilities.as_bytes())),
            "the published bundle schema refused an empty retired capability list"
        );

        let multistage = edited(
            baseline,
            "    acquisition:\n      source: source-a\n",
            "    acquisition:\n      type: search-then-fetch\n      search: source-a\n      fetch: source-b\n",
        );
        assert!(
            EvidenceConfig::parse_yaml(multistage.as_bytes()).is_err(),
            "the retired multistage acquisition parsed"
        );

        let source_batch = edited(
            baseline,
            "    factSchema: schemas/facts.schema.yaml\n",
            "    factSchema: schemas/facts.schema.yaml\n    batch: {maximumItems: 2}\n",
        );
        assert_eq!(decode_cause(&source_batch), "config.removed-key");
    }

    fn holder_bound_bundle() -> String {
        let mut bundle = serde_norway::from_str::<serde_norway::Value>(include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("the audience-scoped fixture parses");
        bundle["service"]["providerId"] = "https://provider.invalid".into();
        bundle["responseFormats"]
            .as_sequence_mut()
            .expect("bundle response formats are a sequence")
            .push("sd-jwt-vc".into());
        let profile = bundle["authorityProfiles"]
            .as_mapping_mut()
            .expect("authority profiles are a mapping")
            .get_mut("statutory-caseworker-v1")
            .expect("the fixture declares its authority profile");
        let grant = profile["grants"]
            .as_sequence_mut()
            .expect("profile grants are a sequence")
            .first_mut()
            .expect("the fixture declares its adult-status grant");
        grant["responseFormats"]
            .as_sequence_mut()
            .expect("grant response formats are a sequence")
            .push("sd-jwt-vc".into());
        grant["subjectBindingModes"] = serde_norway::Value::Sequence(vec!["holder-bound".into()]);
        bundle["requirements"]
            .as_sequence_mut()
            .expect("requirements are a sequence")[0]["subjectBinding"] = "holder-bound".into();
        serde_norway::to_string(&bundle).expect("the holder-bound candidate serializes")
    }

    fn mutate_holder_bundle(edit: impl FnOnce(&mut serde_norway::Value)) -> String {
        let baseline = holder_bound_bundle();
        let mut bundle = serde_norway::from_str::<serde_norway::Value>(&baseline)
            .expect("the holder-bound candidate parses");
        edit(&mut bundle);
        let mutated =
            serde_norway::to_string(&bundle).expect("the holder-bound mutation serializes");
        assert_ne!(mutated, baseline, "the holder-bound mutation applies");
        mutated
    }

    fn first_holder_grant_mut(bundle: &mut serde_norway::Value) -> &mut serde_norway::Value {
        bundle["authorityProfiles"]
            .as_mapping_mut()
            .expect("authority profiles are a mapping")
            .get_mut("statutory-caseworker-v1")
            .expect("the fixture declares its authority profile")["grants"]
            .as_sequence_mut()
            .expect("profile grants are a sequence")
            .first_mut()
            .expect("the fixture declares its adult-status grant")
    }

    fn first_holder_requirement_mut(bundle: &mut serde_norway::Value) -> &mut serde_norway::Value {
        bundle["requirements"]
            .as_sequence_mut()
            .expect("requirements are a sequence")
            .first_mut()
            .expect("the fixture declares its adult-status requirement")
    }

    #[test]
    fn an_undeclared_subject_binding_mode_stays_out_of_the_projected_configuration() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("the acceptance bundle validates");
        assert!(config.maximum_holder_bound_batch_size.is_none());
        assert!(config
            .requirements
            .iter()
            .all(|requirement| requirement.subject_binding.is_none()));
        assert!(config.authority_profiles.iter().all(|(_, profile)| {
            profile
                .grants
                .iter()
                .all(|grant| grant.subject_binding_modes.is_empty())
        }));

        let projected = serde_json::to_value(&config).expect("the configuration projects");
        assert!(
            projected.get("maximumHolderBoundBatchSize").is_none(),
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
        let format_only = mutate_holder_bundle(|document| {
            first_holder_grant_mut(document)
                .as_mapping_mut()
                .expect("the grant is a mapping")
                .remove("subjectBindingModes");
        });
        assert_ne!(format_only, bundle, "the mode withdrawal applies");
        assert!(
            EvidenceConfig::parse_yaml(format_only.as_bytes()).is_err(),
            "a grant permitting the SD-JWT VC serialization silently gained holder-bound issuance"
        );

        // The same grant read directly: it may serialize, and it may not issue.
        let mut audience_scoped = serde_norway::from_str::<serde_norway::Value>(&format_only)
            .expect("the format-only bundle parses as YAML");
        first_holder_requirement_mut(&mut audience_scoped)
            .as_mapping_mut()
            .expect("the requirement is a mapping")
            .remove("subjectBinding");
        let audience_scoped =
            serde_norway::to_string(&audience_scoped).expect("the audience bundle serializes");
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

        let bundle_format = mutate_holder_bundle(|document| {
            document["responseFormats"]
                .as_sequence_mut()
                .expect("bundle response formats are a sequence")
                .retain(|format| format.as_str() != Some("sd-jwt-vc"));
        });
        let grant_format = mutate_holder_bundle(|document| {
            first_holder_grant_mut(document)["responseFormats"]
                .as_sequence_mut()
                .expect("grant response formats are a sequence")
                .retain(|format| format.as_str() != Some("sd-jwt-vc"));
        });
        let grant_mode = mutate_holder_bundle(|document| {
            first_holder_grant_mut(document)
                .as_mapping_mut()
                .expect("the grant is a mapping")
                .remove("subjectBindingModes");
        });
        let audience_scoped_grant = mutate_holder_bundle(|document| {
            first_holder_grant_mut(document)["subjectBindingModes"] =
                serde_norway::Value::Sequence(vec!["audience-scoped".into()]);
        });
        for (name, mutated) in [
            (
                // The bundle half withdraws the one serialization the mode permits.
                "bundle format",
                bundle_format,
            ),
            (
                // The grant half withdraws it while still naming the mode.
                "grant format",
                grant_format,
            ),
            (
                // The grant half withdraws the mode while still permitting the format.
                "grant mode",
                grant_mode,
            ),
            (
                // No grant covers the requirement under the mode at all.
                "grant audience-scoped only",
                audience_scoped_grant,
            ),
        ] {
            assert_ne!(mutated, bundle, "the {name} mutation applies");
            let error = EvidenceConfig::parse_yaml(mutated.as_bytes())
                .expect_err("an unreachable holder-bound requirement was accepted at bundle load");
            assert!(
                !format!("{error}").contains("urn:example:fixture"),
                "the {name} refusal names a configured value"
            );
        }
    }

    #[test]
    fn a_holder_bound_requirement_may_not_disclose_an_entity_reference_value_form() {
        let bundle = holder_bound_bundle();
        for form in [
            "{handle: entity_reference, uri: urn:example:fixture:concept:audience-scoped-entity-reference, type: audience-scoped-entity-reference, required: false, constraints: {maximumBytes: 160}}",
            "{handle: entity_references, uri: urn:example:fixture:concept:entity-reference-list, type: entity-reference-list, required: false, constraints: {minimumItems: 1, maximumItems: 2, unique: true}}",
        ] {
            let concept = serde_norway::from_str::<serde_norway::Value>(form)
                .expect("the candidate concept parses");
            let mutated = mutate_holder_bundle(|document| {
                first_holder_requirement_mut(document)["concepts"]
                    .as_sequence_mut()
                    .expect("requirement concepts are a sequence")
                    .push(concept);
            });
            assert_ne!(mutated, bundle, "the {form} mutation applies");
            let refusal = EvidenceConfig::parse_yaml(mutated.as_bytes())
                .expect_err("a holder-bound requirement disclosed an entity-reference value form");

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
            let mut audience_scoped = serde_norway::from_str::<serde_norway::Value>(&mutated)
                .expect("the mutated bundle parses as YAML");
            first_holder_requirement_mut(&mut audience_scoped)
                .as_mapping_mut()
                .expect("the requirement is a mapping")
                .remove("subjectBinding");
            first_holder_grant_mut(&mut audience_scoped)
                .as_mapping_mut()
                .expect("the grant is a mapping")
                .remove("subjectBindingModes");
            let audience_scoped = serde_norway::to_string(&audience_scoped)
                .expect("the audience-scoped candidate serializes");
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
            let ceiling_value = ceiling.parse::<u64>().expect("the ceiling is an integer");
            let mutated = mutate_holder_bundle(|document| {
                document["maximumHolderBoundBatchSize"] = ceiling_value.into();
            });
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
        assert!(config.authority_profiles.iter().all(|(_, profile)| {
            profile
                .grants
                .iter()
                .all(|grant| grant.response_formats.contains(&ResponseFormat::SignedJws))
        }));
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

        let unknown_requirement_mode = mutate_holder_bundle(|document| {
            first_holder_requirement_mut(document)["subjectBinding"] = "bearer-bound".into();
        });
        let unknown_grant_mode = mutate_holder_bundle(|document| {
            first_holder_grant_mut(document)["subjectBindingModes"] =
                serde_norway::Value::Sequence(vec!["bearer-bound".into()]);
        });
        let repeated_grant_mode = mutate_holder_bundle(|document| {
            first_holder_grant_mut(document)["subjectBindingModes"] =
                serde_norway::Value::Sequence(vec!["holder-bound".into(), "holder-bound".into()]);
        });
        let overlong_grant_modes = mutate_holder_bundle(|document| {
            first_holder_grant_mut(document)["subjectBindingModes"] =
                serde_norway::Value::Sequence(vec![
                    "holder-bound".into(),
                    "audience-scoped".into(),
                    "holder-bound".into(),
                ]);
        });
        for (name, mutated) in [
            ("unknown requirement mode", unknown_requirement_mode),
            ("unknown grant mode", unknown_grant_mode),
            ("repeated grant mode", repeated_grant_mode),
            ("overlong grant mode list", overlong_grant_modes),
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
        let mut normalized = serde_norway::from_str::<serde_norway::Value>(holder_bound)
            .expect("the holder-bound fixture parses");
        assert_eq!(normalized["maximumHolderBoundBatchSize"].as_u64(), Some(4));
        normalized
            .as_mapping_mut()
            .expect("the bundle is a mapping")
            .remove("maximumHolderBoundBatchSize");
        normalized["responseFormats"] =
            serde_norway::Value::Sequence(vec!["signed-jws".into(), "unsigned-json".into()]);
        for profile in normalized["authorityProfiles"]
            .as_mapping_mut()
            .expect("authority profiles are a mapping")
            .values_mut()
        {
            for grant in profile["grants"]
                .as_sequence_mut()
                .expect("profile grants are a sequence")
            {
                assert_eq!(
                    grant["subjectBindingModes"]
                        .as_sequence()
                        .expect("grant modes are a sequence")
                        .len(),
                    1
                );
                grant["responseFormats"] = serde_norway::Value::Sequence(vec![
                    "signed-jws".into(),
                    "unsigned-json".into(),
                ]);
                grant
                    .as_mapping_mut()
                    .expect("the grant is a mapping")
                    .remove("subjectBindingModes");
            }
        }
        for requirement in normalized["requirements"]
            .as_sequence_mut()
            .expect("requirements are a sequence")
        {
            assert_eq!(requirement["subjectBinding"].as_str(), Some("holder-bound"));
            requirement
                .as_mapping_mut()
                .expect("the requirement is a mapping")
                .remove("subjectBinding");
        }
        assert_eq!(
            normalized["service"]["providerId"].as_str(),
            Some("https://provider.invalid")
        );
        normalized["service"]["providerId"] = "urn:example:fixture:provider:evidence".into();
        assert_eq!(
            normalized["service"]["publicOrigin"].as_str(),
            Some("https://provider.invalid")
        );
        normalized["service"]["publicOrigin"] = "https://evidence.invalid".into();
        let normalized =
            serde_norway::to_string(&normalized).expect("the normalized twin serializes");

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
        let mut batch_only = serde_norway::from_str::<serde_norway::Value>(holder_bound)
            .expect("the holder-bound fixture parses");
        let formats = batch_only["responseFormats"]
            .as_sequence_mut()
            .expect("bundle response formats are a sequence");
        let before = formats.len();
        formats.retain(|format| format.as_str() != Some("sd-jwt-vc"));
        assert_eq!(formats.len() + 1, before, "the singular format is removed");
        let batch_only =
            serde_norway::to_string(&batch_only).expect("the batch-only bundle serializes");
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

        let mut urn_provider = serde_norway::from_str::<serde_norway::Value>(&batch_only)
            .expect("the batch-only bundle parses as YAML");
        assert_eq!(
            urn_provider["service"]["providerId"].as_str(),
            Some("https://provider.invalid")
        );
        urn_provider["service"]["providerId"] = "urn:example:fixture:provider:evidence".into();
        let urn_provider =
            serde_norway::to_string(&urn_provider).expect("the URN-provider bundle serializes");
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

    #[test]
    fn access_token_algorithms_accept_exactly_eddsa_es256_and_rs256() {
        const FIXTURE: &str = include_str!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );
        let with = |algorithm: &str| {
            let text = FIXTURE.replace(
                "    algorithms:\n      - ES256\n",
                &format!("    algorithms:\n      - {algorithm}\n"),
            );
            assert!(text.contains(&format!("    algorithms:\n      - {algorithm}\n")));
            EvidenceConfig::parse_yaml(text.as_bytes())
        };
        for accepted in ["EdDSA", "ES256", "RS256"] {
            with(accepted).unwrap_or_else(|error| panic!("{accepted} is accepted: {error}"));
        }
        for rejected in ["ES384", "RS384", "HS256", "PS256", "none", "es256", "EDDSA"] {
            let error = with(rejected).expect_err("an algorithm outside the profile is refused");
            let ConfigError::Refused(report) = error else {
                panic!("{rejected} is refused by the reader, got {error:?}");
            };
            let codes: Vec<&str> = report
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect();
            assert_eq!(codes, ["config.unknown-variant"], "{rejected}");
        }
    }

    mod public_check {
        use super::*;

        fn config() -> EvidenceConfig {
            public_check_test_config()
        }

        #[test]
        fn declaration_is_a_closed_member_of_the_requirement() {
            let config = config();
            let declared = config.requirements[0]
                .public_check
                .as_ref()
                .expect("the fixture declares a public check");
            assert_eq!(declared.check_code_fact, "check_code");
            assert_eq!(declared.status_output, "status");
            assert_eq!(declared.fields_output, "fields");
            config.validate().expect("the declaration validates");

            let mut value = serde_json::to_value(&config).expect("serializes");
            value["requirements"][0]["publicCheck"]["extra"] = true.into();
            assert!(EvidenceConfig::parse_projection(&value).is_err());
        }

        #[test]
        fn an_entity_reference_concept_is_refused() {
            for (form, constraints) in [
                (
                    "audience-scoped-entity-reference",
                    serde_json::json!({"maximumBytes": 160}),
                ),
                (
                    "entity-reference-list",
                    serde_json::json!({"minimumItems": 1, "maximumItems": 2, "unique": true}),
                ),
            ] {
                let mut value = serde_json::to_value(config()).expect("serializes");
                value["requirements"][0]["concepts"]
                    .as_array_mut()
                    .expect("concepts")
                    .push(serde_json::json!({
                        "handle": "owner",
                        "uri": "urn:example:fixture:concept:owner",
                        "type": form,
                        "required": false,
                        "constraints": constraints,
                    }));
                let error = EvidenceConfig::parse_projection(&value)
                    .expect_err("a public check declared an entity-reference concept");
                assert!(
                    format!("{error}")
                        .contains("publicCheck must not declare an entity-reference concept"),
                    "{form}: {error}"
                );
            }
        }

        #[test]
        fn requirement_without_a_declaration_projects_no_member() {
            let mut config = config();
            config.requirements[0].public_check = None;
            let value = serde_json::to_value(&config).expect("serializes");
            assert!(value["requirements"][0].get("publicCheck").is_none());
        }

        #[test]
        fn status_output_must_be_a_controlled_category() {
            let mut config = config();
            config.requirements[0]
                .public_check
                .as_mut()
                .unwrap()
                .status_output = "relying_only".to_owned();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::Invalid(
                    "publicCheck statusOutput must name a controlled-category concept"
                ))
            ));
            config.requirements[0]
                .public_check
                .as_mut()
                .unwrap()
                .status_output = "missing".to_owned();
            assert!(config.validate().is_err());
        }

        #[test]
        fn fields_output_must_be_a_reviewed_structured_value() {
            let mut config = config();
            config.requirements[0]
                .public_check
                .as_mut()
                .unwrap()
                .fields_output = "relying_only".to_owned();
            assert!(matches!(
                config.validate(),
                Err(ConfigError::Invalid(
                    "publicCheck fieldsOutput must name a reviewed-structured-value concept"
                ))
            ));
        }

        #[test]
        fn status_and_fields_must_be_two_outputs() {
            let mut config = config();
            config.requirements[0]
                .public_check
                .as_mut()
                .unwrap()
                .fields_output = "status".to_owned();
            assert!(config.validate().is_err());
        }

        #[test]
        fn definition_with_extra_outputs_still_validates() {
            config()
                .validate()
                .expect("an extra relying-only concept is allowed");
        }

        #[test]
        fn subject_must_be_one_role_one_profile_one_field() {
            let mut two_fields = config();
            let profile = &mut two_fields.selector_profiles.0[0].1;
            let field = profile.fields.0[0].1.clone();
            profile.fields.0.push(("second".to_owned(), field));
            assert!(matches!(
                two_fields.validate(),
                Err(ConfigError::Invalid(
                    "publicCheck requires one subject role with one selector profile that has one text field"
                ))
            ));

            let mut two_roles = config();
            let role = two_roles.requirements[0].subject_roles[0].clone();
            let mut second = role;
            second.role = "other".to_owned();
            two_roles.requirements[0].subject_roles.push(second);
            assert!(two_roles.validate().is_err());
        }

        #[test]
        fn subject_field_must_take_the_number_as_text() {
            for field in [
                SelectorField::Integer {
                    minimum: 1,
                    maximum: 999_999,
                },
                SelectorField::Boolean {},
            ] {
                let mut config = config();
                config.selector_profiles.0[0].1.fields.0[0].1 = field;
                assert!(matches!(
                    config.validate(),
                    Err(ConfigError::Invalid(
                        "publicCheck requires one subject role with one selector profile that has one text field"
                    ))
                ));
            }
        }

        #[test]
        fn acquisition_must_be_one_source_without_holder_presented() {
            let mut config = config();
            let source = config.requirements[0]
                .acquisition
                .initial_source()
                .to_owned();
            config.requirements[0].acquisition.holder_presented =
                Some(HolderPresentedAcquisition {
                    source,
                    selector_profiles: vec!["person-demographics-v1".to_owned()],
                });
            assert!(matches!(
                config.requirements[0].validate_public_check(),
                Err(ConfigError::Invalid(
                    "publicCheck requires one Source and no holderPresented acquisition"
                ))
            ));
        }

        /// An activated check-only authority has no profiles, yet it is not
        /// "no authority": the activated requirement's source must still be
        /// able to fill its route inputs from the public subject.
        #[test]
        fn activated_check_only_authority_is_not_the_no_authority_sentinel() {
            let mut config = config();
            let uri = config.requirements[0].id.clone();
            let incomplete = SourceInputPresenceContract::new(
                SourceInputPresenceRequirement::Required(BTreeSet::from([
                    "no_such_input".to_owned()
                ])),
                None,
            );
            let contracts = BTreeMap::from([("source-a".to_owned(), incomplete)]);

            config
                .validate_source_authority_paths(&contracts)
                .expect("with no activation, an empty profile map means no authority yet");

            config.public_check_requirement = Some(uri.clone());
            config
                .validate_source_authority_paths(&contracts)
                .expect_err("an activated check-only authority is checked against the route");
            assert_eq!(
                config.source_selector_sets("source-a"),
                vec![vec![(
                    "subject".to_owned(),
                    "person-demographics-v1".to_owned()
                )]]
            );
            let activation = config
                .public_check_activation()
                .expect("the activation is exposed");
            assert_eq!(activation.requirement, uri);
            assert_eq!(activation.status_output, "status");
            assert_eq!(activation.fields_output, "fields");
            assert_eq!(activation.check_code_fact, "check_code");
        }

        #[test]
        fn activation_is_absent_when_no_requirement_is_activated() {
            assert!(config().public_check_activation().is_none());
        }
    }
}
