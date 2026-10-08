//! Bounded, strict loading of an operator runtime configuration document.
//!
//! Every Registry Stack runtime reads its `runtime.yaml` through
//! [`RuntimeConfigLoader`], so the same file rules, the same reader and the
//! same environment substitution apply everywhere:
//!
//! 1. the path is absolute and lexically normal, and no component of it is a
//!    symbolic link;
//! 2. the file is a regular file of at most the configured size, opened without
//!    following a link and checked to be the same file before and after the
//!    read;
//! 3. the shared configuration reader (`registry-platform-yaml`) checks the
//!    bytes: UTF-8, at most 1 MiB, and one document in the shared YAML subset.
//!    `${NAME}`, `${NAME:-fallback}` and `${NAME:?message}` are substituted in
//!    string values while the reader builds the document, so a diagnostic
//!    about a substituted value points at the text as written (CFG-SEC-2);
//! 4. `apiVersion` and `kind` must be literally the product's envelope;
//! 5. removed keys are refused with a diagnostic naming their replacement;
//! 6. the document is decoded into the product's typed configuration; every
//!    unknown and removed key is reported, and decoding stops at the first
//!    other error.
//!
//! Substitution is refused in keys, in `apiVersion` and `kind`, in every
//! member whose key ends in `Ref` or `Refs` and everything below it, and
//! everywhere under `secretProviders`. A substituted value is text: it fills a
//! string member and never an integer or boolean one (CFG-VAL-3). There is no
//! escape syntax, and substitution is a single pass, so a literal `${` reaches
//! the configuration as the value of a variable. `${` followed by a name
//! character or `}` starts an expression, and one that is not well formed is
//! refused; any other `${` is text.
//!
//! A refusal is a [`RuntimeConfigError`] carrying the reader's diagnostics
//! (CFG-DIAG-1). No refusal repeats a configured or substituted value; a
//! substitution refusal names the environment variable and nothing else.

use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use registry_platform_yaml::{
    escape_pointer_segment, ApiVersion, Diagnostic, EnvelopeRule, Expect, FormatSpec, Reader,
    Refusal, RemovedKey as RemovedPointer, Report, RetiredApiVersion, ScalarHook, ScalarSite,
    Severity, Source,
};
use serde::de::DeserializeOwned;

use crate::{resolve_config_env_expression, sha256_uri};

/// The default size cap for a runtime configuration document.
pub const DEFAULT_MAX_RUNTIME_CONFIG_BYTES: u64 = 1024 * 1024;

/// The longest runtime configuration path the loader accepts, in bytes.
pub const MAX_RUNTIME_CONFIG_PATH_BYTES: usize = 4096;

/// The name diagnostics carry for a document checked from text rather than a
/// file, such as an unsaved buffer.
const BUFFER_NAME: &str = "runtime.yaml";

/// The name diagnostics carry for an authored document checked from text.
const AUTHORED_BUFFER_NAME: &str = "authored file";

/// The `apiVersion` and `kind` a product's runtime configuration carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeEnvelope {
    pub api_version: &'static str,
    pub kind: &'static str,
}

/// A key a runtime configuration no longer accepts, and what replaced it.
///
/// `path` is dotted from the document root; a `*` segment matches any mapping
/// key or sequence index. `replacement` names what to write instead; it is the
/// refusal's suggested action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemovedKey {
    pub path: &'static str,
    pub replacement: &'static str,
}

/// The single-URL JWKS key the shared OIDC issuer block replaced with
/// `jwksSource`, for a runtime whose issuer block sits at `authentication.oidc`.
pub const REMOVED_OIDC_JWKS_URI: RemovedKey = RemovedKey {
    path: "authentication.oidc.jwksUri",
    replacement: "declare authentication.oidc.jwksSource with kind: uri and uri: <https URL>",
};

/// What kind of rule a runtime configuration broke.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigErrorKind {
    /// The configured path is not absolute and lexically normal.
    Path,
    /// A path component is a symbolic link, the file is not a regular file, or
    /// it changed while it was read.
    UnsafeFile,
    /// The file could not be read.
    Unavailable,
    /// The file is empty or larger than the cap.
    Bounds,
    /// The file is not UTF-8.
    Encoding,
    /// The document is not in the shared YAML subset, or is not a mapping.
    Syntax,
    /// A removed key is present.
    RemovedKey,
    /// `apiVersion` or `kind` is not the product's envelope.
    Envelope,
    /// An environment expression could not be substituted.
    Substitution,
    /// An environment expression appears where substitution is refused: a
    /// key, a secret-reference field, or anything under `secretProviders`.
    SubstitutionInReference,
    /// A value does not satisfy the product's typed configuration.
    InvalidValue,
    /// An authored project file holds an environment expression.
    AuthoredExpression,
    /// An authored project file is not YAML the environment-expression check
    /// can read.
    AuthoredSyntax,
}

impl RuntimeConfigErrorKind {
    /// The stable diagnostic code for this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Path => "runtime_config.path",
            Self::UnsafeFile => "runtime_config.unsafe_file",
            Self::Unavailable => "runtime_config.unavailable",
            Self::Bounds => "runtime_config.bounds",
            Self::Encoding => "runtime_config.encoding",
            Self::Syntax => "runtime_config.syntax",
            Self::RemovedKey => "runtime_config.removed_key",
            Self::Envelope => "runtime_config.envelope",
            Self::Substitution => "runtime_config.substitution",
            Self::SubstitutionInReference => "runtime_config.substitution_in_reference",
            Self::InvalidValue => "runtime_config.invalid_value",
            Self::AuthoredExpression => "authored_config.environment_expression",
            Self::AuthoredSyntax => "authored_config.syntax",
        }
    }
}

/// When a refusal carries several diagnostics, the kind of the first error of
/// the earliest kind in this order is the refusal's kind.
const RUNTIME_PRECEDENCE: [RuntimeConfigErrorKind; 8] = [
    RuntimeConfigErrorKind::Bounds,
    RuntimeConfigErrorKind::Encoding,
    RuntimeConfigErrorKind::Syntax,
    RuntimeConfigErrorKind::Envelope,
    RuntimeConfigErrorKind::SubstitutionInReference,
    RuntimeConfigErrorKind::Substitution,
    RuntimeConfigErrorKind::RemovedKey,
    RuntimeConfigErrorKind::InvalidValue,
];

/// An authored file that the reader cannot read is refused before one that
/// only holds an expression, so a file never passes unchecked.
const AUTHORED_PRECEDENCE: [RuntimeConfigErrorKind; 2] = [
    RuntimeConfigErrorKind::AuthoredSyntax,
    RuntimeConfigErrorKind::AuthoredExpression,
];

/// Codes of the refusals the loader reports itself, before the reader runs
/// (CFG-DIAG-3).
const CODE_PATH: &str = "platform.runtime-config.path";
const CODE_UNSAFE_FILE: &str = "platform.runtime-config.unsafe-file";
const CODE_UNAVAILABLE: &str = "platform.runtime-config.unavailable";
const CODE_SIZE: &str = "platform.runtime-config.size";

/// The reader's code for a `${...}` expression written where substitution is
/// refused.
const CODE_NOT_ALLOWED: &str = "config.substitution-not-allowed";
/// The reader's code for a `${...}` expression that cannot be substituted.
const CODE_SUBSTITUTION: &str = "config.substitution";

/// A refused runtime configuration: which rule broke, at which field, and
/// the diagnostics that say where and what to do (CFG-DIAG-1). No part of it
/// repeats a configured value.
///
/// `Display` renders every diagnostic in the human form (CFG-DIAG-2).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{}", self.render())]
pub struct RuntimeConfigError {
    kind: RuntimeConfigErrorKind,
    /// Boxed, so the products' error types that carry a refusal stay small.
    detail: Box<RefusalDetail>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RefusalDetail {
    file: Option<PathBuf>,
    field: String,
    message: String,
    diagnostics: Vec<Diagnostic>,
    /// The index of the diagnostic the kind, field, and message come from.
    deciding: usize,
}

impl RuntimeConfigError {
    /// A refusal about the file as a whole, found before the reader ran.
    fn file_level(
        kind: RuntimeConfigErrorKind,
        code: &str,
        message: impl Into<String>,
        suggested_action: impl Into<String>,
    ) -> Self {
        Self::from_diagnostics(
            vec![Diagnostic::error(code, "", message, suggested_action)],
            |_| kind,
            &[kind],
        )
    }

    fn from_diagnostics(
        diagnostics: Vec<Diagnostic>,
        classify: impl Fn(&Diagnostic) -> RuntimeConfigErrorKind,
        precedence: &[RuntimeConfigErrorKind],
    ) -> Self {
        let rank = |kind: RuntimeConfigErrorKind| {
            precedence
                .iter()
                .position(|candidate| *candidate == kind)
                .unwrap_or(precedence.len())
        };
        let deciding = diagnostics
            .iter()
            .enumerate()
            .filter(|(_, diagnostic)| diagnostic.severity == Severity::Error)
            .min_by_key(|(_, diagnostic)| rank(classify(diagnostic)))
            .map_or(0, |(index, _)| index);
        let decided = diagnostics
            .get(deciding)
            .expect("a refusal carries at least one diagnostic");
        let kind = classify(decided);
        let field = dotted(&decided.path);
        let message = one_line(&field, decided);
        Self {
            kind,
            detail: Box::new(RefusalDetail {
                file: None,
                field,
                message,
                diagnostics,
                deciding,
            }),
        }
    }

    fn from_runtime_report(report: Report) -> Self {
        Self::from_diagnostics(report.into_diagnostics(), runtime_kind, &RUNTIME_PRECEDENCE)
    }

    fn from_authored_report(report: Report) -> Self {
        Self::from_diagnostics(
            report.into_diagnostics(),
            authored_kind,
            &AUTHORED_PRECEDENCE,
        )
    }

    /// The reader reports a missing envelope member at the mapping that
    /// lacks it, the root; the field names the member itself, `apiVersion`
    /// before `kind`, as consumers match on it.
    fn naming_missing_envelope_member(mut self, file: &str, bytes: &[u8]) -> Self {
        if self.kind == RuntimeConfigErrorKind::Envelope && self.detail.field == "/" {
            let has_api_version = matches!(
                Reader::new(file).scan(bytes),
                Ok(Some(root)) if root.get("apiVersion").is_some()
            );
            let member = if has_api_version {
                "kind"
            } else {
                "apiVersion"
            };
            self.detail.field = member.to_owned();
        }
        self
    }

    /// Name `file` as the refused file, and as the source of every
    /// diagnostic that did not name one.
    fn in_file(mut self, file: &Path) -> Self {
        let name = file.display().to_string();
        for diagnostic in &mut self.detail.diagnostics {
            if diagnostic.source.is_none() {
                diagnostic.source = Some(Source {
                    file: name.clone(),
                    line: None,
                    column: None,
                });
            }
        }
        self.detail.file = Some(file.to_owned());
        self
    }

    #[must_use]
    pub const fn kind(&self) -> RuntimeConfigErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// The runtime configuration file, when the refusal came from one.
    #[must_use]
    pub fn file(&self) -> Option<&Path> {
        self.detail.file.as_deref()
    }

    /// The dotted field the refusal concerns; `/` for the whole document.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.detail.field
    }

    /// The deciding diagnostic on one line, without the file: the dotted
    /// field, the message, and after `next:` the suggested action.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.detail.message
    }

    /// Every diagnostic the refusal carries, in the order the reader
    /// reported them: the first error of each structural kind, every unknown
    /// and removed key, and the first other decoding error (CFG-DIAG-5).
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.detail.diagnostics
    }

    /// The diagnostic the kind, field, and message come from: the first
    /// error of the earliest kind. A consumer that words the refusal itself
    /// classifies it by this diagnostic's code and path.
    #[must_use]
    pub fn deciding_diagnostic(&self) -> &Diagnostic {
        self.detail
            .diagnostics
            .get(self.detail.deciding)
            .expect("the deciding index is within the diagnostics")
    }

    fn render(&self) -> String {
        let mut rendered: String = self
            .detail
            .diagnostics
            .iter()
            .map(Diagnostic::render_human)
            .collect();
        rendered.truncate(rendered.trim_end().len());
        rendered
    }
}

/// The kind of a runtime-file diagnostic, by its reader code and path.
fn runtime_kind(diagnostic: &Diagnostic) -> RuntimeConfigErrorKind {
    let envelope_member = diagnostic.path == "/apiVersion" || diagnostic.path == "/kind";
    match diagnostic.code.as_str() {
        "yaml.too-large" => RuntimeConfigErrorKind::Bounds,
        "yaml.not-utf8" => RuntimeConfigErrorKind::Encoding,
        code if code.starts_with("yaml.") => RuntimeConfigErrorKind::Syntax,
        "config.invalid-type" if diagnostic.path.is_empty() => RuntimeConfigErrorKind::Syntax,
        "config.missing-envelope"
        | "config.wrong-kind"
        | "config.unsupported-api-version"
        | "config.retired-api-version"
        | "config.deprecated-api-version" => RuntimeConfigErrorKind::Envelope,
        "config.expected-string" | "config.null-value" | CODE_NOT_ALLOWED if envelope_member => {
            RuntimeConfigErrorKind::Envelope
        }
        CODE_NOT_ALLOWED => RuntimeConfigErrorKind::SubstitutionInReference,
        CODE_SUBSTITUTION => RuntimeConfigErrorKind::Substitution,
        "config.removed-key" => RuntimeConfigErrorKind::RemovedKey,
        _ => RuntimeConfigErrorKind::InvalidValue,
    }
}

/// The kind of an authored-file diagnostic: an expression the hook refused,
/// or anything else the reader could not read.
fn authored_kind(diagnostic: &Diagnostic) -> RuntimeConfigErrorKind {
    if diagnostic.code == CODE_NOT_ALLOWED {
        RuntimeConfigErrorKind::AuthoredExpression
    } else {
        RuntimeConfigErrorKind::AuthoredSyntax
    }
}

/// `field: message; next: action`, or without the field for the whole
/// document.
fn one_line(field: &str, diagnostic: &Diagnostic) -> String {
    let message = diagnostic.message.trim_end_matches('.');
    let action = &diagnostic.suggested_action;
    if field == "/" {
        format!("{message}; next: {action}")
    } else {
        format!("{field}: {message}; next: {action}")
    }
}

/// An RFC 6901 pointer as the dotted field the loader has always reported;
/// `/` for the root.
fn dotted(pointer: &str) -> String {
    match pointer.strip_prefix('/') {
        None => "/".to_owned(),
        Some(rest) => rest
            .split('/')
            .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
            .collect::<Vec<_>>()
            .join("."),
    }
}

/// A dotted removed-key path as the reader's pointer.
fn pointer_of(dotted: &str) -> String {
    dotted
        .split('.')
        .map(|segment| format!("/{}", escape_pointer_segment(segment)))
        .collect()
}

/// A loaded runtime configuration and the digest of what the runtime runs.
#[derive(Clone, Debug)]
pub struct LoadedRuntimeConfig<T> {
    pub config: T,
    /// `sha256:` label over the RFC 8785 canonical JSON of the document after
    /// substitution: two files that differ only in comments, layout or the
    /// spelling of an environment expression that resolved to the same value
    /// carry the same digest.
    pub effective_digest: String,
}

/// Loads one product's runtime configuration under the shared rules.
#[derive(Clone, Debug)]
pub struct RuntimeConfigLoader {
    envelope: RuntimeEnvelope,
    removed_keys: &'static [RemovedKey],
    retired_api_versions: &'static [RetiredApiVersion<'static>],
    max_bytes: u64,
    trusted_ownership: bool,
}

impl RuntimeConfigLoader {
    #[must_use]
    pub const fn new(envelope: RuntimeEnvelope) -> Self {
        Self {
            envelope,
            removed_keys: &[],
            retired_api_versions: &[],
            max_bytes: DEFAULT_MAX_RUNTIME_CONFIG_BYTES,
            trusted_ownership: false,
        }
    }

    /// Refuse each of these keys with a diagnostic naming its replacement.
    #[must_use]
    pub const fn removed_keys(mut self, removed_keys: &'static [RemovedKey]) -> Self {
        self.removed_keys = removed_keys;
        self
    }

    /// Refuse each of these `apiVersion` values with
    /// `config.retired-api-version` and the sentence naming what to write
    /// instead (CFG-CHANGE-2).
    #[must_use]
    pub const fn retired_api_versions(
        mut self,
        retired_api_versions: &'static [RetiredApiVersion<'static>],
    ) -> Self {
        self.retired_api_versions = retired_api_versions;
        self
    }

    /// Change the size cap of the file read. The shared reader refuses a
    /// document larger than 1 MiB whatever this cap (CFG-YAML-6), so a cap
    /// above that has no further effect.
    #[must_use]
    pub const fn max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Additionally require every directory above the file to be owned by root
    /// or the effective user and not writable by group or others (a root-owned
    /// sticky directory excepted), and the file itself to be owned by root or
    /// the effective user and not writable by group or others. Platforms
    /// without Unix ownership refuse every file under this rule.
    #[must_use]
    pub const fn require_trusted_ownership(mut self) -> Self {
        self.trusted_ownership = true;
        self
    }

    #[must_use]
    pub const fn envelope(&self) -> RuntimeEnvelope {
        self.envelope
    }

    /// Load `path`, substituting environment expressions from the process
    /// environment.
    pub fn load<T: DeserializeOwned>(
        &self,
        path: &Path,
    ) -> Result<LoadedRuntimeConfig<T>, RuntimeConfigError> {
        self.load_with(path, |name| std::env::var(name).ok())
    }

    /// Load `path`, substituting environment expressions from `lookup`.
    pub fn load_with<T: DeserializeOwned>(
        &self,
        path: &Path,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<LoadedRuntimeConfig<T>, RuntimeConfigError> {
        let bytes = self.read(path).map_err(|error| error.in_file(path))?;
        self.parse(&path.display().to_string(), &bytes, &lookup)
            .map_err(|error| error.in_file(path))
    }

    /// Apply every rule after the file read to `text`. Used by authoring tools
    /// that check an unsaved buffer, and by tests. Diagnostics name the
    /// buffer `runtime.yaml`.
    pub fn parse_str<T: DeserializeOwned>(
        &self,
        text: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<LoadedRuntimeConfig<T>, RuntimeConfigError> {
        self.parse(BUFFER_NAME, text.as_bytes(), &lookup)
    }

    fn parse<T: DeserializeOwned>(
        &self,
        file: &str,
        bytes: &[u8],
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<LoadedRuntimeConfig<T>, RuntimeConfigError> {
        let removed: Vec<(String, String)> = self
            .removed_keys
            .iter()
            .map(|removed| (pointer_of(removed.path), sentence(removed.replacement)))
            .collect();
        let removed: Vec<RemovedPointer<'_>> = removed
            .iter()
            .map(|(pointer, replacement)| RemovedPointer {
                pointer,
                replacement,
            })
            .collect();
        let api_versions = [ApiVersion::current(self.envelope.api_version)];
        let format = FormatSpec {
            kind: self.envelope.kind,
            envelope: EnvelopeRule::ApiVersionKind {
                api_versions: &api_versions,
                retired_api_versions: self.retired_api_versions,
            },
            removed_keys: &removed,
        };
        let mut substitution = Substitution { lookup };
        let decoded = Reader::new(file)
            .with_hook(&mut substitution)
            .decode::<T>(bytes, &Expect::one(&format))
            .map_err(|report| {
                RuntimeConfigError::from_runtime_report(report)
                    .naming_missing_envelope_member(file, bytes)
            })?;
        let canonical =
            registry_platform_canonical_json::canonicalize_json(&decoded.document.to_json_value())
                .map_err(|_| {
                    RuntimeConfigError::file_level(
                        RuntimeConfigErrorKind::InvalidValue,
                        "platform.runtime-config.canonical-form",
                        "the runtime configuration holds a value that has no canonical JSON form",
                        "Write every number as a plain decimal within the range JSON can carry.",
                    )
                })?;
        Ok(LoadedRuntimeConfig {
            config: decoded.value,
            effective_digest: sha256_uri(&canonical),
        })
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, RuntimeConfigError> {
        validate_absolute_lexical_path(path)?;
        reject_symlink_components(path)?;
        if self.trusted_ownership {
            require_trusted_ownership(path)?;
        }
        read_bounded(path, self.max_bytes)
    }
}

/// A removed key's replacement as a suggested action: the text as the
/// product wrote it, ending in a full stop.
fn sentence(replacement: &str) -> String {
    let replacement = replacement.trim_end();
    if replacement.ends_with('.') {
        replacement.to_owned()
    } else {
        format!("{replacement}.")
    }
}

/// Whether `text` holds an environment expression the runtime loader would
/// substitute: `${NAME}`, `${NAME:-...}` or `${NAME:?...}` with `NAME` a valid
/// environment variable name.
#[must_use]
pub fn contains_environment_expression(text: &str) -> bool {
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let name_end = after
            .find(|character: char| character != '_' && !character.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        let name = &after[..name_end];
        let tail = &after[name_end..];
        if crate::valid_env_key(name)
            && (tail.starts_with('}') || tail.starts_with(":-") || tail.starts_with(":?"))
        {
            return true;
        }
        rest = after;
    }
    false
}

/// Whether the text after a `${` makes it the start of an expression: a name
/// character or `}`. Any other `${` is text.
fn opens_expression(after: &str) -> bool {
    after.starts_with(|character: char| {
        character == '_' || character == '}' || character.is_ascii_alphanumeric()
    })
}

/// Whether `text` holds a `${` that starts an expression.
fn has_expression_start(text: &str) -> bool {
    text.match_indices("${")
        .any(|(start, _)| opens_expression(&text[start + 2..]))
}

/// Refuse an authored project file that holds an environment expression in a
/// key or a string value.
///
/// Environment substitution applies to `runtime.yaml` only. An authored file
/// is reviewed and packaged as written, so an expression in it would either be
/// taken literally or make the reviewed text differ from what runs. The file
/// is read by the shared reader without an envelope, and a file the reader
/// refuses is refused here, so a file never passes unchecked because a
/// product's parser accepts what this reader does not. Text that is not an
/// expression, such as a lone `${`, is accepted.
///
/// There is no escape for a literal `${NAME}` in an authored file.
pub fn reject_environment_expressions_in_authored_yaml(
    text: &str,
) -> Result<(), RuntimeConfigError> {
    let mut hook = AuthoredExpressions;
    Reader::new(AUTHORED_BUFFER_NAME)
        .with_hook(&mut hook)
        .scan(text.as_bytes())
        .map(|_| ())
        .map_err(RuntimeConfigError::from_authored_report)
}

/// Refuses every environment expression in a key or text value of an
/// authored file (CFG-SEC-2), as a [`ScalarHook`] a product passes to the
/// shared reader that decodes the file.
pub struct AuthoredExpressions;

impl AuthoredExpressions {
    fn check(text: &str) -> Result<(), Refusal> {
        if contains_environment_expression(text) {
            return Err(refusal(
                CODE_NOT_ALLOWED,
                "a `${...}` expression is written in an authored file; substitution applies to \
                 runtime.yaml only",
                "Write the value in the authored file directly.",
            ));
        }
        Ok(())
    }
}

impl ScalarHook for AuthoredExpressions {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        Self::check(site.text)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Self::check(site.text).map(|()| None)
    }
}

fn refusal(code: &str, message: impl Into<String>, suggested_action: impl Into<String>) -> Refusal {
    Refusal {
        code: code.to_owned(),
        message: message.into(),
        suggested_action: suggested_action.into(),
    }
}

/// Substitutes environment expressions in an operator file's string values
/// while the reader builds the document (CFG-SEC-2).
struct Substitution<'l> {
    lookup: &'l dyn Fn(&str) -> Option<String>,
}

/// Why substitution is refused at a value.
enum Literal<'k> {
    /// `apiVersion` or `kind` at the root.
    Envelope(&'k str),
    /// A member whose key ends in `Ref` or `Refs`, or a value below one.
    Reference(&'k str),
    /// A value under `secretProviders`. A provider setting chooses which
    /// secret a reference resolves to, so substitution is refused under it as
    /// it is in a reference.
    SecretProvider,
}

impl Literal<'_> {
    fn refusal(&self) -> Refusal {
        match self {
            Literal::Envelope(member) => refusal(
                CODE_NOT_ALLOWED,
                format!("{member} is never filled by substitution"),
                format!("Write {member} in the file as plain text."),
            ),
            Literal::Reference(key) => refusal(
                CODE_NOT_ALLOWED,
                format!("`{key}` holds secret references, which are never filled by substitution"),
                "Write the reference itself, as secret:env/NAME or secret:file/name.",
            ),
            Literal::SecretProvider => refusal(
                CODE_NOT_ALLOWED,
                "a secret provider setting is never filled by substitution",
                "Write the setting in runtime.yaml as plain text.",
            ),
        }
    }
}

/// The first reason, from the root down, that substitution is refused at
/// the value `site` describes.
fn literal_at<'k>(site: &ScalarSite<'k>) -> Option<Literal<'k>> {
    if let [member @ ("apiVersion" | "kind")] = site.keys {
        if site.pointer == format!("/{member}") {
            return Some(Literal::Envelope(member));
        }
    }
    site.keys.iter().find_map(|key| {
        if *key == "secretProviders" {
            Some(Literal::SecretProvider)
        } else if key.ends_with("Ref") || key.ends_with("Refs") {
            Some(Literal::Reference(key))
        } else {
            None
        }
    })
}

impl ScalarHook for Substitution<'_> {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        if has_expression_start(site.text) {
            return Err(refusal(
                CODE_NOT_ALLOWED,
                "a key is never filled by substitution",
                "Write the key as plain text; substitution fills string values only.",
            ));
        }
        Ok(())
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        if !has_expression_start(site.text) {
            return Ok(None);
        }
        if let Some(literal) = literal_at(site) {
            return Err(literal.refusal());
        }
        substitute_string(site.text, self.lookup).map(Some)
    }
}

fn malformed_expression() -> Refusal {
    refusal(
        CODE_SUBSTITUTION,
        "the `${...}` expression is not well formed",
        "Write ${NAME}, ${NAME:-fallback}, or ${NAME:?message}, where NAME is letters, digits, \
         and underscores and does not start with a digit.",
    )
}

/// Substitute every expression in `text` in one pass. A refusal names the
/// variable and never its value or a `:?` message.
fn substitute_string(
    text: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String, Refusal> {
    let mut substituted = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        substituted.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        if !opens_expression(after_start) {
            substituted.push_str("${");
            rest = after_start;
            continue;
        }
        let Some(end) = after_start.find('}') else {
            return Err(malformed_expression());
        };
        let expression = &after_start[..end];
        let (name, value) = match resolve_config_env_expression(expression, lookup) {
            Ok(resolved) => resolved,
            Err(_) => return Err(unresolved(expression)),
        };
        if value.contains('\0') {
            return Err(refusal(
                CODE_SUBSTITUTION,
                format!("the environment variable {name} holds a NUL byte"),
                format!("Remove the NUL byte from {name}."),
            ));
        }
        substituted.push_str(&value);
        rest = &after_start[end + 1..];
    }
    substituted.push_str(rest);
    Ok(substituted)
}

/// The refusal for an expression that did not resolve: malformed, or a
/// variable that is unset or empty without a fallback. The expression is
/// split the way `resolve_config_env_expression` splits it.
fn unresolved(expression: &str) -> Refusal {
    let (name, message) = if let Some((name, _)) = expression.split_once(":-") {
        (name, None)
    } else if let Some((name, message)) = expression.split_once(":?") {
        (name, Some(message))
    } else {
        (expression, None)
    };
    if !crate::valid_env_key(name) {
        return malformed_expression();
    }
    match message {
        Some(message) if !message.trim().is_empty() => refusal(
            CODE_SUBSTITUTION,
            format!(
                "the environment variable {name} is unset or empty; the message written for it \
                 is withheld"
            ),
            format!("Set {name} in the runtime's environment."),
        ),
        Some(_) => refusal(
            CODE_SUBSTITUTION,
            format!("the environment variable {name} is unset or empty"),
            format!("Set {name} in the runtime's environment."),
        ),
        None => refusal(
            CODE_SUBSTITUTION,
            format!("the environment variable {name} is unset or empty"),
            format!(
                "Set {name} in the runtime's environment, or write a fallback as \
                 ${{{name}:-fallback}}."
            ),
        ),
    }
}

fn unsafe_file(message: &str, suggested_action: &str) -> RuntimeConfigError {
    RuntimeConfigError::file_level(
        RuntimeConfigErrorKind::UnsafeFile,
        CODE_UNSAFE_FILE,
        message,
        suggested_action,
    )
}

fn unavailable() -> RuntimeConfigError {
    RuntimeConfigError::file_level(
        RuntimeConfigErrorKind::Unavailable,
        CODE_UNAVAILABLE,
        "the runtime configuration could not be read",
        "Check that the file exists and that the runtime user can read it.",
    )
}

fn out_of_bounds(maximum: u64) -> RuntimeConfigError {
    RuntimeConfigError::file_level(
        RuntimeConfigErrorKind::Bounds,
        CODE_SIZE,
        format!("the runtime configuration must be between 1 and {maximum} bytes"),
        format!(
            "Give a runtime configuration that is not empty and holds at most {maximum} bytes."
        ),
    )
}

fn not_regular() -> RuntimeConfigError {
    unsafe_file(
        "the runtime configuration must be a regular file",
        "Point the path at a regular file.",
    )
}

fn changed() -> RuntimeConfigError {
    unsafe_file(
        "the runtime configuration changed while it was read",
        "Load the runtime configuration again once nothing is writing to it.",
    )
}

fn validate_absolute_lexical_path(path: &Path) -> Result<(), RuntimeConfigError> {
    let normal = !path.as_os_str().is_empty()
        && path.is_absolute()
        && path.as_os_str().len() <= MAX_RUNTIME_CONFIG_PATH_BYTES
        && !has_current_directory_component(path)
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        });
    if normal {
        Ok(())
    } else {
        Err(RuntimeConfigError::file_level(
            RuntimeConfigErrorKind::Path,
            CODE_PATH,
            "the runtime configuration path must be absolute, without . or .. components",
            "Give the absolute path of the runtime configuration file, without . or .. \
             components.",
        ))
    }
}

/// `Path::components` drops interior `.` components, so they are found in the
/// raw path instead.
fn has_current_directory_component(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .split(|byte| std::path::is_separator(char::from(*byte)))
        .any(|component| component == b".")
}

/// Refuse a path any of whose components is a symbolic link.
fn reject_symlink_components(path: &Path) -> Result<(), RuntimeConfigError> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        checked.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(unsafe_file(
                    "the runtime configuration path must not pass through a symbolic link",
                    "Give the path of the file itself, with no symbolic link in it.",
                ))
            }
            Ok(_) => {}
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_trusted_ownership(path: &Path) -> Result<(), RuntimeConfigError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let effective_user = rustix::process::geteuid().as_raw();
    let count = path.components().count();
    let mut current = PathBuf::new();
    for (index, component) in path.components().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|_| unavailable())?;
        let last = index + 1 == count;
        let owner = metadata.uid();
        let mode = metadata.permissions().mode();
        let trusted_owner = owner == 0 || owner == effective_user;
        let not_writable_by_others = mode & 0o022 == 0;
        let root_sticky = !last && owner == 0 && mode & 0o1000 != 0;
        if !trusted_owner || !(not_writable_by_others || root_sticky) {
            return Err(unsafe_file(
                "the runtime configuration and every directory above it must be owned by root \
                 or the runtime user and not writable by group or others",
                "Give the file and every directory above it to root or the runtime user, and \
                 remove group and other write permission.",
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_trusted_ownership(_path: &Path) -> Result<(), RuntimeConfigError> {
    Err(unsafe_file(
        "trusted ownership of the runtime configuration cannot be checked on this platform",
        "Run the runtime on a platform with Unix file ownership.",
    ))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, RuntimeConfigError> {
    let scanned = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if scanned.file_type().is_symlink() || !scanned.is_file() {
        return Err(not_regular());
    }
    if scanned.len() == 0 || scanned.len() > maximum {
        return Err(out_of_bounds(maximum));
    }
    let file = open_no_follow(path)?;
    let opened = file.metadata().map_err(|_| unavailable())?;
    let current = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if current.file_type().is_symlink() || !opened.is_file() {
        return Err(not_regular());
    }
    if !same_file(&scanned, &opened) || !same_file(&opened, &current) {
        return Err(changed());
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| out_of_bounds(maximum))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(capacity)
        .map_err(|_| out_of_bounds(maximum))?;
    let mut reader = file.take(maximum + 1);
    reader.read_to_end(&mut bytes).map_err(|_| unavailable())?;
    let after = reader.get_ref().metadata().map_err(|_| unavailable())?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(out_of_bounds(maximum));
    }
    if !same_file(&opened, &after) || bytes.len() as u64 != after.len() {
        return Err(changed());
    }
    Ok(bytes)
}

fn open_no_follow(path: &Path) -> Result<fs::File, RuntimeConfigError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32,
        );
    }
    options.open(path).map_err(|_| {
        fs::symlink_metadata(path).map_or_else(
            |_| unavailable(),
            |metadata| {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    not_regular()
                } else {
                    unavailable()
                }
            },
        )
    })
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.permissions().mode() == right.permissions().mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.permissions().readonly() == right.permissions().readonly()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[cfg(test)]
#[path = "loader_tests.rs"]
mod tests;
