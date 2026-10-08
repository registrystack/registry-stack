// SPDX-License-Identifier: Apache-2.0

//! Template versions as the package ships them.
//!
//! A template version lives under `templates/<id>/<version>/` and holds:
//!
//! - `template.yaml`, the closed [`TemplateDocument`], kind
//!   `MessagingTemplate`: its channel, the locales it ships, and the parts
//!   every locale renders;
//! - `schema.json`, the JSON Schema (draft 2020-12) the data must satisfy
//!   before anything renders;
//! - optionally `sample.json`, data the package check renders every locale
//!   with, so an author sees the output and the SMS segment count;
//! - one directory per locale holding one `.j2` file per declared part.
//!
//! The runtime reads the directory; this module checks what it read, without
//! touching a file. Locales are exact: a request for a locale the template
//! does not ship is refused, never answered in another language.
//!
//! `schema.json` and `sample.json` are JSON documents in the JSON Schema
//! grammar and the template's own data, not configuration this product
//! defines, so they are read as JSON rather than through the shared YAML
//! reader.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use jsonschema::{Draft, JSONSchema, SchemaResolver, SchemaResolverError};
use registry_platform_yaml::{
    escape_pointer_segment, ApiVersion, Decoded, EnvelopeRule, Expect, FormatSpec, Invalid, Reader,
    Report, UniqueList,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::finding::{FindingReason, MessagingFinding};
use crate::naming::{MESSAGING_TEMPLATE_API_VERSION, MESSAGING_TEMPLATE_KIND};
use crate::package::Channel;
use crate::render::{check_syntax, render_part, PartKind, RenderFailure};
use crate::sms::{count_segments, SegmentCount};

/// The longest template source file, in bytes.
pub const MAXIMUM_TEMPLATE_SOURCE_BYTES: usize = 64 * 1024;

/// The most locales one template version ships.
pub const MAXIMUM_TEMPLATE_LOCALES: usize = 32;

/// The most data diagnostics one refusal reports.
pub const MAXIMUM_DATA_DIAGNOSTICS: usize = 8;

/// The longest JSON Pointer one diagnostic reports, in bytes.
pub const MAXIMUM_DIAGNOSTIC_POINTER_BYTES: usize = 128;

/// The format a `template.yaml` file declares (CFG-ENV-1).
pub const MESSAGING_TEMPLATE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: MESSAGING_TEMPLATE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(MESSAGING_TEMPLATE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// `template.yaml`, as authored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateDocument {
    pub api_version: String,
    pub kind: String,
    pub channel: Channel,
    /// The locales the version ships, at least one and at most 32, each with
    /// its own directory.
    #[serde(deserialize_with = "locales")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "UniqueList<LocaleTag>", length(min = 1, max = 32))
    )]
    pub locales: Vec<String>,
    /// The parts every locale renders: subject and text, and optionally
    /// html, for email; text alone for SMS.
    #[serde(deserialize_with = "parts")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "UniqueList<PartKind>", length(min = 1))
    )]
    pub parts: Vec<PartKind>,
}

impl TemplateDocument {
    /// Read one `template.yaml` through `reader`. A refusal is the report a
    /// check prints unchanged.
    pub fn decode(reader: Reader<'_>, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        reader.decode(bytes, &Expect::one(&MESSAGING_TEMPLATE_FORMAT))
    }
}

/// A language tag this product accepts: see [`valid_locale`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LocaleTag(String);

impl<'de> Deserialize<'de> for LocaleTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tag = String::deserialize(deserializer)?;
        if valid_locale(&tag) {
            Ok(Self(tag))
        } else {
            Err(serde::de::Error::custom(Invalid::expected(
                "a language tag of the form ll, ll-RR, or ll-Ssss-RR",
                "Write a tag such as en, fr-FR, es-419, or zh-Hant-TW.",
            )))
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for LocaleTag {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "LocaleTag".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$",
        })
    }
}

fn locales<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    let tags = UniqueList::<LocaleTag>::deserialize(deserializer)?.into_vec();
    if tags.is_empty() {
        return Err(serde::de::Error::custom(Invalid::expected(
            "a list of at least one language tag",
            "List each locale the template ships.",
        )));
    }
    Ok(tags.into_iter().map(|LocaleTag(tag)| tag).collect())
}

fn parts<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<PartKind>, D::Error> {
    let parts = UniqueList::<PartKind>::deserialize(deserializer)?.into_vec();
    if parts.is_empty() {
        return Err(serde::de::Error::custom(Invalid::expected(
            "a list of at least one part",
            "List the parts every locale renders: subject and text for email, text for SMS.",
        )));
    }
    Ok(parts)
}

/// The part sources of one locale, as read from its directory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocaleSources {
    pub subject: Option<String>,
    pub text: Option<String>,
    pub html: Option<String>,
}

impl LocaleSources {
    #[must_use]
    pub fn get(&self, kind: PartKind) -> Option<&str> {
        match kind {
            PartKind::Subject => self.subject.as_deref(),
            PartKind::Text => self.text.as_deref(),
            PartKind::Html => self.html.as_deref(),
        }
    }

    fn present(&self) -> BTreeSet<PartKind> {
        [PartKind::Subject, PartKind::Text, PartKind::Html]
            .into_iter()
            .filter(|kind| self.get(*kind).is_some())
            .collect()
    }
}

/// Everything one template version directory holds, parsed.
#[derive(Clone, Debug)]
pub struct TemplateSource {
    pub id: String,
    pub version: String,
    pub document: TemplateDocument,
    pub schema: Value,
    pub locales: BTreeMap<String, LocaleSources>,
    pub sample: Option<Value>,
}

/// One refused data member. The pointer names where in the data the
/// schema failed and the keyword names which rule; neither carries a value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataDiagnostic {
    pub pointer: String,
    pub keyword: String,
}

/// Why data or a locale could not produce a rendered template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenderRefusal {
    LocaleUnavailable,
    /// The data failed the schema. At most [`MAXIMUM_DATA_DIAGNOSTICS`]
    /// diagnostics are kept; `truncated` says whether more were found.
    DataInvalid {
        diagnostics: Vec<DataDiagnostic>,
        truncated: bool,
    },
    Part {
        part: PartKind,
        failure: RenderFailure,
    },
}

impl fmt::Display for RenderRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocaleUnavailable => {
                formatter.write_str("the template does not ship this locale")
            }
            Self::DataInvalid {
                diagnostics,
                truncated,
            } => {
                formatter.write_str("the data does not satisfy the template schema:")?;
                for diagnostic in diagnostics {
                    write!(
                        formatter,
                        " `{}` fails `{}`;",
                        if diagnostic.pointer.is_empty() {
                            "/"
                        } else {
                            &diagnostic.pointer
                        },
                        diagnostic.keyword
                    )?;
                }
                if *truncated {
                    formatter.write_str(" more failures omitted")?;
                }
                Ok(())
            }
            Self::Part { part, failure } => write!(
                formatter,
                "the {} part could not render: {}",
                part.as_str(),
                failure.as_str()
            ),
        }
    }
}

/// The parts one render produced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderedParts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
}

/// A checked template version, ready to render.
#[derive(Clone)]
pub struct CompiledTemplate {
    id: String,
    version: String,
    channel: Channel,
    parts: Vec<PartKind>,
    locales: BTreeMap<String, LocaleSources>,
    schema: Arc<JSONSchema>,
    sample: Option<Value>,
}

impl fmt::Debug for CompiledTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledTemplate")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("channel", &self.channel)
            .field("parts", &self.parts)
            .field("locales", &self.locales.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// A schema never reaches outside the package: every reference is local.
/// The static check in [`remote_reference`] refuses remote references before
/// compilation; this resolver holds the same line whatever `jsonschema`
/// features another crate enables.
struct NoRemoteSchemas;

impl SchemaResolver for NoRemoteSchemas {
    fn resolve(
        &self,
        _root_schema: &Value,
        _url: &url::Url,
        _original_reference: &str,
    ) -> Result<Arc<Value>, SchemaResolverError> {
        Err(std::io::Error::other("template schemas resolve no remote reference").into())
    }
}

impl CompiledTemplate {
    /// Check one template version and compile its schema. `sample`, when
    /// present, must satisfy the schema and render in every locale. The
    /// finding names the member of `template.yaml` or the file beside it.
    pub fn compile(source: TemplateSource) -> Result<Self, MessagingFinding> {
        let document = &source.document;
        if let Some(finding) = document_finding(document) {
            return Err(finding);
        }
        for (index, locale) in document.locales.iter().enumerate() {
            if !source.locales.contains_key(locale) {
                return Err(MessagingFinding::new(
                    FindingReason::MissingLocaleDirectory,
                    format!("/locales/{index}"),
                ));
            }
        }
        if let Some(extra) = source
            .locales
            .keys()
            .find(|locale| !document.locales.contains(*locale))
        {
            return Err(MessagingFinding::in_file(
                FindingReason::UndeclaredLocaleDirectory,
                extra.as_str(),
                None,
            ));
        }
        let parts: BTreeSet<PartKind> = document.parts.iter().copied().collect();
        for (locale, sources) in &source.locales {
            if sources.present() != parts {
                return Err(MessagingFinding::in_file(
                    FindingReason::PartFilesMismatch,
                    locale.as_str(),
                    None,
                ));
            }
            for part in &document.parts {
                let file = format!("{locale}/{}", part.file_name());
                let text = sources.get(*part).unwrap_or_default();
                if text.len() > MAXIMUM_TEMPLATE_SOURCE_BYTES {
                    return Err(MessagingFinding::in_file(
                        FindingReason::PartTooLarge,
                        file,
                        None,
                    ));
                }
                check_syntax(text).map_err(|line| {
                    MessagingFinding::in_file(FindingReason::PartSyntax, file, line)
                })?;
            }
        }
        let schema = compile_schema(&source.schema)?;
        let compiled = Self {
            id: source.id,
            version: source.version,
            channel: source.document.channel,
            parts: source.document.parts,
            locales: source.locales,
            schema: Arc::new(schema),
            sample: source.sample,
        };
        if let Some(sample) = compiled.sample() {
            for locale in compiled.locales() {
                compiled
                    .render(locale, sample)
                    .map_err(|refusal| sample_finding(locale, refusal))?;
            }
        }
        Ok(compiled)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn channel(&self) -> Channel {
        self.channel
    }

    pub fn locales(&self) -> impl Iterator<Item = &str> {
        self.locales.keys().map(String::as_str)
    }

    /// The version's `sample.json`, which renders in every locale.
    #[must_use]
    pub fn sample(&self) -> Option<&Value> {
        self.sample.as_ref()
    }

    /// Validate `data` against the schema, then render every part in
    /// `locale`. Nothing renders unless the data passes.
    pub fn render(&self, locale: &str, data: &Value) -> Result<RenderedParts, RenderRefusal> {
        let sources = self
            .locales
            .get(locale)
            .ok_or(RenderRefusal::LocaleUnavailable)?;
        self.validate(data)?;
        let render = |part: PartKind| -> Result<Option<String>, RenderRefusal> {
            sources
                .get(part)
                .map(|source| {
                    render_part(part, source, data, locale)
                        .map_err(|failure| RenderRefusal::Part { part, failure })
                })
                .transpose()
        };
        Ok(RenderedParts {
            subject: render(PartKind::Subject)?,
            text: render(PartKind::Text)?.unwrap_or_default(),
            html: render(PartKind::Html)?,
        })
    }

    /// The segment count of a rendered SMS text, or none for email.
    #[must_use]
    pub fn segments(&self, parts: &RenderedParts) -> Option<SegmentCount> {
        (self.channel == Channel::Sms).then(|| count_segments(&parts.text))
    }

    fn validate(&self, data: &Value) -> Result<(), RenderRefusal> {
        if !data.is_object() {
            return Err(RenderRefusal::DataInvalid {
                diagnostics: vec![DataDiagnostic {
                    pointer: String::new(),
                    keyword: "type".to_owned(),
                }],
                truncated: false,
            });
        }
        let Err(errors) = self.schema.validate(data) else {
            return Ok(());
        };
        let mut diagnostics = Vec::new();
        let mut truncated = false;
        for error in errors {
            if diagnostics.len() == MAXIMUM_DATA_DIAGNOSTICS {
                truncated = true;
                break;
            }
            let keyword = error
                .schema_path
                .to_string()
                .rsplit('/')
                .next()
                .map(bounded_text)
                .unwrap_or_default();
            diagnostics.push(DataDiagnostic {
                pointer: bounded_text(&error.instance_path.to_string()),
                keyword,
            });
        }
        Err(RenderRefusal::DataInvalid {
            diagnostics,
            truncated,
        })
    }
}

/// Bound a diagnostic string and keep control characters out of it.
fn bounded_text(text: &str) -> String {
    let mut bounded = String::new();
    for character in text.chars() {
        let character = if character.is_control() {
            '\u{fffd}'
        } else {
            character
        };
        if bounded.len() + character.len_utf8() > MAXIMUM_DIAGNOSTIC_POINTER_BYTES {
            bounded.push('…');
            break;
        }
        bounded.push(character);
    }
    bounded
}

/// What `template.yaml` gets wrong reading two members together, or a
/// bound the reader leaves to the check.
fn document_finding(document: &TemplateDocument) -> Option<MessagingFinding> {
    if document.locales.len() > MAXIMUM_TEMPLATE_LOCALES {
        return Some(MessagingFinding::new(
            FindingReason::TooManyLocales,
            "/locales",
        ));
    }
    let parts: BTreeSet<PartKind> = document.parts.iter().copied().collect();
    let fits = match document.channel {
        Channel::Email => parts.contains(&PartKind::Subject) && parts.contains(&PartKind::Text),
        Channel::Sms => parts == BTreeSet::from([PartKind::Text]),
    };
    (!fits).then(|| MessagingFinding::new(FindingReason::PartsDoNotFitChannel, "/parts"))
}

/// The finding for a sample that does not render in `locale`.
fn sample_finding(locale: &str, refusal: RenderRefusal) -> MessagingFinding {
    match refusal {
        RenderRefusal::DataInvalid { diagnostics, .. } => {
            MessagingFinding::in_file(FindingReason::SampleInvalid, "sample.json", None).at(
                diagnostics
                    .first()
                    .map(|diagnostic| diagnostic.pointer.clone())
                    .unwrap_or_default(),
            )
        }
        RenderRefusal::Part { part, failure } => MessagingFinding::in_file(
            FindingReason::SampleRenderFailed(failure),
            format!("{locale}/{}", part.file_name()),
            None,
        ),
        // Every locale rendered is one the template ships.
        RenderRefusal::LocaleUnavailable => {
            MessagingFinding::new(FindingReason::MissingLocaleDirectory, "/locales")
        }
    }
}

/// Whether `value` is a language tag this product accepts: a 2 or 3 letter
/// language, an optional script, and an optional region.
#[must_use]
pub fn valid_locale(value: &str) -> bool {
    let mut subtags = value.split('-');
    let Some(language) = subtags.next() else {
        return false;
    };
    if !(2..=3).contains(&language.len()) || !language.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    let mut rest: Vec<&str> = subtags.collect();
    if let Some(script) = rest.first() {
        let bytes = script.as_bytes();
        if bytes.len() == 4
            && bytes[0].is_ascii_uppercase()
            && bytes[1..].iter().all(u8::is_ascii_lowercase)
        {
            rest.remove(0);
        }
    }
    match rest.as_slice() {
        [] => true,
        [region] => {
            (region.len() == 2 && region.bytes().all(|b| b.is_ascii_uppercase()))
                || (region.len() == 3 && region.bytes().all(|b| b.is_ascii_digit()))
        }
        _ => false,
    }
}

fn compile_schema(schema: &Value) -> Result<JSONSchema, MessagingFinding> {
    const SCHEMA_FILE: &str = "schema.json";
    if !schema.is_object() {
        return Err(MessagingFinding::in_file(
            FindingReason::SchemaNotObject,
            SCHEMA_FILE,
            None,
        ));
    }
    if let Some(pointer) = remote_reference(schema, "") {
        return Err(MessagingFinding::in_file(
            FindingReason::SchemaRemoteReference,
            SCHEMA_FILE,
            None,
        )
        .at(pointer));
    }
    // The compiler's own message may quote the schema, so only the fact
    // that it refused is reported.
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_resolver(NoRemoteSchemas)
        .compile(schema)
        .map_err(|_| MessagingFinding::in_file(FindingReason::SchemaInvalid, SCHEMA_FILE, None))
}

/// The JSON Pointer of the first reference keyword pointing outside the
/// schema, or of an `$id` that would rebase its references.
fn remote_reference(value: &Value, at: &str) -> Option<String> {
    match value {
        Value::Object(members) => {
            for (key, member) in members {
                let pointer = format!("{at}/{}", escape_pointer_segment(key));
                match (key.as_str(), member) {
                    ("$ref" | "$dynamicRef" | "$recursiveRef", Value::String(reference))
                        if !reference.starts_with('#') =>
                    {
                        return Some(pointer);
                    }
                    ("$id", Value::String(_)) => return Some(pointer),
                    _ => {}
                }
                if let Some(found) = remote_reference(member, &pointer) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(index, item)| remote_reference(item, &format!("{at}/{index}"))),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn schema() -> Value {
        json!({
            "type": "object",
            "required": ["name", "day"],
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "maxLength": 1000},
                "day": {"type": "string", "format": "date"},
                "count": {"type": "integer"}
            }
        })
    }

    pub(crate) fn email_source(version: &str) -> TemplateSource {
        let locale = |subject: &str, text: &str, html: &str| LocaleSources {
            subject: Some(subject.to_owned()),
            text: Some(text.to_owned()),
            html: Some(html.to_owned()),
        };
        TemplateSource {
            id: "appointment-reminder".to_owned(),
            version: version.to_owned(),
            document: TemplateDocument {
                api_version: MESSAGING_TEMPLATE_API_VERSION.to_owned(),
                kind: MESSAGING_TEMPLATE_KIND.to_owned(),
                channel: Channel::Email,
                locales: vec!["en".to_owned(), "fr".to_owned()],
                parts: vec![PartKind::Subject, PartKind::Text, PartKind::Html],
            },
            schema: schema(),
            locales: BTreeMap::from([
                (
                    "en".to_owned(),
                    locale(
                        "Appointment on {{ day|date }}",
                        "Hello {{ name }},\nyour appointment is on {{ day|date }}.\n",
                        "<p>Hello {{ name }}</p>",
                    ),
                ),
                (
                    "fr".to_owned(),
                    locale(
                        "Rendez-vous le {{ day|date }}",
                        "Bonjour {{ name }},\nvotre rendez-vous est le {{ day|date }}.\n",
                        "<p>Bonjour {{ name }}</p>",
                    ),
                ),
            ]),
            sample: Some(json!({"name": "Ada", "day": "2026-10-01"})),
        }
    }

    pub(crate) fn sms_source(version: &str, text: &str) -> TemplateSource {
        TemplateSource {
            id: "appointment-sms".to_owned(),
            version: version.to_owned(),
            document: TemplateDocument {
                api_version: MESSAGING_TEMPLATE_API_VERSION.to_owned(),
                kind: MESSAGING_TEMPLATE_KIND.to_owned(),
                channel: Channel::Sms,
                locales: vec!["en".to_owned()],
                parts: vec![PartKind::Text],
            },
            schema: schema(),
            locales: BTreeMap::from([(
                "en".to_owned(),
                LocaleSources {
                    text: Some(text.to_owned()),
                    ..LocaleSources::default()
                },
            )]),
            sample: None,
        }
    }

    fn data() -> Value {
        json!({"name": "Ada", "day": "2026-10-01"})
    }

    #[test]
    fn a_template_renders_every_part_in_the_requested_locale() {
        let template = CompiledTemplate::compile(email_source("1")).unwrap();
        let parts = template.render("fr", &data()).unwrap();
        assert_eq!(parts.subject.as_deref(), Some("Rendez-vous le 01/10/2026"));
        // Like Jinja, the renderer drops the one trailing newline a
        // template file ends with.
        assert_eq!(
            parts.text,
            "Bonjour Ada,\nvotre rendez-vous est le 01/10/2026."
        );
        assert_eq!(parts.html.as_deref(), Some("<p>Bonjour Ada</p>"));
        assert_eq!(template.segments(&parts), None);
    }

    #[test]
    fn a_compiled_template_keeps_its_sample_for_tooling() {
        let template = CompiledTemplate::compile(email_source("1")).unwrap();
        assert_eq!(template.sample(), Some(&data()));
        let template = CompiledTemplate::compile(sms_source("1", "x")).unwrap();
        assert_eq!(template.sample(), None);
    }

    #[test]
    fn a_locale_the_template_does_not_ship_is_refused_without_fallback() {
        let template = CompiledTemplate::compile(email_source("1")).unwrap();
        for locale in ["de", "fr-FR", "en-US", "EN", ""] {
            assert_eq!(
                template.render(locale, &data()),
                Err(RenderRefusal::LocaleUnavailable),
                "{locale}"
            );
        }
    }

    #[test]
    fn data_is_checked_against_the_schema_before_rendering() {
        let template = CompiledTemplate::compile(email_source("1")).unwrap();
        let refusal = template
            .render("en", &json!({"name": 7, "extra": "x"}))
            .unwrap_err();
        let RenderRefusal::DataInvalid {
            diagnostics,
            truncated,
        } = refusal
        else {
            panic!("expected a data refusal");
        };
        assert!(!truncated);
        let keywords: BTreeSet<&str> = diagnostics.iter().map(|d| d.keyword.as_str()).collect();
        assert_eq!(
            keywords,
            BTreeSet::from(["additionalProperties", "required", "type"])
        );
        assert!(diagnostics.iter().any(|d| d.pointer == "/name"));
        // No diagnostic carries a data value.
        for diagnostic in &diagnostics {
            assert!(!diagnostic.pointer.contains('7'));
            assert!(!diagnostic.keyword.contains("extra"));
        }
        assert!(matches!(
            template.render("en", &json!(["not", "an", "object"])),
            Err(RenderRefusal::DataInvalid { .. })
        ));
        assert!(matches!(
            template.render("en", &json!({"name": "Ada", "day": "2026-02-30"})),
            Err(RenderRefusal::DataInvalid { .. })
        ));
    }

    #[test]
    fn data_diagnostics_are_bounded_in_count_and_length() {
        let mut source = email_source("1");
        source.schema = json!({
            "type": "object",
            "additionalProperties": {"type": "string"}
        });
        source.sample = None;
        let template = CompiledTemplate::compile(source).unwrap();
        let mut data = serde_json::Map::new();
        for index in 0..20 {
            data.insert(format!("{index}{}\u{7}", "k".repeat(300)), json!(index));
        }
        let RenderRefusal::DataInvalid {
            diagnostics,
            truncated,
        } = template.render("en", &Value::Object(data)).unwrap_err()
        else {
            panic!("expected a data refusal");
        };
        assert!(truncated);
        assert_eq!(diagnostics.len(), MAXIMUM_DATA_DIAGNOSTICS);
        for diagnostic in diagnostics {
            assert!(diagnostic.pointer.len() <= MAXIMUM_DIAGNOSTIC_POINTER_BYTES + '…'.len_utf8());
            assert!(!diagnostic.pointer.chars().any(char::is_control));
        }
    }

    #[test]
    fn a_render_failure_names_the_part() {
        let mut source = email_source("1");
        source.locales.get_mut("en").unwrap().html = Some("{{ missing }}".to_owned());
        source.sample = None;
        let template = CompiledTemplate::compile(source).unwrap();
        assert_eq!(
            template.render("en", &data()),
            Err(RenderRefusal::Part {
                part: PartKind::Html,
                failure: RenderFailure::Undefined
            })
        );
    }

    #[test]
    fn sms_templates_report_their_segments() {
        let template =
            CompiledTemplate::compile(sms_source("1", "Reminder for {{ name }} on {{ day|date }}"))
                .unwrap();
        let parts = template.render("en", &data()).unwrap();
        assert_eq!(parts.text, "Reminder for Ada on 01/10/2026");
        assert_eq!(parts.subject, None);
        assert_eq!(template.segments(&parts).unwrap().segments, 1);
    }

    fn decode(value: &Value) -> Result<TemplateDocument, Vec<(String, String)>> {
        TemplateDocument::decode(
            Reader::new("template.yaml"),
            &serde_json::to_vec(value).unwrap(),
        )
        .map(|decoded| decoded.value)
        .map_err(|report| {
            report
                .diagnostics()
                .iter()
                .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
                .collect()
        })
    }

    fn document(members: Value) -> Value {
        let mut value = json!({
            "apiVersion": MESSAGING_TEMPLATE_API_VERSION,
            "kind": MESSAGING_TEMPLATE_KIND,
            "channel": "email",
            "locales": ["en"],
            "parts": ["subject", "text"]
        });
        for (key, member) in members.as_object().unwrap() {
            value[key] = member.clone();
        }
        value
    }

    #[test]
    fn the_template_document_is_closed_and_typed() {
        assert!(decode(&document(json!({}))).is_ok());
        assert_eq!(
            decode(&document(json!({"fallback": "en"}))).unwrap_err(),
            vec![("config.unknown-key".to_owned(), "/fallback".to_owned())]
        );
        for (members, path) in [
            (json!({"parts": ["subject", "attachment"]}), "/parts/1"),
            (json!({"parts": ["text", "text"]}), "/parts/1"),
            (json!({"parts": []}), "/parts"),
            (json!({"locales": []}), "/locales"),
            (json!({"locales": ["en", "en"]}), "/locales/1"),
            (json!({"locales": ["en", "english"]}), "/locales/1"),
        ] {
            assert_eq!(
                decode(&document(members.clone())).unwrap_err()[0].1,
                path,
                "{members}"
            );
        }
        let mut value = document(json!({}));
        value.as_object_mut().unwrap().remove("apiVersion");
        assert_eq!(decode(&value).unwrap_err()[0].0, "config.missing-envelope");
    }

    fn refused(edit: fn(&mut TemplateSource)) -> (String, Option<String>, String, Option<usize>) {
        let mut source = email_source("1");
        edit(&mut source);
        let finding = CompiledTemplate::compile(source).unwrap_err();
        (finding.code(), finding.file, finding.path, finding.line)
    }

    fn at(code: &str, path: &str) -> (String, Option<String>, String, Option<usize>) {
        (
            format!("messaging.template.{code}"),
            None,
            path.to_owned(),
            None,
        )
    }

    fn in_file(
        code: &str,
        file: &str,
        line: Option<usize>,
    ) -> (String, Option<String>, String, Option<usize>) {
        (
            format!("messaging.template.{code}"),
            Some(file.to_owned()),
            String::new(),
            line,
        )
    }

    #[test]
    fn the_template_version_is_checked_against_its_files() {
        assert_eq!(
            refused(|s| s.document.parts = vec![PartKind::Text]),
            at("parts-do-not-fit-channel", "/parts")
        );
        assert_eq!(
            refused(|s| {
                s.document.locales = (0..=MAXIMUM_TEMPLATE_LOCALES)
                    .map(|index| format!("l{index}"))
                    .collect();
            }),
            at("too-many-locales", "/locales")
        );
        assert_eq!(
            refused(|s| s.document.locales.push("de".into())),
            at("missing-locale-directory", "/locales/2")
        );
        assert_eq!(
            refused(|s| s.document.locales.retain(|l| l == "en")),
            in_file("undeclared-locale-directory", "fr", None)
        );
        assert_eq!(
            refused(|s| s.locales.get_mut("fr").unwrap().html = None),
            in_file("part-files-mismatch", "fr", None)
        );
        assert_eq!(
            refused(|s| {
                s.locales.get_mut("en").unwrap().text = Some("line one\n{% if %}".into());
            }),
            in_file("part-syntax", "en/text.j2", Some(2))
        );
        assert_eq!(
            refused(|s| {
                s.locales.get_mut("en").unwrap().text =
                    Some("x".repeat(MAXIMUM_TEMPLATE_SOURCE_BYTES + 1));
            }),
            in_file("part-too-large", "en/text.j2", None)
        );
        let (code, file, path, _) = refused(|s| s.sample = Some(json!({"name": "Ada"})));
        assert_eq!(
            (code.as_str(), file.as_deref(), path.as_str()),
            ("messaging.template.sample-invalid", Some("sample.json"), "")
        );
        assert_eq!(
            refused(|s| {
                s.locales.get_mut("fr").unwrap().html = Some("{{ missing }}".into());
            }),
            in_file("sample-render-failed", "fr/html.j2", None)
        );
        let mut sms = sms_source("1", "x");
        sms.document.parts.push(PartKind::Html);
        assert_eq!(
            CompiledTemplate::compile(sms).unwrap_err().code(),
            "messaging.template.parts-do-not-fit-channel"
        );
    }

    #[test]
    fn a_schema_may_not_reach_outside_the_package() {
        for (schema, pointer) in [
            (json!({"$ref": "https://example.org/schema.json"}), "/$ref"),
            (
                json!({"type": "object", "properties": {"a": {"$ref": "file:///etc/passwd"}}}),
                "/properties/a/$ref",
            ),
            (
                json!({"allOf": [{"$dynamicRef": "other.json#node"}]}),
                "/allOf/0/$dynamicRef",
            ),
            (
                json!({"$id": "https://example.org/base", "$ref": "#/$defs/x", "$defs": {"x": {}}}),
                "/$id",
            ),
        ] {
            let mut source = email_source("1");
            source.schema = schema.clone();
            source.sample = None;
            let finding = CompiledTemplate::compile(source).unwrap_err();
            assert_eq!(
                (
                    finding.reason,
                    finding.file.as_deref(),
                    finding.path.as_str()
                ),
                (
                    FindingReason::SchemaRemoteReference,
                    Some("schema.json"),
                    pointer
                ),
                "{schema}"
            );
        }
        let mut source = email_source("1");
        source.schema = json!({
            "type": "object",
            "$defs": {"name": {"type": "string"}},
            "properties": {"name": {"$ref": "#/$defs/name"}}
        });
        source.sample = None;
        assert!(CompiledTemplate::compile(source).is_ok());
        let mut source = email_source("1");
        source.schema = json!(true);
        assert_eq!(
            CompiledTemplate::compile(source).unwrap_err().reason,
            FindingReason::SchemaNotObject
        );
        let mut source = email_source("1");
        source.schema = json!({"type": "no-such-type"});
        source.sample = None;
        assert_eq!(
            CompiledTemplate::compile(source).unwrap_err().reason,
            FindingReason::SchemaInvalid
        );
    }

    #[test]
    fn locales_are_simple_language_tags() {
        for locale in [
            "en",
            "fr",
            "fil",
            "en-US",
            "es-419",
            "sr-Latn",
            "zh-Hant-TW",
        ] {
            assert!(valid_locale(locale), "{locale}");
        }
        for locale in [
            "", "e", "EN", "en_US", "en-us", "en-US-x", "zh-hant", "en-", "abcd",
        ] {
            assert!(!valid_locale(locale), "{locale}");
        }
    }
}
