// SPDX-License-Identifier: Apache-2.0

//! Template versions as the package ships them.
//!
//! A template version lives under `templates/<id>/<version>/` and holds:
//!
//! - `template.yaml`, the closed [`TemplateDocument`]: its channel, the
//!   locales it ships, and the parts every locale renders;
//! - `schema.json`, the JSON Schema (draft 2020-12) the data must satisfy
//!   before anything renders;
//! - optionally `sample.json`, data the package check renders every locale
//!   with, so an author sees the output and the SMS segment count;
//! - one directory per locale holding one `.j2` file per declared part.
//!
//! The runtime reads the directory; this module checks what it read, without
//! touching a file. Locales are exact: a request for a locale the template
//! does not ship is refused, never answered in another language.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use jsonschema::{Draft, JSONSchema, SchemaResolver, SchemaResolverError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// `template.yaml`, as authored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateDocument {
    pub channel: Channel,
    pub locales: Vec<String>,
    pub parts: Vec<PartKind>,
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
    /// present, must satisfy the schema and render in every locale.
    pub fn compile(source: TemplateSource) -> Result<Self, String> {
        check_document(&source.document)?;
        let declared: BTreeSet<&str> = source.document.locales.iter().map(String::as_str).collect();
        let shipped: BTreeSet<&str> = source.locales.keys().map(String::as_str).collect();
        if let Some(missing) = declared.difference(&shipped).next() {
            return Err(format!(
                "locale `{missing}` is declared but has no directory"
            ));
        }
        if let Some(extra) = shipped.difference(&declared).next() {
            return Err(format!("locale directory `{extra}` is not declared"));
        }
        let parts: BTreeSet<PartKind> = source.document.parts.iter().copied().collect();
        for (locale, sources) in &source.locales {
            if sources.present() != parts {
                return Err(format!(
                    "locale `{locale}` must hold exactly the declared parts: {}",
                    source
                        .document
                        .parts
                        .iter()
                        .map(|part| part.file_name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            for part in &source.document.parts {
                let text = sources.get(*part).unwrap_or_default();
                if text.len() > MAXIMUM_TEMPLATE_SOURCE_BYTES {
                    return Err(format!(
                        "`{locale}/{}` exceeds {MAXIMUM_TEMPLATE_SOURCE_BYTES} bytes",
                        part.file_name()
                    ));
                }
                check_syntax(text).map_err(|error| {
                    format!("`{locale}/{}` does not parse: {error}", part.file_name())
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
        };
        if let Some(sample) = &source.sample {
            for locale in compiled.locales() {
                compiled
                    .render(locale, sample)
                    .map_err(|refusal| format!("sample.json in locale `{locale}`: {refusal}"))?;
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

fn check_document(document: &TemplateDocument) -> Result<(), String> {
    if document.locales.is_empty() {
        return Err("template.yaml declares no locale".to_owned());
    }
    if document.locales.len() > MAXIMUM_TEMPLATE_LOCALES {
        return Err(format!(
            "template.yaml declares more than {MAXIMUM_TEMPLATE_LOCALES} locales"
        ));
    }
    let mut locales = BTreeSet::new();
    for locale in &document.locales {
        if !valid_locale(locale) {
            return Err(format!(
                "locale `{locale}` is not a language tag of the form ll, ll-RR, or ll-Ssss-RR"
            ));
        }
        if !locales.insert(locale) {
            return Err(format!("locale `{locale}` is declared more than once"));
        }
    }
    let parts: BTreeSet<PartKind> = document.parts.iter().copied().collect();
    if parts.len() != document.parts.len() {
        return Err("template.yaml declares a part more than once".to_owned());
    }
    let valid = match document.channel {
        Channel::Email => parts.contains(&PartKind::Subject) && parts.contains(&PartKind::Text),
        Channel::Sms => parts == BTreeSet::from([PartKind::Text]),
    };
    if !valid {
        return Err(match document.channel {
            Channel::Email => "an email template renders subject and text, and optionally html",
            Channel::Sms => "an SMS template renders exactly one text part",
        }
        .to_owned());
    }
    Ok(())
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

fn compile_schema(schema: &Value) -> Result<JSONSchema, String> {
    if !schema.is_object() {
        return Err("schema.json must be a JSON Schema object".to_owned());
    }
    if let Some(reference) = remote_reference(schema) {
        return Err(format!(
            "schema.json references `{}`; only references within the schema (`#...`) are allowed",
            bounded_text(reference)
        ));
    }
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_resolver(NoRemoteSchemas)
        .compile(schema)
        .map_err(|error| {
            format!(
                "schema.json does not compile: {}",
                bounded_text(&error.to_string())
            )
        })
}

/// The first reference keyword pointing outside the schema, or an `$id` that
/// would rebase its references.
fn remote_reference(value: &Value) -> Option<&str> {
    match value {
        Value::Object(members) => {
            for (key, member) in members {
                match (key.as_str(), member) {
                    ("$ref" | "$dynamicRef" | "$recursiveRef", Value::String(reference))
                        if !reference.starts_with('#') =>
                    {
                        return Some(reference);
                    }
                    ("$id", Value::String(id)) => return Some(id),
                    _ => {}
                }
                if let Some(found) = remote_reference(member) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(remote_reference),
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

    #[test]
    fn the_template_document_is_closed_and_checked() {
        assert!(serde_json::from_value::<TemplateDocument>(json!({
            "channel": "email", "locales": ["en"], "parts": ["subject", "text"], "fallback": "en"
        }))
        .is_err());
        assert!(serde_json::from_value::<TemplateDocument>(json!({
            "channel": "email", "locales": ["en"], "parts": ["subject", "attachment"]
        }))
        .is_err());
        let refused = |edit: fn(&mut TemplateSource)| {
            let mut source = email_source("1");
            edit(&mut source);
            CompiledTemplate::compile(source).unwrap_err()
        };
        assert!(refused(|s| s.document.parts = vec![PartKind::Text]).contains("subject"));
        assert!(refused(|s| s.document.locales.clear()).contains("no locale"));
        assert!(refused(|s| s.document.locales.push("en".into())).contains("more than once"));
        assert!(refused(|s| s.document.locales.push("english".into())).contains("language tag"));
        assert!(refused(|s| s.document.locales.push("de".into())).contains("no directory"));
        assert!(refused(|s| {
            s.document.locales.retain(|l| l == "en");
        })
        .contains("not declared"));
        assert!(refused(|s| s.locales.get_mut("fr").unwrap().html = None)
            .contains("exactly the declared parts"));
        assert!(refused(|s| {
            s.locales.get_mut("en").unwrap().text = Some("{% if %}".into());
        })
        .contains("does not parse"));
        assert!(refused(|s| {
            s.locales.get_mut("en").unwrap().text =
                Some("x".repeat(MAXIMUM_TEMPLATE_SOURCE_BYTES + 1));
        })
        .contains("exceeds"));
        assert!(refused(|s| s.sample = Some(json!({"name": "Ada"}))).contains("sample.json"));
        let mut sms = sms_source("1", "x");
        sms.document.parts.push(PartKind::Html);
        assert!(CompiledTemplate::compile(sms)
            .unwrap_err()
            .contains("exactly one text part"));
    }

    #[test]
    fn a_schema_may_not_reach_outside_the_package() {
        for schema in [
            json!({"$ref": "https://example.org/schema.json"}),
            json!({"type": "object", "properties": {"a": {"$ref": "file:///etc/passwd"}}}),
            json!({"allOf": [{"$dynamicRef": "other.json#node"}]}),
            json!({"$id": "https://example.org/base", "$ref": "#/$defs/x", "$defs": {"x": {}}}),
        ] {
            let mut source = email_source("1");
            source.schema = schema.clone();
            source.sample = None;
            let error = CompiledTemplate::compile(source).unwrap_err();
            assert!(
                error.contains("only references within"),
                "{schema}: {error}"
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
        assert!(CompiledTemplate::compile(source)
            .unwrap_err()
            .contains("object"));
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
