// SPDX-License-Identifier: Apache-2.0
//! The Evidence codelist format: one `codelists/*.yaml` file of a bundle.
//!
//! A codelist is a list of codes (`type: code-list` with `codes`) or a
//! mapping from input codes to output codes (`type: mapping` with `entries`
//! and `allowedOutputs`). The file is read through the shared configuration
//! reader, so every refusal names the file, the member, its line and column,
//! and the fix, and none repeats a value from the file (CFG-SEC-3).

use std::collections::BTreeMap;

use registry_platform_yaml::{
    tagged_union, ApiVersion, Document, EnvelopeRule, Expect, FormatSpec, Invalid, Reader,
    RemovedKey, Report, Severity, UniqueList,
};
use serde::{Deserialize, Deserializer};

use crate::bundle::Codelist;
use crate::config::BundleExpressions;

/// The `apiVersion` a codelist file declares.
pub const EVIDENCE_CODELIST_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/codelist/v1alpha1";

/// The kind the reader names an Evidence codelist by in its diagnostics.
pub const EVIDENCE_CODELIST_KIND: &str = "EvidenceCodelist";

/// The Evidence codelist format. A file opens with `apiVersion` and `kind`;
/// the members `id` and `allowed_outputs` are refused with the member that
/// replaced each one named.
pub const EVIDENCE_CODELIST_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: EVIDENCE_CODELIST_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(EVIDENCE_CODELIST_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/id",
            replacement: "Write the codelist URI under `uri`.",
        },
        RemovedKey {
            pointer: "/allowed_outputs",
            replacement: "Write the output codes under `allowedOutputs`.",
        },
    ],
};

/// The most codes, mapping entries, or allowed outputs one codelist holds.
const MAXIMUM_CODELIST_ITEMS: usize = 4_096;

/// Read one codelist file and check its rules. `file` is the name the
/// diagnostics carry.
pub fn read_codelist(file: &str, bytes: &[u8]) -> Result<Codelist, Report> {
    let mut hook = BundleExpressions;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<CodelistDocument>(bytes, &Expect::one(&EVIDENCE_CODELIST_FORMAT))?;
    decoded
        .value
        .into_codelist(&decoded.document)
        .map_err(|diagnostic| Report::new(vec![*diagnostic]))
}

/// The `uri` and `version` a codelist file declares, when the file reads as
/// YAML and declares both as text. Bucket schemes find their codelist this
/// way; the codelist found is then read in full by [`read_codelist`].
pub(crate) fn declared_identity(bytes: &[u8]) -> Option<(String, String)> {
    let mut hook = BundleExpressions;
    let root = Reader::new("codelist")
        .with_hook(&mut hook)
        .scan(bytes)
        .ok()??
        .to_json_value();
    Some((
        root.get("uri")?.as_str()?.to_owned(),
        root.get("version")?.as_str()?.to_owned(),
    ))
}

/// A codelist file as written. The `type` member names its form.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub(crate) enum CodelistDocument {
    /// An exact code set.
    CodeList {
        /// The absolute URI identifying the codelist; a bucket concept's
        /// `bucketScheme` names it.
        uri: CodelistUri,
        /// The codelist version; a referencing concept's `codelistVersion`
        /// or `schemeVersion` repeats it exactly.
        version: CodelistVersion,
        /// The exact code set.
        codes: UniqueList<Code>,
    },
    /// An exact mapping from source codes to output codes.
    Mapping {
        /// The absolute URI identifying the codelist.
        uri: CodelistUri,
        /// The codelist version; a referencing concept's `codelistVersion`
        /// repeats it exactly.
        version: CodelistVersion,
        /// The exact source-to-output mapping.
        entries: BTreeMap<Code, Code>,
        /// The output codes the mapping may produce; every `entries` output
        /// is one of them.
        allowed_outputs: UniqueList<Code>,
    },
}
tagged_union!(CodelistDocument);

/// The most codes, mapping entries, or allowed outputs one codelist holds, as
/// the generated schema states it.
#[cfg(feature = "schema")]
pub(crate) const CODELIST_MAXIMUM_ITEMS: usize = MAXIMUM_CODELIST_ITEMS;

type Refusal = Box<registry_platform_yaml::Diagnostic>;

impl CodelistDocument {
    fn into_codelist(self, document: &Document) -> Result<Codelist, Refusal> {
        let refuse = |code: &str, pointer: &str, message: &str, action: &str| -> Refusal {
            Box::new(document.diagnostic_at_value(Severity::Error, code, pointer, message, action))
        };
        match self {
            Self::CodeList {
                uri,
                version,
                codes,
            } => {
                check_size(codes.len(), "/codes", &refuse)?;
                Ok(Codelist::Codes {
                    id: uri.0,
                    version: version.0,
                    codes: codes.into_vec().into_iter().map(|code| code.0).collect(),
                })
            }
            Self::Mapping {
                uri,
                version,
                entries,
                allowed_outputs,
            } => {
                check_size(entries.len(), "/entries", &refuse)?;
                check_size(allowed_outputs.len(), "/allowedOutputs", &refuse)?;
                for (input, output) in &entries {
                    if !allowed_outputs.contains(output) {
                        let pointer = format!(
                            "/entries/{}",
                            registry_platform_yaml::escape_pointer_segment(&input.0)
                        );
                        return Err(refuse(
                            "evidence.codelist.output-not-allowed",
                            &pointer,
                            "a mapping entry names an output code that allowedOutputs does not list",
                            "Map the input to a code listed under `allowedOutputs`, or list the output code there.",
                        ));
                    }
                }
                Ok(Codelist::Mapping {
                    id: uri.0,
                    version: version.0,
                    entries: entries
                        .into_iter()
                        .map(|(input, output)| (input.0, output.0))
                        .collect(),
                    allowed_outputs: allowed_outputs
                        .into_vec()
                        .into_iter()
                        .map(|code| code.0)
                        .collect(),
                })
            }
        }
    }
}

fn check_size(
    count: usize,
    pointer: &str,
    refuse: &impl Fn(&str, &str, &str, &str) -> Refusal,
) -> Result<(), Refusal> {
    if (1..=MAXIMUM_CODELIST_ITEMS).contains(&count) {
        return Ok(());
    }
    Err(refuse(
        "evidence.codelist.invalid-size",
        pointer,
        "a codelist list or mapping holds from 1 to 4096 items",
        "Declare at least one item, and split a longer codelist into reviewed parts.",
    ))
}

/// The codelist identifier: an absolute URI of at most 512 characters, with
/// no whitespace and no control character, kept as written.
pub(crate) struct CodelistUri(String);

impl<'de> Deserialize<'de> for CodelistUri {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        // The URI parser trims a space or control character at either end
        // and drops a tab or line break anywhere, without an error. Refusing
        // them first keeps the identifier as written and the URI as parsed
        // the same URI.
        if text.chars().count() <= 512
            && !text
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
            && url::Url::parse(&text).is_ok()
        {
            return Ok(Self(text));
        }
        Err(Invalid::expected(
            "an absolute URI of at most 512 characters, with no whitespace or control character",
            "Write the codelist identifier as an absolute URI without spaces, tabs, or line breaks, such as urn:example:codelist:regions.",
        )
        .into_error())
    }
}

/// The codelist version: from 1 to 128 characters without control characters.
pub(crate) struct CodelistVersion(String);

impl<'de> Deserialize<'de> for CodelistVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if !text.is_empty() && text.chars().count() <= 128 && !text.chars().any(char::is_control) {
            return Ok(Self(text));
        }
        Err(Invalid::expected(
            "a version of 1 to 128 characters without control characters",
            "Write the codelist version as short text, such as '2026-01'.",
        )
        .into_error())
    }
}

/// One code: 1 to 128 ASCII bytes, starting with a letter or digit, then
/// letters, digits, `.`, `_`, `:`, or `-`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Code(String);

#[cfg(feature = "schema")]
mod schema_impls {
    use std::borrow::Cow;

    use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};

    use super::{Code, CodelistUri, CodelistVersion};

    /// Text holding no character that `char::is_whitespace` or
    /// `char::is_control` accepts, each listed by code point so that every
    /// regular expression engine reads the same set.
    const NO_WHITESPACE_OR_CONTROL_PATTERN: &str = "^[^\\u0000-\\u0020\\u007F-\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]+$";

    impl JsonSchema for CodelistUri {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("CodelistUri")
        }

        fn json_schema(generator: &mut SchemaGenerator) -> Schema {
            // The URI is an identifier other files cite (CFG-ID-2), so the
            // schema names the shared definition beside the URI rule.
            let external = generator.subschema_for::<registry_platform_yaml::ExternalId>();
            json_schema!({
                "allOf": [external],
                "format": "uri",
                "pattern": NO_WHITESPACE_OR_CONTROL_PATTERN,
                "description": "An absolute URI of at most 512 characters, with no whitespace or control character, such as urn:example:codelist:regions.",
            })
        }
    }

    impl JsonSchema for CodelistVersion {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("CodelistVersion")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
                "description": "A version of 1 to 128 characters without control characters, such as '2026-01'.",
            })
        }
    }

    impl JsonSchema for Code {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("Code")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                "description": "A code of 1 to 128 ASCII letters, digits, `.`, `_`, `:`, or `-`, starting with a letter or digit.",
            })
        }
    }
}

impl<'de> Deserialize<'de> for Code {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = text.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= 128
            && bytes[0].is_ascii_alphanumeric()
            && bytes[1..].iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            });
        if valid {
            return Ok(Self(text));
        }
        Err(Invalid::expected(
            "a code of 1 to 128 ASCII letters, digits, `.`, `_`, `:`, or `-`, starting with a letter or digit",
            "Spell the code with letters, digits, `.`, `_`, `:`, and `-` only.",
        )
        .into_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "CANARY-codelist-7f3a";

    /// The two envelope lines every codelist opens with.
    const ENVELOPE: &str =
        "apiVersion: id.registrystack.org/formats/evidence/codelist/v1alpha1\nkind: EvidenceCodelist\n";

    fn enveloped(body: &str) -> String {
        format!("{ENVELOPE}{body}")
    }

    fn refusal(text: &str) -> registry_platform_yaml::Diagnostic {
        let report = read_codelist("codelists/test.yaml", text.as_bytes())
            .expect_err("the codelist is refused");
        let diagnostics = report.diagnostics();
        assert_eq!(diagnostics.len(), 1, "one diagnostic: {diagnostics:?}");
        let diagnostic = diagnostics[0].clone();
        let rendered = report.render_human();
        assert!(!rendered.contains(CANARY), "the refusal repeats no value");
        diagnostic
    }

    fn position(diagnostic: &registry_platform_yaml::Diagnostic) -> (String, usize) {
        let source = diagnostic.source.as_ref().expect("a positioned diagnostic");
        (diagnostic.path.clone(), source.line.expect("a line"))
    }

    #[test]
    fn reads_both_codelist_forms() {
        let codes = read_codelist(
            "codelists/codes.yaml",
            enveloped(
                "uri: urn:example:codelist:status\nversion: '1'\ntype: code-list\ncodes: [ACTIVE, SUSPENDED]\n",
            )
            .as_bytes(),
        )
        .expect("a code list");
        assert_eq!(
            codes,
            Codelist::Codes {
                id: "urn:example:codelist:status".to_owned(),
                version: "1".to_owned(),
                codes: vec!["ACTIVE".to_owned(), "SUSPENDED".to_owned()],
            }
        );
        let mapping = read_codelist(
            "codelists/map.yaml",
            enveloped(
                "uri: urn:example:codelist:map\nversion: '2026-01'\ntype: mapping\nentries:\n  R-101: NORTH\n  R-201: SOUTH\nallowedOutputs: [NORTH, SOUTH]\n",
            )
            .as_bytes(),
        )
        .expect("a mapping");
        assert_eq!(
            mapping,
            Codelist::Mapping {
                id: "urn:example:codelist:map".to_owned(),
                version: "2026-01".to_owned(),
                entries: BTreeMap::from([
                    ("R-101".to_owned(), "NORTH".to_owned()),
                    ("R-201".to_owned(), "SOUTH".to_owned()),
                ]),
                allowed_outputs: vec!["NORTH".to_owned(), "SOUTH".to_owned()],
            }
        );
    }

    #[test]
    fn codelist_version_counts_unicode_characters() {
        let version = "é".repeat(128);
        let parsed = serde_json::from_value::<CodelistVersion>(serde_json::json!(version))
            .expect("128 Unicode characters");
        assert_eq!(parsed.0, version);
        assert!(
            serde_json::from_value::<CodelistVersion>(serde_json::json!("é".repeat(129))).is_err()
        );
    }

    #[test]
    fn codelist_version_refuses_control_characters() {
        for control in ['\0', '\t', '\n', '\r', '\u{7f}', '\u{85}'] {
            assert!(
                serde_json::from_value::<CodelistVersion>(serde_json::json!(format!(
                    "v{control}1"
                )))
                .is_err()
            );
        }
        assert!(serde_json::from_value::<CodelistVersion>(serde_json::json!("2026-01")).is_ok());
    }

    #[test]
    fn the_registered_minimal_example_reads() {
        let example = read_codelist(
            "codelists/registry-regions.yaml",
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/professional-licence/codelists/registry-regions.yaml"
            ),
        )
        .expect("the example config-formats.yaml registers reads");
        assert!(matches!(example, Codelist::Codes { .. }));
    }

    #[test]
    fn refuses_each_rule_at_its_member_without_the_value() {
        let cases: &[(&str, String, &str, &str, usize)] = &[
            (
                "unknown key",
                format!("uri: urn:example:c\nversion: '1'\ntype: code-list\ncodes: [A]\nextra: {CANARY}\n"),
                "config.unknown-key",
                "/extra",
                7,
            ),
            (
                "malformed code",
                format!("uri: urn:example:c\nversion: '1'\ntype: code-list\ncodes: [A, '{CANARY} x']\n"),
                "config.invalid-value",
                "/codes/1",
                6,
            ),
            (
                "malformed identifier",
                format!("uri: '{CANARY} x'\nversion: '1'\ntype: code-list\ncodes: [A]\n"),
                "config.invalid-value",
                "/uri",
                3,
            ),
            (
                "repeated code",
                "uri: urn:example:c\nversion: '1'\ntype: code-list\ncodes: [A, B, A]\n".to_owned(),
                "config.duplicate-item",
                "/codes/2",
                6,
            ),
            (
                "a code list with mapping members",
                "uri: urn:example:c\nversion: '1'\ntype: code-list\ncodes: [A]\nentries: {A: A}\n".to_owned(),
                "config.unknown-key",
                "/entries",
                7,
            ),
            (
                "a mapping without outputs",
                "uri: urn:example:c\nversion: '1'\ntype: mapping\nentries: {A: B}\n".to_owned(),
                "config.missing-key",
                "",
                1,
            ),
            (
                "empty codes",
                "uri: urn:example:c\nversion: '1'\ntype: code-list\ncodes: []\n".to_owned(),
                "evidence.codelist.invalid-size",
                "/codes",
                6,
            ),
            (
                "output not allowed",
                "uri: urn:example:c\nversion: '1'\ntype: mapping\nentries:\n  A: B\n  C: D\nallowedOutputs: [B]\n".to_owned(),
                "evidence.codelist.output-not-allowed",
                "/entries/C",
                8,
            ),
            (
                "substitution",
                "uri: urn:example:c\nversion: '${VERSION}'\ntype: code-list\ncodes: [A]\n".to_owned(),
                "config.substitution-not-allowed",
                "/version",
                4,
            ),
        ];
        for (label, text, code, path, line) in cases {
            let diagnostic = refusal(&enveloped(text));
            assert_eq!(diagnostic.code, *code, "{label}: {diagnostic:?}");
            assert_eq!(
                position(&diagnostic),
                ((*path).to_owned(), *line),
                "{label}"
            );
        }
    }

    #[test]
    fn a_codelist_names_its_form_with_the_type_member() {
        for text in [
            "uri: urn:example:c\nversion: '1'\ncodes: [A]\n",
            "uri: urn:example:c\nversion: '1'\ntype: neither\ncodes: [A]\n",
        ] {
            let diagnostic = refusal(&enveloped(text));
            assert!(
                diagnostic.code.starts_with("config."),
                "the shared reader refuses the form: {diagnostic:?}"
            );
            assert!(
                diagnostic.path == "/type" || diagnostic.message.contains("`type`"),
                "the refusal names the type member: {diagnostic:?}"
            );
        }
    }

    #[test]
    fn the_spellings_written_before_the_stable_form_are_refused_with_the_replacement_named() {
        let report = read_codelist(
            "codelists/test.yaml",
            b"id: urn:example:c\nversion: '1'\ncodes: [A]\n",
        )
        .expect_err("a codelist without the envelope is refused");
        let unenveloped = report.diagnostics();
        assert_eq!(
            unenveloped
                .iter()
                .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
                .collect::<Vec<_>>(),
            [
                ("config.missing-envelope", ""),
                ("config.removed-key", "/id")
            ]
        );
        assert!(
            unenveloped[0]
                .suggested_action
                .contains(EVIDENCE_CODELIST_API_VERSION),
            "the refusal names the apiVersion to write: {unenveloped:?}"
        );
        for (text, path, replacement, line) in [
            (
                "id: urn:example:c\nversion: '1'\ntype: code-list\ncodes: [A]\n",
                "/id",
                "uri",
                3,
            ),
            (
                "uri: urn:example:c\nversion: '1'\ntype: mapping\nentries: {A: B}\nallowed_outputs: [B]\n",
                "/allowed_outputs",
                "allowedOutputs",
                7,
            ),
        ] {
            let report = read_codelist("codelists/test.yaml", enveloped(text).as_bytes())
                .expect_err("the removed key is refused");
            let diagnostic = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == "config.removed-key")
                .unwrap_or_else(|| panic!("a removed-key refusal: {:?}", report.diagnostics()))
                .clone();
            assert_eq!(position(&diagnostic), (path.to_owned(), line));
            assert!(
                diagnostic.suggested_action.contains(replacement)
                    || diagnostic.message.contains(replacement),
                "the refusal names the replacement: {diagnostic:?}"
            );
        }
    }

    #[test]
    fn finds_the_declared_identity_without_reading_the_rest() {
        assert_eq!(
            declared_identity(b"uri: urn:example:c\nversion: '1'\ncodes: oops\n"),
            Some(("urn:example:c".to_owned(), "1".to_owned()))
        );
        assert_eq!(declared_identity(b"uri: [\n"), None);
        assert_eq!(declared_identity(b"version: '1'\n"), None);
        assert_eq!(
            declared_identity(b"id: urn:example:c\nversion: '1'\n"),
            None,
            "the member written before the stable form names no codelist"
        );
    }

    /// A code list whose `uri` is the YAML scalar given.
    fn with_identifier(scalar: &str) -> String {
        enveloped(&format!(
            "uri: {scalar}\nversion: '1'\ntype: code-list\ncodes: [A]\n"
        ))
    }

    #[test]
    fn the_identifier_limit_counts_characters() {
        let prefix = "urn:example:codelist:";
        let boundary = format!("{prefix}{}", "é".repeat(512 - prefix.chars().count()));
        assert!(boundary.len() > 512, "the boundary exceeds 512 UTF-8 bytes");
        let codelist = read_codelist("codelists/test.yaml", with_identifier(&boundary).as_bytes())
            .expect("an identifier of 512 characters is read");
        assert_eq!(
            codelist,
            Codelist::Codes {
                id: boundary.clone(),
                version: "1".to_owned(),
                codes: vec!["A".to_owned()],
            }
        );

        let diagnostic = refusal(&with_identifier(&format!("{boundary}é")));
        assert_eq!(diagnostic.code, "config.invalid-value");
        assert_eq!(position(&diagnostic), ("/uri".to_owned(), 3));
        assert!(
            diagnostic.message.contains("at most 512 characters"),
            "the refusal states the limit in characters: {diagnostic:?}"
        );
    }

    #[test]
    fn the_identifier_holds_no_whitespace_and_no_control_character() {
        for (case, scalar) in [
            ("trailing space", format!("'urn:example:{CANARY} '")),
            ("leading space", format!("' urn:example:{CANARY}'")),
            ("inner space", format!("urn:example:{CANARY} x")),
            ("tab escape", format!("\"urn:example:{CANARY}\\tx\"")),
            ("literal tab", format!("\"urn:example:{CANARY}\tx\"")),
            ("line feed escape", format!("\"urn:example:{CANARY}\\nx\"")),
            (
                "trailing line feed escape",
                format!("\"urn:example:{CANARY}\\n\""),
            ),
            (
                "carriage return escape",
                format!("\"urn:example:{CANARY}\\rx\""),
            ),
            (
                "no-break space escape",
                format!("\"urn:example:{CANARY}\\_x\""),
            ),
            ("block scalar", format!("|\n  urn:example:{CANARY}")),
        ] {
            let diagnostic = refusal(&with_identifier(&scalar));
            assert_eq!(
                diagnostic.code, "config.invalid-value",
                "{case}: {diagnostic:?}"
            );
            assert_eq!(diagnostic.path, "/uri", "{case}");
            assert!(
                diagnostic
                    .message
                    .contains("no whitespace or control character"),
                "{case}: {diagnostic:?}"
            );
        }
        for (case, scalar) in [
            ("percent-encoded space", "urn:example:a%20b"),
            ("stripped block scalar", "|-\n  urn:example:c"),
        ] {
            read_codelist("codelists/test.yaml", with_identifier(scalar).as_bytes())
                .unwrap_or_else(|report| panic!("{case}: {:?}", report.diagnostics()));
        }
    }
}
