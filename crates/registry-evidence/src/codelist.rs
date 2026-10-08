// SPDX-License-Identifier: Apache-2.0
//! The Evidence codelist format: one `codelists/*.yaml` file of a bundle.
//!
//! A codelist is a list of codes (`codes`) or a mapping from input codes to
//! output codes (`entries` with `allowed_outputs`). The file is read through
//! the shared configuration reader, so every refusal names the file, the
//! member, its line and column, and the fix, and none repeats a value from
//! the file (CFG-SEC-3).

use std::collections::BTreeMap;

use registry_platform_yaml::{
    Document, EnvelopeRule, Expect, FormatSpec, Invalid, Reader, Report, Severity, UniqueList,
};
use serde::de;
use serde::{Deserialize, Deserializer};

use crate::bundle::Codelist;
use crate::config::BundleExpressions;

/// The kind the reader names an Evidence codelist by in its diagnostics.
pub const EVIDENCE_CODELIST_KIND: &str = "EvidenceCodelist";

/// The Evidence codelist format. The frozen Version 1 grammar writes `id` and
/// `version` and neither `apiVersion` nor `kind`; the envelope arrives with
/// the move to the stable format line.
pub const EVIDENCE_CODELIST_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: EVIDENCE_CODELIST_KIND,
    envelope: EnvelopeRule::Exempt {
        reason: "the frozen Version 1 codelist grammar declares id and version and no apiVersion or kind",
    },
    removed_keys: &[],
};

/// The most codes, mapping entries, or allowed outputs one codelist holds.
const MAXIMUM_CODELIST_ITEMS: usize = 4_096;

const FORM_ACTION: &str =
    "Declare `codes`, or declare `entries` together with `allowed_outputs`, and nothing else.";

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

/// The `id` and `version` a codelist file declares, when the file reads as
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
        root.get("id")?.as_str()?.to_owned(),
        root.get("version")?.as_str()?.to_owned(),
    ))
}

/// A codelist file as written. Exactly one form is declared: `codes`, or
/// `entries` with `allowed_outputs`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodelistDocument {
    id: CodelistId,
    version: CodelistVersion,
    #[serde(default)]
    codes: Option<UniqueList<Code>>,
    #[serde(default)]
    entries: Option<BTreeMap<Code, Code>>,
    #[serde(default)]
    allowed_outputs: Option<UniqueList<Code>>,
}

type Refusal = Box<registry_platform_yaml::Diagnostic>;

impl CodelistDocument {
    fn into_codelist(self, document: &Document) -> Result<Codelist, Refusal> {
        let refuse = |code: &str, pointer: &str, message: &str, action: &str| -> Refusal {
            Box::new(document.diagnostic_at_value(Severity::Error, code, pointer, message, action))
        };
        let form = |pointer: &str, message: &str| {
            refuse(
                "evidence.codelist.invalid-form",
                pointer,
                message,
                FORM_ACTION,
            )
        };
        let id = self.id.0;
        let version = self.version.0;
        match (self.codes, self.entries, self.allowed_outputs) {
            (Some(codes), None, None) => {
                check_size(codes.len(), "/codes", &refuse)?;
                Ok(Codelist::Codes {
                    id,
                    version,
                    codes: codes.into_vec().into_iter().map(|code| code.0).collect(),
                })
            }
            (None, Some(entries), Some(allowed_outputs)) => {
                check_size(entries.len(), "/entries", &refuse)?;
                check_size(allowed_outputs.len(), "/allowed_outputs", &refuse)?;
                for (input, output) in &entries {
                    if !allowed_outputs.contains(output) {
                        let pointer = format!(
                            "/entries/{}",
                            registry_platform_yaml::escape_pointer_segment(&input.0)
                        );
                        return Err(refuse(
                            "evidence.codelist.output-not-allowed",
                            &pointer,
                            "a mapping entry names an output code that allowed_outputs does not list",
                            "Map the input to a code listed under `allowed_outputs`, or list the output code there.",
                        ));
                    }
                }
                Ok(Codelist::Mapping {
                    id,
                    version,
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
            (Some(_), Some(_), _) | (Some(_), None, Some(_)) => {
                let pointer = if document.span_of("/entries").is_some() {
                    "/entries"
                } else {
                    "/allowed_outputs"
                };
                Err(form(
                    pointer,
                    "a codelist declares codes or a mapping, not both",
                ))
            }
            (None, Some(_), None) => Err(form(
                "/entries",
                "a mapping codelist declares allowed_outputs beside entries",
            )),
            (None, None, Some(_)) => Err(form(
                "/allowed_outputs",
                "allowed_outputs belongs to a mapping codelist, which declares entries",
            )),
            (None, None, None) => Err(form(
                "",
                "a codelist declares codes, or entries with allowed_outputs",
            )),
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

/// The codelist identifier: an absolute URI of at most 512 bytes.
struct CodelistId(String);

impl<'de> Deserialize<'de> for CodelistId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() <= 512 && url::Url::parse(&text).is_ok() {
            return Ok(Self(text));
        }
        Err(de::Error::custom(Invalid::expected(
            "an absolute URI of at most 512 bytes",
            "Write the codelist identifier as an absolute URI, such as urn:example:codelist:regions.",
        )))
    }
}

/// The codelist version: from 1 to 128 bytes of text without a NUL.
struct CodelistVersion(String);

impl<'de> Deserialize<'de> for CodelistVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if !text.is_empty() && text.len() <= 128 && !text.contains('\0') {
            return Ok(Self(text));
        }
        Err(de::Error::custom(Invalid::expected(
            "a version of 1 to 128 bytes without a NUL character",
            "Write the codelist version as short text, such as '2026-01'.",
        )))
    }
}

/// One code: 1 to 128 ASCII bytes, starting with a letter or digit, then
/// letters, digits, `.`, `_`, `:`, or `-`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Code(String);

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
        Err(de::Error::custom(Invalid::expected(
            "a code of 1 to 128 ASCII letters, digits, `.`, `_`, `:`, or `-`, starting with a letter or digit",
            "Spell the code with letters, digits, `.`, `_`, `:`, and `-` only.",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "CANARY-codelist-7f3a";

    fn refusal(text: &str) -> registry_platform_yaml::Diagnostic {
        let report = read_codelist("codelists/test.yaml", text.as_bytes())
            .expect_err("the codelist is refused");
        let diagnostics = report.diagnostics();
        assert_eq!(diagnostics.len(), 1, "one diagnostic");
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
            b"id: urn:example:codelist:status\nversion: '1'\ncodes: [ACTIVE, SUSPENDED]\n",
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
            b"id: urn:example:codelist:map\nversion: '2026-01'\nentries:\n  R-101: NORTH\n  R-201: SOUTH\nallowed_outputs: [NORTH, SOUTH]\n",
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
                format!("id: urn:example:c\nversion: '1'\ncodes: [A]\nextra: {CANARY}\n"),
                "config.unknown-key",
                "/extra",
                4,
            ),
            (
                "malformed code",
                format!("id: urn:example:c\nversion: '1'\ncodes: [A, '{CANARY} x']\n"),
                "config.invalid-value",
                "/codes/1",
                3,
            ),
            (
                "malformed identifier",
                format!("id: '{CANARY} x'\nversion: '1'\ncodes: [A]\n"),
                "config.invalid-value",
                "/id",
                1,
            ),
            (
                "repeated code",
                "id: urn:example:c\nversion: '1'\ncodes: [A, B, A]\n".to_owned(),
                "config.duplicate-item",
                "/codes/2",
                3,
            ),
            (
                "both forms",
                "id: urn:example:c\nversion: '1'\ncodes: [A]\nentries: {A: A}\nallowed_outputs: [A]\n".to_owned(),
                "evidence.codelist.invalid-form",
                "/entries",
                4,
            ),
            (
                "mapping without outputs",
                "id: urn:example:c\nversion: '1'\nentries: {A: B}\n".to_owned(),
                "evidence.codelist.invalid-form",
                "/entries",
                3,
            ),
            (
                "neither form",
                "id: urn:example:c\nversion: '1'\n".to_owned(),
                "evidence.codelist.invalid-form",
                "",
                1,
            ),
            (
                "empty codes",
                "id: urn:example:c\nversion: '1'\ncodes: []\n".to_owned(),
                "evidence.codelist.invalid-size",
                "/codes",
                3,
            ),
            (
                "output not allowed",
                "id: urn:example:c\nversion: '1'\nentries:\n  A: B\n  C: D\nallowed_outputs: [B]\n".to_owned(),
                "evidence.codelist.output-not-allowed",
                "/entries/C",
                5,
            ),
            (
                "substitution",
                "id: urn:example:c\nversion: '${VERSION}'\ncodes: [A]\n".to_owned(),
                "config.substitution-not-allowed",
                "/version",
                2,
            ),
        ];
        for (label, text, code, path, line) in cases {
            let diagnostic = refusal(text);
            assert_eq!(diagnostic.code, *code, "{label}");
            assert_eq!(
                position(&diagnostic),
                ((*path).to_owned(), *line),
                "{label}"
            );
        }
    }

    #[test]
    fn finds_the_declared_identity_without_reading_the_rest() {
        assert_eq!(
            declared_identity(b"id: urn:example:c\nversion: '1'\ncodes: oops\n"),
            Some(("urn:example:c".to_owned(), "1".to_owned()))
        );
        assert_eq!(declared_identity(b"id: [\n"), None);
        assert_eq!(declared_identity(b"version: '1'\n"), None);
    }
}
