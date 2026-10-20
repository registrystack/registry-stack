// SPDX-License-Identifier: Apache-2.0
//! Source-positioned integrity checks shared by authored product formats.

use crate::{
    duplicate_display_text_pairs, lookalike_local_id_pairs, Diagnostic, Document, LocalId, Severity,
};

#[derive(Clone, Copy, Debug)]
pub struct AuthoredId<'a> {
    pub id: &'a str,
    pub pointer: &'a str,
    site: AuthoredIdSite,
}

#[derive(Clone, Copy, Debug)]
enum AuthoredIdSite {
    Key,
    Value,
}

impl<'a> AuthoredId<'a> {
    /// An identifier authored as a mapping key at `pointer`.
    #[must_use]
    pub const fn at_key(id: &'a str, pointer: &'a str) -> Self {
        Self {
            id,
            pointer,
            site: AuthoredIdSite::Key,
        }
    }

    /// An identifier authored as a scalar value at `pointer`.
    #[must_use]
    pub const fn at_value(id: &'a str, pointer: &'a str) -> Self {
        Self {
            id,
            pointer,
            site: AuthoredIdSite::Value,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AuthoredDisplayText<'a> {
    pub id: &'a str,
    pub text: &'a str,
    pub pointer: &'a str,
}

/// Display text whose peer definition has no validated local identifier that
/// is safe to repeat in a diagnostic.
#[derive(Clone, Copy, Debug)]
pub struct AuthoredDisplayTextLocation<'a> {
    pub text: &'a str,
    pub pointer: &'a str,
}

#[must_use]
pub fn local_id_collision_diagnostics(
    document: &Document,
    code: &str,
    entries: &[AuthoredId<'_>],
) -> Vec<Diagnostic> {
    lookalike_local_id_pairs(entries.iter().map(|entry| entry.id))
        .into_iter()
        .map(|(first, second)| {
            let first = entries[first];
            let second = entries[second];
            let repeat_ids =
                LocalId::new(first.id).is_ok() && LocalId::new(second.id).is_ok();
            let message = if repeat_ids {
                format!(
                    "local identifiers `{}` and `{}` differ only by `-` versus `_`",
                    first.id, second.id
                )
            } else {
                "two local identifiers differ only by `-` versus `_`".to_owned()
            };
            let action = "Rename one identifier so the two definitions remain distinct after separator normalization.";
            let mut diagnostic = match second.site {
                AuthoredIdSite::Key => document.diagnostic_at_key(
                    Severity::Error,
                    code,
                    second.pointer,
                    &message,
                    action,
                ),
                AuthoredIdSite::Value => document.diagnostic_at_value(
                    Severity::Error,
                    code,
                    second.pointer,
                    &message,
                    action,
                ),
            };
            let related = if repeat_ids {
                format!("the other definition is `{}`", first.id)
            } else {
                "the other definition is here".to_owned()
            };
            match first.site {
                AuthoredIdSite::Key => {
                    document.add_related_key(&mut diagnostic, first.pointer, related);
                }
                AuthoredIdSite::Value => {
                    document.add_related_value(&mut diagnostic, first.pointer, related);
                }
            }
            diagnostic
        })
        .collect()
}

#[must_use]
pub fn duplicate_display_text_diagnostics(
    document: &Document,
    code: &str,
    kind: &str,
    entries: &[AuthoredDisplayText<'_>],
) -> Vec<Diagnostic> {
    duplicate_display_text_pairs(entries.iter().map(|entry| entry.text))
        .into_iter()
        .map(|(first, second)| {
            let first = entries[first];
            let second = entries[second];
            let mut diagnostic = document.diagnostic_at_value(
                Severity::Warning,
                code,
                second.pointer,
                &format!(
                    "{kind} `{}` and `{}` have display text that compares the same",
                    first.id, second.id
                ),
                "Use display text that lets reviewers distinguish the two definitions.",
            );
            document.add_related_value(
                &mut diagnostic,
                first.pointer,
                format!("the other {kind} is `{}`", first.id),
            );
            diagnostic
        })
        .collect()
}

/// Warn about equal display text without repeating an arbitrary authored key.
#[must_use]
pub fn duplicate_display_text_location_diagnostics(
    document: &Document,
    code: &str,
    kind: &str,
    entries: &[AuthoredDisplayTextLocation<'_>],
) -> Vec<Diagnostic> {
    duplicate_display_text_pairs(entries.iter().map(|entry| entry.text))
        .into_iter()
        .map(|(first, second)| {
            let first = entries[first];
            let second = entries[second];
            let mut diagnostic = document.diagnostic_at_value(
                Severity::Warning,
                code,
                second.pointer,
                &format!("two {kind} have display text that compares the same"),
                "Use display text that lets reviewers distinguish the two definitions.",
            );
            document.add_related_value(
                &mut diagnostic,
                first.pointer,
                format!("the other {kind} is here"),
            );
            diagnostic
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};

    const FORMAT: FormatSpec = FormatSpec {
        kind: "IntegrityTest",
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current("example.test/integrity/v1")],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };

    #[test]
    fn local_id_collision_points_to_both_identifier_values() {
        let document = Reader::new("integrity.yaml")
            .read(
                b"apiVersion: example.test/integrity/v1\nkind: IntegrityTest\nitems:\n  - id: first-id\n  - id: first_id\n",
                &Expect::one(&FORMAT),
            )
            .expect("test document reads");
        let entries = [
            AuthoredId::at_value("first-id", "/items/0/id"),
            AuthoredId::at_value("first_id", "/items/1/id"),
        ];

        let diagnostics = local_id_collision_diagnostics(&document, "test.id-collision", &entries);
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        let source = diagnostic.source.as_ref().expect("primary source position");
        assert_eq!((source.line, source.column), (Some(5), Some(9)));
        assert_eq!(diagnostic.path, "/items/1/id");
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(
            (diagnostic.related[0].line, diagnostic.related[0].column),
            (Some(4), Some(9))
        );
        assert_eq!(diagnostic.related[0].path, "/items/0/id");
        assert!(diagnostic.message.contains("`first-id`"));
        assert!(diagnostic.related[0].message.contains("`first-id`"));
    }

    #[test]
    fn local_id_collision_points_to_both_identifier_keys() {
        let document = Reader::new("integrity.yaml")
            .read(
                b"apiVersion: example.test/integrity/v1\nkind: IntegrityTest\nitems:\n  first-id: true\n  first_id: true\n",
                &Expect::one(&FORMAT),
            )
            .expect("test document reads");
        let entries = [
            AuthoredId::at_key("first-id", "/items/first-id"),
            AuthoredId::at_key("first_id", "/items/first_id"),
        ];

        let diagnostics = local_id_collision_diagnostics(&document, "test.id-collision", &entries);
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        let source = diagnostic.source.as_ref().expect("primary source position");
        assert_eq!((source.line, source.column), (Some(5), Some(3)));
        assert_eq!(diagnostic.path, "/items/first_id");
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(
            (diagnostic.related[0].line, diagnostic.related[0].column),
            (Some(4), Some(3))
        );
        assert_eq!(diagnostic.related[0].path, "/items/first-id");
    }

    #[test]
    fn local_id_collision_redacts_ids_outside_the_repeat_safe_grammar() {
        let first_id = format!("{}-one", "a".repeat(64));
        let second_id = format!("{}_one", "a".repeat(64));
        let source = format!(
            "apiVersion: example.test/integrity/v1\nkind: IntegrityTest\nitems:\n  - id: {first_id}\n  - id: {second_id}\n"
        );
        let document = Reader::new("integrity.yaml")
            .read(source.as_bytes(), &Expect::one(&FORMAT))
            .expect("test document reads");
        let entries = [
            AuthoredId::at_value(&first_id, "/items/0/id"),
            AuthoredId::at_value(&second_id, "/items/1/id"),
        ];

        let diagnostics = local_id_collision_diagnostics(&document, "test.id-collision", &entries);
        assert_eq!(diagnostics.len(), 1);
        let rendered = serde_json::to_string(&diagnostics).expect("diagnostics serialize");
        assert!(!rendered.contains(&first_id), "{rendered}");
        assert!(!rendered.contains(&second_id), "{rendered}");
        assert_eq!(diagnostics[0].path, "/items/1/id");
        assert_eq!(diagnostics[0].related[0].path, "/items/0/id");
    }
}
