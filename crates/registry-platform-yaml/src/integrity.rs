// SPDX-License-Identifier: Apache-2.0
//! Source-positioned integrity checks shared by authored product formats.

use crate::{
    duplicate_display_text_pairs, lookalike_local_id_pairs, Diagnostic, Document, Severity,
};

#[derive(Clone, Copy, Debug)]
pub struct AuthoredId<'a> {
    pub id: &'a str,
    pub pointer: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct AuthoredDisplayText<'a> {
    pub id: &'a str,
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
            let mut diagnostic = document.diagnostic_at_key(
                Severity::Error,
                code,
                second.pointer,
                &format!(
                    "local identifiers `{}` and `{}` differ only by `-` versus `_`",
                    first.id, second.id
                ),
                "Rename one identifier so the two definitions remain distinct after separator normalization.",
            );
            document.add_related_value(
                &mut diagnostic,
                first.pointer,
                format!("the other definition is `{}`", first.id),
            );
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
