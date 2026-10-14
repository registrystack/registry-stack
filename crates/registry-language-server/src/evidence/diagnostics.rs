// SPDX-License-Identifier: Apache-2.0
//! Translate shared authoring reader locations to protocol UTF-16 ranges.
use crate::{
    refs::{bounded_message, IndexedDiagnostic, DOCUMENT_START},
    yaml::{ParsedDocument, SourceMap, YamlValue},
};
use registry_platform_yaml::{Diagnostic, Severity};
use std::path::Path;
use tower_lsp_server::ls_types::{DiagnosticSeverity, Position, Range};
/// The shared reader's diagnostics as the editor shows them: the same code and the same sentence,
/// at the same line and column, counted in UTF-16 code units.
pub(crate) fn reader_diagnostics(
    path: &Path,
    source: &str,
    document: &ParsedDocument,
    diagnostics: &[Diagnostic],
) -> Vec<IndexedDiagnostic> {
    let source_map = SourceMap::new(source);
    diagnostics
        .iter()
        .map(|diagnostic| IndexedDiagnostic {
            path: path.to_path_buf(),
            range: reader_range(source, &source_map, document, diagnostic),
            severity: match diagnostic.severity {
                Severity::Error => DiagnosticSeverity::ERROR,
                Severity::Warning => DiagnosticSeverity::WARNING,
            },
            code: Some(diagnostic.code.clone()),
            // The sentence is the reader's or the authoring library's, so the editor and the
            // compiler say the same thing about the same document.
            message: bounded_message(&diagnostic.message),
        })
        .collect()
}

/// Where a reader diagnostic points, as a protocol range.
///
/// The reader counts a column in Unicode scalar values and does not count a leading byte-order
/// mark; the protocol counts UTF-16 code units of the text the editor holds. The range starts at
/// that place and, when a scalar the editor indexed starts there, ends where that scalar ends, so a
/// value is underlined whole. A diagnostic about the file as a whole is placed at its start.
fn reader_range(
    source: &str,
    source_map: &SourceMap<'_>,
    document: &ParsedDocument,
    diagnostic: &Diagnostic,
) -> Range {
    let Some((line, column)) = diagnostic
        .source
        .as_ref()
        .and_then(|place| Some((place.line?, place.column?)))
    else {
        return DOCUMENT_START;
    };
    let Some(byte) = byte_offset(source, line, column) else {
        return DOCUMENT_START;
    };
    let start = source_map.position(byte);
    let end = scalar_end_at(&document.value, start).unwrap_or(start);
    Range::new(start, end)
}

/// The byte offset of a 1-based line and a 1-based column counted in Unicode scalar values, with a
/// leading byte-order mark skipped the way the reader skips it.
fn byte_offset(source: &str, line: usize, column: usize) -> Option<usize> {
    let mut line_start = 0;
    for _ in 1..line {
        line_start += source.get(line_start..)?.find('\n')? + 1;
    }
    if line == 1 && source.starts_with('\u{feff}') {
        line_start = '\u{feff}'.len_utf8();
    }
    let text = source.get(line_start..)?;
    let within = text
        .char_indices()
        .nth(column.checked_sub(1)?)
        .map_or(text.len(), |(offset, _)| offset);
    Some(line_start + within)
}

/// The end of the key or scalar value the editor indexed at `start`. A quoted scalar's range starts
/// after its opening quote, one code unit past where the reader places it.
fn scalar_end_at(value: &YamlValue, start: Position) -> Option<Position> {
    let starts_here = |range: Range| {
        range.start == start
            || (range.start.line == start.line && range.start.character == start.character + 1)
    };
    match value {
        YamlValue::Scalar(scalar) => starts_here(scalar.range).then_some(scalar.range.end),
        YamlValue::Mapping(entries) => entries.iter().find_map(|entry| {
            if starts_here(entry.key.range) {
                Some(entry.key.range.end)
            } else {
                scalar_end_at(&entry.value, start)
            }
        }),
        YamlValue::Sequence(items) => items.iter().find_map(|item| scalar_end_at(item, start)),
        YamlValue::Other => None,
    }
}
