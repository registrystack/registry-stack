//! Parser conformance over a vendored slice of the YAML test suite.
//!
//! The cases under `tests/yaml-test-suite/` come from the `data-2022-01-17`
//! release of <https://github.com/yaml/yaml-test-suite> (MIT, see its
//! `LICENSE`). They cover the accepted subset (block and flow collections,
//! every scalar style, comments, CRLF-free multi-line text) and every
//! construct the reader refuses (anchors, aliases, tags, complex keys,
//! several documents, directives, malformed input).
//!
//! Two properties are checked here:
//!
//! - the parser's event stream matches the suite's `test.event` for every
//!   well-formed case, so the reader builds its tree from correct events;
//! - the reader itself refuses each refused construct with its own code and a
//!   position, so the conformance is not only the parser's.

use std::fs;
use std::path::{Path, PathBuf};

use registry_platform_yaml::Reader;
use saphyr_parser::{Event, Parser, ScalarStyle};

fn suite_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/yaml-test-suite")
}

fn case_ids() -> Vec<String> {
    let mut ids: Vec<String> = fs::read_dir(suite_dir())
        .expect("the vendored suite is readable")
        .filter_map(|entry| {
            let entry = entry.expect("a suite entry is readable");
            entry
                .file_type()
                .expect("a suite entry has a type")
                .is_dir()
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect();
    ids.sort();
    ids
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{8}' => out.push_str("\\b"),
            other => out.push(other),
        }
    }
    out
}

fn properties(anchor: usize, tag: Option<&saphyr_parser::Tag>) -> String {
    let mut out = String::new();
    if anchor != 0 {
        out.push_str(" &");
    }
    if let Some(tag) = tag {
        out.push_str(&format!(" <{}{}>", tag.handle, tag.suffix));
    }
    out
}

/// Render the parser's events in the suite's `test.event` notation, with
/// anchor names reduced to their presence because the parser numbers them.
fn render_events(input: &str) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    for item in Parser::new_from_str(input) {
        let (event, _span) = item.map_err(|error| error.to_string())?;
        let line = match event {
            Event::Nothing => continue,
            Event::StreamStart => "+STR".to_string(),
            Event::StreamEnd => "-STR".to_string(),
            Event::DocumentStart(explicit) => {
                if explicit {
                    "+DOC ---".to_string()
                } else {
                    "+DOC".to_string()
                }
            }
            Event::DocumentEnd => "-DOC".to_string(),
            Event::Alias(_) => "=ALI *".to_string(),
            Event::Scalar(value, style, anchor, tag) => {
                let indicator = match style {
                    ScalarStyle::Plain => ':',
                    ScalarStyle::SingleQuoted => '\'',
                    ScalarStyle::DoubleQuoted => '"',
                    ScalarStyle::Literal => '|',
                    ScalarStyle::Folded => '>',
                };
                format!(
                    "=VAL{} {indicator}{}",
                    properties(anchor, tag.as_deref()),
                    escape(&value)
                )
            }
            Event::SequenceStart(anchor, tag) => {
                format!("+SEQ{}", properties(anchor, tag.as_deref()))
            }
            Event::SequenceEnd => "-SEQ".to_string(),
            Event::MappingStart(anchor, tag) => {
                format!("+MAP{}", properties(anchor, tag.as_deref()))
            }
            Event::MappingEnd => "-MAP".to_string(),
        };
        lines.push(line);
    }
    Ok(lines)
}

/// Normalize the suite's notation to what the parser can express: flow
/// collection markers and document end markers are dropped, and anchor and
/// alias names are reduced to their presence.
fn normalize_expected(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| {
            let mut words: Vec<String> = Vec::new();
            let mut rest = line;
            // A scalar value may contain spaces; only the properties before
            // it are normalized.
            let value = if line.starts_with("=VAL") {
                let start = line
                    .char_indices()
                    .skip(4)
                    .find(|(index, c)| {
                        matches!(c, ':' | '\'' | '"' | '|' | '>')
                            && line[..*index].ends_with(' ')
                            && !line[..*index].trim_end().ends_with('<')
                            && !inside_tag(&line[..*index])
                    })
                    .map(|(index, _)| index)
                    .expect("a scalar line carries a value");
                rest = &line[..start];
                Some(&line[start..])
            } else {
                None
            };
            for word in rest.split_whitespace() {
                match word {
                    "{}" | "[]" => {}
                    "..." if line.starts_with("-DOC") => {}
                    _ if word.starts_with('&') => words.push("&".to_string()),
                    _ if word.starts_with('*') => words.push("*".to_string()),
                    _ => words.push(word.to_string()),
                }
            }
            let mut normalized = words.join(" ");
            if let Some(value) = value {
                normalized.push(' ');
                normalized.push_str(value);
            }
            normalized
        })
        .collect()
}

fn inside_tag(prefix: &str) -> bool {
    prefix
        .rfind('<')
        .is_some_and(|open| !prefix[open..].contains('>'))
}

#[test]
fn cfg_yaml_1_parser_events_match_the_suite_for_every_vendored_case() {
    let mut checked = 0;
    let mut refused = 0;
    for id in case_ids() {
        let dir = suite_dir().join(&id);
        let input = fs::read_to_string(dir.join("in.yaml")).expect("in.yaml is UTF-8");
        let expects_error = dir.join("error").exists();
        let rendered = render_events(&input);
        if expects_error {
            assert!(
                rendered.is_err(),
                "{id}: the suite marks this input invalid but the parser accepted it"
            );
            refused += 1;
            continue;
        }
        let expected = normalize_expected(
            &fs::read_to_string(dir.join("test.event")).expect("test.event is UTF-8"),
        );
        let rendered = rendered.unwrap_or_else(|error| panic!("{id}: parser refused: {error}"));
        assert_eq!(rendered, expected, "{id}: event stream differs");
        checked += 1;
    }
    assert_eq!(checked + refused, case_ids().len());
    assert!(checked >= 30, "only {checked} well-formed cases ran");
    assert!(refused >= 10, "only {refused} malformed cases ran");
}

/// The syntax codes of CFG-YAML-8. A malformed document is refused with one
/// of them; the narrower ones are chosen when the parser's error matches.
const SYNTAX_CODES: &[&str] = &[
    "yaml.tab-indentation",
    "yaml.unclosed-quote",
    "yaml.colon-in-plain-value",
    "yaml.unexpected-end",
    "yaml.syntax",
];

/// The codes the reader reports for a suite case, read as the YAML subset
/// alone: the suite's documents carry no envelope.
fn codes_for(id: &str) -> Vec<String> {
    let input = fs::read(suite_dir().join(id).join("in.yaml")).expect("in.yaml is readable");
    match Reader::new("in.yaml").scan(&input) {
        Ok(_) => Vec::new(),
        Err(report) => {
            for diagnostic in report.diagnostics() {
                let source = diagnostic
                    .source
                    .as_ref()
                    .unwrap_or_else(|| panic!("{id}: {} has no source", diagnostic.code));
                assert!(
                    source.line.is_some() && source.column.is_some(),
                    "{id}: {} has no position",
                    diagnostic.code
                );
            }
            report
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.clone())
                .collect()
        }
    }
}

fn assert_refused_with(ids: &[&str], code: &str) {
    for id in ids {
        let codes = codes_for(id);
        assert!(
            codes.iter().any(|found| found == code),
            "{id}: expected {code}, got {codes:?}"
        );
    }
}

#[test]
fn cfg_yaml_1_reader_accepts_the_well_formed_subset_cases() {
    // 27NA and 6LVF carry a `%YAML` directive and one document; the
    // directive changes nothing the subset reads.
    for id in [
        "229Q", "27NA", "4Q9F", "4UYU", "5GBF", "6HB6", "6JQW", "6LVF", "7A4E", "7ZZ5", "9U5K",
        "A984", "DC7X", "K858", "MJS9", "P2AD", "S4T7", "SYW4",
    ] {
        assert_eq!(codes_for(id), Vec::<String>::new(), "{id} was refused");
    }
}

#[test]
fn cfg_yaml_3_reader_refuses_anchors_and_aliases_from_the_suite() {
    assert_refused_with(&["7BUB", "E76Z", "U3XV", "X38W", "6M2F"], "yaml.anchor");
    assert_refused_with(&["7BUB", "E76Z", "X38W", "6M2F"], "yaml.alias");
}

#[test]
fn cfg_yaml_4_reader_refuses_tags_from_the_suite() {
    // 2XXW is a `!!set`: the tag is refused, and its explicit keys are text.
    // M5C3 tags a folded scalar.
    assert_refused_with(
        &["2XXW", "6CK3", "35KP", "C4HZ", "J7PZ", "9KAX", "M5C3"],
        "yaml.tag",
    );
}

#[test]
fn cfg_yaml_5_reader_refuses_complex_and_empty_keys_from_the_suite() {
    assert_refused_with(&["4FJ6", "KK5P"], "yaml.non-string-key");
    // 2JQS and DFF7 write empty keys: each is a null key.
    assert_refused_with(&["2JQS", "DFF7"], "yaml.non-string-key");
}

#[test]
fn cfg_env_4_reader_refuses_several_documents_from_the_suite() {
    assert_refused_with(&["JHB9", "RZT7", "6ZKB", "M7A3"], "yaml.multiple-documents");
}

#[test]
fn cfg_yaml_8_reader_refuses_malformed_suite_cases_with_a_syntax_code_and_a_position() {
    let mut malformed = 0;
    for id in case_ids() {
        if !suite_dir().join(&id).join("error").exists() {
            continue;
        }
        malformed += 1;
        let codes = codes_for(&id);
        assert!(
            codes
                .iter()
                .any(|code| SYNTAX_CODES.contains(&code.as_str())),
            "{id}: expected a syntax code, got {codes:?}"
        );
    }
    assert!(malformed >= 10, "only {malformed} malformed cases ran");
}
