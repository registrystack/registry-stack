// SPDX-License-Identifier: Apache-2.0
//! The YAML subset: duplicate keys, anchors, tags, keys, bounds, encoding,
//! documents, and the closed syntax codes (CFG-YAML-2 to 8, CFG-ENV-4,
//! CFG-VAL-1 refusals, CFG-DIAG-5).

mod common;

use common::*;
use registry_platform_yaml::{
    NodeValue, Reader, Refusal, ScalarHook, ScalarSite, Severity, MAXIMUM_DEPTH,
    MAXIMUM_DIAGNOSTICS_PER_FILE, MAXIMUM_DOCUMENT_BYTES,
};

fn scan_ok(text: &str) -> NodeValue {
    Reader::new(FILE)
        .scan(text.as_bytes())
        .unwrap_or_else(|report| panic!("{report}"))
        .expect("the document has a root")
        .value
}

// ----- CFG-YAML-2 -----

#[test]
fn cfg_yaml_2_duplicate_key_names_both_lines() {
    let report = scan_refusal("listener:\n  bind: a\naudit: {}\nlistener:\n  bind: b\n");
    let diagnostic = only(&report);
    assert_diagnostic(
        diagnostic,
        "yaml.duplicate-key",
        "/listener",
        (4, 1),
        "the key is already defined in this mapping",
        "Keep one definition of the key.",
    );
    assert_eq!(diagnostic.related.len(), 1);
    let related = &diagnostic.related[0];
    assert_eq!(related.path, "/listener");
    assert_eq!((related.line, related.column), (Some(1), Some(1)));
    assert_eq!(related.message, "the first definition");
}

#[test]
fn cfg_yaml_2_duplicate_key_is_refused_in_nested_and_flow_mappings() {
    let report = scan_refusal("outer:\n  inner: 1\n  inner: 2\nflow: {a: 1, a: 2}\n");
    let found: Vec<(&str, &str, (usize, usize))> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str(), at(d)))
        .collect();
    assert_eq!(
        found,
        [
            ("yaml.duplicate-key", "/outer/inner", (3, 3)),
            ("yaml.duplicate-key", "/flow/a", (4, 14)),
        ]
    );
}

#[test]
fn cfg_yaml_2_keys_that_differ_only_in_quoting_are_duplicates() {
    let report = scan_refusal("name: a\n\"name\": b\n");
    assert_eq!(codes(&report), ["yaml.duplicate-key"]);
}

// ----- CFG-YAML-3 -----

#[test]
fn cfg_yaml_3_anchor_is_refused_with_the_write_in_full_fix() {
    let report = scan_refusal("base: &shared\n  a: 1\n");
    assert_diagnostic(
        only(&report),
        "yaml.anchor",
        "/base",
        (1, 7),
        "an anchor (`&name`) is not supported",
        "Remove the anchor and write the value in full where it is used.",
    );
}

#[test]
fn cfg_yaml_3_alias_is_refused_with_the_write_in_full_fix() {
    let report = scan_refusal("base: &shared 1\nother: *shared\n");
    assert_eq!(codes(&report), ["yaml.anchor", "yaml.alias"]);
    let alias = &report.diagnostics()[1];
    assert_diagnostic(
        alias,
        "yaml.alias",
        "/other",
        (2, 8),
        "an alias (`*name`) is not supported; a lone `*` is not a wildcard",
        "Write the value in full where it is used, or quote it if it is text such as `*`.",
    );
}

#[test]
fn cfg_yaml_3_alias_to_an_unknown_anchor_is_an_alias() {
    let report = scan_refusal("other: *nowhere\n");
    assert_eq!(codes(&report), ["yaml.alias"]);
    assert_eq!(at(&report.diagnostics()[0]), (1, 8));
}

#[test]
fn cfg_yaml_3_lone_star_is_an_alias_and_the_fix_says_to_quote_it() {
    for text in ["scope: *\n", "scopes: [*]\n", "scopes:\n  - *\n"] {
        let report = scan_refusal(text);
        let diagnostic = only(&report);
        assert_eq!(diagnostic.code, "yaml.alias", "{text}");
        assert!(diagnostic.message.contains("a lone `*` is not a wildcard"));
        assert!(diagnostic.suggested_action.contains("quote it"));
    }
    // Quoted, it is text.
    let value = scan_ok("scope: \"*\"\n");
    let NodeValue::Mapping(entries) = value else {
        panic!("a mapping");
    };
    assert!(matches!(&entries[0].value.value, NodeValue::String(text) if text.text == "*"));
}

#[test]
fn cfg_yaml_3_merge_key_is_named_as_such() {
    let report = scan_refusal("defaults: {a: 1}\nprofile:\n  <<: {a: 1}\n  b: 2\n");
    assert_diagnostic(
        only(&report),
        "yaml.merge-key",
        "/profile/<<",
        (3, 3),
        "a merge key (`<<`) is not supported",
        "Write the value in full where it is used.",
    );
}

/// Only a plain `<<` merges in the YAML versions that have merge keys; a
/// quoted one is an ordinary key, which a format then refuses as unknown.
#[test]
fn cfg_yaml_3_a_quoted_merge_key_is_an_ordinary_key() {
    let value = scan_ok("profile:\n  \"<<\": {a: 1}\n");
    let NodeValue::Mapping(entries) = value else {
        panic!("a mapping");
    };
    let NodeValue::Mapping(profile) = &entries[0].value.value else {
        panic!("a mapping");
    };
    assert_eq!(profile[0].key, "<<");
}

// ----- CFG-YAML-4 -----

#[test]
fn cfg_yaml_4_explicit_tags_are_refused() {
    let report = scan_refusal("a: !!str 1\nb: !custom x\nc: !!map {}\n");
    let found: Vec<(&str, (usize, usize))> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), at(d)))
        .collect();
    assert_eq!(
        found,
        [
            ("yaml.tag", (1, 4)),
            ("yaml.tag", (2, 4)),
            ("yaml.tag", (3, 4))
        ]
    );
    assert_eq!(
        report.diagnostics()[0].suggested_action,
        "Remove the tag; quote the value if it is text."
    );
}

// ----- CFG-YAML-5 -----

#[test]
fn cfg_yaml_5_plain_keys_that_resolve_to_other_types_are_refused() {
    let report = scan_refusal("1: a\ntrue: b\n~: c\n1.5: d\n");
    let found: Vec<(&str, (usize, usize), &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), at(d), d.suggested_action.as_str()))
        .collect();
    let fix = "Quote the key to make it text.";
    assert_eq!(
        found,
        [
            ("yaml.non-string-key", (1, 1), fix),
            ("yaml.non-string-key", (2, 1), fix),
            ("yaml.non-string-key", (3, 1), fix),
            ("yaml.non-string-key", (4, 1), fix),
        ]
    );
}

#[test]
fn cfg_yaml_5_quoted_keys_are_text() {
    let NodeValue::Mapping(entries) = scan_ok("\"1\": a\n'true': b\n") else {
        panic!("a mapping");
    };
    let keys: Vec<&str> = entries.iter().map(|entry| entry.key.as_str()).collect();
    assert_eq!(keys, ["1", "true"]);
}

#[test]
fn cfg_yaml_5_complex_keys_are_refused() {
    let report = scan_refusal("? [a, b]\n: c\n");
    assert_eq!(codes(&report), ["yaml.non-string-key"]);
    assert_eq!(at(&report.diagnostics()[0]), (1, 3));
}

// ----- CFG-YAML-6 -----

/// A document of exactly `size` bytes.
fn document_of(size: usize) -> String {
    let head = format!("{ENVELOPE}padding: \"");
    let tail = "\"\n";
    let fill = size - head.len() - tail.len();
    format!("{head}{}{tail}", "x".repeat(fill))
}

#[test]
fn cfg_yaml_6_a_document_of_exactly_the_bound_is_read() {
    let text = document_of(MAXIMUM_DOCUMENT_BYTES);
    assert_eq!(text.len(), 1024 * 1024);
    let document = Reader::new(FILE)
        .read(text.as_bytes(), &EXPECT)
        .unwrap_or_else(|report| panic!("{report}"));
    assert!(document.root().get("padding").is_some());
}

#[test]
fn cfg_yaml_6_one_byte_over_the_bound_is_refused_before_parsing() {
    // Over the bound, even bytes that are not YAML are never parsed.
    let mut bytes = document_of(MAXIMUM_DOCUMENT_BYTES + 1).into_bytes();
    bytes[0] = 0xff;
    let report = Reader::new(FILE).read(&bytes, &EXPECT).unwrap_err();
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.too-large");
    assert_eq!(diagnostic.path, "");
    let source = diagnostic.source.as_ref().unwrap();
    assert_eq!((source.line, source.column), (None, None));
    assert_eq!(source.file, FILE);
    assert!(
        diagnostic.message.contains("1048576-byte (1 MiB) bound"),
        "{}",
        diagnostic.message
    );
}

fn nested_lists(depth: usize) -> String {
    format!("{}{}\n", "[".repeat(depth), "]".repeat(depth))
}

#[test]
fn cfg_yaml_6_nesting_to_the_bound_is_read() {
    assert_eq!(MAXIMUM_DEPTH, 128);
    let text = nested_lists(MAXIMUM_DEPTH);
    assert!(Reader::new(FILE).scan(text.as_bytes()).is_ok());
}

#[test]
fn cfg_yaml_6_nesting_past_the_bound_is_refused_naming_it() {
    let report = scan_refusal(&nested_lists(MAXIMUM_DEPTH + 1));
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.too-deep");
    assert_eq!(at(diagnostic), (1, 129));
    assert_eq!(
        diagnostic.message,
        "the document nests deeper than 128 levels"
    );
    assert_eq!(diagnostic.suggested_action, "Flatten the structure.");
}

#[test]
fn cfg_yaml_6_block_nesting_past_the_bound_is_refused() {
    let mut text = String::new();
    for level in 0..=MAXIMUM_DEPTH {
        text.push_str(&" ".repeat(level * 2));
        text.push_str("k:\n");
    }
    text.push_str(&" ".repeat((MAXIMUM_DEPTH + 1) * 2));
    text.push_str("k: v\n");
    let report = scan_refusal(&text);
    assert_eq!(codes(&report), ["yaml.too-deep"]);
}

/// A megabyte of open brackets is refused without exhausting a small stack.
#[test]
fn cfg_yaml_6_a_megabyte_of_open_brackets_does_not_overflow_the_stack() {
    let worker = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let mut outcomes = Vec::new();
            for opener in ["[", "{", "- "] {
                let text = opener.repeat(MAXIMUM_DOCUMENT_BYTES / opener.len());
                let report = Reader::new(FILE).scan(text.as_bytes()).unwrap_err();
                outcomes.push(codes(&report).join(","));
            }
            outcomes
        })
        .expect("spawn the reader thread");
    let outcomes = worker.join().expect("the reader thread does not overflow");
    assert_eq!(
        outcomes,
        ["yaml.too-deep", "yaml.too-deep", "yaml.too-deep"]
    );
}

#[test]
fn cfg_yaml_6_a_leading_byte_order_mark_is_ignored() {
    let text = format!("\u{feff}{ENVELOPE}name: a\n");
    let document = Reader::new(FILE)
        .read(text.as_bytes(), &EXPECT)
        .unwrap_or_else(|report| panic!("{report}"));
    let entry = document.root().get("apiVersion").unwrap();
    assert_eq!(
        (entry.key_span.start.line, entry.key_span.start.column),
        (1, 1)
    );
}

#[test]
fn cfg_yaml_6_crlf_line_endings_are_read_with_the_same_positions() {
    let text = format!("{ENVELOPE}a: 1\nb: [1, &x 2]\n").replace('\n', "\r\n");
    let report = Reader::new(FILE)
        .read(text.as_bytes(), &EXPECT)
        .unwrap_err();
    assert_eq!(codes(&report), ["yaml.anchor"]);
    assert_eq!(at(&report.diagnostics()[0]), (4, 8));
    let text = format!("{ENVELOPE}a: \"one\n  two\"\n").replace('\n', "\r\n");
    let document = Reader::new(FILE).read(text.as_bytes(), &EXPECT).unwrap();
    let value = &document.root().get("a").unwrap().value.value;
    assert!(matches!(value, NodeValue::String(text) if text.text == "one two"));
}

#[test]
fn cfg_yaml_6_input_that_is_not_utf8_is_refused_at_the_first_bad_byte() {
    let mut bytes = with_envelope("name: ab").into_bytes();
    bytes.push(0xff);
    bytes.extend_from_slice(b"\n");
    let report = Reader::new(FILE).read(&bytes, &EXPECT).unwrap_err();
    assert_diagnostic(
        only(&report),
        "yaml.not-utf8",
        "",
        (3, 9),
        "the document is not valid UTF-8 from this position",
        "Save the file as UTF-8.",
    );
}

// ----- CFG-YAML-7 -----

#[test]
fn cfg_yaml_7_comments_carry_no_meaning() {
    let as_json = |text: &str| {
        Reader::new(FILE)
            .scan(text.as_bytes())
            .unwrap_or_else(|report| panic!("{report}"))
            .expect("the document has a root")
            .to_json_value()
    };
    let plain = as_json("a: 1\nb:\n  - x\n  - y\nc: {d: e}\n");
    let commented = as_json(
        "# leading\na: 1 # after a value\nb: # after a key\n  # between items\n  - x\n  - y # last\nc: {d: e} # flow\n# trailing\n",
    );
    assert_eq!(plain, commented);
}

// ----- CFG-YAML-8 -----

#[test]
fn cfg_yaml_8_tab_indentation() {
    let report = scan_refusal("a:\n\tb: 1\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.tab-indentation");
    assert_eq!(at(diagnostic), (2, 1));
    assert_eq!(diagnostic.suggested_action, "Indent with spaces.");
}

#[test]
fn cfg_yaml_8_unclosed_quote() {
    let report = scan_refusal("a: 1\nb: \"never closed\nc: 2\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.unclosed-quote");
    assert_eq!(at(diagnostic), (2, 4));
    assert_eq!(diagnostic.suggested_action, "Close the quote.");
}

#[test]
fn cfg_yaml_8_an_unknown_escape_in_double_quotes_names_the_backslash() {
    for text in [
        "path: \"C:\\Users\\me\"\n",
        "path: \"\\q\"\n",
        "path: \"\\x4\"\n",
    ] {
        let report = scan_refusal(text);
        assert_diagnostic(
            only(&report),
            "yaml.invalid-escape",
            "/path",
            (1, 7),
            "a backslash in the double-quoted value starting here begins an escape sequence YAML does not define",
            "Use single quotes, or double the backslash.",
        );
    }
}

#[test]
fn cfg_yaml_8_text_after_a_closing_quote_is_named_as_such() {
    let report = scan_refusal("name: 'it's'\n");
    assert_diagnostic(
        only(&report),
        "yaml.text-after-quote",
        "/name",
        (1, 11),
        "text follows the closing quote of a quoted value",
        "Put the whole value inside the quotes, and write a quote inside single quotes as two (`''`).",
    );
    let report = scan_refusal("name: \"x\" y\n");
    assert_diagnostic(
        only(&report),
        "yaml.text-after-quote",
        "/name",
        (1, 11),
        "text follows the closing quote of a quoted value",
        "Put the whole value inside the quotes, and write a quote inside double quotes as `\\\"`.",
    );
}

#[test]
fn cfg_yaml_8_a_tab_on_a_later_line_is_not_blamed() {
    let report = scan_refusal("tags: [a, b]]\n\t# note\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.syntax", "{report}");
    assert_eq!(at(diagnostic).0, 1);
    let report = scan_refusal("name: x: y\n\t# note\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.colon-in-plain-value", "{report}");
    assert_eq!(at(diagnostic).0, 1);
}

#[test]
fn cfg_yaml_8_a_tab_indenting_a_later_block_line_is_still_named() {
    for (text, line) in [("a:\n  b: 1\n\tc: 2\n", 3), ("- a\n\t- b\n", 2)] {
        let report = scan_refusal(text);
        let diagnostic = only(&report);
        assert_eq!(
            diagnostic.code, "yaml.tab-indentation",
            "{text:?}: {report}"
        );
        assert_eq!(at(diagnostic), (line, 1), "{text:?}");
    }
}

#[test]
fn cfg_yaml_8_colon_in_plain_value() {
    let report = scan_refusal("reason:\n  because: Overdue: move it\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.colon-in-plain-value");
    assert_eq!(at(diagnostic).0, 2);
    assert_eq!(diagnostic.suggested_action, "Quote the value.");
}

#[test]
fn cfg_yaml_8_unexpected_end() {
    let report = scan_refusal("a: 1\nb: [1, 2\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.unexpected-end");
    assert!(at(diagnostic).0 >= 2);
    assert_eq!(
        diagnostic.message,
        "the document ends inside the list or mapping opened with `[` on line 2, which needs a closing `]`"
    );
    assert_eq!(
        diagnostic.suggested_action,
        "Complete or remove the unfinished item."
    );
}

#[test]
fn cfg_yaml_8_an_error_inside_an_open_bracket_names_the_bracket() {
    for (text, path, position, message, action) in [
        (
            "tags: [a, b\nother: 1\n",
            "/tags/1",
            (2, 6),
            "the YAML is not well formed here, inside the list opened with `[` on line 1 (the parser reports: illegal placement of ':' indicator)",
            "Close the list with `]` where it ends, or check the punctuation at this position.",
        ),
        (
            "name: {a: 1\nother: 2\n",
            "/name",
            (2, 6),
            "the YAML is not well formed here, inside the mapping opened with `{` on line 1 (the parser reports: while parsing a flow mapping, did not find expected ',' or '}')",
            "Close the mapping with `}` where it ends, or check the punctuation at this position.",
        ),
    ] {
        let report = scan_refusal(text);
        assert_diagnostic(
            only(&report),
            "yaml.syntax",
            path,
            position,
            message,
            action,
        );
    }
}

#[test]
fn cfg_yaml_8_a_tab_after_a_colon_is_named_at_the_tab() {
    for (text, path, position) in [
        ("name:\tx\n", "", (1, 6)),
        ("outer:\n  a:\tx\n", "/outer", (2, 5)),
        ("- name:\t-x\n", "/0", (1, 8)),
    ] {
        let report = scan_refusal(text);
        assert_diagnostic(
            only(&report),
            "yaml.syntax",
            path,
            position,
            "a tab after `:` is not read as the space before an unquoted value",
            "Write a space after `:` in place of the tab.",
        );
    }
    // A tab is read as that space before a quoted or bracketed value.
    for text in ["a:\t\"x\"\n", "a:\t[1]\n", "a: \tx\n"] {
        Reader::new(FILE)
            .scan(text.as_bytes())
            .unwrap_or_else(|report| panic!("{report}"));
    }
}

#[test]
fn cfg_yaml_8_other_syntax_errors() {
    let report = scan_refusal("a: 1\n- b\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "yaml.syntax");
    // The parser stops after the `- ` indicator it did not expect.
    assert_eq!(at(diagnostic), (2, 3));
    assert_eq!(
        diagnostic.suggested_action,
        "Check the indentation and punctuation at this position."
    );
}

#[test]
fn cfg_yaml_8_syntax_codes_are_the_closed_list() {
    let closed = [
        "yaml.tab-indentation",
        "yaml.unclosed-quote",
        "yaml.colon-in-plain-value",
        "yaml.unexpected-end",
        "yaml.invalid-escape",
        "yaml.text-after-quote",
        "yaml.syntax",
    ];
    for text in [
        "a:\n\tb: 1\n",
        "a: 'x\n",
        "a: b: c\n",
        "a: {b: 1\n",
        "a: 1\n- b\n",
        "]\n",
        "a: b\n c: d\n",
        "key: [a, b]]\n",
        "- a\nb: c\n",
        "a: \"\\q\"\n",
        "a: 'it's'\n",
    ] {
        let report = scan_refusal(text);
        let diagnostic = only(&report);
        assert!(
            closed.contains(&diagnostic.code.as_str()),
            "{text:?}: {report}"
        );
        let source = diagnostic.source.as_ref().unwrap();
        assert!(source.line.is_some() && source.column.is_some(), "{text:?}");
        assert_eq!(diagnostic.severity, Severity::Error);
    }
}

// ----- CFG-ENV-4 -----

#[test]
fn cfg_env_4_a_leading_start_marker_and_a_final_end_marker_are_accepted() {
    let text = format!("---\n{ENVELOPE}name: a\n...\n");
    assert!(Reader::new(FILE).read(text.as_bytes(), &EXPECT).is_ok());
    let text = format!("# comment\n---\n{ENVELOPE}...\n# trailing comment\n");
    assert!(Reader::new(FILE).read(text.as_bytes(), &EXPECT).is_ok());
}

#[test]
fn cfg_env_4_a_second_document_is_refused() {
    let text = format!("{ENVELOPE}---\n{ENVELOPE}");
    let report = read_refusal(&text);
    assert_diagnostic(
        only(&report),
        "yaml.multiple-documents",
        "",
        (3, 1),
        "a second YAML document starts here; a file holds one document",
        "Remove the `---` line and what follows it, or move the second document to its own file.",
    );
}

#[test]
fn cfg_env_4_a_document_after_an_end_marker_is_refused() {
    let text = format!("{ENVELOPE}...\n{ENVELOPE}");
    assert_eq!(codes(&read_refusal(&text)), ["yaml.multiple-documents"]);
}

#[test]
fn cfg_env_4_empty_and_comment_only_files_are_a_missing_envelope() {
    for text in [
        "",
        "\n\n",
        "# only a comment\n# and another\n",
        "---\n",
        "---\n...\n",
    ] {
        let report = read_refusal(text);
        assert_diagnostic(
            only(&report),
            "config.missing-envelope",
            "",
            (1, 1),
            "the document is empty; a configuration file starts with apiVersion and kind",
            "Start the file with `apiVersion: id.registrystack.org/formats/example/runtime/v1alpha1` and `kind: ExampleRuntimeConfig`.",
        );
    }
}

// ----- CFG-VAL-1 refusals -----

#[test]
fn cfg_val_1_ambiguous_numbers_are_refused_together() {
    let report = scan_refusal("a: 0x1F\nb: 0123\nc: .inf\nd: .5\ne: -.NaN\nf: 0o17\ng: 5.\n");
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    let code = "yaml.ambiguous-number";
    assert_eq!(
        found,
        [
            (code, "/a"),
            (code, "/b"),
            (code, "/c"),
            (code, "/d"),
            (code, "/e"),
            (code, "/f"),
            (code, "/g"),
        ]
    );
    assert_eq!(
        report.diagnostics()[0].suggested_action,
        "Write the number in decimal digits; quote it only where the key takes text."
    );
}

#[test]
fn cfg_val_1_quoted_lookalikes_are_text() {
    let NodeValue::Mapping(entries) = scan_ok("a: \"0x1F\"\nb: '0123'\nc: |\n  .inf\n") else {
        panic!("a mapping");
    };
    assert!(entries
        .iter()
        .all(|entry| matches!(entry.value.value, NodeValue::String(_))));
}

#[test]
fn cfg_val_1_integer_literals_outside_the_representable_range_are_refused() {
    let report = scan_refusal("a: 18446744073709551616\nb: -9223372036854775809\nc: 1e999\n");
    assert_eq!(
        codes(&report),
        [
            "config.out-of-range",
            "config.out-of-range",
            "config.out-of-range"
        ]
    );
    assert_no_marker(&report);
}

#[test]
fn cfg_val_1_a_control_character_in_a_text_value_is_refused() {
    let report = scan_refusal(
        "a: \"x\\0y\"\nb: \"x\\ay\"\nc: \"x\\x01y\"\nd: x\u{1}y\ne: |\n  x\u{1b}y\nf: [\"\\u001f\"]\n",
    );
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    let code = "yaml.control-character";
    assert_eq!(
        found,
        [
            (code, "/a"),
            (code, "/b"),
            (code, "/c"),
            (code, "/d"),
            (code, "/e"),
            (code, "/f/0"),
        ]
    );
    assert_diagnostic(
        &report.diagnostics()[0],
        code,
        "/a",
        (1, 4),
        "the text holds a control character other than tab, line feed, or carriage return",
        "Remove the character; in a double-quoted value, look for an escape such as `\\0`, `\\a`, `\\e`, or `\\x01`.",
    );
}

#[test]
fn cfg_val_1_delete_and_a_c1_control_character_in_a_text_value_are_refused() {
    let report = scan_refusal(
        "a: \"x\\x7fy\"\nb: \"x\\x80y\"\nc: \"x\\Ny\"\nd: \"x\\u009fy\"\ne: \"x\u{7f}y\"\nf: \"x\u{85}y\"\ng: \"x\u{9b}y\"\n",
    );
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    let code = "yaml.control-character";
    assert_eq!(
        found,
        [
            (code, "/a"),
            (code, "/b"),
            (code, "/c"),
            (code, "/d"),
            (code, "/e"),
            (code, "/f"),
            (code, "/g"),
        ]
    );
}

#[test]
fn cfg_val_1_a_mapping_key_holding_a_control_character_is_refused_without_repeating_it() {
    let text = format!("ok: 1\n\"{MARKER}\\e\": 2\nnested:\n  \"{MARKER}\u{7f}\": 3\n");
    let report = scan_refusal(&text);
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    let code = "yaml.control-character";
    assert_eq!(found, [(code, ""), (code, "/nested")]);
    assert_eq!(at(&report.diagnostics()[0]), (2, 1));
    assert_eq!(at(&report.diagnostics()[1]), (4, 3));
    assert_no_marker(&report);
}

#[test]
fn cfg_sec_3_debug_of_a_node_shows_no_value_and_no_key() {
    let node = scan_ok(&format!(
        "{MARKER}-key: 8443\nflag: true\nratio: 1.5\nname: {MARKER}\n"
    ));
    let printed = format!("{node:?}");
    for leaked in [MARKER, "8443", "true", "1.5", "flag", "ratio", "name"] {
        assert!(!printed.contains(leaked), "{leaked}: {printed}");
    }
    assert!(printed.contains("Integer(<redacted>)"), "{printed}");
    assert!(printed.contains("<redacted>"), "{printed}");
}

#[test]
fn cfg_val_1_text_around_the_c1_range_is_accepted() {
    let NodeValue::Mapping(entries) = scan_ok("a: \"~\\xa0\"\nb: \"\u{a0}\u{e9}\"\n") else {
        panic!("a mapping");
    };
    assert_eq!(entries.len(), 2);
}

#[test]
fn cfg_val_1_tab_line_feed_and_carriage_return_are_text() {
    let NodeValue::Mapping(entries) = scan_ok("a: \"x\\ty\\nz\\r\"\nb: \"x\ty\"\nc: |\n  x\n  y\n")
    else {
        panic!("a mapping");
    };
    assert_eq!(entries.len(), 3);
}

#[test]
fn cfg_val_1_a_text_value_refused_for_a_control_character_is_not_offered_to_the_hook() {
    struct Record(Vec<String>);
    impl ScalarHook for Record {
        fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
            self.0.push(site.pointer.to_string());
            Ok(None)
        }
    }
    let mut hook = Record(Vec::new());
    let report = Reader::new(FILE)
        .with_hook(&mut hook)
        .scan(b"a: \"${A}\\0\"\nb: ok\n")
        .unwrap_err();
    assert_eq!(codes(&report), ["yaml.control-character"]);
    assert_eq!(hook.0, ["/b"]);
}

// ----- CFG-DIAG-5 -----

#[test]
fn cfg_diag_5_every_structural_problem_is_reported_in_one_run() {
    let text = format!(
        "{ENVELOPE}base: &a 1\nname: !!str x\nname: y\nport: 0x10\n<<: {{}}\nflag: *a\n1: x\n"
    );
    let report = read_refusal(&text);
    assert_eq!(
        codes(&report),
        [
            "yaml.anchor",
            "yaml.tag",
            "yaml.duplicate-key",
            "yaml.ambiguous-number",
            "yaml.merge-key",
            "yaml.alias",
            "yaml.non-string-key",
        ]
    );
    let lines: Vec<usize> = report.diagnostics().iter().map(|d| at(d).0).collect();
    assert_eq!(lines, [3, 4, 5, 6, 7, 8, 9]);
}

#[test]
fn cfg_diag_5_structural_and_envelope_problems_are_reported_together() {
    let report = read_refusal("kind: SomethingElse\nname: a\nname: b\n");
    assert_eq!(
        codes(&report),
        [
            "config.missing-envelope",
            "config.wrong-kind",
            "yaml.duplicate-key"
        ]
    );
}

#[test]
fn cfg_diag_5_a_syntax_error_stops_the_read_alone() {
    // Past a syntax error the parser cannot say where anything is.
    let report = read_refusal("kind: x\nname: &a b\nc: \"open\n");
    assert_eq!(codes(&report), ["yaml.anchor", "yaml.unclosed-quote"]);
}

/// `count` repeats of one key after its first definition: one duplicate
/// problem each, on lines 2 to `count + 1`.
fn repeated_key(count: usize) -> String {
    "name: a\n".repeat(count + 1)
}

#[test]
fn cfg_diag_5_a_file_reports_at_most_the_bound_then_counts_the_rest() {
    let report = scan_refusal(&repeated_key(MAXIMUM_DIAGNOSTICS_PER_FILE + 50));
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), MAXIMUM_DIAGNOSTICS_PER_FILE + 1);
    let shown = &diagnostics[..MAXIMUM_DIAGNOSTICS_PER_FILE];
    assert!(shown.iter().all(|d| d.code == "yaml.duplicate-key"));
    // The first problems by position are the ones shown.
    assert_eq!(at(&shown[0]), (2, 1));
    assert_eq!(at(&shown[MAXIMUM_DIAGNOSTICS_PER_FILE - 1]), (101, 1));
    let rest = &diagnostics[MAXIMUM_DIAGNOSTICS_PER_FILE];
    assert_eq!(rest.severity, Severity::Error);
    assert_eq!(rest.code, "config.too-many-problems");
    assert_eq!(rest.path, "");
    assert_eq!(rest.message, "50 more problems in this file are not shown");
    assert_eq!(
        rest.suggested_action,
        "Fix the problems shown, then check the file again."
    );
    let source = rest.source.as_ref().expect("the count names the file");
    assert_eq!(
        (source.file.as_str(), source.line, source.column),
        (FILE, None, None)
    );
    assert_eq!(report.summary(), "101 errors, 0 warnings in 1 file");
}

#[test]
fn cfg_diag_5_the_count_of_problems_not_shown_is_exact() {
    let report = scan_refusal(&repeated_key(MAXIMUM_DIAGNOSTICS_PER_FILE + 1));
    let rest = report.diagnostics().last().expect("a diagnostic");
    assert_eq!(rest.code, "config.too-many-problems");
    assert_eq!(rest.message, "1 more problem in this file is not shown");

    let report = scan_refusal(&repeated_key(MAXIMUM_DIAGNOSTICS_PER_FILE));
    assert_eq!(report.diagnostics().len(), MAXIMUM_DIAGNOSTICS_PER_FILE);
    assert!(report
        .diagnostics()
        .iter()
        .all(|d| d.code == "yaml.duplicate-key"));
}

#[test]
fn cfg_diag_5_the_problems_shown_are_the_first_by_position_not_the_first_found() {
    // A list used as a key is refused where it starts, which the reader
    // learns only when the list ends, after every problem inside it.
    let items = MAXIMUM_DIAGNOSTICS_PER_FILE + 50;
    let key: String = (0..items)
        .map(|index| {
            if index == 0 {
                "? - 0123\n"
            } else {
                "  - 0123\n"
            }
        })
        .collect();
    let report = scan_refusal(&format!("{key}: a\n"));
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), MAXIMUM_DIAGNOSTICS_PER_FILE + 1);
    assert_eq!(diagnostics[0].code, "yaml.non-string-key");
    assert_eq!(diagnostics[0].path, "");
    assert_eq!(at(&diagnostics[0]), (1, 3));
    let inside = &diagnostics[1..MAXIMUM_DIAGNOSTICS_PER_FILE];
    for (index, diagnostic) in inside.iter().enumerate() {
        assert_eq!(diagnostic.code, "yaml.ambiguous-number");
        assert_eq!(diagnostic.path, format!("/{index}"));
        assert_eq!(at(diagnostic), (index + 1, 5));
    }
    let rest = &diagnostics[MAXIMUM_DIAGNOSTICS_PER_FILE];
    assert_eq!(rest.code, "config.too-many-problems");
    assert_eq!(rest.message, "51 more problems in this file are not shown");
}

#[test]
fn cfg_diag_5_problems_of_two_kinds_past_the_bound_keep_their_order() {
    // A number that is not a plain decimal is a structural problem; one too
    // large to read is kept apart until the read knows it will not decode.
    let pairs = MAXIMUM_DIAGNOSTICS_PER_FILE / 2 + 30;
    let report = scan_refusal(&"- 0123\n- 99999999999999999999999\n".repeat(pairs));
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), MAXIMUM_DIAGNOSTICS_PER_FILE + 1);
    for (index, diagnostic) in diagnostics[..MAXIMUM_DIAGNOSTICS_PER_FILE]
        .iter()
        .enumerate()
    {
        let code = if index % 2 == 0 {
            "yaml.ambiguous-number"
        } else {
            "config.out-of-range"
        };
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.path, format!("/{index}"));
        assert_eq!(at(diagnostic), (index + 1, 3));
    }
    let rest = &diagnostics[MAXIMUM_DIAGNOSTICS_PER_FILE];
    assert_eq!(rest.message, "60 more problems in this file are not shown");
}

#[test]
fn cfg_diag_5_an_envelope_member_refused_past_the_bound_is_not_refused_twice() {
    // The envelope check does not repeat a refusal in other words, whether
    // the refusal is shown or only counted.
    let repeats = "name: a\n".repeat(MAXIMUM_DIAGNOSTICS_PER_FILE + 21);
    let report = read_refusal(&format!("apiVersion: {API_VERSION}\n{repeats}kind: 0123\n"));
    let diagnostics = report.diagnostics();
    assert!(diagnostics[..MAXIMUM_DIAGNOSTICS_PER_FILE]
        .iter()
        .all(|d| d.code == "yaml.duplicate-key"));
    let rest = &diagnostics[MAXIMUM_DIAGNOSTICS_PER_FILE];
    assert_eq!(rest.message, "21 more problems in this file are not shown");

    // A `kind` given twice is refused at its repeat, and the first one is
    // not matched against the expected formats.
    let report = read_refusal(&format!(
        "kind: Other\napiVersion: {API_VERSION}\n{repeats}kind: ExampleRuntimeConfig\n"
    ));
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), MAXIMUM_DIAGNOSTICS_PER_FILE + 1);
    assert!(diagnostics[..MAXIMUM_DIAGNOSTICS_PER_FILE]
        .iter()
        .all(|d| d.code == "yaml.duplicate-key"));
    let rest = &diagnostics[MAXIMUM_DIAGNOSTICS_PER_FILE];
    assert_eq!(rest.message, "21 more problems in this file are not shown");
}
