//! The display-label comparison key as a fixed pipeline.

use registry_platform_text::display_text_comparison_key;

#[test]
fn key_ignores_case_normalisation_form_and_invisible_shaping() {
    let key = display_text_comparison_key;
    assert_eq!(key("Stra\u{df}e"), "strasse");
    assert_eq!(key("STRA\u{1e9e}E"), "strasse");
    assert_eq!(key("cafe\u{301}"), key("CAF\u{c9}"));
    assert_eq!(key("a\u{ad}b\u{200b}c\u{200f}d\u{2060}e\u{61c}f"), "abcdef");
}

#[test]
fn key_keeps_separators_marks_and_edge_whitespace() {
    let key = display_text_comparison_key;
    assert_eq!(key("  A-B  "), "  a-b  ");
    assert_eq!(key("\u{feff}a"), "\u{feff}a");
    assert_eq!(key("\u{a0}"), "\u{a0}");
    assert_eq!(key("\u{e9}"), "\u{e9}");
}

#[test]
fn key_is_untailored_for_turkish_i() {
    let key = display_text_comparison_key;
    assert_eq!(key("\u{130}"), "i\u{307}");
    assert_eq!(key("I"), "i");
    assert_eq!(key("\u{131}"), "\u{131}");
}

#[test]
fn key_of_empty_text_is_empty() {
    assert_eq!(display_text_comparison_key(""), "");
}
