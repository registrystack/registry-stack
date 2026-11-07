//! Regression vectors for the display-label comparison key. The expected
//! values were captured from the implementation before it moved into
//! `registry-platform-text`; the output must stay byte-identical.

use registry_platform_yaml::display_text_comparison_key;

const VECTORS: &[(&str, &str)] = &[
    ("", ""),
    ("Plain", "plain"),
    ("  Padded  ", "  padded  "),
    ("Straße", "strasse"),
    ("STRASSE", "strasse"),
    ("STRAẞE", "strasse"),
    ("café", "café"),
    ("cafe\u{301}", "café"),
    ("CAFE\u{301}", "café"),
    ("İstanbul", "i\u{307}stanbul"),
    ("ISTANBUL", "istanbul"),
    ("ıstanbul", "ıstanbul"),
    ("Σίσυφος", "σίσυφοσ"),
    ("ΣΊΣΥΦΟΣ", "σίσυφοσ"),
    ("ς", "σ"),
    ("ﬃ", "ffi"),
    ("ẞ", "ss"),
    ("a\u{ad}b", "ab"),
    ("a\u{200b}b", "ab"),
    ("a\u{200c}b\u{200d}c", "abc"),
    ("a\u{200e}b\u{200f}c", "abc"),
    ("a\u{2060}b", "ab"),
    ("a\u{61c}b", "ab"),
    ("\u{feff}a", "\u{feff}a"),
    ("a-b", "a-b"),
    ("a b", "a b"),
    ("a\u{a0}b", "a\u{a0}b"),
    ("Å", "å"),
    ("Å", "å"),
    ("A\u{30a}", "å"),
    ("가", "가"),
    ("가", "가"),
    ("ι\u{308}\u{301}", "ΐ"),
    ("ΐ", "ΐ"),
    ("Nguyễn", "nguyễn"),
    ("Nguye\u{302}\u{303}n", "nguyễn"),
    ("Ạ\u{302}", "ậ"),
    ("Ａ", "ａ"),
    ("Ω", "ω"),
    ("Ω", "ω"),
    ("ÿ", "ÿ"),
    ("Ÿ", "ÿ"),
    ("Ǆ", "ǆ"),
    ("ǅ", "ǆ"),
    ("𐐀", "𐐨"),
    ("𐐨", "𐐨"),
    ("a\u{300}\u{323}", "ạ\u{300}"),
    ("a\u{323}\u{300}", "ạ\u{300}"),
];

#[test]
fn comparison_key_matches_captured_vectors() {
    for (input, expected) in VECTORS {
        assert_eq!(
            display_text_comparison_key(input),
            *expected,
            "input {input:?}"
        );
    }
}
