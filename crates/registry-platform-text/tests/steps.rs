//! Golden vectors per step. Each case applies a one-step (or small) pipeline.

use registry_platform_text::{Pipeline, TextStep, TransliterationTable};

const MAX: usize = 1024;

/// Combining diacritics (U+0300 to U+036F) and the Arabic vowel signs
/// (U+064B to U+065F).
fn accent_ranges() -> TextStep {
    TextStep::StripNonspacingMarksIn(vec![('\u{300}', '\u{36f}'), ('\u{64b}', '\u{65f}')])
}

fn run(steps: Vec<TextStep>, input: &str) -> String {
    Pipeline::new(steps, TransliterationTable::empty())
        .expect("valid pipeline")
        .apply(input, MAX)
        .expect("within bounds")
}

fn run_with_table(steps: Vec<TextStep>, table: &[(&str, &str)], input: &str) -> String {
    let table = TransliterationTable::new(table.iter().copied()).expect("valid table");
    Pipeline::new(steps, table)
        .expect("valid pipeline")
        .apply(input, MAX)
        .expect("within bounds")
}

#[test]
fn nfc_composes_decomposed_text_and_leaves_composed_text() {
    assert_eq!(run(vec![TextStep::Nfc], "e\u{301}"), "\u{e9}");
    assert_eq!(run(vec![TextStep::Nfc], "\u{e9}"), "\u{e9}");
    assert_eq!(run(vec![TextStep::Nfc], "A\u{30a}"), "\u{c5}");
    assert_eq!(run(vec![TextStep::Nfc], "\u{212b}"), "\u{c5}");
    assert_eq!(run(vec![TextStep::Nfc], "\u{1100}\u{1161}"), "\u{ac00}");
}

#[test]
fn nfc_does_not_apply_compatibility_mappings() {
    assert_eq!(run(vec![TextStep::Nfc], "\u{fb01}"), "\u{fb01}");
    assert_eq!(run(vec![TextStep::Nfc], "\u{ff21}"), "\u{ff21}");
}

#[test]
fn nfkc_applies_compatibility_mappings() {
    assert_eq!(run(vec![TextStep::Nfkc], "\u{fb01}"), "fi");
    assert_eq!(run(vec![TextStep::Nfkc], "\u{ff21}"), "A");
    assert_eq!(run(vec![TextStep::Nfkc], "e\u{301}"), "\u{e9}");
}

#[test]
fn full_case_fold_expands_sharp_s_in_both_cases() {
    let fold = |s| run(vec![TextStep::FullCaseFold], s);
    assert_eq!(fold("Stra\u{df}e"), "strasse");
    assert_eq!(fold("STRA\u{1e9e}E"), "strasse");
    assert_eq!(fold("STRASSE"), "strasse");
    assert_eq!(fold("\u{df}"), "ss");
    assert_eq!(fold("\u{1e9e}"), "ss");
    assert_eq!(fold("ss"), "ss");
}

/// Case folding is untailored. Turkish and Azeri casing is not applied: the
/// capital dotted I folds to "i" plus a combining dot above, the capital
/// undotted I folds to the ordinary "i" (so "ISTANBUL" and "istanbul" agree,
/// unlike Turkish casing), and the lowercase dotless i is left unchanged.
#[test]
fn full_case_fold_is_untailored_for_turkish_i() {
    let fold = |s| run(vec![TextStep::FullCaseFold], s);
    assert_eq!(fold("\u{130}"), "i\u{307}");
    assert_eq!(fold("I"), "i");
    assert_eq!(fold("\u{131}"), "\u{131}");
    assert_eq!(fold("\u{130}stanbul"), "i\u{307}stanbul");
    assert_eq!(fold("ISTANBUL"), "istanbul");
    assert_eq!(fold("\u{131}stanbul"), "\u{131}stanbul");
}

#[test]
fn full_case_fold_maps_greek_final_sigma_and_ligatures() {
    let fold = |s| run(vec![TextStep::FullCaseFold], s);
    assert_eq!(fold("\u{3c2}"), "\u{3c3}");
    assert_eq!(
        fold("\u{3a3}\u{38a}\u{3a3}\u{3a5}\u{3a6}\u{39f}\u{3a3}"),
        "\u{3c3}\u{3af}\u{3c3}\u{3c5}\u{3c6}\u{3bf}\u{3c3}"
    );
    assert_eq!(fold("\u{fb03}"), "ffi");
}

#[test]
fn strip_marks_in_ranges_on_latin() {
    let strip = |s| run(vec![accent_ranges()], s);
    assert_eq!(strip("caf\u{e9}"), "cafe");
    assert_eq!(strip("cafe\u{301}"), "cafe");
    assert_eq!(strip("Cr\u{e8}me Br\u{fb}l\u{e9}e"), "Creme Brulee");
    assert_eq!(strip("M\u{fc}ller"), "Muller");
    assert_eq!(strip("\u{c5}ngstr\u{f6}m"), "Angstrom");
}

#[test]
fn strip_marks_in_ranges_on_greek() {
    let strip = |s| run(vec![accent_ranges()], s);
    assert_eq!(
        strip("\u{3a3}\u{3af}\u{3c3}\u{3c5}\u{3c6}\u{3bf}\u{3c2}"),
        "\u{3a3}\u{3b9}\u{3c3}\u{3c5}\u{3c6}\u{3bf}\u{3c2}"
    );
    // Iota with dialytika and tonos (U+0390) loses both marks.
    assert_eq!(strip("\u{390}"), "\u{3b9}");
}

#[test]
fn strip_marks_in_ranges_on_vietnamese() {
    let strip = |s| run(vec![accent_ranges()], s);
    assert_eq!(strip("Nguy\u{1ec5}n"), "Nguyen");
    assert_eq!(strip("Vi\u{1ec7}t Nam"), "Viet Nam");
    // o with horn is o plus U+031B (nonspacing), so the horn is removed too.
    assert_eq!(strip("\u{1a1}"), "o");
    assert_eq!(strip("Nguye\u{302}\u{303}n"), "Nguyen");
}

#[test]
fn strip_marks_in_ranges_keeps_letters_without_a_decomposition() {
    let strip = |s| run(vec![accent_ranges()], s);
    // Stroked letters have no canonical decomposition; a transliteration
    // table handles them.
    assert_eq!(strip("\u{111}\u{f8}\u{142}"), "\u{111}\u{f8}\u{142}");
}

#[test]
fn strip_marks_in_ranges_keeps_spacing_marks_and_hangul() {
    let strip = |s| run(vec![accent_ranges()], s);
    // Devanagari "ka" + vowel sign aa (spacing mark, Mc) is kept.
    assert_eq!(strip("\u{915}\u{93e}"), "\u{915}\u{93e}");
    // Hangul syllables decompose to jamo (letters) and recompose.
    assert_eq!(strip("\u{ac00}"), "\u{ac00}");
}

#[test]
fn strip_marks_in_ranges_keeps_nonspacing_marks_outside_the_ranges() {
    let strip = |s| run(vec![accent_ranges()], s);
    // Anusvara (U+0902), virama (U+094D) and nukta (U+093C) are nonspacing
    // marks outside the ranges.
    assert_eq!(strip("\u{939}\u{93f}\u{902}"), "\u{939}\u{93f}\u{902}");
    assert_eq!(strip("\u{928}\u{94d}\u{926}"), "\u{928}\u{94d}\u{926}");
    assert_eq!(strip("\u{91c}\u{93c}"), "\u{91c}\u{93c}");
    // A Thai tone mark (U+0E48) is outside the ranges.
    assert_eq!(strip("\u{e2b}\u{e48}"), "\u{e2b}\u{e48}");
}

#[test]
fn strip_marks_in_ranges_strips_inside_the_ranges_only() {
    // Arabic fatha (U+064E) is inside the second range.
    assert_eq!(run(vec![accent_ranges()], "\u{645}\u{64e}"), "\u{645}");
    // With only the accent block, the fatha stays.
    let accents = TextStep::StripNonspacingMarksIn(vec![('\u{300}', '\u{36f}')]);
    assert_eq!(run(vec![accents], "\u{645}\u{64e}"), "\u{645}\u{64e}");
}

#[test]
fn strip_marks_in_ranges_only_removes_nonspacing_marks() {
    // A range that covers letters and spacing marks strips neither: U+093E
    // is a spacing mark and U+0915 a letter.
    let wide = TextStep::StripNonspacingMarksIn(vec![('\u{900}', '\u{97f}')]);
    assert_eq!(run(vec![wide], "\u{915}\u{93e}\u{93c}"), "\u{915}\u{93e}");
}

#[test]
fn strip_marks_ranges_are_validated_and_fingerprinted() {
    let build = |ranges: Vec<(char, char)>| {
        Pipeline::new(
            vec![TextStep::StripNonspacingMarksIn(ranges)],
            TransliterationTable::empty(),
        )
    };
    assert!(build(vec![]).is_err());
    assert!(build(vec![('\u{36f}', '\u{300}')]).is_err());
    let narrow = build(vec![('\u{300}', '\u{36f}')]).expect("valid");
    let wide = build(vec![('\u{300}', '\u{36f}'), ('\u{64b}', '\u{65f}')]).expect("valid");
    assert_ne!(narrow.fingerprint(), wide.fingerprint());
    // Range order does not change the fingerprint.
    let reversed = build(vec![('\u{64b}', '\u{65f}'), ('\u{300}', '\u{36f}')]).expect("valid");
    assert_eq!(wide.fingerprint(), reversed.fingerprint());
}

#[test]
fn transliterate_replaces_declared_characters_only() {
    let table = [
        ("\u{111}", "d"),
        ("\u{f8}", "o"),
        ("\u{e6}", "ae"),
        ("\u{df}", "ss"),
    ];
    let go = |s| run_with_table(vec![TextStep::Transliterate], &table, s);
    assert_eq!(go("\u{111}\u{f8}\u{e6}"), "doae");
    assert_eq!(go("Stra\u{df}e"), "Strasse");
    assert_eq!(go("\u{111}\u{1ed3}ng"), "d\u{1ed3}ng");
    assert_eq!(go("plain"), "plain");
}

#[test]
fn transliterate_is_a_single_pass() {
    let table = [("a", "b"), ("b", "c")];
    assert_eq!(
        run_with_table(vec![TextStep::Transliterate], &table, "ab"),
        "bc"
    );
}

#[test]
fn transliterate_can_delete_with_an_empty_value() {
    let table = [("x", "")];
    assert_eq!(
        run_with_table(vec![TextStep::Transliterate], &table, "axb"),
        "ab"
    );
}

#[test]
fn remove_chars_drops_only_the_declared_set() {
    let remove = |chars: Vec<char>, s| run(vec![TextStep::RemoveChars(chars)], s);
    assert_eq!(remove(vec!['-', ' '], "a-b c"), "abc");
    assert_eq!(
        remove(
            vec!['-', '\u{2010}', '\u{2011}', ' ', '\u{a0}'],
            "a\u{2010}b\u{2011}c\u{a0}d-e f"
        ),
        "abcdef"
    );
    assert_eq!(remove(vec!['-'], "a_b c"), "a_b c");
    assert_eq!(remove(vec!['\''], "O'Brien"), "OBrien");
}

#[test]
fn remove_invisible_shaping_drops_the_fixed_set() {
    let go = |s| run(vec![TextStep::RemoveInvisibleShaping], s);
    assert_eq!(go("a\u{ad}b"), "ab");
    assert_eq!(go("a\u{61c}b"), "ab");
    assert_eq!(
        go("a\u{200b}b\u{200c}c\u{200d}d\u{200e}e\u{200f}f"),
        "abcdef"
    );
    assert_eq!(go("a\u{2060}b"), "ab");
    // The byte order mark is not part of the set.
    assert_eq!(go("\u{feff}a"), "\u{feff}a");
    assert_eq!(go("a-b c"), "a-b c");
}

#[test]
fn collapse_whitespace_replaces_runs_with_one_space() {
    let go = |s| run(vec![TextStep::CollapseWhitespace], s);
    assert_eq!(go("a  b"), "a b");
    assert_eq!(go("a \t\n b\u{a0}\u{2003}c"), "a b c");
    assert_eq!(go("  a  "), " a ");
    assert_eq!(go("a\u{200b}b"), "a\u{200b}b");
    assert_eq!(go(""), "");
}

#[test]
fn trim_removes_edge_whitespace_only() {
    let go = |s| run(vec![TextStep::Trim], s);
    assert_eq!(go("\u{a0} a  b \n"), "a  b");
    assert_eq!(go("   "), "");
    assert_eq!(go("a"), "a");
}

#[test]
fn nfc_and_nfd_spellings_agree_after_a_profile() {
    let steps = vec![TextStep::Nfc, TextStep::FullCaseFold, TextStep::Nfc];
    assert_eq!(
        run(steps.clone(), "M\u{fc}ller"),
        run(steps.clone(), "Mu\u{308}ller")
    );
    assert_eq!(
        run(steps.clone(), "M\u{dc}LLER"),
        run(steps, "Mu\u{308}ller")
    );
}

#[test]
fn a_composed_profile_reduces_a_name_to_a_comparison_value() {
    let steps = vec![
        TextStep::Nfc,
        TextStep::FullCaseFold,
        accent_ranges(),
        TextStep::Transliterate,
        TextStep::RemoveChars(vec!['-', ' ', '\'']),
    ];
    let table = [("\u{111}", "d")];
    assert_eq!(
        run_with_table(steps.clone(), &table, "Jean-Luc \u{110}\u{1eb7}ng"),
        "jeanlucdang"
    );
    assert_eq!(
        run_with_table(steps, &table, "JEAN LUC DANG"),
        "jeanlucdang"
    );
}
