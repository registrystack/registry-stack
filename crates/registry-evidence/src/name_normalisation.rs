// SPDX-License-Identifier: Apache-2.0
//! The closed name-normalisation profiles behind the `normalise_name` Rhai
//! primitive.
//!
//! A profile is a named, versioned `registry_platform_text::Pipeline` that
//! Evidence owns. The primitive returns the normalised value so a derivation
//! can compare it for exact equality with one expected value normalised the
//! same way. A profile never searches candidates, ranks, or scores similarity.
//! The mechanism lives in `registry-platform-text`; the step list, separator
//! sets and transliteration table below are Evidence policy.

use std::sync::OnceLock;

use registry_platform_text::{Pipeline, TextError, TextStep, TransliterationTable};
use thiserror::Error;

/// The only profile name. The version is part of the name; a changed step,
/// separator set, table entry or Unicode data version is a new profile name.
pub const NAME_MATCH_V1: &str = "name-match-v1";

/// The most bytes of input one call accepts.
pub const MAX_NAME_INPUT_BYTES: usize = 1_024;

/// Hyphen separators removed by `name-match-v1`: hyphen-minus (U+002D),
/// hyphen (U+2010) and non-breaking hyphen (U+2011).
const HYPHENS: [char; 3] = ['\u{002d}', '\u{2010}', '\u{2011}'];

/// Apostrophe separators removed by `name-match-v1`: apostrophe (U+0027),
/// grave accent (U+0060), left and right single quotation marks (U+2018,
/// U+2019), modifier letter apostrophe (U+02BC) and modifier letter turned
/// comma (U+02BB).
const APOSTROPHES: [char; 6] = [
    '\u{0027}', '\u{0060}', '\u{2018}', '\u{2019}', '\u{02bc}', '\u{02bb}',
];

/// Letters with no canonical decomposition that `name-match-v1` maps to
/// ASCII. Keys are lowercase because the table runs after case folding.
const TRANSLITERATIONS: [(&str, &str); 8] = [
    ("\u{0111}", "d"),  // đ
    ("\u{00f0}", "d"),  // ð
    ("\u{00f8}", "o"),  // ø
    ("\u{0142}", "l"),  // ł
    ("\u{00e6}", "ae"), // æ
    ("\u{0153}", "oe"), // œ
    ("\u{0131}", "i"),  // ı
    ("\u{00fe}", "th"), // þ
];

/// The nonspacing-mark ranges `name-match-v1` strips; every other mark is
/// kept because it is part of a spelling. The generic combining diacritic
/// blocks fold the accents of Latin, Greek and Cyrillic; the Arabic vowel
/// signs (U+064B to U+065F, U+0670) and the Hebrew points and cantillation
/// (U+0591 to U+05C7) are optional in everyday writing, so pointed and
/// unpointed spellings match. Brahmic marks (Devanagari virama, nukta and
/// anusvara) and Thai tone marks are outside every range and stay.
const STRIPPED_MARK_RANGES: [(char, char); 8] = [
    ('\u{0300}', '\u{036f}'),
    ('\u{1ab0}', '\u{1aff}'),
    ('\u{1dc0}', '\u{1dff}'),
    ('\u{20d0}', '\u{20ff}'),
    ('\u{fe20}', '\u{fe2f}'),
    ('\u{064b}', '\u{065f}'),
    ('\u{0670}', '\u{0670}'),
    ('\u{0591}', '\u{05c7}'),
];

/// A refusal from `normalise_name`. Variants carry no input text.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum NameNormalisationError {
    #[error("unknown name normalisation profile")]
    UnknownProfile,
    #[error("name input exceeds {MAX_NAME_INPUT_BYTES} bytes")]
    InputTooLarge,
    #[error("name normalisation output exceeds its growth bound")]
    OutputTooLarge,
}

/// The ordered steps of `name-match-v1`.
///
/// Order matters:
/// 1. NFKC folds compatibility forms (full-width Latin, ligatures, no-break
///    spaces) before anything is compared.
/// 2. Full case fold, then NFKC again so the folded text is itself in NFKC.
/// 3. Nonspacing-mark removal in `STRIPPED_MARK_RANGES` runs before transliteration so that a letter
///    that decomposes into a table letter plus a mark (`ǽ` is `æ` plus an
///    acute) reaches the table as the bare table letter.
/// 4. Transliteration of the letters with no decomposition.
/// 5. Invisible shaping characters are removed, whitespace runs collapse to
///    one space, then hyphens, apostrophes and that space are removed.
fn name_match_v1_steps() -> Vec<TextStep> {
    let mut separators: Vec<char> = HYPHENS.into_iter().chain(APOSTROPHES).collect();
    separators.push(' ');
    vec![
        TextStep::Nfkc,
        TextStep::FullCaseFold,
        TextStep::Nfkc,
        TextStep::StripNonspacingMarksIn(STRIPPED_MARK_RANGES.to_vec()),
        TextStep::Transliterate,
        TextStep::RemoveInvisibleShaping,
        TextStep::CollapseWhitespace,
        TextStep::RemoveChars(separators),
    ]
}

fn name_match_v1_table() -> Result<TransliterationTable, TextError> {
    TransliterationTable::new(TRANSLITERATIONS)
}

fn name_match_v1_pipeline() -> &'static Pipeline {
    static PIPELINE: OnceLock<Pipeline> = OnceLock::new();
    PIPELINE.get_or_init(|| {
        name_match_v1_table()
            .and_then(|table| Pipeline::new(name_match_v1_steps(), table))
            .expect("the name-match-v1 steps and table are valid")
    })
}

fn pipeline(profile: &str) -> Result<&'static Pipeline, NameNormalisationError> {
    match profile {
        NAME_MATCH_V1 => Ok(name_match_v1_pipeline()),
        _ => Err(NameNormalisationError::UnknownProfile),
    }
}

/// Normalise one name value under the named profile.
///
/// Input over [`MAX_NAME_INPUT_BYTES`] is refused before any step runs, and
/// the text after any step may not exceed eight times that limit.
pub fn normalise_name(profile: &str, value: &str) -> Result<String, NameNormalisationError> {
    pipeline(profile)?
        .apply(value, MAX_NAME_INPUT_BYTES)
        .map_err(|error| match error {
            TextError::InputTooLarge { .. } => NameNormalisationError::InputTooLarge,
            _ => NameNormalisationError::OutputTooLarge,
        })
}

/// The pinned fingerprint of the named profile: its ordered steps, its
/// transliteration table digest and the Unicode data version.
pub fn profile_fingerprint(profile: &str) -> Result<String, NameNormalisationError> {
    pipeline(profile).map(Pipeline::fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(value: &str) -> String {
        normalise_name(NAME_MATCH_V1, value).expect("within bounds")
    }

    #[test]
    fn composed_and_decomposed_spellings_agree() {
        assert_eq!(norm("Jos\u{e9}"), "jose");
        assert_eq!(norm("Jose\u{301}"), "jose");
        assert_eq!(norm("Zo\u{eb}"), norm("Zoe\u{308}"));
    }

    #[test]
    fn sharp_s_folds_to_ss() {
        assert_eq!(norm("Stra\u{df}e"), "strasse");
        assert_eq!(norm("STRA\u{1e9e}E"), "strasse");
        assert_eq!(norm("strasse"), "strasse");
    }

    #[test]
    fn vietnamese_stacked_marks_are_removed() {
        assert_eq!(
            norm("Nguy\u{1ec5}n Th\u{1ecb} H\u{1b0}\u{1a1}ng"),
            "nguyenthihuong"
        );
        assert_eq!(
            norm("Nguye\u{302}\u{303}n Thi\u{323} Hu\u{31b}o\u{31b}ng"),
            "nguyenthihuong"
        );
        assert_eq!(norm("\u{110}\u{1eb7}ng"), "dang");
        assert_eq!(norm("Tr\u{1ea7}n V\u{103}n"), "tranvan");
    }

    #[test]
    fn dotted_and_dotless_i_follow_the_locale_free_fold() {
        assert_eq!(norm("\u{130}stanbul"), "istanbul");
        assert_eq!(norm("ISTANBUL"), "istanbul");
        assert_eq!(norm("\u{131}spanak"), "ispanak");
        assert_eq!(norm("I\u{11f}d\u{131}r"), "igdir");
        assert_eq!(norm("\u{130}\u{11e}D\u{130}R"), "igdir");
    }

    #[test]
    fn hyphens_apostrophes_and_spaces_are_removed() {
        assert_eq!(norm("Jean-Luc"), "jeanluc");
        assert_eq!(norm("Jean\u{2010}Luc"), "jeanluc");
        assert_eq!(norm("Jean\u{2011}Luc"), "jeanluc");
        for apostrophe in ["'", "`", "\u{2018}", "\u{2019}", "\u{2bc}", "\u{2bb}"] {
            assert_eq!(
                norm(&format!("O{apostrophe}Brien")),
                "obrien",
                "{apostrophe:?}"
            );
        }
        assert_eq!(norm("  Mary \t Ann\u{a0}Smith\n"), "maryannsmith");
        assert_eq!(norm("Mary\u{3000}Ann"), "maryann");
    }

    #[test]
    fn other_dashes_and_punctuation_are_kept() {
        assert_eq!(norm("a\u{2013}b"), "a\u{2013}b");
        assert_eq!(norm("a.b"), "a.b");
    }

    #[test]
    fn full_width_latin_is_folded_by_nfkc() {
        assert_eq!(
            norm("\u{ff21}\u{ff22}\u{ff23}\u{3000}\u{ff24}\u{ff25}\u{ff26}"),
            "abcdef"
        );
        assert_eq!(norm("\u{fb01}scher"), "fischer");
    }

    #[test]
    fn each_transliteration_entry_maps_as_declared() {
        for (letter, capital, expected) in [
            ("\u{111}", "\u{110}", "d"),
            ("\u{f0}", "\u{d0}", "d"),
            ("\u{f8}", "\u{d8}", "o"),
            ("\u{142}", "\u{141}", "l"),
            ("\u{e6}", "\u{c6}", "ae"),
            ("\u{153}", "\u{152}", "oe"),
            ("\u{131}", "I", "i"),
            ("\u{fe}", "\u{de}", "th"),
        ] {
            assert_eq!(norm(letter), expected, "{letter:?}");
            assert_eq!(norm(capital), expected, "{capital:?}");
        }
        assert_eq!(norm("\u{141}ukasz \u{c5}str\u{f6}m"), "lukaszastrom");
        assert_eq!(norm("S\u{f8}ren"), "soren");
        assert_eq!(norm("\u{de}\u{f3}r\u{f0}ur"), "thordur");
    }

    #[test]
    fn a_letter_that_decomposes_to_a_table_letter_reaches_the_table() {
        assert_eq!(norm("\u{1fd}"), "ae");
        assert_eq!(norm("\u{1ff}"), "o");
    }

    #[test]
    fn invisible_shaping_characters_inside_a_name_are_removed() {
        assert_eq!(norm("Ana\u{200d}Maria"), "anamaria");
        assert_eq!(norm("Ana\u{200c}Maria"), "anamaria");
        assert_eq!(norm("Ana\u{200b}Maria"), "anamaria");
        assert_eq!(norm("Ana\u{ad}Maria"), "anamaria");
        assert_eq!(norm("Ana\u{200e}\u{200f}\u{61c}\u{2060}Maria"), "anamaria");
    }

    #[test]
    fn arabic_loses_vowel_points_and_keeps_letters() {
        // Fatha, damma, kasra and shadda are nonspacing marks.
        assert_eq!(
            norm("\u{645}\u{64f}\u{62d}\u{64e}\u{645}\u{64e}\u{651}\u{62f}"),
            "\u{645}\u{62d}\u{645}\u{62f}"
        );
        assert_eq!(
            norm("\u{645}\u{62d}\u{645}\u{62f}"),
            "\u{645}\u{62d}\u{645}\u{62f}"
        );
    }

    #[test]
    fn devanagari_keeps_every_mark_that_is_part_of_the_spelling() {
        // The vowel sign aa (U+093E) is a spacing mark and survives.
        assert_eq!(
            norm("\u{92e}\u{93e}\u{92f}\u{93e}"),
            "\u{92e}\u{93e}\u{92f}\u{93e}"
        );
        // The virama (U+094D), the nukta (U+093C) and the anusvara (U+0902)
        // are nonspacing marks and are kept.
        assert_eq!(
            norm("\u{939}\u{93f}\u{928}\u{94d}\u{926}\u{940}"),
            "\u{939}\u{93f}\u{928}\u{94d}\u{926}\u{940}"
        );
        assert_eq!(norm("\u{91c}\u{93c}"), "\u{91c}\u{93c}");
        assert_eq!(norm("\u{939}\u{93f}\u{902}"), "\u{939}\u{93f}\u{902}");
    }

    #[test]
    fn distinct_devanagari_names_do_not_match() {
        // Each pair differs only by a nonspacing mark.
        for (left, right) in [
            // Without and with a virama between two consonants.
            (
                "\u{939}\u{928}\u{926}\u{940}",
                "\u{939}\u{928}\u{94d}\u{926}\u{940}",
            ),
            // Without and with a nukta.
            ("\u{91c}\u{93e}", "\u{91c}\u{93c}\u{93e}"),
            // Without and with an anusvara.
            ("\u{939}\u{93f}\u{928}", "\u{939}\u{93f}\u{902}\u{928}"),
        ] {
            assert_ne!(norm(left), norm(right), "{left:?} / {right:?}");
        }
    }

    #[test]
    fn latin_and_greek_accents_still_fold() {
        assert_eq!(
            norm("\u{3a3}\u{3af}\u{3c3}\u{3c5}\u{3c6}\u{3bf}\u{3c2}"),
            norm("\u{3c3}\u{3b9}\u{3c3}\u{3c5}\u{3c6}\u{3bf}\u{3c2}")
        );
        assert_eq!(norm("\u{390}"), "\u{3b9}");
        assert_eq!(norm("Cr\u{e8}me"), "creme");
    }

    #[test]
    fn hebrew_with_niqqud_equals_the_unpointed_spelling() {
        // Shalom with shin dot, qamats and a patah, then the unpointed form.
        assert_eq!(
            norm("\u{5e9}\u{5c1}\u{5b8}\u{5dc}\u{5d5}\u{5b9}\u{5dd}"),
            norm("\u{5e9}\u{5dc}\u{5d5}\u{5dd}")
        );
        // A cantillation mark (etnahta, U+0591) is dropped too.
        assert_eq!(norm("\u{5d0}\u{591}\u{5d1}"), norm("\u{5d0}\u{5d1}"));
        assert_eq!(
            norm("\u{5e9}\u{5dc}\u{5d5}\u{5dd}"),
            "\u{5e9}\u{5dc}\u{5d5}\u{5dd}"
        );
    }

    #[test]
    fn a_thai_tone_mark_is_kept() {
        // Mai ek (U+0E48) is a nonspacing mark outside the stripped ranges.
        assert_eq!(norm("\u{e43}\u{e2b}\u{e48}"), "\u{e43}\u{e2b}\u{e48}");
        assert_ne!(norm("\u{e43}\u{e2b}\u{e48}"), norm("\u{e43}\u{e2b}"));
    }

    #[test]
    fn hangul_syllables_and_jamo_agree() {
        assert_eq!(norm("\u{ae40}\u{bbfc}\u{c900}"), "\u{ae40}\u{bbfc}\u{c900}");
        assert_eq!(norm("\u{1100}\u{1175}\u{11b7}"), "\u{ae40}");
    }

    #[test]
    fn output_is_stable_under_a_second_pass() {
        for value in [
            "Nguy\u{1ec5}n Th\u{1ecb}",
            "\u{130}stanbul",
            "\u{141}ukasz",
            "O\u{2019}Brien",
            "STRA\u{1e9e}E",
            "\u{1fd}",
            "\u{939}\u{93f}\u{928}\u{94d}\u{926}\u{940}",
            "\u{1100}\u{1175}\u{11b7}",
        ] {
            let once = norm(value);
            assert_eq!(norm(&once), once, "{value:?}");
        }
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert_eq!(norm(""), "");
        assert_eq!(norm(" - ' "), "");
    }

    #[test]
    fn unknown_profiles_are_refused() {
        for profile in [
            "",
            "name-match-v2",
            "NAME-MATCH-V1",
            "name-match-v1 ",
            "name-match",
        ] {
            assert_eq!(
                normalise_name(profile, "x"),
                Err(NameNormalisationError::UnknownProfile),
                "{profile:?}"
            );
            assert_eq!(
                profile_fingerprint(profile),
                Err(NameNormalisationError::UnknownProfile)
            );
        }
    }

    #[test]
    fn input_is_bounded_in_bytes() {
        let at_limit = "a".repeat(MAX_NAME_INPUT_BYTES);
        assert_eq!(norm(&at_limit), at_limit);
        let over = "a".repeat(MAX_NAME_INPUT_BYTES + 1);
        assert_eq!(
            normalise_name(NAME_MATCH_V1, &over),
            Err(NameNormalisationError::InputTooLarge)
        );
        // The bound is in bytes, not characters: 513 two-byte letters exceed it.
        let wide = "\u{e9}".repeat(MAX_NAME_INPUT_BYTES / 2 + 1);
        assert_eq!(
            normalise_name(NAME_MATCH_V1, &wide),
            Err(NameNormalisationError::InputTooLarge)
        );
    }

    #[test]
    fn output_growth_is_bounded() {
        // U+FDFA is 3 bytes and expands to 33 bytes under NFKC.
        let within_input_bound = "\u{fdfa}".repeat(MAX_NAME_INPUT_BYTES / 3);
        assert!(within_input_bound.len() <= MAX_NAME_INPUT_BYTES);
        assert_eq!(
            normalise_name(NAME_MATCH_V1, &within_input_bound),
            Err(NameNormalisationError::OutputTooLarge)
        );
        // A few of them stay within the bound and expand as declared.
        assert!(!norm("\u{fdfa}").is_empty());
    }

    #[test]
    fn errors_never_carry_input_text() {
        let secret = "Hunter\u{2019}s Secret".repeat(100);
        let error = normalise_name(NAME_MATCH_V1, &secret).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("Hunter"));
        let error = normalise_name("Hunter", "x").unwrap_err();
        assert!(!format!("{error} {error:?}").contains("Hunter"));
    }

    const GOLDEN_FINGERPRINT: &str =
        "text-pipeline-v1:sha256:298be423468d30d635adf179f77b73415cfa303a8461e0a28249a46aad228ded";

    #[test]
    fn fingerprint_matches_the_reviewed_golden() {
        assert_eq!(
            profile_fingerprint(NAME_MATCH_V1).as_deref(),
            Ok(GOLDEN_FINGERPRINT),
            "a changed step, separator, table entry or ICU data pin changes name-match-v1; \
             review the change and publish it as a new profile name"
        );
    }

    #[test]
    fn the_unicode_data_version_is_part_of_the_fingerprint() {
        assert_eq!(
            registry_platform_text::UNICODE_DATA_VERSION,
            "icu4x~2.2.0/unicode-17.0"
        );
    }

    #[test]
    fn reordering_steps_changes_the_fingerprint_and_the_output() {
        let reference = name_match_v1_pipeline().fingerprint();
        let mut steps = name_match_v1_steps();
        let strip = steps
            .iter()
            .position(|step| matches!(step, TextStep::StripNonspacingMarksIn(_)))
            .expect("strip step");
        steps.swap(strip, strip + 1);
        let reordered = Pipeline::new(steps, name_match_v1_table().expect("table")).expect("valid");
        assert_ne!(reordered.fingerprint(), reference);
        // Transliterating before stripping leaves `ǽ` as `æ`.
        assert_eq!(
            reordered.apply("\u{1fd}", MAX_NAME_INPUT_BYTES).as_deref(),
            Ok("\u{e6}")
        );
        assert_eq!(norm("\u{1fd}"), "ae");
    }

    #[test]
    fn a_table_entry_change_changes_the_fingerprint() {
        let reference = name_match_v1_pipeline().fingerprint();
        let table =
            TransliterationTable::new(TRANSLITERATIONS.into_iter().filter(|(k, _)| *k != "\u{fe}"))
                .expect("table");
        let changed = Pipeline::new(name_match_v1_steps(), table).expect("valid");
        assert_ne!(changed.fingerprint(), reference);
    }
}
