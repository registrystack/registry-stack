// SPDX-License-Identifier: Apache-2.0
use icu_casemap::CaseMapper;
use icu_normalizer::{ComposingNormalizerBorrowed, DecomposingNormalizerBorrowed};
use icu_properties::props::{GeneralCategory, WhiteSpace};
use icu_properties::{CodePointMapData, CodePointSetData};
use sha2::{Digest, Sha256};

use crate::{TextError, TransliterationTable, UNICODE_DATA_VERSION};

/// The most steps a pipeline may hold.
pub const MAX_STEPS: usize = 32;
/// The most characters one `RemoveChars` step may name.
pub const MAX_REMOVED_CHARS: usize = 256;
/// After every step the text may be at most this many times the input limit.
/// Full case folding and canonical decomposition grow text by under 3 times,
/// and a table replacement by at most [`crate::MAX_TABLE_VALUE_BYTES`].
pub const MAX_OUTPUT_GROWTH: usize = 8;

/// The most ranges one `StripNonspacingMarksIn` step may name.
pub const MAX_MARK_RANGES: usize = 64;

/// The characters `RemoveInvisibleShaping` drops: soft hyphen, Arabic letter
/// mark, zero-width space, joiners, directional marks (U+200B to U+200F) and
/// word joiner. They shape or direct neighbouring text without being visible.
const INVISIBLE_SHAPING: [char; 8] = [
    '\u{00ad}', '\u{061c}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{2060}',
];

/// One normalisation step. The vocabulary is closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextStep {
    /// Canonical composition (Unicode NFC).
    Nfc,
    /// Compatibility composition (Unicode NFKC).
    Nfkc,
    /// Full Unicode case folding with no locale tailoring: `ß` and `ẞ` fold
    /// to `ss`, the Turkish dotted capital `İ` folds to `i` plus a combining
    /// dot above, and the dotless `ı` is unchanged.
    FullCaseFold,
    /// Decompose canonically (NFD), drop the nonspacing marks
    /// (General_Category Mn) whose code point lies in one of the inclusive
    /// `(first, last)` ranges, recompose (NFC).
    ///
    /// The caller names the ranges, so a profile strips the accents of the
    /// scripts it folds and keeps the marks that are part of a spelling in
    /// the others (Indic virama, nukta and anusvara, Thai tone marks). Only
    /// Mn is stripped: letters, spacing marks (Mc) such as Indic vowel signs,
    /// and Hangul jamo inside a range are kept. Letters with no decomposition
    /// (`đ`, `ø`, `ł`) are untouched; use `Transliterate` for those.
    StripNonspacingMarksIn(Vec<(char, char)>),
    /// Replace each character found in the pipeline's table, in one pass.
    Transliterate,
    /// Remove every occurrence of the named characters.
    RemoveChars(Vec<char>),
    /// Remove the invisible shaping and direction characters
    /// (U+00AD, U+061C, U+200B to U+200F, U+2060).
    RemoveInvisibleShaping,
    /// Replace each run of Unicode White_Space characters with one U+0020.
    CollapseWhitespace,
    /// Remove leading and trailing White_Space characters.
    Trim,
}

impl TextStep {
    fn write_fingerprint(&self, out: &mut String) {
        match self {
            Self::Nfc => out.push_str("nfc"),
            Self::Nfkc => out.push_str("nfkc"),
            Self::FullCaseFold => out.push_str("full-case-fold"),
            Self::StripNonspacingMarksIn(ranges) => {
                let mut sorted = ranges.clone();
                sorted.sort_unstable();
                sorted.dedup();
                out.push_str("strip-nonspacing-marks-in:");
                for (index, (first, last)) in sorted.iter().enumerate() {
                    if index > 0 {
                        out.push('+');
                    }
                    out.push_str(&format!(
                        "{:04x}-{:04x}",
                        u32::from(*first),
                        u32::from(*last)
                    ));
                }
            }
            Self::Transliterate => out.push_str("transliterate"),
            Self::RemoveChars(chars) => {
                let mut sorted = chars.clone();
                sorted.sort_unstable();
                sorted.dedup();
                out.push_str("remove-chars:");
                for (index, character) in sorted.iter().enumerate() {
                    if index > 0 {
                        out.push('+');
                    }
                    out.push_str(&format!("{:04x}", u32::from(*character)));
                }
            }
            Self::RemoveInvisibleShaping => out.push_str("remove-invisible-shaping"),
            Self::CollapseWhitespace => out.push_str("collapse-whitespace"),
            Self::Trim => out.push_str("trim"),
        }
    }
}

/// A validated, ordered list of steps and the table `Transliterate` uses.
#[derive(Clone, Debug)]
pub struct Pipeline {
    steps: Vec<TextStep>,
    table: TransliterationTable,
}

impl Pipeline {
    pub fn new(steps: Vec<TextStep>, table: TransliterationTable) -> Result<Self, TextError> {
        if steps.len() > MAX_STEPS {
            return Err(TextError::TooManySteps);
        }
        for step in &steps {
            match step {
                TextStep::RemoveChars(chars) if chars.is_empty() => {
                    return Err(TextError::EmptyRemoveSet);
                }
                TextStep::RemoveChars(chars) if chars.len() > MAX_REMOVED_CHARS => {
                    return Err(TextError::TooManyRemovedChars);
                }
                TextStep::StripNonspacingMarksIn(ranges)
                    if ranges.is_empty()
                        || ranges.len() > MAX_MARK_RANGES
                        || ranges.iter().any(|(first, last)| first > last) =>
                {
                    return Err(TextError::InvalidMarkRanges);
                }
                TextStep::Transliterate if table.is_empty() => {
                    return Err(TextError::MissingTransliterationTable);
                }
                _ => {}
            }
        }
        Ok(Self { steps, table })
    }

    /// Apply every step in order. Input over `max_bytes` is refused before
    /// any step runs, and the text after each step may not exceed
    /// `max_bytes * MAX_OUTPUT_GROWTH`.
    pub fn apply(&self, input: &str, max_bytes: usize) -> Result<String, TextError> {
        if input.len() > max_bytes {
            return Err(TextError::InputTooLarge { max_bytes });
        }
        let limit = max_bytes.saturating_mul(MAX_OUTPUT_GROWTH);
        let mut text = input.to_owned();
        for step in &self.steps {
            text = self.run(step, text, limit)?;
            if text.len() > limit {
                return Err(TextError::OutputTooLarge { limit_bytes: limit });
            }
        }
        Ok(text)
    }

    /// A digest (`text-pipeline-v1:sha256:<hex>`) over the steps in order,
    /// the transliteration table digest and the Unicode data version. It
    /// changes whenever the output of [`Pipeline::apply`] can change.
    pub fn fingerprint(&self) -> String {
        let mut canonical = String::from("steps=");
        for (index, step) in self.steps.iter().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            step.write_fingerprint(&mut canonical);
        }
        canonical.push_str("\ntable=");
        canonical.push_str(&self.table.digest());
        canonical.push_str("\nunicode=");
        canonical.push_str(UNICODE_DATA_VERSION);
        let digest = Sha256::digest(canonical.as_bytes());
        format!("text-pipeline-v1:sha256:{}", hex::encode(digest))
    }

    fn run(&self, step: &TextStep, text: String, limit: usize) -> Result<String, TextError> {
        Ok(match step {
            TextStep::Nfc => ComposingNormalizerBorrowed::new_nfc()
                .normalize(&text)
                .into_owned(),
            TextStep::Nfkc => ComposingNormalizerBorrowed::new_nfkc()
                .normalize(&text)
                .into_owned(),
            TextStep::FullCaseFold => CaseMapper::new().fold_string(&text).into_owned(),
            TextStep::StripNonspacingMarksIn(ranges) => {
                let marks = CodePointMapData::<GeneralCategory>::new();
                let decomposed = DecomposingNormalizerBorrowed::new_nfd().normalize(&text);
                let kept = decomposed
                    .chars()
                    .filter(|character| {
                        let stripped = marks.get(*character) == GeneralCategory::NonspacingMark
                            && ranges
                                .iter()
                                .any(|(first, last)| (*first..=*last).contains(character));
                        !stripped
                    })
                    .collect::<String>();
                ComposingNormalizerBorrowed::new_nfc()
                    .normalize(&kept)
                    .into_owned()
            }
            TextStep::Transliterate => {
                let mut out = String::with_capacity(text.len());
                for character in text.chars() {
                    match self.table.get(character) {
                        Some(replacement) => out.push_str(replacement),
                        None => out.push(character),
                    }
                    if out.len() > limit {
                        return Err(TextError::OutputTooLarge { limit_bytes: limit });
                    }
                }
                out
            }
            TextStep::RemoveChars(chars) => text
                .chars()
                .filter(|character| !chars.contains(character))
                .collect(),
            TextStep::RemoveInvisibleShaping => text
                .chars()
                .filter(|character| !INVISIBLE_SHAPING.contains(character))
                .collect(),
            TextStep::CollapseWhitespace => {
                let space = CodePointSetData::new::<WhiteSpace>();
                let mut out = String::with_capacity(text.len());
                let mut in_run = false;
                for character in text.chars() {
                    if space.contains(character) {
                        if !in_run {
                            out.push(' ');
                        }
                        in_run = true;
                    } else {
                        in_run = false;
                        out.push(character);
                    }
                }
                out
            }
            TextStep::Trim => {
                let space = CodePointSetData::new::<WhiteSpace>();
                text.trim_matches(|character| space.contains(character))
                    .to_owned()
            }
        })
    }
}
