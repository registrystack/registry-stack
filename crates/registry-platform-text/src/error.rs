// SPDX-License-Identifier: Apache-2.0
use std::fmt;

/// A refusal from table or pipeline construction, or from applying a
/// pipeline. Variants carry limits and never input text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextError {
    /// A transliteration key was empty.
    EmptyKey,
    /// A transliteration key was more than one character.
    KeyNotSingleCharacter,
    /// Two transliteration entries had the same key.
    DuplicateKey,
    /// A transliteration value exceeded the per-value byte bound.
    ValueTooLong,
    /// A transliteration table exceeded the entry bound.
    TooManyEntries,
    /// A pipeline exceeded the step bound.
    TooManySteps,
    /// A `RemoveChars` step named no characters.
    EmptyRemoveSet,
    /// A `RemoveChars` step exceeded the character bound.
    TooManyRemovedChars,
    /// A `StripNonspacingMarksIn` step named no ranges, a range whose start
    /// is after its end, or more ranges than the bound.
    InvalidMarkRanges,
    /// A `Transliterate` step was declared with an empty table.
    MissingTransliterationTable,
    /// The input exceeded the caller's byte limit.
    InputTooLarge { max_bytes: usize },
    /// A step produced more than the allowed growth over the input limit.
    OutputTooLarge { limit_bytes: usize },
}

impl fmt::Display for TextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKey => formatter.write_str("transliteration key is empty"),
            Self::KeyNotSingleCharacter => {
                formatter.write_str("transliteration key is not a single character")
            }
            Self::DuplicateKey => formatter.write_str("transliteration key is duplicated"),
            Self::ValueTooLong => formatter.write_str("transliteration value is too long"),
            Self::TooManyEntries => {
                formatter.write_str("transliteration table has too many entries")
            }
            Self::TooManySteps => formatter.write_str("pipeline has too many steps"),
            Self::EmptyRemoveSet => {
                formatter.write_str("remove-characters step names no characters")
            }
            Self::TooManyRemovedChars => {
                formatter.write_str("remove-characters step names too many characters")
            }
            Self::InvalidMarkRanges => formatter
                .write_str("strip-marks step needs between 1 and 64 ordered character ranges"),
            Self::MissingTransliterationTable => {
                formatter.write_str("transliterate step needs a non-empty table")
            }
            Self::InputTooLarge { max_bytes } => {
                write!(formatter, "input exceeds {max_bytes} bytes")
            }
            Self::OutputTooLarge { limit_bytes } => {
                write!(formatter, "output exceeds {limit_bytes} bytes")
            }
        }
    }
}

impl std::error::Error for TextError {}
