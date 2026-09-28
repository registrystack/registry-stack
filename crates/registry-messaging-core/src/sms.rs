// SPDX-License-Identifier: Apache-2.0

//! SMS segment counting.
//!
//! A text that fits the GSM 03.38 default alphabet, with its extension table,
//! is encoded in 7-bit septets; any other character forces the whole text
//! into UCS-2. A single message carries 160 septets or 70 UCS-2 code units.
//! A concatenated message loses room to its user-data header and carries 153
//! septets or 67 code units per segment. An extension-table character takes
//! two septets (the escape and the character) and a character outside the
//! Basic Multilingual Plane takes two code units; neither pair is split
//! across segments, the way handsets and gateways pack them.
//!
//! The count is what a sender profile's `maximumSegments` is checked
//! against, so a long message is refused at acceptance rather than billed.

use serde::{Deserialize, Serialize};

/// Septets in one unconcatenated GSM-7 message.
pub const GSM7_SINGLE_SEPTETS: usize = 160;
/// Septets in each segment of a concatenated GSM-7 message.
pub const GSM7_CONCATENATED_SEPTETS: usize = 153;
/// UCS-2 code units in one unconcatenated message.
pub const UCS2_SINGLE_UNITS: usize = 70;
/// UCS-2 code units in each segment of a concatenated message.
pub const UCS2_CONCATENATED_UNITS: usize = 67;

/// The most segments any sender profile may allow.
pub const MAXIMUM_SMS_SEGMENTS: u8 = 10;

/// The encoding a text needs on the air interface.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SmsEncoding {
    Gsm7,
    Ucs2,
}

/// How a text is carried as SMS.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SegmentCount {
    pub encoding: SmsEncoding,
    /// Septets for GSM-7, UTF-16 code units for UCS-2.
    pub units: usize,
    pub segments: usize,
}

/// The GSM 03.38 default alphabet, less the escape to the extension table.
const GSM7_BASIC: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?\
¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";

/// The GSM 03.38 extension table: each costs an escape septet plus itself.
const GSM7_EXTENSION: &str = "\u{c}^{}\\[~]|€";

fn gsm7_septets(character: char) -> Option<usize> {
    if GSM7_BASIC.contains(character) {
        Some(1)
    } else if GSM7_EXTENSION.contains(character) {
        Some(2)
    } else {
        None
    }
}

/// Count the segments `text` needs. An empty text is one segment.
#[must_use]
pub fn count_segments(text: &str) -> SegmentCount {
    let septets: Option<Vec<usize>> = text.chars().map(gsm7_septets).collect();
    let (encoding, widths, single, concatenated) = match septets {
        Some(widths) => (
            SmsEncoding::Gsm7,
            widths,
            GSM7_SINGLE_SEPTETS,
            GSM7_CONCATENATED_SEPTETS,
        ),
        None => (
            SmsEncoding::Ucs2,
            text.chars().map(char::len_utf16).collect(),
            UCS2_SINGLE_UNITS,
            UCS2_CONCATENATED_UNITS,
        ),
    };
    let units: usize = widths.iter().sum();
    if units <= single {
        return SegmentCount {
            encoding,
            units,
            segments: 1,
        };
    }
    let mut segments = 1;
    let mut filled = 0;
    for width in widths {
        if filled + width > concatenated {
            segments += 1;
            filled = 0;
        }
        filled += width;
    }
    SegmentCount {
        encoding,
        units,
        segments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeat(text: &str, times: usize) -> String {
        text.repeat(times)
    }

    #[test]
    fn segment_counts_follow_the_encoding_and_concatenation_rules() {
        let cases: Vec<(&str, String, SmsEncoding, usize, usize)> = vec![
            ("empty", String::new(), SmsEncoding::Gsm7, 0, 1),
            ("one septet", "a".into(), SmsEncoding::Gsm7, 1, 1),
            (
                "single boundary",
                repeat("a", 160),
                SmsEncoding::Gsm7,
                160,
                1,
            ),
            (
                "first concatenation",
                repeat("a", 161),
                SmsEncoding::Gsm7,
                161,
                2,
            ),
            (
                "two full segments",
                repeat("a", 306),
                SmsEncoding::Gsm7,
                306,
                2,
            ),
            ("third segment", repeat("a", 307), SmsEncoding::Gsm7, 307, 3),
            ("basic accents", "déjà Ñ ü".into(), SmsEncoding::Gsm7, 8, 1),
            (
                "extension doubles",
                repeat("€", 80),
                SmsEncoding::Gsm7,
                160,
                1,
            ),
            (
                "extension past single",
                repeat("{", 81),
                SmsEncoding::Gsm7,
                162,
                2,
            ),
            (
                // 152 septets then one escape pair: the pair does not split,
                // so it opens the second segment.
                "extension pair never splits",
                format!("{}{}", repeat("a", 152), repeat("[", 5)),
                SmsEncoding::Gsm7,
                162,
                2,
            ),
            (
                // 306 septets fit two segments only if the pair could split.
                "extension pair forces a third segment",
                format!("{}]{}", repeat("a", 152), repeat("a", 152)),
                SmsEncoding::Gsm7,
                306,
                3,
            ),
            (
                "ucs2 single boundary",
                repeat("é€ç", 23) + "ç",
                SmsEncoding::Ucs2,
                70,
                1,
            ),
            (
                "ucs2 concatenation",
                repeat("ç", 71),
                SmsEncoding::Ucs2,
                71,
                2,
            ),
            (
                "ucs2 two full segments",
                repeat("ç", 134),
                SmsEncoding::Ucs2,
                134,
                2,
            ),
            (
                "ucs2 third segment",
                repeat("ç", 135),
                SmsEncoding::Ucs2,
                135,
                3,
            ),
            (
                "astral counts twice",
                repeat("😀", 35),
                SmsEncoding::Ucs2,
                70,
                1,
            ),
            (
                "astral fits a single message",
                format!("{}😀", repeat("ç", 66)),
                SmsEncoding::Ucs2,
                68,
                1,
            ),
            (
                // 134 units fit two segments only if the pair could split.
                "surrogate pair never splits",
                format!("{}😀{}", repeat("ç", 66), repeat("ç", 66)),
                SmsEncoding::Ucs2,
                134,
                3,
            ),
            (
                "one non-gsm character switches the whole text",
                format!("{}ç", repeat("a", 69)),
                SmsEncoding::Ucs2,
                70,
                1,
            ),
        ];
        for (name, text, encoding, units, segments) in cases {
            let count = count_segments(&text);
            assert_eq!(
                count,
                SegmentCount {
                    encoding,
                    units,
                    segments
                },
                "{name}"
            );
        }
    }

    #[test]
    fn the_gsm_tables_hold_exactly_the_standard_characters() {
        assert_eq!(GSM7_BASIC.chars().count(), 127);
        assert_eq!(GSM7_EXTENSION.chars().count(), 10);
        for character in GSM7_EXTENSION.chars() {
            assert!(!GSM7_BASIC.contains(character), "{character:?}");
        }
        assert_eq!(gsm7_septets('\u{1b}'), None);
    }
}
