// SPDX-License-Identifier: Apache-2.0
use std::sync::LazyLock;

use crate::{Pipeline, TextStep, TransliterationTable};

static DISPLAY_TEXT_COMPARISON: LazyLock<Pipeline> = LazyLock::new(|| {
    Pipeline::new(
        vec![
            TextStep::RemoveInvisibleShaping,
            TextStep::Nfc,
            TextStep::FullCaseFold,
            TextStep::Nfc,
        ],
        TransliterationTable::empty(),
    )
    .expect("the display-text comparison pipeline is valid")
});

/// The comparison key for two display labels.
///
/// NFC normalization surrounds full Unicode case folding. Characters retained
/// for multilingual shaping or direction but invisible to a reviewer do not
/// distinguish two labels.
pub fn display_text_comparison_key(text: &str) -> String {
    // NFC and full case folding grow text by under 3 times, inside the
    // pipeline's growth bound, so the input's own length is a sufficient limit.
    DISPLAY_TEXT_COMPARISON
        .apply(text, text.len())
        .expect("normalisation and case folding stay within the growth bound")
}
