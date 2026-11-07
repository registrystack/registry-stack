# Registry Platform Text

`registry-platform-text` provides deterministic, bounded Unicode text normalisation steps (normalisation forms, case folding, mark removal, declared transliteration) that products compose into their own named profiles. It holds the mechanism only; each product owns its profiles.

## Steps

`Nfc`, `Nfkc`, `FullCaseFold` (untailored: no Turkish or Azeri rules), `StripNonspacingMarksIn` (NFD, drop General_Category Mn inside caller-named code point ranges, NFC), `Transliterate` (declared `TransliterationTable`, one pass), `RemoveChars` (declared set), `RemoveInvisibleShaping`, `CollapseWhitespace` and `Trim` (Unicode White_Space).

`Pipeline::apply` refuses input over the caller's byte limit before any work and bounds the text after every step to `MAX_OUTPUT_GROWTH` times that limit. `Pipeline::fingerprint` covers the steps, the table digest and `UNICODE_DATA_VERSION`; a product that stores derived values (a blind index, a stored match key) records the fingerprint and recomputes when it changes. A test fails when the ICU pin in the root `Cargo.toml` moves without the version constants.

`display_text_comparison_key` is the fixed pipeline `registry-platform-yaml` uses to compare display labels.
