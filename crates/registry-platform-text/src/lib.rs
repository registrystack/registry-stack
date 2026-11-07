// SPDX-License-Identifier: Apache-2.0
//! Deterministic Unicode text normalisation primitives.
//!
//! A [`Pipeline`] applies a closed list of [`TextStep`] values to a string,
//! with a declared [`TransliterationTable`] for the one step that needs data.
//! Steps are plain data, so a product can name and version a profile and pin
//! it with [`Pipeline::fingerprint`]. The crate performs no I/O and holds no
//! product policy; the profiles belong to the products that use them.
//!
//! Every output depends on the Unicode data compiled into ICU4X, so the
//! fingerprint covers [`UNICODE_DATA_VERSION`] as well as the steps. A stored
//! value derived through a pipeline (a blind index, for example) must be
//! recomputed when the fingerprint changes.

mod comparison;
mod error;
mod pipeline;
mod table;

pub use comparison::display_text_comparison_key;
pub use error::TextError;
pub use pipeline::{
    Pipeline, TextStep, MAX_MARK_RANGES, MAX_OUTPUT_GROWTH, MAX_REMOVED_CHARS, MAX_STEPS,
};
pub use table::{TransliterationTable, MAX_TABLE_ENTRIES, MAX_TABLE_VALUE_BYTES};

/// The workspace pin of the ICU4X crates (`icu_casemap`, `icu_normalizer`,
/// `icu_properties`) whose compiled data this crate uses. A test reads the
/// root manifest and fails when the pin moves without this constant.
pub const ICU_VERSION_PIN: &str = "~2.2.0";

/// The Unicode version of the data compiled into that ICU4X release (ICU4X
/// 2.2 is generated from ICU 78, which carries Unicode 17.0).
pub const UNICODE_VERSION: &str = "17.0";

/// The identifier of the Unicode data every pipeline output depends on. It is
/// hashed into [`Pipeline::fingerprint`].
pub const UNICODE_DATA_VERSION: &str = "icu4x~2.2.0/unicode-17.0";
