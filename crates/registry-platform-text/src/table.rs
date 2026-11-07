// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::TextError;

/// The most entries a table may hold.
pub const MAX_TABLE_ENTRIES: usize = 4096;
/// The most bytes one replacement may hold.
pub const MAX_TABLE_VALUE_BYTES: usize = 16;

/// A declared single-character to string replacement table.
///
/// Keys are single characters (Unicode scalar values) exactly as written; the
/// table does not normalise them, so a key written in a decomposed form is a
/// two-character key and is refused. A replacement may be empty, which deletes
/// the character.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransliterationTable {
    entries: BTreeMap<char, Box<str>>,
}

impl TransliterationTable {
    /// A table with no entries.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a table from `(key, replacement)` entries.
    pub fn new<K, V>(entries: impl IntoIterator<Item = (K, V)>) -> Result<Self, TextError>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut table = BTreeMap::new();
        for (key, value) in entries {
            let mut characters = key.as_ref().chars();
            let key = characters.next().ok_or(TextError::EmptyKey)?;
            if characters.next().is_some() {
                return Err(TextError::KeyNotSingleCharacter);
            }
            let value = value.as_ref();
            if value.len() > MAX_TABLE_VALUE_BYTES {
                return Err(TextError::ValueTooLong);
            }
            if table.len() == MAX_TABLE_ENTRIES && !table.contains_key(&key) {
                return Err(TextError::TooManyEntries);
            }
            if table.insert(key, Box::<str>::from(value)).is_some() {
                return Err(TextError::DuplicateKey);
            }
        }
        Ok(Self { entries: table })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn get(&self, key: char) -> Option<&str> {
        self.entries.get(&key).map(|value| &**value)
    }

    /// A stable SHA-256 digest (lowercase hex) of the entries in key order,
    /// independent of the order they were supplied in.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"registry-platform-text/transliteration-table/v1\0");
        hasher.update((self.entries.len() as u64).to_be_bytes());
        for (key, value) in &self.entries {
            hasher.update(u32::from(*key).to_be_bytes());
            hasher.update((value.len() as u32).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}
