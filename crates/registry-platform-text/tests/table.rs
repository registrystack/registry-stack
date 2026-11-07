//! Transliteration table validation and digest.

use registry_platform_text::{
    TextError, TransliterationTable, MAX_TABLE_ENTRIES, MAX_TABLE_VALUE_BYTES,
};

#[test]
fn rejects_an_empty_key() {
    assert_eq!(
        TransliterationTable::new([("", "x")]).unwrap_err(),
        TextError::EmptyKey
    );
}

#[test]
fn rejects_a_key_of_more_than_one_character() {
    assert_eq!(
        TransliterationTable::new([("ab", "x")]).unwrap_err(),
        TextError::KeyNotSingleCharacter
    );
    // One scalar value written as base plus combining mark is two characters.
    assert_eq!(
        TransliterationTable::new([("e\u{301}", "e")]).unwrap_err(),
        TextError::KeyNotSingleCharacter
    );
}

#[test]
fn rejects_a_duplicate_key() {
    assert_eq!(
        TransliterationTable::new([("a", "x"), ("a", "y")]).unwrap_err(),
        TextError::DuplicateKey
    );
}

#[test]
fn rejects_an_oversized_value() {
    let at_limit = "v".repeat(MAX_TABLE_VALUE_BYTES);
    assert!(TransliterationTable::new([("a", at_limit.as_str())]).is_ok());
    let over = "v".repeat(MAX_TABLE_VALUE_BYTES + 1);
    assert_eq!(
        TransliterationTable::new([("a", over.as_str())]).unwrap_err(),
        TextError::ValueTooLong
    );
}

#[test]
fn bounds_the_number_of_entries() {
    let entries = |count: usize| {
        (0..count)
            .map(|index| {
                (
                    char::from_u32(0x4e00 + index as u32).unwrap().to_string(),
                    "x".to_owned(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        TransliterationTable::new(entries(MAX_TABLE_ENTRIES))
            .unwrap()
            .len(),
        MAX_TABLE_ENTRIES
    );
    assert_eq!(
        TransliterationTable::new(entries(MAX_TABLE_ENTRIES + 1)).unwrap_err(),
        TextError::TooManyEntries
    );
}

#[test]
fn digest_ignores_entry_order() {
    let one = TransliterationTable::new([("a", "x"), ("b", "y")]).unwrap();
    let two = TransliterationTable::new([("b", "y"), ("a", "x")]).unwrap();
    assert_eq!(one.digest(), two.digest());
}

#[test]
fn digest_changes_with_every_part_of_an_entry() {
    let base = TransliterationTable::new([("a", "x")]).unwrap().digest();
    for changed in [
        vec![("a", "y")],
        vec![("b", "x")],
        vec![("a", "x"), ("b", "y")],
        vec![],
    ] {
        assert_ne!(TransliterationTable::new(changed).unwrap().digest(), base);
    }
}

#[test]
fn digest_separates_value_boundaries() {
    let one = TransliterationTable::new([("a", "bc"), ("d", "e")]).unwrap();
    let two = TransliterationTable::new([("a", "b"), ("d", "ce")]).unwrap();
    assert_ne!(one.digest(), two.digest());
}

#[test]
fn digest_is_stable() {
    let table = TransliterationTable::new([("\u{111}", "d"), ("\u{df}", "ss")]).unwrap();
    assert_eq!(
        table.digest(),
        "427067260671d796c6d5b64354bf742a109f98406fd7dc03ea01eb88460ff59a"
    );
    assert_eq!(
        TransliterationTable::empty().digest(),
        "d5a866800ac39f84f0e084ff7fea19d325d06c1a772a1dcf1fcd81e3730335b2"
    );
}
