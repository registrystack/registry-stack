//! Pipeline construction, bounds and fingerprint.

use registry_platform_text::{
    Pipeline, TextError, TextStep, TransliterationTable, MAX_OUTPUT_GROWTH, MAX_REMOVED_CHARS,
    MAX_STEPS, UNICODE_DATA_VERSION,
};

fn table(entries: &[(&str, &str)]) -> TransliterationTable {
    TransliterationTable::new(entries.iter().copied()).unwrap()
}

fn profile() -> (Vec<TextStep>, TransliterationTable) {
    (
        vec![
            TextStep::Nfc,
            TextStep::FullCaseFold,
            TextStep::Transliterate,
            TextStep::RemoveChars(vec!['-', ' ']),
        ],
        table(&[("\u{111}", "d")]),
    )
}

#[test]
fn refuses_oversized_input_before_any_work() {
    let pipeline = Pipeline::new(vec![TextStep::Nfc], TransliterationTable::empty()).unwrap();
    assert_eq!(pipeline.apply("abcd", 4).unwrap(), "abcd");
    assert_eq!(
        pipeline.apply("abcde", 4).unwrap_err(),
        TextError::InputTooLarge { max_bytes: 4 }
    );
    // Length is in bytes, not characters.
    assert_eq!(
        pipeline.apply("\u{e9}\u{e9}", 3).unwrap_err(),
        TextError::InputTooLarge { max_bytes: 3 }
    );
}

#[test]
fn refuses_input_over_the_limit_even_for_an_empty_pipeline() {
    let pipeline = Pipeline::new(vec![], TransliterationTable::empty()).unwrap();
    assert_eq!(pipeline.apply("abc", 3).unwrap(), "abc");
    assert!(pipeline.apply("abcd", 3).is_err());
}

#[test]
fn bounds_output_growth() {
    let pipeline = Pipeline::new(
        vec![TextStep::Transliterate],
        table(&[("a", "aaaaaaaaaaaa")]),
    )
    .unwrap();
    // 12 bytes out for each byte in exceeds the growth bound of 8.
    assert_eq!(
        pipeline.apply("aa", 2).unwrap_err(),
        TextError::OutputTooLarge {
            limit_bytes: 2 * MAX_OUTPUT_GROWTH
        }
    );
}

#[test]
fn allows_growth_within_the_bound() {
    let pipeline =
        Pipeline::new(vec![TextStep::FullCaseFold], TransliterationTable::empty()).unwrap();
    // U+0390 is 2 bytes and folds to 3 characters (6 bytes).
    assert_eq!(pipeline.apply("\u{390}", 2).unwrap().len(), 6);
}

#[test]
fn growth_is_checked_after_every_step() {
    // The first step grows past the bound; the second would shrink it back.
    let pipeline = Pipeline::new(
        vec![TextStep::Transliterate, TextStep::RemoveChars(vec!['a'])],
        table(&[("a", "aaaaaaaaaaaa")]),
    )
    .unwrap();
    assert!(matches!(
        pipeline.apply("a", 1),
        Err(TextError::OutputTooLarge { .. })
    ));
}

#[test]
fn rejects_too_many_steps() {
    let steps = vec![TextStep::Trim; MAX_STEPS + 1];
    assert_eq!(
        Pipeline::new(steps, TransliterationTable::empty()).unwrap_err(),
        TextError::TooManySteps
    );
    let steps = vec![TextStep::Trim; MAX_STEPS];
    assert!(Pipeline::new(steps, TransliterationTable::empty()).is_ok());
}

#[test]
fn rejects_an_empty_or_oversized_remove_set() {
    assert_eq!(
        Pipeline::new(
            vec![TextStep::RemoveChars(vec![])],
            TransliterationTable::empty()
        )
        .unwrap_err(),
        TextError::EmptyRemoveSet
    );
    let many = (0..=MAX_REMOVED_CHARS as u32)
        .map(|index| char::from_u32(0x4e00 + index).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        Pipeline::new(
            vec![TextStep::RemoveChars(many)],
            TransliterationTable::empty()
        )
        .unwrap_err(),
        TextError::TooManyRemovedChars
    );
}

#[test]
fn a_transliterate_step_needs_a_table() {
    assert_eq!(
        Pipeline::new(vec![TextStep::Transliterate], TransliterationTable::empty()).unwrap_err(),
        TextError::MissingTransliterationTable
    );
}

#[test]
fn errors_name_no_input_values() {
    for error in [
        TextError::InputTooLarge { max_bytes: 4 },
        TextError::OutputTooLarge { limit_bytes: 8 },
        TextError::EmptyKey,
        TextError::DuplicateKey,
    ] {
        let text = error.to_string();
        assert!(!text.is_empty());
        assert!(!text.contains('\u{e9}'));
    }
}

#[test]
fn fingerprint_is_stable_for_equal_inputs() {
    let (steps, table_one) = profile();
    let (steps_again, table_two) = profile();
    let one = Pipeline::new(steps, table_one).unwrap();
    let two = Pipeline::new(steps_again, table_two).unwrap();
    assert_eq!(one.fingerprint(), two.fingerprint());
}

#[test]
fn fingerprint_is_golden() {
    let (steps, table) = profile();
    let pipeline = Pipeline::new(steps, table).unwrap();
    assert_eq!(
        pipeline.fingerprint(),
        "text-pipeline-v1:sha256:46763e08ee3598c88635768b2d59a987e21f11b8251f6300f20d151fea661158"
    );
}

#[test]
fn fingerprint_changes_with_the_steps() {
    let (steps, table) = profile();
    let base = Pipeline::new(steps.clone(), table.clone())
        .unwrap()
        .fingerprint();

    let mut fewer = steps.clone();
    fewer.pop();
    assert_ne!(
        Pipeline::new(fewer, table.clone()).unwrap().fingerprint(),
        base
    );

    let mut more = steps.clone();
    more.push(TextStep::Trim);
    assert_ne!(
        Pipeline::new(more, table.clone()).unwrap().fingerprint(),
        base
    );

    let mut swapped = steps.clone();
    swapped.swap(0, 1);
    assert_ne!(
        Pipeline::new(swapped, table.clone()).unwrap().fingerprint(),
        base
    );

    let mut other_set = steps;
    other_set[3] = TextStep::RemoveChars(vec!['-', ' ', '\'']);
    assert_ne!(Pipeline::new(other_set, table).unwrap().fingerprint(), base);
}

#[test]
fn fingerprint_changes_with_the_table() {
    let (steps, table) = profile();
    let base = Pipeline::new(steps.clone(), table).unwrap().fingerprint();
    let changed = Pipeline::new(steps, self::table(&[("\u{111}", "dd")]))
        .unwrap()
        .fingerprint();
    assert_ne!(changed, base);
}

#[test]
fn fingerprint_ignores_remove_set_order_and_duplicates() {
    let make = |chars: Vec<char>| {
        Pipeline::new(
            vec![TextStep::RemoveChars(chars)],
            TransliterationTable::empty(),
        )
        .unwrap()
        .fingerprint()
    };
    assert_eq!(make(vec!['-', ' ']), make(vec![' ', '-', ' ']));
    assert_ne!(make(vec!['-', ' ']), make(vec!['-', '_']));
}

#[test]
fn fingerprint_covers_the_unicode_data_version() {
    let (steps, table) = profile();
    let pipeline = Pipeline::new(steps, table).unwrap();
    // The data version is hashed, not printed, so changing the constant
    // changes the fingerprint; the constant itself is pinned in unicode_version.rs.
    assert!(!UNICODE_DATA_VERSION.is_empty());
    assert!(pipeline
        .fingerprint()
        .starts_with("text-pipeline-v1:sha256:"));
}

#[test]
fn equal_pipelines_produce_equal_output_for_equivalent_spellings() {
    let (steps, table) = profile();
    let pipeline = Pipeline::new(steps, table).unwrap();
    let composed = pipeline.apply("Jean-Luc \u{110}", 64).unwrap();
    let again = pipeline.apply("JEAN LUC \u{111}", 64).unwrap();
    assert_eq!(composed, again);
    assert_eq!(composed, "jeanlucd");
}
