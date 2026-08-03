//! Tests for the sample-observation stage of `evidencectl source suggest`.
//!
//! `registry-evidencectl` is a binary-only crate (no library target), so the
//! module under test is pulled in directly by path rather than through
//! normal `use registry_evidencectl::...` linkage. `types` is included the
//! same way and declared as a sibling of `sample`, mirroring their real
//! relationship as siblings under `suggest`: `sample.rs` reaches it through
//! `super::types`, and `super` from a crate-root `mod sample;` here is this
//! same crate root, where `mod types;` also lives.

#[path = "../src/suggest/sample.rs"]
mod sample;
#[allow(dead_code)]
#[path = "../src/suggest/types.rs"]
mod types;

use std::{fs, path::PathBuf};

use sample::{load_sample, observe};
use serde_json::json;
use types::Observations;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/samples")
        .join(name)
}

fn load_fixture(name: &str) -> serde_json::Value {
    load_sample(&fixture(name)).unwrap_or_else(|error| panic!("failed to load {name}: {error:#}"))
}

// --- load_sample -----------------------------------------------------------

#[test]
fn load_sample_reads_a_valid_json_file() {
    let value = load_fixture("nested-records.json");
    assert_eq!(value["total"], json!(42));
}

#[test]
fn load_sample_rejects_a_file_that_is_not_valid_json() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("not-json.json");
    fs::write(&path, b"{ this is not json").expect("write fixture");

    let error = load_sample(&path).expect_err("invalid JSON must be rejected");
    assert!(
        error.to_string().contains("not valid JSON"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn load_sample_rejects_a_missing_file() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("missing.json");

    let error = load_sample(&path).expect_err("a missing file must be rejected");
    assert!(
        error
            .to_string()
            .contains("failed to read sample file metadata"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn load_sample_rejects_a_file_over_the_size_ceiling() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("oversized.json");

    // A single 4 MiB+1 array element keeps this a well-formed (if useless)
    // JSON document while tripping the size ceiling before any parsing.
    let mut contents = Vec::with_capacity(4 * 1024 * 1024 + 16);
    contents.extend_from_slice(b"\"");
    contents.resize(contents.len() + 4 * 1024 * 1024 + 1, b'Z');
    contents.extend_from_slice(b"\"");
    fs::write(&path, &contents).expect("write oversized fixture");

    let error = load_sample(&path).expect_err("an oversized file must be rejected");
    let message = error.to_string();
    assert!(message.contains("exceeding"), "unexpected error: {message}");
    // The ceiling is enforced from file metadata alone, before any read, so
    // the fill content can never reach the error message; "ZZZZ" is a
    // pattern a temp-directory path could not plausibly contain.
    assert!(
        !message.contains("ZZZZ"),
        "error message must not echo sample content: {message}"
    );
}

// --- observe: integers -------------------------------------------------------

#[test]
fn observe_tracks_integer_min_and_max_across_every_array_element() {
    let sample = load_fixture("integer-range.json");
    let selection = vec!["/records/*/priority".to_owned()];

    let observations = observe(&sample, &selection).expect("observe");

    let observed = observations
        .by_pointer
        .get("/records/*/priority")
        .expect("priority observed");
    assert_eq!(observed.min_integer, Some(-7));
    assert_eq!(observed.max_integer, Some(12));
    assert!(!observed.saw_null);
    assert_eq!(observed.max_string_bytes, None);
}

// --- observe: strings, unicode ----------------------------------------------

#[test]
fn observe_measures_string_length_in_bytes_not_characters() {
    let sample = load_fixture("unicode.json");
    let selection = vec!["/status".to_owned(), "/note".to_owned()];

    let observations = observe(&sample, &selection).expect("observe");

    // "héllo" is 5 characters but 6 bytes: 'é' is a 2-byte UTF-8 sequence.
    let status = observations
        .by_pointer
        .get("/status")
        .expect("status observed");
    assert_eq!("héllo".chars().count(), 5);
    assert_eq!(status.max_string_bytes, Some(6));

    // "日本語" is 3 characters but 9 bytes: each character is 3 UTF-8 bytes.
    let note = observations.by_pointer.get("/note").expect("note observed");
    assert_eq!("日本語".chars().count(), 3);
    assert_eq!(note.max_string_bytes, Some(9));
}

// --- observe: arrays ---------------------------------------------------------

#[test]
fn observe_records_max_array_items_for_the_wildcard_array_itself() {
    let sample = load_fixture("nested-records.json");
    let selection = vec!["/results/*/trackingId".to_owned()];

    let observations = observe(&sample, &selection).expect("observe");

    let results = observations
        .by_pointer
        .get("/results")
        .expect("results array observed");
    assert_eq!(results.max_array_items, Some(2));

    let tracking_id = observations
        .by_pointer
        .get("/results/*/trackingId")
        .expect("trackingId observed");
    assert_eq!(
        tracking_id.max_string_bytes,
        Some("def-456-longer".len() as u64)
    );
}

#[test]
fn observe_records_max_array_items_for_an_array_selected_wholesale_under_a_wildcard() {
    let sample = load_fixture("nested-records.json");
    // `tags` is itself an array within each record; it is selected without a
    // further `*`, exercising the "array selected wholesale" case nested
    // under an outer wildcard.
    let selection = vec!["/results/*/tags".to_owned()];

    let observations = observe(&sample, &selection).expect("observe");

    let tags = observations
        .by_pointer
        .get("/results/*/tags")
        .expect("tags observed");
    // Record one carries 3 tags, record two carries 1: the largest is kept.
    assert_eq!(tags.max_array_items, Some(3));
}

#[test]
fn observe_records_a_top_level_array_selected_wholesale() {
    let sample = load_fixture("nested-records.json");
    let selection = vec!["/results".to_owned()];

    let observations = observe(&sample, &selection).expect("observe");

    let results = observations
        .by_pointer
        .get("/results")
        .expect("results observed");
    assert_eq!(results.max_array_items, Some(2));
}

// --- observe: nulls and absence ---------------------------------------------

#[test]
fn observe_flags_an_explicit_null_without_recording_a_length() {
    let sample = load_fixture("nulls-and-absent.json");
    let selection = vec!["/recordedOn".to_owned(), "/status".to_owned()];

    let observations = observe(&sample, &selection).expect("observe");

    let recorded_on = observations
        .by_pointer
        .get("/recordedOn")
        .expect("recordedOn observed");
    assert!(recorded_on.saw_null);
    assert_eq!(recorded_on.max_string_bytes, None);

    let status = observations
        .by_pointer
        .get("/status")
        .expect("status observed");
    assert!(!status.saw_null);
    assert_eq!(status.max_string_bytes, Some("active".len() as u64));
}

#[test]
fn observe_leaves_an_absent_pointer_unobserved_without_error() {
    let sample = load_fixture("nulls-and-absent.json");
    let selection = vec!["/doesNotExist".to_owned()];

    let observations = observe(&sample, &selection).expect("an absent pointer is not an error");

    assert!(!observations.by_pointer.contains_key("/doesNotExist"));
    assert!(observations.by_pointer.is_empty());
}

#[test]
fn observe_leaves_a_wildcard_on_a_non_array_unobserved_without_error() {
    let sample = load_fixture("nulls-and-absent.json");
    // `status` is a string, not an array: the `*` segment cannot land.
    let selection = vec!["/status/*/child".to_owned()];

    let observations = observe(&sample, &selection).expect("a type mismatch is not an error");

    assert!(observations.by_pointer.is_empty());
}

#[test]
fn observe_leaves_a_key_lookup_on_a_non_object_unobserved_without_error() {
    let sample = load_fixture("nulls-and-absent.json");
    // `status` is a string, not an object: it has no `child` member.
    let selection = vec!["/status/child".to_owned()];

    let observations = observe(&sample, &selection).expect("a type mismatch is not an error");

    assert!(observations.by_pointer.is_empty());
}

// --- observe: pointer escaping -----------------------------------------------

#[test]
fn observe_unescapes_tilde_one_and_tilde_zero_segments() {
    let sample = load_fixture("escaping.json");
    // "~1" decodes to "/", so "/a~1b" reaches the key "a/b".
    // "~0" decodes to "~", so "/a~0b" reaches the key "a~b".
    let selection = vec!["/a~1b".to_owned(), "/a~0b".to_owned()];

    let observations = observe(&sample, &selection).expect("observe");

    let slash_key = observations.by_pointer.get("/a~1b").expect("a/b observed");
    assert_eq!(slash_key.max_string_bytes, Some("slash-key".len() as u64));

    let tilde_key = observations.by_pointer.get("/a~0b").expect("a~b observed");
    assert_eq!(tilde_key.max_string_bytes, Some("tilde-key".len() as u64));
}

// --- observe: malformed pointer syntax --------------------------------------

#[test]
fn observe_rejects_a_pointer_missing_its_leading_slash() {
    let sample = json!({ "status": "open" });
    let selection = vec!["status".to_owned()];

    let error =
        observe(&sample, &selection).expect_err("a pointer without a leading slash is malformed");
    assert!(error
        .to_string()
        .contains("must be a non-empty extended JSON Pointer"));
}

#[test]
fn observe_rejects_an_empty_pointer() {
    let sample = json!({ "status": "open" });
    let selection = vec![String::new()];

    let error = observe(&sample, &selection).expect_err("an empty pointer is malformed");
    assert!(error
        .to_string()
        .contains("must be a non-empty extended JSON Pointer"));
}

// --- privacy: no sample string value survives into Observations ------------

#[test]
fn observe_never_carries_a_sample_string_value_into_its_debug_rendering() {
    let sample = load_fixture("canary.json");
    let canary = sample["status"].as_str().expect("canary value").to_owned();
    let selection = vec!["/status".to_owned()];

    let observations: Observations = observe(&sample, &selection).expect("observe");

    let rendered = format!("{observations:?}");
    assert!(
        !rendered.contains(&canary),
        "Debug rendering of Observations must never contain a sample string value: {rendered}"
    );
    // The pointer and the derived length are expected to appear; only the
    // value itself must be absent.
    assert!(rendered.contains("/status"));
}
