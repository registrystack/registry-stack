// SPDX-License-Identifier: Apache-2.0
//! Named items written as a mapping from each id to the rest of the item
//! (CFG-ID-5): reading, writing, and the refusals.

mod common;

use common::*;
use registry_platform_yaml::{
    id_keyed, id_keyed_by_local_id, id_keyed_or_list, serialize_id_keyed, Identified, LocalId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Profile {
    id: LocalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    title: Option<String>,
}

impl Identified for Profile {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Profiles {
    #[serde(deserialize_with = "id_keyed", serialize_with = "serialize_id_keyed")]
    profiles: Vec<Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Named {
    #[serde(deserialize_with = "id_keyed_by_local_id")]
    profiles: Vec<Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Either {
    #[serde(deserialize_with = "id_keyed_or_list")]
    profiles: Vec<Profile>,
}

fn ids(profiles: &[Profile]) -> Vec<&str> {
    profiles.iter().map(Identified::id).collect()
}

#[test]
fn a_mapping_reads_as_items_carrying_their_key_as_id() {
    let read = decode::<Profiles>("profiles:\n  intake:\n    title: Intake\n").unwrap();
    assert_eq!(ids(&read.profiles), ["intake"]);
    assert_eq!(read.profiles[0].title.as_deref(), Some("Intake"));
}

#[test]
fn items_are_held_sorted_by_id_whatever_order_the_file_writes() {
    let read = decode::<Profiles>(
        "profiles:\n  zeta:\n    title: Z\n  alpha:\n    title: A\n  mid:\n    title: M\n",
    )
    .unwrap();
    assert_eq!(ids(&read.profiles), ["alpha", "mid", "zeta"]);
}

#[test]
fn a_written_mapping_reads_back_the_same_and_drops_the_inner_id() {
    let read = decode::<Profiles>("profiles:\n  b:\n    title: B\n  a: {}\n").unwrap();
    let value = serde_json::to_value(&read).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"profiles": {"a": {}, "b": {"title": "B"}}})
    );
    let text = format!("{ENVELOPE}profiles:\n  a: {{}}\n  b:\n    title: B\n");
    let again = decode_text::<Profiles>(&text).unwrap();
    assert_eq!(again.profiles, read.profiles);
}

/// The reader refuses a repeated key before decoding, at the repeating key's
/// line, naming the key in the path and the first definition in a note.
fn assert_repeated_key_refused(report: &registry_platform_yaml::Report) {
    let diagnostic = only(report);
    assert_eq!(diagnostic.code, "yaml.duplicate-key", "{diagnostic:?}");
    assert_eq!(diagnostic.path, "/profiles/intake");
    assert_eq!(at(diagnostic), (6, 3));
    assert_eq!(diagnostic.related.len(), 1);
    assert_eq!(diagnostic.related[0].path, "/profiles/intake");
    assert_eq!(diagnostic.related[0].line, Some(4));
}

#[test]
fn a_repeated_key_is_refused_and_names_the_key() {
    assert_repeated_key_refused(&refusal::<Profiles>(
        "profiles:\n  intake: {}\n  review: {}\n  intake: {}\n",
    ));
}

#[test]
fn an_inner_id_is_refused() {
    let report = refusal::<Profiles>("profiles:\n  intake:\n    id: intake\n    title: T\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.duplicate-key", "{diagnostic:?}");
    assert_eq!(diagnostic.path, "/profiles/intake/id");
    assert_eq!(at(diagnostic), (5, 5));
}

#[test]
fn a_list_where_a_mapping_is_expected_names_the_mapping_shape() {
    for body in ["profiles:\n  - id: intake\n", "profiles: []\n"] {
        let report = refusal::<Named>(body);
        let diagnostic = only(&report);
        assert_eq!(diagnostic.code, "config.invalid-type");
        assert_eq!(diagnostic.path, "/profiles");
        assert!(
            diagnostic
                .message
                .contains("a mapping keyed by each item's id"),
            "{diagnostic:?}"
        );
        assert!(
            diagnostic.suggested_action.contains("its id as the key"),
            "{diagnostic:?}"
        );
    }
}

#[test]
fn the_or_list_form_still_reads_a_list() {
    let read = decode::<Either>("profiles:\n  - id: intake\n").unwrap();
    assert_eq!(ids(&read.profiles), ["intake"]);
}

#[test]
fn a_refused_key_of_the_plain_reader_is_placed_at_the_first_member() {
    let report = refusal::<Profiles>("profiles:\n  Intake:\n    title: T\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.invalid-value");
    assert_eq!(diagnostic.path, "/profiles/Intake");
    assert_eq!(at(diagnostic), (5, 5));
}

#[test]
fn a_refused_key_of_the_local_id_reader_is_placed_at_the_key_line() {
    let report = refusal::<Named>("profiles:\n  Intake:\n    title: T\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.invalid-value");
    assert_eq!(diagnostic.path, "/profiles/Intake");
    assert_eq!(at(diagnostic), (4, 3));
}

#[test]
fn the_local_id_reader_reads_a_mapping_sorted_by_id() {
    let read = decode::<Named>("profiles:\n  zeta: {}\n  alpha:\n    title: A\n").unwrap();
    assert_eq!(ids(&read.profiles), ["alpha", "zeta"]);
}

#[test]
fn the_local_id_reader_refuses_a_repeated_key_naming_it() {
    assert_repeated_key_refused(&refusal::<Named>(
        "profiles:\n  intake: {}\n  review: {}\n  intake: {}\n",
    ));
}

#[test]
fn the_local_id_reader_refuses_an_inner_id() {
    let report = refusal::<Named>("profiles:\n  intake:\n    id: intake\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.duplicate-key");
    assert_eq!(at(diagnostic), (5, 5));
}
