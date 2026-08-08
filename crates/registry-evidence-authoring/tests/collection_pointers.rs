//! Reading a fact path for the collections it visits.
//!
//! An author bounds every collection their facts walk through, under
//! `source.collectionBounds`, and both a compiler settling those bounds against
//! the facts and an editor drawing the same edge have to name the collections
//! the same way. The cases below are the ones that decide whether two callers
//! agree: the ordinary path, a path visiting nothing, nesting, and the
//! degenerate pointers an author can write by accident.

use registry_evidence_authoring::validate::collection_pointers;

#[test]
fn a_path_visits_the_collection_that_stands_before_each_star() {
    assert_eq!(
        collection_pointers("/records/*/date_of_birth"),
        vec!["/records".to_owned()]
    );
}

#[test]
fn a_path_that_walks_into_no_array_visits_no_collection() {
    assert!(collection_pointers("/date_of_birth").is_empty());
    assert!(collection_pointers("/person/date_of_birth").is_empty());
}

/// Nesting names the outer collection and then the inner one, and the inner
/// pointer keeps the `*` that reached it: that is the pointer the author writes
/// the bound under, because the inner array is a different array in every
/// element of the outer one.
#[test]
fn a_nested_path_visits_one_collection_per_star_from_the_outside_in() {
    assert_eq!(
        collection_pointers("/records/*/events/*/occurred_at"),
        vec!["/records".to_owned(), "/records/*/events".to_owned()]
    );
}

/// A path may end at the collection itself, and the response root may be the
/// collection. Neither is a shape this function judges: it reports what the path
/// visits and the checks that own those rules speak for themselves.
#[test]
fn a_path_ending_at_a_collection_and_a_collection_at_the_root_are_both_read() {
    assert_eq!(
        collection_pointers("/records/*"),
        vec!["/records".to_owned()]
    );
    assert_eq!(collection_pointers("/*"), vec!["/".to_owned()]);
    assert_eq!(
        collection_pointers("/*/date_of_birth"),
        vec!["/".to_owned()]
    );
}

/// A star inside a segment is part of the member's name rather than a walk into
/// an array, so nothing is visited.
#[test]
fn a_star_that_is_not_a_whole_segment_visits_nothing() {
    assert!(collection_pointers("/records*/date_of_birth").is_empty());
    assert!(collection_pointers("/*x/date_of_birth").is_empty());
}

#[test]
fn an_empty_path_visits_nothing() {
    assert!(collection_pointers("").is_empty());
}
