// SPDX-License-Identifier: Apache-2.0
//! The sealed source of a predecessor package is read through the shared
//! reader, so YAML outside the configuration subset is not a readable baseline.

use super::{retired_access_spellings_read, PackageError};

#[test]
fn a_predecessor_source_in_the_subset_keeps_its_meaning() {
    let rewritten = retired_access_spellings_read(
        b"accessProfiles:\n- id: staff\n  requiredScopes: []\n  rowBoundaries: []\n",
    )
    .expect("a subset source reads");
    let text = String::from_utf8(rewritten).expect("UTF-8");
    assert!(text.contains("requiredScopes: unrestricted"), "{text}");
    assert!(text.contains("rowBoundaries: unrestricted"), "{text}");
}

#[test]
fn a_predecessor_source_with_an_anchor_and_alias_is_refused() {
    let refused = retired_access_spellings_read(
        b"accessProfiles:\n- id: staff\n  requiredScopes: &scopes []\n- id: other\n  requiredScopes: *scopes\n",
    );
    assert!(
        matches!(refused, Err(PackageError::Derivation)),
        "{refused:?}"
    );
}

#[test]
fn an_empty_predecessor_source_reads_as_null() {
    let rewritten = retired_access_spellings_read(b"# nothing\n").expect("an empty source reads");
    assert_eq!(String::from_utf8(rewritten).expect("UTF-8").trim(), "null");
}
