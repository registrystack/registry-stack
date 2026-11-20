// SPDX-License-Identifier: Apache-2.0

//! Field-level canaries: omitted members, derived fields, write responses.

use super::fixture::compile_fixture;
use registry_breg::disclosure::plan;
use registry_breg::model::DisclosureWithhold;

#[test]
fn the_fixture_withholds_contacts_from_the_registrar_only() {
    let registry = compile_fixture();
    let person = &registry.entities()["person"];
    let registrar = plan(person, super::fixture::REGISTRAR);
    let officer = plan(person, super::fixture::PROTECTION_OFFICER);
    assert!(!registrar.is_empty());
    assert!(officer
        .conditions()
        .iter()
        .all(|condition| matches!(condition.withhold, DisclosureWithhold::History)));
    assert_eq!(
        registrar.named_fields().into_iter().collect::<Vec<_>>(),
        ["email-address", "phone-number"]
    );
}
