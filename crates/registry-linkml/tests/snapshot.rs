//! The embedded PublicSchema snapshot reads, and reads as the model the pin
//! says it is. The counts below are facts about the pinned commit; a
//! snapshot refresh that changes them changes this test on purpose.

use registry_linkml::publicschema::{
    self, convergence, featured, label, property_groups, sensitivity, Sensitivity, LANGUAGES,
};
use registry_linkml::Range;

#[test]
fn the_pin_matches_the_embedded_root_schema() {
    let pin = publicschema::pin().expect("PIN.yaml reads");
    let model = publicschema::model().expect("the snapshot reads");
    assert_eq!(pin.version, "0.3.0");
    assert_eq!(model.version.as_deref(), Some(pin.version.as_str()));
    assert_eq!(model.license.as_deref(), Some(pin.license.as_str()));
    assert_eq!(
        pin.repository,
        "https://github.com/PublicSchema/publicschema.org"
    );
    assert_eq!(pin.commit.len(), 40);
    assert_eq!(pin.files.len(), 15);
    assert_eq!(pin.files[0], "schema/publicschema.yaml");
    assert_eq!(model.id, "https://publicschema.org/linkml/publicschema");
    assert_eq!(model.name, "publicschema");
    assert_eq!(model.prefixes["publicschema"], "https://publicschema.org/");
    assert!(
        publicschema::LICENSE_NOTICE.starts_with("Creative Commons Attribution 4.0 International")
    );
}

#[test]
fn the_snapshot_has_the_pinned_shape() {
    let model = publicschema::model().expect("the snapshot reads");
    assert_eq!(model.classes.len(), 63);
    assert_eq!(model.slots.len(), 391);
    assert_eq!(model.enums.len(), 116);
    let values: usize = model.enums.values().map(|e| e.values.len()).sum();
    assert_eq!(values, 10_233);
    let abstract_classes: Vec<&str> = model
        .classes
        .values()
        .filter(|class| class.is_abstract)
        .map(|class| class.name.as_str())
        .collect();
    assert_eq!(
        abstract_classes,
        [
            "Agent",
            "CivilStatusDocument",
            "Credential",
            "Event",
            "Group",
            "Party",
            "Profile",
            "VitalEvent"
        ]
    );
    let featured_count = model
        .classes
        .values()
        .filter(|class| featured(class))
        .count();
    assert_eq!(featured_count, 21);
    assert_eq!(model.enums["Language"].values.len(), 7_927);
    assert_eq!(model.enums["Occupation"].values.len(), 619);
}

#[test]
fn person_carries_its_inherited_slots_first() {
    let model = publicschema::model().expect("the snapshot reads");
    let person = &model.classes["Person"];
    assert_eq!(person.uri, "https://publicschema.org/Person");
    assert_eq!(person.is_a.as_deref(), Some("Party"));
    assert_eq!(person.mixins, ["Agent"]);
    assert!(featured(person));
    assert_eq!(label(person, "en"), Some("Person"));
    assert_eq!(label(person, "fr"), Some("Personne"));
    assert_eq!(label(person, "es"), Some("Persona"));
    let slots = model.induced_slots("Person").expect("Person resolves");
    assert_eq!(slots.len(), 36);
    let first: Vec<&str> = slots
        .iter()
        .take(3)
        .map(|slot| slot.name.as_str())
        .collect();
    assert_eq!(first, ["name", "identifiers", "identity_documents"]);
    assert!(model.is_subclass_of("Household", "Party").unwrap());
    assert!(model.is_subclass_of("Household", "Group").unwrap());
    assert!(!model.is_subclass_of("Person", "Group").unwrap());
    let groups = property_groups(person).expect("Person declares groups");
    assert_eq!(groups[0].category, "identity");
    assert!(groups[0].properties.contains(&"given_name".to_owned()));
}

#[test]
fn slot_conventions_read_from_the_snapshot() {
    let model = publicschema::model().expect("the snapshot reads");
    let sex = &model.slots["sex"];
    assert_eq!(sex.range, Range::Enum("Sex".into()));
    let sex_values: Vec<&str> = model.enums["Sex"]
        .values
        .iter()
        .map(|value| value.text.as_str())
        .collect();
    assert_eq!(sex_values[..3], ["not_known", "male", "female"]);
    assert_eq!(
        model.enums["Sex"].values[1].meaning.as_deref(),
        Some("https://publicschema.org/Sex/male")
    );
    assert_eq!(label(&model.enums["Sex"].values[1], "fr"), Some("Masculin"));

    let person_ref = &model.slots["person"];
    assert_eq!(person_ref.range, Range::Class("Person".into()));
    assert_eq!(
        sensitivity(person_ref).unwrap(),
        Some(Sensitivity::Sensitive)
    );
    let identifiers = &model.slots["identifiers"];
    assert_eq!(identifiers.range, Range::Class("Identifier".into()));
    assert!(identifiers.multivalued);
    let evidence = convergence(identifiers)
        .unwrap()
        .expect("identifiers has evidence");
    assert_eq!((evidence.system_count, evidence.total_systems), (5, 6));
    assert_eq!(
        publicschema::bespoke_type(&model.slots["geometry"]),
        Some("geojson_geometry")
    );

    // Every convention annotation in the snapshot parses.
    for slot in model.slots.values() {
        convergence(slot).unwrap_or_else(|error| panic!("{error}"));
        sensitivity(slot).unwrap_or_else(|error| panic!("{error}"));
    }
    // The credential classes are the only ones the pinned snapshot leaves
    // without a full set of labels, so a consumer must fall back to the
    // class name.
    let mut unlabelled = Vec::new();
    for class in model.classes.values() {
        convergence(class).unwrap_or_else(|error| panic!("{error}"));
        property_groups(class).unwrap_or_else(|error| panic!("{error}"));
        if LANGUAGES
            .iter()
            .any(|language| label(class, language).is_none())
        {
            unlabelled.push(class.name.as_str());
        }
    }
    assert_eq!(
        unlabelled,
        [
            "Credential",
            "EnrollmentCredential",
            "IdentityCredential",
            "PaymentCredential"
        ]
    );
    assert!(model.slots.values().all(|slot| slot.title.is_some()));
    assert!(model.enums.values().all(|enum_| enum_.title.is_some()));
    let restricted = model
        .slots
        .values()
        .filter(|slot| sensitivity(slot).unwrap() == Some(Sensitivity::Restricted))
        .count();
    assert_eq!(restricted, 3);
}
