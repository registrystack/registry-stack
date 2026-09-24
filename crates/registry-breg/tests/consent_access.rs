// SPDX-License-Identifier: Apache-2.0

//! Compiler rules for consent records, recipients and `requireConsent`
//! permissions. Every rule id has at least one refusal here; the PostgreSQL
//! visibility matrix lives in `postgres_consent_access.rs`.

#[path = "support/consent_fixture.rs"]
mod consent_fixture;

use std::collections::BTreeSet;

use consent_fixture::{compile, refusal_codes, source};
use registry_breg::contract::FieldTypeSource;
use registry_breg::evidence_source::{export_evidence_source, EvidenceSourceOptions};
use serde_json::{json, Value};

const PERSON: usize = 0;
const HOUSEHOLD: usize = 1;
const HOUSEHOLD_MEMBER: usize = 2;
const ENROLMENT: usize = 3;
const CONSENT: usize = 4;
const FOOD_TARGETING: usize = 0;
const FEED: usize = 1;
const STEWARD: usize = 2;

fn assert_refused(value: &Value, code: &str) {
    let codes = refusal_codes(value);
    assert!(
        codes.iter().any(|candidate| candidate == code),
        "expected {code}, got {codes:?}"
    );
}

fn consent_field<'a>(value: &'a mut Value, id: &str) -> &'a mut Value {
    value["entities"][CONSENT]["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|field| field["id"] == id)
        .unwrap()
}

fn vocabulary_values(registry: &registry_breg::CompiledRegistry, field: &str) -> Vec<String> {
    match &registry.entities()["consent-decision"].fields[field].field_type {
        FieldTypeSource::VocabularyCode { values, .. } => values.clone(),
        other => panic!("{field} is not a vocabulary code: {other:?}"),
    }
}

#[test]
fn consent_fixture_compiles_with_synthesized_vocabularies_and_feed_bound() {
    let registry = compile(&source()).expect("consent fixture compiles");
    assert_eq!(
        vocabulary_values(&registry, "recipient"),
        ["ngo-alpha", "ngo-beta", "referral-network", "wfp"]
    );
    assert_eq!(
        vocabulary_values(&registry, "scope"),
        ["food-targeting", "food-targeting-2025"]
    );
    let consent = &registry.entities()["consent-decision"];
    let record = consent.consent_record.as_ref().expect("consent record");
    assert_eq!(record.gives, BTreeSet::from(["given".to_owned()]));
    assert_eq!(record.max_duration.iso, "P365D");
    let person = &registry.entities()["person"];
    assert_eq!(person.consent_requirements["food-targeting"].len(), 1);
    assert_eq!(person.consent_requirements["food-targeting"][0].on, "id");
    let enrolment = &registry.entities()["enrolment"];
    assert_eq!(
        enrolment.consent_requirements["food-targeting"][0].on,
        "person"
    );
    // The feed never shows refusals: the compiler adds a decision bound whose
    // value set excludes them.
    let feed = &consent.access_profiles["recipient-feed"];
    let decision_bound = feed
        .row_boundaries
        .iter()
        .find(|boundary| boundary.field == "decision")
        .expect("synthesized decision boundary");
    assert_eq!(
        decision_bound.claim,
        "registry:consent-decisions:consent-decision"
    );
    let recipients = registry.recipients();
    assert_eq!(
        recipients.recipient_set("wfp-scope"),
        BTreeSet::from(["referral-network".to_owned(), "wfp".to_owned()])
    );
    assert!(recipients.recipient_set("unmapped-client").is_empty());
}

#[test]
fn consent_record_must_be_create_only() {
    let mut value = source();
    value["entities"][CONSENT]["mutationMode"] = json!("mutable");
    assert_refused(&value, "consent.record.mutation_mode");
}

#[test]
fn consent_record_fields_have_the_declared_types() {
    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["subject"] = json!("purpose");
    assert_refused(&value, "consent.record.fields");

    let mut value = source();
    consent_field(&mut value, "recipient")["vocabulary"] = json!("data-use-purpose");
    assert_refused(&value, "consent.record.fields");

    let mut value = source();
    consent_field(&mut value, "scope")["vocabulary"] = json!("data-use-purpose");
    assert_refused(&value, "consent.record.fields");

    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["decision"]["field"] = json!("effective-at");
    assert_refused(&value, "consent.record.fields");

    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["validity"]["from"] = json!("decision");
    assert_refused(&value, "consent.record.fields");

    let mut value = source();
    consent_field(&mut value, "effective-at")["required"] = json!(false);
    assert_refused(&value, "consent.record.fields");

    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["validity"]["until"] = json!("unknown-field");
    assert_refused(&value, "consent.record.fields");
}

#[test]
fn consent_record_decision_sets_are_disjoint_and_within_the_vocabulary() {
    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["decision"]["gives"] = json!([]);
    assert_refused(&value, "consent.record.values");

    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["decision"]["revokes"] = json!([]);
    value["entities"][CONSENT]["consentRecord"]["decision"]["refusals"] = json!([]);
    assert_refused(&value, "consent.record.values");

    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["decision"]["gives"] =
        json!(["given", "withdrawn"]);
    assert_refused(&value, "consent.record.values");

    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["decision"]["gives"] = json!(["granted"]);
    assert_refused(&value, "consent.record.values");

    let mut value = source();
    value["entities"][CONSENT]["consentRecord"]["decision"]["refusals"] = json!(["given"]);
    assert_refused(&value, "consent.record.values");
}

#[test]
fn consent_record_max_duration_is_positive_and_bounded() {
    for invalid in [
        "", "P", "PT", "P0D", "P-1D", "365D", "P1.5D", "P3653D", "P10Y1D", "P11Y", "PT1H2X",
    ] {
        let mut value = source();
        value["entities"][CONSENT]["consentRecord"]["validity"]["maxDuration"] = json!(invalid);
        assert_refused(&value, "consent.record.max_duration");
    }
    for valid in ["P10Y", "P3652D", "P1Y2M3W4DT5H6M7S", "PT1S", "P120M"] {
        let mut value = source();
        value["entities"][CONSENT]["consentRecord"]["validity"]["maxDuration"] = json!(valid);
        compile(&value).unwrap_or_else(|failure| panic!("{valid}: {:?}", failure.diagnostics()));
    }
}

/// A consent key or validity field has a reference, vocabulary-code or
/// timestamp type, none of which the source grammar lets carry `encrypted`.
/// That grammar refuses first; `consent.record.plaintext` restates the rule
/// for the compiled record and is proven directly in `consent::tests`.
fn assert_unparseable(value: &Value) {
    let refusal = registry_breg::parse_project_json(&serde_json::to_vec(value).unwrap())
        .expect_err("an encrypted consent key field must not parse");
    assert!(
        format!("{refusal:?}").contains("encrypted requires"),
        "{refusal:?}"
    );
}

#[test]
fn consent_record_key_and_validity_fields_are_plaintext() {
    for field in [
        "subject",
        "recipient",
        "purpose",
        "scope",
        "decision",
        "effective-at",
        "expires-at",
    ] {
        let mut value = source();
        consent_field(&mut value, field)["encrypted"] = json!(true);
        assert_unparseable(&value);
    }
}

#[test]
fn consent_record_is_a_leaf() {
    // Its own profiles cannot require consent.
    let mut value = source();
    value["accessProfiles"][FEED]["permissions"][0]["requireConsent"] =
        json!([{"record": "consent-decision", "on": "subject"}]);
    assert_refused(&value, "consent.record.leaf");

    // No incoming read paths.
    let mut value = source();
    value["entities"][PERSON]["readPaths"] = json!([
        {"id": "decisions", "through": "consent-decision", "to": "household", "route": "decisions"}
    ]);
    value["entities"][CONSENT]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "household", "type": "reference", "target": "household", "classification": "internal"}));
    value["accessProfiles"][FOOD_TARGETING]["permissions"][0]["readPaths"] =
        json!([{"path": "decisions", "readableFields": ["label"]}]);
    assert_refused(&value, "consent.record.leaf");

    // Not the key target of a consent probe.
    let mut value = source();
    let mut second = value["entities"][CONSENT].clone();
    second["id"] = json!("consent-audit");
    second["route"] = json!("consent-audits");
    second["fields"][0]["target"] = json!("consent-decision");
    value["entities"].as_array_mut().unwrap().push(second);
    value["accessProfiles"][FEED]["permissions"][0]["requireConsent"] =
        json!([{"record": "consent-audit", "on": "id"}]);
    assert_refused(&value, "consent.record.leaf");
}

#[test]
fn consent_record_is_never_written_directly() {
    for operation in ["create", "batch"] {
        let mut value = source();
        value["accessProfiles"][STEWARD]["permissions"][4]["operations"] =
            json!(["get", "list", operation]);
        value["accessProfiles"][STEWARD]["permissions"][4]["writableFields"] = json!([
            "subject",
            "recipient",
            "purpose",
            "scope",
            "decision",
            "effective-at",
            "expires-at"
        ]);
        if operation == "batch" {
            value["entities"][CONSENT]["batch"] =
                json!({"maximumItems": 10, "maximumBytes": 65536});
        }
        assert_refused(&value, "consent.record.direct_write");
    }
}

#[test]
fn consent_vocabularies_are_reserved() {
    for id in ["registry-recipients", "registry-consent-scopes"] {
        let mut value = source();
        value["vocabularies"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": id, "values": ["forged"]}));
        assert_refused(&value, "consent.vocabulary.reserved");
    }

    let mut value = source();
    consent_field(&mut value, "recipient")["values"] = json!(["forged"]);
    assert_refused(&value, "consent.vocabulary.reserved");

    let mut value = source();
    value["retiredConsentScopes"] = json!(["food-targeting"]);
    assert_refused(&value, "consent.vocabulary.reserved");

    let mut value = source();
    value["retiredConsentScopes"] = json!(["Not A Code"]);
    assert_refused(&value, "consent.vocabulary.reserved");
}

#[test]
fn consent_actions_declare_an_issuer() {
    let mut value = source();
    value["actions"][0]
        .as_object_mut()
        .unwrap()
        .remove("consentIssuer");
    assert_refused(&value, "consent.issuer.declared");
}

/// A self-issued action in the 5.5 principal-link pattern. An action
/// requirement must name a reference input its effects use, so the consent
/// row also records the link that authorized it.
fn self_issued_project() -> Value {
    let mut value = source();
    value["entities"][CONSENT]["fields"].as_array_mut().unwrap().push(json!(
        {"id": "link", "type": "reference", "target": "consent-subject-link", "classification": "internal"}
    ));
    value["entities"].as_array_mut().unwrap().push(json!({
        "id": "consent-subject-link", "primaryDataset": "consent-dataset", "route": "consent-subject-links",
        "mutationMode": "mutable", "classification": "restricted",
        "fields": [
            {"id": "subject", "type": "reference", "target": "person", "required": true, "classification": "restricted"},
            {"id": "principal", "type": "string", "maxLength": 255, "required": true, "classification": "restricted"},
            {"id": "active", "type": "boolean", "required": true, "classification": "internal"}
        ]
    }));
    value["actions"].as_array_mut().unwrap().push(json!({
        "id": "withdraw-consent",
        "consentIssuer": "self",
        "inputs": [
            {"id": "link", "type": "reference", "target": "consent-subject-link", "required": true, "classification": "internal"},
            {"id": "subject", "type": "reference", "target": "person", "required": true, "classification": "restricted"},
            {"id": "recipient", "type": "vocabulary-code", "vocabulary": "registry-recipients", "required": true, "classification": "internal"},
            {"id": "purpose", "type": "vocabulary-code", "vocabulary": "data-use-purpose", "required": true, "classification": "internal"},
            {"id": "scope", "type": "vocabulary-code", "vocabulary": "registry-consent-scopes", "required": true, "classification": "internal"},
            {"id": "decision", "type": "vocabulary-code", "vocabulary": "consent-decision", "values": ["withdrawn"], "required": true, "classification": "internal"},
            {"id": "effective-at", "type": "timestamp", "required": true, "classification": "internal"}
        ],
        "requires": [
            {"input": "link", "field": "subject", "equalsInput": "subject"},
            {"input": "link", "field": "active", "equals": true}
        ],
        "effects": [{
            "id": "decision", "target": {"entity": "consent-decision"}, "operation": "create",
            "set": {
                "subject": {"fromField": "subject"}, "recipient": {"fromField": "recipient"},
                "purpose": {"fromField": "purpose"}, "scope": {"fromField": "scope"},
                "decision": {"fromField": "decision"}, "effective-at": {"fromField": "effective-at"},
                "link": {"fromField": "link"}
            }
        }]
    }));
    value["accessProfiles"].as_array_mut().unwrap().push(json!({
        "id": "consent-self", "principalClaim": "principal", "requiredScopes": ["consent:self"],
        "permissions": [{
            "action": "withdraw-consent", "operations": ["invoke"],
            "targets": [
                {"entity": "consent-subject-link", "rowBoundaries": [{"field": "principal", "claim": "principal", "operator": "equals"}]},
                {"entity": "person", "rowBoundaries": []},
                {"entity": "consent-decision", "rowBoundaries": []}
            ],
            "results": ["decision"]
        }]
    }));
    value
}

#[test]
fn self_issued_consent_binds_the_subject_through_the_principal_link() {
    compile(&self_issued_project()).unwrap_or_else(|failure| {
        panic!("self-issued action compiles: {:?}", failure.diagnostics())
    });

    // The link must be bound to the caller's principal in every permission.
    let mut value = self_issued_project();
    value["accessProfiles"][3]["permissions"][0]["targets"][0]["rowBoundaries"] = json!([]);
    assert_refused(&value, "consent.issuer.self_binding");

    // The subject must come from the input the link requirement checks.
    let mut value = self_issued_project();
    value["actions"][1]["requires"] = json!([{"input": "link", "field": "active", "equals": true}]);
    assert_refused(&value, "consent.issuer.self_binding");

    // The link must be active.
    let mut value = self_issued_project();
    value["actions"][1]["requires"] =
        json!([{"input": "link", "field": "subject", "equalsInput": "subject"}]);
    assert_refused(&value, "consent.issuer.self_binding");

    // The subject must be set from that input.
    let mut value = self_issued_project();
    value["actions"][1]["inputs"].as_array_mut().unwrap().push(
        json!({"id": "other", "type": "reference", "target": "person", "required": true, "classification": "restricted"}),
    );
    value["actions"][1]["effects"][0]["set"]["subject"] = json!({"fromField": "other"});
    assert_refused(&value, "consent.issuer.self_binding");

    // A steward issuer on the same action is accepted without the binding.
    let mut value = self_issued_project();
    value["actions"][1]["consentIssuer"] = json!("steward");
    value["actions"][1]["requires"] = json!([]);
    compile(&value).unwrap_or_else(|failure| panic!("{:?}", failure.diagnostics()));
}

#[test]
fn gated_permissions_are_read_only() {
    for operation in ["patch", "create", "tombstone"] {
        let mut value = source();
        let permission = &mut value["accessProfiles"][FOOD_TARGETING]["permissions"][0];
        permission["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!(operation));
        permission["writableFields"] = json!(["given-name"]);
        if operation == "tombstone" {
            value["entities"][PERSON]["tombstone"] = json!(true);
        }
        assert_refused(&value, "consent.require.read_only");
    }

    // requireConsent on an action permission is refused.
    let mut value = source();
    value["accessProfiles"][STEWARD]["permissions"][5]["requireConsent"] =
        json!([{"record": "consent-decision", "on": "id"}]);
    assert_refused(&value, "consent.require.read_only");

    // A profile gated on an entity cannot target it through an action.
    let mut value = source();
    let action = value["accessProfiles"][STEWARD]["permissions"][5].clone();
    value["accessProfiles"][FOOD_TARGETING]["permissions"]
        .as_array_mut()
        .unwrap()
        .push(action);
    assert_refused(&value, "consent.require.read_only");
}

#[test]
fn gated_profiles_declare_purposes_from_the_record_vocabulary() {
    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]["requiredPurposes"] = json!([]);
    assert_refused(&value, "consent.require.purpose");

    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]["requiredPurposes"] = json!(["marketing"]);
    assert_refused(&value, "consent.require.purpose");
}

#[test]
fn gated_profiles_declare_mapped_requester_clients() {
    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]
        .as_object_mut()
        .unwrap()
        .remove("requesterClients");
    value["accessProfiles"][FOOD_TARGETING]
        .as_object_mut()
        .unwrap()
        .remove("actorKind");
    assert_refused(&value, "consent.require.clients");

    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]["requesterClients"] =
        json!(["wfp-scope", "unmapped-client"]);
    assert_refused(&value, "consent.require.clients");
}

#[test]
fn consent_key_references_the_consent_subject_entity() {
    // on: id on an entity the consent subject does not reference.
    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]["permissions"][1]["requireConsent"] =
        json!([{"record": "consent-decision", "on": "id"}]);
    assert_refused(&value, "consent.require.key");

    // A non-reference field.
    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]["permissions"][1]["requireConsent"] =
        json!([{"record": "consent-decision", "on": "programme"}]);
    assert_refused(&value, "consent.require.key");

    // A reference to a different entity.
    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]["permissions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "entity": "household-member", "rowBoundaries": [], "operations": ["get"],
            "readableFields": ["household"],
            "requireConsent": [{"record": "consent-decision", "on": "household"}]
        }));
    assert_refused(&value, "consent.require.key");

    // An unknown consent record, or an entity that is not one.
    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]["permissions"][0]["requireConsent"] =
        json!([{"record": "enrolment", "on": "id"}]);
    assert_refused(&value, "consent.require.key");

    // An encrypted key field never parses; `consent::tests` proves the rule.
    let mut value = source();
    value["entities"][ENROLMENT]["fields"][0]["encrypted"] = json!(true);
    assert_unparseable(&value);
}

#[test]
fn anonymous_profiles_cannot_require_consent() {
    let mut value = source();
    value["accessProfiles"].as_array_mut().unwrap().push(json!({
        "id": "public-person", "anonymous": true,
        "permissions": [{
            "entity": "household", "rowBoundaries": [], "operations": ["get"], "readableFields": ["label"],
            "requireConsent": [{"record": "consent-decision", "on": "id"}]
        }]
    }));
    assert_refused(&value, "consent.require.anonymous");
}

#[test]
fn gated_permissions_refuse_spatial_queries() {
    let mut value = source();
    value["entities"][PERSON]["fields"].as_array_mut().unwrap().push(
        json!({"id": "location", "type": "crs84-point", "precision": 4, "classification": "internal"}),
    );
    let permission = &mut value["accessProfiles"][FOOD_TARGETING]["permissions"][0];
    permission["readableFields"] = json!(["given-name", "district", "location"]);
    permission["spatialQueries"] =
        json!({"bbox": {"maximumLongitudeSpanDegrees": 1, "maximumLatitudeSpanDegrees": 1}});
    assert_refused(&value, "consent.require.spatial_unsupported");
}

#[test]
fn gated_permissions_refuse_data_export() {
    let mut value = source();
    value["accessProfiles"][FOOD_TARGETING]["permissions"][0]["allowDataExport"] = json!(true);
    assert_refused(&value, "consent.require.export_unsupported");
}

#[test]
fn read_paths_cannot_reach_a_gated_entity() {
    let mut value = source();
    value["entities"][PERSON]
        .as_object_mut()
        .unwrap()
        .remove("readPaths");
    value["accessProfiles"][FOOD_TARGETING]["permissions"][0]
        .as_object_mut()
        .unwrap()
        .remove("readPaths");
    value["entities"][HOUSEHOLD]["readPaths"] = json!([
        {"id": "members", "through": "household-member", "to": "person", "route": "members"}
    ]);
    value["accessProfiles"][STEWARD]["permissions"][1]["readPaths"] =
        json!([{"path": "members", "readableFields": ["given-name"]}]);
    assert_refused(&value, "consent.require.read_path_target");

    // Nor pass through one.
    let mut value = source();
    value["entities"][HOUSEHOLD_MEMBER]["fields"][0]["target"] = json!("enrolment");
    value["entities"][HOUSEHOLD]["readPaths"] = json!([
        {"id": "enrolments", "through": "household-member", "to": "enrolment", "route": "enrolments"}
    ]);
    value["entities"][PERSON]
        .as_object_mut()
        .unwrap()
        .remove("readPaths");
    value["accessProfiles"][FOOD_TARGETING]["permissions"][0]
        .as_object_mut()
        .unwrap()
        .remove("readPaths");
    value["accessProfiles"][FOOD_TARGETING]["permissions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "entity": "household-member", "rowBoundaries": [], "operations": ["get"],
            "readableFields": ["household"],
            "requireConsent": [{"record": "consent-decision", "on": "id"}]
        }));
    value["accessProfiles"][STEWARD]["permissions"][1]["readPaths"] =
        json!([{"path": "enrolments", "readableFields": ["programme"]}]);
    assert_refused(&value, "consent.require.read_path_target");
}

#[test]
fn evidence_source_export_refuses_a_gated_profile() {
    let registry = compile(&source()).expect("consent fixture compiles");
    let refusal = match export_evidence_source(
        &registry,
        &EvidenceSourceOptions {
            access_profile: "food-targeting".into(),
            entity: "person".into(),
            selectors: vec!["given-name".into()],
            fields: vec!["district".into()],
            source_id: "person-status".into(),
            connection: "registry".into(),
        },
    ) {
        Ok(_) => panic!("a gated profile must not be exported as an Evidence source"),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.code, "consent.require.evidence_source_unsupported");
}

#[test]
fn recipient_ids_are_unique_codes() {
    let mut value = source();
    value["recipients"]["groups"][0]["id"] = json!("wfp");
    assert_refused(&value, "recipients.id");

    let mut value = source();
    value["recipients"]["organizations"][1]["id"] = json!("wfp");
    value["recipients"]["organizations"][1]["clients"] = json!([]);
    assert_refused(&value, "recipients.id");

    let mut value = source();
    value["recipients"]["organizations"][2]["id"] = json!("NGO Beta");
    assert_refused(&value, "recipients.id");

    for field in ["name", "contact"] {
        let mut value = source();
        value["recipients"]["organizations"][0][field] = json!("");
        assert_refused(&value, "recipients.id");
    }
}

#[test]
fn recipient_clients_map_to_one_organization() {
    let mut value = source();
    value["recipients"]["organizations"][2]["clients"] = json!(["wfp-scope"]);
    assert_refused(&value, "recipients.client_unique");
}

#[test]
fn recipient_groups_list_declared_organizations() {
    let mut value = source();
    value["recipients"]["groups"][0]["members"] = json!(["wfp", "unknown"]);
    assert_refused(&value, "recipients.group_members");

    let mut value = source();
    value["recipients"]["groups"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "nested", "name": "Nested", "members": ["referral-network"]}));
    assert_refused(&value, "recipients.group_members");

    let mut value = source();
    value["recipients"]["groups"][0]["members"] = json!(["wfp", "wfp"]);
    assert_refused(&value, "recipients.group_members");
}

#[test]
fn an_organization_belongs_to_at_most_63_groups() {
    let mut value = source();
    let groups = (0..64)
        .map(|index| json!({"id": format!("group-{index}"), "name": "Group", "members": ["wfp"]}))
        .collect::<Vec<_>>();
    value["recipients"]["groups"] = json!(groups);
    assert_refused(&value, "recipients.set_bound");

    let mut value = source();
    let groups = (0..63)
        .map(|index| json!({"id": format!("group-{index}"), "name": "Group", "members": ["wfp"]}))
        .collect::<Vec<_>>();
    value["recipients"]["groups"] = json!(groups);
    compile(&value).unwrap_or_else(|failure| panic!("{:?}", failure.diagnostics()));
}

#[test]
fn the_recipient_claim_binds_only_the_consent_feed() {
    // Not on another field.
    let mut value = source();
    value["accessProfiles"][FEED]["permissions"][0]["rowBoundaries"] =
        json!([{"field": "purpose", "claim": "registry:recipients", "operator": "in"}]);
    assert_refused(&value, "consent.feed.claim");

    // Not with equals.
    let mut value = source();
    value["accessProfiles"][FEED]["permissions"][0]["rowBoundaries"] =
        json!([{"field": "recipient", "claim": "registry:recipients", "operator": "equals"}]);
    assert_refused(&value, "consent.feed.claim");

    // Not on a non-consent entity.
    let mut value = source();
    value["accessProfiles"][FEED]["permissions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "entity": "household", "operations": ["get"], "readableFields": ["label"],
            "rowBoundaries": [{"field": "label", "claim": "registry:recipients", "operator": "in"}]
        }));
    assert_refused(&value, "consent.feed.claim");

    // Not beyond get and list.
    let mut value = source();
    value["accessProfiles"][FEED]["permissions"][0]["operations"] =
        json!(["get", "list", "lookup"]);
    value["entities"][CONSENT]["selectorProfiles"] =
        json!([{"id": "subject", "fields": ["subject"]}]);
    value["accessProfiles"][FEED]["permissions"][0]["lookups"] =
        json!([{"selector": "subject", "valueOrigin": "request"}]);
    assert_refused(&value, "consent.feed.claim");

    // Not in an action target.
    let mut value = source();
    value["accessProfiles"][STEWARD]["permissions"][5]["targets"][1]["rowBoundaries"] =
        json!([{"field": "recipient", "claim": "registry:recipients", "operator": "in"}]);
    assert_refused(&value, "consent.feed.claim");

    // The synthesized decision claim is never authored.
    let mut value = source();
    value["accessProfiles"][FEED]["permissions"][0]["rowBoundaries"] = json!([
        {"field": "recipient", "claim": "registry:recipients", "operator": "in"},
        {"field": "decision", "claim": "registry:consent-decisions:consent-decision", "operator": "in"}
    ]);
    assert_refused(&value, "consent.feed.claim");

    // Nor used as the principal claim.
    let mut value = source();
    value["accessProfiles"][FEED]["principalClaim"] = json!("registry:recipients");
    assert_refused(&value, "consent.feed.claim");
}

#[cfg(feature = "runtime")]
mod startup {
    use std::sync::Arc;

    use registry_breg::auth::{
        AuthenticationConfigError, AuthorityClaimConfig, RegistryAuthenticator,
    };
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
    use registry_platform_testing::{oidc_verifier_config, MockIdp};
    use serde_json::json;

    use super::consent_fixture::{compile, source};

    fn authenticator(
        registry: &registry_breg::CompiledRegistry,
        idp: &MockIdp,
        allowed_clients: &[&str],
    ) -> Result<RegistryAuthenticator, AuthenticationConfigError> {
        let mut verifier = oidc_verifier_config(idp.issuer(), vec!["consent-api".to_owned()]);
        verifier.allowed_clients = allowed_clients
            .iter()
            .map(|client| (*client).to_owned())
            .collect();
        let key_source = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        ));
        RegistryAuthenticator::new(
            registry,
            verifier,
            key_source,
            AuthorityClaimConfig::new("principal", Some("purpose".to_owned())),
        )
    }

    #[tokio::test]
    async fn every_recipient_client_must_be_an_allowed_client() {
        let registry = compile(&source()).expect("consent fixture compiles");
        let idp = MockIdp::start().await;
        authenticator(&registry, &idp, &["wfp-scope", "ngo-alpha-portal"])
            .expect("every recipient client is allowed");

        // An organization client the issuer never admits could never be mapped.
        let mut value = source();
        value["recipients"]["organizations"][2]["clients"] = json!(["ngo-beta-app"]);
        let registry = compile(&value).expect("consent fixture compiles");
        assert_eq!(
            authenticator(&registry, &idp, &["wfp-scope", "ngo-alpha-portal"]).err(),
            Some(AuthenticationConfigError::InvalidClaimMapping)
        );
    }
}

#[test]
fn a_consent_record_needs_declared_recipients() {
    let mut value = source();
    let object = value.as_object_mut().unwrap();
    object.remove("recipients");
    object.remove("retiredConsentScopes");
    assert_refused(&value, "consent.record.fields");
}

#[cfg(feature = "runtime")]
#[test]
fn adding_a_recipient_migrates_the_issuing_action_without_review() {
    use registry_breg::package::{
        change_set_to_applicable_migration_plan, compiled_registry_change_set,
        CompiledRegistryChangeClass, CompiledRegistryChangeCode,
    };
    let before = compile(&source()).unwrap();
    let mut added = source();
    added["recipients"]["organizations"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "ngo-gamma",
            "name": "NGO Gamma",
            "contact": "privacy@ngo-gamma.example.test",
            "clients": []
        }));
    let after = compile(&added).unwrap();
    let changes = compiled_registry_change_set(&before, &after, "prior-package");
    let codes = changes
        .changes
        .iter()
        .map(|change| (change.code, change.class))
        .collect::<Vec<_>>();
    assert!(
        codes.contains(&(
            CompiledRegistryChangeCode::ActionVocabularyCodesAdded,
            CompiledRegistryChangeClass::CompatibleAdditive
        )),
        "{codes:?}"
    );
    assert!(
        !codes
            .iter()
            .any(|(code, _)| *code == CompiledRegistryChangeCode::ActionChanged),
        "{codes:?}"
    );
    assert!(change_set_to_applicable_migration_plan(&changes).is_ok());

    // Any other contract difference beside the added code stays a reviewed
    // action change.
    let mut renamed = added.clone();
    renamed["actions"][0]["inputs"][6]["apiName"] = json!("expiry");
    let renamed = compile(&renamed).unwrap();
    let changes = compiled_registry_change_set(&before, &renamed, "prior-package");
    assert!(changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::ActionChanged));
    assert!(change_set_to_applicable_migration_plan(&changes).is_err());
}

#[cfg(feature = "runtime")]
fn change_codes(
    before: &Value,
    after: &Value,
) -> (
    registry_breg::package::CompiledRegistryChangeSet,
    Vec<(
        registry_breg::package::CompiledRegistryChangeCode,
        registry_breg::package::CompiledRegistryChangeClass,
        Option<String>,
    )>,
) {
    let changes = registry_breg::package::compiled_registry_change_set(
        &compile(before).unwrap(),
        &compile(after).unwrap(),
        "prior-package",
    );
    let codes = changes
        .changes
        .iter()
        .map(|change| (change.code, change.class, change.target.member_id.clone()))
        .collect();
    (changes, codes)
}

#[cfg(feature = "runtime")]
#[test]
fn a_recipient_client_change_is_a_metadata_only_access_change() {
    use registry_breg::package::{
        change_set_to_applicable_migration_plan, CompiledRegistryChangeClass,
        CompiledRegistryChangeCode, CompiledRegistryChangeTargetKind,
    };
    let mut added = source();
    added["recipients"]["organizations"][2]["clients"] = json!(["ngo-beta-portal"]);
    let (changes, codes) = change_codes(&source(), &added);
    assert_eq!(
        codes,
        vec![(
            CompiledRegistryChangeCode::RecipientOrganizationChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            Some("ngo-beta".to_owned()),
        )]
    );
    assert_eq!(
        changes.changes[0].target.kind,
        CompiledRegistryChangeTargetKind::Recipient
    );
    let plan = change_set_to_applicable_migration_plan(&changes).unwrap();
    assert!(plan.statements.is_empty());
    assert_eq!(plan.changes, changes.changes);
}

#[cfg(feature = "runtime")]
#[test]
fn a_group_membership_change_is_a_metadata_only_access_change() {
    use registry_breg::package::{
        change_set_to_applicable_migration_plan, CompiledRegistryChangeClass,
        CompiledRegistryChangeCode,
    };
    let mut widened = source();
    widened["recipients"]["groups"][0]["members"] = json!(["wfp", "ngo-alpha", "ngo-beta"]);
    let (changes, codes) = change_codes(&source(), &widened);
    assert_eq!(
        codes,
        vec![(
            CompiledRegistryChangeCode::RecipientGroupChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            Some("referral-network".to_owned()),
        )]
    );
    assert!(change_set_to_applicable_migration_plan(&changes)
        .unwrap()
        .statements
        .is_empty());
}

#[cfg(feature = "runtime")]
#[test]
fn added_and_removed_recipients_carry_their_own_codes() {
    use registry_breg::package::CompiledRegistryChangeCode;
    let mut added = source();
    added["recipients"]["groups"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "health-network", "name": "Health network", "members": ["ngo-beta"]}));
    let (_, codes) = change_codes(&source(), &added);
    assert!(codes.iter().any(|(code, _, member)| {
        *code == CompiledRegistryChangeCode::RecipientGroupAdded
            && member.as_deref() == Some("health-network")
    }));
    let (_, codes) = change_codes(&added, &source());
    assert!(codes.iter().any(|(code, _, member)| {
        *code == CompiledRegistryChangeCode::RecipientGroupRemoved
            && member.as_deref() == Some("health-network")
    }));

    let mut removed = source();
    removed["recipients"]["organizations"]
        .as_array_mut()
        .unwrap()
        .remove(2);
    let (_, codes) = change_codes(&source(), &removed);
    assert!(codes.iter().any(|(code, _, member)| {
        *code == CompiledRegistryChangeCode::RecipientOrganizationRemoved
            && member.as_deref() == Some("ngo-beta")
    }));
    let (_, codes) = change_codes(&removed, &source());
    assert!(codes.iter().any(|(code, _, member)| {
        *code == CompiledRegistryChangeCode::RecipientOrganizationAdded
            && member.as_deref() == Some("ngo-beta")
    }));
}

#[cfg(feature = "runtime")]
#[test]
fn a_changed_max_duration_is_a_consent_record_change() {
    use registry_breg::package::{CompiledRegistryChangeClass, CompiledRegistryChangeCode};
    let mut raised = source();
    raised["entities"][CONSENT]["consentRecord"]["validity"]["maxDuration"] = json!("P730D");
    let (_, codes) = change_codes(&source(), &raised);
    assert_eq!(
        codes,
        vec![(
            CompiledRegistryChangeCode::ConsentRecordChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            None,
        )]
    );
}

#[cfg(feature = "runtime")]
#[test]
fn switching_the_consent_issuer_changes_the_action_contract() {
    use registry_breg::package::CompiledRegistryChangeCode;
    let before = self_issued_project();
    let mut after = before.clone();
    let withdraw = after["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["id"] == "withdraw-consent")
        .unwrap();
    withdraw["consentIssuer"] = json!("steward");
    let (_, codes) = change_codes(&before, &after);
    assert_eq!(
        codes
            .iter()
            .map(|(code, _, member)| (*code, member.as_deref()))
            .collect::<Vec<_>>(),
        vec![(
            CompiledRegistryChangeCode::ActionChanged,
            Some("withdraw-consent")
        )]
    );
    let compiled = compile(&after).unwrap();
    let action = compiled
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "withdraw-consent")
        .unwrap();
    assert_eq!(
        action.consent_issuer,
        Some(registry_breg::contract::ConsentIssuerSource::Steward)
    );
}

#[cfg(feature = "tooling")]
fn package_request(
    value: &Value,
    sequence: u64,
    prior_revision: Option<&str>,
    migration_plan: registry_breg::package::PackageMigrationPlanInput,
) -> registry_breg::package::PackageBuildRequest {
    use registry_breg::package::{PackageBuildRequest, PackageSourceFile, SignaturePolicy};
    let mut value = value.clone();
    value["package"] = json!({
        "environment": "local", "instanceId": "consent-instance",
        "sequence": sequence, "sourceRevision": "consent-source"
    });
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: "consent-instance".to_owned(),
        database_id: "consent-database".to_owned(),
        sequence,
        prior_revision: prior_revision.map(str::to_owned),
        compiler_source_revision: "consent-source".to_owned(),
        schema_fingerprint: format!("sha256:{}", "4".repeat(64)),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: vec![],
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: serde_json::to_vec(&value).unwrap(),
        },
        modules: vec![],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: b"apiVersion: registry.registrystack.org/breg-journeys/v1\njourneys: []\n"
                .to_vec(),
        },
        migration_plan,
    }
}

/// A signed predecessor keeps its recipients, so a successor that only maps a
/// new client derives a metadata-only plan from it rather than an empty one.
#[cfg(feature = "tooling")]
#[test]
fn a_signed_predecessor_carries_its_recipients_into_a_metadata_only_successor() {
    use registry_breg::package::{
        load_predecessor_package, prepare_package, CompiledRegistryChangeCode,
        CompiledRegistryMigrationBaseline, PackageMigrationPlanInput, PredecessorPackageContext,
    };
    let prepared = prepare_package(package_request(
        &source(),
        1,
        None,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    // The package writer refuses symlinked ancestors such as macOS /var.
    let root = directory.path().canonicalize().unwrap().join("package");
    prepared.publish_to_directory(&root, vec![]).unwrap();
    let revision = prepared.package_revision().to_owned();
    let predecessor = load_predecessor_package(
        &root,
        &PredecessorPackageContext {
            environment: "local",
            instance_id: "consent-instance",
            database_id: "consent-database",
            database_initialization_environment: "local",
            trust_anchor: None,
            expected_package_revision: &revision,
            expected_sequence: 1,
        },
    )
    .unwrap();
    let baseline = predecessor.migration_baseline();
    assert!(!baseline.recipients.is_empty());
    assert_eq!(
        baseline.recipients,
        CompiledRegistryMigrationBaseline::from_compiled(&revision, prepared.registry()).recipients
    );

    let mut mapped = source();
    mapped["recipients"]["organizations"][2]["clients"] = json!(["ngo-beta-portal"]);
    let successor = prepare_package(package_request(
        &mapped,
        2,
        Some(&revision),
        PackageMigrationPlanInput::SuccessorFromBaseline {
            prior_baseline: Box::new(baseline.clone()),
        },
    ))
    .unwrap();
    let plan = &successor.manifest().migration_plan;
    assert!(plan.statements.is_empty());
    assert_eq!(
        plan.changes
            .iter()
            .map(|change| change.code)
            .collect::<Vec<_>>(),
        vec![CompiledRegistryChangeCode::RecipientOrganizationChanged]
    );
}
