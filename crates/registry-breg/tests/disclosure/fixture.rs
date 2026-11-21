// SPDX-License-Identifier: Apache-2.0

//! The protected-persons fixture the disclosure canary suites share.
//!
//! Person `P` carries a protection level and a history flag. Residence `R`
//! copies the protection level from its person as a marker. Closed name-usage
//! `N` records a former name. Each record holds one sentinel, and a canary
//! asserts the sentinel bytes never reach a profile that is not exempt.

use serde_json::{json, Map, Value};

use super::postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, RegistryStateTestIdentity,
};
use registry_breg::CompiledRegistry;

pub const PACKAGE_ID: &str = "disclosure-registry";
pub const DATABASE_ID: &str = "disclosure-database";
pub const PACKAGE_REVISION: &str = "disclosure-package-1";

pub const CANARY_EMAIL: &str = "CANARY-EMAIL@example.invalid";
pub const CANARY_PHONE: &str = "CANARY-PHONE";
pub const CANARY_ADDRESS: &str = "CANARY-ADDRESS";
pub const CANARY_OLD_NAME: &str = "CANARY-OLD-NAME";
pub const SENTINELS: [&str; 4] = [CANARY_EMAIL, CANARY_PHONE, CANARY_ADDRESS, CANARY_OLD_NAME];

pub const REGISTRAR: &str = "registrar";
pub const PROTECTION_OFFICER: &str = "protection-officer";
pub const EMERGENCY_REGISTRAR: &str = "emergency-registrar";

pub const PERSON_ID: &str = "00000000-0000-0000-0000-00000000d001";
pub const RESIDENCE_ID: &str = "00000000-0000-0000-0000-00000000d002";
pub const NAME_USAGE_ID: &str = "00000000-0000-0000-0000-00000000d003";
pub const OPEN_PERSON_ID: &str = "00000000-0000-0000-0000-00000000d004";
pub const ABSENT_ID: &str = "00000000-0000-0000-0000-00000000dfff";

const READ_FIELDS: [&str; 3] = ["person", "residence", "name-usage"];

fn grant(record_type: &str, readable: Value, filterable: Value) -> Value {
    json!({"recordType": record_type, "operations": ["get", "list"],
        "rowBoundaries": "unrestricted", "readableFields": readable,
        "filterableFields": filterable})
}

fn profile(default: bool, filterable_contacts: bool) -> Value {
    let person_filter = if filterable_contacts {
        json!(["family-name", "email-address"])
    } else {
        json!(["family-name"])
    };
    json!({"default": default, "principalClaim": "registry_principal",
    "requiredScopes": "unrestricted",
    "permissions": {"records": [
        grant("person", json!(["family-name", "protection-level", "history-protected", "email-address", "phone-number"]), person_filter),
        grant("residence", json!(["person-id", "protection-level", "address"]), json!(["protection-level"])),
        grant("name-usage", json!(["person-id", "protection-level", "old-name", "closed-on"]), json!(["protection-level"]))
    ]}})
}

/// The project source, as authored.
pub fn project_source() -> Value {
    assert_eq!(READ_FIELDS.len(), 3);
    json!({"datasets": {"test-dataset": {}},
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id": "disclosure", "version": "1", "defaultLanguage": "en",
                    "canonicalBaseIri": "https://disclosure.example.test"},
        "recordTypes": {
            "person": {"primaryDataset": "test-dataset", "route": "people",
             "mutationMode": "mutable", "classification": "internal",
             "fields": [
                {"id": "family-name", "type": "string", "maximumLength": 64, "classification": "internal"},
                {"id": "protection-level", "type": "string", "maximumLength": 32, "classification": "internal"},
                {"id": "history-protected", "type": "boolean", "classification": "internal"},
                {"id": "email-address", "type": "string", "maximumLength": 128, "classification": "internal"},
                {"id": "phone-number", "type": "string", "maximumLength": 32, "classification": "internal"}],
             "disclosureConditions": {
                "hide-contacts": {"when": [{"type": "field-in", "field": "protection-level", "values": ["protected", "substitute-address"]}],
                 "withhold": "fields", "fields": ["email-address", "phone-number"],
                 "exemptProfiles": [PROTECTION_OFFICER, EMERGENCY_REGISTRAR]},
                "hide-history": {"when": [{"type": "field-equals", "field": "history-protected", "value": true}],
                 "withhold": "history", "exemptProfiles": [PROTECTION_OFFICER]}}},
            "residence": {"primaryDataset": "test-dataset", "route": "residences",
             "mutationMode": "mutable", "classification": "internal",
             "fields": [
                {"id": "person-id", "type": "uuid", "classification": "internal"},
                {"id": "protection-level", "type": "string", "maximumLength": 32, "classification": "internal"},
                {"id": "address", "type": "string", "maximumLength": 128, "classification": "internal"}],
             "disclosureConditions": {
                "hide-residence": {"when": [{"type": "field-in", "field": "protection-level", "values": ["protected", "substitute-address"]}],
                 "withhold": "record",
                 "exemptProfiles": [PROTECTION_OFFICER, EMERGENCY_REGISTRAR]}}},
            "name-usage": {"primaryDataset": "test-dataset", "route": "name-usages",
             "mutationMode": "mutable", "classification": "internal",
             "fields": [
                {"id": "person-id", "type": "uuid", "classification": "internal"},
                {"id": "protection-level", "type": "string", "maximumLength": 32, "classification": "internal"},
                {"id": "old-name", "type": "string", "maximumLength": 64, "classification": "internal"},
                {"id": "closed-on", "type": "date", "classification": "internal"}],
             "disclosureConditions": {
                "hide-closed-name": {"when": [{"type": "field-is-not-null", "field": "closed-on"},
                          {"type": "field-in", "field": "protection-level", "values": ["protected", "substitute-address"]}],
                 "withhold": "record", "exemptProfiles": [PROTECTION_OFFICER]}}}},
        "accessProfiles": {
            REGISTRAR: profile(true, false),
            PROTECTION_OFFICER: profile(false, true),
            EMERGENCY_REGISTRAR: profile(false, true)}})
}

pub fn compile_fixture() -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&project_source()).unwrap())
        .expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

pub fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// A compiled fixture installed in a real database with its rows seeded.
pub struct Fixture {
    pub database: TestDatabase,
    pub registry: CompiledRegistry,
}

impl Fixture {
    /// Install the schema, initialize the registry state and seed `P`, `R`, `N`
    /// and an unprotected person.
    pub async fn build(pool_size: usize) -> Self {
        let registry = compile_fixture();
        let database = TestDatabase::create(pool_size).await;
        let (migration, task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("fixture DDL installs");
        initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                database_id: DATABASE_ID,
                label: PACKAGE_REVISION,
            },
        )
        .await
        .expect("fixture registry state initializes");
        task.abort();
        let fixture = Self { database, registry };
        fixture
            .insert(
                "person",
                PERSON_ID,
                &[
                    ("family-name", json!("Protected")),
                    ("protection-level", json!("protected")),
                    ("history-protected", json!(true)),
                    ("email-address", json!(CANARY_EMAIL)),
                    ("phone-number", json!(CANARY_PHONE)),
                ],
            )
            .await;
        fixture
            .insert(
                "person",
                OPEN_PERSON_ID,
                &[
                    ("family-name", json!("Open")),
                    ("protection-level", json!("none")),
                    ("history-protected", json!(false)),
                    ("email-address", json!("open@example.invalid")),
                    ("phone-number", json!("555-0100")),
                ],
            )
            .await;
        fixture
            .insert(
                "residence",
                RESIDENCE_ID,
                &[
                    ("person-id", json!(PERSON_ID)),
                    ("protection-level", json!("protected")),
                    ("address", json!(CANARY_ADDRESS)),
                ],
            )
            .await;
        fixture
            .insert(
                "name-usage",
                NAME_USAGE_ID,
                &[
                    ("person-id", json!(PERSON_ID)),
                    ("protection-level", json!("protected")),
                    ("old-name", json!(CANARY_OLD_NAME)),
                    ("closed-on", json!("2020-01-01")),
                ],
            )
            .await;
        fixture
    }

    /// Insert one row as the database owner. Values are JSON strings or
    /// booleans, cast by the column type.
    pub async fn insert(&self, record_type: &str, record_id: &str, values: &[(&str, Value)]) {
        let entity = &self.registry.entities()[record_type];
        let table = quote_identifier(&entity.physical_table);
        let mut columns = vec![
            "record_id".to_owned(),
            "active_package_revision".to_owned(),
            "record_lifecycle".to_owned(),
        ];
        let mut placeholders = vec![
            "$1::text::uuid".to_owned(),
            format!("'{PACKAGE_REVISION}'"),
            "'active'".to_owned(),
        ];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync>> =
            vec![Box::new(record_id.to_owned())];
        for (field, value) in values {
            let compiled = &entity.fields[*field];
            columns.push(quote_identifier(&compiled.physical_name));
            match value {
                Value::Bool(flag) => {
                    params.push(Box::new(*flag));
                    placeholders.push(format!("${}", params.len()));
                }
                Value::String(text) => {
                    params.push(Box::new(text.clone()));
                    let cast = match compiled.field_type {
                        registry_breg::contract::FieldTypeSource::Uuid => "::text::uuid",
                        registry_breg::contract::FieldTypeSource::Date => "::text::date",
                        _ => "",
                    };
                    placeholders.push(format!("${}{cast}", params.len()));
                }
                other => panic!("fixture value {other} is not supported"),
            }
        }
        let sql = format!(
            "INSERT INTO registry_data.{table} ({}) VALUES ({})",
            columns.join(", "),
            placeholders.join(", ")
        );
        let refs = params
            .iter()
            .map(|param| param.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        self.database
            .admin
            .execute(&sql, &refs)
            .await
            .unwrap_or_else(|error| panic!("fixture row for {record_type} inserts: {error:?}"));
    }
}

/// Fail when any sentinel appears in `body`, naming which one.
pub fn assert_no_sentinel(body: &str) {
    for sentinel in SENTINELS {
        assert!(
            !body.contains(sentinel),
            "sentinel `{sentinel}` reached a response body: {body}"
        );
    }
}

/// Fail unless `body` carries `sentinel`, so a canary never passes because the
/// fixture lost its data.
pub fn assert_has_sentinel(body: &str, sentinel: &str) {
    assert!(
        body.contains(sentinel),
        "sentinel `{sentinel}` is missing from the response body: {body}"
    );
}

/// The JSON shape of a body: keys kept, every string, number and boolean
/// replaced by its type, array elements collapsed to their first element's
/// shape. Two absence answers must share a shape, whatever the ids inside.
pub fn body_shape(value: &Value) -> Value {
    match value {
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(key, member)| (key.clone(), body_shape(member)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(items) => Value::Array(items.first().map(body_shape).into_iter().collect()),
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("boolean"),
        Value::Null => Value::Null,
    }
}

/// An absence answer: the status and the parsed problem or list body.
pub struct Answer {
    pub status: u16,
    pub body: Value,
}

/// Fail unless a withheld record answers exactly like a random identifier:
/// same status, same problem code and same body shape.
pub fn assert_same_absence(withheld: &Answer, random: &Answer) {
    assert_eq!(withheld.status, random.status, "absence status differs");
    assert_eq!(
        withheld.body.get("code"),
        random.body.get("code"),
        "absence problem code differs"
    );
    assert_eq!(
        body_shape(&withheld.body),
        body_shape(&random.body),
        "absence body shape differs"
    );
}
