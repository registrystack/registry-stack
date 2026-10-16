//! The committed JSON Schemas of the documents `evidencectl` itself reads and
//! writes: the local access client, source mock plan, and source-import
//! resolution file. The normalized project and target documents are generated
//! by the authoring crate; this module follows the same rendering.

use std::collections::BTreeMap;

use registry_evidence_authoring::formats::{
    ACCESS_CLIENT_API_VERSION, ACCESS_CLIENT_KIND, ACCESS_CLIENT_SCHEMA_ID, MOCK_PLAN_API_VERSION,
    MOCK_PLAN_KIND, MOCK_PLAN_SCHEMA_ID,
};
use registry_evidence_authoring::schema::publish;

use crate::source_import::{
    resolution_schema, RESOLUTION_API_VERSION, RESOLUTION_KIND, RESOLUTION_SCHEMA_ID,
};

/// The schema for one local access client under `access/clients/`.
pub const ACCESS_CLIENT_SCHEMA_FILE: &str = "access-client.schema.json";

/// The schema for one source mock plan, `mocks/source.yaml`.
pub const MOCK_PLAN_SCHEMA_FILE: &str = "mock-plan.schema.json";

/// The schema for one source import resolution file.
pub const SOURCE_RESOLUTION_SCHEMA_FILE: &str = "source-resolution.schema.json";

/// Every generated schema this crate owns, keyed by the filename it is
/// committed under.
///
/// # Errors
///
/// Returns the `serde_json` error if a derived schema cannot be rendered.
pub fn documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    Ok(BTreeMap::from([
        (
            ACCESS_CLIENT_SCHEMA_FILE,
            publish(
                crate::access::client_document_schema(),
                "Evidence local access client",
                ACCESS_CLIENT_SCHEMA_ID,
                (ACCESS_CLIENT_API_VERSION, ACCESS_CLIENT_KIND),
            )?,
        ),
        (
            MOCK_PLAN_SCHEMA_FILE,
            publish(
                crate::source_mock::plan_schema(),
                "Evidence source mock plan",
                MOCK_PLAN_SCHEMA_ID,
                (MOCK_PLAN_API_VERSION, MOCK_PLAN_KIND),
            )?,
        ),
        (
            SOURCE_RESOLUTION_SCHEMA_FILE,
            publish(
                resolution_schema(),
                "Evidence source import resolution file",
                RESOLUTION_SCHEMA_ID,
                (RESOLUTION_API_VERSION, RESOLUTION_KIND),
            )?,
        ),
    ]))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::{
        documents, ACCESS_CLIENT_SCHEMA_FILE, MOCK_PLAN_SCHEMA_FILE, SOURCE_RESOLUTION_SCHEMA_FILE,
    };

    fn compile(file: &str) -> jsonschema::JSONSchema {
        let value: serde_json::Value =
            serde_json::from_str(&documents().expect("schemas generate")[file])
                .expect("a generated schema is JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&value)
            .expect("a generated schema compiles as 2020-12")
    }

    #[test]
    fn the_committed_schemas_are_the_generated_ones() {
        assert_eq!(
            documents()
                .expect("schemas generate")
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![
                ACCESS_CLIENT_SCHEMA_FILE,
                MOCK_PLAN_SCHEMA_FILE,
                SOURCE_RESOLUTION_SCHEMA_FILE,
            ]
        );
        for (file, generated) in documents().expect("schemas generate") {
            let committed = std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("schemas/authoring")
                    .join(file),
            )
            .expect("the committed schema reads");
            assert_eq!(committed, generated, "{file} drifted from its generator");
        }
    }

    #[test]
    fn an_access_client_with_an_unusable_issuer_is_turned_away() {
        let schema = compile(ACCESS_CLIENT_SCHEMA_FILE);
        let client = |issuer: &str| {
            serde_json::json!({
                "apiVersion": "id.registrystack.org/formats/evidence/access-client/v1alpha1",
                "kind": "EvidenceAccessClient",
                "clientId": "assistant",
                "status": "active",
                "accessProfiles": ["readers"],
                "principal": "assistant",
                "evidenceAudience": "https://evidence.example.test",
                "keys": [],
                "exchange": {
                    "kind": "first-party",
                    "bootstrapScope": "evidence:invoke",
                    "bootstrapResource": "https://evidence.example.test",
                    "sourceIssuer": issuer,
                },
            })
        };
        assert!(schema.is_valid(&client("https://issuer.example.test")));
        assert!(!schema.is_valid(&client("not a url")));
    }

    #[test]
    fn a_mock_plan_the_schema_turns_away_is_turned_away_by_the_reader() {
        let schema = compile(MOCK_PLAN_SCHEMA_FILE);
        let plan = |seed: u64, parameter: serde_json::Value| {
            serde_json::json!({
                "apiVersion": "id.registrystack.org/formats/evidence/mock-plan/v1alpha1",
                "kind": "EvidenceMockPlan",
                "openapi": "../source.openapi.yaml",
                "generation": {
                    "contract": "evidencectl-source-mock-v1",
                    "seed": seed,
                    "asOf": "2025-01-01",
                },
                "operations": [{
                    "method": "GET",
                    "path": "/people/{person_id}",
                    "response": {"status": 200, "mediaType": "application/json"},
                    "cases": [{
                        "name": "sample",
                        "request": {"pathParameters": {"person_id": parameter}},
                        "body": "cases/get-people/sample.json",
                    }],
                }],
            })
        };
        assert!(schema.is_valid(&plan(0, serde_json::json!("person-123"))));
        assert!(!schema.is_valid(&plan(1 << 60, serde_json::json!("person-123"))));
        assert!(!schema.is_valid(&plan(0, serde_json::json!({"nested": true}))));
    }

    #[test]
    fn a_resolution_file_the_schema_turns_away_is_turned_away_by_the_reader() {
        let schema = compile(SOURCE_RESOLUTION_SCHEMA_FILE);
        let file = |artifacts: serde_json::Value| {
            serde_json::json!({
                "apiVersion": "id.registrystack.org/formats/evidence/source-resolution/v1alpha1",
                "kind": "EvidenceSourceResolution",
                "artifacts": artifacts,
            })
        };
        let one = |artifact: serde_json::Value| {
            file(serde_json::json!({"sources/lookup.yaml": artifact}))
        };
        let many = |count: usize| {
            file(serde_json::Value::Object(
                (0..count)
                    .map(|index| {
                        (
                            format!("sources/s{index}.yaml"),
                            serde_json::json!({"type": "keep"}),
                        )
                    })
                    .collect(),
            ))
        };
        let reads = |document: &serde_json::Value| {
            crate::source_import::check_resolution_file(
                "resolutions.json",
                document.to_string().as_bytes(),
            )
            .is_ok()
        };
        for (document, accepted) in [
            (one(serde_json::json!({"type": "keep"})), true),
            (one(serde_json::json!({"type": "adopt"})), true),
            (one(serde_json::json!({"type": "file", "path": "a"})), true),
            (one(serde_json::json!({"type": "merge"})), false),
            (one(serde_json::json!({"type": "keep", "path": "a"})), false),
            (one(serde_json::json!({"type": "file"})), false),
            (many(256), true),
            (many(257), false),
        ] {
            assert_eq!(
                (schema.is_valid(&document), reads(&document)),
                (accepted, accepted),
                "{}",
                document.to_string().chars().take(120).collect::<String>()
            );
        }
    }

    #[test]
    fn normalized_target_schema_and_reader_agree_on_the_top_level() {
        use registry_evidence_authoring::{schema::TARGET_SCHEMA_FILE, target};

        let schemas = registry_evidence_authoring::schema::documents().unwrap();
        let value: serde_json::Value = serde_json::from_str(&schemas[TARGET_SCHEMA_FILE]).unwrap();
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&value)
            .unwrap();
        let canonical =
            include_str!("../../../products/evidence/examples/standalone/local-target.yaml");
        let reads = |text: &str| {
            let value: serde_json::Value = serde_norway::from_str(text).unwrap();
            (
                schema.is_valid(&value),
                target::read_target("local-target.yaml", text.as_bytes()).is_ok(),
            )
        };
        assert_eq!(reads(canonical), (true, true));
        for refused in [
            canonical.replacen("kind: EvidenceTarget\n", "", 1),
            canonical.replacen("apiVersion: id.registrystack.org/formats/evidence/target/v1alpha1\n", "", 1),
            canonical.replacen("id: local\n", "", 1),
            format!("{canonical}unknown: true\n"),
            "apiVersion: id.registrystack.org/formats/evidence/target-settings/v1alpha1\nkind: EvidenceTargetSettings\ngovernance: {}\nruntime: {}\n".to_owned(),
        ] {
            assert_eq!(reads(&refused), (false, false), "{refused}");
        }
    }

    #[test]
    fn normalized_target_authority_schema_and_reader_agree_on_the_top_level() {
        use registry_evidence_authoring::{project, schema::TARGET_AUTHORITY_SCHEMA_FILE, target};

        let schemas = registry_evidence_authoring::schema::documents().unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&schemas[TARGET_AUTHORITY_SCHEMA_FILE]).unwrap();
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&value)
            .unwrap();
        let project = project::read_project(
            "evidence.yaml",
            include_bytes!("../../../products/evidence/examples/standalone/evidence.yaml"),
        )
        .unwrap()
        .value;
        let canonical =
            include_str!("../../../products/evidence/examples/standalone/dev-authority.yaml");
        let reads = |text: &str| {
            let value: serde_json::Value = serde_norway::from_str(text).unwrap();
            (
                schema.is_valid(&value),
                target::read_authority("dev-authority.yaml", text.as_bytes(), &project).is_ok(),
            )
        };
        assert_eq!(reads(canonical), (true, true));
        for refused in [
            canonical.replacen("kind: EvidenceTargetAuthority\n", "", 1),
            canonical.replacen("project: standalone-evidence\n", "", 1),
            format!("{canonical}unknown: true\n"),
            "apiVersion: id.registrystack.org/formats/evidence/target-governance/v1alpha1\nkind: EvidenceTargetGovernance\nassuranceProfile: local\n".to_owned(),
        ] {
            assert_eq!(reads(&refused), (false, false), "{refused}");
        }
    }
}
