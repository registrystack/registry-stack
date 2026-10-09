//! The committed JSON Schemas of the documents `evidencectl` itself reads and
//! writes: the local access client and the source mock plan. The documents the
//! authoring crate owns are generated there; this module follows the same
//! rendering so every committed schema is shaped alike.

use std::collections::BTreeMap;

use registry_evidence_authoring::formats::{
    ACCESS_CLIENT_API_VERSION, ACCESS_CLIENT_KIND, ACCESS_CLIENT_SCHEMA_ID, MOCK_PLAN_API_VERSION,
    MOCK_PLAN_KIND, MOCK_PLAN_SCHEMA_ID, SELECTOR_API_VERSION, SELECTOR_KIND, SELECTOR_SCHEMA_ID,
    SOURCE_API_VERSION, SOURCE_KIND, SOURCE_SCHEMA_ID, TARGET_GOVERNANCE_API_VERSION,
    TARGET_GOVERNANCE_KIND, TARGET_GOVERNANCE_SCHEMA_ID, TARGET_SETTINGS_API_VERSION,
    TARGET_SETTINGS_KIND, TARGET_SETTINGS_SCHEMA_ID,
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

/// The schema for one deployment target's `governance.yaml`.
pub const TARGET_GOVERNANCE_SCHEMA_FILE: &str = "target-governance.schema.json";

/// The schema for one selector profile under `selectors/`.
pub const SELECTOR_SCHEMA_FILE: &str = "selector.schema.json";

/// The schema for one source under `sources/`.
pub const SOURCE_SCHEMA_FILE: &str = "source.schema.json";

/// The schema for one deployment target's `settings.yaml`.
pub const TARGET_SETTINGS_SCHEMA_FILE: &str = "target-settings.schema.json";

/// The schema body of a source or selector: `evidencectl` reads the header and
/// passes the flat body, unchanged, into the Evidence bundle grammar.
fn bundle_body_schema(member: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "x-registry-passthrough": format!(
            "{member} of the Evidence bundle grammar; `evidencectl check` validates it against bundle.schema.yaml after the compile."
        ),
    })
}

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
            TARGET_GOVERNANCE_SCHEMA_FILE,
            publish(
                crate::build::governance_document_schema(),
                "Evidence deployment target governance",
                TARGET_GOVERNANCE_SCHEMA_ID,
                (TARGET_GOVERNANCE_API_VERSION, TARGET_GOVERNANCE_KIND),
            )?,
        ),
        (
            TARGET_SETTINGS_SCHEMA_FILE,
            publish(
                crate::target::settings_document_schema(),
                "Evidence deployment target settings",
                TARGET_SETTINGS_SCHEMA_ID,
                (TARGET_SETTINGS_API_VERSION, TARGET_SETTINGS_KIND),
            )?,
        ),
        (
            SELECTOR_SCHEMA_FILE,
            publish(
                bundle_body_schema("A selector profile"),
                "Evidence selector profile",
                SELECTOR_SCHEMA_ID,
                (SELECTOR_API_VERSION, SELECTOR_KIND),
            )?,
        ),
        (
            SOURCE_SCHEMA_FILE,
            publish(
                bundle_body_schema("A source"),
                "Evidence source",
                SOURCE_SCHEMA_ID,
                (SOURCE_API_VERSION, SOURCE_KIND),
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
    use super::{
        documents, ACCESS_CLIENT_SCHEMA_FILE, MOCK_PLAN_SCHEMA_FILE, SELECTOR_SCHEMA_FILE,
        SOURCE_RESOLUTION_SCHEMA_FILE, SOURCE_SCHEMA_FILE, TARGET_GOVERNANCE_SCHEMA_FILE,
        TARGET_SETTINGS_SCHEMA_FILE,
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
                "policies": ["readers"],
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
        let file = |artifact: serde_json::Value| {
            serde_json::json!({
                "apiVersion": "id.registrystack.org/formats/evidence/source-resolution/v1alpha1",
                "kind": "EvidenceSourceResolution",
                "artifacts": {"sources/lookup.yaml": artifact},
            })
        };
        assert!(schema.is_valid(&file(serde_json::json!({"type": "keep"}))));
        assert!(schema.is_valid(&file(serde_json::json!({"type": "adopt"}))));
        assert!(schema.is_valid(&file(serde_json::json!({"type": "file", "path": "a"}))));
        assert!(!schema.is_valid(&file(serde_json::json!({"type": "merge"}))));
        assert!(!schema.is_valid(&file(serde_json::json!({"type": "keep", "path": "a"}))));
        assert!(!schema.is_valid(&file(serde_json::json!({"type": "file"}))));
    }

    #[test]
    fn source_and_selector_schemas_and_reader_agree_on_the_header() {
        use registry_evidence_authoring::formats::{read_envelope_body, SELECTOR, SOURCE};

        for (file, format, kind, body) in [
            (
                SELECTOR_SCHEMA_FILE,
                SELECTOR,
                "EvidenceSelector",
                "fields: {}\n",
            ),
            (
                SOURCE_SCHEMA_FILE,
                SOURCE,
                "EvidenceSource",
                "transport: http-json\n",
            ),
        ] {
            let schema = compile(file);
            let name = kind.trim_start_matches("Evidence").to_lowercase();
            let header = format!(
                "apiVersion: id.registrystack.org/formats/evidence/{name}/v1alpha1\nkind: {kind}\n"
            );
            let reads = |text: String| {
                let value: serde_json::Value =
                    serde_norway::from_str(&text).expect("the test document is YAML");
                let reader = read_envelope_body("file.yaml", text.as_bytes(), &format).is_ok();
                (schema.is_valid(&value), reader)
            };
            for (document, accepted) in [
                (format!("{header}{body}"), true),
                (header.clone(), true),
                (body.to_owned(), false),
                (format!("apiVersion: id.registrystack.org/formats/evidence/{name}/v1alpha1\n{body}"), false),
                (format!("kind: {kind}\n{body}"), false),
                (format!("apiVersion: id.registrystack.org/formats/evidence/{name}/v2\nkind: {kind}\n{body}"), false),
            ] {
                assert_eq!(reads(document.clone()), (accepted, accepted), "{document}");
            }
        }
    }

    #[test]
    fn target_settings_schema_and_reader_agree_on_the_top_level() {
        use registry_evidence_authoring::formats::{decode_authored, TARGET_SETTINGS};

        let schema = compile(TARGET_SETTINGS_SCHEMA_FILE);
        let header = "apiVersion: id.registrystack.org/formats/evidence/target-settings/v1alpha1\nkind: EvidenceTargetSettings\n";
        let members = "governance: {}\nruntime: {}\n";
        let reads = |text: String| {
            let value: serde_json::Value =
                serde_norway::from_str(&text).expect("the test document is YAML");
            let reader = decode_authored::<crate::target::TargetSettings>(
                "settings.yaml",
                text.as_bytes(),
                &TARGET_SETTINGS,
            )
            .is_ok();
            (schema.is_valid(&value), reader)
        };
        for (document, accepted) in [
            (format!("{header}{members}"), true),
            (format!("{header}{members}publicKeys: {{}}\n"), true),
            (format!("{header}runtime: {{}}\n"), false),
            (format!("{header}governance: {{}}\n"), false),
            (format!("{header}{members}unknown: true\n"), false),
            (members.to_owned(), false),
        ] {
            assert_eq!(reads(document.clone()), (accepted, accepted), "{document}");
        }
    }

    #[test]
    fn target_governance_schema_and_reader_agree_on_the_top_level() {
        use registry_evidence_authoring::formats::{decode_authored, TARGET_GOVERNANCE};

        let schema = compile(TARGET_GOVERNANCE_SCHEMA_FILE);
        let header = "apiVersion: id.registrystack.org/formats/evidence/target-governance/v1alpha1\nkind: EvidenceTargetGovernance\n";
        let required = [
            "assuranceProfile: local",
            "service: {}",
            "issuer: {}",
            "authentication: {}",
            "audit: {}",
            "subjectBinding: {}",
            "rateLimits: {}",
            "signing: {}",
            "authorityProfiles: {}",
        ];
        let optional = [
            "publication: {}",
            "responseFormats: {}",
            "sourceConnections: {}",
        ];
        let document = |members: &[&str]| format!("{header}{}\n", members.join("\n"));
        let agree = |text: String, accepted: bool| {
            let value: serde_json::Value =
                serde_norway::from_str(&text).expect("the test document is YAML");
            let reader = decode_authored::<crate::build::TargetGovernance>(
                "governance.yaml",
                text.as_bytes(),
                &TARGET_GOVERNANCE,
            )
            .is_ok();
            assert_eq!(
                (schema.is_valid(&value), reader),
                (accepted, accepted),
                "{text}"
            );
        };
        agree(document(&required), true);
        let mut with_optional = required.to_vec();
        with_optional.extend(optional);
        agree(document(&with_optional), true);
        for index in 0..required.len() {
            let mut without = required.to_vec();
            without.remove(index);
            agree(document(&without), false);
        }
        let mut unknown = required.to_vec();
        unknown.push("unknown: true");
        agree(document(&unknown), false);
        agree(required.join("\n") + "\n", false);
    }
}
