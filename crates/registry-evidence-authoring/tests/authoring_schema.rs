//! The generated description of the authoring form, and the one direction of
//! agreement it owes the checks beside it.
//!
//! An editor reads a JSON Schema; `evidencectl` reads Rust. Both must describe
//! the same authored document, which is why the schema is derived from the
//! model rather than written next to it. These tests hold the derived documents
//! to the properties a committed artifact needs (a stable dialect, a stable
//! identifier, byte-identical regeneration) and to the one agreement that is
//! safe to assert: a document the schema turns away is a document the checks
//! turn away too.
//!
//! The reverse is deliberately not asserted, and one test pins that. The schema
//! describes shape; the checks describe meaning. A document can be perfectly
//! shaped and still name an identifier the form does not allow, and an editor
//! that reported nothing there would be telling the truth about the schema and
//! the wrong thing about the project.

#![cfg(feature = "schema")]
#![allow(
    clippy::disallowed_macros,
    reason = "this test target embeds the public canonical fixtures; the library performs no I/O"
)]

use jsonschema::{Draft, JSONSchema};
use registry_evidence_authoring::{
    project,
    schema::{documents, PROJECT_SCHEMA_FILE, TARGET_AUTHORITY_SCHEMA_FILE, TARGET_SCHEMA_FILE},
    target,
};
use registry_platform_yaml::Reader;
use serde_json::Value;

/// The envelope every question below is read with. The corpus states only the
/// members after it, so each departure stays visible.
const QUESTION_ENVELOPE: &str =
    "apiVersion: id.registrystack.org/formats/evidence/question/v1alpha1\nkind: EvidenceQuestion\n";

const NORMALIZED_PROJECT: &str =
    include_str!("../../../products/evidence/examples/standalone/evidence.yaml");
const NORMALIZED_TARGET: &str =
    include_str!("../../../products/evidence/examples/standalone/local-target.yaml");
const NORMALIZED_AUTHORITY: &str =
    include_str!("../../../products/evidence/examples/standalone/dev-authority.yaml");

/// A question that satisfies both the schema and the checks, and the base every
/// rejected document below departs from in exactly one way.
const VALID_QUESTION: &str = r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#;

/// Authored questions the schema must turn away, each with the departure it
/// makes from [`VALID_QUESTION`].
const REJECTED_QUESTIONS: &[(&str, &str)] = &[
    (
        "an unknown top-level key",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
notes: this key is not part of the form
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a missing derivation",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "answers written as a single mapping instead of a list",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  concept: is_adult
  type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a fact combination the form does not offer",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: sometimes
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "an answer type the form does not offer",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: free-text
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a disclosure that lists nothing to allow",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure: {}
"#,
    ),
    (
        "an unknown key inside a subject",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
  optional: true
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a question identifier written as a number",
        r#"id: 18
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a collection bound under an empty pointer",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {"": 2}
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a bounded-integer answer whose minimum is past the JSON safe integers",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one

answers:
  - concept: is_adult
    type: bounded-integer
    minimum: -9007199254740992
    maximum: 5
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a bounded-integer answer whose maximum is past the JSON safe integers",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one

answers:
  - concept: is_adult
    type: bounded-integer
    minimum: 0
    maximum: 9007199254740992
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
];

/// The marker documents the schema must turn away.
const REJECTED_MARKERS: &[(&str, &str)] = &[
    (
        "an unknown key",
        "apiVersion: id.registrystack.org/formats/evidence/authoring-project/v1alpha1\nkind: EvidenceAuthoringProject\nextra: true\n",
    ),
    (
        "a project kind the marker does not name",
        "apiVersion: id.registrystack.org/formats/evidence/authoring-project/v1alpha1\nkind: RelayAuthoringProject\n",
    ),
    (
        "a missing kind",
        "apiVersion: id.registrystack.org/formats/evidence/authoring-project/v1alpha1\n",
    ),
    (
        "the members the envelope replaced",
        "version: 1\nproject: evidence-authoring\n",
    ),
];

fn compile(document: &str) -> JSONSchema {
    let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("a generated schema compiles as 2020-12")
}

fn yaml_as_json(document: &str) -> Value {
    Reader::new("corpus.yaml")
        .scan(document.as_bytes())
        .expect("the corpus is well-formed YAML")
        .expect("the corpus is not empty")
        .to_json_value()
}

fn schema(file: &str) -> JSONSchema {
    compile(&documents().expect("the schemas generate")[file])
}

#[test]
fn the_generated_set_is_exactly_the_normalized_authored_documents() {
    let documents = documents().expect("the authoring schemas generate");
    assert_eq!(
        documents.keys().copied().collect::<Vec<_>>(),
        vec![
            PROJECT_SCHEMA_FILE,
            TARGET_AUTHORITY_SCHEMA_FILE,
            TARGET_SCHEMA_FILE
        ],
    );
}

#[test]
fn every_generated_document_declares_the_shared_dialect_and_its_own_identifier() {
    let documents = documents().expect("the authoring schemas generate");
    let mut identifiers = Vec::new();
    for (name, document) in &documents {
        let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
        assert_eq!(
            value.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema"),
            "{name} does not declare the 2020-12 dialect",
        );
        let identifier = value
            .get("$id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name} does not declare an identifier"))
            .to_owned();
        assert!(
            value.get("title").and_then(Value::as_str).is_some(),
            "{name} does not declare a title an editor can show",
        );
        identifiers.push(identifier);
    }
    identifiers.sort();
    identifiers.dedup();
    assert_eq!(
        identifiers.len(),
        documents.len(),
        "two generated schemas share one identifier",
    );
}

#[test]
fn generation_repeats_byte_for_byte() {
    assert_eq!(
        documents().expect("the authoring schemas generate"),
        documents().expect("the authoring schemas generate again"),
    );
}

#[test]
fn every_generated_document_is_canonical_pretty_json_with_a_trailing_newline() {
    for (name, document) in documents().expect("the authoring schemas generate") {
        assert!(
            document.ends_with('\n') && !document.ends_with("\n\n"),
            "{name} does not end with exactly one newline",
        );
        let value: Value = serde_json::from_str(&document).expect("a generated schema is JSON");
        let mut rendered =
            serde_json::to_string_pretty(&value).expect("a parsed schema renders again");
        rendered.push('\n');
        assert_eq!(
            document, rendered,
            "{name} is not the canonical rendering of its own value, so it cannot be reproduced",
        );
    }
}

#[test]
fn the_project_schema_closes_its_shape_and_requires_the_normalized_keys() {
    let documents = documents().expect("the authoring schemas generate");
    let value: Value =
        serde_json::from_str(&documents[PROJECT_SCHEMA_FILE]).expect("the project schema is JSON");
    assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
    let required = value
        .get("required")
        .and_then(Value::as_array)
        .expect("the project schema names its required keys")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    for key in [
        "apiVersion",
        "kind",
        "id",
        "selectorProfiles",
        "functions",
        "sources",
        "assertionDefinitions",
    ] {
        assert!(
            required.contains(&key),
            "the project schema does not require {key}"
        );
    }
    for key in ["label", "description"] {
        assert!(
            !required.contains(&key),
            "the project schema requires {key}, which is presentation only",
        );
    }
}

#[test]
fn the_project_schema_exposes_presentation_variants_and_function_contracts() {
    let documents = documents().expect("the authoring schemas generate");
    let document = &documents[PROJECT_SCHEMA_FILE];
    for member in [
        "assertionDefinitions",
        "selectorProfiles",
        "label",
        "description",
        "source-prepare/v1",
        "source-extract/v1",
        "assertion-derive/v1",
        "search-then-fetch",
        "search-then-fetch-set",
        "selectorInputs",
    ] {
        assert!(document.contains(member), "schema omits {member}");
    }
}

#[test]
fn canonical_project_target_and_authority_satisfy_schema_and_reader() {
    assert!(schema(PROJECT_SCHEMA_FILE).is_valid(&yaml_as_json(NORMALIZED_PROJECT)));
    let project = project::read_project("evidence.yaml", NORMALIZED_PROJECT.as_bytes())
        .expect("the canonical project reads")
        .value;
    assert!(schema(TARGET_SCHEMA_FILE).is_valid(&yaml_as_json(NORMALIZED_TARGET)));
    target::read_target("local-target.yaml", NORMALIZED_TARGET.as_bytes())
        .expect("the target reads");
    assert!(schema(TARGET_AUTHORITY_SCHEMA_FILE).is_valid(&yaml_as_json(NORMALIZED_AUTHORITY)));
    target::read_authority(
        "dev-authority.yaml",
        NORMALIZED_AUTHORITY.as_bytes(),
        &project,
    )
    .expect("the authority reads");
}

#[test]
fn the_target_schema_and_reader_close_nested_deployment_blocks() {
    let mut document = yaml_as_json(NORMALIZED_TARGET);
    document["listener"]["legacyPort"] = serde_json::json!(8080);
    assert!(!schema(TARGET_SCHEMA_FILE).is_valid(&document));

    let report = target::read_target(
        "local-target.yaml",
        &serde_json::to_vec(&document).expect("target renders"),
    )
    .expect_err("an unknown nested deployment member is refused");
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.path == "/listener/legacyPort")
        .expect("the nested unknown member has an exact path");
    assert_eq!(diagnostic.code, "config.unknown-key");
}

#[test]
fn the_target_model_retains_complete_production_deployment_options() {
    let mut document = yaml_as_json(NORMALIZED_TARGET);
    document["assuranceProfile"] = serde_json::json!("production");
    document["package"]["expectedDigest"] =
        serde_json::json!(format!("sha256:{}", "0".repeat(64)));
    document["listener"] = serde_json::json!({
        "bind":"0.0.0.0:8080", "networkExposure":"container-private",
        "tlsTermination":"operator-controlled-upstream", "trustProxyIdentityHeaders":false,
        "maximumRequestBytes":65536, "maximumConcurrentRequests":64,
        "requestTimeoutMilliseconds":10000, "shutdownGraceMilliseconds":30000
    });
    document["authentication"]["oidc"]["allowedClients"] =
        serde_json::json!(["service-client"]);
    document["authentication"]["oidc"]["assertionIssuers"] =
        serde_json::json!({"service-client":["urn:example:issuer:grants"]});
    document["authentication"]["oidc"]["claims"] = serde_json::json!({
        "actorKind":"actor", "purpose":"purpose", "grantId":"grant_id",
        "grantSourceIssuer":"grant_source", "grantClient":"grant_client",
        "grantResource":"grant_resource", "grantExp":"grant_exp",
        "grantBounds":"grant_bounds", "approver":"approver"
    });
    document["authentication"]["oidc"]["actorClaim"] = serde_json::json!("actor");
    document["authentication"]["oidc"]["tlsTrustProfile"] =
        serde_json::json!("private-ca");
    document["authentication"]["oidc"]["revokedKeyIds"] = serde_json::json!([]);
    document["connections"] = serde_json::json!({
        "none":{"origin":"http://127.0.0.1:8081","authentication":{"type":"none"}},
        "basic":{"origin":"https://basic.invalid","authentication":{"type":"basic","usernameRef":"secret:file/user","passwordRef":"secret:file/password"}},
        "bearer":{"origin":"https://bearer.invalid","authentication":{"type":"bearer","tokenRef":"secret:file/token","scheme":"Bearer"}},
        "authorization":{"origin":"https://authorization.invalid","authentication":{"type":"static-authorization","tokenRef":"secret:file/token"}},
        "api-key":{"origin":"https://api.invalid","authentication":{"type":"static-api-key","headerName":"X-Api-Key","valueRef":"secret:file/api-key"}},
        "oauth-secret":{"origin":"https://oauth.invalid","authentication":{"type":"oauth2-client-credentials","tokenEndpoint":"https://issuer.invalid/token","clientIdRef":"secret:file/client-id","clientSecretRef":"secret:file/client-secret","scope":"evidence.read","audience":"evidence","resource":"urn:example:resource","credentialPlacement":"basic-header","maximumCacheSeconds":300,"assumedLifetimeSeconds":300},"tlsTrustProfile":"private-ca","maximumConcurrency":8,"admissionTimeoutMilliseconds":2000,"tokenTimeoutMilliseconds":2000},
        "oauth-jwt":{"origin":"https://jwt.invalid","authentication":{"type":"oauth2-private-key-jwt","tokenEndpoint":"https://issuer.invalid/token","clientIdRef":"secret:file/client-id","clientAssertionKeyRef":"secret:file/client-key","clientAssertionAudience":"urn:example:issuer","scope":"evidence.read","audience":"evidence","resource":"urn:example:resource","maximumCacheSeconds":300,"assumedLifetimeSeconds":300}}
    });
    document["secretProviders"]["environment"] = serde_json::json!({});
    document["signer"] = serde_json::json!({
        "type":"transit", "algorithm":"ES256", "publicJwkFile":"public-keys/active.jwk.json",
        "unixSocketPath":"/run/evidence/transit.sock", "mount":"transit",
        "keyName":"evidence-signing", "keyVersion":7, "attemptTimeoutMilliseconds":2000
    });
    document["audit"] = serde_json::json!({
        "hashKeyRef":"secret:file/audit-hmac-key", "hashKeyVersion":1,
        "destination":"file", "path":"/var/lib/evidence/audit.jsonl",
        "rotateBytes":104857600, "retentionDays":90
    });
    document["publication"] = serde_json::json!({
        "serviceId":"urn:example:service:evidence", "title":"Evidence",
        "description":"Governed Evidence service", "endpointUrl":"https://evidence.invalid",
        "jurisdictions":["urn:example:jurisdiction"],
        "publisherId":"urn:example:publisher", "operatorId":"urn:example:operator"
    });
    document["responseFormats"] =
        serde_json::json!(["signed-jws", "unsigned-json", "sd-jwt-vc", "sd-jwt-vc-batch"]);
    document["outboundTls"] = serde_json::json!({
        "systemRoots":true,
        "trustProfiles":{"private-ca":{"caBundleFile":"/etc/evidence/private-ca.pem"}}
    });
    document["extracts"] =
        serde_json::json!({"registry-snapshot":{"path":"/var/lib/evidence/registry.sqlite"}});

    assert!(schema(TARGET_SCHEMA_FILE).is_valid(&document));
    target::read_target(
        "target.yaml",
        &serde_json::to_vec(&document).expect("target renders"),
    )
    .expect("the complete retained target surface reads");
}

#[test]
fn target_admission_gates_are_exact_in_schema_and_reader() {
    let mut document = yaml_as_json(NORMALIZED_TARGET);
    document["authentication"]["oidc"]["requiredScopes"] = serde_json::json!("everything");
    assert!(!schema(TARGET_SCHEMA_FILE).is_valid(&document));
    let report = target::read_target(
        "target.yaml",
        &serde_json::to_vec(&document).expect("target renders"),
    )
    .expect_err("an unknown admission keyword is refused");
    assert_eq!(
        report.diagnostics()[0].path,
        "/authentication/oidc/requiredScopes"
    );
}

#[test]
fn every_retired_question_corpus_case_is_refused_as_a_normalized_project() {
    let schema = schema(PROJECT_SCHEMA_FILE);
    for (departure, document) in
        std::iter::once(&("the former valid base", VALID_QUESTION)).chain(REJECTED_QUESTIONS.iter())
    {
        let document = format!("{QUESTION_ENVELOPE}{document}");
        assert!(
            !schema.is_valid(&yaml_as_json(&document)),
            "the normalized schema accepts {departure}",
        );
        assert!(
            project::read_project("evidence.yaml", document.as_bytes()).is_err(),
            "the normalized reader accepts {departure}",
        );
    }
}

#[test]
fn retired_parallel_authoring_documents_are_refused_as_normalized_projects() {
    let schema = schema(PROJECT_SCHEMA_FILE);
    for (departure, document) in REJECTED_MARKERS {
        assert!(
            !schema.is_valid(&yaml_as_json(document)),
            "the normalized schema accepts {departure}",
        );
        assert!(
            project::read_project("evidence.yaml", document.as_bytes()).is_err(),
            "the normalized reader accepts {departure}",
        );
    }
    for document in [
        "apiVersion: id.registrystack.org/formats/evidence/source/v1alpha1\nkind: EvidenceSource\ntype: http-json\n",
        "apiVersion: id.registrystack.org/formats/evidence/selector/v1alpha1\nkind: EvidenceSelector\nfields: {}\n",
        "apiVersion: id.registrystack.org/formats/evidence/access-policy/v1alpha1\nkind: EvidenceAccessPolicy\nid: old\nquestions: [old]\n",
    ] {
        assert!(!schema.is_valid(&yaml_as_json(document)));
        assert!(project::read_project("evidence.yaml", document.as_bytes()).is_err());
    }
}

#[test]
fn a_missing_source_passes_shape_validation_and_is_diagnosed_at_its_reference() {
    let document =
        NORMALIZED_PROJECT.replacen("source: person-record", "source: missing-source", 1);
    assert!(
        schema(PROJECT_SCHEMA_FILE).is_valid(&yaml_as_json(&document)),
        "cross-member references are semantic",
    );
    let report = project::read_project("evidence.yaml", document.as_bytes()).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "evidence.project.acquisition-source")
        .expect("the missing source is diagnosed");
    assert_eq!(
        diagnostic.path,
        "/assertionDefinitions/adult-status/acquisition/source"
    );
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
}

#[test]
fn a_bad_typed_value_is_rejected_by_schema_and_reader_at_the_authored_field() {
    let document = NORMALIZED_PROJECT.replacen(
        "maximumAggregateBytes: 64",
        "maximumAggregateBytes: \"64\"",
        1,
    );
    assert!(!schema(PROJECT_SCHEMA_FILE).is_valid(&yaml_as_json(&document)));
    let report = project::read_project("evidence.yaml", document.as_bytes()).unwrap_err();
    let diagnostic = &report.diagnostics()[0];
    assert_eq!(
        diagnostic.path,
        "/selectorProfiles/record-by-id/maximumAggregateBytes"
    );
    assert_eq!(diagnostic.source.as_ref().unwrap().file, "evidence.yaml");
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
}

#[test]
fn source_function_refs_are_closed_while_derivation_calls_expose_bindings() {
    let document = NORMALIZED_PROJECT.replacen(
        "extract:\n      function: extract-person",
        "extract:\n      function: extract-person\n      parameters: {}",
        1,
    );
    assert!(!schema(PROJECT_SCHEMA_FILE).is_valid(&yaml_as_json(&document)));
    assert!(project::read_project("evidence.yaml", document.as_bytes()).is_err());

    let document = NORMALIZED_PROJECT.replacen(
        "derive:\n      function: derive-adult-status",
        "derive:\n      function: derive-adult-status\n      parameters:\n        threshold: 18\n      selectorInputs: []",
        1,
    );
    assert!(schema(PROJECT_SCHEMA_FILE).is_valid(&yaml_as_json(&document)));
}

#[test]
fn a_definition_cannot_declare_an_empty_output_set() {
    let mut document = yaml_as_json(NORMALIZED_PROJECT);
    document["assertionDefinitions"]["adult-status"]["outputs"] = serde_json::json!({});
    assert!(!schema(PROJECT_SCHEMA_FILE).is_valid(&document));
    let bytes = serde_json::to_vec(&document).expect("the project renders");
    assert!(project::read_project("evidence.yaml", &bytes).is_err());
}

#[test]
fn authority_references_are_checked_without_unioning_grants() {
    let project = project::read_project("evidence.yaml", NORMALIZED_PROJECT.as_bytes())
        .unwrap()
        .value;
    let document = NORMALIZED_AUTHORITY.replacen(
        "definition: adult-status",
        "definition: missing-definition",
        1,
    );
    assert!(schema(TARGET_AUTHORITY_SCHEMA_FILE).is_valid(&yaml_as_json(&document)));
    let report =
        target::read_authority("dev-authority.yaml", document.as_bytes(), &project).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "evidence.authority.definition")
        .expect("the missing definition is diagnosed");
    assert_eq!(
        diagnostic.path,
        "/accessProfiles/standalone-service/grants/0/definition"
    );
}

#[test]
fn retired_target_documents_are_refused() {
    for document in [
        "apiVersion: id.registrystack.org/formats/evidence/target-governance/v1alpha1\nkind: EvidenceTargetGovernance\nassuranceProfile: local\n",
        "apiVersion: id.registrystack.org/formats/evidence/target-settings/v1alpha1\nkind: EvidenceTargetSettings\ngovernance: {}\nruntime: {}\n",
    ] {
        assert!(!schema(TARGET_SCHEMA_FILE).is_valid(&yaml_as_json(document)));
        assert!(target::read_target("local-target.yaml", document.as_bytes()).is_err());
    }
}
