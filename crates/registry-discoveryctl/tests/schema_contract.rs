// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::{Draft, JSONSchema};
use registry_discovery::{parse_index, prepare};
use registry_discovery_profile::{
    parse_description, render_description, DiscoveryDescription, ServiceDescription,
};
use registry_discoveryctl::check_project;
use registry_platform_canonical_json::canonicalize_json;
use serde_json::Value;

const PRODUCT_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../products/discovery");

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NegativeCorpus {
    schema_version: String,
    cases: Vec<NegativeCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NegativeCase {
    name: String,
    contract: String,
    pointer: String,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    generator: Option<String>,
}

fn product_path(relative: &str) -> PathBuf {
    Path::new(PRODUCT_ROOT).join(relative)
}

fn load_json(relative: &str) -> Value {
    serde_json::from_slice(&fs::read(product_path(relative)).expect("fixture reads"))
        .expect("fixture is JSON")
}

fn load_yaml(relative: &str) -> Value {
    serde_yaml_ng::from_slice(&fs::read(product_path(relative)).expect("fixture reads"))
        .expect("fixture is YAML")
}

fn validator(relative: &str) -> JSONSchema {
    let schema = load_json(relative);
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .unwrap_or_else(|error| panic!("{relative} compiles as Draft 2020-12: {error}"))
}

fn validators() -> BTreeMap<&'static str, JSONSchema> {
    BTreeMap::from([
        ("origins", validator("schemas/origins.schema.json")),
        (
            "evidence-mapping",
            validator("schemas/evidence-mapping.schema.json"),
        ),
        ("runtime", validator("schemas/runtime.schema.json")),
        ("index", validator("schemas/index.schema.json")),
        (
            "profile",
            validator("profile/schema/registry-discovery-v1alpha1.schema.json"),
        ),
    ])
}

fn positive_document(contract: &str) -> Value {
    match contract {
        "origins" => load_yaml("fixtures/project/origins.yaml"),
        "evidence-mapping" => load_yaml("fixtures/project/mappings/adult-status.yaml"),
        "runtime" => load_yaml("fixtures/project/runtime.yaml"),
        "index" => load_json("fixtures/project/discovery-index.json"),
        "profile" => load_json("fixtures/descriptions/evidence.jsonld"),
        _ => panic!("unknown contract {contract}"),
    }
}

fn set_pointer(document: &mut Value, pointer: &str, value: Value) {
    let mut tokens = pointer
        .strip_prefix('/')
        .expect("corpus pointers are absolute")
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>();
    let last = tokens.pop().expect("corpus pointer has a member");
    let mut current = document;
    for token in tokens {
        current = match current {
            Value::Object(object) => object
                .get_mut(&token)
                .unwrap_or_else(|| panic!("missing object member {token} in {pointer}")),
            Value::Array(array) => {
                &mut array[token
                    .parse::<usize>()
                    .unwrap_or_else(|_| panic!("invalid array index {token} in {pointer}"))]
            }
            _ => panic!("non-container before {token} in {pointer}"),
        };
    }
    match current {
        Value::Object(object) => {
            object.insert(last, value);
        }
        Value::Array(array) => {
            let index = last
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid final array index {last} in {pointer}"));
            array[index] = value;
        }
        _ => panic!("non-container at final member in {pointer}"),
    }
}

fn generated_negative_value(case: &NegativeCase, baseline: &Value) -> Value {
    match case.generator.as_deref() {
        None => case.value.clone().expect("literal corpus case has a value"),
        Some("services-over-bound") => {
            let service = baseline["services"][0].clone();
            Value::Array(
                (0..=registry_discovery_profile::MAX_SERVICES)
                    .map(|_| service.clone())
                    .collect(),
            )
        }
        Some("multibyte-string-over-bound") => {
            Value::String("é".repeat(registry_discovery_profile::MAX_STRING_CHARACTERS + 1))
        }
        Some("identifiers-over-bound") => Value::Array(
            (0..=registry_discovery_profile::MAX_IDENTIFIER_VALUES)
                .map(|index| Value::String(format!("urn:example:jurisdiction:{index:03}")))
                .collect(),
        ),
        Some("excessive-json-depth") => {
            let mut value = Value::Null;
            for _ in 0..256 {
                value = Value::Array(vec![value]);
            }
            value
        }
        Some(generator) => panic!("unknown negative corpus generator {generator}"),
    }
}

fn write_project(origins: &Value, mapping: &Value) -> tempfile::TempDir {
    let temporary = tempfile::tempdir().expect("temporary project");
    fs::create_dir(temporary.path().join("mappings")).expect("mapping directory");
    fs::write(
        temporary.path().join("origins.yaml"),
        serde_yaml_ng::to_string(origins).expect("origins serialize"),
    )
    .expect("origins write");
    fs::write(
        temporary.path().join("mappings/case.yaml"),
        serde_yaml_ng::to_string(mapping).expect("mapping serializes"),
    )
    .expect("mapping write");
    temporary
}

fn accepted_by_rust(contract: &str, document: &Value) -> bool {
    match contract {
        "origins" => {
            let project = write_project(document, &positive_document("evidence-mapping"));
            check_project(project.path(), false).is_ok()
        }
        "evidence-mapping" => {
            let project = write_project(&positive_document("origins"), document);
            check_project(project.path(), false).is_ok()
        }
        "runtime" => {
            let temporary = tempfile::tempdir().expect("temporary runtime");
            let path = temporary.path().join("runtime.yaml");
            fs::write(
                &path,
                serde_yaml_ng::to_string(document).expect("runtime serializes"),
            )
            .expect("runtime write");
            let index = positive_document("index");
            fs::write(
                temporary.path().join("discovery-index.json"),
                canonicalize_json(&index).expect("positive index canonicalizes"),
            )
            .expect("index write");
            prepare(&path).is_ok()
        }
        "index" => canonicalize_json(document).is_ok_and(|bytes| parse_index(&bytes).is_ok()),
        "profile" => {
            serde_json::to_vec(document).is_ok_and(|bytes| parse_description(&bytes).is_ok())
        }
        _ => panic!("unknown contract {contract}"),
    }
}

#[test]
fn every_positive_fixture_satisfies_draft_2020_12_and_the_closed_rust_parser() {
    let validators = validators();

    for (contract, relative) in [
        ("origins", "fixtures/project/origins.yaml"),
        (
            "evidence-mapping",
            "fixtures/project/mappings/adult-status.yaml",
        ),
        ("runtime", "fixtures/project/runtime.yaml"),
        ("index", "fixtures/project/discovery-index.json"),
    ] {
        let document = if relative.ends_with(".json") {
            load_json(relative)
        } else {
            load_yaml(relative)
        };
        assert!(
            validators[contract].is_valid(&document),
            "{relative} must satisfy the {contract} Draft 2020-12 schema"
        );
        assert!(
            accepted_by_rust(contract, &document),
            "{relative} must satisfy the closed Rust parser"
        );
    }

    for fixture in fs::read_dir(product_path("fixtures/descriptions"))
        .expect("description fixture directory reads")
    {
        let path = fixture.expect("description fixture entry reads").path();
        if path.extension().and_then(|value| value.to_str()) != Some("jsonld") {
            continue;
        }
        let document: Value = serde_json::from_slice(&fs::read(&path).expect("fixture reads"))
            .expect("description fixture is JSON");
        assert!(
            validators["profile"].is_valid(&document),
            "{} must satisfy the profile Draft 2020-12 schema",
            path.display()
        );
        assert!(
            accepted_by_rust("profile", &document),
            "{} must satisfy the closed profile parser",
            path.display()
        );
    }
}

#[test]
fn profile_multibyte_strings_use_json_schema_character_semantics() {
    let validator = validator("profile/schema/registry-discovery-v1alpha1.schema.json");
    let mut document = positive_document("profile");
    let boundary = "é".repeat(registry_discovery_profile::MAX_STRING_CHARACTERS);
    assert!(boundary.len() > registry_discovery_profile::MAX_STRING_CHARACTERS);
    set_pointer(&mut document, "/services/0/title", Value::String(boundary));
    assert!(validator.is_valid(&document));
    assert!(accepted_by_rust("profile", &document));

    set_pointer(
        &mut document,
        "/services/0/title",
        Value::String("é".repeat(registry_discovery_profile::MAX_STRING_CHARACTERS + 1)),
    );
    assert!(!validator.is_valid(&document));
    assert!(!accepted_by_rust("profile", &document));
}

#[test]
fn profile_endpoint_schema_and_rust_reject_preparser_whitespace_and_controls() {
    let validator = validator("profile/schema/registry-discovery-v1alpha1.schema.json");
    for endpoint in [
        "https://evidence.example.org/catalog.jsonld",
        "http://localhost:8080/catalog.jsonld",
        "http://127.0.0.1:8080/catalog.jsonld",
        "http://[::1]:8080/catalog.jsonld",
    ] {
        let baseline = parse_description(
            &fs::read(product_path("fixtures/descriptions/evidence.jsonld"))
                .expect("profile fixture reads"),
        )
        .expect("profile fixture parses");
        let original = &baseline.services()[0];
        let service = ServiceDescription::new(
            original.service_id().to_owned(),
            original.service_kind(),
            original.title().to_owned(),
            original.description().to_owned(),
            endpoint.to_owned(),
            original.roles().clone(),
            original.jurisdictions().to_vec(),
            original.conforms_to().to_vec(),
            original.evidence_type_ids().to_vec(),
            original.semantic_class_ids().to_vec(),
            original.operation_family_ids().to_vec(),
        )
        .expect("accepted endpoint constructs a service");
        let document: Value = serde_json::from_slice(
            &render_description(
                &DiscoveryDescription::new(vec![service]).expect("description constructs"),
            )
            .expect("description renders"),
        )
        .expect("description is JSON");
        assert!(validator.is_valid(&document), "schema rejected {endpoint}");
        assert!(
            accepted_by_rust("profile", &document),
            "Rust rejected {endpoint}"
        );
    }
    for endpoint in [
        "http://127.0.0.2:8080/catalog.jsonld",
        "http://127.1:8080/catalog.jsonld",
        "http://LOCALHOST:8080/catalog.jsonld",
        "http://[::2]:8080/catalog.jsonld",
        " https://evidence.example.org/catalog.jsonld",
        "https://evidence.example.org/catalog.jsonld\n",
        "https://evidence.example.org/catalog .jsonld",
        "https://evidence.example.org/catalog\u{0007}.jsonld",
    ] {
        let mut document = positive_document("profile");
        set_pointer(
            &mut document,
            "/services/0/endpointURL",
            Value::String(endpoint.to_owned()),
        );
        assert!(
            !validator.is_valid(&document),
            "schema accepted {endpoint:?}"
        );
        assert!(
            !accepted_by_rust("profile", &document),
            "Rust accepted {endpoint:?}"
        );
    }
}

#[test]
fn runtime_response_and_listener_boundaries_match_the_closed_rust_parser() {
    let schema = load_json("schemas/runtime.schema.json");
    let validator = validator("schemas/runtime.schema.json");
    let minimum_response_bytes = registry_discovery::MINIMUM_HTTP_RESPONSE_BYTES;
    assert_eq!(
        schema["properties"]["limits"]["properties"]["maximumResponseBytes"]["minimum"].as_u64(),
        u64::try_from(minimum_response_bytes).ok(),
        "the public schema must carry the stable Rust response-size minimum"
    );
    assert_eq!(
        schema["properties"]["listener"]["properties"]["address"]["maxLength"].as_u64(),
        u64::try_from(registry_discovery::MAXIMUM_LISTENER_ADDRESS_CHARACTERS).ok(),
        "the public schema must carry the Rust listener-address bound"
    );
    assert!(
        registry_discovery::openapi::OPENAPI_BYTES.len() <= minimum_response_bytes,
        "the stable response-size minimum must contain the embedded OpenAPI document"
    );

    for value in [
        minimum_response_bytes,
        registry_discovery::MAXIMUM_HTTP_BODY_BYTES,
    ] {
        let mut document = positive_document("runtime");
        set_pointer(
            &mut document,
            "/limits/maximumResponseBytes",
            Value::from(value),
        );
        assert!(validator.is_valid(&document), "schema rejected {value}");
        assert!(
            accepted_by_rust("runtime", &document),
            "Rust rejected {value}"
        );
    }

    for value in [
        minimum_response_bytes - 1,
        registry_discovery::MAXIMUM_HTTP_BODY_BYTES + 1,
    ] {
        let mut document = positive_document("runtime");
        set_pointer(
            &mut document,
            "/limits/maximumResponseBytes",
            Value::from(value),
        );
        assert!(!validator.is_valid(&document), "schema accepted {value}");
        assert!(
            !accepted_by_rust("runtime", &document),
            "Rust accepted {value}"
        );
    }

    for address in [
        "0.0.0.0:0",
        "127.0.0.1:00080",
        "255.255.255.255:65535",
        "[::]:0",
        "[::1]:8080",
        "[2001:db8:0:1::1]:443",
        "[::ffff:192.0.2.128]:65535",
        "[2001:db8::192.0.2.128]:443",
    ] {
        let mut document = positive_document("runtime");
        set_pointer(
            &mut document,
            "/listener/address",
            Value::String(address.to_owned()),
        );
        assert!(
            validator.is_valid(&document),
            "schema rejected valid SocketAddr {address}"
        );
        assert!(
            accepted_by_rust("runtime", &document),
            "Rust rejected valid SocketAddr {address}"
        );
    }

    for address in [
        "999.999.999.999:80",
        "127.0.0.1:65536",
        "127.00.0.1:80",
        "::1:80",
        "[2001:::1]:80",
        "[::1]:65536",
        "[gggg::1]:80",
    ] {
        let mut document = positive_document("runtime");
        set_pointer(
            &mut document,
            "/listener/address",
            Value::String(address.to_owned()),
        );
        assert!(
            !validator.is_valid(&document),
            "schema accepted invalid SocketAddr {address}"
        );
        assert!(
            !accepted_by_rust("runtime", &document),
            "Rust accepted invalid SocketAddr {address}"
        );
    }

    let overlong_address = format!(
        "127.0.0.1:{}80",
        "0".repeat(registry_discovery::MAXIMUM_LISTENER_ADDRESS_CHARACTERS)
    );
    let mut document = positive_document("runtime");
    set_pointer(
        &mut document,
        "/listener/address",
        Value::String(overlong_address),
    );
    assert!(!validator.is_valid(&document));
    assert!(!accepted_by_rust("runtime", &document));
}

#[test]
fn shared_negative_corpus_is_refused_by_both_schema_and_rust() {
    let corpus: NegativeCorpus = serde_json::from_slice(
        &fs::read(product_path("fixtures/schema-negative-corpus.json"))
            .expect("negative corpus reads"),
    )
    .expect("negative corpus parses");
    assert_eq!(
        corpus.schema_version,
        "registry-discovery/schema-negative-corpus/v1alpha1"
    );
    let validators = validators();
    let mut covered = std::collections::BTreeSet::new();

    for case in corpus.cases {
        let mut document = positive_document(&case.contract);
        let value = generated_negative_value(&case, &document);
        set_pointer(&mut document, &case.pointer, value);
        assert!(
            !validators[case.contract.as_str()].is_valid(&document),
            "negative corpus case {} must be rejected by its Draft 2020-12 schema",
            case.name
        );
        assert!(
            !accepted_by_rust(&case.contract, &document),
            "negative corpus case {} must be rejected by its closed Rust parser",
            case.name
        );
        covered.insert(case.contract);
    }

    assert_eq!(
        covered,
        std::collections::BTreeSet::from([
            "evidence-mapping".to_owned(),
            "index".to_owned(),
            "origins".to_owned(),
            "profile".to_owned(),
            "runtime".to_owned(),
        ]),
        "the shared negative corpus must cover every closed contract"
    );
}
