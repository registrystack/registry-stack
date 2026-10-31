// SPDX-License-Identifier: Apache-2.0

//! The effective operation contract is produced by the same runtime loader
//! that decides which authored bindings are actually served.

use std::fs;
use std::process::Command;

use registry_adapter::effective_contract::{
    schema as effective_contract_schema, DIGEST_DOMAIN, PIN_PROBLEM_CODE, UNAVAILABLE_PROBLEM_CODE,
};
use registry_adapter_core::{
    ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND, ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND,
    ADAPTER_PROJECT_API_VERSION, ADAPTER_PROJECT_KIND,
};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::sha256_uri;
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde_json::Value;

const USERNAME: &str = "synthetic-reader";
const PASSWORD: &str = "synthetic-password";
const CURSOR_KEY: &str = "synthetic-cursor-key-0123456789!";
const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROFILE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROFILE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
const PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn runtime_file(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("runtime.yaml");
    fs::write(
        &path,
        r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: effective-contract-test
endpoints:
  - endpoint: tracker
    baseUrl: http://127.0.0.1:9
    credential:
      type: basic
      usernameRef: secret:env/TEST_UPSTREAM_USERNAME
      passwordRef: secret:env/TEST_UPSTREAM_PASSWORD
listener:
  bind: 127.0.0.1:0
database:
  runtimeUrlRef: secret:env/TEST_DB_URL
  migrationUrlRef: secret:env/TEST_DB_URL
  testOnlyPlaintext: true
oidc:
  issuer: http://127.0.0.1:9
  audience: registry-adapter-test
  allowInsecureHttp: true
  jwksSource:
    type: static
    documentRef: secret:env/TEST_JWKS
allowedClients:
  - synthetic-client
allowedPrivateCidrs:
  - 192.168.0.0/16
audit:
  retentionDays: 90
cursorKeyRef: secret:env/TEST_CURSOR_KEY
"#,
    )
    .expect("write runtime config");
    path
}

fn export_paths(
    project: &std::path::Path,
    profile: &std::path::Path,
    pack: &std::path::Path,
) -> Value {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let runtime = runtime_file(scratch.path());
    let output = Command::new(env!("CARGO_BIN_EXE_adapter"))
        .arg("effective-contract")
        .arg("--runtime-config")
        .arg(runtime)
        .arg("--project")
        .arg(project)
        .arg("--profile")
        .arg(profile)
        .arg("--pack")
        .arg(pack)
        .env("TEST_UPSTREAM_USERNAME", USERNAME)
        .env("TEST_UPSTREAM_PASSWORD", PASSWORD)
        .env("TEST_CURSOR_KEY", CURSOR_KEY)
        .env("TEST_DB_URL", "postgresql://unused.invalid/test")
        .env("TEST_JWKS", r#"{"keys":[]}"#)
        .output()
        .expect("run adapter effective-contract");
    assert!(
        output.status.success(),
        "effective-contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("contract JSON")
}

fn export(project: &str, profile: &str) -> Value {
    let root = repo_root();
    export_paths(
        &root.join(format!("products/adapter/examples/{project}")),
        &root.join(format!("products/adapter/profiles/{profile}/profile.yaml")),
        &root.join("products/adapter/packs/dhis2-tracker/pack.yaml"),
    )
}

fn read_yaml_value(path: &std::path::Path, format: &'static FormatSpec<'static>) -> Value {
    let bytes = fs::read(path).expect("read authored YAML");
    let document = Reader::new(path.display().to_string())
        .read(&bytes, &Expect::one(format))
        .expect("read authored YAML through the shared reader");
    document
        .decode::<Value>()
        .expect("decode authored YAML through the shared reader")
}

fn empty_version_artifacts(
    scratch: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let root = repo_root();
    let source_profile = root.join("products/adapter/profiles/breg-records/profile.yaml");
    let source_pack = root.join("products/adapter/packs/dhis2-tracker");
    let source_project = root.join("products/adapter/examples/dhis2-tracker/project.yaml");

    let mut profile = read_yaml_value(&source_profile, &PROFILE_FORMAT);
    profile["version"] = Value::String(String::new());
    let profile_document = serde_norway::to_string(&profile).expect("encode profile");
    let profile_path = scratch.join("profile.yaml");
    fs::write(&profile_path, &profile_document).expect("write profile");

    let mut pack = read_yaml_value(&source_pack.join("pack.yaml"), &PACK_FORMAT);
    pack["version"] = Value::String(String::new());
    let pack_document = serde_norway::to_string(&pack).expect("encode pack");
    let pack_directory = scratch.join("pack");
    let script_directory = pack_directory.join("scripts");
    fs::create_dir_all(&script_directory).expect("create pack scripts directory");
    for entry in fs::read_dir(source_pack.join("scripts")).expect("read pack scripts") {
        let entry = entry.expect("pack script entry");
        fs::copy(entry.path(), script_directory.join(entry.file_name())).expect("copy pack script");
    }
    let pack_path = pack_directory.join("pack.yaml");
    fs::write(&pack_path, &pack_document).expect("write pack");

    let mut project = read_yaml_value(&source_project, &PROJECT_FORMAT);
    project["project"]["version"] = Value::String(String::new());
    project["profile"]["version"] = Value::String(String::new());
    project["profile"]["digest"] = Value::String(sha256_uri(profile_document.as_bytes()));
    project["pack"]["version"] = Value::String(String::new());
    project["pack"]["digest"] = Value::String(sha256_uri(pack_document.as_bytes()));
    let project_directory = scratch.join("project");
    fs::create_dir(&project_directory).expect("create project directory");
    fs::write(
        project_directory.join("project.yaml"),
        serde_norway::to_string(&project).expect("encode project"),
    )
    .expect("write project");

    (project_directory, profile_path, pack_path)
}

fn project_with_native_update(scratch: &std::path::Path) -> std::path::PathBuf {
    // The example project carries the records-update binding natively,
    // so the native-update contract is read straight from it.
    let source = repo_root().join("products/adapter/examples/dhis2-tracker/project.yaml");
    let project = read_yaml_value(&source, &PROJECT_FORMAT);
    let directory = scratch.join("project");
    fs::create_dir(&directory).expect("create update project directory");
    fs::write(
        directory.join("project.yaml"),
        serde_norway::to_string(&project).expect("encode update project"),
    )
    .expect("write update project");
    directory
}

#[test]
fn export_contains_only_effectively_served_reads_and_names_unserved_writes() {
    let contract = export("dhis2-tracker", "breg-records");
    let body = &contract["contract"];
    assert_eq!(
        contract["apiVersion"],
        "id.registrystack.org/formats/adapter/effective-contract/v1alpha1"
    );
    assert_eq!(contract["kind"], "AdapterEffectiveContract");
    assert!(contract["digest"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:")));
    assert_eq!(body["project"]["id"], "dhis2-tracker-example");
    assert_eq!(body["profileVersion"], "1");
    assert!(body["artifactDeploymentDigest"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:")));
    let digest_input = serde_json::json!({
        "domain": DIGEST_DOMAIN,
        "apiVersion": contract["apiVersion"],
        "kind": contract["kind"],
        "contract": body,
    });
    let canonical = canonicalize_json(&digest_input).expect("contract input canonicalizes");
    assert_eq!(contract["digest"], sha256_uri(&canonical));
    assert_eq!(
        body["schemaDialect"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(body["authority"]["callerMode"], "trusted-machine");
    assert_eq!(body["authority"]["representedSubject"], "unsupported");
    assert_eq!(body["authority"]["personalDelegation"], "unsupported");
    assert_eq!(body["authority"]["targetBinding"], "unsupported");
    assert_eq!(body["authority"]["rowDisclosureAuthority"], "not-granted");
    assert_eq!(body["authority"]["fieldDisclosureAuthority"], "not-granted");

    let operations = body["operations"].as_array().expect("operations");
    let ids = operations
        .iter()
        .map(|operation| operation["id"].as_str().expect("operation id"))
        .collect::<Vec<_>>();
    assert_eq!(ids, ["records-search.person", "records-get.person"]);
    assert!(operations.iter().all(|operation| {
        operation["support"] == "served"
            && operation["effect"] == "read"
            && operation["successStatus"].as_u64().is_some()
    }));
    assert!(operations.iter().all(|operation| {
        operation["input"]["path"]["additionalProperties"] == false
            && operation["input"]["query"]["additionalProperties"] == false
            && operation["output"]["additionalProperties"] == false
    }));
    let get = operations
        .iter()
        .find(|operation| operation["id"] == "records-get.person")
        .expect("get operation");
    let record_id = &get["input"]["path"]["properties"]["record_id"];
    assert_eq!(record_id["minLength"], 1);
    assert_eq!(
        record_id["not"]["anyOf"][0]["enum"],
        serde_json::json!([".", ".."])
    );
    assert!(record_id["not"]["anyOf"][1]["pattern"]
        .as_str()
        .is_some_and(|pattern| pattern.contains(':')));

    let unserved = body["unserved"].as_array().expect("unserved");
    let write = unserved
        .iter()
        .find(|operation| operation["operationId"] == "records-create.person")
        .expect("the write stays outside the gateway surface");
    assert_eq!(write["bindingId"], "person-create");
    assert_eq!(write["support"], "unserved");
    assert_eq!(write["effect"], "write");
    assert!(write["reasonCode"]
        .as_str()
        .is_some_and(|code| !code.is_empty()));
    assert_eq!(
        body["protocolProblems"]["problems"][0]["code"],
        PIN_PROBLEM_CODE
    );
    assert_eq!(body["protocolProblems"]["problems"][0]["status"], 412);
    assert_eq!(
        body["protocolProblems"]["problems"][1]["code"],
        UNAVAILABLE_PROBLEM_CODE
    );
    assert_eq!(body["protocolProblems"]["problems"][1]["status"], 503);

    let serialized = contract.to_string();
    for forbidden in [
        "synthetic-client",
        USERNAME,
        PASSWORD,
        "127.0.0.1",
        "postgresql://",
        "secret:env",
        "TEST_UPSTREAM",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "contract leaked {forbidden}"
        );
    }
}

#[test]
fn native_put_is_schema_valid_unserved_gateway_metadata() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let root = repo_root();
    let project = project_with_native_update(scratch.path());
    let export = export_paths(
        &project,
        &root.join("products/adapter/profiles/breg-records/profile.yaml"),
        &root.join("products/adapter/packs/dhis2-tracker/pack.yaml"),
    );

    let update = export["contract"]["unserved"]
        .as_array()
        .expect("unserved operations")
        .iter()
        .find(|operation| operation["operationId"] == "records-update.person")
        .expect("the native update remains outside the gateway surface");
    assert_eq!(update["method"], "PUT");
    assert_eq!(update["effect"], "write");
    assert_eq!(update["support"], "unserved");
    assert_eq!(
        update["reasonCode"],
        "adapter.operation.gateway-write-disabled"
    );
    assert!(
        export["contract"]["operations"]
            .as_array()
            .expect("served gateway operations")
            .iter()
            .all(|operation| operation["effect"] == "read"),
        "native PUT cannot enter the gateway's served operation surface"
    );

    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&effective_contract_schema())
        .expect("runtime effective-contract schema compiles");
    assert!(
        validator.is_valid(&export),
        "the native PUT metadata is inside the runtime's closed wire schema"
    );
}

#[test]
fn native_write_202_exports_as_unsupported_until_async_recovery_exists() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let root = repo_root();
    let source_profile = root.join("products/adapter/profiles/breg-records/profile.yaml");
    let mut profile = read_yaml_value(&source_profile, &PROFILE_FORMAT);
    let update = profile["operations"]
        .as_array_mut()
        .expect("profile operations")
        .iter_mut()
        .find(|operation| operation["id"] == "records-update")
        .expect("update operation");
    update["successStatus"] = serde_json::json!(202);
    let profile_document = serde_norway::to_string(&profile).expect("encode async profile");
    let profile_path = scratch.path().join("profile.yaml");
    fs::write(&profile_path, &profile_document).expect("write async profile");

    let project_directory = project_with_native_update(scratch.path());
    let project_path = project_directory.join("project.yaml");
    let mut project = read_yaml_value(&project_path, &PROJECT_FORMAT);
    project["profile"]["digest"] = Value::String(sha256_uri(profile_document.as_bytes()));
    fs::write(
        &project_path,
        serde_norway::to_string(&project).expect("encode async project"),
    )
    .expect("write async project");

    let export = export_paths(
        &project_directory,
        &profile_path,
        &root.join("products/adapter/packs/dhis2-tracker/pack.yaml"),
    );
    let update = export["contract"]["unserved"]
        .as_array()
        .expect("unserved operations")
        .iter()
        .find(|operation| operation["operationId"] == "records-update.person")
        .expect("the asynchronous update is unserved");
    assert_eq!(update["method"], "PUT");
    assert_eq!(
        update["reasonCode"],
        "adapter.operation.write-async-unsupported"
    );
    assert!(export["contract"]["operations"]
        .as_array()
        .expect("served operations")
        .iter()
        .all(|operation| operation["effect"] == "read"));
}

#[test]
fn read_only_post_202_remains_a_served_read() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let root = repo_root();
    let source_profile = root.join("products/adapter/profiles/govstack-consultation/profile.yaml");
    let mut profile = read_yaml_value(&source_profile, &PROFILE_FORMAT);
    let search = profile["operations"]
        .as_array_mut()
        .expect("profile operations")
        .iter_mut()
        .find(|operation| operation["id"] == "records-search")
        .expect("read-only POST search operation");
    assert_eq!(search["method"], "POST");
    assert_eq!(search["readOnly"], true);
    search["successStatus"] = serde_json::json!(202);
    let profile_document = serde_norway::to_string(&profile).expect("encode read profile");
    let profile_path = scratch.path().join("profile.yaml");
    fs::write(&profile_path, &profile_document).expect("write read profile");

    let source_project = root.join("products/adapter/examples/dhis2-govstack/project.yaml");
    let mut project = read_yaml_value(&source_project, &PROJECT_FORMAT);
    project["profile"]["digest"] = Value::String(sha256_uri(profile_document.as_bytes()));
    let project_directory = scratch.path().join("project");
    fs::create_dir(&project_directory).expect("create read project directory");
    fs::write(
        project_directory.join("project.yaml"),
        serde_norway::to_string(&project).expect("encode read project"),
    )
    .expect("write read project");

    let export = export_paths(
        &project_directory,
        &profile_path,
        &root.join("products/adapter/packs/dhis2-tracker/pack.yaml"),
    );
    let search = export["contract"]["operations"]
        .as_array()
        .expect("served operations")
        .iter()
        .find(|operation| operation["id"] == "records-search.persons")
        .expect("the read-only POST remains served");
    assert_eq!(search["method"], "POST");
    assert_eq!(search["effect"], "read");
    assert_eq!(search["successStatus"], 202);
}

#[test]
fn post_read_contract_carries_closed_body_and_pagination_bounds() {
    let contract = export("dhis2-govstack", "govstack-consultation");
    let operations = contract["contract"]["operations"]
        .as_array()
        .expect("operations");
    let search = operations
        .iter()
        .find(|operation| operation["id"] == "records-search.persons")
        .expect("search operation");
    assert_eq!(search["method"], "POST");
    assert_eq!(search["effect"], "read");
    assert_eq!(search["requestMaximumBytes"], 16 * 1024);
    assert_eq!(search["input"]["query"]["additionalProperties"], false);
    let body = &search["input"]["body"];
    assert_eq!(body["additionalProperties"], false);
    assert_eq!(body["properties"]["pageSize"]["minimum"], 1);
    assert_eq!(body["properties"]["pageSize"]["maximum"], 100);
    assert!(body["properties"]["cursor"]["maxLength"]
        .as_u64()
        .is_some_and(|bound| bound > 0));
    assert_eq!(search["output"]["properties"]["items"]["maxItems"], 100);
    assert_eq!(
        search["access"]["anyOf"][0]["allScopes"],
        serde_json::json!(["records.read"])
    );
    assert_eq!(
        contract["contract"]["authentication"]["audience"],
        "registry-adapter-test"
    );
    assert_eq!(
        contract["contract"]["authentication"]["clientAdmission"],
        "allowlist"
    );
}

#[test]
fn export_and_runtime_readback_match_the_registered_closed_schema() {
    let export = export("dhis2-tracker", "breg-records");
    let schema: Value = serde_json::from_str(include_str!(
        "../../../products/adapter/schemas/effective-contract.v1alpha1.schema.json"
    ))
    .expect("effective-contract schema");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("effective-contract schema compiles");
    assert!(
        validator.is_valid(&export),
        "the CLI export matches the registered schema"
    );

    let mut runtime = export.clone();
    runtime["readiness"] = serde_json::json!({
        "ready": true,
        "configuration": "ready",
        "journal": "ready"
    });
    assert!(
        validator.is_valid(&runtime),
        "authenticated runtime readback matches the same wire schema"
    );

    let mut unknown_effect = export;
    unknown_effect["contract"]["operations"][0]["effect"] = serde_json::json!("execute");
    assert!(
        !validator.is_valid(&unknown_effect),
        "an unknown effect is refused by the consuming schema"
    );
}

#[test]
fn schema_accepts_every_plain_string_version_the_cli_accepts() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let (project, profile, pack) = empty_version_artifacts(scratch.path());
    let export = export_paths(&project, &profile, &pack);

    assert_eq!(export["contract"]["project"]["version"], "");
    assert_eq!(export["contract"]["profileVersion"], "");
    assert!(export["contract"]["operations"]
        .as_array()
        .expect("served operations")
        .iter()
        .all(|operation| operation["version"] == ""));
    assert!(export["contract"]["unserved"]
        .as_array()
        .expect("unserved operations")
        .iter()
        .all(|operation| operation["version"] == ""));

    let schema: Value = serde_json::from_str(include_str!(
        "../../../products/adapter/schemas/effective-contract.v1alpha1.schema.json"
    ))
    .expect("effective-contract schema");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("effective-contract schema compiles");
    assert!(
        validator.is_valid(&export),
        "the schema accepts every version value the CLI accepts"
    );
}
