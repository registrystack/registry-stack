// SPDX-License-Identifier: Apache-2.0
//! Exact, opt-in source preparation for one synthetic run, before packaging.
use anyhow::{ensure, Result};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

pub(crate) const API_VERSION: &str = "id.registrystack.org/formats/casework/run-source/v1alpha1";
pub(crate) const KIND: &str = "CaseworkRunSource";
const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request {
    pub api_version: String,
    pub kind: String,
    pub producer: String,
    pub identity_profile: String,
    pub identity_subject: String,
    pub identity_scopes: registry_platform_yaml::UniqueList<String>,
    pub binding: Binding,
}
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Binding {
    pub producer: Producer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<Initiator>,
}
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Producer {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub expected_issuer: String,
    pub expected_profile: String,
    pub expected_subject: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Initiator {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub expected_issuer: String,
    pub trust: InitiatorTrust,
}
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) enum InitiatorTrust {
    #[serde(rename = "run-test-people")]
    RunTestPeople,
}

#[derive(Debug)]
pub(crate) struct Refusal(pub &'static str);
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "run source refused at {}", self.0)
    }
}
impl std::error::Error for Refusal {}
fn require(ok: bool, pointer: &'static str) -> Result<()> {
    if !ok {
        return Err(Refusal(pointer).into());
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    let encoded = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{encoded}")
}
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileDigest {
    pub path: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    pub digest: String,
}
fn hashes(inputs: &BTreeMap<String, Vec<u8>>) -> Vec<FileDigest> {
    inputs
        .iter()
        .map(|(path, bytes)| FileDigest {
            path: path.clone(),
            digest: hex(&Sha256::digest(bytes)),
        })
        .collect()
}

fn digest(inputs: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"casework-run-source-v1\0");
    for (path, bytes) in inputs {
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hex(&hash.finalize())
}

pub(crate) fn generate(
    project: &Path,
    request: &Path,
    issuer: Option<&str>,
    expected: Option<&str>,
    output: Option<&Path>,
) -> Result<Value> {
    let bytes = crate::project::read_package_input(request)?;
    let request = Reader::new("run-source.json")
        .decode::<Request>(&bytes, &Expect::one(&FORMAT))?
        .value;
    let mut inputs = crate::project::checked_source_contents(project)?;
    let original = inputs.clone();
    let source_digest = digest(&inputs);
    require(
        expected.is_none_or(|value| value == source_digest),
        "/sourceDigest",
    )?;
    // Decode and check the captured bytes, never a later ambient reread.
    let decoded = registry_casework_core::CaseworkProject::read_with_schemas(
        "casework.yaml",
        inputs
            .get("casework.yaml")
            .ok_or(Refusal("/sourceDigest"))?,
        &inputs,
    )?;
    let checked = tempfile::tempdir()?;
    write_inputs(checked.path(), &inputs)?;
    crate::project::check(checked.path(), false, false)?;
    let policy = &decoded.value;
    let producer = policy
        .trusted_producers
        .iter()
        .find(|p| p.id == request.producer)
        .ok_or(Refusal("/producer"))?;
    let guard = &request.binding.producer;
    require(
        producer.issuer == guard.expected_issuer,
        "/binding/producer/expectedIssuer",
    )?;
    require(
        producer.profile == guard.expected_profile && request.identity_profile == producer.profile,
        "/binding/producer/expectedProfile",
    )?;
    require(
        producer.subject == guard.expected_subject && request.identity_subject == producer.subject,
        "/binding/producer/expectedSubject",
    )?;
    let profile = policy
        .access_profiles
        .iter()
        .find(|p| p.id == producer.profile)
        .ok_or(Refusal("/identityProfile"))?;
    require(
        profile
            .required_scopes
            .iter()
            .all(|scope| request.identity_scopes.contains(scope)),
        "/identityScopes",
    )?;
    if let Some(initiator) = &request.binding.initiator {
        require(
            producer.trusted_initiator_issuer.as_deref()
                == Some(initiator.expected_issuer.as_str()),
            "/binding/initiator/expectedIssuer",
        )?;
    }
    let mut document = decoded.document.to_json_value();
    let mut changed = Vec::new();
    if let Some(issuer) = issuer {
        // Only a reserved loopback run URL is supported, never a remote issuer.
        let uri: reqwest::Url = issuer.parse().map_err(|_| Refusal("/issuer"))?;
        require(
            uri.scheme() == "http"
                && uri.host_str() == Some("127.0.0.1")
                && uri.port().is_some_and(|port| port > 1)
                && uri.path() == "/"
                && uri.query().is_none()
                && uri.fragment().is_none()
                && uri.username().is_empty()
                && uri.password().is_none(),
            "/issuer",
        )?;
        let entry = &mut document["trustedProducers"][&request.producer];
        require(entry.is_object(), "/producer")?;
        entry["issuer"] = json!(issuer);
        changed.push(format!("/trustedProducers/{}/issuer", request.producer));
        if request.binding.initiator.is_some() {
            entry["trustedInitiatorIssuer"] = json!(issuer);
            changed.push(format!(
                "/trustedProducers/{}/trustedInitiatorIssuer",
                request.producer
            ));
        }
        // The only construction above edits the two explicit members. Restore
        // them and compare the complete document before serializing any copy.
        validate_diff(
            &decoded.document.to_json_value(),
            &document,
            &request.producer,
            request.binding.initiator.is_some(),
        )?;
        let yaml = serde_norway::to_string(&document)?.into_bytes();
        let transformed = registry_casework_core::CaseworkProject::read_with_schemas(
            "casework.yaml",
            &yaml,
            &inputs,
        )?;
        // The owning compiler rejects principal collisions and every other
        // policy error, without changing any runtime admission rule.
        let stage = tempfile::tempdir()?;
        inputs.insert("casework.yaml".to_owned(), yaml);
        write_inputs(stage.path(), &inputs)?;
        crate::project::check(stage.path(), false, false)?;
        ensure!(
            transformed.value.trusted_producers.len() == policy.trusted_producers.len(),
            "producer count changed"
        );
    }
    // Detect a source edit between the original closure capture and output.
    require(
        crate::project::checked_source_contents(project)? == original,
        "/sourceDigest",
    )?;
    let report = json!({"ok":true,"command":"generate-run-source","sourceDigest":source_digest,"sourceFiles":hashes(&original),"bindingDigest":hex(&Sha256::digest(&bytes)),"issuer":issuer,"transformedDigest":digest(&inputs),"files":hashes(&inputs),"changedPointers":changed,"output":output,"networkAccess":false,"databaseAccess":false});
    let receipt_bytes = serde_json::to_vec(&crate::report::CliReport::from_value(
        "generate-run-source",
        report.clone(),
    )?)?;
    if let Some(output) = output {
        fs::DirBuilder::new().mode(0o700).create(output)?;
        write_inputs(output, &inputs)?;
        // A receipt failure is an operational failure, never a usable output.
        let receipt = output.join("run-source-receipt.json");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(receipt)?;
        file.write_all(&receipt_bytes)?;
        file.sync_all()?;
    }
    Ok(report)
}
fn write_inputs(root: &Path, inputs: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for (relative, bytes) in inputs {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

fn validate_diff(
    original: &Value,
    transformed: &Value,
    producer: &str,
    initiator: bool,
) -> Result<()> {
    let mut restored = transformed.clone();
    restored["trustedProducers"][producer]["issuer"] =
        original["trustedProducers"][producer]["issuer"].clone();
    if initiator {
        restored["trustedProducers"][producer]["trustedInitiatorIssuer"] =
            original["trustedProducers"][producer]["trustedInitiatorIssuer"].clone();
    }
    require(restored == *original, "/authorityDiff")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(root: &Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
        let project = root.join("original");
        crate::project::init(&project, "standalone-decision").unwrap();
        let policy = crate::project::load_and_check_policy(&project).unwrap();
        let p = &policy.trusted_producers[0];
        let request = root.join("binding.json");
        fs::write(&request,serde_json::to_vec(&json!({"apiVersion":API_VERSION,"kind":KIND,"producer":p.id,"identityProfile":p.profile,"identitySubject":p.subject,"identityScopes":policy.access_profiles.iter().find(|profile|profile.id==p.profile).unwrap().required_scopes,"binding":{"producer":{"expectedIssuer":p.issuer,"expectedProfile":p.profile,"expectedSubject":p.subject}}})).unwrap()).unwrap();
        (project, request, p.id.clone())
    }
    fn edit(path: &Path, edit: impl FnOnce(&mut Value)) {
        let mut v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        edit(&mut v);
        fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
    }
    fn issuer() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        (listener, url)
    }
    #[test]
    fn captures_original_and_binds_only_selected_existing_producer_before_normal_package() {
        let temp = tempfile::tempdir().unwrap();
        let (project, request, id) = fixture(temp.path());
        let original = crate::project::package_contents(&project).unwrap();
        let captured = temp.path().join("captured");
        let capture = generate(&project, &request, None, None, Some(&captured)).unwrap();
        assert_eq!(
            original,
            crate::project::package_contents(&captured).unwrap()
        );
        let (_listener, url) = issuer();
        let bound = temp.path().join("bound");
        let report = generate(
            &captured,
            &request,
            Some(&url),
            capture["sourceDigest"].as_str(),
            Some(&bound),
        )
        .unwrap();
        assert_eq!(
            report["changedPointers"],
            json!([format!("/trustedProducers/{id}/issuer")])
        );
        assert_ne!(report["sourceDigest"], report["transformedDigest"]);
        let before = crate::project::load_and_check_policy(&project).unwrap();
        let after = crate::project::load_and_check_policy(&bound).unwrap();
        assert_eq!(after.trusted_producers[0].issuer, url);
        assert_eq!(
            before.trusted_producers[0].trusted_initiator_issuer,
            after.trusted_producers[0].trusted_initiator_issuer
        );
        assert_eq!(
            before.trusted_producers[0].subject,
            after.trusted_producers[0].subject
        );
        assert_eq!(
            original,
            crate::project::package_contents(&project).unwrap()
        );
        crate::project::package(&bound, &temp.path().join("package"), None).unwrap();
        assert!(bound.join("run-source-receipt.json").is_file());
        #[cfg(feature = "schema")]
        {
            let schemas = crate::schema::report_documents().unwrap();
            let schema: Value = serde_json::from_str(&schemas["report.schema.json"]).unwrap();
            let validator = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .compile(&schema)
                .unwrap();
            let receipt: Value =
                serde_json::from_slice(&fs::read(bound.join("run-source-receipt.json")).unwrap())
                    .unwrap();
            if let Err(errors) = validator.validate(&receipt) {
                let paths = errors
                    .map(|error| format!("{} at {}", error.instance_path, error.schema_path))
                    .collect::<Vec<_>>();
                panic!("receipt schema paths: {paths:?}");
            };
        }

        assert!(generate(&captured, &request, Some(&url), None, Some(&bound)).is_err());
    }
    #[test]
    fn initiator_is_separate_opt_in_and_never_fills_an_absent_pin() {
        let temp = tempfile::tempdir().unwrap();
        let (project, request, id) = fixture(temp.path());
        let (_listener, url) = issuer();
        edit(
            &request,
            |v| {
                v["binding"]["initiator"] = json!({"expectedIssuer":"https://identity.example.test","trust":"run-test-people"})
            },
        );
        let policy = crate::project::load_and_check_policy(&project).unwrap();
        if let Some(old) = &policy.trusted_producers[0].trusted_initiator_issuer {
            edit(&request, |v| {
                v["binding"]["initiator"]["expectedIssuer"] = json!(old)
            });
        } else {
            assert!(generate(&project, &request, Some(&url), None, None).is_err());
        }
        let mut source = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        source["trustedProducers"][&id]["trustedInitiatorIssuer"] =
            json!("https://identity.example.test");
        fs::write(
            project.join("casework.yaml"),
            serde_norway::to_string(&source).unwrap(),
        )
        .unwrap();
        edit(&request, |v| {
            v["binding"]["initiator"]["expectedIssuer"] = json!("https://identity.example.test")
        });
        let output = temp.path().join("bound");
        let report = generate(&project, &request, Some(&url), None, Some(&output)).unwrap();
        assert_eq!(report["changedPointers"].as_array().unwrap().len(), 2);
        assert_eq!(
            crate::project::load_and_check_policy(&output)
                .unwrap()
                .trusted_producers[0]
                .trusted_initiator_issuer
                .as_deref(),
            Some(url.as_str())
        );
    }
    #[test]
    fn guards_refuse_missing_producer_identity_chain_changed_closure_and_static_issuer() {
        let temp = tempfile::tempdir().unwrap();
        let (project, request, _) = fixture(temp.path());
        let checked = generate(&project, &request, None, None, None).unwrap();
        let bytes = fs::read(&request).unwrap();
        for pointer in [
            "/producer",
            "/identityProfile",
            "/identitySubject",
            "/binding/producer/expectedIssuer",
            "/binding/producer/expectedSubject",
            "/binding/producer/expectedProfile",
        ] {
            edit(&request, |v| {
                *v.pointer_mut(pointer).unwrap() = json!("mismatch")
            });
            assert!(
                generate(&project, &request, None, None, None)
                    .unwrap_err()
                    .is::<Refusal>(),
                "{pointer}"
            );
            fs::write(&request, &bytes).unwrap();
        }
        edit(&request, |v| v["identityScopes"] = json!([]));
        assert!(generate(&project, &request, None, None, None)
            .unwrap_err()
            .is::<Refusal>());
        fs::write(&request, &bytes).unwrap();
        let mut source = fs::read(project.join("casework.yaml")).unwrap();
        source.extend_from_slice(b"\n# edited\n");
        fs::write(project.join("casework.yaml"), source).unwrap();
        assert!(generate(
            &project,
            &request,
            None,
            checked["sourceDigest"].as_str(),
            None
        )
        .unwrap_err()
        .is::<Refusal>());
        for value in [
            "run",
            "http://127.0.0.1:1",
            "http://127.0.0.1:8191/other",
            "https://remote.example.test",
            "http://localhost:8191",
        ] {
            assert!(generate(&project, &request, Some(value), None, None).is_err());
        }
        edit(&request, |v| v["binding"]["unrecognized"] = json!(true));
        assert!(generate(&project, &request, None, None, None).is_err());
    }
    #[test]
    fn refuses_new_principal_collisions_and_additional_authority_diff() {
        let temp = tempfile::tempdir().unwrap();
        let (project, request, id) = fixture(temp.path());
        let (_listener, url) = issuer();
        let mut source = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        let original = source.clone();
        source["trustedProducers"][&id]["subject"] = json!("changed");
        assert!(validate_diff(&original, &source, &id, false).is_err());
        source = original.clone();
        let mut other = source["trustedProducers"][&id].clone();
        other["issuer"] = json!(url);
        source["trustedProducers"]["other-producer"] = other;
        fs::write(
            project.join("casework.yaml"),
            serde_norway::to_string(&source).unwrap(),
        )
        .unwrap();
        assert!(generate(&project, &request, Some(&url), None, None).is_err());
    }
    #[test]
    fn receipt_write_failure_after_capture_never_returns_a_success_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let (project, request, _) = fixture(temp.path());
        let mut source = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        let reviews = source["reviewPolicies"].as_object_mut().unwrap();
        let review = reviews.values_mut().next().unwrap();
        let schema = review["displaySchema"].clone();
        review["displaySchema"] = json!({"$ref":"run-source-receipt.json"});
        fs::write(
            project.join("run-source-receipt.json"),
            serde_json::to_vec(&schema).unwrap(),
        )
        .unwrap();
        fs::write(
            project.join("casework.yaml"),
            serde_norway::to_string(&source).unwrap(),
        )
        .unwrap();
        let original = crate::project::checked_source_contents(&project).unwrap();
        let output = temp.path().join("partial");
        let error = generate(&project, &request, None, None, Some(&output)).unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(
            fs::read(output.join("run-source-receipt.json")).unwrap(),
            serde_json::to_vec(&schema).unwrap()
        );
        assert_eq!(
            original,
            crate::project::checked_source_contents(&project).unwrap()
        );
    }

    #[test]
    fn receipt_failure_never_returns_success_or_overwrites_input() {
        let temp = tempfile::tempdir().unwrap();
        let (project, request, _) = fixture(temp.path());
        let output = temp.path().join("occupied");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("run-source-receipt.json"), b"existing").unwrap();
        assert!(generate(&project, &request, None, None, Some(&output)).is_err());
        assert_eq!(
            fs::read(output.join("run-source-receipt.json")).unwrap(),
            b"existing"
        );
    }
}
