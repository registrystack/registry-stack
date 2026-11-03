use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

use registry_evidence::{
    audit::EvidenceAuditLog,
    authority::{ActivationError, AuthorityDocument, AuthorityError},
    bundle::{evidence_package_limits, Bundle, BundleError},
};
use registry_platform_audit::AuditWriter;
use registry_platform_config::{
    package::is_envelope_file, sha256_uri, verify_package, write_package,
};
use serde_json::{json, Value};

const REQUIREMENT: &str = "urn:example:fixture:requirement:professional-licence-status:v1";
const AUTHORITY_PATH_REFUSAL: &str =
    "an authority path that can activate a source does not supply every required route input";

fn fixture_root(case: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures")
        .join(case)
}

fn package_files(case: &str) -> (BTreeMap<String, Vec<u8>>, Option<String>) {
    let root = fixture_root(case);
    let verified = verify_package(&root, &evidence_package_limits(), "evidencectl package")
        .expect("the maintained fixture package verifies");
    let files = verified
        .files()
        .filter(|path| !is_envelope_file(path))
        .map(|path| {
            (
                path.to_owned(),
                fs::read(root.join(path)).expect("verified fixture artifact reads"),
            )
        })
        .collect();
    (files, verified.revision().map(ToOwned::to_owned))
}

fn disjoint_profiles() -> Value {
    json!({
        "statutory-caseworker-v1": {
            "kind": "statutory",
            "requesterTags": ["fixture-agency"],
            "grants": [
                {
                    "requirement": REQUIREMENT,
                    "purpose": "fixture-registration",
                    "audienceFrom": "authenticated-requester",
                    "responseFormats": ["signed-jws"],
                    "subjects": [
                        {
                            "role": "subject",
                            "selectorProfile": "licence-register-v1",
                            "valueOrigin": "request"
                        },
                        {
                            "role": "jurisdiction",
                            "selectorProfile": "other-region-v1",
                            "valueOrigin": "request"
                        }
                    ]
                },
                {
                    "requirement": REQUIREMENT,
                    "purpose": "fixture-registration",
                    "audienceFrom": "authenticated-requester",
                    "responseFormats": ["signed-jws"],
                    "subjects": [
                        {
                            "role": "subject",
                            "selectorProfile": "other-licence-v1",
                            "valueOrigin": "request"
                        },
                        {
                            "role": "jurisdiction",
                            "selectorProfile": "region-v1",
                            "valueOrigin": "request"
                        }
                    ]
                }
            ]
        }
    })
}

fn complete_narrowed_profile() -> Value {
    json!({
        "statutory-caseworker-v1": {
            "kind": "statutory",
            "requesterTags": ["fixture-agency"],
            "grants": [{
                "requirement": REQUIREMENT,
                "purpose": "fixture-registration",
                "audienceFrom": "authenticated-requester",
                "responseFormats": ["signed-jws"],
                "subjects": [
                    {
                        "role": "subject",
                        "selectorProfile": "licence-register-v1",
                        "valueOrigin": "request"
                    },
                    {
                        "role": "jurisdiction",
                        "selectorProfile": "region-v1",
                        "valueOrigin": "request"
                    }
                ]
            }]
        }
    })
}

fn profiles_with_complete_path() -> Value {
    let mut profiles = disjoint_profiles();
    let complete = complete_narrowed_profile()["statutory-caseworker-v1"]["grants"][0].clone();
    profiles["statutory-caseworker-v1"]["grants"]
        .as_array_mut()
        .expect("the authority profile has grants")
        .push(complete);
    profiles
}

fn configure_two_input_authority_paths(config: &mut Value, normalized: bool, profiles: &Value) {
    config["sources"]["source-c"]["inputs"]["registry_region"]["selector"] = json!({
        "role": "jurisdiction",
        "profile": "region-v1",
        "field": "region"
    });
    config["selectorProfiles"]["other-licence-v1"] = json!({
        "maximumAggregateBytes": 96,
        "fields": {
            "licence_reference": {
                "type": "string", "minimumBytes": 1, "maximumBytes": 96
            }
        }
    });
    for profile in ["region-v1", "other-region-v1"] {
        config["selectorProfiles"][profile] = json!({
            "maximumAggregateBytes": 16,
            "fields": {
                "region": {"type": "string", "minimumBytes": 1, "maximumBytes": 16}
            }
        });
    }
    config["requirements"][0]["subjectRoles"] = json!([
        {
            "role": "subject",
            "cardinality": "one",
            "selectorProfiles": ["licence-register-v1", "other-licence-v1"]
        },
        {
            "role": "jurisdiction",
            "cardinality": "one",
            "selectorProfiles": ["region-v1", "other-region-v1"]
        }
    ]);

    if normalized {
        config["project"] = json!("source-authority-paths");
        config["authorityProfiles"] = json!({});
        config["requirements"][0]["grantCeiling"] = json!({
            "authorities": ["statutory"],
            "actorKinds": ["service"],
            "valueOrigins": ["request"],
            "audiences": ["urn:example:audience:source-authority-paths"]
        });
        config["requirements"][0]["representations"] = json!(["signed-jws"]);
    } else {
        config["authorityProfiles"] = profiles.clone();
    }
}

fn staged_two_input_bundle(normalized: bool, profiles: &Value) -> Result<Bundle, BundleError> {
    staged_two_input_bundle_with_schema(normalized, profiles, None)
}

fn staged_two_input_bundle_with_schema(
    normalized: bool,
    profiles: &Value,
    input_schema: Option<Value>,
) -> Result<Bundle, BundleError> {
    let (mut files, revision) = package_files("acceptance/professional-licence");
    let mut config = registry_platform_yaml::Reader::new("evidence.yaml")
        .read(
            files
                .get("evidence.yaml")
                .expect("fixture package contains evidence.yaml"),
            &registry_platform_yaml::Expect::one(
                &registry_evidence::config::EVIDENCE_BUNDLE_FORMAT,
            ),
        )
        .expect("fixture Evidence configuration follows the owning format")
        .to_json_value();
    configure_two_input_authority_paths(&mut config, normalized, profiles);
    if let Some(input_schema) = input_schema {
        let old_prefix = config["sources"]["source-c"]["pack"]["artifactPrefix"]
            .as_str()
            .expect("the fixture source has a pack prefix")
            .to_owned();
        let input_path = format!("{old_prefix}/schemas/inputs.json");
        let input_bytes = serde_json::to_vec_pretty(&input_schema)
            .expect("the staged route input schema encodes");
        let pack_path = format!("{old_prefix}/pack.yaml");
        let mut pack: Value = serde_json::from_slice(
            files
                .get(&pack_path)
                .expect("the fixture source pack is captured"),
        )
        .expect("the fixture source pack decodes");
        pack["sourceRoutes"][0]["evidence"]["inputsSchema"]["digest"] =
            json!(sha256_uri(&input_bytes));
        let pack_bytes = serde_json::to_vec_pretty(&pack).expect("the staged source pack encodes");
        let pack_digest = sha256_uri(&pack_bytes);
        let new_prefix = format!(
            "adapter-packs/fixture-licence/{}",
            pack_digest
                .strip_prefix("sha256:")
                .expect("a SHA-256 URI has its prefix")
        );
        let pack_paths = files
            .keys()
            .filter(|path| path.starts_with(&format!("{old_prefix}/")))
            .cloned()
            .collect::<Vec<_>>();
        for old_path in pack_paths {
            let suffix = old_path
                .strip_prefix(&old_prefix)
                .expect("the selected path belongs to the old pack prefix");
            let bytes = if old_path == pack_path {
                pack_bytes.clone()
            } else if old_path == input_path {
                input_bytes.clone()
            } else {
                files
                    .get(&old_path)
                    .expect("the captured pack artifact remains available")
                    .clone()
            };
            files.remove(&old_path);
            files.insert(format!("{new_prefix}{suffix}"), bytes);
        }
        config["sources"]["source-c"]["pack"]["digest"] = json!(pack_digest);
        config["sources"]["source-c"]["pack"]["artifactPrefix"] = json!(new_prefix);
    }
    files.insert(
        "evidence.yaml".to_owned(),
        serde_norway::to_string(&config)
            .expect("staged Evidence configuration encodes")
            .into_bytes(),
    );

    let temporary = tempfile::tempdir().expect("isolated package staging");
    let root = temporary.path().join("bundle");
    let verified = write_package(
        &root,
        &files,
        revision.as_deref(),
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("isolated package writes with an exact checksum closure");
    Bundle::load_as_found(&root, &verified)
}

fn authority_document(profiles: Value) -> AuthorityDocument {
    serde_json::from_value(json!({
        "target": "local",
        "project": "source-authority-paths",
        "accessProfiles": profiles
    }))
    .expect("compiled target authority shape")
}

fn assert_value_free_authority_path_refusal(error: &BundleError) {
    let message = error.to_string();
    assert!(message.contains(AUTHORITY_PATH_REFUSAL), "{message}");
    for prohibited in [
        "licence_reference",
        "registry_region",
        "other-licence-v1",
        "other-region-v1",
    ] {
        assert!(
            !message.contains(prohibited),
            "the diagnostic retained configured material: {message}"
        );
    }
}

#[derive(Clone, Default)]
struct RecordingSink(Arc<Mutex<Vec<u8>>>);

impl Write for RecordingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the audit capture locks")
            .extend(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl RecordingSink {
    fn audit(&self) -> EvidenceAuditLog {
        EvidenceAuditLog::with_writer(
            AuditWriter::from_line_sink(Box::new(self.clone())),
            b"source-authority-audit-key-32-bytes".to_vec(),
            1,
        )
        .expect("the activation audit key derives")
    }

    fn entries(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().expect("the audit capture locks").clone())
            .expect("audit entries are UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("an audit entry is JSON"))
            .collect()
    }
}

#[test]
fn active_grants_cannot_union_disjoint_required_route_inputs() {
    let error = staged_two_input_bundle(false, &disjoint_profiles())
        .expect_err("each complete authority path supplies only one of two required inputs");
    assert_value_free_authority_path_refusal(&error);
}

#[test]
fn nested_one_of_retains_exact_dependent_presence_branches() {
    let error = staged_two_input_bundle_with_schema(
        false,
        &profiles_with_complete_path(),
        Some(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "licence_reference": {"type": "string"},
                "registry_region": {"type": "string"}
            },
            "allOf": [{
                "oneOf": [
                    {
                        "dependentRequired": {
                            "licence_reference": ["registry_region"]
                        }
                    },
                    {"required": ["licence_reference"]}
                ]
            }]
        })),
    )
    .expect_err("both dependent presence branches match the complete authority path");
    assert_value_free_authority_path_refusal(&error);
}

#[test]
fn pure_normalized_package_needs_no_active_grants_but_target_narrowing_is_revalidated() {
    let bundle = staged_two_input_bundle(true, &json!({}))
        .expect("pure package compilation has no activated target grants");

    bundle
        .validate_target_authority("local", &authority_document(complete_narrowed_profile()))
        .expect("one narrowed complete grant supplies both required route inputs");

    let error = bundle
        .validate_target_authority("local", &authority_document(disjoint_profiles()))
        .expect_err("target grants cannot jointly supply one source route's required inputs");
    assert_value_free_authority_path_refusal(&error);
}

#[test]
fn maintained_presence_alternatives_keep_unselected_inputs_optional() {
    let root = fixture_root("conformance/selectors");
    let verified = verify_package(&root, &evidence_package_limits(), "evidencectl package")
        .expect("selector conformance package verifies");
    Bundle::load_as_found(&root, &verified).expect(
        "each complete grant satisfies one reviewed oneOf input alternative without the other",
    );
}

#[tokio::test]
async fn public_bundle_activation_refuses_route_incomplete_authority_after_request_audit() {
    let bundle = staged_two_input_bundle(true, &json!({}))
        .expect("pure normalized package compilation needs no active target grants");
    let temporary = tempfile::tempdir().expect("isolated authority storage");
    let authority_root = temporary.path().join("authority");
    let sink = RecordingSink::default();
    let result = bundle
        .activate_target_authority(
            &authority_root,
            "local",
            &authority_document(disjoint_profiles()),
            Some("private-operator-reference-canary"),
            &sink.audit(),
        )
        .await;

    assert!(matches!(
        result,
        Err(ActivationError::Authority(
            AuthorityError::SourceRouteInputs
        ))
    ));
    assert!(!authority_root.exists());
    let entries = sink.entries();
    assert_eq!(entries.len(), 2, "the refusal has one durable audit pair");
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    assert_eq!(entries[1]["record"]["outcome"], "refused");
    assert!(entries[1]["record"]["activationSequence"].is_null());
    let diagnostic = serde_json::to_string(&entries).expect("audit entries serialize");
    for protected in [
        "licence_reference",
        "registry_region",
        "other-licence-v1",
        "other-region-v1",
        "private-operator-reference-canary",
    ] {
        assert!(!diagnostic.contains(protected), "{diagnostic}");
    }
}
