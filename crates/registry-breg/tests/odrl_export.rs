// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{
    parse_module_json, parse_module_yaml, parse_project_json, parse_project_yaml,
};
use registry_breg::odrl_export::{export_odrl, PROFILE_IRI, VOCAB};
use registry_breg::{CompiledRegistry, GeneratedArtifact};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MINIMAL: &[u8] = include_bytes!("../../../products/breg/examples/minimal/registry.yaml");
const MEMBERSHIP: &[u8] =
    include_bytes!("../../../products/breg/fixtures/organization-membership-access/registry.yaml");
const CONSENT: &[u8] =
    include_bytes!("../../../products/breg/fixtures/consent-person-registry/registry.yaml");
const CONSENT_PERSON: &[u8] = include_bytes!(
    "../../../products/breg/fixtures/consent-person-registry/modules/consent-person/module.yaml"
);
const CONSENT_CORE: &[u8] = include_bytes!(
    "../../../products/breg/fixtures/consent-person-registry/modules/consent-person-registry-core/module.yaml"
);

const ODRL_EQ: &str = "http://www.w3.org/ns/odrl/2/eq";
const ODRL_HAS_PART: &str = "http://www.w3.org/ns/odrl/2/hasPart";
const ODRL_IS_PART_OF: &str = "http://www.w3.org/ns/odrl/2/isPartOf";
const ODRL_READ: &str = "http://www.w3.org/ns/odrl/2/read";

fn compile_source(source: &Value) -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

fn minimal_source() -> Value {
    registry_platform_yaml::Reader::new("minimal fixture")
        .scan(MINIMAL)
        .unwrap()
        .unwrap()
        .to_json_value()
}

fn supported_source() -> Value {
    let mut source = minimal_source();
    let profile = &mut source["accessProfiles"][0];
    profile["actorKind"] = json!("human");
    profile["requesterClients"] = json!(["registry-console", "registry-review"]);
    profile["requiredScopes"] = json!(["registry:directory:read", "registry:records:read"]);
    profile["requiredPurposes"] = json!(["directory-administration", "service-delivery"]);
    profile["permissions"]["records"][0]["rowBoundaries"] = json!("unrestricted");
    source
}

fn actor_profiles_source() -> Value {
    let mut source = supported_source();
    let mut base = source["accessProfiles"][0].clone();
    let mut read_grant = base["permissions"]["records"][0].clone();
    read_grant["operations"] = json!(["get", "list"]);
    read_grant.as_object_mut().unwrap().remove("writableFields");
    base["permissions"] = json!({"records": [read_grant]});
    let profiles = [
        ("unspecified-reader", None),
        ("human-reader", Some("human")),
        ("service-reader", Some("service")),
        ("agent-reader", Some("agent")),
    ]
    .into_iter()
    .map(|(id, actor_kind)| {
        let mut profile = base.clone();
        profile["id"] = json!(id);
        profile["default"] = json!(id == "unspecified-reader");
        if let Some(actor_kind) = actor_kind {
            profile["actorKind"] = json!(actor_kind);
        } else {
            profile.as_object_mut().unwrap().remove("actorKind");
            profile.as_object_mut().unwrap().remove("requesterClients");
        }
        profile
    })
    .collect();
    source["accessProfiles"] = Value::Array(profiles);
    source.as_object_mut().unwrap().remove("actions");
    source
}

fn compile_with_modules(project: &[u8], module_sources: &[&[u8]]) -> CompiledRegistry {
    let mut project = parse_project_yaml(project).expect("fixture project parses");
    let modules = module_sources
        .iter()
        .map(|source| parse_module_yaml(source).expect("fixture module parses"))
        .collect::<Vec<_>>();
    for lock in &mut project.modules {
        let module = modules
            .iter()
            .find(|module| module.id == lock.id)
            .expect("every locked module is supplied");
        lock.digest = Some(module_digest(module));
    }
    compile_project(&project, &modules, CompileProfile::Authoring).expect("fixture compiles")
}

fn artifact<'a>(artifacts: &'a [GeneratedArtifact], path: &str) -> &'a GeneratedArtifact {
    artifacts
        .iter()
        .find(|artifact| artifact.path == path)
        .unwrap_or_else(|| panic!("missing {path}"))
}

fn document(export: &registry_breg::odrl_export::OdrlExport, path: &str) -> Value {
    serde_json::from_slice(&artifact(&export.artifacts, path).bytes).expect("artifact is JSON")
}

fn constraint<'a>(permission: &'a Value, term: &str) -> &'a Value {
    permission["odrl:constraint"]
        .as_array()
        .expect("permission constraints")
        .iter()
        .find(|constraint| constraint["odrl:leftOperand"]["@id"] == term)
        .unwrap_or_else(|| panic!("missing constraint {term}"))
}

fn grant<'a>(coverage: &'a Value, operation: &str) -> &'a Value {
    coverage["grants"]
        .as_array()
        .expect("coverage grants")
        .iter()
        .find(|grant| {
            grant["recordType"] == "contact"
                && grant["accessProfile"] == "directory-editor"
                && grant["operation"] == operation
        })
        .unwrap_or_else(|| panic!("missing contact/directory-editor/{operation}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn registered_coverage_example_matches_minimal_project() {
    let registry = compile_source(&minimal_source());
    let export = export_odrl(&registry, None).unwrap();
    assert_eq!(
        artifact(&export.artifacts, "generated/odrl/coverage.json").bytes,
        include_bytes!("../../../products/breg/examples/formats/odrl-coverage.json")
    );
}

#[test]
fn registered_policy_example_matches_authoring_display_fixture() {
    let project = parse_project_yaml(include_bytes!(
        "../../../products/breg/fixtures/authoring-display/registry.yaml"
    ))
    .unwrap();
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let export = export_odrl(&registry, None).unwrap();
    assert_eq!(
        artifact(&export.artifacts, "generated/odrl/policies.jsonld").bytes,
        include_bytes!("../../../products/breg/examples/formats/odrl-policies.jsonld")
    );
    assert!(export.coverage["totals"]["exported"].as_u64().unwrap() > 0);
}

#[test]
fn supported_reads_preserve_profile_conditions_and_projection_fields() {
    let registry = compile_source(&supported_source());
    let source_artifacts = serde_json::to_value(registry.artifacts()).unwrap();

    let first = export_odrl(&registry, Some("directory-editor")).expect("export succeeds");
    let second = export_odrl(&registry, Some("directory-editor")).expect("export repeats");

    assert_eq!(
        first.artifacts, second.artifacts,
        "export bytes and digests are stable"
    );
    assert_eq!(
        first
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect::<Vec<_>>(),
        [
            "generated/odrl/coverage.json",
            "generated/odrl/policies.jsonld",
            "generated/odrl/profile.jsonld",
        ]
    );
    for generated in &first.artifacts {
        assert_eq!(
            generated.sha256,
            format!("sha256:{}", sha256_hex(&generated.bytes))
        );
    }
    assert_eq!(
        artifact(&first.artifacts, "generated/odrl/profile.jsonld").bytes,
        include_bytes!("../../../products/breg/contracts/odrl-profile.jsonld")
    );
    assert_eq!(
        serde_json::to_value(registry.artifacts()).unwrap(),
        source_artifacts
    );
    assert!(registry
        .artifacts()
        .entries()
        .keys()
        .all(|path| !path.starts_with("generated/odrl/")));

    assert_eq!(
        first.coverage["totals"],
        json!({"considered":4,"exported":2,"omitted":2})
    );
    assert_eq!(grant(&first.coverage, "get")["status"], "exported");
    assert_eq!(grant(&first.coverage, "list")["status"], "exported");
    assert_eq!(
        grant(&first.coverage, "create")["reasons"],
        json!(["unsupported-operation"])
    );
    assert_eq!(
        grant(&first.coverage, "patch")["reasons"],
        json!(["unsupported-operation"])
    );
    assert!(first.coverage["excludedSurfaces"]
        .as_array()
        .is_some_and(|surfaces| !surfaces.is_empty()));

    let policies = document(&first, "generated/odrl/policies.jsonld");
    assert_eq!(policies[format!("{VOCAB}partial")], true);
    assert!(policies["http://purl.org/dc/terms/description"].is_string());
    let policy = &policies["@graph"][0];
    assert_eq!(policy[format!("{VOCAB}partial")], true);
    assert_eq!(policy["odrl:profile"], json!([{"@id":PROFILE_IRI}]));
    let permissions = policy["odrl:permission"]
        .as_array()
        .expect("two read permissions");
    assert_eq!(permissions.len(), 2);
    for permission in permissions {
        assert_eq!(permission["odrl:action"]["@id"], ODRL_READ);
        assert_eq!(
            permission["odrl:target"][format!("{VOCAB}recordType")],
            "contact"
        );
        assert_eq!(
            permission["odrl:target"][format!("{VOCAB}readableFields")],
            json!({"@list":[{"@value":"email"},{"@value":"jurisdiction"},{"@value":"name"}]})
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}authenticated"))["odrl:rightOperand"],
            json!({"@value":true})
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}authenticated"))["odrl:operator"]["@id"],
            ODRL_EQ
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}verifiedNonemptyClaims"))["odrl:rightOperand"],
            json!({"@list":[{"@value":"registry_principal"}]})
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}verifiedNonemptyClaims"))["odrl:operator"]
                ["@id"],
            ODRL_HAS_PART
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}tokenScopes"))["odrl:rightOperand"],
            json!({"@list":[{"@value":"registry:directory:read"},{"@value":"registry:records:read"}]})
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}tokenPurpose"))["odrl:operator"]["@id"],
            ODRL_IS_PART_OF
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}tokenPurpose"))["odrl:rightOperand"],
            json!({"@list":[{"@value":"directory-administration"},{"@value":"service-delivery"}]})
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}requesterClient"))["odrl:rightOperand"],
            json!({"@list":[{"@value":"registry-console"},{"@value":"registry-review"}]})
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}actorKind"))["odrl:rightOperand"],
            json!({"@value":"human"})
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}accessProfile"))["odrl:rightOperand"],
            json!({"@value":"directory-editor"})
        );
        let operation =
            &constraint(permission, &format!("{VOCAB}operation"))["odrl:rightOperand"]["@value"];
        assert!(operation == "get" || operation == "list");
    }
}

#[test]
fn every_read_permission_preserves_delegation_and_task_grant_absence() {
    let registry = compile_source(&actor_profiles_source());
    let export = export_odrl(&registry, None).unwrap();
    let policies = document(&export, "generated/odrl/policies.jsonld");
    let permissions = policies["@graph"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|policy| policy["odrl:permission"].as_array().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(permissions.len(), 8);
    for permission in permissions {
        let profile = constraint(permission, &format!("{VOCAB}accessProfile"))["odrl:rightOperand"]
            ["@value"]
            .as_str()
            .unwrap();
        assert_eq!(
            constraint(permission, &format!("{VOCAB}delegatedActor"))["odrl:rightOperand"],
            json!({"@value":profile == "agent-reader"})
        );
        assert_eq!(
            constraint(permission, &format!("{VOCAB}taskGrantPresent"))["odrl:rightOperand"],
            json!({"@value":false})
        );
    }
}

#[test]
fn row_membership_and_consent_restrictions_omit_the_complete_read_grant() {
    let row = compile_source(&minimal_source());
    let row_export = export_odrl(&row, Some("directory-editor")).unwrap();
    for operation in ["get", "list"] {
        assert_eq!(grant(&row_export.coverage, operation)["status"], "omitted");
        assert!(grant(&row_export.coverage, operation)["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("row-boundaries")));
    }
    assert_eq!(
        document(&row_export, "generated/odrl/policies.jsonld")["@graph"],
        json!([])
    );

    let membership = compile_project(
        &parse_project_yaml(MEMBERSHIP).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap();
    let membership_export = export_odrl(&membership, Some("member")).unwrap();
    let membership_reads = membership_export.coverage["grants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|grant| grant["operation"] == "get" || grant["operation"] == "list")
        .collect::<Vec<_>>();
    assert_eq!(membership_reads.len(), 2);
    assert!(membership_reads.iter().all(|grant| {
        grant["status"] == "omitted"
            && grant["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("membership-boundaries"))
    }));

    let consent = compile_with_modules(CONSENT, &[CONSENT_PERSON, CONSENT_CORE]);
    let consent_export = export_odrl(&consent, Some("food-targeting")).unwrap();
    assert!(consent_export.coverage["grants"]
        .as_array()
        .unwrap()
        .iter()
        .all(|grant| {
            grant["status"] == "omitted"
                && grant["reasons"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("consent"))
        }));
}

#[test]
fn task_grant_mutant_is_not_broadened_and_profile_selection_is_exact() {
    let mut source = supported_source();
    let mut other = source["accessProfiles"][0].clone();
    other["id"] = json!("other-reader");
    other["default"] = json!(false);
    source["accessProfiles"].as_array_mut().unwrap().push(other);
    let registry = compile_source(&source);

    let all = export_odrl(&registry, None).unwrap();
    assert!(all.coverage["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|grant| grant["accessProfile"] == "directory-editor"));
    assert!(all.coverage["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|grant| grant["accessProfile"] == "other-reader"));
    assert_eq!(
        document(&all, "generated/odrl/policies.jsonld")["@graph"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let selected = export_odrl(&registry, Some("directory-editor")).unwrap();
    assert!(selected.coverage["grants"]
        .as_array()
        .unwrap()
        .iter()
        .all(|grant| grant["accessProfile"] == "directory-editor"));
    assert!(export_odrl(&registry, Some("directory")).is_err());
    let unknown = export_odrl(&registry, Some("not-a-profile")).unwrap_err();
    assert_eq!(unknown.code, "breg.odrl.unknown-access-profile");

    let mut wire = serde_json::to_value(&registry).unwrap();
    wire["entities"]["contact"]["accessProfiles"]["directory-editor"]["taskGrant"] = json!({
        "sourceIssuer":"https://tasks.example.test",
        "permissions":[{"collection":"record:contact","operations":["get"]}]
    });
    let mutant: CompiledRegistry = serde_json::from_value(wire).unwrap();
    let export = export_odrl(&mutant, Some("directory-editor")).unwrap();
    for operation in ["get", "list"] {
        assert_eq!(grant(&export.coverage, operation)["status"], "omitted");
        assert!(grant(&export.coverage, operation)["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("task-grant")));
    }
    assert_eq!(
        document(&export, "generated/odrl/policies.jsonld")["@graph"],
        json!([])
    );
}

#[test]
fn exact_selection_of_known_action_only_profile_is_empty_and_valid() {
    let mut source = minimal_source();
    source["accessProfiles"][0]["id"] = json!("action-only");
    source["accessProfiles"][0]["permissions"]
        .as_object_mut()
        .unwrap()
        .remove("records");
    source["accessProfiles"][0]["permissions"]
        .as_object_mut()
        .unwrap()
        .remove("proposals");
    let registry = compile_source(&source);
    let export = export_odrl(&registry, Some("action-only")).unwrap();

    assert_eq!(
        export.coverage["totals"],
        json!({"considered":0,"exported":0,"omitted":0})
    );
    assert_eq!(export.coverage["selectedAccessProfile"], "action-only");
    assert_eq!(
        document(&export, "generated/odrl/policies.jsonld")["@graph"],
        json!([])
    );
    let surfaces = export.coverage["excludedSurfaces"].as_array().unwrap();
    for surface in [
        "actions",
        "proposals",
        "statistics",
        "lookups",
        "read-paths",
        "revisions",
        "snapshots",
        "mutations",
    ] {
        assert!(
            surfaces.contains(&json!(surface)),
            "missing {surface}: {surfaces:?}"
        );
    }
}

#[test]
fn exact_selection_accepts_profiles_from_modules_and_extensions() {
    let project = parse_project_json(
        &serde_json::to_vec(&json!({
            "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
            "kind": "BRegProject",
            "project": {"id":"module-profile", "version":"1", "defaultLanguage":"en",
                        "canonicalBaseIri":"https://authoring.example.test"},
            "datasets": [{"id":"records"}],
            "recordTypes": [{
                "id":"case-file", "primaryDataset":"records", "route":"case-files",
                "mutationMode":"mutable",
                "fields":[{"id":"code", "type":"string", "maximumLength":32,
                           "classification":"internal"}]
            }],
            "modules": [{"id":"core", "version":"1"}]
        }))
        .unwrap(),
    )
    .unwrap();
    let profile = |id| {
        json!({
            "id":id, "principalClaim":"sub", "operations":["get"],
            "readableFields":["code"], "requiredScopes":"unrestricted",
            "rowBoundaries":"unrestricted"
        })
    };
    let module = parse_module_json(
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
            "kind":"BRegModule", "id":"core", "version":"1",
            "recordTypes":[{
                "id":"module-record", "primaryDataset":"records", "route":"module-records",
                "mutationMode":"mutable",
                "fields":[{"id":"code", "type":"string", "maximumLength":32,
                           "classification":"internal"}],
                "accessProfiles":[profile("module-reader")]
            }],
            "extendRecordTypes":[{
                "recordType":"case-file", "accessProfiles":[profile("extension-reader")]
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let registry = compile_project(&project, &[module], CompileProfile::Authoring).unwrap();
    assert!(registry.access_profile_displays().is_empty());
    for (id, record_type) in [
        ("module-reader", "module-record"),
        ("extension-reader", "case-file"),
    ] {
        let export = export_odrl(&registry, Some(id)).expect("compiled profile is selectable");
        assert_eq!(export.coverage["selectedAccessProfile"], id);
        assert_eq!(
            export.coverage["totals"],
            json!({"considered":1,"exported":1,"omitted":0})
        );
        assert_eq!(export.coverage["grants"][0]["recordType"], record_type);
        assert_eq!(export.coverage["grants"][0]["accessProfile"], id);
    }
    assert!(export_odrl(&registry, Some("module")).is_err());
}

#[test]
fn profile_declares_every_emitted_extension_and_adopts_read() {
    fn emitted_terms(value: &Value, terms: &mut BTreeSet<String>) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    if key.starts_with(VOCAB) {
                        terms.insert(key.clone());
                    }
                    emitted_terms(value, terms);
                }
            }
            Value::Array(values) => {
                for value in values {
                    emitted_terms(value, terms);
                }
            }
            Value::String(value) if value.starts_with(VOCAB) || value == ODRL_READ => {
                terms.insert(value.clone());
            }
            _ => {}
        }
    }

    let registry = compile_source(&supported_source());
    let export = export_odrl(&registry, None).unwrap();
    let policies = document(&export, "generated/odrl/policies.jsonld");
    let profile = document(&export, "generated/odrl/profile.jsonld");
    let graph = profile["@graph"].as_array().unwrap();
    let collection = graph
        .iter()
        .find(|node| node["@type"] == "skos:Collection")
        .expect("profile vocabulary is a machine-readable collection");
    let expand = |value: &Value| {
        let id = value.as_str().unwrap();
        id.strip_prefix("breg:").map_or_else(
            || id.replace("odrl:", "http://www.w3.org/ns/odrl/2/"),
            |term| format!("{VOCAB}{term}"),
        )
    };
    let members = collection["skos:member"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| expand(&member["@id"]))
        .collect::<BTreeSet<_>>();
    let mut emitted = BTreeSet::new();
    emitted_terms(&policies, &mut emitted);
    assert_eq!(
        emitted.len(),
        14,
        "thirteen BReg terms and odrl:read are exercised"
    );
    assert_eq!(members, emitted);
    for term in graph
        .iter()
        .filter(|node| node["@type"] != "skos:Collection")
    {
        assert_eq!(term["rdfs:isDefinedBy"]["@id"], PROFILE_IRI);
        assert!(members.contains(&expand(&term["@id"])));
    }
    assert_eq!(
        graph.len(),
        14,
        "one collection and thirteen term definitions"
    );
}
