// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::os::unix::fs::PermissionsExt;

const DEV_PLAN: &[u8] = b"# Retain local authority notes\npeople: {}\n";

fn yaml(bytes: &[u8]) -> Value {
    Reader::new("test authoring")
        .scan(bytes)
        .unwrap()
        .unwrap()
        .to_json_value()
}

fn model() -> Value {
    let mut model = yaml(include_bytes!(
        "../../../../products/breg/evidence/registry/registry.yaml"
    ));
    model["recordTypes"]["record"]
        .as_object_mut()
        .unwrap()
        .remove("selectorProfiles");
    model["accessProfiles"]
        .as_object_mut()
        .unwrap()
        .retain(|id, _| id == "operator");
    model
}

fn bytes(model: &Value) -> Vec<u8> {
    serde_norway::to_string(model).unwrap().into_bytes()
}

fn args(root: &Path) -> PrepareSourceArgs {
    PrepareSourceArgs {
        project: root.to_path_buf(),
        run_id: "unused".into(),
        posture: None,
        entity: Some("record".into()),
        selector_field: Some("code".into()),
        readable_fields: vec!["label".into()],
        all_records: true,
        row_field: None,
        row_claim: None,
        row_value_file: None,
        client: "source-reader".into(),
        access_profile: "source-reader".into(),
        selector_profile: "by-code".into(),
        source_id: "registry".into(),
        connection: "registry".into(),
        apply: false,
    }
}

fn registry_files(model: &Value) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([("registry.yaml".into(), bytes(model))])
}

fn compile_files(files: &BTreeMap<String, Vec<u8>>) -> registry_breg::CompiledRegistry {
    let authored = tempfile::tempdir().unwrap();
    for (name, contents) in files {
        let path = authored.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    crate::compile(
        authored.path(),
        crate::ProfileArg::Production,
        "prepare-source",
    )
    .unwrap_or_else(|failure| panic!("{}", serde_json::to_string(&failure).unwrap()))
}

fn prepare(args: &PrepareSourceArgs, files: &BTreeMap<String, Vec<u8>>) -> Result<Pending> {
    let registry = compile_files(files);
    let docs = documents(files)?;
    let report = json!({"entities": inventory(&docs, &registry)?, "status": "inspect"});
    prepare_successor(
        args,
        files,
        docs,
        SuccessorBaseline {
            registry: &registry,
            package_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            principal_claim: "registry_principal",
            scratch: &args.project,
        },
        DEV_PLAN,
        yaml(DEV_PLAN),
        report,
    )
}

fn row_scope(args: &mut PrepareSourceArgs, field: &str, claim: &str, value: &Value) {
    fs::set_permissions(&args.project, fs::Permissions::from_mode(0o700)).unwrap();
    let value_file = args.project.join("row-value.json");
    private::replace(&value_file, &serde_json::to_vec(value).unwrap()).unwrap();
    args.all_records = false;
    args.row_field = Some(field.into());
    args.row_claim = Some(claim.into());
    args.row_value_file = Some(value_file);
}

fn exported_facts(
    args: &PrepareSourceArgs,
    files: &BTreeMap<String, Vec<u8>>,
    pending: &Pending,
) -> Value {
    let mut successor_files = files.clone();
    successor_files.insert("registry.yaml".into(), pending.registry.after.clone());
    let compiled = compile_files(&successor_files);
    let export = registry_breg::evidence_source::export_evidence_source(
        &compiled,
        &evidence_source_options(args, "record".into()),
    )
    .unwrap();
    let facts = export
        .artifacts
        .iter()
        .find(|artifact| artifact.path == "adapter-packs/registry/schemas/facts.json")
        .unwrap();
    serde_json::from_slice(&facts.bytes).unwrap()
}

#[test]
fn a_pending_edit_only_accepts_the_reviewed_before_or_after() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("registry.yaml");
    let before = b"project: original\n";
    let after = b"project: prepared\n";
    let edit = Edit::new(before, after.to_vec());

    fs::write(&path, before).unwrap();
    assert!(edit.pending(&path).unwrap());
    replace_authoring(&path, after).unwrap();
    assert!(!edit.pending(&path).unwrap());
    fs::write(&path, b"project: concurrent-edit\n").unwrap();
    assert!(edit.pending(&path).is_err());
}

#[test]
fn explicit_row_binding_is_private_and_does_not_expand_selected_facts() {
    let scratch = tempfile::tempdir().unwrap();
    let mut selected = args(scratch.path());
    row_scope(&mut selected, "status", "source_status", &json!("active"));
    let files = registry_files(&model());
    let pending = prepare(&selected, &files).unwrap();
    assert_eq!(
        pending.report["rowScope"],
        json!({"kind":"claim","field":"status","claim":"source_status"})
    );
    assert!(!pending.report.to_string().contains("active"));
    let plan = yaml(&pending.plan.after);
    assert_eq!(
        plan["people"]["source-reader"]["grants"]["breg"]["claims"]["source_status"],
        "active"
    );
    let registry = yaml(&pending.registry.after);
    let grant = &registry["accessProfiles"]["source-reader"]["permissions"]["records"][0];
    assert_eq!(grant["operations"], json!(["lookup"]));
    assert_eq!(grant["readableFields"], json!(["label", "code"]));
    assert_eq!(
        grant["rowBoundaries"],
        json!([{"claim":"source_status","field":"status","operator":"equals"}])
    );
    let facts = exported_facts(&selected, &files, &pending);
    assert_eq!(
        facts["properties"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["label"]
    );
}

#[test]
fn nonunique_selector_and_implicit_row_authority_are_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let files = registry_files(&model());
    let mut selected = args(scratch.path());
    selected.selector_field = Some("label".into());
    assert!(prepare(&selected, &files)
        .err()
        .unwrap()
        .to_string()
        .contains("unique"));
    let mut selected = args(scratch.path());
    selected.all_records = false;
    assert!(prepare(&selected, &files)
        .err()
        .unwrap()
        .to_string()
        .contains("--all-records"));
}

#[test]
fn unexportable_selection_is_refused_before_preparing_authority() {
    let scratch = tempfile::tempdir().unwrap();
    let mut model = model();
    model["recordTypes"]["record"]["fields"][0]["minimumLength"] = json!(0);
    let files = registry_files(&model);
    let compiled = compile_files(&files);
    let entities = inventory(&documents(&files).unwrap(), &compiled).unwrap();
    assert!(!entities[0]["selectorFields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|field| field["id"] == "code"));
    let mut selected = args(scratch.path());
    selected.apply = true;
    let refusal = prepare(&selected, &files).err().unwrap().to_string();
    assert!(
        refusal.contains("selector field accepts an empty value"),
        "{refusal}"
    );
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn invalid_mint_or_field_row_claims_leave_authoring_unchanged() {
    let scratch = tempfile::tempdir().unwrap();
    let files = registry_files(&model());
    let path = scratch.path().join("registry.yaml");
    fs::write(&path, &files["registry.yaml"]).unwrap();
    let cases = [
        "iss",
        "aud",
        "exp",
        "iat",
        "nbf",
        "sub",
        "client_id",
        "azp",
        "jti",
        "cnf",
        "scope",
        "registry_principal",
        "registry_purpose",
        "bad claim",
    ]
    .into_iter()
    .map(|claim| (claim, "label", json!("allowed")))
    .chain([
        ("source_label", "label", json!(true)),
        ("source_label", "label", json!("x".repeat(513))),
        ("source_label", "label", json!("x".repeat(101))),
        ("source_status", "status", json!("unlisted")),
    ]);
    for (claim, field, value) in cases {
        let mut selected = args(scratch.path());
        selected.apply = true;
        row_scope(&mut selected, field, claim, &value);
        assert!(prepare(&selected, &files).is_err(), "{claim}");
        assert_eq!(fs::read(&path).unwrap(), files["registry.yaml"]);
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 2);
    }
}

#[test]
fn conflicting_existing_claim_shapes_are_refused_before_preparing_authority() {
    for (field, operator) in [("code", "equals"), ("label", "in")] {
        let scratch = tempfile::tempdir().unwrap();
        let mut model = model();
        model["accessProfiles"]["operator"]["permissions"]["records"][0]["rowBoundaries"] =
            json!([{"field":field,"claim":"existing_row","operator":operator}]);
        let files = registry_files(&model);
        let mut selected = args(scratch.path());
        selected.apply = true;
        row_scope(&mut selected, "label", "existing_row", &json!("allowed"));
        assert!(prepare(&selected, &files)
            .err()
            .unwrap()
            .to_string()
            .contains("different value shapes"));
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 1);
    }
}

#[test]
fn required_unique_references_are_offered_prepared_and_exported_without_row_scope_expansion() {
    let scratch = tempfile::tempdir().unwrap();
    let mut model = model();
    let mut target = model["recordTypes"]["record"].clone();
    target["route"] = json!("organizations");
    model["recordTypes"]["organization"] = target;
    let grants = model["accessProfiles"]["operator"]["permissions"]["records"]
        .as_array_mut()
        .unwrap();
    let mut target_grant = grants[0].clone();
    target_grant["recordType"] = json!("organization");
    grants.push(target_grant);
    for key in ["readableFields", "writableFields"] {
        grants[0][key]
            .as_array_mut()
            .unwrap()
            .push(json!("organization"));
    }
    let record = &mut model["recordTypes"]["record"];
    record["fields"].as_array_mut().unwrap().push(json!({
        "id":"organization","type":"reference","target":"organization","required":true,"classification":"internal"
    }));
    record["constraints"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"unique","fields":["organization"]}));
    let files = registry_files(&model);
    let mut selected = args(scratch.path());
    selected.selector_field = Some("organization".into());
    selected.selector_profile = "by-organization".into();
    selected.readable_fields.push("organization".into());
    row_scope(&mut selected, "label", "source_label", &json!("allowed"));
    let pending = prepare(&selected, &files).unwrap();
    let entity = pending.report["entities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entity| entity["id"] == "record")
        .unwrap();
    let reference = json!({"id":"organization","type":"reference"});
    for key in ["selectorFields", "readableFields"] {
        assert!(entity[key].as_array().unwrap().contains(&reference));
    }
    assert!(!entity["rowFields"].as_array().unwrap().contains(&reference));
    assert_eq!(
        pending.report["rowScope"],
        json!({"kind":"claim","field":"label","claim":"source_label"})
    );
    let facts = exported_facts(&selected, &files, &pending);
    assert_eq!(
        facts["properties"]["organization"],
        json!({"type":"string","format":"uuid","minLength":36,"maxLength":36})
    );
}

#[test]
fn preparation_adds_the_optional_top_level_profiles_without_changing_module_authority() {
    let scratch = tempfile::tempdir().unwrap();
    let mut model = model();
    let mut profiles = model
        .as_object_mut()
        .unwrap()
        .remove("accessProfiles")
        .unwrap();
    let mut operator = profiles
        .as_object_mut()
        .unwrap()
        .remove("operator")
        .unwrap();
    let mut permissions = operator
        .as_object_mut()
        .unwrap()
        .remove("permissions")
        .unwrap();
    let mut permission = permissions["records"].as_array_mut().unwrap().remove(0);
    permission.as_object_mut().unwrap().remove("recordType");
    operator
        .as_object_mut()
        .unwrap()
        .extend(permission.as_object().unwrap().clone());
    let module = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
        "id":"local-authority","version":"1","extendRecordTypes":{"record":{"accessProfiles":{"operator":operator}}}
    });
    let module_bytes = bytes(&module);
    let parsed = registry_breg::contract::parse_module_yaml(&module_bytes).unwrap();
    model["modules"] = json!({"local-authority":{"version":"1","digest":registry_breg::compiler::module_digest(&parsed)}});
    let mut files = registry_files(&model);
    files.insert("modules/local-authority/module.yaml".into(), module_bytes);
    let pending = prepare(&args(scratch.path()), &files).unwrap();
    let successor = yaml(&pending.registry.after);
    assert_eq!(successor["modules"], model["modules"]);
    assert_eq!(
        successor["accessProfiles"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["source-reader"]
    );
}

#[test]
fn existing_unique_selector_and_lookup_grant_are_a_zero_ddl_successor() {
    let scratch = tempfile::tempdir().unwrap();
    let files = registry_files(&model());
    let pending = prepare(&args(scratch.path()), &files).unwrap();
    assert_eq!(pending.report["status"], "preview");
    assert_eq!(
        pending.report["scopes"],
        json!(["registry:source-reader:lookup"])
    );
    let mut successor_files = files.clone();
    successor_files.insert("registry.yaml".into(), pending.registry.after);
    let changes = registry_breg::package::compiled_registry_change_set(
        &compile_files(&files),
        &compile_files(&successor_files),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let plan = registry_breg::package::change_set_to_applicable_migration_plan(&changes).unwrap();
    assert!(plan.statements.is_empty());
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}
