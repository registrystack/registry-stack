// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use registry_metadata_core::{
    compile_manifest, render_base_dcat, render_breg_dcat_ap, render_catalog, render_dcat_profile,
    render_entity_schema_draft_2020_12, render_ogc_records_items, render_shacl, MetadataError,
    MetadataManifest,
};
use serde::Deserialize;
use serde_yml::Value;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("validate") => {
            let path = args.get(1).ok_or_else(usage)?;
            let manifest = load_manifest(path)?;
            registry_metadata_core::validate_manifest(&manifest).map_err(format_metadata_error)?;
            println!("metadata manifest valid: {path}");
            Ok(())
        }
        Some("render") => render_command(&args[1..]),
        Some("publish") => publish_command(&args[1..]),
        Some("validate-profiles") => validate_profiles_command(&args[1..]),
        _ => Err(usage()),
    }
}

fn render_command(args: &[String]) -> Result<(), String> {
    let manifest_path = args.first().ok_or_else(usage)?;
    let format = option_value(args, "--format").ok_or_else(usage)?;
    let profile = option_value(args, "--profile");
    let manifest = load_manifest(manifest_path)?;
    let compiled = compile_manifest(&manifest).map_err(format_metadata_error)?;
    let value = match format.as_str() {
        "catalog" => render_catalog(&compiled),
        "dcat" => {
            if let Some(profile) = profile.as_deref() {
                ensure_dcat_profile_available(&compiled, profile)?;
                render_dcat_profile(&compiled, profile)
                    .ok_or_else(|| format!("unsupported DCAT profile: {profile}"))?
            } else {
                render_base_dcat(&compiled)
            }
        }
        "bregdcat-ap" => {
            ensure_dcat_profile_available(&compiled, "bregdcat-ap")?;
            render_breg_dcat_ap(&compiled)
        }
        "shacl" => render_shacl(&compiled),
        "json-schema" => {
            let dataset = option_value(args, "--dataset").ok_or_else(|| {
                "json-schema render requires --dataset <id> and --entity <name>".to_string()
            })?;
            let entity = option_value(args, "--entity").ok_or_else(|| {
                "json-schema render requires --dataset <id> and --entity <name>".to_string()
            })?;
            render_entity_schema_draft_2020_12(&compiled, &dataset, &entity)
                .ok_or_else(|| format!("entity not found: {dataset}/{entity}"))?
        }
        "ogc-records" => render_ogc_records_items(&compiled),
        other => return Err(format!("unsupported render format: {other}")),
    };
    print_json(&value)
}

fn publish_command(args: &[String]) -> Result<(), String> {
    let manifest_path = args.first().ok_or_else(usage)?;
    let out = option_value(args, "--out").unwrap_or_else(|| "public/metadata".to_string());
    let manifest = load_manifest(manifest_path)?;
    let compiled = compile_manifest(&manifest).map_err(format_metadata_error)?;
    let out = PathBuf::from(out);
    fs::create_dir_all(out.join("schema")).map_err(|error| error.to_string())?;
    fs::create_dir_all(out.join("profiles")).map_err(|error| error.to_string())?;

    fs::copy(manifest_path, out.join("metadata.yaml")).map_err(|error| error.to_string())?;
    write_json(out.join("catalog.json"), &render_catalog(&compiled))?;
    write_json(out.join("dcat.jsonld"), &render_base_dcat(&compiled))?;
    let mut dcat_profiles = Vec::new();
    for profile in &compiled.catalog().application_profiles {
        if let Some(document) = render_dcat_profile(&compiled, &profile.id) {
            let filename = format!("dcat.{}.jsonld", profile.id);
            write_json(out.join(&filename), &document)?;
            dcat_profiles.push(serde_json::json!({
                "id": profile.id,
                "version": profile.version,
                "url": format!("/metadata/{filename}"),
            }));
        }
    }
    write_json(out.join("shacl.jsonld"), &render_shacl(&compiled))?;

    let mut schemas = Vec::new();
    for dataset in compiled.datasets() {
        let schema_dir = out.join("schema").join(&dataset.dataset_id);
        fs::create_dir_all(&schema_dir).map_err(|error| error.to_string())?;
        for entity in dataset.entities.values() {
            let entity_dir = schema_dir.join(&entity.name);
            fs::create_dir_all(&entity_dir).map_err(|error| error.to_string())?;
            let relative = format!(
                "/metadata/schema/{}/{}/schema.json",
                dataset.dataset_id, entity.name
            );
            let schema =
                render_entity_schema_draft_2020_12(&compiled, &dataset.dataset_id, &entity.name)
                    .expect("compiled entity schema renders");
            write_json(entity_dir.join("schema.json"), &schema)?;
            schemas.push(serde_json::json!({
                "dataset": dataset.dataset_id,
                "entity": entity.name,
                "url": relative,
            }));
        }
    }

    let mut profiles = Vec::new();
    for profile in compiled.profiles() {
        let filename = format!("{}.json", profile.id);
        write_json(
            out.join("profiles").join(&filename),
            &serde_json::json!(profile),
        )?;
        profiles.push(serde_json::json!({
            "id": profile.id,
            "version": profile.version,
            "url": format!("/metadata/profiles/{filename}"),
        }));
    }
    let application_profiles = compiled
        .catalog()
        .application_profiles
        .iter()
        .map(|profile| {
            serde_json::json!({
                "id": profile.id,
                "version": profile.version,
            })
        })
        .collect::<Vec<_>>();
    let index = serde_json::json!({
        "schema_version": "registry-relay-metadata-index/v1",
        "manifest": "/metadata/metadata.yaml",
        "catalog": "/metadata/catalog.json",
        "dcat": "/metadata/dcat.jsonld",
        "dcat_profiles": dcat_profiles,
        "shacl": "/metadata/shacl.jsonld",
        "schemas": schemas,
        "profiles": profiles,
        "application_profiles": application_profiles,
    });
    write_json(out.join("index.json"), &index)?;
    println!("published metadata artifacts to {}", out.display());
    Ok(())
}

fn validate_profiles_command(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(
        args.first()
            .cloned()
            .unwrap_or_else(|| "profiles".to_string()),
    );
    let profile_paths = profile_descriptor_paths(&root)?;
    let mut errors = Vec::new();
    for profile_path in &profile_paths {
        match load_profile_descriptor(profile_path) {
            Ok(descriptor) => {
                validate_profile_descriptor(profile_path, &descriptor, &mut errors);
                for fixture in &descriptor.fixtures {
                    validate_profile_fixture(profile_path, &descriptor, fixture, &mut errors);
                }
            }
            Err(error) => errors.push(error),
        }
    }

    if errors.is_empty() {
        println!(
            "validated {} profile descriptors and fixtures",
            profile_paths.len()
        );
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

fn profile_descriptor_paths(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    let entries = fs::read_dir(root)
        .map_err(|error| format!("metadata.profile.directory_read_failed: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("metadata.profile.directory_read_failed: {error}"))?;
        let path = entry.path().join("profile.yaml");
        if path.is_file() {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        Err(format!(
            "metadata.profile.descriptor_missing: no profile.yaml files under {}",
            root.display()
        ))
    } else {
        Ok(paths)
    }
}

fn load_profile_descriptor(path: &Path) -> Result<ProfileDescriptor, String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "metadata.profile.file_not_found: {}: {error}",
            path.display()
        )
    })?;
    serde_yml::from_str(&raw)
        .map_err(|error| format!("metadata.profile.parse_failed: {}: {error}", path.display()))
}

fn validate_profile_descriptor(
    path: &Path,
    descriptor: &ProfileDescriptor,
    errors: &mut Vec<String>,
) {
    if descriptor.schema_version != "registry-relay-profile/v1" {
        errors.push(format!(
            "{}: metadata.profile.version_unsupported",
            path.display()
        ));
    }
    if descriptor.profile.id.trim().is_empty() {
        errors.push(format!("{}: metadata.profile.id_missing", path.display()));
    }
    if let Some(directory_name) = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
    {
        if !descriptor.profile.id.is_empty() && descriptor.profile.id != directory_name {
            errors.push(format!(
                "{}: metadata.profile.id_mismatch expected directory id {directory_name}, found {}",
                path.display(),
                descriptor.profile.id
            ));
        }
    }
    if descriptor.profile.version.trim().is_empty() {
        errors.push(format!(
            "{}: metadata.profile.version_missing",
            path.display()
        ));
    }
    if descriptor.supported_input_artifacts.is_empty() {
        errors.push(format!(
            "{}: metadata.profile.supported_input_artifacts_missing",
            path.display()
        ));
    }
    if descriptor.unsupported_mappings.is_empty() {
        errors.push(format!(
            "{}: metadata.profile.unsupported_mappings_missing",
            path.display()
        ));
    }
    if descriptor.conformance_checks.is_empty() {
        errors.push(format!(
            "{}: metadata.profile.conformance_checks_missing",
            path.display()
        ));
    }
    if descriptor.fixtures.is_empty() {
        errors.push(format!(
            "{}: metadata.profile.fixtures_missing",
            path.display()
        ));
    }
}

fn validate_profile_fixture(
    profile_path: &Path,
    descriptor: &ProfileDescriptor,
    fixture: &ProfileFixture,
    errors: &mut Vec<String>,
) {
    let fixture_path = profile_path
        .parent()
        .expect("profile path has parent")
        .join(&fixture.path);
    let raw = match fs::read_to_string(&fixture_path) {
        Ok(raw) => raw,
        Err(error) => {
            errors.push(format!(
                "{}: metadata.profile.fixture_missing: {}: {error}",
                profile_path.display(),
                fixture.path
            ));
            return;
        }
    };
    let manifest: MetadataManifest = match serde_yml::from_str(&raw) {
        Ok(manifest) => manifest,
        Err(error) => {
            errors.push(format!(
                "{}: metadata.manifest.parse_failed: {error}",
                fixture_path.display()
            ));
            return;
        }
    };
    if let Err(error) = registry_metadata_core::validate_manifest(&manifest) {
        errors.push(format!(
            "{}: {}",
            fixture_path.display(),
            format_metadata_error(error)
        ));
        return;
    }
    let raw_value = match serde_yml::from_str::<Value>(&raw) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!(
                "{}: metadata.profile.fixture_parse_failed: {error}",
                fixture_path.display()
            ));
            return;
        }
    };
    collect_runtime_only_keys(&raw_value, &fixture_path.display().to_string(), errors);

    if !manifest.profiles.iter().any(|claim| {
        claim.id == descriptor.profile.id && claim.version == descriptor.profile.version
    }) {
        errors.push(format!(
            "{}: metadata.profile.claim_missing: {} {}",
            fixture_path.display(),
            descriptor.profile.id,
            descriptor.profile.version
        ));
    }

    let concepts = manifest_concepts(&manifest);
    for required in &descriptor.required_concepts {
        if !concepts.contains(&required.iri) {
            errors.push(format!(
                "{}: metadata.profile.required_concept_missing: {}",
                fixture_path.display(),
                required.iri
            ));
        }
    }

    let entities = manifest_entities(&manifest);
    for required in &descriptor.required_identifiers {
        let identifiers = entities
            .iter()
            .find(|entity| entity.name == required.entity)
            .map(|entity| entity.identifiers.as_slice())
            .unwrap_or_default();
        if !identifiers
            .iter()
            .any(|identifier| identifier.name == required.name && identifier.kind == required.kind)
        {
            errors.push(format!(
                "{}: metadata.profile.identifier_missing: {}.{}",
                fixture_path.display(),
                required.entity,
                required.name
            ));
        }
    }

    for expected in &descriptor.cardinality_expectations {
        let count = entities
            .iter()
            .find(|entity| entity.name == expected.entity)
            .map(|entity| {
                entity
                    .fields
                    .iter()
                    .filter(|field| field.name == expected.field)
                    .count()
            })
            .unwrap_or_default();
        if count < expected.min || count > expected.max {
            errors.push(format!(
                "{}: metadata.profile.cardinality_mismatch: {}.{} expected {}..{}, found {}",
                fixture_path.display(),
                expected.entity,
                expected.field,
                expected.min,
                expected.max,
                count
            ));
        }
    }

    let codelists = manifest_codelists(&manifest);
    for expected in &descriptor.codelist_expectations {
        let actual = codelists.get(&expected.id).cloned().unwrap_or_default();
        let missing = expected
            .required_codes
            .iter()
            .filter(|code| !actual.contains(*code))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            errors.push(format!(
                "{}: metadata.profile.codelist_mismatch: {} missing {}",
                fixture_path.display(),
                expected.id,
                missing.join(", ")
            ));
        }
    }
}

fn load_manifest(path: impl AsRef<Path>) -> Result<MetadataManifest, String> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("metadata.manifest.file_not_found: {error}"))?;
    serde_yml::from_str(&raw).map_err(|error| format!("metadata.manifest.parse_failed: {error}"))
}

fn manifest_entities(manifest: &MetadataManifest) -> Vec<&registry_metadata_core::EntityManifest> {
    manifest
        .datasets
        .iter()
        .flat_map(|dataset| dataset.entities.iter())
        .collect()
}

fn manifest_concepts(manifest: &MetadataManifest) -> BTreeSet<String> {
    manifest_entities(manifest)
        .into_iter()
        .flat_map(|entity| entity.fields.iter())
        .flat_map(|field| field.concepts.iter().cloned())
        .collect()
}

fn manifest_codelists(manifest: &MetadataManifest) -> BTreeMap<String, BTreeSet<String>> {
    manifest
        .codelists
        .iter()
        .map(|codelist| {
            (
                codelist.id.clone(),
                codelist
                    .concepts
                    .iter()
                    .map(|concept| concept.code.clone())
                    .collect(),
            )
        })
        .collect()
}

fn collect_runtime_only_keys(value: &Value, path: &str, errors: &mut Vec<String>) {
    const RUNTIME_ONLY_KEYS: &[&str] = &[
        "bindings",
        "capabilities",
        "column",
        "file_path",
        "query",
        "required_filters",
        "rows_scope",
        "scope",
        "source",
        "source_id",
        "table",
        "url",
        "url_env",
        "visibility",
    ];
    match value {
        Value::Mapping(mapping) => {
            for (key, child) in mapping {
                if let Value::String(key) = key {
                    if RUNTIME_ONLY_KEYS.contains(&key.as_str()) {
                        errors.push(format!(
                            "{path}: metadata.profile.runtime_key_present: {key}"
                        ));
                    }
                }
                collect_runtime_only_keys(child, path, errors);
            }
        }
        Value::Sequence(sequence) => {
            for child in sequence {
                collect_runtime_only_keys(child, path, errors);
            }
        }
        Value::Tagged(tagged) => collect_runtime_only_keys(&tagged.value, path, errors),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ProfileDescriptor {
    schema_version: String,
    profile: ProfileMetadata,
    supported_input_artifacts: Vec<Value>,
    required_concepts: Vec<ConceptExpectation>,
    required_identifiers: Vec<IdentifierExpectation>,
    cardinality_expectations: Vec<CardinalityExpectation>,
    codelist_expectations: Vec<CodelistExpectation>,
    unsupported_mappings: Vec<Value>,
    conformance_checks: Vec<Value>,
    fixtures: Vec<ProfileFixture>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ProfileMetadata {
    id: String,
    version: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConceptExpectation {
    iri: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct IdentifierExpectation {
    entity: String,
    name: String,
    kind: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CardinalityExpectation {
    entity: String,
    field: String,
    min: usize,
    max: usize,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CodelistExpectation {
    id: String,
    required_codes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ProfileFixture {
    path: String,
}

fn format_metadata_error(error: MetadataError) -> String {
    match error {
        MetadataError::VersionUnsupported => "metadata.manifest.version_unsupported".to_string(),
        MetadataError::Validation { errors } => {
            let details = errors
                .into_iter()
                .map(|error| format!("{}: {}", error.path, error.message))
                .collect::<Vec<_>>()
                .join("; ");
            if details.is_empty() {
                "metadata.manifest.validation_failed".to_string()
            } else {
                format!("metadata.manifest.validation_failed: {details}")
            }
        }
    }
}

fn option_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| (window[0] == name).then(|| window[1].clone()))
}

fn ensure_dcat_profile_available(
    compiled: &registry_metadata_core::CompiledMetadata,
    profile: &str,
) -> Result<(), String> {
    if matches!(profile, "dcat" | "dcat-ap") {
        return Ok(());
    }
    if compiled
        .catalog()
        .application_profiles
        .iter()
        .any(|candidate| candidate.id == profile)
    {
        Ok(())
    } else {
        Err(format!(
            "metadata.manifest.unsupported_application_profile: {profile}"
        ))
    }
}

fn write_json(path: impl AsRef<Path>, value: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| error.to_string())
}

fn print_json(value: &serde_json::Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn usage() -> String {
    "usage: registry-metadata validate <metadata.yaml> | validate-profiles [profiles-dir] | render <metadata.yaml> --format <catalog|dcat|bregdcat-ap|shacl|json-schema|ogc-records> [--profile <id>] [--dataset <id> --entity <name>] | publish <metadata.yaml> --out <dir>".to_string()
}
