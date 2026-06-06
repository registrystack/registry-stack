// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::CStr;
use std::fs;
use std::mem::MaybeUninit;
use std::path::{Component, Path, PathBuf};

use registry_manifest_core::{
    canonicalize_json, compile_manifest, is_runtime_only_key, render_base_dcat,
    render_breg_dcat_ap, render_catalog, render_cpsv_ap, render_dataset_policy_document,
    render_dcat_profile, render_entity_schema_draft_2020_12, render_evidence_offering,
    render_evidence_offerings, render_form_schema_draft_2020_12, render_ogc_records_items,
    render_policy_collection, render_shacl, sha256_uri, source_manifest_digest, MetadataError,
    MetadataManifest,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_yaml_ng::Value;
use unsafe_libyaml::{
    yaml_event_delete, yaml_event_t, yaml_parser_delete, yaml_parser_initialize, yaml_parser_parse,
    yaml_parser_set_input_string, yaml_parser_t, YAML_ALIAS_EVENT, YAML_MAPPING_START_EVENT,
    YAML_SCALAR_EVENT, YAML_SEQUENCE_START_EVENT, YAML_STREAM_END_EVENT,
};

const YAML_MAX_BYTES: u64 = 64 * 1024;

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
            registry_manifest_core::validate_manifest(&manifest).map_err(format_metadata_error)?;
            let digest = source_manifest_digest(&manifest).map_err(|error| error.to_string())?;
            println!("metadata manifest valid: {path}");
            println!("source_manifest_digest: {digest}");
            Ok(())
        }
        Some("render") => render_command(&args[1..]),
        Some("publish") => publish_command(&args[1..]),
        Some("validate-profiles") => validate_profiles_command(&args[1..]),
        Some("--help") | Some("-h") | Some("help") => {
            println!("{}", usage());
            Ok(())
        }
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
        "evidence-offerings" => render_evidence_offerings(&compiled),
        "evidence-offering" => {
            let offering = option_value(args, "--offering")
                .ok_or_else(|| "evidence-offering render requires --offering <id>".to_string())?;
            render_evidence_offering(&compiled, &offering)
                .ok_or_else(|| format!("evidence offering not found: {offering}"))?
        }
        "policies" => render_policy_collection(&compiled),
        "policy" => {
            let dataset = option_value(args, "--dataset")
                .ok_or_else(|| "policy render requires --dataset <id>".to_string())?;
            render_dataset_policy_document(&compiled, &dataset)
                .ok_or_else(|| format!("dataset not found: {dataset}"))?
        }
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
        "cpsv-ap" => {
            ensure_dcat_profile_available(&compiled, "cpsv-ap")?;
            render_cpsv_ap(&compiled)
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
        "form-json-schema" => {
            let form = option_value(args, "--form")
                .ok_or_else(|| "form-json-schema render requires --form <id>".to_string())?;
            render_form_schema_draft_2020_12(&compiled, &form)
                .ok_or_else(|| format!("form not found: {form}"))?
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
    let source_digest = source_manifest_digest(&manifest).map_err(|error| error.to_string())?;
    let out = PathBuf::from(out);
    let out_root = prepare_publish_root(&out, "metadata.publish.out_not_directory")?;
    let site_root = option_value(args, "--site-root")
        .map(PathBuf::from)
        .map(|site_root| {
            prepare_publish_root(&site_root, "metadata.publish.site_root_not_directory")
        })
        .transpose()?;
    create_contained_dir_all(&out_root, "schema")?;
    create_contained_dir_all(&out_root, "forms")?;
    create_contained_dir_all(&out_root, "profiles")?;
    create_contained_dir_all(&out_root, "evidence-offerings")?;
    create_contained_dir_all(&out_root, "policies")?;

    copy_contained(&out_root, "metadata.yaml", manifest_path)?;
    write_json(&out_root, "catalog.json", &render_catalog(&compiled))?;
    write_json(
        &out_root,
        "evidence-offerings.json",
        &render_evidence_offerings(&compiled),
    )?;
    write_json(
        &out_root,
        "policies.jsonld",
        &render_policy_collection(&compiled),
    )?;
    write_json(&out_root, "dcat.jsonld", &render_base_dcat(&compiled))?;
    let mut dcat_profiles = Vec::new();
    let mut service_catalogues = Vec::new();
    for profile in &compiled.catalog().application_profiles {
        if profile.id == "cpsv-ap" {
            let service_catalogue = render_cpsv_ap(&compiled);
            write_json(&out_root, "cpsv-ap", &service_catalogue)?;
            write_json(&out_root, "cpsv-ap.jsonld", &service_catalogue)?;
            service_catalogues.push(serde_json::json!({
                "id": profile.id,
                "version": profile.version,
                "url": "/metadata/cpsv-ap.jsonld",
                "aliases": ["/metadata/cpsv-ap"],
                "media_type": "application/ld+json",
            }));
            continue;
        }
        if let Some(document) = render_dcat_profile(&compiled, &profile.id) {
            let filename = format!("dcat.{}.jsonld", profile.id);
            write_json(&out_root, PathBuf::from(&filename), &document)?;
            dcat_profiles.push(serde_json::json!({
                "id": profile.id,
                "version": profile.version,
                "url": format!("/metadata/{filename}"),
            }));
        }
    }
    write_json(&out_root, "shacl.jsonld", &render_shacl(&compiled))?;

    let mut schemas = Vec::new();
    let mut policy_documents = Vec::new();
    for dataset in compiled.datasets() {
        let policy_filename = format!("{}.jsonld", dataset.dataset_id);
        let policy =
            render_dataset_policy_document(&compiled, &dataset.dataset_id).ok_or_else(|| {
                format!(
                    "metadata.publish.compiled_renderer_missing: dataset policy for {}",
                    dataset.dataset_id
                )
            })?;
        write_json(
            &out_root,
            PathBuf::from("policies").join(&policy_filename),
            &policy,
        )?;
        policy_documents.push(serde_json::json!({
            "dataset": dataset.dataset_id,
            "url": format!("/metadata/policies/{policy_filename}"),
        }));

        let schema_dir = PathBuf::from("schema").join(&dataset.dataset_id);
        create_contained_dir_all(&out_root, &schema_dir)?;
        for entity in dataset.entities.values() {
            let entity_dir = schema_dir.join(&entity.name);
            create_contained_dir_all(&out_root, &entity_dir)?;
            let relative = format!(
                "/metadata/schema/{}/{}/schema.json",
                dataset.dataset_id, entity.name
            );
            let schema =
                render_entity_schema_draft_2020_12(&compiled, &dataset.dataset_id, &entity.name)
                    .ok_or_else(|| {
                        format!(
                            "metadata.publish.compiled_renderer_missing: entity schema for {}/{}",
                            dataset.dataset_id, entity.name
                        )
                    })?;
            write_json(&out_root, entity_dir.join("schema.json"), &schema)?;
            schemas.push(serde_json::json!({
                "dataset": dataset.dataset_id,
                "entity": entity.name,
                "url": relative,
            }));
        }
    }

    let mut form_schemas = Vec::new();
    for form in compiled.forms() {
        let form_dir = PathBuf::from("forms").join(&form.id);
        create_contained_dir_all(&out_root, &form_dir)?;
        let relative = format!("/metadata/forms/{}/schema.json", form.id);
        let schema = render_form_schema_draft_2020_12(&compiled, &form.id).ok_or_else(|| {
            format!(
                "metadata.publish.compiled_renderer_missing: form schema for {}",
                form.id
            )
        })?;
        write_json(&out_root, form_dir.join("schema.json"), &schema)?;
        form_schemas.push(serde_json::json!({
            "form": form.id,
            "url": relative,
        }));
    }

    let mut evidence_offerings = Vec::new();
    for offering in compiled.evidence_offerings() {
        let filename = format!("{}.json", offering.id);
        let document = render_evidence_offering(&compiled, &offering.id).ok_or_else(|| {
            format!(
                "metadata.publish.compiled_renderer_missing: evidence offering {}",
                offering.id
            )
        })?;
        write_json(
            &out_root,
            PathBuf::from("evidence-offerings").join(&filename),
            &document,
        )?;
        evidence_offerings.push(serde_json::json!({
            "id": offering.id,
            "dataset": offering.dataset_id,
            "url": format!("/metadata/evidence-offerings/{filename}"),
        }));
    }

    let mut profiles = Vec::new();
    for profile in compiled.profiles() {
        let filename = format!("{}.json", profile.id);
        write_json(
            &out_root,
            PathBuf::from("profiles").join(&filename),
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
    let artifact_digests = collect_artifact_digests(&out_root)?;
    let package_digest = publication_package_digest(&source_digest, &artifact_digests)?;
    let index = serde_json::json!({
        "schema_version": "registry-manifest-index/v1",
        "source_manifest_digest": source_digest,
        "package_digest": package_digest,
        "artifacts": artifact_digests,
        "manifest": "/metadata/metadata.yaml",
        "catalog": "/metadata/catalog.json",
        "evidence_offerings": "/metadata/evidence-offerings.json",
        "evidence_offering_documents": evidence_offerings,
        "policies": "/metadata/policies.jsonld",
        "policy_documents": policy_documents,
        "dcat": "/metadata/dcat.jsonld",
        "dcat_profiles": dcat_profiles,
        "service_catalogues": service_catalogues,
        "shacl": "/metadata/shacl.jsonld",
        "schemas": schemas,
        "form_schemas": form_schemas,
        "profiles": profiles,
        "application_profiles": application_profiles,
    });
    write_json(&out_root, "index.json", &index)?;
    let public_root = site_root.as_ref().unwrap_or(&out_root);
    write_well_known_discovery(public_root, &index)?;
    println!(
        "published metadata artifacts to {}",
        out_root.root.display()
    );
    Ok(())
}

fn write_well_known_discovery(
    public_root: &PublishRoot,
    index: &serde_json::Value,
) -> Result<(), String> {
    create_contained_dir_all(public_root, ".well-known")?;
    write_api_catalog(public_root, index)?;
    write_legacy_registry_manifest_discovery(public_root, index)
}

fn write_api_catalog(public_root: &PublishRoot, index: &serde_json::Value) -> Result<(), String> {
    let mut items = Vec::new();
    push_api_catalog_item(
        &mut items,
        index.get("catalog"),
        "Registry metadata catalog",
        "application/json",
        None,
    );
    push_api_catalog_item(
        &mut items,
        index.get("dcat"),
        "Base DCAT catalog",
        "application/ld+json",
        Some("http://www.w3.org/ns/dcat#"),
    );
    for entry in value_array(index, "dcat_profiles") {
        push_api_catalog_item(
            &mut items,
            entry.get("url"),
            &format!(
                "{} DCAT profile catalog",
                entry
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("profile")
            ),
            "application/ld+json",
            Some("http://www.w3.org/ns/dcat#"),
        );
    }
    for entry in value_array(index, "service_catalogues") {
        push_api_catalog_item(
            &mut items,
            entry.get("url"),
            &format!(
                "{} service catalogue",
                entry
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("service")
            ),
            entry
                .get("media_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("application/json"),
            None,
        );
    }
    push_api_catalog_item(
        &mut items,
        index.get("evidence_offerings"),
        "Evidence offerings",
        "application/json",
        None,
    );
    push_api_catalog_item(
        &mut items,
        index.get("policies"),
        "Policy metadata",
        "application/ld+json",
        None,
    );
    push_api_catalog_item(
        &mut items,
        index.get("shacl"),
        "SHACL shapes",
        "application/ld+json",
        None,
    );

    let api_catalog = serde_json::json!({
        "linkset": [
            {
                "anchor": "/.well-known/api-catalog",
                "describedby": [
                    {
                        "href": "/metadata/index.json",
                        "type": "application/json",
                        "title": "Registry Manifest metadata index"
                    }
                ],
                "item": items
            }
        ]
    });
    write_json(public_root, ".well-known/api-catalog", &api_catalog)
}

fn push_api_catalog_item(
    items: &mut Vec<serde_json::Value>,
    url: Option<&serde_json::Value>,
    title: &str,
    media_type: &str,
    profile: Option<&str>,
) {
    let Some(href) = url.and_then(serde_json::Value::as_str) else {
        return;
    };
    let mut item = serde_json::Map::new();
    item.insert("href".to_string(), serde_json::json!(href));
    item.insert("type".to_string(), serde_json::json!(media_type));
    item.insert("title".to_string(), serde_json::json!(title));
    if let Some(profile) = profile {
        item.insert("profile".to_string(), serde_json::json!(profile));
    }
    items.push(serde_json::Value::Object(item));
}

fn value_array<'a>(value: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn collect_artifact_digests(root: &PublishRoot) -> Result<Vec<serde_json::Value>, String> {
    let mut files = Vec::new();
    collect_artifact_paths(&root.root, Path::new(""), &mut files)?;
    files.sort();
    let mut artifacts = Vec::with_capacity(files.len());
    for relative in files {
        if relative == Path::new("index.json") || relative.starts_with(".well-known") {
            continue;
        }
        let full_path = root.root.join(&relative);
        let bytes = fs::read(&full_path).map_err(|error| error.to_string())?;
        let path = relative_path_string(&relative)?;
        artifacts.push(serde_json::json!({
            "path": path,
            "media_type": media_type_for_artifact(&relative),
            "sha256": sha256_uri(&bytes),
        }));
    }
    Ok(artifacts)
}

fn collect_artifact_paths(
    root: &Path,
    relative: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let dir = root.join(relative);
    for entry in fs::read_dir(&dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let child_relative = relative.join(name);
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            collect_artifact_paths(root, &child_relative, files)?;
        } else if metadata.is_file() {
            files.push(child_relative);
        }
    }
    Ok(())
}

fn relative_path_string(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "metadata.publish.path_escape: invalid generated path {}",
                    path.display()
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

fn media_type_for_artifact(path: &Path) -> &'static str {
    let path_string = path.to_string_lossy();
    if path_string.ends_with(".jsonld") || path == Path::new("cpsv-ap") {
        "application/ld+json"
    } else if path_string.ends_with(".ttl") {
        "text/turtle"
    } else if path_string.ends_with(".yaml") || path_string.ends_with(".yml") {
        "application/yaml"
    } else {
        "application/json"
    }
}

fn publication_package_digest(
    source_manifest_digest: &str,
    artifacts: &[serde_json::Value],
) -> Result<String, String> {
    let package = serde_json::json!({
        "schema_version": "registry-manifest-package/v1",
        "source_manifest_digest": source_manifest_digest,
        "artifacts": artifacts,
    });
    let canonical = canonicalize_json(&package).map_err(|error| error.to_string())?;
    Ok(sha256_uri(&canonical))
}

fn write_legacy_registry_manifest_discovery(
    public_root: &PublishRoot,
    index: &serde_json::Value,
) -> Result<(), String> {
    let discovery = serde_json::json!({
        "schema_version": "registry-manifest-discovery/v1",
        "metadata_index": "/metadata/index.json",
        "manifest": index.get("manifest").cloned().unwrap_or(serde_json::Value::Null),
        "catalog": index.get("catalog").cloned().unwrap_or(serde_json::Value::Null),
        "dcat": index.get("dcat").cloned().unwrap_or(serde_json::Value::Null),
        "dcat_profiles": index.get("dcat_profiles").cloned().unwrap_or_else(|| serde_json::json!([])),
        "service_catalogues": index.get("service_catalogues").cloned().unwrap_or_else(|| serde_json::json!([])),
        "evidence_offerings": index.get("evidence_offerings").cloned().unwrap_or(serde_json::Value::Null),
        "application_profiles": index.get("application_profiles").cloned().unwrap_or_else(|| serde_json::json!([])),
    });
    write_json(
        public_root,
        ".well-known/registry-manifest.json",
        &discovery,
    )
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
    let raw = load_yaml_source(path, YamlInput::ProfileDescriptor)?;
    deserialize_yaml(&raw, path, YamlInput::ProfileDescriptor)
}

fn validate_profile_descriptor(
    path: &Path,
    descriptor: &ProfileDescriptor,
    errors: &mut Vec<String>,
) {
    if descriptor.schema_version != "registry-manifest-profile/v1" {
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
    let yaml_kind = YamlInput::ProfileFixture {
        profile_path,
        fixture: &fixture.path,
    };
    let raw = match load_yaml_source(&fixture_path, yaml_kind) {
        Ok(raw) => raw,
        Err(error) => {
            errors.push(error);
            return;
        }
    };
    let manifest: MetadataManifest = match deserialize_yaml(&raw, &fixture_path, yaml_kind) {
        Ok(manifest) => manifest,
        Err(error) => {
            errors.push(error);
            return;
        }
    };
    if let Err(error) = registry_manifest_core::validate_manifest(&manifest) {
        errors.push(format!(
            "{}: {}",
            fixture_path.display(),
            format_metadata_error(error)
        ));
        return;
    }
    let raw_value = match serde_yaml_ng::from_str::<Value>(&raw) {
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
    let raw = load_yaml_source(path, YamlInput::Manifest)?;
    let raw_value = serde_yaml_ng::from_str::<Value>(&raw)
        .map_err(|error| YamlInput::Manifest.parse_error(path, error))?;
    let mut runtime_key_errors = Vec::new();
    collect_runtime_only_keys(
        &raw_value,
        &path.display().to_string(),
        &mut runtime_key_errors,
    );
    if !runtime_key_errors.is_empty() {
        return Err(runtime_key_errors.join("\n"));
    }
    deserialize_yaml(&raw, path, YamlInput::Manifest)
}

#[derive(Clone, Copy)]
enum YamlInput<'a> {
    Manifest,
    ProfileDescriptor,
    ProfileFixture {
        profile_path: &'a Path,
        fixture: &'a str,
    },
}

impl YamlInput<'_> {
    fn read_error(self, path: &Path, error: std::io::Error) -> String {
        match self {
            YamlInput::Manifest => format!("metadata.manifest.file_not_found: {error}"),
            YamlInput::ProfileDescriptor => {
                format!(
                    "metadata.profile.file_not_found: {}: {error}",
                    path.display()
                )
            }
            YamlInput::ProfileFixture {
                profile_path,
                fixture,
            } => {
                format!(
                    "{}: metadata.profile.fixture_missing: {fixture}: {error}",
                    profile_path.display()
                )
            }
        }
    }

    fn too_large_error(self, path: &Path) -> String {
        match self {
            YamlInput::Manifest | YamlInput::ProfileFixture { .. } => format!(
                "metadata.manifest.too_large: {} exceeds {YAML_MAX_BYTES} bytes",
                path.display()
            ),
            YamlInput::ProfileDescriptor => format!(
                "metadata.profile.too_large: {} exceeds {YAML_MAX_BYTES} bytes",
                path.display()
            ),
        }
    }

    fn aliases_error(self, path: &Path) -> String {
        match self {
            YamlInput::Manifest | YamlInput::ProfileFixture { .. } => {
                format!("metadata.manifest.aliases_unsupported: {}", path.display())
            }
            YamlInput::ProfileDescriptor => {
                format!("metadata.profile.aliases_unsupported: {}", path.display())
            }
        }
    }

    fn parse_error(self, path: &Path, error: impl std::fmt::Display) -> String {
        match self {
            YamlInput::Manifest => format!("metadata.manifest.parse_failed: {error}"),
            YamlInput::ProfileDescriptor => {
                format!("metadata.profile.parse_failed: {}: {error}", path.display())
            }
            YamlInput::ProfileFixture { .. } => {
                format!(
                    "{}: metadata.manifest.parse_failed: {error}",
                    path.display()
                )
            }
        }
    }
}

enum YamlPrepassError {
    AliasesUnsupported,
    Parse(String),
}

fn load_yaml_source(path: &Path, kind: YamlInput<'_>) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|error| kind.read_error(path, error))?;
    if metadata.len() > YAML_MAX_BYTES {
        return Err(kind.too_large_error(path));
    }
    let raw = fs::read_to_string(path).map_err(|error| kind.read_error(path, error))?;
    if raw.len() as u64 > YAML_MAX_BYTES {
        return Err(kind.too_large_error(path));
    }
    reject_yaml_anchors_and_aliases(&raw).map_err(|error| match error {
        YamlPrepassError::AliasesUnsupported => kind.aliases_error(path),
        YamlPrepassError::Parse(error) => kind.parse_error(path, error),
    })?;
    Ok(raw)
}

fn deserialize_yaml<T: DeserializeOwned>(
    raw: &str,
    path: &Path,
    kind: YamlInput<'_>,
) -> Result<T, String> {
    serde_yaml_ng::from_str(raw).map_err(|error| kind.parse_error(path, error))
}

fn reject_yaml_anchors_and_aliases(raw: &str) -> Result<(), YamlPrepassError> {
    if contains_obvious_yaml_anchor_or_alias(raw) {
        return Err(YamlPrepassError::AliasesUnsupported);
    }

    // SAFETY: The libyaml parser receives a pointer into `raw`, which remains
    // alive until `yaml_parser_delete` runs through `ParserGuard`.
    unsafe {
        let mut parser = MaybeUninit::<yaml_parser_t>::uninit();
        let parser = parser.as_mut_ptr();
        if yaml_parser_initialize(parser).fail {
            return Err(YamlPrepassError::Parse(
                "could not initialize YAML parser".to_string(),
            ));
        }
        let _guard = ParserGuard(parser);
        yaml_parser_set_input_string(parser, raw.as_ptr(), raw.len() as u64);

        let mut event = MaybeUninit::<yaml_event_t>::uninit();
        let event = event.as_mut_ptr();
        loop {
            if yaml_parser_parse(parser, event).fail {
                return Err(YamlPrepassError::Parse(parser_problem(parser)));
            }
            let event_type = (*event).type_;
            let unsupported = match event_type {
                YAML_ALIAS_EVENT => true,
                YAML_SCALAR_EVENT => !(*event).data.scalar.anchor.is_null(),
                YAML_SEQUENCE_START_EVENT => !(*event).data.sequence_start.anchor.is_null(),
                YAML_MAPPING_START_EVENT => !(*event).data.mapping_start.anchor.is_null(),
                _ => false,
            };
            yaml_event_delete(event);

            if unsupported {
                return Err(YamlPrepassError::AliasesUnsupported);
            }
            if event_type == YAML_STREAM_END_EVENT {
                return Ok(());
            }
        }
    }
}

fn contains_obvious_yaml_anchor_or_alias(raw: &str) -> bool {
    raw.lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with('#'))
        .any(line_contains_obvious_yaml_anchor_or_alias)
}

fn line_contains_obvious_yaml_anchor_or_alias(line: &str) -> bool {
    starts_anchor_or_alias(line)
        || line
            .strip_prefix("- ")
            .is_some_and(|rest| starts_anchor_or_alias(rest.trim_start()))
}

fn starts_anchor_or_alias(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'&' | b'*'))
        && bytes
            .get(1)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}

struct ParserGuard(*mut yaml_parser_t);

impl Drop for ParserGuard {
    fn drop(&mut self) {
        // SAFETY: `ParserGuard` is constructed only after successful
        // `yaml_parser_initialize` and owns parser teardown.
        unsafe {
            yaml_parser_delete(self.0);
        }
    }
}

unsafe fn parser_problem(parser: *mut yaml_parser_t) -> String {
    let problem = (&*parser).problem;
    if problem.is_null() {
        "unknown YAML parse error".to_string()
    } else {
        CStr::from_ptr(problem).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{reject_yaml_anchors_and_aliases, YamlPrepassError};

    #[test]
    fn yaml_prepass_rejects_scaled_alias_amplification_shape() {
        let raw = r#"
amplified_seed: &seed lol
amplified_1: [*seed, *seed, *seed, *seed, *seed, *seed, *seed, *seed]
amplified_2: [*seed, *seed, *seed, *seed, *seed, *seed, *seed, *seed]
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets:
  - id: demo
    title: Demo
    entities: []
codelists: []
"#;

        assert!(matches!(
            reject_yaml_anchors_and_aliases(raw),
            Err(YamlPrepassError::AliasesUnsupported)
        ));
    }

    #[test]
    fn yaml_prepass_rejects_nested_anchored_mapping_without_hanging() {
        let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets:
  - id: demo
    title: Demo
    entities:
      - name: amplified
        fields:
          - &field
            name: a
            type: string
          - *field
codelists: []
"#;

        assert!(matches!(
            reject_yaml_anchors_and_aliases(raw),
            Err(YamlPrepassError::AliasesUnsupported)
        ));
    }
}

fn manifest_entities(manifest: &MetadataManifest) -> Vec<&registry_manifest_core::EntityManifest> {
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
    match value {
        Value::Mapping(mapping) => {
            for (key, child) in mapping {
                if let Value::String(key) = key {
                    if is_runtime_only_key(key) {
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
    compiled: &registry_manifest_core::CompiledMetadata,
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

struct PublishRoot {
    root: PathBuf,
    canonical: PathBuf,
}

fn prepare_publish_root(path: &Path, not_directory_code: &str) -> Result<PublishRoot, String> {
    if path.exists() && !path.is_dir() {
        return Err(format!("{not_directory_code}: {}", path.display()));
    }
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    Ok(PublishRoot {
        root: path.to_path_buf(),
        canonical,
    })
}

fn contained_path(root: &PublishRoot, relative: impl AsRef<Path>) -> Result<PathBuf, String> {
    let relative = relative.as_ref();
    if relative.is_absolute() {
        return Err(format!(
            "metadata.publish.path_escape: absolute generated path {}",
            relative.display()
        ));
    }

    let mut target = root.canonical.clone();
    for component in relative.components() {
        match component {
            Component::Normal(part) => target.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "metadata.publish.path_escape: parent traversal in generated path {}",
                    relative.display()
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "metadata.publish.path_escape: absolute generated path {}",
                    relative.display()
                ));
            }
        }
    }

    if target.starts_with(&root.canonical) {
        Ok(target)
    } else {
        Err(format!(
            "metadata.publish.path_escape: generated path escaped root {}",
            relative.display()
        ))
    }
}

fn create_contained_dir_all(root: &PublishRoot, relative: impl AsRef<Path>) -> Result<(), String> {
    let relative = relative.as_ref();
    let target = contained_path(root, relative)?;
    reject_existing_symlink_components(root, relative)?;
    fs::create_dir_all(target).map_err(|error| error.to_string())
}

fn write_contained_bytes(
    root: &PublishRoot,
    relative: impl AsRef<Path>,
    bytes: &[u8],
) -> Result<(), String> {
    let relative = relative.as_ref();
    let target = contained_path(root, relative)?;
    reject_existing_symlink_components(root, relative)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(target, bytes).map_err(|error| error.to_string())
}

fn reject_existing_symlink_components(root: &PublishRoot, relative: &Path) -> Result<(), String> {
    let mut current = root.canonical.clone();
    for component in relative.components() {
        match component {
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "metadata.publish.path_escape: invalid generated path {}",
                    relative.display()
                ));
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "metadata.publish.path_escape: symlink in generated path {}",
                    relative.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn copy_contained(
    root: &PublishRoot,
    relative: impl AsRef<Path>,
    source: impl AsRef<Path>,
) -> Result<(), String> {
    let bytes = fs::read(source).map_err(|error| error.to_string())?;
    write_contained_bytes(root, relative, &bytes)
}

fn write_json(
    root: &PublishRoot,
    relative: impl AsRef<Path>,
    value: &serde_json::Value,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    write_contained_bytes(root, relative, &bytes)
}

fn print_json(value: &serde_json::Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn usage() -> String {
    "usage: registry-manifest validate <metadata.yaml> | validate-profiles [profiles-dir] | render <metadata.yaml> --format <catalog|evidence-offerings|evidence-offering|policies|policy|dcat|bregdcat-ap|cpsv-ap|shacl|json-schema|form-json-schema|ogc-records> [--profile <id>] [--dataset <id> --entity <name>] [--form <id>] [--offering <id>] | publish <metadata.yaml> --out <dir> [--site-root <dir>]".to_string()
}
