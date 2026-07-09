#![no_main]

use libfuzzer_sys::fuzz_target;
use registry_manifest_core::{
    canonicalize_json, compile_manifest, render_base_dcat, render_breg_dcat_ap, render_catalog,
    render_cpsv_ap, render_dataset_policy_document, render_dcat_profile,
    render_entity_schema_draft_2020_12, render_entity_shacl, render_evidence_offering,
    render_evidence_offerings, render_form_schema_draft_2020_12, render_ogc_records_item,
    render_ogc_records_items, render_policy_collection, render_shacl, source_manifest_digest,
    validate_manifest, CompiledMetadata, MetadataManifest,
};
use serde_json::Value;

const MAX_INPUT_CHARS: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let bounded = take_chars(input, MAX_INPUT_CHARS);
    let _ = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&bounded);

    let Ok(manifest) = serde_yaml_ng::from_str::<MetadataManifest>(&bounded) else {
        return;
    };

    let _ = source_manifest_digest(&manifest);
    if validate_manifest(&manifest).is_err() {
        return;
    }

    let Ok(compiled) = compile_manifest(&manifest) else {
        return;
    };
    exercise_renderers(&compiled);
});

fn exercise_renderers(compiled: &CompiledMetadata) {
    exercise_json(render_catalog(compiled));
    exercise_json(render_evidence_offerings(compiled));
    exercise_json(render_policy_collection(compiled));
    exercise_json(render_base_dcat(compiled));
    exercise_json(render_breg_dcat_ap(compiled));
    exercise_json(render_cpsv_ap(compiled));
    exercise_json(render_shacl(compiled));
    exercise_json(render_ogc_records_items(compiled));

    for profile in compiled.catalog().application_profiles.iter().take(8) {
        if let Some(value) = render_dcat_profile(compiled, &profile.id) {
            exercise_json(value);
        }
    }

    for dataset in compiled.datasets().take(8) {
        if let Some(value) = render_dataset_policy_document(compiled, &dataset.dataset_id) {
            exercise_json(value);
        }
        if let Some(value) = render_ogc_records_item(compiled, &dataset.dataset_id) {
            exercise_json(value);
        }
        for entity in dataset.entities.values().take(8) {
            if let Some(value) =
                render_entity_schema_draft_2020_12(compiled, &dataset.dataset_id, &entity.name)
            {
                exercise_json(value);
            }
            if let Some(value) = render_entity_shacl(compiled, &dataset.dataset_id, &entity.name) {
                exercise_json(value);
            }
        }
    }

    for form in compiled.forms().take(8) {
        if let Some(value) = render_form_schema_draft_2020_12(compiled, &form.id) {
            exercise_json(value);
        }
    }

    for offering in compiled.evidence_offerings().take(8) {
        if let Some(value) = render_evidence_offering(compiled, &offering.id) {
            exercise_json(value);
        }
    }
}

fn exercise_json(value: Value) {
    let _ = canonicalize_json(&value);
    let _ = serde_json::to_vec(&value);
}

fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
