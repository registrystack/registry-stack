#![no_main]

//! Normalized project, target-authority, output-schema and named Function
//! parsing and compilation, without file, network or process access.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

use libfuzzer_sys::fuzz_target;
use registry_evidence_authoring::{
    compile,
    project::{self, AcquisitionPosture, EvidenceProject, FunctionInterface},
    target, validate_derive_fact_reads, validate_function, validate_output_schema_document,
};

fn default_scripts(project: &EvidenceProject) -> BTreeMap<String, String> {
    project
        .functions
        .iter()
        .map(|function| {
            let script = match function.interface {
                FunctionInterface::AssertionDerive => {
                    include_str!("../corpus/authoring_project/derivation.rhai")
                }
            };
            (function.source.clone(), script.to_owned())
        })
        .collect()
}

fn checked_pack_route(project: &EvidenceProject) -> compile::CheckedPackRoute {
    let source = project
        .sources
        .values()
        .next()
        .expect("the normalized seed must name its operator source");
    assert_eq!(
        project.sources.len(),
        1,
        "the normalized seed has one source"
    );
    assert_eq!(source.pack.id.as_str(), "operator-register");
    assert_eq!(source.pack.version, "1");
    assert_eq!(source.route.as_str(), "operator-active");

    let pack_bytes =
        include_bytes!("../../examples/operator-active/adapter-packs/operator-register/pack.yaml");
    let inputs_bytes = include_bytes!(
        "../../examples/operator-active/adapter-packs/operator-register/schemas/inputs.json"
    );
    let response_bytes = include_bytes!(
        "../../examples/operator-active/adapter-packs/operator-register/schemas/response.json"
    );
    let facts_bytes = include_bytes!(
        "../../examples/operator-active/adapter-packs/operator-register/schemas/facts.json"
    );
    let script_bytes = include_bytes!(
        "../../examples/operator-active/adapter-packs/operator-register/scripts/operator.rhai"
    );

    compile::CheckedPackRoute {
        pack: source.pack.clone(),
        route: source.route.clone(),
        digest: "sha256:6ac8fd3a65e142a359d8d5a0c3274c8439e24aed6938da6656feaa40650f242d"
            .to_owned(),
        inputs_schema: serde_json::from_slice(inputs_bytes)
            .expect("the embedded operator input schema must parse"),
        facts_schema: serde_json::from_slice(facts_bytes)
            .expect("the embedded operator facts schema must parse"),
        acquisition_posture: AcquisitionPosture::RecordTransformed,
        pack_bytes: pack_bytes.to_vec(),
        artifacts: BTreeMap::from([
            ("schemas/inputs.json".to_owned(), inputs_bytes.to_vec()),
            ("schemas/response.json".to_owned(), response_bytes.to_vec()),
            ("schemas/facts.json".to_owned(), facts_bytes.to_vec()),
            ("scripts/operator.rhai".to_owned(), script_bytes.to_vec()),
        ]),
    }
}

fn compiled_fact_names(compiled: &compile::CompiledProject) -> BTreeSet<String> {
    compiled
        .source_facts
        .values()
        .flat_map(|schema| {
            schema
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .into_iter()
                .flat_map(|properties| properties.keys().cloned())
        })
        .collect()
}

struct Baseline {
    project: EvidenceProject,
    pack_routes: Vec<compile::CheckedPackRoute>,
    declared_facts: BTreeSet<String>,
}

fn baseline() -> &'static Baseline {
    static BASELINE: OnceLock<Baseline> = OnceLock::new();
    BASELINE.get_or_init(|| {
        let project = project::read_project(
            "evidence.yaml",
            include_bytes!("../corpus/authoring_project/project.yaml"),
        )
        .expect("the normalized seed must parse")
        .value;
        let pack_routes = vec![checked_pack_route(&project)];
        let compiled =
            compile::compile_with_pack_routes(&project, &default_scripts(&project), &pack_routes)
                .expect("the normalized seed must reach compilation");
        let declared_facts = compiled_fact_names(&compiled);
        assert_eq!(
            declared_facts,
            ["active", "address-canary", "status"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            "the normalized seed must expose the canonical operator facts"
        );
        Baseline {
            project,
            pack_routes,
            declared_facts,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let baseline = baseline();
    let project = &baseline.project;
    let _ = target::read_target("local-target.yaml", data);
    let _ = target::read_authority("target-authority.yaml", data, project);
    if let Ok(decoded) = project::read_project("evidence.yaml", data) {
        if let Ok(compiled) = compile::compile_with_pack_routes(
            &decoded.value,
            &default_scripts(&decoded.value),
            &baseline.pack_routes,
        ) {
            let _ = registry_evidence_authoring::types::typescript(&decoded.value, &compiled);
            let _ = registry_evidence_authoring::types::python(&decoded.value, &compiled);
        }
    }
    let Some(text) = std::str::from_utf8(data)
        .ok()
        .map(|text| text.chars().take(8192).collect::<String>())
    else {
        return;
    };
    let _ = validate_function(&text, FunctionInterface::AssertionDerive);
    let _ = validate_derive_fact_reads(&text, &baseline.declared_facts);
    let mut scripts = default_scripts(project);
    for function in &project.functions {
        if function.interface == FunctionInterface::AssertionDerive {
            scripts.insert(function.source.clone(), text.clone());
        }
    }
    let _ = compile::compile_with_pack_routes(project, &scripts, &baseline.pack_routes);
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(&text) {
        let _ = validate_output_schema_document(&document);
    }
});
