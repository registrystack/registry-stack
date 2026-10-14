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
    project::{self, EvidenceProject, FunctionInterface},
    target, validate_derive_fact_reads, validate_function, validate_output_schema_document,
};

fn default_scripts(project: &EvidenceProject) -> BTreeMap<String, String> {
    project.functions.iter().map(|function| {
        let script = match function.interface {
            FunctionInterface::SourcePrepare => "fn prepare(selectors, context) { #{query: [], body: #{}} }",
            FunctionInterface::SourceExtract => "fn extract(response, context) { #{outcome: \"match\", facts: #{active: true, status: \"active\"}} }",
            FunctionInterface::AssertionDerive => include_str!("../corpus/authoring_project/derivation.rhai"),
        };
        (function.source.clone(), script.to_owned())
    }).collect()
}

fn baseline() -> &'static EvidenceProject {
    static PROJECT: OnceLock<EvidenceProject> = OnceLock::new();
    PROJECT.get_or_init(|| {
        let project = project::read_project(
            "evidence.yaml",
            include_bytes!("../corpus/authoring_project/project.yaml"),
        )
        .expect("the normalized seed must parse")
        .value;
        compile::compile(&project, &default_scripts(&project))
            .expect("the normalized seed must reach compilation");
        project
    })
}

fuzz_target!(|data: &[u8]| {
    let project = baseline();
    let _ = target::read_target("local-target.yaml", data);
    let _ = target::read_authority("target-authority.yaml", data, project);
    if let Ok(decoded) = project::read_project("evidence.yaml", data) {
        if let Ok(compiled) = compile::compile(&decoded.value, &default_scripts(&decoded.value)) {
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
    for interface in [
        FunctionInterface::SourcePrepare,
        FunctionInterface::SourceExtract,
        FunctionInterface::AssertionDerive,
    ] {
        let _ = validate_function(&text, interface);
    }
    let declared = project
        .sources
        .values()
        .flat_map(|source| source.facts.keys().map(ToString::to_string))
        .collect::<BTreeSet<_>>();
    let _ = validate_derive_fact_reads(&text, &declared);
    let mut scripts = default_scripts(project);
    for function in &project.functions {
        if function.interface == FunctionInterface::AssertionDerive {
            scripts.insert(function.source.clone(), text.clone());
        }
    }
    let _ = compile::compile(project, &scripts);
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(&text) {
        let _ = validate_output_schema_document(&document);
    }
});
