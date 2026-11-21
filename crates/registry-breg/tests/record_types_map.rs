// SPDX-License-Identifier: Apache-2.0

//! `recordTypes`, `extendRecordTypes` and a project's `modules` lock are
//! mappings keyed by id (CFG-ID-5). The key is the id, an inner id and the old
//! list shape are refused with the mapping named, a repeated key is refused at
//! the repeating key, and entries are held in id order whatever order the file
//! writes them in.

use registry_breg::contract::{parse_module_yaml, parse_project_yaml};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

const PROJECT_HEAD: &str = "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: record-type-example
  version: '1'
  defaultLanguage: en
  canonicalBaseIri: https://record-type-example.example.test
datasets:
  - id: test-dataset
";

const MODULE_HEAD: &str = "apiVersion: id.registrystack.org/formats/breg/module/v1alpha1
kind: BRegModule
id: extension
version: 0.1.0
";

const ENTRY_BODY: &str = "    primaryDataset: test-dataset
    route: ROUTE
    mutationMode: mutable
    classification: internal
    fields:
      - id: code
        type: string
        maximumLength: 32
        classification: internal
";

fn entry(key: &str, route: &str) -> String {
    format!("  {key}:\n{}", ENTRY_BODY.replace("ROUTE", route))
}

fn project(rest: &str) -> String {
    format!("{PROJECT_HEAD}{rest}")
}

fn module(rest: &str) -> String {
    format!("{MODULE_HEAD}{rest}")
}

fn refusals(failure: &registry_breg::CompileFailure) -> Vec<(&str, &str)> {
    failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect()
}

#[test]
fn a_mapping_of_record_types_reads_each_key_as_the_id_in_id_order() {
    let written = project(&format!(
        "recordTypes:\n{}{}",
        entry("zeta", "zetas"),
        entry("alpha", "alphas")
    ));
    let project = parse_project_yaml(written.as_bytes()).expect("the mapping reads");
    let ids = project
        .entities
        .iter()
        .map(|record_type| record_type.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["alpha", "zeta"]);
}

#[test]
fn a_repeated_record_type_key_is_refused_at_the_repeating_key() {
    let written = project(&format!(
        "recordTypes:\n{}{}",
        entry("entry", "entries"),
        entry("entry", "others")
    ));
    let failure = parse_project_yaml(written.as_bytes()).expect_err("a repeated key is refused");
    assert_eq!(
        refusals(&failure),
        vec![("yaml.duplicate-key", "project.recordTypes.entry")],
        "{failure:?}"
    );
}

#[test]
fn the_record_type_list_shape_is_refused_with_the_mapping_named() {
    let written = project(
        "recordTypes:
  - id: entry
    primaryDataset: test-dataset
    route: entries
",
    );
    let failure = parse_project_yaml(written.as_bytes()).expect_err("the list is refused");
    assert_eq!(
        refusals(&failure),
        vec![("config.removed-key", "project.recordTypes[0].id")],
        "{failure:?}"
    );
    assert!(
        failure.diagnostics()[0]
            .message
            .contains("recordTypes: {RECORD_TYPE_ID: {"),
        "the refusal names the mapping shape: {failure:?}"
    );
}

#[test]
fn an_inner_id_in_a_record_type_is_refused() {
    let written = project(&format!(
        "recordTypes:\n{}",
        entry("entry", "entries").replace("    route:", "    id: entry\n    route:")
    ));
    let failure = parse_project_yaml(written.as_bytes()).expect_err("an inner id is refused");
    assert_eq!(
        refusals(&failure),
        vec![("config.removed-key", "project.recordTypes.entry.id")],
        "{failure:?}"
    );
}

#[test]
fn the_extension_list_shape_is_refused_with_the_mapping_named() {
    let written = module(
        "extendRecordTypes:
  - recordType: entry
    fields: []
",
    );
    let failure = parse_module_yaml(written.as_bytes()).expect_err("the list is refused");
    assert_eq!(
        refusals(&failure),
        vec![(
            "config.removed-key",
            "module.extendRecordTypes[0].recordType"
        )],
        "{failure:?}"
    );
    assert!(
        failure.diagnostics()[0]
            .message
            .contains("extendRecordTypes: {RECORD_TYPE_ID: {"),
        "the refusal names the mapping shape: {failure:?}"
    );
}

#[test]
fn an_inner_record_type_in_an_extension_is_refused() {
    let written = module(
        "extendRecordTypes:
  entry:
    recordType: entry
    fields: []
",
    );
    let failure = parse_module_yaml(written.as_bytes()).expect_err("an inner id is refused");
    assert_eq!(
        refusals(&failure),
        vec![(
            "config.removed-key",
            "module.extendRecordTypes.entry.recordType"
        )],
        "{failure:?}"
    );
}

#[test]
fn a_repeated_extension_key_is_refused_at_the_repeating_key() {
    let written = module(
        "extendRecordTypes:
  entry:
    fields: []
  entry:
    fields: []
",
    );
    let failure = parse_module_yaml(written.as_bytes()).expect_err("a repeated key is refused");
    assert_eq!(
        refusals(&failure),
        vec![("yaml.duplicate-key", "module.extendRecordTypes.entry")],
        "{failure:?}"
    );
}

#[test]
fn a_mapping_of_extensions_reads_each_key_as_the_extended_type_in_id_order() {
    let written = module(
        "extendRecordTypes:
  zeta:
    fields: []
  alpha:
    fields: []
",
    );
    let module = parse_module_yaml(written.as_bytes()).expect("the mapping reads");
    let ids = module
        .extend_entities
        .iter()
        .map(|extension| extension.entity.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["alpha", "zeta"]);
}

#[test]
fn a_mapping_of_module_locks_reads_each_key_as_the_module_id_in_id_order() {
    let written = project(&format!(
        "modules:\n  zeta:\n    version: 0.1.0\n    digest: {DIGEST}\n  alpha:\n    version: 0.2.0\n    digest: {DIGEST}\n"
    ));
    let project = parse_project_yaml(written.as_bytes()).expect("the mapping reads");
    let ids = project
        .modules
        .iter()
        .map(|lock| lock.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["alpha", "zeta"]);
}

#[test]
fn the_module_lock_list_shape_is_refused_with_the_mapping_named() {
    let written = project(&format!(
        "modules:\n  - id: core\n    version: 0.1.0\n    digest: {DIGEST}\n"
    ));
    let failure = parse_project_yaml(written.as_bytes()).expect_err("the list is refused");
    assert_eq!(
        refusals(&failure),
        vec![("config.removed-key", "project.modules[0].id")],
        "{failure:?}"
    );
    assert!(
        failure.diagnostics()[0]
            .message
            .contains("modules: {MODULE_ID: {"),
        "the refusal names the mapping shape: {failure:?}"
    );
}

#[test]
fn an_inner_id_in_a_module_lock_is_refused() {
    let written = project(&format!(
        "modules:\n  core:\n    id: core\n    version: 0.1.0\n    digest: {DIGEST}\n"
    ));
    let failure = parse_project_yaml(written.as_bytes()).expect_err("an inner id is refused");
    assert_eq!(
        refusals(&failure),
        vec![("config.removed-key", "project.modules.core.id")],
        "{failure:?}"
    );
}

#[test]
fn a_repeated_module_lock_key_is_refused_at_the_repeating_key() {
    let written = project(&format!(
        "modules:\n  core:\n    version: 0.1.0\n    digest: {DIGEST}\n  core:\n    version: 0.2.0\n    digest: {DIGEST}\n"
    ));
    let failure = parse_project_yaml(written.as_bytes()).expect_err("a repeated key is refused");
    assert_eq!(
        refusals(&failure),
        vec![("yaml.duplicate-key", "project.modules.core")],
        "{failure:?}"
    );
}
