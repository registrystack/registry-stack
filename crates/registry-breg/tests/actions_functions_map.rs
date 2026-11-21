// SPDX-License-Identifier: Apache-2.0

//! `actions` and `functions` are mappings keyed by id (CFG-ID-5), in a project
//! and in a module. The key is the id, an inner id and the old list shape are
//! refused with the mapping named, a repeated key is refused at the repeating
//! key, and entries are held in id order whatever order the file writes them in.

use registry_breg::contract::{parse_module_yaml, parse_project_yaml};

const PROJECT_HEAD: &str = "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: action-example
  version: '1'
  defaultLanguage: en
  canonicalBaseIri: https://action-example.example.test
datasets:
  - id: test-dataset
";

const MODULE_HEAD: &str = "apiVersion: id.registrystack.org/formats/breg/module/v1alpha1
kind: BRegModule
id: extension
version: 0.1.0
";

fn function(key: &str) -> String {
    format!(
        "  {key}:\n    runtime: rhai\n    source: plans/{key}.rhai\n    entrypoint: plan\n    abi: registry.action-plan/v1\n"
    )
}

fn action(key: &str) -> String {
    format!(
        "  {key}:\n    execution: {{mode: immediate}}\n    inputs: []\n    plan:\n      type: function\n      function: plan\n      inputs: []\n      writes: []\n"
    )
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
fn mappings_of_actions_and_functions_read_each_key_as_the_id_in_id_order() {
    let written = project(&format!(
        "functions:\n{}{}actions:\n{}{}",
        function("zeta"),
        function("alpha"),
        action("zeta"),
        action("alpha"),
    ));
    let project = parse_project_yaml(written.as_bytes()).expect("the mappings read");
    let functions = project
        .functions
        .iter()
        .map(|f| f.id.as_str())
        .collect::<Vec<_>>();
    let actions = project
        .actions
        .iter()
        .map(|a| a.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(functions, ["alpha", "zeta"]);
    assert_eq!(actions, ["alpha", "zeta"]);

    let written = module(&format!(
        "functions:\n{}{}actions:\n{}{}",
        function("zeta"),
        function("alpha"),
        action("zeta"),
        action("alpha"),
    ));
    let module = parse_module_yaml(written.as_bytes()).expect("the mappings read");
    let functions = module
        .functions
        .iter()
        .map(|f| f.id.as_str())
        .collect::<Vec<_>>();
    let actions = module
        .actions
        .iter()
        .map(|a| a.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(functions, ["alpha", "zeta"]);
    assert_eq!(actions, ["alpha", "zeta"]);
}

#[test]
fn a_repeated_action_or_function_key_is_refused_at_the_repeating_key() {
    let written = project(&format!("actions:\n{}{}", action("go"), action("go")));
    let failure = parse_project_yaml(written.as_bytes()).expect_err("a repeated key is refused");
    assert_eq!(
        refusals(&failure),
        vec![("yaml.duplicate-key", "project.actions.go")],
        "{failure:?}"
    );
    let written = project(&format!("functions:\n{}{}", function("go"), function("go")));
    let failure = parse_project_yaml(written.as_bytes()).expect_err("a repeated key is refused");
    assert_eq!(
        refusals(&failure),
        vec![("yaml.duplicate-key", "project.functions.go")],
        "{failure:?}"
    );
    let written = module(&format!("actions:\n{}{}", action("go"), action("go")));
    let failure = parse_module_yaml(written.as_bytes()).expect_err("a repeated key is refused");
    assert_eq!(
        refusals(&failure),
        vec![("yaml.duplicate-key", "module.actions.go")],
        "{failure:?}"
    );
    let written = module(&format!("functions:\n{}{}", function("go"), function("go")));
    let failure = parse_module_yaml(written.as_bytes()).expect_err("a repeated key is refused");
    assert_eq!(
        refusals(&failure),
        vec![("yaml.duplicate-key", "module.functions.go")],
        "{failure:?}"
    );
}

#[test]
fn the_list_shapes_are_refused_with_the_mapping_named() {
    for (collection, body, example) in [
        (
            "actions",
            "actions:\n  - id: go\n    execution: {mode: immediate}\n",
            "actions: {ACTION_ID: {",
        ),
        (
            "functions",
            "functions:\n  - id: go\n    runtime: rhai\n",
            "functions: {FUNCTION_ID: {",
        ),
    ] {
        for (scope, failure) in [
            (
                "project",
                parse_project_yaml(project(body).as_bytes()).expect_err("the list is refused"),
            ),
            (
                "module",
                parse_module_yaml(module(body).as_bytes()).expect_err("the list is refused"),
            ),
        ] {
            assert_eq!(
                refusals(&failure),
                vec![(
                    "config.removed-key",
                    format!("{scope}.{collection}[0].id").as_str()
                )],
                "{failure:?}"
            );
            assert!(
                failure.diagnostics()[0].message.contains(example),
                "the refusal names the mapping shape: {failure:?}"
            );
        }
    }
}

#[test]
fn an_inner_id_in_an_action_or_function_is_refused() {
    for (collection, entry) in [("actions", action("go")), ("functions", function("go"))] {
        let entry = entry.replacen(":\n", ":\n    id: go\n", 1);
        let written = project(&format!("{collection}:\n{entry}"));
        let failure = parse_project_yaml(written.as_bytes()).expect_err("an inner id is refused");
        assert_eq!(
            refusals(&failure),
            vec![(
                "config.removed-key",
                format!("project.{collection}.go.id").as_str()
            )],
            "{failure:?}"
        );
        let written = module(&format!("{collection}:\n{entry}"));
        let failure = parse_module_yaml(written.as_bytes()).expect_err("an inner id is refused");
        assert_eq!(
            refusals(&failure),
            vec![(
                "config.removed-key",
                format!("module.{collection}.go.id").as_str()
            )],
            "{failure:?}"
        );
    }
}
