// SPDX-License-Identifier: Apache-2.0

//! A project's `datasets`, `vocabularies`, `statisticalDatasets`,
//! `reviewAuthorities`, `evidenceProviders`, `externalRecordTypes`,
//! `externalProjections` and `externalViews` are mappings keyed by id
//! (CFG-ID-5). The key is the id, an inner id and the old list shape are
//! refused with the mapping named, a repeated key is refused at the repeating
//! key, and entries are held in id order whatever order the file writes them in.

use registry_breg::contract::{parse_project_yaml, RegistryProject};

const PROJECT_HEAD: &str = "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: collection-example
  version: '1'
  defaultLanguage: en
  canonicalBaseIri: https://collection-example.example.test
";

/// Each collection with the body of one entry, without its id.
const COLLECTIONS: [(&str, &str); 8] = [
    ("datasets", "{}"),
    ("vocabularies", "{values: [a, b]}"),
    ("reviewAuthorities", "{protocol: id.registrystack.org/protocols/review/v1}"),
    (
        "statisticalDatasets",
        "{unit: entry, population: active eq true, period: {type: flow, field: recorded-on, granularity: month, firstPeriod: 2025-01}, dimensions: [active]}",
    ),
    (
        "evidenceProviders",
        "{contracts: contracts.json, subjectResolution: trusted-provider-exact-selector}",
    ),
    (
        "externalRecordTypes",
        "{authority: 'urn:example:source', identifierScheme: 'urn:example:key', fields: [{id: label, type: string, classification: internal}]}",
    ),
    (
        "externalProjections",
        "{recordType: subject, sourceRoute: by-key, sourceRouteVersion: '1', purpose: consultation, scope: subjects, mode: indexed, cardinality: one, fields: [label], cacheTtlSeconds: 600}",
    ),
    (
        "externalViews",
        "{recordType: local, links: [{id: subject, projection: subjects, fromField: key}]}",
    ),
];

fn written(collection: &str, body: &str, keys: &[&str]) -> String {
    let entries: String = keys
        .iter()
        .map(|key| format!("  {key}: {body}\n"))
        .collect();
    format!("{PROJECT_HEAD}{collection}:\n{entries}")
}

fn ids(project: &RegistryProject, collection: &str) -> Vec<String> {
    match collection {
        "datasets" => project.datasets.iter().map(|i| i.id.clone()).collect(),
        "vocabularies" => project.vocabularies.iter().map(|i| i.id.clone()).collect(),
        "reviewAuthorities" => project
            .review_authorities
            .iter()
            .map(|i| i.id.clone())
            .collect(),
        "statisticalDatasets" => project
            .statistical_datasets
            .iter()
            .map(|i| i.id.as_str().to_owned())
            .collect(),
        "evidenceProviders" => project
            .evidence_providers
            .iter()
            .map(|i| i.id.clone())
            .collect(),
        "externalRecordTypes" => project
            .external_record_types
            .iter()
            .map(|i| i.id.as_str().to_owned())
            .collect(),
        "externalProjections" => project
            .external_projections
            .iter()
            .map(|i| i.id.as_str().to_owned())
            .collect(),
        "externalViews" => project
            .external_views
            .iter()
            .map(|i| i.id.as_str().to_owned())
            .collect(),
        other => panic!("unknown collection {other}"),
    }
}

fn refusals(failure: &registry_breg::CompileFailure) -> Vec<(&str, &str)> {
    failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect()
}

#[test]
fn each_collection_reads_its_keys_as_ids_in_id_order() {
    for (collection, body) in COLLECTIONS {
        let source = written(collection, body, &["zeta", "alpha"]);
        let project = parse_project_yaml(source.as_bytes())
            .unwrap_or_else(|failure| panic!("{collection} reads: {failure:?}"));
        assert_eq!(ids(&project, collection), ["alpha", "zeta"], "{collection}");
    }
}

#[test]
fn a_repeated_key_is_refused_at_the_repeating_key() {
    for (collection, body) in COLLECTIONS {
        let source = written(collection, body, &["go", "go"]);
        let failure = parse_project_yaml(source.as_bytes()).expect_err("a repeated key is refused");
        assert_eq!(
            refusals(&failure),
            vec![(
                "yaml.duplicate-key",
                format!("project.{collection}.go").as_str()
            )],
            "{collection}: {failure:?}"
        );
    }
}

#[test]
fn the_list_shape_is_refused_with_the_mapping_named() {
    for (collection, _) in COLLECTIONS {
        let source = format!("{PROJECT_HEAD}{collection}:\n  - id: go\n");
        let failure = parse_project_yaml(source.as_bytes()).expect_err("the list is refused");
        assert_eq!(
            refusals(&failure),
            vec![(
                "config.removed-key",
                format!("project.{collection}[0].id").as_str()
            )],
            "{collection}: {failure:?}"
        );
        assert!(
            failure.diagnostics()[0]
                .message
                .contains(&format!("{collection}: {{")),
            "{collection} refusal names the mapping shape: {failure:?}"
        );
    }
}

#[test]
fn an_inner_id_is_refused() {
    for (collection, body) in COLLECTIONS {
        let body = body
            .replacen('{', "{id: go, ", 1)
            .replace("{id: go, }", "{id: go}");
        let source = written(collection, &body, &["go"]);
        let failure = parse_project_yaml(source.as_bytes()).expect_err("an inner id is refused");
        assert_eq!(
            refusals(&failure),
            vec![(
                "config.removed-key",
                format!("project.{collection}.go.id").as_str()
            )],
            "{collection}: {failure:?}"
        );
    }
}
