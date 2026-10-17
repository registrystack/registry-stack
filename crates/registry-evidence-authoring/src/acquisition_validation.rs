//! Pure structural checks for normalized Evidence acquisition plans.
//!
//! The compiler projects these authored values into the retained runtime
//! configuration. Checking the plan here gives an author field-level findings
//! before that projection, without introducing another lowering path.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::{
    project::{
        value_schema, Acquisition, AcquisitionCapability, EvidenceProject, FetchMember, Source,
    },
    valid_field_name, FieldPath, Finding,
};

const MINIMUM_FETCH_SET_MEMBERS: usize = 2;
const MAXIMUM_FETCH_SET_MEMBERS: usize = 4;
const MAXIMUM_FETCH_SET_FACT_INPUTS: usize = 16;
const MAXIMUM_DERIVATION_FACTS: usize = 64;

/// Validate every normalized acquisition without reading files or lowering it.
#[must_use]
pub fn validate(project: &EvidenceProject) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut initial_sources = BTreeSet::new();
    let mut fetch_sources = BTreeSet::new();
    let mut needs_fetch_set_capability = false;

    for (definition_id, definition) in &project.assertion_definitions {
        let acquisition_path = FieldPath::root()
            .key("assertionDefinitions")
            .map_key(definition_id.to_string())
            .key("acquisition");

        match &definition.acquisition {
            Acquisition::Single { source } => {
                initial_sources.insert(source.to_string());
            }
            Acquisition::SearchThenFetch { search, fetch, .. } => {
                initial_sources.insert(search.to_string());
                fetch_sources.insert(fetch.to_string());
                validate_classic_fetch_bindings(
                    project.sources.get(search),
                    project.sources.get(fetch),
                    fetch,
                    &mut findings,
                );
            }
            Acquisition::SearchThenFetchSet { search, fetch, .. } => {
                needs_fetch_set_capability = true;
                initial_sources.insert(search.to_string());
                fetch_sources.extend(fetch.iter().map(|member| member.source.to_string()));
                validate_fetch_set(project, search, fetch, acquisition_path, &mut findings);
            }
        }
    }

    if needs_fetch_set_capability
        && !project
            .acquisition_capabilities
            .contains(&AcquisitionCapability::SearchThenFetchSet)
    {
        findings.push(Finding::new(
            FieldPath::root().key("acquisitionCapabilities"),
            "acquisition-capability",
            "declare search-then-fetch-set before using that acquisition type",
        ));
    }

    for source_id in &initial_sources {
        if project
            .sources
            .iter()
            .find(|(id, _)| id.as_str() == source_id)
            .is_some_and(|(_, source)| source.selectors.is_empty())
        {
            findings.push(Finding::new(
                source_path(source_id).key("selectors"),
                "acquisition-initial-selectors",
                "single and search Sources must declare selector inputs",
            ));
        }
    }

    // The retained runtime permits prior-fact path bindings only on a source
    // used exclusively after a search. A source used as an initial stage must
    // keep those bindings out even if another definition also fetches it.
    for (source_id, source) in &project.sources {
        let source_id = source_id.to_string();
        if source.facts.len() > MAXIMUM_DERIVATION_FACTS {
            findings.push(Finding::new(
                source_path(&source_id).key("facts"),
                "source-fact-count",
                "a Source must declare at most 64 facts",
            ));
        }
        if fetch_sources.contains(&source_id) && !initial_sources.contains(&source_id) {
            continue;
        }
        for (binding, _) in prior_fact_bindings(source) {
            findings.push(Finding::new(
                binding_path(&source_id, binding),
                "acquisition-prior-fact-role",
                "prior-fact path bindings are permitted only on fetch Sources",
            ));
        }
    }

    findings
}

fn validate_fetch_set(
    project: &EvidenceProject,
    search_id: &registry_platform_yaml::LocalId,
    members: &[FetchMember],
    acquisition_path: FieldPath,
    findings: &mut Vec<Finding>,
) {
    if !(MINIMUM_FETCH_SET_MEMBERS..=MAXIMUM_FETCH_SET_MEMBERS).contains(&members.len()) {
        findings.push(Finding::new(
            acquisition_path.clone().key("fetch"),
            "acquisition-fetch-count",
            "declare between two and four fetch members",
        ));
    }

    let search = project.sources.get(search_id);
    let mut source_ids = BTreeSet::from([search_id.as_str()]);
    let mut merged_names = search
        .into_iter()
        .flat_map(|source| source.facts.keys().map(|name| name.to_string()))
        .collect::<BTreeSet<_>>();
    let mut merged_count = search.map_or(0, |source| source.facts.len());

    for (index, member) in members.iter().enumerate() {
        let member_path = acquisition_path.clone().key("fetch").index(index);
        if !source_ids.insert(member.source.as_str()) {
            findings.push(Finding::new(
                member_path.clone().key("source"),
                "acquisition-source-distinct",
                "each fetch member must name a Source distinct from the search and other members",
            ));
        }

        if member.fact_inputs.is_empty() || member.fact_inputs.len() > MAXIMUM_FETCH_SET_FACT_INPUTS
        {
            findings.push(Finding::new(
                member_path.clone().key("factInputs"),
                "acquisition-fact-input-count",
                "declare between one and 16 search fact inputs",
            ));
        }

        for (input_index, input) in member.fact_inputs.iter().enumerate() {
            let input_path = member_path.clone().key("factInputs").index(input_index);
            if !valid_field_name(input) {
                findings.push(Finding::new(
                    input_path.clone(),
                    "acquisition-fact-input-name",
                    "name a valid bounded search fact",
                ));
            }
            if search.is_some_and(|source| fact(source, input).is_none()) {
                findings.push(Finding::new(
                    input_path,
                    "acquisition-fact-input",
                    "name a fact the search Source always produces",
                ));
            }
        }

        let Some(member_source) = project.sources.get(&member.source) else {
            continue;
        };
        validate_member_bindings(
            search,
            member_source,
            member.source.as_str(),
            Some(
                &member
                    .fact_inputs
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
            ),
            findings,
        );

        merged_count = merged_count.saturating_add(member_source.facts.len());
        for fact_name in member_source.facts.keys() {
            if !merged_names.insert(fact_name.to_string()) {
                findings.push(Finding::new(
                    source_path(member.source.as_str())
                        .key("facts")
                        .map_key(fact_name.to_string()),
                    "acquisition-fact-overlap",
                    "fetch-set stages must declare pairwise-disjoint fact names",
                ));
            }
        }
    }

    if merged_count > MAXIMUM_DERIVATION_FACTS {
        findings.push(Finding::new(
            acquisition_path,
            "acquisition-fact-count",
            "the merged fetch-set facts must contain at most 64 entries",
        ));
    }
}

fn validate_classic_fetch_bindings(
    search: Option<&Source>,
    fetch: Option<&Source>,
    fetch_id: &registry_platform_yaml::LocalId,
    findings: &mut Vec<Finding>,
) {
    if let Some(fetch) = fetch {
        validate_member_bindings(search, fetch, fetch_id.as_str(), None, findings);
    }
}

fn validate_member_bindings(
    search: Option<&Source>,
    fetch: &Source,
    fetch_id: &str,
    declared: Option<&BTreeSet<&str>>,
    findings: &mut Vec<Finding>,
) {
    for (binding, field) in prior_fact_bindings(fetch) {
        let path = binding_path(fetch_id, binding);
        if declared.is_some_and(|allowlist| !allowlist.contains(field)) {
            findings.push(Finding::new(
                path.clone(),
                "acquisition-binding-input",
                "a fetch path binding must name a fact in that member's factInputs",
            ));
        }
        let Some(schema) = search.and_then(|source| fact(source, field)) else {
            if search.is_some() {
                findings.push(Finding::new(
                    path,
                    "acquisition-binding-fact",
                    "a fetch path binding must name a search fact",
                ));
            }
            continue;
        };
        if !scalar_path_fact(schema) {
            findings.push(Finding::new(
                path,
                "acquisition-binding-scalar",
                "a fetch path binding requires a scalar search fact",
            ));
        }
    }
}

fn fact<'a>(source: &'a Source, name: &str) -> Option<&'a Value> {
    source
        .facts
        .iter()
        .find_map(|(id, value)| (id.as_str() == name).then_some(value))
}

fn scalar_path_fact(authored: &Value) -> bool {
    let schema = value_schema(authored);
    schema
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "string" | "integer" | "boolean"))
        || schema
            .get("const")
            .is_some_and(|value| value.is_string() || value.is_i64() || value.is_boolean())
}

fn prior_fact_bindings(source: &Source) -> Vec<(&str, &str)> {
    source
        .request
        .get("pathBindings")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|bindings| bindings.iter())
        .filter_map(|(binding, value)| {
            value
                .get("fact")
                .and_then(Value::as_object)
                .and_then(|fact| fact.get("field"))
                .and_then(Value::as_str)
                .map(|field| (binding.as_str(), field))
        })
        .collect()
}

fn source_path(source: &str) -> FieldPath {
    FieldPath::root().key("sources").map_key(source.to_owned())
}

fn binding_path(source: &str, binding: &str) -> FieldPath {
    source_path(source)
        .key("request")
        .key("pathBindings")
        .map_key(binding.to_owned())
}
