fn derive(facts, selectors, evaluation_context) {
    if facts["record_tracking_id"] !=
       selectors["child"]["values"]["tracking_id"] {
        throw("derivation_input_error");
    }
    let parent_references = required(
        facts["parent_references"],
        "required_fact_missing"
    );
    let complete = required(
        facts["relationship_set_complete"],
        "required_fact_missing"
    );
    let namespace = required(
        facts["reference_namespace"],
        "required_fact_missing"
    );
    let contract = required(
        facts["relationship_set_contract"],
        "required_fact_missing"
    );
    if complete != true ||
       namespace != evaluation_context["parameters"]["reference_namespace"] ||
       contract != evaluation_context["parameters"]["relationship_set_contract"] {
        throw("derivation_input_error");
    }
    let seeds = [];
    for reference in parent_references {
        seeds.push(entity_reference_seed(
            namespace + ":" + reference
        ));
    }
    [#{
        concept_id: "urn:gov:example:concept:registered-parent-references",
        value: seeds
    }]
}
