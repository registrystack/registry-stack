fn derive(facts, selectors, evaluation_context) {
    if evaluation_context["parameters"]["matching_policy"] !=
       "exact-opaque-reference-v1" {
        throw("derivation_input_error");
    }

    let candidate = selectors["candidate-parent"];
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
       namespace != evaluation_context["parameters"]["candidate_reference_namespace"] ||
       contract != evaluation_context["parameters"]["relationship_set_contract"] {
        throw("derivation_input_error");
    }
    [#{
        concept_id: "urn:gov:example:concept:registered-parent-relationship-confirmed",
        value: list_contains(
            parent_references,
            candidate["values"]["person_reference"]
        )
    }]
}
