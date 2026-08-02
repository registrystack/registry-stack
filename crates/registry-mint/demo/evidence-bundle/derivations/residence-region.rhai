fn derive(facts, selectors, evaluation_context) {
    let mapped = codelist_lookup(
        evaluation_context.codelists["region-map"],
        required(facts.official_residence_code, "required_fact_missing")
    );
    [#{
        concept_id: "urn:example:demo:concept:residence-region",
        value: required(mapped, "unknown_controlled_code")
    }]
}
