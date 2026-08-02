fn derive(facts, selectors, evaluation_context) {
    [#{
        concept_id: "urn:example:fixture:concept:boolean",
        value: required(facts.marker, "required_fact_missing") == "accepted"
    }]
}
