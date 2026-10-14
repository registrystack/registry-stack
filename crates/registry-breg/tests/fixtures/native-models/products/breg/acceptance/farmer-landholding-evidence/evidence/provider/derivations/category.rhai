fn derive(facts, selectors, context) {
    [#{concept_id: "urn:example:farmer:category", value: required(facts["category"], "required_fact_missing")}]
}
