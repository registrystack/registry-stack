fn derive(facts, selectors, context) {
    [#{concept_id: "urn:example:farmer:active", value: required(facts["active"], "required_fact_missing")}]
}
