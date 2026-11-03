fn derive(facts, selectors, context) {
    [#{output: "active", value: required(facts["active"], "required_fact_missing")}]
}
