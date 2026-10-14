fn derive(facts, selectors, context) {
    [#{output: "healthcare-provider-record-active", value: facts.active && facts["provider-type"]}]
}
