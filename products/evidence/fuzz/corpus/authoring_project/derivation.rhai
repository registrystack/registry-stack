fn derive(facts, selectors, context) {
    [#{output: "operator-active", value: facts.active == true && facts.status == "active"}]
}
