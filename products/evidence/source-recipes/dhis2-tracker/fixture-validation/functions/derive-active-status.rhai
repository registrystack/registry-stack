fn derive(facts, selectors, context) {
    [#{output: "active", value: facts["status_code"] == "ACTIVE"}]
}
