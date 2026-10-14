fn derive(facts, selectors, context) {
    [#{output: "is-parent", value: list_contains(facts.parents, selectors["candidate-parent"].values["record-id"])}]
}
