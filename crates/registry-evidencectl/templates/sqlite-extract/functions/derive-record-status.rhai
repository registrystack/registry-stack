// Map the private fact to the sole declared assertion output.
fn derive(facts, selectors, context) {
    [#{output: "satisfied", value: facts["record-count"] > 0}]
}
