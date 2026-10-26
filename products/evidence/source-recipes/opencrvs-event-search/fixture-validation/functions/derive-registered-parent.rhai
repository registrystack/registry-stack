fn derive(facts, selectors, context) {
    if !facts["relationship_set_complete"] {
        throw("derivation_input_error");
    }
    [#{output: "registered-parent-present", value: facts["parent_references"].len > 0}]
}
