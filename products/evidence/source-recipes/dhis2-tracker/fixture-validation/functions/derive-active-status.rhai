fn derive(facts, selectors, context) {
    if facts["record_reference"] != selectors["subject"]["values"]["record_reference"] {
        throw("derivation_input_error");
    }
    [#{output: "active", value: facts["status_code"] == "ACTIVE"}]
}
