fn derive(facts, selectors, context) {
    if facts["beneficiary-reference"] != "Patient/" + selectors.patient.values.patient_id {
        throw("derivation_input_error");
    }
    [#{output: "coverage-record-reports-active", value: facts.status == "active"}]
}
