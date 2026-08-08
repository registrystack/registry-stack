fn derive(facts, selectors, evaluation_context) {
    let parameters = evaluation_context["parameters"];
    if parameters["matching_policy"] != "exact-opaque-reference-membership-v1" || parameters["legal_authority_attestation"] != "urn:example:fixture:governance:legal-parent-register:v1" || facts["returned_child_reference"] != selectors["child"]["values"]["record_reference"] || facts["relationship_set_complete"] != true || facts["reference_namespace"] != parameters["candidate_reference_namespace"] || facts["relationship_set_contract"] != parameters["relationship_set_contract"] { throw("derivation_input_error"); }
    [#{concept_id: "urn:example:fixture:concept:legal-parent-relationship-confirmed", value: list_contains(facts["parent_references"], selectors["candidate-parent"]["values"]["person_reference"])}]
}
