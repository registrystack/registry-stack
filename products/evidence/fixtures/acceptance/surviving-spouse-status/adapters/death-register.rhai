fn extract(source_response, context) {
    let parameters = context["parameters"];
    required(context["prior_facts"]["civil_record_reference"], "required_fact_missing");
    // Same allowlist assertion as the union register: this member declared one
    // input and must be handed exactly that one.
    if !is_missing(context["prior_facts"]["reference_namespace"]) {
        throw("source_protocol_error");
    }
    // A complete register that holds no death record still resolves the person
    // and answers `not-recorded`. Failing to resolve at all is a different
    // thing, and it is not a fact about the subject.
    if source_response["record_found"] != true {
        return #{outcome: "no_match"};
    }
    if is_missing(source_response["death_subject_reference"]) ||
       is_missing(source_response["date_of_death"]) ||
       is_missing(source_response["death_record_contract"]) ||
       is_missing(source_response["death_record_complete"]) {
        throw("source_protocol_error");
    }
    if source_response["death_record_contract"] != parameters["deathRegisterContract"] {
        throw("source_protocol_error");
    }
    // The reference this register answered for is carried, not compared. Only
    // the derivation sees the search FactSet as well, so only the derivation
    // can tell whether two registers answered about one subject.
    #{outcome: "match", facts: #{
        death_subject_reference: source_response["death_subject_reference"],
        date_of_death: source_response["date_of_death"],
        death_record_contract: source_response["death_record_contract"],
        death_record_complete: source_response["death_record_complete"]
    }}
}
