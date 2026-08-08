fn extract(source_response, context) {
    let parameters = context["parameters"];
    required(context["prior_facts"]["civil_record_reference"], "required_fact_missing");
    // factInputs is an allowlist, not a convenience. The other search fact was
    // not declared for this member, so its arrival here would mean the whole
    // search FactSet had been handed to a register that never asked for it.
    if !is_missing(context["prior_facts"]["reference_namespace"]) {
        throw("source_protocol_error");
    }
    if source_response["record_found"] != true {
        return #{outcome: "no_match"};
    }
    if is_missing(source_response["union_events"]) ||
       is_missing(source_response["union_set_contract"]) ||
       is_missing(source_response["union_set_complete"]) {
        throw("source_protocol_error");
    }
    let events = source_response["union_events"];
    if events.len > parameters["maximumUnionEvents"] {
        throw("source_protocol_error");
    }
    if source_response["union_set_contract"] != parameters["unionSetContract"] {
        throw("source_protocol_error");
    }
    // union_set_complete is carried, not enforced. A register that admits an
    // incomplete set has answered honestly; refusing to read a partial history
    // as a whole one is the derivation's decision, not this adapter's.
    #{outcome: "match", facts: #{
        union_events: events,
        union_set_contract: source_response["union_set_contract"],
        union_set_complete: source_response["union_set_complete"]
    }}
}
