fn extract(source_response, context) {
    let parameters = context["parameters"];
    let total = source_response["total"];
    let records = source_response["records"];
    if records.len > parameters["resultLimit"] {
        throw("source_protocol_error");
    }
    if total == 0 {
        if records.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if records.len < 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if records.len != 1 { throw("source_protocol_error"); }
    let record = records[0];
    // The shape cannot require this of every record, because the ambiguous
    // page is decided before any record is read. A single matched record that
    // omits the reference is a source this adapter does not understand.
    if is_missing(record["civil_record_reference"]) {
        throw("source_protocol_error");
    }
    if record["reference_namespace"] != parameters["referenceNamespace"] {
        throw("source_protocol_error");
    }
    // Both fields become the search FactSet. Only the subset each fetch member
    // names in factInputs is handed on; the namespace stays here and in the
    // derivation, and never reaches a register.
    #{outcome: "match", facts: #{
        civil_record_reference: record["civil_record_reference"],
        reference_namespace: record["reference_namespace"]
    }}
}
