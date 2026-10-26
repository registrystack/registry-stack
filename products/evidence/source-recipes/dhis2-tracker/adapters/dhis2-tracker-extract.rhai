// Pager consistency, exact returned identity, and unique-match extraction
// remain reviewed recipe logic. The returned identity also remains a private
// fact for assertion semantics that need it.
fn extract(source_response, selectors, context) {
    let parameters = context["parameters"];
    let pager = source_response["pager"];
    let records = source_response["trackedEntities"];
    let expected_page_count =
        (pager["total"] + pager["pageSize"] - 1) / pager["pageSize"];
    if pager["pageCount"] != expected_page_count { throw("source_protocol_error"); }
    if pager["total"] == 0 {
        if records.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if pager["total"] > 1 {
        if records.len != 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if records.len != 1 { throw("source_protocol_error"); }

    let record = records[0];
    if is_missing(record["trackedEntity"]) { throw("source_protocol_error"); }
    let returned_reference = record["trackedEntity"];
    let expected_reference = selectors["subject"]["values"]["record_reference"];
    if type_of(returned_reference) != type_of(expected_reference) ||
       returned_reference != expected_reference {
        throw("source_protocol_error");
    }
    let found_status = false;
    let status_code = ();
    for attribute in record["attributes"] {
        if attribute["attribute"] == parameters["statusAttribute"] {
            if found_status { throw("source_protocol_error"); }
            found_status = true;
            status_code = attribute["value"];
        }
    }
    if !found_status { throw("source_protocol_error"); }
    #{outcome: "match", facts: #{
        record_reference: returned_reference,
        status_code: status_code
    }}
}
