// Extract one exact event and its configured complete parent-reference set.
// Returned identity is checked against the minimized authorized selector before
// any private facts are released to assertion derivation.
fn extract(source_response, selectors, context) {
    let parameters = context["parameters"];
    let total = source_response["total"];
    let results = source_response["results"];
    if results.len > parameters["resultLimit"] { throw("source_protocol_error"); }
    if total == 0 {
        if results.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if results.len < 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if results.len != 1 { throw("source_protocol_error"); }

    let result = results[0];
    if result["type"] != parameters["eventType"] ||
       result["status"] != parameters["registeredStatus"] ||
       is_missing(result["trackingId"]) {
        throw("source_protocol_error");
    }
    let returned_tracking_id = result["trackingId"];
    let expected_tracking_id = selectors["child"]["values"]["tracking_id"];
    if type_of(returned_tracking_id) != type_of(expected_tracking_id) ||
       returned_tracking_id != expected_tracking_id {
        throw("source_protocol_error");
    }
    let parent_references = [];
    for field in parameters["parentReferenceFields"] {
        if result["declaration"].contains(field) {
            let reference = result["declaration"][field];
            if list_contains(parent_references, reference) { throw("source_protocol_error"); }
            parent_references.push(reference);
        }
    }
    if parent_references.len < parameters["minimumParentReferences"] ||
       parent_references.len > parameters["maximumParentReferences"] {
        throw("source_protocol_error");
    }
    #{outcome: "match", facts: #{
        record_tracking_id: returned_tracking_id,
        parent_references: parent_references,
        reference_namespace: parameters["parentReferenceNamespace"],
        relationship_set_contract: parameters["relationshipSetContract"],
        relationship_set_complete: true
    }}
}
