// Extraction validates one exact child-event result and returns only the
// configured complete parent-reference set. Relationship comparison belongs
// to the selector-aware requirement derivation.
//
// The response schema has already refused anything outside the declared shape,
// so what remains is the part a shape cannot state: how total relates to the
// records returned, which values must agree with the adapter parameters, and
// how many distinct parent references a registered record must carry.

fn extract(source_response, parameters) {
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
       result["status"] != parameters["registeredStatus"] {
        throw("source_protocol_error");
    }

    let parent_references = [];
    for field in parameters["parentReferenceFields"] {
        if result["declaration"].contains(field) {
            let reference = result["declaration"][field];
            if list_contains(parent_references, reference) {
                throw("source_protocol_error");
            }
            parent_references.push(reference);
        }
    }
    if parent_references.len < parameters["minimumParentReferences"] ||
       parent_references.len > parameters["maximumParentReferences"] {
        throw("source_protocol_error");
    }

    #{
        outcome: "match",
        facts: #{
            record_tracking_id: result["trackingId"],
            parent_references: parent_references,
            reference_namespace: parameters["parentReferenceNamespace"],
            relationship_set_contract: parameters["relationshipSetContract"],
            relationship_set_complete: true
        }
    }
}
