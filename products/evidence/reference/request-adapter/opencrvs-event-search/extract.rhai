// Extraction validates one exact child-event result and returns only the
// configured complete parent-reference set. Relationship comparison belongs
// to the selector-aware requirement derivation.

fn extract(source_response, parameters) {
    if len(source_response) != 2 ||
       !source_response.contains("total") ||
       !source_response.contains("results") ||
       type_of(source_response["total"]) != "i64" ||
       source_response["total"] < 0 ||
       type_of(source_response["results"]) != "array" ||
       source_response["results"].len > parameters["resultLimit"] {
        throw("source_protocol_error");
    }

    let total = source_response["total"];
    let results = source_response["results"];
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
    if !result.contains("type") ||
       !result.contains("status") ||
       result["type"] != parameters["eventType"] ||
       result["status"] != parameters["registeredStatus"] ||
       !result.contains("trackingId") ||
       type_of(result["trackingId"]) != "string" ||
       !result.contains("declaration") ||
       type_of(result["declaration"]) != "map" {
        throw("source_protocol_error");
    }

    let parent_references = [];
    for field in parameters["parentReferenceFields"] {
        if result["declaration"].contains(field) {
            let reference = result["declaration"][field];
            if type_of(reference) != "string" || reference == "" ||
               list_contains(parent_references, reference) {
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
