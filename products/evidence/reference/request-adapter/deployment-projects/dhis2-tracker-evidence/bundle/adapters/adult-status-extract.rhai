// The response schema has already refused any envelope outside the declared
// pager and record shape. What is left is the part a shape cannot state:
// requiring the page count to agree with the total, so a truncated or
// inconsistent envelope is not read as an authoritative no-match or unique
// match, and matching the one attribute this requirement names.
fn extract(source_response, parameters) {
    let pager = source_response["pager"];
    let records = source_response["trackedEntities"];
    let total = pager["total"];
    if pager["pageCount"] != (total + pager["pageSize"] - 1) / pager["pageSize"] {
        throw("source_protocol_error");
    }

    if total == 0 {
        if records.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if records.len != 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if records.len != 1 { throw("source_protocol_error"); }

    let record = records[0];
    // The attribute is named by an adapter parameter, and a register that
    // reports it twice has no single value to read, so this loop stays.
    let date_of_birth = ();
    let matches = 0;
    for attribute in record["attributes"] {
        if attribute["attribute"] == parameters["dateOfBirthAttribute"] {
            date_of_birth = attribute["value"];
            matches += 1;
        }
    }
    if matches > 1 { throw("source_protocol_error"); }

    let facts = #{record_reference: record["trackedEntity"]};
    if matches == 1 {
        facts["date_of_birth"] = date_of_birth;
    }

    #{outcome: "match", facts: facts}
}
