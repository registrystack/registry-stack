fn extract(source_response, context) {
    let parameters = context["parameters"];
    if source_response.len() != 2 ||
       !source_response.contains("total") ||
       !source_response.contains("results") ||
       type_of(source_response.total) != "i64" ||
       source_response.total < 0 ||
       source_response.results.len > parameters["resultLimit"] {
        throw("source_protocol_error");
    }

    if source_response.total == 0 {
        if source_response.results.len != 0 {
            throw("source_protocol_error");
        }
        return #{ outcome: "no_match" };
    }

    // total is the register's count of holder records and is a cardinality
    // guard only. Above one the request selected more than one holder, so the
    // single returned result is never read.
    if source_response.total > 1 {
        if source_response.results.len < 1 {
            throw("source_protocol_error");
        }
        return #{ outcome: "ambiguous" };
    }

    if source_response.results.len != 1 {
        throw("source_protocol_error");
    }

    let holder = source_response.results[0];
    if !holder.contains("holder.relatedTotal") {
        return #{ outcome: "match", facts: #{} };
    }

    // holder.relatedTotal is a second register-supplied count, consumed as the
    // value of the fact rather than as a cardinality guard. Zero is the counted
    // answer here, not an absence, because the preceding stage already resolved
    // this holder in this register.
    let related = holder["holder.relatedTotal"];
    if type_of(related) != "i64" ||
       related < 0 ||
       related > parameters["maximumRelatedTotal"] {
        throw("source_protocol_error");
    }

    #{ outcome: "match", facts: #{ related_record_count: related } }
}
