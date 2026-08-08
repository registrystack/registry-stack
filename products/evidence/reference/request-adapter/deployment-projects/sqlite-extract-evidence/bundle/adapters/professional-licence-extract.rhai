// The statement returns one row for each registrant carrying the requested
// reference, and on that row the number of licences the registrant currently
// holds. Uniqueness is therefore decided by counting rows, and there is no
// pagination envelope to reconcile: a statement either matched the whole
// extract or it did not, so the result is complete by construction.
//
// Nothing here inspects a licence, because no licence reached this script. The
// aggregate crossed the source boundary alone.

fn extract(source_response, context) {
    let rows = source_response["rows"];

    if rows.len == 0 {
        return #{outcome: "no_match"};
    }
    // Two registrants filed under one reference. Answering from either would be
    // asserting something about a registrant nobody identified.
    if rows.len > 1 {
        return #{outcome: "ambiguous"};
    }

    #{
        outcome: "match",
        facts: #{active_licence_count: rows[0]["active_licence_count"]}
    }
}
