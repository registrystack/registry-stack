fn extract(response, selectors, context) {
    if response.total == 0 { return #{outcome: "no_match"}; }
    if response.total != 1 { return #{outcome: "ambiguous"}; }
    // The source must return exactly the canonical identifier requested.
    if required(response.reference, "required_fact_missing") != selectors["farmer"]["values"]["farmer-number"] {
        return #{outcome: "no_match"};
    }
    let facts = #{};
    facts[context.parameters.fact] = required(response[context.parameters.fact], "required_fact_missing");
    #{outcome: "match", facts: facts}
}
