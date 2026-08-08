// There is no returned-reference check here, and that is the point. An HTTP
// source echoes an identifier back and the derivation has to compare it with
// the authorized selector. Rust binds the authorized reference into this
// statement's own WHERE clause, so a row can only be the subject's; the
// comparison would be checking a guarantee the transport already made.
fn derive(facts, selectors, evaluation_context) {
    let count = required(facts["active_licence_count"], "required_fact_missing");
    // The count itself is never disclosed. How many licences a registrant holds
    // is a fact about their practice; whether they hold one is the question
    // that was asked.
    [#{
        concept_id: "urn:gov:example:concept:professional-licence-active",
        value: count > 0
    }]
}
