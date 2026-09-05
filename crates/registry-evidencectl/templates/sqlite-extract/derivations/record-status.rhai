// Bounded derivation: it turns the extracted facts into the answers the
// question declares, and nothing else. It never sees the caller's reference,
// the statement, or any row value the extraction left behind.
fn answer(facts, selectors, context) {
    // `required` fails the request with the named reason when a declared fact
    // is missing, rather than deriving an answer from an absent value.
    let count = required(
        facts["qualifying_record_count"],
        "qualifying_record_count_missing"
    );

    // The one answer the question allows to be disclosed.
    #{condition_satisfied: count > 0}
}
