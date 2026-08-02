// Requirement derivation. Reduces the extracted facts to the single reviewed
// concept the requester is authorized to learn. The event date enters here and
// never leaves: only the boolean below reaches the signed assertion.
fn derive(facts, selectors, evaluation_context) {
    let event_date = parse_date(required(facts.event_date, "required_fact_missing"));
    let threshold_date = add_calendar_years(
        event_date,
        evaluation_context.parameters.threshold_years
    );
    [#{
        concept_id: "{{concept_id}}",
        value: compare_dates(evaluation_context.legal_local_date, threshold_date) >= 0
    }]
}
