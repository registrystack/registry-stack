fn derive(facts, selectors, evaluation_context) {
    let date_of_birth = parse_date(required(facts.date_of_birth, "required_fact_missing"));
    let threshold = add_calendar_years(
        date_of_birth,
        evaluation_context.parameters.minimum_age_years
    );
    [#{
        concept_id: "urn:example:fixture:concept:adult-status",
        value: compare_dates(evaluation_context.legal_local_date, threshold) >= 0
    }]
}
