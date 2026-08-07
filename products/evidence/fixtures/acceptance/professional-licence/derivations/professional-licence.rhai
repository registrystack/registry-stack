fn derive(facts, selectors, evaluation_context) {
    let starts = parse_date(required(facts.valid_from, "required_fact_missing"));
    let ends = parse_date(required(facts.valid_until, "required_fact_missing"));
    let state = required(facts.licence_state, "required_fact_missing");
    let current = evaluation_context.legal_local_date;
    let active =
        state == evaluation_context.parameters.active_state &&
        compare_dates(current, starts) >= 0 &&
        compare_dates(current, ends) <= 0;
    let remaining_days = integer_to_decimal(days_between(current, ends));
    let category = bucket_number(
        remaining_days,
        evaluation_context.parameters.expiry_buckets
    );
    [
        #{
            concept_id: "urn:example:fixture:concept:licence-active",
            value: active
        },
        #{
            concept_id: "urn:example:fixture:concept:licence-expiry-category",
            value: category
        }
    ]
}
