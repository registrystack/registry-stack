fn derive(facts, selectors, evaluation_context) {
    if facts["record_reference"] !=
       selectors["subject"]["values"]["record_reference"] {
        throw("derivation_input_error");
    }
    let starts = parse_date(required(facts["valid_from"], "required_fact_missing"));
    let ends = parse_date(required(facts["valid_until"], "required_fact_missing"));
    let state = required(facts["licence_state"], "required_fact_missing");
    let restricted = required(facts["restriction_recorded"], "required_fact_missing");
    // A validity window that ends before it starts is an inconsistent record
    // rather than an expired licence.
    if compare_dates(ends, starts) < 0 {
        throw("derivation_input_error");
    }
    let current = evaluation_context["legal_local_date"];
    let active =
        state == evaluation_context["parameters"]["active_state"] &&
        !restricted &&
        compare_dates(current, starts) >= 0 &&
        compare_dates(current, ends) <= 0;
    let remaining_days = integer_to_decimal(days_between(current, ends));
    let category = bucket_number(
        remaining_days,
        evaluation_context["parameters"]["expiry_buckets"]
    );
    [
        #{
            concept_id: "urn:gov:example:concept:professional-licence-active",
            value: active
        },
        #{
            concept_id: "urn:gov:example:concept:professional-licence-expiry-category",
            value: category
        }
    ]
}
