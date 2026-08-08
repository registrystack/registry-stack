fn prepare(selectors, context) {
    // This member carries its reference in the body it builds here, and no
    // static check reads a body. The projected prior_facts map is the whole of
    // what this script can see, so the allowlist is what bounds the request:
    // a search fact the member did not declare cannot be written into it.
    let reference = required(
        context["prior_facts"]["civil_record_reference"],
        "required_fact_missing"
    );
    #{query: [], body: #{subject_reference: reference}}
}
