fn prepare(selectors, context) {
    // Rust binds the reference into the fixed path. Requiring it here is what
    // makes this member refuse to be called without the one input it declared.
    required(context["prior_facts"]["civil_record_reference"], "required_fact_missing");
    #{query: [], body: ()}
}
