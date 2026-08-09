fn answer(facts, selectors, context) {
    let count = required(
        facts["qualifying_record_count"],
        "qualifying_record_count_missing"
    );
    #{condition_satisfied: count > 0}
}
