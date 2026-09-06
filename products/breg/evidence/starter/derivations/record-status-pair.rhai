fn answer(facts, selectors, context) {
    let status = required(facts["status"], "status_missing");
    #{ currently_active: status == "active", retired: status == "retired" }
}
