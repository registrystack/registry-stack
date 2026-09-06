fn answer(facts, selectors, context) {
    let status = required(facts["status"], "status_missing");
    #{ active: status == "active" }
}
