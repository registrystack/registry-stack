fn derive(facts, selectors, context) {
    let status = required(facts["status"], "status_missing");
    [#{output: "active", value: status == "active"}]
}
