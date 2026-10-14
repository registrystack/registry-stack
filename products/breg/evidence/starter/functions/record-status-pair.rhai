fn derive(facts, selectors, context) {
    let status = required(facts["status"], "status_missing");
    [#{output: "currently_active", value: status == "active"}, #{output: "retired", value: status == "retired"}]
}
