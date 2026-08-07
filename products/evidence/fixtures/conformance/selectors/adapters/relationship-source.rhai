fn extract(source_response, context) {
    let parameters = context["parameters"];
    if source_response["matched"] {
        return #{outcome: "match", facts: #{result: true}};
    }
    #{outcome: "no_match"}
}
