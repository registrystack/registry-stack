fn extract(source_response, parameters) {
    if source_response["matched"] {
        return #{outcome: "match", facts: #{result: true}};
    }
    #{outcome: "no_match"}
}
