fn extract(source_response, context) {
    let parameters = context["parameters"];
    if source_response.total == 0 {
        return #{ outcome: "no_match" };
    }
    if source_response.total > 1 {
        return #{ outcome: "ambiguous" };
    }
    #{ outcome: "match", facts: #{ marker: source_response.marker } }
}
