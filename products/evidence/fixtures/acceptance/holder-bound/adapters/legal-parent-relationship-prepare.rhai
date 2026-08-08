fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let child = selectors["child"];
    #{query: [], body: #{lookup: #{record_reference: child["values"]["record_reference"]}, fields: parameters["requestedFields"], limit: parameters["resultLimit"]}}
}
