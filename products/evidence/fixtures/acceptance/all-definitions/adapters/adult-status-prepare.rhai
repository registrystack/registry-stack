fn prepare(selectors, parameters) {
    let subject = selectors["subject"];
    #{query: [], body: #{lookup: #{given_name: subject["values"]["given_name"], family_name: subject["values"]["family_name"], birth_date: subject["values"]["birth_date"]}, fields: parameters["requestedFields"], limit: parameters["resultLimit"]}}
}
