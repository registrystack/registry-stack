fn answer(facts, selectors, context) {
    let name = required(facts["name"], "name_missing");
    #{ named: name != "" }
}
