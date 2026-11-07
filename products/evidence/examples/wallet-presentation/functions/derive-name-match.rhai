// One exact comparison of two names normalised by the same reviewed profile.
fn derive(facts, selectors, context) {
    let presented = normalise_name("name-match-v1", facts.name);
    let expected = normalise_name("name-match-v1", selectors["subject"].values["expected-name"]);
    [#{output: "name-matches", value: presented == expected}]
}
