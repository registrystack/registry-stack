fn derive(facts, selectors, evaluation_context) {
    if facts["record_reference"] !=
       selectors["subject"]["values"]["record_reference"] {
        throw("derivation_input_error");
    }
    // The register's own region code is never disclosed. It is mapped to a
    // coarser reviewed code, and a source code with no mapping leaves the
    // requirement unresolved rather than passing the precise code through.
    let mapped = codelist_lookup(
        evaluation_context["codelists"]["residence-regions"],
        required(facts["official_residence_code"], "required_fact_missing")
    );
    [
        #{
            concept_id: "urn:gov:example:concept:residence-region",
            value: required(mapped, "unknown_controlled_code")
        }
    ]
}
