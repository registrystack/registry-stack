fn derive(facts, selectors, evaluation_context) {
    let parameters = evaluation_context["parameters"];
    if parameters["survivorship_policy"] !=
       "latest-recognized-union-ended-by-other-party-death-v1" ||
       facts["reference_namespace"] != parameters["civil_reference_namespace"] ||
       facts["union_set_contract"] != parameters["union_set_contract"] ||
       facts["death_record_contract"] != parameters["death_register_contract"] {
        throw("derivation_input_error");
    }
    // Two registers answered about one subject only if the second says which
    // subject it answered for. The search FactSet and both member FactSets
    // reach one derivation for exactly this comparison.
    if facts["death_subject_reference"] != facts["civil_record_reference"] {
        throw("derivation_input_error");
    }
    // An incomplete set is not a smaller set. A union the register did not send
    // cannot be read as a union that does not exist, so the only honest answer
    // is to refuse rather than to return false.
    if facts["union_set_complete"] != true || facts["death_record_complete"] != true {
        throw("derivation_input_error");
    }
    // The latest recognized union decides the answer, so the latest start date
    // is found before any reason is read. A single fold that kept the first
    // event it saw would answer a tie by array order, which is a property of
    // how the register serialized its response and not of the subject.
    let have_latest = false;
    let latest_start = "";
    for event in facts["union_events"] {
        if event["union_recognized"] == true {
            if !have_latest || compare_dates(
                parse_date(event["union_start_date"]),
                parse_date(latest_start)
            ) > 0 {
                have_latest = true;
                latest_start = event["union_start_date"];
            }
        }
    }
    let latest_reason = "";
    if have_latest {
        let sharing_latest = 0;
        for event in facts["union_events"] {
            if event["union_recognized"] == true && compare_dates(
                parse_date(event["union_start_date"]),
                parse_date(latest_start)
            ) == 0 {
                sharing_latest += 1;
                latest_reason = event["union_end_reason"];
            }
        }
        // Two recognized unions beginning on one day leave no latest one. The
        // register has not said which it is, and guessing signs an answer it
        // did not give.
        if sharing_latest > 1 {
            throw("derivation_input_error");
        }
    }
    [#{
        concept_id: "urn:example:fixture:concept:surviving-spouse-status",
        value: have_latest &&
            latest_reason == "death-of-other-party" &&
            facts["death_recorded"] == false
    }]
}
