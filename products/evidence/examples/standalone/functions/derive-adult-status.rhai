fn derive(facts, selectors, context) {
    let threshold = add_calendar_years(parse_date(facts["birth-date"]), 18);
    [#{output: "adult", value: compare_dates(context.legal_local_date, threshold) >= 0}]
}
