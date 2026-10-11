// Pure mappings for the synthetic bounded poll. The source owns the review
// state; the Coordinator only reads it at each timed check.
fn review_state(record) {
    let state = record.data.domainData.reviewState;
    if state == "approved" || state == "rejected" { "decided" } else { "pending" }
}

// Each later check is a whole number of days after the first one.
fn check_time(first_check, round) {
    add_seconds(first_check, round * 86400)
}
