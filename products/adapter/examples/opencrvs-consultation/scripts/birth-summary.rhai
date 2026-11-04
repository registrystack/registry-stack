// Select this deployment's birth-summary view from the native event.
// Source identity and lookup classification remain outside this function.
fn birth_summary(source) {
    let result = #{registration: #{eventType: source["type"], status: source.status}};
    if source.dateOfEvent != () { result.dateOfEvent = source.dateOfEvent; }
    result
}
