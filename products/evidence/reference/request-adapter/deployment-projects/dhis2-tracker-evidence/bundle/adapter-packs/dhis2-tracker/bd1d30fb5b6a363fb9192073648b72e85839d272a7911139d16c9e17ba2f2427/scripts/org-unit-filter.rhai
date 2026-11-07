// The organisation unit a search narrows to.
//
// The engine sets the AdapterFilters property to the filters the caller
// sent (CONCEPT 8.11.1), an object from declared filter name to typed
// value. This pack's search binding declares `org_unit`, so the value is
// the DHIS2 organisation unit UID the route sends as `orgUnits`. The
// route that reads this property is bound only where the filter is
// declared, and the search is refused without it. Pure and
// deterministic; no I/O.
fn org_unit_filter(exchange) {
    let filters = exchange.properties.AdapterFilters;
    if filters == () || filters.org_unit == () {
        throw "the search carries no org_unit filter";
    }
    filters.org_unit
}
