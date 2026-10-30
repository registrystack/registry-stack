// Whether a fetched tracked entity is absent from the registry's view.
//
// DHIS2 keeps soft-deleted and deactivated entities in the tracker store:
// the `deleted` and `inactive` flags of the tracker object (DHIS2
// documentation, "Tracker", tracked-entity property table). The engine
// evaluates the choice step's `when` predicate on the exchange
// (CONCEPT 8.11.3), whose body is the fetched entity, and returns true
// when either flag carries true, so the route answers the profile's
// not-found problem instead of serving the entity. Pure and
// deterministic; no I/O.
fn soft_deleted(exchange) {
    let entity = exchange.body;
    (entity.deleted == true) || (entity.inactive == true)
}
