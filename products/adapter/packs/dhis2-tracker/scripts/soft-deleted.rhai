// Whether a fetched tracked entity is absent from the registry's view.
//
// DHIS2 keeps soft-deleted and deactivated entities in the tracker store:
// the `deleted` and `inactive` flags of the tracker object (DHIS2
// documentation, "Tracker", tracked-entity property table). The engine
// calls `soft_deleted` with the fetched entity and returns true when
// either flag carries true, so the route answers the profile's not-found
// problem instead of serving the entity. Pure and deterministic; no I/O.
fn soft_deleted(entity) {
    (entity.deleted == true) || (entity.inactive == true)
}
