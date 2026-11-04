// One DHIS2 tracker page in the source-neutral acquisition contract.
//
// Each source entity stays intact under `value`; project-owned transforms
// select caller-visible fields per item. The engine keeps continuation state
// out of the public payload and supplies the next position through the
// existing AdapterNextContinuation exchange property. Pure and deterministic;
// no I/O.
fn source_read_page(exchange) {
    let entities = exchange.body.trackedEntities;
    if entities == () {
        throw "tracker reply carries no trackedEntities";
    }
    let items = [];
    for entity in entities {
        if entity.trackedEntity == () {
            throw "tracked entity carries no UID";
        }
        let item = #{key: entity.trackedEntity, value: entity};
        if entity.updatedAt != () {
            item.revision = entity.updatedAt;
        }
        items.push(item);
    }
    let page = #{items: items};
    let next = exchange.properties.AdapterNextContinuation;
    if next != () {
        page.next = next;
    }
    page
}
