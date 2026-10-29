// The fetched tracker pages, mapped record by record.
//
// The engine calls `shape_records` with the raw tracker instances the
// search loop accumulated and returns the array of record slot objects
// the facade's collection envelope wraps, using the same per-entity
// mapping as scripts/to-record.rhai. An instance without its UID throws.
// Pure and deterministic; no I/O.
fn shape_records(instances) {
    let records = [];
    for entity in instances {
        records.push(to_record(entity));
    }
    records
}
