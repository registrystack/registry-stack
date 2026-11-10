// SPDX-License-Identifier: Apache-2.0

fn person(row) {
    if row.state == "found" {
        return #{outcome: "present", key: row.subject, fields: row.properties, sourceRevision: row.revision};
    }
    if row.state == "confirmed-absent" {
        return #{outcome: "authoritative-absent", key: row.subject, sourceRevision: row.revision};
    }
    #{outcome: "unavailable", key: row.subject}
}

fn exact(exchange) {
    #{"type": "exact", record: person(exchange.body)}
}

fn batch(exchange) {
    let records = [];
    for row in exchange.body.records {
        records.push(person(row));
    }
    #{"type": "batch", records: records}
}

fn holdings(exchange) {
    let page = exchange.body;
    if page.state != "snapshot" {
        return #{"type": "unavailable"};
    }
    let rows = [];
    for row in page.items {
        rows.push(#{key: row.holding, parentKey: row.business, fields: row.properties, sourceRevision: row.revision});
    }
    #{
        "type": "by-parent",
        parentKey: page.business,
        snapshot: page.snapshotId,
        rows: rows,
        complete: page.finished,
        nextCursor: page.next
    }
}
