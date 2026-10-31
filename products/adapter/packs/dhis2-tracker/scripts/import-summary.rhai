// Classify a synchronous DHIS2 tracker import summary without returning its
// source content. The route always sends async=false. A complete import has
// an OK or WARNING status, internally consistent non-negative counters, at
// least one accepted object, and no ignored object. A partial import has at
// least one accepted and at least one ignored object. DHIS2 2.43 exposes no
// rejected aggregate: rejected is the number of distinct (trackerType, uid)
// pairs in an explicitly present validationReport.errorReports array. It is
// orthogonal to stats.total and several errors for one object count once.
// Anything unfinished, malformed, empty, internally inconsistent, or carrying
// a delete count matches neither and is refused by the route's validate step.
// Pure and deterministic; no I/O.

fn accepted_status(body) {
    body != () && type_of(body) == "map" && body.status != () &&
        type_of(body.status) == "string" &&
        (body.status == "OK" || body.status == "WARNING")
}

fn partial_status(body, rejected) {
    body != () && type_of(body) == "map" && body.status != () &&
        type_of(body.status) == "string" &&
        ((body.status == "OK" && rejected == 0) ||
         (body.status == "WARNING" && rejected == 0) ||
         (body.status == "ERROR" && rejected > 0))
}

fn counts(body) {
    if body == () || type_of(body) != "map" || body.stats == () ||
            type_of(body.stats) != "map" {
        return ();
    }
    let stats = body.stats;
    if stats.created == () || stats.updated == () || stats.deleted == () ||
            stats.ignored == () || stats.total == () {
        return ();
    }
    if type_of(stats.created) != "i64" || type_of(stats.updated) != "i64" ||
            type_of(stats.deleted) != "i64" || type_of(stats.ignored) != "i64" ||
            type_of(stats.total) != "i64" ||
            stats.created < 0 || stats.updated < 0 || stats.deleted < 0 ||
            stats.ignored < 0 || stats.total < 0 {
        return ();
    }
    let accepted = stats.created + stats.updated + stats.deleted;
    if accepted + stats.ignored != stats.total {
        return ();
    }
    #{
        accepted: accepted,
        imported: stats.created,
        updated: stats.updated,
        deleted: stats.deleted,
        ignored: stats.ignored,
        total: stats.total
    }
}

fn rejected_count(body) {
    if body.validationReport == () || type_of(body.validationReport) != "map" ||
            body.validationReport.errorReports == () ||
            type_of(body.validationReport.errorReports) != "array" {
        return ();
    }

    let rejected_objects = [];
    for report in body.validationReport.errorReports {
        if type_of(report) != "map" || report.trackerType == () || report.uid == () ||
                type_of(report.trackerType) != "string" ||
                type_of(report.uid) != "string" ||
                report.trackerType == "" || report.uid == "" {
            return ();
        }
        let seen = false;
        for rejected in rejected_objects {
            if rejected.trackerType == report.trackerType && rejected.uid == report.uid {
                seen = true;
            }
        }
        if !seen {
            rejected_objects.push(#{trackerType: report.trackerType, uid: report.uid});
        }
    }
    rejected_objects.len()
}

fn normalized_partial(body) {
    let summary = counts(body);
    if summary == () || summary.deleted != 0 || summary.accepted <= 0 ||
            summary.ignored <= 0 {
        return ();
    }
    let rejected = rejected_count(body);
    if rejected == () || !partial_status(body, rejected) {
        return ();
    }
    #{
        imported: summary.imported,
        updated: summary.updated,
        ignored: summary.ignored,
        rejected: rejected
    }
}

fn is_complete_import(exchange) {
    let body = exchange.body;
    let summary = counts(body);
    accepted_status(body) && summary != () && summary.deleted == 0 && summary.accepted > 0 &&
        summary.ignored == 0 && summary.accepted == summary.total
}

fn is_partial_import(exchange) {
    normalized_partial(exchange.body) != ()
}

fn partial_import_data(exchange) {
    normalized_partial(exchange.body)
}
