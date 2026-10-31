// Classify a synchronous DHIS2 tracker import summary without returning its
// source content. The route always sends async=false. A complete import has
// an OK or WARNING status, internally consistent non-negative counters, at
// least one accepted object, and no ignored object. A partial import has at
// least one accepted and at least one ignored object. Anything unfinished,
// malformed, empty, or internally inconsistent matches neither and is
// refused by the route's validate step. Pure and deterministic; no I/O.

fn accepted_status(body) {
    body.status == "OK" || body.status == "WARNING"
}

fn counts(body) {
    if body == () || body.stats == () {
        return ();
    }
    let stats = body.stats;
    if stats.created == () || stats.updated == () || stats.deleted == () ||
            stats.ignored == () || stats.total == () {
        return ();
    }
    if stats.created < 0 || stats.updated < 0 || stats.deleted < 0 ||
            stats.ignored < 0 || stats.total < 0 {
        return ();
    }
    let accepted = stats.created + stats.updated + stats.deleted;
    if accepted + stats.ignored != stats.total {
        return ();
    }
    #{accepted: accepted, ignored: stats.ignored, total: stats.total}
}

fn is_complete_import(exchange) {
    let body = exchange.body;
    let summary = counts(body);
    accepted_status(body) && summary != () && summary.accepted > 0 &&
        summary.ignored == 0 && summary.accepted == summary.total
}

fn is_partial_import(exchange) {
    let body = exchange.body;
    let summary = counts(body);
    accepted_status(body) && summary != () && summary.accepted > 0 &&
        summary.ignored > 0
}
