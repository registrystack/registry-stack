// The predicate the odk-submissions route's choice reads: does this
// run follow a next link (a continuation) or open the first page?
//
// The engine evaluates the choice `when` predicate on the exchange
// (CONCEPT 8.11.3); scripts/shape-page.rhai's entrypoint
// seed_next_link set odkNextLink from the job cursor before this
// predicate runs. Absent means the first page, so the route sends the
// `$top`/`$count` query; present means the origin-pinned
// `httpUri` send of the cursor's `@odata.nextLink` (CONCEPT 8.11.5).
// A predicate returns a bool; anything else raises `script`. Pure and
// deterministic; no I/O.
fn has_next_link(exchange) {
    exchange.properties.odkNextLink != ()
}
