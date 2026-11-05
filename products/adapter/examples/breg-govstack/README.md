# BReg-backed GovStack Write example

This project exposes one `contacts` collection through the built-in GovStack
Consultation and Write target. The reusable `breg-records` pack owns BReg HTTP
normalization. This project owns the public contact schemas and the mappings
between public data and BReg domain data.

Create accepts `name`, `email`, and an optional `note`. The create mapping adds
the BReg-only `jurisdiction` field. Update is a closed, nonempty flat JSON Merge
Patch. A null `note` removes the public member. The read projection excludes
the native jurisdiction and omits a native null note.

The runtime example explicitly enables the file secret provider under
`secretProviders.file.root`, alongside its environment provider for database
and cursor references. Omitting `secretProviders` keeps environment secrets
only. A static credential file (such as the bearer token here) is re-read for
each source request, and an OAuth client secret file is re-read each time the
facade acquires a token, so an operator can atomically replace either without
restarting the facade. Everything else resolved from a secret reference is read
once at startup and needs a restart to change: the mTLS client identity, the
CA bundle, the database URL, the cursor key and the OIDC keys. A replacement
file must keep the facade user as owner, mode 0400 or 0600, and a single hard
link, or the provider refuses it; write it beside the old one and rename it
into place.

The runtime binds a dedicated BReg bearer token whose access profile grants
only the selected Record route. Reads and writes use the same BReg principal,
access profile, and readable-field projection so the companion GET ETag is the
same native validator returned by the one-item batch write.

Pending-write recovery must retain the same BReg origin, access profile,
provider idempotency namespace, and source principal. Rotating the bearer token
is safe when BReg still recognizes that same principal and key namespace.
Before changing the binding to another principal, finish or reconcile every
pending write; secret-reference strings do not prove principal continuity.

The public authorization surface separates `records.read` from
`records.write`. A caller holding only the read scope can discover and invoke
Retrieve, while Create and Update require the write scope. A caller holding
both scopes can use the whole collection.

`crates/registry-adapter/tests/govstack_breg_write.rs` starts current `breg`,
`bregctl`, and `adapter` processes from explicit absolute binary paths and
proves the successful, refusal, exact-replay, stale-condition, and
lost-response recovery journeys against real PostgreSQL. Teardown stops the
owned development services. It does not delete the retained BReg database
volume, so destructive fixture cleanup remains an explicit operator action.
