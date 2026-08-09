# Extract deployment project

This complete target bundle answers from a published SQLite extract instead of
a live API, and supports one minimum-disclosure requirement: whether a
registrant currently holds a professional licence.

It is the pattern to copy when the authoritative data can be published as a
snapshot but cannot be queried live: the register runs on a mainframe, or an
overnight export is the only thing the authority will hand out, or the
deployment must keep answering while the register is down. Professional licence
status is deliberately the same acceptance definition the tracker project
answers from a live API. The concept does not change with the transport; only
where the answer comes from does.

The reviewed governance bundle is under `bundle/`. Process-local paths and
listener settings are in `runtime.yaml`. Deployments review and mount both files
read-only, but staging and production may use different runtime files without
changing evidence semantics.

Before deployment, the operator changes only:

- the `.example` token-issuer host;
- the table and column names in the statement, to match the published extract;
- issuer, provider, trust-domain, framework, evidence-type, and concept URIs;
- the staleness bound, if this concept tolerates a different one;
- authority tags and purposes;
- the referenced secret files; and
- the runtime paths, listener binding, and bound extract file.

## Lookup shape

The source runs one reviewed statement. It joins registrants to licences,
groups by the registrant, and returns one aggregate column: how many licences
that registrant currently holds. Uniqueness is decided by counting the rows that
came back, because a statement either matched the whole extract or it did not.
There is no pagination envelope to reconcile and no second page to decline: the
result is complete by construction, which is the one thing an extract gives you
that a paginated API does not.

Zero rows is no match, one row is a unique registrant, two rows is two
registrants filed under one reference, and a third row is past the declared row
bound and fails as a dependency rather than as an ambiguous lookup. The bound is
two for the same reason the protected-read project asks for a page of two: it is
the smallest result that can still tell one match from several.

The left join is load-bearing. A registrant holding no current licence must
still produce a row, or a registrant nobody has licensed would be
indistinguishable from a reference this register has never heard of.

## Aggregating in the statement

The statement is a reviewed, hash-identified bundle artifact, so it is allowed
to be a real query, and that is the minimum-disclosure win. `COUNT` moves one
number across the source boundary. Selecting the licence rows so the extraction
script could count them would move licence identifiers, validity windows, and
issuing offices into the runtime, into diagnostics, and into every later mistake
that could disclose them. The extraction script here never observes a licence,
because no licence was ever handed to it.

Two columns in the extract, `contact_reference` and `issuing_office`, are never
selected. They are the standing proof: the fixture's privacy expectation forbids
their canary value anywhere in an assertion or a diagnostic, and the statement is
what keeps that true.

The count itself is not disclosed either. How many licences a registrant holds
is a fact about their practice; whether they hold one is the question that was
asked, so the derivation reduces the aggregate to a boolean before the output
gate ever sees it.

That makes this source `source-derived`: only the narrow aggregate crosses the
source boundary. The later derivation maps that fact to the asserted boolean
without changing what the statement returned.

## One clock

The statement compares validity windows against `:evidence_now`, which Rust
binds as the runtime's own evaluation instant in fixed-width, whole-second RFC
3339 UTC. This direct text comparison is valid only because the publisher must
store every compared bound in the exact `YYYY-MM-DDTHH:MM:SSZ` form. General
RFC 3339 values with fractional seconds do not sort chronologically against the
shorter whole-second form. SQLite's own date and time functions are denied
by name, so a statement cannot read a second clock and a fixture run pinned to
an instant reproduces exactly, on every host and on every day.

The window is half-open: current from the instant a licence starts until the
instant it ends. `bundle/fixtures/professional-licence-cases.yaml` pins a case
on each side of that boundary.

## Staleness

`maximumExtractAgeSeconds` is declared in the reviewed bundle, not in
`runtime.yaml`, because staleness tolerance is a property of the concept. A
licence can be revoked on any day, so a week is the most this concept tolerates;
adult status would tolerate far more, because a recorded date of birth does not
change. The published instant comes from the extract's own `evidence_extract`
row and never from the file's modification time, which records when bytes landed
on this host rather than anything the publisher said. The bound is inclusive and
is checked before a row is read, so a stale extract fails as a dependency rather
than answering.

## No credential

The source declares no authentication, because there is nothing to authenticate
to. Inbound callers still present access tokens from the deployment's own
issuer, so that is the only credential in the project. This is the property that
makes an extract worth the staleness it costs: no outbound network, no token
endpoint, no third party that can be down when the request arrives.

The bound file must be a regular, non-symlink, read-only file. That is a
correctness requirement rather than hygiene: the runtime opens it with SQLite's
`immutable=1`, and a file that anything can still write makes that promise
false. Publish a new extract as a new file, mount it read-only, and restart.
Follow the complete publication checklist in
[Building an extract](../CONFIG.md#building-an-extract); `evidencectl` validates
projects but does not create, convert, approve, or publish extract files.

## Secrets

Required secret files beneath `/run/secrets/registry-evidence`, each owned by
the service identity with mode `0600`, are:

```text
audit-hmac-key
subject-binding-hmac-key
```

The audit and subject-binding files must contain independently generated raw key
material of at least 32 bytes each; they are not base64-decoded. Production
signing uses the pinned P-256 version in Transit through the workload-local
Unix-socket proxy. Evidence receives no private signing key. No secret value is
stored in this project.

Author with synthetic fixtures first, then promote the same reviewed `bundle/`
bytes through staging and production. Bind environment-specific runtime paths,
credentials, public signing key, pinned Transit version, and the published
extract in each environment. Staging must verify the configured `at+jwt` header
and claims, readiness, one approved synthetic source lookup, audit durability,
and JWS verification. See the
[authoring and production-build workflow](../CONFIG.md#authoring-and-production-build-workflow).
