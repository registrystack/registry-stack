# Statistical datasets

Declare count datasets when you need a governed aggregate API for operational
analysis or for publishing a statistical series. Base Registry Engine computes
the counts in PostgreSQL and serves JSON or CSV. The model fixes the population,
periods, dimensions, disclosure parameters, and permitted profiles. Consumers
choose periods and a representation, rather than supplying SQL or groupings.

The implementation lives in `src/compiler/statistics.rs`, `src/statistics.rs`,
`src/postgres/statistics.rs`, and `src/api/statistics.rs` under
`crates/registry-breg`. The facility acceptance project declares flow and stock
examples, including a dimension derived from the evaluation date.

## Declare a dataset

A root `registry.yaml` may declare `statisticalDatasets`. Modules cannot add
these declarations. For example, the facility project includes:

```yaml
statisticalDatasets:
  - id: monthly-discharge-reports
    unit: discharge-report
    population: "substanceCode ne null"
    period:
      kind: flow
      field: period-start
      granularity: month
      firstPeriod: 2025-01
    dimensions:
      - administrative-boundary
      - has-measured-quantity
    disclosure:
      minimumCount: 5
      roundingBase: 5
    live:
      - facility-operator
    releases:
      publisher: statistics-publisher
      readers:
        - statistics-reader
```

The unit is a mutable entity. Population expressions use the typed read-filter
grammar and API field names. Dimensions name logical field IDs and must be
boolean or closed vocabulary fields. Their expanded cells for one period,
including totals and null codes, must fit the 10,000-cell cap. Boolean codes are
`true` and `false`. Vocabulary codes beginning with `_` are reserved. `_T`
denotes a total; `_U` denotes a null value when the field can be null. Derived
fields are nullable for this purpose. A non-null value outside the declared
vocabulary refuses the whole computation without disclosing that value.

The column names `period`, `periodStart`, `periodEnd`, `value`, and `status`
are reserved for the document and CSV representation. A dimension cannot use
one of them. Encrypted fields and consent-gated source grants are refused.

## Profiles and count equivalence

Every dataset profile is authenticated. A declaration needs live profiles,
release grants, or both. Releases have exactly one publisher and at least one
reader. A released-data reader can have no record permissions at all.
Release GET routes authorize the publisher, every live profile, and every
profile listed in `releases.readers`. A reader can have no entity permission.

A live profile and the publisher must have an ordinary `list` grant on the unit
with `allowCount: true`. That grant must permit the fields and typed filter
operators used by the population, period or validity selection, and dimensions.
The statistical query uses the same list predicates, forced row security,
visibility checks, and field expressions. Its cell is therefore a count the
profile can obtain through its corresponding list query. Live reads retain the
caller's row and membership boundaries, purpose, and request visibility.

A publisher's population must be independent of the caller. The compiler checks
the unit and every source entity read by a referenced derived definition. On
each dependency, the publisher needs a read grant without claim-bound rows,
membership boundaries, purpose filters, consent gates, or owner-dependent
request visibility. Mandatory entity boundaries also make publication
ineligible. This prevents different publishers from producing different
populations under one dataset identity.

Choose one profile with `accessProfile`. Profiles are never combined into a
larger grant. `/v1/registry` and `/openapi.json` filter dataset operations using
the same authorization checks; a release-only reader receives no entity grant.

## Periods and evaluation dates

Supported granularities are day, month, quarter, and year, using UTC calendar
periods. Codes are `YYYY-MM-DD`, `YYYY-MM`, `YYYY-Qn`, and `YYYY`. A range
uses positive four-digit years, and each period's exclusive end must also fit
that date range. For example, `9999-11` is valid and `9999-12` is refused. A range
includes both named periods and contains at most 366 periods. Responses contain
at most 10,000 cells, including totals and zero-filled domain combinations.
Canonical JSON documents and CSV responses are limited to 8 MiB, matching the
maintained clients' default body limit. The compiler bounds a single-period
document; reduce a multi-period range if it returns `400 query.invalid` naming
no parameter because its representation exceeds that limit.

A flow counts unit rows whose date field is in `[start, end)`. A stock counts
rows valid at the reference date. It may use the entity's temporal declaration:

```yaml
period:
  kind: stock
  granularity: month
  firstPeriod: 2025-01
  validity: temporal
```

Or it may name date fields with `validity: {from: valid-from, until: valid-to}`.
The interval is `[from, until)`, with a null end meaning open-ended. An ended
period's reference date is its final day. The current period uses today's UTC
date. Publication requires an ended period at or after `firstPeriod`.

A derived field that uses `registry_context.evaluation_date()` runs at today's
UTC date for live reads and at the period's reference date for publication.
Live reads of a dataset that depends on this function accept only its current
period. This keeps the live result count-equivalent to its ordinary list query.
A release counts the registry's present rows evaluated at the reference date;
it does not reconstruct what the registry held at that past date.

## Disclosure

Live data contains exact counts for the selected profile. Released data applies
`minimum-count-and-rounding`. Both `minimumCount` and `roundingBase` must be
explicit integers of at least two. For every base cell and every margin:

- An exact zero remains zero with status `exact`.
- A positive count below `minimumCount` becomes null with status `suppressed`.
- Every other count rounds to the nearest multiple of `roundingBase`, with
  halves rounded up, and has status `rounded`, including a rounded zero.

Totals round independently. They need not equal the sum of visible cells.
True counts exist only during computation; release storage retains the
transformed document, its digest, and lifecycle metadata.

This method accepts inference risks. With minimum five and base five, two
suppressed positive cells whose true counts are four each have a published
total of ten. Suppression bounds each at one through four, while the rounded
total bounds their sum at eight through twelve. The intersection pins both to
four. Seven positive suppressed cells with a rounded total of five pin every
cell to one. `tests/statistics.rs` executes these examples.

Deterministic rounding permits differencing between releases or overlapping
populations. Exact zeros disclose absence and can disclose group attributes.
There is no privacy budget, differential privacy, or claim of universal
statistical confidentiality. Review each dataset's population, dimensions,
release cadence, and auxiliary information before granting readers access.

If the interval-pinning residual is unacceptable, evaluate cell key
perturbation through a separate statistical design and review. That mechanism
is outside the implemented release path.

## Release lifecycle

Publication computes under one source snapshot and records the shared history
head with that computation. The release's `snapshot` is an opaque bookmark
when history coverage is available, or `null` after erasure or other coverage
invalidation. Publication continues from current data without requiring
history rebaseline; rebaseline can restore bookmarks for subsequent releases.
Persistence then verifies
the same package activation, takes the caller's idempotency-key lock followed
by the dataset-period lock, rechecks eligibility and freshness, and allocates
the next version. A computation superseded by a newer committed computation
is refused. Immediate actions and ordinary mutations advance the same head.

Versions increase monotonically per dataset and period, including across
changed definitions. A final release permits another final correction, but
refuses a subsequent provisional release for the same definition. Latest
reads skip withdrawn versions. `status=final` selects only final releases.

A definition digest covers everything that can affect the true or published
cells: unit, population, period, dimensions and codes, the definitions of
referenced fields and derived SQL inputs, publisher visibility on every source
dependency, and disclosure parameters.
Reader and live grants and `firstPeriod` do not change it. Read eligibility
uses the active definition digest, so versions from another definition remain
stored but are unavailable until that exact definition is active again.

Publication and withdrawal require `Idempotency-Key`. An identical retry under
the same current authority returns the retained status, headers, and body
without creating another version. Binding the key to a different request
returns `409 idempotency.conflict`.

Withdraw using one of `computation-error`, `source-data-error`, or
`disclosure-risk`. The database records the withdrawal and deletes content in
one fixed PostgreSQL function. The immutable version header remains. A direct
read of that version returns `410 statistical_dataset.version_withdrawn` with
the reason code. A second withdrawal is refused; an identical idempotent retry
returns its original response.

## HTTP and representations

| Method and path | Access | Result |
| --- | --- | --- |
| `GET /v1/statistics/{dataset}:live` | live profile | Exact live document |
| `GET /v1/statistics/{dataset}/releases` | released-data access | Version headers and `pageInfo` |
| `GET /v1/statistics/{dataset}/releases:series` | released-data access | Latest eligible version per period |
| `GET /v1/statistics/{dataset}/releases/{period}` | released-data access | Latest eligible document |
| `GET /v1/statistics/{dataset}/releases/{period}/versions/{version}` | released-data access | One immutable version |
| `POST /v1/statistics/{dataset}/releases/{period}/versions` | publisher | 201 version header |
| `POST /v1/statistics/{dataset}/releases/{period}/versions/{version}/withdrawal` | publisher | 200 header with withdrawal |

Live and series reads use `from` and `to`; a series requires both. Latest and
series accept `status=final`. Header listing accepts `$top` from one through
100 and an opaque `$skiptoken`. Its cursor binds the activation, dataset
definition, selected profile, principal, purpose, and page size. Reauthorize
before opening it. Listings order periods newest first, then versions newest
first. Consumers should tolerate concurrent publications while paging.

Documents contain `dataset`, `periods`, `dimensions`, and `cells`, plus `live`
or `release` metadata. Released documents also describe `disclosure`. A cell
contains `period`, dimension codes, `value`, and `status`. Dimensions contain
codes rather than labels. A released series explicitly represents missing
periods without inventing cells for them.

An absent or unmatched `Accept` header selects JSON.
Use `Accept: application/json` or `Accept: text/csv` for live, latest, version,
and series reads. CSV has RFC 4180 quoting and these columns:

```text
period,periodStart,periodEnd,<dimension field IDs...>,value,status
```

Suppressed values are blank in CSV. Plot `periodStart` against `value`, filter
dimension codes before plotting, and keep `status` so a blank cell cannot be
mistaken for zero. Release listings and mutation responses are JSON.

Stored JSON is canonicalized using RFC 8785 and hashed with SHA-256. The
`contentDigest` in a header names the stored document. `Repr-Digest` uses RFC
9530 syntax and hashes the exact response bytes; a CSV digest therefore differs
from its JSON digest. Responses use `Cache-Control: no-store` and
`Vary: authorization, accept`, without a strong ETag.

## Operation and deployment

Release tables are engine-owned and installed in every package. The runtime
can insert and select headers and content and select withdrawals; it cannot
update or delete those tables. Only the migration-owned withdrawal function
can delete content, while recording the withdrawal. Catalog verification
covers its owner, body, language, volatility, privileges, and fixed search path.

Every protected request has an audit attempt before database I/O and an
accepted terminal entry before bytes are returned. A publication or withdrawal
whose COMMIT fails, or whose deadline passes while COMMIT is in flight, has no
proven outcome. It returns `503 source.unavailable` and appends no terminal
entry: its attempt is answered `unfinished`, never `refused`. Retry with the
same `Idempotency-Key`; a write that did commit returns its retained response.
Audit entries contain keyed
references and lifecycle metadata, never cell values or unit counts. Aggregate
reads do not add individual subject access-log hits.

Computations consume the HTTP request deadline, including pool acquisition,
locks, the grouped statement, and persistence. The statement budget is capped
at 30 seconds; test routers without an outer deadline use ten seconds.
There is no release cache or background scheduler. Schedule the HTTP publish
command from the institution's cron or CI, supplying a token file. A dashboard
reader needs an OAuth client capable of satisfying the deployed issuer and
selected profile. Verify that authentication journey for the chosen dashboard
connector before configuring it.

This is a native count-document API with standard JSON, CSV, HTTP digest, and
calendar conventions. It does not implement the full SDMX REST API or a
JSON-stat representation.
