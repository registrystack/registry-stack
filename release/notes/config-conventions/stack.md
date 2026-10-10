# Registry Stack configuration conventions: breaking changes and diagnostic codes

Every product reads its authored and operator files through the shared
Registry Stack reader, and every `check` command reports in one diagnostic
shape. This section is the index an operator reads first. The per-product
fragments in this directory hold each change with its exact migration step;
this section counts them, says where each diagnostic code table is, and lists
the breaking changes of the same release that sit outside the program.

## BREAKING: v0.40.0 does not upgrade v0.39.0 state in place

No production deployment of `v0.39.0` exists, so this release carries no
forward state path from it. Configuration, packages, and databases written by
`v0.39.0` have no supported in-place upgrade to `v0.40.0`. Start from a fresh
project and a fresh database, and use each product's `BREAKING` sections in
this directory to rewrite the configuration you carry over. From `v0.40.0` on the forward state
path holds again: each release reads the state its immediate predecessor
wrote, and `release/scripts/rehearse-upgrade.py` rehearses it.

## Breaking changes by product

Each count is the number of `BREAKING` items in the product's fragment (a
numbered item of a `BREAKING changes` list, or one `BREAKING:` heading). Every
item states its migration step in the fragment.

A fragment's "Protocol words" section is counted the same way: each `BREAKING`
heading in it is one item. The "Protocol words" sections of `discovery.md` and
`manifest.md` have no such heading, so they add nothing to the count, although
every word they list changed with no alias.

| Product | Breaking items | Fragment |
|---|---|---|
| Base Registry Engine | 74 | `breg.md` |
| Casework | 43 | `casework.md` |
| Discovery | 9 | `discovery.md` |
| Evidence | 69 | `evidence.md` |
| Manifest | 6 | `manifest.md` |
| Messaging | 21 | `messaging.md` |
| Platform files and tooling | 16 | `platform.md` |
| Render | 11 | `render.md` |
| Scheduling | 17 | `scheduling.md` |
| Total | 266 | |

A fragment's "Stable move" section holds the respellings and retaggings this
release makes with no alias, and its `BREAKING` headings are counted like any
other.

Each fragment gives the final v0.40.0 spelling and diagnostic code beside the
earlier form it replaces. Apply those final forms when rewriting a project.

### Changes stated in more than one fragment

A change to a block or a client several products share is stated in the
fragment of each product that reads it, with that product's own keys, codes,
and migration step, and is counted once in each of those fragments.

| Change | Fragments |
|---|---|
| The issuer key source `jwksSource` names its variant in `type`, not `kind` | `platform.md`, `breg.md`, `casework.md`, `messaging.md`, `scheduling.md`; `evidence.md` for the access-token key source |
| A hook handler and an action handler name their variant in `type`, not `kind` | `platform.md`, `breg.md`, `casework.md` |
| A client listed under `authentication.oidc.assertionIssuers` names at least one issuer | `platform.md`, `breg.md`, `casework.md`, `scheduling.md` |
| `authentication.oidc.allowedClients` is required, and a repeated client is refused | `platform.md`, `breg.md`, `casework.md`, `messaging.md`, `scheduling.md`; `evidence.md` for the bundle |
| The client error words of the Rust, Node.js, and Python clients are written in kebab-case | `platform.md`, `breg.md`, `casework.md`, `evidence.md`, `messaging.md`, `scheduling.md`; `discovery.md` under "Protocol words" |

## Diagnostic codes, old to new

Each product's codes changed to the shared `config.*` codes or to a product
code that names the failing key. The old-to-new tables are in the fragments:

| Product | Where the table is |
|---|---|
| Base Registry Engine | `breg.md`, the sections that list codes no longer reported and the replacement codes |
| Casework | `casework.md`, "Diagnostic codes" and the per-refusal tables |
| Discovery | `discovery.md`, "Diagnostic codes, old to new" |
| Evidence | `evidence.md`, the sections that map each old message to its code |
| Manifest | `manifest.md`, "Diagnostic codes, old to new" |
| Messaging | `messaging.md`, the `check` and runtime refusal sections |
| Platform files and tooling | `platform.md`, "Diagnostic codes, old to new" |
| Render | `render.md`, "Diagnostic codes, old to new" |
| Scheduling | `scheduling.md`, "runtime refusals carry their own codes and JSON Pointers" |

## Breaking changes outside the program fragments

These items are in the product `CHANGELOG.md` files as `BREAKING:` and have no
entry in a fragment. Each states its migration step.

### Base Registry Engine

1. **Governed read routes refuse `HEAD`.** A `HEAD` request to a record,
   history, statistics, attachment, GIS, ingestion-run, or discovery route
   receives the concealed 404 that any method the route does not accept
   receives. Migration: send `GET`. `/health`, `/healthz`, and `/ready` still
   answer `HEAD`.
2. **Idempotency keys are per caller.** A spent key is found by the
   configured OIDC issuer, the verified principal, and the key, in one scope
   every ordinary write shares. A caller reusing a key on a different write
   route receives `409 idempotency.conflict`; an exact retry past
   `idempotency.receiptRetentionDays` (default 7, at most 365) receives
   `410 idempotency.expired` and is never executed. Migration: use a fresh key
   for each distinct write. Run `bregctl idempotency-retention erase-expired
   --runtime-config PATH --before RFC3339` to drop held responses past their
   horizon.
3. **The caller-keyed idempotency store is an engine capability, so a package
   an earlier release built does not load.** Migration: rebuild the package
   with this release and apply it to a new database with `bregctl apply
   --initial`. The new database holds no idempotency record, so a request the
   earlier release committed and a caller retries against this one executes
   again.
4. **No stored ingestion run is carried across.** A run names the verified
   caller that created it, and the new database starts with no run, chunk, or
   receipt. Migration: a `bregctl data import` checkpoint written against the
   earlier registry refuses to resume; import the data again under a fresh
   checkpoint path.

### Messaging

1. **A spent idempotency key is scoped to the caller's issuer and subject.**
   Rotating `audit.hashKeyRef` no longer frees spent keys. Past
   `retention.submissionReceiptRetentionDays` a changed request under a spent
   key is refused with `409 idempotency.key-reused`. The new database holds no
   idempotency record, so every key spent under the earlier release can be used
   again, and a retry this release receives under such a key sends its message
   a second time. Migration: stop new submissions, let in-flight senders finish
   retrying against the earlier release the submissions whose answers they
   lost, then stop every runtime of the earlier release before you point
   callers at this one.

### Platform

These items change a `registry-platform-*` crate a Rust consumer links, not a
file an adopter writes.

1. **`RuntimeConfigError` carries diagnostics only.**
   `RuntimeConfigErrorKind`, `kind()`, `code()`, `field()`, and `message()` are
   removed, with the `runtime_config.*` and `authored_config.*` codes they
   reported. Migration: match on a diagnostic's `code`. `deciding_diagnostic()`
   is the error to word a refusal from, `diagnostics()` lists all of them, and
   a file that cannot be read has the code `UNAVAILABLE_CODE`
   (`platform.runtime-config.unavailable`). The dotted field is the
   diagnostic's JSON Pointer `path`.
2. **`registry-platform-dispatch` spells its job words in kebab-case.** The
   stored job state and the disposition `dead-lettered`, the dispositions
   `retry-pending` and `replay-pending`, and the transition `lease-lapsed`
   replace the underscore spellings, with no alias and no reader for the old
   word. Migration: a consumer of the crate compares against the new words and
   creates its job table as `JobTable::create_statements` renders it.
   `messaging.md` states the step for the Messaging dispatch queue.
3. **`registry-platform-hooks` spells the hook delivery words in kebab-case.**
   The delivery state and proposal disposition `dead-lettered`, the
   authentication profile `hmac-sha256-v1`, the delivery mode `after-commit`,
   and every dead-letter reason replace the underscore spellings, with no
   alias. `delivery_schema::install` creates the tables in the new spelling
   and respells no stored row. Migration: a consumer that supplies
   `authentication_profile` or `delivery_mode` in a `DeliveryCapture` supplies
   the new word. `breg.md` and `scheduling.md` state the words their own
   deliveries carry.
4. **The audit query redactor reports `invalid-query-encoding`.** The `_error`
   object of an undecodable query carried `invalid_query_encoding`. Migration:
   none for a product, since none reads the code; a consumer of the crate
   compares against the new word.
5. **The CLI reference data spells constraint kinds in kebab-case.**
   `registry-cli-reference` writes `required-exactly-one`,
   `required-one-or-more`, `requires-all`, and `mutually-exclusive`.
   Migration: none outside the docs site generator, its only reader.

## Reconciliation

The counts above come from the fragments. The `Unreleased` section of each
product changelog lists its own number of `BREAKING:` bullets (Base Registry
Engine 66, Casework 43, Discovery 8, Evidence 49, Manifest 8, Messaging 16,
Platform 28, Render 8, Scheduling 15; 241 in all). The two numbers differ for
a product because a fragment item is one migration step and a changelog bullet
often covers several, and because a changelog also lists the items no fragment
states. Those items are the ones in "Breaking changes outside the program
fragments".
