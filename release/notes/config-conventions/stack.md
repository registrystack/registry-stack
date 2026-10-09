# Registry Stack configuration conventions: breaking changes and diagnostic codes

Every product reads its authored and operator files through the shared
Registry Stack reader, and every `check` command reports in one diagnostic
shape. This section is the index an operator reads first. The per-product
fragments in this directory hold each change with its exact migration step;
this section counts them, says where each diagnostic code table is, and lists
the breaking changes of the same release that sit outside the program.

## Breaking changes by product

Each count is the number of `BREAKING` items in the product's fragment (a
numbered item of a `BREAKING changes` list, or one `BREAKING:` heading). Every
item states its migration step in the fragment.

| Product | Breaking items | Fragment |
|---|---|---|
| Base Registry Engine | 34 | `breg.md` |
| Casework | 13 | `casework.md` |
| Discovery | 6 | `discovery.md` |
| Evidence | 35 | `evidence.md` |
| Manifest | 6 | `manifest.md` |
| Messaging | 14 | `messaging.md` |
| Platform files and tooling | 9 | `platform.md` |
| Render | 11 | `render.md` |
| Scheduling | 11 | `scheduling.md` |
| Total | 139 | |

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
   unchanged with `bregctl package --baseline-package <deployed package>` and
   apply it once before starting the upgraded runtime. A request committed
   before the upgrade and retried after it executes again.
4. **The upgrade discards every stored ingestion run with its chunks and
   receipts.** The records that committed chunks wrote stay. Migration: finish
   or cancel open runs before upgrading. A `bregctl data import` whose run was
   discarded refuses to resume; import only the uncommitted lines under a fresh
   checkpoint path.

### Messaging

1. **A spent idempotency key is scoped to the caller's issuer and subject.**
   Rotating `audit.hashKeyRef` no longer frees spent keys. Past
   `retention.submissionReceiptRetentionDays` a changed request under a spent
   key is refused with `409 idempotency.key-reused`. The upgrade discards
   existing idempotency records, so every key spent before it can be used again,
   and a retry the upgraded runtime receives under a discarded key sends its
   message a second time. Migration: before you run `messagingctl apply`, stop
   new submissions, let in-flight senders finish retrying the submissions whose
   answers they lost, then stop every runtime of the earlier release; start the
   upgraded runtime only after `apply` succeeds.

### Platform

1. **`RuntimeConfigError` carries diagnostics only.**
   `RuntimeConfigErrorKind`, `kind()`, `code()`, `field()`, and `message()` are
   removed, with the `runtime_config.*` and `authored_config.*` codes they
   reported. Migration: match on a diagnostic's `code`. `deciding_diagnostic()`
   is the error to word a refusal from, `diagnostics()` lists all of them, and
   a file that cannot be read has the code `UNAVAILABLE_CODE`
   (`platform.runtime-config.unavailable`). The dotted field is the
   diagnostic's JSON Pointer `path`.

## Reconciliation

The counts above come from the fragments. The product changelogs list fewer
`BREAKING:` bullets than the fragments (Base Registry Engine 25, Casework 13,
Discovery 3, Evidence 18, Manifest 6, Messaging 9, Platform 6, Render 8,
Scheduling 6), because a fragment item is one migration step and a changelog
bullet often covers several. The items in "Breaking changes outside the
program fragments" are the changelog items no fragment states.
