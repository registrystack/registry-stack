# Experiment 5: a second target profile over an unchanged pack

Status: experiment, not a maintained profile or pack. The profile is
authored from the public FHIR R4 specification
(https://hl7.org/fhir/R4/bundle.html, https://hl7.org/fhir/R4/http.html#paging,
https://hl7.org/fhir/R4/operationoutcome.html); no server was contacted.
Nothing here changes Rust.

## What it tries to express

D17 says "the same DHIS2 pack serves a `breg-records` deployment and a
later GovStack deployment unchanged" (CONCEPT section 7). This experiment
writes a third facade profile, `fhir-facade` (`profile.yaml`), and binds an
existing pack to it without touching the pack:

- `pack.yaml` and `scripts/` are byte copies of experiment 4's
  `jsonapi-households` pack (same digest,
  `sha256:993b64ddd49a122dade6ae198e5d72209c89d87a13fd737ef01e2761bd025e28`).
- `fhir-search-type` answers a searchset Bundle with `entry` and a `next`
  link; `_page_token` and `_count` are the paging parameters.
- `fhir-read` answers one resource with `resourceType` and `id`.
- Problems answer an OperationOutcome whose codes are FHIR IssueType codes
  (`not-found`, `transient`, `processing`, `exception`), with no `status`
  member (FHIR carries the status on the HTTP response only).
- A probe also rebinds the maintained `dhis2-tracker` example deployment
  (`products/adapter/packs/dhis2-tracker/pack.yaml`) to this profile.

## What it proves

- A third profile with its own operation ids, underscore query parameter
  names (`_page_token`, `_count`), problem codes, and a problem envelope
  without a `status` slot is pure configuration: `check` accepts it.
- The engine-side search and read routes bind to it with no pack change.
- The envelope's result slot is validated against the bound record type:
  the fixture's `entry` items are checked against `household` (probe
  `e5-fhir-entry-wrapper` shows the reverse).

## What it could not express (gaps)

1. **Per-record wrapping.** FHIR wraps every Bundle entry as `{"resource":
   ...}`. The `records` slot fills a whole array with bare records and has
   no item template, so the FHIR-correct expected body is refused (probe
   `e5-fhir-entry-wrapper`, `adapter.fixture.response-schema` at
   `/entries/0/expectedFacadeResponse/body/entry/0/resource`). The committed
   fixture asserts the non-FHIR shape the vocabulary does produce.
2. **Record members at the top level.** A FHIR read puts the resource's own
   members beside `resourceType` and `id`. The `record` slot is one member
   value, so the profile nests the record in an `extension`. A spread form
   (`{"resourceType": .., "id": .., {{record}}}`) is not JSON; it passes
   `check` only because no fixture exercises the read (probe
   `e5-read-spread`, and the defect below).
3. **Field and type names.** FHIR member names are camelCase
   (`resourceType`, `birthDate`) and resource types are capitalized
   (`Patient`). Record field and record type names must match
   `^[a-z][a-z0-9_-]{0,63}$` (probes `e5-camel-fields`,
   `e5-camel-field-only`, `config.invalid-value`), and the record type is
   what fills `{type}` in the facade path, so `/fhir/Patient` cannot be
   served. There is no per-profile name mapping.
4. **Cursor inside a URL.** R4 `Bundle.link.url` is an absolute URL. A slot
   is a whole member value or a whole JSON value; `"url":
   "https://../household?_page_token={{?nextCursor}}"` is not a valid slot
   use, and the check does not notice (probe `e5-link-absolute-url`
   passes, see the defect below).
5. **Conditional members.** With no next page, `{{?nextCursor}}` drops the
   `url` member but leaves `{"relation": "next"}` in the `link` array, which
   is invalid FHIR (`link.url` is 1..1). There is no conditional array item
   or object.
6. **Problem vocabulary lives in the pack.** The pack's handled clauses
   build breg-records problem bodies (`type`, `title`, `status`, `code`
   with `source.*` codes). Under `fhir-facade` the codes are not in
   `problems` and the body is not an OperationOutcome, yet `check`
   passes, both for the copied pack and for the maintained `dhis2-tracker`
   pack (probe `e5-dhis2-pack`). Either the runtime refuses every mapped
   error, or a FHIR caller receives a breg-records problem. CONCEPT section
   7 says the engine fills `problemCode`, `problemTitle`, `problemDetail`,
   and `status`, but no pack construct supplies those values: the pack
   writes the whole body. D17 does not hold for errors.
7. **Fixtures are profile-bound.** A fixture entry names a profile
   operation and asserts a facade body in the profile's envelope, so a
   pack's fixture corpus cannot move with the pack. The dhis2 fixtures
   against `fhir-facade` give five `adapter.fixture.unknown-operation`
   errors (probe `e5-dhis2-pack`, `check-with-fixtures.txt`), and this
   experiment's own first run gave
   `error[adapter.fixture.unknown-operation] /fixtures/0/entries/0/operation`
   until the entry was renamed. Upstream exchange and record result would
   need to be split from the envelope assertion to reuse them.

## Check defects found

- **A non-JSON envelope silently disables fixture validation.** The
  profile check scans placeholders but never parses an envelope as JSON;
  the fixture body check calls `derive_operation_result_schema` and, on
  `Err(_)`, skips the entry (`crates/registry-adapterctl/src/check.rs`,
  `check_fixture_bodies`). The comment claims the pairing refusal is
  already reported by the core fixture checks; that is true only for an
  unknown operation. Probes `e5-search-not-json` (a search envelope with
  `,,,`, exercised by the fixture), `e5-envelope-not-json` and
  `e5-read-spread` (read envelopes that are not JSON), and
  `e5-link-absolute-url` (a slot inside a string) all pass.
- **A problem envelope that is not JSON passes**: `'<OperationOutcome
  code="{{problemCode}}"/>'` (probe `e5-problem-not-json`).
- **Envelope literals are not asserted.** A literal string member derives
  `{"type": "string"}`, so an expected body with `resourceType: Patient`,
  `type: transaction-response`, and `relation: previous` passes against an
  envelope that fixes `Bundle`, `searchset`, and `next` (probe
  `e5-literal-mismatch`).
- **Facade paths unchecked.** `path: /fhir/Basic` (no `{type}`) for a
  search, and `path: fhir/Basic/{whatever}` (relative, unknown placeholder,
  no `{record_id}`) for a read, pass (probe `e5-path-without-type`).
- **Problem bodies not checked against the profile** (gap 6): neither the
  code list nor the envelope shape.

## Check run

```
adapterctl check products/adapter/experiments/second-target-profile/project.yaml \
  --profile products/adapter/experiments/second-target-profile/profile.yaml \
  --runtime products/adapter/experiments/second-target-profile/runtime.yaml
Authoring check passed.
0 errors, 0 warnings in 13 files
exit=0
```

Probe outputs are recorded verbatim in the findings report returned with these
experiments, not in this directory.
