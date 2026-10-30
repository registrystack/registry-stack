# Adapter bad-authoring corpus

One minimal, self-describing workspace per refusal code in the Adapter
authoring surface. `adapterctl check` must refuse every `bad/` member with
exactly its expected code, and must pass the `base/` control with zero
findings. The corpus lives at `products/adapter/fixtures/corpus/`; this
file is its manifest.

## Layout

- `base/` is the clean control: profile, pack, and project that pass with
  zero findings. Any change here is a regression in the checks or reader.
- `bad/<code>/` is one member per code. The directory name IS the expected
  code, except the two reader-level members whose directories carry a
  suffix (`config.unknown-key-predicate`, `config.unknown-key-redelivery`);
  both expect `config.unknown-key`.
- Each member carries `profile.yaml`, `pack.yaml`, and `project.yaml`
  (plus `scripts/` or `fixtures/` where the defect needs them, and
  `runtime.yaml` where the expected code is a runtime or auth code).
- Every file's header comment names the expected code, the defect, and the
  exact `adapterctl check` invocation.
- Every `profile.yaml` and `pack.yaml` declares `version: "1"`; every
  `project.yaml` pins the sibling artifacts by `id`, `version`, and the real
  `sha256` of their bytes. If you edit an artifact, recompute the pins:
  `shasum -a 256 profile.yaml pack.yaml`.
- Every fixture entry names the profile operation it exercises
  (`operation: cases.get`).

## Running

One member:

```bash
target/debug/adapterctl check products/adapter/fixtures/corpus/bad/<code>/project.yaml
# runtime and auth members add:
#   --runtime products/adapter/fixtures/corpus/bad/<code>/runtime.yaml
```

The whole corpus (from the repository root):

```bash
for project in products/adapter/fixtures/corpus/base \
    products/adapter/fixtures/corpus/bad/*/; do
  name="$(basename "$project")"
  flags=()
  [[ -f "$project/runtime.yaml" ]] && flags+=(--runtime "$project/runtime.yaml")
  echo "=== $name"
  target/debug/adapterctl check "$project/project.yaml" "${flags[@]}" || true
done
```

`base/` prints `Authoring check passed.`; every `bad/` member refuses. On
macOS, source `scripts/cargo-runtime-library-path.sh` first.

## Member map

Codes are grouped by the artifact that carries the defect. "Layer" is who
refuses: reader (the platform YAML reader, before any check runs), checks
(the core authoring checks), or tool (adapterctl's own verification, here
the script digest pins). Members marked "per body" report the finding once
per route body carrying the defect (pack template plus instantiated route),
so the code appears twice; the refused code set is still exactly one.

### Profile members

| Member | Defect | Expected code | Layer |
|---|---|---|---|
| `adapter.envelope.invalid-placeholder` | A `{{bogus` placeholder never closes (co-fires `adapter.profile.response-envelope-uncompilable`, see the note above) | `adapter.envelope.invalid-placeholder` | checks |
| `adapter.profile.unknown-slot` | Response envelope names `bogusSlot`, outside the closed ten-slot vocabulary (co-fires `adapter.profile.response-envelope-uncompilable`) | `adapter.profile.unknown-slot` | checks |
| `adapter.profile.response-envelope-missing-result-slot` | Response envelope names neither `record` nor `records` | `adapter.profile.response-envelope-missing-result-slot` | checks |
| `adapter.profile.request-envelope-missing-record-slot` | A write operation's request envelope names no `record` slot | `adapter.profile.request-envelope-missing-record-slot` | checks |
| `adapter.profile.problem-envelope-missing-code-slot` | Problem envelope names no `problemCode` slot | `adapter.profile.problem-envelope-missing-code-slot` | checks |

### Pack members

| Member | Defect | Expected code | Layer |
|---|---|---|---|
| `adapter.pack.endpoint-component-invalid` | Endpoint declares component `direct`, not a producer | `adapter.pack.endpoint-component-invalid` | checks |
| `adapter.pack.graphql-query-required` | `graphql` endpoint names no `queryFile` | `adapter.pack.graphql-query-required` | checks |
| `adapter.pack.reserved-header-name` | `static-api-key` declares the reserved header `Authorization` | `adapter.pack.reserved-header-name` | checks |
| `adapter.pack.unknown-script` | A route's `rhai` file is not in the digest-pinned inventory | `adapter.pack.unknown-script` | checks |
| `adapter.pack.unknown-template-parameter` | Template body references `{{missingParam}}`, no declared parameter provides it | `adapter.pack.unknown-template-parameter` | checks |
| `adapter.pack.digest-pin-required` | Script file's bytes do not hash to its pin (the pin is valid hex, wrong value) | `adapter.pack.digest-pin-required` | tool |
| `adapter.pack.script-uncompilable` | A pinned script does not parse (missing closing brace; its pin matches the broken bytes) | `adapter.pack.script-uncompilable` | tool |

`adapter.route.nesting-depth-exceeded` has no corpus member: it fires when
the worst-case walk saturates past the reader's depth bound, and a YAML
document nested that deep is refused by the reader first with
`yaml.too-deep` (both bounds are the same 128-level constant), so no
member can reach it from authored files. Every other code in the closed
authoring vocabulary carries exactly one member, and the sweep over all of
them must stay green before this corpus is relied on as a gate.

One structural co-fire is accepted: `adapter.project.unknown-route`'s
condition (a binding whose route id has no steps) is a strict subset of
`adapter.project.template-not-instantiated`'s condition (a template ref
that never materializes as a pack route or instantiated route), so the
unknown-route member is refused with both codes at once and its sweep
expectation lists both.

Three more co-fires come from the workspace-level envelope derivation,
which walks every operation's response envelope with the project's
bindings. A profile whose response envelope cannot compile is refused by
its own code and by `adapter.profile.response-envelope-uncompilable`
(`adapter.envelope.invalid-placeholder`, `adapter.profile.unknown-slot`):
the same malformed text trips both. And a binding naming an undeclared
record type (`adapter.project.unknown-record-type`) fails the record-slot
expansion of its operation's envelope, so the derivation code rides along.
All three are inherent: the fault the member tests is the fault the
derivation sees, and their sweep expectations list both codes.

### Project members

| Member | Defect | Expected code | Layer |
|---|---|---|---|
| `adapter.project.unknown-template` | An orphan instantiation references no declared template | `adapter.project.unknown-template` | checks |
| `adapter.project.unknown-template-parameter` | Instantiation supplies parameter `bogus`, undeclared by the template | `adapter.project.unknown-template-parameter` | checks |
| `adapter.project.parameter-type-mismatch` | Instantiation binds integer parameter `page_size` a string | `adapter.project.parameter-type-mismatch` | checks |
| `adapter.project.required-parameter-unbound` | Instantiation omits required parameter `program` | `adapter.project.required-parameter-unbound` | checks |
| `adapter.project.pin-digest-mismatch` | Pinned profile digest does not match the profile bytes (valid hex, wrong value) | `adapter.project.pin-digest-mismatch` | checks |
| `adapter.project.pin-version-mismatch` | Pack pinned at version `0.0.1`, pack declares `1` (digest matches the bytes) | `adapter.project.pin-version-mismatch` | checks |
| `adapter.project.duplicate-route-id` | Instantiated route id collides with the pack template name | `adapter.project.duplicate-route-id` | checks |
| `adapter.project.unknown-operation` | Binding references no declared profile operation | `adapter.project.unknown-operation` | checks |
| `adapter.project.unknown-record-type` | Binding references no declared record type (co-fires `adapter.profile.response-envelope-uncompilable`, see the note above) | `adapter.project.unknown-record-type` | checks |
| `adapter.project.unknown-route` | Binding references no declared route (co-fires `adapter.project.template-not-instantiated`, see the note above) | `adapter.project.unknown-route` | checks |
| `adapter.project.template-not-instantiated` | Binding names the raw template `findCases`; `templatedRoutes` is empty | `adapter.project.template-not-instantiated` | checks |
| `adapter.project.upstream-budget-exceeded` | Worst case 2 sends (loop bound 2) against a budget of 1 | `adapter.project.upstream-budget-exceeded` | checks |

### Route members

| Member | Defect | Expected code | Layer |
|---|---|---|---|
| `adapter.route.unknown-endpoint` | Send names endpoint `nope` | `adapter.route.unknown-endpoint` | checks, per body |
| `adapter.route.unknown-direct-target` | Enrich names `direct:absentRoute` | `adapter.route.unknown-direct-target` | checks, per body |
| `adapter.route.direct-cycle` | Internal routes `loopA` and `loopB` call each other | `adapter.route.direct-cycle` | checks |
| `adapter.route.direct-depth-exceeded` | 18 chained direct routes exceed the 16-deep bound | `adapter.route.direct-depth-exceeded` | checks |
| `adapter.route.from-not-direct` | A route consumes from `http:cases`, not `direct:` | `adapter.route.from-not-direct` | checks |
| `adapter.route.maximum-items-required` | Split declares no `maximumItems` | `adapter.route.maximum-items-required` | checks, per body |
| `adapter.route.non-safe-send-in-split` | POST inside a split with `stopOnException: false` | `adapter.route.non-safe-send-in-split` | checks, per body |
| `adapter.route.maximum-iterations-required` | Loop declares no `maximumIterations` | `adapter.route.maximum-iterations-required` | checks, per body |
| `adapter.route.loop-count-above-bound` | Loop count `5` exceeds `maximumIterations: 2` | `adapter.route.loop-count-above-bound` | checks, per body |
| `adapter.route.multiple-non-safe-sends` | One `idempotentConsumer` guards two POST sends | `adapter.route.multiple-non-safe-sends` | checks |
| `adapter.route.write-without-idempotency` | Write route's POST sits outside any `idempotentConsumer` | `adapter.route.write-without-idempotency` | checks |
| `adapter.route.redelivery-over-non-safe-send` | Redelivery over a POST send whose endpoint operation claims no `idempotentUpstream` | `adapter.route.redelivery-over-non-safe-send` | checks, per body |
| `adapter.route.uncatchable-clause` | onException names `budget.exhausted` | `adapter.route.uncatchable-clause` | checks, per body |
| `adapter.route.redelivery-without-upstream-send` | Redelivery declared, no upstream send reachable | `adapter.route.redelivery-without-upstream-send` | checks, per body |
| `adapter.route.retry-while-without-redeliveries` | `retryWhile` on a policy with `maximumRedeliveries` 0 | `adapter.route.retry-while-without-redeliveries` | checks, per body |
| `adapter.route.predicate-ambiguous` | `when` clause carries `constant` and `jsonpath` | `adapter.route.predicate-ambiguous` | checks, per body |
| `adapter.route.predicate-language-required` | `when` clause carries no language key | `adapter.route.predicate-language-required` | checks, per body |
| `adapter.route.error-handler-shape` | `errorHandler` step carries no handler | `adapter.route.error-handler-shape` | checks, per body |
| `adapter.route.empty-exception-list` | onException clause names no error class | `adapter.route.empty-exception-list` | checks, per body |
| `adapter.route.handled-and-continued` | onException clause sets `handled: true` and `continued: true` | `adapter.route.handled-and-continued` | checks, per body |
| `adapter.route.unknown-operation` | POST send names operation `nope`, which its endpoint does not declare | `adapter.route.unknown-operation` | checks, per body |

### Runtime and auth members

These members ship `runtime.yaml`; check them with `--runtime runtime.yaml`.

| Member | Defect | Expected code | Layer |
|---|---|---|---|
| `adapter.auth.kind-mismatch` | `static-authorization` credential on a `basic` endpoint | `adapter.auth.kind-mismatch` | checks |
| `adapter.auth.none-not-loopback` | `none` endpoint reaches a named TLS host with no mTLS identity | `adapter.auth.none-not-loopback` | checks |
| `adapter.runtime.insecure-origin` | Binding on `http://` off the loopback exception | `adapter.runtime.insecure-origin` | checks |
| `adapter.runtime.missing-endpoint` | Runtime binds no endpoint; the pack declares `cases` | `adapter.runtime.missing-endpoint` | checks |
| `adapter.runtime.unknown-endpoint` | Runtime binds endpoint `nope` | `adapter.runtime.unknown-endpoint` | checks |

### Fixture members

Fixture files sit in the member's `fixtures/` directory, which
`adapterctl check` discovers beside the project.

| Member | Defect | Expected code | Layer |
|---|---|---|---|
| `adapter.fixture.unknown-endpoint` | Recorded request names endpoint `nope` | `adapter.fixture.unknown-endpoint` | checks |
| `adapter.fixture.unknown-intercept` | Intercept names endpoint `nope` | `adapter.fixture.unknown-intercept` | checks |
| `adapter.fixture.response-schema` | Expected facade response's record violates the derived result schema (`case_type` integer, declared string) | `adapter.fixture.response-schema` | checks |
| `adapter.fixture.unknown-problem-code` | Expected 404 problem body names code `cases.spectre`, which the profile does not declare; the member's profile spells the problem slot as a literal `code` member, the member the check reads | `adapter.fixture.unknown-problem-code` | checks |

### Reader-level members

Three members expect the platform YAML reader's own codes, refused with
path, line, and column before any check runs.

| Member | Defect | Expected code | Layer |
|---|---|---|---|
| `config.unknown-key-predicate` | `bogusKey` beside a valid `jsonpath` predicate | `config.unknown-key` | reader |
| `config.unknown-key-redelivery` | `bogusOption` inside the nested `redeliveryPolicy` | `config.unknown-key` | reader |
| `config.missing-key-project` | The project document omits the required `project` block | `config.missing-key` | reader |

## Conventions

- Member workspaces are foreign on purpose: the `case-api` profile serves
  `/v2/cases/{type}/{case_id}` with `case_id` identifiers, proving the
  checks are convention-free. They are also minimal: one endpoint, one
  template, one binding, one defect.
- Credentials are always `secret:` references, never values; example
  origins use the reserved `.example.invalid` names.
- The wrong pins are valid form, wrong value: the pack script digest pin is
  `sha256:1111…`, the project's profile digest pin is `sha256:2222…`; every
  other member pins real digests and the pinned versions are real.
