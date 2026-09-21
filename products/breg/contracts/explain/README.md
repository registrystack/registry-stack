# `bregctl explain` wire contract

`bregctl --format json explain <subject> <project>` returns a `SuccessReport`
whose `explanation` field carries an envelope plus a subject-specific payload:

```json
{
  "ok": true,
  "command": "explain",
  "profile": "authoring",
  "revision": "...",
  "findings": [],
  "explanation": {
    "apiVersion": "registry.registrystack.org/breg-explain/v1alpha1",
    "kind": "RoutesExplanation",
    "routes": [ "..." ]
  }
}
```

`apiVersion` and `kind` are injected into `explanation` after serialization by
`explain_envelope` in `crates/registry-bregctl/src/lib.rs`; they are not
fields on any `registry-breg` type. Nine `kind` values exist, one per
subject (ten invocations, because `explain access` produces a different
`kind` with `--scenario` than without):

| Subject | `--scenario` | `kind` | Schema |
|---|---|---|---|
| `model` | n/a | `ModelExplanation` | `ModelExplanation.schema.json` |
| `access` | absent | `AccessExplanation` | `AccessExplanation.schema.json` |
| `access` | present | `AccessPreview` | `AccessPreview.schema.json` |
| `routes` | n/a | `RoutesExplanation` | `RoutesExplanation.schema.json` |
| `queries` | n/a | `QueriesExplanation` | `QueriesExplanation.schema.json` |
| `actions` | n/a | `ActionsExplanation` | `ActionsExplanation.schema.json` |
| `change-requests` | n/a | `ChangeRequestsExplanation` | `ChangeRequestsExplanation.schema.json` |
| `events` | n/a | `EventsExplanation` | `EventsExplanation.schema.json` |
| `lifecycle` | n/a | `LifecycleExplanation` | `LifecycleExplanation.schema.json` |

`lifecycle` is the one subject that takes no PROJECT: `bregctl explain
lifecycle` reports the request lifecycle the engine enforces, which no
registry project changes. It refuses a PROJECT rather than ignoring one, so
that a reader is never taught the lifecycle might vary, and so that an
unrelated authoring error cannot refuse an answer that never depended on a
project. Its report is also the only one whose `revision` is absent, for the
same reason: there is no compiled project to name.

Each schema file is draft 2020-12, self-contained (its own `$defs`, no
cross-file `$ref`), and is validated against every fixture the gate covers by
`crates/registry-bregctl/tests/explain_contract.rs`.

## What is pinned, what is opaque, and why

A key is **pinned** (named in `required`, typed, `additionalProperties:
false` on its containing object) when bregctl's `explain_*` function
reconstructs it key by key: each output key is an explicit line of Rust in
`lib.rs` that names the key and picks the value.

A key is declared **opaque** (`type: "object"` or `"array"`, with a
description, and no further `required`/`additionalProperties` constraint)
when bregctl instead serializes a `registry-breg` compiled-model value
directly (a "passthrough"): `serde_json::to_value(compiled.entities())`,
`"application": request.application`, `"limits": handler.limits`, and
similar. A passthrough's wire shape changes automatically whenever the
compiled-model type changes, with no corresponding line changing in
`explain_*`, so pinning it would create a contract nothing in `lib.rs` is
actually holding.

The two constructions can sit side by side under the same key name with
different treatment. For example, `actions[].handler.possibleWrites` is
`"possibleWrites": handler.writes` (a raw passthrough) and is opaque, while
`requests[].planner.possibleWrites` in `ChangeRequestsExplanation` is built
field by field (`target`, `operation`, `fields` each assigned explicitly) and
is pinned in full. Likewise `actions[].handler.limits` is a raw passthrough
of `CompiledActionHandlerLimits` and is opaque, while
`requests[].planner.limits` is eleven individually named integer fields and
is pinned in full.

`fieldType` (the compiled field's `FieldTypeSource`) is always a passthrough
wherever it appears (`queries[].operations[].apiFields[].fieldType`,
`actions[].inputs[].fieldType`, and elsewhere), so it is opaque everywhere,
even though it sits inside otherwise fully pinned `queries` and `actions`
payloads.

Four keys are pinned despite being technically passthroughs of primitive or
small values, because they are read by adopters today and are unlikely to
grow internal structure that would make a passthrough opaque in practice:
`model.registryId`, `model.version`, `model.moduleOrder`, and
`model.moduleClosure` (including its `id`, `digest`, and `version` entries).
`access.routes.entries[].entityId` and `AccessPreview.admitted` /
`AccessPreview.reason` are pinned the same way, alongside the other scalar
fields of `AccessExplanation`'s and `AccessPreview`'s own top level, because
both are small, hand-authored structs whose fields are named directly in
`registry-breg`.

`LifecycleExplanation` is pinned in full for a different reason. It is a
passthrough by construction (`serde_json::to_value` of a
`registry_breg::lifecycle::LifecycleDescription`), but the usual argument
against pinning a passthrough does not apply: `LifecycleDescription` is not
a compiled-model type that `explain_*` happens to forward, it exists only to
be this payload. Nothing else reads it, so its fields cannot drift under this
contract as a side effect of an unrelated change to the compiler; changing
them is changing this contract, and the test that gates it is the same test
that gates the engine's own lifecycle table.

Opaque nodes, in full:

- `model.entities`, `model.physicalNames`, `model.package`,
  `model.manifestProjection`
- `access.routes.entries[].*` other than `entityId`, `access.entities`,
  `access.actions`, `access.rowReach`, `access.claimContract`
- `AccessPreview.effectiveProfile`
- `RoutesExplanation`'s entity-route half of `routes[]` (every field other
  than the injected `kind`)
- `fieldType` everywhere it appears (`QueriesExplanation`,
  `ActionsExplanation`)
- `ActionsExplanation`'s `actions[].handler.possibleWrites`,
  `actions[].handler.limits`, and `actions[].evidence.capabilities`
- `ChangeRequestsExplanation`'s `requests[].application`,
  `requests[].onApproved`, and `requests[].fields[].schema` (a JSON Schema
  fragment read from the entity's generated schema artifact, not authored by
  `explain_*`)
- `EventsExplanation.deliveries` in full (the entire kind is one
  `serde_json::to_value` passthrough of `CompiledEventDeliveryInventory`)

## Compatibility promise

`apiVersion` versions the payload as a whole, across all nine kinds. A
change bumps it when it removes a pinned key, renames a pinned key, changes
a pinned key's type or enum member set, or **adds any key to a pinned
object**, optional or not. Adding a key is a breaking change here and
nowhere else in the stack, because every pinned object seals itself with
`additionalProperties: false`: a consumer holding this version's schema
rejects a response carrying tomorrow's new key, so calling that addition
compatible would be a promise the published schemas refuse to keep. A change
does not need a new `apiVersion` when it changes content inside a node this
contract declares opaque (adding, removing, or reshaping fields under
`entities`, `application`, `fieldType`, and so on), since those nodes are
not part of the pinned contract to begin with.

Read that second half as a warning, not as a permission. A stable
`apiVersion` is not a promise that the opaque nodes have not moved, and for a
consumer reading the compiled model, the event deliveries, the entity routes,
or a `fieldType`, the opaque nodes are most of what it consumes. Assert each
of those shapes where you read it, because drift inside an opaque node does
not fail loudly: a key that is renamed or removed reads as absent, which is
indistinguishable from a project that never declared it, so a consumer
returns a confident wrong answer instead of an error.

## Unexercised branches

No fixture tracked by `explain_contract.rs` declares a WASM action handler
(`handler.kind == "wasm"`). `ActionsExplanation.schema.json` pins that branch
from the `lib.rs` source (`kind`, `abi`, `moduleSha256`, `compatibility`),
but the gate never instantiates it; a WASM handler fixture is a good addition
to the tracked set the next time this contract needs to change.

A further branch is visible in the same sense but not exercised today: the
`"clear"` field-mutation kind in both `ActionsExplanation` and
`ChangeRequestsExplanation` (every tracked action and change request only
ever `"set"`s a field). It is pinned from source and unexercised by the gate.

No tracked fixture publishes a revisions route
(`operation: "revisions"` with `revisionKind: "list" | "detail"`) either, but
that costs this contract nothing: the entity-route half of
`RoutesExplanation.routes[]` is opaque, so an unexercised `revisionKind`
is simply one more field this contract does not pin.
