# registry-linkml

Reader for the LinkML subset Registry Stack adopter tooling consumes, plus an
embedded snapshot of the [PublicSchema](https://publicschema.org) reference
model that tooling offers as a starting point.

The crate knows nothing about registries. `bregctl init --from publicschema`
is its consumer: it reads the model here, lets an adopter pick concepts and
properties, and writes the registry project itself.

## Layout

| Path | Holds |
|---|---|
| `src/reader.rs` | `read_bundle`: a list of LinkML files in, one resolved `Model` out |
| `src/model.rs` | The resolved types and the inheritance helpers (`induced_slots`, `is_subclass_of`, `concrete_descendants`) |
| `src/publicschema.rs` | The embedded snapshot, its pin, and PublicSchema's annotation conventions (labels, convergence, sensitivity, property groups) |
| `publicschema/schema/` | The vendored PublicSchema domain files, byte for byte |
| `publicschema/PIN.yaml` | Which upstream commit the files came from |
| `publicschema/LICENSE-VOCABULARY` | The CC BY 4.0 notice the vendored files are published under |
| `publicschema/starters/` | Ready-made `bregctl` selections; their format belongs to `bregctl`, this crate only ships the bytes |
| `publicschema/sync-snapshot.sh` | Refreshes `schema/`, the licence notice, and `PIN.yaml` from a local checkout |

## The LinkML subset

The reader takes the files it is given and nothing else: no `imports` are
followed. It models classes (`is_a`, `mixins`, `abstract`, `slots`), slots
(`range`, `multivalued`, `required`, `identifier`), enums
(`permissible_values` with `meaning`), scalar `annotations`, and CURIE
prefixes, which it expands to absolute URIs while reading.

Keys whose absence would change a class's shape are refused rather than
dropped: `attributes`, `slot_usage`, and `union_of` on a class; `any_of`,
`exactly_one_of`, `all_of`, and `none_of` on a slot; `inherits`, `include`,
`minus`, and `reachable_from` on an enum. A bundle that relies on them fails
to read instead of reading wrong. Other LinkML keys are ignored.

## The PublicSchema snapshot

The vendored files are the domain half of the upstream composite: the root
`publicschema.yaml` and the fourteen files that define PublicSchema's own
classes, slots, and vocabularies. The `external/*` alignment schemas,
`bibliography`, `metrics`, and `publicschema-extensions` are not vendored;
nothing in the domain files depends on them.

`PIN.yaml` names the upstream commit. Refresh the snapshot with:

```bash
crates/registry-linkml/publicschema/sync-snapshot.sh /path/to/publicschema.org
cargo test -p registry-linkml
```

The snapshot test in `tests/snapshot.rs` states the pinned model's counts
(classes, slots, enums, values, abstract and featured classes); a refresh that
changes them updates the test on purpose, so a review sees what moved.

Provenance caveat: when the snapshot was first taken, the pinned commit was
ahead of the upstream remote's `main`. Before a release that ships this
crate, confirm the commit in `PIN.yaml` is reachable from a published
upstream branch, or re-sync from one that is.

## Licence and attribution

The crate's code is Apache-2.0 like the rest of the workspace. The files
under `publicschema/schema/` are PublicSchema's reference model, published
under Creative Commons Attribution 4.0 International; `LICENSE-VOCABULARY`
is the notice that travels with them, and `publicschema::LICENSE_NOTICE`
exposes it. Anything that reproduces the vendored definitions, such as a
registry project generated from them, carries a "PublicSchema, CC BY 4.0"
attribution with the model version from `PIN.yaml`.
