# Engine boundary plan (module now, crate after the owner moves the branch)

Decision, 31 Oct: the engine boundary inside `registry-adapter` is built
as a module now, and becomes the `registry-adapter-engine` crate as the
first group after the owner moves this branch onto the rebased
candidate. The Evidence switch sequences the crate split from the
rebased candidate, so the module shape below is the crate shape: the
split itself must be a move, an import-prefix rewrite, and a Cargo
manifest, nothing else.

## Module layout

`crates/registry-adapter/src/engine/` holds, from today's flat layout:

- `auth` (outbound authentication), `component` and `component/*`,
  `decoder`, `effective_contract`, `egress`, `errorhandler`,
  `exchange`, `job`, `job_sources`, `language`, `load`, `processor`,
  `replay`, `resilience`, `route`, `scripts`.

The crate root keeps the facade: `cli`, `envelope`, `facade`,
`facade_generated_properties`, `idempotent`, `journal`, `notifier`,
`read_request`, `serve`, `main`.

`engine/mod.rs` is the boundary: the public compile entry, the program
and run types, and the re-exports consumers may name. Nothing under
`engine/` may reference a facade module or a facade-only dependency
(axum, tokio-postgres, deadpool-postgres, tokio-postgres-rustls,
jsonwebtoken, registry-platform-oidc, registry-platform-authcommon).

## Untangling the exchange module

`exchange.rs` carries two concerns. The exchange itself (properties,
bounded-value helpers, split and loop bookkeeping, replay capability)
is engine. The write-custody half (`WriteState`, the claim guard,
`finish_with_client` over `GenericClient`, the `PostgresIdempotencyStore`
types, `idempotency_failure`) is facade custody and moves beside the
idempotency store at the crate root. The route interpreter must not
name custody types; the facade wraps its write sends.

## Postgres source: compile in the engine, client in the host

`component/postgres.rs` keeps the query parse and check (`pg_query`),
the transaction preamble, the parameter typing, and the row-to-item
shaping, and defines the `PostgresSource` seam. The pool and TLS
connector construction is host work and moves to `registry-adapter-job`
(and test fixtures). No postgres client type or dependency is reachable
from `engine/`.

## Runtime bindings

Core states the binding shape (`AdapterEndpointBindings`, landed):
id, endpoints, outbound TLS, the private-CIDR allowlist. The job's
runtime document carries those members alone plus the job `sources`
block; the facade document is unchanged and yields the same view
through `endpoint_bindings()`. `check_endpoint_bindings` is the check
every mode runs; the facade's `check_runtime` adds only its OIDC block.
At integration: `JobRuntimeConfig.core` becomes the bindings type, the
check-context field follows, `egress` compiles against the bindings,
and the job crate names core plus the engine boundary only.

## Public compile entry

One entry compiles a pack route from in-memory artifacts (the parsed
pack, project, profile, job, and endpoint bindings) under a named
profile (today `facade` and `job`) to a reusable program.
`compile_job` parses its files into those artifacts and calls the same
entry. No file I/O below the entry.

## Dependency proof while the boundary is a module

`products/adapter/scripts/check_dependency_direction.py` gains a
module-boundary section: it fails if a file under
`crates/registry-adapter/src/engine/` names a facade module, a
facade-only dependency, or a postgres client crate. The proof becomes
`cargo tree -p registry-adapter-engine` (no axum, tokio-postgres,
deadpool) when the crate split lands; until then the import-surface
check holds the same line.
