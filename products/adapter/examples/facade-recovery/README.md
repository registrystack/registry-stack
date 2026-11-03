# Recover a linear facade write

This reference project shows the Adapter's smallest supported multi-effect
write. Use it when a source process has a fixed sequence of provider-idempotent
HTTP operations and a later operation needs only bounded identifiers returned
by an earlier one.

The first operation creates a draft and checkpoints only `source_id`. The
second operation reconstructs its request from that identifier and the
governed constant `finalize`. If either operation fails, the facade returns its
bounded 409 problem and keeps the first unfinished ordinal. Send the same body
and `Idempotency-Key` after repairing the source or credential. The retry skips
every committed ordinal. A clean failed attempt releases its lease for that
immediate retry; cancellation or process loss keeps the lease until expiry. A
changed body returns 422 instead.

The provider must document why each named source operation is idempotent. The
two `idempotentUpstream: true` declarations in `pack.yaml` describe the
controlled reference service only. They do not make an arbitrary API exactly
once, and they do not extend a provider's own deduplication window. Configure
the Adapter's response retention no longer than that documented provider
window.

Check and compile the project from the repository root:

```sh
adapterctl check products/adapter/examples/facade-recovery/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/examples/facade-recovery/pack.yaml

adapterctl compile products/adapter/examples/facade-recovery/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/examples/facade-recovery/pack.yaml \
  --output /tmp/facade-recovery-openapi.json
```

Replay the source transcript without a live source:

```sh
adapterctl fixtures replay \
  products/adapter/examples/facade-recovery/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/examples/facade-recovery/pack.yaml \
  --fixtures products/adapter/examples/facade-recovery/fixture.yaml
```

Run the controlled request journey from the repository root. It requires
Cargo, Docker, and an available loopback port:

```sh
CARGO_TARGET_DIR=/absolute/path/to/external-target \
  products/adapter/examples/facade-recovery/run-loopback.sh
```

Choose a target directory outside the repository. The runner refuses to build
until `CARGO_TARGET_DIR` is explicit, and disables incremental and debug build
data to keep the local proof bounded.

The runner starts a disposable pinned PostgreSQL container and invokes one
named `postgres-test` integration journey. The maintained harness generates
an ephemeral runtime configuration, signing key, JWKS, access token, and
controlled loopback provider, then starts the real `adapter` binary. The live
client observes a 409 when the second provider operation is unavailable, an
immediate 201 after sending the same body and key again, an exact 201 replay,
and a 422 after changing the body under that key. The journey also verifies
that only two provider-side logical effects occurred. This is a test-feature
local executable journey, not a deployment template or an external-provider
conformance claim.

The runtime keeps only the checkpoint ordinal and declared identifier strings.
It never stores the caller body, a prepared request, source response body,
headers, credentials, or an arbitrary script value. The finite lease prevents
concurrent recovery. The retention expiry erases checkpoint authority while
leaving the key spent, so an expired process cannot be started again by a
retry. Deploying another artifact under the same `runtime.id` is fenced while
live recovery belongs to the current artifact.

This closed form does not admit scripts, branches, loops, redelivery,
`direct`, exception bodies, or nested EIPs. Those shapes would require state
from a skipped response that this data-minimizing contract deliberately does
not store. It also keeps the default non-2xx failure classification and uses
source endpoints without `requestHeaders`, so a retry cannot reinterpret a
generic 4xx as success or depend on an unstored header from an earlier reply.
It also keeps a source 202 at the current ordinal because this generic form
declares no source-native status operation.
The original caller record is digest-bound and resupplied, but this initial
subset still limits later sends to constants and checkpointed identifiers so
the reconstruction rule stays locally reviewable. That is a supported-subset
choice, not a claim that resuming from caller fields would require storing the
caller body.
