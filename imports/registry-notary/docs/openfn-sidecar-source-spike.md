# OpenFn Sidecar Source Spike

> Historical note: this file records the initial sidecar spike and decision
> trail. For adopter-facing setup, use
> [`source-claim-modeling-guide.md`](source-claim-modeling-guide.md) and
> [`../crates/registry-notary-openfn-sidecar/README.md`](../crates/registry-notary-openfn-sidecar/README.md).

This spike explores using an OpenFn-powered sidecar as a one-record source for
Registry Notary claim evaluation. The starting point is intentionally narrow:
support one subject lookup at a time, return at most one normalized source
record, and let Registry Notary keep the attestation decision.

## Preferred First Shape

Use the existing `registry_data_api` source connector and make the sidecar expose
a small Registry Data API facade:

```text
GET /datasets/{dataset}/{entity}?{lookup_field}={lookup_value}&fields=a,b&limit=2
Authorization: Bearer <notary-to-sidecar-token>
Data-Purpose: <purpose>
```

Response:

```json
{
  "data": [
    {
      "national_id": "person-123",
      "birth_date": "1990-01-01"
    }
  ]
}
```

Registry Notary already interprets this shape:

- `data: []` becomes `SourceNotFound`.
- `data: [record]` feeds the claim rule.
- `data` with more than one row becomes `SourceAmbiguous`.

That means the first spike needs no new connector type. OpenFn can sit behind
the facade, call the target service through an adaptor, and normalize the result
into the existing one-record contract.

## OpenFn Execution Model

Do not put an OpenFn Lightning webhook or queued run directly in the Notary
request path. Lightning is designed around work orders and runs that are queued,
claimed by workers, and completed asynchronously. That model is useful for
background sync and durable workflow processing, but it is a poor fit for a
claim evaluation that needs a bounded answer before the HTTP response returns.

For this Notary source shape, the sidecar should use the local OpenFn runtime
or CLI execution path instead. The CLI supports running a job or workflow as a
blocking command and writing the final state to stdout or a file. A sidecar can
wrap that process with its own timeout, output parsing, and error mapping.

The local confirmation command used for this spike was:

```sh
npx -y @openfn/cli@1.36.0 target/openfn-sidecar-spike/lookup-job.js \
  -a common@3.1.0 \
  -s target/openfn-sidecar-spike/state.json \
  -O \
  --log-json \
  --timeout 10000
```

The first run installed the adaptor and took about 4.2 seconds. A subsequent
cached run completed in about 157 ms and printed a final state containing:

```json
{
  "data": {
    "data": [
      {
        "national_id": "person-123",
        "birth_date": "1990-01-01"
      }
    ]
  }
}
```

That confirms the synchronous sidecar approach is viable in principle, with one
important operational requirement: adaptors must be pre-installed or warmed
before serving Notary traffic. Cold installs are too slow and too dependent on
network/package registry availability for an attestation request.

## Boundary

The sidecar should fetch and normalize source facts. Registry Notary should keep
ownership of:

- public caller authorization;
- purpose requirement;
- evidence scopes;
- claim rules;
- disclosure policy;
- credential issuance;
- evaluation audit.

The sidecar must not decide claim satisfaction. For example, it can return
`birth_date`, but the configured Notary claim decides how that value is
attested or disclosed.

## Sidecar Responsibilities

- Hold target-service credentials outside Notary config.
- Run pinned OpenFn workflow or adaptor code, not `latest` in production.
- Enforce one lookup per request for this spike.
- Return no more than two records so ambiguity can be detected cheaply.
- Respect `fields` as a projection hint where possible.
- Propagate `Data-Purpose` and correlation headers to downstream systems where
  appropriate.
- Return a compact, normalized JSON record with no credential material.

## Notary Config Sketch

```yaml
evidence:
  source_connections:
    openfn_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: OPENFN_SIDECAR_TOKEN

  claims:
    - id: date-of-birth
      source_bindings:
        crvs:
          connector: registry_data_api
          connection: openfn_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: subject_id
            field: national_id
            op: eq
            cardinality: one
          fields:
            birth_date:
              field: birth_date
              type: date
              required: true
      rule:
        type: extract
        source: crvs
        field: birth_date
```

## Spike Evidence

`openfn_sidecar_rda_facade_can_source_single_item_attestation` in
`crates/registry-notary-server/src/standalone.rs` starts a test-only sidecar
that behaves like the facade above. The test proves that Registry Notary can:

- authenticate to the sidecar with a source token;
- send the configured `Data-Purpose`;
- request `limit=2` and the projected fields;
- evaluate a claim from one normalized record;
- preserve Notary provenance with `source_count = 1`.

## Next Decisions

1. Keep using the Registry Data API facade, or add an explicit `openfn`
   connector once the contract grows beyond RDA.
2. Decide whether the sidecar wraps OpenFn CLI child processes first, or embeds
   the runtime more directly once the API is stable enough.
3. Decide whether the sidecar should expose only per-source routes or a generic
   `/lookup` route.
4. Define the error mapping for target-service failures: unavailable,
   rate-limited, auth failed, ambiguous, and not found.
5. Decide where correlation ID propagation becomes mandatory.
6. Pick one real adaptor-backed target for the next spike, preferably a simple
   HTTP or OpenCRVS-style lookup before OAuth-heavy systems.
