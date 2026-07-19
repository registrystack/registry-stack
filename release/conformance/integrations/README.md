# External integration evidence

This directory defines the release-owned evidence boundary for Registry Stack's
OpenCRVS and DHIS2 integration profiles. It lets an approved operator prepare a
repeatable run and publish a bounded result without publishing source records,
credentials, infrastructure details, or raw logs.

Both profiles are **Registry Stack-supported unofficial integration profiles**.
They prove one reviewed read operation against one exact upstream baseline.
They are not product certification or general conformance claims.

## Evidence boundary

The checked-in profiles, schema, and runner are a source packet, not live
evidence. A passing public result also requires all of these external inputs:

- A published Registry Stack candidate and its complete signed release assets.
- An owner-approved non-production source instance with stable test records.
- Owner-attested metadata, source routes, identifiers, and credentials.
- A source-side audit or request-counter probe that can distinguish zero from
  one data-operation call for every case.
- Approved restricted evidence storage, retention, redaction, and teardown.

For OpenCRVS, the `/registry/sync/search` compatibility probe must pass against
the exact pinned DCI adapter, core, and Farajaland tuple before the live run.
The current starter's synthetic route is not evidence that the real operation
is compatible.

For DHIS2, the instance owner must attest every metadata UID used by the
authored adapter. The `DEMO_*` values in the starter are examples and cannot
appear in a live evidence project.

Do not simulate either prerequisite. Do not convert fixture output, a dry run,
or application-only logs into candidate evidence.

## Inspect the plan

Validate the checked-in packet:

```sh
python3 release/scripts/integration-e2-runner.py validate
```

Inspect either profile as a readable plan:

```sh
python3 release/scripts/integration-e2-runner.py plan \
  --profile opencrvs-dci-v1.9
```

Use `dry-run` for the same bounded contract as JSON:

```sh
python3 release/scripts/integration-e2-runner.py dry-run \
  --profile dhis2-tracker-2.41.9 > integration-plan.json
```

The JSON has `candidate_evidence: false` and
`status: planned_not_executed`. It includes input names, not values.

## Run the operator-owned journey

The approved operator wrapper must execute these stages in order and within
the profile limits:

1. Download the candidate assets listed in `release/VERIFY.md` into a fresh,
   dedicated directory.
2. Use the public runner to validate checksums, signatures, provenance,
   capsule lineage, image locks, and digest files. The runner copies the exact
   closed asset set through no-follow file descriptors into a fresh owner-only
   temporary snapshot. It makes every snapshot file non-writable, verifies
   and authenticates only snapshot files, then executes only the snapshot
   binary for its self-reported version. It removes the snapshot after success
   or failure. The source-directory binary is never executed.
3. Have the approved operator wrapper create its own authenticated,
   non-writable snapshot and initialize the profile's starter only from that
   snapshot. A completed candidate-only validation does not make the mutable
   source directory safe for later execution.
4. Apply only the reviewed authored changes listed in the selected profile.
   Do not edit generated YAML.
5. Run the offline project `test`, `check`, and `build` commands. Inspect the
   generated project, then record hashes of authored inputs, the build review,
   and both generated closures.
6. Deploy one candidate-digest Registry Relay, Registry Notary, and PostgreSQL
   set per authority.
7. Query the approved source-side probe before and after every closed test
   case. The five trust denials must prove no data-operation contact.
8. Retain raw evidence only in the approved restricted location. Publish only
   safe result codes, timings, contact classifications, correlation hashes,
   and evidence hashes.
9. Seed restricted-value canaries. Scan restricted evidence before producing
   the public artifact, then re-hash generated files and compare them with the
   reviewed build hashes. The public runner separately scans the supplied
   public result for the same canaries.
10. Attempt scoped teardown from a `finally` path, even after a failed case.
    Record its start and completion times, bounded duration, outcome, and
    sanitized evidence hash.

`source_data_access` counts only the profile's reviewed data operation. For
OpenCRVS, OAuth or JSON Web Key Set (JWKS) traffic does not count as a
`/registry/sync/search` call. The source-side evidence still has to account for
that supporting traffic.

The operator wrapper owns product credentials, network access, deployment
details, project inspection, source probe invocation, restricted evidence
inspection and storage, generated-file comparisons, and cleanup. A maintainer
must compare the public hashes and flags with that restricted evidence. Those
instance-specific operations are intentionally not embedded in this public
runner.

Run the candidate-only validation before creating the project:

```sh
python3 release/scripts/integration-e2-runner.py validate \
  --candidate-dir /restricted/candidate-assets \
  --tag v1.0.0
```

## Validate candidate evidence

Create an owner-only canary file with one unique 8 to 128 character ASCII value
per line. Canary values can contain letters, digits, `.`, `_`, `:`, `@`, and
`-`. Seed the same values into the restricted test inputs so the scan can
detect accidental disclosure. Do not pass canary values on the command line.

```sh
chmod 0600 /restricted/run-72.canaries

python3 release/scripts/integration-e2-runner.py validate \
  --profile opencrvs-dci-v1.9 \
  --candidate-dir /restricted/candidate-assets \
  --tag v1.0.0 \
  --result /restricted/sanitized-run-result.json \
  --canary-file /restricted/run-72.canaries
```

This validation requires `cosign` and `slsa-verifier`. The runner independently
rejects missing or extra candidate assets, symlinks, wrong checksums, invalid
signatures or provenance, capsule and image-lock disagreements, an unbounded
result, an unknown public field, a public-result canary match, inconsistent
timestamps or durations, a passed case without the required recorded
source-contact classification, over-time recorded teardown, and a `passed`
status paired with failed recorded teardown.

Candidate validation always uses a disposable private snapshot. Replacing a
file in the supplied candidate directory during or after validation cannot
change the executable path used for the version check. The runner removes the
snapshot in its cleanup path and never returns the snapshot path as an
operator artifact.

The public runner receives neither the generated project nor restricted raw
evidence. It validates the closed flags, hashes, timings, and classifications
in the sanitized result, but it cannot independently re-hash the project,
inspect source-side audit records, or confirm the restricted redaction report.
The operator wrapper performs those checks, and a maintainer reviews their
restricted evidence before treating the result as proof.

The result schema is
[`schema/run-result.schema.json`](schema/run-result.schema.json). It is closed:
raw responses, request bodies, headers, tokens, source identifiers, hostnames,
and credentials have no public fields. A failed run can remain as honest
non-closing evidence. The validator accepts `status: passed` only when every
applicable case and teardown is recorded as passed; maintainer review still
establishes whether the recorded hashes correspond to the restricted evidence.

## Review the source packet

- [`profiles/opencrvs-dci-v1.9.profile.json`](profiles/opencrvs-dci-v1.9.profile.json)
  pins the OpenCRVS tuple and signed exact-UIN search.
- [`profiles/dhis2-tracker-2.41.9.profile.json`](profiles/dhis2-tracker-2.41.9.profile.json)
  pins DHIS2 2.41.9 and the singleton tracked-entity read.
- [`schema/run-result.schema.json`](schema/run-result.schema.json) defines the
  only public result shape.

Review raw evidence and the owner attestation outside the public repository.
Commit only the sanitized result after a maintainer compares its hashes and
flags with the generated project, source audit records, redaction report, and
teardown evidence. Candidate identity is the part the public runner verifies
directly.
