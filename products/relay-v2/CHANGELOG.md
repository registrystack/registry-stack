# Relay V2 changelog

## Unreleased

### BREAKING: write audit through the shared platform audit writer

Relay no longer keeps a keyed hash chain over its audit log. Each audit line is
now the envelope every Registry Stack product writes:

```json
{"schema":"registry.relay.audit/v2alpha2","eventId":"...","time":"2026-09-25T10:00:00.000Z","phase":"request","correlation":"<operation id>","record":{"phase":"attempt","operationId":"<operation id>"}}
```

The `record` is abbreviated above. The attempt written before source access is
a `request` entry, and the refusal or terminal outcome is a `response` entry.
Both carry the operation id as `correlation`. The record keeps every field it
had except `schema`, which moved to the envelope. The package artifact
`generated/artifacts/audit-event.schema.json` now describes one line, and its
`$id` is
`https://id.registrystack.org/schemas/registry-relay/audit-event/v2alpha2`.
Source access and response release are gated exactly as before, and an
unavailable destination still returns `503 audit.unavailable`.

Before:

```yaml
audit:
  sink: /var/lib/relay/audit/relay.jsonl
  integrityKeyRef: secret:file/audit-integrity-key
```

After:

```yaml
audit:
  destination: file        # or stdout
  path: /var/lib/relay/audit/relay.jsonl
  rotateBytes: 67108864    # optional, file only
  retainDays: 90           # optional, file only
```

Migration:

1. Rename `audit.sink` to `audit.path` and delete `audit.integrityKeyRef`; the
   audit key is no longer read and can be retired. Unknown audit fields fail
   startup.
2. Move or archive the existing log before starting the upgraded Relay. Lines
   written by earlier versions use the old format, so read the two separately.
3. Update log consumers to read the envelope and the `record` inside it, and to
   join a request and its outcome by `correlation`.
4. `relay check --require-audit-under` refuses a `stdout` destination, which
   has no path to prove.
5. Reseal packages; the audit event schema artifact changed.

## v0.26.0 - 2026-09-03

### BREAKING: adopt Registry Record profile v1

Relay JSON and JSON-LD consultation responses now conform to
`https://id.registrystack.org/profiles/registry-record/v1`. Every resource must
declare `datasetIdentifier` and `entityTypeIdentifier` beside `id`. These are
governed identifiers and are never inferred.

Before, every JSON or JSON-LD Record repeated `registryIdentifier`:

```json
{"data":{"registryIdentifier":"urn:example:registry:businesses","recordIdentifier":"B-1"}}
```

After, one homogeneous response context is carried by `meta`, and the Record
does not duplicate it:

```json
{"data":{"recordIdentifier":"B-1"},"meta":{"registryIdentifier":"urn:example:registry:businesses","datasetIdentifier":"legal-entities","entityTypeIdentifier":"company"}}
```

Migration:

1. Add stable `datasetIdentifier` and `entityTypeIdentifier` fields to every
   authored resource. Rename any domain property using a Registry Record
   envelope, identifier, context, or pagination member; those keys are
   reserved infrastructure and cannot appear in `domainData`.
2. Regenerate and reseal packages. Existing packages fail strict compilation
   because the new fields are required and participate in the package digest.
3. Read Registry, dataset, and entity-type identity from response `meta`, not
   from each `data` or `items` Record.
4. For JSON-LD, accept the two-entry `@context` array containing the shared
   Registry Record context followed by the generated operation context. The
   second context adds Relay and selected domain terms without redefining any
   shared term.
5. Treat pre-change cursors and ETags as invalid. Restart pagination and cache
   revalidation after deployment.
6. If you publish a Registry Discovery description for this deployment,
   declare `conformsTo` with both
   `https://id.registrystack.org/profiles/registry-record/v1` and the
   bumped `https://registrystack.org/relay/profile/v3`, replacing the prior
   `https://registrystack.org/relay/profile/v2`.

JSON and JSON-LD success responses advertise both the shared profile and Relay
profile v3 in `Link` headers. Generated OpenAPI operations identify the shared
response profile and close the three response-context values to the compiled
Registry and resource. GeoJSON keeps its separate OGC media profile and shape.
