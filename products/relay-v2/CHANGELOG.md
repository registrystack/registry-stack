# Relay V2 changelog

## Unreleased

### BREAKING: read runtime.yaml through the shared configuration loader

`relay` reads its deployment binding through the shared Registry Stack runtime
configuration loader, with the shared listener, package, secret-provider, and
OIDC blocks. There is no compatibility reader: every removed key is refused
with a diagnostic naming the field and its replacement, never its value.

Before:

```yaml
apiVersion: relay.registrystack.org/v2alpha1
kind: RelayRuntime
server: {bind: "127.0.0.1:8080"}
packagePath: package
authentication:
  issuer:
    id: institutional-issuer
    discoveryUrl: https://identity.example.invalid/.well-known/openid-configuration
    audience: relay-registry
    tokenTypes: [at+jwt]
    algorithms: [ES256]
audit: {sink: var/audit.jsonl, integrityKeyRef: secret:file/audit-key}
```

After:

```yaml
apiVersion: registry.registrystack.org/relay-runtime/v1alpha1
kind: RelayRuntimeConfig
listener: {bind: "127.0.0.1:8080"}
package: {root: /srv/relay/package}
secretProviders:
  file: {root: /run/secrets/relay}
authentication:
  oidc:
    issuer: https://identity.example.invalid
    audience: relay-registry
    tokenTypes: [at+jwt]
    algorithms: [ES256]
audit: {sink: var/audit.jsonl, hashKeyRef: secret:file/audit-key}
```

Migration:

1. Replace the envelope with `apiVersion:
   registry.registrystack.org/relay-runtime/v1alpha1` and `kind:
   RelayRuntimeConfig`.
2. Move `server.bind` to `listener.bind`, and `packagePath` to `package.root`
   as an absolute path. Optionally pin the package with
   `package.expectedDigest`, its `sha256:` package revision; any other package
   at that path is refused.
3. Declare `secretProviders`. A `secret:file/` reference now resolves under
   `secretProviders.file.root` instead of the runtime file's directory; move
   the secret files there. A `secret:env/` reference needs
   `secretProviders.environment: {}`.
4. Rename `audit.integrityKeyRef` to `audit.hashKeyRef`.
   `cursor.integrityKeyRef` is unchanged.
5. Replace `authentication.issuer` with `authentication.oidc`. `issuer` is the
   exact token `iss` value; `id`, `trustedIssuer`, `discoveryUrl`, and
   `jwksUrl` are gone. The key source is `jwksSource`: the default `kind:
   discovery` reads the issuer's own `/.well-known/openid-configuration`, and
   `kind: uri` with `uri` binds one exact JWKS endpoint, which may sit on
   another host. A discovery document served from a different origin than the
   issuer is no longer configurable; use `kind: uri` with the JWKS URL it
   named. `kind: static` is refused. Omit `authentication.oidc` when every
   access rule is public.
6. `relay check` and `relay serve` take the required absolute
   `--runtime-config <FILE>`. The `--runtime` flag, the `RELAY_RUNTIME`
   environment variable, and the `/etc/relay/runtime.yaml` default for `relay
   check` are gone. The container image passes `--runtime-config
   /etc/relay/runtime.yaml` in its default command.

Values other than secret references may use `${VAR}` and `${VAR:-default}`
substitution; a field whose name ends in `Ref` refuses it. The runtime file
must be absolute, free of symbolic links, at most 1 MiB, and owned by root or
the service identity with no group- or world-writable ancestor other than a
root-owned sticky directory. `relayctl` and the editor check the runtime with
an empty environment, so a substitution without a default is reported there.
Substitution applies to `runtime.yaml` only: an environment expression in the
authored `registry.yaml` is refused as `contract.environment_expression` with
the field that holds it.
`relayctl init` writes a starter whose `package.root` reads
`RELAY_PACKAGE_ROOT` and defaults to `/srv/relay/package`.

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
