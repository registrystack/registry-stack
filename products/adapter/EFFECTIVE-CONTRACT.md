# Adapter effective operation contract

The registered output example is produced by the real CLI with synthetic
bindings. After building `adapter` and setting `CARGO_TARGET_DIR`, regenerate
it with `products/adapter/scripts/generate-effective-contract-example.sh`.
The same command with `--check` compares a fresh export byte for byte; the
Adapter contract gate runs that check.

The effective operation contract describes the read operations one loaded
Adapter process can expose to an external gateway. It is generated from the
same validated `Loaded` plan used by `adapter serve`. It is not an
authorization grant, an embedded MCP server, or personal-data delegation.
Authored or executable operations excluded from the gateway surface remain
listed as unserved with a stable reason code.

## Export

```console
adapter effective-contract \
  --runtime-config /absolute/path/runtime.yaml \
  --project /absolute/path/project-directory \
  --profile /absolute/path/profile.yaml \
  --pack /absolute/path/pack.yaml
```

`--profile` and `--pack` have the same beside-the-project defaults as
`adapter serve`. The command validates and loads the artifacts and runtime
binding without opening a listener, connecting to the journal database, or
probing an upstream source. Secret references that the loader normally
resolves, including static upstream credentials, must still resolve.

The JSON envelope is:

```text
apiVersion: id.registrystack.org/formats/adapter/effective-contract/v1alpha1
kind: AdapterEffectiveContract
digest: sha256:<RFC 8785 digest of contract>
contract:
  schemaDialect
  project: { id, version }
  profileVersion
  artifactDeploymentDigest
  authentication: { scheme, audience, clientAdmission }
  authority
  operations[]
  unserved[]
  problemSchema
  protocolProblems
```

Each served operation carries its stable concrete id and version, binding and
profile-operation ids, method, concrete path, `support: served`, `effect:
read`, any request-body byte limit, closed path/query/body
schemas, the exact derived output schema, and the alternative all-of scope
sets that admit the call. Only GET reads and profile-declared read-only POST
operations enter the served gateway surface. A runtime-served write remains
unserved here with `adapter.operation.gateway-write-disabled`. Effect
classification is explicit, so a future write cannot be mislabeled as a read.
Pagination schemas preserve the runtime page-size and cursor bounds;
paginated output arrays preserve the maximum page size. Request-body bounds
are applied by the envelope's actual slots, not by guessing property names.

An unserved entry carries the same identities, its classified effect,
`support: unserved`, and a stable reason code with a value-free operator
reason. Its effect is `unknown` only when the referenced profile operation is
itself missing, so no method semantics exist to classify. A consumer must
never turn an unserved entry into a tool or HTTP call.

`digest` is SHA-256 over RFC 8785 canonical JSON containing a fixed digest
domain, `apiVersion`, `kind`, and the complete `contract` member. Runtime
readiness and the digest field itself are outside that digest. One whole
contract digest is pinned on every operation request; there is no separate
per-operation digest. The `artifactDeploymentDigest` separately identifies
the exact project, profile, and pack bytes loaded by the Adapter.

The export includes the resource audience, the generic allowlist admission
mode, and operation scope requirements because a machine client needs them to
request and present the right bearer token. It deliberately excludes OAuth
client ids, secret references and values, database configuration, upstream
origins, private network declarations, and source credentials.

The authority block fixes this increment's limit in machine-readable form:
the admitted caller is a trusted machine, represented-subject and personal
delegation are unsupported, target binding is unsupported, and the contract
grants no row- or field-level disclosure authority. Operation and record-type
scopes do not become personal disclosure authority.

`problemSchema` remains the profile's problem envelope for ordinary operation
failures, including the resolved profile code/title with the engine's fixed
facade admission statuses. Profiles declaring typed problem data keep each
code, title, allowed status set, and data shape correlated.
`protocolProblems` separately binds a closed problem envelope and
two code/status pairs owned by this protocol:

- `adapter.contract.precondition-failed`, HTTP 412;
- `adapter.contract.unavailable`, HTTP 503.

The Adapter never changes a profile problem's declared HTTP status to produce
one of these protocol failures.

## Runtime readback and readiness

An Adapter that has completed startup serves:

```text
GET /.well-known/registry-adapter/effective-contract
Authorization: Bearer <admitted machine token>
```

The endpoint requires the existing OIDC audience and client allowlist. It does
not require a data-operation scope, create a new grant, or make contract
metadata anonymous. A successful response is the export envelope plus:

```json
{"readiness":{"ready":true,"configuration":"ready","journal":"ready"}}
```

The endpoint returns `adapter.contract.unavailable` when it cannot query
the journal or the live migration set differs from the set this binary
supports. A gateway should pin the expected `digest`, read the protected
runtime document, and refuse listing or invocation when the two differ.
Readiness does not probe the upstream source and must not be presented as a
source-health or end-to-end facade check.

To bind preflight to execution, a gateway sends the pinned digest on every
operation request:

```text
x-registry-adapter-contract: sha256:<effective contract digest>
```

After authenticating the machine client, the Adapter requires an exact,
single header match before it creates an exchange, reads a body, or calls the
source. A mismatch or repeated header receives
`adapter.contract.precondition-failed` with HTTP 412. The refusal is durably
audit-journaled before the response, but no body is read, no exchange is
created, and no source I/O occurs. If the journal cannot record the refusal,
the Adapter returns `adapter.contract.unavailable` with HTTP 503 instead of
claiming a durable 412. Omitting the header preserves existing clients; a
gateway that uses effective discovery must always send it.

## Request identity

Every facade success and problem has `x-registry-request-id`, minted by the
Adapter. The protocol problems carry the same request id in their closed body.
When the profile's problem envelope exposes its request-id slot, that body
value and the header are identical. This increment accepts no caller-supplied
correlation header and records no reversible digest of caller correlation
data.

Native write replays retain the original Adapter-minted response ID in both
body and header so the cached response remains byte-identical. Their physical
retry attempts have distinct journal IDs. Native writes remain unserved in
the external gateway contract.
