# Evidence authoring reference

Author one `EvidenceProject` in `evidence.yaml`, with named Sources and Functions.
A separate `EvidenceTarget` binds that project to one environment, and an
`EvidenceTargetAuthority` supplies complete grants for that target. These closed
v1alpha1 formats are adopter tooling, generated from the same pure Rust model
used by `evidencectl` and the language server. They may change before 1.0.

Use the runnable [standalone example](../../examples/standalone/README.md) for
setup through independent verification. The [generated authoring schemas](../../../../crates/registry-evidencectl/schemas/authoring/)
provide exact key shapes and editor completion. The [compiled deployment reference](../request-adapter/deployment-projects/CONFIG.md)
owns the runtime contracts these inputs compile into.

## Documents and ownership

Every authored YAML document requires its exact `apiVersion` and `kind`.
Keys are case-sensitive, and unknown keys are refused. The current formats are:

| Input | `kind` | Owns |
| --- | --- | --- |
| `evidence.yaml` | `EvidenceProject` | Definitions, named Sources and Functions, selectors, Outputs and package ceilings |
| `<target>.yaml` | `EvidenceTarget` | Project selection, target authority reference, connections and process bindings |
| `<target>-authority.yaml` | `EvidenceTargetAuthority` | Identity profiles and complete target grants |
| `access/clients/<id>.yaml` | `EvidenceAccessClient` | Local caller registration and access-profile membership |
| `mocks/source.yaml` | `EvidenceMockPlan` | Synthetic source cases for a reviewed OpenAPI description |
| Source import resolution file | `EvidenceSourceResolution` | Explicit keep/adopt/file decisions for an imported source update |

The schemas state each format's complete envelope. There are no separate
question, source, selector or access-policy document formats. Sources,
selector profiles and Functions are members of `evidence.yaml`.

Keep reviewed Function programs under `functions/`, fixture documents under
`fixtures/`, and referenced codelists, JSON Schemas and SQL statements as plain
project assets. Function programs are bounded to 64 KiB. Referenced assets stay
inside the project and cannot traverse symbolic links. `.generated/` and
`.evidence/` hold disposable local runtime material and request artifacts;
keep generated credentials, keys, responses and private source data out of
version control. A project contains no deployment credential values.

## Project and definition identity

`id` is the stable local project identifier. Stable identifiers connect
`assertionDefinitions`, `sources`, `selectorProfiles` and named `functions`.
Optional `label` and `description` fields are presentation metadata. They do
not change a definition's behavior revision; presentation bytes included in a
package remain covered by its integrity digest.

Each AssertionDefinition declares its human-readable `question`, `semantics`,
`purpose`, `subjects`, `acquisition`, `derive`, `outputs`, `validitySeconds`,
`subjectBinding`, `representations` and `grantCeiling`. `semantics` supplies the
Requirement URI, assertion kind, Evidence Type URI and reference-framework
URIs. Public requests select the Requirement URI; the local definition ID is
for authoring, inspection and generated code. `expectedConfigurationRevision`
is an optional public pin and refuses stale requests before authority resolution,
credentials or source calls. URI-only requests still carry the resolved
revision in their signed assertion.

The revision covers this definition's behavior and transitive Source,
Function, selector, Output, asset and package-ceiling dependencies. Unrelated
definitions, presentation and target bindings do not churn it. Existing issued
assertions keep their original revision and trust bindings.

`subjects` names each role and its permitted selector profiles. `grantCeiling`
bounds authority kinds, actor kinds, value origins and audiences. Definition
purpose, subject profiles, representations and binding supply the remaining
grant ceilings. A target may narrow these ceilings, never widen them.
`observationTimezone` defaults to `UTC`; it interprets the runtime's observation
instant and does not let a caller supply a clock. `existenceDisclosure`
defaults to `collapse-unresolved`. An optional `disclosureGuard` governs
combinations of Outputs under the retained disclosure contract.

## Sources, acquisition and Functions

Every Source has one named transport boundary: `http-json` or `sqlite-extract`.
The Source owns its fixed request, minimized selector inputs, response
projection and bounded shape, private fact schema, extraction Function and
resource limits. HTTP `connection` selects a target binding without embedding
an origin or credential in the project. SQLite selects a governed extract
profile and a reviewed read-only statement; the target binds the local extract.

`request` carries the transport's reviewed request fields. `response` declares
`projection`, `shape` and `maximumBytes`. `facts` declares the private values
an extraction may return after a unique match. Optional `prepare`,
`adapterParameters`, `adapterParametersSchema` and `preparationLimits` shape
bounded request parts without granting I/O. `limits.attemptTimeoutMilliseconds`
bounds one source attempt; `limits.maximumConcurrency` remains independent of
the target connection's concurrency bound. `batch` declares bounded slotted
preparation/extraction and its response shape when source batching is enabled.
Source `behaviorRevision`, signed-Evidence protocol metadata and unresolved
problem handling retain their compiled source-contract meaning.

An acquisition is explicitly tagged with `type`:

- `single` names one `source`.
- `search-then-fetch` names `search` and `fetch`. Search facts are visible to
  fetch preparation; only fetched facts reach assertion derivation. Optional
  `onFetchNoMatch: unavailable` permits an absent optional fetch record to return
  `evidence.unavailable`; omission or `dependency-failure` retains 503.
  Ambiguity and transport failures remain dependency failures.
- `search-then-fetch-set` names `search`, two through four distinct fetch
  members, each member's `factInputs`, and
  `maximumAcquisitionMilliseconds`. The package and target must opt into this
  acquisition capability. Each member sees only its declared search-fact
  projection; fetched fact names must not collide.

The optional project `acquisitionCapabilities` also governs source batching.
`maximumHolderBoundBatchSize` defaults to one and cannot exceed 16. These are
package ceilings; operator opt-ins and complete grants remain independently
necessary.

Each `functions` entry has a stable `id`, reviewed `source` asset and one
`interface`: `source-prepare/v1`, `source-extract/v1` or `assertion-derive/v1`.
Source calls reference named prepare/extract Functions; `derive.function`
references a derive Function. `derive.parameters` contains reviewed literal
parameters. The compiler checks each call site's inputs and Outputs rather
than giving a reused Function every fact in the project. Preparation shapes
bounded request parts, extraction returns `match`, `no_match` or `ambiguous`,
and only `match` carries private facts. Derivation returns exactly the declared
Outputs. Functions cannot authorize, choose a Source, read credentials,
perform I/O, sign, audit or construct an assertion.

An authored `assertion-derive/v1` Function returns an array whose entries each
have exactly `output` and `value`. `output` names a local Output declared by the
calling definition, for example `#{output: "region", value: facts["residence-region"]}`.
The compiler maps those names to the declared public concept identifiers in the
compiled runtime ABI. Do not return runtime `concept_id` entries from an authored
Function. Unknown, duplicate, missing or malformed outputs are refused.

`explain` exposes Function interfaces, typed call sites, capabilities, digests
and the Source-to-Fact-to-Output flow without source values or secrets. `types`
generates TypeScript or Python declarations from that same model. A scalar
FactSet value does not become public merely because its type is visible.

## Selector and Output fields

### Selector fields and derivation references

Each `selectorProfiles.<id>.fields.<field>` declares a closed `type` and only
its applicable constraints:

| `type` | Required constraints |
|---|---|
| `string` | `minimumBytes`, `maximumBytes`, each 1 through 8192, with minimum no greater than maximum |
| `date` | None; values use canonical calendar dates |
| `integer` | Inclusive `minimum` and `maximum`, within the JSON-safe integer range |
| `boolean` | None |
| `controlled-code` | Reviewed `codelist` asset, exact `codelistVersion`, and `maximumBytes` from 1 through 8192 |

Each field may also have `label` and `description`. A profile has 1 through 16
fields and a `maximumAggregateBytes` ceiling; each string or code field must
fit that ceiling. Codelist paths name plain YAML or JSON assets under
`codelists/`, and the declared version must match the reviewed asset.

An assertion's `derive.selectorInputs` explicitly exposes selector fields to
its named derive Function. Each entry names a subject `role` and an
`alternatives` list. Each alternative names a declared selector `profile` and
a nonempty unique `fields` list from that profile. The role and profile must
also belong to the definition's subjects. This reference grants the Function
access to those fields during derivation; it does not grant a caller access
or include those private fields in the public assertion.

### Output constraints

A definition declares 1 through 16 Outputs.
Each `assertionDefinitions.<id>.outputs.<id>` names a public `concept` URI and
one of the following exact `type` values. Supply all constraints listed for
that type and omit constraints belonging to other types.

| `type` | Required constraints |
|---|---|
| `boolean` | None |
| `controlled-code` | `codelist`, `codelistVersion`, `maximumBytes` |
| `controlled-category` | Inline nonempty unique `values`, or `codelist`, `categoryScheme`, `schemeVersion`, `maximumBytes` |
| `bounded-identifier` | `prefix`, `minimumBytes`, `maximumBytes`; the maximum is at most 1024 bytes and exceeds the prefix length |
| `bounded-integer` | Inclusive JSON-safe integer `minimum` and `maximum` |
| `bounded-decimal` | Quoted canonical decimal `minimum` and `maximum`, plus `maximumScale` from 0 through 9 |
| `date-bucket` | `bucketScheme`, `schemeVersion`, `codelist` |
| `time-bucket` | `bucketScheme`, `schemeVersion`, `codelist` |
| `audience-scoped-entity-reference` | `maximumBytes` |
| `controlled-code-list` | `codelist`, `codelistVersion`, `minimumItems`, `maximumItems`, `unique: true` |
| `entity-reference-list` | `minimumItems`, `maximumItems`, `unique: true` |
| `reviewed-structured-value` | Reviewed `schema` asset and `maximumSerializedBytes` |

Numeric minima cannot exceed maxima. JSON-safe integers range from
-9007199254740991 through 9007199254740991. Decimal bounds are strings rather
than floating-point numbers, with at most 28 digits and 9 fractional digits;
canonical text has no leading plus, redundant leading zero, or trailing
fractional zero. List bounds are 1 through 64
items, byte maxima are 1 through 8192 unless the type specifies a smaller
ceiling, and structured values have a serialized ceiling of 1 through 65536
bytes.

Explicit codelists are reviewed project assets. `codelistVersion` identifies a
code vocabulary; `categoryScheme` or `bucketScheme` identifies the scheme URI,
and `schemeVersion` its version. The compiler checks those identities against
the asset and includes it in the package. Inline category values are compiled
to a deterministic codelist. A structured Output's `schema` supplies its closed
field shape to validation and generated TypeScript/Python declarations.

Only `reviewed-structured-value` may declare `sdJwtVc`. Its `claim` is a unique,
non-reserved ASCII claim name of at most 64 characters within the definition, and
`disclosure` must be `top-level`. This projection does not authorize holder
delivery: the definition ceiling, complete target grant, and selected
representation must permit it.

### Local client actor choice and target authority

An `EvidenceAccessClient` may declare `actorKind` as `human`, `agent`, or
`service`. When omitted, local tooling infers an actor only if the assigned
access profiles and exchange mode admit one compatible choice. An ambiguous
choice requires `evidencectl access client add --actor-kind`. Selecting an
actor never widens a definition's ceiling or the target's complete grants;
each request remains subject to its own definition and authority checks.

The target's `authority` reference selects a separate
`EvidenceTargetAuthority` for the same target and project. Its `accessProfiles`
contain complete grants, including purpose, subject selectors and value
origins, binding, and representations. Client registration and selector
references grant no authority themselves. Private selector values, source
responses, credentials, and secret values remain outside public inspection
and generated declarations, which describe their types.

## Target bindings and complete grants

A target names its own `id`, the exact `project`, a package installation `root`
and an `authority` file. `service` supplies provider, issuer, public origin and
trust-domain identity. `authentication.oidc` supplies issuer verification,
resource audience, allowed token types/algorithms, JWKS URI, identity claim
mapping and scope/client constraints. The target's `connections` map each
project connection name to its origin, authentication references, TLS profile
and operational concurrency ceiling. Write `connections: {}` explicitly when
there are no HTTP bindings, as in an extract-only project. This grants no HTTP
connection; every HTTP Source must still resolve its named binding.

`service.issuer` is an absolute Evidence issuer identifier, including a URN,
within 512 Unicode characters and without whitespace or control characters. It
names the signer and is never fetched. The OIDC issuer and connection origins
use their separate network URL rules. Members under `authentication.oidc.claims`
name direct JWT claims: dots are literal characters, and `grantSourceIssuer`
there names a claim rather than holding an issuer URL.

Optional `assertionIssuers` maps external client identifiers, preserved exactly,
to the issuer strings they may assert. A present map has one to 32 clients,
each within 128 bytes, with one to eight distinct nonempty issuer strings per
client, each within 512 bytes. Omit the map to add no assertion-issuer rule.

`listener`, `secretProviders`, `signer`, `subjectBinding`, `audit`, `rateLimits`,
optional `outboundTls` and `extracts` bind the process. They do not change a
Source's meaning or grant access. Secret references identify externally
provisioned material using exact `secret:env/NAME` or `secret:file/name` syntax.
An optional `package.expectedDigest` is `sha256:` followed by 64 lowercase hex
digits. Target reading checks these scalar forms before runtime delegation.
`signer.publicJwkFile` supplies the reviewed public key
asset; the private key is never a portable project input. Local authoring may
use a disposable JWK signer. Production and evidence-grade targets require
the retained pinned non-exportable Transit signer and transport guarantees.
Optional `publication`, `responseFormats` and `acquisitionCapabilities` retain
their compiled governance and runtime ceilings. Governed fields are revalidated during bundle and package compilation.
Process-local paths and secret readiness are validated by `doctor` or process start.

The target authority's `project` and `target` must match the selected project
and target. Each `accessProfiles` entry matches authenticated requester tags,
an authority kind and optional actor narrowing, then carries one or more
complete grants. A grant declares its definition, purpose,
`audienceFrom: authenticated-requester`, representations, subject binding and
every subject's role, selector profile and value origin. `valueClaims` is
required for authenticated-context or authenticated-grant values and forbidden
for request-origin values. Task profiles additionally bind requester clients
and their grant-source issuer. Partial grants are never combined to authorize
a request, and overlapping complete grants refuse.

Compiled target authority has its own derived revision and digest; authors do
not provide a hash specimen. Activation records durable history atomically.
Requests retain one active authority snapshot, while live task-grant validity
and exact durable release audit remain mandatory. Authority updates do not
rewrite the immutable package or existing assertions and take effect through
the documented process restart.

## Check, test and package

`evidencectl check <project>` and `explain <project>` read the normalized model
offline. Add `--target <target>` for the selected target's complete grants and
bindings. A target may be a YAML file or a directory containing `target.yaml`.
An ordinary target check may report missing local deployment inputs; a
production check requires complete public inputs and an explicit target whose
assurance is `production` or `evidence-grade`. Neither check resolves secrets,
contacts Sources or initializes a deployed signer/audit destination.

Fixture execution is explicit: `evidencectl test <project> --target <target>`
delegates to the actual Evidence fixture kernel. The SQLite starter supports
this offline lane; `dev start` refuses SQLite serving rather than pretending
to provide a live SQLite source. Use `evidencectl dev start` for the local HTTP
journey and `doctor --runtime-config <absolute-file>` for live dependencies.

`evidencectl package <project> --target <target> --output <new-directory>`
creates one immutable candidate containing `bundle/`, `runtime.yaml` and
`compiled-authority.yaml`. Keep the output outside the authored project.
One captured project snapshot supplies every candidate artifact. Runtime-owned
bundle and authority validation runs even without fixtures. Install the bundle,
provision referenced secrets, activate the compiled authority and run doctor
before starting the intended process. The standalone walkthrough exercises
that sequence and cleanup with synthetic data.

A schema validates document shape; pure checks add reference and cross-field
rules; compilation and runtime bundle checks establish the retained security
and execution contracts. A successful shape check alone is not evidence of a
working deployment. A refused command identifies the file/field with a
value-free diagnostic. Preserve that distinction when inspecting machine
reports or using an editor.

## Complete key-path inventory

Every key path the generated authoring schemas define, in one machine-checked
list. A property is written `name`, an array item `name[]`, and a map value
`name.*`.

`products/evidence/scripts/check-config-key-paths.sh` fails when a block
and its schema disagree in either direction, so a key added to the authoring
model cannot ship without a line here, and a line here cannot outlive its key.
The blocks are generated. After regenerating the schemas with
`products/evidence/scripts/check-authoring-schema.sh`, run
`products/evidence/scripts/check-config-key-paths.sh --write`, review the diff,
and document the new keys in this page's prose.

Parity is the same rule the frozen contracts are held to, and it is not the
same promise. These schemas are adopter tooling. A key path leaving this
inventory is a tooling change, not a break in the Version 1 configuration
contract.

### `evidence.yaml`

The normalized project document owns stable source, selector-profile, function,
assertion-definition, and output identifiers. Presentation labels and
descriptions remain optional metadata.

<!-- evidence-authoring-project-key-paths:start -->
```text
acquisitionCapabilities
acquisitionCapabilities[]
apiVersion
assertionDefinitions
assertionDefinitions.*
assertionDefinitions.*.acquisition
assertionDefinitions.*.acquisition.fetch
assertionDefinitions.*.acquisition.fetch[]
assertionDefinitions.*.acquisition.fetch[].factInputs
assertionDefinitions.*.acquisition.fetch[].factInputs[]
assertionDefinitions.*.acquisition.fetch[].source
assertionDefinitions.*.acquisition.maximumAcquisitionMilliseconds
assertionDefinitions.*.acquisition.onFetchNoMatch
assertionDefinitions.*.acquisition.search
assertionDefinitions.*.acquisition.source
assertionDefinitions.*.acquisition.type
assertionDefinitions.*.derive
assertionDefinitions.*.derive.function
assertionDefinitions.*.derive.parameters
assertionDefinitions.*.derive.selectorInputs
assertionDefinitions.*.derive.selectorInputs[]
assertionDefinitions.*.derive.selectorInputs[].alternatives
assertionDefinitions.*.derive.selectorInputs[].alternatives[]
assertionDefinitions.*.derive.selectorInputs[].alternatives[].fields
assertionDefinitions.*.derive.selectorInputs[].alternatives[].fields[]
assertionDefinitions.*.derive.selectorInputs[].alternatives[].profile
assertionDefinitions.*.derive.selectorInputs[].role
assertionDefinitions.*.description
assertionDefinitions.*.disclosureGuard
assertionDefinitions.*.existenceDisclosure
assertionDefinitions.*.fixtures
assertionDefinitions.*.grantCeiling
assertionDefinitions.*.grantCeiling.actorKinds
assertionDefinitions.*.grantCeiling.actorKinds[]
assertionDefinitions.*.grantCeiling.audiences
assertionDefinitions.*.grantCeiling.audiences[]
assertionDefinitions.*.grantCeiling.authorities
assertionDefinitions.*.grantCeiling.authorities[]
assertionDefinitions.*.grantCeiling.valueOrigins
assertionDefinitions.*.grantCeiling.valueOrigins[]
assertionDefinitions.*.label
assertionDefinitions.*.observationTimezone
assertionDefinitions.*.outputs
assertionDefinitions.*.outputs.*
assertionDefinitions.*.outputs.*.bucketScheme
assertionDefinitions.*.outputs.*.categoryScheme
assertionDefinitions.*.outputs.*.codelist
assertionDefinitions.*.outputs.*.codelistVersion
assertionDefinitions.*.outputs.*.concept
assertionDefinitions.*.outputs.*.description
assertionDefinitions.*.outputs.*.label
assertionDefinitions.*.outputs.*.maximum
assertionDefinitions.*.outputs.*.maximumBytes
assertionDefinitions.*.outputs.*.maximumItems
assertionDefinitions.*.outputs.*.maximumScale
assertionDefinitions.*.outputs.*.maximumSerializedBytes
assertionDefinitions.*.outputs.*.minimum
assertionDefinitions.*.outputs.*.minimumBytes
assertionDefinitions.*.outputs.*.minimumItems
assertionDefinitions.*.outputs.*.prefix
assertionDefinitions.*.outputs.*.schema
assertionDefinitions.*.outputs.*.schemeVersion
assertionDefinitions.*.outputs.*.sdJwtVc
assertionDefinitions.*.outputs.*.sdJwtVc.claim
assertionDefinitions.*.outputs.*.sdJwtVc.disclosure
assertionDefinitions.*.outputs.*.type
assertionDefinitions.*.outputs.*.unique
assertionDefinitions.*.outputs.*.values
assertionDefinitions.*.outputs.*.values[]
assertionDefinitions.*.purpose
assertionDefinitions.*.question
assertionDefinitions.*.representations
assertionDefinitions.*.representations[]
assertionDefinitions.*.semantics
assertionDefinitions.*.semantics.evidenceType
assertionDefinitions.*.semantics.kind
assertionDefinitions.*.semantics.referenceFrameworks
assertionDefinitions.*.semantics.referenceFrameworks[]
assertionDefinitions.*.semantics.requirement
assertionDefinitions.*.subjectBinding
assertionDefinitions.*.subjects
assertionDefinitions.*.subjects[]
assertionDefinitions.*.subjects[].role
assertionDefinitions.*.subjects[].selectors
assertionDefinitions.*.subjects[].selectors[]
assertionDefinitions.*.validitySeconds
description
functions
functions[]
functions[].description
functions[].id
functions[].interface
functions[].label
functions[].source
id
kind
label
maximumHolderBoundBatchSize
selectorProfiles
selectorProfiles.*
selectorProfiles.*.description
selectorProfiles.*.fields
selectorProfiles.*.fields.*
selectorProfiles.*.fields.*.codelist
selectorProfiles.*.fields.*.codelistVersion
selectorProfiles.*.fields.*.description
selectorProfiles.*.fields.*.label
selectorProfiles.*.fields.*.maximum
selectorProfiles.*.fields.*.maximumBytes
selectorProfiles.*.fields.*.minimum
selectorProfiles.*.fields.*.minimumBytes
selectorProfiles.*.fields.*.type
selectorProfiles.*.label
selectorProfiles.*.maximumAggregateBytes
sources
sources.*
sources.*.acquisitionPosture
sources.*.adapterParameters
sources.*.adapterParametersSchema
sources.*.batch
sources.*.batch.extract
sources.*.batch.extract.function
sources.*.batch.maximumItems
sources.*.batch.prepare
sources.*.batch.prepare.function
sources.*.batch.response
sources.*.batch.response.projection
sources.*.batch.response.projection[]
sources.*.batch.response.shape
sources.*.behaviorRevision
sources.*.connection
sources.*.description
sources.*.evidence
sources.*.extract
sources.*.extract.function
sources.*.extractProfile
sources.*.facts
sources.*.forwardAccessAttribution
sources.*.label
sources.*.limits
sources.*.limits.attemptTimeoutMilliseconds
sources.*.limits.maximumConcurrency
sources.*.maximumExtractAgeSeconds
sources.*.preparationLimits
sources.*.prepare
sources.*.prepare.function
sources.*.request
sources.*.response
sources.*.response.maximumBytes
sources.*.response.projection
sources.*.response.projection[]
sources.*.response.shape
sources.*.selectors
sources.*.selectors[]
sources.*.selectors[].profiles
sources.*.selectors[].profiles[]
sources.*.selectors[].role
sources.*.type
sources.*.unresolvedProblem
```
<!-- evidence-authoring-project-key-paths:end -->

### `access/clients/<id>.yaml`

A local access client document names one caller of a development Evidence
runtime. `apiVersion` and `kind` are the envelope in the table above.
`clientId` is the lowercase client identifier, `status` is `active` or
`revoked`, and `accessProfiles` lists the target authority profiles assigned to
the client.
`principal` and `evidenceAudience` must both equal the local URI derived from
`clientId`. `keys` holds exactly one public JWK for the client. `exchange` is
optional local issuer wiring for a client whose authority comes from a task
assertion; it grants no access. Its `kind` is `institutional-grant` or
`first-party`, `bootstrapScope` is one bounded OAuth scope token,
`bootstrapResource` is a bounded resource URI (when it is omitted, the issuer
owner's default resource applies, not the Evidence resource), and
`sourceIssuer` is the issuer URL, which a `first-party` exchange requires and
an `institutional-grant` exchange refuses because that issuer comes from its
governed task policy. A `first-party` exchange also requires
`bootstrapResource`.

<!-- evidence-authoring-access-client-key-paths:start -->
```text
accessProfiles
accessProfiles[]
actorKind
apiVersion
clientId
evidenceAudience
exchange
exchange.bootstrapResource
exchange.bootstrapScope
exchange.kind
exchange.sourceIssuer
keys
kind
principal
status
```
<!-- evidence-authoring-access-client-key-paths:end -->

### `mocks/source.yaml`

The mock plan configures the source mock that `evidencectl` serves from an
OpenAPI description. `openapi` names that description and `openapiDigest`
optionally pins it as a `sha256:` digest. `generation` holds the settings that
`generate --config` keeps to create missing response bodies: `contract` names
the contract, `seed` is the generator seed, `asOf` is an ISO calendar date, and
`datasets` maps local identifiers to the `sha256:` digest of each dataset.
Each entry of `operations` is one configured GET operation, identified by
`method` plus the templated `path`, with an optional `operationId`. Its
`response` carries `status`, which is always 200, and `mediaType`. Each entry
of its `cases` has a `name`, a `body`, and a `request` whose `pathParameters`
bind each template parameter name to one string, boolean, or number.

<!-- evidence-authoring-mock-plan-key-paths:start -->
```text
apiVersion
generation
generation.asOf
generation.contract
generation.datasets
generation.datasets.*
generation.seed
kind
openapi
openapiDigest
operations
operations[]
operations[].cases
operations[].cases[]
operations[].cases[].body
operations[].cases[].name
operations[].cases[].request
operations[].cases[].request.pathParameters
operations[].cases[].request.pathParameters.*
operations[].method
operations[].operationId
operations[].path
operations[].response
operations[].response.mediaType
operations[].response.status
```
<!-- evidence-authoring-mock-plan-key-paths:end -->

### Source import resolution file

A resolution file records what to do with each artifact a source import could
not decide. `artifacts` maps an artifact identifier, at most 256 of them, to
one resolution. The `type` of a resolution is `keep` (keep the current file),
`adopt` (take the upstream file), or `file` (use the file named by `path`, read relative to the resolution file).
`path` is allowed and required only for `file`. The reader checks and strips
`apiVersion` and `kind`.

<!-- evidence-authoring-source-resolution-key-paths:start -->
```text
apiVersion
artifacts
artifacts.*
artifacts.*.path
artifacts.*.type
kind
```
<!-- evidence-authoring-source-resolution-key-paths:end -->

### `<target>.yaml`

The normalized target document selects one project and declares the target's
acquisition capabilities. Its authority reference points to a separate
operator-owned target authority document.

<!-- evidence-authoring-target-key-paths:start -->
```text
acquisitionCapabilities
acquisitionCapabilities[]
apiVersion
assuranceProfile
audit
audit.destination
audit.hashKeyRef
audit.hashKeyVersion
audit.path
audit.retentionDays
audit.rotateBytes
authentication
authentication.oidc
authentication.oidc.actorClaim
authentication.oidc.algorithms
authentication.oidc.algorithms[]
authentication.oidc.allowedClients
authentication.oidc.allowedClients[]
authentication.oidc.assertionIssuers
authentication.oidc.assertionIssuers.*
authentication.oidc.assertionIssuers.*[]
authentication.oidc.audience
authentication.oidc.claims
authentication.oidc.claims.actorKind
authentication.oidc.claims.approver
authentication.oidc.claims.grantBounds
authentication.oidc.claims.grantClient
authentication.oidc.claims.grantExp
authentication.oidc.claims.grantId
authentication.oidc.claims.grantResource
authentication.oidc.claims.grantSourceIssuer
authentication.oidc.claims.purpose
authentication.oidc.evidenceAudienceClaim
authentication.oidc.issuer
authentication.oidc.jwksSource
authentication.oidc.jwksSource.type
authentication.oidc.jwksSource.uri
authentication.oidc.maximumTokenLifetimeSeconds
authentication.oidc.principalClaim
authentication.oidc.requesterTagsClaim
authentication.oidc.requiredScopes
authentication.oidc.requiredScopes[]
authentication.oidc.revokedKeyIds
authentication.oidc.revokedKeyIds[]
authentication.oidc.tlsTrustProfile
authentication.oidc.tokenTypes
authentication.oidc.tokenTypes[]
authority
connections
connections.*
connections.*.admissionTimeoutMilliseconds
connections.*.authentication
connections.*.authentication.assumedLifetimeSeconds
connections.*.authentication.audience
connections.*.authentication.clientAssertionAudience
connections.*.authentication.clientAssertionKeyRef
connections.*.authentication.clientIdRef
connections.*.authentication.clientSecretRef
connections.*.authentication.credentialPlacement
connections.*.authentication.headerName
connections.*.authentication.maximumCacheSeconds
connections.*.authentication.passwordRef
connections.*.authentication.resource
connections.*.authentication.scheme
connections.*.authentication.scope
connections.*.authentication.tokenEndpoint
connections.*.authentication.tokenRef
connections.*.authentication.type
connections.*.authentication.usernameRef
connections.*.authentication.valueRef
connections.*.maximumConcurrency
connections.*.origin
connections.*.tlsTrustProfile
connections.*.tokenTimeoutMilliseconds
extracts
extracts.*
extracts.*.path
id
kind
listener
listener.bind
listener.maximumConcurrentRequests
listener.maximumRequestBytes
listener.networkExposure
listener.requestTimeoutMilliseconds
listener.shutdownGraceMilliseconds
listener.tlsTermination
listener.trustProxyIdentityHeaders
outboundTls
outboundTls.systemRoots
outboundTls.trustProfiles
outboundTls.trustProfiles.*
outboundTls.trustProfiles.*.caBundleFile
package
package.expectedDigest
package.root
project
publication
publication.description
publication.endpointUrl
publication.jurisdictions
publication.jurisdictions[]
publication.operatorId
publication.publisherId
publication.serviceId
publication.title
rateLimits
rateLimits.burstPerPrincipal
rateLimits.failedSelectorAttemptsPerPrincipalAuthorityPerMinute
rateLimits.requestsPerPrincipalPerMinute
responseFormats
responseFormats[]
secretProviders
secretProviders.environment
secretProviders.file
secretProviders.file.root
service
service.issuer
service.providerId
service.publicOrigin
service.trustDomain
signer
signer.algorithm
signer.attemptTimeoutMilliseconds
signer.keyName
signer.keyVersion
signer.mount
signer.privateKeyRef
signer.publicJwkFile
signer.type
signer.unixSocketPath
subjectBinding
subjectBinding.keyVersion
subjectBinding.secretRef
```
<!-- evidence-authoring-target-key-paths:end -->

### `<target>-authority.yaml`

The normalized target authority document selects one target and project and
owns its complete `accessProfiles` grants. Operational settings remain in the
target document. Authority is compiled and activated separately from the
immutable governed package.

<!-- evidence-authoring-target-authority-key-paths:start -->
```text
accessProfiles
accessProfiles.*
accessProfiles.*.actorKind
accessProfiles.*.authority
accessProfiles.*.grantSourceIssuer
accessProfiles.*.grants
accessProfiles.*.grants[]
accessProfiles.*.grants[].audienceFrom
accessProfiles.*.grants[].definition
accessProfiles.*.grants[].purpose
accessProfiles.*.grants[].representations
accessProfiles.*.grants[].representations[]
accessProfiles.*.grants[].subjectBinding
accessProfiles.*.grants[].subjects
accessProfiles.*.grants[].subjects[]
accessProfiles.*.grants[].subjects[].role
accessProfiles.*.grants[].subjects[].selectorProfile
accessProfiles.*.grants[].subjects[].valueClaims
accessProfiles.*.grants[].subjects[].valueClaims.*
accessProfiles.*.grants[].subjects[].valueOrigin
accessProfiles.*.requesterClients
accessProfiles.*.requesterClients[]
accessProfiles.*.requesterTags
accessProfiles.*.requesterTags[]
apiVersion
kind
project
target
```
<!-- evidence-authoring-target-authority-key-paths:end -->

Selector fields support `type: uuid` for the exact 36-character hyphenated
lowercase hexadecimal representation, the RFC 9562 canonical form. An uppercase
value is refused, never folded or normalized. Facts may
use `type: uuid`, compiled to JSON Schema `type: string, format: uuid`, or declare
that JSON Schema form directly. Malformed values fail before derivation.
