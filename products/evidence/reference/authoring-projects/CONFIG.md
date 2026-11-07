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

Each Source selects one reviewed Adapter `pack` by id and version, one `route`
and one named `connection`. Its `inputs` map route input names to explicit
`selector` references with a role, profile and field. `acquisitionPosture`
states whether the provider answer is source-derived, field-projected or
record-transformed; local projection does not strengthen the acquisition claim.
The Source contains no provider request program or acquisition Function.

An optional `projection` selects a project-owned Rhai `source`, its one-argument
`entrypoint`, and a JSON `schema` asset for final facts. For example:

```yaml
projection:
  source: projections/person-facts.rhai
  entrypoint: project_facts
  schema: schemas/person-facts.json
```

The function receives one already-matched native facts object and returns one
object validated against the versioned, closed JSON Schema. Nested objects,
bounded arrays and local references are supported; remote references are
refused. The schema carries a versioned HTTPS `$id`. The compiler captures both
assets in the governed package and includes them in definition revisions.
Projection requires `record-transformed` acquisition posture, retains the
acquisition deadline and cannot change source inputs,
lookup classification, credentials, destinations or authority. A no-match,
ambiguous or unresolved lookup never runs the projection. A script, budget or
output-schema failure prevents derivation and never becomes a negative fact.
The standalone example retains two facts while removing a private canary using
the same unmodified source pack.

Keep the owned pack at `adapter-packs/<pack-id>/pack.yaml` with its referenced
scripts and schemas. The compiler captures the reviewed artifact closure,
checks its declared digests and derives the compiled Source's exact pack digest.
The route's declared input and output schemas supply the checked lookup and
private fact contract. Caller input cannot choose a pack, route, endpoint,
credential or broader selector set.

A route whose input schema has a root `oneOf` offers alternative lookup keys,
for example a person identifier or a household identifier with a region. The
Source `inputs` must map every input of at least one alternative; `evidencectl
check` reports `source-route-input-alternative` at `sources.<id>.inputs` when
none is complete. Each target grant must then supply exactly one alternative:
its subjects' selector profiles decide which mapped inputs the grant makes
available. A grant that supplies too few inputs, or enough inputs for two
alternatives, is refused when the target authority is activated, because the
lookup key would be missing or ambiguous at runtime.

An AssertionDefinition's `acquisition` contains only `source`, naming one of
these Sources. The pack owns the complete provider interaction, including any
reviewed branches, reads, retries or pages. The shared engine enforces one
finite operation budget and absolute deadline. The retired tagged acquisition
kinds and Source `request`, `response`, `prepare`, `extract` and `batch` fields
are refused rather than converted into packs.

Each `functions` entry has a stable `id`, reviewed `source` asset and the
`assertion-derive/v1` interface. `derive.function` selects that Function and
`derive.parameters` carries reviewed requirement parameters. A completed
matched lookup supplies its private facts; other lookup outcomes stop before
derivation. Derivation receives only its separately declared authorized
selector inputs and returns the declared Outputs. It cannot authorize, choose
a Source, read credentials, perform I/O, sign, audit or construct an assertion.
The `source-prepare/v1` and `source-extract/v1` Function interfaces are retired;
pack scripts use the separate Adapter exchange ABI.

`maximumHolderBoundBatchSize` defaults to one and cannot exceed 16. It is a
package disclosure ceiling, independently constrained by complete grants.
It does not create a provider-side batching interface.

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

### Holder-presented acquisition

A definition may add a second acquisition channel beside `source`:

```yaml
acquisition:
  source: person-record
  holderPresented:
    source: wallet-session
    selectorProfiles: [session-reference-v1]
```

The request's selector profile selects exactly one channel. A profile listed in
`holderPresented.selectorProfiles` acquires only through
`holderPresented.source`; every other profile acquires only through `source`.
There is no fallback from one channel to the other, and grants keep restricting
callers by selector profile (a grant has no `channels` member). `source` may be
omitted only when `holderPresented.selectorProfiles` lists every selector
profile the subject roles allow. Omitting `holderPresented` leaves the
definition, its compiled configuration and its revision unchanged.

Startup refuses, at the named member and without echoing a value:

1. `holderPresented.source` naming a Source whose pack route does not reach the
   `wallet-presentation-v1` host protocol, or `source` naming one that does
   (`acquisition/holderPresented/source`, `acquisition/source`);
2. a `holderPresented.selectorProfiles` list that is empty, repeats a profile,
   names a profile no subject role allows, leaves an allowed profile without a
   channel when `source` is absent (`acquisition/holderPresented/selectorProfiles`),
   or the same Source on both channels;
3. an `sd-jwt-vc` or `sd-jwt-vc-batch` representation on a definition with
   `holderPresented`, which answers as signed JWS only (`representations`);
4. a `channels` member on a grant, a grant whose selector profiles span both
   channels (`subjects`), and a definition with neither `source` nor
   `holderPresented` (`acquisition`).

At run time a holder-presented channel whose Source returns no verified
presented facts is a dependency failure, and a source channel whose Source
returns them is a protocol refusal; neither releases a fact.

### Migrate a retired Source project

Use a matching Evidence compiler and runtime that support pack Sources. The
0.44.0 tools accept the earlier transport form and refuse the pack form.
The acquisition interfaces are not derivation interfaces: renaming an old
Function to `assertion-derive/v1` does not migrate its behavior.

1. Keep a copy of your authored project and existing fixture outcomes. Choose a
   current source export, or author a reviewed pack using the
   [Adapter pack contract](../../../adapter/CONCEPT.md#6-artifact-model).
   Put provider requests, paging, preparation and extraction in its routes and
   scripts, with closed input and private-fact schemas.
2. Replace each retired Source in `evidence.yaml` with its `pack`, `route`,
   `connection` and explicit selector `inputs`. Replace each definition's
   acquisition program with `acquisition: {source: <source-id>}`. Keep the
   Requirement URI, selector authority, Outputs and derivation meaning.
3. Remove acquisition Functions from the authored `functions` list after their
   behavior is represented in the pack. Keep requirement derivations under
   `assertion-derive/v1`. Update the named target connection's endpoints to
   match the pack; credentials remain target secret references. A 0.44.0
   flat connection moves its endpoint members under one entry per pack
   endpoint:

   ```yaml
   # 0.44.0
   connections:
     registry:
       origin: https://registry.example.org
       authentication:
         type: bearer
         tokenRef: secret:file/registry-token
       tlsTrustProfile: registry-ca
   # current: `api` is the endpoint id the pack declares
   connections:
     registry:
       endpoints:
         api:
           origin: https://registry.example.org
           authentication:
             type: bearer
             tokenRef: secret:file/registry-token
           tlsTrustProfile: registry-ca
   ```

   `maximumConcurrency`, `admissionTimeoutMilliseconds` and
   `tokenTimeoutMilliseconds` are retired; bound each attempt with the
   endpoint's `attemptTimeoutMilliseconds` and the whole acquisition with the
   target's `sourceAcquisition`.
4. For a reusable export, compare it with `evidencectl source diff EXPORT
   --project PROJECT`, then apply the reviewed result with `evidencectl source
   import EXPORT --project PROJECT`. Resolve reported keep/adopt/file conflicts
   explicitly. The importer requires a current-form `EvidenceProject`; it does
   not convert a retired project. Later changes use `source update`; use
   `source detach` when you want to maintain an installed source locally.
5. Rewrite each fixture case's `source`. The retired form held the provider
   response itself; a pack Source replays an exact transcript of the pack's
   `intercepts` and `exchanges`, including any token exchange its endpoint
   authentication performs, as in
   `products/evidence/fixtures/acceptance/adult-status/fixtures/cases.yaml`.
   `evidencectl check` does not read case transcripts, so an unmigrated case
   first fails in `evidencectl test`, naming the retired form. Then refresh
   recorded facts with `evidencectl fixtures record-facts PROJECT --target
   TARGET --fixture FIXTURE --write` and review the diff.
6. Run `evidencectl check PROJECT --target TARGET` and `evidencectl test PROJECT
   --target TARGET` with the matching runtime. Retain the assertion outcomes and
   refusal cases, and verify no-match, ambiguity and dependency failure
   separately. A transport error must not become a false assertion or no-match.
7. Rebuild the package through the normal deployment workflow. Review the new
   definition revisions and update exact revision pins deliberately. A preserved
   Requirement URI does not make old and new behavior revisions interchangeable.

The reader reports `evidence.project.source-acquisition-retired` at the retired
Function interface or Source transport member. Follow these steps instead of
rewriting acquisition as a derivation. Source lifecycle commands install and
update reviewed artifacts; they do not infer provider behavior or convert the
retired acquisition language.

### Generate explicit OpenAPI request bindings

`evidencectl source suggest <project>` reads the project's retained
`source.openapi.yaml`. Repeat `--map-selector
<role>.<profile>.<field>=<target>` to bind an existing selector field to one
request input. The role and profile must already be used by an assertion in
that project. A mapping never creates a selector profile or caller authority.

| Target | Generated artifact |
|---|---|
| `path:<parameter>` | A reviewed pack endpoint path with an explicit route-input binding |
| `query:<parameter>` | A logical string query pair in the pack preparation script |
| `body:</json/pointer>` | A scalar property in a closed JSON object for a fixed POST request |

For the FHIR example's existing `coverage-record` role and `coverage-by-id`
profile, generate a separate draft source:

```sh
evidencectl source suggest ./fhir-record-evidence \
  --operation 'GET /Coverage/{coverage_id}' --source-id coverage-record-draft \
  --select /status --select /beneficiary/reference \
  --map-selector 'coverage-record.coverage-by-id.coverage_id=path:coverage_id'
```

Each dynamic input is explicit. One field may populate several distinct
targets; duplicate target assignments and unmapped required inputs are refused
before files change. Scalar string, integer and Boolean inputs are supported.
Integer and Boolean query values use canonical text; Rust percent-encodes the
logical query strings. JSON body pointers use RFC 6901 escaping and traverse
closed object properties. Arrays, polymorphic bodies, arbitrary headers,
cookies and authentication mappings are refused. Credentials remain in the
target connection.

The planner checks effective required inputs after operation overrides; optional
inputs are inspected only when you map them. Parameter and request-body
references must resolve locally so their requiredness is known.
Every path placeholder must occupy a unique complete segment, have a mapping,
and use a Registry Stack local identifier (`[a-z][a-z0-9_-]{0,63}`).
The complete request path, including the server path prefix, must fit the
runtime's 2–2048-byte absolute ASCII path contract, with no empty or dot segments,
query, fragment, backslash, or noncanonical or ambiguous percent escapes.

Scalar types must agree, and the selector's admitted domain must fit the
supported string-length or integer-range constraints. Integer formats `int32`
and `int64` are supported; `int32` requires the entire selector range to fit
the signed 32-bit range. Date and UUID formats require the corresponding
selector type. Generation refuses unproven enums,
constants, patterns and conditional constraints, nonstandard parameter
serialization, and object constraints outside this subset. Use a reviewed pack route and script for those contracts.

Source selector inputs retain the existing complete role/profile field set.
Use a narrowly reviewed profile when an integration needs fewer fields; only
explicitly mapped fields enter the generated request. The generated request must fit the pack endpoint and shared-engine request
bounds. Unsupported shapes and bounds need an explicitly reviewed pack route.

The generated preparation and extraction files belong to the owned Adapter
pack and each receives the Adapter `exchange` argument. They are not Evidence
Functions. Review the lookup cardinality and returned-record identity rules,
resolve draft markers and supply assertion semantics before packaging. A run
without `--map-selector` keeps the incomplete mechanical draft workflow.

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
project connection name to explicit
`endpoints`, keyed by the pack endpoint id. Each endpoint supplies its origin,
matching authentication references, optional trust profile and finite attempt
and response bounds. Every Source resolves its named connection; a local-only or
no-send route uses a connection with an empty `endpoints` map, granting no network
endpoint authority.

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
Optional `publication` and `responseFormats` retain their compiled governance
and runtime ceilings. Optional `sourceAcquisition` supplies finite operational
limits for data operations, the absolute acquisition deadline and response
bytes without changing reviewed route or endpoint authority. Governed fields
are revalidated during bundle and package compilation.
Process-local paths and secret readiness are validated by `doctor` or process start.

Optional `signing.maximumAssertionValiditySeconds` is the longest validity, in
seconds, that any definition on the target may sign an assertion for. It is an
integer from 1 to 31,536,000 and defaults to 300 when `signing` is omitted. A
definition whose `validitySeconds` exceeds it is refused at check and build
time. A longer maximum lets every definition on that target sign for longer,
and a bearer assertion (one not bound to a holder) stays replayable for its
whole validity; raise it only for the holder-bound credentials that need it.

The target authority's `project` and `target` must match the selected project
and target. Each `accessProfiles` entry matches authenticated requester tags,
an authority kind and optional actor narrowing, then carries one or more
complete grants. An entry may also carry a `label` and a `description` for
authoring and tooling, which compilation drops; neither is matched against a caller. A grant declares its definition, purpose,
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

A pack Source fixture case's `source` is the exact transcript the pack would
send: its `intercepts` and ordered `exchanges`, each a `request` and the
`response` (`status`, optional `headers`, and one body form). An endpoint with
no host protocol records a JSON `body`. An endpoint whose host protocol checks
the response records it as `rawBodyBase64`, the exact bytes in standard padded
base64; `registry-lookup-v1` signs nothing, so it also accepts a readable JSON
`body`. A response cannot carry both forms, and a refused replay names which
form the endpoint needs.

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
apiVersion
assertionDefinitions
assertionDefinitions.*
assertionDefinitions.*.acquisition
assertionDefinitions.*.acquisition.holderPresented
assertionDefinitions.*.acquisition.holderPresented.selectorProfiles
assertionDefinitions.*.acquisition.holderPresented.selectorProfiles[]
assertionDefinitions.*.acquisition.holderPresented.source
assertionDefinitions.*.acquisition.source
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
sources.*.connection
sources.*.description
sources.*.inputs
sources.*.inputs.*
sources.*.inputs.*.selector
sources.*.inputs.*.selector.field
sources.*.inputs.*.selector.profile
sources.*.inputs.*.selector.role
sources.*.label
sources.*.pack
sources.*.pack.id
sources.*.pack.version
sources.*.projection
sources.*.projection.entrypoint
sources.*.projection.schema
sources.*.projection.source
sources.*.route
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

The normalized target document selects one project and binds its named
connections and finite operational acquisition limits. Its authority reference
points to a separate operator-owned target authority document.

<!-- evidence-authoring-target-key-paths:start -->
```text
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
connections.*.allowedPrivateCidrs
connections.*.allowedPrivateCidrs[]
connections.*.endpoints
connections.*.endpoints.*
connections.*.endpoints.*.attemptTimeoutMilliseconds
connections.*.endpoints.*.authentication
connections.*.endpoints.*.authentication.assumedLifetimeSeconds
connections.*.endpoints.*.authentication.audience
connections.*.endpoints.*.authentication.clientAssertionAudience
connections.*.endpoints.*.authentication.clientAssertionKeyRef
connections.*.endpoints.*.authentication.clientIdRef
connections.*.endpoints.*.authentication.clientSecretRef
connections.*.endpoints.*.authentication.credentialPlacement
connections.*.endpoints.*.authentication.headerName
connections.*.endpoints.*.authentication.maximumCacheSeconds
connections.*.endpoints.*.authentication.passwordRef
connections.*.endpoints.*.authentication.resource
connections.*.endpoints.*.authentication.scheme
connections.*.endpoints.*.authentication.scope
connections.*.endpoints.*.authentication.tokenEndpoint
connections.*.endpoints.*.authentication.tokenRef
connections.*.endpoints.*.authentication.type
connections.*.endpoints.*.authentication.usernameRef
connections.*.endpoints.*.authentication.valueRef
connections.*.endpoints.*.maximumResponseBytes
connections.*.endpoints.*.mtlsIdentity
connections.*.endpoints.*.mtlsIdentity.certificateRef
connections.*.endpoints.*.mtlsIdentity.keyRef
connections.*.endpoints.*.origin
connections.*.endpoints.*.tlsTrustProfile
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
signing
signing.maximumAssertionValiditySeconds
sourceAcquisition
sourceAcquisition.acquisitionDeadlineMilliseconds
sourceAcquisition.maximumDataOperations
sourceAcquisition.maximumResponseBytes
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
accessProfiles.*.description
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
accessProfiles.*.label
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
