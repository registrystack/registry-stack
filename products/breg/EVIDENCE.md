# Export a lookup for Evidence

BReg can export an explicitly selected lookup from its compiled registry into
ordinary Evidence source, selector, schema and adapter files. Evidence owns the
questions those facts answer, caller authorization, disclosure, signing and
deployment configuration. The two services communicate over the existing HTTP
lookup API.

This is an optional authoring path. Evidence's existing OpenAPI authoring,
custom HTTP adapters and SQLite sources remain usable without an export,
import manifest or named connection.

## Select the technical contract

Start with an authored registry whose selected access profile already grants
the lookup and the readable fields you intend to expose. The exporter reads
the compiled model, including locked modules and derived SQL assets. It does
not change the registry or create an access grant.

```sh
mkdir exports
bregctl generate evidence-source ./registry \
  --access-profile evidence-source --entity record \
  --selector by-code --selector by-registration-number \
  --fields status --source-id registry-status --connection registry \
  --output ./exports/registry-status
```

Repeat `--selector` to offer alternatives in the same source. Each request
chooses exactly one profile and makes one lookup. There is no fallback search.
Use another export with another `--source-id` when the selected facts, authority
or intended maintenance boundary differ. Several Evidence questions can reuse
one source without exporting it again.

`--fields` names logical BReg fields, as does `--entity`. API property aliases
are resolved by the compiler. A `registration-number` field can therefore
become the `registrationNumber` property on the wire while keeping its logical
name in Evidence selectors and facts.

For each selected alternative, the generated request uses the fixed lookup
route, method and access profile, and asks for the selected facts plus only
that alternative's identity fields. Those identity fields must already be
readable. The command reports additional identity fields and generated profile
names; it refuses insufficient authority with a diagnostic.

The output directory must be new. Generate the next version into another
directory so that you can compare and review it before changing an Evidence
project.

## Configure the connection in Evidence

The export records a logical connection name, `registry` in this example.
The Evidence operator supplies its fixed base URL, authentication and optional
TLS trust profile in the target's `sourceConnections`. Credentials remain
logical secret references resolved by that deployment. A BReg package or
metadata response never supplies Evidence caller authority.

Use the existing authentication mode appropriate for the source. A named
connection shares its HTTP pool, admission limit and OAuth token state across
the sources which explicitly reference it within one Evidence process.
Separate names keep separate resource owners. Existing inline source
configuration remains available.

The exporter intentionally refuses a `verified_claim` lookup. Such a lookup
uses claims of the source workload's token, which do not identify the Evidence
caller. Select a reviewed `request` lookup when the caller's authorized
selector values must identify the record.

## Review identity and fact handling

The generated extraction adapter uses Evidence's optional
`extract(response, selectors, context)` form. It checks the returned selected
identity's scalar type and exact value before returning matched facts. Missing,
wrongly typed or mismatched identity fails as a source protocol error. No
question can skip that check by replacing its derivation.

Only the explicit fact fields enter the fact set. An absent or null required
fact produces no match and cannot become an authoritative negative answer.
A genuine BReg unresolved lookup is recognized only by its exact declared
Problem Details status, type and code. Other HTTP failures remain failures.

Selectors support bounded nonempty strings, dates, booleans, UUID/reference
strings and vocabulary-code strings. Composite profiles must fit Evidence's
aggregate selector bound. String maxima allow four UTF-8 bytes per BReg
character; the provider retains its character and vocabulary validation.
Identity values are never normalized by the adapter. UUID/reference inputs
must use the representation returned by the provider.

BReg's unrestricted `int64` selector range exceeds Evidence's exact
safe-integer selector range, so the exporter refuses it instead of silently
narrowing its advertised identity contract. Use a bounded string selector or
maintain a reviewed custom adapter for unsupported shapes. Bounded scalar
facts are supported; structured and spatial facts require a custom adapter.

## Import and update ordinary files

```sh
evidencectl source import ./exports/registry-status --project ./evidence
evidencectl source diff ./exports/registry-status-next --project ./evidence
evidencectl source update ./exports/registry-status-next --project ./evidence
```

The optional [source export contract](../evidence/reference/authoring-projects/SOURCE-EXPORT.md)
defines checksums, explicit customization resolutions, shared artifact
ownership and interrupted-update recovery. Imported files remain ordinary
authored files. Use `evidencectl source detach registry-status --project
./evidence` to retain them under your own maintenance.

The consumed `behaviorRevision` covers selected fields, selectors, authority
and reached derived behavior. A reached derived SQL file is fingerprinted as
one implementation, together with its referenced source schemas and row
visibility. An unused derived computation or unrelated field on a simple
stored-field lookup does not change that consumed identity. The complete
registry package revision is separate export provenance.

Changing a record's values does not require another export. Changing consumed
lookup behavior does. Build and test the Evidence candidate against the exact
provider candidate before a coordinated deployment. The export is an offline
contract, not a request-time attestation of the currently running provider.
Independently evolving providers require a paused, coordinated cutover when
their consumed meaning changes.
