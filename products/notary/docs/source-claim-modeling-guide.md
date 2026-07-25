# Source and claim modeling guide

Use this guide to keep source adaptation in Relay and evidence policy in
Notary.

## Choose the topology

| Need | Project topology | Notary evidence mode |
| --- | --- | --- |
| Governed records or materialization only | Relay only | Not applicable |
| Source-free evidence from an authenticated subject | Notary only | `self_attested` |
| Evidence derived from registry data | Relay and Notary | `registry_backed` |

A Registry Stack project has one registry trust domain and one logical source
available to Relay. Separate independent registries require separate projects.
Do not join them inside one Notary claim.

## Model the Relay integration

Author an integration with one product-neutral capability:

- `http` for one bounded request and output projection;
- `script` for reviewed bounded Rhai orchestration and normalization; or
- `snapshot` for an exact lookup over a Relay-local entity generation.

Product and tested-version metadata is interoperability evidence only. It must
not select an executor. Rhai availability depends on the `script` capability
and runtime ABI, never on DHIS2, OpenCRVS, FHIR, OpenSPP, or a version label.

Declare typed inputs, typed minimized outputs, fixtures, source authority, and
only the operational overrides the integration needs. Authentication,
destinations, private networks, trust roots, and secrets belong to the private
environment binding.

## Model the Notary service

An evidence service owns purpose, legal basis, consent policy, caller access,
consultations, claims, disclosure, and credential profiles. A consultation is
one named use of a Relay integration. It may feed several direct or CEL claims.

Use a direct output claim for a single Relay output. Use CEL for
purpose-specific predicates or derived values. CEL is not a source adapter and
cannot perform I/O. Credential profile membership has one authored direction:
the profile lists its claims.

## Preserve failure semantics

Treat `no_match` as an explicit consultation outcome. Do not model presence as
an author-declared output. Ambiguity and Relay failures abort the consultation
group. A credential containing a direct output claim is not issuable on
`no_match`; a reviewed predicate may explicitly turn `matched == false` into
`false` when its profile allows that predicate.

## Review checklist

- Caller authorization and purpose are enforced before Relay access.
- Notary contains no source destination or source credential.
- The compiler-produced semantic contract and hash are pinned exactly.
- Inputs map only from the closed request grammar.
- Outputs are typed, bounded, minimized, and distinct from claims.
- One consultation is reused for related claims within an evaluation.
- No raw Relay error becomes a claim.
- Fixtures cover match, no-match, ambiguity, mismatch where applicable, and
  country or jurisdiction variations when geographically material.
