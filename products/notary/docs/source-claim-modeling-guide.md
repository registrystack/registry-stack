# Source and claim modeling guide

Use this guide to keep source adaptation in Relay, reusable evidence in
Notary, and consumer decisions in the consuming system.

## Choose the topology

| Need | Project topology | Notary evidence mode |
| --- | --- | --- |
| Governed records or materialization only | Relay only | Not applicable |
| Source-free evidence from an authenticated subject | Notary only | `self_attested` |
| Evidence derived from registry data | Relay and Notary | `registry_backed` |

A Registry Stack project has one registry trust domain and one logical source
available to Relay. Separate independent registries require separate projects.
Do not join them inside one Notary claim.

## Keep evidence separate from consumer decisions

This evidence-versus-decision boundary is normative for 1.0 project
authoring. Use it for every registry-backed flow:

```text
Source system
  -> Registry Relay: source-specific acquisition and typed normalization
  -> Registry Notary: atomic, precise, reusable evidence statements
  -> Evidence consumer: use evidence under consumer-owned policy
  -> Decision owner: remain accountable for requirements and outcomes
```

The caller, evidence consumer, and decision owner can be the same component or
separate components. The caller is the technical client that invokes Notary.
The evidence consumer uses the returned evidence. The decision owner is the
institution accountable for the requirements, rules, decisions, and actions.

The products and consuming roles have different responsibilities:

| Role | Responsibility |
| --- | --- |
| Registry Relay | Source access, bounded acquisition, and source-specific adaptation |
| Registry Notary | Evidence meaning, caller authorization, disclosure, and credential issuance |
| Evidence consumer | Evidence use, presentation, routing, and workflow integration |
| Decision owner | Requirements, eligibility, qualification, prioritization, approval, referral, payment, and action |

Registry Notary may attest a decision already made by an authoritative source.
Name and document that claim as a source-owned decision, such as
`social-registry-assessed-eligible`. Do not present it as a decision computed
by Registry Notary.

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

Relay outputs describe the source response in a stable typed form. They do not
encode an evidence consumer's decision or action rules.

## Model the Notary service

An evidence service owns purpose, legal basis, consent policy, caller access,
consultations, claims, disclosure, and credential profiles. A consultation is
one named use of a Relay integration. It may feed several direct or CEL claims.

Use a direct output claim for a single Relay output. Use CEL for evidence
predicates or derived evidence values. CEL is not a source adapter, cannot
perform I/O, and is not a general-purpose consumer eligibility or decision
engine.
Credential profile membership has one authored direction: the profile lists
its claims.

A claim can be evaluated under purpose-bound authorization while retaining
evidence semantics that several services or procedures can reuse. The evidence
consumer determines how the claims are used after Notary returns them, while
the decision owner remains accountable for any resulting outcome.

## Test each claim design

Before accepting a claim, confirm that:

- The claim states evidence, not an entitlement, payment, referral, outreach,
  or workflow action.
- Its `true`, `false`, `null`, and unavailable cases have reviewed meanings.
- Another service or procedure can reuse the statement without importing the
  first consumer's decision rules.
- A claim that reports an authoritative source's decision is named and
  documented as source-owned.

## Preserve failure semantics

Treat `no_match` as an explicit consultation outcome. Do not model presence as
an author-declared output. Ambiguity and Relay failures abort the consultation
group. A credential containing a direct output claim is not issuable on
`no_match`. Do not turn missing evidence into a negative fact merely to produce
a boolean. A boolean evidence claim can return `false` from a matched source
outcome whose declared typed outputs establish the negative fact. An explicitly
named existence predicate may also map `matched == false` to `false` when its
reviewed meaning is exactly whether one admissible match exists. This exception
does not make other claims negative, and ambiguity or failure remains
unavailable.

## Review checklist

- Caller authorization and purpose are enforced before Relay access.
- Notary contains no source destination or source credential.
- The compiler-produced semantic contract and hash are pinned exactly.
- Inputs map only from the closed request grammar.
- Outputs are typed, bounded, minimized, and distinct from claims.
- Claims pass the evidence-versus-decision design test.
- One consultation is reused for related claims within an evaluation.
- No raw Relay error becomes a claim.
- Fixtures cover match, no-match, ambiguity, mismatch where applicable, and
  country or jurisdiction variations when geographically material.
