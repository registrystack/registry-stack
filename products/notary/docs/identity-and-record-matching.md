# Consultation identity and outcomes

Notary does not search registry records itself. A Registry-backed claim maps
the authenticated evidence request to a named Relay consultation. Relay owns
selector canonicalization, source access, protocol verification, cardinality,
and output normalization.

## Inputs

Each consultation input is compiler-defined and closed. Selector inputs
identify the target record; parameter inputs carry other bounded request
values admitted by the evidence service. Notary maps only the approved request
grammar, such as `request.target.identifiers.<name>`, into those inputs.

Caller scope, purpose, requester identity, target identity, relationship, and
authorization details are checked before Relay is invoked. A failed binding or
scope check must produce zero Relay calls.

## Outcomes

Relay returns a closed outcome union:

- `match`: declared typed outputs are present.
- `no_match`: outputs are absent. Notary exposes `matched: false` and nulls in
  its evaluation-only view so policy can derive an explicit predicate.
- `ambiguous`: evaluation stops. Notary cannot choose one candidate.

Denial, source, verification, contract, and availability failures are not
outcomes. They abort the consultation group and cannot be converted into
`no_match` or a claim value.

## Claims

One consultation may supply several claims. A direct output claim reads one
declared output. A CEL claim may combine the consultation's outcome and
allowed outputs with request-bound variables. CEL cannot acquire source data,
change the consultation, or inspect raw Relay errors.

For delegated requests, relationship authorization remains Notary policy. A
configured Relay proof consultation can prove exactly the delegated edge it
was compiled for, but it does not expand the caller's scopes or source
authority.
