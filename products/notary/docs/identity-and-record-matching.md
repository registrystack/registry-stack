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

## Structured direct outputs

A direct output claim may preserve one schema-declared object or array value.
The Relay public contract and the matching Notary consultation expectation use
the same recursive tagged shape. Objects declare every field as
`{ required, schema }`; arrays declare one `items` schema and `max_items`.
Each object and array also declares `max_bytes`, the maximum canonical
serialized size of that value.

The recursive contract is closed and bounded:

- No more than 32 top-level outputs or fields in one object
- No more than 256 items in one array
- No more than 8 schema levels, 256 schema nodes, or 4,096 expanded nodes
- No more than 128 UTF-8 bytes in one output or field name
- No more than 65,536 canonical serialized bytes in one structured value

Unknown object keys, missing required fields, wrong nested types, excessive
arrays, and values over a serialized-size bound fail without becoming claim
values. CEL claim rules remain scalar-only. Use a direct output rule when the
credential must preserve a structured Relay output.

For example, the synthetic OpenCRVS fixture releases this minimized value:

```json
{
  "parents": [
    {
      "type": "mother",
      "name": "Mira Example",
      "identifier": "PARENT-0001"
    },
    {
      "type": "father",
      "name": "Noah Example",
      "identifier": "PARENT-0002"
    }
  ]
}
```

The source fixture also contains a source-only parent reference. The reviewed
adapter constructs each output object field by field, so that reference is not
released.

Registry Notary stores the exact validated result and binds its canonical
content into issuance provenance. Issuance reloads and revalidates that stored
value against the active compiler-pinned contract. A request cannot provide or
replace an object field or array item.

In a Selective Disclosure JSON Web Token (SD-JWT) credential, `parents` is one
top-level disclosure. A holder can disclose or withhold the complete array.
Nested fields and individual array items are not independently disclosable.
Type Metadata publishes `registry_notary_value_schema` for a direct Relay
output so wallets and verifiers can understand the closed value shape without
implying nested disclosure.

Diagnostics, logs, metrics, and audit events may record bounded claim names,
outcome classes, and commitments. They must not record the structured value,
source record, civil identifier, or disclosure content.

For delegated requests, relationship authorization remains Notary policy. A
configured Relay proof consultation can prove exactly the delegated edge it
was compiled for, but it does not expand the caller's scopes or source
authority.
