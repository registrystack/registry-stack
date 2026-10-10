# Subject-facing access logs

An entity can opt in to a subject-facing log of reads of its records. The log
answers who accessed one subject's record, when, and for which declared purpose.
It is stored separately from BReg's operational audit, which keeps its existing
redaction and retention rules. Exemptions add the bounded policy events described
below.

The log is registry-local and keyed to the record that was read. BReg does not
create a global subject pseudonym, share a subject key with another registry, or
make the log searchable across registries. There is no backfill for reads that
happened before a package enabling the log became active.

The log's storage is installed by an apply. A database activated by a release
without it keeps serving its active package after an upgrade, as long as that
package declares no `accessLog`; the next successor apply installs the storage,
and a package that declares `accessLog` is never served without it.

## Author the policy

Add `accessLog` to each entity whose reads must be visible to its subjects:

```yaml
entities:
  - id: person
    primaryDataset: people
    route: people
    mutationMode: mutable
    classification: restricted
    fields:
      - id: citizen-id
        type: string
        minimumLength: 1
        maximumLength: 128
        required: true
        classification: restricted
      - id: display-name
        type: string
        maximumLength: 200
        required: true
        classification: restricted
    accessLog:
      subjectField: citizen-id
      retentionDays: 90
      trustedIntermediaries: [evidence-service]
      exemptions:
        investigator:
          reason: active-investigation
          delayDays: 30
```

`subjectField` names the entity field compared with the subject's verified
principal when the subject retrieves the log. It must be a required,
plaintext, stored `string` or `text` field with `maximumLength` no greater than
512. A subject uses an authenticated access profile that currently grants
`get` for the record, and BReg returns the access log only when the verified
principal selected by that profile's `principalClaim` exactly equals the
stored `subjectField` value. The access-log route is not a separate grant and
does not bypass current record visibility.

The HTTP route is only for the record subject under that current `get` grant
and ownership check. BReg does not expose a separate officer or operator HTTP
listing of subject logs. Database administrators can inspect the underlying
rows, which contain the actual requester and purpose, so deployments must scope
that database access as sensitive operational access. Operators also govern
backup retention separately from the live subject-log retention described
below.

The subject reads:

```http
GET /v1/records/people/00000000-0000-4000-8000-000000000001/access-log?accessProfile=subject&limit=50
```

The response is a bounded page:

```json
{
  "events": [
    {
      "id": "00000000-0000-4000-8000-000000000002",
      "accessedAt": "2026-09-29T10:00:00Z",
      "requester": "benefits-agency",
      "serviceClient": "evidence-service",
      "purpose": "eligibility-check",
      "operationId": "lookup",
      "visibleAfter": "2026-09-29T10:00:00Z",
      "exemptionReason": null
    }
  ],
  "nextCursor": null
}
```

`limit` accepts 1 through 100 and defaults to 50. `cursor` is the opaque event
identifier returned as `nextCursor`; it is always scoped to this record and the
currently verified subject. It conveys no authority. Once retention has removed
the referenced history, the cursor yields an empty page and the caller restarts
without it.

`retentionDays` defaults to 90 and accepts 1 through 3650. Each row records its
own expiry when the read occurs. A later package can change the policy for new
rows, but it does not extend already-recorded expiry, remove retained history,
or turn disabling `accessLog` into erasure. Every minute, the background
retention worker erases expired rows in batches of 1000, each committed on its
own, until a batch comes back short, including after a later package disables
logging. One tick stops after 100 batches (100,000 rows) and logs a warning
with the remaining expired backlog; the next tick continues from there. Expired
rows are hidden immediately even when their physical deletion awaits a later
tick. Operator backup retention is separate from the live subject-log retention
contract.

Every access profile names a verified caller, so every log entry has one.

## Preserve requester attribution through an intermediary

By default, an entry identifies the verified client that called BReg. A service
such as Evidence may need the entry to identify the original requester and
purpose rather than the intermediary alone. `trustedIntermediaries` is the
closed set of verified OAuth client IDs allowed to supply that forwarded
attribution. Each value is a nonempty, non-whitespace client identifier of at
most 512 UTF-8 bytes, and an entity can list at most 64.

BReg accepts forwarded attribution only after authentication, when the selected
profile and verified token identify a client in that set. The forwarded values
travel together in `Registry-Access-Requester` and `Registry-Access-Purpose`.
Each header is the canonical base64url encoding without padding of a nonblank
UTF-8 value of at most 512 bytes, with no control characters. Duplicate or
incomplete pairs are refused. This is the same
[source attribution contract](../evidence/reference/request-adapter/ADAPTER-API.md)
Evidence uses, and it grants no record authority.
An unlisted caller cannot make another client appear in the
subject log. BReg never derives this trust from a request header, issuer name,
or a Registry Manifest projection.

The BReg Evidence exporter enables forwarding for an entity with `accessLog`.
The operator must configure the exported Evidence source connection to
authenticate as a client listed in that entity's `trustedIntermediaries`; BReg
refuses the forwarded request when the verified connection client is absent.

Evidence forwards attribution only for a verified requester and a declared
purpose. Other read paths record the direct verified client and the request's
verified purpose. Operational audit continues to record only its existing
bounded metadata and does not gain raw purpose or subject values from this
feature.

## Delay a documented entry

Some authorized reads cannot be disclosed immediately. `exemptions` maps an
existing read-capable access profile to a governed policy reason and delay. An
entity can declare at most 64 exemptions. `reason` must be trimmed printable
text of at most 256 UTF-8 bytes. `delayDays` must be at least 1 and less than
`retentionDays`.

An exemption without `sourceEntity` applies to direct reads authorized by the
named profile on the logged entity. A relationship read uses the profile and
entity at the start of its read path, so a delayed relationship entry names
that authority entity explicitly:

```yaml
exemptions:
  relationship-investigator:
    sourceEntity: case
    reason: active-investigation
    delayDays: 30
```

The compiler accepts this form only when the named profile belongs to
`sourceEntity` and grants a declared read path from that entity to the logged
entity. BReg matches both the source entity and profile when applying the
delay, so an unrelated profile with the same ID cannot inherit the exemption.

An exempt read is still written. Its row retains the policy reason and an exact
`visibleAfter` time, and the operational audit records that the governed exemption
was applied without copying the subject, purpose, or other access-log values.
That audit entry uses the `breg-access-log/v1` schema and includes only a
policy-keyed reference, delay, profile, entity, and package binding. It does not
copy the policy reason. The subject route withholds the row until `visibleAfter`; an exemption never
silently omits a read. A package upgrade does not retroactively hide a visible
entry, reveal a delayed entry early, or rewrite its reason.

## Reads covered

BReg logs each authorized record materialized from storage through direct get,
list (including GIS collection items), lookup, relationship traversal, snapshot,
revision, and attachment download routes. Paging lookahead rows are removed first, so they do not become
events. A refusal before record access and a query that matches no record create
no subject-log entry. An unresolved ambiguous lookup can materialize candidate
records before it refuses the response; those accesses are recorded. Each
materialized record gets its own entry, so a list or historical query cannot be
represented as one ambiguous subject event.

The access-log insert occurs before response release and its failure refuses the
read. Once the entry commits, a later serialization, terminal-audit, or network
failure does not erase it. An entry therefore records that BReg accessed and
prepared the record under the caller's authority, even when the caller did not
ultimately receive response bytes.

The log contains the accessing client attribution, access time, operation, and
verified purpose value, plus delayed-disclosure metadata when an exemption
applies. `purpose` is null when the verified token carries no purpose; BReg does
not invent one. On a direct read, `requester` identifies the verified OAuth
client when one is available and otherwise the verified principal;
`serviceClient` is null. On a trusted forwarded read, `requester` is the original
verified requester and `serviceClient` identifies the verified intermediary.
The log does not copy record fields, query values, tokens, or a global subject
identifier. Access-log persistence and the read response are governed product
state; they are not reconstructed from the operational audit.
