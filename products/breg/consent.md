# Consent-gated reads

A read permission can require the subject's recorded consent before a row
reaches a named recipient. Consent decisions are ordinary create-only records
written by governed actions. PostgreSQL checks them on every read, so a
withdrawal takes effect for the next request without a token change, cache
flush, or restart.

Consent here gates disclosure to a recipient organization that reads through
its own client. It is not a lawful-basis engine, a consent-request workflow,
or a credential: the registry records what the subject decided and refuses a
gated read that the recorded decisions do not cover.

## Authoring

### Recipients and groups

Declare who can receive gated rows once, at the top of the project:

```yaml
recipients:
  organizations:
    - id: food-agency
      name: Food Assistance Agency
      contact: privacy@food-agency.example.gov
      clients: [food-agency-portal]
    - id: health-ngo
      name: Health Referral NGO
      contact: dpo@health-ngo.example.org
      clients: [health-ngo-portal]
  groups:
    - id: referral-network
      name: Referral network
      members: [food-agency, health-ngo]
```

Organization and group ids share one namespace and use the lowercase
identifier grammar. A client acts for at most one organization. Group members
are distinct declared organizations, groups do not nest, and an organization
belongs to at most 63 groups. An organization with no clients is retired: it
keeps its code so stored decisions stay valid, and no client acts for it.

The compiler synthesizes two vocabularies from this block and the gated
profiles. They cannot be declared by hand:

| Vocabulary | Values |
|---|---|
| `registry-recipients` | every organization and group id |
| `registry-consent-scopes` | every profile id that carries `requireConsent`, plus each id in `retiredConsentScopes` |

A synthesized vocabulary exists only once it has values, so a project whose
consent record uses `registry-consent-scopes` compiles only after some
permission requires consent. Until then the compiler reports
`consent.require.unused` and names the `requireConsent` line to add, or the
`retiredConsentScopes` entry that keeps a former scope.

At startup, every client that a recipient organization lists must also be in
the issuer's `allowedClients`. The runtime refuses to start otherwise, so a
recipient client can never be one the verifier would reject.

### The consent record

A consent record is a create-only entity that declares `consentRecord`:

```yaml
- id: person-consent-decision
  mutationMode: create_only
  fields:
    - {id: subject, type: reference, target: person, required: true}
    - {id: recipient, type: vocabulary-code, vocabulary: registry-recipients, required: true}
    - {id: purpose, type: vocabulary-code, vocabulary: data-use-purpose, required: true}
    - {id: scope, type: vocabulary-code, vocabulary: registry-consent-scopes, required: true}
    - {id: decision, type: vocabulary-code, vocabulary: consent-decision, required: true}
    - {id: effective-at, type: timestamp, required: true}
    - {id: expires-at, type: timestamp}
  consentRecord:
    subject: subject
    recipient: recipient
    purpose: purpose
    scope: scope
    decision:
      field: decision
      gives: [given]
      revokes: [refused, withdrawn, invalidated]
      refusals: [refused]
    validity:
      from: effective-at
      until: expires-at
      maxDuration: P365D
```

The field declarations above omit classifications for brevity. The rules the
compiler holds:

- `subject` is a reference to the entity whose rows the consent covers.
- `recipient` uses `registry-recipients` and `scope` uses
  `registry-consent-scopes`; `purpose` and `decision` are codes of ordinary
  project vocabularies.
- `gives` and `revokes` are non-empty, distinct, disjoint codes of the
  decision vocabulary, at most 64 together. `refusals` is a subset of
  `revokes`.
- `from` is a required timestamp and `until` an optional one. `maxDuration`
  is a positive ISO 8601 duration of at most ten years.
- The key and validity fields are plaintext. The check compares stored
  values, so ciphertext could never match.
- The record is a leaf: no change request, no `requireConsent` on its own
  profiles, no incoming read paths, and its subject is not another consent
  record.
- No profile grants `create` or `batch` on it. Rows are written only by
  actions that declare `consentIssuer`.

### Issuing actions

Every action that creates consent rows declares `consentIssuer`:

- `self`: the subject decides through their own principal. The action uses
  fixed effects, sets the subject from an input `S`, and requires a link input
  `L` with `{input: L, field: <link subject>, equalsInput: S}` and
  `{input: L, field: <link active>, equals: true}`. Every permission that
  admits the action bounds `L`'s target to the caller's principal.
- `steward`: a registry officer records the decision, as in assisted capture,
  invalidation, or an import from a prior system. The steward acts without
  the subject's principal, so these actions deserve the same review as any
  other privileged write.

The self-service link is an ordinary entity holding `subject`, `principal`,
and `active`. Its self profile reads its own links through a principal row
boundary, reads its own decisions through a membership boundary on that
link, and targets the link in every self action through the same principal
row boundary. Provisioning a link is a steward identity-proofing act: whoever
can create or activate a link decides which principal speaks for which
subject.

### Gating a permission

Add `requireConsent` to a read permission:

```yaml
- id: food-targeting
  principalClaim: registry_principal
  actorKind: service
  requesterClients: [food-agency-portal, health-ngo-portal]
  requiredScopes: [registry:person:read]
  requiredPurposes: [food-assistance]
  permissions:
    - entity: person
      operations: [get, list]
      readableFields: [person-code, legal-name, district]
      allowCount: true
      rowBoundaries: []
      requireConsent:
        - {record: person-consent-decision, on: id}
```

`on: id` gates the row on its own identity and needs a consent subject that
references this entity. Any other `on` value names a plaintext stored
reference to the consent subject's entity, so an enrolment can be gated on its
`person`. A row whose reference is empty is never disclosed. Every listed
check must hold.

A gated profile needs `actorKind`, `requesterClients` that a declared
recipient organization lists, and `requiredPurposes` drawn from the consent
record's purpose vocabulary. It cannot be anonymous.

### The recipient feed

A recipient reads the decisions addressed to it through a profile bounded by
the reserved `registry:recipients` claim:

```yaml
- id: person-consent-recipient
  principalClaim: registry_principal
  requiredScopes: ['consent:person:read']
  permissions:
    - entity: person-consent-decision
      rowBoundaries:
        - {field: recipient, claim: 'registry:recipients', operator: in}
      operations: [get, list]
      readableFields: [subject, recipient, purpose, scope, decision, effective-at, expires-at]
```

`registry:recipients` binds only an `in` row boundary on a consent record's
recipient field, in a permission limited to `get` and `list`. The compiler
refuses it, and every `registry:consent-decisions:` claim, on each other
surface that names a verified claim: a principal claim, another row boundary,
an entity access requirement, a lookup `claimMapping`, an action target, an
`applyTargets` grant, or a `requestPresence` grant. Each refusal is
`consent.feed.claim`, so no authored selector reaches a consent record without
the feed's decision bound. The
compiler adds a second row boundary to the feed on the decision field, filled
by the engine with the codes a recipient may learn: every give, and every
revoke that is not a refusal.

### Generating the module

`bregctl module add consent --subject person <project>` writes a module with
the privacy notice, its clauses, the principal link, the create-only decision,
the self and steward actions, and five access profiles: self, assisted
capture, steward, link steward, and recipient feed. It prints the
`requireConsent` line that gates a permission on the new decision. The
complete generated result for a person registry is
[`consent-person-registry`](fixtures/consent-person-registry/registry.yaml);
[`consent-land-registry`](fixtures/consent-land-registry/registry.yaml) gates
tenure rights for lenders, including a group give.

The command refuses until the project declares `recipients` and a
`data-use-purpose` vocabulary. The generated entities belong to a dataset
named `consent`. When the project carries a `manifestProjection`, the command
declares that dataset itself if it is not there yet, naming a generated
steward profile as its `accessProfile`, such as `person-consent-steward`. If
the project already declares a `consent` dataset, the command leaves it
exactly as authored and reuses it for the new subject too, the way a second
subject's run already reuses the first subject's shared vocabularies; if that
existing dataset's access profile does not cover the module's entities, the
command reports `module.consent.dataset_conflict` and writes nothing. The
`consent` dataset in
[`consent-land-registry`](fixtures/consent-land-registry/registry.yaml)
shows the declaration a first run writes.

## Semantics

A gated row is disclosed while, for every `requireConsent` check, a live give
exists whose:

- subject is the row's id, or the value of its `on` reference;
- scope is the gated profile id;
- purpose is the request's verified purpose;
- recipient is one of the caller's recipients;
- `from` is at or before the transaction start;
- effective end is after the transaction start;
- and no later revoke supersedes it.

The caller's recipients come from the verified requester client
(`azp` or `client_id`): the organization that lists the client, plus every
group that organization belongs to. A token cannot supply them. A client no
organization lists has an empty recipient set, so every check it reaches
fails closed.

A group give and an organization give are separate keys. A food agency that
received both keeps reading while either is live; withdrawing the group give
ends it for every member organization that had no give of its own.

### Ordering and supersession

Decisions are ordered by capped time, `LEAST(from, created_at)`: the earlier
of the declared start and the moment the registry recorded the row. A revoke
supersedes a give with the same subject, recipient, purpose, and scope when
its capped time is at or after the give's. Consequences:

- A future-dated give cannot outrank a withdrawal recorded after it, because
  its capped time is its recording time.
- A backdated give recorded after a withdrawal is superseded by that
  withdrawal. A re-give after a withdrawal must use a current `from`.
- A withdrawal with no earlier give is accepted and has nothing to end.
- On a tie, the revoke wins.

### Validity

A give takes effect at `from` and ends at the earlier of `until` and
`LEAST(from, created_at) + maxDuration`. `maxDuration` caps every give,
including one that sets no `until` or a later one. A give with a future
`from` is scheduled: it is recorded now and discloses nothing until `from`.
Expiry is computed at read time; nothing rewrites the row.

A withdrawal takes effect for transactions that start after it commits. A
read already running may finish from its snapshot.

## What it enforces, and what it does not

Enforced, and refused at compilation where the shape is configuration:

- Every read operation of a gated permission is checked: get, lookup, list,
  count, snapshot including pinned snapshots, revisions, continuation
  cursors, and read paths rooted at a gated entity. A row without consent
  answers `404` exactly like an absent row.
- Gated permissions are read-only (`consent.require.read_only`). Writes,
  actions, change requests, and request lifecycle grants use a separate
  profile.
- Spatial bbox queries are refused on gated permissions
  (`consent.require.spatial_unsupported`): they run under a separate database
  authority role that cannot evaluate consent.
- Bulk data export is refused (`consent.require.export_unsupported`), and so
  is exporting a gated profile as an Evidence source
  (`consent.require.evidence_source_unsupported`).
- A read path cannot reach a gated entity through an intermediate or target
  step (`consent.require.read_path_target`). Use that entity's direct read
  route.
- A refusal never reaches a recipient through the feed.

Not enforced:

- A profile without `requireConsent` bypasses consent entirely. `bregctl
  check` reports `access.consent.ungated_client` for a profile that reads a
  gated entity's rows without consent while it admits any client, or while it
  shares a client with a gated profile. Give each gated profile's recipients
  their own clients, and give an ungated reader clients no gated profile
  admits.
- The feed discloses unsolicited withdrawals and invalidations. A recipient
  learns of every non-refusal decision addressed to it, including a
  withdrawal for a subject it never received a give for.
- Assisted capture and link provisioning rely on staff integrity plus the
  audit journal. The engine cannot tell a real assisted decision from an
  invented one.
- List response timing is not equalized. A caller that can measure latency
  across many requests may infer the size of a gated population.

The self actions answer an unknown subject exactly like a subject the caller's
link does not cover, so a self action is not an existence oracle.

## Processing

For each consent record, the compiler generates one `SECURITY INVOKER`
set-returning probe function. It reads the consent table only under its own
marker (`registry.consent_probe` set to the probe and
`registry.access_profile` set to the gated profile), the same
processing-only marker model as membership boundaries. The runtime sets
`registry.recipients` from the verified requester client in the record
transaction, never from a token claim or request header. The probe parses
that setting strictly: a missing or empty value matches nothing, and a
malformed one raises an error.

The probe is uncorrelated. A gated read runs it once per query and tests each
row with `IN`, so its cost does not grow with the page size. Two indexes
support it: one on subject, recipient, purpose, and scope, and a partial one
on live revokes by key and capped time. A single-record read still evaluates
the probe for the whole key, so its cost scales with the number of live
decisions that share the caller's recipients, purpose, and scope, not with
the number of rows returned. The opt-in measurement
`real_postgres_consent_gated_list_latency_budget` in
[`postgres_consent_access.rs`](../../crates/registry-breg/tests/postgres_consent_access.rs)
reports the p50 and p95 of a 100-row page with its count over 100,000
subjects and 10,000 live gives; it gates nothing.

The catalog identity check covers the probe functions, so a runtime refuses
an altered probe.

## Changing a consent-gated project

Consent codes are append-only. Stored decisions carry recipient and scope
codes, so a migration that removes one fails against existing rows and
`bregctl diff` flags it. Retire instead:

- A recipient organization is retired by removing its clients; its code
  stays.
- A gated scope is retired by renaming the profile and listing the old id in
  `retiredConsentScopes`. The gated profile id is the scope subjects
  consented to, so removing `requireConsent` in place, or widening the
  profile's fields, operations, lookups, or read paths, would read under a
  scope the subjects never saw. A new profile id is a new scope and asks
  again.

Adding a vocabulary code to a field is a compatible additive migration: stored
codes stay valid and only the check constraint widens. The migration replaces
that check under an exclusive table lock and validates every stored row, so
`bregctl diff` classifies the change `lock_or_rewrite_risk`; it still needs
no reviewed migration.

An action input that starts accepting more codes is compatible and additive,
and metadata-only, only when every code it gained is new to its vocabulary in
the same revision. Adding a recipient or scope therefore migrates the issuing
actions that pick it up without a schema change. An input that starts
accepting a code its vocabulary already had, such as a withdraw action whose
decision input adds `given`, changes what the action does: it is an
`action_changed` access change and needs a reviewed migration. `bregctl diff`
still marks new-code input widenings for review, because the action then
accepts each new code with no further check. A package built before the
engine recorded each input's vocabulary cannot show a code is new, so every
input widening against it is reviewed.

`bregctl diff` classifies consent, recipient, and consent-issuer changes as
access changes and attaches a `reason` to each change that alters who holds
an existing consent:

| Change | Reason |
|---|---|
| a gated profile widens, including added lookups or read paths | the profile is the scope; a new profile id asks again |
| `requireConsent` removed | rename the profile and retire the scope instead |
| a client added to an organization | every existing give to the organization and its groups extends to the client |
| a group's members change | every existing group give changes holders; prefer a new group id and clause |
| `maxDuration` raised | existing gives last longer than the notice said |
| a consent vocabulary code removed | codes are append-only; retire the code |
| an action becomes a steward issuer | steward actions create consent without the subject's principal |
| an action accepts codes new to their vocabulary | check each code is one the action may write |
| the consent indexes are rebuilt | the build blocks writes to the consent table until the migration commits |

Removing a client or lowering `maxDuration` narrows access and carries no
reason. The `reason` is a review aid in tooling output, not a runtime
guarantee: the registry enforces what the new package declares.

A consent record change replaces its probe function, so it is an access
change and never metadata-only. Recipient organization and group changes are
metadata-only access changes. A successor replaces or drops each probe and
index so the result matches a fresh install. A changed key or revoke set
drops the prior consent index and builds the new one with a plain
`CREATE INDEX` in the migration's transaction, since `CREATE INDEX
CONCURRENTLY` cannot run inside one; the diff lists the dropped and built
indexes under `consentIndexes`.

## Explain and preview

`bregctl explain access` reports a `consent` section: the disclosure
condition, how unmapped clients fail closed, the trust model of the probe
markers, the rule for ungating, every recipient organization and group, and,
for each gated permission, its record, key, indexes, readable fields, client
recipients, and issuing actions with their issuer kind.

An access preview scenario takes `actorKind` and `requesterClient`. The
preview derives the recipient set from the client the way the runtime does
and reports it as `recipients`; an unmapped or absent client yields an empty
set. `directClaims` cannot name `registry:recipients` or a
`registry:consent-decisions:` claim, since those are filled only by the
engine.

## Known limits

- The feed discloses unsolicited withdrawals and invalidations to the named
  recipient.
- List timing side channels are not addressed.
- Assisted capture and link provisioning rest on staff integrity and the
  audit journal.
- The engine has no consent-request or pending state. A request for consent
  is outside the registry; only the subject's decision is recorded.
- Consent gates rows, not fields. A field-level disclosure policy still needs
  separate profiles.
- A gated profile serves only get, lookup, list, count, snapshot, and
  revisions. Spatial queries, bulk export, and Evidence sources over gated
  rows are refused rather than approximated.

Focused verification lives in
[`consent_access.rs`](../../crates/registry-breg/tests/consent_access.rs),
[`consent_tooling.rs`](../../crates/registry-breg/tests/consent_tooling.rs),
[`postgres_consent_access.rs`](../../crates/registry-breg/tests/postgres_consent_access.rs),
and
[`postgres_consent_examples.rs`](../../crates/registry-breg/tests/postgres_consent_examples.rs),
which runs acceptance journeys BREG-J22 and BREG-J23.
